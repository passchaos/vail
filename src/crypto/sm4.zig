//! SM4 block cipher plus SM4-GCM and SM4-CCM AEAD support.
//!
//! This module provides a compact portable implementation with the same
//! fixed-size, allocation-free calling style as Zig's AES-GCM primitives.

const std = @import("std");
const builtin = @import("builtin");
const ccm = @import("aes_ccm.zig");
const ghash_accelerated = @import("ghash.zig");

pub const key_len = 16;
pub const block_len = 16;
pub const rounds = 32;
pub const Key = [key_len]u8;
pub const Block = [block_len]u8;

const wide8_enabled = builtin.cpu.arch == .x86_64 and
    builtin.zig_backend != .stage2_x86_64 and
    builtin.cpu.has(.x86, .avx2);

pub const KeySchedule = struct {
    round_keys: [rounds]u32,

    pub fn init(key: Key) KeySchedule {
        var k: [4]u32 = undefined;
        for (0..4) |index| {
            k[index] = std.mem.readInt(
                u32,
                key[index * 4 ..][0..4],
                .big,
            ) ^ fk[index];
        }

        var round_keys: [rounds]u32 = undefined;
        for (0..rounds) |index| {
            const next = k[0] ^ keyTransform(k[1] ^ k[2] ^ k[3] ^ ck[index]);
            round_keys[index] = next;
            k = .{ k[1], k[2], k[3], next };
        }
        return .{ .round_keys = round_keys };
    }

    pub fn encryptBlock(self: *const KeySchedule, plaintext: Block) Block {
        return cryptBlock(&self.round_keys, plaintext, .encrypt);
    }

    pub fn decryptBlock(self: *const KeySchedule, ciphertext: Block) Block {
        return cryptBlock(&self.round_keys, ciphertext, .decrypt);
    }

    pub fn encryptWide2(
        self: *const KeySchedule,
        output: *[2 * block_len]u8,
        input: *const [2 * block_len]u8,
    ) void {
        self.encryptWide(2, output, input);
    }

    pub fn encryptWide4(
        self: *const KeySchedule,
        output: *[4 * block_len]u8,
        input: *const [4 * block_len]u8,
    ) void {
        self.encryptWide(4, output, input);
    }

    pub fn encryptWide8(
        self: *const KeySchedule,
        output: *[8 * block_len]u8,
        input: *const [8 * block_len]u8,
    ) void {
        self.encryptWide(8, output, input);
    }

    inline fn encryptWide(
        self: *const KeySchedule,
        comptime degree: usize,
        output: *[degree * block_len]u8,
        input: *const [degree * block_len]u8,
    ) void {
        const Lane = @Vector(degree, u32);
        var x0: Lane = undefined;
        var x1: Lane = undefined;
        var x2: Lane = undefined;
        var x3: Lane = undefined;
        inline for (0..degree) |lane| {
            const offset = lane * block_len;
            x0[lane] = std.mem.readInt(u32, input[offset..][0..4], .big);
            x1[lane] = std.mem.readInt(u32, input[offset + 4 ..][0..4], .big);
            x2[lane] = std.mem.readInt(u32, input[offset + 8 ..][0..4], .big);
            x3[lane] = std.mem.readInt(u32, input[offset + 12 ..][0..4], .big);
        }
        for (self.round_keys) |round_key| {
            const next = x0 ^ roundTransformWide(
                degree,
                x1 ^ x2 ^ x3 ^ @as(Lane, @splat(round_key)),
            );
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = next;
        }
        inline for (0..degree) |lane| {
            const offset = lane * block_len;
            std.mem.writeInt(u32, output[offset..][0..4], x3[lane], .big);
            std.mem.writeInt(u32, output[offset + 4 ..][0..4], x2[lane], .big);
            std.mem.writeInt(u32, output[offset + 8 ..][0..4], x1[lane], .big);
            std.mem.writeInt(u32, output[offset + 12 ..][0..4], x0[lane], .big);
        }
    }
};

const CcmBlockCipher = struct {
    pub const key_length = key_len;

    schedule: KeySchedule,

    pub fn init(key: Key) CcmBlockCipher {
        return .{ .schedule = KeySchedule.init(key) };
    }

    pub inline fn encryptBlock(
        self: *const CcmBlockCipher,
        output: *Block,
        input: *const Block,
    ) void {
        output.* = self.schedule.encryptBlock(input.*);
    }

    pub inline fn encryptPair(
        self: *const CcmBlockCipher,
        output: *[2 * block_len]u8,
        input: *const [2 * block_len]u8,
    ) void {
        self.schedule.encryptWide2(output, input);
    }
};

/// RFC 8998 AEAD_SM4_CCM with a 12-byte nonce and 16-byte tag.
pub const Ccm = ccm.Ccm(CcmBlockCipher, 16);

pub fn encryptBlock(key: Key, plaintext: Block) Block {
    return KeySchedule.init(key).encryptBlock(plaintext);
}

pub fn decryptBlock(key: Key, ciphertext: Block) Block {
    return KeySchedule.init(key).decryptBlock(ciphertext);
}

pub const GcmContext = struct {
    pub const key_length = key_len;
    pub const nonce_length = 12;
    pub const tag_length = 16;

    schedule: KeySchedule,
    ghash: Ghash,

    pub fn init(key: Key) GcmContext {
        const schedule = KeySchedule.init(key);
        var hash_subkey = schedule.encryptBlock([_]u8{0} ** block_len);
        defer std.crypto.secureZero(u8, &hash_subkey);
        return .{
            .schedule = schedule,
            .ghash = Ghash.init(&hash_subkey),
        };
    }

    pub fn deinit(self: *GcmContext) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    pub fn encrypt(
        self: *const GcmContext,
        ciphertext: []u8,
        tag: *[tag_length]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) void {
        std.debug.assert(ciphertext.len == plaintext.len);

        var j0: Block = undefined;
        j0[0..nonce_length].* = nonce;
        std.mem.writeInt(u32, j0[nonce_length..][0..4], 1, .big);
        const tag_mask = self.schedule.encryptBlock(j0);

        var counter = j0;
        incrementGcmCounter(&counter);
        ctrXor(&self.schedule, ciphertext, plaintext, counter);
        ghash_accelerated.create(
            &self.ghash,
            tag,
            associated_data,
            ciphertext,
        );
        for (tag_mask, 0..) |byte, index| tag[index] ^= byte;
    }

    pub fn decrypt(
        self: *const GcmContext,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [tag_length]u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) std.crypto.errors.AuthenticationError!void {
        std.debug.assert(plaintext.len == ciphertext.len);

        var j0: Block = undefined;
        j0[0..nonce_length].* = nonce;
        std.mem.writeInt(u32, j0[nonce_length..][0..4], 1, .big);
        const tag_mask = self.schedule.encryptBlock(j0);

        var computed_tag: [tag_length]u8 = undefined;
        ghash_accelerated.create(
            &self.ghash,
            &computed_tag,
            associated_data,
            ciphertext,
        );
        for (tag_mask, 0..) |byte, index| computed_tag[index] ^= byte;

        if (!std.crypto.timing_safe.eql([tag_length]u8, computed_tag, tag)) {
            std.crypto.secureZero(u8, &computed_tag);
            @memset(plaintext, undefined);
            return error.AuthenticationFailed;
        }

        var counter = j0;
        incrementGcmCounter(&counter);
        ctrXor(&self.schedule, plaintext, ciphertext, counter);
    }
};

pub const Gcm = struct {
    pub const key_length = GcmContext.key_length;
    pub const nonce_length = GcmContext.nonce_length;
    pub const tag_length = GcmContext.tag_length;

    pub fn encrypt(
        ciphertext: []u8,
        tag: *[tag_length]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
        key: Key,
    ) void {
        var context = GcmContext.init(key);
        defer context.deinit();
        context.encrypt(ciphertext, tag, plaintext, associated_data, nonce);
    }

    pub fn decrypt(
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [tag_length]u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
        key: Key,
    ) std.crypto.errors.AuthenticationError!void {
        var context = GcmContext.init(key);
        defer context.deinit();
        return context.decrypt(
            plaintext,
            ciphertext,
            tag,
            associated_data,
            nonce,
        );
    }
};

const Direction = enum { encrypt, decrypt };
const Ghash = std.crypto.onetimeauth.Ghash;

fn cryptBlock(
    round_keys: *const [rounds]u32,
    input: Block,
    direction: Direction,
) Block {
    var x0 = std.mem.readInt(u32, input[0..4], .big);
    var x1 = std.mem.readInt(u32, input[4..8], .big);
    var x2 = std.mem.readInt(u32, input[8..12], .big);
    var x3 = std.mem.readInt(u32, input[12..16], .big);

    for (0..rounds) |index| {
        const round_key = switch (direction) {
            .encrypt => round_keys[index],
            .decrypt => round_keys[rounds - 1 - index],
        };
        const next = x0 ^ roundTransform(x1 ^ x2 ^ x3 ^ round_key);
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = next;
    }

    var output: Block = undefined;
    std.mem.writeInt(u32, output[0..4], x3, .big);
    std.mem.writeInt(u32, output[4..8], x2, .big);
    std.mem.writeInt(u32, output[8..12], x1, .big);
    std.mem.writeInt(u32, output[12..16], x0, .big);
    return output;
}

fn ctrXor(
    schedule: *const KeySchedule,
    destination: []u8,
    source: []const u8,
    initial_counter: Block,
) void {
    std.debug.assert(destination.len == source.len);

    var counter = initial_counter;
    var offset: usize = 0;
    if (comptime wide8_enabled) {
        while (offset + 8 * block_len <= source.len) : (offset += 8 * block_len) {
            var counters: [8 * block_len]u8 = undefined;
            inline for (0..8) |index| {
                counters[index * block_len ..][0..block_len].* = counter;
                incrementGcmCounter(&counter);
            }
            var streams: [8 * block_len]u8 = undefined;
            schedule.encryptWide8(&streams, &counters);
            const Bytes = @Vector(8 * block_len, u8);
            destination[offset..][0 .. 8 * block_len].* = @bitCast(
                @as(Bytes, @bitCast(source[offset..][0 .. 8 * block_len].*)) ^
                    @as(Bytes, @bitCast(streams)),
            );
        }
    }
    while (offset + 4 * block_len <= source.len) : (offset += 4 * block_len) {
        var counter1 = counter;
        incrementGcmCounter(&counter1);
        var counter2 = counter1;
        incrementGcmCounter(&counter2);
        var counter3 = counter2;
        incrementGcmCounter(&counter3);
        const counters = counter ++ counter1 ++ counter2 ++ counter3;
        var streams: [4 * block_len]u8 = undefined;
        schedule.encryptWide4(&streams, &counters);
        const Bytes = @Vector(4 * block_len, u8);
        destination[offset..][0 .. 4 * block_len].* = @bitCast(
            @as(Bytes, @bitCast(source[offset..][0 .. 4 * block_len].*)) ^
                @as(Bytes, @bitCast(streams)),
        );
        counter = counter3;
        incrementGcmCounter(&counter);
    }
    while (offset + 2 * block_len <= source.len) : (offset += 2 * block_len) {
        var next_counter = counter;
        incrementGcmCounter(&next_counter);
        const counters = counter ++ next_counter;
        var streams: [2 * block_len]u8 = undefined;
        schedule.encryptWide2(&streams, &counters);
        const Bytes = @Vector(2 * block_len, u8);
        destination[offset..][0 .. 2 * block_len].* = @bitCast(
            @as(Bytes, @bitCast(source[offset..][0 .. 2 * block_len].*)) ^
                @as(Bytes, @bitCast(streams)),
        );
        counter = next_counter;
        incrementGcmCounter(&counter);
    }
    while (offset + block_len <= source.len) : (offset += block_len) {
        const stream = schedule.encryptBlock(counter);
        for (0..block_len) |index| {
            destination[offset + index] = source[offset + index] ^ stream[index];
        }
        incrementGcmCounter(&counter);
    }

    if (offset < source.len) {
        const stream = schedule.encryptBlock(counter);
        for (source[offset..], 0..) |byte, index| {
            destination[offset + index] = byte ^ stream[index];
        }
    }
}

fn incrementGcmCounter(counter: *Block) void {
    const value = std.mem.readInt(u32, counter[12..16], .big) +% 1;
    std.mem.writeInt(u32, counter[12..16], value, .big);
}

fn roundTransform(x: u32) u32 {
    const y = tau(x);
    return y ^ rotl(y, 2) ^ rotl(y, 10) ^ rotl(y, 18) ^ rotl(y, 24);
}

fn roundTransformWide(
    comptime degree: usize,
    x: @Vector(degree, u32),
) @Vector(degree, u32) {
    const Lane = @Vector(degree, u32);
    var substituted: Lane = undefined;
    inline for (0..degree) |lane| substituted[lane] = tau(x[lane]);
    return substituted ^
        std.math.rotl(Lane, substituted, 2) ^
        std.math.rotl(Lane, substituted, 10) ^
        std.math.rotl(Lane, substituted, 18) ^
        std.math.rotl(Lane, substituted, 24);
}

fn keyTransform(x: u32) u32 {
    const y = tau(x);
    return y ^ rotl(y, 13) ^ rotl(y, 23);
}

fn tau(x: u32) u32 {
    return (@as(u32, sbox[@as(u8, @truncate(x >> 24))]) << 24) |
        (@as(u32, sbox[@as(u8, @truncate(x >> 16))]) << 16) |
        (@as(u32, sbox[@as(u8, @truncate(x >> 8))]) << 8) |
        @as(u32, sbox[@as(u8, @truncate(x))]);
}

fn rotl(value: u32, amount: anytype) u32 {
    return std.math.rotl(u32, value, amount);
}

const fk = [4]u32{
    0xa3b1bac6,
    0x56aa3350,
    0x677d9197,
    0xb27022dc,
};

const ck = [rounds]u32{
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

const sbox = [256]u8{
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var output: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, hex) catch unreachable;
    return output;
}

test "SM4 block cipher official vector" {
    const key = decodeHex("0123456789abcdeffedcba9876543210");
    const plaintext = decodeHex("0123456789abcdeffedcba9876543210");
    const expected = decodeHex("681edf34d206965e86b3e94f536e4246");
    const ciphertext = encryptBlock(key, plaintext);
    try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
    const opened = decryptBlock(key, ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &opened);
}

test "SM4 wide encryption matches independent block calls" {
    const key = decodeHex("0123456789abcdeffedcba9876543210");
    const input = decodeHex(
        "0123456789abcdeffedcba9876543210" ++
            "00112233445566778899aabbccddeeff",
    );
    const schedule = KeySchedule.init(key);
    var output: [2 * block_len]u8 = undefined;
    schedule.encryptWide2(&output, &input);
    try std.testing.expectEqual(
        schedule.encryptBlock(input[0..block_len].*),
        output[0..block_len].*,
    );
    try std.testing.expectEqual(
        schedule.encryptBlock(input[block_len..][0..block_len].*),
        output[block_len..][0..block_len].*,
    );

    const wide_input = input ++ input;
    var wide_output: [4 * block_len]u8 = undefined;
    schedule.encryptWide4(&wide_output, &wide_input);
    inline for (0..4) |index| {
        const offset = index * block_len;
        try std.testing.expectEqual(
            schedule.encryptBlock(wide_input[offset..][0..block_len].*),
            wide_output[offset..][0..block_len].*,
        );
    }

    const widest_input = wide_input ++ wide_input;
    var widest_output: [8 * block_len]u8 = undefined;
    schedule.encryptWide8(&widest_output, &widest_input);
    inline for (0..8) |index| {
        const offset = index * block_len;
        try std.testing.expectEqual(
            schedule.encryptBlock(widest_input[offset..][0..block_len].*),
            widest_output[offset..][0..block_len].*,
        );
    }
}

test "SM4-GCM matches OpenSSL 3.6 SM4-GCM vector" {
    const key = [_]u8{0} ** key_len;
    const nonce = [_]u8{0} ** Gcm.nonce_length;
    const aad = "header";
    const plaintext = "Vail SM4-GCM";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Gcm.tag_length]u8 = undefined;
    Gcm.encrypt(&ciphertext, &tag, plaintext, aad, nonce, key);

    const expected_ciphertext = decodeHex("2b83c313314355b6354178ac");
    const expected_tag = decodeHex("1919a4243341eb9ffca177709f1287bd");
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    var opened: [plaintext.len]u8 = undefined;
    try Gcm.decrypt(&opened, &ciphertext, tag, aad, nonce, key);
    try std.testing.expectEqualStrings(plaintext, &opened);

    var bad_tag = tag;
    bad_tag[0] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        Gcm.decrypt(&opened, &ciphertext, bad_tag, aad, nonce, key),
    );
}

test "SM4-CCM matches RFC 8998 appendix A.2" {
    const key = decodeHex("0123456789abcdeffedcba9876543210");
    const nonce = decodeHex("00001234567800000000abcd");
    const plaintext = decodeHex(
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb" ++
            "ccccccccccccccccdddddddddddddddd" ++
            "eeeeeeeeeeeeeeeeffffffffffffffff" ++
            "eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
    );
    const associated_data = decodeHex(
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    );
    const expected_ciphertext = decodeHex(
        "48af93501fa62adbcd414cce6034d895" ++
            "dda1bf8f132f042098661572e7483094" ++
            "fd12e518ce062c98acee28d95df4416b" ++
            "ed31a2f04476c18bb40c84a74b97dc5b",
    );
    const expected_tag = decodeHex("16842d4fa186f56ab33256971fa110f4");

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Ccm.tag_length]u8 = undefined;
    Ccm.encryptOneShot(
        &ciphertext,
        &tag,
        &plaintext,
        &associated_data,
        nonce,
        key,
    );
    try std.testing.expectEqual(expected_ciphertext, ciphertext);
    try std.testing.expectEqual(expected_tag, tag);

    var opened: [plaintext.len]u8 = undefined;
    try Ccm.decryptOneShot(
        &opened,
        &ciphertext,
        tag,
        &associated_data,
        nonce,
        key,
    );
    try std.testing.expectEqual(plaintext, opened);
    var in_place = ciphertext;
    try Ccm.decryptOneShot(
        &in_place,
        &in_place,
        tag,
        &associated_data,
        nonce,
        key,
    );
    try std.testing.expectEqual(plaintext, in_place);

    var bad_tag = tag;
    bad_tag[0] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        Ccm.decryptOneShot(
            &opened,
            &ciphertext,
            bad_tag,
            &associated_data,
            nonce,
            key,
        ),
    );
    try std.testing.expectEqual([_]u8{0} ** plaintext.len, opened);
}
