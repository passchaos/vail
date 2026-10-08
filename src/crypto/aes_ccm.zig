//! Pure-Zig AES-CCM for the 12-byte nonce used by TLS 1.3.
//!
//! Zig's standard library provides the AES and counter-mode building blocks.
//! Its public CCM aliases currently use 13-byte nonces, so TLS needs this
//! narrowly parameterized wrapper for the three-byte CCM length field.

const std = @import("std");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Enc = std.crypto.core.aes.AesEncryptCtx(Aes128);

const Aes128Cipher = struct {
    pub const key_length = Aes128.key_bits / 8;

    context: Aes128Enc,

    fn init(key: [key_length]u8) Aes128Cipher {
        return .{ .context = Aes128.initEnc(key) };
    }

    inline fn encryptBlock(
        self: *const Aes128Cipher,
        output: *[16]u8,
        input: *const [16]u8,
    ) void {
        self.context.encrypt(output, input);
    }

    inline fn encryptPair(
        self: *const Aes128Cipher,
        output: *[32]u8,
        input: *const [32]u8,
    ) void {
        self.context.encryptWide(2, output, input);
    }
};

pub const Aes128Ccm = Ccm(Aes128Cipher, 16);
pub const Aes128Ccm8 = Ccm(Aes128Cipher, 8);

/// Build a 12-byte-nonce CCM AEAD from a 128-bit block cipher. `BlockCipher`
/// supplies `init`, single-block encryption, and a two-block encryption path;
/// the latter lets implementations schedule CBC-MAC and CTR independently.
pub fn Ccm(comptime BlockCipher: type, comptime tag_length_value: usize) type {
    const nonce_length_value = 12;
    const length_length = 15 - nonce_length_value;

    comptime {
        std.debug.assert(tag_length_value == 8 or tag_length_value == 16);
        std.debug.assert(length_length == 3);
    }

    return struct {
        const Self = @This();

        pub const key_length = BlockCipher.key_length;
        pub const nonce_length = nonce_length_value;
        pub const tag_length = tag_length_value;

        cipher: BlockCipher,

        pub fn init(key: [key_length]u8) Self {
            return .{ .cipher = BlockCipher.init(key) };
        }

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
            self.* = undefined;
        }

        pub fn encrypt(
            self: *const Self,
            ciphertext: []u8,
            tag: *[tag_length]u8,
            plaintext: []const u8,
            associated_data: []const u8,
            nonce: [nonce_length]u8,
        ) void {
            std.debug.assert(ciphertext.len == plaintext.len);
            std.debug.assert(plaintext.len < (@as(usize, 1) << 24));

            var initial = self.initialAuth(
                plaintext.len,
                associated_data,
                nonce,
            );
            defer std.crypto.secureZero(u8, std.mem.asBytes(&initial));
            var counter = initial.counter;
            var offset: usize = 0;
            while (offset < plaintext.len) : (offset += 16) {
                const len = @min(@as(usize, 16), plaintext.len - offset);
                var input_blocks = [_]u8{0} ** 32;
                @memcpy(input_blocks[0..16], &initial.mac);
                for (input_blocks[0..len], plaintext[offset..][0..len]) |
                    *mac_byte,
                    plaintext_byte,
                | mac_byte.* ^= plaintext_byte;
                @memcpy(input_blocks[16..32], &counter);
                var encrypted: [32]u8 = undefined;
                self.cipher.encryptPair(&encrypted, &input_blocks);
                initial.mac = encrypted[0..16].*;
                xorBlock(
                    ciphertext[offset..][0..len],
                    plaintext[offset..][0..len],
                    encrypted[16..32],
                );
                incrementCounter(&counter);
                std.crypto.secureZero(u8, &input_blocks);
                std.crypto.secureZero(u8, &encrypted);
            }
            writeTag(tag, initial.mac, initial.tag_mask);
        }

        pub fn decrypt(
            self: *const Self,
            plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_length]u8,
            associated_data: []const u8,
            nonce: [nonce_length]u8,
        ) std.crypto.errors.AuthenticationError!void {
            std.debug.assert(plaintext.len == ciphertext.len);
            std.debug.assert(ciphertext.len < (@as(usize, 1) << 24));

            var initial = self.initialAuth(
                ciphertext.len,
                associated_data,
                nonce,
            );
            defer std.crypto.secureZero(u8, std.mem.asBytes(&initial));
            if (ciphertext.len != 0) {
                var counter = initial.counter;
                var stream: [16]u8 = undefined;
                self.cipher.encryptBlock(&stream, &counter);
                incrementCounter(&counter);
                var previous = [_]u8{0} ** 16;
                const first_len = @min(@as(usize, 16), ciphertext.len);
                decryptBlock(
                    plaintext[0..first_len],
                    ciphertext[0..first_len],
                    &stream,
                    &previous,
                );
                var offset: usize = first_len;
                while (offset < ciphertext.len) : (offset += 16) {
                    var input_blocks: [32]u8 = undefined;
                    const mac_input: @Vector(16, u8) =
                        @as(@Vector(16, u8), @bitCast(initial.mac)) ^
                        @as(@Vector(16, u8), @bitCast(previous));
                    input_blocks[0..16].* = @bitCast(mac_input);
                    input_blocks[16..32].* = counter;
                    var encrypted: [32]u8 = undefined;
                    self.cipher.encryptPair(&encrypted, &input_blocks);
                    initial.mac = encrypted[0..16].*;
                    const len = @min(
                        @as(usize, 16),
                        ciphertext.len - offset,
                    );
                    @memset(&previous, 0);
                    decryptBlock(
                        plaintext[offset..][0..len],
                        ciphertext[offset..][0..len],
                        encrypted[16..32],
                        &previous,
                    );
                    incrementCounter(&counter);
                    std.crypto.secureZero(u8, &input_blocks);
                    std.crypto.secureZero(u8, &encrypted);
                }
                const final_input: [16]u8 = @bitCast(
                    @as(@Vector(16, u8), @bitCast(initial.mac)) ^
                        @as(@Vector(16, u8), @bitCast(previous)),
                );
                self.cipher.encryptBlock(&initial.mac, &final_input);
                std.crypto.secureZero(u8, &stream);
                std.crypto.secureZero(u8, &previous);
            }

            var expected: [tag_length]u8 = undefined;
            writeTag(&expected, initial.mac, initial.tag_mask);

            const valid = std.crypto.timing_safe.eql(
                [tag_length]u8,
                expected,
                tag,
            );
            std.crypto.secureZero(u8, &expected);
            if (!valid) {
                std.crypto.secureZero(u8, plaintext);
                return error.AuthenticationFailed;
            }
        }

        const InitialAuth = struct {
            mac: [16]u8,
            tag_mask: [16]u8,
            counter: [16]u8,
        };

        fn initialAuth(
            self: *const Self,
            plaintext_len: usize,
            associated_data: []const u8,
            nonce: [nonce_length]u8,
        ) InitialAuth {
            var b0: [16]u8 = undefined;
            formatB0(&b0, plaintext_len, associated_data.len, nonce);
            var counter0: [16]u8 = undefined;
            formatCounter(&counter0, nonce, 0);
            var initial_blocks = b0 ++ counter0;
            var encrypted: [32]u8 = undefined;
            self.cipher.encryptPair(&encrypted, &initial_blocks);
            defer std.crypto.secureZero(u8, &initial_blocks);
            var result = InitialAuth{
                .mac = encrypted[0..16].*,
                .tag_mask = encrypted[16..32].*,
                .counter = undefined,
            };
            defer std.crypto.secureZero(u8, &encrypted);

            if (associated_data.len != 0) {
                var mac = Mac.initWithState(&self.cipher, result.mac);
                defer mac.deinit();
                var encoded_len: [10]u8 = undefined;
                const encoded_len_size = encodeAssociatedDataLength(
                    &encoded_len,
                    associated_data.len,
                );
                mac.update(encoded_len[0..encoded_len_size]);
                mac.update(associated_data);
                const used = encoded_len_size + associated_data.len;
                const remainder = used % 16;
                if (remainder != 0) {
                    const zeroes = [_]u8{0} ** 16;
                    mac.update(zeroes[0 .. 16 - remainder]);
                }
                mac.final(&result.mac);
            }
            formatCounter(&result.counter, nonce, 1);
            return result;
        }

        pub fn encryptOneShot(
            ciphertext: []u8,
            tag: *[tag_length]u8,
            plaintext: []const u8,
            associated_data: []const u8,
            nonce: [nonce_length]u8,
            key: [key_length]u8,
        ) void {
            var context = Self.init(key);
            defer context.deinit();
            context.encrypt(ciphertext, tag, plaintext, associated_data, nonce);
        }

        pub fn decryptOneShot(
            plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_length]u8,
            associated_data: []const u8,
            nonce: [nonce_length]u8,
            key: [key_length]u8,
        ) std.crypto.errors.AuthenticationError!void {
            var context = Self.init(key);
            defer context.deinit();
            return context.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
            );
        }

        fn formatB0(
            block: *[16]u8,
            plaintext_len: usize,
            associated_data_len: usize,
            nonce: [nonce_length]u8,
        ) void {
            @memset(block, 0);
            block[0] = @as(u8, @intFromBool(associated_data_len != 0)) << 6 |
                @as(u8, (tag_length - 2) / 2) << 3 |
                (length_length - 1);
            @memcpy(block[1..][0..nonce_length], &nonce);
            writeLength(block[1 + nonce_length ..][0..length_length], plaintext_len);
        }

        fn formatCounter(
            block: *[16]u8,
            nonce: [nonce_length]u8,
            counter: usize,
        ) void {
            @memset(block, 0);
            block[0] = length_length - 1;
            @memcpy(block[1..][0..nonce_length], &nonce);
            writeLength(block[1 + nonce_length ..][0..length_length], counter);
        }

        fn writeLength(output: *[length_length]u8, value: usize) void {
            std.debug.assert(value < (@as(usize, 1) << 24));
            output.* = .{
                @truncate(value >> 16),
                @truncate(value >> 8),
                @truncate(value),
            };
        }

        fn encodeAssociatedDataLength(output: *[10]u8, len: usize) usize {
            if (len < 0xff00) {
                std.mem.writeInt(u16, output[0..2], @intCast(len), .big);
                return 2;
            }
            if (len <= std.math.maxInt(u32)) {
                output[0..2].* = .{ 0xff, 0xfe };
                std.mem.writeInt(u32, output[2..6], @intCast(len), .big);
                return 6;
            }
            output[0..2].* = .{ 0xff, 0xff };
            std.mem.writeInt(u64, output[2..10], @intCast(len), .big);
            return 10;
        }

        inline fn incrementCounter(counter: *[16]u8) void {
            const value = std.mem.readInt(
                u24,
                counter[1 + nonce_length ..][0..length_length],
                .big,
            );
            std.mem.writeInt(
                u24,
                counter[1 + nonce_length ..][0..length_length],
                value +% 1,
                .big,
            );
        }

        inline fn writeTag(
            tag: *[tag_length]u8,
            mac: [16]u8,
            tag_mask: [16]u8,
        ) void {
            for (tag, mac[0..tag_length], tag_mask[0..tag_length]) |
                *output,
                mac_byte,
                mask_byte,
            | output.* = mac_byte ^ mask_byte;
        }

        inline fn xorBlock(
            output: []u8,
            input: []const u8,
            stream: *const [16]u8,
        ) void {
            if (input.len == 16) {
                const Bytes = @Vector(16, u8);
                output[0..16].* = @bitCast(
                    @as(Bytes, @bitCast(input[0..16].*)) ^
                        @as(Bytes, @bitCast(stream.*)),
                );
                return;
            }
            for (output, input, stream[0..input.len]) |
                *output_byte,
                input_byte,
                stream_byte,
            | output_byte.* = input_byte ^ stream_byte;
        }

        inline fn decryptBlock(
            output: []u8,
            input: []const u8,
            stream: *const [16]u8,
            padded: *[16]u8,
        ) void {
            if (input.len == 16) {
                const Bytes = @Vector(16, u8);
                const value: [16]u8 = @bitCast(
                    @as(Bytes, @bitCast(input[0..16].*)) ^
                        @as(Bytes, @bitCast(stream.*)),
                );
                output[0..16].* = value;
                padded.* = value;
                return;
            }
            for (output, input, stream[0..input.len], padded[0..input.len]) |
                *output_byte,
                input_byte,
                stream_byte,
                *padded_byte,
            | {
                const value = input_byte ^ stream_byte;
                output_byte.* = value;
                padded_byte.* = value;
            }
        }

        const Mac = struct {
            cipher: *const BlockCipher,
            block: [16]u8 = @splat(0),
            used: usize = 0,

            fn initWithState(
                cipher: *const BlockCipher,
                state: [16]u8,
            ) Mac {
                return .{ .cipher = cipher, .block = state };
            }

            fn deinit(self: *Mac) void {
                std.crypto.secureZero(u8, &self.block);
                self.* = undefined;
            }

            fn update(self: *Mac, bytes: []const u8) void {
                var input = bytes;
                const available = 16 - self.used;
                if (input.len > available) {
                    for (self.block[self.used..], input[0..available]) |
                        *state_byte,
                        input_byte,
                    | state_byte.* ^= input_byte;
                    self.cipher.encryptBlock(&self.block, &self.block);
                    self.used = 0;
                    input = input[available..];
                }
                while (input.len > 16) {
                    for (&self.block, input[0..16]) |*state_byte, input_byte| {
                        state_byte.* ^= input_byte;
                    }
                    self.cipher.encryptBlock(&self.block, &self.block);
                    self.used = 0;
                    input = input[16..];
                }
                if (input.len != 0) {
                    for (self.block[self.used..][0..input.len], input) |
                        *state_byte,
                        input_byte,
                    | state_byte.* ^= input_byte;
                    self.used += input.len;
                }
            }

            fn final(self: *Mac, output: *[16]u8) void {
                self.cipher.encryptBlock(output, &self.block);
            }
        };
    };
}

pub fn encrypt(
    ciphertext: []u8,
    tag: *[Aes128Ccm.tag_length]u8,
    plaintext: []const u8,
    associated_data: []const u8,
    nonce: [Aes128Ccm.nonce_length]u8,
    key: [Aes128Ccm.key_length]u8,
) void {
    Aes128Ccm.encryptOneShot(
        ciphertext,
        tag,
        plaintext,
        associated_data,
        nonce,
        key,
    );
}

pub fn decrypt(
    plaintext: []u8,
    ciphertext: []const u8,
    tag: [Aes128Ccm.tag_length]u8,
    associated_data: []const u8,
    nonce: [Aes128Ccm.nonce_length]u8,
    key: [Aes128Ccm.key_length]u8,
) std.crypto.errors.AuthenticationError!void {
    return Aes128Ccm.decryptOneShot(
        plaintext,
        ciphertext,
        tag,
        associated_data,
        nonce,
        key,
    );
}

test "AES-128-CCM-8 with a 12-byte nonce matches NIST SP 800-38C" {
    const key = try hexBytes("404142434445464748494a4b4c4d4e4f");
    const nonce = try hexBytes("101112131415161718191a1b");
    const associated_data = try hexBytes(
        "000102030405060708090a0b0c0d0e0f10111213",
    );
    const plaintext = try hexBytes(
        "202122232425262728292a2b2c2d2e2f3031323334353637",
    );
    const expected_ciphertext = try hexBytes(
        "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
    );
    const expected_tag = try hexBytes("484392fbc1b09951");
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aes128Ccm8.tag_length]u8 = undefined;
    var context = Aes128Ccm8.init(key);
    defer context.deinit();
    context.encrypt(
        &ciphertext,
        &tag,
        &plaintext,
        &associated_data,
        nonce,
    );
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try std.testing.expectEqual(expected_tag, tag);
}

test "AES-128-CCM with a 12-byte nonce matches an independent oracle" {
    const key = try hexBytes("404142434445464748494a4b4c4d4e4f");
    const nonce = try hexBytes("101112131415161718191a1b");
    const associated_data = try hexBytes(
        "000102030405060708090a0b0c0d0e0f10111213",
    );
    const plaintext = try hexBytes(
        "202122232425262728292a2b2c2d2e2f3031323334353637",
    );
    const expected_ciphertext = try hexBytes(
        "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
    );
    const expected_tag = try hexBytes("c87ae488918de93f17dd3e4934347f44");

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aes128Ccm.tag_length]u8 = undefined;
    var context = Aes128Ccm.init(key);
    defer context.deinit();
    context.encrypt(
        &ciphertext,
        &tag,
        &plaintext,
        &associated_data,
        nonce,
    );
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try std.testing.expectEqual(expected_tag, tag);

    var opened: [plaintext.len]u8 = undefined;
    try context.decrypt(
        &opened,
        &ciphertext,
        tag,
        &associated_data,
        nonce,
    );
    try std.testing.expectEqualSlices(u8, &plaintext, &opened);
    var in_place = ciphertext;
    try context.decrypt(
        &in_place,
        &in_place,
        tag,
        &associated_data,
        nonce,
    );
    try std.testing.expectEqualSlices(u8, &plaintext, &in_place);
    tag[0] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        context.decrypt(
            &opened,
            &ciphertext,
            tag,
            &associated_data,
            nonce,
        ),
    );
    try std.testing.expectEqual([_]u8{0} ** opened.len, opened);
}

test "AES-CCM associated-data length encodings cover every boundary" {
    var encoded: [10]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 2),
        Aes128Ccm.encodeAssociatedDataLength(&encoded, 0xfeff),
    );
    try std.testing.expectEqualSlices(u8, &.{ 0xfe, 0xff }, encoded[0..2]);
    try std.testing.expectEqual(
        @as(usize, 6),
        Aes128Ccm.encodeAssociatedDataLength(&encoded, 0xff00),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0xfe, 0x00, 0x00, 0xff, 0x00 },
        encoded[0..6],
    );
    if (@sizeOf(usize) >= 8) {
        try std.testing.expectEqual(
            @as(usize, 10),
            Aes128Ccm.encodeAssociatedDataLength(
                &encoded,
                @as(usize, std.math.maxInt(u32)) + 1,
            ),
        );
        try std.testing.expectEqualSlices(
            u8,
            &.{ 0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 0 },
            &encoded,
        );
    }
}

test "fused AES-CCM matches independent std building blocks across boundaries" {
    const key = [_]u8{0xa5} ** Aes128Ccm.key_length;
    const nonce = [_]u8{0x5a} ** Aes128Ccm.nonce_length;
    var plaintext: [1200]u8 = undefined;
    var associated_data: [65]u8 = undefined;
    for (&plaintext, 0..) |*byte, index| byte.* = @truncate(index *% 37 +% 3);
    for (&associated_data, 0..) |*byte, index| byte.* = @truncate(index *% 53 +% 7);

    inline for (.{ Aes128Ccm, Aes128Ccm8 }) |Aead| {
        var context = Aead.init(key);
        defer context.deinit();
        inline for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1200 }) |len| {
            inline for ([_]usize{ 0, 1, 14, 15, 16, 17, 63, 64, 65 }) |aad_len| {
                var expected_ciphertext: [plaintext.len]u8 = undefined;
                var expected_tag: [Aead.tag_length]u8 = undefined;
                referenceEncrypt(
                    Aead,
                    expected_ciphertext[0..len],
                    &expected_tag,
                    plaintext[0..len],
                    associated_data[0..aad_len],
                    nonce,
                    key,
                );

                var actual_ciphertext: [plaintext.len]u8 = undefined;
                var actual_tag: [Aead.tag_length]u8 = undefined;
                context.encrypt(
                    actual_ciphertext[0..len],
                    &actual_tag,
                    plaintext[0..len],
                    associated_data[0..aad_len],
                    nonce,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    expected_ciphertext[0..len],
                    actual_ciphertext[0..len],
                );
                try std.testing.expectEqual(expected_tag, actual_tag);

                var opened: [plaintext.len]u8 = undefined;
                try context.decrypt(
                    opened[0..len],
                    actual_ciphertext[0..len],
                    actual_tag,
                    associated_data[0..aad_len],
                    nonce,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    plaintext[0..len],
                    opened[0..len],
                );
            }
        }
    }
}

fn referenceEncrypt(
    comptime Aead: type,
    ciphertext: []u8,
    tag: *[Aead.tag_length]u8,
    plaintext: []const u8,
    associated_data: []const u8,
    nonce: [Aead.nonce_length]u8,
    key: [Aead.key_length]u8,
) void {
    const ReferenceMac = std.crypto.auth.cbc_mac.CbcMac(Aes128);
    const cipher = Aes128.initEnc(key);
    var mac = ReferenceMac.init(&key);
    var b0: [16]u8 = undefined;
    Aead.formatB0(&b0, plaintext.len, associated_data.len, nonce);
    mac.update(&b0);
    if (associated_data.len != 0) {
        var encoded_len: [10]u8 = undefined;
        const encoded_len_size = Aead.encodeAssociatedDataLength(
            &encoded_len,
            associated_data.len,
        );
        mac.update(encoded_len[0..encoded_len_size]);
        mac.update(associated_data);
        const used = encoded_len_size + associated_data.len;
        const remainder = used % 16;
        if (remainder != 0) {
            const zeroes = [_]u8{0} ** 16;
            mac.update(zeroes[0 .. 16 - remainder]);
        }
    }
    mac.update(plaintext);
    var mac_result: [16]u8 = undefined;
    mac.final(&mac_result);
    var counter: [16]u8 = undefined;
    Aead.formatCounter(&counter, nonce, 0);
    var tag_mask: [16]u8 = undefined;
    cipher.encrypt(&tag_mask, &counter);
    Aead.writeTag(tag, mac_result, tag_mask);
    Aead.formatCounter(&counter, nonce, 1);
    std.crypto.core.modes.ctrSlice(
        Aes128Enc,
        cipher,
        ciphertext,
        plaintext,
        counter,
        .big,
        1 + Aead.nonce_length,
        15 - Aead.nonce_length,
    );
}

fn hexBytes(comptime encoded: []const u8) ![encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
}
