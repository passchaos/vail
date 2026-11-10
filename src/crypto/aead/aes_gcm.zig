//! Pure-Zig AES-GCM contexts with reusable AES and GHASH key material.
//!
//! Zig's standard one-shot AES-GCM API expands the AES key and derives the
//! GHASH multiplication table for every call. Protocols such as QUIC reuse a
//! traffic key for many records, so this context prepares that key-dependent
//! state once while retaining the standard library's constant-time primitives.

const std = @import("std");
const aes_ctr = @import("../block/aes_ctr.zig");
const ghash_accelerated = @import("ghash.zig");

const Ghash = std.crypto.onetimeauth.Ghash;

pub const Aes128Gcm = AesGcm(std.crypto.core.aes.Aes128);
pub const Aes256Gcm = AesGcm(std.crypto.core.aes.Aes256);

/// Runtime-selected reusable context for protocol code negotiating AES suites.
pub const Context = union(enum) {
    aes_128: Aes128Gcm,
    aes_256: Aes256Gcm,

    pub fn init128(key: [Aes128Gcm.key_length]u8) Context {
        return .{ .aes_128 = Aes128Gcm.init(key) };
    }

    pub fn init256(key: [Aes256Gcm.key_length]u8) Context {
        return .{ .aes_256 = Aes256Gcm.init(key) };
    }

    pub fn deinit(self: *Context) void {
        switch (self.*) {
            .aes_128 => |*context| context.deinit(),
            .aes_256 => |*context| context.deinit(),
        }
    }

    pub fn encrypt(
        self: *const Context,
        ciphertext: []u8,
        tag: *[16]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [12]u8,
    ) void {
        switch (self.*) {
            .aes_128 => |*context| context.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
            ),
            .aes_256 => |*context| context.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
            ),
        }
    }

    pub fn decrypt(
        self: *const Context,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [16]u8,
        associated_data: []const u8,
        nonce: [12]u8,
    ) std.crypto.errors.AuthenticationError!void {
        switch (self.*) {
            .aes_128 => |*context| try context.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
            ),
            .aes_256 => |*context| try context.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
            ),
        }
    }
};

fn AesGcm(comptime Aes: type) type {
    comptime std.debug.assert(Aes.block.block_length == 16);

    return struct {
        const Self = @This();
        const AesContext = std.crypto.core.aes.AesEncryptCtx(Aes);

        pub const key_length = Aes.key_bits / 8;
        pub const nonce_length = 12;
        pub const tag_length = 16;

        aes: AesContext,
        ghash: Ghash,

        pub fn init(key: [key_length]u8) Self {
            const aes = Aes.initEnc(key);
            var hash_key: [Ghash.key_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &hash_key);
            aes.encrypt(&hash_key, &([_]u8{0} ** Aes.block.block_length));
            return .{
                .aes = aes,
                .ghash = Ghash.init(&hash_key),
            };
        }

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(Self, self[0..1]);
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
            std.debug.assert(plaintext.len <= 16 * ((1 << 32) - 2));

            var counter: [Aes.block.block_length]u8 = undefined;
            counter[0..nonce_length].* = nonce;
            std.mem.writeInt(u32, counter[nonce_length..][0..4], 1, .big);

            var tag_mask: [tag_length]u8 = undefined;
            aes_ctr.xorWithTagMask(
                Aes,
                self.aes,
                &tag_mask,
                ciphertext,
                plaintext,
                counter,
            );
            ghash_accelerated.create(
                &self.ghash,
                tag,
                associated_data,
                ciphertext,
            );
            xorTag(tag, tag_mask);
        }

        /// The plaintext buffer is undefined when authentication fails.
        pub fn decrypt(
            self: *const Self,
            plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_length]u8,
            associated_data: []const u8,
            nonce: [nonce_length]u8,
        ) std.crypto.errors.AuthenticationError!void {
            std.debug.assert(plaintext.len == ciphertext.len);
            std.debug.assert(ciphertext.len <= 16 * ((1 << 32) - 2));

            var counter: [Aes.block.block_length]u8 = undefined;
            counter[0..nonce_length].* = nonce;
            std.mem.writeInt(u32, counter[nonce_length..][0..4], 1, .big);

            var tag_mask: [tag_length]u8 = undefined;
            self.aes.encrypt(&tag_mask, &counter);

            var computed_tag: [tag_length]u8 = undefined;
            ghash_accelerated.create(
                &self.ghash,
                &computed_tag,
                associated_data,
                ciphertext,
            );
            xorTag(&computed_tag, tag_mask);
            if (!std.crypto.timing_safe.eql(
                [tag_length]u8,
                computed_tag,
                tag,
            )) {
                std.crypto.secureZero(u8, &computed_tag);
                @memset(plaintext, undefined);
                return error.AuthenticationFailed;
            }

            std.mem.writeInt(u32, counter[nonce_length..][0..4], 2, .big);
            aes_ctr.xor(
                Aes,
                self.aes,
                plaintext,
                ciphertext,
                counter,
            );
        }

        fn xorTag(
            tag: *[tag_length]u8,
            tag_mask: [tag_length]u8,
        ) void {
            for (tag_mask, 0..) |byte, index| tag[index] ^= byte;
        }
    };
}

test "prepared AES-128-GCM matches a NIST vector" {
    var context = Aes128Gcm.init([_]u8{0} ** Aes128Gcm.key_length);
    defer context.deinit();

    const plaintext = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** Aes128Gcm.nonce_length;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    context.encrypt(&ciphertext, &tag, &plaintext, "", nonce);

    var expected_ciphertext: [ciphertext.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_ciphertext,
        "0388dace60b6a392f328c2b971b2fe78",
    );
    var expected_tag: [tag.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_tag,
        "ab6e47d42cec13bdf53a67b21257bddf",
    );
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    var opened: [plaintext.len]u8 = undefined;
    try context.decrypt(&opened, &ciphertext, tag, "", nonce);
    try std.testing.expectEqualSlices(u8, &plaintext, &opened);
}

test "prepared AES-GCM matches NIST multi-block vectors with associated data" {
    const plaintext = try hexBytes(
        "d9313225f88406e5a55909c5aff5269a" ++
            "86a7a9531534f7da2e4c303d8a318a72" ++
            "1c3c0c95956809532fcf0e2449a6b525" ++
            "b16aedf5aa0de657ba637b39",
    );
    const associated_data = try hexBytes(
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    );
    const nonce = try hexBytes("cafebabefacedbaddecaf888");
    const ciphertext_128 = try hexBytes(
        "42831ec2217774244b7221b784d0d49c" ++
            "e3aa212f2c02a4e035c17e2329aca12e" ++
            "21d514b25466931c7d8f6a5aac84aa05" ++
            "1ba30b396a0aac973d58e091",
    );
    const ciphertext_256 = try hexBytes(
        "522dc1f099567d07f47f37a32a84427d" ++
            "643a8cdcbfe5c0c97598a2bd2555d1aa" ++
            "8cb08e48590dbb3da7b08b1056828838" ++
            "c5f61e6393ba7a0abcc9f662",
    );

    try testNistVector(
        Aes128Gcm,
        try hexBytes("feffe9928665731c6d6a8f9467308308"),
        nonce,
        &associated_data,
        &plaintext,
        &ciphertext_128,
        try hexBytes("5bc94fbc3221a5db94fae95ae7121a47"),
    );
    try testNistVector(
        Aes256Gcm,
        try hexBytes(
            "feffe9928665731c6d6a8f9467308308" ++
                "feffe9928665731c6d6a8f9467308308",
        ),
        nonce,
        &associated_data,
        &plaintext,
        &ciphertext_256,
        try hexBytes("76fc6ece0f4e1768cddf8853bb2d551b"),
    );
}

test "prepared AES-GCM matches Zig one-shot APIs at block boundaries" {
    inline for ([_]usize{
        0,   1,    15,  16,  17,  31,  32,  33,
        127, 128,  129, 255, 256, 257, 511, 512,
        513, 1200,
    }) |len| {
        try testMatchesOneShot(Aes128Gcm, std.crypto.aead.aes_gcm.Aes128Gcm, len);
        try testMatchesOneShot(Aes256Gcm, std.crypto.aead.aes_gcm.Aes256Gcm, len);
    }
}

test "prepared AES-GCM matches Zig one-shot APIs at AAD boundaries" {
    inline for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 257 }) |len| {
        try testAadMatchesOneShot(
            Aes128Gcm,
            std.crypto.aead.aes_gcm.Aes128Gcm,
            len,
        );
        try testAadMatchesOneShot(
            Aes256Gcm,
            std.crypto.aead.aes_gcm.Aes256Gcm,
            len,
        );
    }
}

test "prepared AES-GCM rejects a modified tag" {
    var context = Aes256Gcm.init([_]u8{0x42} ** Aes256Gcm.key_length);
    defer context.deinit();

    const plaintext = "authenticated plaintext";
    const nonce = [_]u8{0x24} ** Aes256Gcm.nonce_length;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    context.encrypt(&ciphertext, &tag, plaintext, "associated data", nonce);
    tag[0] ^= 1;

    var opened: [plaintext.len]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        context.decrypt(
            &opened,
            &ciphertext,
            tag,
            "associated data",
            nonce,
        ),
    );
}

test "prepared AES-GCM matches one-shot APIs across a deterministic corpus" {
    try testDifferentialCorpus(
        Aes128Gcm,
        std.crypto.aead.aes_gcm.Aes128Gcm,
    );
    try testDifferentialCorpus(
        Aes256Gcm,
        std.crypto.aead.aes_gcm.Aes256Gcm,
    );
}

test "prepared AES-GCM supports in-place encryption and decryption" {
    try testInPlace(Aes128Gcm, std.crypto.aead.aes_gcm.Aes128Gcm);
    try testInPlace(Aes256Gcm, std.crypto.aead.aes_gcm.Aes256Gcm);
}

fn testMatchesOneShot(
    comptime Prepared: type,
    comptime OneShot: type,
    comptime plaintext_len: usize,
) !void {
    const key = [_]u8{0x42} ** Prepared.key_length;
    const nonce = [_]u8{0x24} ** Prepared.nonce_length;
    const associated_data = "non-block-sized associated data";
    var plaintext: [plaintext_len]u8 = undefined;
    for (&plaintext, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);

    var context = Prepared.init(key);
    defer context.deinit();
    var actual_ciphertext: [plaintext_len]u8 = undefined;
    var actual_tag: [Prepared.tag_length]u8 = undefined;
    context.encrypt(
        &actual_ciphertext,
        &actual_tag,
        &plaintext,
        associated_data,
        nonce,
    );

    var expected_ciphertext: [plaintext_len]u8 = undefined;
    var expected_tag: [OneShot.tag_length]u8 = undefined;
    OneShot.encrypt(
        &expected_ciphertext,
        &expected_tag,
        &plaintext,
        associated_data,
        nonce,
        key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_ciphertext,
        &actual_ciphertext,
    );
    try std.testing.expectEqualSlices(u8, &expected_tag, &actual_tag);

    var opened: [plaintext_len]u8 = undefined;
    try context.decrypt(
        &opened,
        &actual_ciphertext,
        actual_tag,
        associated_data,
        nonce,
    );
    try std.testing.expectEqualSlices(u8, &plaintext, &opened);
}

fn testAadMatchesOneShot(
    comptime Prepared: type,
    comptime OneShot: type,
    comptime associated_data_len: usize,
) !void {
    const key = [_]u8{0x37} ** Prepared.key_length;
    const nonce = [_]u8{0x91} ** Prepared.nonce_length;
    const plaintext = [_]u8{0xa5} ** 257;
    var associated_data: [associated_data_len]u8 = undefined;
    for (&associated_data, 0..) |*byte, index| {
        byte.* = @truncate(index *% 197 +% 29);
    }

    var context = Prepared.init(key);
    defer context.deinit();
    var actual_ciphertext: [plaintext.len]u8 = undefined;
    var actual_tag: [Prepared.tag_length]u8 = undefined;
    context.encrypt(
        &actual_ciphertext,
        &actual_tag,
        &plaintext,
        &associated_data,
        nonce,
    );

    var expected_ciphertext: [plaintext.len]u8 = undefined;
    var expected_tag: [OneShot.tag_length]u8 = undefined;
    OneShot.encrypt(
        &expected_ciphertext,
        &expected_tag,
        &plaintext,
        &associated_data,
        nonce,
        key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_ciphertext,
        &actual_ciphertext,
    );
    try std.testing.expectEqualSlices(u8, &expected_tag, &actual_tag);
}

fn testDifferentialCorpus(
    comptime Prepared: type,
    comptime OneShot: type,
) !void {
    const key = [_]u8{0x6d} ** Prepared.key_length;
    const nonce = [_]u8{0xb7} ** Prepared.nonce_length;
    var plaintext: [521]u8 = undefined;
    var associated_data: [79]u8 = undefined;
    for (&plaintext, 0..) |*byte, index| {
        byte.* = @truncate(index *% 149 +% 11);
    }
    for (&associated_data, 0..) |*byte, index| {
        byte.* = @truncate(index *% 211 +% 37);
    }

    var context = Prepared.init(key);
    defer context.deinit();
    var actual_ciphertext: [plaintext.len]u8 = undefined;
    var expected_ciphertext: [plaintext.len]u8 = undefined;
    var opened: [plaintext.len]u8 = undefined;
    for (0..plaintext.len + 1) |plaintext_len| {
        const associated_data_len = (plaintext_len * 37 + 13) %
            (associated_data.len + 1);
        var actual_tag: [Prepared.tag_length]u8 = undefined;
        var expected_tag: [OneShot.tag_length]u8 = undefined;
        context.encrypt(
            actual_ciphertext[0..plaintext_len],
            &actual_tag,
            plaintext[0..plaintext_len],
            associated_data[0..associated_data_len],
            nonce,
        );
        OneShot.encrypt(
            expected_ciphertext[0..plaintext_len],
            &expected_tag,
            plaintext[0..plaintext_len],
            associated_data[0..associated_data_len],
            nonce,
            key,
        );
        try std.testing.expectEqualSlices(
            u8,
            expected_ciphertext[0..plaintext_len],
            actual_ciphertext[0..plaintext_len],
        );
        try std.testing.expectEqualSlices(u8, &expected_tag, &actual_tag);
        try context.decrypt(
            opened[0..plaintext_len],
            actual_ciphertext[0..plaintext_len],
            actual_tag,
            associated_data[0..associated_data_len],
            nonce,
        );
        try std.testing.expectEqualSlices(
            u8,
            plaintext[0..plaintext_len],
            opened[0..plaintext_len],
        );
    }
}

fn testInPlace(
    comptime Prepared: type,
    comptime OneShot: type,
) !void {
    const key = [_]u8{0x83} ** Prepared.key_length;
    const nonce = [_]u8{0x2c} ** Prepared.nonce_length;
    const associated_data = "in-place associated data";
    var buffer: [1200]u8 = undefined;
    for (&buffer, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% 19);
    const plaintext = buffer;
    var expected_ciphertext: [buffer.len]u8 = undefined;
    var expected_tag: [OneShot.tag_length]u8 = undefined;
    OneShot.encrypt(
        &expected_ciphertext,
        &expected_tag,
        &plaintext,
        associated_data,
        nonce,
        key,
    );

    var context = Prepared.init(key);
    defer context.deinit();
    var tag: [Prepared.tag_length]u8 = undefined;
    context.encrypt(&buffer, &tag, &buffer, associated_data, nonce);
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &buffer);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);
    try context.decrypt(&buffer, &buffer, tag, associated_data, nonce);
    try std.testing.expectEqualSlices(u8, &plaintext, &buffer);
}

fn testNistVector(
    comptime Prepared: type,
    key: [Prepared.key_length]u8,
    nonce: [Prepared.nonce_length]u8,
    associated_data: []const u8,
    plaintext: []const u8,
    expected_ciphertext: []const u8,
    expected_tag: [Prepared.tag_length]u8,
) !void {
    try std.testing.expectEqual(plaintext.len, expected_ciphertext.len);
    var context = Prepared.init(key);
    defer context.deinit();

    const ciphertext = try std.testing.allocator.alloc(u8, plaintext.len);
    defer std.testing.allocator.free(ciphertext);
    var tag: [Prepared.tag_length]u8 = undefined;
    context.encrypt(
        ciphertext,
        &tag,
        plaintext,
        associated_data,
        nonce,
    );
    try std.testing.expectEqualSlices(u8, expected_ciphertext, ciphertext);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    const opened = try std.testing.allocator.alloc(u8, plaintext.len);
    defer std.testing.allocator.free(opened);
    try context.decrypt(
        opened,
        ciphertext,
        tag,
        associated_data,
        nonce,
    );
    try std.testing.expectEqualSlices(u8, plaintext, opened);
}

fn hexBytes(comptime hex: []const u8) ![hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex);
    return bytes;
}
