//! 7-Zip password-based cryptographic primitives.
//!
//! The archive layer owns 7zAES coder properties, IV allocation, block
//! padding, packed-size accounting, and decoded-content verification. This
//! module owns the UTF-16LE/SHA-256 key derivation and AES-256-CBC transform.
//! 7zAES is unauthenticated, so callers must validate archive CRCs after
//! decryption.

const std = @import("std");

const Aes = std.crypto.core.aes;
const Aes256EncryptContext = Aes.AesEncryptCtx(Aes.Aes256);
const Aes256DecryptContext = Aes.AesDecryptCtx(Aes.Aes256);
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const block_len: usize = 16;
pub const key_len: usize = 32;
pub const max_salt_len: usize = 16;
pub const hard_max_cycles_power: u6 = 24;
pub const direct_key_power: u6 = 0x3f;

pub const Error = error{
    InvalidBlockLength,
    InvalidKdfCycles,
    InvalidPassword,
    KdfWorkLimitExceeded,
};

pub const DeriveOptions = struct {
    /// Bounds the binary logarithm of the SHA-256 iteration count. The hard
    /// implementation ceiling matches current 7-Zip decoder policy.
    max_cycles_power: u6 = hard_max_cycles_power,
};

/// Derives a 7zAES key from a UTF-8 password, optional salt, and the coder's
/// cycle-power field. The reserved direct-key value concatenates salt and the
/// UTF-16LE password into the fixed-size key instead of hashing.
pub fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    num_cycles_power: u6,
    options: DeriveOptions,
) (Error || std.mem.Allocator.Error)![key_len]u8 {
    if (salt.len > max_salt_len or
        (num_cycles_power > hard_max_cycles_power and num_cycles_power != direct_key_power))
        return error.InvalidKdfCycles;
    if (num_cycles_power != direct_key_power and
        num_cycles_power > options.max_cycles_power)
        return error.KdfWorkLimitExceeded;

    const utf16 = std.unicode.utf8ToUtf16LeAlloc(allocator, password) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUtf8 => return error.InvalidPassword,
    };
    defer {
        std.crypto.secureZero(u16, utf16);
        allocator.free(utf16);
    }
    const password_bytes = std.mem.sliceAsBytes(utf16);

    var key: [key_len]u8 = @splat(0);
    if (num_cycles_power == direct_key_power) {
        const salt_count = @min(salt.len, key.len);
        @memcpy(key[0..salt_count], salt[0..salt_count]);
        const password_count = @min(password_bytes.len, key.len - salt_count);
        @memcpy(key[salt_count..][0..password_count], password_bytes[0..password_count]);
        return key;
    }

    var hash = Sha256.init(.{});
    var counter_bytes: [8]u8 = undefined;
    defer std.crypto.secureZero(u8, &counter_bytes);
    const rounds = @as(u64, 1) << num_cycles_power;
    // Zig ranges use usize. Keep the 7z counter full-width on narrow targets;
    // the validated hashed power is at most 24, so the increment cannot wrap.
    var counter: u64 = 0;
    while (counter < rounds) : (counter += 1) {
        hash.update(salt);
        hash.update(password_bytes);
        std.mem.writeInt(u64, &counter_bytes, counter, .little);
        hash.update(&counter_bytes);
    }
    hash.final(&key);
    return key;
}

/// Resumable AES-256-CBC encryptor. Inputs must consist of complete blocks.
/// The same slice may be used for input and output; other overlap is unsupported.
pub const Encryptor = struct {
    cipher: Aes256EncryptContext,
    previous: [block_len]u8,

    const Self = @This();

    pub fn init(key: [key_len]u8, iv: [block_len]u8) Self {
        return .{ .cipher = Aes.Aes256.initEnc(key), .previous = iv };
    }

    pub fn encryptBlocks(self: *Self, input: []const u8, output: []u8) Error!void {
        if (input.len != output.len or input.len % block_len != 0)
            return error.InvalidBlockLength;
        var offset: usize = 0;
        while (offset < input.len) : (offset += block_len) {
            var block = input[offset..][0..block_len].*;
            defer std.crypto.secureZero(u8, &block);
            for (&block, self.previous) |*byte, previous| byte.* ^= previous;
            self.cipher.encrypt(output[offset..][0..block_len], &block);
            self.previous = output[offset..][0..block_len].*;
        }
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(Aes256EncryptContext, (&self.cipher)[0..1]);
        std.crypto.secureZero(u8, &self.previous);
        self.* = undefined;
    }
};

/// Resumable AES-256-CBC decryptor with the same overlap contract as
/// `Encryptor`.
pub const Decryptor = struct {
    cipher: Aes256DecryptContext,
    previous: [block_len]u8,

    const Self = @This();

    pub fn init(key: [key_len]u8, iv: [block_len]u8) Self {
        return .{ .cipher = Aes.Aes256.initDec(key), .previous = iv };
    }

    pub fn decryptBlocks(self: *Self, input: []const u8, output: []u8) Error!void {
        if (input.len != output.len or input.len % block_len != 0)
            return error.InvalidBlockLength;
        var offset: usize = 0;
        while (offset < input.len) : (offset += block_len) {
            const ciphertext = input[offset..][0..block_len].*;
            var block: [block_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &block);
            self.cipher.decrypt(&block, &ciphertext);
            for (&block, self.previous) |*byte, previous| byte.* ^= previous;
            output[offset..][0..block_len].* = block;
            self.previous = ciphertext;
        }
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(Aes256DecryptContext, (&self.cipher)[0..1]);
        std.crypto.secureZero(u8, &self.previous);
        self.* = undefined;
    }
};

test "7-Zip SHA-256 KDF matches independent vectors" {
    const expected = [_]u8{
        0x65, 0x11, 0xf1, 0x50, 0x7a, 0x3c, 0x2a, 0x98,
        0x2a, 0xe6, 0xde, 0xf4, 0xf6, 0x58, 0x18, 0xed,
        0x6c, 0xf2, 0x42, 0x65, 0x1a, 0xca, 0x19, 0xd1,
        0x5c, 0xeb, 0xc6, 0xa6, 0x7a, 0xe2, 0x89, 0x1d,
    };
    const key = try deriveKey(std.testing.allocator, "secret", &.{}, 19, .{});
    try std.testing.expectEqual(expected, key);

    const direct = try deriveKey(
        std.testing.allocator,
        "密码",
        &.{ 0x24, 0x24, 0x24, 0x24 },
        direct_key_power,
        .{},
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x24, 0x24, 0x24, 0x24, 0xc6, 0x5b, 0x01, 0x78 },
        direct[0..8],
    );
}

test "7-Zip AES-256-CBC matches OpenSSL and decrypts in place" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const iv = [_]u8{
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const plaintext = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const expected = [_]u8{
        0x22, 0x4c, 0x27, 0xf4, 0xba, 0x37, 0x8b, 0x27,
        0xd3, 0xd6, 0x88, 0x8a, 0xdc, 0xed, 0x64, 0x42,
        0x58, 0x30, 0xcb, 0x29, 0x73, 0xf0, 0x08, 0xc4,
        0x6e, 0x64, 0xc4, 0xe1, 0xca, 0x61, 0x21, 0x06,
    };
    var encrypted: [plaintext.len]u8 = undefined;
    var encryptor = Encryptor.init(key, iv);
    defer encryptor.deinit();
    try encryptor.encryptBlocks(&plaintext, &encrypted);
    try std.testing.expectEqualSlices(u8, &expected, &encrypted);

    var decryptor = Decryptor.init(key, iv);
    defer decryptor.deinit();
    try decryptor.decryptBlocks(&encrypted, &encrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &encrypted);
}

test "7-Zip crypto rejects excessive KDF work and partial AES blocks" {
    try std.testing.expectError(
        error.KdfWorkLimitExceeded,
        deriveKey(std.testing.allocator, "password", &.{}, 19, .{ .max_cycles_power = 18 }),
    );
    try std.testing.expectError(
        error.InvalidPassword,
        deriveKey(std.testing.allocator, &.{0xff}, &.{}, 1, .{}),
    );
    var encryptor = Encryptor.init([_]u8{0} ** key_len, [_]u8{0} ** block_len);
    defer encryptor.deinit();
    var output: [1]u8 = undefined;
    try std.testing.expectError(error.InvalidBlockLength, encryptor.encryptBlocks(&.{0}, &output));
}

test "7-Zip KDF releases every allocation failure" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var key = try deriveKey(
                allocator,
                "allocation-密码",
                &.{ 0, 1, 2, 3, 4, 5, 6, 7 },
                direct_key_power,
                .{},
            );
            defer std.crypto.secureZero(u8, &key);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}

test "7-Zip SHA-256 KDF portable counter matches salted Unicode and small-power golden keys" {
    // Frozen independent Python hashlib SHA-256 vectors. Each round feeds
    // salt, UTF-16LE password, and the complete eight-byte little-endian counter.
    const Vector = struct { password: []const u8, salt: []const u8, power: u6, key_hex: []const u8 };
    const vectors = [_]Vector{
        .{ .password = "", .salt = &.{}, .power = 0, .key_hex = "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc" },
        .{ .password = "password", .salt = &.{}, .power = 0, .key_hex = "140053b53e9dd0b594a283c08f6205891b2b7717e32a04e78eaf237208e9d484" },
        .{ .password = "password", .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, .power = 1, .key_hex = "25b58cc6b527b4ba03ac8c8f26e71a16431da8de0397c0c354c716c149161cc2" },
        .{ .password = "密码🔒", .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, .power = 12, .key_hex = "030bdaea2db2deec556a84fe28f051d4c5ba507f022f85bbcbd43144a52137e9" },
    };
    const Runtime = struct {
        // Compile the whole public derivation with a runtime coder field on
        // both native and x86, rather than specializing a usize-sized range.
        noinline fn derive(password: []const u8, salt: []const u8, power: u6) ![key_len]u8 {
            return deriveKey(std.testing.allocator, password, salt, power, .{});
        }
    };
    for (vectors) |vector| {
        var expected: [key_len]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, vector.key_hex);
        var key = try Runtime.derive(vector.password, vector.salt, vector.power);
        defer std.crypto.secureZero(u8, &key);
        try std.testing.expectEqual(expected, key);
    }
}

test "7-Zip direct key preserves UTF-16LE padding truncation and cycle-limit exemption" {
    var direct = try deriveKey(std.testing.allocator, "密码", &.{ 0x24, 0x24, 0x24, 0x24 }, direct_key_power, .{ .max_cycles_power = 0 });
    defer std.crypto.secureZero(u8, &direct);
    var expected: [key_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "24242424c65b0178000000000000000000000000000000000000000000000000");
    try std.testing.expectEqual(expected, direct);

    var truncated = try deriveKey(std.testing.allocator, "密码🔒abcdefghijklmnop", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, direct_key_power, .{ .max_cycles_power = 0 });
    defer std.crypto.secureZero(u8, &truncated);
    _ = try std.fmt.hexToBytes(&expected, "000102030405060708090a0b0c0d0e0fc65b01783dd812dd6100620063006400");
    try std.testing.expectEqual(expected, truncated);
    try std.testing.expectEqual([_]u8{0} ** key_len, try deriveKey(std.testing.allocator, "", &.{}, direct_key_power, .{ .max_cycles_power = 0 }));
}

test "7-Zip KDF validates cycle policy before password allocation on narrow targets" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const a = failing.allocator();
    // The six-bit field retains its format meaning: 25 through 62 are invalid,
    // and 63 is the direct-key mode. No platform-dependent round cap is added.
    for (25..63) |power| {
        try std.testing.expectError(error.InvalidKdfCycles, deriveKey(a, &.{0xff}, &.{}, @intCast(power), .{ .max_cycles_power = 63 }));
    }
    try std.testing.expectError(error.InvalidKdfCycles, deriveKey(a, "password", &([_]u8{0} ** 17), direct_key_power, .{}));
    try std.testing.expectError(error.KdfWorkLimitExceeded, deriveKey(a, &.{0xff}, &.{}, 12, .{ .max_cycles_power = 11 }));
    try std.testing.expectError(error.KdfWorkLimitExceeded, deriveKey(a, &.{0xff}, &.{}, hard_max_cycles_power, .{ .max_cycles_power = hard_max_cycles_power - 1 }));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expectEqual(@as(usize, 0), failing.allocated_bytes);
    // Power 24 is still valid policy; the failing allocator stops before its
    // costly rounds. The reserved direct mode also reaches password allocation.
    try std.testing.expectError(error.OutOfMemory, deriveKey(a, "password", &.{}, hard_max_cycles_power, .{}));
    try std.testing.expectError(error.OutOfMemory, deriveKey(a, "password", &.{}, direct_key_power, .{ .max_cycles_power = 0 }));
    try std.testing.expectEqual(@as(usize, 0), failing.allocated_bytes);
}

test "7-Zip SHA-256 KDF preserves the UTF-16 password allocation failure contract" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var key = try deriveKey(allocator, "allocation-密码🔒", &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, 12, .{});
            defer std.crypto.secureZero(u8, &key);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}
