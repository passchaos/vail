//! WinZip AES (AE-1/AE-2) cryptographic primitives.
//!
//! The ZIP container owns method 99, the `0x9901` extra field, CRC policy and
//! compressed-size accounting. This module owns only PBKDF2-HMAC-SHA1 key
//! derivation, WinZip's little-endian AES-CTR stream and HMAC-SHA1-80.

const std = @import("std");
const aes192 = @import("aes192.zig");

const Aes = std.crypto.core.aes;
const Aes128Context = Aes.AesEncryptCtx(Aes.Aes128);
const Aes256Context = Aes.AesEncryptCtx(Aes.Aes256);
const HmacSha1 = std.crypto.auth.hmac.Hmac(std.crypto.hash.Sha1);

pub const password_verifier_len: usize = 2;
pub const authentication_code_len: usize = 10;
pub const iteration_count: u32 = 1000;
pub const max_key_len: usize = 32;
pub const max_salt_len: usize = 16;
const block_len: usize = 16;
const max_derived_len: usize = 2 * max_key_len + password_verifier_len;

pub const Error = std.mem.Allocator.Error || error{
    InvalidSaltLength,
    TruncatedWinZipAesPayload,
    InvalidZipPassword,
    InvalidAuthenticationCode,
    IntegerOverflow,
    WeakParameters,
    OutputTooLong,
};

pub const Strength = enum(u8) {
    aes128 = 1,
    aes192 = 2,
    aes256 = 3,

    pub fn keyLen(self: Strength) usize {
        return switch (self) {
            .aes128 => 16,
            .aes192 => 24,
            .aes256 => 32,
        };
    }

    pub fn saltLen(self: Strength) usize {
        return self.keyLen() / 2;
    }

    pub fn overhead(self: Strength) usize {
        return self.saltLen() + password_verifier_len + authentication_code_len;
    }
};

/// Encryption inputs. Salt generation remains explicit so the archive layer
/// can use a caller-owned CSPRNG and deterministic fixtures remain possible.
pub const Options = struct {
    password: []const u8,
    strength: Strength = .aes256,
    salt: []const u8,
};

const BlockCipher = union(Strength) {
    aes128: Aes128Context,
    aes192: aes192.EncryptContext,
    aes256: Aes256Context,

    fn init(strength: Strength, key: []const u8) BlockCipher {
        std.debug.assert(key.len == strength.keyLen());
        return switch (strength) {
            .aes128 => .{ .aes128 = Aes.Aes128.initEnc(key[0..16].*) },
            .aes192 => .{ .aes192 = aes192.EncryptContext.init(key[0..24].*) },
            .aes256 => .{ .aes256 = Aes.Aes256.initEnc(key[0..32].*) },
        };
    }

    fn encrypt(self: *const BlockCipher, output: *[block_len]u8, input: *const [block_len]u8) void {
        switch (self.*) {
            inline else => |context| context.encrypt(output, input),
        }
    }
};

/// Resumable Encrypt-then-MAC state. `encrypt` authenticates produced
/// ciphertext; `decrypt` authenticates supplied ciphertext before revealing
/// the corresponding plaintext.
pub const Cipher = struct {
    block_cipher: BlockCipher,
    hmac: HmacSha1,
    verifier: [password_verifier_len]u8,
    counter: u128 = 1,
    key_stream: [block_len]u8 = undefined,
    key_stream_pos: usize = block_len,

    const Self = @This();

    pub fn init(password: []const u8, salt: []const u8, strength: Strength) Error!Self {
        if (salt.len != strength.saltLen()) return error.InvalidSaltLength;
        const key_len = strength.keyLen();
        const derived_len = 2 * key_len + password_verifier_len;
        var derived: [max_derived_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &derived);
        try std.crypto.pwhash.pbkdf2(
            derived[0..derived_len],
            password,
            salt,
            iteration_count,
            HmacSha1,
        );
        return .{
            .block_cipher = BlockCipher.init(strength, derived[0..key_len]),
            .hmac = HmacSha1.init(derived[key_len .. 2 * key_len]),
            .verifier = derived[2 * key_len ..][0..password_verifier_len].*,
        };
    }

    pub fn passwordVerifier(self: *const Self) [password_verifier_len]u8 {
        return self.verifier;
    }

    pub fn verifyPassword(self: *const Self, verifier: [password_verifier_len]u8) bool {
        return std.crypto.timing_safe.eql(
            [password_verifier_len]u8,
            self.verifier,
            verifier,
        );
    }

    pub fn encrypt(self: *Self, plaintext: []const u8, ciphertext: []u8) void {
        std.debug.assert(ciphertext.len >= plaintext.len);
        self.crypt(plaintext, ciphertext[0..plaintext.len]);
        self.hmac.update(ciphertext[0..plaintext.len]);
    }

    pub fn decrypt(self: *Self, ciphertext: []const u8, plaintext: []u8) void {
        std.debug.assert(plaintext.len >= ciphertext.len);
        self.hmac.update(ciphertext);
        self.crypt(ciphertext, plaintext[0..ciphertext.len]);
    }

    pub fn authenticationCode(self: *const Self) [authentication_code_len]u8 {
        var copy = self.hmac;
        defer std.crypto.secureZero(HmacSha1, (&copy)[0..1]);
        var full: [HmacSha1.mac_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &full);
        copy.final(&full);
        return full[0..authentication_code_len].*;
    }

    pub fn verifyAuthenticationCode(
        self: *const Self,
        expected: [authentication_code_len]u8,
    ) bool {
        const actual = self.authenticationCode();
        return std.crypto.timing_safe.eql(
            [authentication_code_len]u8,
            actual,
            expected,
        );
    }

    pub fn deinit(self: *Self) void {
        switch (self.block_cipher) {
            .aes128 => |*context| std.crypto.secureZero(Aes128Context, context[0..1]),
            .aes192 => |*context| context.deinit(),
            .aes256 => |*context| std.crypto.secureZero(Aes256Context, context[0..1]),
        }
        std.crypto.secureZero(HmacSha1, (&self.hmac)[0..1]);
        std.crypto.secureZero(u8, &self.verifier);
        std.crypto.secureZero(u128, (&self.counter)[0..1]);
        std.crypto.secureZero(u8, &self.key_stream);
        self.key_stream_pos = 0;
        self.* = undefined;
    }

    fn crypt(self: *Self, input: []const u8, output: []u8) void {
        for (input, output) |byte, *result| {
            if (self.key_stream_pos == block_len) self.refill();
            result.* = byte ^ self.key_stream[self.key_stream_pos];
            self.key_stream_pos += 1;
        }
    }

    fn refill(self: *Self) void {
        var counter_bytes: [block_len]u8 = undefined;
        std.mem.writeInt(u128, &counter_bytes, self.counter, .little);
        self.block_cipher.encrypt(&self.key_stream, &counter_bytes);
        self.counter +%= 1;
        self.key_stream_pos = 0;
        std.crypto.secureZero(u8, &counter_bytes);
    }
};

pub fn encryptAlloc(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    options: Options,
) Error![]u8 {
    if (options.salt.len != options.strength.saltLen()) return error.InvalidSaltLength;
    const output_len = std.math.add(usize, compressed.len, options.strength.overhead()) catch
        return error.IntegerOverflow;
    const output = try allocator.alloc(u8, output_len);
    errdefer {
        std.crypto.secureZero(u8, output);
        allocator.free(output);
    }
    @memcpy(output[0..options.salt.len], options.salt);
    var cipher = try Cipher.init(options.password, options.salt, options.strength);
    defer cipher.deinit();
    const verifier_offset = options.salt.len;
    output[verifier_offset..][0..password_verifier_len].* = cipher.passwordVerifier();
    const ciphertext_offset = verifier_offset + password_verifier_len;
    cipher.encrypt(compressed, output[ciphertext_offset..][0..compressed.len]);
    output[output.len - authentication_code_len ..][0..authentication_code_len].* =
        cipher.authenticationCode();
    return output;
}

pub fn decryptAlloc(
    allocator: std.mem.Allocator,
    encrypted: []const u8,
    password: []const u8,
    strength: Strength,
) Error![]u8 {
    if (encrypted.len < strength.overhead()) return error.TruncatedWinZipAesPayload;
    const salt_len = strength.saltLen();
    var cipher = try Cipher.init(password, encrypted[0..salt_len], strength);
    defer cipher.deinit();
    const verifier = encrypted[salt_len..][0..password_verifier_len].*;
    if (!cipher.verifyPassword(verifier)) return error.InvalidZipPassword;
    const ciphertext = encrypted[salt_len + password_verifier_len .. encrypted.len - authentication_code_len];
    const output = try allocator.alloc(u8, ciphertext.len);
    errdefer {
        std.crypto.secureZero(u8, output);
        allocator.free(output);
    }
    cipher.decrypt(ciphertext, output);
    const expected = encrypted[encrypted.len - authentication_code_len ..][0..authentication_code_len].*;
    if (!cipher.verifyAuthenticationCode(expected)) return error.InvalidAuthenticationCode;
    return output;
}

test "WinZip AES derives independent PBKDF2 key material" {
    const password = "WinZip AES password";
    const vectors = [_]struct {
        strength: Strength,
        salt: []const u8,
        verifier: [password_verifier_len]u8,
    }{
        .{ .strength = .aes128, .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, .verifier = .{ 0x08, 0x2f } },
        .{ .strength = .aes192, .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, .verifier = .{ 0x21, 0x2d } },
        .{ .strength = .aes256, .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, .verifier = .{ 0x7c, 0xfd } },
    };
    for (vectors) |vector| {
        var cipher = try Cipher.init(password, vector.salt, vector.strength);
        defer cipher.deinit();
        try std.testing.expectEqual(vector.verifier, cipher.passwordVerifier());
    }
}

test "WinZip AES CTR matches p7zip vectors for every strength" {
    const plaintext = "Lorem ipsum dolor sit amet, consectetur\n";
    const vectors = [_]struct {
        strength: Strength,
        key: []const u8,
        ciphertext: []const u8,
    }{
        .{
            .strength = .aes128,
            .key = &.{ 0x43, 0x2b, 0x6d, 0xbe, 0x05, 0x76, 0x6c, 0x9e, 0xde, 0xca, 0x3b, 0xf8, 0xaf, 0x5d, 0x81, 0xb6 },
            .ciphertext = &.{ 0xcf, 0x72, 0x6b, 0xa1, 0xb2, 0x0f, 0xdf, 0xaa, 0x10, 0xad, 0x9c, 0x7f, 0x6d, 0x1c, 0x8d, 0xb5, 0x16, 0x7e, 0xbb, 0x11, 0x69, 0x52, 0x8c, 0x89, 0x80, 0x32, 0xaa, 0x76, 0xa6, 0x18, 0x31, 0x98, 0xee, 0xdd, 0x22, 0x68, 0xb7, 0xe6, 0x77, 0xd2 },
        },
        .{
            .strength = .aes192,
            .key = &.{ 0xac, 0x92, 0x41, 0xba, 0xde, 0xd9, 0x02, 0xfe, 0x40, 0x92, 0x20, 0xf6, 0x56, 0x03, 0xfe, 0xae, 0x1b, 0xba, 0x01, 0x97, 0x97, 0x79, 0xbb, 0xa6 },
            .ciphertext = &.{ 0xa6, 0xfc, 0x52, 0x79, 0x2c, 0x6c, 0xfe, 0x68, 0xb1, 0xa8, 0xb3, 0x07, 0x52, 0x8b, 0x82, 0xa6, 0x87, 0x9c, 0x72, 0x42, 0x3a, 0xf8, 0xc6, 0xa9, 0xc9, 0xfb, 0x61, 0x19, 0x37, 0xb9, 0x56, 0x62, 0xf4, 0xfc, 0x5e, 0x7a, 0xdd, 0x55, 0x0a, 0x48 },
        },
        .{
            .strength = .aes256,
            .key = &.{ 0x64, 0x7c, 0x7a, 0xde, 0xf0, 0xf2, 0x61, 0x49, 0x1c, 0xf1, 0xf1, 0xe3, 0x37, 0xfc, 0xe1, 0x4d, 0x4a, 0x77, 0xd4, 0xeb, 0x9e, 0x3d, 0x75, 0xce, 0x9a, 0x3e, 0x10, 0x50, 0xc2, 0x07, 0x36, 0xb6 },
            .ciphertext = &.{ 0xa9, 0x99, 0xbd, 0xea, 0x82, 0x9b, 0x8f, 0x2f, 0xb7, 0x52, 0x2f, 0x6b, 0xd8, 0xf6, 0xab, 0x0e, 0x24, 0x51, 0x9e, 0x18, 0x0f, 0xc0, 0x8f, 0x54, 0x15, 0x80, 0xae, 0xbc, 0xa0, 0x5c, 0x8a, 0x11, 0x8d, 0x14, 0x7e, 0xc5, 0xb4, 0xae, 0xd3, 0x37 },
        },
    };

    for (vectors) |vector| {
        var cipher = Cipher{
            .block_cipher = BlockCipher.init(vector.strength, vector.key),
            .hmac = HmacSha1.init("test authentication key"),
            .verifier = .{ 0, 0 },
        };
        defer cipher.deinit();
        var encrypted: [plaintext.len]u8 = undefined;
        cipher.encrypt(plaintext, &encrypted);
        try std.testing.expectEqualSlices(u8, vector.ciphertext, &encrypted);
    }
}

test "WinZip AES one-shot round trips and authenticates" {
    const allocator = std.testing.allocator;
    const payload = "authenticated WinZip AES compressed payload";
    inline for (std.meta.tags(Strength)) |strength| {
        var salt: [max_salt_len]u8 = undefined;
        for (salt[0..strength.saltLen()], 0..) |*byte, index| byte.* = @intCast(index);
        const encrypted = try encryptAlloc(allocator, payload, .{
            .password = "correct password",
            .strength = strength,
            .salt = salt[0..strength.saltLen()],
        });
        defer allocator.free(encrypted);
        const decrypted = try decryptAlloc(allocator, encrypted, "correct password", strength);
        defer allocator.free(decrypted);
        try std.testing.expectEqualSlices(u8, payload, decrypted);
        try std.testing.expectError(
            error.InvalidZipPassword,
            decryptAlloc(allocator, encrypted, "wrong password", strength),
        );
        const corrupt = try allocator.dupe(u8, encrypted);
        defer allocator.free(corrupt);
        corrupt[corrupt.len - 1] ^= 1;
        try std.testing.expectError(
            error.InvalidAuthenticationCode,
            decryptAlloc(allocator, corrupt, "correct password", strength),
        );
    }
}

test "WinZip AES matches Python PBKDF2 HMAC and OpenSSL AES vectors" {
    const allocator = std.testing.allocator;
    const payload = "authenticated WinZip AES compressed payload";
    const vectors = [_]struct {
        strength: Strength,
        salt: []const u8,
        expected_hex: []const u8,
    }{
        .{
            .strength = .aes128,
            .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7 },
            .expected_hex = "0001020304050607082f029ed97590485bbf88710e7d12fa01ca175722ea1f657ea39beebd38ccec6764e35dd2557b6e0f28802cfa2c3bd23f9f20c9c82385",
        },
        .{
            .strength = .aes192,
            .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
            .expected_hex = "000102030405060708090a0b212d01f5906dac4b93764aabee2a19b96e63c3701f1310a02c93116c51a5c6b406f5173e8efd6f6206cae80858e8bd434a72a80a43310c",
        },
        .{
            .strength = .aes256,
            .salt = &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            .expected_hex = "000102030405060708090a0b0c0d0e0f7cfdbaf84e9d80264ebc4600755b97490c821cc5a0a23e65e31903c20049a794877c9d0afdd58b4abb17d62867cd84ecd9f22424ccfe0f",
        },
    };
    for (vectors) |vector| {
        const encrypted = try encryptAlloc(allocator, payload, .{
            .password = "WinZip AES password",
            .strength = vector.strength,
            .salt = vector.salt,
        });
        defer allocator.free(encrypted);
        var expected: [max_salt_len + password_verifier_len + payload.len + authentication_code_len]u8 = undefined;
        const decoded = try std.fmt.hexToBytes(&expected, vector.expected_hex);
        try std.testing.expectEqualSlices(u8, decoded, encrypted);
    }
}

test "WinZip AES releases every allocation failure" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const salt = [_]u8{0x5a} ** 16;
            const encrypted = try encryptAlloc(allocator, "allocation-safe payload", .{
                .password = "allocation-safe password",
                .strength = .aes256,
                .salt = &salt,
            });
            defer allocator.free(encrypted);
            const decrypted = try decryptAlloc(
                allocator,
                encrypted,
                "allocation-safe password",
                .aes256,
            );
            defer allocator.free(decrypted);
            try std.testing.expectEqualSlices(u8, "allocation-safe payload", decrypted);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}
