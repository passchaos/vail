//! RAR 5 password-based cryptographic primitives.
//!
//! The archive layer owns encryption-extra records, compressed-size accounting,
//! block padding, and file checksum policy. This module owns RAR 5's extended
//! PBKDF2-HMAC-SHA256 derivation, AES-256-CBC, password checks, and keyed
//! checksum transforms. RAR 5 encryption is not authenticated; callers must
//! still validate the archive's transformed CRC-32 or hash after decoding.

const std = @import("std");

const Aes = std.crypto.core.aes;
const Aes256EncryptContext = Aes.AesEncryptCtx(Aes.Aes256);
const Aes256DecryptContext = Aes.AesDecryptCtx(Aes.Aes256);
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const block_len: usize = 16;
pub const salt_len: usize = 16;
pub const key_len: usize = 32;
pub const password_check_len: usize = 8;
pub const password_check_record_len: usize = 12;
pub const hard_max_kdf_count: u8 = 24;

pub const Error = error{
    InvalidBlockLength,
    InvalidKdfCount,
};

pub const DeriveOptions = struct {
    /// Bounds the binary logarithm of the PBKDF2 iteration count. The hard
    /// implementation ceiling matches current 7-Zip's RAR5 decoder policy.
    max_kdf_count: u8 = hard_max_kdf_count,
};

/// Fixed-capacity RAR 5 key material. Call `deinit` as soon as it is no longer
/// needed. Password bytes are consumed exactly as supplied; UTF-8 validation
/// and text conversion remain archive/application policy.
pub const Keys = struct {
    encryption: [key_len]u8,
    hash: [key_len]u8,
    password_check: [password_check_len]u8,

    const Self = @This();

    pub fn passwordCheckRecord(self: *const Self) [password_check_record_len]u8 {
        var record: [password_check_record_len]u8 = undefined;
        @memcpy(record[0..password_check_len], &self.password_check);
        var digest: [Sha256.digest_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        Sha256.hash(&self.password_check, &digest, .{});
        @memcpy(record[password_check_len..], digest[0..4]);
        return record;
    }

    pub fn verifyPasswordCheck(
        self: *const Self,
        expected: [password_check_len]u8,
    ) bool {
        return std.crypto.timing_safe.eql(
            [password_check_len]u8,
            self.password_check,
            expected,
        );
    }

    pub fn tweakCrc32(self: *const Self, crc32: u32) u32 {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, crc32, .little);
        var digest: [HmacSha256.mac_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        HmacSha256.create(&digest, &encoded, &self.hash);
        var tweaked: u32 = 0;
        for (0..8) |index|
            tweaked ^= std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
        return tweaked;
    }

    pub fn tweakDigest(
        self: *const Self,
        digest: [Sha256.digest_length]u8,
    ) [Sha256.digest_length]u8 {
        var tweaked: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&tweaked, &digest, &self.hash);
        return tweaked;
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(Self, (&self.*)[0..1]);
        self.* = undefined;
    }
};

/// Derives the AES key, keyed-checksum key, and password check in one extended
/// PBKDF2 chain. RAR takes checkpoints after 2^N, 2^N+16, and 2^N+32 rounds.
pub fn deriveKeys(
    password: []const u8,
    salt: [salt_len]u8,
    kdf_count: u8,
    options: DeriveOptions,
) Error!Keys {
    if (kdf_count > options.max_kdf_count or kdf_count > hard_max_kdf_count)
        return error.InvalidKdfCount;

    const base_rounds: u32 = @as(u32, 1) << @intCast(kdf_count);
    const final_rounds = base_rounds + 32;
    var base = HmacSha256.init(password);
    defer std.crypto.secureZero(HmacSha256, (&base)[0..1]);

    var first = base;
    defer std.crypto.secureZero(HmacSha256, (&first)[0..1]);
    first.update(&salt);
    first.update(&.{ 0, 0, 0, 1 });
    var u: [HmacSha256.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &u);
    first.final(&u);
    var aggregate = u;
    defer std.crypto.secureZero(u8, &aggregate);

    var keys: Keys = undefined;
    var password_digest: [HmacSha256.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &password_digest);
    var completed: u32 = 1;
    checkpoint(&keys, &password_digest, completed, base_rounds, aggregate);
    while (completed < final_rounds) {
        var iteration = base;
        iteration.update(&u);
        var next: [HmacSha256.mac_length]u8 = undefined;
        iteration.final(&next);
        std.crypto.secureZero(HmacSha256, (&iteration)[0..1]);
        for (&aggregate, next) |*byte, next_byte| byte.* ^= next_byte;
        u = next;
        std.crypto.secureZero(u8, &next);
        completed += 1;
        checkpoint(&keys, &password_digest, completed, base_rounds, aggregate);
    }

    var even: u32 = 0;
    var odd: u32 = 0;
    for (0..8) |index| {
        const word = std.mem.readInt(u32, password_digest[index * 4 ..][0..4], .little);
        if (index & 1 == 0) even ^= word else odd ^= word;
    }
    std.mem.writeInt(u32, keys.password_check[0..4], even, .little);
    std.mem.writeInt(u32, keys.password_check[4..8], odd, .little);
    return keys;
}

fn checkpoint(
    keys: *Keys,
    password_digest: *[HmacSha256.mac_length]u8,
    completed: u32,
    base_rounds: u32,
    aggregate: [HmacSha256.mac_length]u8,
) void {
    if (completed == base_rounds) keys.encryption = aggregate;
    if (completed == base_rounds + 16) keys.hash = aggregate;
    if (completed == base_rounds + 32) password_digest.* = aggregate;
}

/// Validates the four-byte SHA-256 checksum protecting an on-wire password
/// check before the password itself is compared.
pub fn passwordCheckRecordValid(record: [password_check_record_len]u8) bool {
    var digest: [Sha256.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    Sha256.hash(record[0..password_check_len], &digest, .{});
    return std.crypto.timing_safe.eql(
        [4]u8,
        digest[0..4].*,
        record[password_check_len..][0..4].*,
    );
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

test "RAR5 extended PBKDF2 matches independent vectors" {
    const salt = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var keys = try deriveKeys("RAR5 密码", salt, 3, .{});
    defer keys.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x1f, 0x93, 0x5d, 0x2c, 0xe3, 0x7a, 0xb1, 0xd3, 0xad, 0x93, 0x17, 0x30, 0xeb, 0x0d, 0xa8, 0x8f, 0x27, 0xd3, 0x02, 0xaa, 0x9a, 0x1f, 0x26, 0x4f, 0xc9, 0x73, 0xfa, 0x45, 0x9b, 0xb2, 0xb1, 0xba },
        &keys.encryption,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf9, 0xa9, 0x36, 0x89, 0x51, 0xdd, 0x57, 0xa5, 0xdc, 0x03, 0x95, 0xb7, 0x52, 0x2d, 0xc9, 0xf7, 0x79, 0xb3, 0xbd, 0x81, 0xf4, 0xf5, 0x50, 0x31, 0x08, 0x53, 0xaa, 0xb8, 0x78, 0x20, 0x44, 0xed },
        &keys.hash,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xa6, 0x2b, 0x51, 0x0e, 0xd0, 0x6c, 0x5c, 0xdd },
        &keys.password_check,
    );
    const record = keys.passwordCheckRecord();
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xa6, 0x2b, 0x51, 0x0e, 0xd0, 0x6c, 0x5c, 0xdd, 0xe0, 0x7f, 0xbc, 0x33 },
        &record,
    );
    try std.testing.expect(passwordCheckRecordValid(record));
    try std.testing.expect(keys.verifyPasswordCheck(record[0..password_check_len].*));
}

test "RAR5 keyed checksum transforms match independent vectors" {
    const salt = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var keys = try deriveKeys("RAR5 密码", salt, 3, .{});
    defer keys.deinit();
    try std.testing.expectEqual(@as(u32, 0xae79_3a12), keys.tweakCrc32(0x1234_5678));
    const digest = keys.tweakDigest(.{
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    });
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x55, 0xb0, 0xa3, 0x6d, 0x41, 0xd5, 0xfb, 0x88, 0x33, 0x8f, 0x80, 0xd1, 0xd3, 0x7f, 0xb2, 0x3f, 0x4e, 0x12, 0x19, 0xb4, 0x62, 0x8e, 0x54, 0x5c, 0x1f, 0x85, 0xb3, 0xa9, 0xc5, 0xf0, 0x69, 0x82 },
        &digest,
    );
}

test "RAR5 AES-256-CBC matches OpenSSL and supports in-place decryption" {
    const key = [_]u8{ 0x1f, 0x93, 0x5d, 0x2c, 0xe3, 0x7a, 0xb1, 0xd3, 0xad, 0x93, 0x17, 0x30, 0xeb, 0x0d, 0xa8, 0x8f, 0x27, 0xd3, 0x02, 0xaa, 0x9a, 0x1f, 0x26, 0x4f, 0xc9, 0x73, 0xfa, 0x45, 0x9b, 0xb2, 0xb1, 0xba };
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    const plaintext = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    };
    const expected = [_]u8{ 0xeb, 0xbd, 0x18, 0x11, 0x2a, 0xb2, 0x16, 0x06, 0xeb, 0x09, 0x9b, 0xf0, 0x97, 0xb6, 0xbc, 0x11, 0x12, 0x3f, 0x18, 0xaa, 0x6d, 0x25, 0xb8, 0xe0, 0x84, 0x04, 0x23, 0x1b, 0x6a, 0x47, 0xd8, 0x96 };
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

test "RAR5 rejects excessive KDF work and partial AES blocks" {
    try std.testing.expectError(
        error.InvalidKdfCount,
        deriveKeys("password", [_]u8{0} ** salt_len, 9, .{ .max_kdf_count = 8 }),
    );
    var encryptor = Encryptor.init([_]u8{0} ** key_len, [_]u8{0} ** block_len);
    defer encryptor.deinit();
    var output: [1]u8 = undefined;
    try std.testing.expectError(error.InvalidBlockLength, encryptor.encryptBlocks(&.{0}, &output));
}
