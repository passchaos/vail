//! PKWARE Strong Encryption cryptographic protocol primitives.
//!
//! This module implements the password-based AES subset from APPNOTE 6.3.5:
//! SHA-1/CryptDeriveKey-compatible key expansion, AES-CBC, PKCS#7 padding,
//! encrypted random data, and CRC-32 password validation. ZIP record layout,
//! general-purpose flags, extra fields, and size accounting remain the archive
//! layer's responsibility.
//!
//! PKWARE Strong Encryption is a legacy confidentiality format. It does not
//! authenticate ciphertext; callers must still verify the ZIP entry CRC-32.

const std = @import("std");
const aes192 = @import("aes192.zig");

const Aes = std.crypto.core.aes;
const Aes128EncryptContext = Aes.AesEncryptCtx(Aes.Aes128);
const Aes128DecryptContext = Aes.AesDecryptCtx(Aes.Aes128);
const Aes256EncryptContext = Aes.AesEncryptCtx(Aes.Aes256);
const Aes256DecryptContext = Aes.AesDecryptCtx(Aes.Aes256);
const Sha1 = std.crypto.hash.Sha1;

pub const block_len: usize = 16;
pub const max_key_len: usize = 32;
pub const digest_len: usize = Sha1.digest_length;
const derive_block_len: usize = Sha1.block_length;

pub const Error = std.mem.Allocator.Error || error{
    IntegerOverflow,
    InvalidBlockLength,
    InvalidEncryptedRandomData,
    InvalidIvLength,
    InvalidPadding,
    InvalidPasswordValidation,
    InvalidRandomDataLength,
    InvalidValidationDataLength,
    TruncatedEncryptedPayload,
};

pub const Strength = enum {
    aes128,
    aes192,
    aes256,

    pub fn keyLen(self: Strength) usize {
        return switch (self) {
            .aes128 => 16,
            .aes192 => 24,
            .aes256 => 32,
        };
    }
};

/// Fixed-capacity key material. Call `deinit` as soon as the key is no longer
/// needed. Only `bytes()[0..strength.keyLen()]` contains key material.
pub const Key = struct {
    material: [max_key_len]u8,
    strength: Strength,

    const Self = @This();

    pub fn bytes(self: *const Self) []const u8 {
        return self.material[0..self.strength.keyLen()];
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(Self, (&self.*)[0..1]);
        self.* = undefined;
    }
};

/// Derives the master session key from the password bytes exactly as supplied.
/// Password text encoding is intentionally owned by the archive/application
/// layer because historic ZIP producers disagree about that encoding.
pub fn derivePasswordKey(password: []const u8, strength: Strength) Key {
    var digest: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    Sha1.hash(password, &digest, .{});
    return deriveDigestKey(digest, strength);
}

/// Derives a per-file session key from `SHA1(iv_material || random_data)`.
/// For an explicit AES IV, `iv_material` is all 16 IV bytes. APPNOTE's legacy
/// zero-length IV form instead supplies the synthesized 12-byte value here
/// while CBC still receives its zero-extended 16-byte IV.
pub fn deriveFileKey(
    iv_material: []const u8,
    random_data: []const u8,
    strength: Strength,
) Key {
    var hasher = Sha1.init(.{});
    hasher.update(iv_material);
    hasher.update(random_data);
    var digest: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    hasher.final(&digest);
    return deriveDigestKey(digest, strength);
}

const EncryptBlockCipher = union(Strength) {
    aes128: Aes128EncryptContext,
    aes192: aes192.EncryptContext,
    aes256: Aes256EncryptContext,

    fn init(key: *const Key) EncryptBlockCipher {
        return switch (key.strength) {
            .aes128 => .{ .aes128 = Aes.Aes128.initEnc(key.bytes()[0..16].*) },
            .aes192 => .{ .aes192 = aes192.EncryptContext.init(key.bytes()[0..24].*) },
            .aes256 => .{ .aes256 = Aes.Aes256.initEnc(key.bytes()[0..32].*) },
        };
    }

    fn encrypt(self: *const EncryptBlockCipher, output: *[block_len]u8, input: *const [block_len]u8) void {
        switch (self.*) {
            inline else => |context| context.encrypt(output, input),
        }
    }

    fn deinit(self: *EncryptBlockCipher) void {
        switch (self.*) {
            .aes128 => |*context| std.crypto.secureZero(Aes128EncryptContext, context[0..1]),
            .aes192 => |*context| context.deinit(),
            .aes256 => |*context| std.crypto.secureZero(Aes256EncryptContext, context[0..1]),
        }
        self.* = undefined;
    }
};

const DecryptBlockCipher = union(Strength) {
    aes128: Aes128DecryptContext,
    aes192: aes192.DecryptContext,
    aes256: Aes256DecryptContext,

    fn init(key: *const Key) DecryptBlockCipher {
        return switch (key.strength) {
            .aes128 => .{ .aes128 = Aes.Aes128.initDec(key.bytes()[0..16].*) },
            .aes192 => .{ .aes192 = aes192.DecryptContext.init(key.bytes()[0..24].*) },
            .aes256 => .{ .aes256 = Aes.Aes256.initDec(key.bytes()[0..32].*) },
        };
    }

    fn decrypt(self: *const DecryptBlockCipher, output: *[block_len]u8, input: *const [block_len]u8) void {
        switch (self.*) {
            inline else => |context| context.decrypt(output, input),
        }
    }

    fn deinit(self: *DecryptBlockCipher) void {
        switch (self.*) {
            .aes128 => |*context| std.crypto.secureZero(Aes128DecryptContext, context[0..1]),
            .aes192 => |*context| context.deinit(),
            .aes256 => |*context| std.crypto.secureZero(Aes256DecryptContext, context[0..1]),
        }
        self.* = undefined;
    }
};

/// Resumable AES-CBC encryptor. Inputs must consist of complete blocks. The
/// same slice may be used for input and output; other overlap is unsupported.
pub const CbcEncryptor = struct {
    cipher: EncryptBlockCipher,
    previous: [block_len]u8,

    const Self = @This();

    pub fn init(key: *const Key, iv: [block_len]u8) Self {
        return .{ .cipher = EncryptBlockCipher.init(key), .previous = iv };
    }

    pub fn encryptBlocks(self: *Self, input: []const u8, output: []u8) Error!void {
        if (input.len != output.len or input.len % block_len != 0)
            return error.InvalidBlockLength;
        var offset: usize = 0;
        while (offset < input.len) : (offset += block_len) {
            var block = input[offset..][0..block_len].*;
            defer std.crypto.secureZero(u8, &block);
            for (&block, self.previous) |*byte, previous_byte|
                byte.* ^= previous_byte;
            self.cipher.encrypt(output[offset..][0..block_len], &block);
            self.previous = output[offset..][0..block_len].*;
        }
    }

    pub fn deinit(self: *Self) void {
        self.cipher.deinit();
        std.crypto.secureZero(u8, &self.previous);
        self.* = undefined;
    }
};

/// Resumable AES-CBC decryptor. Inputs must consist of complete blocks. The
/// same slice may be used for input and output; other overlap is unsupported.
pub const CbcDecryptor = struct {
    cipher: DecryptBlockCipher,
    previous: [block_len]u8,

    const Self = @This();

    pub fn init(key: *const Key, iv: [block_len]u8) Self {
        return .{ .cipher = DecryptBlockCipher.init(key), .previous = iv };
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
            for (&block, self.previous) |*byte, previous_byte|
                byte.* ^= previous_byte;
            output[offset..][0..block_len].* = block;
            self.previous = ciphertext;
        }
    }

    pub fn deinit(self: *Self) void {
        self.cipher.deinit();
        std.crypto.secureZero(u8, &self.previous);
        self.* = undefined;
    }
};

pub const EncryptOptions = struct {
    password: []const u8,
    strength: Strength = .aes256,
    cbc_iv: [block_len]u8,
    iv_material: []const u8,
    /// Writer-generated entropy. For compatibility with the 7-Zip decoder,
    /// this must be non-empty and block-aligned so ErdData has a full padding
    /// block.
    random_data: []const u8,
    /// Writer-generated password-check bytes. `len + 4` must be a non-zero
    /// multiple of the cipher block length; 12 bytes is the compact choice.
    validation_data: []const u8,
};

pub const Encrypted = struct {
    encrypted_random_data: []u8,
    encrypted_payload: []u8,
    validation_size: usize,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.encrypted_random_data);
        allocator.free(self.encrypted_payload);
        self.* = undefined;
    }
};

/// Encrypts the protocol-owned ErdData and the validator/data CBC stream.
/// The archive layer serializes these slices into its decryption header.
pub fn encryptAlloc(
    allocator: std.mem.Allocator,
    data: []const u8,
    options: EncryptOptions,
) Error!Encrypted {
    if (options.iv_material.len == 0 or options.iv_material.len > block_len)
        return error.InvalidIvLength;
    if (options.random_data.len == 0 or options.random_data.len % block_len != 0)
        return error.InvalidRandomDataLength;
    const validation_size = std.math.add(usize, options.validation_data.len, @sizeOf(u32)) catch
        return error.IntegerOverflow;
    if (options.validation_data.len == 0 or validation_size % block_len != 0)
        return error.InvalidValidationDataLength;

    var master_key = derivePasswordKey(options.password, options.strength);
    defer master_key.deinit();
    const random_plain_len = std.math.add(usize, options.random_data.len, block_len) catch
        return error.IntegerOverflow;
    const random_plain = try allocator.alloc(u8, random_plain_len);
    defer {
        std.crypto.secureZero(u8, random_plain);
        allocator.free(random_plain);
    }
    @memcpy(random_plain[0..options.random_data.len], options.random_data);
    @memset(random_plain[options.random_data.len..], block_len);

    const encrypted_random_data = try allocator.alloc(u8, random_plain_len);
    errdefer allocator.free(encrypted_random_data);
    var random_cipher = CbcEncryptor.init(&master_key, options.cbc_iv);
    defer random_cipher.deinit();
    try random_cipher.encryptBlocks(random_plain, encrypted_random_data);

    var file_key = deriveFileKey(options.iv_material, options.random_data, options.strength);
    defer file_key.deinit();
    const unpadded_payload_len = std.math.add(usize, validation_size, data.len) catch
        return error.IntegerOverflow;
    const payload_len = try paddedLength(unpadded_payload_len);
    const payload_plain = try allocator.alloc(u8, payload_len);
    defer {
        std.crypto.secureZero(u8, payload_plain);
        allocator.free(payload_plain);
    }
    @memcpy(payload_plain[0..options.validation_data.len], options.validation_data);
    std.mem.writeInt(
        u32,
        payload_plain[options.validation_data.len..][0..@sizeOf(u32)],
        std.hash.Crc32.hash(options.validation_data),
        .little,
    );
    @memcpy(payload_plain[validation_size..][0..data.len], data);
    const padding_len: u8 = @intCast(payload_len - unpadded_payload_len);
    @memset(payload_plain[unpadded_payload_len..], padding_len);

    const encrypted_payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(encrypted_payload);
    var payload_cipher = CbcEncryptor.init(&file_key, options.cbc_iv);
    defer payload_cipher.deinit();
    try payload_cipher.encryptBlocks(payload_plain, encrypted_payload);

    return .{
        .encrypted_random_data = encrypted_random_data,
        .encrypted_payload = encrypted_payload,
        .validation_size = validation_size,
    };
}

pub const DecryptOptions = struct {
    password: []const u8,
    strength: Strength,
    cbc_iv: [block_len]u8,
    iv_material: []const u8,
    validation_size: usize,
};

/// Decrypts and validates the password-check block before revealing file data.
/// Payload integrity still requires the archive layer's ZIP CRC-32 check.
pub fn decryptAlloc(
    allocator: std.mem.Allocator,
    encrypted_random_data: []const u8,
    encrypted_payload: []const u8,
    options: DecryptOptions,
) Error![]u8 {
    if (options.iv_material.len == 0 or options.iv_material.len > block_len)
        return error.InvalidIvLength;
    if (encrypted_random_data.len < block_len or encrypted_random_data.len % block_len != 0)
        return error.InvalidEncryptedRandomData;
    if (options.validation_size <= @sizeOf(u32) or options.validation_size % block_len != 0)
        return error.InvalidValidationDataLength;
    const minimum_payload_len = std.math.add(usize, options.validation_size, block_len) catch
        return error.IntegerOverflow;
    if (encrypted_payload.len < minimum_payload_len or encrypted_payload.len % block_len != 0)
        return error.TruncatedEncryptedPayload;

    var master_key = derivePasswordKey(options.password, options.strength);
    defer master_key.deinit();
    const padded_random = try allocator.alloc(u8, encrypted_random_data.len);
    defer {
        std.crypto.secureZero(u8, padded_random);
        allocator.free(padded_random);
    }
    var random_cipher = CbcDecryptor.init(&master_key, options.cbc_iv);
    defer random_cipher.deinit();
    try random_cipher.decryptBlocks(encrypted_random_data, padded_random);
    const random_len = unpaddedLength(padded_random) catch |err| switch (err) {
        error.InvalidPadding => return error.InvalidPasswordValidation,
        else => return err,
    };
    const random_data = padded_random[0..random_len];

    var file_key = deriveFileKey(options.iv_material, random_data, options.strength);
    defer file_key.deinit();
    const validation_plain = try allocator.alloc(u8, options.validation_size);
    defer {
        std.crypto.secureZero(u8, validation_plain);
        allocator.free(validation_plain);
    }
    var payload_cipher = CbcDecryptor.init(&file_key, options.cbc_iv);
    defer payload_cipher.deinit();
    try payload_cipher.decryptBlocks(
        encrypted_payload[0..options.validation_size],
        validation_plain,
    );
    const validation_data = validation_plain[0 .. options.validation_size - @sizeOf(u32)];
    const expected_crc = validation_plain[validation_data.len..][0..@sizeOf(u32)].*;
    var actual_crc: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &actual_crc, std.hash.Crc32.hash(validation_data), .little);
    if (!std.crypto.timing_safe.eql([@sizeOf(u32)]u8, actual_crc, expected_crc))
        return error.InvalidPasswordValidation;

    const encrypted_data = encrypted_payload[options.validation_size..];
    const padded_data = try allocator.alloc(u8, encrypted_data.len);
    defer {
        std.crypto.secureZero(u8, padded_data);
        allocator.free(padded_data);
    }
    try payload_cipher.decryptBlocks(encrypted_data, padded_data);
    const data_len = try unpaddedLength(padded_data);
    return allocator.dupe(u8, padded_data[0..data_len]);
}

fn deriveDigestKey(digest: [digest_len]u8, strength: Strength) Key {
    var material: [max_key_len]u8 = undefined;
    var first = deriveHalf(digest, 0x36);
    defer std.crypto.secureZero(u8, &first);
    var second = deriveHalf(digest, 0x5c);
    defer std.crypto.secureZero(u8, &second);
    @memcpy(material[0..digest_len], &first);
    @memcpy(material[digest_len..], second[0 .. max_key_len - digest_len]);
    return .{ .material = material, .strength = strength };
}

fn deriveHalf(digest: [digest_len]u8, fill: u8) [digest_len]u8 {
    var block: [derive_block_len]u8 = @splat(fill);
    defer std.crypto.secureZero(u8, &block);
    for (block[0..digest_len], digest) |*byte, digest_byte|
        byte.* ^= digest_byte;
    var result: [digest_len]u8 = undefined;
    Sha1.hash(&block, &result, .{});
    return result;
}

fn paddedLength(input_len: usize) Error!usize {
    const remainder = input_len % block_len;
    const padding_len = block_len - remainder;
    return std.math.add(usize, input_len, padding_len) catch error.IntegerOverflow;
}

fn unpaddedLength(input: []const u8) Error!usize {
    if (input.len == 0 or input.len % block_len != 0) return error.InvalidPadding;
    const padding_len = input[input.len - 1];
    if (padding_len == 0 or padding_len > block_len) return error.InvalidPadding;
    var difference: u8 = 0;
    for (input[input.len - block_len ..], 0..) |byte, index| {
        const distance_from_end = block_len - index;
        if (distance_from_end <= padding_len)
            difference |= byte ^ padding_len;
    }
    if (difference != 0) return error.InvalidPadding;
    return input.len - padding_len;
}
