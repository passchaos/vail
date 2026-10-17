//! Cryptographic primitives for Microsoft encrypted ESD ranges.
//!
//! The container layer owns XML/range parsing. Each listed range is an
//! independent AES-256-CBC stream with an all-zero IV and no padding.

const std = @import("std");

const Aes = std.crypto.core.aes;
const Aes256EncryptContext = Aes.AesEncryptCtx(Aes.Aes256);
const Aes256DecryptContext = Aes.AesDecryptCtx(Aes.Aes256);

pub const key_len: usize = 32;
pub const block_len: usize = 16;

pub const Error = error{
    InvalidRangeLength,
    OutputSizeMismatch,
};

pub fn decryptRange(
    key: *const [key_len]u8,
    encrypted: []const u8,
    output: []u8,
) Error!void {
    if (encrypted.len == 0 or encrypted.len % block_len != 0)
        return error.InvalidRangeLength;
    if (output.len != encrypted.len) return error.OutputSizeMismatch;
    var cipher = Aes.Aes256.initDec(key.*);
    defer std.crypto.secureZero(Aes256DecryptContext, (&cipher)[0..1]);
    var previous: [block_len]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &previous);
    var offset: usize = 0;
    while (offset < encrypted.len) : (offset += block_len) {
        const block = encrypted[offset..][0..block_len].*;
        var plain: [block_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
        cipher.decrypt(&plain, &block);
        for (&plain, previous) |*byte, prior| byte.* ^= prior;
        @memcpy(output[offset..][0..block_len], &plain);
        previous = block;
    }
}

pub fn encryptRange(
    key: *const [key_len]u8,
    plaintext: []const u8,
    output: []u8,
) Error!void {
    if (plaintext.len == 0 or plaintext.len % block_len != 0)
        return error.InvalidRangeLength;
    if (output.len != plaintext.len) return error.OutputSizeMismatch;
    var cipher = Aes.Aes256.initEnc(key.*);
    defer std.crypto.secureZero(Aes256EncryptContext, (&cipher)[0..1]);
    var previous: [block_len]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &previous);
    var offset: usize = 0;
    while (offset < plaintext.len) : (offset += block_len) {
        var block = plaintext[offset..][0..block_len].*;
        defer std.crypto.secureZero(u8, &block);
        for (&block, previous) |*byte, prior| byte.* ^= prior;
        cipher.encrypt(output[offset..][0..block_len], &block);
        previous = output[offset..][0..block_len].*;
    }
}

test "ESD AES-256-CBC zero-IV range matches OpenSSL" {
    const key: [key_len]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const plaintext: [32]u8 = .{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    const expected: [32]u8 = .{
        0xe0, 0xa8, 0xf5, 0x0e, 0xc7, 0x6a, 0x04, 0xd5,
        0xa9, 0x6a, 0x17, 0x5a, 0xa8, 0x70, 0xef, 0x63,
        0x55, 0x4c, 0xf9, 0xf0, 0x4f, 0xd0, 0x37, 0xa1,
        0xa1, 0xa4, 0x69, 0xf7, 0xd0, 0xaf, 0xcc, 0x80,
    };
    var encrypted: [plaintext.len]u8 = undefined;
    try encryptRange(&key, &plaintext, &encrypted);
    try std.testing.expectEqualSlices(u8, &expected, &encrypted);
    var decoded: [plaintext.len]u8 = undefined;
    try decryptRange(&key, &encrypted, &decoded);
    try std.testing.expectEqualSlices(u8, &plaintext, &decoded);
    try std.testing.expectError(
        error.InvalidRangeLength,
        decryptRange(&key, encrypted[0..31], decoded[0..31]),
    );
}
