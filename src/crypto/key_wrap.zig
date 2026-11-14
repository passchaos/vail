//! RFC 3394 AES key wrap and unwrap.
//!
//! Supports 128-, 192-, and 256-bit key-encryption keys. Unwrap performs a
//! constant-time integrity check and wipes the output buffer on failure.

const std = @import("std");
const aes = @import("block/aes.zig");

pub const Error = error{
    InvalidKeyLength,
    InvalidPlaintextLength,
    InvalidWrappedLength,
    IntegrityCheckFailed,
};

pub const overhead = 8;

const initial_value: [overhead]u8 = @splat(0xa6);

/// Wrap `plaintext` under `kek`. `wrapped.len` must be `plaintext.len + 8` and
/// the buffers must not overlap.
pub fn wrap(wrapped: []u8, kek: []const u8, plaintext: []const u8) Error!void {
    if (plaintext.len < 16 or plaintext.len % 8 != 0) {
        return error.InvalidPlaintextLength;
    }
    if (wrapped.len != plaintext.len + overhead) {
        return error.InvalidWrappedLength;
    }
    switch (kek.len) {
        16 => wrapWith(aes.Aes128, kek[0..16].*, wrapped, plaintext),
        24 => wrapWith(aes.Aes192, kek[0..24].*, wrapped, plaintext),
        32 => wrapWith(aes.Aes256, kek[0..32].*, wrapped, plaintext),
        else => return error.InvalidKeyLength,
    }
}

/// Unwrap `wrapped` under `kek`. `plaintext.len` must be `wrapped.len - 8`.
/// On an integrity failure the output is wiped before returning.
pub fn unwrap(plaintext: []u8, kek: []const u8, wrapped: []const u8) Error!void {
    if (wrapped.len < 24 or wrapped.len % 8 != 0) {
        return error.InvalidWrappedLength;
    }
    if (plaintext.len + overhead != wrapped.len) {
        return error.InvalidPlaintextLength;
    }
    const valid = switch (kek.len) {
        16 => unwrapWith(aes.Aes128, kek[0..16].*, plaintext, wrapped),
        24 => unwrapWith(aes.Aes192, kek[0..24].*, plaintext, wrapped),
        32 => unwrapWith(aes.Aes256, kek[0..32].*, plaintext, wrapped),
        else => return error.InvalidKeyLength,
    };
    if (!valid) {
        std.crypto.secureZero(u8, plaintext);
        return error.IntegrityCheckFailed;
    }
}

fn wrapWith(
    comptime Cipher: type,
    kek: [Cipher.key_bits / 8]u8,
    wrapped: []u8,
    plaintext: []const u8,
) void {
    const cipher = Cipher.initEnc(kek);
    var a = initial_value;
    @memcpy(wrapped[overhead..], plaintext);
    const n = plaintext.len / 8;
    for (0..6) |j| {
        for (0..n) |i| {
            var block: [aes.block_length]u8 = undefined;
            block[0..8].* = a;
            block[8..16].* = wrapped[overhead + i * 8 ..][0..8].*;
            cipher.encrypt(&block, &block);
            a = block[0..8].*;
            xorCounter(&a, @intCast(n * j + i + 1));
            wrapped[overhead + i * 8 ..][0..8].* = block[8..16].*;
        }
    }
    wrapped[0..8].* = a;
}

fn unwrapWith(
    comptime Cipher: type,
    kek: [Cipher.key_bits / 8]u8,
    plaintext: []u8,
    wrapped: []const u8,
) bool {
    const cipher = Cipher.initDec(kek);
    var a: [8]u8 = wrapped[0..8].*;
    @memcpy(plaintext, wrapped[overhead..]);
    const n = plaintext.len / 8;
    var j: usize = 6;
    while (j > 0) {
        j -= 1;
        var i = n;
        while (i > 0) {
            i -= 1;
            var block: [aes.block_length]u8 = undefined;
            xorCounter(&a, @intCast(n * j + i + 1));
            block[0..8].* = a;
            block[8..16].* = plaintext[i * 8 ..][0..8].*;
            cipher.decrypt(&block, &block);
            a = block[0..8].*;
            plaintext[i * 8 ..][0..8].* = block[8..16].*;
        }
    }
    return std.crypto.timing_safe.eql([8]u8, a, initial_value);
}

fn xorCounter(a: *[8]u8, value: u64) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, value, .big);
    for (a, encoded) |*byte, counter_byte| byte.* ^= counter_byte;
}

test "RFC 3394 wrap and unwrap vectors" {
    const cases = .{
        .{
            .kek = "000102030405060708090A0B0C0D0E0F",
            .key = "00112233445566778899AABBCCDDEEFF",
            .wrapped = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        },
        .{
            .kek = "000102030405060708090A0B0C0D0E0F1011121314151617",
            .key = "00112233445566778899AABBCCDDEEFF",
            .wrapped = "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        },
        .{
            .kek = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            .key = "00112233445566778899AABBCCDDEEFF",
            .wrapped = "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        },
        .{
            .kek = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            .key = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            .wrapped = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326" ++
                "CBC7F0E71A99F43BFB988B9B7A02DD21",
        },
    };
    inline for (cases) |case| {
        var kek: [case.kek.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&kek, case.kek);
        var key: [case.key.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, case.key);
        var expected: [case.wrapped.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case.wrapped);

        var wrapped: [expected.len]u8 = undefined;
        try wrap(&wrapped, &kek, &key);
        try std.testing.expectEqualSlices(u8, &expected, &wrapped);

        var unwrapped: [key.len]u8 = undefined;
        try unwrap(&unwrapped, &kek, &expected);
        try std.testing.expectEqualSlices(u8, &key, &unwrapped);
    }
}

test "RFC 3394 unwrap rejects tampering and wipes the output" {
    const kek = [_]u8{0x11} ** 16;
    const key = [_]u8{0x22} ** 32;
    var wrapped: [key.len + overhead]u8 = undefined;
    try wrap(&wrapped, &kek, &key);
    wrapped[3] ^= 1;
    var unwrapped: [key.len]u8 = undefined;
    try std.testing.expectError(
        error.IntegrityCheckFailed,
        unwrap(&unwrapped, &kek, &wrapped),
    );
    try std.testing.expectEqual([_]u8{0} ** key.len, unwrapped);
}

test "RFC 3394 rejects invalid lengths" {
    var output: [32]u8 = undefined;
    var wrapped24: [24]u8 = undefined;
    try std.testing.expectError(
        error.InvalidKeyLength,
        wrap(&wrapped24, &([_]u8{0} ** 20), &([_]u8{0} ** 16)),
    );
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        wrap(&wrapped24, &([_]u8{0} ** 16), &([_]u8{0} ** 8)),
    );
    try std.testing.expectError(
        error.InvalidWrappedLength,
        unwrap(&output, &([_]u8{0} ** 16), &([_]u8{0} ** 16)),
    );
}
