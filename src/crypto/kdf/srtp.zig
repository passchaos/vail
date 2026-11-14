//! RFC 3711 section 4.3.1 AES-CM PRF for SRTP/SRTCP key derivation.
//!
//! The master salt is 12 bytes for the WebRTC AEAD profiles (RFC 7714) and
//! 14 bytes for the original SRTP profiles (RFC 3711). The label is XORed
//! into bit 48 of the salt and the 16-bit block counter occupies the final
//! two bytes of the 128-bit AES input.

const std = @import("std");
const aes = @import("../block/aes.zig");

pub const Error = error{
    InvalidKeyLength,
    InvalidSaltLength,
    InvalidOutputLength,
};

/// Derive `out` from a master key and salt with the RFC 3711 AES-CM PRF.
pub fn derive(
    out: []u8,
    master_key: []const u8,
    master_salt: []const u8,
    label: u8,
) Error!void {
    if (master_salt.len < 8 or master_salt.len > 14) {
        return error.InvalidSaltLength;
    }
    if (out.len > 255 * aes.block_length) return error.InvalidOutputLength;
    switch (master_key.len) {
        16 => deriveWith(aes.Aes128, out, master_key[0..16].*, master_salt, label),
        32 => deriveWith(aes.Aes256, out, master_key[0..32].*, master_salt, label),
        else => return error.InvalidKeyLength,
    }
}

fn deriveWith(
    comptime Cipher: type,
    out: []u8,
    master_key: [Cipher.key_bits / 8]u8,
    master_salt: []const u8,
    label: u8,
) void {
    const cipher = Cipher.initEnc(master_key);
    var input: [aes.block_length]u8 = @splat(0);
    @memcpy(input[0..master_salt.len], master_salt);
    input[7] ^= label;
    var offset: usize = 0;
    var counter: u16 = 0;
    while (offset < out.len) : (counter +%= 1) {
        std.mem.writeInt(u16, input[14..16], counter, .big);
        var block: [aes.block_length]u8 = undefined;
        cipher.encrypt(&block, &input);
        const take = @min(block.len, out.len - offset);
        @memcpy(out[offset..][0..take], block[0..take]);
        offset += take;
        std.crypto.secureZero(u8, &block);
    }
    std.crypto.secureZero(u8, &input);
}

test "RFC 3711 appendix B.3 cipher key" {
    const master_key = try hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139");
    const master_salt = try hexBytes("0EC675AD498AFEEBB6960B3AABE6");
    var out: [16]u8 = undefined;
    try derive(&out, &master_key, &master_salt, 0x00);
    const expected = try hexBytes("C61E7A93744F39EE10734AFE3FF7A087");
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "RFC 7714 12-byte salt profile matches an independent AES-CM block" {
    const master_key = try hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139");
    const master_salt = try hexBytes("0EC675AD498AFEEBB6960B3A");
    var out: [12]u8 = undefined;
    try derive(&out, &master_key, &master_salt, 0x02);
    const expected = try hexBytes("F2FEE04070FC3F65D706E2E4");
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "SRTP KDF rejects invalid lengths" {
    var out: [16]u8 = undefined;
    try std.testing.expectError(
        error.InvalidKeyLength,
        derive(&out, &([_]u8{0} ** 20), &([_]u8{0} ** 12), 0),
    );
    try std.testing.expectError(
        error.InvalidSaltLength,
        derive(&out, &([_]u8{0} ** 16), &([_]u8{0} ** 4), 0),
    );
}

fn hexBytes(comptime encoded: []const u8) ![encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
}
