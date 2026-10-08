//! Shared QUIC packet-protection data layout.
//!
//! Cipher suites differ in HKDF hash, AEAD, and header-protection primitive,
//! but RFC 9001 fixes nonce, tag, sample, and mask sizes across the TLS 1.3
//! suites supported by Vail.

const std = @import("std");

pub const max_key_len: usize = 32;
pub const iv_len: usize = 12;
pub const tag_len: usize = 16;
pub const sample_len: usize = 16;
pub const mask_len: usize = 5;

pub const Labels = struct {
    key: []const u8 = "quic key",
    iv: []const u8 = "quic iv",
    hp: []const u8 = "quic hp",
    ku: []const u8 = "quic ku",
};

pub const labels_v1 = Labels{};
pub const labels_v2 = Labels{
    .key = "quicv2 key",
    .iv = "quicv2 iv",
    .hp = "quicv2 hp",
    .ku = "quicv2 ku",
};

/// RFC 9001 §5.3 packet nonce construction.
///
/// The packet number is encoded in network byte order and XORed into the
/// least-significant bytes of the static IV. QUIC packet numbers are at most
/// 62 bits, so their eight-byte representation always fits the 12-byte IV.
pub fn packetNonce(iv: [iv_len]u8, packet_number: u64) [iv_len]u8 {
    var nonce = iv;
    const encoded = std.mem.nativeToBig(u64, packet_number);
    const tail: u64 = @bitCast(nonce[iv_len - 8 ..][0..8].*);
    nonce[iv_len - 8 ..][0..8].* = @bitCast(tail ^ encoded);
    return nonce;
}

test "packet nonce XORs the network-order packet number into the IV tail" {
    const iv = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    try std.testing.expectEqual(
        [_]u8{ 0, 1, 2, 3, 5, 7, 5, 3, 13, 15, 13, 3 },
        packetNonce(iv, 0x0102030405060708),
    );
}
