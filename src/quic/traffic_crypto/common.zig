//! Shared QUIC packet-protection data layout.
//!
//! Cipher suites differ in HKDF hash, AEAD, and header-protection primitive,
//! but RFC 9001 fixes nonce, tag, sample, and mask sizes across the TLS 1.3
//! suites supported by Vail.

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
    var packet_number_bytes: [8]u8 = undefined;
    @import("std").mem.writeInt(
        u64,
        &packet_number_bytes,
        packet_number,
        .big,
    );
    for (packet_number_bytes, 0..) |byte, index| {
        nonce[iv_len - packet_number_bytes.len + index] ^= byte;
    }
    return nonce;
}
