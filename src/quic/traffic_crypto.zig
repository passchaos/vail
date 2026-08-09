//! QUIC traffic-secret packet cryptography for TLS 1.3 cipher suites.
//!
//! Header construction, packet-number reconstruction, and key-phase state are
//! transport concerns. This module owns key derivation, nonce construction,
//! AEAD payload protection, and header-protection masks.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const cipher_suite = @import("../tls/cipher_suite.zig");
const common = @import("traffic_crypto/common.zig");

/// SHA-384 traffic protection is exposed separately until the higher-level TLS
/// key schedule can carry both 32-byte and 48-byte traffic secrets.
pub const aes256_sha384 =
    @import("traffic_crypto/aes256_sha384.zig");

pub const secret_len = HkdfSha256.prk_length;
pub const max_key_len = common.max_key_len;
pub const iv_len = common.iv_len;
pub const tag_len = common.tag_len;
pub const sample_len = common.sample_len;
pub const mask_len = common.mask_len;

comptime {
    std.debug.assert(ChaCha20Poly1305.key_length == max_key_len);
    std.debug.assert(Aes128Gcm.nonce_length == iv_len);
    std.debug.assert(Aes128Gcm.tag_length == tag_len);
}

/// QUIC uses the TLS-negotiated suite identity directly.  Keeping one enum in
/// the TLS layer prevents adapters from translating or accidentally assigning
/// different limits to the same wire value.
pub const Suite = cipher_suite.Suite;

pub const Labels = common.Labels;

pub const Keys = struct {
    suite: Suite,
    secret: [secret_len]u8,
    key: [max_key_len]u8,
    iv: [iv_len]u8,
    hp: [max_key_len]u8,

    pub fn derive(
        suite: Suite,
        secret: [secret_len]u8,
        labels: Labels,
    ) Keys {
        var keys = Keys{
            .suite = suite,
            .secret = secret,
            .key = [_]u8{0} ** max_key_len,
            .iv = std.crypto.tls.hkdfExpandLabel(
                HkdfSha256,
                secret,
                labels.iv,
                "",
                iv_len,
            ),
            .hp = [_]u8{0} ** max_key_len,
        };
        switch (suite) {
            .aes_128_gcm_sha256 => {
                keys.key[0..Aes128Gcm.key_length].* =
                    std.crypto.tls.hkdfExpandLabel(
                        HkdfSha256,
                        secret,
                        labels.key,
                        "",
                        Aes128Gcm.key_length,
                    );
                keys.hp[0..Aes128Gcm.key_length].* =
                    std.crypto.tls.hkdfExpandLabel(
                        HkdfSha256,
                        secret,
                        labels.hp,
                        "",
                        Aes128Gcm.key_length,
                    );
            },
            .chacha20_poly1305_sha256 => {
                keys.key = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    secret,
                    labels.key,
                    "",
                    ChaCha20Poly1305.key_length,
                );
                keys.hp = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    secret,
                    labels.hp,
                    "",
                    ChaCha20Poly1305.key_length,
                );
            },
        }
        return keys;
    }

    pub fn protect(
        self: Keys,
        packet_number: u64,
        associated_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[tag_len]u8,
    ) error{InvalidPayloadLength}!void {
        if (ciphertext.len != plaintext.len) {
            return error.InvalidPayloadLength;
        }
        const nonce = packetNonce(self.iv, packet_number);
        switch (self.suite) {
            .aes_128_gcm_sha256 => Aes128Gcm.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
                self.key[0..Aes128Gcm.key_length].*,
            ),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
                self.key,
            ),
        }
    }

    pub fn open(
        self: Keys,
        packet_number: u64,
        associated_data: []const u8,
        ciphertext: []const u8,
        tag: [tag_len]u8,
        plaintext: []u8,
    ) (error{InvalidPayloadLength} ||
        std.crypto.errors.AuthenticationError)!void {
        if (plaintext.len != ciphertext.len) {
            return error.InvalidPayloadLength;
        }
        const nonce = packetNonce(self.iv, packet_number);
        switch (self.suite) {
            .aes_128_gcm_sha256 => try Aes128Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
                self.key[0..Aes128Gcm.key_length].*,
            ),
            .chacha20_poly1305_sha256 => try ChaCha20Poly1305.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
                self.key,
            ),
        }
    }

    pub fn headerProtectionMask(
        self: Keys,
        sample: [sample_len]u8,
    ) [mask_len]u8 {
        switch (self.suite) {
            .aes_128_gcm_sha256 => {
                const aes = std.crypto.core.aes.Aes128.initEnc(
                    self.hp[0..Aes128Gcm.key_length].*,
                );
                var encrypted: [sample_len]u8 = undefined;
                aes.encrypt(&encrypted, &sample);
                return encrypted[0..mask_len].*;
            },
            .chacha20_poly1305_sha256 => {
                const counter = std.mem.readInt(
                    u32,
                    sample[0..4],
                    .little,
                );
                const nonce = sample[4..16].*;
                var mask: [mask_len]u8 = undefined;
                ChaCha20IETF.stream(&mask, counter, self.hp, nonce);
                return mask;
            },
        }
    }
};

pub fn packetNonce(iv: [iv_len]u8, packet_number: u64) [iv_len]u8 {
    return common.packetNonce(iv, packet_number);
}
