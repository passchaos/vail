//! QUIC traffic protection for TLS_AES_256_GCM_SHA384.
//!
//! This module deliberately accepts only 48-byte SHA-384 traffic secrets.
//! Keeping it separate from the existing SHA-256 compatibility API prevents a
//! caller from deriving AES-256 keys from a truncated or incorrectly hashed
//! TLS secret while Vail's higher-level TLS state is being generalized.

const std = @import("std");
const common = @import("common.zig");
const fast_sha2 = @import("../../crypto/hash/sha512.zig");

const Sha384 = fast_sha2.Sha384;
const HmacSha384 = std.crypto.auth.hmac.Hmac(Sha384);
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const secret_len = Sha384.digest_length;
pub const key_len = Aes256Gcm.key_length;
pub const iv_len = common.iv_len;
pub const tag_len = common.tag_len;
pub const sample_len = common.sample_len;
pub const mask_len = common.mask_len;
pub const Labels = common.Labels;

comptime {
    std.debug.assert(HkdfSha384.prk_length == secret_len);
    std.debug.assert(Aes256Gcm.nonce_length == iv_len);
    std.debug.assert(Aes256Gcm.tag_length == tag_len);
}

pub const Keys = struct {
    secret: [secret_len]u8,
    key: [key_len]u8,
    iv: [iv_len]u8,
    hp: [key_len]u8,

    pub fn derive(secret: [secret_len]u8, labels: Labels) Keys {
        var expander = fast_sha2.PreparedHmac(Sha384).init(&secret);
        defer expander.deinit();
        return .{
            .secret = secret,
            .key = expander.expandLabel(labels.key, "", key_len),
            .iv = expander.expandLabel(labels.iv, "", iv_len),
            .hp = expander.expandLabel(labels.hp, "", key_len),
        };
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
        Aes256Gcm.encrypt(
            ciphertext,
            tag,
            plaintext,
            associated_data,
            common.packetNonce(self.iv, packet_number),
            self.key,
        );
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
        try Aes256Gcm.decrypt(
            plaintext,
            ciphertext,
            tag,
            associated_data,
            common.packetNonce(self.iv, packet_number),
            self.key,
        );
    }

    pub fn headerProtectionMask(
        self: Keys,
        sample: [sample_len]u8,
    ) [mask_len]u8 {
        const aes = std.crypto.core.aes.Aes256.initEnc(self.hp);
        var encrypted: [sample_len]u8 = undefined;
        aes.encrypt(&encrypted, &sample);
        return encrypted[0..mask_len].*;
    }
};

pub const confidentiality_limit: u64 = @as(u64, 1) << 23;
pub const integrity_limit: u64 = @as(u64, 1) << 52;
