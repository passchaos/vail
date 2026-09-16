//! QUIC traffic-secret packet cryptography for TLS 1.3 cipher suites.
//!
//! Header construction, packet-number reconstruction, and key-phase state are
//! transport concerns. This module owns key derivation, nonce construction,
//! AEAD payload protection, and header-protection masks.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const backend = @import("../crypto/backend.zig");
const sm3 = @import("../crypto/sm3.zig");
const sm4 = @import("../crypto/sm4.zig");
const cipher_suite = @import("../tls/cipher_suite.zig");
const common = @import("traffic_crypto/common.zig");
const tls_secret = @import("../tls/secret.zig");

/// SHA-384 traffic protection is exposed separately until the higher-level TLS
/// key schedule can carry both 32-byte and 48-byte traffic secrets.
pub const aes256_sha384 =
    @import("traffic_crypto/aes256_sha384.zig");

const HmacSm3 = std.crypto.auth.hmac.Hmac(sm3.Hash);
const HkdfSm3 = std.crypto.kdf.hkdf.Hkdf(HmacSm3);

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
    std.debug.assert(sm4.Gcm.key_length <= max_key_len);
    std.debug.assert(sm4.Gcm.nonce_length == iv_len);
    std.debug.assert(sm4.Gcm.tag_length == tag_len);
}

/// QUIC uses the TLS-negotiated suite identity directly.  Keeping one enum in
/// the TLS layer prevents adapters from translating or accidentally assigning
/// different limits to the same wire value.
pub const Suite = cipher_suite.Suite;

pub const Labels = common.Labels;
pub const labels_v1 = common.labels_v1;
pub const labels_v2 = common.labels_v2;

pub const Keys = struct {
    suite: Suite,
    /// Source-compatible SHA-256 secret view.
    secret: [secret_len]u8,
    traffic_secret: tls_secret.Secret =
        .fromSha256([_]u8{0} ** secret_len),
    key: [max_key_len]u8,
    iv: [iv_len]u8,
    hp: [max_key_len]u8,

    pub fn derive(
        suite: Suite,
        secret: [secret_len]u8,
        labels: Labels,
    ) Keys {
        return deriveChecked(
            suite,
            .fromSha256(secret),
            labels,
        ) catch unreachable;
    }

    pub fn deriveChecked(
        suite: Suite,
        traffic_secret: tls_secret.Secret,
        labels: Labels,
    ) error{HashMismatch}!Keys {
        if (traffic_secret.hash != suite.hash()) {
            return error.HashMismatch;
        }
        var compatibility_secret = [_]u8{0} ** secret_len;
        if (traffic_secret.hash == .sha256) {
            compatibility_secret =
                traffic_secret.sha256() catch unreachable;
        }
        var keys = Keys{
            .suite = suite,
            .secret = compatibility_secret,
            .traffic_secret = traffic_secret,
            .key = [_]u8{0} ** max_key_len,
            .iv = undefined,
            .hp = [_]u8{0} ** max_key_len,
        };
        switch (suite) {
            .aes_128_gcm_sha256 => {
                const sha256_secret =
                    traffic_secret.sha256() catch unreachable;
                keys.iv = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    sha256_secret,
                    labels.iv,
                    "",
                    iv_len,
                );
                keys.key[0..Aes128Gcm.key_length].* =
                    std.crypto.tls.hkdfExpandLabel(
                        HkdfSha256,
                        sha256_secret,
                        labels.key,
                        "",
                        Aes128Gcm.key_length,
                    );
                keys.hp[0..Aes128Gcm.key_length].* =
                    std.crypto.tls.hkdfExpandLabel(
                        HkdfSha256,
                        sha256_secret,
                        labels.hp,
                        "",
                        Aes128Gcm.key_length,
                    );
            },
            .aes_256_gcm_sha384 => {
                const derived = aes256_sha384.Keys.derive(
                    traffic_secret.sha384() catch unreachable,
                    labels,
                );
                keys.iv = derived.iv;
                keys.key = derived.key;
                keys.hp = derived.hp;
            },
            .sm4_gcm_sm3 => {
                const sm3_secret =
                    traffic_secret.sm3() catch unreachable;
                keys.iv = std.crypto.tls.hkdfExpandLabel(
                    HkdfSm3,
                    sm3_secret,
                    labels.iv,
                    "",
                    iv_len,
                );
                keys.key[0..sm4.key_len].* =
                    std.crypto.tls.hkdfExpandLabel(
                        HkdfSm3,
                        sm3_secret,
                        labels.key,
                        "",
                        sm4.key_len,
                    );
                keys.hp[0..sm4.key_len].* =
                    std.crypto.tls.hkdfExpandLabel(
                        HkdfSm3,
                        sm3_secret,
                        labels.hp,
                        "",
                        sm4.key_len,
                    );
            },
            .chacha20_poly1305_sha256 => {
                const sha256_secret =
                    traffic_secret.sha256() catch unreachable;
                keys.iv = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    sha256_secret,
                    labels.iv,
                    "",
                    iv_len,
                );
                keys.key = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    sha256_secret,
                    labels.key,
                    "",
                    ChaCha20Poly1305.key_length,
                );
                keys.hp = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    sha256_secret,
                    labels.hp,
                    "",
                    ChaCha20Poly1305.key_length,
                );
            },
        }
        return keys;
    }

    /// Derive the next QUIC 1-RTT key phase.
    ///
    /// RFC 9001 updates the packet-protection secret, key, and IV, but keeps
    /// the header-protection key stable for the connection. Transport code
    /// should prefer this helper over a raw `deriveChecked(next_secret, ...)`
    /// during key updates so it cannot accidentally rotate `hp`.
    pub fn nextKeyPhase(
        self: Keys,
        labels: Labels,
    ) error{HashMismatch}!Keys {
        const next_secret = try nextTrafficSecret(
            self.suite,
            self.traffic_secret,
            labels,
        );
        var next = try deriveChecked(self.suite, next_secret, labels);
        next.hp = self.hp;
        return next;
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
            .aes_128_gcm_sha256 => {
                if (protectAwsLcAesGcm(
                    .aes_128_gcm,
                    self.key[0..Aes128Gcm.key_length],
                    nonce,
                    associated_data,
                    plaintext,
                    ciphertext,
                    tag,
                )) return;
                Aes128Gcm.encrypt(
                    ciphertext,
                    tag,
                    plaintext,
                    associated_data,
                    nonce,
                    self.key[0..Aes128Gcm.key_length].*,
                );
            },
            .aes_256_gcm_sha384 => {
                if (protectAwsLcAesGcm(
                    .aes_256_gcm,
                    &self.key,
                    nonce,
                    associated_data,
                    plaintext,
                    ciphertext,
                    tag,
                )) return;
                Aes256Gcm.encrypt(
                    ciphertext,
                    tag,
                    plaintext,
                    associated_data,
                    nonce,
                    self.key,
                );
            },
            .sm4_gcm_sm3 => sm4.Gcm.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
                self.key[0..sm4.key_len].*,
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
            .aes_128_gcm_sha256 => {
                if (openAwsLcAesGcm(
                    .aes_128_gcm,
                    self.key[0..Aes128Gcm.key_length],
                    nonce,
                    associated_data,
                    ciphertext,
                    tag,
                    plaintext,
                )) return;
                try Aes128Gcm.decrypt(
                    plaintext,
                    ciphertext,
                    tag,
                    associated_data,
                    nonce,
                    self.key[0..Aes128Gcm.key_length].*,
                );
            },
            .aes_256_gcm_sha384 => {
                if (openAwsLcAesGcm(
                    .aes_256_gcm,
                    &self.key,
                    nonce,
                    associated_data,
                    ciphertext,
                    tag,
                    plaintext,
                )) return;
                try Aes256Gcm.decrypt(
                    plaintext,
                    ciphertext,
                    tag,
                    associated_data,
                    nonce,
                    self.key,
                );
            },
            .sm4_gcm_sm3 => try sm4.Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
                self.key[0..sm4.key_len].*,
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
            .aes_256_gcm_sha384 => {
                const aes = std.crypto.core.aes.Aes256.initEnc(
                    self.hp,
                );
                var encrypted: [sample_len]u8 = undefined;
                aes.encrypt(&encrypted, &sample);
                return encrypted[0..mask_len].*;
            },
            .sm4_gcm_sm3 => {
                const schedule = sm4.KeySchedule.init(
                    self.hp[0..sm4.key_len].*,
                );
                const encrypted = schedule.encryptBlock(sample);
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

/// RFC 9001 §6.1 QUIC key update secret derivation.
///
/// QUIC replaces TLS KeyUpdate with the packet-layer Key Phase bit. The
/// transport owns the phase transition rules and packet-number bookkeeping;
/// Vail owns only the version-specific HKDF label and hash-bound secret
/// derivation used to install the next 1-RTT packet-protection keys.
pub fn nextTrafficSecret(
    suite: Suite,
    traffic_secret: tls_secret.Secret,
    labels: Labels,
) error{HashMismatch}!tls_secret.Secret {
    if (traffic_secret.hash != suite.hash()) return error.HashMismatch;
    return switch (suite) {
        .aes_128_gcm_sha256,
        .chacha20_poly1305_sha256,
        => .fromSha256(std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            traffic_secret.sha256() catch unreachable,
            labels.ku,
            "",
            tls_secret.Hash.sha256.len(),
        )),
        .aes_256_gcm_sha384 => .fromSha384(std.crypto.tls.hkdfExpandLabel(
            HkdfSha384,
            traffic_secret.sha384() catch unreachable,
            labels.ku,
            "",
            tls_secret.Hash.sha384.len(),
        )),
        .sm4_gcm_sm3 => .fromSm3(std.crypto.tls.hkdfExpandLabel(
            HkdfSm3,
            traffic_secret.sm3() catch unreachable,
            labels.ku,
            "",
            tls_secret.Hash.sm3.len(),
        )),
    };
}

pub const PreparedKeys = struct {
    keys: Keys,
    aes_gcm: ?backend.AesGcmContext = null,

    /// Prepare packet-protection state for repeated operations with one key.
    /// In AWS-LC linked builds this caches EVP_AEAD_CTX precomputation so the
    /// hot packet path avoids per-packet context initialization. Non-AES suites
    /// and non-linked builds retain the allocation-free Zig implementation.
    pub fn init(keys: Keys) PreparedKeys {
        return .{
            .keys = keys,
            .aes_gcm = switch (keys.suite) {
                .aes_128_gcm_sha256 => backend.AesGcmContext.init(
                    .aes_128_gcm,
                    keys.key[0..Aes128Gcm.key_length],
                ),
                .aes_256_gcm_sha384 => backend.AesGcmContext.init(
                    .aes_256_gcm,
                    &keys.key,
                ),
                else => null,
            },
        };
    }

    pub fn deinit(self: *PreparedKeys) void {
        if (self.aes_gcm) |*ctx| ctx.deinit();
        self.* = undefined;
    }

    pub fn protect(
        self: *const PreparedKeys,
        packet_number: u64,
        associated_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[tag_len]u8,
    ) error{InvalidPayloadLength}!void {
        if (ciphertext.len != plaintext.len) {
            return error.InvalidPayloadLength;
        }
        const nonce = packetNonce(self.keys.iv, packet_number);
        switch (self.keys.suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => if (self.aes_gcm) |*ctx| {
                if (ctx.seal(&nonce, associated_data, plaintext, ciphertext, tag)) {
                    return;
                }
            },
            else => {},
        }
        try self.keys.protect(
            packet_number,
            associated_data,
            plaintext,
            ciphertext,
            tag,
        );
    }

    pub fn open(
        self: *const PreparedKeys,
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
        const nonce = packetNonce(self.keys.iv, packet_number);
        switch (self.keys.suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => if (self.aes_gcm) |*ctx| {
                if (ctx.open(&nonce, associated_data, ciphertext, &tag, plaintext)) {
                    return;
                }
                return error.AuthenticationFailed;
            },
            else => {},
        }
        try self.keys.open(
            packet_number,
            associated_data,
            ciphertext,
            tag,
            plaintext,
        );
    }

    pub fn headerProtectionMask(
        self: *const PreparedKeys,
        sample: [sample_len]u8,
    ) [mask_len]u8 {
        return self.keys.headerProtectionMask(sample);
    }
};

pub fn packetNonce(iv: [iv_len]u8, packet_number: u64) [iv_len]u8 {
    return common.packetNonce(iv, packet_number);
}

fn protectAwsLcAesGcm(
    suite: backend.AesGcmSuite,
    key: []const u8,
    nonce: [iv_len]u8,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[tag_len]u8,
) bool {
    var ctx = backend.AesGcmContext.init(suite, key) orelse return false;
    defer ctx.deinit();
    return ctx.seal(&nonce, associated_data, plaintext, ciphertext, tag);
}

fn openAwsLcAesGcm(
    suite: backend.AesGcmSuite,
    key: []const u8,
    nonce: [iv_len]u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: [tag_len]u8,
    plaintext: []u8,
) bool {
    var ctx = backend.AesGcmContext.init(suite, key) orelse return false;
    defer ctx.deinit();
    return ctx.open(&nonce, associated_data, ciphertext, &tag, plaintext);
}
