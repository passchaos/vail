//! TLS 1.3 record-layer AEAD protection.
//!
//! This module implements RFC 8446 application-data records: legacy outer
//! content type 23, version 0x0303, sequence-number nonce XOR, inner content
//! type/padding, and AEAD authentication over the five-byte record header.

const std = @import("std");

const prepared_aes_gcm = @import("../crypto/aes_gcm.zig");
const sm4 = @import("../crypto/sm4.zig");
const cipher_suite = @import("cipher_suite.zig");
const secret = @import("secret.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.Hkdf(HmacSha256);
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
const HmacSm3 = std.crypto.auth.hmac.Hmac(@import("../crypto/sm3.zig").Hash);
const HkdfSm3 = std.crypto.kdf.hkdf.Hkdf(HmacSm3);

pub const content_type_application_data: u8 = 23;
pub const content_type_handshake: u8 = 22;
pub const content_type_alert: u8 = 21;
pub const legacy_record_version = [_]u8{ 0x03, 0x03 };
pub const header_len = 5;
pub const iv_len = 12;
pub const tag_len = 16;
pub const max_key_len = 32;
pub const max_plaintext_len = 1 << 14;
pub const max_ciphertext_len = max_plaintext_len + 256;
pub const max_inner_plaintext_len = max_ciphertext_len - tag_len;
pub const max_record_len = header_len + max_ciphertext_len;

pub const Error = error{
    HashMismatch,
    InvalidRecord,
    InvalidPlaintextLength,
    InvalidCiphertextLength,
    UnsupportedContentType,
    AuthenticationFailed,
};

pub const Keys = struct {
    suite: cipher_suite.Suite,
    key: [max_key_len]u8,
    iv: [iv_len]u8,
    aes_gcm: ?prepared_aes_gcm.Context = null,

    pub fn derive(
        suite: cipher_suite.Suite,
        traffic_secret: secret.Secret,
    ) Error!Keys {
        if (traffic_secret.hash != suite.hash()) return error.HashMismatch;
        var keys = Keys{
            .suite = suite,
            .key = [_]u8{0} ** max_key_len,
            .iv = undefined,
        };
        switch (suite) {
            .aes_128_gcm_sha256 => {
                const value = traffic_secret.sha256() catch return error.HashMismatch;
                keys.key[0..16].* = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    value,
                    "key",
                    "",
                    16,
                );
                keys.iv = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    value,
                    "iv",
                    "",
                    iv_len,
                );
                keys.aes_gcm = prepared_aes_gcm.Context.init128(
                    keys.key[0..Aes128Gcm.key_length].*,
                );
            },
            .aes_256_gcm_sha384 => {
                const value = traffic_secret.sha384() catch return error.HashMismatch;
                keys.key = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha384,
                    value,
                    "key",
                    "",
                    32,
                );
                keys.iv = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha384,
                    value,
                    "iv",
                    "",
                    iv_len,
                );
                keys.aes_gcm = prepared_aes_gcm.Context.init256(keys.key);
            },
            .chacha20_poly1305_sha256 => {
                const value = traffic_secret.sha256() catch return error.HashMismatch;
                keys.key = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    value,
                    "key",
                    "",
                    32,
                );
                keys.iv = std.crypto.tls.hkdfExpandLabel(
                    HkdfSha256,
                    value,
                    "iv",
                    "",
                    iv_len,
                );
            },
            .sm4_gcm_sm3 => {
                const value = traffic_secret.sm3() catch return error.HashMismatch;
                keys.key[0..16].* = std.crypto.tls.hkdfExpandLabel(
                    HkdfSm3,
                    value,
                    "key",
                    "",
                    16,
                );
                keys.iv = std.crypto.tls.hkdfExpandLabel(
                    HkdfSm3,
                    value,
                    "iv",
                    "",
                    iv_len,
                );
            },
        }
        return keys;
    }

    pub fn deinit(self: *Keys) void {
        if (self.aes_gcm) |*context| context.deinit();
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
        self.* = undefined;
    }

    pub fn seal(
        self: *const Keys,
        sequence_number: u64,
        inner_type: u8,
        plaintext: []const u8,
        record: []u8,
    ) Error!usize {
        return self.sealPadded(
            sequence_number,
            inner_type,
            plaintext,
            0,
            record,
        );
    }

    /// Seal a TLSInnerPlaintext with explicit zero padding.
    ///
    /// The returned TLSCiphertext always respects RFC 8446 section 5.2's
    /// `2^14 + 256` byte length limit. Padding hides the exact content length;
    /// callers remain responsible for choosing a padding policy.
    pub fn sealPadded(
        self: *const Keys,
        sequence_number: u64,
        inner_type: u8,
        plaintext: []const u8,
        padding_len: usize,
        record: []u8,
    ) Error!usize {
        if (!validInnerType(inner_type)) return error.UnsupportedContentType;
        if (plaintext.len > max_plaintext_len or
            padding_len > max_inner_plaintext_len - plaintext.len - 1)
        {
            return error.InvalidPlaintextLength;
        }
        const ciphertext_len = plaintext.len + 1 + padding_len;
        const record_len = header_len + ciphertext_len + tag_len;
        if (record.len < record_len) return error.InvalidCiphertextLength;

        record[0] = content_type_application_data;
        record[1..3].* = legacy_record_version;
        std.mem.writeInt(u16, record[3..5], @intCast(ciphertext_len + tag_len), .big);
        var inner: [max_inner_plaintext_len]u8 = undefined;
        @memcpy(inner[0..plaintext.len], plaintext);
        inner[plaintext.len] = inner_type;
        @memset(inner[plaintext.len + 1 .. ciphertext_len], 0);
        const nonce = recordNonce(self.iv, sequence_number);
        const ciphertext = record[header_len..][0..ciphertext_len];
        const tag = record[header_len + ciphertext_len ..][0..tag_len];
        switch (self.suite) {
            .aes_128_gcm_sha256 => {
                if (self.aes_gcm) |*context| context.encrypt(
                    ciphertext,
                    tag,
                    inner[0..ciphertext_len],
                    record[0..header_len],
                    nonce,
                ) else Aes128Gcm.encrypt(
                    ciphertext,
                    tag,
                    inner[0..ciphertext_len],
                    record[0..header_len],
                    nonce,
                    self.key[0..Aes128Gcm.key_length].*,
                );
            },
            .aes_256_gcm_sha384 => {
                if (self.aes_gcm) |*context| context.encrypt(
                    ciphertext,
                    tag,
                    inner[0..ciphertext_len],
                    record[0..header_len],
                    nonce,
                ) else Aes256Gcm.encrypt(
                    ciphertext,
                    tag,
                    inner[0..ciphertext_len],
                    record[0..header_len],
                    nonce,
                    self.key,
                );
            },
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.encrypt(ciphertext, tag, inner[0..ciphertext_len], record[0..header_len], nonce, self.key),
            .sm4_gcm_sm3 => sm4.Gcm.encrypt(ciphertext, tag, inner[0..ciphertext_len], record[0..header_len], nonce, self.key[0..16].*),
        }
        return record_len;
    }

    pub fn open(
        self: *const Keys,
        sequence_number: u64,
        record: []const u8,
        plaintext: []u8,
    ) Error!Opened {
        if (record.len < header_len + tag_len + 1) return error.InvalidRecord;
        if (record[0] != content_type_application_data or
            !std.mem.eql(u8, record[1..3], &legacy_record_version))
        {
            return error.InvalidRecord;
        }
        const encrypted_len = std.mem.readInt(u16, record[3..5], .big);
        if (encrypted_len != record.len - header_len or
            encrypted_len <= tag_len or
            encrypted_len > max_ciphertext_len)
        {
            return error.InvalidRecord;
        }
        const ciphertext_len = encrypted_len - tag_len;
        if (plaintext.len < ciphertext_len) return error.InvalidPlaintextLength;
        const nonce = recordNonce(self.iv, sequence_number);
        const ciphertext = record[header_len..][0..ciphertext_len];
        const tag = record[header_len + ciphertext_len ..][0..tag_len].*;
        switch (self.suite) {
            .aes_128_gcm_sha256 => {
                if (self.aes_gcm) |*context| context.decrypt(
                    plaintext[0..ciphertext_len],
                    ciphertext,
                    tag,
                    record[0..header_len],
                    nonce,
                ) catch return error.AuthenticationFailed else Aes128Gcm.decrypt(
                    plaintext[0..ciphertext_len],
                    ciphertext,
                    tag,
                    record[0..header_len],
                    nonce,
                    self.key[0..Aes128Gcm.key_length].*,
                ) catch return error.AuthenticationFailed;
            },
            .aes_256_gcm_sha384 => {
                if (self.aes_gcm) |*context| context.decrypt(
                    plaintext[0..ciphertext_len],
                    ciphertext,
                    tag,
                    record[0..header_len],
                    nonce,
                ) catch return error.AuthenticationFailed else Aes256Gcm.decrypt(
                    plaintext[0..ciphertext_len],
                    ciphertext,
                    tag,
                    record[0..header_len],
                    nonce,
                    self.key,
                ) catch return error.AuthenticationFailed;
            },
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.decrypt(plaintext[0..ciphertext_len], ciphertext, tag, record[0..header_len], nonce, self.key) catch return error.AuthenticationFailed,
            .sm4_gcm_sm3 => sm4.Gcm.decrypt(plaintext[0..ciphertext_len], ciphertext, tag, record[0..header_len], nonce, self.key[0..16].*) catch return error.AuthenticationFailed,
        }
        var opened_len = ciphertext_len;
        while (opened_len > 0 and plaintext[opened_len - 1] == 0) {
            opened_len -= 1;
        }
        if (opened_len == 0) return error.InvalidRecord;
        opened_len -= 1;
        if (opened_len > max_plaintext_len) return error.InvalidRecord;
        const inner_type = plaintext[opened_len];
        if (!validInnerType(inner_type)) return error.InvalidRecord;
        return .{ .content_type = inner_type, .len = opened_len };
    }
};

pub const Opened = struct {
    content_type: u8,
    len: usize,
};

pub fn recordNonce(iv: [iv_len]u8, sequence_number: u64) [iv_len]u8 {
    var nonce = iv;
    var seq: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq, sequence_number, .big);
    for (seq, 0..) |byte, index| nonce[iv_len - seq.len + index] ^= byte;
    return nonce;
}

fn validInnerType(value: u8) bool {
    return value == content_type_application_data or
        value == content_type_handshake or
        value == content_type_alert;
}

test "TLS 1.3 records round-trip and authenticate headers" {
    inline for ([_]cipher_suite.Suite{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
        .sm4_gcm_sm3,
    }) |suite| {
        const tls_secret = switch (suite.hash()) {
            .sha256 => secret.Secret.fromSha256([_]u8{0x42} ** 32),
            .sha384 => secret.Secret.fromSha384([_]u8{0x43} ** 48),
            .sm3 => secret.Secret.fromSm3([_]u8{0x44} ** 32),
        };
        var keys = try Keys.derive(suite, tls_secret);
        defer keys.deinit();
        var record: [256]u8 = undefined;
        const plaintext = "record plaintext";
        const len = try keys.seal(7, content_type_application_data, plaintext, &record);
        var opened: [plaintext.len + 1]u8 = undefined;
        const parsed = try keys.open(7, record[0..len], &opened);
        try std.testing.expectEqual(content_type_application_data, parsed.content_type);
        try std.testing.expectEqualStrings(plaintext, opened[0..parsed.len]);
        record[4] ^= 1;
        try std.testing.expectError(error.InvalidRecord, keys.open(7, record[0..len], &opened));
    }
}

test "TLS 1.3 records round-trip explicit zero padding" {
    inline for ([_]cipher_suite.Suite{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
        .sm4_gcm_sm3,
    }) |suite| {
        const tls_secret = switch (suite.hash()) {
            .sha256 => secret.Secret.fromSha256([_]u8{0x52} ** 32),
            .sha384 => secret.Secret.fromSha384([_]u8{0x53} ** 48),
            .sm3 => secret.Secret.fromSm3([_]u8{0x54} ** 32),
        };
        var keys = try Keys.derive(suite, tls_secret);
        defer keys.deinit();

        const content = "padded record";
        const padding_len = 31;
        var encoded: [128]u8 = undefined;
        const encoded_len = try keys.sealPadded(
            9,
            content_type_handshake,
            content,
            padding_len,
            &encoded,
        );
        try std.testing.expectEqual(
            header_len + content.len + 1 + padding_len + tag_len,
            encoded_len,
        );

        var decoded: [128]u8 = undefined;
        const opened = try keys.open(9, encoded[0..encoded_len], &decoded);
        try std.testing.expectEqual(content_type_handshake, opened.content_type);
        try std.testing.expectEqual(content.len, opened.len);
        try std.testing.expectEqualStrings(content, decoded[0..opened.len]);
        try std.testing.expectEqual(
            content_type_handshake,
            decoded[opened.len],
        );
        try std.testing.expectEqualSlices(
            u8,
            &([_]u8{0} ** padding_len),
            decoded[opened.len + 1 ..][0..padding_len],
        );
    }
}

test "TLS 1.3 record padding enforces RFC ciphertext limits" {
    const tls_secret = secret.Secret.fromSha256([_]u8{0x62} ** 32);
    var keys = try Keys.derive(.aes_128_gcm_sha256, tls_secret);
    defer keys.deinit();

    const content = [_]u8{0x63} ** max_plaintext_len;
    const max_padding_len = max_inner_plaintext_len - content.len - 1;
    var encoded: [max_record_len]u8 = undefined;
    const encoded_len = try keys.sealPadded(
        11,
        content_type_application_data,
        &content,
        max_padding_len,
        &encoded,
    );
    try std.testing.expectEqual(max_record_len, encoded_len);

    var decoded: [max_inner_plaintext_len]u8 = undefined;
    const opened = try keys.open(11, &encoded, &decoded);
    try std.testing.expectEqual(content.len, opened.len);
    try std.testing.expectEqualSlices(u8, &content, decoded[0..opened.len]);

    try std.testing.expectError(
        error.InvalidPlaintextLength,
        keys.sealPadded(
            12,
            content_type_application_data,
            &content,
            max_padding_len + 1,
            &encoded,
        ),
    );
}
