const std = @import("std");
const traffic = @import("traffic_crypto.zig");

test "AES and ChaCha traffic suites round-trip without allocation" {
    const secret = [_]u8{0x42} ** traffic.secret_len;
    inline for (.{ traffic.Suite.aes_128_gcm_sha256, .chacha20_poly1305_sha256 }) |suite| {
        const keys = traffic.Keys.derive(suite, secret, .{});
        const plaintext = "Vail QUIC traffic";
        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [traffic.tag_len]u8 = undefined;
        try keys.protect(7, "header", plaintext, &ciphertext, &tag);
        var opened: [plaintext.len]u8 = undefined;
        try keys.open(7, "header", &ciphertext, tag, &opened);
        try std.testing.expectEqualStrings(plaintext, &opened);
        var bad_tag = tag;
        bad_tag[0] ^= 1;
        try std.testing.expectError(
            error.AuthenticationFailed,
            keys.open(7, "header", &ciphertext, bad_tag, &opened),
        );
    }
}

test "ChaCha header protection follows RFC 9001 sample layout" {
    const keys = traffic.Keys{
        .suite = .chacha20_poly1305_sha256,
        .secret = [_]u8{0} ** traffic.secret_len,
        .key = [_]u8{0} ** traffic.max_key_len,
        .iv = [_]u8{0} ** traffic.iv_len,
        .hp = [_]u8{0} ** traffic.max_key_len,
    };
    const sample = [traffic.sample_len]u8{
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    };
    const mask = keys.headerProtectionMask(sample);
    // RFC 8439 §2.3.2 first ChaCha20 block under all-zero key/nonce.
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x76, 0xb8, 0xe0, 0xad, 0xa0 },
        &mask,
    );
}

test "AES-256-GCM SHA-384 traffic keys match an independent vector" {
    const aes256 = traffic.aes256_sha384;
    const secret = [_]u8{0x42} ** aes256.secret_len;
    const keys = aes256.Keys.derive(secret, .{});

    // Generated independently with Python cryptography's HKDFExpand and
    // AESGCM implementations. Keeping the expected bytes here catches both
    // TLS 1.3 HKDF-label encoding errors and accidental SHA-256 fallback.
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0xfb, 0x68, 0x81, 0x1e, 0x87, 0x5a, 0x2d, 0x8f,
            0x74, 0x6b, 0x0b, 0x7d, 0x08, 0x94, 0xd9, 0xc7,
            0xf5, 0xd7, 0x48, 0x80, 0x84, 0x75, 0x5a, 0x4c,
            0x2f, 0x3e, 0x05, 0xaf, 0xbc, 0xb6, 0xa6, 0xe8,
        },
        &keys.key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0xfc, 0x70, 0x00, 0xd2, 0x21, 0x22,
            0xc0, 0x58, 0x70, 0xb4, 0xff, 0x40,
        },
        &keys.iv,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x8e, 0x2f, 0x23, 0x23, 0x74, 0xc7, 0x1f, 0xfe,
            0x78, 0xa7, 0x24, 0xbc, 0xb0, 0x55, 0x05, 0x10,
            0x1d, 0x86, 0x61, 0x3c, 0x51, 0xb9, 0x18, 0x17,
            0x68, 0xe9, 0xec, 0x75, 0xf2, 0x06, 0x25, 0x93,
        },
        &keys.hp,
    );

    const plaintext = "Vail AES-256 QUIC";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [aes256.tag_len]u8 = undefined;
    try keys.protect(7, "header", plaintext, &ciphertext, &tag);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0xf9, 0x12, 0x12, 0x1c, 0x08, 0x08,
            0xa6, 0x5a, 0xf1, 0x09, 0xab, 0x14,
            0xe8, 0xbb, 0x6d, 0x63, 0x67,
        },
        &ciphertext,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x81, 0x95, 0x11, 0x22, 0x2b, 0xac, 0xfd, 0x47,
            0xae, 0xac, 0x14, 0x80, 0x54, 0xda, 0xb7, 0xd6,
        },
        &tag,
    );

    var opened: [plaintext.len]u8 = undefined;
    try keys.open(7, "header", &ciphertext, tag, &opened);
    try std.testing.expectEqualStrings(plaintext, &opened);

    const unified = try traffic.Keys.deriveChecked(
        .aes_256_gcm_sha384,
        .fromSha384(secret),
        .{},
    );
    try std.testing.expectEqualSlices(u8, &keys.key, &unified.key);
    try std.testing.expectEqualSlices(u8, &keys.iv, &unified.iv);
    try std.testing.expectEqualSlices(u8, &keys.hp, &unified.hp);
    try std.testing.expectError(
        error.HashMismatch,
        traffic.Keys.deriveChecked(
            .aes_256_gcm_sha384,
            .fromSha256([_]u8{0} ** 32),
            .{},
        ),
    );
}

test "SM4-GCM SM3 traffic keys match independent vectors" {
    const secret = [_]u8{0x42} ** traffic.secret_len;
    const keys = try traffic.Keys.deriveChecked(
        .sm4_gcm_sm3,
        .fromSm3(secret),
        .{},
    );

    // Key/IV/HP bytes were generated with Python cryptography's HKDFExpand
    // using SM3. Ciphertext and tag were generated with OpenSSL 3.6 SM4-GCM
    // using the QUIC packet nonce for packet number 7.
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0xaf, 0xb1, 0x28, 0xb4, 0x72, 0x33, 0x4c, 0xfc,
            0xa2, 0xb0, 0x56, 0x56, 0xde, 0xfd, 0xa9, 0xe7,
        },
        keys.key[0..16],
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x3b, 0x84, 0x76, 0xed, 0x92, 0xae,
            0xa6, 0x11, 0x8d, 0xa1, 0x0b, 0x2d,
        },
        &keys.iv,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x8d, 0xab, 0xfe, 0x0c, 0xd7, 0x6f, 0x16, 0x5e,
            0x49, 0xea, 0x06, 0x33, 0x08, 0x12, 0x1f, 0x02,
        },
        keys.hp[0..16],
    );

    const plaintext = "Vail SM4 QUIC";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [traffic.tag_len]u8 = undefined;
    try keys.protect(7, "header", plaintext, &ciphertext, &tag);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x44, 0xc4, 0x53, 0x23, 0x7c, 0x37, 0x17,
            0x4f, 0x37, 0xf5, 0xda, 0x6c, 0x46,
        },
        &ciphertext,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x0a, 0xe4, 0xb4, 0x22, 0x41, 0x28, 0x23, 0x7d,
            0x21, 0xdb, 0x8c, 0x4b, 0x79, 0x76, 0x51, 0xcc,
        },
        &tag,
    );

    var opened: [plaintext.len]u8 = undefined;
    try keys.open(7, "header", &ciphertext, tag, &opened);
    try std.testing.expectEqualStrings(plaintext, &opened);

    const sample = [traffic.sample_len]u8{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };
    const mask = keys.headerProtectionMask(sample);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xb8, 0xf5, 0x37, 0xf0, 0xce },
        &mask,
    );
    try std.testing.expectError(
        error.HashMismatch,
        traffic.Keys.deriveChecked(
            .sm4_gcm_sm3,
            .fromSha256(secret),
            .{},
        ),
    );
}
