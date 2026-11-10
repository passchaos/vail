const std = @import("std");
const initial = @import("initial.zig");
const retry = @import("retry.zig");
const key_schedule = @import("../tls/crypto/key_schedule.zig");
const tls_secret = @import("../tls/crypto/secret.zig");
const tls_transcript = @import("../tls/crypto/transcript.zig");
const tls_secrets = @import("tls_secrets.zig");
const traffic = @import("traffic_crypto.zig");
const transport_parameters = @import("transport_parameters.zig");

test "QUIC v1 Initial secrets match RFC 9001 vectors" {
    const dcid = [_]u8{
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
    };
    const secrets = try initial.deriveSecretsForVersion(
        initial.version_1,
        &dcid,
    );
    try expectHex(
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
        &secrets.initial_secret,
    );
    try expectHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
        secrets.client.bytes(),
    );
    try expectHex(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
        secrets.server.bytes(),
    );

    const keys = try initial.deriveKeysForVersion(initial.version_1, &dcid);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", keys.client.key[0..16]);
    try expectHex("fa044b2f42a3fd3b46fb255c", &keys.client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", keys.client.hp[0..16]);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", keys.server.key[0..16]);
    try expectHex("0ac1493ca1905853b0bba03e", &keys.server.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", keys.server.hp[0..16]);
}

test "QUIC v2 Initial secrets use version-specific labels" {
    const dcid = [_]u8{
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
    };
    const secrets = try initial.deriveSecretsForVersion(
        initial.version_2,
        &dcid,
    );
    try expectHex(
        "2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba",
        &secrets.initial_secret,
    );
    try expectHex(
        "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b",
        secrets.client.bytes(),
    );

    const keys = try initial.deriveKeysForVersion(initial.version_2, &dcid);
    try expectHex("8b1a0bc121284290a29e0971b5cd045d", keys.client.key[0..16]);
    try expectHex("91f73e2351d8fa91660e909f", &keys.client.iv);
    try expectHex("45b95e15235d6f45a6b19cbcb0294ba9", keys.client.hp[0..16]);
    try expectHex("82db637861d55e1d011f19ea71d5d2a7", keys.server.key[0..16]);
    try expectHex("dd13c276499c0249d3310652", &keys.server.iv);
    try expectHex("edf6d05c83121201b436e16877593c3a", keys.server.hp[0..16]);
}

test "QUIC Retry integrity tags match v1 and v2 vectors" {
    const odcid = [_]u8{
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
    };
    const retry_v1_without_tag = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e,
    };
    const retry_v2_without_tag = [_]u8{
        0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e,
    };
    var pseudo: [64]u8 = undefined;
    const tag_v1 = try retry.computeIntegrityTagForVersion(
        initial.version_1,
        &odcid,
        &retry_v1_without_tag,
        &pseudo,
    );
    try expectHex("04a265ba2eff4d829058fb3f0f2496ba", &tag_v1);
    const tag_v2 = try retry.computeIntegrityTagForVersion(
        initial.version_2,
        &odcid,
        &retry_v2_without_tag,
        &pseudo,
    );
    try expectHex("c8646ce8bfe33952d955543665dcc7b6", &tag_v2);

    var full_retry_v1: [retry_v1_without_tag.len + retry.tag_len]u8 =
        undefined;
    @memcpy(full_retry_v1[0..retry_v1_without_tag.len], &retry_v1_without_tag);
    @memcpy(full_retry_v1[retry_v1_without_tag.len..], &tag_v1);
    try retry.verifyIntegrityTagForVersion(
        initial.version_1,
        &odcid,
        &full_retry_v1,
        &pseudo,
    );
    full_retry_v1[full_retry_v1.len - 1] ^= 1;
    try std.testing.expectError(
        error.RetryIntegrityTagMismatch,
        retry.verifyIntegrityTagForVersion(
            initial.version_1,
            &odcid,
            &full_retry_v1,
            &pseudo,
        ),
    );
}

test "QUIC transport parameters extension exposes opaque payloads" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try transport_parameters.appendExtension(
        &out,
        std.testing.allocator,
        &.{ 0x40, 0x75, 0x01 },
    );
    const found = (try transport_parameters.findExtension(out.items)).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x40, 0x75, 0x01 }, found);
}

test "TLS runtime secrets install QUIC handshake and application keys" {
    const shared = [_]u8{0x71} ** key_schedule.secret_len;
    const transcript_hash = tls_transcript.Digest{
        .hash = .sha256,
        .storage = ([_]u8{0x72} ** 32) ++ ([_]u8{0} ** 16),
    };
    const handshake = try key_schedule.deriveHandshakeFor(
        .sha256,
        &shared,
        transcript_hash,
        null,
    );
    const handshake_keys = try tls_secrets.handshakeKeys(
        .aes_128_gcm_sha256,
        handshake,
        traffic.labels_v1,
    );
    try expectHex(
        "2091977ff09711cb6ecb10a8efcb4a7f",
        handshake_keys.client.key[0..16],
    );
    try expectHex(
        "387f496db9c68aaeae7c480e87e21e27",
        handshake_keys.server.key[0..16],
    );

    const application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        transcript_hash,
    );
    const application_keys = try tls_secrets.applicationKeys(
        .aes_128_gcm_sha256,
        application,
        traffic.labels_v1,
    );
    try expectHex(
        "1015f929303993a072958f5a60c2b6c6",
        application_keys.client.key[0..16],
    );
    try expectHex(
        "6dedad711b485ffeb67c374e11a8638a",
        application_keys.server.key[0..16],
    );
    try std.testing.expectError(
        error.HashMismatch,
        tls_secrets.keysForSecret(
            .aes_256_gcm_sha384,
            tls_secret.Secret.fromSha256([_]u8{0} ** 32),
            traffic.labels_v1,
        ),
    );
}

test "TLS runtime PSKs install QUIC 0-RTT client keys" {
    const psk = tls_secret.Secret.fromSha256([_]u8{0x73} ** 32);
    const client_hello_hash = tls_transcript.Digest{
        .hash = .sha256,
        .storage = ([_]u8{0x72} ** 32) ++ ([_]u8{0} ** 16),
    };
    const early_keys = try tls_secrets.clientEarlyKeys(
        .aes_128_gcm_sha256,
        psk,
        client_hello_hash,
        traffic.labels_v1,
    );
    try expectHex("8a42265aaa292e0e3fb6b73745bb04f4", early_keys.key[0..16]);
    try expectHex("5219bf25ede695ea90f0f858", &early_keys.iv);
    try expectHex("a1868326687403f478922e352b42a7d3", early_keys.hp[0..16]);
}

test "QUIC AEAD traffic suites round-trip without allocation" {
    const secret = [_]u8{0x42} ** traffic.secret_len;
    inline for (.{
        traffic.Suite.aes_128_gcm_sha256,
        .aes_128_ccm_sha256,
        .chacha20_poly1305_sha256,
    }) |suite| {
        const keys = try traffic.Keys.derive(suite, secret, .{});
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

test "AES-CCM QUIC traffic matches an independent vector" {
    const keys = try traffic.Keys.derive(
        .aes_128_ccm_sha256,
        [_]u8{0x42} ** traffic.secret_len,
        .{},
    );
    try expectHex("da4f3a4cddb4f22a0a3480aa02d23e16", keys.key[0..16]);
    try expectHex("55c937e2671304101facd192", &keys.iv);
    try expectHex("1fa5fdcb2578e7f3bc03e9965473aa42", keys.hp[0..16]);

    const plaintext = "Vail QUIC traffic";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [traffic.tag_len]u8 = undefined;
    try keys.protect(7, "header", plaintext, &ciphertext, &tag);
    try expectHex("b1ff573b2ba4a9e064c7beae5c0cb7c942", &ciphertext);
    try expectHex("2775f00aa06097325ac2a26894602d99", &tag);
    try expectHex(
        "6c1e2bc551",
        &keys.headerProtectionMask([_]u8{0} ** traffic.sample_len),
    );
}

test "QUIC rejects TLS AES-128-CCM-8 explicitly" {
    const secret = tls_secret.Secret.fromSha256([_]u8{0x42} ** traffic.secret_len);
    try std.testing.expect(!traffic.Suite.aes_128_ccm_8_sha256.quicCompatible());
    try std.testing.expectError(
        error.UnsupportedCipherSuite,
        traffic.Keys.deriveChecked(
            .aes_128_ccm_8_sha256,
            secret,
            traffic.labels_v1,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedCipherSuite,
        traffic.nextTrafficSecret(
            .aes_128_ccm_8_sha256,
            secret,
            traffic.labels_v1,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedCipherSuite,
        tls_secrets.keysForSecret(
            .aes_128_ccm_8_sha256,
            secret,
            traffic.labels_v1,
        ),
    );
}

test "prepared QUIC traffic keys match value-key suites" {
    const plaintext = "prepared Vail QUIC traffic";
    const aad = "header";
    inline for (.{
        traffic.Suite.aes_128_gcm_sha256,
        traffic.Suite.aes_128_ccm_sha256,
        traffic.Suite.aes_256_gcm_sha384,
        traffic.Suite.chacha20_poly1305_sha256,
        traffic.Suite.sm4_gcm_sm3,
        traffic.Suite.sm4_ccm_sm3,
    }) |suite| {
        const secret: tls_secret.Secret = switch (suite.hash()) {
            .sha256 => .fromSha256([_]u8{0x61} ** 32),
            .sha384 => .fromSha384([_]u8{0x62} ** 48),
            .sm3 => .fromSm3([_]u8{0x63} ** 32),
        };
        const keys = try traffic.Keys.deriveChecked(suite, secret, .{});
        var prepared = traffic.PreparedKeys.init(keys);
        defer prepared.deinit();

        var expected_ciphertext: [plaintext.len]u8 = undefined;
        var expected_tag: [traffic.tag_len]u8 = undefined;
        try keys.protect(23, aad, plaintext, &expected_ciphertext, &expected_tag);
        var actual_ciphertext: [plaintext.len]u8 = undefined;
        var actual_tag: [traffic.tag_len]u8 = undefined;
        try prepared.protect(23, aad, plaintext, &actual_ciphertext, &actual_tag);
        try std.testing.expectEqualSlices(
            u8,
            &expected_ciphertext,
            &actual_ciphertext,
        );
        try std.testing.expectEqualSlices(u8, &expected_tag, &actual_tag);

        var opened: [plaintext.len]u8 = undefined;
        try prepared.open(23, aad, &actual_ciphertext, actual_tag, &opened);
        try std.testing.expectEqualStrings(plaintext, &opened);
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

test "SM4-CCM SM3 QUIC traffic uses the RFC 8998 primitive" {
    const secret = [_]u8{0x42} ** traffic.secret_len;
    const keys = try traffic.Keys.deriveChecked(
        .sm4_ccm_sm3,
        .fromSm3(secret),
        .{},
    );
    try std.testing.expect(traffic.Suite.sm4_ccm_sm3.quicCompatible());
    try expectHex("afb128b472334cfca2b05656defda9e7", keys.key[0..16]);
    try expectHex("3b8476ed92aea6118da10b2d", &keys.iv);
    try expectHex("8dabfe0cd76f165e49ea063308121f02", keys.hp[0..16]);

    const plaintext = "Vail SM4-CCM QUIC";
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
    try std.testing.expectEqual([_]u8{0} ** plaintext.len, opened);
}

test "QUIC key update keeps header protection key stable" {
    const secret = [_]u8{
        0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
        0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
        0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
        0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
    };
    const keys = try traffic.Keys.deriveChecked(
        .chacha20_poly1305_sha256,
        .fromSha256(secret),
        traffic.labels_v1,
    );
    const next_secret = try traffic.nextTrafficSecret(
        .chacha20_poly1305_sha256,
        .fromSha256(secret),
        traffic.labels_v1,
    );
    try expectHex(
        "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
        next_secret.bytes(),
    );
    const next = try keys.nextKeyPhase(traffic.labels_v1);
    try std.testing.expectEqualSlices(u8, &keys.hp, &next.hp);
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &next.key));

    const next_v2 = try traffic.nextTrafficSecret(
        .chacha20_poly1305_sha256,
        .fromSha256(secret),
        traffic.labels_v2,
    );
    try expectHex(
        "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88",
        next_v2.bytes(),
    );
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected: [64]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(
        expected[0 .. expected_hex.len / 2],
        expected_hex,
    );
    try std.testing.expectEqualSlices(u8, decoded, actual);
}
