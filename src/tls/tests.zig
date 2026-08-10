const std = @import("std");
const auth = @import("auth.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_auth = @import("client_auth.zig");
const key_schedule = @import("key_schedule.zig");
const key_exchange = @import("key_exchange.zig");
const secret = @import("secret.zig");
const ticket_keyring = @import("ticket_keyring.zig");
const transcript = @import("transcript.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

test "TLS cipher suites expose protocol limits from one canonical type" {
    try std.testing.expectEqual(
        @as(u16, 0x1301),
        cipher_suite.Suite.aes_128_gcm_sha256.wireValue(),
    );
    try std.testing.expectEqual(
        @as(usize, 32),
        cipher_suite.Suite.chacha20_poly1305_sha256.keyLen(),
    );
    try std.testing.expect(
        cipher_suite.Suite.chacha20_poly1305_sha256
            .confidentialityLimit() >
            cipher_suite.Suite.aes_128_gcm_sha256
                .confidentialityLimit(),
    );
    try std.testing.expectEqual(
        @as(u16, 0x00c6),
        cipher_suite.Suite.sm4_gcm_sm3.wireValue(),
    );
    try std.testing.expectEqual(
        secret.Hash.sm3,
        cipher_suite.Suite.sm4_gcm_sm3.hash(),
    );
}

test "Certificate and Ed25519 CertificateVerify round-trip" {
    const allocator = std.testing.allocator;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try auth.writeCertificate(&certificate, allocator, &.{&public_key});
    var parsed = try auth.parseCertificate(allocator, certificate.items);
    defer parsed.deinit(allocator);

    const transcript_hash = [_]u8{0x33} ** 32;
    var verify: std.ArrayList(u8) = .empty;
    defer verify.deinit(allocator);
    try auth.writeCertificateVerify(
        &verify,
        allocator,
        .{ .ed25519 = .{ .key_pair = key_pair } },
        &transcript_hash,
    );
    const parsed_verify = try auth.parseCertificateVerify(verify.items);
    try auth.verifyCertificateVerify(
        parsed.entries[0],
        parsed_verify,
        &transcript_hash,
    );
    var wrong_hash = transcript_hash;
    wrong_hash[0] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerify(
            parsed.entries[0],
            parsed_verify,
            &wrong_hash,
        ),
    );
}

test "ECDSA P256 CertificateVerify round-trip" {
    const allocator = std.testing.allocator;
    const key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0x43} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toUncompressedSec1();
    const transcript_hash = [_]u8{0x34} ** 32;
    var verify: std.ArrayList(u8) = .empty;
    defer verify.deinit(allocator);
    try auth.writeCertificateVerify(
        &verify,
        allocator,
        .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        &transcript_hash,
    );
    const parsed = try auth.parseCertificateVerify(verify.items);
    try auth.verifyCertificateVerify(&public_key, parsed, &transcript_hash);
}

test "ECDSA P384 CertificateVerify round-trip and pin" {
    const allocator = std.testing.allocator;
    const key_pair = try EcdsaP384Sha384.KeyPair.generateDeterministic(
        [_]u8{0x44} ** EcdsaP384Sha384.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toUncompressedSec1();
    const transcript_hash = [_]u8{0x35} ** 48;
    var verify: std.ArrayList(u8) = .empty;
    defer verify.deinit(allocator);
    try auth.writeCertificateVerify(
        &verify,
        allocator,
        .{ .ecdsa_p384_sha384 = .{ .key_pair = key_pair } },
        &transcript_hash,
    );
    const parsed = try auth.parseCertificateVerify(verify.items);
    try std.testing.expectEqual(
        auth.signature_scheme_ecdsa_secp384r1_sha384,
        parsed.scheme,
    );
    try auth.verifyCertificateVerify(
        &public_key,
        parsed,
        &transcript_hash,
    );
    const verifier = auth.ClientVerifier{
        .pinned_ecdsa_p384_public_key = public_key,
    };
    try verifier.verifyTrust(null, &.{&public_key});
    var wrong_hash = transcript_hash;
    wrong_hash[0] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerify(
            &public_key,
            parsed,
            &wrong_hash,
        ),
    );
}

test "CertificateRequest advertises built-in signature schemes" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try client_auth.writeRequest(
        &encoded,
        allocator,
        "request",
        &.{"ca-subject"},
    );
    const parsed = try client_auth.parseRequest(encoded.items);
    try std.testing.expectEqualStrings("request", parsed.request_context);
    try std.testing.expect(parsed.supports_ed25519);
    try std.testing.expect(parsed.supports_ecdsa_p256_sha256);
    try std.testing.expect(parsed.supports_ecdsa_p384_sha384);
    try std.testing.expect(parsed.supports_sm2sig_sm3);
}

test "client CertificateVerify uses the distinct TLS context" {
    const allocator = std.testing.allocator;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x61} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    const transcript_hash = [_]u8{0x62} ** 32;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try auth.writeCertificateVerifyForRole(
        &encoded,
        allocator,
        .{ .ed25519 = .{ .key_pair = key_pair } },
        &transcript_hash,
        .client,
    );
    const parsed = try auth.parseCertificateVerify(encoded.items);
    try auth.verifyCertificateVerifyForRole(
        &public_key,
        parsed,
        &transcript_hash,
        .client,
    );
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerifyForRole(
            &public_key,
            parsed,
            &transcript_hash,
            .server,
        ),
    );
}

test "CertificateVerify signs a SHA-384 transcript without truncation" {
    const allocator = std.testing.allocator;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x63} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    const transcript_hash = [_]u8{0x64} **
        std.crypto.hash.sha2.Sha384.digest_length;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try auth.writeCertificateVerify(
        &encoded,
        allocator,
        .{ .ed25519 = .{ .key_pair = key_pair } },
        &transcript_hash,
    );
    const parsed = try auth.parseCertificateVerify(encoded.items);
    try auth.verifyCertificateVerify(
        &public_key,
        parsed,
        &transcript_hash,
    );
    var truncated = transcript_hash[0..32].*;
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerify(
            &public_key,
            parsed,
            &truncated,
        ),
    );
}

test "SM2 CertificateVerify validates raw SEC1 identities" {
    const public_key = [_]u8{
        0x04,
        0xac,
        0x48,
        0x0a,
        0x72,
        0xad,
        0x1b,
        0xeb,
        0x6f,
        0xa9,
        0x88,
        0xd7,
        0x0d,
        0x44,
        0xac,
        0x07,
        0x48,
        0xe8,
        0x11,
        0xbf,
        0xbf,
        0xed,
        0xd6,
        0x8e,
        0x99,
        0x17,
        0xf9,
        0x99,
        0xe6,
        0x1c,
        0xd3,
        0xc1,
        0xc8,
        0x39,
        0xf7,
        0x7d,
        0x94,
        0xb9,
        0xd0,
        0x8d,
        0x2c,
        0x38,
        0x01,
        0x3d,
        0xae,
        0x20,
        0x7e,
        0xc9,
        0x0d,
        0xbd,
        0xb1,
        0x31,
        0xc3,
        0x7e,
        0xb9,
        0x90,
        0xad,
        0xd0,
        0xc3,
        0xc0,
        0xa0,
        0xe1,
        0x8e,
        0x0a,
        0x69,
    };
    const signature = [_]u8{
        0x30, 0x45, 0x02, 0x21, 0x00, 0xf9, 0x09, 0xd5,
        0x25, 0x7b, 0x09, 0x6e, 0xd6, 0xab, 0x34, 0x3a,
        0x8e, 0x2e, 0x16, 0xb2, 0x99, 0x37, 0xbd, 0x6e,
        0xc0, 0x43, 0x20, 0x82, 0x30, 0x04, 0x13, 0xea,
        0x8d, 0xc9, 0xb7, 0x12, 0x06, 0x02, 0x20, 0x09,
        0xfb, 0x22, 0x70, 0xf4, 0xd8, 0xab, 0x0b, 0xbc,
        0x35, 0x2b, 0xdf, 0x32, 0x53, 0xb0, 0x78, 0x51,
        0xe1, 0x91, 0x3a, 0xa8, 0xb1, 0xfb, 0xa1, 0xaa,
        0xd7, 0xc3, 0x25, 0xd2, 0xe7, 0xde, 0x7b,
    };
    const transcript_hash = [_]u8{0x5a} ** 32;
    var verify_message: std.ArrayList(u8) = .empty;
    defer verify_message.deinit(std.testing.allocator);
    try verify_message.append(
        std.testing.allocator,
        auth.handshake_type_certificate_verify,
    );
    const body_len = 2 + 2 + signature.len;
    try verify_message.appendSlice(std.testing.allocator, &.{
        @truncate(body_len >> 16),
        @truncate(body_len >> 8),
        @truncate(body_len),
        @truncate(auth.signature_scheme_sm2sig_sm3 >> 8),
        @truncate(auth.signature_scheme_sm2sig_sm3),
        @truncate(signature.len >> 8),
        @truncate(signature.len),
    });
    try verify_message.appendSlice(std.testing.allocator, &signature);
    const parsed = try auth.parseCertificateVerify(verify_message.items);
    try auth.verifyCertificateVerify(
        &public_key,
        parsed,
        &transcript_hash,
    );
    const verifier = auth.ClientVerifier{
        .pinned_sm2_public_key = public_key,
    };
    try verifier.verifyTrust(null, &.{&public_key});
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerifyForRole(
            &public_key,
            parsed,
            &transcript_hash,
            .client,
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificateVerify,
        auth.verifyCertificateVerify(
            &public_key,
            parsed,
            &([_]u8{0x5a} ** 48),
        ),
    );
}

test "SM2 pinned verifier extracts an X.509 SM2 SubjectPublicKeyInfo" {
    const certificate_hex =
        "3082018030820127a00302010202146b75ed48ff4c0f1be4db8da788d262d7a74f8ab1300a06082a811ccf5501837530163114301206035504030c0b736d322e6578616d706c65301e170d3236303831303039343432335a170d3236303831313039343432335a30163114301206035504030c0b736d322e6578616d706c653059301306072a8648ce3d020106082a811ccf5501822d03420004351c616c65550219aa9cb33a9a631d80197f2f87c313cbfd0095d783bbe8aa8cf86c355f04c31fc1b0084eeaf6cdc7c89a85335d13effa2ba8141920664f91daa3533051301d0603551d0e041604143ec5c9b72001b4884e04600da19b27f93dd82080301f0603551d230418301680143ec5c9b72001b4884e04600da19b27f93dd82080300f0603551d130101ff040530030101ff300a06082a811ccf55018375034700304402201142af0eee83c0d76118f95c581e765a06d1dafc31d24cf4bcf31751baa62cbe022021522fa7ecadb7d8cbdb0af464de41ce7e48c48b83c3975ddaffe189887a2fb8";
    var certificate: [certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate, certificate_hex);
    const public_key = [_]u8{
        0x04, 0x35, 0x1c, 0x61, 0x6c, 0x65, 0x55, 0x02,
        0x19, 0xaa, 0x9c, 0xb3, 0x3a, 0x9a, 0x63, 0x1d,
        0x80, 0x19, 0x7f, 0x2f, 0x87, 0xc3, 0x13, 0xcb,
        0xfd, 0x00, 0x95, 0xd7, 0x83, 0xbb, 0xe8, 0xaa,
        0x8c, 0xf8, 0x6c, 0x35, 0x5f, 0x04, 0xc3, 0x1f,
        0xc1, 0xb0, 0x08, 0x4e, 0xea, 0xf6, 0xcd, 0xc7,
        0xc8, 0x9a, 0x85, 0x33, 0x5d, 0x13, 0xef, 0xfa,
        0x2b, 0xa8, 0x14, 0x19, 0x20, 0x66, 0x4f, 0x91,
        0xda,
    };
    const verifier = auth.ClientVerifier{
        .pinned_sm2_public_key = public_key,
    };
    try verifier.verifyTrust(null, &.{&certificate});
    var wrong_key = public_key;
    wrong_key[64] ^= 1;
    try std.testing.expectError(
        error.CertificateUntrusted,
        (auth.ClientVerifier{ .pinned_sm2_public_key = wrong_key })
            .verifyTrust(null, &.{&certificate}),
    );
}

test "RSA-PSS/RSAE SHA-256 CertificateVerify validates an X.509 leaf" {
    const vector = @import("test_vectors/rsa_pss_sha256.zig");
    var certificate: [vector.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate, vector.certificate_hex);
    var signature: [vector.signature_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&signature, vector.signature_hex);
    const transcript_hash = [_]u8{0x5a} ** 32;
    var certificate_message: std.ArrayList(u8) = .empty;
    defer certificate_message.deinit(std.testing.allocator);
    try auth.writeCertificate(
        &certificate_message,
        std.testing.allocator,
        &.{&certificate},
    );
    var parsed_chain = try auth.parseCertificate(
        std.testing.allocator,
        certificate_message.items,
    );
    defer parsed_chain.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), parsed_chain.entries.len);

    var verify_message: std.ArrayList(u8) = .empty;
    defer verify_message.deinit(std.testing.allocator);
    try verify_message.append(
        std.testing.allocator,
        auth.handshake_type_certificate_verify,
    );
    const verify_body_len = 2 + 2 + signature.len;
    try verify_message.appendSlice(std.testing.allocator, &.{
        @truncate(verify_body_len >> 16),
        @truncate(verify_body_len >> 8),
        @truncate(verify_body_len),
        0x08,
        0x04,
        @truncate(signature.len >> 8),
        @truncate(signature.len),
    });
    try verify_message.appendSlice(std.testing.allocator, &signature);
    const parsed = try auth.parseCertificateVerify(verify_message.items);
    try auth.verifyCertificateVerify(
        parsed_chain.entries[0],
        parsed,
        &transcript_hash,
    );

    const parsed_certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate,
        .index = 0,
    });
    const rsa_public_key = parsed_certificate.pubKey();
    const verifier = auth.ClientVerifier{
        .pinned_rsa_public_key = rsa_public_key,
    };
    try verifier.verifyTrust(null, &.{&certificate});

    signature[0] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerify(
            &certificate,
            .{
                .scheme = auth.signature_scheme_rsa_pss_rsae_sha256,
                .signature = &signature,
            },
            &transcript_hash,
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificate,
        auth.verifyCertificateVerify(
            &([_]u8{0} ** 32),
            .{
                .scheme = auth.signature_scheme_rsa_pss_rsae_sha256,
                .signature = &signature,
            },
            &transcript_hash,
        ),
    );
}

test "RSA-PSS/RSAE SHA-384 and SHA-512 CertificateVerify validate" {
    const vector = @import(
        "test_vectors/rsa_pss_sha384_sha512.zig",
    );
    var certificate: [vector.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate, vector.certificate_hex);
    inline for (.{
        .{
            .scheme = auth.signature_scheme_rsa_pss_rsae_sha384,
            .signature_hex = vector.sha384_signature_hex,
            .hash_len = 48,
        },
        .{
            .scheme = auth.signature_scheme_rsa_pss_rsae_sha512,
            .signature_hex = vector.sha512_signature_hex,
            .hash_len = 64,
        },
    }) |case| {
        var signature: [case.signature_hex.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&signature, case.signature_hex);
        var transcript_hash: [case.hash_len]u8 =
            [_]u8{0x5a} ** case.hash_len;
        var verify_message: std.ArrayList(u8) = .empty;
        defer verify_message.deinit(std.testing.allocator);
        try verify_message.append(
            std.testing.allocator,
            auth.handshake_type_certificate_verify,
        );
        const body_len = 2 + 2 + signature.len;
        try verify_message.appendSlice(std.testing.allocator, &.{
            @truncate(body_len >> 16),
            @truncate(body_len >> 8),
            @truncate(body_len),
            @truncate(case.scheme >> 8),
            @truncate(case.scheme),
            @truncate(signature.len >> 8),
            @truncate(signature.len),
        });
        try verify_message.appendSlice(
            std.testing.allocator,
            &signature,
        );
        const parsed = try auth.parseCertificateVerify(
            verify_message.items,
        );
        try auth.verifyCertificateVerify(
            &certificate,
            parsed,
            &transcript_hash,
        );

        transcript_hash[0] ^= 1;
        try std.testing.expectError(
            error.BadCertificateVerify,
            auth.verifyCertificateVerify(
                &certificate,
                parsed,
                &transcript_hash,
            ),
        );
    }
}

test "RSA-PSS/PSS CertificateVerify enforces the SPKI algorithm" {
    const vector = @import("test_vectors/rsa_pss_pss.zig");
    var certificate: [vector.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate, vector.certificate_hex);
    inline for (.{
        .{
            .scheme = auth.signature_scheme_rsa_pss_pss_sha256,
            .signature_hex = vector.sha256_signature_hex,
            .hash_len = 32,
        },
        .{
            .scheme = auth.signature_scheme_rsa_pss_pss_sha384,
            .signature_hex = vector.sha384_signature_hex,
            .hash_len = 48,
        },
        .{
            .scheme = auth.signature_scheme_rsa_pss_pss_sha512,
            .signature_hex = vector.sha512_signature_hex,
            .hash_len = 64,
        },
    }) |case| {
        var signature: [case.signature_hex.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&signature, case.signature_hex);
        const transcript_hash = [_]u8{0x6b} ** case.hash_len;
        try auth.verifyCertificateVerify(
            &certificate,
            .{
                .scheme = case.scheme,
                .signature = &signature,
            },
            &transcript_hash,
        );
    }

    // rsa_pss_rsae requires rsaEncryption in SubjectPublicKeyInfo; accepting
    // the same mathematical key under rsassaPss would violate TLS scheme/key
    // compatibility and could bypass certificate policy.
    var signature: [vector.sha256_signature_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &signature,
        vector.sha256_signature_hex,
    );
    try std.testing.expectError(
        error.UnsupportedCertificateKey,
        auth.verifyCertificateVerify(
            &certificate,
            .{
                .scheme = auth.signature_scheme_rsa_pss_rsae_sha256,
                .signature = &signature,
            },
            &([_]u8{0x6b} ** 32),
        ),
    );
}

test "TLS 1.3 key schedule separates handshake application and PSK secrets" {
    const shared = [_]u8{0x71} ** key_schedule.secret_len;
    const transcript_hash = [_]u8{0x72} ** key_schedule.secret_len;
    const psk = [_]u8{0x73} ** key_schedule.secret_len;
    const plain = key_schedule.deriveHandshake(shared, transcript_hash, null);
    const resumed = key_schedule.deriveHandshake(shared, transcript_hash, psk);
    try std.testing.expect(!std.mem.eql(
        u8,
        &plain.handshake_secret,
        &resumed.handshake_secret,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &resumed.client_traffic_secret,
        &resumed.server_traffic_secret,
    ));

    const application = key_schedule.deriveApplication(
        resumed.handshake_secret,
        transcript_hash,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &application.client_traffic_secret,
        &application.server_traffic_secret,
    ));
    const finished = key_schedule.computeFinished(
        resumed.client_traffic_secret,
        transcript_hash,
    );
    try key_schedule.verifyFinished(
        resumed.client_traffic_secret,
        transcript_hash,
        finished,
    );
    var wrong = finished;
    wrong[0] ^= 1;
    try std.testing.expectError(
        error.BadFinished,
        key_schedule.verifyFinished(
            resumed.client_traffic_secret,
            transcript_hash,
            wrong,
        ),
    );

    const resumption_master = key_schedule.deriveResumptionMasterSecret(
        application.master_secret,
        transcript_hash,
    );
    const first_psk = key_schedule.deriveResumptionPsk(
        resumption_master,
        "one",
    );
    const second_psk = key_schedule.deriveResumptionPsk(
        resumption_master,
        "two",
    );
    try std.testing.expect(!std.mem.eql(u8, &first_psk, &second_psk));
    const updated = key_schedule.nextTrafficSecret(
        application.client_traffic_secret,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &updated,
        &application.client_traffic_secret,
    ));
}

test "TLS 1.3 SHA-384 schedule keeps 48-byte secrets and Finished values" {
    const Schedule = key_schedule.Sha384;
    const shared = [_]u8{0x81} ** Schedule.secret_len;
    const transcript_hash = [_]u8{0x82} ** Schedule.secret_len;
    const psk = [_]u8{0x83} ** Schedule.secret_len;
    const handshake = Schedule.deriveHandshake(
        &shared,
        transcript_hash,
        psk,
    );
    try std.testing.expectEqual(
        @as(usize, 48),
        handshake.handshake_secret.len,
    );
    try expectHex(
        "fffef14f7d6ee618525454268d25ec5ff81d5c28bfd6ca38dc3df7acadb0ac16aaac1a81f6f08115550935b74afbf7ac",
        &handshake.handshake_secret,
    );
    try expectHex(
        "a54c4371989e45778aa9cf31ecb21a6c7ab1ffc13675257f0b072ea27074eb7fa9e74488eea18cb40135a37f33c8c7f3",
        &handshake.client_traffic_secret,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &handshake.client_traffic_secret,
        &handshake.server_traffic_secret,
    ));

    const application = Schedule.deriveApplication(
        handshake.handshake_secret,
        transcript_hash,
    );
    const finished = Schedule.computeFinished(
        application.client_traffic_secret,
        transcript_hash,
    );
    try expectHex(
        "b0f1f1f5e4665d80ff3e6ba0bf0c1095bfff9cdc79a9a23de31eba619f204151749243d66ed82b5af9a727efa774c02e",
        &finished,
    );
    try Schedule.verifyFinished(
        application.client_traffic_secret,
        transcript_hash,
        finished,
    );
    var wrong = finished;
    wrong[wrong.len - 1] ^= 1;
    try std.testing.expectError(
        error.BadFinished,
        Schedule.verifyFinished(
            application.client_traffic_secret,
            transcript_hash,
            wrong,
        ),
    );
}

test "runtime TLS key schedule dispatch preserves SHA-384 secret identity" {
    const shared = [_]u8{0x91} ** 32;
    const handshake_hash = transcript.hashFor(
        .sha384,
        &.{ "client hello", "server hello" },
    );
    const handshake = try key_schedule.deriveHandshakeFor(
        .sha384,
        &shared,
        handshake_hash,
        null,
    );
    try std.testing.expectEqual(
        secret.Hash.sha384,
        handshake.handshake_secret.hash,
    );
    const application_hash = transcript.hashFor(
        .sha384,
        &.{ "client hello", "server flight" },
    );
    const application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        application_hash,
    );
    const finished = try key_schedule.computeFinishedFor(
        application.client_traffic_secret,
        application_hash,
    );
    try key_schedule.verifyFinishedFor(
        application.client_traffic_secret,
        application_hash,
        finished,
    );
    try std.testing.expectError(
        error.HashMismatch,
        key_schedule.deriveApplicationFor(
            secret.Secret.fromSha256([_]u8{0} ** 32),
            application_hash,
        ),
    );
}

test "TLS 1.3 SM3 schedule matches independent HKDF/HMAC vectors" {
    const Schedule = key_schedule.Sm3;
    const shared = [_]u8{0xa1} ** Schedule.secret_len;
    const transcript_hash = [_]u8{0xa2} ** Schedule.secret_len;
    const pre_shared_key = [_]u8{0xa3} ** Schedule.secret_len;
    const handshake = Schedule.deriveHandshake(
        &shared,
        transcript_hash,
        pre_shared_key,
    );
    try expectHex(
        "6b6dd537c27cda9f89fc794b72c7fe68a82911f62c6038e073b12096f527570e",
        &handshake.handshake_secret,
    );
    try expectHex(
        "b22e419148ec08217e6a278aad1fef71339ea12165f7ad7cbfe35176c9dd9370",
        &handshake.client_traffic_secret,
    );
    try expectHex(
        "28444e8d916999098f337193ee2b67a7fbd77d9771bd58f86d2ca973c9cd3862",
        &handshake.server_traffic_secret,
    );
    const application = Schedule.deriveApplication(
        handshake.handshake_secret,
        transcript_hash,
    );
    try expectHex(
        "9ce50556da429235a8f402db078ff677cc491448b487a0e324dbfdf19b498d62",
        &application.master_secret,
    );
    try expectHex(
        "c2a7ed0b6d95d1a2263503656ef79c585cd8071f473e1ea072f4e445628a6d41",
        &application.client_traffic_secret,
    );
    const finished = Schedule.computeFinished(
        application.client_traffic_secret,
        transcript_hash,
    );
    try expectHex(
        "6c0b1f0e0bceba777a43fd5020de844628df64feef2df180ceab72e7991d70c0",
        &finished,
    );
}

test "runtime TLS key schedule dispatch preserves SM3 secret identity" {
    const shared = [_]u8{0x93} ** 32;
    const handshake_hash = transcript.hashFor(
        .sm3,
        &.{ "client hello", "server hello" },
    );
    const handshake = try key_schedule.deriveHandshakeFor(
        .sm3,
        &shared,
        handshake_hash,
        null,
    );
    try std.testing.expectEqual(
        secret.Hash.sm3,
        handshake.handshake_secret.hash,
    );
    const application_hash = transcript.hashFor(
        .sm3,
        &.{ "client hello", "server flight" },
    );
    const application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        application_hash,
    );
    const finished = try key_schedule.computeFinishedFor(
        application.client_traffic_secret,
        application_hash,
    );
    try key_schedule.verifyFinishedFor(
        application.client_traffic_secret,
        application_hash,
        finished,
    );
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected: [64]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, decoded, actual);
}

test "stateless ticket keyring binds context and retains rotation history" {
    var keyring = try ticket_keyring.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{0x11} ** ticket_keyring.key_len,
    });
    defer keyring.deinit();
    const opened = ticket_keyring.Opened{
        .secret = [_]u8{0x42} ** 32,
        .age_add = 17,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
        .cipher_suite = .chacha20_poly1305_sha256,
    };
    const identity = try keyring.seal(
        [_]u8{0x01} ** ticket_keyring.nonce_len,
        "example:443",
        "h3",
        opened,
    );
    const decoded = try keyring.open(
        &identity,
        "example:443",
        "h3",
        1500,
    );
    try std.testing.expectEqualSlices(u8, &opened.secret, &decoded.secret);
    try std.testing.expectEqual(opened.cipher_suite, decoded.cipher_suite);
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.open(&identity, "other:443", "h3", 1500),
    );
    try keyring.rotate(.{
        .id = 2,
        .secret = [_]u8{0x22} ** ticket_keyring.key_len,
    });
    _ = try keyring.open(&identity, "example:443", "h3", 1500);
}

test "stateless ticket keyring preserves a SHA-384 PSK" {
    var keyring = try ticket_keyring.Keyring.init(.{
        .id = 7,
        .secret = [_]u8{0x71} ** ticket_keyring.key_len,
    });
    defer keyring.deinit();
    const expected = secret.Secret.fromSha384([_]u8{0x72} ** 48);
    const identity = try keyring.sealSecret(
        [_]u8{0x73} ** ticket_keyring.nonce_len,
        "sha384.example:443",
        "h3",
        .{
            .secret = expected,
            .age_add = 21,
            .issued_at_ms = 2000,
            .lifetime_seconds = 60,
            .cipher_suite_wire = 0x1302,
        },
    );
    const opened = try keyring.openSecret(
        &identity,
        "sha384.example:443",
        "h3",
        2500,
    );
    try std.testing.expectEqual(secret.Hash.sha384, opened.secret.hash);
    try std.testing.expect(expected.eql(&opened.secret));
    try std.testing.expectEqual(@as(u16, 0x1302), opened.cipher_suite_wire);
    try std.testing.expectError(
        error.InvalidTicket,
        keyring.open(
            &identity,
            "sha384.example:443",
            "h3",
            2500,
        ),
    );
}

test "stateless ticket keyring preserves an SM3 PSK" {
    var keyring = try ticket_keyring.Keyring.init(.{
        .id = 8,
        .secret = [_]u8{0x81} ** ticket_keyring.key_len,
    });
    defer keyring.deinit();
    const expected = secret.Secret.fromSm3([_]u8{0x82} ** 32);
    const identity = try keyring.sealSecret(
        [_]u8{0x83} ** ticket_keyring.nonce_len,
        "sm3.example:443",
        "h3",
        .{
            .secret = expected,
            .age_add = 22,
            .issued_at_ms = 3000,
            .lifetime_seconds = 60,
            .cipher_suite_wire = 0x00c6,
        },
    );
    const opened = try keyring.openSecret(
        &identity,
        "sm3.example:443",
        "h3",
        3500,
    );
    try std.testing.expectEqual(secret.Hash.sm3, opened.secret.hash);
    try std.testing.expect(expected.eql(&opened.secret));
    try std.testing.expectEqual(@as(u16, 0x00c6), opened.cipher_suite_wire);
}

test "X25519 exchange and transcript hashing agree on both roles" {
    const client_secret = [_]u8{0x31} ** key_exchange.secret_len;
    const server_secret = [_]u8{0x32} ** key_exchange.secret_len;
    const client_public = try key_exchange.publicKey(client_secret);
    const server_public = try key_exchange.publicKey(server_secret);
    const client_shared = try key_exchange.sharedSecret(
        client_secret,
        &server_public,
    );
    const server_shared = try key_exchange.sharedSecret(
        server_secret,
        &client_public,
    );
    try std.testing.expectEqualSlices(u8, &client_shared, &server_shared);
    try std.testing.expectError(
        error.InvalidPublicKey,
        key_exchange.sharedSecret(client_secret, "short"),
    );

    const one_shot = transcript.hash(&.{ "client", "server" });
    var incremental = transcript.Transcript{};
    incremental.update("client");
    incremental.update("server");
    try std.testing.expectEqualSlices(
        u8,
        &one_shot,
        &incremental.digest(),
    );

    const sha384 = transcript.Sha384.hash(&.{ "client", "server" });
    try std.testing.expectEqual(@as(usize, 48), sha384.len);
    try std.testing.expect(!std.mem.eql(
        u8,
        one_shot[0..],
        sha384[0..one_shot.len],
    ));
}

test "secp256r1 ECDH validates keys and agrees on the shared x-coordinate" {
    const client_secret = [_]u8{0} ** 31 ++ [_]u8{1};
    const server_secret = [_]u8{0} ** 31 ++ [_]u8{2};
    const client_public = try key_exchange.p256.publicKey(client_secret);
    const server_public = try key_exchange.p256.publicKey(server_secret);
    const client_shared = try key_exchange.p256.sharedSecret(
        client_secret,
        &server_public,
    );
    const server_shared = try key_exchange.p256.sharedSecret(
        server_secret,
        &client_public,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_shared,
        &server_shared,
    );
    try std.testing.expectEqual(@as(u8, 0x04), client_public[0]);
    try std.testing.expectError(
        error.InvalidSecretKey,
        key_exchange.p256.publicKey([_]u8{0} ** 32),
    );
    var invalid_public = client_public;
    invalid_public[0] = 0x02;
    try std.testing.expectError(
        error.InvalidPublicKey,
        key_exchange.p256.sharedSecret(
            server_secret,
            &invalid_public,
        ),
    );
}

test "secp384r1 ECDH validates keys and agrees on the shared x-coordinate" {
    const client_secret = [_]u8{0} ** 47 ++ [_]u8{1};
    const server_secret = [_]u8{0} ** 47 ++ [_]u8{2};
    const client_public = try key_exchange.p384.publicKey(client_secret);
    const server_public = try key_exchange.p384.publicKey(server_secret);
    const client_shared = try key_exchange.p384.sharedSecret(
        client_secret,
        &server_public,
    );
    const server_shared = try key_exchange.p384.sharedSecret(
        server_secret,
        &client_public,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_shared,
        &server_shared,
    );
    try std.testing.expectEqual(@as(usize, 48), client_shared.len);
    try std.testing.expectError(
        error.InvalidSecretKey,
        key_exchange.p384.publicKey([_]u8{0} ** 48),
    );
    var invalid_public = client_public;
    invalid_public[0] = 0x02;
    try std.testing.expectError(
        error.InvalidPublicKey,
        key_exchange.p384.sharedSecret(
            server_secret,
            &invalid_public,
        ),
    );
}

fn checkCertificateAllocationFailure(allocator: std.mem.Allocator) !void {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x55} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try auth.writeCertificate(&certificate, allocator, &.{&public_key});
    var parsed = try auth.parseCertificate(allocator, certificate.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &public_key, parsed.entries[0]);
}

test "Certificate codec is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCertificateAllocationFailure,
        .{},
    );
}
