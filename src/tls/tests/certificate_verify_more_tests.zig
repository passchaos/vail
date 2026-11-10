const std = @import("std");
const auth = @import("../handshake/auth.zig");
const certificate_compression = @import("../handshake/certificate_compression.zig");
const cipher_suite = @import("../crypto/cipher_suite.zig");
const client_auth = @import("../handshake/client_auth.zig");
const key_schedule = @import("../crypto/key_schedule.zig");
const key_exchange = @import("../key_exchange.zig");
const secret = @import("../crypto/secret.zig");
const ticket_keyring = @import("../crypto/ticket_keyring.zig");
const transcript = @import("../crypto/transcript.zig");
const p521 = @import("../../crypto/ec/p521.zig");
const sm2 = @import("../../crypto/sign/sm2.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const common = @import("common.zig");
const decodeHex = common.decodeHex;
const writeTestFinished = common.writeTestFinished;
const expectHex = common.expectHex;
const checkCertificateAllocationFailure = common.checkCertificateAllocationFailure;

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

test "SM2 CertificateVerify signs and verifies raw SEC1 identities" {
    const sm2_secret = try sm2.SecretKey.fromBytes(.{
        0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x33, 0xb1,
        0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95,
        0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a,
        0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8,
    });
    const key_pair = try sm2.KeyPair.fromSecretKey(sm2_secret);
    const public_key = key_pair.public_key.toUncompressedSec1();
    const transcript_hash = [_]u8{0x71} ** 32;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try auth.writeCertificateVerify(
        &encoded,
        std.testing.allocator,
        .{ .sm2sig_sm3 = .{
            .key_pair = key_pair,
            .nonce = .{
                0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a,
                0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0, 0x2d, 0xcc,
                0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4,
                0xce, 0x6d, 0x54, 0xb8, 0x0d, 0xea, 0xc1, 0xbc,
            },
        } },
        &transcript_hash,
    );
    const parsed = try auth.parseCertificateVerify(encoded.items);
    try std.testing.expectEqual(auth.signature_scheme_sm2sig_sm3, parsed.scheme);
    try auth.verifyCertificateVerify(&public_key, parsed, &transcript_hash);
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerifyForRole(
            &public_key,
            parsed,
            &transcript_hash,
            .client,
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
    const vector = @import("../test_vectors/rsa_pss_sha256.zig");
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
        "../test_vectors/rsa_pss_sha384_sha512.zig",
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

test "pure Zig RSA-PSS signer emits TLS CertificateVerify" {
    const allocator = std.testing.allocator;
    const vector = @import("../../crypto/testdata/rsa_signing.zig");
    var private_key_der: [vector.private_key_pkcs8_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &private_key_der,
        vector.private_key_pkcs8_hex,
    );
    var certificate: [vector.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate, vector.certificate_hex);
    const private_key = try @import("../../crypto/sign/rsa.zig").PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const transcript_hash = [_]u8{0x5c} ** 32;

    inline for (.{
        .{
            .scheme = auth.signature_scheme_rsa_pss_rsae_sha256,
        },
        .{
            .scheme = auth.signature_scheme_rsa_pss_rsae_sha384,
        },
        .{
            .scheme = auth.signature_scheme_rsa_pss_rsae_sha512,
        },
    }) |case| {
        const signer = auth.Signer{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .signature_scheme = case.scheme,
            .io = std.testing.io,
        } };
        try (auth.ServerIdentity{
            .certificate_chain = &.{&certificate},
            .signer = signer,
        }).validate();
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try auth.writeCertificateVerify(
            &encoded,
            allocator,
            signer,
            &transcript_hash,
        );
        const parsed = try auth.parseCertificateVerify(encoded.items);
        try std.testing.expectEqual(case.scheme, parsed.scheme);
        try auth.verifyCertificateVerify(
            &certificate,
            parsed,
            &transcript_hash,
        );
    }

    const other_vector = @import("../test_vectors/rsa_pss_sha256.zig");
    var other_certificate: [other_vector.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &other_certificate,
        other_vector.certificate_hex,
    );
    try std.testing.expectError(
        error.InvalidCertificate,
        (auth.ServerIdentity{
            .certificate_chain = &.{&other_certificate},
            .signer = .{ .rsa_pss = .{
                .prepared_key = &prepared_key,
                .io = std.testing.io,
            } },
        }).validate(),
    );
}

test "RSA-PSS/PSS CertificateVerify enforces the SPKI algorithm" {
    const vector = @import("../test_vectors/rsa_pss_pss.zig");
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
