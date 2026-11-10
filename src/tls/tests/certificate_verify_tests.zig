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
    var wrong_hash = transcript_hash;
    wrong_hash[0] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerify(&public_key, parsed, &wrong_hash),
    );
}

test "ECDSA P256 CertificateVerify matches the standard verifier" {
    const allocator = std.testing.allocator;
    for (0..32) |index| {
        var seed = [_]u8{0x43} ** EcdsaP256Sha256.KeyPair.seed_length;
        std.mem.writeInt(u64, seed[0..8], index + 1, .little);
        const key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
        const public_key = key_pair.public_key.toUncompressedSec1();
        var transcript_hash = [_]u8{0x34} ** 32;
        std.mem.writeInt(u64, transcript_hash[0..8], index + 1, .little);
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try auth.writeCertificateVerify(
            &encoded,
            allocator,
            .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            &transcript_hash,
        );
        const parsed = try auth.parseCertificateVerify(encoded.items);
        try auth.verifyCertificateVerify(
            &public_key,
            parsed,
            &transcript_hash,
        );

        const signature = try EcdsaP256Sha256.Signature.fromDer(
            parsed.signature,
        );
        var message: [
            64 + "TLS 1.3, server CertificateVerify".len + 1 +
                transcript_hash.len
        ]u8 = undefined;
        @memset(message[0..64], 0x20);
        @memcpy(
            message[64..][0.."TLS 1.3, server CertificateVerify".len],
            "TLS 1.3, server CertificateVerify",
        );
        message[64 + "TLS 1.3, server CertificateVerify".len] = 0;
        @memcpy(message[message.len - transcript_hash.len ..], &transcript_hash);
        try signature.verify(
            &message,
            try EcdsaP256Sha256.PublicKey.fromSec1(&public_key),
        );

        transcript_hash[31] ^= 1;
        try std.testing.expectError(
            error.BadCertificateVerify,
            auth.verifyCertificateVerify(
                &public_key,
                parsed,
                &transcript_hash,
            ),
        );
    }
}

test "ECDSA P256 CertificateVerify rejects invalid scalars" {
    const key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0x45} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toUncompressedSec1();
    const transcript_hash = [_]u8{0x36} ** 32;
    const zero_r = [_]u8{
        0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
    };
    const non_canonical_r = [_]u8{
        0x30, 0x26, 0x02, 0x21, 0x00,
    } ++ ([_]u8{0xff} ** 32) ++ [_]u8{ 0x02, 0x01, 0x01 };

    inline for (.{ zero_r, non_canonical_r }) |signature| {
        try std.testing.expectError(
            error.BadCertificateVerify,
            auth.verifyCertificateVerify(
                &public_key,
                .{
                    .scheme = auth.signature_scheme_ecdsa_secp256r1_sha256,
                    .signature = &signature,
                },
                &transcript_hash,
            ),
        );
    }
}

test "ECDSA P256 client CertificateVerify uses the client context" {
    const allocator = std.testing.allocator;
    const key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0x46} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toUncompressedSec1();
    const transcript_hash = [_]u8{0x37} ** 32;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try auth.writeCertificateVerifyForRole(
        &encoded,
        allocator,
        .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
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

test "ECDSA P521 CertificateVerify round-trip and pin" {
    const allocator = std.testing.allocator;
    var p521_secret = try p521.SecretKey.fromBytes(decodeHex(
        "00123456789abcdef00112233445566778899aabbccddeeff1021324354657687" ++
            "98a9bacbdcedfe0f112233445566778899aabbccddeeff00123456789abcdef1234",
    ));
    defer p521_secret.deinit();
    var key_pair = try p521.KeyPair.fromSecretKey(p521_secret);
    defer key_pair.deinit();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const transcript_hash = [_]u8{0x36} ** 64;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try auth.writeCertificateVerify(
        &encoded,
        allocator,
        .{ .ecdsa_p521_sha512 = .{
            .key_pair = &key_pair,
            .io = std.testing.io,
        } },
        &transcript_hash,
    );
    const parsed = try auth.parseCertificateVerify(encoded.items);
    try std.testing.expectEqual(
        auth.signature_scheme_ecdsa_secp521r1_sha512,
        parsed.scheme,
    );
    try auth.verifyCertificateVerify(
        &public_key,
        parsed,
        &transcript_hash,
    );
    const verifier = auth.ClientVerifier{
        .pinned_ecdsa_p521_public_key = public_key,
    };
    try verifier.verifyTrust(null, &.{&public_key});

    const prepared_nonce_bytes = decodeHex(
        "000deadbeefcafebabefeedface0123456789abcdef102030405060708090a0b0" ++
            "c0d0e0f00112233445566778899aabbccddeeff13579bdf2468ace00123456789ab",
    );
    var prepared_nonce = try key_pair.prepareNonce(&prepared_nonce_bytes);
    defer prepared_nonce.deinit();
    const prepared_signer = auth.Signer{
        .ecdsa_p521_sha512_prepared = .{
            .key_pair = &key_pair,
            .nonce = &prepared_nonce,
        },
    };
    var prepared_encoded: std.ArrayList(u8) = .empty;
    defer prepared_encoded.deinit(allocator);
    try auth.writeCertificateVerify(
        &prepared_encoded,
        allocator,
        prepared_signer,
        &transcript_hash,
    );
    try auth.verifyCertificateVerify(
        &public_key,
        try auth.parseCertificateVerify(prepared_encoded.items),
        &transcript_hash,
    );
    var reused: std.ArrayList(u8) = .empty;
    defer reused.deinit(allocator);
    try std.testing.expectError(
        error.InvalidCertificateVerify,
        auth.writeCertificateVerify(
            &reused,
            allocator,
            prepared_signer,
            &transcript_hash,
        ),
    );
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
