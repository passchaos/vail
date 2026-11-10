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

test "TLS cipher suites expose protocol limits from one canonical type" {
    try std.testing.expectEqual(
        @as(u16, 0x1301),
        cipher_suite.Suite.aes_128_gcm_sha256.wireValue(),
    );
    try std.testing.expectEqual(
        @as(u16, 0x1304),
        cipher_suite.Suite.aes_128_ccm_sha256.wireValue(),
    );
    try std.testing.expectEqual(
        @as(u16, 0x1305),
        cipher_suite.Suite.aes_128_ccm_8_sha256.wireValue(),
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        cipher_suite.Suite.aes_128_ccm_sha256.keyLen(),
    );
    try std.testing.expectEqual(
        @as(u64, 1) << 21,
        cipher_suite.Suite.aes_128_ccm_sha256.confidentialityLimit(),
    );
    try std.testing.expectEqual(
        @as(u64, 1) << 21,
        cipher_suite.Suite.aes_128_ccm_sha256.integrityLimit(),
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        cipher_suite.Suite.aes_128_ccm_8_sha256.tagLen(),
    );
    try std.testing.expectEqual(
        @as(u64, 1) << 21,
        cipher_suite.Suite.aes_128_ccm_8_sha256.tlsConfidentialityLimit(),
    );
    try std.testing.expectEqual(
        @as(u64, 1) << 7,
        cipher_suite.Suite.aes_128_ccm_8_sha256.integrityLimit(),
    );
    try std.testing.expect(!cipher_suite.Suite.aes_128_ccm_8_sha256.quicCompatible());
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
        @as(u16, 0x00c7),
        cipher_suite.Suite.sm4_ccm_sm3.wireValue(),
    );
    try std.testing.expectEqual(
        secret.Hash.sm3,
        cipher_suite.Suite.sm4_gcm_sm3.hash(),
    );
    try std.testing.expectEqual(
        secret.Hash.sm3,
        cipher_suite.Suite.sm4_ccm_sm3.hash(),
    );
    try std.testing.expectEqual(
        @as(u64, 1) << 21,
        cipher_suite.Suite.sm4_ccm_sm3.tlsConfidentialityLimit(),
    );
    try std.testing.expectEqual(
        @as(u64, 1) << 21,
        cipher_suite.Suite.sm4_ccm_sm3.integrityLimit(),
    );
    try std.testing.expect(cipher_suite.Suite.sm4_ccm_sm3.quicCompatible());
}
