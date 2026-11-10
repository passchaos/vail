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
