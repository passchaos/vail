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
