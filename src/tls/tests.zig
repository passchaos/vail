const std = @import("std");
const auth = @import("auth.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_auth = @import("client_auth.zig");
const key_schedule = @import("key_schedule.zig");
const key_exchange = @import("key_exchange.zig");
const ticket_keyring = @import("ticket_keyring.zig");
const transcript = @import("transcript.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

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
        shared,
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
