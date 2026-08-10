//! TLS 1.3 server-flight builder for QUIC CRYPTO streams.
//!
//! QUIC carries TLS handshake bytes in CRYPTO frames and protects packets with
//! QUIC packet keys. It never uses TLS record protection. This adapter keeps
//! that boundary explicit: Vail emits plaintext handshake messages separated
//! by encryption level and returns the packet-protection keys that a transport
//! implementation installs into its Initial/Handshake/1-RTT packet spaces.

const std = @import("std");

const auth = @import("../tls/auth.zig");
const client_hello = @import("../tls/client_hello.zig");
const key_schedule = @import("../tls/key_schedule.zig");
const secret = @import("../tls/secret.zig");
const server_flight = @import("../tls/server_flight.zig");
const server_hello = @import("../tls/server_hello.zig");
const transcript = @import("../tls/transcript.zig");
const traffic = @import("traffic_crypto.zig");
const tls_secrets = @import("tls_secrets.zig");

pub const handshake_type_finished: u8 = 0x14;

pub const Error = std.mem.Allocator.Error || server_flight.Error ||
    server_hello.Error || key_schedule.Error || auth.Error || error{
    InvalidFinished,
};

pub const Result = struct {
    selection: server_flight.Selection,
    handshake_secret: secret.Secret,
    client_handshake_traffic_secret: secret.Secret,
    server_handshake_traffic_secret: secret.Secret,
    transcript_after_server_finished: transcript.Digest,
    handshake_packet_keys: tls_secrets.DirectionalKeys,
    application_packet_keys: tls_secrets.DirectionalKeys,
};

pub const Options = struct {
    client_hello_bytes: []const u8,
    parsed_client_hello: client_hello.Parsed,
    policy: server_flight.Policy,
    server_random: [32]u8,
    server_key_share: []const u8,
    shared_secret: []const u8,
    certificate_chain: []const []const u8,
    signer: auth.Signer,
    labels: traffic.Labels = traffic.labels_v1,
};

pub fn writeServerCryptoFlight(
    initial_crypto: *std.ArrayList(u8),
    handshake_crypto: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: Options,
) Error!Result {
    const selection = try server_flight.select(
        options.parsed_client_hello,
        options.policy,
    );

    var server_hello_msg: std.ArrayList(u8) = .empty;
    defer server_hello_msg.deinit(allocator);
    try server_hello.writeServerHello(&server_hello_msg, allocator, .{
        .random = options.server_random,
        .session_id_echo = options.parsed_client_hello.session_id,
        .cipher_suite = selection.suite,
        .key_share_group = selection.key_share_group,
        .key_share = options.server_key_share,
    });
    // The QUIC transport wraps these bytes in Initial CRYPTO frames, then
    // packet-protects those frames with Initial keys derived from the DCID.
    try initial_crypto.appendSlice(allocator, server_hello_msg.items);

    const hello_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{ options.client_hello_bytes, server_hello_msg.items },
    );
    const handshake = try key_schedule.deriveHandshakeFor(
        selection.suite.hash(),
        options.shared_secret,
        hello_hash,
        null,
    );

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(allocator);
    try server_hello.writeEncryptedExtensions(&encrypted_extensions, allocator, .{
        .alpn_protocol = selection.alpn_protocol,
        .quic_transport_parameters = options.policy.quic_transport_parameters,
    });
    try handshake_crypto.appendSlice(allocator, encrypted_extensions.items);

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try auth.writeCertificate(
        &certificate,
        allocator,
        options.certificate_chain,
    );
    try handshake_crypto.appendSlice(allocator, certificate.items);

    const certificate_verify_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate.items,
        },
    );
    var certificate_verify: std.ArrayList(u8) = .empty;
    defer certificate_verify.deinit(allocator);
    try auth.writeCertificateVerify(
        &certificate_verify,
        allocator,
        options.signer,
        certificate_verify_hash.bytes(),
    );
    try handshake_crypto.appendSlice(allocator, certificate_verify.items);

    const finished_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate.items,
            certificate_verify.items,
        },
    );
    const verify_data = try key_schedule.computeFinishedFor(
        handshake.server_traffic_secret,
        finished_hash,
    );
    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try writeFinished(&finished, allocator, verify_data.bytes());
    try handshake_crypto.appendSlice(allocator, finished.items);

    const transcript_after_server_finished = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate.items,
            certificate_verify.items,
            finished.items,
        },
    );
    const application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        transcript_after_server_finished,
    );

    return .{
        .selection = selection,
        .handshake_secret = handshake.handshake_secret,
        .client_handshake_traffic_secret = handshake.client_traffic_secret,
        .server_handshake_traffic_secret = handshake.server_traffic_secret,
        .transcript_after_server_finished = transcript_after_server_finished,
        .handshake_packet_keys = try tls_secrets.handshakeKeys(
            selection.suite,
            handshake,
            options.labels,
        ),
        .application_packet_keys = try tls_secrets.applicationKeys(
            selection.suite,
            application,
            options.labels,
        ),
    };
}

fn writeFinished(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    verify_data: []const u8,
) Error!void {
    if (verify_data.len > std.math.maxInt(u24)) return error.InvalidFinished;
    try out.append(allocator, handshake_type_finished);
    try out.appendSlice(allocator, &.{
        @truncate(verify_data.len >> 16),
        @truncate(verify_data.len >> 8),
        @truncate(verify_data.len),
    });
    try out.appendSlice(allocator, verify_data);
}

test "QUIC TLS server flight emits CRYPTO bytes by encryption level" {
    const hello = [_]u8{
        0x01, 0x00, 0x00, 0x73, 0x03, 0x03,
    } ++ ([_]u8{0x11} ** 32) ++ [_]u8{
        0x03, 1,    2,    3,
        0x00, 0x04, 0x13, 0x01,
        0x13, 0x03, 0x01, 0x00,
        0x00, 0x43, 0x00, 0x2b,
        0x00, 0x03, 0x02, 0x03,
        0x04, 0x00, 0x10, 0x00,
        0x05, 0x00, 0x03, 0x02,
        'h',  '3',  0x00, 0x33,
        0x00, 0x0c, 0x00, 0x0a,
        0x00, 0x1d, 0x00, 0x06,
        1,    2,    3,    4,
        5,    6,    0x00, 0x00,
        0x00, 0x10, 0x00, 0x0e,
        0x00, 0x00, 0x0b, 'e',
        'x',  'a',  'm',  'p',
        'l',  'e',  '.',  'c',
        'o',  'm',  0x00, 0x0a,
        0x00, 0x04, 0x00, 0x02,
        0x00, 0x1d, 0x00, 0x39,
        0x00, 0x03, 1,    2,
        3,
    };
    const parsed = try client_hello.parse(&hello);
    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x56} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const cert = key_pair.public_key.toBytes();
    var initial_crypto: std.ArrayList(u8) = .empty;
    defer initial_crypto.deinit(std.testing.allocator);
    var handshake_crypto: std.ArrayList(u8) = .empty;
    defer handshake_crypto.deinit(std.testing.allocator);

    const result = try writeServerCryptoFlight(
        &initial_crypto,
        &handshake_crypto,
        std.testing.allocator,
        .{
            .client_hello_bytes = &hello,
            .parsed_client_hello = parsed,
            .policy = .{
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
            },
            .server_random = [_]u8{0x22} ** 32,
            .server_key_share = &.{ 9, 8, 7, 6 },
            .shared_secret = &([_]u8{0x33} ** 32),
            .certificate_chain = &.{&cert},
            .signer = .{ .ed25519 = .{ .key_pair = key_pair } },
        },
    );

    try std.testing.expectEqual(
        server_hello.handshake_type_server_hello,
        initial_crypto.items[0],
    );
    try std.testing.expectEqual(
        server_hello.handshake_type_encrypted_extensions,
        handshake_crypto.items[0],
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        handshake_crypto.items,
        &.{ 0x00, 0x39, 0x00, 0x03, 4, 5, 6 },
    ) != null);
    try std.testing.expectEqual(
        secret.Hash.sha256,
        result.client_handshake_traffic_secret.hash,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &result.handshake_packet_keys.client.key,
        &result.application_packet_keys.client.key,
    ));
}
