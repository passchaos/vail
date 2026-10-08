const std = @import("std");
const vail = @import("vail");

const iterations: usize = 1_000;
const client_transport_parameters = [_]u8{ 0x01, 0x02, 0x03 };
const server_transport_parameters = [_]u8{ 0x04, 0x05, 0x06 };
const signature_scheme =
    vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256;
const now_seconds: i64 = 1_900_000_000;

const Buffers = struct {
    client_initial: std.ArrayList(u8) = .empty,
    server_initial: std.ArrayList(u8) = .empty,
    server_handshake: std.ArrayList(u8) = .empty,
    client_handshake: std.ArrayList(u8) = .empty,

    fn clear(self: *Buffers) void {
        self.client_initial.clearRetainingCapacity();
        self.server_initial.clearRetainingCapacity();
        self.server_handshake.clearRetainingCapacity();
        self.client_handshake.clearRetainingCapacity();
    }

    fn deinit(self: *Buffers, allocator: std.mem.Allocator) void {
        self.client_initial.deinit(allocator);
        self.server_initial.deinit(allocator);
        self.server_handshake.deinit(allocator);
        self.client_handshake.deinit(allocator);
        self.* = undefined;
    }
};

const HandshakeStats = struct {
    client_initial_len: usize,
    server_initial_len: usize,
    server_handshake_len: usize,
    client_handshake_len: usize,
    checksum: u64,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const vectors = vail.crypto.testing.rsa_signing;
    const certificate = decodeHex(vectors.certificate_hex);
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(&private_der);
    var prepared_private = try private_key.prepare();
    defer prepared_private.deinit();
    const signer = vail.tls.auth.Signer{ .rsa_pss = .{
        .prepared_key = &prepared_private,
        .signature_scheme = signature_scheme,
        .io = init.io,
    } };

    var roots: std.crypto.Certificate.Bundle = .empty;
    defer roots.deinit(allocator);
    try roots.bytes.appendSlice(allocator, &certificate);
    try roots.parseCert(allocator, 0, now_seconds);
    const trust_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &roots,
        .now_seconds = now_seconds,
    };
    const prepared_public = try vail.tls.auth.PreparedRsaVerifier.init(
        &certificate,
        signature_scheme,
    );
    var verifier = trust_verifier.clientVerifier();
    verifier.prepared_rsa_verifier = &prepared_public;

    var buffers: Buffers = .{};
    defer buffers.deinit(allocator);

    // Validate the complete state transition once outside the measured loop
    // and populate reusable output-buffer capacities.
    _ = try runHandshake(
        allocator,
        &buffers,
        &certificate,
        signer,
        verifier,
    );

    var checksum: u64 = 0;
    var stats: HandshakeStats = undefined;
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        stats = try runHandshake(
            allocator,
            &buffers,
            &certificate,
            signer,
            verifier,
        );
        checksum +%= stats.checksum;
        checksum +%= @as(u64, @intCast(iteration));
        std.mem.doNotOptimizeAway(stats.checksum);
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519-rsapss-aes128={d} ns/full-quic-tls13-handshake " ++
            "client-initial={d} server-initial={d} " ++
            "server-handshake={d} client-handshake={d} checksum={d}\n",
        .{
            elapsed / iterations,
            stats.client_initial_len,
            stats.server_initial_len,
            stats.server_handshake_len,
            stats.client_handshake_len,
            checksum,
        },
    );
}

fn runHandshake(
    allocator: std.mem.Allocator,
    buffers: *Buffers,
    certificate: []const u8,
    signer: vail.tls.auth.Signer,
    verifier: vail.tls.auth.ClientVerifier,
) !HandshakeStats {
    buffers.clear();

    var client_key_material = vail.tls.key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xd1} ** vail.tls.key_exchange.secret_len,
    };
    var client_exchange = try client_key_material.start();
    var client_exchange_live = true;
    defer if (client_exchange_live) client_exchange.deinit();
    try vail.tls.client_hello.writeWithKeyShare(
        &buffers.client_initial,
        allocator,
        .{
            .random = [_]u8{0xd2} ** 32,
            .server_name = "localhost",
            .key_share = .{
                .group = client_exchange.namedGroup(),
                .key_exchange = client_exchange.clientShare(),
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .signature_schemes = &.{signature_scheme},
            .alpn_protocols = &.{"h3"},
            .quic_transport_parameters = &client_transport_parameters,
        },
    );

    const parsed_client = try vail.tls.client_hello.parse(
        buffers.client_initial.items,
    );
    if (parsed_client.quic_transport_parameters == null or
        !std.mem.eql(
            u8,
            parsed_client.quic_transport_parameters.?,
            &client_transport_parameters,
        ) or
        !try parsed_client.supportsAlpnProtocol("h3"))
    {
        return error.UnexpectedClientNegotiation;
    }
    const client_share = (try parsed_client.keyShareForGroup(
        vail.tls.key_exchange.named_group_x25519,
    )) orelse return error.MissingClientKeyShare;

    var server_key_material = vail.tls.key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xc1} ** vail.tls.key_exchange.secret_len,
    };
    defer server_key_material.wipe();
    var server_exchange = try server_key_material.respond(
        client_share.key_exchange,
    );
    defer server_exchange.deinit();

    var client_shared_secret = try client_exchange.complete(
        server_exchange.serverShare(),
    );
    client_exchange_live = false;
    defer client_shared_secret.deinit();

    var server_result = try vail.quic.tls_handshake.writeServerCryptoFlight(
        &buffers.server_initial,
        &buffers.server_handshake,
        allocator,
        .{
            .client_hello_bytes = buffers.client_initial.items,
            .parsed_client_hello = parsed_client,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{vail.tls.key_exchange.named_group_x25519},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &server_transport_parameters,
            },
            .server_random = [_]u8{0xc2} ** 32,
            .server_key_share = server_exchange.serverShare(),
            .shared_secret = server_exchange.sharedSecretBytes(),
            .certificate_chain = &.{certificate},
            .signer = signer,
        },
    );
    defer server_result.deinit();

    var client_result = try vail.quic.tls_handshake.writeClientCryptoFlight(
        &buffers.client_handshake,
        allocator,
        .{
            .client_hello_bytes = buffers.client_initial.items,
            .server_hello_bytes = buffers.server_initial.items,
            .server_handshake_crypto = buffers.server_handshake.items,
            .shared_secret = client_shared_secret.bytes(),
            .server_verifier = verifier,
            .server_name = "localhost",
        },
    );
    defer client_result.deinit();

    var verified_client = try vail.quic.tls_handshake.verifyClientCryptoFlight(
        allocator,
        &server_result,
        buffers.client_handshake.items,
    );
    defer verified_client.deinit();

    if (server_result.selection.suite != .aes_128_gcm_sha256 or
        server_result.selection.key_share_group !=
            vail.tls.key_exchange.named_group_x25519 or
        server_result.selection.alpn_protocol == null or
        !std.mem.eql(u8, server_result.selection.alpn_protocol.?, "h3") or
        server_result.resumed or
        client_result.verified.cipher_suite != .aes_128_gcm_sha256 or
        client_result.resumed or
        !std.mem.eql(u8, client_result.selected_alpn, "h3") or
        !std.mem.eql(
            u8,
            client_result.peer_transport_parameters,
            &server_transport_parameters,
        ) or
        client_result.verified.peer_certificate_chain.len != 1 or
        !std.mem.eql(
            u8,
            client_result.verified.peer_certificate_chain[0],
            certificate,
        ) or
        verified_client.peer_certificate_chain.len != 0)
    {
        return error.UnexpectedHandshake;
    }
    if (!std.mem.eql(
        u8,
        client_result.verified.transcript_after_client_finished.bytes(),
        verified_client.transcript_after_client_finished.bytes(),
    )) return error.TranscriptMismatch;
    try checkDirectionalKeys(
        &client_result.handshake_packet_keys,
        &server_result.handshake_packet_keys,
    );
    try checkDirectionalKeys(
        &client_result.application_packet_keys,
        &server_result.application_packet_keys,
    );

    const checksum = @as(u64, buffers.client_initial.getLast()) +%
        @as(u64, buffers.server_initial.getLast()) +%
        @as(u64, buffers.server_handshake.getLast()) +%
        @as(u64, buffers.client_handshake.getLast()) +%
        @as(u64, client_result.application_packet_keys.client.key[0]) +%
        @as(u64, client_result.application_packet_keys.server.key[0]);
    return .{
        .client_initial_len = buffers.client_initial.items.len,
        .server_initial_len = buffers.server_initial.items.len,
        .server_handshake_len = buffers.server_handshake.items.len,
        .client_handshake_len = buffers.client_handshake.items.len,
        .checksum = checksum,
    };
}

fn checkDirectionalKeys(
    client: *const vail.quic.tls_secrets.DirectionalKeys,
    server: *const vail.quic.tls_secrets.DirectionalKeys,
) !void {
    if (client.client.suite != server.client.suite or
        client.server.suite != server.server.suite or
        !std.mem.eql(u8, &client.client.key, &server.client.key) or
        !std.mem.eql(u8, &client.client.iv, &server.client.iv) or
        !std.mem.eql(u8, &client.client.hp, &server.client.hp) or
        !std.mem.eql(u8, &client.server.key, &server.server.key) or
        !std.mem.eql(u8, &client.server.iv, &server.server.iv) or
        !std.mem.eql(u8, &client.server.hp, &server.server.hp))
    {
        return error.PacketKeyMismatch;
    }
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var decoded: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, encoded) catch unreachable;
    return decoded;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
