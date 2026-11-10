const std = @import("std");
const vail = @import("vail");

const iterations: usize = 1_000;
const Client = vail.tls.versioned_client_connection.ClientConnection(4096, 256);
const Server = vail.tls.versioned_server_connection.ServerConnection(4096, 256);
const compatibility_ccs = [_]u8{ 20, 3, 3, 0, 1, 1 };
const tls13_suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
const tls12_suite = vail.tls.tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256;
const signature_scheme =
    vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256;
const certificate_scheme =
    vail.tls.auth.signature_scheme_rsa_pkcs1_sha256;
const now_seconds: i64 = 1_900_000_000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const vectors = vail.testdata.crypto.rsa_signing;
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

    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(allocator);
    var server_output: std.ArrayList(u8) = .empty;
    defer server_output.deinit(allocator);
    var checksum: u64 = 0;
    var server_wire_len: usize = 0;
    var client_finished_len: usize = 0;

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        client_wire.clearRetainingCapacity();
        server_wire.clearRetainingCapacity();
        client_finished.clearRetainingCapacity();
        server_output.clearRetainingCapacity();

        var client_tls13_key = vail.tls.key_exchange.ClientKeyMaterial{
            .x25519 = [_]u8{@truncate(iteration + 0x41)} **
                vail.tls.key_exchange.secret_len,
        };
        var client_tls13_retry_key = vail.tls.key_exchange.ClientKeyMaterial{
            .secp256r1 = p256Private(4),
        };
        var client_tls12_key = p256Private(3);
        var client: Client = undefined;
        try client.initInto(.{
            .tls13 = .{
                .allocator = allocator,
                .random = [_]u8{0x42} ** 32,
                .session_id = &([_]u8{0x43} ** 32),
                .server_name = "localhost",
                .key_material = &client_tls13_key,
                .retry_key_material = &client_tls13_retry_key,
                .cipher_suites = &.{tls13_suite},
                .additional_cipher_suites = &.{
                    @intFromEnum(tls12_suite),
                    0x00ff,
                },
                .supported_versions = &.{ 0x0304, 0x0303 },
                .signature_schemes = &.{signature_scheme},
                .certificate_signature_schemes = &.{certificate_scheme},
                .offer_extended_master_secret = true,
                .alpn_protocols = &.{"h2"},
                .request_ocsp = false,
                .certificate_compression_algorithms = &.{},
                .server_verifier = clientVerifier(
                    &trust_verifier,
                    &prepared_public,
                ),
            },
            .tls12 = .{
                .allocator = allocator,
                .random = [_]u8{0x42} ** 32,
                .server_name = "localhost",
                .client_private_key = &client_tls12_key,
                .policy = .{
                    .cipher_suites = &.{tls12_suite},
                    .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
                    .alpn_protocols = &.{"h2"},
                },
                .signature_schemes = &.{signature_scheme},
                .certificate_signature_schemes = &.{certificate_scheme},
                .request_ocsp = false,
                .server_verifier = clientVerifier(
                    &trust_verifier,
                    &prepared_public,
                ),
            },
        }, &client_wire);
        defer client.deinit();

        var server_tls13_key = vail.tls.key_exchange.ServerKeyMaterial{
            .x25519 = [_]u8{@truncate(iteration + 0x61)} **
                vail.tls.key_exchange.secret_len,
        };
        var server_tls12_key = p256Private(5);
        var server: Server = undefined;
        server.initInto(.{
            .tls13 = .{
                .allocator = allocator,
                .policy = .{
                    .cipher_suites = &.{tls13_suite},
                    .groups = &.{vail.tls.key_exchange.named_group_x25519},
                    .alpn_protocols = &.{"h2"},
                },
                .server_random = [_]u8{0x45} ** 32,
                .key_material = &server_tls13_key,
                .certificate_chain = &.{&certificate},
                .signer = signer,
            },
            .tls12 = .{
                .allocator = allocator,
                .policy = .{
                    .cipher_suites = &.{tls12_suite},
                    .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
                    .alpn_protocols = &.{"h2"},
                },
                .server_random = [_]u8{0x46} ** 32,
                .server_private_key = &server_tls12_key,
                .certificate_chain = &.{&certificate},
                .signer = signer,
            },
        });
        defer server.deinit();

        var established_client: Client.Established = undefined;
        var established_server: Server.Established = undefined;
        const server_result = try server.receiveInto(
            client_wire.items,
            &server_wire,
            &established_server,
        );
        if (server_result.event == null or
            std.meta.activeTag(server_result.event.?) != .tls13 or
            std.meta.activeTag(server_result.event.?.tls13) != .server_flight or
            server.protocol() != .tls13)
        {
            return error.ServerDidNotNegotiateTls13;
        }
        const first_record_len = vail.tls.record.header_len +
            std.mem.readInt(u16, server_wire.items[3..5], .big);
        try server_wire.insertSlice(
            allocator,
            first_record_len,
            &compatibility_ccs,
        );

        try client_finished.appendSlice(allocator, &compatibility_ccs);
        try establishClient(
            &client,
            server_wire.items,
            &client_finished,
            &established_client,
        );
        defer established_client.deinit();
        try establishServer(
            &server,
            client_finished.items,
            &server_output,
            &established_server,
        );
        defer established_server.deinit();

        if (client.protocol() != .tls13 or server.protocol() != .tls13) {
            return error.UnexpectedProtocol;
        }
        switch (established_client) {
            .tls13 => |established| if (established.resumed or
                established.application.suite != tls13_suite)
            {
                return error.UnexpectedClientState;
            },
            .tls12 => return error.UnexpectedProtocol,
        }
        switch (established_server) {
            .tls13 => |established| if (established.resumed or
                established.application.suite != tls13_suite)
            {
                return error.UnexpectedServerState;
            },
            .tls12 => return error.UnexpectedProtocol,
        }
        server_wire_len = server_wire.items.len;
        client_finished_len = client_finished.items.len;
        checksum +%= server_wire.items[server_wire.items.len - 1];
        checksum +%= client_finished.items[client_finished.items.len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519-rsapss-aes128={d} ns/versioned-full-tls13-handshake " ++
            "hello={d} server-flight={d} client-finished={d} checksum={d}\n",
        .{
            elapsed / iterations,
            client_wire.items.len,
            server_wire_len,
            client_finished_len,
            checksum,
        },
    );
}

fn establishClient(
    client: *Client,
    server_wire: []const u8,
    output: *std.ArrayList(u8),
    established_output: *Client.Established,
) !void {
    var offset: usize = 0;
    while (true) {
        const input = if (offset < server_wire.len)
            server_wire[offset..]
        else
            "";
        const result = try client.receiveInto(input, output, established_output);
        offset += result.consumed;
        if (result.event) |event| switch (event) {
            .tls13 => |tls13_event| switch (tls13_event) {
                .server_hello,
                .compatibility_change_cipher_spec,
                => {},
                .established => return,
                .hello_retry_request => return error.UnexpectedHelloRetryRequest,
                .peer_alert => return error.PeerAbortedHandshake,
                .ech_rejected => |rejection| {
                    var owned = rejection;
                    owned.deinit();
                    return error.UnexpectedEchRejection;
                },
            },
            .tls12 => return error.UnexpectedProtocol,
        } else if (result.consumed == 0) {
            return error.ClientStateStalled;
        }
    }
}

fn establishServer(
    server: *Server,
    client_wire: []const u8,
    output: *std.ArrayList(u8),
    established_output: *Server.Established,
) !void {
    var offset: usize = 0;
    while (true) {
        const input = if (offset < client_wire.len)
            client_wire[offset..]
        else
            "";
        const result = try server.receiveInto(input, output, established_output);
        offset += result.consumed;
        if (result.event) |event| switch (event) {
            .tls13 => |tls13_event| switch (tls13_event) {
                .compatibility_change_cipher_spec => {},
                .established => return,
                .peer_alert => return error.PeerAbortedHandshake,
                .hello_retry_request,
                .server_flight,
                .early_data,
                .end_of_early_data,
                => return error.UnexpectedServerEvent,
            },
            .tls12 => return error.UnexpectedProtocol,
        } else if (result.consumed == 0) {
            return error.ServerStateStalled;
        }
    }
}

fn clientVerifier(
    trust: *const vail.x509.trust.BundleVerifier,
    prepared: *const vail.tls.auth.PreparedRsaVerifier,
) vail.tls.auth.ClientVerifier {
    var verifier = vail.tls.auth.ClientVerifier.fromTrustVerifier(trust.clientVerifier());
    verifier.prepared_rsa_verifier = prepared;
    return verifier;
}

fn p256Private(last: u8) [vail.tls.key_exchange.p256.secret_len]u8 {
    return [_]u8{0} ** (vail.tls.key_exchange.p256.secret_len - 1) ++ .{last};
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
