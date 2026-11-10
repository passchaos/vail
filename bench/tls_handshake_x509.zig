const std = @import("std");
const vail = @import("vail");

const iterations: usize = 1_000;
const Client = vail.tls.client_connection.ClientConnection(4096, 256);
const Server = vail.tls.server_connection.ServerConnection(4096, 256);
const compatibility_ccs = [_]u8{ 20, 3, 3, 0, 1, 1 };
const handshake_schemes = [_]u16{
    vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256,
};
const certificate_schemes = [_]u16{
    vail.tls.auth.signature_scheme_rsa_pkcs1_sha256,
};
const now_seconds: i64 = 1_900_000_000;

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
        .signature_scheme = vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256,
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
        vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256,
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

        var client_material = vail.tls.key_exchange.ClientKeyMaterial{
            .x25519 = [_]u8{@truncate(iteration + 0x41)} **
                vail.tls.key_exchange.secret_len,
        };
        var client: Client = undefined;
        try client.initInto(.{
            .allocator = allocator,
            .random = [_]u8{0x42} ** 32,
            .session_id = &([_]u8{0x43} ** 32),
            .server_name = "localhost",
            .key_material = &client_material,
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .signature_schemes = &handshake_schemes,
            .certificate_signature_schemes = &certificate_schemes,
            .alpn_protocols = &.{"h2"},
            .request_ocsp = false,
            .certificate_compression_algorithms = &.{},
            .server_verifier = blk: {
                var verifier = vail.tls.auth.ClientVerifier.fromTrustVerifier(trust_verifier.clientVerifier());
                verifier.prepared_rsa_verifier = &prepared_public;
                break :blk verifier;
            },
        }, &client_wire);
        defer client.deinit();

        var server_material = vail.tls.key_exchange.ServerKeyMaterial{
            .x25519 = [_]u8{@truncate(iteration + 0x61)} **
                vail.tls.key_exchange.secret_len,
        };
        var server = Server.init(.{
            .allocator = allocator,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{vail.tls.key_exchange.named_group_x25519},
                .alpn_protocols = &.{"h2"},
            },
            .server_random = [_]u8{0x45} ** 32,
            .key_material = &server_material,
            .certificate_chain = &.{&certificate},
            .signer = signer,
        });
        defer server.deinit();

        var established_client: Client.Established = undefined;
        var established_server: Server.Established = undefined;

        try server_wire.appendSlice(allocator, &.{ 22, 3, 3, 0, 0 });
        const server_result = try server.receiveInto(
            client_wire.items,
            &server_wire,
            &established_server,
        );
        if (server_result.event == null or
            std.meta.activeTag(server_result.event.?) != .server_flight)
        {
            return error.ServerDidNotProduceFlight;
        }
        const server_hello_len = 4 +
            (@as(usize, server_wire.items[6]) << 16) +
            (@as(usize, server_wire.items[7]) << 8) +
            server_wire.items[8];
        std.mem.writeInt(
            u16,
            server_wire.items[3..5],
            @intCast(server_hello_len),
            .big,
        );
        try server_wire.insertSlice(
            allocator,
            5 + server_hello_len,
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

        server_wire_len = server_wire.items.len;
        client_finished_len = client_finished.items.len;
        checksum +%= server_wire.items[server_wire.items.len - 1];
        checksum +%= client_finished.items[client_finished.items.len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519_rsapss_aes128={d} ns/full-x509-handshake " ++
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
        const result = try client.receiveInto(
            input,
            output,
            established_output,
        );
        offset += result.consumed;
        if (result.event) |event| switch (event) {
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
        const result = try server.receiveInto(
            input,
            output,
            established_output,
        );
        offset += result.consumed;
        if (result.event) |event| switch (event) {
            .compatibility_change_cipher_spec => {},
            .established => return,
            .peer_alert => return error.PeerAbortedHandshake,
            .hello_retry_request,
            .server_flight,
            .early_data,
            .end_of_early_data,
            => return error.UnexpectedServerEvent,
        } else if (result.consumed == 0) {
            return error.ServerStateStalled;
        }
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
