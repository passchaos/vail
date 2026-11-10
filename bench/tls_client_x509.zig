const std = @import("std");
const vail = @import("vail");

const iterations: usize = 2_000;
const Client = vail.tls.client_connection.ClientConnection(4096, 256);
const Server = vail.tls.server_connection.ServerConnection(4096, 256);
const client_secret = [_]u8{0x41} ** vail.tls.key_exchange.secret_len;
const client_random = [_]u8{0x42} ** 32;
const client_session_id = [_]u8{0x43} ** 32;
const server_secret = [_]u8{0x44} ** vail.tls.key_exchange.secret_len;
const server_random = [_]u8{0x45} ** 32;
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
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const signer = vail.tls.auth.Signer{ .rsa_pss = .{
        .prepared_key = &prepared_key,
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
    const prepared_verifier = try vail.tls.auth.PreparedRsaVerifier.init(
        &certificate,
        vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256,
    );

    var template_hello: std.ArrayList(u8) = .empty;
    defer template_hello.deinit(allocator);
    var template_material = vail.tls.key_exchange.ClientKeyMaterial{
        .x25519 = client_secret,
    };
    var template_client: Client = undefined;
    try template_client.initInto(
        clientConfig(
            allocator,
            &template_material,
            &trust_verifier,
            &prepared_verifier,
        ),
        &template_hello,
    );
    defer template_client.deinit();

    var server_material = vail.tls.key_exchange.ServerKeyMaterial{
        .x25519 = server_secret,
    };
    var server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{vail.tls.key_exchange.named_group_x25519},
            .alpn_protocols = &.{"h2"},
        },
        .server_random = server_random,
        .key_material = &server_material,
        .certificate_chain = &.{&certificate},
        .signer = signer,
    });
    defer server.deinit();

    var raw_server_flight: std.ArrayList(u8) = .empty;
    defer raw_server_flight.deinit(allocator);
    const server_result = try server.receive(
        template_hello.items,
        &raw_server_flight,
    );
    if (server_result.event == null or
        std.meta.activeTag(server_result.event.?) != .server_flight)
    {
        return error.ServerDidNotProduceFlight;
    }
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    try frameServerFlight(
        &server_wire,
        allocator,
        raw_server_flight.items,
    );

    var template_finished: std.ArrayList(u8) = .empty;
    defer template_finished.deinit(allocator);
    var template_established: Client.Established = undefined;
    try establishClient(
        &template_client,
        server_wire.items,
        &template_finished,
        &template_established,
    );
    template_established.deinit();

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(allocator);
    var checksum: u64 = 0;
    var hello_len: usize = 0;
    var finished_len: usize = 0;

    const start = nowNs(init.io);
    for (0..iterations) |_| {
        client_hello.clearRetainingCapacity();
        client_finished.clearRetainingCapacity();
        var material = vail.tls.key_exchange.ClientKeyMaterial{
            .x25519 = client_secret,
        };
        var client: Client = undefined;
        try client.initInto(
            clientConfig(
                allocator,
                &material,
                &trust_verifier,
                &prepared_verifier,
            ),
            &client_hello,
        );
        defer client.deinit();
        var established: Client.Established = undefined;
        try establishClient(
            &client,
            server_wire.items,
            &client_finished,
            &established,
        );
        defer established.deinit();
        hello_len = client_hello.items.len;
        finished_len = client_finished.items.len;
        checksum +%= client_hello.items[client_hello.items.len - 1];
        checksum +%= client_finished.items[client_finished.items.len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519_rsapss_aes128={d} ns/client-x509-handshake " ++
            "hello={d} server-flight={d} finished={d} checksum={d}\n",
        .{
            elapsed / iterations,
            hello_len,
            server_wire.items.len,
            finished_len,
            checksum,
        },
    );
}

fn clientConfig(
    allocator: std.mem.Allocator,
    material: *vail.tls.key_exchange.ClientKeyMaterial,
    verifier: *const vail.x509.trust.BundleVerifier,
    prepared_verifier: *const vail.tls.auth.PreparedRsaVerifier,
) vail.tls.client_connection.Config {
    return .{
        .allocator = allocator,
        .random = client_random,
        .session_id = &client_session_id,
        .server_name = "localhost",
        .key_material = material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .signature_schemes = &handshake_schemes,
        .certificate_signature_schemes = &certificate_schemes,
        .alpn_protocols = &.{"h2"},
        .request_ocsp = false,
        .certificate_compression_algorithms = &.{},
        .server_verifier = blk: {
            var client_verifier = vail.tls.auth.ClientVerifier.fromTrustVerifier(verifier.clientVerifier());
            client_verifier.prepared_rsa_verifier = prepared_verifier;
            break :blk client_verifier;
        },
    };
}

fn frameServerFlight(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    flight: []const u8,
) !void {
    const server_hello_len = 4 +
        (@as(usize, flight[1]) << 16) +
        (@as(usize, flight[2]) << 8) +
        flight[3];
    try output.appendSlice(allocator, &.{
        vail.tls.record.content_type_handshake,
        3,
        3,
        @truncate(server_hello_len >> 8),
        @truncate(server_hello_len),
    });
    try output.appendSlice(allocator, flight[0..server_hello_len]);
    try output.appendSlice(allocator, &.{ 20, 3, 3, 0, 1, 1 });
    try output.appendSlice(allocator, flight[server_hello_len..]);
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
            .established => {
                if (offset != server_wire.len) {
                    established_output.deinit();
                    return error.TrailingServerFlight;
                }
                return;
            },
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
