const std = @import("std");
const vail = @import("vail");

const iterations: usize = 500;
const Client = vail.tls.tls12_client_connection.ClientConnection(4096, 4096);
const Server = vail.tls.tls12_server_connection.ServerConnection(4096, 4096);
const ClientEstablished = vail.tls.tls12_client_connection.Established;
const ServerEstablished = vail.tls.tls12_server_connection.Established;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next();
    const use_pss = if (mode) |value| std.mem.eql(u8, value, "pss") else false;
    const use_aes256 = if (mode) |value|
        std.mem.eql(u8, value, "aes256")
    else
        false;
    if (mode) |value| {
        if (!use_pss and !use_aes256 and !std.mem.eql(u8, value, "pkcs1")) {
            return error.InvalidMode;
        }
    }
    const signature_scheme: u16 = if (use_pss)
        vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256
    else
        vail.tls.auth.signature_scheme_rsa_pkcs1_sha256;
    const vectors = vail.testdata.crypto.rsa_signing;
    const certificate = decodeHex(vectors.certificate_hex);
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(&private_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const prepared_verifier = try vail.tls.auth.PreparedRsaVerifier.init(
        &certificate,
        signature_scheme,
    );
    const signer: vail.tls.auth.Signer = if (use_pss)
        .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .signature_scheme = signature_scheme,
            .io = init.io,
        } }
    else
        .{ .rsa_pkcs1 = .{
            .prepared_key = &prepared_key,
            .signature_scheme = signature_scheme,
        } };
    const selected_suite: vail.tls.tls12.Suite = if (use_aes256)
        .ecdhe_rsa_aes_256_gcm_sha384
    else
        .ecdhe_rsa_aes_128_gcm_sha256;
    const policy = vail.tls.tls12_handshake.Policy{
        .cipher_suites = &.{selected_suite},
        .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
        .alpn_protocols = &.{"h2"},
    };

    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    var checksum: u64 = 0;
    var client_hello_len: usize = 0;
    var server_flight_len: usize = 0;
    var client_flight_len: usize = 0;
    var server_finished_len: usize = 0;

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        client_wire.clearRetainingCapacity();
        server_wire.clearRetainingCapacity();
        var client_private = p256Private(3);
        var server_private = p256Private(5);
        var client: Client = undefined;
        try client.initInto(.{
            .allocator = allocator,
            .random = [_]u8{0xa1} ** 32,
            .server_name = "localhost",
            .client_private_key = &client_private,
            .policy = policy,
            .signature_schemes = &.{signature_scheme},
            .request_ocsp = false,
            .server_verifier = .{
                .verify_trust = acceptCertificate,
                .prepared_rsa_verifier = &prepared_verifier,
            },
        }, &client_wire);
        defer client.deinit();
        var server: Server = undefined;
        server.initInto(.{
            .allocator = allocator,
            .policy = policy,
            .server_random = [_]u8{0xa2} ** 32,
            .server_private_key = &server_private,
            .certificate_chain = &.{&certificate},
            .signer = signer,
        });
        defer server.deinit();
        var established_server: ServerEstablished = undefined;
        var established_client: ClientEstablished = undefined;

        client_hello_len = client_wire.items.len;
        checksum +%= client_wire.items[client_wire.items.len - 1];
        try produceServerFlight(
            &server,
            client_wire.items,
            &server_wire,
            &established_server,
        );
        server_flight_len = server_wire.items.len;
        checksum +%= server_wire.items[server_wire.items.len - 1];

        client_wire.clearRetainingCapacity();
        try produceClientFlight(
            &client,
            server_wire.items,
            &client_wire,
            &established_client,
        );
        client_flight_len = client_wire.items.len;
        checksum +%= client_wire.items[client_wire.items.len - 1];

        server_wire.clearRetainingCapacity();
        try establishServer(
            &server,
            client_wire.items,
            &server_wire,
            &established_server,
        );
        defer established_server.deinit();
        server_finished_len = server_wire.items.len;

        client_wire.clearRetainingCapacity();
        try establishClient(
            &client,
            server_wire.items,
            &client_wire,
            &established_client,
        );
        defer established_client.deinit();

        if (established_client.resumed or established_server.resumed or
            established_client.suite != selected_suite or
            established_server.suite != selected_suite)
        {
            return error.UnexpectedHandshake;
        }
        checksum +%= @as(u64, @intCast(iteration));
        checksum +%= server_wire.items[server_wire.items.len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "p256-rsa2048-{s}-{s}={d} ns/full-tls12-handshake " ++
            "hello={d} server-flight={d} client-flight={d} " ++
            "server-finished={d} checksum={d}\n",
        .{
            if (use_pss) "pss" else "pkcs1",
            if (use_aes256) "aes256" else "aes128",
            elapsed / iterations,
            client_hello_len,
            server_flight_len,
            client_flight_len,
            server_finished_len,
            checksum,
        },
    );
}

fn produceServerFlight(
    server: *Server,
    input: []const u8,
    output: *std.ArrayList(u8),
    established_output: *ServerEstablished,
) !void {
    var offset: usize = 0;
    while (offset < input.len) {
        const result = try server.receiveInto(
            input[offset..],
            output,
            established_output,
        );
        offset += result.consumed;
        if (result.event) |event| switch (event) {
            .server_flight => return,
            .client_key_exchange,
            .change_cipher_spec,
            .established,
            => return error.UnexpectedServerEvent,
            .peer_alert => return error.PeerAbortedHandshake,
        };
        if (result.consumed == 0) return error.ServerStateStalled;
    }
    return error.ServerDidNotProduceFlight;
}

fn produceClientFlight(
    client: *Client,
    input: []const u8,
    output: *std.ArrayList(u8),
    established_output: *ClientEstablished,
) !void {
    var offset: usize = 0;
    while (offset < input.len) {
        const result = try client.receiveInto(
            input[offset..],
            output,
            established_output,
        );
        offset += result.consumed;
        if (result.event) |event| switch (event) {
            .client_flight => return,
            .change_cipher_spec,
            .established,
            => return error.UnexpectedClientEvent,
            .peer_alert => return error.PeerAbortedHandshake,
        };
        if (result.consumed == 0) return error.ClientStateStalled;
    }
    return error.ClientDidNotProduceFlight;
}

fn establishServer(
    server: *Server,
    input: []const u8,
    output: *std.ArrayList(u8),
    established_output: *ServerEstablished,
) !void {
    var offset: usize = 0;
    while (offset < input.len) {
        const result = try server.receiveInto(
            input[offset..],
            output,
            established_output,
        );
        offset += result.consumed;
        if (result.event) |event| switch (event) {
            .client_key_exchange,
            .change_cipher_spec,
            => {},
            .established => return,
            .server_flight => return error.UnexpectedServerFlight,
            .peer_alert => return error.PeerAbortedHandshake,
        };
        if (result.consumed == 0) return error.ServerStateStalled;
    }
    return error.ServerDidNotEstablish;
}

fn establishClient(
    client: *Client,
    input: []const u8,
    output: *std.ArrayList(u8),
    established_output: *ClientEstablished,
) !void {
    var offset: usize = 0;
    while (offset < input.len) {
        const result = try client.receiveInto(
            input[offset..],
            output,
            established_output,
        );
        offset += result.consumed;
        if (result.event) |event| switch (event) {
            .change_cipher_spec => {},
            .established => return,
            .client_flight => return error.UnexpectedClientFlight,
            .peer_alert => return error.PeerAbortedHandshake,
        };
        if (result.consumed == 0) return error.ClientStateStalled;
    }
    return error.ClientDidNotEstablish;
}

fn acceptCertificate(
    context: ?*anyopaque,
    trust: vail.tls.auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0) return error.EmptyCertificateChain;
}

fn p256Private(last: u8) [vail.tls.key_exchange.p256.secret_len]u8 {
    return [_]u8{0} ** (vail.tls.key_exchange.p256.secret_len - 1) ++ .{last};
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
