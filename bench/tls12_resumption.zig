const std = @import("std");
const vail = @import("vail");

const iterations: usize = 20_000;
const Client = vail.tls.tls12_client_connection.ClientConnection(4096, 4096);
const Server = vail.tls.tls12_server_connection.ServerConnection(4096, 4096);
const ClientEstablished = vail.tls.tls12_client_connection.Established;
const ServerEstablished = vail.tls.tls12_server_connection.Established;
const server_name = "localhost";
const server_id = "tls12-benchmark-server";
const alpn = "h2";
const now_seconds: u64 = 101;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next();
    const use_session_id = if (mode) |value|
        std.mem.eql(u8, value, "session")
    else
        false;
    if (mode) |value| {
        if (!use_session_id and !std.mem.eql(u8, value, "ticket")) {
            return error.InvalidMode;
        }
    }
    const vectors = vail.crypto.testing.rsa_signing;
    const certificate = decodeHex(vectors.certificate_hex);
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(&private_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const signer = vail.tls.auth.Signer{ .rsa_pkcs1 = .{
        .prepared_key = &prepared_key,
    } };
    const policy = vail.tls.tls12_handshake.Policy{
        .cipher_suites = &.{.ecdhe_rsa_aes_128_gcm_sha256},
        .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
        .alpn_protocols = &.{alpn},
    };
    var keyring = try vail.tls.ticket_keyring.Keyring.init(.{
        .id = 17,
        .secret = [_]u8{0xa6} ** vail.tls.ticket_keyring.key_len,
    });
    defer keyring.deinit();
    var initial_master_secret =
        [_]u8{0xa7} ** vail.tls.tls12.master_secret_len;
    defer std.crypto.secureZero(u8, &initial_master_secret);
    const initial_ticket = try keyring.sealTls12(
        nonceFor(0),
        server_id,
        alpn,
        .{
            .master_secret = &initial_master_secret,
            .suite = .ecdhe_rsa_aes_128_gcm_sha256,
            .issued_at_seconds = 100,
            .lifetime_seconds = 3_600,
            .extended_master_secret = true,
        },
    );
    var cached = try vail.tls.tls12_ticket.Cached.init(
        allocator,
        &initial_ticket,
        &.{},
        .ecdhe_rsa_aes_128_gcm_sha256,
        initial_master_secret,
        server_name,
        alpn,
        100,
        3_600,
    );
    defer cached.deinit();
    const session_id = [_]u8{0xa8} ** vail.tls.tls12.max_session_id_len;
    var client_session = try vail.tls.tls12.Session.init(
        &session_id,
        .ecdhe_rsa_aes_128_gcm_sha256,
        initial_master_secret,
        server_name,
        alpn,
        100,
        3_600,
    );
    defer client_session.deinit();
    var server_session = try vail.tls.tls12.Session.init(
        &session_id,
        .ecdhe_rsa_aes_128_gcm_sha256,
        initial_master_secret,
        server_id,
        alpn,
        100,
        3_600,
    );
    defer server_session.deinit();

    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    var server_output: std.ArrayList(u8) = .empty;
    defer server_output.deinit(allocator);
    try client_wire.ensureTotalCapacity(allocator, 512);
    try server_wire.ensureTotalCapacity(allocator, 512);
    try server_output.ensureTotalCapacity(allocator, 64);

    var checksum: u64 = 0;
    var client_hello_len: usize = 0;
    var server_flight_len: usize = 0;
    var client_finished_len: usize = 0;
    var ticket_len: usize = 0;
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        client_wire.clearRetainingCapacity();
        server_wire.clearRetainingCapacity();
        server_output.clearRetainingCapacity();
        var client_private = p256Private(3);
        var server_private = p256Private(5);
        var client: Client = undefined;
        try client.initInto(.{
            .allocator = allocator,
            .random = [_]u8{0xb1} ** 32,
            .server_name = server_name,
            .client_private_key = &client_private,
            .policy = policy,
            .signature_schemes = &.{
                vail.tls.auth.signature_scheme_rsa_pkcs1_sha256,
            },
            .request_ocsp = false,
            .server_verifier = .{ .verify_trust = acceptCertificate },
            .resumption = if (use_session_id) client_session else null,
            .ticket_resumption = if (use_session_id) null else &cached,
            .now_seconds = now_seconds,
        }, &client_wire);
        defer client.deinit();
        var server: Server = undefined;
        server.initInto(.{
            .allocator = allocator,
            .policy = policy,
            .server_random = [_]u8{0xb2} ** 32,
            .server_private_key = &server_private,
            .certificate_chain = &.{&certificate},
            .signer = signer,
            .resumption = if (use_session_id) .{
                .session = &server_session,
                .identity = server_id,
                .now_seconds = now_seconds,
            } else null,
            .session_tickets = if (use_session_id) null else .{
                .keyring = &keyring,
                .server_id = server_id,
                .now_seconds = now_seconds,
                .lifetime_seconds = 3_600,
                .sealing_nonce = nonceFor(iteration + 1),
            },
        });
        defer server.deinit();
        var established_client: ClientEstablished = undefined;
        var established_server: ServerEstablished = undefined;

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
        try establishClient(
            &client,
            server_wire.items,
            &client_wire,
            &established_client,
        );
        defer established_client.deinit();
        if (!established_client.resumed) {
            return error.ClientDidNotResume;
        }
        client_finished_len = client_wire.items.len;
        if (use_session_id) {
            if (established_client.session_ticket != null or
                !std.mem.eql(
                    u8,
                    established_client.session_id[0..established_client.session_id_len],
                    &session_id,
                )) return error.UnexpectedSessionState;
        } else {
            const replacement = established_client.session_ticket orelse
                return error.ClientDidNotReceiveTicket;
            ticket_len = replacement.len;
            if (std.mem.eql(u8, cached.ticket(), replacement)) {
                return error.TicketDidNotRollOver;
            }
        }

        server_wire.clearRetainingCapacity();
        try establishServer(
            &server,
            client_wire.items,
            &server_output,
            &established_server,
        );
        defer established_server.deinit();
        if (!established_server.resumed) return error.ServerDidNotResume;

        if (!use_session_id) {
            const next_cached = try established_client.createTicketSession(
                server_name,
                now_seconds,
            );
            cached.deinit();
            cached = next_cached;
        }
        checksum +%= client_wire.items[client_wire.items.len - 1];
        checksum +%= if (use_session_id)
            established_client.session_id[established_client.session_id_len - 1]
        else
            cached.ticket()[cached.ticket().len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "tls12-{s}-aes128={d} ns/resumed-handshake-{s} " ++
            "hello={d} server-flight={d} client-finished={d} " ++
            "ticket={d} checksum={d}\n",
        .{
            if (use_session_id) "session" else "ticket",
            elapsed / iterations,
            if (use_session_id) "session-reuse" else "ticket-rollover",
            client_hello_len,
            server_flight_len,
            client_finished_len,
            ticket_len,
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
            .change_cipher_spec => {},
            .established => return,
            .server_flight,
            .client_key_exchange,
            => return error.UnexpectedServerEvent,
            .peer_alert => return error.PeerAbortedHandshake,
        };
        if (result.consumed == 0) return error.ServerStateStalled;
    }
    return error.ServerDidNotEstablish;
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

fn nonceFor(value: usize) [vail.tls.ticket_keyring.nonce_len]u8 {
    var nonce = [_]u8{0} ** vail.tls.ticket_keyring.nonce_len;
    std.mem.writeInt(u64, nonce[nonce.len - 8 ..], @intCast(value), .big);
    return nonce;
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
