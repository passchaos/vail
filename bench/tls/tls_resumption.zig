const std = @import("std");
const vail = @import("vail");

const iterations: usize = 2_000;
const Client = vail.tls.client_connection.ClientConnection(4096, 256);
const Server = vail.tls.server_connection.ServerConnection(4096, 256);
const compatibility_ccs = [_]u8{ 20, 3, 3, 0, 1, 1 };
const server_name = "example.com";
const alpn = "h2";

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var keyring = try vail.tls.ticket_keyring.Keyring.init(.{
        .id = 7,
        .secret = [_]u8{0xa6} ** vail.tls.ticket_keyring.key_len,
    });
    defer keyring.deinit();
    const initial_psk = vail.tls.secret.Secret.fromSha256(
        [_]u8{0xa7} ** 32,
    );
    const initial_identity = try keyring.sealSecret(
        nonceFor(0),
        server_name,
        alpn,
        .{
            .secret = initial_psk,
            .age_add = 100,
            .issued_at_ms = 10_000,
            .lifetime_seconds = 3_600,
            .cipher_suite_wire = 0x1301,
        },
    );
    const identity = try allocator.dupe(u8, &initial_identity);
    errdefer allocator.free(identity);
    const owned_server_name = try allocator.dupe(u8, server_name);
    errdefer allocator.free(owned_server_name);
    const owned_alpn = try allocator.dupe(u8, alpn);
    errdefer allocator.free(owned_alpn);
    var cached = vail.tls.ticket.Cached{
        .allocator = allocator,
        .identity = identity,
        .psk = initial_psk,
        .suite = .aes_128_gcm_sha256,
        .server_name = owned_server_name,
        .alpn = owned_alpn,
        .age_add = 100,
        .received_at_ms = 10_000,
        .lifetime_seconds = 3_600,
        .max_early_data_size = null,
        .application_settings_codepoint = null,
        .local_application_settings = null,
        .peer_application_settings = null,
    };
    defer cached.deinit();

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xaa} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    var prepared_signer = try vail.crypto.ed25519.PreparedSigner.init(
        signing_key,
    );
    defer prepared_signer.deinit();
    const certificate = signing_key.public_key.toBytes();

    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(allocator);
    var server_output: std.ArrayList(u8) = .empty;
    defer server_output.deinit(allocator);
    var ticket_record: [512]u8 = undefined;
    var checksum: u64 = 0;
    var server_wire_len: usize = 0;
    var client_finished_len: usize = 0;
    var ticket_record_len: usize = 0;

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const now_ms = 11_000 + iteration;
        client_wire.clearRetainingCapacity();
        server_wire.clearRetainingCapacity();
        client_finished.clearRetainingCapacity();
        server_output.clearRetainingCapacity();

        var client_material = vail.tls.key_exchange.ClientKeyMaterial{
            .x25519 = [_]u8{@truncate(iteration + 0x41)} **
                vail.tls.key_exchange.secret_len,
        };
        var offered = try vail.tls.client_connection.ClientPsk.fromCached(
            &cached,
            now_ms,
        );
        var client: Client = undefined;
        try client.initInto(.{
            .allocator = allocator,
            .random = [_]u8{0xa9} ** 32,
            .session_id = &([_]u8{0x43} ** 32),
            .server_name = server_name,
            .key_material = &client_material,
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .alpn_protocols = &.{alpn},
            .request_ocsp = false,
            .certificate_compression_algorithms = &.{},
            .server_verifier = .{},
            .resumption = offered,
        }, &client_wire);
        offered.secret.deinit();
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
                .alpn_protocols = &.{alpn},
            },
            .server_random = [_]u8{0xac} ** 32,
            .key_material = &server_material,
            .certificate_chain = &.{&certificate},
            .signer = .{ .ed25519 = .{
                .key_pair = signing_key,
                .prepared = &prepared_signer,
            } },
            .resumption = .{ .tickets = .{
                .keyring = &keyring,
                .server_id = server_name,
                .now_ms = now_ms,
            } },
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
            std.meta.activeTag(server_result.event.?) != .server_flight or
            !server.has_pending or !server.pending.resumed)
        {
            return error.ServerDidNotResume;
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
        if (!established_client.resumed) return error.ClientDidNotResume;
        try establishServer(
            &server,
            client_finished.items,
            &server_output,
            &established_server,
        );
        defer established_server.deinit();
        if (!established_server.resumed) return error.ServerDidNotResume;

        var ticket_nonce = nonceFor(iteration + 1);
        ticket_record_len = try established_server.sealNewSessionTicket(
            allocator,
            .{
                .keyring = &keyring,
                .sealing_nonce = ticket_nonce,
                .server_id = server_name,
                .alpn = alpn,
                .ticket_nonce = &ticket_nonce,
                .age_add = @truncate(101 + iteration),
                .issued_at_ms = now_ms,
                .lifetime_seconds = 3_600,
            },
            &ticket_record,
        );
        const received_ticket = try established_client.application.receive(
            ticket_record[0..ticket_record_len],
        );
        const next_cached = try established_client.cacheNewSessionTicket(
            received_ticket.event.?.post_handshake,
            server_name,
            now_ms,
        );
        cached.deinit();
        cached = next_cached;

        server_wire_len = server_wire.items.len;
        client_finished_len = client_finished.items.len;
        checksum +%= client_wire.items[client_wire.items.len - 1];
        checksum +%= server_wire.items[server_wire.items.len - 1];
        checksum +%= client_finished.items[client_finished.items.len - 1];
        checksum +%= ticket_record[ticket_record_len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519_psk_aes128={d} ns/resumed-handshake-ticket-rollover " ++
            "hello={d} server-flight={d} client-finished={d} " ++
            "ticket={d} checksum={d}\n",
        .{
            elapsed / iterations,
            client_wire.items.len,
            server_wire_len,
            client_finished_len,
            ticket_record_len,
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

fn nonceFor(value: usize) [vail.tls.ticket_keyring.nonce_len]u8 {
    var nonce = [_]u8{0} ** vail.tls.ticket_keyring.nonce_len;
    std.mem.writeInt(u64, nonce[nonce.len - 8 ..], @intCast(value), .big);
    return nonce;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
