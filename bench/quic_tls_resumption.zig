const std = @import("std");
const vail = @import("vail");

const iterations: usize = 2_000;
const client_transport_parameters = [_]u8{ 0x01, 0x02, 0x03 };
const server_transport_parameters = [_]u8{ 0x04, 0x05, 0x06 };
const early_header = "quic-0rtt-header";
const early_plaintext = [_]u8{0x5a} ** 1_200;
const server_name = "localhost";
const alpn = "h3";

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const use_early_data = if (args.next()) |value|
        std.mem.eql(u8, value, "early")
    else
        false;
    if (args.next() != null) return error.InvalidArguments;
    var keyring = try vail.tls.ticket_keyring.Keyring.init(.{
        .id = 23,
        .secret = [_]u8{0xa6} ** vail.tls.ticket_keyring.key_len,
    });
    defer keyring.deinit();
    var initial_psk = vail.tls.secret.Secret.fromSha256(
        [_]u8{0xa7} ** 32,
    );
    defer initial_psk.deinit();
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
            .max_early_data_size = if (use_early_data)
                vail.tls.ticket.quic_early_data_size
            else
                null,
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
        .max_early_data_size = if (use_early_data)
            vail.tls.ticket.quic_early_data_size
        else
            null,
        .application_settings_codepoint = null,
        .local_application_settings = null,
        .peer_application_settings = null,
    };
    defer cached.deinit();

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xa8} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const signer = vail.tls.auth.Signer{ .ed25519 = .{
        .key_pair = signing_key,
    } };

    var client_initial: std.ArrayList(u8) = .empty;
    defer client_initial.deinit(allocator);
    var server_initial: std.ArrayList(u8) = .empty;
    defer server_initial.deinit(allocator);
    var server_handshake: std.ArrayList(u8) = .empty;
    defer server_handshake.deinit(allocator);
    var client_handshake: std.ArrayList(u8) = .empty;
    defer client_handshake.deinit(allocator);
    var replacement_ticket: std.ArrayList(u8) = .empty;
    defer replacement_ticket.deinit(allocator);
    var early_ciphertext: [early_plaintext.len]u8 = undefined;
    var early_tag: [vail.quic.traffic_crypto.tag_len]u8 = undefined;
    var opened_early: [early_plaintext.len]u8 = undefined;
    var checksum: u64 = 0;
    var server_initial_len: usize = 0;
    var server_handshake_len: usize = 0;
    var client_handshake_len: usize = 0;
    var replacement_ticket_len: usize = 0;

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const now_ms = 11_000 + iteration;
        client_initial.clearRetainingCapacity();
        server_initial.clearRetainingCapacity();
        server_handshake.clearRetainingCapacity();
        client_handshake.clearRetainingCapacity();
        replacement_ticket.clearRetainingCapacity();

        const age_policy = vail.tls.psk.TicketAgePolicy{
            .age_add = cached.age_add,
            .issued_at_ms = cached.received_at_ms,
            .lifetime_seconds = cached.lifetime_seconds,
            .now_ms = now_ms,
        };
        const client_resumption = vail.quic.tls_handshake.ResumptionPsk{
            .identity = cached.identity,
            .secret = cached.psk,
            .suite = cached.suite,
            .age_policy = age_policy,
            .max_early_data_size = cached.max_early_data_size,
        };
        var client_key_material = vail.tls.key_exchange.ClientKeyMaterial{
            .x25519 = [_]u8{0xd1} ** vail.tls.key_exchange.secret_len,
        };
        var client_exchange = try client_key_material.start();
        var client_exchange_live = true;
        defer if (client_exchange_live) client_exchange.deinit();
        try vail.tls.client_hello.writeWithKeyShare(
            &client_initial,
            allocator,
            .{
                .random = [_]u8{0xd2} ** 32,
                .server_name = server_name,
                .key_share = .{
                    .group = client_exchange.namedGroup(),
                    .key_exchange = client_exchange.clientShare(),
                },
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{alpn},
                .quic_transport_parameters = &client_transport_parameters,
            },
        );
        try vail.tls.psk.appendClientOfferForSecret(
            &client_initial,
            allocator,
            client_resumption.identity,
            try cached.obfuscatedTicketAge(now_ms),
            client_resumption.secret,
            use_early_data,
            null,
        );
        var client_early_keys = if (use_early_data)
            try vail.quic.tls_handshake.clientEarlyPacketKeys(
                client_initial.items,
                client_resumption,
                vail.quic.traffic_crypto.labels_v1,
            )
        else
            null;
        defer if (client_early_keys) |*keys| keys.deinit();
        const parsed_client = try vail.tls.client_hello.parse(
            client_initial.items,
        );
        const offer = try vail.tls.psk.parseClientOfferForHash(
            client_initial.items,
            .sha256,
        );

        var opened = try keyring.openSecret(
            offer.identity,
            server_name,
            alpn,
            now_ms,
        );
        defer opened.secret.deinit();
        const opened_suite = vail.tls.cipher_suite.Suite.fromWire(
            opened.cipher_suite_wire,
        ) orelse return error.InvalidTicketSuite;
        const server_resumption = vail.quic.tls_handshake.ResumptionPsk{
            .identity = offer.identity,
            .secret = opened.secret,
            .suite = opened_suite,
            .max_early_data_size = opened.max_early_data_size,
            .age_policy = .{
                .age_add = opened.age_add,
                .issued_at_ms = opened.issued_at_ms,
                .lifetime_seconds = opened.lifetime_seconds,
                .now_ms = now_ms,
            },
        };
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
            &server_initial,
            &server_handshake,
            allocator,
            .{
                .client_hello_bytes = client_initial.items,
                .parsed_client_hello = parsed_client,
                .policy = .{
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .groups = &.{vail.tls.key_exchange.named_group_x25519},
                    .alpn_protocols = &.{alpn},
                    .quic_transport_parameters = &server_transport_parameters,
                },
                .server_random = [_]u8{0xc2} ** 32,
                .server_key_share = server_exchange.serverShare(),
                .shared_secret = server_exchange.sharedSecretBytes(),
                .certificate_chain = &.{},
                .signer = signer,
                .resumption = server_resumption,
                .accept_early_data = use_early_data,
            },
        );
        defer server_result.deinit();

        if (use_early_data) {
            const client_keys = if (client_early_keys) |*keys|
                keys
            else
                return error.MissingClientEarlyKeys;
            const server_keys = if (server_result.client_early_packet_keys) |*keys|
                keys
            else
                return error.MissingServerEarlyKeys;
            try client_keys.protect(
                7,
                early_header,
                &early_plaintext,
                &early_ciphertext,
                &early_tag,
            );
            try server_keys.open(
                7,
                early_header,
                &early_ciphertext,
                early_tag,
                &opened_early,
            );
            if (!std.mem.eql(u8, &opened_early, &early_plaintext)) {
                return error.EarlyDataMismatch;
            }
        } else if (server_result.client_early_packet_keys != null) {
            return error.UnexpectedServerEarlyKeys;
        }

        var client_result = try vail.quic.tls_handshake.writeClientCryptoFlight(
            &client_handshake,
            allocator,
            .{
                .client_hello_bytes = client_initial.items,
                .server_hello_bytes = server_initial.items,
                .server_handshake_crypto = server_handshake.items,
                .shared_secret = client_shared_secret.bytes(),
                .server_verifier = .{},
                .server_name = server_name,
                .resumption = client_resumption,
            },
        );
        defer client_result.deinit();
        var verified_client = try vail.quic.tls_handshake
            .verifyClientCryptoFlight(
            allocator,
            &server_result,
            client_handshake.items,
        );
        defer verified_client.deinit();

        if (!server_result.resumed or !client_result.resumed or
            client_result.verified.early_data_accepted != use_early_data or
            client_result.verified.peer_certificate_chain.len != 0 or
            !std.mem.eql(u8, client_result.selected_alpn, alpn) or
            !std.mem.eql(
                u8,
                client_result.peer_transport_parameters,
                &server_transport_parameters,
            ) or verified_client.peer_certificate_chain.len != 0)
        {
            return error.UnexpectedHandshake;
        }
        try checkDirectionalKeys(
            &client_result.handshake_packet_keys,
            &server_result.handshake_packet_keys,
        );
        try checkDirectionalKeys(
            &client_result.application_packet_keys,
            &server_result.application_packet_keys,
        );

        const ticket_nonce = nonceFor(iteration + 1);
        try vail.quic.tls_handshake.writeNewSessionTicket(
            &replacement_ticket,
            allocator,
            &server_result,
            &verified_client,
            .{
                .keyring = &keyring,
                .sealing_nonce = ticket_nonce,
                .server_id = server_name,
                .alpn = alpn,
                .ticket_nonce = &ticket_nonce,
                .age_add = @truncate(101 + iteration),
                .issued_at_ms = now_ms,
                .lifetime_seconds = 3_600,
                .allow_early_data = use_early_data,
            },
        );
        const next_cached = try vail.tls.ticket.cache(
            allocator,
            replacement_ticket.items,
            client_result.verified.cipher_suite,
            client_result.verified.application.master_secret,
            client_result.verified.transcript_after_client_finished,
            server_name,
            alpn,
            now_ms,
        );
        if (std.mem.eql(u8, cached.identity, next_cached.identity)) {
            var rejected = next_cached;
            rejected.deinit();
            return error.TicketDidNotRollOver;
        }
        cached.deinit();
        cached = next_cached;

        server_initial_len = server_initial.items.len;
        server_handshake_len = server_handshake.items.len;
        client_handshake_len = client_handshake.items.len;
        replacement_ticket_len = replacement_ticket.items.len;
        checksum +%= client_initial.items[client_initial.items.len - 1];
        checksum +%= server_initial.items[server_initial.items.len - 1];
        checksum +%= server_handshake.items[server_handshake.items.len - 1];
        checksum +%= client_handshake.items[client_handshake.items.len - 1];
        checksum +%= replacement_ticket.items[replacement_ticket.items.len - 1];
        if (use_early_data) checksum +%= opened_early[iteration % opened_early.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519-psk-aes128={d} ns/{s}-quic-tls13-ticket-rollover " ++
            "client-initial={d} server-initial={d} server-handshake={d} " ++
            "client-handshake={d} ticket={d} checksum={d}\n",
        .{
            elapsed / iterations,
            if (use_early_data) "0rtt" else "resumed",
            client_initial.items.len,
            server_initial_len,
            server_handshake_len,
            client_handshake_len,
            replacement_ticket_len,
            checksum,
        },
    );
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
