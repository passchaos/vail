//! TLS 1.3 encrypted server handshake flight construction.
//!
//! This module composes the lower-level negotiation, key schedule, record
//! protection, and authentication codecs into the server's first TLS 1.3
//! flight: cleartext ServerHello followed by encrypted EncryptedExtensions,
//! Certificate, CertificateVerify, and Finished records.

const std = @import("std");
const application_settings = @import("application_settings.zig");
const auth = @import("auth.zig");
const certificate_compression = @import("certificate_compression.zig");
const client_auth = @import("client_auth.zig");
const client_hello = @import("client_hello.zig");
const ech = @import("ech.zig");
const key_exchange = @import("key_exchange.zig");
const key_schedule = @import("key_schedule.zig");
const psk_module = @import("psk.zig");
const record = @import("record.zig");
const record_size_limit = @import("record_size_limit.zig");
const secret = @import("secret.zig");
const server_flight = @import("server_flight.zig");
const server_hello = @import("server_hello.zig");
const stream = @import("stream.zig");
const traffic = @import("traffic.zig");
const transcript = @import("transcript.zig");

pub const handshake_type_finished: u8 = 0x14;

pub const Error = std.mem.Allocator.Error || server_flight.Error ||
    client_hello.Error ||
    key_schedule.Error || record.Error || traffic.Error || auth.Error ||
    certificate_compression.Error ||
    application_settings.Error ||
    record_size_limit.Error ||
    key_exchange.Error ||
    client_auth.Error || ech.Error || error{
    InvalidFinished,
    InvalidPskSelection,
    MissingServerKeyMaterial,
};

pub const Result = struct {
    selection: server_flight.Selection,
    handshake_secret: secret.Secret,
    client_handshake_traffic_secret: secret.Secret,
    server_handshake_traffic_secret: secret.Secret,
    transcript_after_server_finished: transcript.Digest,
    /// Cloneable state retained at the server Finished boundary. Stream and
    /// QUIC transports extend it with the client's authentication flight.
    transcript_state_after_server_finished: transcript.State,
    early_data_accepted: bool,
    certificate_compression: ?certificate_compression.Algorithm,
    local_record_size_limit: ?u16,
    peer_record_size_limit: ?u16,
    requested_ticket_count: u8,
    application_settings: ?application_settings.Payload,
    client_application_settings_required: bool,
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
    psk: ?secret.Secret = null,
    selected_psk_identity: ?u16 = null,
    accept_early_data: bool = false,
    /// Present only when `client_hello_bytes` is an accepted ECH inner hello.
    ech_inner_random: ?[32]u8 = null,
    ech_retry_configs: ?[]const u8 = null,
    /// Transcript through ClientHello2 for a HelloRetryRequest handshake.
    /// Null starts the ordinary transcript with `client_hello_bytes`.
    transcript_prefix: ?transcript.State = null,
    /// Emit CertificateRequest immediately after EncryptedExtensions.
    client_auth: ?ClientAuthOptions = null,
    record_size_limit: ?u16 = null,
    max_requested_tickets: u8 = 0,
    early_application_settings_validated: bool = false,
};

pub const ClientAuthOptions = struct {
    request_context: []const u8 = &.{},
    certificate_authorities: []const []const u8 = &.{},
    /// Optional constraints for signatures on the client's X.509 chain.
    certificate_signature_schemes: ?[]const u16 = null,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{
        .zlib,
        .brotli,
        .zstd,
    },
    max_decompressed_certificate_len: usize = 64 * 1024,
};

/// Server-flight inputs with single-use key-exchange material. Unlike
/// `Options`, this API does not trust its caller to construct the ServerHello
/// share or ECDHE/KEM shared secret consistently.
pub const ManagedOptions = struct {
    client_hello_bytes: []const u8,
    parsed_client_hello: client_hello.Parsed,
    policy: server_flight.Policy,
    server_random: [32]u8,
    key_material: *key_exchange.ServerKeyMaterial,
    certificate_chain: []const []const u8,
    signer: auth.Signer,
    psk: ?secret.Secret = null,
    selected_psk_identity: ?u16 = null,
    accept_early_data: bool = false,
    ech_inner_random: ?[32]u8 = null,
    ech_retry_configs: ?[]const u8 = null,
    transcript_prefix: ?transcript.State = null,
    client_auth: ?ClientAuthOptions = null,
    record_size_limit: ?u16 = null,
    max_requested_tickets: u8 = 0,
    early_application_settings_validated: bool = false,
};

/// Select the offered share, complete key exchange, and construct the server
/// flight. `key_material` is consumed and wiped on every return path.
pub fn writeServerHandshakeFlightManaged(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: ManagedOptions,
) Error!Result {
    defer options.key_material.wipe();
    const material_group = options.key_material.namedGroup();
    var material_allowed = false;
    for (options.policy.groups) |group| {
        if (group == material_group) material_allowed = true;
    }
    if (!material_allowed) return error.MissingServerKeyMaterial;
    if (options.psk == null and
        !try options.parsed_client_hello.supportsSignatureScheme(
            options.signer.scheme(),
        )) return error.UnsupportedSignatureScheme;

    const managed_groups = [_]u16{material_group};
    var managed_policy = options.policy;
    managed_policy.groups = &managed_groups;
    const selection = try server_flight.select(
        options.parsed_client_hello,
        managed_policy,
    );
    const client_share = (try options.parsed_client_hello.keyShareForGroup(
        selection.key_share_group,
    )) orelse return error.NoSupportedKeyShare;
    var exchange = try options.key_material.respond(
        client_share.key_exchange,
    );
    defer exchange.deinit();
    return writeServerHandshakeFlightSelected(out, allocator, .{
        .client_hello_bytes = options.client_hello_bytes,
        .parsed_client_hello = options.parsed_client_hello,
        .policy = managed_policy,
        .server_random = options.server_random,
        .server_key_share = exchange.serverShare(),
        .shared_secret = exchange.sharedSecretBytes(),
        .certificate_chain = options.certificate_chain,
        .signer = options.signer,
        .psk = options.psk,
        .selected_psk_identity = options.selected_psk_identity,
        .accept_early_data = options.accept_early_data,
        .ech_inner_random = options.ech_inner_random,
        .ech_retry_configs = options.ech_retry_configs,
        .transcript_prefix = options.transcript_prefix,
        .client_auth = options.client_auth,
        .record_size_limit = options.record_size_limit,
        .max_requested_tickets = options.max_requested_tickets,
        .early_application_settings_validated = options.early_application_settings_validated,
    }, selection);
}

pub fn writeServerHandshakeFlight(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: Options,
) Error!Result {
    const selection = try server_flight.select(
        options.parsed_client_hello,
        options.policy,
    );
    return writeServerHandshakeFlightSelected(
        out,
        allocator,
        options,
        selection,
    );
}

fn writeServerHandshakeFlightSelected(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: Options,
    selection: server_flight.Selection,
) Error!Result {
    if ((options.psk == null) !=
        (options.selected_psk_identity == null))
    {
        return error.InvalidPskSelection;
    }
    if (options.accept_early_data and options.psk == null) {
        return error.InvalidPskSelection;
    }
    if (options.accept_early_data and selection.application_settings != null and
        !options.early_application_settings_validated)
    {
        return error.InvalidApplicationSettings;
    }
    if (options.ech_inner_random != null and
        options.ech_retry_configs != null)
    {
        return error.InvalidEchExtension;
    }
    if (options.record_size_limit) |limit| {
        _ = record_size_limit.validate(limit) catch
            return error.InvalidEncryptedExtensions;
    }
    if (options.psk) |psk_secret| {
        if (psk_secret.hash != selection.suite.hash()) {
            return error.HashMismatch;
        }
    }
    if (options.psk == null and
        selection.server_certificate_type == .x509 and
        !try options.parsed_client_hello.supportsCertificateChain(
            options.certificate_chain,
        ))
    {
        return error.UnsupportedSignatureScheme;
    }
    var server_hello_msg: std.ArrayList(u8) = .empty;
    defer server_hello_msg.deinit(allocator);
    var server_random = options.server_random;
    if (options.ech_inner_random != null) {
        @memset(server_random[server_random.len - ech.confirmation_len ..], 0);
    }
    try server_hello.writeServerHello(&server_hello_msg, allocator, .{
        .random = server_random,
        .session_id_echo = options.parsed_client_hello.session_id,
        .cipher_suite = selection.suite,
        .key_share_group = selection.key_share_group,
        .key_share = options.server_key_share,
        .selected_psk_identity = options.selected_psk_identity,
    });
    if (options.ech_inner_random) |inner_random| {
        var confirmation_transcript = options.transcript_prefix orelse blk: {
            var state = transcript.State.init(selection.suite.hash());
            state.update(options.client_hello_bytes);
            break :blk state;
        };
        confirmation_transcript.update(server_hello_msg.items);
        const confirmation = try ech.acceptConfirmation(
            selection.suite.hash(),
            inner_random,
            confirmation_transcript.digest(),
        );
        const confirmation_offset = 4 + 2 + 32 - ech.confirmation_len;
        server_hello_msg.items[confirmation_offset..][0..ech.confirmation_len].* =
            confirmation;
    }
    try out.appendSlice(allocator, server_hello_msg.items);

    var transcript_state = options.transcript_prefix orelse blk: {
        var state = transcript.State.init(selection.suite.hash());
        state.update(options.client_hello_bytes);
        break :blk state;
    };
    transcript_state.update(server_hello_msg.items);
    const hello_hash = transcript_state.digest();
    var handshake = try key_schedule.deriveHandshakeFor(
        selection.suite.hash(),
        options.shared_secret,
        hello_hash,
        options.psk,
    );
    defer handshake.early_secret.deinit();
    var record_traffic = try traffic.State.init(
        selection.suite,
        handshake.server_traffic_secret,
    );
    defer record_traffic.deinit();

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(allocator);
    const local_record_size_limit = if (options.parsed_client_hello.record_size_limit != null) options.record_size_limit else null;
    const peer_fragment_limit = if (options.parsed_client_hello.record_size_limit) |limit| try record_size_limit.maxApplicationData(limit) else record.max_plaintext_len;
    const can_resume = std.mem.indexOfScalar(
        u8,
        options.parsed_client_hello.psk_key_exchange_modes,
        psk_module.psk_dhe_ke,
    ) != null;
    const requested_ticket_count: u8 = if (can_resume) if (options.parsed_client_hello.ticket_request) |request|
        @min(
            if (options.psk == null)
                request.new_session_count
            else
                request.resumption_count,
            options.max_requested_tickets,
        )
    else
        0 else 0;
    const ticket_request_hint: ?u8 = if (options.parsed_client_hello.ticket_request != null and
        options.max_requested_tickets != 0) requested_ticket_count else null;
    try server_hello.writeEncryptedExtensions(&encrypted_extensions, allocator, .{
        .alpn_protocol = selection.alpn_protocol,
        .quic_transport_parameters = options.policy.quic_transport_parameters,
        .accept_early_data = options.accept_early_data,
        .server_certificate_type = if (selection.send_server_certificate_type)
            selection.server_certificate_type
        else
            null,
        .client_certificate_type = if (selection.send_client_certificate_type)
            selection.client_certificate_type
        else
            null,
        .ech_retry_configs = options.ech_retry_configs,
        .record_size_limit = local_record_size_limit,
        .ticket_request_hint = ticket_request_hint,
        .application_settings = if (options.accept_early_data)
            null
        else
            selection.application_settings,
    });
    try appendEncryptedHandshake(
        out,
        allocator,
        &record_traffic,
        encrypted_extensions.items,
        peer_fragment_limit,
    );
    transcript_state.update(encrypted_extensions.items);

    var certificate_request: std.ArrayList(u8) = .empty;
    defer certificate_request.deinit(allocator);
    if (options.client_auth) |client_auth_options| {
        try client_auth.writeRequestWithOptions(
            &certificate_request,
            allocator,
            .{
                .request_context = client_auth_options.request_context,
                .certificate_authorities = client_auth_options.certificate_authorities,
                .compression_algorithms = client_auth_options.certificate_compression_algorithms,
                .certificate_signature_schemes = client_auth_options.certificate_signature_schemes,
            },
        );
        try appendEncryptedHandshake(
            out,
            allocator,
            &record_traffic,
            certificate_request.items,
            peer_fragment_limit,
        );
        transcript_state.update(certificate_request.items);
    }

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    var certificate_verify: std.ArrayList(u8) = .empty;
    defer certificate_verify.deinit(allocator);
    var selected_certificate_compression: ?certificate_compression.Algorithm = null;
    if (options.psk == null) {
        if (selection.server_certificate_type == .x509 and
            options.parsed_client_hello.requests_ocsp and
            options.policy.ocsp_response != null)
        {
            try auth.writeCertificateWithOcsp(
                &certificate,
                allocator,
                options.certificate_chain,
                options.policy.ocsp_response.?,
            );
        } else {
            try auth.writeCertificate(
                &certificate,
                allocator,
                options.certificate_chain,
            );
        }
        var compressed_certificate: std.ArrayList(u8) = .empty;
        defer compressed_certificate.deinit(allocator);
        const certificate_wire = for (options.policy.compressed_certificates) |prepared| {
            if (options.parsed_client_hello.supportsCertificateCompression(
                prepared.algorithm,
            ) and prepared.matchesCertificateMessage(certificate.items) and
                prepared.savesBytes(certificate.items.len))
            {
                try prepared.write(&compressed_certificate, allocator);
                selected_certificate_compression = prepared.algorithm;
                break compressed_certificate.items;
            }
        } else certificate.items;
        try appendEncryptedHandshake(
            out,
            allocator,
            &record_traffic,
            certificate_wire,
            peer_fragment_limit,
        );
        transcript_state.update(certificate_wire);

        const certificate_verify_hash = transcript_state.digest();
        try auth.writeCertificateVerify(
            &certificate_verify,
            allocator,
            options.signer,
            certificate_verify_hash.bytes(),
        );
        try appendEncryptedHandshake(
            out,
            allocator,
            &record_traffic,
            certificate_verify.items,
            peer_fragment_limit,
        );
        transcript_state.update(certificate_verify.items);
    }

    const finished_hash = transcript_state.digest();
    const verify_data = try key_schedule.computeFinishedFor(
        handshake.server_traffic_secret,
        finished_hash,
    );
    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try writeFinished(&finished, allocator, verify_data.bytes());
    try appendEncryptedHandshake(
        out,
        allocator,
        &record_traffic,
        finished.items,
        peer_fragment_limit,
    );
    transcript_state.update(finished.items);
    const transcript_after_server_finished = transcript_state.digest();

    return .{
        .selection = selection,
        .handshake_secret = handshake.handshake_secret,
        .client_handshake_traffic_secret = handshake.client_traffic_secret,
        .server_handshake_traffic_secret = handshake.server_traffic_secret,
        .transcript_after_server_finished = transcript_after_server_finished,
        .transcript_state_after_server_finished = transcript_state,
        .early_data_accepted = options.accept_early_data,
        .certificate_compression = selected_certificate_compression,
        .local_record_size_limit = local_record_size_limit,
        .peer_record_size_limit = options.parsed_client_hello.record_size_limit,
        .requested_ticket_count = requested_ticket_count,
        .application_settings = selection.application_settings,
        .client_application_settings_required = selection.application_settings != null and
            !options.accept_early_data,
    };
}

fn appendEncryptedHandshake(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    record_traffic: *traffic.State,
    handshake_message: []const u8,
    max_fragment_plaintext: usize,
) Error!void {
    var buffer: [record.max_record_len]u8 = undefined;
    var offset: usize = 0;
    while (offset < handshake_message.len) {
        const chunk_len = @min(
            max_fragment_plaintext,
            handshake_message.len - offset,
        );
        const len = try record_traffic.seal(
            record.content_type_handshake,
            handshake_message[offset..][0..chunk_len],
            &buffer,
        );
        try out.appendSlice(allocator, buffer[0..len]);
        offset += chunk_len;
    }
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

test "server handshake flight encrypts messages after ServerHello" {
    const hello = [_]u8{
        0x01, 0x00, 0x00, 0x6c, 0x03, 0x03,
    } ++ ([_]u8{0x11} ** 32) ++ [_]u8{
        0x03, 1,    2,    3,
        0x00, 0x04, 0x13, 0x01,
        0x13, 0x03, 0x01, 0x00,
        0x00, 0x3c, 0x00, 0x2b,
        0x00, 0x03, 0x02, 0x03,
        0x04, 0x00, 0x10, 0x00,
        0x05, 0x00, 0x03, 0x02,
        'h',  '2',  0x00, 0x33,
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
        0x00, 0x1d,
    };
    const parsed = try client_hello.parse(&hello);
    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x55} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const cert = key_pair.public_key.toBytes();
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(std.testing.allocator);
    const result = try writeServerHandshakeFlight(&flight, std.testing.allocator, .{
        .client_hello_bytes = &hello,
        .parsed_client_hello = parsed,
        .policy = .{ .alpn_protocols = &.{"h2"} },
        .server_random = [_]u8{0x22} ** 32,
        .server_key_share = &.{ 9, 8, 7, 6 },
        .shared_secret = &([_]u8{0x33} ** 32),
        .certificate_chain = &.{&cert},
        .signer = .{ .ed25519 = .{ .key_pair = key_pair } },
    });
    try std.testing.expectEqual(@as(u8, server_hello.handshake_type_server_hello), flight.items[0]);
    const server_hello_len = 4 + ((@as(usize, flight.items[1]) << 16) |
        (@as(usize, flight.items[2]) << 8) | flight.items[3]);
    var keys = try record.Keys.derive(
        result.selection.suite,
        result.server_handshake_traffic_secret,
    );
    defer keys.deinit();
    var opened: [1024]u8 = undefined;
    const encrypted_len = std.mem.readInt(u16, flight.items[server_hello_len + 3 ..][0..2], .big);
    const first_record = flight.items[server_hello_len..][0 .. record.header_len + encrypted_len];
    const first = try keys.open(0, first_record, &opened);
    try std.testing.expectEqual(@as(u8, server_hello.handshake_type_encrypted_extensions), opened[0]);
    try std.testing.expectEqual(record.content_type_handshake, first.content_type);
}

test "server handshake flight inserts encrypted CertificateRequest" {
    const hello = [_]u8{
        0x01, 0x00, 0x00, 0x6c, 0x03, 0x03,
    } ++ ([_]u8{0x11} ** 32) ++ [_]u8{
        0x03, 1,    2,    3,
        0x00, 0x04, 0x13, 0x01,
        0x13, 0x03, 0x01, 0x00,
        0x00, 0x3c, 0x00, 0x2b,
        0x00, 0x03, 0x02, 0x03,
        0x04, 0x00, 0x10, 0x00,
        0x05, 0x00, 0x03, 0x02,
        'h',  '2',  0x00, 0x33,
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
        0x00, 0x1d,
    };
    const parsed = try client_hello.parse(&hello);
    const key_pair = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x65} **
            std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const cert = key_pair.public_key.toBytes();
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(std.testing.allocator);
    var result = try writeServerHandshakeFlight(
        &flight,
        std.testing.allocator,
        .{
            .client_hello_bytes = &hello,
            .parsed_client_hello = parsed,
            .policy = .{},
            .server_random = [_]u8{0x66} ** 32,
            .server_key_share = &.{ 9, 8, 7, 6 },
            .shared_secret = &([_]u8{0x67} ** 32),
            .certificate_chain = &.{&cert},
            .signer = .{ .ed25519 = .{ .key_pair = key_pair } },
            .client_auth = .{
                .request_context = "client-auth",
                .certificate_authorities = &.{"test-ca"},
            },
        },
    );
    defer result.handshake_secret.deinit();
    defer result.client_handshake_traffic_secret.deinit();
    defer result.server_handshake_traffic_secret.deinit();

    const server_hello_len = 4 +
        ((@as(usize, flight.items[1]) << 16) |
            (@as(usize, flight.items[2]) << 8) |
            flight.items[3]);
    var keys = try record.Keys.derive(
        result.selection.suite,
        result.server_handshake_traffic_secret,
    );
    defer keys.deinit();
    var offset = server_hello_len;
    var plaintext: [1024]u8 = undefined;
    const encrypted_extensions = try openRecordAt(
        flight.items,
        &offset,
        &keys,
        0,
        &plaintext,
    );
    try std.testing.expectEqual(
        server_hello.handshake_type_encrypted_extensions,
        encrypted_extensions[0],
    );
    const request = try openRecordAt(
        flight.items,
        &offset,
        &keys,
        1,
        &plaintext,
    );
    const parsed_request = try client_auth.parseRequest(request);
    try std.testing.expectEqualStrings(
        "client-auth",
        parsed_request.request_context,
    );
}

fn openRecordAt(
    flight: []const u8,
    offset: *usize,
    keys: *const record.Keys,
    sequence: u64,
    plaintext: []u8,
) ![]const u8 {
    if (flight.len - offset.* < record.header_len) {
        return error.InvalidServerFlight;
    }
    const encrypted_len = std.mem.readInt(
        u16,
        flight[offset.* + 3 ..][0..2],
        .big,
    );
    const record_len = record.header_len + encrypted_len;
    if (record_len > flight.len - offset.*) {
        return error.InvalidServerFlight;
    }
    const opened = try keys.open(
        sequence,
        flight[offset.* .. offset.* + record_len],
        plaintext,
    );
    offset.* += record_len;
    if (opened.content_type != record.content_type_handshake) {
        return error.InvalidServerFlight;
    }
    return plaintext[0..opened.len];
}

test "server handshake staples OCSP only when requested" {
    const allocator = std.testing.allocator;
    const public_key = [_]u8{0x71} ** key_exchange.secret_len;
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x72} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    const ocsp_response = "authenticated-ocsp-response";

    for ([_]bool{ true, false }) |request_ocsp| {
        var hello: std.ArrayList(u8) = .empty;
        defer hello.deinit(allocator);
        try client_hello.write(&hello, allocator, .{
            .random = [_]u8{0x73} ** 32,
            .x25519_public_key = public_key,
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .request_ocsp = request_ocsp,
        });
        const parsed_hello = try client_hello.parse(hello.items);

        var flight: std.ArrayList(u8) = .empty;
        defer flight.deinit(allocator);
        var result = try writeServerHandshakeFlight(
            &flight,
            allocator,
            .{
                .client_hello_bytes = hello.items,
                .parsed_client_hello = parsed_hello,
                .policy = .{
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .groups = &.{key_exchange.named_group_x25519},
                    .ocsp_response = ocsp_response,
                },
                .server_random = [_]u8{0x74} ** 32,
                .server_key_share = &([_]u8{0x75} ** 32),
                .shared_secret = &([_]u8{0x76} ** 32),
                .certificate_chain = &.{&certificate},
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            },
        );
        defer result.handshake_secret.deinit();
        defer result.client_handshake_traffic_secret.deinit();
        defer result.server_handshake_traffic_secret.deinit();

        const server_hello_len = 4 +
            ((@as(usize, flight.items[1]) << 16) |
                (@as(usize, flight.items[2]) << 8) |
                flight.items[3]);
        var keys = try record.Keys.derive(
            result.selection.suite,
            result.server_handshake_traffic_secret,
        );
        defer keys.deinit();
        var offset = server_hello_len;
        var plaintext: [1024]u8 = undefined;
        _ = try openRecordAt(
            flight.items,
            &offset,
            &keys,
            0,
            &plaintext,
        );
        const certificate_message = try openRecordAt(
            flight.items,
            &offset,
            &keys,
            1,
            &plaintext,
        );
        var parsed_certificate = try auth.parseCertificate(
            allocator,
            certificate_message,
        );
        defer parsed_certificate.deinit(allocator);
        if (request_ocsp) {
            try std.testing.expectEqualStrings(
                ocsp_response,
                parsed_certificate.ocsp_response.?,
            );
        } else {
            try std.testing.expect(parsed_certificate.ocsp_response == null);
        }
    }
}

test "server handshake selects a matching offered compressed certificate" {
    const allocator = std.testing.allocator;
    const public_key = [_]u8{0x79} ** key_exchange.secret_len;
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.write(&hello, allocator, .{
        .random = [_]u8{0x7a} ** 32,
        .x25519_public_key = public_key,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .certificate_compression_algorithms = &.{.zlib},
    });
    const parsed_hello = try client_hello.parse(hello.items);

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x7b} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const large_certificate = [_]u8{0x7c} ** 4096;
    var ordinary: std.ArrayList(u8) = .empty;
    defer ordinary.deinit(allocator);
    try auth.writeCertificate(
        &ordinary,
        allocator,
        &.{&large_certificate},
    );
    var prepared = try certificate_compression.Prepared.initZlib(
        allocator,
        ordinary.items,
        .amortized,
    );
    defer prepared.deinit();
    const compressed = [_]certificate_compression.PreparedView{
        prepared.view(),
    };

    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    var result = try writeServerHandshakeFlight(
        &flight,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed_hello,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{key_exchange.named_group_x25519},
                .compressed_certificates = &compressed,
            },
            .server_random = [_]u8{0x7d} ** 32,
            .server_key_share = &([_]u8{0x7e} ** 32),
            .shared_secret = &([_]u8{0x7f} ** 32),
            .certificate_chain = &.{&large_certificate},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        },
    );
    defer result.handshake_secret.deinit();
    defer result.client_handshake_traffic_secret.deinit();
    defer result.server_handshake_traffic_secret.deinit();

    const server_hello_len = 4 +
        ((@as(usize, flight.items[1]) << 16) |
            (@as(usize, flight.items[2]) << 8) |
            flight.items[3]);
    var keys = try record.Keys.derive(
        result.selection.suite,
        result.server_handshake_traffic_secret,
    );
    defer keys.deinit();
    var offset = server_hello_len;
    var plaintext: [1024]u8 = undefined;
    _ = try openRecordAt(flight.items, &offset, &keys, 0, &plaintext);
    const certificate_message = try openRecordAt(
        flight.items,
        &offset,
        &keys,
        1,
        &plaintext,
    );
    try std.testing.expectEqual(
        certificate_compression.handshake_type_compressed_certificate,
        certificate_message[0],
    );
    try std.testing.expectEqual(
        certificate_compression.Algorithm.zlib,
        result.certificate_compression.?,
    );
    const restored = try certificate_compression.decompressCertificate(
        allocator,
        certificate_message,
        &.{.zlib},
        ordinary.items.len,
    );
    defer allocator.free(restored);
    try std.testing.expectEqualSlices(u8, ordinary.items, restored);
}

test "managed server flight binds ServerHello to internal X25519 exchange" {
    const allocator = std.testing.allocator;
    const client_private = [_]u8{0xa1} ** key_exchange.secret_len;
    const client_public = try key_exchange.publicKey(client_private);
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.write(&hello, allocator, .{
        .random = [_]u8{0xa2} ** 32,
        .server_name = "example.com",
        .x25519_public_key = client_public,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    const parsed = try client_hello.parse(hello.items);

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xa3} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    const server_private = [_]u8{0xa4} ** key_exchange.secret_len;
    var key_material = key_exchange.ServerKeyMaterial{
        .x25519 = server_private,
    };
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    var result = try writeServerHandshakeFlightManaged(
        &flight,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{key_exchange.named_group_x25519},
            },
            .server_random = [_]u8{0xa5} ** 32,
            .key_material = &key_material,
            .certificate_chain = &.{&certificate},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        },
    );
    defer result.handshake_secret.deinit();
    defer result.client_handshake_traffic_secret.deinit();
    defer result.server_handshake_traffic_secret.deinit();

    const server_hello_len = 4 +
        ((@as(usize, flight.items[1]) << 16) |
            (@as(usize, flight.items[2]) << 8) |
            flight.items[3]);
    const parsed_server = try server_hello.parseServerHello(
        flight.items[0..server_hello_len],
    );
    const client_shared = try key_exchange.sharedSecret(
        client_private,
        parsed_server.key_share,
    );
    const hello_hash = transcript.hashFor(
        result.selection.suite.hash(),
        &.{ hello.items, flight.items[0..server_hello_len] },
    );
    var client_handshake = try key_schedule.deriveHandshakeFor(
        result.selection.suite.hash(),
        &client_shared,
        hello_hash,
        null,
    );
    defer client_handshake.early_secret.deinit();
    defer client_handshake.handshake_secret.deinit();
    defer client_handshake.client_traffic_secret.deinit();
    defer client_handshake.server_traffic_secret.deinit();
    try std.testing.expect(
        result.handshake_secret.eql(&client_handshake.handshake_secret),
    );
    try std.testing.expect(
        result.client_handshake_traffic_secret.eql(
            &client_handshake.client_traffic_secret,
        ),
    );
}

test "server handshake fragments large Certificate messages across records" {
    const allocator = std.testing.allocator;
    const client_private = [_]u8{0xe1} ** key_exchange.secret_len;
    const client_public = try key_exchange.publicKey(client_private);
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.write(&hello, allocator, .{
        .random = [_]u8{0xe2} ** 32,
        .x25519_public_key = client_public,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    const parsed = try client_hello.parse(hello.items);
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xe3} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const large_certificate =
        [_]u8{0xe4} ** (record.max_plaintext_len + 1024);
    var material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xe5} ** key_exchange.secret_len,
    };
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    var result = try writeServerHandshakeFlightManaged(
        &flight,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{key_exchange.named_group_x25519},
            },
            .server_random = [_]u8{0xe6} ** 32,
            .key_material = &material,
            .certificate_chain = &.{&large_certificate},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        },
    );
    defer result.handshake_secret.deinit();
    defer result.client_handshake_traffic_secret.deinit();
    defer result.server_handshake_traffic_secret.deinit();

    const server_hello_len = 4 +
        ((@as(usize, flight.items[1]) << 16) |
            (@as(usize, flight.items[2]) << 8) |
            flight.items[3]);
    var opener = try traffic.State.init(
        result.selection.suite,
        result.server_handshake_traffic_secret,
    );
    defer opener.deinit();
    var messages = stream.HandshakeReassembler(
        2 * record.max_plaintext_len,
    ){};
    var plaintext: [record.max_inner_plaintext_len]u8 = undefined;
    var offset = server_hello_len;
    var record_count: usize = 0;
    var message_count: usize = 0;
    var saw_large_certificate = false;
    while (offset < flight.items.len) {
        const encrypted_len = std.mem.readInt(
            u16,
            flight.items[offset + 3 ..][0..2],
            .big,
        );
        try std.testing.expect(encrypted_len <= record.max_ciphertext_len);
        const encoded_len = record.header_len + encrypted_len;
        const opened = try opener.open(
            flight.items[offset..][0..encoded_len],
            &plaintext,
        );
        record_count += 1;
        var remaining = plaintext[0..opened.len];
        while (remaining.len != 0) {
            const message = try messages.push(remaining);
            remaining = remaining[message.consumed..];
            if (message.message) |complete| {
                message_count += 1;
                if (complete[0] == auth.handshake_type_certificate) {
                    try std.testing.expect(
                        complete.len > record.max_plaintext_len,
                    );
                    saw_large_certificate = true;
                }
            }
        }
        offset += encoded_len;
    }
    try std.testing.expect(saw_large_certificate);
    try std.testing.expectEqual(@as(usize, 4), message_count);
    try std.testing.expect(record_count > message_count);
}
