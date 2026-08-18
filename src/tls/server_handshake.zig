//! TLS 1.3 encrypted server handshake flight construction.
//!
//! This module composes the lower-level negotiation, key schedule, record
//! protection, and authentication codecs into the server's first TLS 1.3
//! flight: cleartext ServerHello followed by encrypted EncryptedExtensions,
//! Certificate, CertificateVerify, and Finished records.

const std = @import("std");
const auth = @import("auth.zig");
const client_auth = @import("client_auth.zig");
const client_hello = @import("client_hello.zig");
const key_schedule = @import("key_schedule.zig");
const record = @import("record.zig");
const secret = @import("secret.zig");
const server_flight = @import("server_flight.zig");
const server_hello = @import("server_hello.zig");
const transcript = @import("transcript.zig");

pub const handshake_type_finished: u8 = 0x14;

pub const Error = std.mem.Allocator.Error || server_flight.Error ||
    key_schedule.Error || record.Error || auth.Error ||
    client_auth.Error || error{
    InvalidFinished,
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
    /// Emit CertificateRequest immediately after EncryptedExtensions.
    client_auth: ?ClientAuthOptions = null,
};

pub const ClientAuthOptions = struct {
    request_context: []const u8 = &.{},
    certificate_authorities: []const []const u8 = &.{},
};

pub fn writeServerHandshakeFlight(
    out: *std.ArrayList(u8),
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
    try out.appendSlice(allocator, server_hello_msg.items);

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
    var record_keys = try record.Keys.derive(
        selection.suite,
        handshake.server_traffic_secret,
    );
    defer record_keys.deinit();

    var sequence_number: u64 = 0;
    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(allocator);
    try server_hello.writeEncryptedExtensions(&encrypted_extensions, allocator, .{
        .alpn_protocol = selection.alpn_protocol,
        .quic_transport_parameters = options.policy.quic_transport_parameters,
    });
    try appendEncryptedHandshake(
        out,
        allocator,
        &record_keys,
        &sequence_number,
        encrypted_extensions.items,
    );

    var certificate_request: std.ArrayList(u8) = .empty;
    defer certificate_request.deinit(allocator);
    if (options.client_auth) |client_auth_options| {
        try client_auth.writeRequest(
            &certificate_request,
            allocator,
            client_auth_options.request_context,
            client_auth_options.certificate_authorities,
        );
        try appendEncryptedHandshake(
            out,
            allocator,
            &record_keys,
            &sequence_number,
            certificate_request.items,
        );
    }

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try auth.writeCertificate(
        &certificate,
        allocator,
        options.certificate_chain,
    );
    try appendEncryptedHandshake(
        out,
        allocator,
        &record_keys,
        &sequence_number,
        certificate.items,
    );

    const certificate_verify_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate_request.items,
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
    try appendEncryptedHandshake(
        out,
        allocator,
        &record_keys,
        &sequence_number,
        certificate_verify.items,
    );

    const finished_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate_request.items,
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
    try appendEncryptedHandshake(
        out,
        allocator,
        &record_keys,
        &sequence_number,
        finished.items,
    );
    var transcript_state =
        transcript.State.init(selection.suite.hash());
    for ([_][]const u8{
        options.client_hello_bytes,
        server_hello_msg.items,
        encrypted_extensions.items,
        certificate_request.items,
        certificate.items,
        certificate_verify.items,
        finished.items,
    }) |message| transcript_state.update(message);
    const transcript_after_server_finished = transcript_state.digest();

    return .{
        .selection = selection,
        .handshake_secret = handshake.handshake_secret,
        .client_handshake_traffic_secret = handshake.client_traffic_secret,
        .server_handshake_traffic_secret = handshake.server_traffic_secret,
        .transcript_after_server_finished = transcript_after_server_finished,
        .transcript_state_after_server_finished = transcript_state,
    };
}

fn appendEncryptedHandshake(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    keys: *const record.Keys,
    sequence_number: *u64,
    handshake_message: []const u8,
) Error!void {
    const max_record_len = record.header_len + handshake_message.len + 1 + record.tag_len;
    const buffer = try allocator.alloc(u8, max_record_len);
    defer allocator.free(buffer);
    const len = try keys.seal(
        sequence_number.*,
        record.content_type_handshake,
        handshake_message,
        buffer,
    );
    sequence_number.* += 1;
    try out.appendSlice(allocator, buffer[0..len]);
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
