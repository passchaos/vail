//! Established TLS 1.3 application-traffic connection state.
//!
//! This layer joins the incremental protected-record receiver with directional
//! traffic secrets, post-handshake KeyUpdate, alerts, and bidirectional close
//! state. It deliberately owns no socket: callers feed arbitrary byte slices
//! and write the returned records using their preferred blocking or async I/O.

const alert = @import("../alert.zig");
const cipher_suite = @import("../crypto/cipher_suite.zig");
const key_update = @import("../crypto/key_update.zig");
const record = @import("../record.zig");
const record_fragment = @import("../record_fragment.zig");
const record_size_limit = @import("../handshake/record_size_limit.zig");
const secret = @import("../crypto/secret.zig");
const stream = @import("stream.zig");
const traffic_secrets = @import("../crypto/traffic_secrets.zig");

pub const SealFragmentResult = record_fragment.SealResult;
pub const ExtractedSecrets = traffic_secrets.Extracted;

pub const Error = stream.ProtectedError || key_update.Error ||
    record_size_limit.Error || error{
    LocalClosed,
    PeerClosed,
    CloseNotifyResponseRequired,
    NoCloseNotifyResponsePending,
    NoKeyUpdateResponsePending,
    UnexpectedPostHandshakeMessage,
    ConnectionFailed,
    PeerRecordSizeLimitExceeded,
};

pub const Event = union(enum) {
    application_data: []const u8,
    /// A valid, complete post-handshake message not consumed internally, such
    /// as NewSessionTicket. Its storage is borrowed from the connection.
    post_handshake: []const u8,
    key_update: key_update.Request,
    alert: alert.Alert,
};

pub const ReceiveResult = struct {
    consumed: usize,
    event: ?Event,
};

/// Build an established application-traffic connection with an explicit
/// maximum post-handshake message size.
pub fn ApplicationConnection(comptime max_handshake_message_len: usize) type {
    return struct {
        const Self = @This();

        suite: cipher_suite.Suite,
        traffic: key_update.Duplex,
        receiver: stream.ProtectedReceiver(max_handshake_message_len) = .{},
        local_record_size_limit: ?u16 = null,
        peer_record_size_limit: ?u16 = null,
        local_closed: bool = false,
        close_response_pending: bool = false,
        failed: bool = false,
        secrets_extracted: bool = false,

        pub fn init(
            suite: cipher_suite.Suite,
            read_secret: secret.Secret,
            write_secret: secret.Secret,
        ) Error!Self {
            var result: Self = undefined;
            try result.initInto(suite, read_secret, write_secret);
            return result;
        }

        /// Initialize caller-owned storage without returning the inline record
        /// and handshake buffers through an error union.
        pub fn initInto(
            self: *Self,
            suite: cipher_suite.Suite,
            read_secret: secret.Secret,
            write_secret: secret.Secret,
        ) Error!void {
            return self.initIntoWithRecordSizeLimits(
                suite,
                read_secret,
                write_secret,
                null,
                null,
            );
        }

        pub fn initWithRecordSizeLimits(
            suite: cipher_suite.Suite,
            read_secret: secret.Secret,
            write_secret: secret.Secret,
            local_limit: ?u16,
            peer_limit: ?u16,
        ) Error!Self {
            var result: Self = undefined;
            try result.initIntoWithRecordSizeLimits(
                suite,
                read_secret,
                write_secret,
                local_limit,
                peer_limit,
            );
            return result;
        }

        /// Initialize caller-owned storage with explicit record-size limits.
        pub fn initIntoWithRecordSizeLimits(
            self: *Self,
            suite: cipher_suite.Suite,
            read_secret: secret.Secret,
            write_secret: secret.Secret,
            local_limit: ?u16,
            peer_limit: ?u16,
        ) Error!void {
            if (local_limit) |limit| _ = try record_size_limit.validate(limit);
            if (peer_limit) |limit| _ = try record_size_limit.validate(limit);
            const max_ciphertext_fragment_len = if (local_limit) |limit|
                try record_size_limit.maxCiphertextFragmentWithTag(
                    limit,
                    suite.tagLen(),
                )
            else
                record.max_ciphertext_len;
            self.*.suite = suite;
            self.*.traffic = try key_update.Duplex.init(
                suite,
                read_secret,
                write_secret,
            );
            self.*.receiver.records.buffered = 0;
            self.*.receiver.handshakes.buffered = 0;
            self.*.receiver.max_ciphertext_fragment_len =
                max_ciphertext_fragment_len;
            self.*.receiver.pending_start = 0;
            self.*.receiver.pending_end = 0;
            self.*.receiver.peer_closed = false;
            self.*.receiver.failed = false;
            self.*.local_record_size_limit = local_limit;
            self.*.peer_record_size_limit = peer_limit;
            self.*.local_closed = false;
            self.*.close_response_pending = false;
            self.*.failed = false;
            self.*.secrets_extracted = false;
        }

        pub fn deinit(self: *Self) void {
            if (!self.secrets_extracted) self.traffic.deinit();
            self.* = undefined;
        }

        pub fn peerClosed(self: *const Self) bool {
            return self.receiver.peerClosed();
        }

        pub fn fullyClosed(self: *const Self) bool {
            return self.local_closed and self.peerClosed();
        }

        pub fn keyUpdateResponseRequired(self: *const Self) bool {
            if (self.secrets_extracted) return false;
            return self.traffic.responseRequired();
        }

        pub fn closeNotifyResponseRequired(self: *const Self) bool {
            return self.close_response_pending;
        }

        /// Consume the live record layer and return its current transmit and
        /// receive keys for kTLS or another external record implementation.
        /// The connection remains safe to `deinit` but cannot be used again.
        pub fn dangerousExtractSecrets(
            self: *Self,
        ) Error!ExtractedSecrets {
            try self.requireWritable();
            if (self.traffic.responseRequired()) {
                return error.KeyUpdateResponseRequired;
            }
            const extracted = try self.traffic.extractSecrets();
            self.secrets_extracted = true;
            self.failed = true;
            return extracted;
        }

        /// Feed arbitrary transport bytes. One call returns at most one event;
        /// call again with the unconsumed suffix, or with an empty slice to
        /// drain additional handshake messages from the last record.
        pub fn receive(
            self: *Self,
            input: []const u8,
        ) Error!ReceiveResult {
            if (self.failed) return error.ConnectionFailed;
            return self.receiveInner(input) catch |err| {
                self.failed = true;
                return err;
            };
        }

        pub fn sealApplicationData(
            self: *Self,
            plaintext: []const u8,
            output: []u8,
        ) Error!usize {
            try self.requireWritable();
            return self.sealLimited(
                record.content_type_application_data,
                plaintext,
                output,
            );
        }

        /// Seal one non-empty application-data record with an explicit
        /// plaintext limit. Repeated calls with the unconsumed suffix provide
        /// allocation-free fragmentation without hidden buffered state.
        pub fn sealApplicationDataFragment(
            self: *Self,
            plaintext: []const u8,
            max_fragment_plaintext: usize,
            output: []u8,
        ) Error!SealFragmentResult {
            try self.requireWritable();
            if (max_fragment_plaintext == 0 or
                max_fragment_plaintext > record.max_plaintext_len)
            {
                return error.InvalidPlaintextLength;
            }
            const effective_limit = @min(
                max_fragment_plaintext,
                try self.maxPeerApplicationData(),
            );
            return self.traffic.sealFragment(
                record.content_type_application_data,
                plaintext,
                effective_limit,
                output,
            );
        }

        /// Initiate an independent key update. A peer-requested response must
        /// instead use `sealKeyUpdateResponse` so the response bit is correct.
        pub fn sealKeyUpdate(
            self: *Self,
            request: key_update.Request,
            output: []u8,
        ) Error!usize {
            try self.requireOpenForControl();
            if (self.traffic.responseRequired()) {
                return error.KeyUpdateResponseRequired;
            }
            return self.traffic.sendKeyUpdate(request, output);
        }

        pub fn sealKeyUpdateResponse(
            self: *Self,
            output: []u8,
        ) Error!usize {
            try self.requireOpenForControl();
            if (!self.traffic.responseRequired()) {
                return error.NoKeyUpdateResponsePending;
            }
            return self.traffic.sendKeyUpdate(
                .update_not_requested,
                output,
            );
        }

        pub fn sealPostHandshake(
            self: *Self,
            message: []const u8,
            output: []u8,
        ) Error!usize {
            try self.requireOpenForControl();
            if (self.traffic.responseRequired()) {
                return error.KeyUpdateResponseRequired;
            }
            return self.sealLimited(
                record.content_type_handshake,
                message,
                output,
            );
        }

        pub fn sealCloseNotify(
            self: *Self,
            output: []u8,
        ) Error!usize {
            if (self.failed) return error.ConnectionFailed;
            if (self.local_closed) return error.LocalClosed;
            if (self.traffic.responseRequired()) {
                return error.KeyUpdateResponseRequired;
            }
            const encoded = alert.closeNotify().toBytes();
            const len = try self.traffic.seal(
                record.content_type_alert,
                &encoded,
                output,
            );
            self.local_closed = true;
            self.close_response_pending = false;
            return len;
        }

        pub fn sealFatalAlert(
            self: *Self,
            cause: anyerror,
            output: []u8,
        ) Error!usize {
            if (self.secrets_extracted) return error.ConnectionFailed;
            if (self.local_closed) return error.LocalClosed;
            const encoded = alert.fatalForError(cause).toBytes();
            const len = try self.traffic.seal(
                record.content_type_alert,
                &encoded,
                output,
            );
            self.local_closed = true;
            self.close_response_pending = false;
            return len;
        }

        fn receiveInner(
            self: *Self,
            input: []const u8,
        ) Error!ReceiveResult {
            const result = try self.receiver.push(
                input,
                &self.traffic.read,
            );
            const protected = result.event orelse return .{
                .consumed = result.consumed,
                .event = null,
            };
            const event: Event = switch (protected) {
                .application_data => |bytes| .{ .application_data = bytes },
                .alert => |received| blk: {
                    if (received.isCloseNotify() and !self.local_closed) {
                        self.close_response_pending = true;
                    }
                    break :blk .{ .alert = received };
                },
                .change_cipher_spec => return error.UnexpectedPostHandshakeMessage,
                .handshake => |message| blk: {
                    if (message.len != 0 and
                        message[0] == key_update.handshake_type)
                    {
                        const request = try self.traffic.receiveKeyUpdate(
                            message,
                        );
                        break :blk .{ .key_update = request };
                    }
                    break :blk .{ .post_handshake = message };
                },
            };
            return .{ .consumed = result.consumed, .event = event };
        }

        fn requireWritable(self: *const Self) Error!void {
            try self.requireOpenForControl();
            if (self.peerClosed()) return error.PeerClosed;
            if (self.close_response_pending) {
                return error.CloseNotifyResponseRequired;
            }
        }

        fn sealLimited(
            self: *Self,
            inner_type: u8,
            plaintext: []const u8,
            output: []u8,
        ) Error!usize {
            const max_plaintext = try self.maxPeerApplicationData();
            if (plaintext.len > max_plaintext) {
                return error.PeerRecordSizeLimitExceeded;
            }
            return self.traffic.seal(inner_type, plaintext, output);
        }

        fn maxPeerApplicationData(self: *const Self) Error!usize {
            return if (self.peer_record_size_limit) |limit|
                try record_size_limit.maxApplicationData(limit)
            else
                record.max_plaintext_len;
        }

        fn requireOpenForControl(self: *const Self) Error!void {
            if (self.failed) return error.ConnectionFailed;
            if (self.local_closed) return error.LocalClosed;
        }
    };
}

test "application connection caller-owned initialization matches returned initialization" {
    const std = @import("std");
    const Connection = ApplicationConnection(256);
    const read_secret = secret.Secret.fromSha256([_]u8{0x41} ** 32);
    const write_secret = secret.Secret.fromSha256([_]u8{0x51} ** 32);

    var returned = try Connection.initWithRecordSizeLimits(
        .aes_128_gcm_sha256,
        read_secret,
        write_secret,
        1_200,
        1_300,
    );
    defer returned.deinit();
    var caller_owned: Connection = undefined;
    try caller_owned.initIntoWithRecordSizeLimits(
        .aes_128_gcm_sha256,
        read_secret,
        write_secret,
        1_200,
        1_300,
    );
    defer caller_owned.deinit();

    var returned_wire: [64]u8 = undefined;
    var caller_owned_wire: [64]u8 = undefined;
    const returned_len = try returned.sealApplicationData(
        "caller-owned",
        &returned_wire,
    );
    const caller_owned_len = try caller_owned.sealApplicationData(
        "caller-owned",
        &caller_owned_wire,
    );
    try std.testing.expectEqual(returned_len, caller_owned_len);
    try std.testing.expectEqualSlices(
        u8,
        returned_wire[0..returned_len],
        caller_owned_wire[0..caller_owned_len],
    );
    try std.testing.expectEqual(
        returned.local_record_size_limit,
        caller_owned.local_record_size_limit,
    );
    try std.testing.expectEqual(
        returned.peer_record_size_limit,
        caller_owned.peer_record_size_limit,
    );
}

test "application connection handles fragmented data and bidirectional close" {
    const std = @import("std");
    const client_secret = secret.Secret.fromSha256([_]u8{0x21} ** 32);
    const server_secret = secret.Secret.fromSha256([_]u8{0x31} ** 32);
    var client = try ApplicationConnection(256).init(
        .aes_128_gcm_sha256,
        server_secret,
        client_secret,
    );
    defer client.deinit();
    var server = try ApplicationConnection(256).init(
        .aes_128_gcm_sha256,
        client_secret,
        server_secret,
    );
    defer server.deinit();

    var wire: [256]u8 = undefined;
    const wire_len = try client.sealApplicationData("hello", &wire);
    var event_count: usize = 0;
    for (wire[0..wire_len]) |byte| {
        const result = try server.receive(&.{byte});
        try std.testing.expectEqual(@as(usize, 1), result.consumed);
        if (result.event) |event| switch (event) {
            .application_data => |bytes| {
                try std.testing.expectEqualStrings("hello", bytes);
                event_count += 1;
            },
            else => return error.UnexpectedConnectionEvent,
        };
    }
    try std.testing.expectEqual(@as(usize, 1), event_count);

    const close_len = try client.sealCloseNotify(&wire);
    const close = try server.receive(wire[0..close_len]);
    try std.testing.expect(close.event.?.alert.isCloseNotify());
    try std.testing.expect(server.peerClosed());
    try std.testing.expect(server.closeNotifyResponseRequired());
    try std.testing.expectError(
        error.PeerClosed,
        server.sealApplicationData("late", &wire),
    );
    try std.testing.expectError(
        error.PeerClosed,
        server.sealApplicationDataFragment("late", 2, &wire),
    );
    try std.testing.expectError(
        error.PeerClosed,
        server.dangerousExtractSecrets(),
    );

    const response_len = try server.sealCloseNotify(&wire);
    const response = try client.receive(wire[0..response_len]);
    try std.testing.expect(response.event.?.alert.isCloseNotify());
    try std.testing.expect(client.fullyClosed());
    try std.testing.expect(server.fullyClosed());
    try std.testing.expectError(
        error.LocalClosed,
        client.sealApplicationData("closed", &wire),
    );
    try std.testing.expectError(
        error.LocalClosed,
        client.sealApplicationDataFragment("closed", 2, &wire),
    );
    try std.testing.expectError(
        error.LocalClosed,
        client.dangerousExtractSecrets(),
    );
}

test "application connection seals bounded fragments with explicit progress" {
    const std = @import("std");
    const client_secret = secret.Secret.fromSha256([_]u8{0x81} ** 32);
    const server_secret = secret.Secret.fromSha256([_]u8{0x91} ** 32);
    var client = try ApplicationConnection(256).init(
        .aes_128_gcm_sha256,
        server_secret,
        client_secret,
    );
    defer client.deinit();
    var server = try ApplicationConnection(256).init(
        .aes_128_gcm_sha256,
        client_secret,
        server_secret,
    );
    defer server.deinit();

    var wire: [record.max_record_len]u8 = undefined;
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        client.sealApplicationDataFragment("", 7, &wire),
    );
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        client.sealApplicationDataFragment("payload", 0, &wire),
    );
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        client.sealApplicationDataFragment(
            "payload",
            record.max_plaintext_len + 1,
            &wire,
        ),
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        client.traffic.write.sequenceNumber(),
    );
    try std.testing.expectError(
        error.InvalidCiphertextLength,
        client.sealApplicationDataFragment("payload", 7, wire[0..1]),
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        client.traffic.write.sequenceNumber(),
    );

    const payload = "fragmented application data crosses several records";
    var offset: usize = 0;
    var record_count: u64 = 0;
    while (offset < payload.len) {
        const fragment = try client.sealApplicationDataFragment(
            payload[offset..],
            7,
            &wire,
        );
        try std.testing.expect(fragment.plaintext_consumed > 0);
        try std.testing.expect(fragment.plaintext_consumed <= 7);
        const received = try server.receive(wire[0..fragment.output_written]);
        try std.testing.expectEqual(fragment.output_written, received.consumed);
        try std.testing.expectEqualStrings(
            payload[offset..][0..fragment.plaintext_consumed],
            received.event.?.application_data,
        );
        offset += fragment.plaintext_consumed;
        record_count += 1;
    }
    try std.testing.expectEqual(payload.len, offset);
    try std.testing.expectEqual(
        @as(?u64, record_count),
        client.traffic.write.sequenceNumber(),
    );
    try std.testing.expectEqual(
        @as(?u64, record_count),
        server.traffic.read.sequenceNumber(),
    );
}

test "application connection enforces negotiated record size limits" {
    const std = @import("std");
    const read_secret = secret.Secret.fromSha256([_]u8{0xa4} ** 32);
    const write_secret = secret.Secret.fromSha256([_]u8{0xb4} ** 32);
    var limited_sender = try ApplicationConnection(256).initWithRecordSizeLimits(
        .aes_128_gcm_sha256,
        read_secret,
        write_secret,
        null,
        64,
    );
    defer limited_sender.deinit();
    var receiver = try ApplicationConnection(256).init(
        .aes_128_gcm_sha256,
        write_secret,
        read_secret,
    );
    defer receiver.deinit();

    var wire: [256]u8 = undefined;
    const too_large = [_]u8{0x41} ** 64;
    try std.testing.expectError(
        error.PeerRecordSizeLimitExceeded,
        limited_sender.sealApplicationData(&too_large, &wire),
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        limited_sender.traffic.write.sequenceNumber(),
    );

    const fragment = try limited_sender.sealApplicationDataFragment(
        &too_large,
        too_large.len,
        &wire,
    );
    try std.testing.expectEqual(@as(usize, 63), fragment.plaintext_consumed);
    const received = try receiver.receive(wire[0..fragment.output_written]);
    try std.testing.expectEqualSlices(
        u8,
        too_large[0..63],
        received.event.?.application_data,
    );
    try std.testing.expectError(
        error.PeerRecordSizeLimitExceeded,
        limited_sender.sealPostHandshake(&too_large, &wire),
    );

    var unbounded_sender = try ApplicationConnection(256).init(
        .aes_128_gcm_sha256,
        read_secret,
        write_secret,
    );
    defer unbounded_sender.deinit();
    var limited_receiver = try ApplicationConnection(256).initWithRecordSizeLimits(
        .aes_128_gcm_sha256,
        write_secret,
        read_secret,
        64,
        null,
    );
    defer limited_receiver.deinit();
    const oversized_len = try unbounded_sender.sealApplicationData(
        &too_large,
        &wire,
    );
    try std.testing.expectError(
        error.RecordTooLarge,
        limited_receiver.receive(wire[0..oversized_len]),
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        limited_receiver.traffic.read.sequenceNumber(),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        limited_receiver.receive(""),
    );
}

test "application connection extracts directional record secrets atomically" {
    const std = @import("std");

    inline for ([_]cipher_suite.Suite{
        .aes_128_gcm_sha256,
        .aes_128_ccm_sha256,
        .aes_128_ccm_8_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
        .sm4_gcm_sm3,
        .sm4_ccm_sm3,
    }) |suite| {
        const client_secret = switch (suite.hash()) {
            .sha256 => secret.Secret.fromSha256([_]u8{0xa1} ** 32),
            .sha384 => secret.Secret.fromSha384([_]u8{0xa2} ** 48),
            .sm3 => secret.Secret.fromSm3([_]u8{0xa3} ** 32),
        };
        const server_secret = switch (suite.hash()) {
            .sha256 => secret.Secret.fromSha256([_]u8{0xb1} ** 32),
            .sha384 => secret.Secret.fromSha384([_]u8{0xb2} ** 48),
            .sm3 => secret.Secret.fromSm3([_]u8{0xb3} ** 32),
        };
        var client = try ApplicationConnection(256).init(
            suite,
            server_secret,
            client_secret,
        );
        defer client.deinit();
        var server = try ApplicationConnection(256).init(
            suite,
            client_secret,
            server_secret,
        );
        defer server.deinit();

        var wire: [128]u8 = undefined;
        inline for (.{ "first", "second" }) |message| {
            const len = try client.sealApplicationData(message, &wire);
            const received = try server.receive(wire[0..len]);
            try std.testing.expectEqualStrings(
                message,
                received.event.?.application_data,
            );
        }
        const response_len = try server.sealApplicationData("reply", &wire);
        const response = try client.receive(wire[0..response_len]);
        try std.testing.expectEqualStrings(
            "reply",
            response.event.?.application_data,
        );

        var client_keys = try client.dangerousExtractSecrets();
        defer client_keys.deinit();
        var server_keys = try server.dangerousExtractSecrets();
        defer server_keys.deinit();
        try std.testing.expectEqual(traffic_secrets.Version.tls13, client_keys.version);
        try std.testing.expectEqual(@as(u64, 2), client_keys.tx.sequence_number);
        try std.testing.expectEqual(@as(u64, 1), client_keys.rx.sequence_number);
        try std.testing.expectEqual(@as(u64, 1), server_keys.tx.sequence_number);
        try std.testing.expectEqual(@as(u64, 2), server_keys.rx.sequence_number);
        try std.testing.expectEqual(@as(u64, 0), client_keys.tx.generation);
        try std.testing.expectEqual(@as(u64, 0), client_keys.rx.generation);
        try std.testing.expectEqual(client_keys.tx.algorithm, server_keys.rx.algorithm);
        try std.testing.expectEqual(client_keys.rx.algorithm, server_keys.tx.algorithm);
        try std.testing.expectEqualSlices(u8, client_keys.tx.key(), server_keys.rx.key());
        try std.testing.expectEqualSlices(u8, client_keys.rx.key(), server_keys.tx.key());
        try std.testing.expectEqual(client_keys.tx.iv, server_keys.rx.iv);
        try std.testing.expectEqual(client_keys.rx.iv, server_keys.tx.iv);
        try std.testing.expectError(
            error.ConnectionFailed,
            client.sealApplicationData("after extraction", &wire),
        );
        try std.testing.expectError(
            error.ConnectionFailed,
            client.dangerousExtractSecrets(),
        );
    }
}

test "traffic-secret extraction failure preserves both directions" {
    const std = @import("std");
    const initial = secret.Secret.fromSha256([_]u8{0xc1} ** 32);
    var connection = try ApplicationConnection(64).init(
        .aes_128_gcm_sha256,
        initial,
        initial,
    );
    defer connection.deinit();
    connection.traffic.read.next_sequence_number = std.math.maxInt(u64);
    try std.testing.expectError(
        error.SequenceExhausted,
        connection.dangerousExtractSecrets(),
    );
    var wire: [64]u8 = undefined;
    _ = try connection.sealApplicationData("still owned", &wire);
    try std.testing.expectEqual(
        @as(?u64, 1),
        connection.traffic.write.sequenceNumber(),
    );
}

test "application connection processes requested KeyUpdate before data" {
    const std = @import("std");
    const client_secret = secret.Secret.fromSha384([_]u8{0x41} ** 48);
    const server_secret = secret.Secret.fromSha384([_]u8{0x51} ** 48);
    var client = try ApplicationConnection(256).init(
        .aes_256_gcm_sha384,
        server_secret,
        client_secret,
    );
    defer client.deinit();
    var server = try ApplicationConnection(256).init(
        .aes_256_gcm_sha384,
        client_secret,
        server_secret,
    );
    defer server.deinit();

    var wire: [256]u8 = undefined;
    const update_len = try client.sealKeyUpdate(.update_requested, &wire);
    const update = try server.receive(wire[0..update_len]);
    try std.testing.expectEqual(
        key_update.Request.update_requested,
        update.event.?.key_update,
    );
    try std.testing.expect(server.keyUpdateResponseRequired());
    try std.testing.expectError(
        error.KeyUpdateResponseRequired,
        server.sealApplicationData("blocked", &wire),
    );
    try std.testing.expectError(
        error.KeyUpdateResponseRequired,
        server.sealApplicationDataFragment("blocked", 3, &wire),
    );
    try std.testing.expectError(
        error.KeyUpdateResponseRequired,
        server.dangerousExtractSecrets(),
    );
    try std.testing.expectError(
        error.KeyUpdateResponseRequired,
        server.sealKeyUpdate(.update_requested, &wire),
    );

    const response_len = try server.sealKeyUpdateResponse(&wire);
    const response = try client.receive(wire[0..response_len]);
    try std.testing.expectEqual(
        key_update.Request.update_not_requested,
        response.event.?.key_update,
    );
    try std.testing.expect(!server.keyUpdateResponseRequired());

    const data_len = try server.sealApplicationData("updated", &wire);
    const data = try client.receive(wire[0..data_len]);
    try std.testing.expectEqualStrings(
        "updated",
        data.event.?.application_data,
    );

    var client_keys = try client.dangerousExtractSecrets();
    defer client_keys.deinit();
    var server_keys = try server.dangerousExtractSecrets();
    defer server_keys.deinit();
    try std.testing.expectEqual(@as(u64, 1), client_keys.tx.generation);
    try std.testing.expectEqual(@as(u64, 1), client_keys.rx.generation);
    try std.testing.expectEqual(@as(u64, 1), server_keys.tx.generation);
    try std.testing.expectEqual(@as(u64, 1), server_keys.rx.generation);
    try std.testing.expectEqualSlices(u8, client_keys.tx.key(), server_keys.rx.key());
    try std.testing.expectEqualSlices(u8, client_keys.rx.key(), server_keys.tx.key());
}

test "application connection latches malformed post-handshake messages" {
    const std = @import("std");
    const initial = secret.Secret.fromSha256([_]u8{0x61} ** 32);
    var sender = try @import("../crypto/traffic.zig").State.init(
        .aes_128_gcm_sha256,
        initial,
    );
    defer sender.deinit();
    var connection = try ApplicationConnection(64).init(
        .aes_128_gcm_sha256,
        initial,
        secret.Secret.fromSha256([_]u8{0x71} ** 32),
    );
    defer connection.deinit();

    const malformed = [_]u8{ key_update.handshake_type, 0, 0, 1, 2 };
    var wire: [128]u8 = undefined;
    const wire_len = try sender.seal(
        record.content_type_handshake,
        &malformed,
        &wire,
    );
    try std.testing.expectError(
        error.InvalidKeyUpdate,
        connection.receive(wire[0..wire_len]),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        connection.receive(""),
    );
    const fatal_len = try connection.sealFatalAlert(
        error.InvalidKeyUpdate,
        &wire,
    );
    try std.testing.expect(fatal_len > record.header_len);
    try std.testing.expect(connection.local_closed);
}
