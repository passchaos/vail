//! Allocation-free incremental TLS record and handshake framing.
//!
//! Network reads are not aligned to TLS records, and handshake messages are
//! allowed to span records. These framers accept arbitrary input slices and
//! return at most one complete item per call together with the number of input
//! bytes consumed. Callers can therefore loop over coalesced input without
//! allocating or copying already-contiguous records/messages.

const std = @import("std");
const alert = @import("../alert.zig");
const record = @import("../record.zig");
const traffic = @import("../crypto/traffic.zig");

pub const content_type_change_cipher_spec: u8 = 20;

pub const Error = error{
    InvalidContentType,
    InvalidLegacyVersion,
    RecordTooLarge,
};

pub const FramedRecord = struct {
    bytes: []const u8,
    fragment: []const u8,
    content_type: u8,
    legacy_version: u16,
};

pub const RecordResult = struct {
    consumed: usize,
    framed: ?FramedRecord,
};

/// Incrementally frames TLSPlaintext and TLSCiphertext records.
///
/// A returned slice remains valid until the caller mutates its source input or
/// calls `push` again with data that must be buffered. Consume it immediately.
pub const RecordDeframer = struct {
    buffered: usize = 0,
    storage: [record.max_record_len]u8 = undefined,

    pub fn reset(self: *RecordDeframer) void {
        self.buffered = 0;
    }

    pub fn pending(self: *const RecordDeframer) usize {
        return self.buffered;
    }

    pub fn push(
        self: *RecordDeframer,
        input: []const u8,
    ) Error!RecordResult {
        if (self.buffered == 0 and input.len >= record.header_len) {
            const total_len = try recordLength(input[0..record.header_len]);
            if (input.len >= total_len) {
                return .{
                    .consumed = total_len,
                    .framed = framedRecord(input[0..total_len]),
                };
            }
        }

        var consumed: usize = 0;
        if (self.buffered < record.header_len) {
            const header_needed = record.header_len - self.buffered;
            const copied = @min(header_needed, input.len);
            @memcpy(
                self.storage[self.buffered..][0..copied],
                input[0..copied],
            );
            self.buffered += copied;
            consumed += copied;
            if (self.buffered < record.header_len) {
                return .{ .consumed = consumed, .framed = null };
            }
        }

        const total_len = recordLength(
            self.storage[0..record.header_len],
        ) catch |err| {
            self.reset();
            return err;
        };
        const copied = @min(total_len - self.buffered, input.len - consumed);
        @memcpy(
            self.storage[self.buffered..][0..copied],
            input[consumed..][0..copied],
        );
        self.buffered += copied;
        consumed += copied;
        if (self.buffered < total_len) {
            return .{ .consumed = consumed, .framed = null };
        }

        const bytes = self.storage[0..total_len];
        self.buffered = 0;
        return .{
            .consumed = consumed,
            .framed = framedRecord(bytes),
        };
    }
};

fn recordLength(header: *const [record.header_len]u8) Error!usize {
    const content_type = header[0];
    if (content_type != content_type_change_cipher_spec and
        content_type != record.content_type_alert and
        content_type != record.content_type_handshake and
        content_type != record.content_type_application_data)
    {
        return error.InvalidContentType;
    }
    const legacy_version = std.mem.readInt(u16, header[1..3], .big);
    if (legacy_version != 0x0301 and legacy_version != 0x0303) {
        return error.InvalidLegacyVersion;
    }
    const fragment_len = std.mem.readInt(u16, header[3..5], .big);
    const limit: usize = if (content_type == record.content_type_application_data)
        record.max_ciphertext_len
    else
        record.max_plaintext_len;
    if (fragment_len > limit) return error.RecordTooLarge;
    return record.header_len + fragment_len;
}

fn framedRecord(bytes: []const u8) FramedRecord {
    return .{
        .bytes = bytes,
        .fragment = bytes[record.header_len..],
        .content_type = bytes[0],
        .legacy_version = std.mem.readInt(u16, bytes[1..3], .big),
    };
}

pub const HandshakeError = error{
    HandshakeMessageTooLarge,
};

pub const HandshakeResult = struct {
    consumed: usize,
    message: ?[]const u8,
};

/// Incrementally reassembles TLS handshake messages up to `max_message_len`
/// bytes including their four-byte handshake header.
pub fn HandshakeReassembler(comptime max_message_len: usize) type {
    comptime std.debug.assert(max_message_len >= 4);
    return struct {
        const Self = @This();

        buffered: usize = 0,
        storage: [max_message_len]u8 = undefined,

        pub fn reset(self: *Self) void {
            self.buffered = 0;
        }

        pub fn pending(self: *const Self) usize {
            return self.buffered;
        }

        pub fn push(
            self: *Self,
            input: []const u8,
        ) HandshakeError!HandshakeResult {
            if (self.buffered == 0 and input.len >= 4) {
                const total_len = handshakeLength(input[0..4]);
                if (total_len > max_message_len) {
                    return error.HandshakeMessageTooLarge;
                }
                if (input.len >= total_len) {
                    return .{
                        .consumed = total_len,
                        .message = input[0..total_len],
                    };
                }
            }

            var consumed: usize = 0;
            if (self.buffered < 4) {
                const header_needed = 4 - self.buffered;
                const copied = @min(header_needed, input.len);
                @memcpy(
                    self.storage[self.buffered..][0..copied],
                    input[0..copied],
                );
                self.buffered += copied;
                consumed += copied;
                if (self.buffered < 4) {
                    return .{ .consumed = consumed, .message = null };
                }
            }

            const total_len = handshakeLength(self.storage[0..4]);
            if (total_len > max_message_len) {
                self.reset();
                return error.HandshakeMessageTooLarge;
            }
            const copied = @min(
                total_len - self.buffered,
                input.len - consumed,
            );
            @memcpy(
                self.storage[self.buffered..][0..copied],
                input[consumed..][0..copied],
            );
            self.buffered += copied;
            consumed += copied;
            if (self.buffered < total_len) {
                return .{ .consumed = consumed, .message = null };
            }

            const message = self.storage[0..total_len];
            self.buffered = 0;
            return .{ .consumed = consumed, .message = message };
        }
    };
}

fn handshakeLength(header: *const [4]u8) usize {
    return 4 + (@as(usize, header[1]) << 16) +
        (@as(usize, header[2]) << 8) + header[3];
}

pub const ProtectedError = Error || HandshakeError || traffic.Error ||
    alert.Error || error{
    UnexpectedPlaintextRecord,
    InterleavedHandshake,
    InvalidChangeCipherSpec,
    DataAfterCloseNotify,
    ConnectionFailed,
};

pub const ProtectedEvent = union(enum) {
    handshake: []const u8,
    application_data: []const u8,
    alert: alert.Alert,
    change_cipher_spec: void,
};

pub const ProtectedResult = struct {
    consumed: usize,
    event: ?ProtectedEvent,
};

/// Incremental TLS 1.3 protected-record receive pipeline.
///
/// It composes record deframing, authenticated decryption with automatically
/// managed sequence numbers, TLSInnerPlaintext padding removal, alert parsing,
/// and handshake reassembly. An input record containing multiple handshake
/// messages can produce later events with `consumed == 0`; callers should keep
/// invoking `push` until it returns no event before waiting for more input.
pub fn ProtectedReceiver(comptime max_handshake_message_len: usize) type {
    return struct {
        const Self = @This();

        records: RecordDeframer = .{},
        handshakes: HandshakeReassembler(max_handshake_message_len) = .{},
        plaintext: [record.max_inner_plaintext_len]u8 = undefined,
        max_ciphertext_fragment_len: usize = record.max_ciphertext_len,
        pending_start: usize = 0,
        pending_end: usize = 0,
        peer_closed: bool = false,
        failed: bool = false,

        pub fn peerClosed(self: *const Self) bool {
            return self.peer_closed;
        }

        pub fn hasPendingHandshakeData(self: *const Self) bool {
            return self.pending_start < self.pending_end or
                self.handshakes.pending() != 0;
        }

        pub fn setMaxCiphertextFragmentLen(
            self: *Self,
            limit: usize,
        ) void {
            std.debug.assert(limit <= record.max_ciphertext_len);
            self.max_ciphertext_fragment_len = limit;
        }

        pub fn push(
            self: *Self,
            input: []const u8,
            opener: *traffic.State,
        ) ProtectedError!ProtectedResult {
            if (self.failed) return error.ConnectionFailed;
            return self.pushInner(input, opener) catch |err| {
                self.failed = true;
                return err;
            };
        }

        fn pushInner(
            self: *Self,
            input: []const u8,
            opener: *traffic.State,
        ) ProtectedError!ProtectedResult {
            if (try self.drainHandshake()) |event| {
                return .{ .consumed = 0, .event = event };
            }

            const framed_result = try self.records.push(input);
            const framed = framed_result.framed orelse return .{
                .consumed = framed_result.consumed,
                .event = null,
            };

            return .{
                .consumed = framed_result.consumed,
                .event = try self.processFramed(framed, opener),
            };
        }

        /// Process a record already produced by `RecordDeframer`. This allows
        /// an epoch-switching connection to try 0-RTT keys before permanently
        /// switching the same framed ciphertext to handshake keys.
        pub fn processFramed(
            self: *Self,
            framed: FramedRecord,
            opener: *traffic.State,
        ) ProtectedError!?ProtectedEvent {
            if (self.failed) return error.ConnectionFailed;
            if (self.pending_start < self.pending_end) {
                return error.InterleavedHandshake;
            }
            return self.processFramedInner(framed, opener) catch |err| {
                self.failed = true;
                return err;
            };
        }

        fn processFramedInner(
            self: *Self,
            framed: FramedRecord,
            opener: *traffic.State,
        ) ProtectedError!?ProtectedEvent {
            if (framed.content_type == content_type_change_cipher_spec) {
                if (self.handshakes.pending() != 0) {
                    return error.InterleavedHandshake;
                }
                if (!std.mem.eql(u8, framed.fragment, &.{1})) {
                    return error.InvalidChangeCipherSpec;
                }
                return .{ .change_cipher_spec = {} };
            }
            if (framed.content_type != record.content_type_application_data) {
                return error.UnexpectedPlaintextRecord;
            }
            if (framed.fragment.len > self.max_ciphertext_fragment_len) {
                return error.RecordTooLarge;
            }
            if (self.peer_closed) return error.DataAfterCloseNotify;

            const opened = try opener.open(framed.bytes, &self.plaintext);
            if (opened.content_type != record.content_type_handshake and
                self.handshakes.pending() != 0)
            {
                return error.InterleavedHandshake;
            }
            switch (opened.content_type) {
                record.content_type_handshake => {
                    self.pending_start = 0;
                    self.pending_end = opened.len;
                    return self.drainHandshake();
                },
                record.content_type_application_data => return .{
                    .application_data = self.plaintext[0..opened.len],
                },
                record.content_type_alert => {
                    const parsed = try alert.parse(
                        self.plaintext[0..opened.len],
                    );
                    if (parsed.terminatesConnection()) {
                        self.peer_closed = true;
                    }
                    return .{ .alert = parsed };
                },
                else => unreachable,
            }
        }

        fn drainHandshake(
            self: *Self,
        ) HandshakeError!?ProtectedEvent {
            while (self.pending_start < self.pending_end) {
                const result = try self.handshakes.push(
                    self.plaintext[self.pending_start..self.pending_end],
                );
                self.pending_start += result.consumed;
                if (result.message) |message| {
                    return .{ .handshake = message };
                }
            }
            self.pending_start = 0;
            self.pending_end = 0;
            return null;
        }
    };
}

test "record deframer handles every byte boundary" {
    const first = [_]u8{ 22, 3, 1, 0, 5, 1, 0, 0, 1, 0xaa };
    const second = [_]u8{ 23, 3, 3, 0, 3, 0xbb, 0xcc, 0xdd };
    const wire = first ++ second;

    for (0..wire.len + 1) |split| {
        var deframer = RecordDeframer{};
        var record_index: usize = 0;
        for ([_][]const u8{ wire[0..split], wire[split..] }) |chunk| {
            var remaining = chunk;
            while (remaining.len != 0) {
                const result = try deframer.push(remaining);
                try std.testing.expect(result.consumed != 0);
                remaining = remaining[result.consumed..];
                if (result.framed) |framed| {
                    const expected: []const u8 = if (record_index == 0)
                        &first
                    else
                        &second;
                    try std.testing.expectEqualSlices(
                        u8,
                        expected,
                        framed.bytes,
                    );
                    record_index += 1;
                }
            }
        }
        try std.testing.expectEqual(@as(usize, 2), record_index);
        try std.testing.expectEqual(@as(usize, 0), deframer.pending());
    }
}

test "record deframer rejects invalid headers and recovers after reset" {
    var deframer = RecordDeframer{};
    try std.testing.expectError(
        error.InvalidContentType,
        deframer.push(&.{ 19, 3, 3, 0, 0 }),
    );
    try std.testing.expectEqual(@as(usize, 0), deframer.pending());
    try std.testing.expectError(
        error.InvalidLegacyVersion,
        deframer.push(&.{ 22, 3, 2, 0, 0 }),
    );
    try std.testing.expectError(
        error.RecordTooLarge,
        deframer.push(&.{ 22, 3, 3, 0x40, 0x01 }),
    );

    const result = try deframer.push(&.{ 22, 3, 3, 0, 0 });
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
    try std.testing.expectEqual(@as(usize, 0), result.framed.?.fragment.len);
}

test "handshake reassembler handles fragmentation and coalescing" {
    const first = [_]u8{ 1, 0, 0, 3, 0xaa, 0xbb, 0xcc };
    const second = [_]u8{ 20, 0, 0, 2, 0xdd, 0xee };
    const wire = first ++ second;

    for (0..wire.len + 1) |split| {
        var reassembler = HandshakeReassembler(32){};
        var message_index: usize = 0;
        for ([_][]const u8{ wire[0..split], wire[split..] }) |chunk| {
            var remaining = chunk;
            while (remaining.len != 0) {
                const result = try reassembler.push(remaining);
                try std.testing.expect(result.consumed != 0);
                remaining = remaining[result.consumed..];
                if (result.message) |message| {
                    const expected: []const u8 = if (message_index == 0)
                        &first
                    else
                        &second;
                    try std.testing.expectEqualSlices(u8, expected, message);
                    message_index += 1;
                }
            }
        }
        try std.testing.expectEqual(@as(usize, 2), message_index);
        try std.testing.expectEqual(@as(usize, 0), reassembler.pending());
    }
}

test "handshake reassembler rejects oversized messages" {
    var reassembler = HandshakeReassembler(8){};
    try std.testing.expectError(
        error.HandshakeMessageTooLarge,
        reassembler.push(&.{ 11, 0, 0, 5 }),
    );
    try std.testing.expectEqual(@as(usize, 0), reassembler.pending());
}

test "record and handshake framers compose across arbitrary network reads" {
    const first_message = [_]u8{ 1, 0, 0, 5, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    const second_message = [_]u8{ 20, 0, 0, 1, 0xff };
    const first_record = [_]u8{ 22, 3, 3, 0, 2 } ++ first_message[0..2].*;
    const second_fragment = first_message[2..].* ++ second_message;
    const second_record = [_]u8{
        22,
        3,
        3,
        0,
        second_fragment.len,
    } ++ second_fragment;
    const wire = first_record ++ second_record;

    var deframer = RecordDeframer{};
    var reassembler = HandshakeReassembler(32){};
    var record_count: usize = 0;
    var message_count: usize = 0;

    for (wire) |byte| {
        const result = try deframer.push(&.{byte});
        try std.testing.expectEqual(@as(usize, 1), result.consumed);
        if (result.framed) |framed| {
            record_count += 1;
            var remaining = framed.fragment;
            while (remaining.len != 0) {
                const handshake = try reassembler.push(remaining);
                remaining = remaining[handshake.consumed..];
                if (handshake.message) |message| {
                    const expected: []const u8 = if (message_count == 0)
                        &first_message
                    else
                        &second_message;
                    try std.testing.expectEqualSlices(u8, expected, message);
                    message_count += 1;
                }
            }
        }
    }

    try std.testing.expectEqual(@as(usize, 2), record_count);
    try std.testing.expectEqual(@as(usize, 2), message_count);
    try std.testing.expectEqual(@as(usize, 0), deframer.pending());
    try std.testing.expectEqual(@as(usize, 0), reassembler.pending());
}

test "protected receiver composes CCS decryption and handshake messages" {
    const secret = @import("../crypto/secret.zig");
    const initial = secret.Secret.fromSha256([_]u8{0xa1} ** 32);
    var sender = try traffic.State.init(.aes_128_gcm_sha256, initial);
    defer sender.deinit();
    var opener = try traffic.State.init(.aes_128_gcm_sha256, initial);
    defer opener.deinit();
    var receiver = ProtectedReceiver(64){};

    const ccs = [_]u8{ content_type_change_cipher_spec, 3, 3, 0, 1, 1 };
    const ccs_result = try receiver.push(&ccs, &opener);
    try std.testing.expectEqual(ccs.len, ccs_result.consumed);
    try std.testing.expectEqual(
        std.meta.Tag(ProtectedEvent).change_cipher_spec,
        std.meta.activeTag(ccs_result.event.?),
    );
    try std.testing.expectEqual(@as(?u64, 0), opener.sequenceNumber());

    const first = [_]u8{ 1, 0, 0, 3, 0xaa, 0xbb, 0xcc };
    const second = [_]u8{ 20, 0, 0, 1, 0xdd };
    const messages = first ++ second;
    var encrypted: [128]u8 = undefined;
    const encrypted_len = try sender.seal(
        record.content_type_handshake,
        &messages,
        &encrypted,
    );

    const first_result = try receiver.push(encrypted[0..encrypted_len], &opener);
    try std.testing.expectEqual(encrypted_len, first_result.consumed);
    try std.testing.expectEqualSlices(
        u8,
        &first,
        first_result.event.?.handshake,
    );
    const second_result = try receiver.push("", &opener);
    try std.testing.expectEqual(@as(usize, 0), second_result.consumed);
    try std.testing.expectEqualSlices(
        u8,
        &second,
        second_result.event.?.handshake,
    );
    const drained = try receiver.push("", &opener);
    try std.testing.expect(drained.event == null);
    try std.testing.expectEqual(@as(?u64, 1), opener.sequenceNumber());
}

test "protected receiver reassembles encrypted handshake across records" {
    const secret = @import("../crypto/secret.zig");
    const initial = secret.Secret.fromSha384([_]u8{0xb1} ** 48);
    var sender = try traffic.State.init(.aes_256_gcm_sha384, initial);
    defer sender.deinit();
    var opener = try traffic.State.init(.aes_256_gcm_sha384, initial);
    defer opener.deinit();
    var receiver = ProtectedReceiver(64){};

    const message = [_]u8{ 11, 0, 0, 6, 1, 2, 3, 4, 5, 6 };
    var first: [128]u8 = undefined;
    const first_len = try sender.seal(
        record.content_type_handshake,
        message[0..3],
        &first,
    );
    var second: [128]u8 = undefined;
    const second_len = try sender.seal(
        record.content_type_handshake,
        message[3..],
        &second,
    );
    var wire: [256]u8 = undefined;
    @memcpy(wire[0..first_len], first[0..first_len]);
    @memcpy(wire[first_len..][0..second_len], second[0..second_len]);

    var saw_message = false;
    for (wire[0 .. first_len + second_len]) |byte| {
        const result = try receiver.push(&.{byte}, &opener);
        try std.testing.expectEqual(@as(usize, 1), result.consumed);
        if (result.event) |event| switch (event) {
            .handshake => |actual| {
                try std.testing.expect(!saw_message);
                try std.testing.expectEqualSlices(u8, &message, actual);
                saw_message = true;
            },
            else => return error.UnexpectedProtectedEvent,
        };
    }
    try std.testing.expect(saw_message);
    try std.testing.expectEqual(@as(?u64, 2), opener.sequenceNumber());
}

test "protected receiver enforces handshake and close boundaries" {
    const secret = @import("../crypto/secret.zig");
    const initial = secret.Secret.fromSha256([_]u8{0xc1} ** 32);
    var sender = try traffic.State.init(.chacha20_poly1305_sha256, initial);
    defer sender.deinit();
    var opener = try traffic.State.init(.chacha20_poly1305_sha256, initial);
    defer opener.deinit();
    var receiver = ProtectedReceiver(64){};

    var partial: [128]u8 = undefined;
    const partial_len = try sender.seal(
        record.content_type_handshake,
        &.{ 1, 0 },
        &partial,
    );
    const partial_result = try receiver.push(partial[0..partial_len], &opener);
    try std.testing.expect(partial_result.event == null);

    var interleaved: [128]u8 = undefined;
    const interleaved_len = try sender.seal(
        record.content_type_application_data,
        "not allowed inside a handshake message",
        &interleaved,
    );
    try std.testing.expectError(
        error.InterleavedHandshake,
        receiver.push(interleaved[0..interleaved_len], &opener),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        receiver.push("", &opener),
    );

    const close_initial = secret.Secret.fromSha256([_]u8{0xd1} ** 32);
    var close_sender = try traffic.State.init(
        .chacha20_poly1305_sha256,
        close_initial,
    );
    defer close_sender.deinit();
    var close_opener = try traffic.State.init(
        .chacha20_poly1305_sha256,
        close_initial,
    );
    defer close_opener.deinit();
    var close_receiver = ProtectedReceiver(64){};

    const close = (alert.Alert{
        .level = .warning,
        .description = .close_notify,
    }).toBytes();
    var close_record: [64]u8 = undefined;
    const close_len = try close_sender.seal(
        record.content_type_alert,
        &close,
        &close_record,
    );
    const close_result = try close_receiver.push(
        close_record[0..close_len],
        &close_opener,
    );
    try std.testing.expect(close_result.event.?.alert.isCloseNotify());
    try std.testing.expect(close_receiver.peerClosed());

    var late_record: [64]u8 = undefined;
    const late_len = try close_sender.seal(
        record.content_type_application_data,
        "late",
        &late_record,
    );
    try std.testing.expectError(
        error.DataAfterCloseNotify,
        close_receiver.push(late_record[0..late_len], &close_opener),
    );
}

test "protected receiver latches malformed alert failures" {
    const secret = @import("../crypto/secret.zig");
    const initial = secret.Secret.fromSha256([_]u8{0xe1} ** 32);
    var sender = try traffic.State.init(.aes_128_gcm_sha256, initial);
    defer sender.deinit();
    var opener = try traffic.State.init(.aes_128_gcm_sha256, initial);
    defer opener.deinit();
    var receiver = ProtectedReceiver(64){};

    var encoded: [64]u8 = undefined;
    const encoded_len = try sender.seal(
        record.content_type_alert,
        &.{2},
        &encoded,
    );
    try std.testing.expectError(
        error.InvalidAlert,
        receiver.push(encoded[0..encoded_len], &opener),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        receiver.push("", &opener),
    );
}
