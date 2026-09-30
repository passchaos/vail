//! TLS 1.3 post-handshake KeyUpdate codec and record-key transition helpers.

const std = @import("std");
const record = @import("record.zig");
const record_fragment = @import("record_fragment.zig");
const traffic = @import("traffic.zig");

pub const handshake_type: u8 = 24;
pub const encoded_len: usize = 5;

pub const Request = enum(u8) {
    update_not_requested = 0,
    update_requested = 1,
};

pub const Error = traffic.Error || error{
    InvalidKeyUpdate,
    KeyUpdateResponseRequired,
};

pub fn encode(request: Request) [encoded_len]u8 {
    return .{ handshake_type, 0, 0, 1, @intFromEnum(request) };
}

pub fn parse(message: []const u8) Error!Request {
    if (message.len != encoded_len or
        message[0] != handshake_type or
        !std.mem.eql(u8, message[1..4], &.{ 0, 0, 1 }))
    {
        return error.InvalidKeyUpdate;
    }
    return switch (message[4]) {
        0 => .update_not_requested,
        1 => .update_requested,
        else => error.InvalidKeyUpdate,
    };
}

/// Encrypt KeyUpdate under the current write keys, then advance the write
/// traffic secret as required by RFC 8446 section 4.6.3.
pub fn sealAndUpdate(
    state: *traffic.State,
    request: Request,
    output: []u8,
) Error!usize {
    if (!state.canUpdate()) return error.KeyGenerationExhausted;
    const message = encode(request);
    const len = try state.sealForKeyUpdate(&message, output);
    try state.update();
    return len;
}

/// Process a decrypted KeyUpdate and advance the read traffic secret. The
/// returned request tells the connection whether it must schedule a response.
pub fn receiveAndUpdate(
    state: *traffic.State,
    message: []const u8,
) Error!Request {
    const request = try parse(message);
    try state.update();
    return request;
}

/// Bidirectional application-traffic state with RFC 8446 KeyUpdate response
/// ordering. A requested response blocks further application-data writes until
/// the response has been encrypted under the current write keys.
pub const Duplex = struct {
    read: traffic.State,
    write: traffic.State,
    response_pending: bool = false,

    pub fn init(
        suite: @import("cipher_suite.zig").Suite,
        read_secret: @import("secret.zig").Secret,
        write_secret: @import("secret.zig").Secret,
    ) Error!Duplex {
        var read = try traffic.State.init(suite, read_secret);
        errdefer read.deinit();
        return .{
            .read = read,
            .write = try traffic.State.init(suite, write_secret),
        };
    }

    pub fn deinit(self: *Duplex) void {
        self.read.deinit();
        self.write.deinit();
        self.* = undefined;
    }

    pub fn responseRequired(self: *const Duplex) bool {
        return self.response_pending;
    }

    pub fn open(
        self: *Duplex,
        ciphertext: []const u8,
        plaintext: []u8,
    ) Error!record.Opened {
        return self.read.open(ciphertext, plaintext);
    }

    pub fn seal(
        self: *Duplex,
        inner_type: u8,
        plaintext: []const u8,
        output: []u8,
    ) Error!usize {
        if (self.response_pending and
            inner_type == record.content_type_application_data)
        {
            return error.KeyUpdateResponseRequired;
        }
        return self.write.seal(inner_type, plaintext, output);
    }

    pub fn sealFragment(
        self: *Duplex,
        inner_type: u8,
        plaintext: []const u8,
        max_fragment_plaintext: usize,
        output: []u8,
    ) Error!record_fragment.SealResult {
        if (self.response_pending and
            inner_type == record.content_type_application_data)
        {
            return error.KeyUpdateResponseRequired;
        }
        return self.write.sealFragment(
            inner_type,
            plaintext,
            max_fragment_plaintext,
            output,
        );
    }

    pub fn sendKeyUpdate(
        self: *Duplex,
        request: Request,
        output: []u8,
    ) Error!usize {
        const len = try sealAndUpdate(&self.write, request, output);
        self.response_pending = false;
        return len;
    }

    pub fn receiveKeyUpdate(
        self: *Duplex,
        message: []const u8,
    ) Error!Request {
        const request = try receiveAndUpdate(&self.read, message);
        if (request == .update_requested) self.response_pending = true;
        return request;
    }
};

test "KeyUpdate uses old keys for its record and new keys afterward" {
    const secret = @import("secret.zig");
    const initial = secret.Secret.fromSha256([_]u8{0x81} ** 32);
    var sender = try traffic.State.init(.aes_128_gcm_sha256, initial);
    defer sender.deinit();
    var receiver = try traffic.State.init(.aes_128_gcm_sha256, initial);
    defer receiver.deinit();

    var update_record: [128]u8 = undefined;
    const update_record_len = try sealAndUpdate(
        &sender,
        .update_requested,
        &update_record,
    );
    try std.testing.expectEqual(@as(u64, 1), sender.generation);
    try std.testing.expectEqual(@as(?u64, 0), sender.sequenceNumber());

    var plaintext: [128]u8 = undefined;
    const opened = try receiver.open(
        update_record[0..update_record_len],
        &plaintext,
    );
    try std.testing.expectEqual(record.content_type_handshake, opened.content_type);
    try std.testing.expectEqual(
        Request.update_requested,
        try receiveAndUpdate(&receiver, plaintext[0..opened.len]),
    );
    try std.testing.expectEqual(@as(u64, 1), receiver.generation);
    try std.testing.expectEqual(@as(?u64, 0), receiver.sequenceNumber());

    var application_record: [128]u8 = undefined;
    const application_record_len = try sender.seal(
        record.content_type_application_data,
        "after update",
        &application_record,
    );
    const application = try receiver.open(
        application_record[0..application_record_len],
        &plaintext,
    );
    try std.testing.expectEqualStrings(
        "after update",
        plaintext[0..application.len],
    );
}

test "invalid KeyUpdate does not change traffic generation" {
    const secret = @import("secret.zig");
    const initial = secret.Secret.fromSha256([_]u8{0x91} ** 32);
    var state = try traffic.State.init(.aes_128_gcm_sha256, initial);
    defer state.deinit();

    try std.testing.expectError(
        error.InvalidKeyUpdate,
        receiveAndUpdate(&state, &.{ handshake_type, 0, 0, 1, 2 }),
    );
    try std.testing.expectEqual(@as(u64, 0), state.generation);
    try std.testing.expectEqual(@as(?u64, 0), state.sequenceNumber());
}

test "requested KeyUpdate blocks application data until response" {
    const secret = @import("secret.zig");
    const client_secret = secret.Secret.fromSha384([_]u8{0xa1} ** 48);
    const server_secret = secret.Secret.fromSha384([_]u8{0xb1} ** 48);
    var client = try Duplex.init(
        .aes_256_gcm_sha384,
        server_secret,
        client_secret,
    );
    defer client.deinit();
    var server = try Duplex.init(
        .aes_256_gcm_sha384,
        client_secret,
        server_secret,
    );
    defer server.deinit();

    var wire: [128]u8 = undefined;
    var plaintext: [128]u8 = undefined;
    const request_len = try client.sendKeyUpdate(.update_requested, &wire);
    const opened_request = try server.open(wire[0..request_len], &plaintext);
    try std.testing.expectEqual(
        Request.update_requested,
        try server.receiveKeyUpdate(plaintext[0..opened_request.len]),
    );
    try std.testing.expect(server.responseRequired());
    try std.testing.expectError(
        error.KeyUpdateResponseRequired,
        server.seal(
            record.content_type_application_data,
            "blocked",
            &wire,
        ),
    );

    const response_len = try server.sendKeyUpdate(
        .update_not_requested,
        &wire,
    );
    try std.testing.expect(!server.responseRequired());
    const opened_response = try client.open(wire[0..response_len], &plaintext);
    try std.testing.expectEqual(
        Request.update_not_requested,
        try client.receiveKeyUpdate(plaintext[0..opened_response.len]),
    );

    const application_len = try server.seal(
        record.content_type_application_data,
        "new server generation",
        &wire,
    );
    const application = try client.open(
        wire[0..application_len],
        &plaintext,
    );
    try std.testing.expectEqualStrings(
        "new server generation",
        plaintext[0..application.len],
    );
}
