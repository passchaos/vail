//! Version-negotiating TLS 1.2/TLS 1.3 client connection.
//!
//! Both protocol engines are initialized from the same exact ClientHello.
//! The wrapper buffers the first server handshake message, selects its version,
//! destroys the unused engine (wiping its secrets), and replays the untouched
//! record prefix into the selected state machine.

const std = @import("std");
const client12 = @import("../tls12/tls12_client_connection.zig");
const client13 = @import("client_connection.zig");
const client_hello = @import("../handshake/client_hello.zig");
const record = @import("../record.zig");
const server_hello = @import("../handshake/server_hello.zig");
const stream = @import("stream.zig");

pub const Protocol = enum {
    tls12,
    tls13,
};

pub const Config = struct {
    tls13: client13.Config,
    tls12: client12.Config,
};

pub const Error = std.mem.Allocator.Error || stream.Error ||
    stream.HandshakeError || client_hello.Error || client13.Error ||
    client12.Error || error{
    InvalidUnifiedClientHello,
    UnexpectedRecord,
    UnexpectedHandshakeMessage,
    ConnectionFailed,
};

pub fn ClientConnection(
    comptime max_server_flight_len: usize,
    comptime max_post_handshake_len: usize,
) type {
    const Tls13 = client13.ClientConnection(
        max_server_flight_len,
        max_post_handshake_len,
    );
    const Tls12 = client12.ClientConnection(
        max_server_flight_len,
        max_post_handshake_len,
    );
    return struct {
        const Self = @This();

        pub const Event = union(enum) {
            tls13: Tls13.Event,
            tls12: client12.Event,
        };

        pub const ReceiveResult = struct {
            consumed: usize,
            event: ?Event,
        };

        pub const Established = union(enum) {
            tls13: Tls13.Established,
            tls12: client12.Established,

            pub fn deinit(self: *Established) void {
                switch (self.*) {
                    .tls13 => |*established| established.deinit(),
                    .tls12 => |*established| established.deinit(),
                }
                self.* = undefined;
            }
        };

        pub const ReceiveIntoEvent = union(enum) {
            tls13: Tls13.ReceiveIntoEvent,
            tls12: client12.ReceiveIntoEvent,
        };

        pub const ReceiveIntoResult = struct {
            consumed: usize,
            event: ?ReceiveIntoEvent,
        };

        const State = enum {
            negotiating,
            tls13,
            tls12,
            failed,
        };

        allocator: std.mem.Allocator,
        state: State,
        tls13: Tls13,
        tls12: Tls12,
        records: stream.RecordDeframer = .{},
        messages: stream.HandshakeReassembler(max_server_flight_len) = .{},
        server_prefix: std.ArrayList(u8) = .empty,

        pub fn init(
            config: Config,
            output: *std.ArrayList(u8),
        ) Error!Self {
            var self: Self = undefined;
            try self.initInto(config, output);
            return self;
        }

        /// Initialize the dual-version negotiation state directly in
        /// caller-owned storage.
        pub fn initInto(
            self: *Self,
            config: Config,
            output: *std.ArrayList(u8),
        ) Error!void {
            if (config.tls12.resumption != null and
                config.tls12.ticket_resumption != null)
            {
                return error.InvalidUnifiedClientHello;
            }
            if (config.tls13.record_size_limit !=
                config.tls12.policy.record_size_limit)
            {
                return error.InvalidUnifiedClientHello;
            }
            if (config.tls13.request_ocsp != config.tls12.request_ocsp) {
                return error.InvalidUnifiedClientHello;
            }
            const output_start = output.items.len;
            errdefer output.shrinkRetainingCapacity(output_start);
            var tls13_config = config.tls13;
            tls13_config.request_ocsp_multi =
                config.tls12.request_ocsp_multi orelse
                config.tls12.request_ocsp;
            const ticket_session_id = client12.deriveTicketSessionId(
                config.tls13.random,
            );
            if (config.tls12.ticket_resumption) |cached| {
                tls13_config.session_id = &ticket_session_id;
                tls13_config.tls12_session_ticket = cached.ticket();
            } else if (config.tls12.resumption) |*session| {
                tls13_config.session_id = session.id();
                tls13_config.tls12_session_ticket = if (config.tls12.request_session_ticket)
                    &.{}
                else
                    null;
            } else if (config.tls12.request_session_ticket) {
                tls13_config.tls12_session_ticket = &.{};
            }
            var tls13 = try Tls13.init(tls13_config, output);
            errdefer tls13.deinit();
            if (output.items.len - output_start < record.header_len) {
                return error.InvalidUnifiedClientHello;
            }
            const hello_record = output.items[output_start..];
            const hello_len = std.mem.readInt(u16, hello_record[3..5], .big);
            if (hello_record.len != record.header_len + hello_len) {
                return error.InvalidUnifiedClientHello;
            }
            const hello = hello_record[record.header_len..];
            const parsed = try client_hello.parse(hello);
            if (!parsed.supportsVersion(0x0304) or
                !parsed.supportsVersion(0x0303) or
                !parsed.offers_extended_master_secret or
                !parsed.offers_secure_renegotiation)
            {
                return error.InvalidUnifiedClientHello;
            }
            var tls12 = try Tls12.initWithClientHello(config.tls12, hello);
            errdefer tls12.deinit();
            self.*.allocator = config.tls13.allocator;
            self.*.state = .negotiating;
            self.*.tls13 = tls13;
            self.*.tls12 = tls12;
            self.*.records.buffered = 0;
            self.*.messages.buffered = 0;
            self.*.server_prefix = .empty;
        }

        pub fn protocol(self: *const Self) ?Protocol {
            return switch (self.state) {
                .tls13 => Protocol.tls13,
                .tls12 => Protocol.tls12,
                else => null,
            };
        }

        pub fn deinit(self: *Self) void {
            switch (self.state) {
                .negotiating => {
                    self.tls13.deinit();
                    self.tls12.deinit();
                },
                .tls13 => self.tls13.deinit(),
                .tls12 => self.tls12.deinit(),
                .failed => {},
            }
            self.server_prefix.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn receive(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            var established: Established = undefined;
            const result = try self.receiveInto(
                input,
                output,
                &established,
            );
            return .{
                .consumed = result.consumed,
                .event = if (result.event) |event| switch (event) {
                    .tls13 => |nested| .{ .tls13 = legacy13Event(
                        nested,
                        &established,
                    ) },
                    .tls12 => |nested| .{ .tls12 = legacy12Event(
                        nested,
                        &established,
                    ) },
                } else null,
            };
        }

        /// Feed transport bytes and transfer an established TLS 1.2 or TLS
        /// 1.3 connection directly into caller-owned union storage.
        pub fn receiveInto(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
            established_output: *Established,
        ) Error!ReceiveIntoResult {
            return switch (self.state) {
                .negotiating => self.receiveNegotiatingInto(
                    input,
                    output,
                    established_output,
                ) catch |err| {
                    self.failNegotiating();
                    return err;
                },
                .tls13 => blk: {
                    established_output.* = .{ .tls13 = undefined };
                    break :blk wrap13(try self.tls13.receiveInto(
                        input,
                        output,
                        &established_output.tls13,
                    ));
                },
                .tls12 => blk: {
                    established_output.* = .{ .tls12 = undefined };
                    break :blk wrap12(try self.tls12.receiveInto(
                        input,
                        output,
                        &established_output.tls12,
                    ));
                },
                .failed => error.ConnectionFailed,
            };
        }

        fn receiveNegotiatingInto(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
            established_output: *Established,
        ) Error!ReceiveIntoResult {
            const framed_result = try self.records.push(input);
            const framed = framed_result.framed orelse return .{
                .consumed = framed_result.consumed,
                .event = null,
            };
            if (framed.content_type != record.content_type_handshake) {
                return error.UnexpectedRecord;
            }
            try self.server_prefix.appendSlice(self.allocator, framed.bytes);
            const message_result = try self.messages.push(framed.fragment);
            const message = message_result.message orelse return .{
                .consumed = framed_result.consumed,
                .event = null,
            };
            if (message[0] != server_hello.handshake_type_server_hello) {
                return error.UnexpectedHandshakeMessage;
            }
            const is_tls13 = server_hello.isHelloRetryRequest(message) or
                (server_hello.parseServerHello(message) catch null) != null;
            std.debug.assert(self.state == .negotiating);
            if (is_tls13) {
                self.tls12.deinit();
                self.state = .tls13;
                established_output.* = .{ .tls13 = undefined };
                const delegated = try replayPrefixInto(
                    Tls13,
                    Tls13.ReceiveIntoResult,
                    Tls13.Established,
                    &self.tls13,
                    self.server_prefix.items,
                    output,
                    &established_output.tls13,
                );
                self.server_prefix.clearRetainingCapacity();
                return .{
                    .consumed = framed_result.consumed,
                    .event = if (delegated.event) |event|
                        .{ .tls13 = event }
                    else
                        null,
                };
            }
            self.tls13.deinit();
            self.state = .tls12;
            established_output.* = .{ .tls12 = undefined };
            const delegated = try replayPrefixInto(
                Tls12,
                client12.ReceiveIntoResult,
                client12.Established,
                &self.tls12,
                self.server_prefix.items,
                output,
                &established_output.tls12,
            );
            self.server_prefix.clearRetainingCapacity();
            return .{
                .consumed = framed_result.consumed,
                .event = if (delegated.event) |event|
                    .{ .tls12 = event }
                else
                    null,
            };
        }

        fn failNegotiating(self: *Self) void {
            if (self.state == .negotiating) {
                self.tls13.deinit();
                self.tls12.deinit();
            }
            self.state = .failed;
        }

        fn wrap13(result: Tls13.ReceiveIntoResult) ReceiveIntoResult {
            return .{
                .consumed = result.consumed,
                .event = if (result.event) |event|
                    .{ .tls13 = event }
                else
                    null,
            };
        }

        fn wrap12(result: client12.ReceiveIntoResult) ReceiveIntoResult {
            return .{
                .consumed = result.consumed,
                .event = if (result.event) |event|
                    .{ .tls12 = event }
                else
                    null,
            };
        }

        fn legacy13Event(
            event: Tls13.ReceiveIntoEvent,
            established: *Established,
        ) Tls13.Event {
            return switch (event) {
                .hello_retry_request => .{ .hello_retry_request = {} },
                .server_hello => .{ .server_hello = {} },
                .compatibility_change_cipher_spec => .{ .compatibility_change_cipher_spec = {} },
                .peer_alert => |received| .{ .peer_alert = received },
                .ech_rejected => |rejection| .{ .ech_rejected = rejection },
                .established => .{ .established = established.tls13 },
            };
        }

        fn legacy12Event(
            event: client12.ReceiveIntoEvent,
            established: *Established,
        ) client12.Event {
            return switch (event) {
                .client_flight => .{ .client_flight = {} },
                .change_cipher_spec => .{ .change_cipher_spec = {} },
                .peer_alert => |received| .{ .peer_alert = received },
                .established => .{ .established = established.tls12 },
            };
        }
    };
}

fn replayPrefixInto(
    comptime Connection: type,
    comptime Result: type,
    comptime Established: type,
    connection: *Connection,
    prefix: []const u8,
    output: *std.ArrayList(u8),
    established_output: *Established,
) Error!Result {
    var offset: usize = 0;
    var last: Result = .{ .consumed = 0, .event = null };
    while (offset < prefix.len) {
        last = try connection.receiveInto(
            prefix[offset..],
            output,
            established_output,
        );
        if (last.consumed == 0) return error.ConnectionFailed;
        offset += last.consumed;
        if (last.event != null and offset != prefix.len) {
            return error.UnexpectedHandshakeMessage;
        }
    }
    return last;
}

test "versioned ClientHello carries a TLS 1.2 session ticket" {
    const allocator = std.testing.allocator;
    const tls12 = @import("../tls12/tls12.zig");
    const tls12_ticket = @import("../tls12/tls12_ticket.zig");
    const key_exchange = @import("../key_exchange.zig");
    var cached = try tls12_ticket.Cached.init(
        allocator,
        "opaque-rfc5077-ticket",
        &.{},
        .ecdhe_rsa_aes_128_gcm_sha256,
        [_]u8{0x61} ** tls12.master_secret_len,
        "example.com",
        "h2",
        100,
        60,
    );
    defer cached.deinit();
    var tls13_key = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0x62} ** key_exchange.secret_len,
    };
    var tls13_retry_key = key_exchange.ClientKeyMaterial{
        .secp256r1 = [_]u8{0} ** (key_exchange.p256.secret_len - 1) ++ .{2},
    };
    var tls12_key = [_]u8{0} ** key_exchange.p256.secret_len;
    tls12_key[tls12_key.len - 1] = 1;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var client = try ClientConnection(4096, 4096).init(.{
        .tls13 = .{
            .allocator = allocator,
            .random = [_]u8{0x63} ** 32,
            .server_name = "example.com",
            .key_material = &tls13_key,
            .retry_key_material = &tls13_retry_key,
            .additional_cipher_suites = &.{ 0xc02f, 0x00ff },
            .supported_versions = &.{ 0x0304, 0x0303 },
            .offer_extended_master_secret = true,
            .record_size_limit = 1024,
            .alpn_protocols = &.{"h2"},
            .server_verifier = .{},
        },
        .tls12 = .{
            .allocator = allocator,
            .random = [_]u8{0x63} ** 32,
            .server_name = "example.com",
            .client_private_key = &tls12_key,
            .policy = .{
                .alpn_protocols = &.{"h2"},
                .record_size_limit = 1024,
            },
            .server_verifier = .{},
            .ticket_resumption = &cached,
            .now_seconds = 101,
        },
    }, &output);
    defer client.deinit();
    const hello = try client_hello.parse(output.items[record.header_len..]);
    try std.testing.expect(hello.requests_ocsp);
    try std.testing.expect(hello.requests_ocsp_multi);
    try std.testing.expectEqualSlices(
        u8,
        cached.ticket(),
        hello.session_ticket.?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client12.deriveTicketSessionId([_]u8{0x63} ** 32),
        hello.session_id,
    );
    try std.testing.expectEqual(@as(?u16, 1024), hello.record_size_limit);
}
