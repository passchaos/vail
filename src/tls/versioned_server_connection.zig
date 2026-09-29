//! Version-negotiating TLS 1.2/TLS 1.3 server connection.
//!
//! This wrapper owns the first plaintext ClientHello, selects the highest
//! enabled protocol version, then delegates every later byte to the dedicated
//! version state machine. Unused one-shot key material is wiped at selection.

const std = @import("std");
const client_hello = @import("client_hello.zig");
const record = @import("record.zig");
const server13 = @import("server_connection.zig");
const stream = @import("stream.zig");
const server12 = @import("tls12_server_connection.zig");

pub const Protocol = enum {
    tls12,
    tls13,
};

pub const Config = struct {
    tls13: server13.Config,
    tls12: server12.Config,
    enable_tls13: bool = true,
    enable_tls12: bool = true,
};

pub const Error = std.mem.Allocator.Error || stream.Error ||
    stream.HandshakeError || client_hello.Error || server13.Error ||
    server12.Error || error{
    NoSupportedProtocolVersion,
    UnexpectedRecord,
    UnexpectedHandshakeMessage,
    AlreadyEstablished,
    ConnectionFailed,
};

/// `max_handshake_message_len` bounds both the ClientHello and the TLS 1.3
/// encrypted client authentication messages.
pub fn ServerConnection(
    comptime max_handshake_message_len: usize,
    comptime max_post_handshake_len: usize,
) type {
    const Tls13 = server13.ServerConnection(
        max_handshake_message_len,
        max_post_handshake_len,
    );
    const Tls12 = server12.ServerConnection(
        max_handshake_message_len,
        max_post_handshake_len,
    );
    return struct {
        const Self = @This();

        pub const Event = union(enum) {
            tls13: Tls13.Event,
            tls12: server12.Event,
        };

        pub const ReceiveResult = struct {
            consumed: usize,
            event: ?Event,
        };

        const State = union(enum) {
            initial,
            tls13: Tls13,
            tls12: Tls12,
            failed,
        };

        config: Config,
        state: State = .initial,
        records: stream.RecordDeframer = .{},
        messages: stream.HandshakeReassembler(max_handshake_message_len) = .{},

        pub fn init(config: Config) Self {
            return .{ .config = config };
        }

        pub fn protocol(self: *const Self) ?Protocol {
            return switch (self.state) {
                .tls13 => .tls13,
                .tls12 => .tls12,
                else => null,
            };
        }

        pub fn deinit(self: *Self) void {
            switch (self.state) {
                .initial => self.wipeAllKeyMaterial(),
                .tls13 => |*connection| connection.deinit(),
                .tls12 => |*connection| connection.deinit(),
                .failed => {},
            }
            self.* = undefined;
        }

        pub fn receive(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            return switch (self.state) {
                .initial => self.receiveInitial(input, output) catch |err| {
                    self.wipeAllKeyMaterial();
                    self.state = .failed;
                    return err;
                },
                .tls13 => |*connection| wrap13(
                    try connection.receive(input, output),
                ),
                .tls12 => |*connection| wrap12(
                    try connection.receive(input, output),
                ),
                .failed => error.ConnectionFailed,
            };
        }

        fn receiveInitial(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const framed_result = try self.records.push(input);
            const framed = framed_result.framed orelse return .{
                .consumed = framed_result.consumed,
                .event = null,
            };
            if (framed.content_type != record.content_type_handshake) {
                return error.UnexpectedRecord;
            }
            const message_result = try self.messages.push(framed.fragment);
            const message = message_result.message orelse return .{
                .consumed = framed_result.consumed,
                .event = null,
            };
            if (message_result.consumed != framed.fragment.len or
                message[0] != client_hello.handshake_type_client_hello)
            {
                return error.UnexpectedHandshakeMessage;
            }
            const parsed = try client_hello.parse(message);
            if (self.config.enable_tls13 and parsed.supportsVersion(0x0304)) {
                self.wipeTls12KeyMaterial();
                self.state = .{ .tls13 = Tls13.init(self.config.tls13) };
                const output_start = output.items.len;
                const delegated = switch (self.state) {
                    .tls13 => |*connection| try replayClientHello(
                        Tls13,
                        Tls13.ReceiveResult,
                        connection,
                        self.config.tls13.allocator,
                        framed.legacy_version,
                        message,
                        output,
                    ),
                    else => unreachable,
                };
                try frameTls13FirstMessage(
                    output,
                    self.config.tls13.allocator,
                    output_start,
                );
                return .{
                    .consumed = framed_result.consumed,
                    .event = if (delegated.event) |event|
                        .{ .tls13 = event }
                    else
                        null,
                };
            }
            const tls12_offered = if (parsed.supported_versions.len == 0)
                parsed.legacy_version >= 0x0303
            else
                parsed.supportsVersion(0x0303);
            if (!self.config.enable_tls12 or !tls12_offered) {
                return error.NoSupportedProtocolVersion;
            }
            self.wipeTls13KeyMaterial();
            self.state = .{ .tls12 = Tls12.init(self.config.tls12) };
            const delegated = switch (self.state) {
                .tls12 => |*connection| try replayClientHello(
                    Tls12,
                    server12.ReceiveResult,
                    connection,
                    self.config.tls12.allocator,
                    framed.legacy_version,
                    message,
                    output,
                ),
                else => unreachable,
            };
            return .{
                .consumed = framed_result.consumed,
                .event = if (delegated.event) |event|
                    .{ .tls12 = event }
                else
                    null,
            };
        }

        fn wipeTls13KeyMaterial(self: *Self) void {
            self.config.tls13.key_material.wipe();
        }

        fn wipeTls12KeyMaterial(self: *Self) void {
            if (self.config.tls12.server_private_key) |private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            if (self.config.tls12.server_private_key_p384) |private_key| {
                std.crypto.secureZero(u8, private_key);
            }
        }

        fn wipeAllKeyMaterial(self: *Self) void {
            self.wipeTls13KeyMaterial();
            self.wipeTls12KeyMaterial();
        }

        fn wrap13(result: Tls13.ReceiveResult) ReceiveResult {
            return .{
                .consumed = result.consumed,
                .event = if (result.event) |event|
                    .{ .tls13 = event }
                else
                    null,
            };
        }

        fn wrap12(result: server12.ReceiveResult) ReceiveResult {
            return .{
                .consumed = result.consumed,
                .event = if (result.event) |event|
                    .{ .tls12 = event }
                else
                    null,
            };
        }
    };
}

fn frameTls13FirstMessage(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    start: usize,
) Error!void {
    if (output.items.len - start < 4) return error.ConnectionFailed;
    const message_len = 4 + (@as(usize, output.items[start + 1]) << 16) +
        (@as(usize, output.items[start + 2]) << 8) +
        output.items[start + 3];
    if (message_len > output.items.len - start or
        message_len > record.max_plaintext_len)
    {
        return error.ConnectionFailed;
    }
    const header = [_]u8{
        record.content_type_handshake,
        3,
        3,
        @truncate(message_len >> 8),
        @truncate(message_len),
    };
    try output.insertSlice(allocator, start, &header);
}

fn replayClientHello(
    comptime Connection: type,
    comptime Result: type,
    connection: *Connection,
    allocator: std.mem.Allocator,
    legacy_version: u16,
    message: []const u8,
    output: *std.ArrayList(u8),
) Error!Result {
    var replay: std.ArrayList(u8) = .empty;
    defer replay.deinit(allocator);
    var offset: usize = 0;
    var last: Result = .{ .consumed = 0, .event = null };
    while (offset < message.len) {
        const len = @min(record.max_plaintext_len, message.len - offset);
        try replay.appendSlice(allocator, &.{
            record.content_type_handshake,
            @truncate(legacy_version >> 8),
            @truncate(legacy_version),
            @truncate(len >> 8),
            @truncate(len),
        });
        try replay.appendSlice(allocator, message[offset..][0..len]);
        offset += len;
    }
    offset = 0;
    while (offset < replay.items.len) {
        last = try connection.receive(replay.items[offset..], output);
        if (last.consumed == 0) return error.ConnectionFailed;
        offset += last.consumed;
        if (last.event != null and offset != replay.items.len) {
            return error.UnexpectedHandshakeMessage;
        }
    }
    return last;
}

test "versioned server selects TLS 1.3 and TLS 1.2 from ClientHello" {
    const allocator = std.testing.allocator;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const signing_key = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0x51} ** Ecdsa.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toUncompressedSec1();

    inline for (.{ Protocol.tls13, Protocol.tls12 }) |expected| {
        var tls13_key = @import("key_exchange.zig").ServerKeyMaterial{
            .x25519 = [_]u8{0x52} ** @import("key_exchange.zig").secret_len,
        };
        var tls12_key = [_]u8{0} ** @import("key_exchange.zig").p256.secret_len;
        tls12_key[tls12_key.len - 1] = 2;
        var server = ServerConnection(4096, 4096).init(.{
            .tls13 = .{
                .allocator = allocator,
                .policy = .{},
                .server_random = [_]u8{0x53} ** 32,
                .key_material = &tls13_key,
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = signing_key,
                } },
            },
            .tls12 = .{
                .allocator = allocator,
                .policy = .{
                    .cipher_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256},
                },
                .server_random = [_]u8{0x54} ** 32,
                .server_private_key = &tls12_key,
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = signing_key,
                } },
            },
        });
        defer server.deinit();
        const client_private = [_]u8{0x55} ** 32;
        const client_public = try @import("key_exchange.zig").publicKey(
            client_private,
        );
        var hello: std.ArrayList(u8) = .empty;
        defer hello.deinit(allocator);
        try client_hello.writeWithKeyShare(&hello, allocator, .{
            .random = [_]u8{0x56} ** 32,
            .key_share = if (expected == .tls13) .{
                .group = @import("key_exchange.zig").named_group_x25519,
                .key_exchange = &client_public,
            } else null,
            .supported_groups = if (expected == .tls13)
                &.{@import("key_exchange.zig").named_group_x25519}
            else
                &.{@import("key_exchange.zig").named_group_secp256r1},
            .cipher_suites = if (expected == .tls13)
                &.{.aes_128_gcm_sha256}
            else
                &.{},
            .additional_cipher_suites = if (expected == .tls12)
                &.{@intFromEnum(
                    @import("tls12.zig").Suite.ecdhe_ecdsa_aes_128_gcm_sha256,
                )}
            else
                &.{},
            .supported_versions = if (expected == .tls13)
                &.{ 0x0304, 0x0303 }
            else
                &.{0x0303},
            .offer_extended_master_secret = expected == .tls12,
        });
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encoded.appendSlice(allocator, &.{
            record.content_type_handshake,
            3,
            1,
            @truncate(hello.items.len >> 8),
            @truncate(hello.items.len),
        });
        try encoded.appendSlice(allocator, hello.items);
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(allocator);
        const result = try server.receive(encoded.items, &output);
        try std.testing.expect(result.event != null);
        try std.testing.expectEqual(expected, server.protocol().?);
    }
}
