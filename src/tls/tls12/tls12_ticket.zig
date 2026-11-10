//! RFC 5077 TLS 1.2 session-ticket codec and client-owned cached state.
//!
//! Ticket bytes remain opaque to the client. The client retains the negotiated
//! master secret and context locally, while a server may use `ticket_keyring`
//! to place equivalent state inside an authenticated, encrypted ticket.

const std = @import("std");
const tls12 = @import("tls12.zig");

pub const handshake_type_new_session_ticket: u8 = 0x04;
pub const max_lifetime_seconds: u32 = 7 * 24 * 60 * 60;

pub const Error = std.mem.Allocator.Error || tls12.Error || error{
    InvalidNewSessionTicket,
    InvalidTicket,
    InvalidTicketLifetime,
};

pub const Parsed = struct {
    lifetime_hint_seconds: u32,
    ticket: []const u8,
};

/// Client-owned RFC 5077 resumption state. `ticket` is the opaque identity
/// emitted by the server; `session` binds its master secret to the server name,
/// cipher suite, ALPN, issue time, and advertised lifetime.
pub const Cached = struct {
    allocator: std.mem.Allocator,
    session: tls12.Session,
    ticket_storage: []u8,

    pub fn init(
        allocator: std.mem.Allocator,
        ticket_bytes: []const u8,
        session_id: []const u8,
        suite: tls12.Suite,
        master_secret: [tls12.master_secret_len]u8,
        identity: []const u8,
        alpn_protocol: []const u8,
        created_at_seconds: u64,
        lifetime_seconds: u32,
    ) Error!Cached {
        if (ticket_bytes.len == 0 or
            ticket_bytes.len > std.math.maxInt(u16)) return error.InvalidTicket;
        if (lifetime_seconds == 0 or
            lifetime_seconds > max_lifetime_seconds)
        {
            return error.InvalidTicketLifetime;
        }
        var session = try tls12.Session.initForTicket(
            session_id,
            suite,
            master_secret,
            identity,
            alpn_protocol,
            created_at_seconds,
            lifetime_seconds,
        );
        errdefer session.deinit();
        return .{
            .allocator = allocator,
            .session = session,
            .ticket_storage = try allocator.dupe(u8, ticket_bytes),
        };
    }

    pub fn clone(
        self: *const Cached,
        allocator: std.mem.Allocator,
    ) Error!Cached {
        return .{
            .allocator = allocator,
            .session = self.session,
            .ticket_storage = try allocator.dupe(u8, self.ticket()),
        };
    }

    pub fn ticket(self: *const Cached) []const u8 {
        return self.ticket_storage;
    }

    pub fn sessionId(self: *const Cached) []const u8 {
        return self.session.id();
    }

    pub fn alpn(self: *const Cached) []const u8 {
        return self.session.alpn();
    }

    pub fn validate(
        self: *const Cached,
        now_seconds: u64,
        identity: []const u8,
    ) Error!void {
        if (self.ticket_storage.len == 0 or
            self.ticket_storage.len > std.math.maxInt(u16))
        {
            return error.InvalidTicket;
        }
        try self.session.validate(now_seconds, identity);
    }

    pub fn deinit(self: *Cached) void {
        self.session.deinit();
        std.crypto.secureZero(u8, self.ticket_storage);
        self.allocator.free(self.ticket_storage);
        self.* = undefined;
    }
};

pub fn write(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    lifetime_hint_seconds: u32,
    ticket_bytes: []const u8,
) Error!void {
    if (ticket_bytes.len > std.math.maxInt(u16)) {
        return error.InvalidNewSessionTicket;
    }
    const body_len = 4 + 2 + ticket_bytes.len;
    if (body_len > std.math.maxInt(u24)) {
        return error.InvalidNewSessionTicket;
    }
    try output.append(allocator, handshake_type_new_session_ticket);
    try output.appendSlice(allocator, &.{
        @truncate(body_len >> 16),
        @truncate(body_len >> 8),
        @truncate(body_len),
    });
    var lifetime: [4]u8 = undefined;
    std.mem.writeInt(u32, &lifetime, lifetime_hint_seconds, .big);
    try output.appendSlice(allocator, &lifetime);
    var ticket_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &ticket_len, @intCast(ticket_bytes.len), .big);
    try output.appendSlice(allocator, &ticket_len);
    try output.appendSlice(allocator, ticket_bytes);
}

pub fn parse(message: []const u8) Error!Parsed {
    if (message.len < 10 or message[0] != handshake_type_new_session_ticket) {
        return error.InvalidNewSessionTicket;
    }
    const body_len = (@as(usize, message[1]) << 16) |
        (@as(usize, message[2]) << 8) | message[3];
    if (body_len != message.len - 4) {
        return error.InvalidNewSessionTicket;
    }
    const lifetime_hint_seconds = std.mem.readInt(u32, message[4..8], .big);
    const ticket_len = std.mem.readInt(u16, message[8..10], .big);
    if (ticket_len != message.len - 10) {
        return error.InvalidNewSessionTicket;
    }
    return .{
        .lifetime_hint_seconds = lifetime_hint_seconds,
        .ticket = message[10..],
    };
}

test "RFC 5077 NewSessionTicket round trip and strict lengths" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try write(&encoded, std.testing.allocator, 3600, "opaque ticket");
    const parsed = try parse(encoded.items);
    try std.testing.expectEqual(@as(u32, 3600), parsed.lifetime_hint_seconds);
    try std.testing.expectEqualStrings("opaque ticket", parsed.ticket);

    encoded.clearRetainingCapacity();
    try write(&encoded, std.testing.allocator, 0, &.{});
    const empty = try parse(encoded.items);
    try std.testing.expectEqual(@as(u32, 0), empty.lifetime_hint_seconds);
    try std.testing.expectEqual(@as(usize, 0), empty.ticket.len);

    var truncated = try std.testing.allocator.dupe(u8, encoded.items);
    defer std.testing.allocator.free(truncated);
    truncated[9] += 1;
    try std.testing.expectError(
        error.InvalidNewSessionTicket,
        parse(truncated),
    );

    var cached = try Cached.init(
        std.testing.allocator,
        "opaque ticket",
        &.{},
        .ecdhe_rsa_aes_128_gcm_sha256,
        [_]u8{0x44} ** tls12.master_secret_len,
        "example.com",
        "h2",
        100,
        60,
    );
    defer cached.deinit();
    try cached.validate(159, "example.com");
    try std.testing.expectError(
        error.SessionExpired,
        cached.validate(160, "example.com"),
    );
    try std.testing.expectError(
        error.SessionContextMismatch,
        cached.validate(159, "other.example"),
    );
    var cloned = try cached.clone(std.testing.allocator);
    defer cloned.deinit();
    try std.testing.expectEqualSlices(u8, cached.ticket(), cloned.ticket());
}
