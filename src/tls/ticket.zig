//! TLS 1.3 NewSessionTicket codec and resumption-PSK derivation.
//!
//! Slices in `Parsed` borrow from the encoded handshake message.  The owning
//! session cache copies all fields that must outlive packet processing.

const std = @import("std");

const application_settings = @import("application_settings.zig");
const key_schedule = @import("key_schedule.zig");
const cipher_suite = @import("cipher_suite.zig");
const secret = @import("secret.zig");
const transcript = @import("transcript.zig");

pub const handshake_type_new_session_ticket: u8 = 0x04;
pub const ext_early_data: u16 = 0x002a;
pub const quic_early_data_size: u32 = std.math.maxInt(u32);
pub const max_lifetime_seconds: u32 = 7 * 24 * 60 * 60;

pub const Error = std.mem.Allocator.Error || error{
    InvalidNewSessionTicket,
    InvalidTicketLifetime,
    InvalidEarlyDataSize,
    TicketNotYetValid,
    ExpiredTicket,
};

/// Client-owned session state derived from an authenticated NewSessionTicket.
pub const Cached = struct {
    allocator: std.mem.Allocator,
    identity: []u8,
    psk: secret.Secret,
    suite: cipher_suite.Suite,
    server_name: []u8,
    alpn: []u8,
    age_add: u32,
    received_at_ms: u64,
    lifetime_seconds: u32,
    max_early_data_size: ?u32,
    application_settings_codepoint: ?application_settings.Codepoint,
    local_application_settings: ?[]u8,
    peer_application_settings: ?[]u8,

    pub fn deinit(self: *Cached) void {
        self.psk.deinit();
        self.allocator.free(self.identity);
        self.allocator.free(self.server_name);
        self.allocator.free(self.alpn);
        if (self.local_application_settings) |settings| {
            self.allocator.free(settings);
        }
        if (self.peer_application_settings) |settings| {
            self.allocator.free(settings);
        }
        self.* = undefined;
    }

    pub fn obfuscatedTicketAge(
        self: *const Cached,
        now_ms: u64,
    ) Error!u32 {
        if (now_ms < self.received_at_ms) return error.TicketNotYetValid;
        const age = now_ms - self.received_at_ms;
        if (age > @as(u64, self.lifetime_seconds) * std.time.ms_per_s or
            age > std.math.maxInt(u32))
        {
            return error.ExpiredTicket;
        }
        return @as(u32, @intCast(age)) +% self.age_add;
    }
};

pub fn cache(
    allocator: std.mem.Allocator,
    message: []const u8,
    suite: cipher_suite.Suite,
    master_secret: secret.Secret,
    transcript_after_client_finished: transcript.Digest,
    server_name: []const u8,
    alpn: []const u8,
    received_at_ms: u64,
    negotiated_application_settings: ?application_settings.Session,
) (Error || key_schedule.Error)!Cached {
    if (master_secret.hash != suite.hash() or
        transcript_after_client_finished.hash != suite.hash())
    {
        return error.InvalidNewSessionTicket;
    }
    const parsed = try parse(message);
    var resumption_master = try key_schedule.deriveResumptionMasterSecretFor(
        master_secret,
        transcript_after_client_finished,
    );
    defer resumption_master.deinit();
    var psk_secret = try key_schedule.deriveResumptionPskFor(
        resumption_master,
        parsed.nonce,
    );
    errdefer psk_secret.deinit();
    const identity = try allocator.dupe(u8, parsed.ticket);
    errdefer allocator.free(identity);
    const owned_server_name = try allocator.dupe(u8, server_name);
    errdefer allocator.free(owned_server_name);
    const owned_alpn = try allocator.dupe(u8, alpn);
    errdefer allocator.free(owned_alpn);
    const local_application_settings = if (negotiated_application_settings) |settings|
        try allocator.dupe(u8, settings.local)
    else
        null;
    errdefer if (local_application_settings) |settings| allocator.free(settings);
    const peer_application_settings = if (negotiated_application_settings) |settings|
        try allocator.dupe(u8, settings.peer)
    else
        null;
    errdefer if (peer_application_settings) |settings| allocator.free(settings);
    return .{
        .allocator = allocator,
        .identity = identity,
        .psk = psk_secret,
        .suite = suite,
        .server_name = owned_server_name,
        .alpn = owned_alpn,
        .age_add = parsed.age_add,
        .received_at_ms = received_at_ms,
        .lifetime_seconds = parsed.lifetime_seconds,
        .max_early_data_size = parsed.max_early_data_size,
        .application_settings_codepoint = if (negotiated_application_settings) |settings|
            settings.codepoint
        else
            null,
        .local_application_settings = local_application_settings,
        .peer_application_settings = peer_application_settings,
    };
}

pub const Options = struct {
    lifetime_seconds: u32,
    age_add: u32,
    nonce: []const u8,
    ticket: []const u8,
    allow_early_data: bool = false,
};

pub const Parsed = struct {
    lifetime_seconds: u32,
    age_add: u32,
    nonce: []const u8,
    ticket: []const u8,
    max_early_data_size: ?u32,
};

pub fn write(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: Options,
) Error!void {
    try validateOptions(options);
    const original_len = list.items.len;
    errdefer list.items.len = original_len;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendInt(&body, allocator, u32, options.lifetime_seconds);
    try appendInt(&body, allocator, u32, options.age_add);
    try body.append(allocator, @intCast(options.nonce.len));
    try body.appendSlice(allocator, options.nonce);
    try appendInt(&body, allocator, u16, @intCast(options.ticket.len));
    try body.appendSlice(allocator, options.ticket);
    if (options.allow_early_data) {
        try appendInt(&body, allocator, u16, 8);
        try appendInt(&body, allocator, u16, ext_early_data);
        try appendInt(&body, allocator, u16, @sizeOf(u32));
        try appendInt(&body, allocator, u32, quic_early_data_size);
    } else {
        try appendInt(&body, allocator, u16, 0);
    }
    if (body.items.len > std.math.maxInt(u24)) {
        return error.InvalidNewSessionTicket;
    }

    try list.append(allocator, handshake_type_new_session_ticket);
    var len: [3]u8 = undefined;
    writeU24(&len, @intCast(body.items.len));
    try list.appendSlice(allocator, &len);
    try list.appendSlice(allocator, body.items);
}

pub fn parse(bytes: []const u8) Error!Parsed {
    if (bytes.len < 4 or bytes[0] != handshake_type_new_session_ticket) {
        return error.InvalidNewSessionTicket;
    }
    const body_len = readU24(bytes[1..4]);
    if (body_len + 4 != bytes.len) return error.InvalidNewSessionTicket;
    var pos: usize = 4;

    const lifetime_seconds = try readInt(u32, bytes, &pos);
    if (lifetime_seconds == 0 or
        lifetime_seconds > max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
    const age_add = try readInt(u32, bytes, &pos);
    const nonce_len = try readInt(u8, bytes, &pos);
    const nonce = try readSlice(bytes, &pos, nonce_len);
    const ticket_len = try readInt(u16, bytes, &pos);
    if (ticket_len == 0) return error.InvalidNewSessionTicket;
    const ticket = try readSlice(bytes, &pos, ticket_len);
    const extensions_len = try readInt(u16, bytes, &pos);
    const extensions = try readSlice(bytes, &pos, extensions_len);
    if (pos != bytes.len) return error.InvalidNewSessionTicket;

    var early_data_size: ?u32 = null;
    var ext_pos: usize = 0;
    var seen: [64]u16 = undefined;
    var seen_len: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const len = try readInt(u16, extensions, &ext_pos);
        const payload = try readSlice(extensions, &ext_pos, len);
        for (seen[0..seen_len]) |existing| {
            if (existing == typ) return error.InvalidNewSessionTicket;
        }
        if (seen_len == seen.len) return error.InvalidNewSessionTicket;
        seen[seen_len] = typ;
        seen_len += 1;

        if (typ == ext_early_data) {
            if (payload.len != @sizeOf(u32)) {
                return error.InvalidEarlyDataSize;
            }
            const size = std.mem.readInt(u32, payload[0..4], .big);
            if (size != quic_early_data_size) {
                return error.InvalidEarlyDataSize;
            }
            early_data_size = size;
        }
    }
    return .{
        .lifetime_seconds = lifetime_seconds,
        .age_add = age_add,
        .nonce = nonce,
        .ticket = ticket,
        .max_early_data_size = early_data_size,
    };
}

pub fn deriveResumptionMasterSecret(
    master_secret: [32]u8,
    transcript_hash: [32]u8,
) [32]u8 {
    return key_schedule.deriveResumptionMasterSecret(
        master_secret,
        transcript_hash,
    );
}

pub fn deriveResumptionMasterSecretSha384(
    master_secret: [48]u8,
    transcript_hash: [48]u8,
) [48]u8 {
    return key_schedule.Sha384.deriveResumptionMasterSecret(
        master_secret,
        transcript_hash,
    );
}

pub fn derivePsk(
    resumption_master_secret: [32]u8,
    ticket_nonce: []const u8,
) [32]u8 {
    return key_schedule.deriveResumptionPsk(
        resumption_master_secret,
        ticket_nonce,
    );
}

pub fn derivePskSha384(
    resumption_master_secret: [48]u8,
    ticket_nonce: []const u8,
) [48]u8 {
    return key_schedule.Sha384.deriveResumptionPsk(
        resumption_master_secret,
        ticket_nonce,
    );
}

fn validateOptions(options: Options) Error!void {
    if (options.lifetime_seconds == 0 or
        options.lifetime_seconds > max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
    if (options.nonce.len > std.math.maxInt(u8) or
        options.ticket.len == 0 or
        options.ticket.len > std.math.maxInt(u16))
    {
        return error.InvalidNewSessionTicket;
    }
}

fn appendInt(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try list.appendSlice(allocator, &bytes);
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) Error!T {
    const slice = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, slice[0..@sizeOf(T)], .big);
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch
        return error.InvalidNewSessionTicket;
    if (end > bytes.len) return error.InvalidNewSessionTicket;
    const result = bytes[pos.*..end];
    pos.* = end;
    return result;
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn writeU24(bytes: *[3]u8, value: u24) void {
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}

test "authenticated NewSessionTicket becomes an owned client cache entry" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try write(&encoded, allocator, .{
        .lifetime_seconds = 60,
        .age_add = 17,
        .nonce = &.{ 1, 2, 3 },
        .ticket = "opaque-ticket",
        .allow_early_data = true,
    });
    const master = secret.Secret.fromSha384([_]u8{0x44} ** 48);
    var state = transcript.State.init(.sha384);
    state.update("complete-handshake");
    var cached = try cache(
        allocator,
        encoded.items,
        .aes_256_gcm_sha384,
        master,
        state.digest(),
        "example.com",
        "h2",
        10_000,
        .{
            .codepoint = .legacy,
            .local = "client-settings",
            .peer = "server-settings",
        },
    );
    defer cached.deinit();
    try std.testing.expectEqual(secret.Hash.sha384, cached.psk.hash);
    try std.testing.expectEqualStrings("opaque-ticket", cached.identity);
    try std.testing.expectEqualStrings("example.com", cached.server_name);
    try std.testing.expectEqualStrings("h2", cached.alpn);
    try std.testing.expectEqual(
        application_settings.Codepoint.legacy,
        cached.application_settings_codepoint.?,
    );
    try std.testing.expectEqualStrings(
        "client-settings",
        cached.local_application_settings.?,
    );
    try std.testing.expectEqualStrings(
        "server-settings",
        cached.peer_application_settings.?,
    );
    try std.testing.expectEqual(
        @as(u32, 1_017),
        try cached.obfuscatedTicketAge(11_000),
    );
    try std.testing.expectError(
        error.ExpiredTicket,
        cached.obfuscatedTicketAge(70_001),
    );
}
