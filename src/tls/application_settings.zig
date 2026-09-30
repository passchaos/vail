//! TLS Application-Layer Protocol Settings (ALPS).
//!
//! ALPS remains a deployed Internet-Draft. AWS-LC/BoringSSL use 17513 by
//! default and optionally support the newer experimental value 17613. Vail
//! accepts both and preserves the offered codepoint throughout the exchange.

const std = @import("std");

pub const legacy_extension_type: u16 = 17513;
pub const current_extension_type: u16 = 17613;
pub const handshake_type_encrypted_extensions: u8 = 0x08;

pub const Codepoint = enum(u16) {
    legacy = legacy_extension_type,
    current = current_extension_type,
};

pub const Setting = struct {
    protocol: []const u8,
    settings: []const u8,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidApplicationSettings,
};

pub const ProtocolIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *ProtocolIterator) ?[]const u8 {
        if (self.pos == self.bytes.len) return null;
        const len: usize = self.bytes[self.pos];
        self.pos += 1;
        std.debug.assert(len != 0 and len <= self.bytes.len - self.pos);
        defer self.pos += len;
        return self.bytes[self.pos..][0..len];
    }
};

pub fn appendSupportPayload(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocols: []const []const u8,
) Error!void {
    if (protocols.len == 0) return error.InvalidApplicationSettings;
    const start = out.items.len;
    try out.appendSlice(allocator, &.{ 0, 0 });
    errdefer out.items.len = start;
    for (protocols, 0..) |protocol, index| {
        if (protocol.len == 0 or protocol.len > std.math.maxInt(u8) or
            out.items.len - start > std.math.maxInt(u16) - protocol.len - 1)
        {
            return error.InvalidApplicationSettings;
        }
        for (protocols[0..index]) |previous| {
            if (std.mem.eql(u8, previous, protocol)) {
                return error.InvalidApplicationSettings;
            }
        }
        try out.append(allocator, @intCast(protocol.len));
        try out.appendSlice(allocator, protocol);
    }
    std.mem.writeInt(
        u16,
        out.items[start..][0..2],
        @intCast(out.items.len - start - 2),
        .big,
    );
}

/// Validate a ClientHello ALPS payload and return the inner ProtocolNameList.
pub fn parseSupportPayload(payload: []const u8) Error![]const u8 {
    if (payload.len < 2) return error.InvalidApplicationSettings;
    const list_len = std.mem.readInt(u16, payload[0..2], .big);
    if (list_len == 0 or list_len != payload.len - 2) {
        return error.InvalidApplicationSettings;
    }
    const protocols = payload[2..];
    var protocol_pos: usize = 0;
    var count: usize = 0;
    while (protocol_pos < protocols.len) {
        const protocol_len: usize = protocols[protocol_pos];
        protocol_pos += 1;
        if (protocol_len == 0 or protocol_len > protocols.len - protocol_pos) {
            return error.InvalidApplicationSettings;
        }
        const protocol = protocols[protocol_pos..][0..protocol_len];
        var previous_pos: usize = 0;
        for (0..count) |_| {
            const previous_len: usize = protocols[previous_pos];
            previous_pos += 1;
            const previous = protocols[previous_pos..][0..previous_len];
            previous_pos += previous_len;
            if (std.mem.eql(u8, previous, protocol)) {
                return error.InvalidApplicationSettings;
            }
        }
        protocol_pos += protocol_len;
        count += 1;
    }
    return protocols;
}

pub fn supportsProtocol(protocols: []const u8, target: []const u8) bool {
    var iterator = ProtocolIterator{ .bytes = protocols };
    while (iterator.next()) |protocol| {
        if (std.mem.eql(u8, protocol, target)) return true;
    }
    return false;
}

pub fn findSetting(
    settings: []const Setting,
    protocol: []const u8,
) ?[]const u8 {
    for (settings) |entry| {
        if (std.mem.eql(u8, entry.protocol, protocol)) return entry.settings;
    }
    return null;
}

pub const Payload = struct {
    codepoint: Codepoint,
    settings: []const u8,
};

pub const ParsedClientEncryptedExtensions = Payload;

pub fn writeClientEncryptedExtensions(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    codepoint: Codepoint,
    settings: []const u8,
) Error!void {
    if (settings.len > std.math.maxInt(u16)) {
        return error.InvalidApplicationSettings;
    }
    const body_len = 2 + 2 + 2 + settings.len;
    try out.append(allocator, handshake_type_encrypted_extensions);
    try appendU24(out, allocator, @intCast(body_len));
    try appendInt(out, allocator, u16, 4 + settings.len);
    try appendInt(out, allocator, u16, @intFromEnum(codepoint));
    try appendInt(out, allocator, u16, settings.len);
    try out.appendSlice(allocator, settings);
}

pub fn parseClientEncryptedExtensions(
    message: []const u8,
) Error!ParsedClientEncryptedExtensions {
    var pos: usize = 0;
    if (try readByte(message, &pos) != handshake_type_encrypted_extensions or
        try readU24(message, &pos) != message.len - pos)
    {
        return error.InvalidApplicationSettings;
    }
    const extensions = try readU16Vector(message, &pos);
    if (pos != message.len) return error.InvalidApplicationSettings;
    var extension_pos: usize = 0;
    const raw_type = try readInt(u16, extensions, &extension_pos);
    const codepoint: Codepoint = switch (raw_type) {
        legacy_extension_type => .legacy,
        current_extension_type => .current,
        else => return error.InvalidApplicationSettings,
    };
    const settings = try readU16Vector(extensions, &extension_pos);
    if (extension_pos != extensions.len) {
        return error.InvalidApplicationSettings;
    }
    return .{ .codepoint = codepoint, .settings = settings };
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: anytype,
) std.mem.Allocator.Error!void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .big);
    try out.appendSlice(allocator, &bytes);
}

fn appendU24(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u24,
) std.mem.Allocator.Error!void {
    try out.appendSlice(allocator, &.{
        @truncate(value >> 16),
        @truncate(value >> 8),
        @truncate(value),
    });
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    return (try readSlice(bytes, pos, 1))[0];
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) Error!T {
    const value = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, value[0..@sizeOf(T)], .big);
}

fn readU24(bytes: []const u8, pos: *usize) Error!usize {
    const value = try readSlice(bytes, pos, 3);
    return (@as(usize, value[0]) << 16) |
        (@as(usize, value[1]) << 8) | value[2];
}

fn readU16Vector(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readInt(u16, bytes, pos);
    return readSlice(bytes, pos, len);
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch
        return error.InvalidApplicationSettings;
    if (end > bytes.len) return error.InvalidApplicationSettings;
    defer pos.* = end;
    return bytes[pos.*..end];
}

test "ALPS support and client EncryptedExtensions codecs are strict" {
    const allocator = std.testing.allocator;
    var support: std.ArrayList(u8) = .empty;
    defer support.deinit(allocator);
    try appendSupportPayload(&support, allocator, &.{ "h2", "h3" });
    const protocols = try parseSupportPayload(support.items);
    try std.testing.expect(supportsProtocol(protocols, "h2"));
    try std.testing.expect(supportsProtocol(protocols, "h3"));
    try std.testing.expect(!supportsProtocol(protocols, "http/1.1"));
    try std.testing.expectError(
        error.InvalidApplicationSettings,
        parseSupportPayload(&.{ 0, 0 }),
    );
    try std.testing.expectError(
        error.InvalidApplicationSettings,
        parseSupportPayload(&.{ 0, 2, 0, 0 }),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeClientEncryptedExtensions(
        &encoded,
        allocator,
        .current,
        &.{ 1, 2, 3 },
    );
    const parsed = try parseClientEncryptedExtensions(encoded.items);
    try std.testing.expectEqual(Codepoint.current, parsed.codepoint);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, parsed.settings);
    try std.testing.expectError(
        error.InvalidApplicationSettings,
        parseClientEncryptedExtensions(encoded.items[0 .. encoded.items.len - 1]),
    );
}
