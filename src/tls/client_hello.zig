//! TLS ClientHello parser for interoperability tests and server negotiation.
//!
//! The parser intentionally keeps slices borrowed from the input so callers can
//! feed OpenSSL/rustls wire bytes without allocation. It validates vector
//! lengths and extracts the extensions Vail negotiates today.

const std = @import("std");

pub const handshake_type_client_hello: u8 = 0x01;
pub const ext_server_name: u16 = 0x0000;
pub const ext_supported_groups: u16 = 0x000a;
pub const ext_signature_algorithms: u16 = 0x000d;
pub const ext_application_layer_protocol_negotiation: u16 = 0x0010;
pub const ext_supported_versions: u16 = 0x002b;
pub const ext_psk_key_exchange_modes: u16 = 0x002d;
pub const ext_key_share: u16 = 0x0033;
pub const ext_pre_shared_key: u16 = 0x0029;
pub const tls13: u16 = 0x0304;

pub const Error = error{
    InvalidClientHello,
    DuplicateExtension,
};

pub const KeyShare = struct {
    group: u16,
    key_exchange: []const u8,
};

pub const Parsed = struct {
    legacy_version: u16,
    random: *const [32]u8,
    session_id: []const u8,
    cipher_suites: []const u8,
    compression_methods: []const u8,
    server_name: ?[]const u8 = null,
    supported_groups: []const u8 = &.{},
    signature_algorithms: []const u8 = &.{},
    alpn_protocols: []const u8 = &.{},
    supported_versions: []const u8 = &.{},
    psk_key_exchange_modes: []const u8 = &.{},
    key_shares: []const u8 = &.{},
    pre_shared_key: ?[]const u8 = null,

    pub fn offersTls13(self: Parsed) bool {
        var pos: usize = 0;
        while (pos < self.supported_versions.len) : (pos += 2) {
            if (pos + 2 > self.supported_versions.len) return false;
            if (std.mem.readInt(u16, self.supported_versions[pos..][0..2], .big) == tls13) {
                return true;
            }
        }
        return false;
    }

    pub fn hasCipherSuite(self: Parsed, suite: u16) bool {
        var pos: usize = 0;
        while (pos < self.cipher_suites.len) : (pos += 2) {
            if (pos + 2 > self.cipher_suites.len) return false;
            if (std.mem.readInt(u16, self.cipher_suites[pos..][0..2], .big) == suite) {
                return true;
            }
        }
        return false;
    }

    pub fn firstKeyShare(self: Parsed) Error!?KeyShare {
        var pos: usize = 0;
        if (self.key_shares.len == 0) return null;
        const shares_len = try readU16VectorLen(self.key_shares, &pos);
        if (shares_len != self.key_shares.len - pos) return error.InvalidClientHello;
        if (pos == self.key_shares.len) return null;
        const group = try readInt(u16, self.key_shares, &pos);
        const key_exchange = try readU16Vector(self.key_shares, &pos);
        if (key_exchange.len == 0) return error.InvalidClientHello;
        return .{ .group = group, .key_exchange = key_exchange };
    }

    pub fn keyShareForGroup(self: Parsed, target_group: u16) Error!?KeyShare {
        var pos: usize = 0;
        if (self.key_shares.len == 0) return null;
        const shares_len = try readU16VectorLen(self.key_shares, &pos);
        if (shares_len != self.key_shares.len - pos) return error.InvalidClientHello;
        while (pos < self.key_shares.len) {
            const group = try readInt(u16, self.key_shares, &pos);
            const key_exchange = try readU16Vector(self.key_shares, &pos);
            if (key_exchange.len == 0) return error.InvalidClientHello;
            if (group == target_group) return .{ .group = group, .key_exchange = key_exchange };
        }
        return null;
    }
};

pub fn parse(bytes: []const u8) Error!Parsed {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_client_hello) {
        return error.InvalidClientHello;
    }
    const body_len = try readU24(bytes, &pos);
    if (body_len != bytes.len - pos) return error.InvalidClientHello;
    const legacy_version = try readInt(u16, bytes, &pos);
    const random = (try readSlice(bytes, &pos, 32))[0..32];
    const session_id = try readU8Vector(bytes, &pos);
    const cipher_suites = try readU16Vector(bytes, &pos);
    if (cipher_suites.len == 0 or cipher_suites.len % 2 != 0) {
        return error.InvalidClientHello;
    }
    const compression_methods = try readU8Vector(bytes, &pos);
    if (compression_methods.len == 0) return error.InvalidClientHello;
    var parsed = Parsed{
        .legacy_version = legacy_version,
        .random = random,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
    };
    if (pos == bytes.len) return parsed;
    const extensions = try readU16Vector(bytes, &pos);
    if (pos != bytes.len) return error.InvalidClientHello;
    var seen = std.StaticBitSet(65536).initEmpty();
    var ext_pos: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const payload = try readU16Vector(extensions, &ext_pos);
        if (seen.isSet(typ)) return error.DuplicateExtension;
        seen.set(typ);
        switch (typ) {
            ext_server_name => parsed.server_name = try parseSni(payload),
            ext_supported_groups => parsed.supported_groups = payload,
            ext_signature_algorithms => parsed.signature_algorithms = payload,
            ext_application_layer_protocol_negotiation => parsed.alpn_protocols = payload,
            ext_supported_versions => parsed.supported_versions = try parseSupportedVersions(payload),
            ext_psk_key_exchange_modes => parsed.psk_key_exchange_modes = try parseU8List(payload),
            ext_key_share => parsed.key_shares = payload,
            ext_pre_shared_key => parsed.pre_shared_key = payload,
            else => {},
        }
    }
    return parsed;
}

fn parseSni(payload: []const u8) Error!?[]const u8 {
    var pos: usize = 0;
    const list = try readU16Vector(payload, &pos);
    if (pos != payload.len or list.len == 0) return error.InvalidClientHello;
    var list_pos: usize = 0;
    var first_host: ?[]const u8 = null;
    while (list_pos < list.len) {
        const name_type = try readByte(list, &list_pos);
        const name = try readU16Vector(list, &list_pos);
        if (name.len == 0) return error.InvalidClientHello;
        if (name_type == 0 and first_host == null) first_host = name;
    }
    return first_host;
}

fn parseSupportedVersions(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const versions = try readU8Vector(payload, &pos);
    if (pos != payload.len or versions.len == 0 or versions.len % 2 != 0) {
        return error.InvalidClientHello;
    }
    return versions;
}

fn parseU8List(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const list = try readU8Vector(payload, &pos);
    if (pos != payload.len) return error.InvalidClientHello;
    return list;
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    const out = try readSlice(bytes, pos, 1);
    return out[0];
}

fn readInt(comptime T: type, bytes: []const u8, pos: *usize) Error!T {
    const out = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, out[0..@sizeOf(T)], .big);
}

fn readU24(bytes: []const u8, pos: *usize) Error!usize {
    const out = try readSlice(bytes, pos, 3);
    return (@as(usize, out[0]) << 16) | (@as(usize, out[1]) << 8) | out[2];
}

fn readU8Vector(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readByte(bytes, pos);
    return readSlice(bytes, pos, len);
}

fn readU16VectorLen(bytes: []const u8, pos: *usize) Error!usize {
    return @intCast(try readInt(u16, bytes, pos));
}

fn readU16Vector(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16VectorLen(bytes, pos);
    return readSlice(bytes, pos, len);
}

fn readSlice(bytes: []const u8, pos: *usize, len: usize) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch return error.InvalidClientHello;
    if (end > bytes.len) return error.InvalidClientHello;
    defer pos.* = end;
    return bytes[pos.*..end];
}

test "ClientHello parser extracts a minimal TLS 1.3 offer" {
    const hello = [_]u8{
        0x01, 0x00, 0x00, 0x6c, 0x03, 0x03,
    } ++ ([_]u8{0x11} ** 32) ++ [_]u8{
        0x00, // session id
        0x00,
        0x04,
        0x13,
        0x01,
        0x13,
        0x03,
        0x01,
        0x00,
        0x00,
        0x3f,
        0x00,
        0x2b,
        0x00,
        0x03,
        0x02,
        0x03,
        0x04,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x0e,
        0x00,
        0x00,
        0x0b,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        '.',
        'c',
        'o',
        'm',
        0x00,
        0x0a,
        0x00,
        0x06,
        0x00,
        0x04,
        0x00,
        0x1d,
        0x00,
        0x17,
        0x00,
        0x0d,
        0x00,
        0x06,
        0x00,
        0x04,
        0x08,
        0x07,
        0x04,
        0x03,
        0x00,
        0x33,
        0x00,
        0x0c,
        0x00,
        0x0a,
        0x00,
        0x1d,
        0x00,
        0x06,
        1,
        2,
        3,
        4,
        5,
        6,
    };
    const parsed = try parse(&hello);
    try std.testing.expect(parsed.offersTls13());
    try std.testing.expect(parsed.hasCipherSuite(0x1301));
    try std.testing.expectEqualStrings("example.com", parsed.server_name.?);
    const share = (try parsed.firstKeyShare()).?;
    try std.testing.expectEqual(@as(u16, 0x001d), share.group);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, share.key_exchange);
    const same_share = (try parsed.keyShareForGroup(0x001d)).?;
    try std.testing.expectEqualSlices(u8, share.key_exchange, same_share.key_exchange);
    try std.testing.expectEqual(@as(?KeyShare, null), try parsed.keyShareForGroup(0x0020));
}
