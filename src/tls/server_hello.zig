//! TLS 1.3 ServerHello and EncryptedExtensions builders.
//!
//! These wire writers are intentionally small and allocation-friendly so the
//! server state machine can compose interoperable OpenSSL/rustls handshakes
//! from parsed ClientHello state without duplicating extension encoding logic.

const std = @import("std");
const cipher_suite = @import("cipher_suite.zig");

pub const handshake_type_server_hello: u8 = 0x02;
pub const handshake_type_encrypted_extensions: u8 = 0x08;
pub const legacy_version = [_]u8{ 0x03, 0x03 };
pub const ext_supported_versions: u16 = 0x002b;
pub const ext_cookie: u16 = 0x002c;
pub const ext_key_share: u16 = 0x0033;
pub const ext_server_name: u16 = 0x0000;
pub const ext_supported_groups: u16 = 0x000a;
pub const ext_application_layer_protocol_negotiation: u16 = 0x0010;
pub const ext_early_data: u16 = 0x002a;
pub const ext_pre_shared_key: u16 = 0x0029;
pub const ext_quic_transport_parameters: u16 = 0x0039;
pub const tls13: u16 = 0x0304;
pub const hello_retry_request_random = [_]u8{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidServerHello,
    InvalidEncryptedExtensions,
};

pub const ServerHello = struct {
    random: [32]u8,
    session_id_echo: []const u8,
    cipher_suite: cipher_suite.Suite,
    key_share_group: u16,
    key_share: []const u8,
    selected_psk_identity: ?u16 = null,
};

pub const ParsedServerHello = struct {
    random: [32]u8,
    session_id_echo: []const u8,
    cipher_suite: cipher_suite.Suite,
    key_share_group: u16,
    key_share: []const u8,
    selected_psk_identity: ?u16 = null,
};

pub const HelloRetryRequest = struct {
    session_id_echo: []const u8,
    cipher_suite: cipher_suite.Suite,
    selected_group: u16,
    cookie: ?[]const u8 = null,
};

pub const ParsedHelloRetryRequest = struct {
    session_id_echo: []const u8,
    cipher_suite: cipher_suite.Suite,
    selected_group: u16,
    cookie: ?[]const u8,
};

pub fn isHelloRetryRequest(bytes: []const u8) bool {
    const random_offset = 4 + 2;
    return bytes.len >= random_offset + hello_retry_request_random.len and
        std.mem.eql(
            u8,
            bytes[random_offset..][0..hello_retry_request_random.len],
            &hello_retry_request_random,
        );
}

pub fn parseHelloRetryRequest(
    bytes: []const u8,
) Error!ParsedHelloRetryRequest {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_server_hello) {
        return error.InvalidServerHello;
    }
    const body_len = try readU24(bytes, &pos);
    if (body_len != bytes.len - pos or
        try readInt(u16, bytes, &pos) != 0x0303)
    {
        return error.InvalidServerHello;
    }
    const random = try readSlice(bytes, &pos, 32);
    if (!std.mem.eql(u8, random, &hello_retry_request_random)) {
        return error.InvalidServerHello;
    }
    const session_id_len = try readByte(bytes, &pos);
    const session_id_echo = try readSlice(bytes, &pos, session_id_len);
    if (session_id_echo.len > 32) return error.InvalidServerHello;
    const suite = cipher_suite.Suite.fromWire(
        try readInt(u16, bytes, &pos),
    ) orelse return error.InvalidServerHello;
    if (try readByte(bytes, &pos) != 0) return error.InvalidServerHello;
    const extensions_len = try readInt(u16, bytes, &pos);
    const extensions = try readSlice(bytes, &pos, extensions_len);
    if (pos != bytes.len) return error.InvalidServerHello;

    var selected_group: ?u16 = null;
    var cookie: ?[]const u8 = null;
    var saw_version = false;
    var seen = std.StaticBitSet(65536).initEmpty();
    var ext_pos: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const payload_len = try readInt(u16, extensions, &ext_pos);
        const payload = try readSlice(extensions, &ext_pos, payload_len);
        if (seen.isSet(typ)) return error.InvalidServerHello;
        seen.set(typ);
        switch (typ) {
            ext_supported_versions => {
                if (payload.len != 2 or
                    std.mem.readInt(u16, payload[0..2], .big) != tls13)
                {
                    return error.InvalidServerHello;
                }
                saw_version = true;
            },
            ext_key_share => {
                if (payload.len != 2) return error.InvalidServerHello;
                selected_group = std.mem.readInt(u16, payload[0..2], .big);
            },
            ext_cookie => {
                var cookie_pos: usize = 0;
                const cookie_len = try readInt(u16, payload, &cookie_pos);
                cookie = try readSlice(payload, &cookie_pos, cookie_len);
                if (cookie.?.len == 0 or cookie_pos != payload.len) {
                    return error.InvalidServerHello;
                }
            },
            else => return error.InvalidServerHello,
        }
    }
    if (!saw_version or selected_group == null) {
        return error.InvalidServerHello;
    }
    return .{
        .session_id_echo = session_id_echo,
        .cipher_suite = suite,
        .selected_group = selected_group.?,
        .cookie = cookie,
    };
}

pub fn writeHelloRetryRequest(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    retry: HelloRetryRequest,
) Error!void {
    if (retry.session_id_echo.len > 32) return error.InvalidServerHello;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, &legacy_version);
    try body.appendSlice(allocator, &hello_retry_request_random);
    try body.append(allocator, @intCast(retry.session_id_echo.len));
    try body.appendSlice(allocator, retry.session_id_echo);
    try appendInt(&body, allocator, u16, retry.cipher_suite.wireValue());
    try body.append(allocator, 0);

    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    try appendExtensionHeader(&extensions, allocator, ext_supported_versions, 2);
    try appendInt(&extensions, allocator, u16, tls13);
    try appendExtensionHeader(&extensions, allocator, ext_key_share, 2);
    try appendInt(&extensions, allocator, u16, retry.selected_group);
    if (retry.cookie) |cookie| {
        if (cookie.len == 0 or cookie.len > std.math.maxInt(u16)) {
            return error.InvalidServerHello;
        }
        try appendExtensionHeader(
            &extensions,
            allocator,
            ext_cookie,
            2 + cookie.len,
        );
        try appendInt(&extensions, allocator, u16, cookie.len);
        try extensions.appendSlice(allocator, cookie);
    }
    try appendInt(&body, allocator, u16, extensions.items.len);
    try body.appendSlice(allocator, extensions.items);
    try writeHandshake(
        out,
        allocator,
        handshake_type_server_hello,
        body.items,
    );
}

pub fn parseServerHello(
    bytes: []const u8,
) Error!ParsedServerHello {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_server_hello) {
        return error.InvalidServerHello;
    }
    const body_len = try readU24(bytes, &pos);
    if (body_len != bytes.len - pos) return error.InvalidServerHello;
    if (try readInt(u16, bytes, &pos) != 0x0303) {
        return error.InvalidServerHello;
    }
    const random = (try readSlice(bytes, &pos, 32))[0..32].*;
    const session_id_len = try readByte(bytes, &pos);
    const session_id_echo = try readSlice(
        bytes,
        &pos,
        session_id_len,
    );
    if (session_id_echo.len > 32) return error.InvalidServerHello;
    const suite = cipher_suite.Suite.fromWire(
        try readInt(u16, bytes, &pos),
    ) orelse return error.InvalidServerHello;
    if (try readByte(bytes, &pos) != 0) {
        return error.InvalidServerHello;
    }
    const extensions_len = try readInt(u16, bytes, &pos);
    const extensions = try readSlice(bytes, &pos, extensions_len);
    if (pos != bytes.len) return error.InvalidServerHello;

    var saw_version = false;
    var key_share_group: ?u16 = null;
    var key_share: ?[]const u8 = null;
    var selected_psk_identity: ?u16 = null;
    var seen = std.StaticBitSet(65536).initEmpty();
    var ext_pos: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const payload_len = try readInt(u16, extensions, &ext_pos);
        const payload = try readSlice(
            extensions,
            &ext_pos,
            payload_len,
        );
        if (seen.isSet(typ)) return error.InvalidServerHello;
        seen.set(typ);
        switch (typ) {
            ext_supported_versions => {
                if (payload.len != 2 or
                    std.mem.readInt(u16, payload[0..2], .big) != tls13)
                {
                    return error.InvalidServerHello;
                }
                saw_version = true;
            },
            ext_key_share => {
                var share_pos: usize = 0;
                key_share_group = try readInt(u16, payload, &share_pos);
                const len = try readInt(u16, payload, &share_pos);
                key_share = try readSlice(payload, &share_pos, len);
                if (key_share.?.len == 0 or share_pos != payload.len) {
                    return error.InvalidServerHello;
                }
            },
            ext_pre_shared_key => {
                if (payload.len != 2) return error.InvalidServerHello;
                selected_psk_identity = std.mem.readInt(
                    u16,
                    payload[0..2],
                    .big,
                );
            },
            else => return error.InvalidServerHello,
        }
    }
    if (!saw_version or key_share == null) {
        return error.InvalidServerHello;
    }
    return .{
        .random = random,
        .session_id_echo = session_id_echo,
        .cipher_suite = suite,
        .key_share_group = key_share_group.?,
        .key_share = key_share.?,
        .selected_psk_identity = selected_psk_identity,
    };
}

pub fn writeServerHello(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    hello: ServerHello,
) Error!void {
    if (hello.session_id_echo.len > 32 or hello.key_share.len == 0 or
        hello.key_share.len > std.math.maxInt(u16))
    {
        return error.InvalidServerHello;
    }
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, &legacy_version);
    try body.appendSlice(allocator, &hello.random);
    try body.append(allocator, @intCast(hello.session_id_echo.len));
    try body.appendSlice(allocator, hello.session_id_echo);
    try appendInt(&body, allocator, u16, hello.cipher_suite.wireValue());
    try body.append(allocator, 0);

    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    try appendExtensionHeader(&extensions, allocator, ext_supported_versions, 2);
    try appendInt(&extensions, allocator, u16, tls13);
    try appendExtensionHeader(
        &extensions,
        allocator,
        ext_key_share,
        2 + 2 + hello.key_share.len,
    );
    try appendInt(&extensions, allocator, u16, hello.key_share_group);
    try appendInt(&extensions, allocator, u16, hello.key_share.len);
    try extensions.appendSlice(allocator, hello.key_share);
    if (hello.selected_psk_identity) |identity| {
        try appendExtensionHeader(
            &extensions,
            allocator,
            ext_pre_shared_key,
            2,
        );
        try appendInt(&extensions, allocator, u16, identity);
    }
    try appendInt(&body, allocator, u16, extensions.items.len);
    try body.appendSlice(allocator, extensions.items);
    try writeHandshake(out, allocator, handshake_type_server_hello, body.items);
}

pub const EncryptedExtensions = struct {
    alpn_protocol: ?[]const u8 = null,
    quic_transport_parameters: ?[]const u8 = null,
    accept_early_data: bool = false,
};

pub const ParsedEncryptedExtensions = struct {
    alpn_protocol: ?[]const u8 = null,
    supported_groups: []const u8 = &.{},
    early_data_accepted: bool = false,
};

pub fn parseEncryptedExtensions(
    bytes: []const u8,
) Error!ParsedEncryptedExtensions {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) !=
        handshake_type_encrypted_extensions)
    {
        return error.InvalidEncryptedExtensions;
    }
    const body_len = try readU24(bytes, &pos);
    if (body_len != bytes.len - pos) {
        return error.InvalidEncryptedExtensions;
    }
    const extensions_len = try readInt(u16, bytes, &pos);
    const extensions = try readSlice(bytes, &pos, extensions_len);
    if (pos != bytes.len) return error.InvalidEncryptedExtensions;

    var result = ParsedEncryptedExtensions{};
    var seen = std.StaticBitSet(65536).initEmpty();
    var ext_pos: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const len = try readInt(u16, extensions, &ext_pos);
        const payload = try readSlice(extensions, &ext_pos, len);
        if (seen.isSet(typ)) return error.InvalidEncryptedExtensions;
        seen.set(typ);
        if (typ == ext_application_layer_protocol_negotiation) {
            var alpn_pos: usize = 0;
            const names_len = try readInt(u16, payload, &alpn_pos);
            if (names_len != payload.len - alpn_pos) {
                return error.InvalidEncryptedExtensions;
            }
            const protocol_len = try readByte(payload, &alpn_pos);
            result.alpn_protocol = try readSlice(
                payload,
                &alpn_pos,
                protocol_len,
            );
            if (result.alpn_protocol.?.len == 0 or
                alpn_pos != payload.len)
            {
                return error.InvalidEncryptedExtensions;
            }
        } else if (typ == ext_server_name) {
            if (payload.len != 0) {
                return error.InvalidEncryptedExtensions;
            }
        } else if (typ == ext_supported_groups) {
            var groups_pos: usize = 0;
            const groups_len = try readInt(u16, payload, &groups_pos);
            result.supported_groups = try readSlice(
                payload,
                &groups_pos,
                groups_len,
            );
            if (result.supported_groups.len == 0 or
                result.supported_groups.len % 2 != 0 or
                groups_pos != payload.len)
            {
                return error.InvalidEncryptedExtensions;
            }
        } else if (typ == ext_early_data) {
            if (payload.len != 0) return error.InvalidEncryptedExtensions;
            result.early_data_accepted = true;
        } else {
            // A stream TLS adapter does not understand QUIC extensions or
            // early-data acceptance and must fail closed rather than silently
            // extending an unsupported handshake mode.
            return error.InvalidEncryptedExtensions;
        }
    }
    return result;
}

pub fn writeEncryptedExtensions(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    extensions: EncryptedExtensions,
) Error!void {
    var extension_bytes: std.ArrayList(u8) = .empty;
    defer extension_bytes.deinit(allocator);
    if (extensions.alpn_protocol) |protocol| {
        if (protocol.len == 0 or protocol.len > std.math.maxInt(u8)) {
            return error.InvalidEncryptedExtensions;
        }
        const payload_len = 2 + 1 + protocol.len;
        try appendExtensionHeader(
            &extension_bytes,
            allocator,
            ext_application_layer_protocol_negotiation,
            payload_len,
        );
        try appendInt(&extension_bytes, allocator, u16, 1 + protocol.len);
        try extension_bytes.append(allocator, @intCast(protocol.len));
        try extension_bytes.appendSlice(allocator, protocol);
    }
    if (extensions.quic_transport_parameters) |parameters| {
        if (parameters.len > std.math.maxInt(u16)) {
            return error.InvalidEncryptedExtensions;
        }
        try appendExtensionHeader(
            &extension_bytes,
            allocator,
            ext_quic_transport_parameters,
            parameters.len,
        );
        try extension_bytes.appendSlice(allocator, parameters);
    }
    if (extensions.accept_early_data) {
        try appendExtensionHeader(
            &extension_bytes,
            allocator,
            ext_early_data,
            0,
        );
    }
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendInt(&body, allocator, u16, extension_bytes.items.len);
    try body.appendSlice(allocator, extension_bytes.items);
    try writeHandshake(out, allocator, handshake_type_encrypted_extensions, body.items);
}

fn writeHandshake(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u8,
    body: []const u8,
) Error!void {
    if (body.len > std.math.maxInt(u24)) return error.InvalidServerHello;
    try out.append(allocator, typ);
    try appendU24(out, allocator, @intCast(body.len));
    try out.appendSlice(allocator, body);
}

test "HelloRetryRequest codec preserves selected group and cookie" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeHelloRetryRequest(&encoded, allocator, .{
        .session_id_echo = &.{ 1, 2, 3 },
        .cipher_suite = .aes_128_gcm_sha256,
        .selected_group = 0x0017,
        .cookie = "stateless-cookie",
    });
    try std.testing.expect(isHelloRetryRequest(encoded.items));
    const parsed = try parseHelloRetryRequest(encoded.items);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, parsed.session_id_echo);
    try std.testing.expectEqual(
        cipher_suite.Suite.aes_128_gcm_sha256,
        parsed.cipher_suite,
    );
    try std.testing.expectEqual(@as(u16, 0x0017), parsed.selected_group);
    try std.testing.expectEqualStrings("stateless-cookie", parsed.cookie.?);
    try std.testing.expectError(
        error.InvalidServerHello,
        parseServerHello(encoded.items),
    );
}

fn appendExtensionHeader(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u16,
    len: usize,
) Error!void {
    if (len > std.math.maxInt(u16)) return error.InvalidServerHello;
    try appendInt(out, allocator, u16, typ);
    try appendInt(out, allocator, u16, len);
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
    const slice = try readSlice(bytes, pos, 1);
    return slice[0];
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) Error!T {
    const slice = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, slice[0..@sizeOf(T)], .big);
}

fn readU24(bytes: []const u8, pos: *usize) Error!usize {
    const slice = try readSlice(bytes, pos, 3);
    return (@as(usize, slice[0]) << 16) |
        (@as(usize, slice[1]) << 8) |
        slice[2];
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch
        return error.InvalidServerHello;
    if (end > bytes.len) return error.InvalidServerHello;
    const result = bytes[pos.*..end];
    pos.* = end;
    return result;
}

test "ServerHello and EncryptedExtensions encode TLS 1.3 extensions" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try writeServerHello(&out, std.testing.allocator, .{
        .random = [_]u8{0x44} ** 32,
        .session_id_echo = &.{ 1, 2, 3 },
        .cipher_suite = .aes_128_gcm_sha256,
        .key_share_group = 0x001d,
        .key_share = &.{ 4, 5, 6, 7 },
        .selected_psk_identity = 0,
    });
    try std.testing.expectEqual(handshake_type_server_hello, out.items[0]);
    try std.testing.expectEqual(@as(u16, 0x1301), std.mem.readInt(u16, out.items[4 + 2 + 32 + 1 + 3 ..][0..2], .big));
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 }) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x33, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x04, 4, 5, 6, 7 }) != null);
    const parsed_server = try parseServerHello(out.items);
    try std.testing.expectEqual(@as(?u16, 0), parsed_server.selected_psk_identity);

    out.clearRetainingCapacity();
    try writeEncryptedExtensions(&out, std.testing.allocator, .{
        .alpn_protocol = "h2",
        .quic_transport_parameters = &.{ 0x00, 0x01, 0x00 },
    });
    try std.testing.expectEqual(handshake_type_encrypted_extensions, out.items[0]);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2' }) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x39, 0x00, 0x03, 0x00, 0x01, 0x00 }) != null);
}
