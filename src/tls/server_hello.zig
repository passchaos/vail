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
pub const ext_key_share: u16 = 0x0033;
pub const ext_application_layer_protocol_negotiation: u16 = 0x0010;
pub const ext_quic_transport_parameters: u16 = 0x0039;
pub const tls13: u16 = 0x0304;

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
};

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
    try appendInt(&body, allocator, u16, extensions.items.len);
    try body.appendSlice(allocator, extensions.items);
    try writeHandshake(out, allocator, handshake_type_server_hello, body.items);
}

pub const EncryptedExtensions = struct {
    alpn_protocol: ?[]const u8 = null,
    quic_transport_parameters: ?[]const u8 = null,
};

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

test "ServerHello and EncryptedExtensions encode TLS 1.3 extensions" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try writeServerHello(&out, std.testing.allocator, .{
        .random = [_]u8{0x44} ** 32,
        .session_id_echo = &.{ 1, 2, 3 },
        .cipher_suite = .aes_128_gcm_sha256,
        .key_share_group = 0x001d,
        .key_share = &.{ 4, 5, 6, 7 },
    });
    try std.testing.expectEqual(handshake_type_server_hello, out.items[0]);
    try std.testing.expectEqual(@as(u16, 0x1301), std.mem.readInt(u16, out.items[4 + 2 + 32 + 1 + 3 ..][0..2], .big));
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 }) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x33, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x04, 4, 5, 6, 7 }) != null);

    out.clearRetainingCapacity();
    try writeEncryptedExtensions(&out, std.testing.allocator, .{
        .alpn_protocol = "h2",
        .quic_transport_parameters = &.{ 0x00, 0x01, 0x00 },
    });
    try std.testing.expectEqual(handshake_type_encrypted_extensions, out.items[0]);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2' }) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x00, 0x39, 0x00, 0x03, 0x00, 0x01, 0x00 }) != null);
}
