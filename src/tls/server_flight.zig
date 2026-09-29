//! Minimal TLS 1.3 server first-flight planner.
//!
//! This composes ClientHello parsing with ServerHello/EncryptedExtensions wire
//! builders. It is not a complete handshake state machine yet, but it provides
//! the negotiation core that OpenSSL/rustls interop will exercise next.

const std = @import("std");
const certificate_compression = @import("certificate_compression.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const server_hello = @import("server_hello.zig");

pub const Error = std.mem.Allocator.Error || client_hello.Error || error{
    NoTls13,
    NoSharedCipherSuite,
    NoSupportedKeyShare,
    NoSupportedGroup,
    RetryGroupAlreadyOffered,
    MissingQuicTransportParameters,
    InvalidAlpn,
    InvalidServerHello,
    InvalidEncryptedExtensions,
};

pub const RetrySelection = struct {
    suite: cipher_suite.Suite,
    selected_group: u16,
};

pub fn selectHelloRetryRequest(
    client: client_hello.Parsed,
    policy: Policy,
    requested_group: u16,
) Error!RetrySelection {
    if (!client.offersTls13()) return error.NoTls13;
    if (policy.quic_transport_parameters != null and
        client.quic_transport_parameters == null)
    {
        return error.MissingQuicTransportParameters;
    }
    var group_allowed = false;
    for (policy.groups) |group| {
        if (group == requested_group) group_allowed = true;
    }
    if (!group_allowed or !try client.supportsGroup(requested_group)) {
        return error.NoSupportedGroup;
    }
    if (try client.keyShareForGroup(requested_group) != null) {
        return error.RetryGroupAlreadyOffered;
    }
    const suite = for (policy.cipher_suites) |candidate| {
        if (client.hasCipherSuite(candidate.wireValue())) break candidate;
    } else return error.NoSharedCipherSuite;
    return .{ .suite = suite, .selected_group = requested_group };
}

pub const Selection = struct {
    suite: cipher_suite.Suite,
    key_share_group: u16,
    alpn_protocol: ?[]const u8,
};

pub const Policy = struct {
    cipher_suites: []const cipher_suite.Suite = &cipher_suite.default_preference,
    groups: []const u16 = &.{ 0x001d, 0x0017 },
    alpn_protocols: []const []const u8 = &.{},
    quic_transport_parameters: ?[]const u8 = null,
    /// DER-encoded OCSPResponse stapled only when the client offered the
    /// status_request extension and the handshake is certificate based.
    ocsp_response: ?[]const u8 = null,
    /// Precomputed compressed Certificate messages. The first entry matching
    /// both the actual Certificate body and a client-offered algorithm wins.
    compressed_certificates: []const certificate_compression.PreparedView = &.{},
};

pub fn select(client: client_hello.Parsed, policy: Policy) Error!Selection {
    if (!client.offersTls13()) return error.NoTls13;
    if (policy.quic_transport_parameters != null and
        client.quic_transport_parameters == null)
    {
        return error.MissingQuicTransportParameters;
    }
    const suite = for (policy.cipher_suites) |candidate| {
        if (client.hasCipherSuite(candidate.wireValue())) break candidate;
    } else return error.NoSharedCipherSuite;
    const key_share = try firstSupportedShare(client, policy.groups) orelse
        return error.NoSupportedKeyShare;
    return .{
        .suite = suite,
        .key_share_group = key_share.group,
        .alpn_protocol = try selectAlpn(client.alpn_protocols, policy.alpn_protocols),
    };
}

pub fn writeFirstFlight(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    client: client_hello.Parsed,
    policy: Policy,
    server_random: [32]u8,
    server_key_share: []const u8,
) Error!Selection {
    const chosen = try select(client, policy);
    try server_hello.writeServerHello(out, allocator, .{
        .random = server_random,
        .session_id_echo = client.session_id,
        .cipher_suite = chosen.suite,
        .key_share_group = chosen.key_share_group,
        .key_share = server_key_share,
    });
    try server_hello.writeEncryptedExtensions(out, allocator, .{
        .alpn_protocol = chosen.alpn_protocol,
        .quic_transport_parameters = policy.quic_transport_parameters,
    });
    return chosen;
}

fn firstSupportedShare(
    client: client_hello.Parsed,
    groups: []const u16,
) Error!?client_hello.KeyShare {
    var pos: usize = 0;
    if (client.key_shares.len == 0) return null;
    const shares_len = readU16(client.key_shares, &pos) orelse
        return error.InvalidClientHello;
    if (shares_len != client.key_shares.len - pos) return error.InvalidClientHello;
    while (pos < client.key_shares.len) {
        const group = readU16(client.key_shares, &pos) orelse
            return error.InvalidClientHello;
        const key_exchange = readU16Vector(client.key_shares, &pos) orelse
            return error.InvalidClientHello;
        if (key_exchange.len == 0) return error.InvalidClientHello;
        for (groups) |allowed| {
            if (allowed == group) return .{ .group = group, .key_exchange = key_exchange };
        }
    }
    return null;
}

fn selectAlpn(
    client_protocols: []const u8,
    server_protocols: []const []const u8,
) Error!?[]const u8 {
    if (server_protocols.len == 0 or client_protocols.len == 0) return null;
    var pos: usize = 0;
    const list_len = readU16(client_protocols, &pos) orelse
        return error.InvalidAlpn;
    if (list_len != client_protocols.len - pos) return error.InvalidAlpn;
    while (pos < client_protocols.len) {
        if (pos >= client_protocols.len) return error.InvalidAlpn;
        const len = client_protocols[pos];
        pos += 1;
        if (len == 0 or pos + len > client_protocols.len) return error.InvalidAlpn;
        const protocol = client_protocols[pos .. pos + len];
        pos += len;
        for (server_protocols) |server_protocol| {
            if (std.mem.eql(u8, protocol, server_protocol)) return server_protocol;
        }
    }
    return null;
}

fn readU16(bytes: []const u8, pos: *usize) ?u16 {
    if (pos.* + 2 > bytes.len) return null;
    defer pos.* += 2;
    return std.mem.readInt(u16, bytes[pos.*..][0..2], .big);
}

fn readU16Vector(bytes: []const u8, pos: *usize) ?[]const u8 {
    const len = readU16(bytes, pos) orelse return null;
    if (pos.* + len > bytes.len) return null;
    defer pos.* += len;
    return bytes[pos.* .. pos.* + len];
}

test "server first flight selects from a parsed ClientHello" {
    const hello = [_]u8{
        0x01, 0x00, 0x00, 0x6c, 0x03, 0x03,
    } ++ ([_]u8{0x11} ** 32) ++ [_]u8{
        0x03, 1,    2,    3,
        0x00, 0x04, 0x13, 0x01,
        0x13, 0x03, 0x01, 0x00,
        0x00, 0x3c, 0x00, 0x2b,
        0x00, 0x03, 0x02, 0x03,
        0x04, 0x00, 0x10, 0x00,
        0x05, 0x00, 0x03, 0x02,
        'h',  '2',  0x00, 0x33,
        0x00, 0x0c, 0x00, 0x0a,
        0x00, 0x1d, 0x00, 0x06,
        1,    2,    3,    4,
        5,    6,    0x00, 0x00,
        0x00, 0x10, 0x00, 0x0e,
        0x00, 0x00, 0x0b, 'e',
        'x',  'a',  'm',  'p',
        'l',  'e',  '.',  'c',
        'o',  'm',  0x00, 0x0a,
        0x00, 0x04, 0x00, 0x02,
        0x00, 0x1d,
    };
    const parsed = try client_hello.parse(&hello);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    const chosen = try writeFirstFlight(
        &out,
        std.testing.allocator,
        parsed,
        .{ .alpn_protocols = &.{"h2"} },
        [_]u8{0x22} ** 32,
        &.{ 9, 8, 7, 6 },
    );
    try std.testing.expectEqual(cipher_suite.Suite.aes_128_gcm_sha256, chosen.suite);
    try std.testing.expectEqual(@as(u16, 0x001d), chosen.key_share_group);
    try std.testing.expectEqualStrings("h2", chosen.alpn_protocol.?);
    try std.testing.expectEqual(server_hello.handshake_type_server_hello, out.items[0]);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{server_hello.handshake_type_encrypted_extensions}) != null);
}
