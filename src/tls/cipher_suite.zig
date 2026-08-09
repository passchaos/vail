//! TLS 1.3 cipher-suite identities and deterministic negotiation policy.
//!
//! Cipher-suite selection belongs to TLS rather than to any transport.  QUIC,
//! record-layer, and future protocol adapters consume the selected suite but
//! must not each implement subtly different offer parsing or preference rules.

const std = @import("std");

pub const Suite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    chacha20_poly1305_sha256 = 0x1303,

    pub fn wireValue(self: Suite) u16 {
        return @intFromEnum(self);
    }

    pub fn fromWire(value: u16) ?Suite {
        return switch (value) {
            @intFromEnum(Suite.aes_128_gcm_sha256) => .aes_128_gcm_sha256,
            @intFromEnum(Suite.chacha20_poly1305_sha256) => .chacha20_poly1305_sha256,
            else => null,
        };
    }

    pub fn keyLen(self: Suite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    /// RFC 9001 §6.6 per-key packet confidentiality limits.
    pub fn confidentialityLimit(self: Suite) u64 {
        return switch (self) {
            .aes_128_gcm_sha256 => @as(u64, 1) << 23,
            .chacha20_poly1305_sha256 => @as(u64, 1) << 62,
        };
    }

    /// RFC 9001 §6.6 per-connection authentication-failure limits.
    pub fn integrityLimit(self: Suite) u64 {
        return switch (self) {
            .aes_128_gcm_sha256 => @as(u64, 1) << 52,
            .chacha20_poly1305_sha256 => @as(u64, 1) << 36,
        };
    }
};

/// Safe default preference for machines with fast hardware AES.  Callers can
/// put ChaCha first, or expose only ChaCha, without changing parser behavior.
pub const default_preference = [_]Suite{
    .aes_128_gcm_sha256,
    .chacha20_poly1305_sha256,
};

pub const SelectionPolicy = enum {
    server_order,
    client_order,
};

pub const Error = error{
    InvalidCipherSuiteList,
    InvalidServerPreference,
    NoSharedCipherSuite,
};

/// Select a supported TLS 1.3 suite from the ClientHello wire vector.
///
/// Unknown values are intentionally ignored so future clients remain
/// interoperable.  The vector shape and the local preference list are
/// validated before selection; this keeps malformed configuration distinct
/// from the ordinary no-overlap handshake failure.
pub fn selectFromWire(
    client_wire: []const u8,
    server_preference: []const Suite,
    policy: SelectionPolicy,
) Error!Suite {
    if (client_wire.len < 2 or client_wire.len % 2 != 0) {
        return error.InvalidCipherSuiteList;
    }
    try validatePreference(server_preference);

    return switch (policy) {
        .server_order => selectServerOrder(
            client_wire,
            server_preference,
        ),
        .client_order => selectClientOrder(
            client_wire,
            server_preference,
        ),
    } orelse error.NoSharedCipherSuite;
}

pub fn containsWire(client_wire: []const u8, suite: Suite) bool {
    if (client_wire.len % 2 != 0) return false;
    var offset: usize = 0;
    while (offset < client_wire.len) : (offset += 2) {
        if (std.mem.readInt(
            u16,
            client_wire[offset..][0..2],
            .big,
        ) == suite.wireValue()) {
            return true;
        }
    }
    return false;
}

fn validatePreference(preference: []const Suite) Error!void {
    if (preference.len == 0) return error.InvalidServerPreference;
    for (preference, 0..) |suite, index| {
        for (preference[0..index]) |previous| {
            if (suite == previous) {
                return error.InvalidServerPreference;
            }
        }
    }
}

fn selectServerOrder(
    client_wire: []const u8,
    server_preference: []const Suite,
) ?Suite {
    for (server_preference) |suite| {
        if (containsWire(client_wire, suite)) return suite;
    }
    return null;
}

fn selectClientOrder(
    client_wire: []const u8,
    server_preference: []const Suite,
) ?Suite {
    var offset: usize = 0;
    while (offset < client_wire.len) : (offset += 2) {
        const suite = Suite.fromWire(std.mem.readInt(
            u16,
            client_wire[offset..][0..2],
            .big,
        )) orelse continue;
        for (server_preference) |supported| {
            if (suite == supported) return suite;
        }
    }
    return null;
}

test "TLS 1.3 cipher-suite selection supports both preference policies" {
    const offered = [_]u8{
        0x13, 0x03,
        0x13, 0x02, // Unknown to this SHA-256-only implementation.
        0x13, 0x01,
    };
    try std.testing.expectEqual(
        Suite.aes_128_gcm_sha256,
        try selectFromWire(
            &offered,
            &default_preference,
            .server_order,
        ),
    );
    try std.testing.expectEqual(
        Suite.chacha20_poly1305_sha256,
        try selectFromWire(
            &offered,
            &default_preference,
            .client_order,
        ),
    );
}

test "TLS 1.3 cipher-suite selection validates local and wire lists" {
    try std.testing.expectError(
        error.InvalidCipherSuiteList,
        selectFromWire(&.{0x13}, &default_preference, .server_order),
    );
    try std.testing.expectError(
        error.InvalidServerPreference,
        selectFromWire(
            &.{ 0x13, 0x01 },
            &.{ .aes_128_gcm_sha256, .aes_128_gcm_sha256 },
            .server_order,
        ),
    );
    try std.testing.expectError(
        error.NoSharedCipherSuite,
        selectFromWire(
            &.{ 0x13, 0x02 },
            &default_preference,
            .server_order,
        ),
    );
}
