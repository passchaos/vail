//! RFC 6066 host_name excludes literal IPv4 and IPv6 addresses.
const std = @import("std");

/// The caller keeps the original identity for certificate verification and
/// ticket binding. Only the ClientHello extension omits numeric identities.
pub fn wireName(identity: ?[]const u8) ?[]const u8 {
    const name = identity orelse return null;
    if (std.Io.net.IpAddress.parse(name, 0)) |_| return null else |_| {}
    return name;
}

test "TLS SNI omits IP literals while retaining DNS names" {
    try std.testing.expect(wireName(null) == null);
    for ([_][]const u8{ "127.0.0.1", "192.0.2.1", "::1", "2001:db8::1", "::ffff:192.0.2.1" }) |identity| {
        try std.testing.expect(wireName(identity) == null);
    }
    for ([_][]const u8{ "localhost", "example.com", "123.example.com" }) |identity| {
        try std.testing.expectEqualStrings(identity, wireName(identity).?);
    }
}
