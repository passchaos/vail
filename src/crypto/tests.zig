const std = @import("std");
const mac = @import("mac.zig");

test "domain-separated MAC binds part boundaries" {
    const key = [_]u8{0x42} ** mac.key_len;
    const joined = mac.authenticate(&key, "token-a", &.{ "ab", "c" });
    const split = mac.authenticate(&key, "token-a", &.{ "a", "bc" });
    const other_domain = mac.authenticate(&key, "token-b", &.{ "ab", "c" });
    try std.testing.expect(!std.mem.eql(u8, &joined, &split));
    try std.testing.expect(!std.mem.eql(u8, &joined, &other_domain));
    try std.testing.expect(mac.verify(joined, joined));
    var tampered = joined;
    tampered[0] ^= 1;
    try std.testing.expect(!mac.verify(joined, tampered));
}
