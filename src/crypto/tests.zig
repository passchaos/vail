const std = @import("std");
const mac = @import("mac.zig");
const memory = @import("memory.zig");
const sha256 = @import("hash/sha256.zig");

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

test "secure memory and SHA256 helpers preserve fixed-size contracts" {
    const digest = sha256.hash("vail");
    try std.testing.expect(sha256.eql(digest, digest));
    var wrong = digest;
    wrong[0] ^= 1;
    try std.testing.expect(!sha256.eql(digest, wrong));

    var secret = [_]u8{0x42} ** 32;
    memory.zeroValue(&secret);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &secret);
}
