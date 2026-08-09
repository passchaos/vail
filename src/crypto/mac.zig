//! Domain-separated HMAC-SHA256 helpers and constant-time tag verification.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const key_len = HmacSha256.key_length;
pub const tag_len = HmacSha256.mac_length;
pub const Key = [key_len]u8;
pub const Tag = [tag_len]u8;

pub fn authenticate(
    key: []const u8,
    domain: []const u8,
    parts: []const []const u8,
) Tag {
    var hmac = HmacSha256.init(key);
    var domain_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &domain_len, @intCast(domain.len), .big);
    hmac.update(&domain_len);
    hmac.update(domain);
    for (parts) |part| {
        var part_len: [8]u8 = undefined;
        std.mem.writeInt(u64, &part_len, part.len, .big);
        hmac.update(&part_len);
        hmac.update(part);
    }
    var tag: Tag = undefined;
    hmac.final(&tag);
    return tag;
}

pub fn verify(expected: Tag, received: Tag) bool {
    return std.crypto.timing_safe.eql(Tag, expected, received);
}

pub fn verifyTruncated(
    comptime len: usize,
    expected: [len]u8,
    received: [len]u8,
) bool {
    return std.crypto.timing_safe.eql([len]u8, expected, received);
}
