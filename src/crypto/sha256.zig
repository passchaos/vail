//! Fixed-length SHA-256 digest and constant-time comparison helpers.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const digest_len = Sha256.digest_length;
pub const Digest = [digest_len]u8;

pub fn hash(bytes: []const u8) Digest {
    var output: Digest = undefined;
    Sha256.hash(bytes, &output, .{});
    return output;
}

pub fn eql(expected: Digest, received: Digest) bool {
    return std.crypto.timing_safe.eql(Digest, expected, received);
}
