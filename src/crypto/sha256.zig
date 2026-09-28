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

test "SHA-256 helper produces a stable digest" {
    var expected: Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "0c1e785d63a51283ffecd0d4b165c41ca1ab9da1d620854f58c79d8058400197",
    );
    try std.testing.expectEqualSlices(u8, &expected, &hash("vail"));
}
