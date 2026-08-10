//! Optional cryptographic backend metadata.
//!
//! Vail's protocol APIs default to audited Zig implementations.  Builds may
//! point at an AWS-LC checkout with `-Daws-lc-path=...`; when libraries are
//! available, `-Daws-lc-link=true` also links libcrypto.  The local checkout at
//! `~/Work/aws-lc` currently disables SM2/SM3/SM4, so ShangMi primitives remain
//! provided by Vail's Zig modules until an AWS-LC provider is available.

const std = @import("std");
const options = @import("vail_build_options");
const c = @import("aws_lc_c");

pub const Backend = enum {
    pure_zig,
    aws_lc,
};

pub const selected: Backend = if (options.aws_lc_path != null)
    .aws_lc
else
    .pure_zig;

pub const aws_lc_path: ?[]const u8 = options.aws_lc_path;
pub const aws_lc_linked: bool = options.aws_lc_link;
pub const aws_lc_shangmi_available: bool = options.aws_lc_sm_available;

pub const ShangMiProvider = enum {
    vail_zig,
    aws_lc,
};

pub const shangmi_provider: ShangMiProvider = if (aws_lc_shangmi_available)
    .aws_lc
else
    .vail_zig;

pub fn isAwsLcConfigured() bool {
    return selected == .aws_lc;
}

/// Hash with AWS-LC libcrypto when the caller explicitly requested linking.
/// Returns null for metadata-only `-Daws-lc-path` builds so downstream code can
/// probe capability without accidentally requiring libcrypto symbols.
pub fn sha256AwsLc(bytes: []const u8) ?[32]u8 {
    if (!aws_lc_linked) return null;
    var out: [32]u8 = undefined;
    const result = c.SHA256(bytes.ptr, bytes.len, &out);
    if (result == null) return null;
    return out;
}

test "backend metadata is internally consistent" {
    if (aws_lc_path == null) {
        try @import("std").testing.expectEqual(Backend.pure_zig, selected);
        try @import("std").testing.expect(!aws_lc_linked);
    } else {
        try @import("std").testing.expectEqual(Backend.aws_lc, selected);
    }
    if (!aws_lc_shangmi_available) {
        try @import("std").testing.expectEqual(
            ShangMiProvider.vail_zig,
            shangmi_provider,
        );
    }
}

test "AWS-LC linked SHA-256 smoke matches Zig SHA-256" {
    const digest = sha256AwsLc("vail aws-lc smoke") orelse {
        try std.testing.expect(!aws_lc_linked);
        return;
    };
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("vail aws-lc smoke", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}
