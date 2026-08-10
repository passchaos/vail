//! Optional cryptographic backend metadata.
//!
//! Vail's protocol APIs default to audited Zig implementations.  Builds may
//! point at an AWS-LC checkout with `-Daws-lc-path=...`; when libraries are
//! available, `-Daws-lc-link=true` also links libcrypto.  The local checkout at
//! `~/Work/aws-lc` currently disables SM2/SM3/SM4, so ShangMi primitives remain
//! provided by Vail's Zig modules until an AWS-LC provider is available.

const options = @import("vail_build_options");

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
