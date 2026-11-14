//! Public-input P-384 Montgomery-Jacobian point operations.
//!
//! Linux x86_64 BMI2/ADX and Linux AArch64 ReleaseFast/ReleaseSafe builds use
//! formally verified s2n-bignum schedules. Other targets keep the portable
//! formulas in `p384.zig`.

const adx = @import("p384_point_ops_adx.zig");
const arm64 = @import("p384_point_ops_arm64.zig");

pub const enabled = adx.enabled or arm64.enabled;

pub fn pointAdd(
    output: *[18]u64,
    left: *const [18]u64,
    right: *const [18]u64,
) void {
    if (comptime adx.enabled) {
        adx.pointAdd(output, left, right);
    } else {
        arm64.pointAdd(output, left, right);
    }
}

pub fn pointDouble(output: *[18]u64, point: *const [18]u64) void {
    if (comptime adx.enabled) {
        adx.pointDouble(output, point);
    } else {
        arm64.pointDouble(output, point);
    }
}

pub fn pointMixedAdd(
    output: *[18]u64,
    point: *const [18]u64,
    affine: *const [12]u64,
) void {
    if (comptime adx.enabled) {
        adx.pointMixedAdd(output, point, affine);
    } else {
        arm64.pointMixedAdd(output, point, affine);
    }
}
