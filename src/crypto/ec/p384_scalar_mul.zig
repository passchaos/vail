//! Dispatches P-384 Montgomery-Jacobian scalar multiplication to the active
//! architecture backend.

const x86 = @import("p384_scalar_mul_x86.zig");
const arm64 = @import("p384_scalar_mul_arm64.zig");

pub const enabled = x86.enabled or arm64.enabled;

pub fn scalarMult(
    output: *[18]u64,
    scalar: *const [6]u64,
    point: *const [18]u64,
) void {
    if (comptime x86.enabled) {
        x86.scalarMult(output, scalar, point);
    } else {
        arm64.scalarMult(output, scalar, point);
    }
}
