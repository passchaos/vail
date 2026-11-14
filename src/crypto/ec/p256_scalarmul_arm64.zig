//! ARM64 P-256 Montgomery-Jacobian scalar multiplication from s2n-bignum.
//!
//! The kernel is constant-time in the scalar: it scans the whole window
//! table and selects entries with masks.

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = builtin.object_format == .macho and
    builtin.cpu.arch == .aarch64 and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn scalarMult(
    output: *[12]u64,
    scalar: *const [4]u64,
    point: *const [12]u64,
) void {
    vailP256MontJacobianScalarMulAltArm64(output, scalar, point);
}

extern fn vailP256MontJacobianScalarMulAltArm64(
    output: *[12]u64,
    scalar: *const [4]u64,
    point: *const [12]u64,
) callconv(.c) void;
