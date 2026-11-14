//! Constant-time ARM64 P-384 Montgomery-Jacobian scalar multiplication.
//!
//! The instruction schedule comes from the formally verified s2n-bignum
//! implementation.

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn scalarMult(
    output: *[18]u64,
    scalar: *const [6]u64,
    point: *const [18]u64,
) void {
    if (comptime !enabled) {
        @compileError("ARM64 P-384 scalar multiplication is unavailable");
    }
    vailP384JacobianScalarMulArm64(output, scalar, point);
}

extern fn vailP384JacobianScalarMulArm64(
    output: *[18]u64,
    scalar: *const [6]u64,
    point: *const [18]u64,
) callconv(.c) void;

const transformed = asm_compat.arm64(@embedFile("p384_scalarmul_arm64.S"));

comptime {
    if (enabled) asm (transformed.bytes[0..transformed.len]);
}
