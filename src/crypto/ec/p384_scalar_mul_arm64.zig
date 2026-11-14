//! Constant-time ARM64 P-384 Montgomery-Jacobian scalar multiplication.
//!
//! The instruction schedule comes from the formally verified s2n-bignum
//! implementation.

const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
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

comptime {
    if (enabled) asm (@embedFile("p384_scalarmul_arm64.S"));
}
