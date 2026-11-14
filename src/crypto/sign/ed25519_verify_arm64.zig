//! Constant-time ARM64 Ed25519 verification kernels from s2n-bignum.
//!
//! The decoded point representation is `(X, Y)`, each four 64-bit limbs in
//! little-endian order. The scalar multiplication computes
//! `scalar * point + bscalar * B`.

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn decode(point: *[8]u64, encoded: *const [32]u8) bool {
    if (comptime !enabled) @compileError("ARM64 Ed25519 verify is unavailable");
    return vailEd25519DecodeArm64(point, encoded) == 0;
}

pub fn negate(output: *[4]u64, input: *const [4]u64) void {
    if (comptime !enabled) @compileError("ARM64 Ed25519 verify is unavailable");
    vailEd25519NegateArm64(output, input);
}

pub fn epdouble(output: *[16]u64, point: *const [12]u64) void {
    if (comptime !enabled) @compileError("ARM64 Ed25519 verify is unavailable");
    vailEd25519EpdoubleArm64(output, point);
}

pub fn scalarMulDouble(
    output: *[8]u64,
    scalar: *const [4]u64,
    point: *const [8]u64,
    bscalar: *const [4]u64,
) void {
    if (comptime !enabled) @compileError("ARM64 Ed25519 verify is unavailable");
    vailEd25519ScalarMulDoubleArm64(output, scalar, point, bscalar);
}

/// Defined by the ARM64 fixed-base module; reused here to avoid duplicating
/// the encoding kernel.
extern fn vailEd25519EncodeArm64(
    output: *[32]u8,
    point: *const [8]u64,
) callconv(.c) void;

pub fn encode(output: *[32]u8, point: *const [8]u64) void {
    if (comptime !enabled) @compileError("ARM64 Ed25519 verify is unavailable");
    vailEd25519EncodeArm64(output, point);
}

extern fn vailEd25519EpdoubleArm64(
    output: *[16]u64,
    point: *const [12]u64,
) callconv(.c) void;

extern fn vailEd25519DecodeArm64(
    point: *[8]u64,
    encoded: *const [32]u8,
) callconv(.c) u64;

extern fn vailEd25519NegateArm64(
    output: *[4]u64,
    input: *const [4]u64,
) callconv(.c) void;

extern fn vailEd25519ScalarMulDoubleArm64(
    output: *[8]u64,
    scalar: *const [4]u64,
    point: *const [8]u64,
    bscalar: *const [4]u64,
) callconv(.c) void;

const verify_asm = asm_compat.slice(@embedFile("ed25519_verify_arm64.S"));
const epdouble_asm = asm_compat.slice(@embedFile("ed25519_epdouble_arm64.S"));

comptime {
    if (enabled) {
        asm (verify_asm);
        asm (epdouble_asm);
    }
}
