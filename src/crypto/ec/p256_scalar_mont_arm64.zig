//! ARM64 Montgomery arithmetic modulo the P-256 scalar order.
//!
//! The AWS-LC (BoringSSL) nistz256 order kernels operate on the same
//! R = 2^256 Montgomery representation as the Zig scalar helpers, so they are
//! drop-in replacements for the scalar multiply and square.

const std = @import("std");
const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

/// `output = a * b * R^-1 mod n`.
pub inline fn mul(
    output: *[4]u64,
    a: *const [4]u64,
    b: *const [4]u64,
) void {
    vailP256ScalarMontMulArm64(output, a, b);
}

/// `output = a^(2^rep) * R^(1 - 2^rep) mod n`; `rep` must be at least one.
pub inline fn sqr(
    output: *[4]u64,
    a: *const [4]u64,
    rep: u64,
) void {
    std.debug.assert(rep >= 1);
    vailP256ScalarMontSqrArm64(output, a, rep);
}

extern fn vailP256ScalarMontMulArm64(
    output: *[4]u64,
    a: *const [4]u64,
    b: *const [4]u64,
) callconv(.c) void;

extern fn vailP256ScalarMontSqrArm64(
    output: *[4]u64,
    a: *const [4]u64,
    rep: u64,
) callconv(.c) void;

const asm_source = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("p256_scalar_mont_arm64.S")) else "";

comptime {
    if (enabled and !asm_compat.external) asm (asm_source);
}
