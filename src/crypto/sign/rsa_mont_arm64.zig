//! ARM64 Montgomery multiplication for RSA-sized operands.
//!
//! The AWS-LC (OpenSSL `armv8-mont.pl`) `bn_mul_mont` kernel accepts any limb
//! count and dispatches to dedicated eight-way squaring and four-way
//! multiplication paths.

const std = @import("std");
const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

/// `rp = ap * bp * R^-1 mod np` with `R = 2^(64 * rp.len)`.
pub fn mul(
    rp: []u64,
    ap: []const u64,
    bp: []const u64,
    np: []const u64,
    n0: *const u64,
) void {
    std.debug.assert(rp.len == ap.len);
    std.debug.assert(rp.len == bp.len);
    std.debug.assert(rp.len == np.len);
    const success = vailBnMulMontArm64(
        rp.ptr,
        ap.ptr,
        bp.ptr,
        np.ptr,
        n0,
        rp.len,
    );
    std.debug.assert(success == 1);
}

/// `rp = ap^2 * R^-1 mod np` with `R = 2^(64 * rp.len)`.
pub fn square(
    rp: []u64,
    ap: []const u64,
    np: []const u64,
    n0: *const u64,
) void {
    std.debug.assert(rp.len == ap.len);
    std.debug.assert(rp.len == np.len);
    const success = vailBnMulMontArm64(
        rp.ptr,
        ap.ptr,
        ap.ptr,
        np.ptr,
        n0,
        rp.len,
    );
    std.debug.assert(success == 1);
}

extern fn vailBnMulMontArm64(
    rp: [*]u64,
    ap: [*]const u64,
    bp: [*]const u64,
    np: [*]const u64,
    n0: *const u64,
    num: usize,
) callconv(.c) c_int;

const asm_source = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("armv8_mont_arm64.S")) else "";

comptime {
    if (enabled and !asm_compat.external) asm (asm_source);
}
