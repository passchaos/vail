//! Formally verified ARM64 P-384 Montgomery-Jacobian point operations.
//!
//! The embedded kernels come from s2n-bignum and operate on the same
//! little-endian Montgomery coordinates used by `p384.zig`.
//! Source snapshot: awslabs/s2n-bignum (imported by AWS-LC).
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn pointAdd(
    output: *[18]u64,
    left: *const [18]u64,
    right: *const [18]u64,
) void {
    if (comptime !enabled) @compileError("ARM64 P-384 is unavailable");
    vailP384MontgomeryJacobianAddArm64(output, left, right);
}

pub fn pointDouble(output: *[18]u64, point: *const [18]u64) void {
    if (comptime !enabled) @compileError("ARM64 P-384 is unavailable");
    vailP384MontgomeryJacobianDoubleArm64(output, point);
}

pub fn pointMixedAdd(
    output: *[18]u64,
    point: *const [18]u64,
    affine: *const [12]u64,
) void {
    if (comptime !enabled) @compileError("ARM64 P-384 is unavailable");
    vailP384MontgomeryJacobianMixedAddArm64(output, point, affine);
}

extern fn vailP384MontgomeryJacobianAddArm64(
    output: *[18]u64,
    left: *const [18]u64,
    right: *const [18]u64,
) callconv(.c) void;

extern fn vailP384MontgomeryJacobianDoubleArm64(
    output: *[18]u64,
    point: *const [18]u64,
) callconv(.c) void;

extern fn vailP384MontgomeryJacobianMixedAddArm64(
    output: *[18]u64,
    point: *const [18]u64,
    affine: *const [12]u64,
) callconv(.c) void;

const add = asm_compat.arm64(@embedFile("p384_montjadd_arm64.S"));
const double = asm_compat.arm64(@embedFile("p384_montjdouble_arm64.S"));
const mixed_add = asm_compat.arm64(@embedFile("p384_montjmixadd_arm64.S"));

comptime {
    if (enabled) {
        asm (add.bytes[0..add.len]);
        asm (double.bytes[0..double.len]);
        asm (mixed_add.bytes[0..mixed_add.len]);
    }
}
