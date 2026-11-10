//! Formally verified ARM64 P-256 Montgomery-Jacobian point operations.
//!
//! The embedded kernels come from s2n-bignum and operate on the same
//! little-endian Montgomery coordinates used by `p256.zig`.
//! Source snapshot: awslabs/s2n-bignum
//! 4d1356a7470663c752660a59375dc3a9ef548428.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub inline fn pointDouble(
    output: *[12]u64,
    point: *const [12]u64,
) void {
    if (comptime !enabled) {
        @compileError("ARM64 P-256 point doubling is unavailable");
    }
    vailP256MontgomeryJacobianDoubleArm64(output, point);
}

pub inline fn pointMixedAdd(
    output: *[12]u64,
    point: *const [12]u64,
    affine: *const [8]u64,
) void {
    if (comptime !enabled) {
        @compileError("ARM64 P-256 mixed point addition is unavailable");
    }
    vailP256MontgomeryJacobianMixedAddArm64(output, point, affine);
}

extern fn vailP256MontgomeryJacobianDoubleArm64(
    output: *[12]u64,
    point: *const [12]u64,
) callconv(.c) void;

extern fn vailP256MontgomeryJacobianMixedAddArm64(
    output: *[12]u64,
    point: *const [12]u64,
    affine: *const [8]u64,
) callconv(.c) void;

comptime {
    if (enabled) {
        asm (@embedFile("p256_point_mixed_add_arm64.S"));
        asm (@embedFile("p256_point_double_arm64.S"));
    }
}
