//! Formally verified ARM64 P-256 Montgomery field arithmetic.
//!
//! The embedded kernels come from s2n-bignum and operate on the same
//! four-limb little-endian Montgomery representation used by `p256.zig`.
//! Source snapshot: awslabs/s2n-bignum
//! 4d1356a7470663c752660a59375dc3a9ef548428.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub inline fn mul(
    output: *[4]u64,
    left: *const [4]u64,
    right: *const [4]u64,
) void {
    if (comptime !enabled) {
        @compileError("ARM64 P-256 Montgomery multiplication is unavailable");
    }
    vailP256MontgomeryMulArm64(output, left, right);
}

pub inline fn square(output: *[4]u64, value: *const [4]u64) void {
    if (comptime !enabled) {
        @compileError("ARM64 P-256 Montgomery squaring is unavailable");
    }
    vailP256MontgomerySquareArm64(output, value);
}

extern fn vailP256MontgomeryMulArm64(
    output: *[4]u64,
    left: *const [4]u64,
    right: *const [4]u64,
) callconv(.c) void;

extern fn vailP256MontgomerySquareArm64(
    output: *[4]u64,
    value: *const [4]u64,
) callconv(.c) void;

comptime {
    if (enabled) asm (@embedFile("p256_field_arm64.S"));
}
