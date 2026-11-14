//! Constant-time ARM64 fixed-base X25519 kernel embedded in Zig.
//!
//! The instruction schedule and affine table are derived from the formally
//! verified s2n-bignum Curve25519 implementation (Apache-2.0 OR ISC OR MIT-0).
//! The upstream function is self-contained; this copy additionally clears its
//! 448-byte secret stack and caller-saved general-purpose registers before
//! returning. Source snapshot: AWS-LC as bundled by aws-lc-sys 0.45.0.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub inline fn scalarMultBase(
    secret_key: *const [32]u8,
) [32]u8 {
    if (comptime !enabled) @compileError("ARM64 fixed-base X25519 is unavailable");
    var output: [32]u8 = undefined;
    vailX25519BaseArm64(&output, secret_key);
    return output;
}

extern fn vailX25519BaseArm64(
    output: *[32]u8,
    scalar: *const [32]u8,
) callconv(.c) void;

const asm_source = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("x25519_base_arm64.S")) else "";

comptime {
    if (enabled and !asm_compat.external) asm (asm_source);
}
