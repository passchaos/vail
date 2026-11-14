//! Constant-time ARM64 X25519 kernel embedded in Zig.
//!
//! The instruction schedule is derived from the formally verified s2n-bignum
//! Curve25519 implementation (Apache-2.0 OR ISC OR MIT-0). The upstream
//! function is self-contained; this copy additionally clears its 320-byte
//! secret stack and caller-saved general-purpose registers before returning.
//! Source snapshot: AWS-LC as bundled by aws-lc-sys 0.45.0.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub inline fn scalarMultInto(
    output: *[32]u8,
    secret_key: *const [32]u8,
    public_key: *const [32]u8,
) bool {
    if (comptime !enabled) @compileError("ARM64 X25519 is unavailable");
    vailX25519Arm64(output, secret_key, public_key);
    var combined: u8 = 0;
    inline for (output) |byte| combined |= byte;
    return combined != 0;
}

extern fn vailX25519Arm64(
    output: *[32]u8,
    scalar: *const [32]u8,
    point: *const [32]u8,
) callconv(.c) void;

const asm_source = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("x25519_arm64.S")) else "";

comptime {
    if (enabled and !asm_compat.external) asm (asm_source);
}
