//! Variable-time ARM64 inversion modulo the P-256 scalar order.
//!
//! The embedded public-input BEEU schedule comes from the audited BoringSSL
//! snapshot used by tquic. Inputs and output are canonical four-limb
//! little-endian integers, not Montgomery values.
//! Source snapshot: BoringSSL
//! 7eab8046db664ee9cd7b090df9d1e5f67352a089.
// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: ISC

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub inline fn invert(
    input: *const [4]u64,
    modulus: *const [4]u64,
) [4]u64 {
    if (comptime !enabled) {
        @compileError("ARM64 public P-256 scalar inversion is unavailable");
    }
    var output: [4]u64 = undefined;
    const success = vailP256ScalarInvertPublicArm64(
        &output,
        input,
        modulus,
    );
    std.debug.assert(success == 1);
    return output;
}

extern fn vailP256ScalarInvertPublicArm64(
    output: *[4]u64,
    input: *const [4]u64,
    modulus: *const [4]u64,
) callconv(.c) c_int;

comptime {
    if (enabled) asm (@embedFile("p256_scalar_inv_arm64.S"));
}
