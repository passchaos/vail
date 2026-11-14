//! ARM64 P-256 fixed-base scalar multiplication from s2n-bignum.
//!
//! The kernel consumes a table of Montgomery-affine multiples of the base
//! point (blocksize 4, 64 blocks, 8 entries per block) and writes the
//! Montgomery-affine result coordinates.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");
const table_values = @import("p256_tables.zig");

pub const enabled = builtin.object_format == .macho and
    builtin.cpu.arch == .aarch64 and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn scalarMultBase(output: *[8]u64, scalar: *const [4]u64) void {
    if (comptime !enabled) {
        @compileError("ARM64 P-256 fixed-base scalar multiplication is unavailable");
    }
    vailP256ScalarMulBaseArm64(
        output,
        scalar,
        4,
        &table_values.base_scalarmul_4,
    );
}

extern fn vailP256ScalarMulBaseArm64(
    result: *[8]u64,
    scalar: *const [4]u64,
    blocksize: u64,
    table: *const [520][8]u64,
) callconv(.c) void;
