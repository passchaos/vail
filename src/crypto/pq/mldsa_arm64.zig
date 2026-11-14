//! ARM64 ML-DSA arithmetic embedded in Zig.
//
// The instruction schedules and constant tables come from the formally
// verified mldsa-native AArch64 backend, which is imported by AWS-LC.
//
// Copyright (c) The mldsa-native project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

const std = @import("std");
const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");
const tables = @import("mldsa/tables_arm64.zig");

pub const enabled = asm_compat.arm64_native and
    builtin.mode != .Debug;

/// The AArch64 NTT emits the standard coefficient order directly.
pub const uses_custom_order = false;

extern fn vailMldsaNttArm64(
    data: *align(32) [256]i32,
    zetas123456: *align(32) const [144]i32,
    zetas78: *align(32) const [384]i32,
) callconv(.c) void;
extern fn vailMldsaInvNttArm64(
    data: *align(32) [256]i32,
    zetas78: *align(32) const [384]i32,
    zetas123456: *align(32) const [160]i32,
) callconv(.c) void;
extern fn vailMldsaPointwiseArm64(
    left_and_output: *align(32) [256]i32,
    right: *align(32) const [256]i32,
) callconv(.c) void;
extern fn vailMldsaPointwiseAccL4Arm64(
    output: *align(32) [256]i32,
    left: *align(32) const [4][256]i32,
    right: *align(32) const [4][256]i32,
) callconv(.c) void;
extern fn vailMldsaPointwiseAccL5Arm64(
    output: *align(32) [256]i32,
    left: *align(32) const [5][256]i32,
    right: *align(32) const [5][256]i32,
) callconv(.c) void;
extern fn vailMldsaPointwiseAccL7Arm64(
    output: *align(32) [256]i32,
    left: *align(32) const [7][256]i32,
    right: *align(32) const [7][256]i32,
) callconv(.c) void;
extern fn vailMldsaRejectUniformArm64(
    output: *[256]i32,
    input: *const [840]u8,
    input_len: usize,
    table: *align(32) const [256]u8,
) callconv(.c) u64;
extern fn vailMldsaUseHint88Arm64(
    data: *align(32) [256]i32,
    hint: *align(32) const [256]i32,
) callconv(.c) void;
extern fn vailMldsaUseHint32Arm64(
    data: *align(32) [256]i32,
    hint: *align(32) const [256]i32,
) callconv(.c) void;
extern fn vailMldsaUnpackZ17Arm64(
    output: *align(32) [256]i32,
    input: *const [576]u8,
    indices: *align(32) const [64]u8,
) callconv(.c) void;
extern fn vailMldsaUnpackZ19Arm64(
    output: *align(32) [256]i32,
    input: *const [640]u8,
    indices: *align(32) const [64]u8,
) callconv(.c) void;
extern fn vailMldsaCheckNormArm64(
    data: *align(32) const [256]i32,
    bound: i32,
) callconv(.c) c_int;
extern fn vailMldsaDecompose88Arm64(
    high: *align(32) [256]i32,
    low: *align(32) [256]i32,
) callconv(.c) void;
extern fn vailMldsaRejectEta2Arm64(
    output: *[256]i32,
    input: *const [136]u8,
    input_len: usize,
    table: *align(32) const [4096]u8,
) callconv(.c) u64;
extern fn vailMldsaRejectEta4Arm64(
    output: [*]i32,
    input: *const [272]u8,
    input_len: usize,
    table: *align(32) const [4096]u8,
) callconv(.c) u64;

pub fn ntt(data: *align(32) [256]i32) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA NTT is unavailable");
    vailMldsaNttArm64(
        data,
        &tables.ntt_zetas_layer123456,
        &tables.ntt_zetas_layer78,
    );
}

pub fn invNtt(data: *align(32) [256]i32) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA inverse NTT is unavailable");
    vailMldsaInvNttArm64(
        data,
        &tables.intt_zetas_layer78,
        &tables.intt_zetas_layer123456,
    );
}

pub fn pointwise(
    left_and_output: *align(32) [256]i32,
    right: *align(32) const [256]i32,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA pointwise multiply is unavailable");
    vailMldsaPointwiseArm64(left_and_output, right);
}

pub fn dotHatL4(
    output: *align(32) [256]i32,
    left: *align(32) const [4][256]i32,
    right: *align(32) const [4][256]i32,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA L=4 dot product is unavailable");
    vailMldsaPointwiseAccL4Arm64(output, left, right);
}

pub fn dotHatL5(
    output: *align(32) [256]i32,
    left: *align(32) const [5][256]i32,
    right: *align(32) const [5][256]i32,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA L=5 dot product is unavailable");
    vailMldsaPointwiseAccL5Arm64(output, left, right);
}

pub fn dotHatL7(
    output: *align(32) [256]i32,
    left: *align(32) const [7][256]i32,
    right: *align(32) const [7][256]i32,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA L=7 dot product is unavailable");
    vailMldsaPointwiseAccL7Arm64(output, left, right);
}

pub fn rejectUniform(
    output: *[256]u32,
    input: *const [840]u8,
) usize {
    if (comptime !enabled) @compileError("ARM64 ML-DSA rejection sampling is unavailable");
    std.debug.assert(840 % 24 == 0);
    return @intCast(vailMldsaRejectUniformArm64(
        @ptrCast(output),
        input,
        input.len,
        &tables.rej_uniform_table,
    ));
}

/// The AArch64 NTT already emits the standard coefficient order shared with
/// the portable implementation, so no AVX2-style permutation is required.
pub fn toCustomOrder(data: *align(32) [256]u32) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA NTT permutation is unavailable");
    _ = data;
}

pub fn useHint88(
    data: *align(32) [256]u32,
    hint: *align(32) const [256]u32,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA use-hint is unavailable");
    vailMldsaUseHint88Arm64(@ptrCast(data), @ptrCast(hint));
}

pub fn useHint32(
    data: *align(32) [256]u32,
    hint: *align(32) const [256]u32,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA use-hint is unavailable");
    vailMldsaUseHint32Arm64(@ptrCast(data), @ptrCast(hint));
}

pub fn unpackZ17(
    output: *align(32) [256]u32,
    input: *const [576]u8,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA z unpacking is unavailable");
    vailMldsaUnpackZ17Arm64(
        @ptrCast(output),
        input,
        &tables.polyz_unpack_17_indices,
    );
}

pub fn unpackZ19(
    output: *align(32) [256]u32,
    input: *const [640]u8,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA z unpacking is unavailable");
    vailMldsaUnpackZ19Arm64(
        @ptrCast(output),
        input,
        &tables.polyz_unpack_19_indices,
    );
}

pub fn exceeds(data: *align(32) const [256]u32, bound: i32) bool {
    if (comptime !enabled) @compileError("ARM64 ML-DSA norm check is unavailable");
    return vailMldsaCheckNormArm64(@ptrCast(data), bound) != 0;
}

pub fn decompose88(
    high: *align(32) [256]u32,
    low: *align(32) [256]u32,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-DSA decomposition is unavailable");
    vailMldsaDecompose88Arm64(@ptrCast(high), @ptrCast(low));
}

pub fn rejectEta2(output: *[256]u32, input: *const [136]u8) usize {
    if (comptime !enabled) @compileError("ARM64 ML-DSA eta=2 sampling is unavailable");
    std.debug.assert(136 % 8 == 0);
    return @intCast(vailMldsaRejectEta2Arm64(
        @ptrCast(output),
        input,
        input.len,
        &tables.rej_uniform_eta_table,
    ));
}

pub fn rejectEta4(
    output: [*]u32,
    input: *const [272]u8,
    capacity: usize,
) usize {
    if (comptime !enabled) @compileError("ARM64 ML-DSA eta=4 sampling is unavailable");
    std.debug.assert(capacity <= 256);
    if (capacity == 256) {
        return @intCast(vailMldsaRejectEta4Arm64(
            @ptrCast(output),
            input,
            input.len,
            &tables.rej_uniform_eta_table,
        ));
    }
    // The AArch64 kernel always fills up to 256 coefficients; truncate when a
    // caller asks for a smaller window.
    var temp: [256]i32 align(32) = undefined;
    const count: usize = @intCast(vailMldsaRejectEta4Arm64(
        &temp,
        input,
        input.len,
        &tables.rej_uniform_eta_table,
    ));
    const bounded = @min(count, capacity);
    for (0..bounded) |i| output[i] = @bitCast(temp[i]);
    return bounded;
}

const ntt_asm = asm_compat.slice(@embedFile("mldsa/ntt_arm64.S"));
const intt_asm = asm_compat.slice(@embedFile("mldsa/intt_arm64.S"));
const pointwise_asm = asm_compat.slice(@embedFile("mldsa/pointwise_arm64.S"));
const pointwise_l4_asm = asm_compat.slice(@embedFile("mldsa/pointwise_acc_l4_arm64.S"));
const pointwise_l5_asm = asm_compat.slice(@embedFile("mldsa/pointwise_acc_l5_arm64.S"));
const pointwise_l7_asm = asm_compat.slice(@embedFile("mldsa/pointwise_acc_l7_arm64.S"));
const rej_uniform_asm = asm_compat.slice(@embedFile("mldsa/rej_uniform_arm64.S"));
const rej_uniform_eta2_asm = asm_compat.slice(@embedFile("mldsa/rej_uniform_eta2_arm64.S"));
const rej_uniform_eta4_asm = asm_compat.slice(@embedFile("mldsa/rej_uniform_eta4_arm64.S"));
const caddq_asm = asm_compat.slice(@embedFile("mldsa/caddq_arm64.S"));
const chknorm_asm = asm_compat.slice(@embedFile("mldsa/chknorm_arm64.S"));
const decompose_32_asm = asm_compat.slice(@embedFile("mldsa/decompose_32_arm64.S"));
const decompose_88_asm = asm_compat.slice(@embedFile("mldsa/decompose_88_arm64.S"));
const use_hint_32_asm = asm_compat.slice(@embedFile("mldsa/use_hint_32_arm64.S"));
const use_hint_88_asm = asm_compat.slice(@embedFile("mldsa/use_hint_88_arm64.S"));
const unpack_z17_asm = asm_compat.slice(@embedFile("mldsa/unpack_z17_arm64.S"));
const unpack_z19_asm = asm_compat.slice(@embedFile("mldsa/unpack_z19_arm64.S"));

comptime {
    if (enabled) {
        asm (ntt_asm);
        asm (intt_asm);
        asm (pointwise_asm);
        asm (pointwise_l4_asm);
        asm (pointwise_l5_asm);
        asm (pointwise_l7_asm);
        asm (rej_uniform_asm);
        asm (rej_uniform_eta2_asm);
        asm (rej_uniform_eta4_asm);
        asm (caddq_asm);
        asm (chknorm_asm);
        asm (decompose_32_asm);
        asm (decompose_88_asm);
        asm (use_hint_32_asm);
        asm (use_hint_88_asm);
        asm (unpack_z17_asm);
        asm (unpack_z19_asm);
    }
}
