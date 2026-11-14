//! ARM64 ML-KEM polynomial kernels.
//!
//! These kernels operate on the standard-order `int16_t[256]` representation
//! shared with the portable implementation. The forward and inverse NTT, the
//! pointwise multiply-accumulate, and the serialization/reduction helpers come
//! from mlkem-native (imported by AWS-LC) and follow the FIPS 203 arithmetic.

const std = @import("std");
const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");
const zetas = @import("mlkem/zetas_arm64.zig");
const rej_uniform_table = @import("mlkem/rej_uniform_table_arm64.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

/// Rejection sampling of the public matrix uses the same AArch64 gating as the
/// arithmetic kernels and needs no extra CPU features.
pub const rejection_enabled = enabled;

const q: i16 = 3329;

pub const DotHatK2Cache = [2 * 128]i16;
pub const DotHatK3Cache = [3 * 128]i16;
pub const DotHatK4Cache = [4 * 128]i16;

pub fn barrettReduce(data: *align(32) [256]i16) void {
    if (comptime !enabled) {
        @compileError("ARM64 ML-KEM Barrett reduction is unavailable");
    }
    vailMlKemReduceArm64(data);
}

pub fn normalize(data: *align(32) [256]i16) void {
    if (comptime !enabled) {
        @compileError("ARM64 ML-KEM normalization is unavailable");
    }
    vailMlKemReduceArm64(data);
    for (data) |*coefficient| {
        var value = coefficient.* -% q;
        value +%= (value >> 15) & q;
        coefficient.* = value;
    }
}

pub fn toMont(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("ARM64 ML-KEM toMont is unavailable");
    vailMlKemToMontArm64(data);
}

pub fn toBytes(
    output: *[384]u8,
    input: *align(32) const [256]i16,
) void {
    if (comptime !enabled) {
        @compileError("ARM64 ML-KEM serialization is unavailable");
    }
    vailMlKemToBytesArm64(output, input);
}

pub fn ntt(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("ARM64 ML-KEM NTT is unavailable");
    vailMlKemNttArm64(data, &zetas.ntt_zetas_layer12345, &zetas.ntt_zetas_layer67);
    // mlkem-native leaves the NTT output lazily reduced (up to 8q); reduce it
    // to [0, q) so that the postconditions of the portable implementation and
    // the pointwise-multiplication bounds continue to hold.
    vailMlKemReduceArm64(data);
}

pub fn invNtt(data: *align(32) [256]i16) void {
    if (comptime !enabled) {
        @compileError("ARM64 ML-KEM inverse NTT is unavailable");
    }
    vailMlKemInttArm64(
        data,
        &zetas.invntt_zetas_layer12345,
        &zetas.invntt_zetas_layer67,
    );
    // The inverse NTT leaves coefficients bounded by 8q; reduce to [0, q) to
    // match the portable postcondition.
    vailMlKemReduceArm64(data);
}

pub fn rejectUniform(output: *align(32) [256]i16, input: []const u8) usize {
    if (comptime !rejection_enabled) {
        @compileError("ARM64 ML-KEM rejection sampling is unavailable");
    }
    std.debug.assert(input.len % 24 == 0);
    return vailMlKemRejUniformArm64(
        output,
        input.ptr,
        input.len,
        &rej_uniform_table.table,
    );
}

pub fn mulCache(cache: *align(32) [128]i16, poly: *align(32) const [256]i16) void {
    if (comptime !enabled) {
        @compileError("ARM64 ML-KEM multiplication cache is unavailable");
    }
    vailMlKemMulCacheArm64(
        cache,
        poly,
        &zetas.zetas_mulcache_native,
        &zetas.zetas_mulcache_twisted_native,
    );
}

pub fn basemulK2(
    output: *align(32) [256]i16,
    a: *align(32) const [512]i16,
    b: *align(32) const [512]i16,
    cache: *align(32) const [256]i16,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-KEM basemul k=2 is unavailable");
    vailMlKemBasemulK2Arm64(output, a, b, cache);
}

pub fn basemulK3(
    output: *align(32) [256]i16,
    a: *align(32) const [768]i16,
    b: *align(32) const [768]i16,
    cache: *align(32) const [384]i16,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-KEM basemul k=3 is unavailable");
    vailMlKemBasemulK3Arm64(output, a, b, cache);
}

pub fn basemulK4(
    output: *align(32) [256]i16,
    a: *align(32) const [1024]i16,
    b: *align(32) const [1024]i16,
    cache: *align(32) const [512]i16,
) void {
    if (comptime !enabled) @compileError("ARM64 ML-KEM basemul k=4 is unavailable");
    vailMlKemBasemulK4Arm64(output, a, b, cache);
}

extern fn vailMlKemReduceArm64(data: *align(32) [256]i16) callconv(.c) void;

extern fn vailMlKemToMontArm64(data: *align(32) [256]i16) callconv(.c) void;

extern fn vailMlKemToBytesArm64(
    output: *[384]u8,
    input: *align(32) const [256]i16,
) callconv(.c) void;

extern fn vailMlKemNttArm64(
    data: *align(32) [256]i16,
    twiddles12345: *const [80]i16,
    twiddles56: *const [384]i16,
) callconv(.c) void;

extern fn vailMlKemInttArm64(
    data: *align(32) [256]i16,
    twiddles12345: *const [80]i16,
    twiddles56: *const [384]i16,
) callconv(.c) void;

extern fn vailMlKemRejUniformArm64(
    output: *align(32) [256]i16,
    input: [*]const u8,
    input_len: usize,
    table: *const [4096]u8,
) callconv(.c) usize;

extern fn vailMlKemMulCacheArm64(
    cache: *align(32) [128]i16,
    poly: *align(32) const [256]i16,
    zetas_native: *const [128]i16,
    zetas_twisted: *const [128]i16,
) callconv(.c) void;

extern fn vailMlKemBasemulK2Arm64(
    output: *align(32) [256]i16,
    a: *align(32) const [512]i16,
    b: *align(32) const [512]i16,
    cache: *align(32) const [256]i16,
) callconv(.c) void;

extern fn vailMlKemBasemulK3Arm64(
    output: *align(32) [256]i16,
    a: *align(32) const [768]i16,
    b: *align(32) const [768]i16,
    cache: *align(32) const [384]i16,
) callconv(.c) void;

extern fn vailMlKemBasemulK4Arm64(
    output: *align(32) [256]i16,
    a: *align(32) const [1024]i16,
    b: *align(32) const [1024]i16,
    cache: *align(32) const [512]i16,
) callconv(.c) void;

const poly_reduce_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/poly_reduce_arm64.S")) else "";
const poly_tomont_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/poly_tomont_arm64.S")) else "";
const poly_tobytes_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/poly_tobytes_arm64.S")) else "";
const rej_uniform_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/rej_uniform_arm64.S")) else "";
const ntt_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/ntt_arm64.S")) else "";
const intt_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/intt_arm64.S")) else "";
const mulcache_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/poly_mulcache_compute_arm64.S")) else "";
const basemul_k2_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/polyvec_basemul_acc_montgomery_cached_k2_arm64.S")) else "";
const basemul_k3_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/polyvec_basemul_acc_montgomery_cached_k3_arm64.S")) else "";
const basemul_k4_asm = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("mlkem/polyvec_basemul_acc_montgomery_cached_k4_arm64.S")) else "";

comptime {
    if (enabled and !asm_compat.external) {
        asm (poly_reduce_asm);
        asm (poly_tomont_asm);
        asm (poly_tobytes_asm);
        asm (rej_uniform_asm);
        asm (ntt_asm);
        asm (intt_asm);
        asm (mulcache_asm);
        asm (basemul_k2_asm);
        asm (basemul_k3_asm);
        asm (basemul_k4_asm);
    }
}
