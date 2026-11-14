//! ARM64 ML-KEM polynomial kernels.
//!
//! These kernels operate on the standard-order `int16_t[256]` representation
//! shared with the portable implementation. The forward and inverse NTT, the
//! pointwise multiply-accumulate, and the serialization/reduction helpers come
//! from mlkem-native (imported by AWS-LC) and follow the FIPS 203 arithmetic.

const builtin = @import("builtin");
const zetas = @import("mlkem/zetas_arm64.zig");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

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

comptime {
    if (enabled) {
        asm (@embedFile("mlkem/poly_reduce_arm64.S"));
        asm (@embedFile("mlkem/poly_tomont_arm64.S"));
        asm (@embedFile("mlkem/poly_tobytes_arm64.S"));
        asm (@embedFile("mlkem/ntt_arm64.S"));
        asm (@embedFile("mlkem/intt_arm64.S"));
        asm (@embedFile("mlkem/poly_mulcache_compute_arm64.S"));
        asm (@embedFile("mlkem/polyvec_basemul_acc_montgomery_cached_k2_arm64.S"));
        asm (@embedFile("mlkem/polyvec_basemul_acc_montgomery_cached_k3_arm64.S"));
        asm (@embedFile("mlkem/polyvec_basemul_acc_montgomery_cached_k4_arm64.S"));
    }
}
