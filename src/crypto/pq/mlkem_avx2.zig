//! AVX2 ML-KEM polynomial primitives embedded in Zig.
//!
//! The instruction schedules come from the formally verified s2n-bignum
//! ML-KEM backend, derived from the public-domain mlkem-native AVX2 code.
// Copyright (c) 2024 The mlkem-native project authors
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

const std = @import("std");
const builtin = @import("builtin");

pub const compression = @import("mlkem/compression_avx2.zig");

pub const enabled = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
pub const rejection_enabled = enabled and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .popcnt);

pub const DotHatK2Cache = [256]i16;
pub const DotHatK3Cache = [384]i16;
pub const DotHatK4Cache = [512]i16;

pub fn ntt(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM NTT is unavailable");
    vailMlKemNtt(data, &qdata);
}

pub fn invNtt(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM inverse NTT is unavailable");
    vailMlKemInvNtt(data, &qdata);
}

pub fn toNativeOrder(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM permutation is unavailable");
    vailMlKemUnpack(data);
}

pub fn dotHatK3(
    output: *align(32) [256]i16,
    a: *align(32) const [768]i16,
    b: *align(32) const [768]i16,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    var cache: DotHatK3Cache align(32) = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cache));
    initDotHatK3Cache(&cache, b);
    dotHatK3Cached(output, a, b, &cache);
}

pub fn dotHatK2(
    output: *align(32) [256]i16,
    a: *align(32) const [512]i16,
    b: *align(32) const [512]i16,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    var cache: DotHatK2Cache align(32) = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cache));
    initDotHatK2Cache(&cache, b);
    dotHatK2Cached(output, a, b, &cache);
}

pub fn initDotHatK2Cache(
    cache: *align(32) DotHatK2Cache,
    input: *align(32) const [512]i16,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    inline for (0..2) |index| {
        vailMlKemMulCache(
            @ptrCast(cache[index * 128 ..][0..128]),
            @ptrCast(input[index * 256 ..][0..256]),
            &qdata,
        );
    }
}

pub fn dotHatK2Cached(
    output: *align(32) [256]i16,
    a: *align(32) const [512]i16,
    b: *align(32) const [512]i16,
    cache: *align(32) const DotHatK2Cache,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    vailMlKemBaseMulK2(output, a, b, cache);
}

pub fn initDotHatK3Cache(
    cache: *align(32) DotHatK3Cache,
    input: *align(32) const [768]i16,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    inline for (0..3) |index| {
        vailMlKemMulCache(
            @ptrCast(cache[index * 128 ..][0..128]),
            @ptrCast(input[index * 256 ..][0..256]),
            &qdata,
        );
    }
}

pub fn dotHatK3Cached(
    output: *align(32) [256]i16,
    a: *align(32) const [768]i16,
    b: *align(32) const [768]i16,
    cache: *align(32) const DotHatK3Cache,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    vailMlKemBaseMulK3(output, a, b, cache);
}

pub fn dotHatK4(
    output: *align(32) [256]i16,
    a: *align(32) const [1024]i16,
    b: *align(32) const [1024]i16,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    var cache: DotHatK4Cache align(32) = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cache));
    initDotHatK4Cache(&cache, b);
    dotHatK4Cached(output, a, b, &cache);
}

pub fn initDotHatK4Cache(
    cache: *align(32) DotHatK4Cache,
    input: *align(32) const [1024]i16,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    inline for (0..4) |index| {
        vailMlKemMulCache(
            @ptrCast(cache[index * 128 ..][0..128]),
            @ptrCast(input[index * 256 ..][0..256]),
            &qdata,
        );
    }
}

pub fn dotHatK4Cached(
    output: *align(32) [256]i16,
    a: *align(32) const [1024]i16,
    b: *align(32) const [1024]i16,
    cache: *align(32) const DotHatK4Cache,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM base multiplication is unavailable");
    vailMlKemBaseMulK4(output, a, b, cache);
}

pub fn toBytes(
    output: *[384]u8,
    input: *align(32) const [256]i16,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM serialization is unavailable");
    vailMlKemToBytes(output, input);
}

pub fn fromBytes(
    output: *align(32) [256]i16,
    input: *const [384]u8,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM deserialization is unavailable");
    vailMlKemFromBytes(output, input);
}

pub fn rejectUniform(
    output: *align(32) [256]i16,
    input: []const u8,
) usize {
    if (comptime !rejection_enabled) @compileError("SIMD ML-KEM rejection sampling is unavailable");
    std.debug.assert(input.len % 12 == 0);
    return vailMlKemRejectUniform(output, input.ptr, input.len, &rejection_table);
}

pub fn toMont(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM Montgomery conversion is unavailable");
    vailMlKemToMont(data);
}

pub fn normalize(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM normalization is unavailable");
    vailMlKemNormalize(data);
}

pub fn barrettReduce(data: *align(32) [256]i16) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM Barrett reduction is unavailable");
    vailMlKemBarrettReduce(data);
}

pub fn cbdEta2(
    output: *align(32) [256]i16,
    input: *const [128]u8,
) void {
    if (comptime !enabled) @compileError("AVX2 ML-KEM eta=2 sampling is unavailable");
    vailMlKemCbdEta2(output, input);
}

extern fn vailMlKemNtt(data: *align(32) [256]i16, constants: *const [624]i16) callconv(.c) void;
extern fn vailMlKemInvNtt(data: *align(32) [256]i16, constants: *const [624]i16) callconv(.c) void;
extern fn vailMlKemUnpack(data: *align(32) [256]i16) callconv(.c) void;
extern fn vailMlKemMulCache(output: *align(32) [128]i16, input: *align(32) const [256]i16, constants: *const [624]i16) callconv(.c) void;
extern fn vailMlKemBaseMulK2(output: *align(32) [256]i16, a: *align(32) const [512]i16, b: *align(32) const [512]i16, cache: *align(32) const [256]i16) callconv(.c) void;
extern fn vailMlKemBaseMulK3(output: *align(32) [256]i16, a: *align(32) const [768]i16, b: *align(32) const [768]i16, cache: *align(32) const [384]i16) callconv(.c) void;
extern fn vailMlKemBaseMulK4(output: *align(32) [256]i16, a: *align(32) const [1024]i16, b: *align(32) const [1024]i16, cache: *align(32) const [512]i16) callconv(.c) void;
extern fn vailMlKemToBytes(output: *[384]u8, input: *align(32) const [256]i16) callconv(.c) void;
extern fn vailMlKemFromBytes(output: *align(32) [256]i16, input: *const [384]u8) callconv(.c) void;
extern fn vailMlKemRejectUniform(output: *align(32) [256]i16, input: [*]const u8, input_len: usize, table: *align(16) const [4096]u8) callconv(.c) usize;
extern fn vailMlKemToMont(data: *align(32) [256]i16) callconv(.c) void;
extern fn vailMlKemNormalize(data: *align(32) [256]i16) callconv(.c) void;
extern fn vailMlKemBarrettReduce(data: *align(32) [256]i16) callconv(.c) void;
extern fn vailMlKemCbdEta2(output: *align(32) [256]i16, input: *const [128]u8) callconv(.c) void;

fn makeRejectionTable() [4096]u8 {
    @setEvalBranchQuota(5000);
    var table = [_]u8{0xff} ** 4096;
    for (0..256) |mask| {
        var output_index: usize = 0;
        for (0..8) |lane| {
            if (((mask >> @intCast(lane)) & 1) != 0) {
                table[mask * 16 + output_index] = @intCast(2 * lane);
                table[mask * 16 + output_index + 1] = @intCast(2 * lane + 1);
                output_index += 2;
            }
        }
    }
    return table;
}

const rejection_table: [4096]u8 align(16) = makeRejectionTable();

comptime {
    if (enabled) asm (@embedFile("mlkem/core_avx2.S"));
}

const qdata: [624]i16 align(32) = .{
    3854,   3340,   2826,   2312,   1798,   1284,   770,    256,    3854,
    3340,   2826,   2312,   1798,   1284,   770,    256,    7,      0,
    6,      0,      5,      0,      4,      0,      3,      0,      2,
    0,      1,      0,      0,      0,      31498,  31498,  31498,  31498,
    -758,   -758,   -758,   -758,   0,      0,      0,      0,      0,
    0,      0,      0,      14745,  14745,  14745,  14745,  14745,  14745,
    14745,  14745,  14745,  14745,  14745,  14745,  14745,  14745,  14745,
    14745,  -359,   -359,   -359,   -359,   -359,   -359,   -359,   -359,
    -359,   -359,   -359,   -359,   -359,   -359,   -359,   -359,   13525,
    13525,  13525,  13525,  13525,  13525,  13525,  13525,  -12402, -12402,
    -12402, -12402, -12402, -12402, -12402, -12402, 1493,   1493,   1493,
    1493,   1493,   1493,   1493,   1493,   1422,   1422,   1422,   1422,
    1422,   1422,   1422,   1422,   -20907, -20907, -20907, -20907, 27758,
    27758,  27758,  27758,  -3799,  -3799,  -3799,  -3799,  -15690, -15690,
    -15690, -15690, -171,   -171,   -171,   -171,   622,    622,    622,
    622,    1577,   1577,   1577,   1577,   182,    182,    182,    182,
    -5827,  -5827,  17363,  17363,  -26360, -26360, -29057, -29057, 5571,
    5571,   -1102,  -1102,  21438,  21438,  -26242, -26242, 573,    573,
    -1325,  -1325,  264,    264,    383,    383,    -829,   -829,   1458,
    1458,   -1602,  -1602,  -130,   -130,   -5689,  -6516,  1496,   30967,
    -23565, 20179,  20710,  25080,  -12796, 26616,  16064,  -12442, 9134,
    -650,   -25986, 27837,  1223,   652,    -552,   1015,   -1293,  1491,
    -282,   -1544,  516,    -8,     -320,   -666,   -1618,  -1162,  126,
    1469,   -335,   -11477, -32227, 20494,  -27738, 945,    -14883, 6182,
    32010,  10631,  29175,  -28762, -18486, 17560,  -14430, -5276,  -1103,
    555,    -1251,  1550,   422,    177,    -291,   1574,   -246,   1159,
    -777,   -602,   -1590,  -872,   418,    -156,   11182,  13387,  -14233,
    -21655, 13131,  -4587,  23092,  5493,   -32502, 30317,  -18741, 12639,
    20100,  18525,  19529,  -12619, 430,    843,    871,    105,    587,
    -235,   -460,   1653,   778,    -147,   1483,   1119,   644,    349,
    329,    -75,    787,    787,    787,    787,    787,    787,    787,
    787,    787,    787,    787,    787,    787,    787,    787,    787,
    -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,
    -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  28191,  28191,
    28191,  28191,  28191,  28191,  28191,  28191,  -16694, -16694, -16694,
    -16694, -16694, -16694, -16694, -16694, 287,    287,    287,    287,
    287,    287,    287,    287,    202,    202,    202,    202,    202,
    202,    202,    202,    10690,  10690,  10690,  10690,  1358,   1358,
    1358,   1358,   -11202, -11202, -11202, -11202, 31164,  31164,  31164,
    31164,  962,    962,    962,    962,    -1202,  -1202,  -1202,  -1202,
    -1474,  -1474,  -1474,  -1474,  1468,   1468,   1468,   1468,   -28073,
    -28073, 24313,  24313,  -10532, -10532, 8800,   8800,   18426,  18426,
    8859,   8859,   26675,  26675,  -16163, -16163, -681,   -681,   1017,
    1017,   732,    732,    608,    608,    -1542,  -1542,  411,    411,
    -205,   -205,   -1571,  -1571,  19883,  -28250, -15887, -8898,  -28309,
    9075,   -30199, 18249,  13426,  14017,  -29156, -12757, 16832,  4311,
    -24155, -17915, -853,   -90,    -271,   830,    107,    -1421,  -247,
    -951,   -398,   961,    -1508,  -725,   448,    -1065,  677,    -1275,
    -31183, 25435,  -7382,  24391,  -20927, 10946,  24214,  16989,  10335,
    -7934,  -22502, 10906,  31636,  28644,  23998,  -17422, 817,    603,
    1322,   -1465,  -1215,  1218,   -874,   -1187,  -1185,  -1278,  -1510,
    -870,   -108,   996,    958,    1522,   20297,  2146,   15355,  -32384,
    -6280,  -14903, -11044, 14469,  -21498, -20198, 23210,  -17442, -23860,
    -20257, 7756,   23132,  1097,   610,    -1285,  384,    -136,   -1335,
    220,    -1659,  -1530,  794,    -854,   478,    -308,   991,    -1460,
    1628,   -1103,  555,    -1251,  1550,   422,    177,    -291,   1574,
    -246,   1159,   -777,   -602,   -1590,  -872,   418,    -156,   430,
    843,    871,    105,    587,    -235,   -460,   1653,   778,    -147,
    1483,   1119,   644,    349,    329,    -75,    817,    603,    1322,
    -1465,  -1215,  1218,   -874,   -1187,  -1185,  -1278,  -1510,  -870,
    -108,   996,    958,    1522,   1097,   610,    -1285,  384,    -136,
    -1335,  220,    -1659,  -1530,  794,    -854,   478,    -308,   991,
    -1460,  1628,   -335,   -11477, -32227, 20494,  -27738, 945,    -14883,
    6182,   32010,  10631,  29175,  -28762, -18486, 17560,  -14430, -5276,
    11182,  13387,  -14233, -21655, 13131,  -4587,  23092,  5493,   -32502,
    30317,  -18741, 12639,  20100,  18525,  19529,  -12619, -31183, 25435,
    -7382,  24391,  -20927, 10946,  24214,  16989,  10335,  -7934,  -22502,
    10906,  31636,  28644,  23998,  -17422, 20297,  2146,   15355,  -32384,
    -6280,  -14903, -11044, 14469,  -21498, -20198, 23210,  -17442, -23860,
    -20257, 7756,   23132,
};

comptime {
    if (enabled) {
        asm (@embedFile("mlkem/transform_avx2.S"));
        asm (@embedFile("mlkem/pointwise_k2_avx2.S"));
        asm (@embedFile("mlkem/pointwise_k4_avx2.S"));
        asm (@embedFile("mlkem/compression_avx2.S"));
    }
}
