//! Type-safe ABI wrapper and constant tables for the formally verified AVX2
//! ML-KEM polynomial compression kernels.
// Copyright (c) 2024 The mlkem-native project authors
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

pub const Coefficients = [256]i16;
pub const D4 = [128]u8;
pub const D5 = [160]u8;
pub const D10 = [320]u8;
pub const D11 = [352]u8;

/// Compresses normalized coefficients in the range [0, 3329).
pub fn compressD4(output: *D4, input: *align(32) const Coefficients) void {
    vailMlKemCompressD4(output, input, &compress_d4_data);
}

pub fn decompressD4(output: *align(32) Coefficients, input: *const D4) void {
    vailMlKemDecompressD4(output, input, &decompress_d4_data);
}

/// Compresses normalized coefficients in the range [0, 3329).
pub fn compressD5(output: *D5, input: *align(32) const Coefficients) void {
    vailMlKemCompressD5(output, input, &compress_d5_data);
}

pub fn decompressD5(output: *align(32) Coefficients, input: *const D5) void {
    vailMlKemDecompressD5(output, input, &decompress_d5_data);
}

/// Compresses normalized coefficients in the range [0, 3329).
pub fn compressD10(output: *D10, input: *align(32) const Coefficients) void {
    vailMlKemCompressD10(output, input, &compress_d10_data);
}

pub fn decompressD10(output: *align(32) Coefficients, input: *const D10) void {
    vailMlKemDecompressD10(output, input, &decompress_d10_data);
}

/// Compresses normalized coefficients in the range [0, 3329).
pub fn compressD11(output: *D11, input: *align(32) const Coefficients) void {
    vailMlKemCompressD11(output, input, &compress_d11_data);
}

pub fn decompressD11(output: *align(32) Coefficients, input: *const D11) void {
    vailMlKemDecompressD11(output, input, &decompress_d11_data);
}

extern fn vailMlKemCompressD4(*D4, *align(32) const Coefficients, *align(32) const [32]u8) callconv(.c) void;
extern fn vailMlKemDecompressD4(*align(32) Coefficients, *const D4, *align(32) const [32]u8) callconv(.c) void;
extern fn vailMlKemCompressD5(*D5, *align(32) const Coefficients, *align(32) const [32]u8) callconv(.c) void;
extern fn vailMlKemDecompressD5(*align(32) Coefficients, *const D5, *align(32) const [96]u8) callconv(.c) void;
extern fn vailMlKemCompressD10(*D10, *align(32) const Coefficients, *align(32) const [32]u8) callconv(.c) void;
extern fn vailMlKemDecompressD10(*align(32) Coefficients, *const D10, *align(32) const [32]u8) callconv(.c) void;
extern fn vailMlKemCompressD11(*D11, *align(32) const Coefficients, *align(32) const [64]u8) callconv(.c) void;
extern fn vailMlKemDecompressD11(*align(32) Coefficients, *const D11, *align(32) const [128]u8) callconv(.c) void;

const compress_d4_data: [32]u8 align(32) = .{
    0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0,
    2, 0, 0, 0, 6, 0, 0, 0, 3, 0, 0, 0, 7, 0, 0, 0,
};

const decompress_d4_data: [32]u8 align(32) = .{
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
};

const compress_d5_data: [32]u8 align(32) = .{
    0, 1,  2,  3,  4,   255, 255, 255, 255, 255, 8,
    9, 10, 11, 12, 255, 9,   10,  11,  12,  255, 0,
    1, 2,  3,  4,  255, 255, 255, 255, 255, 8,
};

// shufbidx[0..32], mask[32..64], shift[64..96]
const decompress_d5_data: [96]u8 align(32) = .{
    0,  0, 0,   1, 1,   1, 1,   2,  2,   3, 3,  3, 3,   4, 4,   4,
    5,  5, 5,   6, 6,   6, 6,   7,  7,   8, 8,  8, 8,   9, 9,   9,
    31, 0, 224, 3, 124, 0, 128, 15, 240, 1, 62, 0, 192, 7, 248, 0,
    31, 0, 224, 3, 124, 0, 128, 15, 240, 1, 62, 0, 192, 7, 248, 0,
    0,  4, 32,  0, 0,   1, 8,   0,  64,  0, 0,  2, 16,  0, 128, 0,
    0,  4, 32,  0, 0,   1, 8,   0,  64,  0, 0,  2, 16,  0, 128, 0,
};

const compress_d10_data: [32]u8 align(32) = .{
    0, 1,  2,  3,  4,   8,   9,   10,  11,  12,  255, 255, 255, 255, 255, 255,
    9, 10, 11, 12, 255, 255, 255, 255, 255, 255, 0,   1,   2,   3,   4,   8,
};

const decompress_d10_data: [32]u8 align(32) = .{
    0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8,  8,  9,
    2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11,
};

// srlvqidx[0..32], shufbidx[32..64]
const compress_d11_data: [64]u8 align(32) = .{
    10, 0, 0, 0, 0, 0,  0,   0,   30,  0,   0,  0,   0,   0,   0,   0,
    10, 0, 0, 0, 0, 0,  0,   0,   30,  0,   0,  0,   0,   0,   0,   0,
    0,  1, 2, 3, 4, 5,  6,   7,   8,   9,   10, 255, 255, 255, 255, 255,
    5,  6, 7, 8, 9, 10, 255, 255, 255, 255, 0,  0,   1,   2,   3,   4,
};

// shufbidx[0..32], srlvdidx[32..64], srlvqidx[64..96], shift[96..128]
const decompress_d11_data: [128]u8 align(32) = .{
    0,  1, 1, 2, 2, 3, 4,  5, 5, 6, 6, 7,  8,  9,  9,  10,
    3,  4, 4, 5, 5, 6, 7,  8, 8, 9, 9, 10, 11, 12, 12, 13,
    0,  0, 0, 0, 1, 0, 0,  0, 0, 0, 0, 0,  0,  0,  0,  0,
    0,  0, 0, 0, 1, 0, 0,  0, 0, 0, 0, 0,  0,  0,  0,  0,
    0,  0, 0, 0, 0, 0, 0,  0, 2, 0, 0, 0,  0,  0,  0,  0,
    0,  0, 0, 0, 0, 0, 0,  0, 2, 0, 0, 0,  0,  0,  0,  0,
    32, 0, 4, 0, 1, 0, 32, 0, 8, 0, 1, 0,  32, 0,  4,  0,
    32, 0, 4, 0, 1, 0, 32, 0, 8, 0, 1, 0,  32, 0,  4,  0,
};
