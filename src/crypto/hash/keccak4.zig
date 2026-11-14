//! Four-way Keccak-f1600 and fixed-input SHAKE for ML-KEM sampling.

const std = @import("std");
const builtin = @import("builtin");
const arm64 = @import("keccak4_arm64.zig");

const x86_enabled = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

pub const enabled = x86_enabled or arm64.enabled;

pub const shake128_rate = 168;
pub const matrix_input_length = 34;
pub const matrix_output_length = 3 * shake128_rate;
pub const mldsa_matrix_output_length = 5 * shake128_rate;
pub const noise_output_length = 128;
pub const noise_eta3_output_length = 192;
pub const mldsa_mask_input_length = 66;
pub const mldsa_mask_output_length = 5 * 136;
pub const mldsa_eta_input_length = 66;
pub const mldsa_eta_output_length = 2 * 136;

const round_constants = [_]u64{
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
};

const rho8: [4]u64 align(32) = .{
    0x0605040302010007,
    0x0e0d0c0b0a09080f,
    0x1615141312111017,
    0x1e1d1c1b1a19181f,
};
const rho56: [4]u64 align(32) = .{
    0x0007060504030201,
    0x080f0e0d0c0b0a09,
    0x1017161514131211,
    0x181f1e1d1c1b1a19,
};

extern fn vailKeccakF1600x4Alt(
    states: *align(32) [100]u64,
    constants: *const [24]u64,
    rho8_table: *align(32) const [4]u64,
    rho56_table: *align(32) const [4]u64,
) callconv(.c) void;

fn permute4(states: *[4][25]u64) void {
    if (comptime x86_enabled) {
        vailKeccakF1600x4Alt(
            @ptrCast(states),
            &round_constants,
            &rho8,
            &rho56,
        );
    } else {
        arm64.permute(states, &round_constants);
    }
}

comptime {
    if (x86_enabled) asm (@embedFile("keccak4_avx2.S"));
}

/// Expand four 34-byte ML-KEM matrix inputs with SHAKE128 in parallel.
pub fn shake128Matrix(
    inputs: *const [4][matrix_input_length]u8,
) [4][matrix_output_length]u8 {
    return shake128Fixed(matrix_output_length, inputs);
}

/// Expand four 34-byte ML-DSA matrix inputs through five SHAKE128 rate blocks.
pub fn shake128MldsaMatrix(
    inputs: *const [4][matrix_input_length]u8,
) [4][mldsa_matrix_output_length]u8 {
    return shake128Fixed(mldsa_matrix_output_length, inputs);
}

fn shake128Fixed(
    comptime output_length: usize,
    inputs: *const [4][matrix_input_length]u8,
) [4][output_length]u8 {
    if (comptime !enabled) @compileError("four-way fast SHAKE128 is unavailable");
    comptime std.debug.assert(output_length % shake128_rate == 0);
    // These states contain only the public matrix seed and domain bytes.
    var states: [4][25]u64 align(32) = [_][25]u64{[_]u64{0} ** 25} ** 4;
    for (&states, 0..) |*state, lane| {
        inline for (0..4) |word| {
            state[word] = std.mem.readInt(u64, inputs[lane][word * 8 ..][0..8], .little);
        }
        state[4] = @as(u64, inputs[lane][32]) |
            (@as(u64, inputs[lane][33]) << 8) |
            (@as(u64, 0x1f) << 16);
        state[20] = @as(u64, 0x80) << 56;
    }

    var output: [4][output_length]u8 = undefined;
    for (0..output_length / shake128_rate) |block| {
        permute4(&states);
        for (&output, &states) |*bytes, *state| {
            @memcpy(
                bytes[block * shake128_rate ..][0..shake128_rate],
                std.mem.asBytes(state)[0..shake128_rate],
            );
        }
    }
    return output;
}

/// Four independent one-block SHAKE256 calls for ML-KEM eta=2 noise.
pub fn shake256Noise(seed: *const [32]u8, nonce: u8) [4][noise_output_length]u8 {
    return shake256NoiseFixed(noise_output_length, seed, nonce);
}

/// Four independent two-block SHAKE256 calls for ML-KEM eta=3 noise.
pub fn shake256NoiseEta3(
    seed: *const [32]u8,
    nonce: u8,
) [4][noise_eta3_output_length]u8 {
    return shake256NoiseFixed(noise_eta3_output_length, seed, nonce);
}

fn shake256NoiseFixed(
    comptime output_length: usize,
    seed: *const [32]u8,
    nonce: u8,
) [4][output_length]u8 {
    if (comptime !enabled) @compileError("four-way fast SHAKE256 is unavailable");
    const rate = std.crypto.hash.sha3.Shake256.block_length;
    var states: [4][25]u64 align(32) = [_][25]u64{[_]u64{0} ** 25} ** 4;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&states));
    for (&states, 0..) |*state, lane| {
        inline for (0..4) |word| {
            state[word] = std.mem.readInt(u64, seed[word * 8 ..][0..8], .little);
        }
        state[4] = nonce + @as(u8, @intCast(lane)) | (@as(u64, 0x1f) << 8);
        state[16] = @as(u64, 0x80) << 56;
    }
    var output: [4][output_length]u8 = undefined;
    var offset: usize = 0;
    while (offset < output_length) {
        permute4(&states);
        const take = @min(rate, output_length - offset);
        for (&output, &states) |*bytes, *state| {
            @memcpy(bytes[offset..][0..take], std.mem.asBytes(state)[0..take]);
        }
        offset += take;
    }
    return output;
}

/// Expand four 66-byte ML-DSA mask inputs through five SHAKE256 rate blocks.
pub fn shake256MldsaMask(
    inputs: *const [4][mldsa_mask_input_length]u8,
) [4][mldsa_mask_output_length]u8 {
    if (comptime !enabled) @compileError("four-way fast SHAKE256 is unavailable");
    const rate = std.crypto.hash.sha3.Shake256.block_length;
    var states: [4][25]u64 align(32) = [_][25]u64{[_]u64{0} ** 25} ** 4;
    for (&states, 0..) |*state, lane| {
        inline for (0..8) |word| {
            state[word] = std.mem.readInt(
                u64,
                inputs[lane][word * 8 ..][0..8],
                .little,
            );
        }
        state[8] = @as(u64, inputs[lane][64]) |
            (@as(u64, inputs[lane][65]) << 8) |
            (@as(u64, 0x1f) << 16);
        state[16] = @as(u64, 0x80) << 56;
    }

    var output: [4][mldsa_mask_output_length]u8 = undefined;
    for (0..mldsa_mask_output_length / rate) |block| {
        permute4(&states);
        for (&output, &states) |*bytes, *state| {
            @memcpy(
                bytes[block * rate ..][0..rate],
                std.mem.asBytes(state)[0..rate],
            );
        }
    }
    return output;
}

/// Expand four 66-byte ML-DSA eta-sampling inputs through two SHAKE256 blocks.
pub fn shake256MldsaEta(
    inputs: *const [4][mldsa_eta_input_length]u8,
) [4][mldsa_eta_output_length]u8 {
    if (comptime !enabled) @compileError("four-way fast SHAKE256 is unavailable");
    const rate = std.crypto.hash.sha3.Shake256.block_length;
    var states: [4][25]u64 align(32) = [_][25]u64{[_]u64{0} ** 25} ** 4;
    for (&states, 0..) |*state, lane| {
        inline for (0..8) |word| {
            state[word] = std.mem.readInt(
                u64,
                inputs[lane][word * 8 ..][0..8],
                .little,
            );
        }
        state[8] = @as(u64, inputs[lane][64]) |
            (@as(u64, inputs[lane][65]) << 8) |
            (@as(u64, 0x1f) << 16);
        state[16] = @as(u64, 0x80) << 56;
    }

    var output: [4][mldsa_eta_output_length]u8 = undefined;
    for (0..mldsa_eta_output_length / rate) |block| {
        permute4(&states);
        for (&output, &states) |*bytes, *state| {
            @memcpy(
                bytes[block * rate ..][0..rate],
                std.mem.asBytes(state)[0..rate],
            );
        }
    }
    return output;
}

test "four-way SHAKE128 matrix expansion matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    var inputs: [4][matrix_input_length]u8 = undefined;
    for (&inputs, 0..) |*input, lane| {
        for (input, 0..) |*byte, index| byte.* = @truncate(index + lane * 17);
    }
    const actual = shake128Matrix(&inputs);
    for (inputs, 0..) |input, lane| {
        var expected: [matrix_output_length]u8 = undefined;
        std.crypto.hash.sha3.Shake128.hash(&input, &expected, .{});
        try std.testing.expectEqual(expected, actual[lane]);
    }
}

test "four-way SHAKE128 ML-DSA matrix expansion matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    var inputs: [4][matrix_input_length]u8 = undefined;
    for (&inputs, 0..) |*input, lane| {
        for (input, 0..) |*byte, index| byte.* = @truncate(index + lane * 31);
    }
    const actual = shake128MldsaMatrix(&inputs);
    for (inputs, 0..) |input, lane| {
        var expected: [mldsa_matrix_output_length]u8 = undefined;
        std.crypto.hash.sha3.Shake128.hash(&input, &expected, .{});
        try std.testing.expectEqual(expected, actual[lane]);
    }
}

test "four-way SHAKE256 noise expansion matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*byte, index| byte.* = @truncate(index * 29 + 5);
    const nonce = 37;
    const actual = shake256Noise(&seed, nonce);
    for (actual, 0..) |bytes, lane| {
        const input = seed ++ [1]u8{nonce + @as(u8, @intCast(lane))};
        var expected: [noise_output_length]u8 = undefined;
        std.crypto.hash.sha3.Shake256.hash(&input, &expected, .{});
        try std.testing.expectEqual(expected, bytes);
    }
}

test "four-way SHAKE256 eta=3 noise expansion matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*byte, index| byte.* = @truncate(index * 41 + 11);
    const nonce = 29;
    const actual = shake256NoiseEta3(&seed, nonce);
    for (actual, 0..) |bytes, lane| {
        const input = seed ++ [1]u8{nonce + @as(u8, @intCast(lane))};
        var expected: [noise_eta3_output_length]u8 = undefined;
        std.crypto.hash.sha3.Shake256.hash(&input, &expected, .{});
        try std.testing.expectEqual(expected, bytes);
    }
}

test "four-way SHAKE256 ML-DSA mask expansion matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    var inputs: [4][mldsa_mask_input_length]u8 = undefined;
    for (&inputs, 0..) |*input, lane| {
        for (input, 0..) |*byte, index| byte.* = @truncate(index * 43 + lane * 19);
    }
    const actual = shake256MldsaMask(&inputs);
    for (inputs, 0..) |input, lane| {
        var expected: [mldsa_mask_output_length]u8 = undefined;
        std.crypto.hash.sha3.Shake256.hash(&input, &expected, .{});
        try std.testing.expectEqual(expected, actual[lane]);
    }
}

test "four-way SHAKE256 ML-DSA eta expansion matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    var inputs: [4][mldsa_eta_input_length]u8 = undefined;
    for (&inputs, 0..) |*input, lane| {
        for (input, 0..) |*byte, index| byte.* = @truncate(index * 47 + lane * 23);
    }
    const actual = shake256MldsaEta(&inputs);
    for (inputs, 0..) |input, lane| {
        var expected: [mldsa_eta_output_length]u8 = undefined;
        std.crypto.hash.sha3.Shake256.hash(&input, &expected, .{});
        try std.testing.expectEqual(expected, actual[lane]);
    }
}
