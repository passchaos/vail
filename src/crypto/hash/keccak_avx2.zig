//! x86_64 AVX2-backed Keccak-f1600 permutation for pure-Zig sponges.

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

const round_constants = [24]u64{
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

extern fn vailKeccakF1600(
    state: *[25]u64,
    constants: *const [24]u64,
) callconv(.c) void;

pub fn permute(state: *[25]u64) void {
    if (comptime !enabled) @compileError("AVX2 Keccak-f1600 is unavailable");
    vailKeccakF1600(state, &round_constants);
}

fn Sponge(
    comptime rate_bytes: usize,
    comptime digest_bytes: usize,
    comptime default_delimiter: u8,
) type {
    return struct {
        const Self = @This();

        pub const block_length = rate_bytes;
        pub const rate = block_length;
        pub const digest_length = digest_bytes;
        pub const Options = struct { delim: u8 = default_delimiter };

        state: [25]u64 = .{0} ** 25,
        buffer: [rate]u8 = undefined,
        offset: usize = 0,
        squeeze_offset: usize = 0,
        finalized: bool = false,

        pub fn init(options: Options) Self {
            if (comptime !enabled) @compileError("AVX2 Keccak sponge is unavailable");
            std.debug.assert(options.delim == default_delimiter);
            return .{};
        }

        pub fn hash(input: []const u8, output: anytype, options: Options) void {
            var state = init(options);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&state));
            state.update(input);
            state.squeeze(output);
        }

        pub fn update(self: *Self, input: []const u8) void {
            std.debug.assert(!self.finalized);
            var remaining = input;
            if (self.offset != 0) {
                const take = @min(rate - self.offset, remaining.len);
                @memcpy(self.buffer[self.offset..][0..take], remaining[0..take]);
                self.offset += take;
                remaining = remaining[take..];
                if (self.offset != rate) return;
                self.absorbBlock(&self.buffer);
                self.offset = 0;
            }
            while (remaining.len >= rate) {
                self.absorbBlock(remaining[0..rate]);
                remaining = remaining[rate..];
            }
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.offset = remaining.len;
        }

        pub fn final(self: *Self, output: *[digest_length]u8) void {
            self.squeeze(output);
        }

        pub fn squeeze(self: *Self, output: []u8) void {
            if (!self.finalized) self.finalizeAbsorb();
            var remaining = output;
            while (remaining.len != 0) {
                if (self.squeeze_offset == rate) {
                    permute(&self.state);
                    self.squeeze_offset = 0;
                }
                const take = @min(rate - self.squeeze_offset, remaining.len);
                @memcpy(
                    remaining[0..take],
                    std.mem.asBytes(&self.state)[self.squeeze_offset..][0..take],
                );
                self.squeeze_offset += take;
                remaining = remaining[take..];
            }
        }

        fn absorbBlock(self: *Self, block: *const [rate]u8) void {
            inline for (0..rate / 8) |index| {
                self.state[index] ^= std.mem.readInt(
                    u64,
                    block[index * 8 ..][0..8],
                    .little,
                );
            }
            permute(&self.state);
        }

        fn finalizeAbsorb(self: *Self) void {
            const state_bytes = std.mem.asBytes(&self.state);
            for (self.buffer[0..self.offset], 0..) |byte, index| {
                state_bytes[index] ^= byte;
            }
            state_bytes[self.offset] ^= default_delimiter;
            state_bytes[rate - 1] ^= 0x80;
            permute(&self.state);
            self.finalized = true;
            self.squeeze_offset = 0;
        }
    };
}

/// Incremental SHAKE128/SHAKE256 and SHA3 hashes backed by the formally
/// verified AVX2 permutation.
pub const Shake128 = Sponge(168, 32, 0x1f);
pub const Shake256 = Sponge(136, 64, 0x1f);
pub const Sha3_256 = Sponge(136, 32, 0x06);
pub const Sha3_512 = Sponge(72, 64, 0x06);

/// Hashes two adjacent slices without requiring their concatenation to be
/// materialized by the caller. Keeping this boundary out of line prevents the
/// sponge state machine from inflating its cryptographic caller.
pub noinline fn shake256Parts(first: []const u8, second: []const u8, output: []u8) void {
    var state = Shake256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&state));
    state.update(first);
    state.update(second);
    state.squeeze(output);
}

pub noinline fn sha3_256(input: []const u8, output: *[32]u8) void {
    Sha3_256.hash(input, output, .{});
}

pub noinline fn sha3_512Parts(first: []const u8, second: []const u8, output: *[64]u8) void {
    var state = Sha3_512.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&state));
    state.update(first);
    state.update(second);
    state.final(output);
}

comptime {
    if (enabled) asm (@embedFile("keccak_avx2.S"));
}

test "AVX2 Keccak-f1600 permutation matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    var expected = std.crypto.core.keccak.KeccakF(1600){};
    for (&expected.st, 0..) |*word, index| {
        word.* = @as(u64, index) *% 0x9e3779b97f4a7c15;
    }
    var actual = expected.st;
    expected.permute();
    permute(&actual);
    try std.testing.expectEqual(expected.st, actual);
}

test "AVX2 SHAKE256 matches Zig std across absorb and squeeze boundaries" {
    if (comptime !enabled) return error.SkipZigTest;

    var input: [333]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index * 29 + 7);

    inline for (.{ 0, 1, 32, 64, 135, 136, 137, 271, 272, 273, 333 }) |input_length| {
        inline for (.{ 1, 32, 135, 136, 137, 272, 400 }) |output_length| {
            var expected: [400]u8 = undefined;
            std.crypto.hash.sha3.Shake256.hash(
                input[0..input_length],
                expected[0..output_length],
                .{},
            );

            var actual: [400]u8 = undefined;
            var state = Shake256.init(.{});
            defer std.crypto.secureZero(u8, std.mem.asBytes(&state));
            const first = input_length / 3;
            const second = 2 * input_length / 3;
            state.update(input[0..first]);
            state.update(input[first..second]);
            state.update(input[second..input_length]);
            const output_split = output_length / 2;
            state.squeeze(actual[0..output_split]);
            state.squeeze(actual[output_split..output_length]);

            try std.testing.expectEqualSlices(
                u8,
                expected[0..output_length],
                actual[0..output_length],
            );

            var actual_parts: [400]u8 = undefined;
            shake256Parts(
                input[0..first],
                input[first..input_length],
                actual_parts[0..output_length],
            );
            try std.testing.expectEqualSlices(
                u8,
                expected[0..output_length],
                actual_parts[0..output_length],
            );
        }
    }
}

test "AVX2 SHAKE128 matches Zig std across absorb and squeeze boundaries" {
    if (comptime !enabled) return error.SkipZigTest;

    var input: [333]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index * 43 + 11);

    inline for (.{ 0, 1, 32, 64, 167, 168, 169, 333 }) |input_length| {
        var expected: [400]u8 = undefined;
        std.crypto.hash.sha3.Shake128.hash(input[0..input_length], &expected, .{});

        var actual: [400]u8 = undefined;
        var state = Shake128.init(.{});
        defer std.crypto.secureZero(u8, std.mem.asBytes(&state));
        const split = input_length / 2;
        state.update(input[0..split]);
        state.update(input[split..input_length]);
        state.squeeze(actual[0..137]);
        state.squeeze(actual[137..]);
        try std.testing.expectEqual(expected, actual);
    }
}

test "AVX2 SHA3-256 and SHA3-512 match Zig std" {
    if (comptime !enabled) return error.SkipZigTest;

    var input: [333]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index * 61 + 13);

    inline for (.{ 0, 1, 32, 64, 71, 72, 73, 135, 136, 137, 333 }) |input_length| {
        var expected_256: [32]u8 = undefined;
        std.crypto.hash.sha3.Sha3_256.hash(input[0..input_length], &expected_256, .{});
        var actual_256: [32]u8 = undefined;
        sha3_256(input[0..input_length], &actual_256);
        try std.testing.expectEqual(expected_256, actual_256);

        var expected_512: [64]u8 = undefined;
        std.crypto.hash.sha3.Sha3_512.hash(input[0..input_length], &expected_512, .{});
        var actual_512: [64]u8 = undefined;
        const split = input_length / 2;
        sha3_512Parts(input[0..split], input[split..input_length], &actual_512);
        try std.testing.expectEqual(expected_512, actual_512);
    }
}
