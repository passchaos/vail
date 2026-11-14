//! ARM64 four-way Keccak-f1600 permutation from s2n-bignum / mlkem-native.
//!
//! The kernel operates on four independent row-major 25-word states, matching
//! the `[4][25]u64` layout used by `keccak4.zig`.

const std = @import("std");
const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

const has_sha3 = std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha3);

pub const enabled = asm_compat.arm64_native and
    has_sha3 and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn permute(states: *[4][25]u64, constants: *const [24]u64) void {
    if (comptime !enabled) @compileError("ARM64 four-way Keccak is unavailable");
    vailKeccakF1600x4Arm64(states, constants);
}

extern fn vailKeccakF1600x4Arm64(
    states: *[4][25]u64,
    constants: *const [24]u64,
) callconv(.c) void;

const asm_source = asm_compat.slice(@embedFile("keccak4_arm64.S"));

comptime {
    if (enabled) asm (asm_source);
}
