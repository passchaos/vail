//! ARM64 Keccak-f1600 permutation from s2n-bignum / mlkem-native.
//!
//! The kernel operates on the same row-major 25-word state as the portable
//! sponge and uses baseline NEON instructions.

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn permute(state: *[25]u64, constants: *const [24]u64) void {
    if (comptime !enabled) @compileError("ARM64 Keccak-f1600 is unavailable");
    vailKeccakF1600Arm64(state, constants);
}

extern fn vailKeccakF1600Arm64(
    state: *[25]u64,
    constants: *const [24]u64,
) callconv(.c) void;

const asm_source = asm_compat.slice(@embedFile("keccak_arm64.S"));

comptime {
    if (enabled) asm (asm_source);
}
