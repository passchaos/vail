//! ARM64 Keccak-f1600 permutation from s2n-bignum / mlkem-native.
//!
//! The kernel uses the ARMv8.2 SHA-3 instructions and operates on the same
//! row-major 25-word state as the portable sponge.

const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn permute(state: *[25]u64, constants: *const [24]u64) void {
    if (comptime !enabled) @compileError("ARM64 Keccak-f1600 is unavailable");
    vailKeccakF1600Arm64(state, constants);
}

extern fn vailKeccakF1600Arm64(
    state: *[25]u64,
    constants: *const [24]u64,
) callconv(.c) void;

comptime {
    if (enabled) asm (@embedFile("keccak_arm64.S"));
}
