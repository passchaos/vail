//! ARM64 scalar Keccak-f1600 permutation using the ARMv8.2 SHA3 extension.
//!
//! The SHA3 extension combines the three-way XOR and rotate-xor steps, so this
//! kernel replaces the plain NEON permutation on CPUs that implement it.

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe) and
    builtin.cpu.has(.aarch64, .sha3);

pub fn permute(state: *[25]u64, constants: *const [24]u64) void {
    if (comptime !enabled) @compileError("ARM64 SHA3 Keccak is unavailable");
    vailKeccakF1600Sha3Arm64(state, constants);
}

extern fn vailKeccakF1600Sha3Arm64(
    state: *[25]u64,
    constants: *const [24]u64,
) callconv(.c) void;

const asm_source = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("keccak_sha3_arm64.S")) else "";

comptime {
    if (enabled and !asm_compat.external) asm (asm_source);
}
