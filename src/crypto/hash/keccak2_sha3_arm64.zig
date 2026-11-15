//! ARM64 two-way Keccak-f1600 permutation using the ARMv8.2 SHA3 extension.
//!
//! Apple silicon exposes the SHA3 extension, so the two-way kernel is faster
//! than the plain NEON four-way kernel for batched SHAKE expansion.

const std = @import("std");
const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe) and
    builtin.cpu.has(.aarch64, .sha3);

/// Permute two independent 25-word Keccak states stored back to back.
pub fn permute2(states: *[2][25]u64, constants: *const [24]u64) void {
    if (comptime !enabled) @compileError("ARM64 SHA3 Keccak is unavailable");
    vailKeccakF1600x2Sha3Arm64(@ptrCast(states), constants);
}

extern fn vailKeccakF1600x2Sha3Arm64(
    states: *[50]u64,
    constants: *const [24]u64,
) callconv(.c) void;

const asm_source = if (enabled and !asm_compat.external) asm_compat.slice(@embedFile("keccak2_sha3_arm64.S")) else "";

comptime {
    if (enabled and !asm_compat.external) asm (asm_source);
}
