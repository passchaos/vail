//! ARM64 four-way Keccak-f1600 permutation from s2n-bignum / mlkem-native.
//!
//! The kernel operates on four independent row-major 25-word states, matching
//! the `[4][25]u64` layout used by `keccak4.zig`.

const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn permute(states: *[4][25]u64, constants: *const [24]u64) void {
    if (comptime !enabled) @compileError("ARM64 four-way Keccak is unavailable");
    vailKeccakF1600x4Arm64(states, constants);
}

extern fn vailKeccakF1600x4Arm64(
    states: *[4][25]u64,
    constants: *const [24]u64,
) callconv(.c) void;

comptime {
    if (enabled) asm (@embedFile("keccak4_arm64.S"));
}
