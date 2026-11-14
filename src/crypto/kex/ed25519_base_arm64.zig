//! Constant-time ARM64 Ed25519 fixed-base scalar multiplication.
//!
//! The instruction schedule comes from the formally verified s2n-bignum
//! Edwards25519 implementation.

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .aarch64 and
    builtin.os.tag == .linux and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub const Result = struct {
    encoded: [32]u8,
    non_identity: bool,
};

pub fn scalarMultBase(scalar: *const [32]u8) Result {
    if (comptime !enabled) @compileError("ARM64 Ed25519 is unavailable");
    var scalar_limbs: [4]u64 align(8) = undefined;
    @memcpy(std.mem.asBytes(&scalar_limbs), scalar);
    var coordinates: [8]u64 = undefined;
    vailEd25519ScalarMulBaseArm64(&coordinates, &scalar_limbs);
    const encoded = encodeCoordinates(&coordinates);
    return .{
        .encoded = encoded,
        .non_identity = (coordinates[0] | coordinates[1] |
            coordinates[2] | coordinates[3]) != 0,
    };
}

/// Fixed-base multiplication for callers that have already established that
/// the scalar is non-zero modulo the group order.
pub fn scalarMultBaseNonZero(scalar: *const [32]u8) [32]u8 {
    if (comptime !enabled) @compileError("ARM64 Ed25519 is unavailable");
    var scalar_limbs: [4]u64 align(8) = undefined;
    @memcpy(std.mem.asBytes(&scalar_limbs), scalar);
    var coordinates: [8]u64 = undefined;
    vailEd25519ScalarMulBaseArm64(&coordinates, &scalar_limbs);
    return encodeCoordinates(&coordinates);
}

inline fn encodeCoordinates(coordinates: *const [8]u64) [32]u8 {
    var encoded: [32]u8 = @bitCast(coordinates[4..8].*);
    encoded[31] |= @as(u8, @intCast(coordinates[0] & 1)) << 7;
    return encoded;
}

extern fn vailEd25519ScalarMulBaseArm64(
    output_xy: *[8]u64,
    scalar: *const [4]u64,
) callconv(.c) void;

comptime {
    if (enabled) asm (@embedFile("ed25519_base_arm64.S"));
}
