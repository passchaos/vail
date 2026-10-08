//! Cryptographic memory hygiene helpers.

const std = @import("std");

pub fn zero(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

pub fn zeroValue(value: anytype) void {
    zero(std.mem.asBytes(value));
}

/// Securely clears a fixed-size, 32-byte-aligned value with volatile vector
/// stores. This avoids the byte-at-a-time fallback used by `secureZero` for
/// large aligned cryptographic scratch buffers.
pub fn zeroAligned32(value: anytype) void {
    const byte_length = @sizeOf(@TypeOf(value.*));
    comptime std.debug.assert(byte_length % 32 == 0);
    const Vector = @Vector(32, u8);
    const blocks: *align(32) volatile [byte_length / 32]Vector = @ptrCast(value);
    for (0..blocks.len) |index| blocks[index] = @splat(0);
    asm volatile ("" ::: .{ .memory = true });
}

test "aligned vector zero clears the complete value" {
    var value: [96]u8 align(32) = .{0xa5} ** 96;
    zeroAligned32(&value);
    try std.testing.expectEqual([_]u8{0} ** 96, value);
}
