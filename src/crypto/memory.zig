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

/// Securely clears a 32-byte-aligned slice, including a partial final block.
pub fn zeroAlignedSlice32(bytes: []align(32) u8) void {
    const Vector = @Vector(32, u8);
    const block_count = bytes.len / 32;
    const blocks: [*]align(32) volatile Vector = @ptrCast(bytes.ptr);
    for (0..block_count) |index| blocks[index] = @splat(0);
    zero(bytes[block_count * 32 ..]);
    asm volatile ("" ::: .{ .memory = true });
}

test "aligned vector zero clears the complete value" {
    var value: [96]u8 align(32) = .{0xa5} ** 96;
    zeroAligned32(&value);
    try std.testing.expectEqual([_]u8{0} ** 96, value);
}

test "aligned slice zero preserves canaries for empty slices and every short boundary" {
    for (0..128) |length| {
        try expectAlignedSliceCleared(127, 32, length);
        try expectAlignedSliceCleared(127, 64, length);
    }
}

test "aligned slice zero preserves canaries for large blocks and partial tails" {
    for ([_]usize{ 2048, 2049, 65535, 65536, 65537 }) |length| {
        try expectAlignedSliceCleared(65537, 64, length);
    }
}

fn expectAlignedSliceCleared(
    comptime capacity: usize,
    start: usize,
    length: usize,
) !void {
    var value: [capacity + 96]u8 align(32) = .{0xa5} ** (capacity + 96);
    const end = start + length;
    const bytes: []align(32) u8 = @alignCast(value[start..end]);
    @memset(bytes, 0x3c);
    @memset(value[end..], 0x5a);

    zeroAlignedSlice32(bytes);

    for (value[0..start]) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    for (bytes) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (value[end..]) |byte| try std.testing.expectEqual(@as(u8, 0x5a), byte);
}
