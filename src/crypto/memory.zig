//! Cryptographic memory hygiene helpers.

const std = @import("std");

pub fn zero(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

pub fn zeroValue(value: anytype) void {
    zero(std.mem.asBytes(value));
}
