//! Minimal DER reader shared by cryptographic and X.509 parsers.
//!
//! The reader deliberately accepts only definite-length, single-byte-tag
//! elements. Callers own the semantic validation of tags and values.

const std = @import("std");

pub const Error = error{InvalidDer};

pub const max_depth: usize = 64;
pub const max_elements: usize = 100_000;

/// Validate the complete DER structure, including nested constructed values.
///
/// This is a defensive pre-pass for parsers that use index-based readers which
/// assume every length field is in bounds. It rejects trailing data, empty
/// end-of-contents tags, over-deep nesting, and excessive element counts.
pub fn validateDocument(bytes: []const u8) Error!void {
    var reader = Reader{ .bytes = bytes };
    const element = (try reader.next()) orelse return error.InvalidDer;
    if (!reader.done()) return error.InvalidDer;
    var budget: usize = max_elements;
    try validateElement(element, 0, &budget);
}

fn validateElement(element: Element, depth: usize, budget: *usize) Error!void {
    if (depth > max_depth or budget.* == 0) return error.InvalidDer;
    budget.* -= 1;
    if (element.tag == 0x00) return error.InvalidDer;
    if ((element.tag & 0x20) == 0) return;
    var reader = Reader{ .bytes = element.value };
    while (try reader.next()) |child| {
        try validateElement(child, depth + 1, budget);
    }
}

pub const Element = struct {
    tag: u8,
    value: []const u8,
};

pub const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn require(self: *Reader, tag: u8) Error!Element {
        const value = (try self.next()) orelse return error.InvalidDer;
        if (value.tag != tag) return error.InvalidDer;
        return value;
    }

    pub fn next(self: *Reader) Error!?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidDer;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidDer;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidDer;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidDer;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidDer;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidDer;
        }
        if (length > self.bytes.len - self.offset) return error.InvalidDer;
        const value = self.bytes[self.offset .. self.offset + length];
        self.offset += length;
        return .{ .tag = tag, .value = value };
    }

    pub fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

test "validateDocument rejects truncated and malformed lengths" {
    const valid = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    try validateDocument(&valid);
    try std.testing.expectError(
        error.InvalidDer,
        validateDocument(valid[0 .. valid.len - 1]),
    );

    const nested_overflow = [_]u8{ 0x30, 0x04, 0x30, 0x05, 0x00, 0x00 };
    try std.testing.expectError(
        error.InvalidDer,
        validateDocument(&nested_overflow),
    );

    const trailing = [_]u8{ 0x30, 0x00, 0x00 };
    try std.testing.expectError(
        error.InvalidDer,
        validateDocument(&trailing),
    );
}
