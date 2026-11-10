//! Minimal DER reader shared by cryptographic and X.509 parsers.
//!
//! The reader deliberately accepts only definite-length, single-byte-tag
//! elements. Callers own the semantic validation of tags and values.

const std = @import("std");

pub const Error = error{InvalidDer};

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
