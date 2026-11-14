//! Bounds-checked DER reader used by X.509 trust extension parsing.
//!
//! The reader accepts definite-length, single-byte-tag elements and reports
//! malformed lengths as `error.InvalidCertificateExtension`.

const std = @import("std");

pub const Error = error{InvalidCertificateExtension};

pub const Tlv = struct {
    tag: u8,
    value: []const u8,
};

pub const DerReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *DerReader) Error!?Tlv {
        if (self.pos == self.bytes.len) return null;
        if (self.pos > self.bytes.len) return error.InvalidCertificateExtension;
        const tag = self.bytes[self.pos];
        self.pos += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidCertificateExtension;
        const len = try self.readLength();
        const end = std.math.add(usize, self.pos, len) catch
            return error.InvalidCertificateExtension;
        if (end > self.bytes.len) return error.InvalidCertificateExtension;
        const value = self.bytes[self.pos..end];
        self.pos = end;
        return .{ .tag = tag, .value = value };
    }

    pub fn require(self: *DerReader, tag: u8) Error!Tlv {
        const value = (try self.next()) orelse
            return error.InvalidCertificateExtension;
        if (value.tag != tag) return error.InvalidCertificateExtension;
        return value;
    }

    fn readLength(self: *DerReader) Error!usize {
        if (self.pos >= self.bytes.len) return error.InvalidCertificateExtension;
        const first = self.bytes[self.pos];
        self.pos += 1;
        if ((first & 0x80) == 0) return first;
        const count: usize = first & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) {
            return error.InvalidCertificateExtension;
        }
        const end = std.math.add(usize, self.pos, count) catch
            return error.InvalidCertificateExtension;
        if (end > self.bytes.len or self.bytes[self.pos] == 0) {
            return error.InvalidCertificateExtension;
        }
        var len: usize = 0;
        for (self.bytes[self.pos..end]) |byte| {
            len = std.math.mul(usize, len, 256) catch
                return error.InvalidCertificateExtension;
            len = std.math.add(usize, len, byte) catch
                return error.InvalidCertificateExtension;
        }
        self.pos = end;
        if (len < 128) return error.InvalidCertificateExtension;
        return len;
    }
};

test "DerReader rejects truncated lengths" {
    var reader = DerReader{ .bytes = &.{ 0x30, 0x03, 0x02, 0x01 } };
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        reader.next(),
    );
}
