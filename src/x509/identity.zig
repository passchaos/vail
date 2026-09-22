//! Strict X.509 subject identity extraction.
//!
//! The returned common name is deeply owned UTF-8. Ambiguous subjects with
//! multiple commonName attributes and legacy string encodings whose Unicode
//! meaning is not defined here fail closed.

const std = @import("std");

const Certificate = std.crypto.Certificate;

pub const Error = std.mem.Allocator.Error || error{
    InvalidCertificate,
    InvalidSubject,
    MissingCommonName,
    DuplicateCommonName,
    EmptyCommonName,
    UnsupportedDirectoryString,
    InvalidDirectoryString,
};

const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };

pub fn commonNameAlloc(
    allocator: std.mem.Allocator,
    certificate_der: []const u8,
) Error![]u8 {
    const certificate = Certificate.der.Element.parse(
        certificate_der,
        0,
    ) catch return error.InvalidCertificate;
    if (certificate.slice.end != certificate_der.len) {
        return error.InvalidCertificate;
    }
    const parsed = Certificate.parse(.{
        .buffer = certificate_der,
        .index = 0,
    }) catch return error.InvalidCertificate;
    return commonNameFromSubjectAlloc(
        allocator,
        parsed.subject(),
    );
}

fn commonNameFromSubjectAlloc(
    allocator: std.mem.Allocator,
    subject: []const u8,
) Error![]u8 {
    var common_name: ?Element = null;
    var rdns = Reader{ .bytes = subject };
    while (try rdns.next()) |rdn| {
        if (rdn.tag != 0x31) return error.InvalidSubject;
        var attributes = Reader{ .bytes = rdn.value };
        while (try attributes.next()) |attribute| {
            if (attribute.tag != 0x30) return error.InvalidSubject;
            var fields = Reader{ .bytes = attribute.value };
            const oid = (try fields.next()) orelse
                return error.InvalidSubject;
            if (oid.tag != 0x06) return error.InvalidSubject;
            const value = (try fields.next()) orelse
                return error.InvalidSubject;
            if (try fields.next() != null) return error.InvalidSubject;
            if (!std.mem.eql(u8, oid.value, &oid_common_name)) continue;
            if (common_name != null) return error.DuplicateCommonName;
            common_name = value;
        }
    }
    const value = common_name orelse return error.MissingCommonName;
    return directoryStringAlloc(allocator, value);
}

fn directoryStringAlloc(
    allocator: std.mem.Allocator,
    value: Element,
) Error![]u8 {
    return switch (value.tag) {
        // UTF8String
        0x0c => blk: {
            if (value.value.len == 0) return error.EmptyCommonName;
            if (!std.unicode.utf8ValidateSlice(value.value) or
                std.mem.indexOfScalar(u8, value.value, 0) != null)
            {
                return error.InvalidDirectoryString;
            }
            break :blk try allocator.dupe(u8, value.value);
        },
        // PrintableString
        0x13 => blk: {
            if (value.value.len == 0) return error.EmptyCommonName;
            for (value.value) |byte| {
                if (!isPrintableStringByte(byte) or byte == 0) {
                    return error.InvalidDirectoryString;
                }
            }
            break :blk try allocator.dupe(u8, value.value);
        },
        // BMPString (UCS-2/UTF-16BE without surrogate pairs).
        0x1e => try fixedWidthStringAlloc(allocator, value.value, 2),
        // UniversalString (UCS-4/UTF-32BE).
        0x1c => try fixedWidthStringAlloc(allocator, value.value, 4),
        else => error.UnsupportedDirectoryString,
    };
}

fn fixedWidthStringAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    comptime width: usize,
) Error![]u8 {
    if (encoded.len == 0) return error.EmptyCommonName;
    if (encoded.len % width != 0) return error.InvalidDirectoryString;
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);
    var offset: usize = 0;
    while (offset < encoded.len) : (offset += width) {
        const codepoint_u32 = if (width == 2)
            @as(u32, std.mem.readInt(u16, encoded[offset..][0..2], .big))
        else
            std.mem.readInt(u32, encoded[offset..][0..4], .big);
        if (codepoint_u32 == 0 or codepoint_u32 > 0x10ffff or
            (codepoint_u32 >= 0xd800 and codepoint_u32 <= 0xdfff))
        {
            return error.InvalidDirectoryString;
        }
        const codepoint: u21 = @intCast(codepoint_u32);
        var buffer: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(codepoint, &buffer) catch
            return error.InvalidDirectoryString;
        try result.appendSlice(allocator, buffer[0..len]);
    }
    return result.toOwnedSlice(allocator);
}

fn isPrintableStringByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?' => true,
        else => false,
    };
}

const Element = struct {
    tag: u8,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn next(self: *Reader) Error!?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidSubject;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidSubject;
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
                return error.InvalidSubject;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidSubject;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidSubject;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidSubject;
        }
        if (length > self.bytes.len - self.offset) {
            return error.InvalidSubject;
        }
        const value = self.bytes[self.offset .. self.offset + length];
        self.offset += length;
        return .{ .tag = tag, .value = value };
    }
};

test "X509 identity extracts an owned UTF8 common name" {
    const certificate = @embedFile("testdata/server.der");
    const common_name = try commonNameAlloc(std.testing.allocator, certificate);
    defer std.testing.allocator.free(common_name);
    try std.testing.expectEqualStrings("localhost", common_name);
}

test "X509 identity converts supported DirectoryString encodings" {
    const utf8 = try directoryStringAlloc(std.testing.allocator, .{
        .tag = 0x0c,
        .value = "客户端",
    });
    defer std.testing.allocator.free(utf8);
    try std.testing.expectEqualStrings("客户端", utf8);

    const printable = try directoryStringAlloc(std.testing.allocator, .{
        .tag = 0x13,
        .value = "client-01",
    });
    defer std.testing.allocator.free(printable);
    try std.testing.expectEqualStrings("client-01", printable);

    const bmp = try directoryStringAlloc(std.testing.allocator, .{
        .tag = 0x1e,
        .value = &.{ 0x00, 'A', 0x4e, 0x2d },
    });
    defer std.testing.allocator.free(bmp);
    try std.testing.expectEqualStrings("A中", bmp);

    const universal = try directoryStringAlloc(std.testing.allocator, .{
        .tag = 0x1c,
        .value = &.{ 0x00, 0x01, 0xf6, 0x00 },
    });
    defer std.testing.allocator.free(universal);
    try std.testing.expectEqualStrings("😀", universal);
}

test "X509 identity rejects ambiguous and unsafe subjects" {
    const cn = [_]u8{ 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 'c', 'l', 'i', 'e', 'n', 't' };
    const duplicate_cn = cn ++ cn;
    try std.testing.expectError(
        error.DuplicateCommonName,
        commonNameFromSubjectAlloc(std.testing.allocator, &duplicate_cn),
    );
    try std.testing.expectError(
        error.MissingCommonName,
        commonNameFromSubjectAlloc(std.testing.allocator, &.{}),
    );
    try std.testing.expectError(
        error.InvalidDirectoryString,
        directoryStringAlloc(std.testing.allocator, .{
            .tag = 0x0c,
            .value = "bad\x00name",
        }),
    );
    try std.testing.expectError(
        error.UnsupportedDirectoryString,
        directoryStringAlloc(std.testing.allocator, .{
            .tag = 0x14,
            .value = "legacy",
        }),
    );
    try std.testing.expectError(
        error.InvalidDirectoryString,
        directoryStringAlloc(std.testing.allocator, .{
            .tag = 0x1e,
            .value = &.{ 0xd8, 0x00 },
        }),
    );
    const certificate = @embedFile("testdata/server.der");
    const trailing = certificate.* ++ .{0x00};
    try std.testing.expectError(
        error.InvalidCertificate,
        commonNameAlloc(std.testing.allocator, &trailing),
    );
}
