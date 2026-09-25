//! OpenSSL-compatible RFC 2253 formatting for DER X.509 Names.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    InvalidSubject,
    InvalidDirectoryString,
    InvalidObjectIdentifier,
    UnsupportedDirectoryString,
};

pub fn nameAlloc(
    allocator: std.mem.Allocator,
    subject: []const u8,
) Error![]u8 {
    var rdns: std.ArrayList([]const u8) = .empty;
    defer rdns.deinit(allocator);
    var reader = Reader{ .bytes = subject };
    while (try reader.next()) |rdn| {
        if (rdn.tag != 0x31) return error.InvalidSubject;
        try validateRdn(rdn.value);
        try rdns.append(allocator, rdn.value);
    }

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    var index = rdns.items.len;
    while (index != 0) {
        index -= 1;
        if (index != rdns.items.len - 1) try result.append(allocator, ',');
        try appendRdn(&result, allocator, rdns.items[index]);
    }
    return result.toOwnedSlice(allocator);
}

fn validateRdn(bytes: []const u8) Error!void {
    var attributes = Reader{ .bytes = bytes };
    var count: usize = 0;
    while (try attributes.next()) |attribute| {
        if (attribute.tag != 0x30) return error.InvalidSubject;
        count += 1;
    }
    if (count == 0) return error.InvalidSubject;
}

fn appendRdn(
    result: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!void {
    var attributes: std.ArrayList(Element) = .empty;
    defer attributes.deinit(allocator);
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |attribute| {
        if (attribute.tag != 0x30) return error.InvalidSubject;
        try attributes.append(allocator, attribute);
    }

    var index = attributes.items.len;
    while (index != 0) {
        index -= 1;
        if (index != attributes.items.len - 1) {
            try result.append(allocator, '+');
        }
        try appendAttribute(result, allocator, attributes.items[index]);
    }
}

fn appendAttribute(
    result: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    attribute: Element,
) Error!void {
    var fields = Reader{ .bytes = attribute.value };
    const oid = (try fields.next()) orelse return error.InvalidSubject;
    if (oid.tag != 0x06) return error.InvalidSubject;
    const value = (try fields.next()) orelse return error.InvalidSubject;
    if (try fields.next() != null) return error.InvalidSubject;

    if (attributeShortName(oid.value)) |name| {
        try result.appendSlice(allocator, name);
        try result.append(allocator, '=');
        try appendValue(result, allocator, value);
        return;
    }
    try appendObjectIdentifier(result, allocator, oid.value);
    try result.appendSlice(allocator, "=#");
    try appendHex(result, allocator, value.encoded);
}

fn attributeShortName(oid: []const u8) ?[]const u8 {
    const AttributeName = struct {
        oid: []const u8,
        short_name: []const u8,
    };
    const names = [_]AttributeName{
        .{ .oid = &.{ 0x55, 0x04, 0x03 }, .short_name = "CN" },
        .{ .oid = &.{ 0x55, 0x04, 0x04 }, .short_name = "SN" },
        .{ .oid = &.{ 0x55, 0x04, 0x05 }, .short_name = "serialNumber" },
        .{ .oid = &.{ 0x55, 0x04, 0x06 }, .short_name = "C" },
        .{ .oid = &.{ 0x55, 0x04, 0x07 }, .short_name = "L" },
        .{ .oid = &.{ 0x55, 0x04, 0x08 }, .short_name = "ST" },
        .{ .oid = &.{ 0x55, 0x04, 0x09 }, .short_name = "street" },
        .{ .oid = &.{ 0x55, 0x04, 0x0a }, .short_name = "O" },
        .{ .oid = &.{ 0x55, 0x04, 0x0b }, .short_name = "OU" },
        .{ .oid = &.{ 0x55, 0x04, 0x11 }, .short_name = "postalCode" },
        .{ .oid = &.{ 0x55, 0x04, 0x2a }, .short_name = "GN" },
        .{ .oid = &.{ 0x55, 0x04, 0x61 }, .short_name = "organizationIdentifier" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 }, .short_name = "emailAddress" },
        .{ .oid = &.{ 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19 }, .short_name = "DC" },
    };
    for (names) |name| {
        if (std.mem.eql(u8, oid, name.oid)) return name.short_name;
    }
    return null;
}

fn appendValue(
    result: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: Element,
) Error!void {
    const decoded = stringAlloc(allocator, value) catch |err| switch (err) {
        error.UnsupportedDirectoryString => {
            try result.append(allocator, '#');
            return appendHex(result, allocator, value.encoded);
        },
        else => |other| return other,
    };
    defer allocator.free(decoded);
    for (decoded, 0..) |byte, index| {
        const hex_escape = byte < 0x20 or byte == 0x7f or byte >= 0x80;
        const simple_escape = byte == '\\' or byte == '"' or byte == ',' or
            byte == '+' or byte == '<' or byte == '>' or byte == ';' or
            (index == 0 and (byte == ' ' or byte == '#')) or
            (index + 1 == decoded.len and byte == ' ');
        if (hex_escape) {
            try result.append(allocator, '\\');
            try appendHexByte(result, allocator, byte);
        } else {
            if (simple_escape) try result.append(allocator, '\\');
            try result.append(allocator, byte);
        }
    }
}

fn stringAlloc(
    allocator: std.mem.Allocator,
    value: Element,
) Error![]u8 {
    return switch (value.tag) {
        0x0c => blk: {
            if (!std.unicode.utf8ValidateSlice(value.value)) {
                return error.InvalidDirectoryString;
            }
            break :blk try allocator.dupe(u8, value.value);
        },
        0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1a => latin1StringAlloc(allocator, value.value),
        0x1c => fixedWidthStringAlloc(allocator, value.value, 4),
        0x1e => fixedWidthStringAlloc(allocator, value.value, 2),
        else => error.UnsupportedDirectoryString,
    };
}

fn latin1StringAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) std.mem.Allocator.Error![]u8 {
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);
    for (encoded) |byte| {
        if (byte < 0x80) {
            try result.append(allocator, byte);
        } else {
            var buffer: [2]u8 = undefined;
            const len = std.unicode.utf8Encode(byte, &buffer) catch unreachable;
            try result.appendSlice(allocator, buffer[0..len]);
        }
    }
    return result.toOwnedSlice(allocator);
}

fn fixedWidthStringAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    comptime width: usize,
) Error![]u8 {
    if (encoded.len % width != 0) return error.InvalidDirectoryString;
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);
    var offset: usize = 0;
    while (offset < encoded.len) : (offset += width) {
        const codepoint_u32 = if (width == 2)
            @as(u32, std.mem.readInt(u16, encoded[offset..][0..2], .big))
        else
            std.mem.readInt(u32, encoded[offset..][0..4], .big);
        if (codepoint_u32 > 0x10ffff or
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

fn appendObjectIdentifier(
    result: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    encoded: []const u8,
) Error!void {
    if (encoded.len == 0) return error.InvalidObjectIdentifier;
    var index: usize = 0;
    const first = try nextObjectIdentifierComponent(encoded, &index);
    const first_component: u64 = @min(first / 40, 2);
    const second_component = first - first_component * 40;
    try appendDecimal(result, allocator, first_component);
    try result.append(allocator, '.');
    try appendDecimal(result, allocator, second_component);
    while (index < encoded.len) {
        const component = try nextObjectIdentifierComponent(encoded, &index);
        try result.append(allocator, '.');
        try appendDecimal(result, allocator, component);
    }
}

fn nextObjectIdentifierComponent(
    encoded: []const u8,
    index: *usize,
) Error!u64 {
    var component: u64 = 0;
    var first_octet = true;
    while (true) {
        if (index.* == encoded.len) return error.InvalidObjectIdentifier;
        const byte = encoded[index.*];
        index.* += 1;
        if (first_octet and byte == 0x80) return error.InvalidObjectIdentifier;
        first_octet = false;
        component = std.math.mul(u64, component, 128) catch
            return error.InvalidObjectIdentifier;
        component = std.math.add(u64, component, byte & 0x7f) catch
            return error.InvalidObjectIdentifier;
        if ((byte & 0x80) == 0) return component;
    }
}

fn appendDecimal(
    result: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: anytype,
) std.mem.Allocator.Error!void {
    var buffer: [20]u8 = undefined;
    const rendered = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch
        unreachable;
    try result.appendSlice(allocator, rendered);
}

fn appendHex(
    result: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) std.mem.Allocator.Error!void {
    for (bytes) |byte| try appendHexByte(result, allocator, byte);
}

fn appendHexByte(
    result: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    byte: u8,
) std.mem.Allocator.Error!void {
    const digits = "0123456789ABCDEF";
    try result.append(allocator, digits[byte >> 4]);
    try result.append(allocator, digits[byte & 0x0f]);
}

const Element = struct {
    tag: u8,
    encoded: []const u8,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn next(self: *Reader) Error!?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidSubject;
        const start = self.offset;
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
        if (length > self.bytes.len - self.offset) return error.InvalidSubject;
        const value = self.bytes[self.offset .. self.offset + length];
        self.offset += length;
        return .{
            .tag = tag,
            .encoded = self.bytes[start..self.offset],
            .value = value,
        };
    }
};

test "RFC2253 reverses RDN and multi-valued attribute order" {
    const structured = [_]u8{
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
        0x13, 0x02, 'G',  'B',  0x31, 0x0c, 0x30, 0x0a, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 'O',  'r',  'g',
        0x31, 0x1c, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x0c, 0x04, 'U',  'n',  'i',  't',  0x30, 0x0d, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 'c',  'l',  'i',
        'e',  'n',  't',
    };
    const rendered = try nameAlloc(std.testing.allocator, &structured);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings("CN=client+OU=Unit,O=Org,C=GB", rendered);
}

test "RFC2253 escaping matches OpenSSL boundaries" {
    var escaped: std.ArrayList(u8) = .empty;
    defer escaped.deinit(std.testing.allocator);
    try appendValue(&escaped, std.testing.allocator, .{
        .tag = 0x0c,
        .encoded = &.{ 0x0c, 0x0c },
        .value = " #a,b+c<d>; ",
    });
    try std.testing.expectEqualStrings(
        "\\ #a\\,b\\+c\\<d\\>\\;\\ ",
        escaped.items,
    );

    escaped.clearRetainingCapacity();
    try appendValue(&escaped, std.testing.allocator, .{
        .tag = 0x0c,
        .encoded = &.{ 0x0c, 0x04 },
        .value = &.{ 'A', 0xc2, 0x9f, 'B' },
    });
    try std.testing.expectEqualStrings("A\\C2\\9FB", escaped.items);
}

test "RFC2253 renders unknown OID values as DER hex" {
    const unknown = [_]u8{
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x02, 0x2a, 0x03,
        0x0c, 0x03, 'a',  'b',  'c',
    };
    const rendered = try nameAlloc(std.testing.allocator, &unknown);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings("1.2.3=#0C03616263", rendered);

    const large_second_component = [_]u8{
        0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x88, 0x37, 0x03,
        0x0c, 0x03, 'a',  'b',  'c',
    };
    const large_rendered = try nameAlloc(
        std.testing.allocator,
        &large_second_component,
    );
    defer std.testing.allocator.free(large_rendered);
    try std.testing.expectEqualStrings("2.999.3=#0C03616263", large_rendered);

    const malformed_oid = [_]u8{
        0x31, 0x0a, 0x30, 0x08, 0x06, 0x01, 0x80,
        0x0c, 0x03, 'a',  'b',  'c',
    };
    try std.testing.expectError(
        error.InvalidObjectIdentifier,
        nameAlloc(std.testing.allocator, &malformed_oid),
    );
}
