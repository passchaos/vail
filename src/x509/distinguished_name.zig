//! Allocation-free RFC 5280 section 7.1 distinguished-name comparison.

const std = @import("std");
const stringprep = @import("stringprep.zig");

pub const Error = error{
    InvalidName,
    UnsupportedDirectoryString,
};

const oid_domain_component = [_]u8{
    0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19,
};

const Attribute = struct {
    oid: []const u8,
    value: Tlv,
};

pub fn validate(name: []const u8) Error!void {
    var rdns = Reader{ .bytes = name };
    while (try rdns.next()) |rdn| {
        if (rdn.tag != 0x31 or rdn.value.len == 0) return error.InvalidName;
        var attributes = Reader{ .bytes = rdn.value };
        var count: usize = 0;
        while (try attributes.next()) |encoded_attribute| {
            const attribute = try parseAttribute(encoded_attribute);
            try validateAttribute(attribute);
            count += 1;
        }
        if (count == 0) return error.InvalidName;
    }
}

pub fn eql(a: []const u8, b: []const u8) Error!bool {
    if (std.mem.eql(u8, a, b)) return true;
    try validate(a);
    try validate(b);
    var a_rdns = Reader{ .bytes = a };
    var b_rdns = Reader{ .bytes = b };
    while (try a_rdns.next()) |a_rdn| {
        const b_rdn = (try b_rdns.next()) orelse return false;
        if (!try rdnMatches(a_rdn, b_rdn)) return false;
    }
    return try b_rdns.next() == null;
}

pub fn withinSubtree(name: []const u8, constraint: []const u8) Error!bool {
    try validate(name);
    try validate(constraint);
    var name_rdns = Reader{ .bytes = name };
    var constraint_rdns = Reader{ .bytes = constraint };
    while (try constraint_rdns.next()) |constraint_rdn| {
        const name_rdn = (try name_rdns.next()) orelse return false;
        if (!try rdnMatches(name_rdn, constraint_rdn)) return false;
    }
    return true;
}

/// Validate the contents of an implicitly tagged RelativeDistinguishedName.
pub fn validateRelativeName(encoded: []const u8) Error!void {
    const rdn = Tlv{ .tag = 0x31, .value = encoded };
    _ = try attributeCount(rdn.value);
    var attributes = Reader{ .bytes = rdn.value };
    while (try attributes.next()) |attribute| {
        try validateAttribute(try parseAttribute(attribute));
    }
}

pub fn relativeNamesEqual(a: []const u8, b: []const u8) Error!bool {
    if (std.mem.eql(u8, a, b)) return true;
    try validateRelativeName(a);
    try validateRelativeName(b);
    return rdnMatches(
        .{ .tag = 0x31, .value = a },
        .{ .tag = 0x31, .value = b },
    );
}

/// Compare `full_name` with the DN formed by appending one relative RDN to
/// `base_name`, without allocating a temporary DER Name.
pub fn eqlWithAppendedRdn(
    full_name: []const u8,
    base_name: []const u8,
    relative_name: []const u8,
) Error!bool {
    try validate(full_name);
    try validate(base_name);
    try validateRelativeName(relative_name);
    var full = Reader{ .bytes = full_name };
    var base = Reader{ .bytes = base_name };
    while (try base.next()) |base_rdn| {
        const full_rdn = (try full.next()) orelse return false;
        if (!try rdnMatches(full_rdn, base_rdn)) return false;
    }
    const appended = (try full.next()) orelse return false;
    if (!try rdnMatches(
        appended,
        .{ .tag = 0x31, .value = relative_name },
    )) return false;
    return try full.next() == null;
}

fn parseAttribute(encoded: Tlv) Error!Attribute {
    if (encoded.tag != 0x30) return error.InvalidName;
    var fields = Reader{ .bytes = encoded.value };
    const oid = try fields.require(0x06);
    try validateOid(oid.value);
    const value = (try fields.next()) orelse return error.InvalidName;
    if (try fields.next() != null) return error.InvalidName;
    return .{ .oid = oid.value, .value = value };
}

fn validateAttribute(attribute: Attribute) Error!void {
    if (std.mem.eql(u8, attribute.oid, &oid_domain_component)) {
        if (attribute.value.tag != 0x16 or
            !validDomainComponent(attribute.value.value))
        {
            return error.InvalidName;
        }
    } else if (isDirectoryStringTag(attribute.value.tag)) {
        stringprep.validate(.{
            .tag = attribute.value.tag,
            .bytes = attribute.value.value,
        }) catch |err| return switch (err) {
            error.InvalidDirectoryString => error.InvalidName,
            error.UnsupportedDirectoryString => error.UnsupportedDirectoryString,
        };
    }
}

fn rdnMatches(a: Tlv, b: Tlv) Error!bool {
    if (a.tag != 0x31 or b.tag != 0x31) return error.InvalidName;
    const a_count = try attributeCount(a.value);
    const b_count = try attributeCount(b.value);
    if (a_count != b_count) return false;

    var attributes = Reader{ .bytes = a.value };
    while (try attributes.next()) |encoded_attribute| {
        const attribute = try parseAttribute(encoded_attribute);
        var occurrences_in_a: usize = 0;
        var peers = Reader{ .bytes = a.value };
        while (try peers.next()) |encoded_peer| {
            if (try attributesMatch(
                attribute,
                try parseAttribute(encoded_peer),
            )) occurrences_in_a += 1;
        }

        var occurrences_in_b: usize = 0;
        var candidates = Reader{ .bytes = b.value };
        while (try candidates.next()) |encoded_candidate| {
            if (try attributesMatch(
                attribute,
                try parseAttribute(encoded_candidate),
            )) occurrences_in_b += 1;
        }
        if (occurrences_in_a != occurrences_in_b) return false;
    }
    return true;
}

fn attributeCount(encoded: []const u8) Error!usize {
    var attributes = Reader{ .bytes = encoded };
    var count: usize = 0;
    while (try attributes.next()) |attribute| {
        _ = try parseAttribute(attribute);
        count += 1;
    }
    if (count == 0) return error.InvalidName;
    return count;
}

fn attributesMatch(a: Attribute, b: Attribute) Error!bool {
    if (!std.mem.eql(u8, a.oid, b.oid)) return false;
    if (std.mem.eql(u8, a.oid, &oid_domain_component)) {
        if (a.value.tag != 0x16 or b.value.tag != 0x16 or
            !validDomainComponent(a.value.value) or
            !validDomainComponent(b.value.value))
        {
            return error.InvalidName;
        }
        return std.ascii.eqlIgnoreCase(a.value.value, b.value.value);
    }
    const a_directory_string = isDirectoryStringTag(a.value.tag);
    const b_directory_string = isDirectoryStringTag(b.value.tag);
    if (a_directory_string or b_directory_string) {
        if (!a_directory_string or !b_directory_string) return false;
        return stringprep.eqlCaseIgnoreValidated(
            .{ .tag = a.value.tag, .bytes = a.value.value },
            .{ .tag = b.value.tag, .bytes = b.value.value },
        ) catch |err| return switch (err) {
            error.InvalidDirectoryString => error.InvalidName,
            error.UnsupportedDirectoryString => error.UnsupportedDirectoryString,
        };
    }
    return a.value.tag == b.value.tag and
        std.mem.eql(u8, a.value.value, b.value.value);
}

fn isDirectoryStringTag(tag: u8) bool {
    return switch (tag) {
        // TeletexString is recognized but intentionally unsupported because
        // RFC 4518 leaves its Unicode transcoding to local policy.
        0x0c, 0x13, 0x14, 0x1c, 0x1e => true,
        else => false,
    };
}

fn validDomainComponent(value: []const u8) bool {
    if (value.len == 0 or value.len > 63 or
        value[0] == '-' or value[value.len - 1] == '-')
    {
        return false;
    }
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn validateOid(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidName;
    var at_start = true;
    for (value) |byte| {
        if (at_start and byte == 0x80) return error.InvalidName;
        at_start = byte & 0x80 == 0;
    }
    if (!at_start) return error.InvalidName;
}

const Tlv = struct {
    tag: u8,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn next(self: *Reader) Error!?Tlv {
        if (self.pos == self.bytes.len) return null;
        if (self.pos > self.bytes.len) return error.InvalidName;
        const tag = self.bytes[self.pos];
        self.pos += 1;
        if (tag & 0x1f == 0x1f) return error.InvalidName;
        const len = try self.readLength();
        const end = std.math.add(usize, self.pos, len) catch
            return error.InvalidName;
        if (end > self.bytes.len) return error.InvalidName;
        const value = self.bytes[self.pos..end];
        self.pos = end;
        return .{ .tag = tag, .value = value };
    }

    fn require(self: *Reader, tag: u8) Error!Tlv {
        const value = (try self.next()) orelse return error.InvalidName;
        if (value.tag != tag) return error.InvalidName;
        return value;
    }

    fn readLength(self: *Reader) Error!usize {
        if (self.pos >= self.bytes.len) return error.InvalidName;
        const first = self.bytes[self.pos];
        self.pos += 1;
        if (first & 0x80 == 0) return first;
        const count: usize = first & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) return error.InvalidName;
        const end = std.math.add(usize, self.pos, count) catch
            return error.InvalidName;
        if (end > self.bytes.len or self.bytes[self.pos] == 0) {
            return error.InvalidName;
        }
        var len: usize = 0;
        for (self.bytes[self.pos..end]) |byte| {
            len = std.math.mul(usize, len, 256) catch
                return error.InvalidName;
            len = std.math.add(usize, len, byte) catch
                return error.InvalidName;
        }
        self.pos = end;
        if (len < 128) return error.InvalidName;
        return len;
    }
};

test "RFC 5280 distinguished names compare attributes and string encodings" {
    const a =
        "\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x0c\x0bExample Org" ++
        "\x31\x1f" ++
        "\x30\x0b\x06\x03\x55\x04\x0b\x13\x04Beta" ++
        "\x30\x10\x06\x03\x55\x04\x0b\x13\x09Team  One";
    const b =
        "\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x13\x0bexample org" ++
        "\x31\x1e" ++
        "\x30\x0b\x06\x03\x55\x04\x0b\x0c\x04BETA" ++
        "\x30\x0f\x06\x03\x55\x04\x0b\x0c\x08team one";
    try std.testing.expect(try eql(a, b));
    try std.testing.expect(try withinSubtree(
        b ++ "\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host",
        a,
    ));
    try std.testing.expect(!(try eql(
        a,
        b ++ "\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host",
    )));
    const relative = "\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host";
    try std.testing.expect(try eqlWithAppendedRdn(
        b ++ "\x31\x0d" ++ relative,
        a,
        relative,
    ));
}
