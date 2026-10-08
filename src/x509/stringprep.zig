//! Allocation-free RFC 4518 `caseIgnoreMatch` preparation for X.509 names.
//!
//! RFC 5280 section 7.1 requires this comparison for UTF8String and
//! PrintableString distinguished-name attributes. The Unicode repertoire and
//! mappings are intentionally fixed at Unicode 3.2, as required by RFC 4518.

const std = @import("std");
const data = @import("stringprep_data.zig");

pub const Error = error{
    InvalidDirectoryString,
    UnsupportedDirectoryString,
};

pub const Value = struct {
    tag: u8,
    bytes: []const u8,
};

/// Validate a DirectoryString and every code point produced by the RFC 4518
/// map and normalization steps.
pub fn validate(value: Value) Error!void {
    var prepared = try PreparedIterator.init(value);
    while (try prepared.next() != null) {}
}

/// Compare two DirectoryString values with RFC 4518 caseIgnoreMatch. This uses
/// NFKD instead of materializing NFKC: equality of the canonical compatibility
/// decompositions is equivalent to equality of the corresponding NFKC forms.
pub fn eqlCaseIgnore(a: Value, b: Value) Error!bool {
    // Exhaust both inputs first so malformed or prohibited suffixes never turn
    // an early inequality into a successful parse.
    try validate(a);
    try validate(b);

    return eqlCaseIgnoreValidated(a, b);
}

/// Compare values already accepted by `validate`. Keeping this entry point
/// separate lets the DN matcher validate each complete Name exactly once.
pub fn eqlCaseIgnoreValidated(a: Value, b: Value) Error!bool {
    var left = try PreparedIterator.init(a);
    var right = try PreparedIterator.init(b);
    while (true) {
        const left_scalar = try left.next();
        const right_scalar = try right.next();
        if (left_scalar == null or right_scalar == null) {
            return left_scalar == null and right_scalar == null;
        }
        if (left_scalar.? != right_scalar.?) return false;
    }
}

const ScalarReader = struct {
    tag: u8,
    bytes: []const u8,
    pos: usize = 0,

    fn init(value: Value) Error!ScalarReader {
        switch (value.tag) {
            // UTF8String, PrintableString, UniversalString, BMPString.
            0x0c, 0x13, 0x1c, 0x1e => {},
            // TeletexString transcoding is deliberately unsupported because
            // RFC 4518 leaves its mapping to local policy.
            else => return error.UnsupportedDirectoryString,
        }
        if ((value.tag == 0x1c and value.bytes.len % 4 != 0) or
            (value.tag == 0x1e and value.bytes.len % 2 != 0))
        {
            return error.InvalidDirectoryString;
        }
        return .{ .tag = value.tag, .bytes = value.bytes };
    }

    fn next(self: *ScalarReader) Error!?u21 {
        if (self.pos == self.bytes.len) return null;
        return switch (self.tag) {
            0x0c => try self.nextUtf8(),
            0x13 => try self.nextPrintable(),
            0x1c => try self.nextUniversal(),
            0x1e => try self.nextBmp(),
            else => unreachable,
        };
    }

    fn nextUtf8(self: *ScalarReader) Error!u21 {
        const len = std.unicode.utf8ByteSequenceLength(
            self.bytes[self.pos],
        ) catch return error.InvalidDirectoryString;
        const end = self.pos + len;
        if (end > self.bytes.len) return error.InvalidDirectoryString;
        const scalar = std.unicode.utf8Decode(
            self.bytes[self.pos..end],
        ) catch return error.InvalidDirectoryString;
        self.pos = end;
        return scalar;
    }

    fn nextPrintable(self: *ScalarReader) Error!u21 {
        const byte = self.bytes[self.pos];
        self.pos += 1;
        if (!isPrintableStringByte(byte)) {
            return error.InvalidDirectoryString;
        }
        return byte;
    }

    fn nextUniversal(self: *ScalarReader) Error!u21 {
        const scalar = std.mem.readInt(
            u32,
            self.bytes[self.pos..][0..4],
            .big,
        );
        self.pos += 4;
        if (scalar > 0x10ffff or scalar >= 0xd800 and scalar <= 0xdfff) {
            return error.InvalidDirectoryString;
        }
        return @intCast(scalar);
    }

    fn nextBmp(self: *ScalarReader) Error!u21 {
        const scalar = std.mem.readInt(
            u16,
            self.bytes[self.pos..][0..2],
            .big,
        );
        self.pos += 2;
        if (scalar >= 0xd800 and scalar <= 0xdfff) {
            return error.InvalidDirectoryString;
        }
        return @intCast(scalar);
    }
};

const MappedIterator = struct {
    input: ScalarReader,
    pending: [18]u21 = undefined,
    pending_pos: u5 = 0,
    pending_len: u5 = 0,

    fn init(value: Value) Error!MappedIterator {
        return .{ .input = try ScalarReader.init(value) };
    }

    fn next(self: *MappedIterator) Error!?u21 {
        while (true) {
            if (self.pending_pos < self.pending_len) {
                const scalar = self.pending[self.pending_pos];
                self.pending_pos += 1;
                if (isProhibited(scalar)) {
                    return error.InvalidDirectoryString;
                }
                return scalar;
            }

            const scalar = try self.input.next() orelse return null;
            self.pending_pos = 0;
            self.pending_len = 0;
            if (hangulDecomposition(scalar, &self.pending)) |len| {
                self.pending_len = len;
                continue;
            }
            if (mapping(scalar)) |mapped| {
                std.debug.assert(mapped.len <= self.pending.len);
                @memcpy(self.pending[0..mapped.len], mapped);
                self.pending_len = @intCast(mapped.len);
                continue;
            }
            if (isProhibited(scalar)) {
                return error.InvalidDirectoryString;
            }
            return scalar;
        }
    }
};

/// Emits the mapped NFKD stream in canonical combining-class order. The
/// implementation deliberately uses rescans instead of an attacker-sized
/// scratch buffer: Name Constraints are uncommon, and preserving the trust
/// verifier's allocation-free contract is more important than optimizing a
/// maliciously long combining sequence.
const CanonicalIterator = struct {
    source: MappedIterator,
    segment_start: MappedIterator = undefined,
    segment_count: usize = 0,
    segment_emitted: usize = 0,
    last_class: u8 = 0,
    last_ordinal: usize = 0,
    have_last: bool = false,
    segment_active: bool = false,

    fn init(value: Value) Error!CanonicalIterator {
        return .{ .source = try MappedIterator.init(value) };
    }

    fn next(self: *CanonicalIterator) Error!?u21 {
        while (true) {
            if (self.segment_active) {
                if (self.segment_emitted < self.segment_count) {
                    return try self.nextCombiningScalar();
                }
                self.segment_active = false;
            }

            const before_first = self.source;
            const first = try self.source.next() orelse return null;
            if (combiningClass(first) == 0) {
                try self.prepareSegment(self.source);
                return first;
            }
            try self.prepareSegment(before_first);
            // The segment contains `first`, so this cannot be empty.
            return try self.nextCombiningScalar();
        }
    }

    fn prepareSegment(
        self: *CanonicalIterator,
        start: MappedIterator,
    ) Error!void {
        var scan = start;
        var count: usize = 0;
        while (true) {
            const before = scan;
            const scalar = try scan.next() orelse {
                self.source = scan;
                break;
            };
            if (combiningClass(scalar) == 0) {
                self.source = before;
                break;
            }
            count += 1;
        }
        self.segment_start = start;
        self.segment_count = count;
        self.segment_emitted = 0;
        self.have_last = false;
        self.segment_active = count != 0;
    }

    fn nextCombiningScalar(self: *CanonicalIterator) Error!u21 {
        var scan = self.segment_start;
        var best: ?u21 = null;
        var best_class: u8 = 0;
        var best_ordinal: usize = 0;
        var ordinal: usize = 0;
        while (ordinal < self.segment_count) : (ordinal += 1) {
            const scalar = (try scan.next()) orelse unreachable;
            const class = combiningClass(scalar);
            std.debug.assert(class != 0);
            const after_last = !self.have_last or class > self.last_class or
                (class == self.last_class and ordinal > self.last_ordinal);
            if (!after_last) continue;
            if (best == null or class < best_class or
                (class == best_class and ordinal < best_ordinal))
            {
                best = scalar;
                best_class = class;
                best_ordinal = ordinal;
            }
        }
        self.have_last = true;
        self.last_class = best_class;
        self.last_ordinal = best_ordinal;
        self.segment_emitted += 1;
        return best.?;
    }
};

const Token = union(enum) {
    collapsible_space,
    scalar: u21,
};

const TokenIterator = struct {
    canonical: CanonicalIterator,
    pending: ?u21 = null,

    fn init(value: Value) Error!TokenIterator {
        return .{ .canonical = try CanonicalIterator.init(value) };
    }

    fn next(self: *TokenIterator) Error!?Token {
        const scalar = if (self.pending) |pending| blk: {
            self.pending = null;
            break :blk pending;
        } else try self.canonical.next() orelse return null;
        if (scalar != ' ') return .{ .scalar = scalar };

        const following = try self.canonical.next();
        self.pending = following;
        if (following != null and combiningClass(following.?) != 0) {
            return .{ .scalar = scalar };
        }
        return .collapsible_space;
    }
};

const PreparedIterator = struct {
    tokens: TokenIterator,
    pending: ?u21 = null,
    started: bool = false,

    fn init(value: Value) Error!PreparedIterator {
        return .{ .tokens = try TokenIterator.init(value) };
    }

    fn next(self: *PreparedIterator) Error!?u21 {
        if (self.pending) |pending| {
            self.pending = null;
            self.started = true;
            return pending;
        }
        while (try self.tokens.next()) |token| switch (token) {
            .scalar => |scalar| {
                self.started = true;
                return scalar;
            },
            .collapsible_space => {
                if (!self.started) continue;
                while (try self.tokens.next()) |following| switch (following) {
                    .collapsible_space => continue,
                    .scalar => |scalar| {
                        self.pending = scalar;
                        return ' ';
                    },
                } else return null;
            },
        };
        return null;
    }
};

fn mapping(scalar: u21) ?[]const u21 {
    var low: usize = 0;
    var high: usize = data.mappings.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const candidate = data.mappings[middle];
        const source: u21 = @intCast(candidate >> 24);
        if (scalar < source) {
            high = middle;
        } else if (scalar > source) {
            low = middle + 1;
        } else {
            const start: usize = @intCast((candidate >> 8) & 0xffff);
            const len: usize = @intCast(candidate & 0xff);
            return data.mapping_values[start .. start + len];
        }
    }
    return null;
}

fn combiningClass(scalar: u21) u8 {
    var low: usize = 0;
    var high: usize = data.combining_classes.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const candidate = data.combining_classes[middle];
        const candidate_scalar: u21 = @intCast(candidate >> 8);
        if (scalar < candidate_scalar) {
            high = middle;
        } else if (scalar > candidate_scalar) {
            low = middle + 1;
        } else {
            return @intCast(candidate & 0xff);
        }
    }
    return 0;
}

fn isProhibited(scalar: u21) bool {
    var low: usize = 0;
    var high: usize = data.prohibited_ranges.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const range = data.prohibited_ranges[middle];
        const first: u21 = @intCast(range >> 32);
        const last: u21 = @intCast(range & 0xffffffff);
        if (scalar < first) {
            high = middle;
        } else if (scalar > last) {
            low = middle + 1;
        } else {
            return true;
        }
    }
    return false;
}

fn hangulDecomposition(scalar: u21, output: *[18]u21) ?u5 {
    const s_base = 0xac00;
    const l_base = 0x1100;
    const v_base = 0x1161;
    const t_base = 0x11a7;
    const l_count = 19;
    const v_count = 21;
    const t_count = 28;
    const n_count = v_count * t_count;
    const s_count = l_count * n_count;
    if (scalar < s_base or scalar >= s_base + s_count) return null;
    const index = scalar - s_base;
    output[0] = l_base + index / n_count;
    output[1] = v_base + index % n_count / t_count;
    const trailing = index % t_count;
    if (trailing == 0) return 2;
    output[2] = t_base + trailing;
    return 3;
}

fn isPrintableStringByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z',
        'a'...'z',
        '0'...'9',
        ' ',
        '\'',
        '(',
        ')',
        '+',
        ',',
        '-',
        '.',
        '/',
        ':',
        '=',
        '?',
        => true,
        else => false,
    };
}

test "RFC 4518 caseIgnoreMatch handles case compatibility and spaces" {
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x0c, .bytes = "  Stra\xc3\x9fe  " },
        .{ .tag = 0x13, .bytes = "STRASSE" },
    ));
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x0c, .bytes = "Fullwidth \xef\xbc\xa1" },
        .{ .tag = 0x0c, .bytes = " fullwidth a " },
    ));
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x0c, .bytes = "a  b" },
        .{ .tag = 0x0c, .bytes = " A b " },
    ));
}

test "RFC 4518 caseIgnoreMatch canonicalizes combining order" {
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x0c, .bytes = "\xc3\xa9" },
        .{ .tag = 0x0c, .bytes = "e\xcc\x81" },
    ));
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x0c, .bytes = "a\xcc\x95\xcc\x80" },
        .{ .tag = 0x0c, .bytes = "A\xcc\x80\xcc\x95" },
    ));
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x0c, .bytes = "\xed\x95\x9c" },
        .{ .tag = 0x0c, .bytes = "\xe1\x84\x92\xe1\x85\xa1\xe1\x86\xab" },
    ));
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x0c, .bytes = "soft\xc2\xadhyphen" },
        .{ .tag = 0x0c, .bytes = "SOFTHYPHEN" },
    ));
    try std.testing.expect(try eqlCaseIgnore(
        .{ .tag = 0x1e, .bytes = "\x00\x41\x00\x42" },
        .{ .tag = 0x1c, .bytes = "\x00\x00\x00\x61\x00\x00\x00\x62" },
    ));
}

test "RFC 4518 rejects malformed unsupported and prohibited strings" {
    try std.testing.expectError(
        error.InvalidDirectoryString,
        validate(.{ .tag = 0x0c, .bytes = "\xff" }),
    );
    try std.testing.expectError(
        error.UnsupportedDirectoryString,
        validate(.{ .tag = 0x14, .bytes = "legacy" }),
    );
    try std.testing.expectError(
        error.InvalidDirectoryString,
        validate(.{ .tag = 0x0c, .bytes = "\xef\xbf\xbd" }),
    );
    // U+0221 was unassigned in Unicode 3.2 and remains prohibited even if a
    // newer Unicode release assigns it.
    try std.testing.expectError(
        error.InvalidDirectoryString,
        validate(.{ .tag = 0x0c, .bytes = "\xc8\xa1" }),
    );
}

test "RFC 4518 generated tables are sorted and internally bounded" {
    var previous_mapping: u21 = 0;
    for (data.mappings, 0..) |entry, index| {
        const source: u21 = @intCast(entry >> 24);
        const offset: usize = @intCast((entry >> 8) & 0xffff);
        const len: usize = @intCast(entry & 0xff);
        if (index != 0) try std.testing.expect(source > previous_mapping);
        try std.testing.expect(offset + len <= data.mapping_values.len);
        previous_mapping = source;
    }
    var previous_combining: u21 = 0;
    for (data.combining_classes, 0..) |entry, index| {
        const scalar: u21 = @intCast(entry >> 8);
        if (index != 0) try std.testing.expect(scalar > previous_combining);
        try std.testing.expect(entry & 0xff != 0);
        previous_combining = scalar;
    }
    var previous_last: u21 = 0;
    for (data.prohibited_ranges, 0..) |entry, index| {
        const first: u21 = @intCast(entry >> 32);
        const last: u21 = @intCast(entry & 0xffffffff);
        try std.testing.expect(first <= last);
        if (index != 0) try std.testing.expect(first > previous_last + 1);
        previous_last = last;
    }
}
