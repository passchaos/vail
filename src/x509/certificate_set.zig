//! Strict, allocation-free parsing of AIA caIssuers response bodies.
//!
//! RFC 5280 permits either one DER Certificate or a DER/BER certs-only CMS
//! SignedData object. The default parser accepts strict definite-length DER;
//! `parseBer` additionally accepts bounded indefinite-length constructed CMS
//! wrappers. Both yield borrowed, deduplicated X.509 certificate slices.

const std = @import("std");
const certificate_compat = @import("certificate.zig");

const oid_signed_data = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
};
const oid_data = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
};

pub const max_certificates = 32;
pub const max_ber_depth = 8;
pub const max_ber_elements = 256;

pub const Error = error{
    InvalidCertificateResponse,
    TooManyCertificates,
};

pub const Certificates = struct {
    encoded: []const u8,
    offset: usize = 0,
    single_pending: bool = false,
    seen: [max_certificates][]const u8 = undefined,
    seen_count: usize = 0,
    previous: ?[]const u8 = null,
    require_der_order: bool = true,

    pub fn next(self: *Certificates) Error!?[]const u8 {
        if (self.single_pending) {
            self.single_pending = false;
            self.seen[0] = self.encoded;
            self.seen_count = 1;
            return self.encoded;
        }
        certificate_loop: while (self.offset < self.encoded.len) {
            var reader = Reader{ .bytes = self.encoded, .offset = self.offset };
            const certificate = (try reader.next()) orelse unreachable;
            self.offset = reader.offset;
            if (certificate.tag != 0x30) {
                return error.InvalidCertificateResponse;
            }
            const der = self.encoded[certificate.start..certificate.end];
            _ = certificate_compat.parse(der) catch
                return error.InvalidCertificateResponse;
            if (self.require_der_order and self.previous != null) {
                const previous = self.previous.?;
                if (std.mem.order(u8, previous, der) == .gt) {
                    return error.InvalidCertificateResponse;
                }
            }
            self.previous = der;
            for (self.seen[0..self.seen_count]) |prior| {
                if (std.mem.eql(u8, prior, der)) continue :certificate_loop;
            }
            if (self.seen_count == self.seen.len) {
                return error.TooManyCertificates;
            }
            self.seen[self.seen_count] = der;
            self.seen_count += 1;
            return der;
        }
        return null;
    }
};

pub fn parse(encoded: []const u8) Error!Certificates {
    if (looksLikeDerCertificate(encoded)) {
        if (certificate_compat.parse(encoded)) |_| {
            return .{ .encoded = encoded, .single_pending = true };
        } else |_| {}
    }

    const certificates = try parseCertsOnlySignedData(encoded);
    const result = Certificates{ .encoded = certificates };
    var validation = result;
    var count: usize = 0;
    while (try validation.next()) |_| count += 1;
    if (count == 0) return error.InvalidCertificateResponse;
    return result;
}

/// Parse a single DER certificate or a certs-only CMS response whose
/// constructed wrappers may use BER indefinite lengths. Primitive values and
/// embedded X.509 certificates remain strict DER.
pub fn parseBer(encoded: []const u8) Error!Certificates {
    if (looksLikeDerCertificate(encoded)) {
        if (certificate_compat.parse(encoded)) |_| {
            return .{ .encoded = encoded, .single_pending = true };
        } else |_| {}
    }

    const certificates = try parseCertsOnlySignedDataBer(encoded);
    const result = Certificates{
        .encoded = certificates,
        .require_der_order = false,
    };
    var validation = result;
    var count: usize = 0;
    while (try validation.next()) |_| count += 1;
    if (count == 0) return error.InvalidCertificateResponse;
    return result;
}

fn looksLikeDerCertificate(encoded: []const u8) bool {
    const certificate = singleInner(encoded, 0x30) catch return false;
    var outer = Reader{ .bytes = certificate.value };
    const tbs = outer.require(0x30) catch return false;
    _ = outer.require(0x30) catch return false;
    _ = outer.require(0x03) catch return false;
    if ((outer.next() catch return false) != null) return false;

    var fields = Reader{ .bytes = tbs.value };
    var serial = (fields.next() catch return false) orelse return false;
    if (serial.tag == 0xa0) {
        serial = (fields.next() catch return false) orelse return false;
    }
    if (serial.tag != 0x02) return false;
    inline for ([_]u8{ 0x30, 0x30, 0x30, 0x30, 0x30 }) |tag| {
        _ = fields.require(tag) catch return false;
    }
    return true;
}

fn parseCertsOnlySignedData(encoded: []const u8) Error![]const u8 {
    const content_info = try singleInner(encoded, 0x30);
    var content_fields = Reader{ .bytes = content_info.value };
    const content_type = try content_fields.require(0x06);
    if (!std.mem.eql(u8, content_type.value, &oid_signed_data)) {
        return error.InvalidCertificateResponse;
    }
    const explicit = try content_fields.require(0xa0);
    if (try content_fields.next() != null) {
        return error.InvalidCertificateResponse;
    }
    const signed_data = try singleInner(explicit.value, 0x30);
    var fields = Reader{ .bytes = signed_data.value };
    const version = try fields.require(0x02);
    if (!std.mem.eql(u8, version.value, &.{0x01})) {
        return error.InvalidCertificateResponse;
    }
    const digest_algorithms = try fields.require(0x31);
    if (digest_algorithms.value.len != 0) {
        return error.InvalidCertificateResponse;
    }
    const encapsulated = try fields.require(0x30);
    var encapsulated_fields = Reader{ .bytes = encapsulated.value };
    const data_type = try encapsulated_fields.require(0x06);
    if (!std.mem.eql(u8, data_type.value, &oid_data) or
        try encapsulated_fields.next() != null)
    {
        return error.InvalidCertificateResponse;
    }
    const certificates = try fields.require(0xa0);
    if (certificates.value.len == 0) {
        return error.InvalidCertificateResponse;
    }
    const signer_infos = try fields.require(0x31);
    if (signer_infos.value.len != 0 or try fields.next() != null) {
        return error.InvalidCertificateResponse;
    }
    return certificates.value;
}

fn parseCertsOnlySignedDataBer(encoded: []const u8) Error![]const u8 {
    var element_count: usize = 0;
    const content_info = try singleInnerBer(
        encoded,
        0x30,
        &element_count,
        0,
    );
    var content_fields = BerReader{
        .bytes = content_info.value,
        .element_count = &element_count,
        .depth = 1,
    };
    const content_type = try content_fields.require(0x06);
    if (!std.mem.eql(u8, content_type.value, &oid_signed_data)) {
        return error.InvalidCertificateResponse;
    }
    const explicit = try content_fields.require(0xa0);
    if (try content_fields.next() != null) {
        return error.InvalidCertificateResponse;
    }
    const signed_data = try singleInnerBer(
        explicit.value,
        0x30,
        &element_count,
        2,
    );
    var fields = BerReader{
        .bytes = signed_data.value,
        .element_count = &element_count,
        .depth = 3,
    };
    const version = try fields.require(0x02);
    if (!std.mem.eql(u8, version.value, &.{0x01})) {
        return error.InvalidCertificateResponse;
    }
    const digest_algorithms = try fields.require(0x31);
    if (digest_algorithms.value.len != 0) {
        return error.InvalidCertificateResponse;
    }
    const encapsulated = try fields.require(0x30);
    var encapsulated_fields = BerReader{
        .bytes = encapsulated.value,
        .element_count = &element_count,
        .depth = 4,
    };
    const data_type = try encapsulated_fields.require(0x06);
    if (!std.mem.eql(u8, data_type.value, &oid_data) or
        try encapsulated_fields.next() != null)
    {
        return error.InvalidCertificateResponse;
    }
    const certificates = try fields.require(0xa0);
    if (certificates.value.len == 0) {
        return error.InvalidCertificateResponse;
    }
    const signer_infos = try fields.require(0x31);
    if (signer_infos.value.len != 0 or try fields.next() != null) {
        return error.InvalidCertificateResponse;
    }
    return certificates.value;
}

const Element = struct {
    tag: u8,
    start: usize,
    end: usize,
    value: []const u8,
};

fn singleInner(encoded: []const u8, tag: u8) Error!Element {
    var reader = Reader{ .bytes = encoded };
    const element = try reader.require(tag);
    if (try reader.next() != null) return error.InvalidCertificateResponse;
    return element;
}

fn singleInnerBer(
    encoded: []const u8,
    tag: u8,
    element_count: *usize,
    depth: usize,
) Error!Element {
    var reader = BerReader{
        .bytes = encoded,
        .element_count = element_count,
        .depth = depth,
    };
    const element = try reader.require(tag);
    if (try reader.next() != null) return error.InvalidCertificateResponse;
    return element;
}

const BerReader = struct {
    bytes: []const u8,
    element_count: *usize,
    depth: usize,
    offset: usize = 0,

    fn next(self: *BerReader) Error!?Element {
        if (self.offset == self.bytes.len) return null;
        const element = try parseBerElement(
            self.bytes,
            self.offset,
            self.depth,
            self.element_count,
        );
        self.offset = element.end;
        return element;
    }

    fn require(self: *BerReader, tag: u8) Error!Element {
        const value = (try self.next()) orelse
            return error.InvalidCertificateResponse;
        if (value.tag != tag) return error.InvalidCertificateResponse;
        return value;
    }
};

fn parseBerElement(
    bytes: []const u8,
    start: usize,
    depth: usize,
    element_count: *usize,
) Error!Element {
    if (depth > max_ber_depth or element_count.* >= max_ber_elements) {
        return error.InvalidCertificateResponse;
    }
    element_count.* += 1;
    if (start + 2 > bytes.len) return error.InvalidCertificateResponse;
    const tag = bytes[start];
    if (tag == 0 or tag & 0x1f == 0x1f) {
        return error.InvalidCertificateResponse;
    }
    const first = bytes[start + 1];
    var content_start = start + 2;
    if (first == 0x80) {
        if ((tag & 0x20) == 0) return error.InvalidCertificateResponse;
        var cursor = content_start;
        while (true) {
            if (cursor + 2 > bytes.len) {
                return error.InvalidCertificateResponse;
            }
            if (bytes[cursor] == 0 and bytes[cursor + 1] == 0) {
                return .{
                    .tag = tag,
                    .start = start,
                    .end = cursor + 2,
                    .value = bytes[content_start..cursor],
                };
            }
            cursor = (try parseBerElement(
                bytes,
                cursor,
                depth + 1,
                element_count,
            )).end;
        }
    }

    var length: usize = 0;
    if (first < 0x80) {
        length = first;
    } else {
        const count: usize = first & 0x7f;
        if (count == 0 or count > @sizeOf(usize) or
            count > bytes.len - content_start or bytes[content_start] == 0)
        {
            return error.InvalidCertificateResponse;
        }
        for (bytes[content_start .. content_start + count]) |byte| {
            length = std.math.mul(usize, length, 256) catch
                return error.InvalidCertificateResponse;
            length = std.math.add(usize, length, byte) catch
                return error.InvalidCertificateResponse;
        }
        content_start += count;
        if (length < 128) return error.InvalidCertificateResponse;
    }
    const end = std.math.add(usize, content_start, length) catch
        return error.InvalidCertificateResponse;
    if (end > bytes.len) return error.InvalidCertificateResponse;
    return .{
        .tag = tag,
        .start = start,
        .end = end,
        .value = bytes[content_start..end],
    };
}

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn next(self: *Reader) Error!?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) {
            return error.InvalidCertificateResponse;
        }
        const start = self.offset;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if (tag & 0x1f == 0x1f) return error.InvalidCertificateResponse;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var len: usize = 0;
        if (first < 0x80) {
            len = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidCertificateResponse;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                len = std.math.mul(usize, len, 256) catch
                    return error.InvalidCertificateResponse;
                len = std.math.add(usize, len, byte) catch
                    return error.InvalidCertificateResponse;
            }
            self.offset += count;
            if (len < 128) return error.InvalidCertificateResponse;
        }
        const end = std.math.add(usize, self.offset, len) catch
            return error.InvalidCertificateResponse;
        if (end > self.bytes.len) return error.InvalidCertificateResponse;
        const value = self.bytes[self.offset..end];
        self.offset = end;
        return .{ .tag = tag, .start = start, .end = end, .value = value };
    }

    fn require(self: *Reader, tag: u8) Error!Element {
        const value = (try self.next()) orelse
            return error.InvalidCertificateResponse;
        if (value.tag != tag) return error.InvalidCertificateResponse;
        return value;
    }
};

test "single DER certificate response is yielded once" {
    const certificate = @embedFile("testdata/ca.der");
    var certificates = try parse(certificate);
    try std.testing.expectEqualSlices(u8, certificate, (try certificates.next()).?);
    try std.testing.expect(try certificates.next() == null);
}

test "OpenSSL CMS certs-only response is strict and deduplicated" {
    const vectors = @import("testdata/path_vectors.zig");
    const cms = decodeHex(vectors.aia_ca_issuers_certs_only_hex);
    const certificate = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    var certificates = try parse(&cms);
    try std.testing.expectEqualSlices(
        u8,
        &certificate,
        (try certificates.next()).?,
    );
    try std.testing.expect(try certificates.next() == null);

    var malformed = cms;
    // SignedData digestAlgorithms must remain the empty SET in certs-only
    // content. Turning it into an empty SEQUENCE is structurally invalid.
    const empty_set = std.mem.indexOf(u8, &malformed, "\x31\x00") orelse
        return error.TestUnexpectedResult;
    malformed[empty_set] = 0x30;
    try std.testing.expectError(
        error.InvalidCertificateResponse,
        parse(&malformed),
    );

    var unsorted = cms;
    const first = std.mem.indexOf(u8, &unsorted, &certificate) orelse
        return error.TestUnexpectedResult;
    const second = std.mem.indexOfPos(
        u8,
        &unsorted,
        first + certificate.len,
        &certificate,
    ) orelse return error.TestUnexpectedResult;
    _ = second;
    unsorted[first + certificate.len - 1] = 0xff;
    try std.testing.expectError(
        error.InvalidCertificateResponse,
        parse(&unsorted),
    );
}

test "BER certs-only accepts bounded indefinite constructed wrappers" {
    const vectors = @import("testdata/path_vectors.zig");
    const cms = decodeHex(vectors.aia_ca_issuers_certs_only_hex);
    const certificate = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    const ber = try indefiniteCms(std.testing.allocator, &cms);
    defer std.testing.allocator.free(ber);

    try std.testing.expectError(
        error.InvalidCertificateResponse,
        parse(ber),
    );
    var certificates = try parseBer(ber);
    try std.testing.expectEqualSlices(
        u8,
        &certificate,
        (try certificates.next()).?,
    );
    try std.testing.expect(try certificates.next() == null);

    try std.testing.expectError(
        error.InvalidCertificateResponse,
        parseBer(ber[0 .. ber.len - 1]),
    );
    try std.testing.expectError(
        error.InvalidCertificateResponse,
        parseBer("\x30\x80\x06\x80\x00\x00\x00\x00"),
    );

    var nested: [2 * (max_ber_depth + 2) + 2 * (max_ber_depth + 2)]u8 =
        undefined;
    for (0..max_ber_depth + 2) |index| {
        nested[index * 2 ..][0..2].* = .{ 0x30, 0x80 };
        const end = nested.len - (index + 1) * 2;
        nested[end..][0..2].* = .{ 0, 0 };
    }
    var element_count: usize = 0;
    try std.testing.expectError(
        error.InvalidCertificateResponse,
        singleInnerBer(&nested, 0x30, &element_count, 0),
    );

    var numerous: [2 * max_ber_elements + 4]u8 = undefined;
    numerous[0..2].* = .{ 0x30, 0x80 };
    for (0..max_ber_elements) |index| {
        numerous[2 + index * 2 ..][0..2].* = .{ 0x30, 0x00 };
    }
    numerous[numerous.len - 2 ..].* = .{ 0, 0 };
    element_count = 0;
    try std.testing.expectError(
        error.InvalidCertificateResponse,
        singleInnerBer(&numerous, 0x30, &element_count, 0),
    );
}

fn indefiniteCms(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) ![]u8 {
    const content_info = try singleInner(encoded, 0x30);
    var content_fields = Reader{ .bytes = content_info.value };
    const content_type = try content_fields.require(0x06);
    const explicit = try content_fields.require(0xa0);
    const signed_data = try singleInner(explicit.value, 0x30);
    var fields = Reader{ .bytes = signed_data.value };
    const version = try fields.require(0x02);
    _ = try fields.require(0x31);
    const encapsulated = try fields.require(0x30);
    var encapsulated_fields = Reader{ .bytes = encapsulated.value };
    const data_type = try encapsulated_fields.require(0x06);
    const certificates = try fields.require(0xa0);
    _ = try fields.require(0x31);

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "\x30\x80");
    try result.appendSlice(
        allocator,
        content_info.value[content_type.start..content_type.end],
    );
    try result.appendSlice(allocator, "\xa0\x80\x30\x80");
    try result.appendSlice(
        allocator,
        signed_data.value[version.start..version.end],
    );
    try result.appendSlice(allocator, "\x31\x80\x00\x00\x30\x80");
    try result.appendSlice(
        allocator,
        encapsulated.value[data_type.start..data_type.end],
    );
    try result.appendSlice(allocator, "\x00\x00\xa0\x80");
    try result.appendSlice(allocator, certificates.value);
    try result.appendSlice(
        allocator,
        "\x00\x00\x31\x80\x00\x00" ++
            "\x00\x00\x00\x00\x00\x00",
    );
    return result.toOwnedSlice(allocator);
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
