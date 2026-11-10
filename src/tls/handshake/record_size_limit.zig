//! RFC 8449 TLS record size limit negotiation.
//!
//! The advertised value bounds the peer's TLSPlaintext or TLSInnerPlaintext.
//! TLS 1.3 therefore reserves one byte for the inner content type when
//! deriving the maximum unpadded application-data fragment.

const std = @import("std");

pub const extension_type: u16 = 0x001c;
pub const min: u16 = 64;
pub const max: u16 = (1 << 14) + 1;
pub const tls13_tag_len: usize = 16;

pub const Error = error{InvalidRecordSizeLimit};

pub fn validate(value: u16) Error!u16 {
    if (value < min or value > max) return error.InvalidRecordSizeLimit;
    return value;
}

pub fn validateTls12(value: u16) Error!u16 {
    const valid = try validate(value);
    if (valid > 1 << 14) return error.InvalidRecordSizeLimit;
    return valid;
}

pub fn parse(payload: []const u8) Error!u16 {
    if (payload.len != 2) return error.InvalidRecordSizeLimit;
    return validate(std.mem.readInt(u16, payload[0..2], .big));
}

pub fn encode(value: u16) Error![2]u8 {
    const valid = try validate(value);
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, valid, .big);
    return bytes;
}

pub fn maxApplicationData(value: u16) Error!usize {
    return @as(usize, try validate(value)) - 1;
}

pub fn maxCiphertextFragment(value: u16) Error!usize {
    return maxCiphertextFragmentWithTag(value, tls13_tag_len);
}

/// Convert an RFC 8449 TLSInnerPlaintext limit to the corresponding
/// TLSCiphertext fragment limit for the negotiated AEAD tag size.
pub fn maxCiphertextFragmentWithTag(
    value: u16,
    tag_length: usize,
) Error!usize {
    return @as(usize, try validate(value)) + tag_length;
}

test "RFC 8449 record size limit validates exact wire bounds" {
    try std.testing.expectEqual(min, try parse(&.{ 0, min }));
    try std.testing.expectEqual(max, try parse(&.{ 0x40, 0x01 }));
    try std.testing.expectEqualSlices(u8, &.{ 0x04, 0x00 }, &(try encode(1024)));
    try std.testing.expectEqual(@as(usize, 1023), try maxApplicationData(1024));
    try std.testing.expectEqual(@as(usize, 1040), try maxCiphertextFragment(1024));
    try std.testing.expectEqual(
        @as(usize, 1032),
        try maxCiphertextFragmentWithTag(1024, 8),
    );
    try std.testing.expectError(error.InvalidRecordSizeLimit, parse(&.{0}));
    try std.testing.expectError(error.InvalidRecordSizeLimit, parse(&.{ 0, 63 }));
    try std.testing.expectError(
        error.InvalidRecordSizeLimit,
        parse(&.{ 0x40, 0x02 }),
    );
    try std.testing.expectEqual(@as(u16, 1 << 14), try validateTls12(1 << 14));
    try std.testing.expectError(
        error.InvalidRecordSizeLimit,
        validateTls12(max),
    );
}
