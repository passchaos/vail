//! QUIC transport-parameters TLS extension helpers.
//!
//! The QUIC transport owns the parameter schema and semantic validation. Vail
//! only needs a small, allocation-free extension codec so a TLS-over-QUIC
//! driver can put already-encoded transport parameters into ClientHello and
//! EncryptedExtensions without duplicating TLS extension framing.

const std = @import("std");

pub const extension_type: u16 = 0x0039;

pub const Error = std.mem.Allocator.Error || error{
    TransportParametersTooLarge,
    InvalidTransportParametersExtension,
};

pub fn appendExtension(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    encoded_transport_parameters: []const u8,
) Error!void {
    if (encoded_transport_parameters.len > std.math.maxInt(u16)) {
        return error.TransportParametersTooLarge;
    }
    try appendInt(out, allocator, u16, extension_type);
    try appendInt(
        out,
        allocator,
        u16,
        @as(u16, @intCast(encoded_transport_parameters.len)),
    );
    try out.appendSlice(allocator, encoded_transport_parameters);
}

pub fn parseExtension(payload: []const u8) []const u8 {
    return payload;
}

pub fn findExtension(extension_block: []const u8) Error!?[]const u8 {
    var pos: usize = 0;
    while (pos < extension_block.len) {
        if (pos + 4 > extension_block.len) {
            return error.InvalidTransportParametersExtension;
        }
        const typ = std.mem.readInt(u16, extension_block[pos..][0..2], .big);
        pos += 2;
        const len = std.mem.readInt(u16, extension_block[pos..][0..2], .big);
        pos += 2;
        if (pos + len > extension_block.len) {
            return error.InvalidTransportParametersExtension;
        }
        const payload = extension_block[pos .. pos + len];
        pos += len;
        if (typ == extension_type) return payload;
    }
    return null;
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try out.appendSlice(allocator, &bytes);
}

test "QUIC transport parameters extension frames opaque bytes" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try appendExtension(
        &out,
        std.testing.allocator,
        &.{ 0x00, 0x01, 0x02, 0x03 },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x00, 0x39, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03 },
        out.items,
    );
    const found = (try findExtension(out.items)).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x03 }, found);
}
