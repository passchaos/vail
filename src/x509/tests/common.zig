//! Shared helpers for X.509 tests.

const std = @import("std");

pub fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

pub const AiaPathFetchContext = struct {
    intermediate_cms: []const u8,
    root: []const u8,
    calls: usize = 0,

    pub fn fetch(
        opaque_context: ?*anyopaque,
        uri: []const u8,
        output: []u8,
    ) anyerror!?usize {
        const self: *@This() = @ptrCast(@alignCast(
            opaque_context orelse return error.MissingTestContext,
        ));
        const response = if (std.mem.eql(
            u8,
            uri,
            "http://aia.example.test/intermediate.p7c",
        ))
            self.intermediate_cms
        else if (std.mem.eql(
            u8,
            uri,
            "http://aia.example.test/root.der",
        ))
            self.root
        else
            return error.UnexpectedIssuerUrl;
        self.calls += 1;
        if (response.len > output.len) return error.BufferTooSmall;
        @memcpy(output[0..response.len], response);
        return response.len;
    }
};

pub fn pemCertificate(
    allocator: std.mem.Allocator,
    certificate_der: []const u8,
) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    const encoded_start = result.items.len;
    try result.resize(allocator, encoded_start + encoded_len);
    _ = std.base64.standard.Encoder.encode(
        result.items[encoded_start..],
        certificate_der,
    );
    try result.appendSlice(allocator, "\n-----END CERTIFICATE-----\n");
    return result.toOwnedSlice(allocator);
}
