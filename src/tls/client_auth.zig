//! TLS 1.3 CertificateRequest codec and mTLS policy types.

const std = @import("std");
const auth = @import("auth.zig");

pub const handshake_type_certificate_request: u8 = 0x0d;
const ext_signature_algorithms: u16 = 0x000d;
const ext_certificate_authorities: u16 = 0x002f;

pub const Error = std.mem.Allocator.Error || error{
    InvalidCertificateRequest,
    UnsupportedSignatureScheme,
    ClientCertificateRequired,
};

pub const ClientIdentity = auth.ServerIdentity;

pub const ServerPolicy = struct {
    verifier: auth.ClientVerifier,
    certificate_authorities: []const []const u8 = &.{},
};

pub const ParsedRequest = struct {
    request_context: []const u8,
    supports_ed25519: bool,
    supports_ecdsa_p256_sha256: bool,
};

pub fn writeRequest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    request_context: []const u8,
    certificate_authorities: []const []const u8,
) Error!void {
    if (request_context.len > std.math.maxInt(u8)) {
        return error.InvalidCertificateRequest;
    }
    const original_len = list.items.len;
    errdefer list.items.len = original_len;

    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    try appendInt(&extensions, allocator, u16, ext_signature_algorithms);
    try appendInt(&extensions, allocator, u16, 6);
    try appendInt(&extensions, allocator, u16, 4);
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_ecdsa_secp256r1_sha256,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_ed25519,
    );
    if (certificate_authorities.len != 0) {
        var authorities: std.ArrayList(u8) = .empty;
        defer authorities.deinit(allocator);
        for (certificate_authorities) |subject| {
            if (subject.len == 0 or subject.len > std.math.maxInt(u16)) {
                return error.InvalidCertificateRequest;
            }
            try appendInt(
                &authorities,
                allocator,
                u16,
                subject.len,
            );
            try authorities.appendSlice(allocator, subject);
        }
        if (authorities.items.len > std.math.maxInt(u16)) {
            return error.InvalidCertificateRequest;
        }
        try appendInt(
            &extensions,
            allocator,
            u16,
            ext_certificate_authorities,
        );
        try appendInt(
            &extensions,
            allocator,
            u16,
            2 + authorities.items.len,
        );
        try appendInt(
            &extensions,
            allocator,
            u16,
            authorities.items.len,
        );
        try extensions.appendSlice(allocator, authorities.items);
    }
    if (extensions.items.len > std.math.maxInt(u16)) {
        return error.InvalidCertificateRequest;
    }

    const body_len = 1 + request_context.len + 2 + extensions.items.len;
    if (body_len > std.math.maxInt(u24)) {
        return error.InvalidCertificateRequest;
    }
    try list.append(allocator, handshake_type_certificate_request);
    var body_len_bytes: [3]u8 = undefined;
    writeU24(&body_len_bytes, @intCast(body_len));
    try list.appendSlice(allocator, &body_len_bytes);
    try list.append(allocator, @intCast(request_context.len));
    try list.appendSlice(allocator, request_context);
    try appendInt(
        list,
        allocator,
        u16,
        extensions.items.len,
    );
    try list.appendSlice(allocator, extensions.items);
}

pub fn parseRequest(bytes: []const u8) Error!ParsedRequest {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_certificate_request) {
        return error.InvalidCertificateRequest;
    }
    const body_len = try readU24At(bytes, &pos);
    if (body_len != bytes.len - pos) {
        return error.InvalidCertificateRequest;
    }
    const context_len = try readByte(bytes, &pos);
    const request_context = try readSlice(bytes, &pos, context_len);
    const extensions_len = try readInt(u16, bytes, &pos);
    const extensions = try readSlice(bytes, &pos, extensions_len);
    if (pos != bytes.len) return error.InvalidCertificateRequest;

    var supports_ed25519 = false;
    var supports_ecdsa = false;
    var saw_signature_algorithms = false;
    var ext_pos: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const len = try readInt(u16, extensions, &ext_pos);
        const payload = try readSlice(extensions, &ext_pos, len);
        if (typ == ext_signature_algorithms) {
            if (saw_signature_algorithms) {
                return error.InvalidCertificateRequest;
            }
            saw_signature_algorithms = true;
            var scheme_pos: usize = 0;
            const schemes_len = try readInt(u16, payload, &scheme_pos);
            if (schemes_len == 0 or schemes_len % 2 != 0 or
                schemes_len != payload.len - scheme_pos)
            {
                return error.InvalidCertificateRequest;
            }
            while (scheme_pos < payload.len) {
                const scheme = try readInt(u16, payload, &scheme_pos);
                if (scheme == auth.signature_scheme_ed25519) {
                    supports_ed25519 = true;
                }
                if (scheme ==
                    auth.signature_scheme_ecdsa_secp256r1_sha256)
                {
                    supports_ecdsa = true;
                }
            }
        } else if (typ == ext_certificate_authorities) {
            var ca_pos: usize = 0;
            const names_len = try readInt(u16, payload, &ca_pos);
            if (names_len != payload.len - ca_pos) {
                return error.InvalidCertificateRequest;
            }
            while (ca_pos < payload.len) {
                const name_len = try readInt(u16, payload, &ca_pos);
                if (name_len == 0) return error.InvalidCertificateRequest;
                _ = try readSlice(payload, &ca_pos, name_len);
            }
        } else {
            return error.InvalidCertificateRequest;
        }
    }
    if (!saw_signature_algorithms) {
        return error.InvalidCertificateRequest;
    }
    return .{
        .request_context = request_context,
        .supports_ed25519 = supports_ed25519,
        .supports_ecdsa_p256_sha256 = supports_ecdsa,
    };
}

fn appendInt(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: anytype,
) std.mem.Allocator.Error!void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .big);
    try list.appendSlice(allocator, &bytes);
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    if (pos.* >= bytes.len) return error.InvalidCertificateRequest;
    const result = bytes[pos.*];
    pos.* += 1;
    return result;
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) Error!T {
    const slice = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, slice[0..@sizeOf(T)], .big);
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch
        return error.InvalidCertificateRequest;
    if (end > bytes.len) return error.InvalidCertificateRequest;
    const result = bytes[pos.*..end];
    pos.* = end;
    return result;
}

fn readU24At(bytes: []const u8, pos: *usize) Error!usize {
    const slice = try readSlice(bytes, pos, 3);
    return (@as(usize, slice[0]) << 16) |
        (@as(usize, slice[1]) << 8) |
        slice[2];
}

fn writeU24(bytes: *[3]u8, value: u24) void {
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}
