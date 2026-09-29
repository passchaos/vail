//! TLS 1.3 CertificateRequest codec and mTLS policy types.

const std = @import("std");
const auth = @import("auth.zig");
const certificate_compression = @import("certificate_compression.zig");
const key_schedule = @import("key_schedule.zig");
const secret = @import("secret.zig");
const transcript = @import("transcript.zig");

pub const handshake_type_certificate_request: u8 = 0x0d;
const ext_signature_algorithms: u16 = 0x000d;
const ext_certificate_authorities: u16 = 0x002f;
const ext_compress_certificate: u16 =
    certificate_compression.extension_type_compress_certificate;

pub const Error = std.mem.Allocator.Error || auth.Error ||
    certificate_compression.Error || key_schedule.Error || secret.Error || error{
    BadClientFinished,
    InvalidClientFlight,
    InvalidCertificateRequest,
    UnsupportedSignatureScheme,
    ClientCertificateRequired,
};

pub const ClientIdentity = struct {
    certificate_chain: []const []const u8,
    signer: auth.Signer,
    certificate_type: auth.CertificateType = .x509,
    compressed_certificates: []const certificate_compression.PreparedView = &.{},

    pub fn validate(self: ClientIdentity) auth.Error!void {
        try (auth.ServerIdentity{
            .certificate_chain = self.certificate_chain,
            .signer = self.signer,
            .certificate_type = self.certificate_type,
        }).validate();
    }
};

pub const Requirement = enum {
    /// Abort the handshake when the client returns an empty Certificate list.
    required,
    /// Request a certificate, but allow an anonymous client to return the
    /// TLS 1.3 empty Certificate message and continue with Finished.
    optional,
};

pub const ServerPolicy = struct {
    verifier: auth.ClientVerifier,
    certificate_authorities: []const []const u8 = &.{},
    requirement: Requirement = .required,
    certificate_type: auth.CertificateType = .x509,
};

pub const ParsedRequest = struct {
    request_context: []const u8,
    supports_ed25519: bool,
    supports_ecdsa_p256_sha256: bool,
    supports_ecdsa_p384_sha384: bool,
    supports_rsa_pss_rsae_sha256: bool,
    supports_rsa_pss_rsae_sha384: bool,
    supports_rsa_pss_rsae_sha512: bool,
    supports_rsa_pss_pss_sha256: bool,
    supports_rsa_pss_pss_sha384: bool,
    supports_rsa_pss_pss_sha512: bool,
    supports_sm2sig_sm3: bool,
    certificate_compression_algorithms: []const u8,

    pub fn supportsCertificateCompression(
        self: ParsedRequest,
        algorithm: certificate_compression.Algorithm,
    ) bool {
        var pos: usize = 0;
        while (pos < self.certificate_compression_algorithms.len) : (pos += 2) {
            const offered: certificate_compression.Algorithm = @enumFromInt(
                std.mem.readInt(
                    u16,
                    self.certificate_compression_algorithms[pos..][0..2],
                    .big,
                ),
            );
            if (offered == algorithm) return true;
        }
        return false;
    }
};

pub const Verification = struct {
    certificate: auth.ParsedCertificate,
    decompressed_certificate_message: ?[]u8 = null,
    certificate_compression: ?certificate_compression.Algorithm = null,
    transcript_after_client_finished: transcript.Digest,

    pub fn deinit(
        self: *Verification,
        allocator: std.mem.Allocator,
    ) void {
        self.certificate.deinit(allocator);
        if (self.decompressed_certificate_message) |message| {
            allocator.free(message);
        }
        self.* = undefined;
    }

    pub fn authenticated(self: Verification) bool {
        return self.certificate.entries.len != 0;
    }
};

/// Verify the client's response to a handshake-time CertificateRequest.
///
/// The caller supplies exact encoded handshake messages because every byte is
/// transcript-bound. Certificate entries borrow their DER bytes from
/// `certificate_bytes`; only the entry index is allocated and owned by the
/// returned value.
pub fn verifyClientFlight(
    allocator: std.mem.Allocator,
    policy: ServerPolicy,
    request_context: []const u8,
    transcript_after_server_finished: transcript.State,
    client_handshake_traffic_secret: secret.Secret,
    certificate_bytes: []const u8,
    certificate_verify_bytes: ?[]const u8,
    finished_bytes: []const u8,
) Error!Verification {
    return verifyClientFlightWithCompression(
        allocator,
        policy,
        request_context,
        transcript_after_server_finished,
        client_handshake_traffic_secret,
        certificate_bytes,
        certificate_verify_bytes,
        finished_bytes,
        &.{},
        64 * 1024,
    );
}

pub fn verifyClientFlightWithCompression(
    allocator: std.mem.Allocator,
    policy: ServerPolicy,
    request_context: []const u8,
    transcript_after_server_finished: transcript.State,
    client_handshake_traffic_secret: secret.Secret,
    certificate_bytes: []const u8,
    certificate_verify_bytes: ?[]const u8,
    finished_bytes: []const u8,
    accepted_compression_algorithms: []const certificate_compression.Algorithm,
    max_decompressed_certificate_len: usize,
) Error!Verification {
    var decompressed_certificate_message: ?[]u8 = null;
    errdefer if (decompressed_certificate_message) |message| {
        allocator.free(message);
    };
    var selected_certificate_compression: ?certificate_compression.Algorithm = null;
    const certificate_message = if (certificate_bytes.len != 0 and
        certificate_bytes[0] ==
            certificate_compression.handshake_type_compressed_certificate)
    blk: {
        selected_certificate_compression =
            (try certificate_compression.parse(certificate_bytes)).algorithm;
        decompressed_certificate_message =
            try certificate_compression.decompressCertificate(
                allocator,
                certificate_bytes,
                accepted_compression_algorithms,
                max_decompressed_certificate_len,
            );
        break :blk decompressed_certificate_message.?;
    } else certificate_bytes;
    var certificate = try auth.parseClientCertificateWithContext(
        allocator,
        certificate_message,
        request_context,
    );
    errdefer certificate.deinit(allocator);

    var state = transcript_after_server_finished;
    state.update(certificate_bytes);
    if (certificate.entries.len == 0) {
        if (policy.requirement == .required) {
            return error.ClientCertificateRequired;
        }
        if (certificate_verify_bytes != null) {
            return error.InvalidClientFlight;
        }
    } else {
        if (policy.certificate_type == .raw_public_key) {
            if (certificate.ocsp_response != null) {
                return error.InvalidClientFlight;
            }
            try policy.verifier.verifyRawPublicKey(null, certificate.entries);
        } else {
            try policy.verifier.verifyTrust(null, certificate.entries);
        }
        const verify_bytes = certificate_verify_bytes orelse
            return error.InvalidClientFlight;
        const parsed_verify = try auth.parseCertificateVerify(
            verify_bytes,
        );
        const verify_hash = state.digest();
        try auth.verifyCertificateVerifyForRole(
            certificate.entries[0],
            parsed_verify,
            verify_hash.bytes(),
            .client,
        );
        state.update(verify_bytes);
    }

    const verify_data = try parseFinished(
        finished_bytes,
        client_handshake_traffic_secret.hash,
    );
    var expected = try key_schedule.computeFinishedFor(
        client_handshake_traffic_secret,
        state.digest(),
    );
    defer expected.deinit();
    var actual = try secret.Secret.init(
        expected.hash,
        verify_data,
    );
    defer actual.deinit();
    if (!expected.eql(&actual)) return error.BadClientFinished;
    state.update(finished_bytes);

    return .{
        .certificate = certificate,
        .decompressed_certificate_message = decompressed_certificate_message,
        .certificate_compression = selected_certificate_compression,
        .transcript_after_client_finished = state.digest(),
    };
}

fn parseFinished(
    bytes: []const u8,
    hash: secret.Hash,
) Error![]const u8 {
    if (bytes.len < 4 or bytes[0] != 0x14) {
        return error.InvalidClientFlight;
    }
    const body_len =
        (@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) |
        bytes[3];
    if (body_len != hash.len() or body_len != bytes.len - 4) {
        return error.InvalidClientFlight;
    }
    return bytes[4..];
}

pub fn writeRequest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    request_context: []const u8,
    certificate_authorities: []const []const u8,
) Error!void {
    return writeRequestWithCompression(
        list,
        allocator,
        request_context,
        certificate_authorities,
        &.{},
    );
}

pub fn writeRequestWithCompression(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    request_context: []const u8,
    certificate_authorities: []const []const u8,
    compression_algorithms: []const certificate_compression.Algorithm,
) Error!void {
    if (request_context.len > std.math.maxInt(u8)) {
        return error.InvalidCertificateRequest;
    }
    const original_len = list.items.len;
    errdefer list.items.len = original_len;

    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    try appendInt(&extensions, allocator, u16, ext_signature_algorithms);
    try appendInt(&extensions, allocator, u16, 22);
    try appendInt(&extensions, allocator, u16, 20);
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_sm2sig_sm3,
    );
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
        auth.signature_scheme_ecdsa_secp384r1_sha384,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_rsa_pss_rsae_sha256,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_rsa_pss_rsae_sha384,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_rsa_pss_rsae_sha512,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_rsa_pss_pss_sha256,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_rsa_pss_pss_sha384,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_rsa_pss_pss_sha512,
    );
    try appendInt(
        &extensions,
        allocator,
        u16,
        auth.signature_scheme_ed25519,
    );
    if (compression_algorithms.len != 0) {
        certificate_compression.validateAlgorithms(
            compression_algorithms,
        ) catch return error.InvalidCertificateRequest;
        try appendInt(
            &extensions,
            allocator,
            u16,
            ext_compress_certificate,
        );
        try appendInt(
            &extensions,
            allocator,
            u16,
            1 + compression_algorithms.len * 2,
        );
        try extensions.append(
            allocator,
            @intCast(compression_algorithms.len * 2),
        );
        for (compression_algorithms) |algorithm| {
            try appendInt(
                &extensions,
                allocator,
                u16,
                @intFromEnum(algorithm),
            );
        }
    }
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
    var supports_ecdsa_p256 = false;
    var supports_ecdsa_p384 = false;
    var supports_rsa_pss_rsae_sha256 = false;
    var supports_rsa_pss_rsae_sha384 = false;
    var supports_rsa_pss_rsae_sha512 = false;
    var supports_rsa_pss_pss_sha256 = false;
    var supports_rsa_pss_pss_sha384 = false;
    var supports_rsa_pss_pss_sha512 = false;
    var supports_sm2 = false;
    var certificate_compression_algorithms: []const u8 = &.{};
    var saw_signature_algorithms = false;
    var saw_certificate_compression = false;
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
                    supports_ecdsa_p256 = true;
                }
                if (scheme ==
                    auth.signature_scheme_ecdsa_secp384r1_sha384)
                {
                    supports_ecdsa_p384 = true;
                }
                if (scheme == auth.signature_scheme_sm2sig_sm3) {
                    supports_sm2 = true;
                }
                if (scheme ==
                    auth.signature_scheme_rsa_pss_rsae_sha256)
                {
                    supports_rsa_pss_rsae_sha256 = true;
                }
                if (scheme ==
                    auth.signature_scheme_rsa_pss_rsae_sha384)
                {
                    supports_rsa_pss_rsae_sha384 = true;
                }
                if (scheme ==
                    auth.signature_scheme_rsa_pss_rsae_sha512)
                {
                    supports_rsa_pss_rsae_sha512 = true;
                }
                if (scheme ==
                    auth.signature_scheme_rsa_pss_pss_sha256)
                {
                    supports_rsa_pss_pss_sha256 = true;
                }
                if (scheme ==
                    auth.signature_scheme_rsa_pss_pss_sha384)
                {
                    supports_rsa_pss_pss_sha384 = true;
                }
                if (scheme ==
                    auth.signature_scheme_rsa_pss_pss_sha512)
                {
                    supports_rsa_pss_pss_sha512 = true;
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
        } else if (typ == ext_compress_certificate) {
            if (saw_certificate_compression) {
                return error.InvalidCertificateRequest;
            }
            saw_certificate_compression = true;
            certificate_compression_algorithms =
                try parseCompressionAlgorithms(payload);
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
        .supports_ecdsa_p256_sha256 = supports_ecdsa_p256,
        .supports_ecdsa_p384_sha384 = supports_ecdsa_p384,
        .supports_rsa_pss_rsae_sha256 = supports_rsa_pss_rsae_sha256,
        .supports_rsa_pss_rsae_sha384 = supports_rsa_pss_rsae_sha384,
        .supports_rsa_pss_rsae_sha512 = supports_rsa_pss_rsae_sha512,
        .supports_rsa_pss_pss_sha256 = supports_rsa_pss_pss_sha256,
        .supports_rsa_pss_pss_sha384 = supports_rsa_pss_pss_sha384,
        .supports_rsa_pss_pss_sha512 = supports_rsa_pss_pss_sha512,
        .supports_sm2sig_sm3 = supports_sm2,
        .certificate_compression_algorithms = certificate_compression_algorithms,
    };
}

fn parseCompressionAlgorithms(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const encoded_len = try readByte(payload, &pos);
    if (encoded_len == 0 or encoded_len % 2 != 0 or
        encoded_len != payload.len - pos)
    {
        return error.InvalidCertificateRequest;
    }
    const algorithms = payload[pos..];
    var current: usize = 0;
    while (current < algorithms.len) : (current += 2) {
        const algorithm = std.mem.readInt(
            u16,
            algorithms[current..][0..2],
            .big,
        );
        var previous: usize = 0;
        while (previous < current) : (previous += 2) {
            if (algorithm == std.mem.readInt(
                u16,
                algorithms[previous..][0..2],
                .big,
            )) return error.InvalidCertificateRequest;
        }
    }
    return algorithms;
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
