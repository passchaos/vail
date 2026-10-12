//! TLS 1.2 ECDHE server-handshake message construction and parsing.

const std = @import("std");
const auth = @import("auth.zig");
const client_hello = @import("client_hello.zig");
const key_exchange = @import("key_exchange.zig");
const record_size_limit = @import("record_size_limit.zig");
const tls12 = @import("tls12.zig");
const transcript = @import("transcript.zig");

pub const handshake_type_server_hello: u8 = 0x02;
pub const handshake_type_certificate: u8 = 0x0b;
pub const handshake_type_server_key_exchange: u8 = 0x0c;
pub const handshake_type_certificate_request: u8 = 0x0d;
pub const handshake_type_server_hello_done: u8 = 0x0e;
pub const handshake_type_certificate_verify: u8 = 0x0f;
pub const handshake_type_client_key_exchange: u8 = 0x10;
pub const handshake_type_finished: u8 = 0x14;
pub const handshake_type_certificate_status: u8 = 0x16;

const ext_server_name: u16 = 0x0000;
const ext_status_request: u16 = 0x0005;
const ext_status_request_v2: u16 = 0x0011;
const ext_ec_point_formats: u16 = 0x000b;
const ext_application_layer_protocol_negotiation: u16 = 0x0010;
const ext_extended_master_secret: u16 = 0x0017;
const ext_record_size_limit: u16 = record_size_limit.extension_type;
const ext_session_ticket: u16 = 0x0023;
const ext_renegotiation_info: u16 = 0xff01;
const named_curve_type: u8 = 3;

const client_certificate_signature_schemes = [_]u16{
    auth.signature_scheme_ecdsa_secp256r1_sha256,
    auth.signature_scheme_ecdsa_secp384r1_sha384,
    auth.signature_scheme_ecdsa_secp521r1_sha512,
    auth.signature_scheme_ed25519,
    auth.signature_scheme_rsa_pss_rsae_sha256,
    auth.signature_scheme_rsa_pss_rsae_sha384,
    auth.signature_scheme_rsa_pss_rsae_sha512,
    auth.signature_scheme_rsa_pss_pss_sha256,
    auth.signature_scheme_rsa_pss_pss_sha384,
    auth.signature_scheme_rsa_pss_pss_sha512,
    auth.signature_scheme_rsa_pkcs1_sha256,
    auth.signature_scheme_rsa_pkcs1_sha384,
    auth.signature_scheme_rsa_pkcs1_sha512,
};

pub const Error = std.mem.Allocator.Error || auth.Error ||
    client_hello.Error || key_exchange.Error || error{
    InvalidClientHello,
    InvalidServerHello,
    DuplicateServerExtension,
    UnsupportedServerExtension,
    ServerSelectedUnofferedSuite,
    ServerSelectedUnofferedAlpn,
    MissingSecureRenegotiation,
    NoSharedCipherSuite,
    NoSupportedGroup,
    UnsupportedSignatureScheme,
    MissingExtendedMasterSecret,
    InvalidAlpn,
    InvalidCertificate,
    InvalidCertificateStatus,
    InvalidCertificateRequest,
    ClientCertificateRequired,
    InvalidServerKeyExchange,
    InvalidServerHelloDone,
    InvalidClientKeyExchange,
    InvalidFinished,
};

pub const Policy = struct {
    cipher_suites: []const tls12.Suite = &.{
        .ecdhe_rsa_aes_128_gcm_sha256,
    },
    groups: []const u16 = &.{key_exchange.named_group_secp256r1},
    alpn_protocols: []const []const u8 = &.{},
    require_extended_master_secret: bool = true,
    require_secure_renegotiation: bool = true,
    /// `null` disables TLS 1.2 client authentication. A non-null, possibly
    /// empty list emits CertificateRequest with these distinguished names.
    client_certificate_authorities: ?[]const []const u8 = null,
    /// Non-empty ID issued by a full handshake for later stateful resumption.
    new_session_id: []const u8 = &.{},
    /// Acknowledge RFC 5077 when the client offers the session_ticket
    /// extension. Ticket issuance remains owned by the connection state.
    issue_session_ticket: bool = false,
    /// DER-encoded OCSPResponse stapled only when the client offered the
    /// TLS 1.2 status_request extension.
    ocsp_response: ?[]const u8 = null,
    /// RFC 6961 responses aligned with the certificate chain. This and
    /// `ocsp_response` are mutually exclusive; a null entry encodes an empty
    /// OCSPResponse and trailing entries may be omitted on the wire.
    ocsp_responses: ?[]const ?[]const u8 = null,
    /// Limit this endpoint accepts for TLS 1.2 plaintext fragments.
    record_size_limit: ?u16 = null,
};

pub const Selection = struct {
    suite: tls12.Suite,
    group: u16,
    alpn_protocol: ?[]const u8,
    extended_master_secret: bool,
    session_ticket_acknowledged: bool = false,
    status_request_acknowledged: bool = false,
    status_request_v2_acknowledged: bool = false,
    local_record_size_limit: ?u16 = null,
    peer_record_size_limit: ?u16 = null,
};

pub const ServerFlight = struct {
    selection: Selection,
    transcript_state: transcript.State,
};

pub const ParsedServerHello = struct {
    random: [32]u8,
    session_id: []const u8,
    suite: tls12.Suite,
    alpn_protocol: ?[]const u8,
    extended_master_secret: bool,
    secure_renegotiation: bool,
    session_ticket_acknowledged: bool,
    status_request_acknowledged: bool,
    status_request_v2_acknowledged: bool,
    local_record_size_limit: ?u16,
    peer_record_size_limit: ?u16,
};

pub const ParsedServerKeyExchange = struct {
    group: u16,
    public_key: []const u8,
    signature_scheme: u16,
};

pub const ServerFlightMessages = struct {
    server_hello: []const u8,
    certificate: []const u8,
    certificate_status: ?[]const u8,
    server_key_exchange: []const u8,
    certificate_request: ?[]const u8,
    server_hello_done: []const u8,
};

pub const ParsedCertificateRequest = struct {
    certificate_types: []const u8,
    signature_algorithms: []const u8,
    certificate_authorities: []const u8,

    pub fn supportsSigner(
        self: ParsedCertificateRequest,
        signer: auth.Signer,
    ) bool {
        var pos: usize = 0;
        while (pos < self.signature_algorithms.len) : (pos += 2) {
            if (std.mem.readInt(
                u16,
                self.signature_algorithms[pos..][0..2],
                .big,
            ) == signer.scheme()) return true;
        }
        return false;
    }
};

/// Split the full, non-resumed TLS 1.2 server flight and reject omitted,
/// reordered, duplicated, or trailing messages.
pub fn splitServerFlight(bytes: []const u8) Error!ServerFlightMessages {
    var pos: usize = 0;
    const server_hello = try takeHandshakeMessage(bytes, &pos);
    if (server_hello[0] != handshake_type_server_hello) {
        return error.InvalidServerHello;
    }
    const certificate = try takeHandshakeMessage(bytes, &pos);
    if (certificate[0] != handshake_type_certificate) {
        return error.InvalidCertificate;
    }
    var certificate_status: ?[]const u8 = null;
    if (pos < bytes.len and
        bytes[pos] == handshake_type_certificate_status)
    {
        certificate_status = try takeHandshakeMessage(bytes, &pos);
    }
    const server_key_exchange = try takeHandshakeMessage(bytes, &pos);
    if (server_key_exchange[0] != handshake_type_server_key_exchange) {
        return error.InvalidServerKeyExchange;
    }
    var certificate_request: ?[]const u8 = null;
    if (pos < bytes.len and bytes[pos] == handshake_type_certificate_request) {
        certificate_request = try takeHandshakeMessage(bytes, &pos);
    }
    const server_hello_done = try takeHandshakeMessage(bytes, &pos);
    if (server_hello_done[0] != handshake_type_server_hello_done or
        pos != bytes.len)
    {
        return error.InvalidServerHelloDone;
    }
    return .{
        .server_hello = server_hello,
        .certificate = certificate,
        .certificate_status = certificate_status,
        .server_key_exchange = server_key_exchange,
        .certificate_request = certificate_request,
        .server_hello_done = server_hello_done,
    };
}

/// Parse and validate the server's negotiated TLS 1.2 parameters against the
/// exact client offer represented by `policy`.
pub fn parseServerHello(
    message: []const u8,
    policy: Policy,
    offered_server_name: bool,
) Error!ParsedServerHello {
    if (policy.record_size_limit) |limit| {
        _ = record_size_limit.validateTls12(limit) catch
            return error.InvalidServerHello;
    }
    var pos: usize = 0;
    if (try readByte(message, &pos) != handshake_type_server_hello or
        try readU24At(message, &pos) != message.len - pos)
    {
        return error.InvalidServerHello;
    }
    if (try readInt(u16, message, &pos) != 0x0303) {
        return error.InvalidServerHello;
    }
    const random = (try readSlice(message, &pos, 32))[0..32].*;
    const session_id_len = try readByte(message, &pos);
    if (session_id_len > 32) return error.InvalidServerHello;
    const session_id = try readSlice(message, &pos, session_id_len);
    const suite_wire = try readInt(u16, message, &pos);
    const suite = tls12.Suite.fromWire(suite_wire) orelse
        return error.ServerSelectedUnofferedSuite;
    if (!containsSuite(policy.cipher_suites, suite)) {
        return error.ServerSelectedUnofferedSuite;
    }
    if (try readByte(message, &pos) != 0) return error.InvalidServerHello;
    const extensions_len = try readInt(u16, message, &pos);
    const extensions = try readSlice(message, &pos, extensions_len);
    if (pos != message.len) return error.InvalidServerHello;

    var ext_pos: usize = 0;
    var seen_sni = false;
    var seen_point_formats = false;
    var seen_alpn = false;
    var seen_ems = false;
    var seen_renegotiation = false;
    var seen_session_ticket = false;
    var seen_status_request = false;
    var seen_status_request_v2 = false;
    var seen_record_size_limit = false;
    var peer_record_size_limit: ?u16 = null;
    var selected_alpn: ?[]const u8 = null;
    while (ext_pos < extensions.len) {
        const extension_type = try readInt(u16, extensions, &ext_pos);
        const extension_len = try readInt(u16, extensions, &ext_pos);
        const payload = try readSlice(extensions, &ext_pos, extension_len);
        switch (extension_type) {
            ext_server_name => {
                if (seen_sni) return error.DuplicateServerExtension;
                seen_sni = true;
                if (!offered_server_name or payload.len != 0) {
                    return error.InvalidServerHello;
                }
            },
            ext_ec_point_formats => {
                if (seen_point_formats) {
                    return error.DuplicateServerExtension;
                }
                seen_point_formats = true;
                if (!std.mem.eql(u8, payload, &.{ 1, 0 })) {
                    return error.InvalidServerHello;
                }
            },
            ext_application_layer_protocol_negotiation => {
                if (seen_alpn) return error.DuplicateServerExtension;
                seen_alpn = true;
                selected_alpn = try parseSelectedAlpn(
                    payload,
                    policy.alpn_protocols,
                );
            },
            ext_extended_master_secret => {
                if (seen_ems) return error.DuplicateServerExtension;
                seen_ems = true;
                if (payload.len != 0) return error.InvalidServerHello;
            },
            ext_renegotiation_info => {
                if (seen_renegotiation) {
                    return error.DuplicateServerExtension;
                }
                seen_renegotiation = true;
                if (!std.mem.eql(u8, payload, &.{0})) {
                    return error.InvalidServerHello;
                }
            },
            ext_session_ticket => {
                if (seen_session_ticket) {
                    return error.DuplicateServerExtension;
                }
                seen_session_ticket = true;
                if (payload.len != 0) return error.InvalidServerHello;
            },
            ext_status_request => {
                if (seen_status_request) {
                    return error.DuplicateServerExtension;
                }
                seen_status_request = true;
                if (payload.len != 0) return error.InvalidServerHello;
            },
            ext_status_request_v2 => {
                if (seen_status_request_v2) {
                    return error.DuplicateServerExtension;
                }
                seen_status_request_v2 = true;
                if (payload.len != 0) return error.InvalidServerHello;
            },
            ext_record_size_limit => {
                if (seen_record_size_limit) {
                    return error.DuplicateServerExtension;
                }
                seen_record_size_limit = true;
                if (policy.record_size_limit == null) {
                    return error.InvalidServerHello;
                }
                peer_record_size_limit = record_size_limit.parse(payload) catch
                    return error.InvalidServerHello;
                _ = record_size_limit.validateTls12(
                    peer_record_size_limit.?,
                ) catch return error.InvalidServerHello;
            },
            else => return error.UnsupportedServerExtension,
        }
    }
    if (policy.require_extended_master_secret and !seen_ems) {
        return error.MissingExtendedMasterSecret;
    }
    if (policy.require_secure_renegotiation and !seen_renegotiation) {
        return error.MissingSecureRenegotiation;
    }
    if (seen_status_request and seen_status_request_v2) {
        return error.InvalidServerHello;
    }
    return .{
        .random = random,
        .session_id = session_id,
        .suite = suite,
        .alpn_protocol = selected_alpn,
        .extended_master_secret = seen_ems,
        .secure_renegotiation = seen_renegotiation,
        .session_ticket_acknowledged = seen_session_ticket,
        .status_request_acknowledged = seen_status_request,
        .status_request_v2_acknowledged = seen_status_request_v2,
        .local_record_size_limit = policy.record_size_limit,
        .peer_record_size_limit = peer_record_size_limit,
    };
}

/// Parse a TLS 1.2 Certificate message. Unlike TLS 1.3, entries have no
/// request context or per-certificate extensions.
pub fn parseCertificate(
    allocator: std.mem.Allocator,
    message: []const u8,
) Error!auth.ParsedCertificate {
    return parseCertificateImpl(allocator, message, false);
}

pub fn parseClientCertificate(
    allocator: std.mem.Allocator,
    message: []const u8,
) Error!auth.ParsedCertificate {
    return parseCertificateImpl(allocator, message, true);
}

fn parseCertificateImpl(
    allocator: std.mem.Allocator,
    message: []const u8,
    allow_empty: bool,
) Error!auth.ParsedCertificate {
    var pos: usize = 0;
    if (try readByte(message, &pos) != handshake_type_certificate or
        try readU24At(message, &pos) != message.len - pos)
    {
        return error.InvalidCertificate;
    }
    const list_len = try readU24At(message, &pos);
    if ((!allow_empty and list_len == 0) or list_len != message.len - pos) {
        return error.InvalidCertificate;
    }
    var count: usize = 0;
    var scan = pos;
    while (scan < message.len) {
        const certificate_len = try readU24At(message, &scan);
        if (certificate_len == 0) return error.InvalidCertificate;
        _ = try readSlice(message, &scan, certificate_len);
        count = std.math.add(usize, count, 1) catch
            return error.InvalidCertificate;
    }
    if (scan != message.len) return error.InvalidCertificate;
    const entries = try allocator.alloc([]const u8, count);
    errdefer allocator.free(entries);
    for (entries) |*entry| {
        const certificate_len = try readU24At(message, &pos);
        entry.* = try readSlice(message, &pos, certificate_len);
    }
    if (pos != message.len) return error.InvalidCertificate;
    return .{ .entries = entries };
}

/// Authenticate an ECDHE ServerKeyExchange and return its peer share.
pub fn parseAndVerifyServerKeyExchange(
    message: []const u8,
    certificate: []const u8,
    client_random: [32]u8,
    server_random: [32]u8,
    suite: tls12.Suite,
    policy: Policy,
) Error!ParsedServerKeyExchange {
    return parseAndVerifyServerKeyExchangeWithVerifier(
        message,
        certificate,
        client_random,
        server_random,
        suite,
        policy,
        .{},
    );
}

/// Authenticate an ECDHE ServerKeyExchange with caller-retained verification
/// state when available.
pub fn parseAndVerifyServerKeyExchangeWithVerifier(
    message: []const u8,
    certificate: []const u8,
    client_random: [32]u8,
    server_random: [32]u8,
    suite: tls12.Suite,
    policy: Policy,
    verifier: auth.ClientVerifier,
) Error!ParsedServerKeyExchange {
    var pos: usize = 0;
    if (try readByte(message, &pos) != handshake_type_server_key_exchange or
        try readU24At(message, &pos) != message.len - pos)
    {
        return error.InvalidServerKeyExchange;
    }
    const params_start = pos;
    if (try readByte(message, &pos) != named_curve_type) {
        return error.InvalidServerKeyExchange;
    }
    const group = try readInt(u16, message, &pos);
    if (!containsU16(policy.groups, group)) return error.NoSupportedGroup;
    const public_key_len = try readByte(message, &pos);
    if (public_key_len == 0 or public_key_len > key_exchange.p521.public_len) {
        return error.InvalidServerKeyExchange;
    }
    const public_key = try readSlice(message, &pos, public_key_len);
    const params_end = pos;
    const signature_scheme = try readInt(u16, message, &pos);
    if (!signatureMatchesSuite(signature_scheme, suite)) {
        return error.UnsupportedSignatureScheme;
    }
    const signature_len = try readInt(u16, message, &pos);
    if (signature_len == 0 or
        signature_len > auth.max_classical_signature_len)
    {
        return error.InvalidServerKeyExchange;
    }
    const signature = try readSlice(message, &pos, signature_len);
    if (pos != message.len) return error.InvalidServerKeyExchange;
    var signed_content: [64 + 1 + 2 + 1 + key_exchange.p521.public_len]u8 =
        undefined;
    signed_content[0..32].* = client_random;
    signed_content[32..64].* = server_random;
    const params = message[params_start..params_end];
    @memcpy(signed_content[64..][0..params.len], params);
    try verifier.verifyTls12Signature(
        certificate,
        .{ .scheme = signature_scheme, .signature = signature },
        signed_content[0 .. 64 + params.len],
    );
    return .{
        .group = group,
        .public_key = public_key,
        .signature_scheme = signature_scheme,
    };
}

pub fn parseServerHelloDone(message: []const u8) Error!void {
    if (!std.mem.eql(
        u8,
        message,
        &.{ handshake_type_server_hello_done, 0, 0, 0 },
    )) return error.InvalidServerHelloDone;
}

pub fn writeClientKeyExchange(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    public_key: []const u8,
) Error!void {
    if (public_key.len == 0 or public_key.len > std.math.maxInt(u8)) {
        return error.InvalidClientKeyExchange;
    }
    try appendHandshakeHeader(
        out,
        allocator,
        handshake_type_client_key_exchange,
        1 + public_key.len,
    );
    try out.append(allocator, @intCast(public_key.len));
    try out.appendSlice(allocator, public_key);
}

pub fn select(
    client: client_hello.Parsed,
    signer: auth.Signer,
    policy: Policy,
) Error!Selection {
    if (client.record_size_limit) |limit| {
        _ = record_size_limit.validateTls12(limit) catch
            return error.InvalidClientHello;
    }
    if (policy.record_size_limit) |limit| {
        _ = record_size_limit.validateTls12(limit) catch
            return error.InvalidClientHello;
    }
    if (policy.ocsp_response) |response| {
        if (response.len == 0 or response.len > std.math.maxInt(u24)) {
            return error.InvalidCertificateStatus;
        }
    }
    if (policy.ocsp_response != null and policy.ocsp_responses != null) {
        return error.InvalidCertificateStatus;
    }
    if (policy.ocsp_responses) |responses| {
        if (responses.len == 0) return error.InvalidCertificateStatus;
        var encoded_len: usize = 0;
        var has_response = false;
        for (responses) |response| {
            const response_len = if (response) |bytes| bytes.len else 0;
            has_response = has_response or response_len != 0;
            if (response_len > std.math.maxInt(u24)) {
                return error.InvalidCertificateStatus;
            }
            encoded_len = std.math.add(
                usize,
                encoded_len,
                3 + response_len,
            ) catch return error.InvalidCertificateStatus;
            if (encoded_len > std.math.maxInt(u24) - 4) {
                return error.InvalidCertificateStatus;
            }
        }
        if (!has_response) return error.InvalidCertificateStatus;
    }
    if (client.legacy_version < 0x0303 or
        !containsByte(client.compression_methods, 0))
    {
        return error.InvalidClientHello;
    }
    if (client.supported_versions.len != 0 and
        !client.supportsVersion(0x0303))
    {
        return error.InvalidClientHello;
    }
    if (policy.require_extended_master_secret and
        !client.offers_extended_master_secret)
    {
        return error.MissingExtendedMasterSecret;
    }
    if (!try client.supportsSignatureScheme(signer.scheme())) {
        return error.UnsupportedSignatureScheme;
    }
    const suite = for (policy.cipher_suites) |candidate| {
        if (client.hasCipherSuite(@intFromEnum(candidate)) and
            signerMatchesSuite(signer, candidate)) break candidate;
    } else return error.NoSharedCipherSuite;
    const group = for (policy.groups) |candidate| {
        const implemented = candidate == key_exchange.named_group_secp256r1 or
            candidate == key_exchange.named_group_secp384r1 or
            candidate == key_exchange.named_group_secp521r1;
        if (!implemented) continue;
        if (client.supported_groups.len == 0 or
            try client.supportsGroup(candidate)) break candidate;
    } else return error.NoSupportedGroup;
    const acknowledge_multi = client.requests_ocsp_multi and
        policy.ocsp_responses != null;
    const legacy_response = policy.ocsp_response orelse
        if (policy.ocsp_responses) |responses|
            responses[0]
        else
            null;
    return .{
        .suite = suite,
        .group = group,
        .alpn_protocol = try selectAlpn(
            client.alpn_protocols,
            policy.alpn_protocols,
        ),
        .extended_master_secret = client.offers_extended_master_secret,
        .session_ticket_acknowledged = policy.issue_session_ticket and
            client.session_ticket != null and
            client.offers_extended_master_secret,
        .status_request_acknowledged = !acknowledge_multi and
            client.requests_ocsp and legacy_response != null,
        .status_request_v2_acknowledged = acknowledge_multi,
        .local_record_size_limit = if (client.record_size_limit != null)
            policy.record_size_limit
        else
            null,
        .peer_record_size_limit = client.record_size_limit,
    };
}

pub fn writeServerFlight(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    client_hello_bytes: []const u8,
    client: client_hello.Parsed,
    policy: Policy,
    server_random: [32]u8,
    server_public_key: []const u8,
    certificate_chain: []const []const u8,
    signer: auth.Signer,
) Error!ServerFlight {
    if (policy.ocsp_responses) |responses| {
        if (responses.len != certificate_chain.len) {
            return error.InvalidCertificateStatus;
        }
    }
    const selection = try select(client, signer, policy);
    const expected_public_len: usize = switch (selection.group) {
        key_exchange.named_group_secp256r1 => key_exchange.p256.public_len,
        key_exchange.named_group_secp384r1 => key_exchange.p384.public_len,
        key_exchange.named_group_secp521r1 => key_exchange.p521.public_len,
        else => return error.NoSupportedGroup,
    };
    if (server_public_key.len != expected_public_len or
        server_public_key[0] != 4 or certificate_chain.len == 0)
    {
        return error.InvalidClientHello;
    }
    try (auth.ServerIdentity{
        .certificate_chain = certificate_chain,
        .signer = signer,
    }).validate();
    const original_len = out.items.len;
    errdefer out.items.len = original_len;

    var state = transcript.State.init(selection.suite.transcriptHash());
    state.update(client_hello_bytes);

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try writeServerHello(
        &server_hello,
        allocator,
        client,
        selection,
        server_random,
        policy.new_session_id,
    );
    try out.appendSlice(allocator, server_hello.items);
    state.update(server_hello.items);

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try writeCertificate(&certificate, allocator, certificate_chain);
    try out.appendSlice(allocator, certificate.items);
    state.update(certificate.items);

    if (selection.status_request_v2_acknowledged) {
        var certificate_status: std.ArrayList(u8) = .empty;
        defer certificate_status.deinit(allocator);
        try writeCertificateStatusV2(
            &certificate_status,
            allocator,
            policy.ocsp_responses.?,
        );
        try out.appendSlice(allocator, certificate_status.items);
        state.update(certificate_status.items);
    } else if (selection.status_request_acknowledged) {
        var certificate_status: std.ArrayList(u8) = .empty;
        defer certificate_status.deinit(allocator);
        const response = policy.ocsp_response orelse
            policy.ocsp_responses.?[0].?;
        try writeCertificateStatus(
            &certificate_status,
            allocator,
            response,
        );
        try out.appendSlice(allocator, certificate_status.items);
        state.update(certificate_status.items);
    }

    var server_key_exchange: std.ArrayList(u8) = .empty;
    defer server_key_exchange.deinit(allocator);
    try writeServerKeyExchange(
        &server_key_exchange,
        allocator,
        client.random.*,
        server_random,
        selection.group,
        server_public_key,
        signer,
    );
    try out.appendSlice(allocator, server_key_exchange.items);
    state.update(server_key_exchange.items);

    if (policy.client_certificate_authorities) |authorities| {
        var request: std.ArrayList(u8) = .empty;
        defer request.deinit(allocator);
        try writeCertificateRequest(&request, allocator, authorities);
        try out.appendSlice(allocator, request.items);
        state.update(request.items);
    }

    const done = [_]u8{ handshake_type_server_hello_done, 0, 0, 0 };
    try out.appendSlice(allocator, &done);
    state.update(&done);
    return .{ .selection = selection, .transcript_state = state };
}

pub fn parseClientKeyExchange(message: []const u8) Error![]const u8 {
    if (message.len < 5 or message[0] != handshake_type_client_key_exchange) {
        return error.InvalidClientKeyExchange;
    }
    const body_len = readU24(message[1..4]);
    if (body_len != message.len - 4) return error.InvalidClientKeyExchange;
    const point_len: usize = message[4];
    if (point_len == 0 or point_len != message.len - 5) {
        return error.InvalidClientKeyExchange;
    }
    return message[5..];
}

pub fn writeFinished(
    out: *[4 + tls12.finished_verify_data_len]u8,
    verify_data: [tls12.finished_verify_data_len]u8,
) void {
    out[0] = handshake_type_finished;
    out[1..4].* = .{ 0, 0, tls12.finished_verify_data_len };
    out[4..].* = verify_data;
}

pub fn parseFinished(message: []const u8) Error![tls12.finished_verify_data_len]u8 {
    if (message.len != 4 + tls12.finished_verify_data_len or
        message[0] != handshake_type_finished or
        readU24(message[1..4]) != tls12.finished_verify_data_len)
    {
        return error.InvalidFinished;
    }
    return message[4..][0..tls12.finished_verify_data_len].*;
}

fn writeServerHello(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    client: client_hello.Parsed,
    selection: Selection,
    server_random: [32]u8,
    session_id: []const u8,
) Error!void {
    if (session_id.len > tls12.max_session_id_len) {
        return error.InvalidServerHello;
    }
    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    if (client.server_name != null) {
        try appendExtension(&extensions, allocator, ext_server_name, &.{});
    }
    if (selection.extended_master_secret) {
        try appendExtension(
            &extensions,
            allocator,
            ext_extended_master_secret,
            &.{},
        );
    }
    if (selection.local_record_size_limit) |limit| {
        const payload = record_size_limit.encode(limit) catch
            return error.InvalidServerHello;
        try appendExtension(
            &extensions,
            allocator,
            ext_record_size_limit,
            &payload,
        );
    }
    if (client.offers_secure_renegotiation or
        client.hasCipherSuite(0x00ff))
    {
        try appendExtension(
            &extensions,
            allocator,
            ext_renegotiation_info,
            &.{0},
        );
    }
    try appendExtension(
        &extensions,
        allocator,
        ext_ec_point_formats,
        &.{ 1, 0 },
    );
    if (selection.alpn_protocol) |protocol| {
        if (protocol.len == 0 or protocol.len > std.math.maxInt(u8)) {
            return error.InvalidAlpn;
        }
        var alpn: std.ArrayList(u8) = .empty;
        defer alpn.deinit(allocator);
        try appendInt(&alpn, allocator, u16, 1 + protocol.len);
        try alpn.append(allocator, @intCast(protocol.len));
        try alpn.appendSlice(allocator, protocol);
        try appendExtension(
            &extensions,
            allocator,
            ext_application_layer_protocol_negotiation,
            alpn.items,
        );
    }
    if (selection.session_ticket_acknowledged) {
        try appendExtension(
            &extensions,
            allocator,
            ext_session_ticket,
            &.{},
        );
    }
    if (selection.status_request_acknowledged) {
        try appendExtension(
            &extensions,
            allocator,
            ext_status_request,
            &.{},
        );
    }
    if (selection.status_request_v2_acknowledged) {
        try appendExtension(
            &extensions,
            allocator,
            ext_status_request_v2,
            &.{},
        );
    }

    const body_len = 2 + 32 + 1 + session_id.len + 2 + 1 + 2 +
        extensions.items.len;
    try appendHandshakeHeader(out, allocator, handshake_type_server_hello, body_len);
    try out.appendSlice(allocator, &.{ 3, 3 });
    try out.appendSlice(allocator, &server_random);
    try out.append(allocator, @intCast(session_id.len));
    try out.appendSlice(allocator, session_id);
    try appendInt(out, allocator, u16, @intFromEnum(selection.suite));
    try out.append(allocator, 0);
    try appendInt(out, allocator, u16, extensions.items.len);
    try out.appendSlice(allocator, extensions.items);
}

pub fn writeResumedServerHello(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    client: client_hello.Parsed,
    policy: Policy,
    server_random: [32]u8,
    session: *const tls12.Session,
) Error!Selection {
    if (client.record_size_limit) |limit| {
        _ = record_size_limit.validateTls12(limit) catch
            return error.InvalidClientHello;
    }
    if (policy.record_size_limit) |limit| {
        _ = record_size_limit.validateTls12(limit) catch
            return error.InvalidClientHello;
    }
    if (!std.mem.eql(u8, client.session_id, session.id()) or
        !client.hasCipherSuite(@intFromEnum(session.suite)) or
        !client.offers_extended_master_secret or
        (!client.offers_secure_renegotiation and
            !client.hasCipherSuite(0x00ff)))
    {
        return error.InvalidClientHello;
    }
    if (!containsSuite(policy.cipher_suites, session.suite)) {
        return error.NoSharedCipherSuite;
    }
    if (session.alpn().len != 0 and
        !try client.supportsAlpnProtocol(session.alpn()))
    {
        return error.ServerSelectedUnofferedAlpn;
    }
    const selection = Selection{
        .suite = session.suite,
        .group = 0,
        .alpn_protocol = if (session.alpn().len == 0)
            null
        else
            session.alpn(),
        .extended_master_secret = true,
        .session_ticket_acknowledged = policy.issue_session_ticket and
            client.session_ticket != null and
            client.offers_extended_master_secret,
        .status_request_acknowledged = false,
        .local_record_size_limit = if (client.record_size_limit != null)
            policy.record_size_limit
        else
            null,
        .peer_record_size_limit = client.record_size_limit,
    };
    try writeServerHello(
        out,
        allocator,
        client,
        selection,
        server_random,
        session.id(),
    );
    return selection;
}

pub fn writeCertificate(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
) Error!void {
    var list_len: usize = 0;
    for (chain) |certificate| {
        if (certificate.len == 0 or certificate.len > std.math.maxInt(u24)) {
            return error.InvalidClientHello;
        }
        list_len = std.math.add(usize, list_len, 3 + certificate.len) catch
            return error.InvalidClientHello;
    }
    if (list_len == 0 or list_len > std.math.maxInt(u24)) {
        return error.InvalidClientHello;
    }
    try appendHandshakeHeader(
        out,
        allocator,
        handshake_type_certificate,
        3 + list_len,
    );
    try appendU24(out, allocator, @intCast(list_len));
    for (chain) |certificate| {
        try appendU24(out, allocator, @intCast(certificate.len));
        try out.appendSlice(allocator, certificate);
    }
}

pub fn writeClientCertificate(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
) Error!void {
    if (chain.len != 0) return writeCertificate(out, allocator, chain);
    try appendHandshakeHeader(out, allocator, handshake_type_certificate, 3);
    try appendU24(out, allocator, 0);
}

pub fn writeCertificateStatus(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    ocsp_response: []const u8,
) Error!void {
    if (ocsp_response.len == 0 or
        ocsp_response.len > std.math.maxInt(u24))
    {
        return error.InvalidCertificateStatus;
    }
    const body_len = 1 + 3 + ocsp_response.len;
    if (body_len > std.math.maxInt(u24)) {
        return error.InvalidCertificateStatus;
    }
    try appendHandshakeHeader(
        out,
        allocator,
        handshake_type_certificate_status,
        body_len,
    );
    try out.append(allocator, 1); // ocsp
    try appendU24(out, allocator, @intCast(ocsp_response.len));
    try out.appendSlice(allocator, ocsp_response);
}

pub fn parseCertificateStatus(message: []const u8) Error![]const u8 {
    if (message.len < 9 or
        message[0] != handshake_type_certificate_status or
        readU24(message[1..4]) != message.len - 4 or
        message[4] != 1)
    {
        return error.InvalidCertificateStatus;
    }
    const response_len = readU24(message[5..8]);
    if (response_len == 0 or response_len != message.len - 8) {
        return error.InvalidCertificateStatus;
    }
    return message[8..];
}

pub fn writeCertificateStatusV2(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    ocsp_responses: []const ?[]const u8,
) Error!void {
    var response_count = ocsp_responses.len;
    while (response_count != 0 and
        ocsp_responses[response_count - 1] == null)
    {
        response_count -= 1;
    }
    if (response_count == 0) return error.InvalidCertificateStatus;

    var responses_len: usize = 0;
    for (ocsp_responses[0..response_count]) |response| {
        const response_len = if (response) |bytes| bytes.len else 0;
        if (response_len > std.math.maxInt(u24)) {
            return error.InvalidCertificateStatus;
        }
        responses_len = std.math.add(
            usize,
            responses_len,
            3 + response_len,
        ) catch return error.InvalidCertificateStatus;
    }
    if (responses_len > std.math.maxInt(u24) - 4) {
        return error.InvalidCertificateStatus;
    }

    const original_len = out.items.len;
    errdefer out.items.len = original_len;
    try appendHandshakeHeader(
        out,
        allocator,
        handshake_type_certificate_status,
        1 + 3 + responses_len,
    );
    try out.append(allocator, 2); // ocsp_multi
    try appendU24(out, allocator, @intCast(responses_len));
    for (ocsp_responses[0..response_count]) |response| {
        const encoded = response orelse &.{};
        try appendU24(out, allocator, @intCast(encoded.len));
        try out.appendSlice(allocator, encoded);
    }
}

pub fn parseCertificateStatusV2(
    allocator: std.mem.Allocator,
    message: []const u8,
    certificate_count: usize,
) Error![]?[]const u8 {
    if (certificate_count == 0 or message.len < 11 or
        message[0] != handshake_type_certificate_status or
        readU24(message[1..4]) != message.len - 4 or
        message[4] != 2)
    {
        return error.InvalidCertificateStatus;
    }
    const responses_len = readU24(message[5..8]);
    if (responses_len < 3 or responses_len != message.len - 8) {
        return error.InvalidCertificateStatus;
    }

    const responses = try allocator.alloc(?[]const u8, certificate_count);
    errdefer allocator.free(responses);
    @memset(responses, null);
    var pos: usize = 8;
    var response_index: usize = 0;
    while (pos < message.len) : (response_index += 1) {
        if (response_index == responses.len) {
            return error.InvalidCertificateStatus;
        }
        const response_len = readU24At(message, &pos) catch
            return error.InvalidCertificateStatus;
        const response = readSlice(message, &pos, response_len) catch
            return error.InvalidCertificateStatus;
        responses[response_index] = if (response.len == 0) null else response;
    }
    return responses;
}

pub fn writeCertificateRequest(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    certificate_authorities: []const []const u8,
) Error!void {
    var authorities: std.ArrayList(u8) = .empty;
    defer authorities.deinit(allocator);
    for (certificate_authorities) |name| {
        if (name.len == 0 or name.len > std.math.maxInt(u16)) {
            return error.InvalidCertificateRequest;
        }
        try appendInt(&authorities, allocator, u16, name.len);
        try authorities.appendSlice(allocator, name);
    }
    if (authorities.items.len > std.math.maxInt(u16)) {
        return error.InvalidCertificateRequest;
    }
    const body_len = 1 + 2 + 2 + client_certificate_signature_schemes.len * 2 + 2 +
        authorities.items.len;
    try appendHandshakeHeader(
        out,
        allocator,
        handshake_type_certificate_request,
        body_len,
    );
    // rsa_sign and ecdsa_sign (RFC 4492).
    try out.appendSlice(allocator, &.{ 2, 1, 64 });
    try appendInt(
        out,
        allocator,
        u16,
        client_certificate_signature_schemes.len * 2,
    );
    for (client_certificate_signature_schemes) |scheme| {
        try appendInt(out, allocator, u16, scheme);
    }
    try appendInt(out, allocator, u16, authorities.items.len);
    try out.appendSlice(allocator, authorities.items);
}

pub fn parseCertificateRequest(
    message: []const u8,
) Error!ParsedCertificateRequest {
    var pos: usize = 0;
    if (try readByte(message, &pos) != handshake_type_certificate_request or
        try readU24At(message, &pos) != message.len - pos)
    {
        return error.InvalidCertificateRequest;
    }
    const certificate_types_len = try readByte(message, &pos);
    if (certificate_types_len == 0) return error.InvalidCertificateRequest;
    const certificate_types = try readSlice(
        message,
        &pos,
        certificate_types_len,
    );
    const algorithms_len = try readInt(u16, message, &pos);
    if (algorithms_len == 0 or algorithms_len % 2 != 0) {
        return error.InvalidCertificateRequest;
    }
    const algorithms = try readSlice(message, &pos, algorithms_len);
    const authorities_len = try readInt(u16, message, &pos);
    const authorities = try readSlice(message, &pos, authorities_len);
    if (pos != message.len) return error.InvalidCertificateRequest;
    var authority_pos: usize = 0;
    while (authority_pos < authorities.len) {
        const name_len = try readInt(u16, authorities, &authority_pos);
        if (name_len == 0) return error.InvalidCertificateRequest;
        _ = try readSlice(authorities, &authority_pos, name_len);
    }
    return .{
        .certificate_types = certificate_types,
        .signature_algorithms = algorithms,
        .certificate_authorities = authorities,
    };
}

pub fn writeCertificateVerify(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    signer: auth.Signer,
    handshake_messages: []const u8,
) Error!void {
    var signature: [auth.max_classical_signature_len]u8 = undefined;
    const signature_len = try signer.sign(handshake_messages, &signature);
    try appendHandshakeHeader(
        out,
        allocator,
        handshake_type_certificate_verify,
        4 + signature_len,
    );
    try appendInt(out, allocator, u16, signer.scheme());
    try appendInt(out, allocator, u16, signature_len);
    try out.appendSlice(allocator, signature[0..signature_len]);
}

pub fn verifyCertificateVerify(
    certificate: []const u8,
    message: []const u8,
    handshake_messages: []const u8,
) Error!void {
    if (message.len == 0 or message[0] != handshake_type_certificate_verify) {
        return error.InvalidCertificateRequest;
    }
    const parsed = try auth.parseCertificateVerify(message);
    if (std.mem.indexOfScalar(
        u16,
        &client_certificate_signature_schemes,
        parsed.scheme,
    ) == null) return error.UnsupportedSignatureScheme;
    try auth.verifyTls12SignedContent(
        certificate,
        parsed,
        handshake_messages,
    );
}

fn writeServerKeyExchange(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    client_random: [32]u8,
    server_random: [32]u8,
    group: u16,
    public_key: []const u8,
    signer: auth.Signer,
) Error!void {
    var params: [1 + 2 + 1 + key_exchange.p521.public_len]u8 = undefined;
    params[0] = named_curve_type;
    std.mem.writeInt(u16, params[1..3], group, .big);
    params[3] = @intCast(public_key.len);
    @memcpy(params[4..][0..public_key.len], public_key);
    const params_len = 4 + public_key.len;
    var signed_content: [64 + params.len]u8 = undefined;
    signed_content[0..32].* = client_random;
    signed_content[32..64].* = server_random;
    @memcpy(signed_content[64..][0..params_len], params[0..params_len]);
    var signature: [auth.max_classical_signature_len]u8 = undefined;
    const signature_len = try signer.sign(
        signed_content[0 .. 64 + params_len],
        &signature,
    );
    const body_len = params_len + 2 + 2 + signature_len;
    try appendHandshakeHeader(
        out,
        allocator,
        handshake_type_server_key_exchange,
        body_len,
    );
    try out.appendSlice(allocator, params[0..params_len]);
    try appendInt(out, allocator, u16, signer.scheme());
    try appendInt(out, allocator, u16, signature_len);
    try out.appendSlice(allocator, signature[0..signature_len]);
}

fn signerMatchesSuite(signer: auth.Signer, suite: tls12.Suite) bool {
    return switch (suite) {
        .ecdhe_rsa_aes_128_gcm_sha256,
        .ecdhe_rsa_aes_256_gcm_sha384,
        .ecdhe_rsa_chacha20_poly1305_sha256,
        => switch (signer.scheme()) {
            auth.signature_scheme_rsa_pkcs1_sha256,
            auth.signature_scheme_rsa_pkcs1_sha384,
            auth.signature_scheme_rsa_pkcs1_sha512,
            auth.signature_scheme_rsa_pss_rsae_sha256,
            auth.signature_scheme_rsa_pss_rsae_sha384,
            auth.signature_scheme_rsa_pss_rsae_sha512,
            => true,
            else => false,
        },
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        .ecdhe_ecdsa_aes_256_gcm_sha384,
        .ecdhe_ecdsa_chacha20_poly1305_sha256,
        => switch (signer.scheme()) {
            auth.signature_scheme_ecdsa_secp256r1_sha256,
            auth.signature_scheme_ecdsa_secp384r1_sha384,
            auth.signature_scheme_ecdsa_secp521r1_sha512,
            => true,
            else => false,
        },
    };
}

fn signatureMatchesSuite(signature_scheme: u16, suite: tls12.Suite) bool {
    return switch (suite) {
        .ecdhe_rsa_aes_128_gcm_sha256,
        .ecdhe_rsa_aes_256_gcm_sha384,
        .ecdhe_rsa_chacha20_poly1305_sha256,
        => signature_scheme == auth.signature_scheme_rsa_pkcs1_sha256 or
            signature_scheme == auth.signature_scheme_rsa_pkcs1_sha384 or
            signature_scheme == auth.signature_scheme_rsa_pkcs1_sha512 or
            signature_scheme == auth.signature_scheme_rsa_pss_rsae_sha256 or
            signature_scheme == auth.signature_scheme_rsa_pss_rsae_sha384 or
            signature_scheme == auth.signature_scheme_rsa_pss_rsae_sha512,
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        .ecdhe_ecdsa_aes_256_gcm_sha384,
        .ecdhe_ecdsa_chacha20_poly1305_sha256,
        => signature_scheme ==
            auth.signature_scheme_ecdsa_secp256r1_sha256 or
            signature_scheme ==
                auth.signature_scheme_ecdsa_secp384r1_sha384 or
            signature_scheme ==
                auth.signature_scheme_ecdsa_secp521r1_sha512,
    };
}

fn containsSuite(suites: []const tls12.Suite, target: tls12.Suite) bool {
    for (suites) |suite| if (suite == target) return true;
    return false;
}

fn containsU16(values: []const u16, target: u16) bool {
    for (values) |value| if (value == target) return true;
    return false;
}

fn parseSelectedAlpn(
    payload: []const u8,
    offered: []const []const u8,
) Error![]const u8 {
    var pos: usize = 0;
    const protocols_len = try readInt(u16, payload, &pos);
    if (protocols_len == 0 or protocols_len != payload.len - pos) {
        return error.InvalidAlpn;
    }
    const selected_len = try readByte(payload, &pos);
    if (selected_len == 0) return error.InvalidAlpn;
    const selected = try readSlice(payload, &pos, selected_len);
    if (pos != payload.len) return error.InvalidAlpn;
    for (offered) |protocol| {
        if (std.mem.eql(u8, protocol, selected)) return selected;
    }
    return error.ServerSelectedUnofferedAlpn;
}

pub fn selectAlpn(
    client_protocols: []const u8,
    server_protocols: []const []const u8,
) Error!?[]const u8 {
    if (server_protocols.len == 0 or client_protocols.len == 0) return null;
    var pos: usize = 0;
    const list = try readU16Vector(client_protocols, &pos);
    if (list.len == 0 or pos != client_protocols.len) return error.InvalidAlpn;
    var protocol_pos: usize = 0;
    while (protocol_pos < list.len) {
        const len = try readByte(list, &protocol_pos);
        if (len == 0 or len > list.len - protocol_pos) return error.InvalidAlpn;
        const protocol = list[protocol_pos..][0..len];
        protocol_pos += len;
        for (server_protocols) |supported| {
            if (std.mem.eql(u8, protocol, supported)) return supported;
        }
    }
    return null;
}

fn containsByte(bytes: []const u8, target: u8) bool {
    for (bytes) |byte| if (byte == target) return true;
    return false;
}

fn appendExtension(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    extension_type: u16,
    payload: []const u8,
) Error!void {
    if (payload.len > std.math.maxInt(u16)) return error.InvalidClientHello;
    try appendInt(out, allocator, u16, extension_type);
    try appendInt(out, allocator, u16, payload.len);
    try out.appendSlice(allocator, payload);
}

fn appendHandshakeHeader(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    message_type: u8,
    body_len: usize,
) Error!void {
    if (body_len > std.math.maxInt(u24)) return error.InvalidClientHello;
    try out.append(allocator, message_type);
    try appendU24(out, allocator, @intCast(body_len));
}

fn appendU24(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u24,
) std.mem.Allocator.Error!void {
    try out.appendSlice(allocator, &.{
        @truncate(value >> 16),
        @truncate(value >> 8),
        @truncate(value),
    });
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: anytype,
) std.mem.Allocator.Error!void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .big);
    try out.appendSlice(allocator, &encoded);
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    if (pos.* >= bytes.len) return error.InvalidClientHello;
    defer pos.* += 1;
    return bytes[pos.*];
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) Error!T {
    if (pos.* + @sizeOf(T) > bytes.len) return error.InvalidServerHello;
    defer pos.* += @sizeOf(T);
    return std.mem.readInt(T, bytes[pos.*..][0..@sizeOf(T)], .big);
}

fn readU24At(bytes: []const u8, pos: *usize) Error!usize {
    if (pos.* + 3 > bytes.len) return error.InvalidServerHello;
    defer pos.* += 3;
    return readU24(bytes[pos.*..][0..3]);
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) Error![]const u8 {
    if (len > bytes.len -| pos.*) return error.InvalidServerHello;
    defer pos.* += len;
    return bytes[pos.*..][0..len];
}

fn takeHandshakeMessage(
    bytes: []const u8,
    pos: *usize,
) Error![]const u8 {
    if (pos.* + 4 > bytes.len) return error.InvalidServerHello;
    const body_len = readU24(bytes[pos.* + 1 ..][0..3]);
    const total_len = std.math.add(usize, 4, body_len) catch
        return error.InvalidServerHello;
    if (total_len > bytes.len - pos.*) return error.InvalidServerHello;
    defer pos.* += total_len;
    return bytes[pos.*..][0..total_len];
}

fn readU16Vector(bytes: []const u8, pos: *usize) Error![]const u8 {
    if (pos.* + 2 > bytes.len) return error.InvalidAlpn;
    const len = std.mem.readInt(u16, bytes[pos.*..][0..2], .big);
    pos.* += 2;
    if (len > bytes.len - pos.*) return error.InvalidAlpn;
    defer pos.* += len;
    return bytes[pos.*..][0..len];
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

test "RFC 6961 CertificateStatus response lists round-trip strictly" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCertificateStatusV2(
        &encoded,
        allocator,
        &.{ "leaf-status", null, "issuer-status", null },
    );
    const parsed = try parseCertificateStatusV2(
        allocator,
        encoded.items,
        4,
    );
    defer allocator.free(parsed);
    try std.testing.expectEqual(@as(usize, 4), parsed.len);
    try std.testing.expectEqualStrings("leaf-status", parsed[0].?);
    try std.testing.expect(parsed[1] == null);
    try std.testing.expectEqualStrings("issuer-status", parsed[2].?);
    try std.testing.expect(parsed[3] == null);

    try std.testing.expectError(
        error.InvalidCertificateStatus,
        parseCertificateStatusV2(allocator, encoded.items, 2),
    );
    var malformed = try allocator.dupe(u8, encoded.items);
    defer allocator.free(malformed);
    malformed[7] -%= 1;
    try std.testing.expectError(
        error.InvalidCertificateStatus,
        parseCertificateStatusV2(allocator, malformed, 4),
    );
    try std.testing.expectError(
        error.InvalidCertificateStatus,
        writeCertificateStatusV2(&encoded, allocator, &.{ null, null }),
    );
}

test "TLS 1.2 server flight is transcript-bound and signed" {
    const allocator = std.testing.allocator;
    const vector = @import("../crypto/testdata/rsa_signing.zig");
    const certificate = decodeHex(vector.certificate_hex);
    const private_der = decodeHex(vector.private_key_pkcs8_hex);
    const private = try @import("../crypto/rsa.zig").PrivateKey.fromDer(
        &private_der,
    );
    var prepared = try private.prepare();
    defer prepared.deinit();
    const signer = auth.Signer{ .rsa_pss = .{
        .prepared_key = &prepared,
        .io = std.testing.io,
    } };
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.writeWithKeyShare(&hello, allocator, .{
        .random = [_]u8{0x31} ** 32,
        .server_name = "localhost",
        .key_share = .{
            .group = key_exchange.named_group_x25519,
            .key_exchange = &([_]u8{0x32} ** 32),
        },
        .supported_groups = &.{
            key_exchange.named_group_x25519,
            key_exchange.named_group_secp256r1,
        },
        .additional_cipher_suites = &.{
            @intFromEnum(tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256),
        },
        .supported_versions = &.{0x0303},
        .offer_extended_master_secret = true,
        .request_ocsp = true,
        .record_size_limit = 512,
    });
    const parsed = try client_hello.parse(hello.items);
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    const server_private = [_]u8{0} ** 31 ++ .{1};
    const server_public = try key_exchange.p256.publicKey(server_private);
    const result = try writeServerFlight(
        &flight,
        allocator,
        hello.items,
        parsed,
        .{
            .ocsp_response = "test-ocsp-response",
            .record_size_limit = 256,
        },
        [_]u8{0x33} ** 32,
        &server_public,
        &.{&certificate},
        signer,
    );
    try std.testing.expectEqual(
        tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256,
        result.selection.suite,
    );
    try std.testing.expect(result.selection.extended_master_secret);
    try std.testing.expect(result.selection.status_request_acknowledged);
    try std.testing.expectEqual(
        @as(?u16, 256),
        result.selection.local_record_size_limit,
    );
    try std.testing.expectEqual(
        @as(?u16, 512),
        result.selection.peer_record_size_limit,
    );
    try std.testing.expectEqual(
        result.transcript_state.digest(),
        transcript.hashFor(.sha256, &.{ hello.items, flight.items }),
    );
    try std.testing.expect(std.mem.endsWith(
        u8,
        flight.items,
        &.{ handshake_type_server_hello_done, 0, 0, 0 },
    ));

    const messages = try splitServerFlight(flight.items);
    const parsed_server = try parseServerHello(
        messages.server_hello,
        .{
            .require_secure_renegotiation = false,
            .record_size_limit = 512,
        },
        true,
    );
    try std.testing.expectError(
        error.MissingSecureRenegotiation,
        parseServerHello(
            messages.server_hello,
            .{ .record_size_limit = 512 },
            true,
        ),
    );
    try std.testing.expectEqual(
        tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256,
        parsed_server.suite,
    );
    try std.testing.expect(parsed_server.extended_master_secret);
    try std.testing.expect(parsed_server.status_request_acknowledged);
    try std.testing.expectEqual(
        @as(?u16, 512),
        parsed_server.local_record_size_limit,
    );
    try std.testing.expectEqual(
        @as(?u16, 256),
        parsed_server.peer_record_size_limit,
    );
    try std.testing.expectEqualStrings(
        "test-ocsp-response",
        try parseCertificateStatus(messages.certificate_status.?),
    );
    var malformed_status = try allocator.dupe(
        u8,
        messages.certificate_status.?,
    );
    defer allocator.free(malformed_status);
    malformed_status[4] = 2;
    try std.testing.expectError(
        error.InvalidCertificateStatus,
        parseCertificateStatus(malformed_status),
    );
    var parsed_certificate = try parseCertificate(
        allocator,
        messages.certificate,
    );
    defer parsed_certificate.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), parsed_certificate.entries.len);
    const parsed_key_exchange = try parseAndVerifyServerKeyExchange(
        messages.server_key_exchange,
        parsed_certificate.entries[0],
        parsed.random.*,
        parsed_server.random,
        parsed_server.suite,
        .{},
    );
    try std.testing.expectEqual(
        key_exchange.named_group_secp256r1,
        parsed_key_exchange.group,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_public,
        parsed_key_exchange.public_key,
    );
    var tampered_key_exchange = try allocator.dupe(
        u8,
        messages.server_key_exchange,
    );
    defer allocator.free(tampered_key_exchange);
    tampered_key_exchange[tampered_key_exchange.len - 1] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        parseAndVerifyServerKeyExchange(
            tampered_key_exchange,
            parsed_certificate.entries[0],
            parsed.random.*,
            parsed_server.random,
            parsed_server.suite,
            .{},
        ),
    );
    try parseServerHelloDone(messages.server_hello_done);

    var multi_hello: std.ArrayList(u8) = .empty;
    defer multi_hello.deinit(allocator);
    try client_hello.writeWithKeyShare(&multi_hello, allocator, .{
        .random = [_]u8{0x34} ** 32,
        .key_share = .{
            .group = key_exchange.named_group_x25519,
            .key_exchange = &([_]u8{0x35} ** 32),
        },
        .supported_groups = &.{
            key_exchange.named_group_x25519,
            key_exchange.named_group_secp256r1,
        },
        .additional_cipher_suites = &.{
            @intFromEnum(tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256),
        },
        .supported_versions = &.{0x0303},
        .offer_extended_master_secret = true,
        .request_ocsp = true,
        .request_ocsp_multi = true,
    });
    const parsed_multi_hello = try client_hello.parse(multi_hello.items);
    var multi_flight: std.ArrayList(u8) = .empty;
    defer multi_flight.deinit(allocator);
    const multi_result = try writeServerFlight(
        &multi_flight,
        allocator,
        multi_hello.items,
        parsed_multi_hello,
        .{ .ocsp_responses = &.{ "leaf-status", "issuer-status" } },
        [_]u8{0x36} ** 32,
        &server_public,
        &.{ &certificate, &certificate },
        signer,
    );
    try std.testing.expect(!multi_result.selection.status_request_acknowledged);
    try std.testing.expect(
        multi_result.selection.status_request_v2_acknowledged,
    );
    const multi_messages = try splitServerFlight(multi_flight.items);
    const parsed_multi_server = try parseServerHello(
        multi_messages.server_hello,
        .{ .require_secure_renegotiation = false },
        false,
    );
    try std.testing.expect(
        parsed_multi_server.status_request_v2_acknowledged,
    );
    const multi_status = try parseCertificateStatusV2(
        allocator,
        multi_messages.certificate_status.?,
        2,
    );
    defer allocator.free(multi_status);
    try std.testing.expectEqualStrings("leaf-status", multi_status[0].?);
    try std.testing.expectEqualStrings("issuer-status", multi_status[1].?);
    const legacy_fallback = try select(
        parsed,
        signer,
        .{ .ocsp_responses = &.{ "leaf-status", "issuer-status" } },
    );
    try std.testing.expect(legacy_fallback.status_request_acknowledged);
    try std.testing.expect(
        !legacy_fallback.status_request_v2_acknowledged,
    );
    try std.testing.expectError(
        error.InvalidCertificateStatus,
        select(parsed_multi_hello, signer, .{
            .ocsp_response = "legacy",
            .ocsp_responses = &.{ "leaf-status", "issuer-status" },
        }),
    );
    var invalid_flight: std.ArrayList(u8) = .empty;
    defer invalid_flight.deinit(allocator);
    try std.testing.expectError(
        error.InvalidCertificateStatus,
        writeServerFlight(
            &invalid_flight,
            allocator,
            multi_hello.items,
            parsed_multi_hello,
            .{ .ocsp_responses = &.{"leaf-status"} },
            [_]u8{0x37} ** 32,
            &server_public,
            &.{ &certificate, &certificate },
            signer,
        ),
    );

    var client_key_exchange: std.ArrayList(u8) = .empty;
    defer client_key_exchange.deinit(allocator);
    try writeClientKeyExchange(
        &client_key_exchange,
        allocator,
        &server_public,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_public,
        try parseClientKeyExchange(client_key_exchange.items),
    );

    var tls13_only = parsed;
    tls13_only.supported_versions = &.{ 3, 4 };
    try std.testing.expectError(
        error.InvalidClientHello,
        select(tls13_only, signer, .{}),
    );
}

test "TLS 1.2 CertificateVerify rejects an unadvertised signature scheme" {
    try std.testing.expect(std.mem.indexOfScalar(
        u16,
        &client_certificate_signature_schemes,
        auth.signature_scheme_ecdsa_secp521r1_sha512,
    ) != null);
    try std.testing.expect(std.mem.indexOfScalar(
        u16,
        &client_certificate_signature_schemes,
        auth.signature_scheme_sm2sig_sm3,
    ) == null);

    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(std.testing.allocator);
    try appendHandshakeHeader(
        &message,
        std.testing.allocator,
        auth.handshake_type_certificate_verify,
        5,
    );
    try appendInt(
        &message,
        std.testing.allocator,
        u16,
        auth.signature_scheme_sm2sig_sm3,
    );
    try appendInt(&message, std.testing.allocator, u16, 1);
    try message.append(std.testing.allocator, 0);
    try std.testing.expectError(
        error.UnsupportedSignatureScheme,
        verifyCertificateVerify(&.{}, message.items, "transcript"),
    );
}

test "TLS 1.2 ClientKeyExchange and Finished codecs reject bad lengths" {
    const public_key = [_]u8{0x41} ** key_exchange.p256.public_len;
    const message = [_]u8{
        handshake_type_client_key_exchange,
        0,
        0,
        66,
        key_exchange.p256.public_len,
    } ++ public_key;
    try std.testing.expectEqualSlices(
        u8,
        &public_key,
        try parseClientKeyExchange(&message),
    );
    var malformed = message;
    malformed[4] -= 1;
    try std.testing.expectError(
        error.InvalidClientKeyExchange,
        parseClientKeyExchange(&malformed),
    );

    const verify_data = [_]u8{0x42} ** tls12.finished_verify_data_len;
    var finished: [4 + tls12.finished_verify_data_len]u8 = undefined;
    writeFinished(&finished, verify_data);
    try std.testing.expectEqual(
        verify_data,
        try parseFinished(&finished),
    );
    finished[3] -= 1;
    try std.testing.expectError(
        error.InvalidFinished,
        parseFinished(&finished),
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
