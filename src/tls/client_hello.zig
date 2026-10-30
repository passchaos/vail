//! TLS ClientHello parser for interoperability tests and server negotiation.
//!
//! The parser intentionally keeps slices borrowed from the input so callers can
//! feed OpenSSL/rustls wire bytes without allocation. It validates vector
//! lengths and extracts the extensions Vail negotiates today.

const std = @import("std");
const application_settings = @import("application_settings.zig");
const auth = @import("auth.zig");
const certificate_compression = @import("certificate_compression.zig");
const cipher_suite = @import("cipher_suite.zig");
const extension_set = @import("extension_set.zig");
const record_size_limit = @import("record_size_limit.zig");
const sni_policy = @import("client_hello/sni.zig");

pub const handshake_type_client_hello: u8 = 0x01;
pub const ext_server_name: u16 = 0x0000;
pub const ext_status_request: u16 = 0x0005;
pub const ext_status_request_v2: u16 = 0x0011;
pub const ext_supported_groups: u16 = 0x000a;
pub const ext_signature_algorithms: u16 = 0x000d;
pub const ext_application_layer_protocol_negotiation: u16 = 0x0010;
pub const ext_client_certificate_type: u16 = 0x0013;
pub const ext_server_certificate_type: u16 = 0x0014;
pub const ext_extended_master_secret: u16 = 0x0017;
pub const ext_session_ticket: u16 = 0x0023;
pub const ext_compress_certificate: u16 =
    certificate_compression.extension_type_compress_certificate;
pub const ext_early_data: u16 = 0x002a;
pub const ext_certificate_authorities: u16 = 0x002f;
pub const ext_oid_filters: u16 = 0x0030;
pub const ext_signature_algorithms_cert: u16 = 0x0032;
pub const ext_record_size_limit: u16 = record_size_limit.extension_type;
pub const ext_quic_transport_parameters: u16 = 0x0039;
pub const ext_ticket_request: u16 = 0x003a;
pub const ext_renegotiation_info: u16 = 0xff01;
pub const ext_supported_versions: u16 = 0x002b;
pub const ext_cookie: u16 = 0x002c;
pub const ext_psk_key_exchange_modes: u16 = 0x002d;
pub const ext_key_share: u16 = 0x0033;
pub const ext_pre_shared_key: u16 = 0x0029;
pub const ext_encrypted_client_hello: u16 = 0xfe0d;
pub const ext_application_settings_legacy: u16 =
    application_settings.legacy_extension_type;
pub const ext_application_settings: u16 =
    application_settings.current_extension_type;
pub const tls13: u16 = 0x0304;

/// Return whether Vail implements semantics for this extension type in at
/// least one TLS handshake message.
pub fn isRecognizedExtension(extension_type: u16) bool {
    return switch (extension_type) {
        ext_server_name,
        ext_status_request,
        ext_status_request_v2,
        ext_supported_groups,
        ext_signature_algorithms,
        ext_application_layer_protocol_negotiation,
        ext_client_certificate_type,
        ext_server_certificate_type,
        ext_extended_master_secret,
        ext_session_ticket,
        ext_compress_certificate,
        ext_early_data,
        ext_certificate_authorities,
        ext_oid_filters,
        ext_signature_algorithms_cert,
        ext_record_size_limit,
        ext_quic_transport_parameters,
        ext_ticket_request,
        ext_renegotiation_info,
        ext_supported_versions,
        ext_cookie,
        ext_psk_key_exchange_modes,
        ext_key_share,
        ext_pre_shared_key,
        ext_encrypted_client_hello,
        ext_application_settings_legacy,
        ext_application_settings,
        => true,
        else => false,
    };
}

pub const default_signature_schemes = [_]u16{
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
    auth.signature_scheme_sm2sig_sm3,
};

pub const Error = error{
    InvalidClientHello,
    DuplicateExtension,
};

pub const RetryValidationError = Error || error{
    InvalidSecondClientHello,
    InvalidRetryCookie,
    EarlyDataAfterRetry,
};

pub const KeyShare = struct {
    group: u16,
    key_exchange: []const u8,
};

/// RFC 9149 ticket counts requested for a new or resumed TLS 1.3 handshake.
pub const TicketRequest = struct {
    new_session_count: u8,
    resumption_count: u8,
};

pub const WriteOptions = struct {
    random: [32]u8,
    session_id: []const u8 = &.{},
    server_name: ?[]const u8 = null,
    x25519_public_key: [32]u8,
    cipher_suites: []const cipher_suite.Suite =
        &cipher_suite.default_preference,
    additional_cipher_suites: []const u16 = &.{},
    supported_versions: []const u16 = &.{tls13},
    alpn_protocols: []const []const u8 = &.{},
    quic_transport_parameters: ?[]const u8 = null,
    signature_schemes: []const u16 = &default_signature_schemes,
    /// RFC 8446 certificate-signature constraints. Null omits the extension
    /// and leaves certificate-chain policy to the verifier.
    certificate_signature_schemes: ?[]const u16 = null,
    request_ocsp: bool = false,
    /// RFC 6961 OCSP multi-stapling request. TLS 1.3 peers ignore this
    /// extension; TLS 1.2 peers may acknowledge it instead of status_request.
    request_ocsp_multi: bool = false,
    offer_extended_master_secret: bool = false,
    record_size_limit: ?u16 = null,
    certificate_authorities: []const []const u8 = &.{},
    ticket_request: ?TicketRequest = null,
    application_settings_protocols: []const []const u8 = &.{},
    application_settings_codepoint: application_settings.Codepoint = .legacy,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{},
    server_certificate_types: []const auth.CertificateType = &.{},
    client_certificate_types: []const auth.CertificateType = &.{},
    /// Null omits RFC 5077. A non-null empty slice requests a new ticket;
    /// non-empty bytes offer a cached ticket for TLS 1.2 resumption.
    session_ticket: ?[]const u8 = null,
    /// Exact RFC 9849 ECHClientHello payload. The ECH layer constructs and
    /// authenticates this value; this writer only frames the TLS extension.
    encrypted_client_hello: ?[]const u8 = null,
};

pub const OfferedKeyShare = struct {
    group: u16,
    key_exchange: []const u8,
};

pub const FlexibleWriteOptions = struct {
    random: [32]u8,
    session_id: []const u8 = &.{},
    server_name: ?[]const u8 = null,
    /// TLS 1.3 requires a key share (or an HRR-selected retry share). TLS 1.2
    /// ClientHellos can omit the TLS 1.3-only extension while still advertising
    /// their ECDHE curves through supported_groups.
    key_share: ?OfferedKeyShare = null,
    supported_groups: []const u16 = &.{},
    cookie: ?[]const u8 = null,
    cipher_suites: []const cipher_suite.Suite =
        &cipher_suite.default_preference,
    additional_cipher_suites: []const u16 = &.{},
    supported_versions: []const u16 = &.{tls13},
    alpn_protocols: []const []const u8 = &.{},
    quic_transport_parameters: ?[]const u8 = null,
    signature_schemes: []const u16 = &default_signature_schemes,
    /// Null omits signature_algorithms_cert.
    certificate_signature_schemes: ?[]const u16 = null,
    request_ocsp: bool = false,
    request_ocsp_multi: bool = false,
    offer_extended_master_secret: bool = false,
    record_size_limit: ?u16 = null,
    certificate_authorities: []const []const u8 = &.{},
    ticket_request: ?TicketRequest = null,
    application_settings_protocols: []const []const u8 = &.{},
    application_settings_codepoint: application_settings.Codepoint = .legacy,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{},
    server_certificate_types: []const auth.CertificateType = &.{},
    client_certificate_types: []const auth.CertificateType = &.{},
    session_ticket: ?[]const u8 = null,
    encrypted_client_hello: ?[]const u8 = null,
};

/// Write a standards-focused TLS 1.3 ClientHello with one X25519 key share.
/// QUIC callers may attach their opaque transport parameters; callers needing
/// another classical or hybrid group should use `writeWithKeyShare`.
pub fn write(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: WriteOptions,
) (std.mem.Allocator.Error || Error)!void {
    return writeWithKeyShare(out, allocator, .{
        .random = options.random,
        .session_id = options.session_id,
        .server_name = options.server_name,
        .key_share = .{
            .group = 0x001d,
            .key_exchange = &options.x25519_public_key,
        },
        .supported_groups = &.{0x001d},
        .cipher_suites = options.cipher_suites,
        .additional_cipher_suites = options.additional_cipher_suites,
        .supported_versions = options.supported_versions,
        .alpn_protocols = options.alpn_protocols,
        .quic_transport_parameters = options.quic_transport_parameters,
        .signature_schemes = options.signature_schemes,
        .certificate_signature_schemes = options.certificate_signature_schemes,
        .request_ocsp = options.request_ocsp,
        .request_ocsp_multi = options.request_ocsp_multi,
        .offer_extended_master_secret = options.offer_extended_master_secret,
        .record_size_limit = options.record_size_limit,
        .certificate_authorities = options.certificate_authorities,
        .ticket_request = options.ticket_request,
        .application_settings_protocols = options.application_settings_protocols,
        .application_settings_codepoint = options.application_settings_codepoint,
        .certificate_compression_algorithms = options.certificate_compression_algorithms,
        .server_certificate_types = options.server_certificate_types,
        .client_certificate_types = options.client_certificate_types,
        .session_ticket = options.session_ticket,
        .encrypted_client_hello = options.encrypted_client_hello,
    });
}

/// Write a TLS 1.3 ClientHello with one caller-selected classical or hybrid
/// key share. The matching private material should be retained through
/// `key_exchange.ClientExchange`, not reconstructed by transport code.
pub fn writeWithKeyShare(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: FlexibleWriteOptions,
) (std.mem.Allocator.Error || Error)!void {
    if (options.session_id.len > 32 or
        (options.cipher_suites.len == 0 and
            options.additional_cipher_suites.len == 0))
    {
        return error.InvalidClientHello;
    }
    if (options.key_share) |share| {
        if (share.key_exchange.len == 0 or
            share.key_exchange.len > std.math.maxInt(u16))
        {
            return error.InvalidClientHello;
        }
    }
    var offers_tls13 = false;
    for (options.supported_versions) |version| {
        if (version == tls13) offers_tls13 = true;
    }
    if (!offers_tls13 and
        (options.certificate_authorities.len != 0 or
            options.ticket_request != null or
            options.application_settings_protocols.len != 0))
    {
        return error.InvalidClientHello;
    }
    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);

    if (options.server_name) |name| {
        if (name.len == 0) return error.InvalidClientHello;
    }
    if (sni_policy.wireName(options.server_name)) |server_name| {
        var sni: std.ArrayList(u8) = .empty;
        defer sni.deinit(allocator);
        try appendInt(&sni, allocator, u16, 3 + server_name.len);
        try sni.append(allocator, 0);
        try appendInt(&sni, allocator, u16, server_name.len);
        try sni.appendSlice(allocator, server_name);
        try appendExtension(
            &extensions,
            allocator,
            ext_server_name,
            sni.items,
        );
    }

    if (options.encrypted_client_hello) |payload| {
        if (payload.len == 0) return error.InvalidClientHello;
        try appendExtension(
            &extensions,
            allocator,
            ext_encrypted_client_hello,
            payload,
        );
    }

    if (options.request_ocsp) {
        try appendExtension(
            &extensions,
            allocator,
            ext_status_request,
            &.{ 1, 0, 0, 0, 0 },
        );
    }
    if (options.request_ocsp_multi) {
        try appendExtension(
            &extensions,
            allocator,
            ext_status_request_v2,
            &.{ 0, 7, 2, 0, 4, 0, 0, 0, 0 },
        );
    }

    if (options.certificate_compression_algorithms.len != 0) {
        certificate_compression.validateAlgorithms(
            options.certificate_compression_algorithms,
        ) catch return error.InvalidClientHello;
        var algorithms: std.ArrayList(u8) = .empty;
        defer algorithms.deinit(allocator);
        try algorithms.append(
            allocator,
            @intCast(options.certificate_compression_algorithms.len * 2),
        );
        for (options.certificate_compression_algorithms) |algorithm| {
            try appendInt(
                &algorithms,
                allocator,
                u16,
                @intFromEnum(algorithm),
            );
        }
        try appendExtension(
            &extensions,
            allocator,
            ext_compress_certificate,
            algorithms.items,
        );
    }

    if (options.offer_extended_master_secret) {
        try appendExtension(
            &extensions,
            allocator,
            ext_extended_master_secret,
            &.{},
        );
    }

    if (options.record_size_limit) |limit| {
        const payload = record_size_limit.encode(limit) catch
            return error.InvalidClientHello;
        try appendExtension(
            &extensions,
            allocator,
            ext_record_size_limit,
            &payload,
        );
    }

    if (options.certificate_authorities.len != 0) {
        var authorities: std.ArrayList(u8) = .empty;
        defer authorities.deinit(allocator);
        try authorities.appendSlice(allocator, &.{ 0, 0 });
        for (options.certificate_authorities) |name| {
            if (name.len == 0 or name.len > std.math.maxInt(u16) or
                authorities.items.len >
                    std.math.maxInt(u16) - name.len - 2)
            {
                return error.InvalidClientHello;
            }
            try appendInt(&authorities, allocator, u16, name.len);
            try authorities.appendSlice(allocator, name);
        }
        std.mem.writeInt(
            u16,
            authorities.items[0..2],
            @intCast(authorities.items.len - 2),
            .big,
        );
        try appendExtension(
            &extensions,
            allocator,
            ext_certificate_authorities,
            authorities.items,
        );
    }

    if (options.ticket_request) |request| {
        try appendExtension(
            &extensions,
            allocator,
            ext_ticket_request,
            &.{ request.new_session_count, request.resumption_count },
        );
    }

    if (options.application_settings_protocols.len != 0) {
        if (options.alpn_protocols.len == 0) {
            return error.InvalidClientHello;
        }
        for (options.application_settings_protocols) |protocol| {
            for (options.alpn_protocols) |alpn| {
                if (std.mem.eql(u8, protocol, alpn)) break;
            } else return error.InvalidClientHello;
        }
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        application_settings.appendSupportPayload(
            &payload,
            allocator,
            options.application_settings_protocols,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidApplicationSettings => return error.InvalidClientHello,
        };
        try appendExtension(
            &extensions,
            allocator,
            @intFromEnum(options.application_settings_codepoint),
            payload.items,
        );
    }

    try appendCertificateTypes(
        &extensions,
        allocator,
        ext_server_certificate_type,
        options.server_certificate_types,
    );
    try appendCertificateTypes(
        &extensions,
        allocator,
        ext_client_certificate_type,
        options.client_certificate_types,
    );
    if (options.session_ticket) |ticket| {
        try appendExtension(
            &extensions,
            allocator,
            ext_session_ticket,
            ticket,
        );
    }

    var default_group: [1]u16 = undefined;
    const offered_groups: []const u16 = if (options.supported_groups.len != 0)
        options.supported_groups
    else if (options.key_share) |share| blk: {
        default_group[0] = share.group;
        break :blk &default_group;
    } else &.{};
    if (offered_groups.len > std.math.maxInt(u16) / 2) {
        return error.InvalidClientHello;
    }
    var includes_key_share = options.key_share == null;
    for (offered_groups, 0..) |group, index| {
        if (options.key_share) |share| {
            if (group == share.group) includes_key_share = true;
        }
        for (offered_groups[0..index]) |previous| {
            if (group == previous) return error.InvalidClientHello;
        }
    }
    if (!includes_key_share) return error.InvalidClientHello;

    if (offered_groups.len != 0) {
        var groups: std.ArrayList(u8) = .empty;
        defer groups.deinit(allocator);
        try appendInt(&groups, allocator, u16, offered_groups.len * 2);
        for (offered_groups) |group| {
            try appendInt(&groups, allocator, u16, group);
        }
        try appendExtension(
            &extensions,
            allocator,
            ext_supported_groups,
            groups.items,
        );
    }

    if (options.signature_schemes.len == 0 or
        options.signature_schemes.len > std.math.maxInt(u16) / 2)
    {
        return error.InvalidClientHello;
    }
    var signatures: std.ArrayList(u8) = .empty;
    defer signatures.deinit(allocator);
    try appendInt(
        &signatures,
        allocator,
        u16,
        options.signature_schemes.len * 2,
    );
    for (options.signature_schemes, 0..) |scheme, index| {
        for (options.signature_schemes[0..index]) |previous| {
            if (scheme == previous) return error.InvalidClientHello;
        }
        try appendInt(&signatures, allocator, u16, scheme);
    }
    try appendExtension(
        &extensions,
        allocator,
        ext_signature_algorithms,
        signatures.items,
    );

    if (options.certificate_signature_schemes) |schemes| {
        if (schemes.len == 0 or schemes.len > std.math.maxInt(u16) / 2) {
            return error.InvalidClientHello;
        }
        var certificate_signatures: std.ArrayList(u8) = .empty;
        defer certificate_signatures.deinit(allocator);
        try appendInt(
            &certificate_signatures,
            allocator,
            u16,
            schemes.len * 2,
        );
        for (schemes, 0..) |scheme, index| {
            for (schemes[0..index]) |previous| {
                if (scheme == previous) return error.InvalidClientHello;
            }
            try appendInt(
                &certificate_signatures,
                allocator,
                u16,
                scheme,
            );
        }
        try appendExtension(
            &extensions,
            allocator,
            ext_signature_algorithms_cert,
            certificate_signatures.items,
        );
    }

    if (options.alpn_protocols.len != 0) {
        var alpn_names: std.ArrayList(u8) = .empty;
        defer alpn_names.deinit(allocator);
        for (options.alpn_protocols) |protocol| {
            if (protocol.len == 0 or protocol.len > std.math.maxInt(u8)) {
                return error.InvalidClientHello;
            }
            try alpn_names.append(allocator, @intCast(protocol.len));
            try alpn_names.appendSlice(allocator, protocol);
        }
        if (alpn_names.items.len > std.math.maxInt(u16)) {
            return error.InvalidClientHello;
        }
        var alpn: std.ArrayList(u8) = .empty;
        defer alpn.deinit(allocator);
        try appendInt(
            &alpn,
            allocator,
            u16,
            alpn_names.items.len,
        );
        try alpn.appendSlice(allocator, alpn_names.items);
        try appendExtension(
            &extensions,
            allocator,
            ext_application_layer_protocol_negotiation,
            alpn.items,
        );
    }

    if (options.quic_transport_parameters) |parameters| {
        try appendExtension(
            &extensions,
            allocator,
            ext_quic_transport_parameters,
            parameters,
        );
    }

    if (options.supported_versions.len != 0) {
        if (options.supported_versions.len > std.math.maxInt(u8) / 2) {
            return error.InvalidClientHello;
        }
        var versions: std.ArrayList(u8) = .empty;
        defer versions.deinit(allocator);
        try versions.append(
            allocator,
            @intCast(options.supported_versions.len * 2),
        );
        for (options.supported_versions, 0..) |version, index| {
            for (options.supported_versions[0..index]) |previous| {
                if (version == previous) return error.InvalidClientHello;
            }
            try appendInt(&versions, allocator, u16, version);
        }
        try appendExtension(
            &extensions,
            allocator,
            ext_supported_versions,
            versions.items,
        );
    }

    if (options.cookie) |cookie| {
        if (cookie.len == 0 or cookie.len > std.math.maxInt(u16)) {
            return error.InvalidClientHello;
        }
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        try appendInt(&payload, allocator, u16, cookie.len);
        try payload.appendSlice(allocator, cookie);
        try appendExtension(
            &extensions,
            allocator,
            ext_cookie,
            payload.items,
        );
    }

    if (options.key_share) |share| {
        var shares: std.ArrayList(u8) = .empty;
        defer shares.deinit(allocator);
        try appendInt(
            &shares,
            allocator,
            u16,
            4 + share.key_exchange.len,
        );
        try appendInt(&shares, allocator, u16, share.group);
        try appendInt(
            &shares,
            allocator,
            u16,
            share.key_exchange.len,
        );
        try shares.appendSlice(allocator, share.key_exchange);
        try appendExtension(
            &extensions,
            allocator,
            ext_key_share,
            shares.items,
        );
    }

    var suites: std.ArrayList(u8) = .empty;
    defer suites.deinit(allocator);
    for (options.cipher_suites, 0..) |suite, index| {
        for (options.cipher_suites[0..index]) |previous| {
            if (suite == previous) return error.InvalidClientHello;
        }
        try appendInt(
            &suites,
            allocator,
            u16,
            suite.wireValue(),
        );
    }
    for (options.additional_cipher_suites, 0..) |suite, index| {
        for (options.additional_cipher_suites[0..index]) |previous| {
            if (suite == previous) return error.InvalidClientHello;
        }
        for (options.cipher_suites) |tls13_suite| {
            if (suite == tls13_suite.wireValue()) {
                return error.InvalidClientHello;
            }
        }
        try appendInt(&suites, allocator, u16, suite);
    }
    if (suites.items.len > std.math.maxInt(u16) or
        extensions.items.len > std.math.maxInt(u16))
    {
        return error.InvalidClientHello;
    }

    const body_len = 2 + 32 + 1 + options.session_id.len +
        2 + suites.items.len + 2 + 2 + extensions.items.len;
    if (body_len > std.math.maxInt(u24)) {
        return error.InvalidClientHello;
    }
    try out.append(allocator, handshake_type_client_hello);
    try appendU24(out, allocator, @intCast(body_len));
    try appendInt(out, allocator, u16, 0x0303);
    try out.appendSlice(allocator, &options.random);
    try out.append(allocator, @intCast(options.session_id.len));
    try out.appendSlice(allocator, options.session_id);
    try appendInt(out, allocator, u16, suites.items.len);
    try out.appendSlice(allocator, suites.items);
    try out.appendSlice(allocator, &.{ 1, 0 });
    try appendInt(out, allocator, u16, extensions.items.len);
    try out.appendSlice(allocator, extensions.items);
}

pub const CertificateAuthorityIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *CertificateAuthorityIterator) ?[]const u8 {
        if (self.pos == self.bytes.len) return null;
        std.debug.assert(self.pos + 2 <= self.bytes.len);
        const len = std.mem.readInt(
            u16,
            self.bytes[self.pos..][0..2],
            .big,
        );
        self.pos += 2;
        std.debug.assert(len != 0 and len <= self.bytes.len - self.pos);
        defer self.pos += len;
        return self.bytes[self.pos..][0..len];
    }
};

pub const Parsed = struct {
    legacy_version: u16,
    random: *const [32]u8,
    session_id: []const u8,
    cipher_suites: []const u8,
    compression_methods: []const u8,
    server_name: ?[]const u8 = null,
    requests_ocsp: bool = false,
    requests_ocsp_multi: bool = false,
    offers_extended_master_secret: bool = false,
    offers_secure_renegotiation: bool = false,
    record_size_limit: ?u16 = null,
    certificate_authorities: ?[]const u8 = null,
    ticket_request: ?TicketRequest = null,
    application_settings_protocols: ?[]const u8 = null,
    application_settings_codepoint: ?application_settings.Codepoint = null,
    certificate_compression_algorithms: []const u8 = &.{},
    server_certificate_types: []const u8 = &.{},
    client_certificate_types: []const u8 = &.{},
    session_ticket: ?[]const u8 = null,
    supported_groups: []const u8 = &.{},
    signature_algorithms: []const u8 = &.{},
    signature_algorithms_cert: ?[]const u8 = null,
    alpn_protocols: []const u8 = &.{},
    quic_transport_parameters: ?[]const u8 = null,
    supported_versions: []const u8 = &.{},
    psk_key_exchange_modes: []const u8 = &.{},
    key_shares: []const u8 = &.{},
    cookie: ?[]const u8 = null,
    pre_shared_key: ?[]const u8 = null,
    early_data: bool = false,
    encrypted_client_hello: ?[]const u8 = null,

    pub fn offersTls13(self: Parsed) bool {
        return self.supportsVersion(tls13);
    }

    pub fn supportsVersion(self: Parsed, target: u16) bool {
        var pos: usize = 0;
        while (pos < self.supported_versions.len) : (pos += 2) {
            if (pos + 2 > self.supported_versions.len) return false;
            if (std.mem.readInt(u16, self.supported_versions[pos..][0..2], .big) == target) {
                return true;
            }
        }
        return false;
    }

    pub fn hasCipherSuite(self: Parsed, suite: u16) bool {
        var pos: usize = 0;
        while (pos < self.cipher_suites.len) : (pos += 2) {
            if (pos + 2 > self.cipher_suites.len) return false;
            if (std.mem.readInt(u16, self.cipher_suites[pos..][0..2], .big) == suite) {
                return true;
            }
        }
        return false;
    }

    pub fn supportsSignatureScheme(
        self: Parsed,
        target_scheme: u16,
    ) Error!bool {
        return supportsSignatureSchemeIn(
            self.signature_algorithms,
            target_scheme,
        );
    }

    pub fn supportsCertificateSignatureScheme(
        self: Parsed,
        target_scheme: u16,
    ) Error!bool {
        return supportsSignatureSchemeIn(
            self.signature_algorithms_cert orelse
                self.signature_algorithms,
            target_scheme,
        );
    }

    pub fn supportsCertificateChain(
        self: Parsed,
        chain: []const []const u8,
    ) (Error || auth.Error)!bool {
        const extension = self.signature_algorithms_cert orelse return true;
        return auth.certificateChainSupportsSchemes(
            chain,
            try parseSignatureAlgorithms(extension),
        );
    }

    fn supportsSignatureSchemeIn(
        encoded: []const u8,
        target_scheme: u16,
    ) Error!bool {
        if (encoded.len == 0) return false;
        const algorithms = try parseSignatureAlgorithms(encoded);
        var algorithm_pos: usize = 0;
        while (algorithm_pos < algorithms.len) : (algorithm_pos += 2) {
            if (std.mem.readInt(
                u16,
                algorithms[algorithm_pos..][0..2],
                .big,
            ) == target_scheme) return true;
        }
        return false;
    }

    pub fn supportsAlpnProtocol(
        self: Parsed,
        target_protocol: []const u8,
    ) Error!bool {
        if (self.alpn_protocols.len == 0) return false;
        var pos: usize = 0;
        const protocols = try readU16Vector(self.alpn_protocols, &pos);
        if (pos != self.alpn_protocols.len or protocols.len == 0) {
            return error.InvalidClientHello;
        }
        var protocol_pos: usize = 0;
        while (protocol_pos < protocols.len) {
            const protocol = try readU8Vector(protocols, &protocol_pos);
            if (protocol.len == 0) return error.InvalidClientHello;
            if (std.mem.eql(u8, protocol, target_protocol)) return true;
        }
        return false;
    }

    pub fn supportsGroup(self: Parsed, target_group: u16) Error!bool {
        if (self.supported_groups.len == 0) return false;
        var pos: usize = 0;
        const groups = try readU16Vector(self.supported_groups, &pos);
        if (pos != self.supported_groups.len or
            groups.len == 0 or groups.len % 2 != 0)
        {
            return error.InvalidClientHello;
        }
        var group_pos: usize = 0;
        while (group_pos < groups.len) : (group_pos += 2) {
            if (std.mem.readInt(
                u16,
                groups[group_pos..][0..2],
                .big,
            ) == target_group) return true;
        }
        return false;
    }

    pub fn supportsCertificateCompression(
        self: Parsed,
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

    pub fn supportsServerCertificateType(
        self: Parsed,
        certificate_type: auth.CertificateType,
    ) bool {
        return containsCertificateType(
            self.server_certificate_types,
            certificate_type,
        );
    }

    pub fn supportsClientCertificateType(
        self: Parsed,
        certificate_type: auth.CertificateType,
    ) bool {
        return containsCertificateType(
            self.client_certificate_types,
            certificate_type,
        );
    }

    pub fn certificateAuthorityIterator(
        self: Parsed,
    ) CertificateAuthorityIterator {
        return .{ .bytes = self.certificate_authorities orelse &.{} };
    }

    pub fn supportsCertificateAuthority(
        self: Parsed,
        target: []const u8,
    ) bool {
        var iterator = self.certificateAuthorityIterator();
        while (iterator.next()) |name| {
            if (std.mem.eql(u8, name, target)) return true;
        }
        return false;
    }

    pub fn supportsApplicationSettings(
        self: Parsed,
        protocol: []const u8,
    ) bool {
        return if (self.application_settings_protocols) |protocols|
            application_settings.supportsProtocol(protocols, protocol)
        else
            false;
    }

    pub fn firstKeyShare(self: Parsed) Error!?KeyShare {
        var pos: usize = 0;
        if (self.key_shares.len == 0) return null;
        const shares_len = try readU16VectorLen(self.key_shares, &pos);
        if (shares_len != self.key_shares.len - pos) return error.InvalidClientHello;
        if (pos == self.key_shares.len) return null;
        const group = try readInt(u16, self.key_shares, &pos);
        const key_exchange = try readU16Vector(self.key_shares, &pos);
        if (key_exchange.len == 0) return error.InvalidClientHello;
        return .{ .group = group, .key_exchange = key_exchange };
    }

    pub fn keyShareForGroup(self: Parsed, target_group: u16) Error!?KeyShare {
        var pos: usize = 0;
        if (self.key_shares.len == 0) return null;
        const shares_len = try readU16VectorLen(self.key_shares, &pos);
        if (shares_len != self.key_shares.len - pos) return error.InvalidClientHello;
        while (pos < self.key_shares.len) {
            const group = try readInt(u16, self.key_shares, &pos);
            const key_exchange = try readU16Vector(self.key_shares, &pos);
            if (key_exchange.len == 0) return error.InvalidClientHello;
            if (group == target_group) return .{ .group = group, .key_exchange = key_exchange };
        }
        return null;
    }
};

pub fn parse(bytes: []const u8) Error!Parsed {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_client_hello) {
        return error.InvalidClientHello;
    }
    const body_len = try readU24(bytes, &pos);
    if (body_len != bytes.len - pos) return error.InvalidClientHello;
    const legacy_version = try readInt(u16, bytes, &pos);
    const random = (try readSlice(bytes, &pos, 32))[0..32];
    const session_id = try readU8Vector(bytes, &pos);
    const cipher_suites = try readU16Vector(bytes, &pos);
    if (cipher_suites.len == 0 or cipher_suites.len % 2 != 0) {
        return error.InvalidClientHello;
    }
    const compression_methods = try readU8Vector(bytes, &pos);
    if (compression_methods.len == 0) return error.InvalidClientHello;
    var parsed = Parsed{
        .legacy_version = legacy_version,
        .random = random,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
    };
    parsed.offers_secure_renegotiation = parsed.hasCipherSuite(0x00ff);
    if (pos == bytes.len) return parsed;
    const extensions = try readU16Vector(bytes, &pos);
    if (pos != bytes.len) return error.InvalidClientHello;
    var seen: extension_set.Set = undefined;
    seen.reset();
    var ext_pos: usize = 0;
    while (ext_pos < extensions.len) {
        const typ = try readInt(u16, extensions, &ext_pos);
        const payload = try readU16Vector(extensions, &ext_pos);
        if (seen.containsOrInsert(typ)) return error.DuplicateExtension;
        switch (typ) {
            ext_server_name => parsed.server_name = try parseSni(payload),
            ext_status_request => {
                parsed.requests_ocsp = try parseStatusRequest(payload);
            },
            ext_status_request_v2 => {
                parsed.requests_ocsp_multi = try parseStatusRequestV2(payload);
            },
            ext_supported_groups => parsed.supported_groups = payload,
            ext_signature_algorithms => parsed.signature_algorithms = payload,
            ext_signature_algorithms_cert => {
                _ = try parseSignatureAlgorithms(payload);
                parsed.signature_algorithms_cert = payload;
            },
            ext_application_layer_protocol_negotiation => parsed.alpn_protocols = payload,
            ext_extended_master_secret => {
                if (payload.len != 0) return error.InvalidClientHello;
                parsed.offers_extended_master_secret = true;
            },
            ext_record_size_limit => {
                parsed.record_size_limit = record_size_limit.parse(payload) catch
                    return error.InvalidClientHello;
            },
            ext_certificate_authorities => {
                parsed.certificate_authorities =
                    try parseCertificateAuthorities(payload);
            },
            ext_ticket_request => {
                if (payload.len != 2) return error.InvalidClientHello;
                parsed.ticket_request = .{
                    .new_session_count = payload[0],
                    .resumption_count = payload[1],
                };
            },
            ext_application_settings_legacy,
            ext_application_settings,
            => {
                if (parsed.application_settings_protocols != null) {
                    return error.DuplicateExtension;
                }
                parsed.application_settings_codepoint = if (typ == ext_application_settings_legacy) .legacy else .current;
                parsed.application_settings_protocols =
                    application_settings.parseSupportPayload(payload) catch
                        return error.InvalidClientHello;
            },
            ext_server_certificate_type => {
                parsed.server_certificate_types =
                    try parseCertificateTypes(payload);
            },
            ext_client_certificate_type => {
                parsed.client_certificate_types =
                    try parseCertificateTypes(payload);
            },
            ext_session_ticket => parsed.session_ticket = payload,
            ext_compress_certificate => {
                parsed.certificate_compression_algorithms =
                    try parseCertificateCompressionAlgorithms(payload);
            },
            ext_quic_transport_parameters => parsed.quic_transport_parameters = payload,
            ext_supported_versions => parsed.supported_versions = try parseSupportedVersions(payload),
            ext_cookie => parsed.cookie = try parseCookie(payload),
            ext_early_data => {
                if (payload.len != 0) return error.InvalidClientHello;
                parsed.early_data = true;
            },
            ext_psk_key_exchange_modes => parsed.psk_key_exchange_modes = try parseU8List(payload),
            ext_key_share => parsed.key_shares = payload,
            ext_pre_shared_key => parsed.pre_shared_key = payload,
            ext_encrypted_client_hello => {
                if (payload.len == 0) return error.InvalidClientHello;
                parsed.encrypted_client_hello = payload;
            },
            ext_renegotiation_info => {
                if (!std.mem.eql(u8, payload, &.{0})) {
                    return error.InvalidClientHello;
                }
                parsed.offers_secure_renegotiation = true;
            },
            else => {},
        }
    }
    if (parsed.application_settings_protocols) |protocols| {
        var iterator = application_settings.ProtocolIterator{
            .bytes = protocols,
        };
        while (iterator.next()) |protocol| {
            if (!try parsed.supportsAlpnProtocol(protocol)) {
                return error.InvalidClientHello;
            }
        }
    }
    return parsed;
}

fn parseSni(payload: []const u8) Error!?[]const u8 {
    var pos: usize = 0;
    const list = try readU16Vector(payload, &pos);
    if (pos != payload.len or list.len == 0) return error.InvalidClientHello;
    var list_pos: usize = 0;
    var first_host: ?[]const u8 = null;
    while (list_pos < list.len) {
        const name_type = try readByte(list, &list_pos);
        const name = try readU16Vector(list, &list_pos);
        if (name.len == 0) return error.InvalidClientHello;
        if (name_type == 0 and first_host == null) first_host = name;
    }
    return first_host;
}

fn parseStatusRequest(payload: []const u8) Error!bool {
    var pos: usize = 0;
    const status_type = try readByte(payload, &pos);
    if (status_type != 1) return false;
    try parseOcspStatusRequest(payload[pos..]);
    return true;
}

fn parseStatusRequestV2(payload: []const u8) Error!bool {
    var pos: usize = 0;
    const requests = try readU16Vector(payload, &pos);
    if (pos != payload.len or requests.len == 0) {
        return error.InvalidClientHello;
    }
    var request_pos: usize = 0;
    var requests_multi = false;
    while (request_pos < requests.len) {
        const status_type = try readByte(requests, &request_pos);
        const request = try readU16Vector(requests, &request_pos);
        switch (status_type) {
            1 => try parseOcspStatusRequest(request),
            2 => {
                try parseOcspStatusRequest(request);
                requests_multi = true;
            },
            else => {},
        }
    }
    return requests_multi;
}

fn parseOcspStatusRequest(payload: []const u8) Error!void {
    var pos: usize = 0;
    const responder_ids = try readU16Vector(payload, &pos);
    var responder_pos: usize = 0;
    while (responder_pos < responder_ids.len) {
        const responder_id = try readU16Vector(
            responder_ids,
            &responder_pos,
        );
        if (responder_id.len == 0) return error.InvalidClientHello;
    }
    _ = try readU16Vector(payload, &pos);
    if (pos != payload.len) return error.InvalidClientHello;
}

fn parseCertificateCompressionAlgorithms(
    payload: []const u8,
) Error![]const u8 {
    var pos: usize = 0;
    const algorithms = try readU8Vector(payload, &pos);
    if (pos != payload.len or algorithms.len == 0 or
        algorithms.len % 2 != 0)
    {
        return error.InvalidClientHello;
    }
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
            )) return error.InvalidClientHello;
        }
    }
    return algorithms;
}

fn parseCertificateAuthorities(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const authorities = try readU16Vector(payload, &pos);
    if (pos != payload.len or authorities.len < 3) {
        return error.InvalidClientHello;
    }
    var authority_pos: usize = 0;
    while (authority_pos < authorities.len) {
        const name = try readU16Vector(authorities, &authority_pos);
        if (name.len == 0) return error.InvalidClientHello;
    }
    return authorities;
}

fn parseSupportedVersions(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const versions = try readU8Vector(payload, &pos);
    if (pos != payload.len or versions.len == 0 or versions.len % 2 != 0) {
        return error.InvalidClientHello;
    }
    return versions;
}

fn parseU8List(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const list = try readU8Vector(payload, &pos);
    if (pos != payload.len) return error.InvalidClientHello;
    return list;
}

fn parseCookie(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const cookie = try readU16Vector(payload, &pos);
    if (cookie.len == 0 or pos != payload.len) {
        return error.InvalidClientHello;
    }
    return cookie;
}

fn appendCertificateTypes(
    extensions: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    extension_type: u16,
    certificate_types: []const auth.CertificateType,
) (std.mem.Allocator.Error || Error)!void {
    if (certificate_types.len == 0) return;
    if (certificate_types.len > std.math.maxInt(u8)) {
        return error.InvalidClientHello;
    }
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.append(allocator, @intCast(certificate_types.len));
    for (certificate_types, 0..) |certificate_type, index| {
        for (certificate_types[0..index]) |previous| {
            if (previous == certificate_type) return error.InvalidClientHello;
        }
        try payload.append(allocator, @intFromEnum(certificate_type));
    }
    try appendExtension(
        extensions,
        allocator,
        extension_type,
        payload.items,
    );
}

fn parseCertificateTypes(payload: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const values = try readU8Vector(payload, &pos);
    if (values.len == 0 or pos != payload.len) {
        return error.InvalidClientHello;
    }
    for (values, 0..) |value, index| {
        for (values[0..index]) |previous| {
            if (previous == value) return error.InvalidClientHello;
        }
    }
    return values;
}

fn containsCertificateType(
    values: []const u8,
    target: auth.CertificateType,
) bool {
    for (values) |value| {
        if (value == @intFromEnum(target)) return true;
    }
    return false;
}

fn parseSignatureAlgorithms(encoded: []const u8) Error![]const u8 {
    var pos: usize = 0;
    const algorithms = try readU16Vector(encoded, &pos);
    if (pos != encoded.len or algorithms.len == 0 or
        algorithms.len % 2 != 0)
    {
        return error.InvalidClientHello;
    }
    // RFC 5246 and RFC 8446 constrain framing, not value uniqueness.
    return algorithms;
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    const out = try readSlice(bytes, pos, 1);
    return out[0];
}

fn readInt(comptime T: type, bytes: []const u8, pos: *usize) Error!T {
    const out = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, out[0..@sizeOf(T)], .big);
}

fn readU24(bytes: []const u8, pos: *usize) Error!usize {
    const out = try readSlice(bytes, pos, 3);
    return (@as(usize, out[0]) << 16) | (@as(usize, out[1]) << 8) | out[2];
}

fn readU8Vector(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readByte(bytes, pos);
    return readSlice(bytes, pos, len);
}

fn readU16VectorLen(bytes: []const u8, pos: *usize) Error!usize {
    return @intCast(try readInt(u16, bytes, pos));
}

fn readU16Vector(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16VectorLen(bytes, pos);
    return readSlice(bytes, pos, len);
}

fn readSlice(bytes: []const u8, pos: *usize, len: usize) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch return error.InvalidClientHello;
    if (end > bytes.len) return error.InvalidClientHello;
    defer pos.* = end;
    return bytes[pos.*..end];
}

/// Enforce the RFC 8446 ClientHello2 consistency rules for the fields Vail
/// understands. Only the HRR-selected key share, cookie, PSK binders, removal
/// of early_data, and padding may differ from ClientHello1.
pub fn validateSecondClientHello(
    first_bytes: []const u8,
    second: Parsed,
    selected_group: u16,
    expected_cookie: ?[]const u8,
) RetryValidationError!void {
    const first = try parse(first_bytes);
    if (first.legacy_version != second.legacy_version or
        !std.mem.eql(u8, first.random, second.random) or
        !std.mem.eql(u8, first.session_id, second.session_id) or
        !std.mem.eql(u8, first.cipher_suites, second.cipher_suites) or
        !std.mem.eql(u8, first.compression_methods, second.compression_methods) or
        !optionalBytesEql(first.server_name, second.server_name) or
        first.requests_ocsp != second.requests_ocsp or
        first.requests_ocsp_multi != second.requests_ocsp_multi or
        first.offers_extended_master_secret !=
            second.offers_extended_master_secret or
        first.record_size_limit != second.record_size_limit or
        !optionalBytesEql(
            first.certificate_authorities,
            second.certificate_authorities,
        ) or
        !std.meta.eql(first.ticket_request, second.ticket_request) or
        first.application_settings_codepoint !=
            second.application_settings_codepoint or
        !optionalBytesEql(
            first.application_settings_protocols,
            second.application_settings_protocols,
        ) or
        first.offers_secure_renegotiation !=
            second.offers_secure_renegotiation or
        !std.mem.eql(
            u8,
            first.certificate_compression_algorithms,
            second.certificate_compression_algorithms,
        ) or
        !std.mem.eql(
            u8,
            first.server_certificate_types,
            second.server_certificate_types,
        ) or
        !std.mem.eql(
            u8,
            first.client_certificate_types,
            second.client_certificate_types,
        ) or
        !optionalBytesEql(first.session_ticket, second.session_ticket) or
        !std.mem.eql(u8, first.supported_groups, second.supported_groups) or
        !std.mem.eql(u8, first.signature_algorithms, second.signature_algorithms) or
        !optionalBytesEql(
            first.signature_algorithms_cert,
            second.signature_algorithms_cert,
        ) or
        !std.mem.eql(u8, first.alpn_protocols, second.alpn_protocols) or
        !std.mem.eql(u8, first.supported_versions, second.supported_versions) or
        !std.mem.eql(u8, first.psk_key_exchange_modes, second.psk_key_exchange_modes) or
        !optionalBytesEql(
            first.encrypted_client_hello,
            second.encrypted_client_hello,
        ) or
        !optionalBytesEql(
            first.quic_transport_parameters,
            second.quic_transport_parameters,
        ) or
        ((first.pre_shared_key == null) !=
            (second.pre_shared_key == null)))
    {
        return error.InvalidSecondClientHello;
    }
    if (second.early_data) return error.EarlyDataAfterRetry;
    if (!optionalBytesEql(expected_cookie, second.cookie)) {
        return error.InvalidRetryCookie;
    }
    if (try first.keyShareForGroup(selected_group) != null) {
        return error.InvalidSecondClientHello;
    }
    const share = (try second.keyShareForGroup(selected_group)) orelse
        return error.InvalidSecondClientHello;
    if (second.key_shares.len != 2 + 2 + 2 + share.key_exchange.len) {
        return error.InvalidSecondClientHello;
    }
}

fn optionalBytesEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

test "ClientHello IP identities omit SNI in TLS 1.2 and TLS 1.3" {
    const allocator = std.testing.allocator;
    const versions = [_][]const u16{ &.{0x0303}, &.{0x0304}, &.{ 0x0304, 0x0303 } };
    for (versions) |offered| {
        for ([_][]const u8{ "127.0.0.1", "::1", "::ffff:192.0.2.1", "example.com" }) |identity| {
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try writeWithKeyShare(&encoded, allocator, .{
                .random = [_]u8{0x79} ** 32,
                .server_name = identity,
                .key_share = .{ .group = 0x001d, .key_exchange = &([_]u8{0x7a} ** 32) },
                .supported_versions = offered,
                .alpn_protocols = &.{"h2"},
            });
            const parsed = try parse(encoded.items);
            if (std.mem.eql(u8, identity, "example.com")) {
                try std.testing.expectEqualStrings(identity, parsed.server_name.?);
            } else {
                try std.testing.expect(parsed.server_name == null);
            }
            try std.testing.expect(try parsed.supportsAlpnProtocol("h2"));
            try std.testing.expect((try parsed.keyShareForGroup(0x001d)) != null);
        }
    }
}

test "ClientHello writer carries an arbitrary single key share" {
    const allocator = std.testing.allocator;
    const hybrid_share = [_]u8{0x7a} ** 1216;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeWithKeyShare(&encoded, allocator, .{
        .random = [_]u8{0x79} ** 32,
        .server_name = "example.com",
        .key_share = .{
            .group = 0x11ec,
            .key_exchange = &hybrid_share,
        },
        .supported_groups = &.{ 0x11ec, 0x001d },
        .cookie = "retry-cookie",
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{ "h3", "test" },
    });
    const parsed = try parse(encoded.items);
    const share = (try parsed.keyShareForGroup(0x11ec)).?;
    try std.testing.expectEqualSlices(
        u8,
        &hybrid_share,
        share.key_exchange,
    );
    try std.testing.expect(try parsed.supportsAlpnProtocol("h3"));
    try std.testing.expect(!try parsed.supportsAlpnProtocol("h2"));
    try std.testing.expect(try parsed.supportsGroup(0x11ec));
    try std.testing.expect(try parsed.supportsGroup(0x001d));
    try std.testing.expectEqualStrings("retry-cookie", parsed.cookie.?);
}

test "HelloRetryRequest preserves certificate signature algorithms" {
    const allocator = std.testing.allocator;
    const groups = &.{ @as(u16, 0x001d), @as(u16, 0x0017) };
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try writeWithKeyShare(&first, allocator, .{
        .random = [_]u8{0x73} ** 32,
        .key_share = .{
            .group = 0x001d,
            .key_exchange = &([_]u8{0x74} ** 32),
        },
        .supported_groups = groups,
        .certificate_signature_schemes = &.{auth.signature_scheme_ed25519},
    });
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try writeWithKeyShare(&second, allocator, .{
        .random = [_]u8{0x73} ** 32,
        .key_share = .{
            .group = 0x0017,
            .key_exchange = &([_]u8{0x04} ++ ([_]u8{0x75} ** 64)),
        },
        .supported_groups = groups,
        .cookie = "cookie",
        .certificate_signature_schemes = &.{
            auth.signature_scheme_rsa_pss_rsae_sha256,
        },
    });
    try std.testing.expectError(
        error.InvalidSecondClientHello,
        validateSecondClientHello(
            first.items,
            try parse(second.items),
            0x0017,
            "cookie",
        ),
    );
}

test "RFC 7250 certificate type lists round-trip and validate structure" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try write(&encoded, allocator, .{
        .random = [_]u8{0x7b} ** 32,
        .x25519_public_key = [_]u8{0x7c} ** 32,
        .server_certificate_types = &.{.raw_public_key},
        .client_certificate_types = &.{ .raw_public_key, .x509 },
    });
    const parsed = try parse(encoded.items);
    try std.testing.expect(parsed.supportsServerCertificateType(
        .raw_public_key,
    ));
    try std.testing.expect(!parsed.supportsServerCertificateType(.x509));
    try std.testing.expect(parsed.supportsClientCertificateType(
        .raw_public_key,
    ));
    try std.testing.expect(parsed.supportsClientCertificateType(.x509));

    try std.testing.expectError(
        error.InvalidClientHello,
        parseCertificateTypes(&.{}),
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        parseCertificateTypes(&.{ 2, 2, 2 }),
    );
    const future_type = try parseCertificateTypes(&.{ 1, 254 });
    try std.testing.expectEqualSlices(u8, &.{254}, future_type);
}

test "RFC 5077 session ticket request and offer round-trip" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try write(&encoded, allocator, .{
        .random = [_]u8{0x7d} ** 32,
        .x25519_public_key = [_]u8{0x7e} ** 32,
        .session_ticket = &.{},
    });
    const request = try parse(encoded.items);
    try std.testing.expect(request.session_ticket != null);
    try std.testing.expectEqual(@as(usize, 0), request.session_ticket.?.len);

    encoded.clearRetainingCapacity();
    try write(&encoded, allocator, .{
        .random = [_]u8{0x7f} ** 32,
        .x25519_public_key = [_]u8{0x80} ** 32,
        .session_ticket = "opaque-ticket",
    });
    const offer = try parse(encoded.items);
    try std.testing.expectEqualStrings("opaque-ticket", offer.session_ticket.?);
}

test "certificate authorities reject empty and truncated names" {
    try std.testing.expectError(
        error.InvalidClientHello,
        parseCertificateAuthorities(&.{ 0, 0 }),
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        parseCertificateAuthorities(&.{ 0, 2, 0, 0 }),
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        parseCertificateAuthorities(&.{ 0, 3, 0, 2, 0xaa }),
    );
}

test "certificate signature algorithm lists validate framing and preserve duplicates" {
    try std.testing.expectError(
        error.InvalidClientHello,
        parseSignatureAlgorithms(&.{ 0, 0 }),
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        parseSignatureAlgorithms(&.{ 0, 1, 0x08 }),
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        parseSignatureAlgorithms(&.{ 0, 2, 0x08 }),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x07, 0x08, 0x07 },
        try parseSignatureAlgorithms(
            &.{ 0, 4, 0x08, 0x07, 0x08, 0x07 },
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x07, 0x08, 0x04 },
        try parseSignatureAlgorithms(
            &.{ 0, 4, 0x08, 0x07, 0x08, 0x04 },
        ),
    );
}

test "TLS 1.2 ClientHello omits the TLS 1.3 key_share extension" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try writeWithKeyShare(&encoded, std.testing.allocator, .{
        .random = [_]u8{0x2a} ** 32,
        .server_name = "example.com",
        .key_share = null,
        .supported_groups = &.{0x0017},
        .cipher_suites = &.{},
        .additional_cipher_suites = &.{ 0xc02f, 0x00ff },
        .supported_versions = &.{0x0303},
        .offer_extended_master_secret = true,
    });
    const parsed = try parse(encoded.items);
    try std.testing.expectEqual(@as(usize, 0), parsed.key_shares.len);
    try std.testing.expect(try parsed.supportsGroup(0x0017));
    try std.testing.expect(parsed.hasCipherSuite(0xc02f));
    try std.testing.expect(parsed.hasCipherSuite(0x00ff));
    try std.testing.expect(parsed.supportsVersion(0x0303));
    try std.testing.expect(parsed.offers_extended_master_secret);
    try std.testing.expect(parsed.offers_secure_renegotiation);
}

test "RFC 6961 status_request_v2 is strict and round-trips" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try writeWithKeyShare(&encoded, std.testing.allocator, .{
        .random = [_]u8{0x2b} ** 32,
        .key_share = null,
        .supported_groups = &.{0x0017},
        .cipher_suites = &.{},
        .additional_cipher_suites = &.{0xc02f},
        .supported_versions = &.{0x0303},
        .request_ocsp = true,
        .request_ocsp_multi = true,
    });
    const parsed = try parse(encoded.items);
    try std.testing.expect(parsed.requests_ocsp);
    try std.testing.expect(parsed.requests_ocsp_multi);

    try std.testing.expect(try parseStatusRequestV2(
        &.{ 0, 7, 2, 0, 4, 0, 0, 0, 0 },
    ));
    try std.testing.expect(try parseStatusRequestV2(
        &.{ 0, 14, 1, 0, 4, 0, 0, 0, 0, 2, 0, 4, 0, 0, 0, 0 },
    ));
    try std.testing.expect(try parseStatusRequestV2(
        &.{ 0, 14, 2, 0, 4, 0, 0, 0, 0, 2, 0, 4, 0, 0, 0, 0 },
    ));
    try std.testing.expect(!(try parseStatusRequestV2(
        &.{ 0, 3, 0xfe, 0, 0 },
    )));

    const invalid = [_][]const u8{
        &.{ 0, 0 },
        &.{ 0, 7, 2, 0, 4, 0, 0, 0 },
        &.{ 0, 7, 2, 0, 3, 0, 0, 0 },
    };
    for (invalid) |payload| {
        try std.testing.expectError(
            error.InvalidClientHello,
            parseStatusRequestV2(payload),
        );
    }
}

fn appendExtension(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u16,
    payload: []const u8,
) (std.mem.Allocator.Error || Error)!void {
    if (payload.len > std.math.maxInt(u16)) {
        return error.InvalidClientHello;
    }
    try appendInt(out, allocator, u16, typ);
    try appendInt(out, allocator, u16, payload.len);
    try out.appendSlice(allocator, payload);
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: anytype,
) std.mem.Allocator.Error!void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .big);
    try out.appendSlice(allocator, &bytes);
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

test "stream ClientHello writer round-trips without QUIC extensions" {
    const allocator = std.testing.allocator;
    const public_key = [_]u8{0x44} ** 32;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try write(&encoded, allocator, .{
        .random = [_]u8{0x33} ** 32,
        .session_id = "session",
        .server_name = "mqtt.example",
        .x25519_public_key = public_key,
        .cipher_suites = &.{
            .aes_256_gcm_sha384,
            .aes_128_gcm_sha256,
        },
        .request_ocsp = true,
        .certificate_signature_schemes = &.{auth.signature_scheme_ed25519},
        .record_size_limit = 4096,
        .certificate_authorities = &.{
            &.{ 0x30, 0x03, 0x31, 0x01, 0x41 },
            &.{ 0x30, 0x03, 0x31, 0x01, 0x42 },
        },
        .ticket_request = .{
            .new_session_count = 3,
            .resumption_count = 2,
        },
        .alpn_protocols = &.{ "h2", "http/1.1" },
        .application_settings_protocols = &.{"h2"},
        .application_settings_codepoint = .current,
        .certificate_compression_algorithms = &.{.zlib},
    });
    const parsed = try parse(encoded.items);
    try std.testing.expect(parsed.offersTls13());
    try std.testing.expect(parsed.requests_ocsp);
    try std.testing.expect(parsed.signature_algorithms_cert != null);
    try std.testing.expect(try parsed.supportsCertificateSignatureScheme(
        auth.signature_scheme_ed25519,
    ));
    try std.testing.expect(!try parsed.supportsCertificateSignatureScheme(
        auth.signature_scheme_rsa_pss_rsae_sha256,
    ));
    try std.testing.expect(try parsed.supportsSignatureScheme(
        auth.signature_scheme_rsa_pss_rsae_sha256,
    ));
    var fallback_algorithms = parsed;
    fallback_algorithms.signature_algorithms_cert = null;
    try std.testing.expect(try fallback_algorithms.supportsCertificateSignatureScheme(
        auth.signature_scheme_rsa_pss_rsae_sha256,
    ));
    var malformed_algorithms = parsed;
    malformed_algorithms.signature_algorithms_cert = &.{ 0, 0 };
    try std.testing.expectError(
        error.InvalidClientHello,
        malformed_algorithms.supportsCertificateSignatureScheme(
            auth.signature_scheme_ed25519,
        ),
    );
    try std.testing.expectEqual(@as(?u16, 4096), parsed.record_size_limit);
    var authorities = parsed.certificateAuthorityIterator();
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x03, 0x31, 0x01, 0x41 },
        authorities.next().?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x03, 0x31, 0x01, 0x42 },
        authorities.next().?,
    );
    try std.testing.expect(authorities.next() == null);
    try std.testing.expect(parsed.supportsCertificateAuthority(
        &.{ 0x30, 0x03, 0x31, 0x01, 0x42 },
    ));
    try std.testing.expectEqual(
        TicketRequest{ .new_session_count = 3, .resumption_count = 2 },
        parsed.ticket_request.?,
    );
    try std.testing.expect(parsed.supportsApplicationSettings("h2"));
    try std.testing.expect(!parsed.supportsApplicationSettings("http/1.1"));
    try std.testing.expectEqual(
        application_settings.Codepoint.current,
        parsed.application_settings_codepoint.?,
    );
    try std.testing.expect(parsed.supportsCertificateCompression(.zlib));
    try std.testing.expect(!parsed.supportsCertificateCompression(.brotli));
    try std.testing.expectEqualStrings(
        "mqtt.example",
        parsed.server_name.?,
    );
    try std.testing.expectEqualStrings("session", parsed.session_id);
    const share = (try parsed.keyShareForGroup(0x001d)).?;
    try std.testing.expectEqualSlices(
        u8,
        &public_key,
        share.key_exchange,
    );
    try std.testing.expect(parsed.quic_transport_parameters == null);

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientHello,
        write(&encoded, allocator, .{
            .random = [_]u8{0x55} ** 32,
            .x25519_public_key = public_key,
            .record_size_limit = record_size_limit.min - 1,
        }),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientHello,
        write(&encoded, allocator, .{
            .random = [_]u8{0x58} ** 32,
            .x25519_public_key = public_key,
            .certificate_signature_schemes = &.{},
        }),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientHello,
        write(&encoded, allocator, .{
            .random = [_]u8{0x56} ** 32,
            .x25519_public_key = public_key,
            .certificate_authorities = &.{&.{}},
        }),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientHello,
        write(&encoded, allocator, .{
            .random = [_]u8{0x57} ** 32,
            .x25519_public_key = public_key,
            .alpn_protocols = &.{"h2"},
            .application_settings_protocols = &.{"h3"},
        }),
    );
}

test "ClientHello parser extracts a minimal TLS 1.3 offer" {
    const hello = [_]u8{
        0x01, 0x00, 0x00, 0x6c, 0x03, 0x03,
    } ++ ([_]u8{0x11} ** 32) ++ [_]u8{
        0x00, // session id
        0x00,
        0x04,
        0x13,
        0x01,
        0x13,
        0x03,
        0x01,
        0x00,
        0x00,
        0x3f,
        0x00,
        0x2b,
        0x00,
        0x03,
        0x02,
        0x03,
        0x04,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x0e,
        0x00,
        0x00,
        0x0b,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        '.',
        'c',
        'o',
        'm',
        0x00,
        0x0a,
        0x00,
        0x06,
        0x00,
        0x04,
        0x00,
        0x1d,
        0x00,
        0x17,
        0x00,
        0x0d,
        0x00,
        0x06,
        0x00,
        0x04,
        0x08,
        0x07,
        0x04,
        0x03,
        0x00,
        0x33,
        0x00,
        0x0c,
        0x00,
        0x0a,
        0x00,
        0x1d,
        0x00,
        0x06,
        1,
        2,
        3,
        4,
        5,
        6,
    };
    const parsed = try parse(&hello);
    try std.testing.expect(parsed.offersTls13());
    try std.testing.expect(parsed.hasCipherSuite(0x1301));
    try std.testing.expectEqualStrings("example.com", parsed.server_name.?);
    const share = (try parsed.firstKeyShare()).?;
    try std.testing.expectEqual(@as(u16, 0x001d), share.group);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, share.key_exchange);
    const same_share = (try parsed.keyShareForGroup(0x001d)).?;
    try std.testing.expectEqualSlices(u8, share.key_exchange, same_share.key_exchange);
    try std.testing.expectEqual(@as(?KeyShare, null), try parsed.keyShareForGroup(0x0020));
}

test "ClientHello parser exposes QUIC transport parameters extension" {
    const hello = [_]u8{
        0x01, 0x00, 0x00, 0x32, 0x03, 0x03,
    } ++ ([_]u8{0x22} ** 32) ++ [_]u8{
        0x00, // empty legacy_session_id
        0x00,
        0x02,
        0x13,
        0x01,
        0x01,
        0x00,
        0x00,
        0x07,
        0x00,
        0x39,
        0x00,
        0x03,
        1,
        2,
        3,
    };
    const parsed = try parse(&hello);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 2, 3 },
        parsed.quic_transport_parameters.?,
    );
}

test "ClientHello writer round-trips QUIC transport parameters" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try write(&encoded, std.testing.allocator, .{
        .random = [_]u8{0x23} ** 32,
        .x25519_public_key = [_]u8{0x24} ** 32,
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 0x01, 0x02, 0x03 },
    });
    const parsed = try parse(encoded.items);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x02, 0x03 },
        parsed.quic_transport_parameters.?,
    );
}
