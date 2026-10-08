//! Strict RFC 5280 responder discovery plus issuer- and
//! delegated-responder-signed RFC 6960 request/response handling.
//!
//! A result is returned only after CertID binding, responder identity,
//! responder authorization, signature, and time-window verification succeed.
//! Response and SingleResponse extensions are bounded, unknown critical
//! extensions fail closed, and RFC 8954 response nonces can be matched exactly.

const std = @import("std");
const certificate_compat = @import("certificate.zig");
const distinguished_name = @import("distinguished_name.zig");
const x509_signature = @import("signature.zig");

const Certificate = std.crypto.Certificate;
const Sha1 = std.crypto.hash.Sha1;
const Sha224 = std.crypto.hash.sha2.Sha224;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha512_224 = std.crypto.hash.sha2.Sha512_224;
const Sha512_256 = std.crypto.hash.sha2.Sha512_256;
const Sha3_224 = std.crypto.hash.sha3.Sha3_224;
const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const Sha3_384 = std.crypto.hash.sha3.Sha3_384;
const Sha3_512 = std.crypto.hash.sha3.Sha3_512;

const oid_basic_response = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
};
const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
const oid_sha256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
};
const oid_sha384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
};
const oid_sha512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
};
const oid_sha224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
};
const oid_sha512_224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
};
const oid_sha512_256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
};
const oid_sha3_224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
};
const oid_sha3_256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
};
const oid_sha3_384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
};
const oid_sha3_512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
};
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f };
const oid_extended_key_usage = [_]u8{ 0x55, 0x1d, 0x25 };
const oid_ocsp_signing = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09,
};
const oid_ocsp_no_check = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05,
};
const oid_ocsp_nonce = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02,
};
const oid_authority_information_access = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01,
};
const oid_ad_ocsp = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
};
const oid_ad_ca_issuers = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02,
};
const max_extensions_per_scope = 32;
const max_access_descriptions = 32;
const max_nonce_len = 32;
pub const max_request_len = 512;
pub const max_request_entries = 16;
pub const max_batch_request_len = max_request_entries * 264 + 96;
pub const max_verification_targets = 16;

pub const Status = enum {
    good,
    revoked,
    unknown,
};

pub const Policy = struct {
    clock_skew_seconds: u64 = 300,
    max_age_without_next_update_seconds: u64 = 24 * 60 * 60,
    max_response_bytes: usize = 64 * 1024,
    max_embedded_responder_certificates: usize = 8,
    /// When set, require an RFC 8954 response nonce with these exact bytes.
    /// A syntactically valid unsolicited nonce is otherwise ignored, as TLS
    /// stapling does not carry the corresponding OCSP request.
    expected_nonce: ?[]const u8 = null,
    max_extensions: usize = max_extensions_per_scope,
};

pub const RequestOptions = struct {
    hash: CertIdHash = .sha256,
    nonce: ?[]const u8 = null,
};

pub const RequestTarget = struct {
    certificate_der: []const u8,
    issuer_der: []const u8,
};

pub const Error = error{
    InvalidOcspResponse,
    OcspResponseUnsuccessful,
    UnsupportedResponseType,
    UnsupportedResponder,
    UnsupportedHashAlgorithm,
    UnsupportedSignatureAlgorithm,
    UnsupportedExtension,
    InvalidResponder,
    InvalidCertId,
    CertificateStatusNotFound,
    DuplicateCertificateStatus,
    OcspResponseNotYetValid,
    OcspResponseExpired,
    InvalidOcspSignature,
    InvalidIssuer,
    UnauthorizedResponder,
    DuplicateResponder,
    TooManyResponderCertificates,
    TooManyExtensions,
    OcspResponseTooLarge,
    InvalidNonce,
    MissingNonce,
    NonceMismatch,
    BufferTooSmall,
    InvalidCertificate,
    InvalidAuthorityInfoAccess,
    CriticalAuthorityInfoAccess,
    DuplicateAuthorityInfoAccess,
    TooManyAccessDescriptions,
    InvalidRequestCount,
    InvalidStatusCount,
    DuplicateCertificateTarget,
};

/// Allocation-free iterator over RFC 5280 id-ad-ocsp URIs. Returned slices
/// borrow the certificate passed to `responderUrls`.
pub const AccessUrls = struct {
    encoded: []const u8 = &.{},
    offset: usize = 0,
    count: usize = 0,
    target_method: []const u8 = &oid_ad_ocsp,

    pub fn next(self: *AccessUrls) Error!?[]const u8 {
        var descriptions = Reader{
            .bytes = self.encoded,
            .offset = self.offset,
        };
        while (descriptions.next() catch
            return error.InvalidAuthorityInfoAccess) |description|
        {
            self.offset = descriptions.offset;
            self.count += 1;
            if (self.count > max_access_descriptions) {
                return error.TooManyAccessDescriptions;
            }
            if (description.tag != 0x30) {
                return error.InvalidAuthorityInfoAccess;
            }
            var fields = Reader{ .bytes = description.value };
            const method = fields.require(0x06) catch
                return error.InvalidAuthorityInfoAccess;
            validateOid(method.value) catch
                return error.InvalidAuthorityInfoAccess;
            const location = (fields.next() catch
                return error.InvalidAuthorityInfoAccess) orelse
                return error.InvalidAuthorityInfoAccess;
            if (!fields.done()) return error.InvalidAuthorityInfoAccess;
            if (std.mem.eql(u8, method.value, self.target_method)) {
                if (location.tag != 0x86 or
                    !validAbsoluteIa5Uri(location.value))
                {
                    return error.InvalidAuthorityInfoAccess;
                }
                return location.value;
            }
            if (!validGeneralName(location)) {
                return error.InvalidAuthorityInfoAccess;
            }
        }
        return null;
    }
};

pub const ResponderUrls = AccessUrls;
pub const CaIssuerUrls = AccessUrls;

/// Return all RFC 5280 id-ad-ocsp URIs from a certificate's Authority
/// Information Access extension. Construction validates every access
/// description before returning, so malformed entries after a usable first URI
/// cannot be hidden by partial iteration.
pub fn responderUrls(certificate_der: []const u8) Error!ResponderUrls {
    _ = certificate_compat.parse(certificate_der) catch
        return error.InvalidCertificate;
    const extensions = certificateExtensions(certificate_der) catch
        return error.InvalidCertificate;
    const encoded_extensions = (extensions orelse return .{}).value;

    return responderUrlsFromExtensions(encoded_extensions);
}

/// Return the first OCSP responder URI, or null when the certificate has no
/// such access description. The returned slice borrows `certificate_der`.
pub fn responderUrl(certificate_der: []const u8) Error!?[]const u8 {
    var urls = try responderUrls(certificate_der);
    return urls.next();
}

/// Return every ordered id-ad-caIssuers absolute URI from a certificate's
/// Authority Information Access extension. Returned slices borrow the input.
pub fn caIssuerUrls(certificate_der: []const u8) Error!CaIssuerUrls {
    _ = certificate_compat.parse(certificate_der) catch
        return error.InvalidCertificate;
    const extensions = certificateExtensions(certificate_der) catch
        return error.InvalidCertificate;
    const encoded_extensions = (extensions orelse return .{}).value;
    return accessUrlsFromExtensions(encoded_extensions, &oid_ad_ca_issuers);
}

fn responderUrlsFromExtensions(
    encoded_extensions: []const u8,
) Error!ResponderUrls {
    return accessUrlsFromExtensions(encoded_extensions, &oid_ad_ocsp);
}

fn accessUrlsFromExtensions(
    encoded_extensions: []const u8,
    target_method: []const u8,
) Error!AccessUrls {
    var aia_value: ?[]const u8 = null;
    var reader = Reader{ .bytes = encoded_extensions };
    while (reader.next() catch return error.InvalidCertificate) |extension| {
        if (extension.tag != 0x30) return error.InvalidCertificate;
        var fields = Reader{ .bytes = extension.value };
        const oid = fields.require(0x06) catch
            return error.InvalidCertificate;
        validateOid(oid.value) catch return error.InvalidCertificate;
        var value = (fields.next() catch
            return error.InvalidCertificate) orelse
            return error.InvalidCertificate;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidCertificate;
            }
            critical = true;
            value = (fields.next() catch
                return error.InvalidCertificate) orelse
                return error.InvalidCertificate;
        }
        if (value.tag != 0x04 or !fields.done()) {
            return error.InvalidCertificate;
        }
        if (!std.mem.eql(
            u8,
            oid.value,
            &oid_authority_information_access,
        )) continue;
        if (aia_value != null) return error.DuplicateAuthorityInfoAccess;
        if (critical) return error.CriticalAuthorityInfoAccess;
        aia_value = value.value;
    }

    return accessUrlsFromValue(
        aia_value orelse return .{ .target_method = target_method },
        target_method,
    );
}

fn parseAuthorityInfoAccess(encoded: []const u8) Error!?[]const u8 {
    var urls = try responderUrlsFromValue(encoded);
    return urls.next();
}

fn responderUrlsFromValue(encoded: []const u8) Error!ResponderUrls {
    return accessUrlsFromValue(encoded, &oid_ad_ocsp);
}

fn accessUrlsFromValue(
    encoded: []const u8,
    target_method: []const u8,
) Error!AccessUrls {
    const sequence = singleInner(encoded, 0x30) catch
        return error.InvalidAuthorityInfoAccess;
    if (sequence.value.len == 0) {
        return error.InvalidAuthorityInfoAccess;
    }
    const result = AccessUrls{
        .encoded = sequence.value,
        .target_method = target_method,
    };
    var validation = result;
    while (try validation.next()) |_| {}
    return result;
}

fn validAbsoluteIa5Uri(uri: []const u8) bool {
    if (uri.len < 3 or !std.ascii.isAlphabetic(uri[0])) return false;
    for (uri[1..], 1..) |byte, index| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
        if (byte == ':') return index + 1 < uri.len;
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '+' and byte != '-' and byte != '.')
        {
            return false;
        }
    }
    return false;
}

fn validGeneralName(name: Element) bool {
    return switch (name.tag) {
        0xa0, 0xa3, 0xa4, 0xa5 => name.value.len != 0,
        0x81, 0x82 => validNonEmptyIa5(name.value),
        0x86 => validAbsoluteIa5Uri(name.value),
        0x87 => name.value.len == 4 or name.value.len == 16,
        0x88 => blk: {
            validateOid(name.value) catch break :blk false;
            break :blk true;
        },
        else => false,
    };
}

fn validNonEmptyIa5(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte > 0x7f) return false;
    }
    return true;
}

/// Encode one allocation-free RFC 6960 OCSPRequest into caller-owned storage.
/// The CertID binds the leaf serial to the issuer's exact DER Name and
/// subjectPublicKey bits. An optional nonce is encoded per RFC 8954.
pub fn createRequest(
    output: []u8,
    certificate_der: []const u8,
    issuer_der: []const u8,
    options: RequestOptions,
) Error!usize {
    const targets = [_]RequestTarget{.{
        .certificate_der = certificate_der,
        .issuer_der = issuer_der,
    }};
    return createRequestsBounded(1, output, &targets, options);
}

/// Encode an allocation-free RFC 6960 OCSPRequest containing one CertID for
/// every target. Entries may use different issuers, but share the selected
/// CertID hash and optional request nonce. At least one and at most
/// `max_request_entries` targets are accepted.
pub fn createRequests(
    output: []u8,
    targets: []const RequestTarget,
    options: RequestOptions,
) Error!usize {
    return createRequestsBounded(
        max_request_entries,
        output,
        targets,
        options,
    );
}

fn createRequestsBounded(
    comptime entry_capacity: usize,
    output: []u8,
    targets: []const RequestTarget,
    options: RequestOptions,
) Error!usize {
    if (targets.len == 0 or targets.len > entry_capacity) {
        return error.InvalidRequestCount;
    }
    if (options.nonce) |nonce| {
        if (nonce.len == 0 or nonce.len > max_nonce_len) {
            return error.InvalidNonce;
        }
    }

    var request_list_content: [entry_capacity * 264]u8 = undefined;
    var request_list_content_len: usize = 0;
    for (targets) |target| {
        request_list_content_len += try encodeRequestEntry(
            request_list_content[request_list_content_len..],
            target,
            options.hash,
        );
    }

    var request_extensions: [80]u8 = undefined;
    const request_extensions_len = if (options.nonce) |nonce|
        try encodeNonceExtension(&request_extensions, nonce)
    else
        0;

    const request_list_header_len = try derHeaderLen(
        request_list_content_len,
    );
    const request_list_len = request_list_header_len +
        request_list_content_len;
    const tbs_content_len = request_list_len + request_extensions_len;
    const tbs_len = (try derHeaderLen(tbs_content_len)) + tbs_content_len;
    const total_len = (try derHeaderLen(tbs_len)) + tbs_len;
    if (output.len < total_len) return error.BufferTooSmall;

    var offset: usize = 0;
    offset += try writeDerHeader(output[offset..], 0x30, tbs_len);
    offset += try writeDerHeader(output[offset..], 0x30, tbs_content_len);
    offset += try writeDerHeader(
        output[offset..],
        0x30,
        request_list_content_len,
    );
    @memcpy(
        output[offset..][0..request_list_content_len],
        request_list_content[0..request_list_content_len],
    );
    offset += request_list_content_len;
    @memcpy(
        output[offset..][0..request_extensions_len],
        request_extensions[0..request_extensions_len],
    );
    offset += request_extensions_len;
    std.debug.assert(offset == total_len);
    return total_len;
}

fn encodeRequestEntry(
    output: []u8,
    target: RequestTarget,
    hash: CertIdHash,
) Error!usize {
    _ = certificate_compat.parse(target.certificate_der) catch
        return error.InvalidCertId;
    const issuer = (certificate_compat.parse(target.issuer_der) catch
        return error.InvalidIssuer).standard;
    const issuer_name_der = certificateSubjectDer(target.issuer_der) catch
        return error.InvalidIssuer;
    const serial = certificateSerial(target.certificate_der) catch
        return error.InvalidCertId;

    var name_digest_storage: [Sha512.digest_length]u8 = undefined;
    var key_digest_storage: [Sha512.digest_length]u8 = undefined;
    const name_digest = hashCertIdBytes(
        hash,
        issuer_name_der,
        &name_digest_storage,
    );
    const key_digest = hashCertIdBytes(
        hash,
        issuer.pubKey(),
        &key_digest_storage,
    );

    var algorithm_content: [16]u8 = undefined;
    var algorithm_content_len: usize = 0;
    algorithm_content_len += try writeDerElement(
        algorithm_content[algorithm_content_len..],
        0x06,
        certIdHashOid(hash),
    );
    algorithm_content_len += try writeDerElement(
        algorithm_content[algorithm_content_len..],
        0x05,
        "",
    );
    var algorithm: [20]u8 = undefined;
    const algorithm_len = try writeDerElement(
        &algorithm,
        0x30,
        algorithm_content[0..algorithm_content_len],
    );

    var cert_id_content: [256]u8 = undefined;
    var cert_id_content_len: usize = 0;
    try appendDerBytes(
        &cert_id_content,
        &cert_id_content_len,
        algorithm[0..algorithm_len],
    );
    cert_id_content_len += try writeDerElement(
        cert_id_content[cert_id_content_len..],
        0x04,
        name_digest,
    );
    cert_id_content_len += try writeDerElement(
        cert_id_content[cert_id_content_len..],
        0x04,
        key_digest,
    );
    cert_id_content_len += try writeDerElement(
        cert_id_content[cert_id_content_len..],
        0x02,
        serial,
    );
    var cert_id: [260]u8 = undefined;
    const cert_id_len = try writeDerElement(
        &cert_id,
        0x30,
        cert_id_content[0..cert_id_content_len],
    );

    return writeDerElement(
        output,
        0x30,
        cert_id[0..cert_id_len],
    );
}

fn encodeNonceExtension(output: []u8, nonce: []const u8) Error!usize {
    var encoded_nonce: [2 + max_nonce_len]u8 = undefined;
    const encoded_nonce_len = try writeDerElement(
        &encoded_nonce,
        0x04,
        nonce,
    );
    var extension_content: [64]u8 = undefined;
    var extension_content_len: usize = 0;
    extension_content_len += try writeDerElement(
        extension_content[extension_content_len..],
        0x06,
        &oid_ocsp_nonce,
    );
    extension_content_len += try writeDerElement(
        extension_content[extension_content_len..],
        0x04,
        encoded_nonce[0..encoded_nonce_len],
    );
    var extension: [68]u8 = undefined;
    const extension_len = try writeDerElement(
        &extension,
        0x30,
        extension_content[0..extension_content_len],
    );
    var extensions: [72]u8 = undefined;
    const extensions_len = try writeDerElement(
        &extensions,
        0x30,
        extension[0..extension_len],
    );
    return writeDerElement(
        output,
        0xa2,
        extensions[0..extensions_len],
    );
}

pub fn verify(
    response_der: []const u8,
    certificate_der: []const u8,
    issuer_der: []const u8,
    now_seconds: i64,
    policy: Policy,
) Error!Status {
    const certificates = [_][]const u8{certificate_der};
    var statuses: [1]Status = undefined;
    try verifyManyBounded(
        1,
        &statuses,
        response_der,
        &certificates,
        issuer_der,
        now_seconds,
        policy,
        null,
    );
    return statuses[0];
}

/// Verify one response while reusing a prepared P-521 issuer public key for
/// both target-certificate and issuer-signed responder authentication.
pub fn verifyWithP521(
    response_der: []const u8,
    certificate_der: []const u8,
    issuer_der: []const u8,
    now_seconds: i64,
    policy: Policy,
    verifier: *const x509_signature.P521Verifier,
) Error!Status {
    const certificates = [_][]const u8{certificate_der};
    var statuses: [1]Status = undefined;
    try verifyManyBounded(
        1,
        &statuses,
        response_der,
        &certificates,
        issuer_der,
        now_seconds,
        policy,
        verifier,
    );
    return statuses[0];
}

/// Verify one BasicOCSPResponse for multiple certificates issued by the same
/// CA. The response and responder signature are parsed and authenticated once;
/// `statuses` is updated only after every target has exactly one valid
/// SingleResponse. Inputs and output are bounded by `max_verification_targets`.
pub fn verifyMany(
    statuses: []Status,
    response_der: []const u8,
    certificate_der: []const []const u8,
    issuer_der: []const u8,
    now_seconds: i64,
    policy: Policy,
) Error!void {
    return verifyManyBounded(
        max_verification_targets,
        statuses,
        response_der,
        certificate_der,
        issuer_der,
        now_seconds,
        policy,
        null,
    );
}

fn verifyManyBounded(
    comptime target_capacity: usize,
    statuses: []Status,
    response_der: []const u8,
    certificates_der: []const []const u8,
    issuer_der: []const u8,
    now_seconds: i64,
    policy: Policy,
    p521_verifier: ?*const x509_signature.P521Verifier,
) Error!void {
    if (certificates_der.len == 0 or
        certificates_der.len > target_capacity)
    {
        return error.InvalidRequestCount;
    }
    if (statuses.len != certificates_der.len) {
        return error.InvalidStatusCount;
    }
    if (now_seconds < 0) return error.OcspResponseNotYetValid;
    if (response_der.len > policy.max_response_bytes) {
        return error.OcspResponseTooLarge;
    }
    if (policy.expected_nonce) |nonce| {
        if (nonce.len == 0 or nonce.len > max_nonce_len) {
            return error.InvalidNonce;
        }
    }
    const compatible_issuer = certificate_compat.parse(issuer_der) catch
        return error.InvalidIssuer;
    const issuer = compatible_issuer.standard;
    if (now_seconds < issuer.validity.not_before or
        now_seconds > issuer.validity.not_after)
    {
        return error.InvalidIssuer;
    }

    var certificates: [target_capacity]Certificate.Parsed = undefined;
    var serials: [target_capacity][]const u8 = undefined;
    for (certificates_der, 0..) |certificate_der, index| {
        const compatible = certificate_compat.parse(certificate_der) catch
            return error.InvalidOcspResponse;
        if (p521_verifier) |verifier| {
            certificate_compat.verifySignatureAndValidityWithP521(
                compatible.standard,
                compatible.signature_algorithm,
                issuer,
                now_seconds,
                verifier,
            ) catch return error.InvalidIssuer;
        } else {
            compatible.verify(compatible_issuer, now_seconds) catch
                return error.InvalidIssuer;
        }
        certificates[index] = compatible.standard;
        serials[index] = certificateSerial(certificate_der) catch
            return error.InvalidOcspResponse;
        for (serials[0..index]) |prior_serial| {
            if (std.mem.eql(u8, prior_serial, serials[index])) {
                return error.DuplicateCertificateTarget;
            }
        }
    }

    var outer = Reader{ .bytes = response_der };
    const response = outer.require(0x30) catch
        return error.InvalidOcspResponse;
    if (!outer.done()) return error.InvalidOcspResponse;
    var response_fields = Reader{ .bytes = response.value };
    const status = response_fields.require(0x0a) catch
        return error.InvalidOcspResponse;
    if (status.value.len != 1 or status.value[0] != 0) {
        return error.OcspResponseUnsuccessful;
    }
    const response_bytes = response_fields.require(0xa0) catch
        return error.InvalidOcspResponse;
    if (!response_fields.done()) return error.InvalidOcspResponse;
    var explicit = Reader{ .bytes = response_bytes.value };
    const response_bytes_sequence = explicit.require(0x30) catch
        return error.InvalidOcspResponse;
    if (!explicit.done()) return error.InvalidOcspResponse;
    var encoded_response = Reader{ .bytes = response_bytes_sequence.value };
    const response_type = encoded_response.require(0x06) catch
        return error.InvalidOcspResponse;
    if (!std.mem.eql(u8, response_type.value, &oid_basic_response)) {
        return error.UnsupportedResponseType;
    }
    const basic_octets = encoded_response.require(0x04) catch
        return error.InvalidOcspResponse;
    if (!encoded_response.done()) return error.InvalidOcspResponse;

    var basic_reader = Reader{ .bytes = basic_octets.value };
    const basic = basic_reader.require(0x30) catch
        return error.InvalidOcspResponse;
    if (!basic_reader.done()) return error.InvalidOcspResponse;
    var basic_fields = Reader{ .bytes = basic.value };
    const response_data = basic_fields.require(0x30) catch
        return error.InvalidOcspResponse;
    const signature_algorithm_element = basic_fields.require(0x30) catch
        return error.InvalidOcspResponse;
    const signature_value = basic_fields.require(0x03) catch
        return error.InvalidOcspResponse;
    var embedded_certificates: ?[]const u8 = null;
    if (basic_fields.next() catch return error.InvalidOcspResponse) |certs| {
        if (certs.tag != 0xa0) return error.InvalidOcspResponse;
        var certs_explicit = Reader{ .bytes = certs.value };
        const sequence = certs_explicit.require(0x30) catch
            return error.InvalidOcspResponse;
        if (!certs_explicit.done() or sequence.value.len == 0) {
            return error.InvalidOcspResponse;
        }
        embedded_certificates = sequence.value;
        if ((basic_fields.next() catch
            return error.InvalidOcspResponse) != null)
        {
            return error.InvalidOcspResponse;
        }
    }
    if (signature_value.value.len < 2 or signature_value.value[0] != 0) {
        return error.InvalidOcspResponse;
    }

    var verified_statuses: [target_capacity]Status = undefined;
    const responder = try verifyResponseDataMany(
        target_capacity,
        response_data,
        verified_statuses[0..certificates_der.len],
        certificates_der,
        certificates[0..certificates_der.len],
        issuer_der,
        issuer,
        @intCast(now_seconds),
        &policy,
    );
    const signature_algorithm = try parseSignatureAlgorithm(
        signature_algorithm_element,
    );
    try verifyAuthorizedResponderSignature(
        responder,
        issuer_der,
        issuer,
        embedded_certificates,
        now_seconds,
        &policy,
        signature_algorithm,
        basic.value[response_data.start..response_data.end],
        signature_value.value[1..],
        p521_verifier,
    );
    @memcpy(statuses, verified_statuses[0..certificates_der.len]);
}

fn verifyResponseDataMany(
    comptime target_capacity: usize,
    response_data: Element,
    statuses: []Status,
    certificates_der: []const []const u8,
    certificates: []const Certificate.Parsed,
    issuer_der: []const u8,
    issuer: Certificate.Parsed,
    now: u64,
    policy: *const Policy,
) Error!Element {
    var fields = Reader{ .bytes = response_data.value };
    var responder = (fields.next() catch return error.InvalidOcspResponse) orelse
        return error.InvalidOcspResponse;
    if (responder.tag == 0xa0) {
        var version = Reader{ .bytes = responder.value };
        const integer = version.require(0x02) catch
            return error.InvalidOcspResponse;
        if (integer.value.len != 1 or integer.value[0] != 0 or
            !version.done())
        {
            return error.InvalidOcspResponse;
        }
        responder = (fields.next() catch return error.InvalidOcspResponse) orelse
            return error.InvalidOcspResponse;
    }
    const produced_at = (fields.next() catch
        return error.InvalidOcspResponse) orelse
        return error.InvalidOcspResponse;
    const produced_at_seconds = parseGeneralizedTime(
        response_data.value,
        produced_at,
    ) catch return error.InvalidOcspResponse;
    if (produced_at_seconds > now +| policy.clock_skew_seconds) {
        return error.OcspResponseNotYetValid;
    }
    const responses = fields.require(0x30) catch
        return error.InvalidOcspResponse;
    if (responses.value.len == 0) return error.InvalidOcspResponse;
    var response_nonce: ?[]const u8 = null;
    if (fields.next() catch return error.InvalidOcspResponse) |extensions| {
        if (extensions.tag != 0xa1) return error.InvalidOcspResponse;
        response_nonce = try parseExtensions(
            extensions.value,
            @min(policy.max_extensions, max_extensions_per_scope),
            true,
        );
        if ((fields.next() catch return error.InvalidOcspResponse) != null) {
            return error.InvalidOcspResponse;
        }
    }
    if (policy.expected_nonce) |expected| {
        const actual = response_nonce orelse return error.MissingNonce;
        if (!std.mem.eql(u8, expected, actual)) return error.NonceMismatch;
    }

    var matches: [target_capacity]bool = @splat(false);
    var singles = Reader{ .bytes = responses.value };
    while (singles.next() catch return error.InvalidOcspResponse) |single| {
        if (single.tag != 0x30) return error.InvalidOcspResponse;
        for (certificates_der, certificates, 0..) |certificate_der, certificate, index| {
            const parsed = try parseSingleResponse(
                single,
                certificate_der,
                certificate,
                issuer_der,
                issuer,
                now,
                policy,
            );
            if (parsed) |certificate_status| {
                if (matches[index]) return error.DuplicateCertificateStatus;
                matches[index] = true;
                statuses[index] = certificate_status;
            }
        }
    }
    for (matches[0..certificates_der.len]) |matched| {
        if (!matched) return error.CertificateStatusNotFound;
    }
    return responder;
}

fn responderMatches(
    responder: Element,
    certificate_der: []const u8,
    certificate: Certificate.Parsed,
) Error!bool {
    return switch (responder.tag) {
        0xa1 => blk: {
            const subject_der = certificateSubjectDer(certificate_der) catch
                return error.InvalidOcspResponse;
            // RFC 6960 uses EXPLICIT tagging, while some deployed encoders
            // apply the context tag implicitly. Compare either representation
            // with RFC 5280 section 7.1 Name equality.
            var subject_name = Reader{ .bytes = subject_der };
            const subject_sequence = subject_name.require(0x30) catch
                return error.InvalidOcspResponse;
            if (!subject_name.done()) return error.InvalidOcspResponse;
            var explicit_name = Reader{ .bytes = responder.value };
            const maybe_sequence = explicit_name.next() catch
                return error.InvalidResponder;
            const responder_name = if (maybe_sequence != null and
                maybe_sequence.?.tag == 0x30 and explicit_name.done())
                maybe_sequence.?.value
            else
                responder.value;
            break :blk distinguished_name.eql(
                responder_name,
                subject_sequence.value,
            ) catch return error.InvalidResponder;
        },
        // RFC 6960's module uses EXPLICIT TAGS, so byKey wraps the KeyHash
        // OCTET STRING. Retain the implicit form for deployed encoders that
        // followed the older ASN.1 text literally.
        0xa2, 0x82 => blk: {
            const key_hash = if (responder.tag == 0xa2) explicit: {
                var wrapper = Reader{ .bytes = responder.value };
                const octets = wrapper.require(0x04) catch
                    return error.InvalidResponder;
                if (!wrapper.done()) return error.InvalidResponder;
                break :explicit octets.value;
            } else responder.value;
            if (key_hash.len != Sha1.digest_length) {
                return error.InvalidResponder;
            }
            var expected: [Sha1.digest_length]u8 = undefined;
            Sha1.hash(certificate.pubKey(), &expected, .{});
            break :blk std.crypto.timing_safe.eql(
                [Sha1.digest_length]u8,
                key_hash[0..Sha1.digest_length].*,
                expected,
            );
        },
        else => return error.InvalidResponder,
    };
}

fn verifyAuthorizedResponderSignature(
    responder_id: Element,
    issuer_der: []const u8,
    issuer: Certificate.Parsed,
    embedded_certificates: ?[]const u8,
    now_seconds: i64,
    policy: *const Policy,
    signature_algorithm: x509_signature.Algorithm,
    message: []const u8,
    signature: []const u8,
    p521_verifier: ?*const x509_signature.P521Verifier,
) Error!void {
    var identity_matches: usize = 0;
    var authorized_matches: usize = 0;
    var verified_matches: usize = 0;
    var signature_error: ?Error = null;

    if (try responderMatches(responder_id, issuer_der, issuer)) {
        identity_matches += 1;
        authorized_matches += 1;
        verifySignaturePrepared(
            signature_algorithm,
            issuer,
            message,
            signature,
            p521_verifier,
        ) catch |err| {
            signature_error = err;
        };
        if (signature_error == null) verified_matches += 1;
    }

    if (embedded_certificates) |encoded| {
        var certificates = Reader{ .bytes = encoded };
        var count: usize = 0;
        while (certificates.next() catch
            return error.InvalidOcspResponse) |element|
        {
            count += 1;
            if (count > policy.max_embedded_responder_certificates) {
                return error.TooManyResponderCertificates;
            }
            if (element.tag != 0x30) return error.InvalidOcspResponse;
            const certificate_der = encoded[element.start..element.end];
            const compatible_candidate = certificate_compat.parse(
                certificate_der,
            ) catch
                return error.InvalidOcspResponse;
            const candidate = compatible_candidate.standard;
            if (!try responderMatches(
                responder_id,
                certificate_der,
                candidate,
            )) continue;
            identity_matches += 1;
            if (!(distinguished_name.eql(
                candidate.issuer(),
                issuer.subject(),
            ) catch false)) continue;
            if (p521_verifier) |verifier| {
                certificate_compat.verifySignatureAndValidityWithP521(
                    candidate,
                    compatible_candidate.signature_algorithm,
                    issuer,
                    now_seconds,
                    verifier,
                ) catch continue;
            } else {
                certificate_compat.verifySignatureAndValidity(
                    candidate,
                    compatible_candidate.signature_algorithm,
                    issuer,
                    now_seconds,
                ) catch continue;
            }
            validateDelegatedResponderUsage(certificate_der) catch continue;
            authorized_matches += 1;
            verifySignature(
                signature_algorithm,
                candidate,
                message,
                signature,
            ) catch |err| {
                signature_error = err;
                continue;
            };
            verified_matches += 1;
        }
    }

    if (verified_matches == 1) return;
    if (verified_matches > 1) return error.DuplicateResponder;
    if (authorized_matches != 0) {
        return signature_error orelse error.InvalidOcspSignature;
    }
    if (identity_matches != 0) return error.UnauthorizedResponder;
    return error.InvalidResponder;
}

fn validateDelegatedResponderUsage(certificate_der: []const u8) !void {
    const extensions = try certificateExtensions(certificate_der) orelse
        return error.UnauthorizedResponder;
    var reader = Reader{ .bytes = extensions.value };
    var seen_oids: [32][]const u8 = undefined;
    var seen_count: usize = 0;
    var key_usage_present = false;
    var digital_signature = false;
    var extended_key_usage_present = false;
    var ocsp_signing = false;

    while (try reader.next()) |extension| {
        if (extension.tag != 0x30 or seen_count == seen_oids.len) {
            return error.UnauthorizedResponder;
        }
        var fields = Reader{ .bytes = extension.value };
        const oid = try fields.require(0x06);
        try validateOid(oid.value);
        for (seen_oids[0..seen_count]) |previous| {
            if (std.mem.eql(u8, previous, oid.value)) {
                return error.UnauthorizedResponder;
            }
        }
        seen_oids[seen_count] = oid.value;
        seen_count += 1;

        var value = (try fields.next()) orelse
            return error.UnauthorizedResponder;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.UnauthorizedResponder;
            }
            critical = true;
            value = (try fields.next()) orelse
                return error.UnauthorizedResponder;
        }
        if (value.tag != 0x04 or try fields.next() != null) {
            return error.UnauthorizedResponder;
        }

        if (std.mem.eql(u8, oid.value, &oid_key_usage)) {
            if (key_usage_present) return error.UnauthorizedResponder;
            key_usage_present = true;
            digital_signature = try keyUsageAllowsDigitalSignature(
                value.value,
            );
        } else if (std.mem.eql(u8, oid.value, &oid_extended_key_usage)) {
            if (extended_key_usage_present) {
                return error.UnauthorizedResponder;
            }
            extended_key_usage_present = true;
            ocsp_signing = try extendedKeyUsageAllowsOcspSigning(
                value.value,
            );
        } else if (std.mem.eql(u8, oid.value, &oid_basic_constraints)) {
            try validateBasicConstraints(value.value);
        } else if (std.mem.eql(u8, oid.value, &oid_ocsp_no_check)) {
            const no_check = try singleInner(value.value, 0x05);
            if (no_check.value.len != 0) return error.UnauthorizedResponder;
        } else if (critical) {
            return error.UnsupportedResponder;
        }
    }
    if (!extended_key_usage_present or !ocsp_signing or
        (key_usage_present and !digital_signature))
    {
        return error.UnauthorizedResponder;
    }
}

fn certificateExtensions(certificate_der: []const u8) !?Element {
    var top = Reader{ .bytes = certificate_der };
    const certificate = try top.require(0x30);
    if (!top.done()) return error.InvalidOcspResponse;
    var certificate_fields = Reader{ .bytes = certificate.value };
    const tbs = try certificate_fields.require(0x30);
    _ = try certificate_fields.require(0x30);
    _ = try certificate_fields.require(0x03);
    if (!certificate_fields.done()) return error.InvalidOcspResponse;

    var fields = Reader{ .bytes = tbs.value };
    var first = (try fields.next()) orelse return error.InvalidOcspResponse;
    if (first.tag == 0xa0) {
        first = (try fields.next()) orelse return error.InvalidOcspResponse;
    }
    if (first.tag != 0x02) return error.InvalidOcspResponse;
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    while (try fields.next()) |optional| {
        switch (optional.tag) {
            0x81, 0x82 => {},
            0xa3 => {
                const extensions = try singleInner(optional.value, 0x30);
                if (!fields.done()) return error.InvalidOcspResponse;
                return extensions;
            },
            else => return error.InvalidOcspResponse,
        }
    }
    return null;
}

fn keyUsageAllowsDigitalSignature(encoded: []const u8) !bool {
    const bits = try singleInner(encoded, 0x03);
    if (bits.value.len < 2 or bits.value.len > 3) {
        return error.UnauthorizedResponder;
    }
    const unused = bits.value[0];
    if (unused > 7) return error.UnauthorizedResponder;
    const last = bits.value[bits.value.len - 1];
    if (last == 0 or
        (unused != 0 and
            (last & ((@as(u8, 1) << @intCast(unused)) - 1)) != 0))
    {
        return error.UnauthorizedResponder;
    }
    var trailing_zero_bits: u4 = 0;
    var shifted = last;
    while ((shifted & 1) == 0) : (shifted >>= 1) {
        trailing_zero_bits += 1;
    }
    if (unused != trailing_zero_bits or
        (bits.value.len == 3 and (bits.value[2] & 0x7f) != 0))
    {
        return error.UnauthorizedResponder;
    }
    return (bits.value[1] & 0x80) != 0;
}

fn extendedKeyUsageAllowsOcspSigning(encoded: []const u8) !bool {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.UnauthorizedResponder;
    var purposes = Reader{ .bytes = sequence.value };
    var allowed = false;
    while (try purposes.next()) |purpose| {
        if (purpose.tag != 0x06) return error.UnauthorizedResponder;
        try validateOid(purpose.value);
        allowed = allowed or std.mem.eql(
            u8,
            purpose.value,
            &oid_ocsp_signing,
        );
    }
    return allowed;
}

fn validateBasicConstraints(encoded: []const u8) !void {
    const sequence = try singleInner(encoded, 0x30);
    var fields = Reader{ .bytes = sequence.value };
    if (try fields.next()) |first| {
        if (first.tag != 0x01 or first.value.len != 1 or
            first.value[0] != 0xff)
        {
            return error.UnauthorizedResponder;
        }
        if (try fields.next()) |path_len| {
            try validateNonNegativeInteger(path_len);
            if (!fields.done()) return error.UnauthorizedResponder;
        }
    }
}

fn validateNonNegativeInteger(integer: Element) !void {
    if (integer.tag != 0x02 or integer.value.len == 0 or
        (integer.value[0] & 0x80) != 0 or
        (integer.value.len > 1 and integer.value[0] == 0 and
            (integer.value[1] & 0x80) == 0))
    {
        return error.UnauthorizedResponder;
    }
}

fn validateOid(value: []const u8) !void {
    if (value.len == 0) return error.UnauthorizedResponder;
    var at_subidentifier_start = true;
    for (value) |byte| {
        if (at_subidentifier_start and byte == 0x80) {
            return error.UnauthorizedResponder;
        }
        at_subidentifier_start = (byte & 0x80) == 0;
    }
    if (!at_subidentifier_start) return error.UnauthorizedResponder;
}

fn singleInner(encoded: []const u8, tag: u8) !Element {
    var reader = Reader{ .bytes = encoded };
    const value = try reader.require(tag);
    if (!reader.done()) return error.UnauthorizedResponder;
    return value;
}

fn parseSingleResponse(
    single: Element,
    certificate_der: []const u8,
    certificate: Certificate.Parsed,
    issuer_der: []const u8,
    issuer: Certificate.Parsed,
    now: u64,
    policy: *const Policy,
) Error!?Status {
    var fields = Reader{ .bytes = single.value };
    const cert_id = fields.require(0x30) catch
        return error.InvalidOcspResponse;
    const matches = try certIdMatches(
        cert_id,
        certificate_der,
        certificate,
        issuer_der,
        issuer,
    );
    const status_element = (fields.next() catch
        return error.InvalidOcspResponse) orelse
        return error.InvalidOcspResponse;
    const status: Status = switch (status_element.tag) {
        0x80 => if (status_element.value.len == 0)
            .good
        else
            return error.InvalidOcspResponse,
        0xa1 => blk: {
            var revoked = Reader{ .bytes = status_element.value };
            const revocation_time = (revoked.next() catch
                return error.InvalidOcspResponse) orelse
                return error.InvalidOcspResponse;
            _ = parseGeneralizedTime(
                status_element.value,
                revocation_time,
            ) catch return error.InvalidOcspResponse;
            if (revoked.next() catch return error.InvalidOcspResponse) |reason| {
                if (reason.tag != 0xa0 or !revoked.done()) {
                    return error.InvalidOcspResponse;
                }
            }
            break :blk .revoked;
        },
        0x82 => if (status_element.value.len == 0)
            .unknown
        else
            return error.InvalidOcspResponse,
        else => return error.InvalidOcspResponse,
    };
    const this_update_element = (fields.next() catch
        return error.InvalidOcspResponse) orelse
        return error.InvalidOcspResponse;
    const this_update = parseGeneralizedTime(
        single.value,
        this_update_element,
    ) catch return error.InvalidOcspResponse;
    var next_update: ?u64 = null;
    var next_field = fields.next() catch return error.InvalidOcspResponse;
    if (next_field != null and next_field.?.tag == 0xa0) {
        const next_update_wrapper = next_field.?;
        var explicit = Reader{ .bytes = next_update_wrapper.value };
        const time = (explicit.next() catch
            return error.InvalidOcspResponse) orelse
            return error.InvalidOcspResponse;
        next_update = parseGeneralizedTime(
            next_update_wrapper.value,
            time,
        ) catch return error.InvalidOcspResponse;
        if (!explicit.done()) return error.InvalidOcspResponse;
        next_field = fields.next() catch return error.InvalidOcspResponse;
    }
    if (next_field) |extensions| {
        if (extensions.tag != 0xa1) return error.InvalidOcspResponse;
        _ = try parseExtensions(
            extensions.value,
            @min(policy.max_extensions, max_extensions_per_scope),
            false,
        );
        if (!fields.done()) return error.InvalidOcspResponse;
    }
    if (!matches) return null;
    if (this_update > now +| policy.clock_skew_seconds) {
        return error.OcspResponseNotYetValid;
    }
    if (next_update) |next| {
        if (next < this_update) return error.InvalidOcspResponse;
        if (now > next +| policy.clock_skew_seconds) {
            return error.OcspResponseExpired;
        }
    } else if (now > this_update +| policy.clock_skew_seconds and
        now - this_update > policy.max_age_without_next_update_seconds)
    {
        return error.OcspResponseExpired;
    }
    return status;
}

fn parseExtensions(
    encoded: []const u8,
    max_extensions: usize,
    response_scope: bool,
) Error!?[]const u8 {
    var explicit = Reader{ .bytes = encoded };
    const sequence = explicit.require(0x30) catch
        return error.InvalidOcspResponse;
    if (!explicit.done() or sequence.value.len == 0) {
        return error.InvalidOcspResponse;
    }
    var extensions = Reader{ .bytes = sequence.value };
    var seen_oids: [max_extensions_per_scope][]const u8 = undefined;
    var seen_count: usize = 0;
    var nonce: ?[]const u8 = null;
    while (extensions.next() catch
        return error.InvalidOcspResponse) |extension|
    {
        if (extension.tag != 0x30) return error.InvalidOcspResponse;
        if (seen_count >= max_extensions) return error.TooManyExtensions;
        var fields = Reader{ .bytes = extension.value };
        const oid = fields.require(0x06) catch
            return error.InvalidOcspResponse;
        validateOid(oid.value) catch return error.InvalidOcspResponse;
        for (seen_oids[0..seen_count]) |previous| {
            if (std.mem.eql(u8, previous, oid.value)) {
                return error.InvalidOcspResponse;
            }
        }
        seen_oids[seen_count] = oid.value;
        seen_count += 1;

        var value = (fields.next() catch
            return error.InvalidOcspResponse) orelse
            return error.InvalidOcspResponse;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidOcspResponse;
            }
            critical = true;
            value = (fields.next() catch
                return error.InvalidOcspResponse) orelse
                return error.InvalidOcspResponse;
        }
        if (value.tag != 0x04 or !fields.done()) {
            return error.InvalidOcspResponse;
        }
        if (std.mem.eql(u8, oid.value, &oid_ocsp_nonce)) {
            if (!response_scope or critical or nonce != null) {
                return error.UnsupportedExtension;
            }
            var nonce_reader = Reader{ .bytes = value.value };
            const nonce_value = nonce_reader.require(0x04) catch
                return error.InvalidNonce;
            if (!nonce_reader.done() or nonce_value.value.len == 0 or
                nonce_value.value.len > max_nonce_len)
            {
                return error.InvalidNonce;
            }
            nonce = nonce_value.value;
        } else if (critical) {
            return error.UnsupportedExtension;
        }
    }
    return nonce;
}

pub const CertIdHash = enum {
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
};

fn certIdHashOid(hash: CertIdHash) []const u8 {
    return switch (hash) {
        .sha1 => &oid_sha1,
        .sha224 => &oid_sha224,
        .sha256 => &oid_sha256,
        .sha384 => &oid_sha384,
        .sha512 => &oid_sha512,
        .sha512_224 => &oid_sha512_224,
        .sha512_256 => &oid_sha512_256,
        .sha3_224 => &oid_sha3_224,
        .sha3_256 => &oid_sha3_256,
        .sha3_384 => &oid_sha3_384,
        .sha3_512 => &oid_sha3_512,
    };
}

fn hashCertIdBytes(
    hash: CertIdHash,
    input: []const u8,
    output: *[Sha512.digest_length]u8,
) []const u8 {
    const len: usize = switch (hash) {
        .sha1 => blk: {
            Sha1.hash(input, output[0..Sha1.digest_length], .{});
            break :blk Sha1.digest_length;
        },
        .sha224 => blk: {
            Sha224.hash(input, output[0..Sha224.digest_length], .{});
            break :blk Sha224.digest_length;
        },
        .sha256 => blk: {
            Sha256.hash(input, output[0..Sha256.digest_length], .{});
            break :blk Sha256.digest_length;
        },
        .sha384 => blk: {
            Sha384.hash(input, output[0..Sha384.digest_length], .{});
            break :blk Sha384.digest_length;
        },
        .sha512 => blk: {
            Sha512.hash(input, output, .{});
            break :blk Sha512.digest_length;
        },
        .sha512_224 => blk: {
            Sha512_224.hash(input, output[0..Sha512_224.digest_length], .{});
            break :blk Sha512_224.digest_length;
        },
        .sha512_256 => blk: {
            Sha512_256.hash(input, output[0..Sha512_256.digest_length], .{});
            break :blk Sha512_256.digest_length;
        },
        .sha3_224 => blk: {
            Sha3_224.hash(input, output[0..Sha3_224.digest_length], .{});
            break :blk Sha3_224.digest_length;
        },
        .sha3_256 => blk: {
            Sha3_256.hash(input, output[0..Sha3_256.digest_length], .{});
            break :blk Sha3_256.digest_length;
        },
        .sha3_384 => blk: {
            Sha3_384.hash(input, output[0..Sha3_384.digest_length], .{});
            break :blk Sha3_384.digest_length;
        },
        .sha3_512 => blk: {
            Sha3_512.hash(input, output, .{});
            break :blk Sha3_512.digest_length;
        },
    };
    return output[0..len];
}

fn certIdMatches(
    cert_id: Element,
    certificate_der: []const u8,
    certificate: Certificate.Parsed,
    issuer_der: []const u8,
    issuer: Certificate.Parsed,
) Error!bool {
    var fields = Reader{ .bytes = cert_id.value };
    const algorithm = fields.require(0x30) catch return error.InvalidCertId;
    const hash = try parseCertIdHash(algorithm);
    const name_hash = fields.require(0x04) catch return error.InvalidCertId;
    const key_hash = fields.require(0x04) catch return error.InvalidCertId;
    const serial = fields.require(0x02) catch return error.InvalidCertId;
    if (!fields.done()) return error.InvalidCertId;
    const expected_len: usize = switch (hash) {
        .sha1 => Sha1.digest_length,
        .sha224 => Sha224.digest_length,
        .sha256 => Sha256.digest_length,
        .sha384 => Sha384.digest_length,
        .sha512 => Sha512.digest_length,
        .sha512_224 => Sha512_224.digest_length,
        .sha512_256 => Sha512_256.digest_length,
        .sha3_224 => Sha3_224.digest_length,
        .sha3_256 => Sha3_256.digest_length,
        .sha3_384 => Sha3_384.digest_length,
        .sha3_512 => Sha3_512.digest_length,
    };
    if (name_hash.value.len != expected_len or
        key_hash.value.len != expected_len)
    {
        return error.InvalidCertId;
    }
    var expected_name: [Sha512.digest_length]u8 = undefined;
    var expected_key: [Sha512.digest_length]u8 = undefined;
    const issuer_name_der = certificateSubjectDer(issuer_der) catch
        return error.InvalidIssuer;
    switch (hash) {
        .sha1 => {
            Sha1.hash(issuer_name_der, expected_name[0..20], .{});
            Sha1.hash(issuer.pubKey(), expected_key[0..20], .{});
        },
        .sha224 => {
            Sha224.hash(issuer_name_der, expected_name[0..Sha224.digest_length], .{});
            Sha224.hash(issuer.pubKey(), expected_key[0..Sha224.digest_length], .{});
        },
        .sha256 => {
            Sha256.hash(issuer_name_der, expected_name[0..Sha256.digest_length], .{});
            Sha256.hash(issuer.pubKey(), expected_key[0..Sha256.digest_length], .{});
        },
        .sha384 => {
            Sha384.hash(issuer_name_der, expected_name[0..Sha384.digest_length], .{});
            Sha384.hash(issuer.pubKey(), expected_key[0..Sha384.digest_length], .{});
        },
        .sha512 => {
            Sha512.hash(issuer_name_der, &expected_name, .{});
            Sha512.hash(issuer.pubKey(), &expected_key, .{});
        },
        .sha512_224 => {
            Sha512_224.hash(issuer_name_der, expected_name[0..Sha512_224.digest_length], .{});
            Sha512_224.hash(issuer.pubKey(), expected_key[0..Sha512_224.digest_length], .{});
        },
        .sha512_256 => {
            Sha512_256.hash(issuer_name_der, expected_name[0..Sha512_256.digest_length], .{});
            Sha512_256.hash(issuer.pubKey(), expected_key[0..Sha512_256.digest_length], .{});
        },
        .sha3_224 => {
            Sha3_224.hash(issuer_name_der, expected_name[0..Sha3_224.digest_length], .{});
            Sha3_224.hash(issuer.pubKey(), expected_key[0..Sha3_224.digest_length], .{});
        },
        .sha3_256 => {
            Sha3_256.hash(issuer_name_der, expected_name[0..Sha3_256.digest_length], .{});
            Sha3_256.hash(issuer.pubKey(), expected_key[0..Sha3_256.digest_length], .{});
        },
        .sha3_384 => {
            Sha3_384.hash(issuer_name_der, expected_name[0..Sha3_384.digest_length], .{});
            Sha3_384.hash(issuer.pubKey(), expected_key[0..Sha3_384.digest_length], .{});
        },
        .sha3_512 => {
            Sha3_512.hash(issuer_name_der, &expected_name, .{});
            Sha3_512.hash(issuer.pubKey(), &expected_key, .{});
        },
    }
    const certificate_serial = certificateSerial(certificate_der) catch
        return error.InvalidCertId;
    _ = certificate;
    return std.mem.eql(
        u8,
        name_hash.value,
        expected_name[0..expected_len],
    ) and std.mem.eql(
        u8,
        key_hash.value,
        expected_key[0..expected_len],
    ) and std.mem.eql(u8, serial.value, certificate_serial);
}

fn parseCertIdHash(algorithm: Element) Error!CertIdHash {
    var fields = Reader{ .bytes = algorithm.value };
    const oid = fields.require(0x06) catch return error.InvalidCertId;
    const result: CertIdHash = if (std.mem.eql(u8, oid.value, &oid_sha1))
        .sha1
    else if (std.mem.eql(u8, oid.value, &oid_sha224))
        .sha224
    else if (std.mem.eql(u8, oid.value, &oid_sha256))
        .sha256
    else if (std.mem.eql(u8, oid.value, &oid_sha384))
        .sha384
    else if (std.mem.eql(u8, oid.value, &oid_sha512))
        .sha512
    else if (std.mem.eql(u8, oid.value, &oid_sha512_224))
        .sha512_224
    else if (std.mem.eql(u8, oid.value, &oid_sha512_256))
        .sha512_256
    else if (std.mem.eql(u8, oid.value, &oid_sha3_224))
        .sha3_224
    else if (std.mem.eql(u8, oid.value, &oid_sha3_256))
        .sha3_256
    else if (std.mem.eql(u8, oid.value, &oid_sha3_384))
        .sha3_384
    else if (std.mem.eql(u8, oid.value, &oid_sha3_512))
        .sha3_512
    else
        return error.UnsupportedHashAlgorithm;
    if (fields.next() catch return error.InvalidCertId) |parameters| {
        if (parameters.tag != 0x05 or parameters.value.len != 0 or
            !fields.done())
        {
            return error.InvalidCertId;
        }
    }
    return result;
}

const SignatureAlgorithm = x509_signature.Algorithm;

fn parseSignatureAlgorithm(algorithm: Element) Error!SignatureAlgorithm {
    return x509_signature.parseAlgorithmIdentifier(algorithm.value) catch |err| switch (err) {
        error.UnsupportedSignatureAlgorithm => error.UnsupportedSignatureAlgorithm,
        else => error.InvalidOcspResponse,
    };
}

fn verifySignature(
    algorithm: SignatureAlgorithm,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    x509_signature.verify(algorithm, issuer, message, signature_bytes) catch |err| switch (err) {
        error.InvalidIssuer => return error.InvalidIssuer,
        error.UnsupportedSignatureAlgorithm => return error.UnsupportedSignatureAlgorithm,
        else => return error.InvalidOcspSignature,
    };
}

fn verifySignaturePrepared(
    algorithm: SignatureAlgorithm,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
    p521_verifier: ?*const x509_signature.P521Verifier,
) Error!void {
    const verifier = p521_verifier orelse
        return verifySignature(algorithm, issuer, message, signature_bytes);
    x509_signature.verifyWithP521(
        algorithm,
        verifier,
        message,
        signature_bytes,
    ) catch |err| switch (err) {
        error.InvalidIssuer => return error.InvalidIssuer,
        error.UnsupportedSignatureAlgorithm => return error.UnsupportedSignatureAlgorithm,
        else => return error.InvalidOcspSignature,
    };
}

fn certificateSubjectDer(certificate_der: []const u8) ![]const u8 {
    var top = Reader{ .bytes = certificate_der };
    const certificate = try top.require(0x30);
    if (!top.done()) return error.InvalidDer;
    var certificate_fields = Reader{ .bytes = certificate.value };
    const tbs = try certificate_fields.require(0x30);
    var fields = Reader{ .bytes = tbs.value };
    var first = (try fields.next()) orelse return error.InvalidDer;
    if (first.tag == 0xa0) {
        first = (try fields.next()) orelse return error.InvalidDer;
    }
    if (first.tag != 0x02) return error.InvalidDer;
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    const subject = try fields.require(0x30);
    return tbs.value[subject.start..subject.end];
}

fn certificateSerial(certificate_der: []const u8) ![]const u8 {
    var top = Reader{ .bytes = certificate_der };
    const certificate = try top.require(0x30);
    if (!top.done()) return error.InvalidDer;
    var certificate_fields = Reader{ .bytes = certificate.value };
    const tbs = try certificate_fields.require(0x30);
    var fields = Reader{ .bytes = tbs.value };
    var serial = (try fields.next()) orelse return error.InvalidDer;
    if (serial.tag == 0xa0) {
        serial = (try fields.next()) orelse return error.InvalidDer;
    }
    if (serial.tag != 0x02 or serial.value.len == 0 or
        (serial.value[0] & 0x80) != 0)
    {
        return error.InvalidDer;
    }
    return serial.value;
}

fn parseCertificate(der: []const u8) !Certificate.Parsed {
    var reader = Reader{ .bytes = der };
    _ = try reader.require(0x30);
    if (!reader.done()) return error.InvalidDer;
    return (try certificate_compat.parse(der)).standard;
}

fn parseGeneralizedTime(bytes: []const u8, element: Element) !u64 {
    if (element.tag != 0x18 or element.value.len != 15 or
        element.value[14] != 'Z' or
        element.value_start > std.math.maxInt(u32) or
        element.end > std.math.maxInt(u32))
    {
        return error.InvalidDer;
    }
    const identifier: Certificate.der.Identifier = @bitCast(element.tag);
    return Certificate.parseTime(.{ .buffer = bytes, .index = 0 }, .{
        .identifier = identifier,
        .slice = .{
            .start = @intCast(element.value_start),
            .end = @intCast(element.end),
        },
    });
}

const Element = struct {
    tag: u8,
    start: usize,
    value_start: usize,
    end: usize,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn require(self: *Reader, tag: u8) !Element {
        const element = (try self.next()) orelse return error.InvalidDer;
        if (element.tag != tag) return error.InvalidDer;
        return element;
    }

    fn next(self: *Reader) !?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidDer;
        const start = self.offset;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidDer;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidDer;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidDer;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidDer;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidDer;
        }
        if (length > self.bytes.len - self.offset) return error.InvalidDer;
        const value_start = self.offset;
        self.offset += length;
        return .{
            .tag = tag,
            .start = start,
            .value_start = value_start,
            .end = self.offset,
            .value = self.bytes[value_start..self.offset],
        };
    }

    fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

fn derHeaderLen(value_len: usize) Error!usize {
    return if (value_len < 0x80)
        2
    else if (value_len <= std.math.maxInt(u8))
        3
    else if (value_len <= std.math.maxInt(u16))
        4
    else
        error.BufferTooSmall;
}

fn writeDerHeader(output: []u8, tag: u8, value_len: usize) Error!usize {
    const header_len = try derHeaderLen(value_len);
    if (output.len < header_len) return error.BufferTooSmall;
    output[0] = tag;
    if (header_len == 2) {
        output[1] = @intCast(value_len);
    } else if (header_len == 3) {
        output[1] = 0x81;
        output[2] = @intCast(value_len);
    } else {
        output[1] = 0x82;
        std.mem.writeInt(u16, output[2..4], @intCast(value_len), .big);
    }
    return header_len;
}

fn writeDerElement(
    output: []u8,
    tag: u8,
    value: []const u8,
) Error!usize {
    const header_len = try derHeaderLen(value.len);
    const total_len = header_len + value.len;
    if (output.len < total_len) return error.BufferTooSmall;
    _ = try writeDerHeader(output, tag, value.len);
    @memcpy(output[header_len..total_len], value);
    return total_len;
}

fn appendDerBytes(
    output: []u8,
    offset: *usize,
    bytes: []const u8,
) Error!void {
    if (bytes.len > output.len -| offset.*) return error.BufferTooSmall;
    @memcpy(output[offset.*..][0..bytes.len], bytes);
    offset.* += bytes.len;
}

test "certificate AIA exposes the first OCSP responder URI" {
    const vectors = @import("testdata/path_vectors.zig");
    const certificate = decodeHex(vectors.aia_leaf_hex);
    var urls = try responderUrls(&certificate);
    try std.testing.expectEqualStrings(
        "http://ocsp.example.test/status",
        (try urls.next()).?,
    );
    try std.testing.expectEqualStrings(
        "https://backup.example.test/ocsp",
        (try urls.next()).?,
    );
    try std.testing.expect(try urls.next() == null);
    try std.testing.expectEqualStrings(
        "http://ocsp.example.test/status",
        (try responderUrl(&certificate)).?,
    );

    const without_aia = decodeHex(vectors.leaf_hex);
    try std.testing.expect(try responderUrl(&without_aia) == null);
    var no_urls = try responderUrls(&without_aia);
    try std.testing.expect(try no_urls.next() == null);
    try std.testing.expectError(
        error.InvalidCertificate,
        responderUrl(certificate[0 .. certificate.len - 1]),
    );
}

test "certificate AIA exposes ordered caIssuers URIs independently" {
    const vectors = @import("testdata/path_vectors.zig");
    const certificate = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    var issuers = try caIssuerUrls(&certificate);
    try std.testing.expectEqualStrings(
        "http://ca.example.test/issuer.der",
        (try issuers.next()).?,
    );
    try std.testing.expectEqualStrings(
        "https://backup.example.test/issuer.p7c",
        (try issuers.next()).?,
    );
    try std.testing.expect(try issuers.next() == null);

    var responders = try responderUrls(&certificate);
    try std.testing.expectEqualStrings(
        "http://ocsp.example.test/status",
        (try responders.next()).?,
    );
    try std.testing.expect(try responders.next() == null);
}

test "Authority Information Access OCSP locations are strict" {
    const valid = [_]u8{
        0x30, 0x16,
        0x30, 0x14,
        0x06, 0x08,
        0x2b, 0x06,
        0x01, 0x05,
        0x05, 0x07,
        0x30, 0x01,
        0x86, 0x08,
        'h',  't',
        't',  'p',
        ':',  '/',
        '/',  'a',
    };
    try std.testing.expectEqualStrings(
        "http://a",
        (try parseAuthorityInfoAccess(&valid)).?,
    );
    var ca_issuers_only = valid;
    ca_issuers_only[13] = 0x02;
    try std.testing.expect(
        try parseAuthorityInfoAccess(&ca_issuers_only) == null,
    );

    var critical_fields: [128]u8 = undefined;
    var critical_fields_len: usize = 0;
    critical_fields_len += try writeDerElement(
        critical_fields[critical_fields_len..],
        0x06,
        &oid_authority_information_access,
    );
    critical_fields_len += try writeDerElement(
        critical_fields[critical_fields_len..],
        0x01,
        &.{0xff},
    );
    critical_fields_len += try writeDerElement(
        critical_fields[critical_fields_len..],
        0x04,
        &valid,
    );
    var critical_extension: [160]u8 = undefined;
    const critical_extension_len = try writeDerElement(
        &critical_extension,
        0x30,
        critical_fields[0..critical_fields_len],
    );
    try std.testing.expectError(
        error.CriticalAuthorityInfoAccess,
        responderUrlsFromExtensions(
            critical_extension[0..critical_extension_len],
        ),
    );

    var ordinary_fields: [128]u8 = undefined;
    var ordinary_fields_len: usize = 0;
    ordinary_fields_len += try writeDerElement(
        ordinary_fields[ordinary_fields_len..],
        0x06,
        &oid_authority_information_access,
    );
    ordinary_fields_len += try writeDerElement(
        ordinary_fields[ordinary_fields_len..],
        0x04,
        &valid,
    );
    var ordinary_extension: [160]u8 = undefined;
    const ordinary_extension_len = try writeDerElement(
        &ordinary_extension,
        0x30,
        ordinary_fields[0..ordinary_fields_len],
    );
    var duplicate_extensions: [320]u8 = undefined;
    @memcpy(
        duplicate_extensions[0..ordinary_extension_len],
        ordinary_extension[0..ordinary_extension_len],
    );
    @memcpy(
        duplicate_extensions[ordinary_extension_len..][0..ordinary_extension_len],
        ordinary_extension[0..ordinary_extension_len],
    );
    try std.testing.expectError(
        error.DuplicateAuthorityInfoAccess,
        responderUrlsFromExtensions(
            duplicate_extensions[0 .. 2 * ordinary_extension_len],
        ),
    );

    const invalid = [_][]const u8{
        &.{ 0x30, 0x00 },
        &.{ 0x30, 0x03, 0x02, 0x01, 0x01 },
        &.{
            0x30, 0x14,
            0x30, 0x14,
            0x06, 0x08,
            0x2b, 0x06,
            0x01, 0x05,
            0x05, 0x07,
            0x30, 0x01,
            0x82, 0x08,
            'h',  't',
            't',  'p',
            ':',  '/',
            '/',  'a',
        },
        &.{
            0x30, 0x0f,
            0x30, 0x0d,
            0x06, 0x08,
            0x2b, 0x06,
            0x01, 0x05,
            0x05, 0x07,
            0x30, 0x01,
            0x86, 0x03,
            'h',  ':',
            0x80,
        },
        &.{
            0x30, 0x12,
            0x30, 0x10,
            0x06, 0x08,
            0x2b, 0x06,
            0x01, 0x05,
            0x05, 0x07,
            0x30, 0x01,
            0x86, 0x04,
            'o',  'c',
            's',  'p',
        },
    };
    for (invalid) |encoded| {
        try std.testing.expectError(
            error.InvalidAuthorityInfoAccess,
            parseAuthorityInfoAccess(encoded),
        );
    }

    var hidden_malformed_body: [64]u8 = undefined;
    @memcpy(hidden_malformed_body[0 .. valid.len - 2], valid[2..]);
    hidden_malformed_body[valid.len - 2 ..][0..5].* =
        .{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    var hidden_malformed: [80]u8 = undefined;
    const hidden_malformed_len = try writeDerElement(
        &hidden_malformed,
        0x30,
        hidden_malformed_body[0 .. valid.len + 3],
    );
    try std.testing.expectError(
        error.InvalidAuthorityInfoAccess,
        responderUrlsFromValue(hidden_malformed[0..hidden_malformed_len]),
    );

    const descriptor = [_]u8{
        0x30, 0x14,
        0x06, 0x08,
        0x2b, 0x06,
        0x01, 0x05,
        0x05, 0x07,
        0x30, 0x01,
        0x86, 0x08,
        'h',  't',
        't',  'p',
        ':',  '/',
        '/',  'a',
    };
    var descriptions: std.ArrayList(u8) = .empty;
    defer descriptions.deinit(std.testing.allocator);
    for (0..max_access_descriptions + 1) |_| {
        try descriptions.appendSlice(std.testing.allocator, &descriptor);
    }
    var encoded: [1024]u8 = undefined;
    const encoded_len = try writeDerElement(
        &encoded,
        0x30,
        descriptions.items,
    );
    try std.testing.expectError(
        error.TooManyAccessDescriptions,
        parseAuthorityInfoAccess(encoded[0..encoded_len]),
    );
}

test "issuer-signed OCSP responses bind status, CertID, time, and signature" {
    const vectors = @import("testdata/path_vectors.zig");
    const issuer = decodeHex(vectors.intermediate_hex);
    const leaf = decodeHex(vectors.leaf_hex);
    const other_leaf = decodeHex(vectors.example_leaf_hex);
    const good = decodeHex(vectors.ocsp_good_hex);
    const revoked = decodeHex(vectors.ocsp_revoked_hex);
    const now = 1_790_663_000;

    try std.testing.expectEqual(
        Status.good,
        try verify(&good, &leaf, &issuer, now, .{}),
    );
    try std.testing.expectEqual(
        Status.revoked,
        try verify(&revoked, &leaf, &issuer, now, .{}),
    );
    try std.testing.expectError(
        error.CertificateStatusNotFound,
        verify(&good, &other_leaf, &issuer, now, .{}),
    );
    try std.testing.expectError(
        error.OcspResponseExpired,
        verify(&good, &leaf, &issuer, 1_800_000_000, .{}),
    );

    var tampered = good;
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOcspSignature,
        verify(&tampered, &leaf, &issuer, now, .{}),
    );
}

test "batched OCSP verification authenticates once and returns every status" {
    const certificate_vectors = @import("../crypto/testdata/rsa_signing.zig");
    const path_vectors = @import("testdata/path_vectors.zig");
    const issuer = decodeHex(certificate_vectors.certificate_hex);
    const leaf1 = decodeHex(path_vectors.ocsp_batch_leaf1_hex);
    const leaf2 = decodeHex(path_vectors.ocsp_batch_leaf2_hex);
    const response = decodeHex(path_vectors.ocsp_batch_response_hex);
    const now = 1_790_819_160;
    const certificates = [_][]const u8{ &leaf1, &leaf2 };

    var statuses: [2]Status = undefined;
    try verifyMany(
        &statuses,
        &response,
        &certificates,
        &issuer,
        now,
        .{},
    );
    try std.testing.expectEqualSlices(
        Status,
        &.{ .good, .revoked },
        &statuses,
    );
    try std.testing.expectEqual(
        Status.good,
        try verify(&response, &leaf1, &issuer, now, .{}),
    );
    try std.testing.expectEqual(
        Status.revoked,
        try verify(&response, &leaf2, &issuer, now, .{}),
    );

    const reversed = [_][]const u8{ &leaf2, &leaf1 };
    try verifyMany(
        &statuses,
        &response,
        &reversed,
        &issuer,
        now,
        .{},
    );
    try std.testing.expectEqualSlices(
        Status,
        &.{ .revoked, .good },
        &statuses,
    );

    const unknown_response = decodeHex(
        path_vectors.ocsp_batch_unknown_response_hex,
    );
    try verifyMany(
        &statuses,
        &unknown_response,
        &certificates,
        &issuer,
        now,
        .{},
    );
    try std.testing.expectEqualSlices(
        Status,
        &.{ .good, .unknown },
        &statuses,
    );

    try std.testing.expectError(
        error.InvalidRequestCount,
        verifyMany(&statuses, &response, &.{}, &issuer, now, .{}),
    );
    try std.testing.expectError(
        error.InvalidStatusCount,
        verifyMany(statuses[0..1], &response, &certificates, &issuer, now, .{}),
    );
    const duplicates = [_][]const u8{ &leaf1, &leaf1 };
    try std.testing.expectError(
        error.DuplicateCertificateTarget,
        verifyMany(&statuses, &response, &duplicates, &issuer, now, .{}),
    );
    const too_many = [_][]const u8{&leaf1} **
        (max_verification_targets + 1);
    var too_many_statuses: [max_verification_targets + 1]Status = undefined;
    try std.testing.expectError(
        error.InvalidRequestCount,
        verifyMany(
            &too_many_statuses,
            &response,
            &too_many,
            &issuer,
            now,
            .{},
        ),
    );
    try std.testing.expectError(
        error.CertificateStatusNotFound,
        verify(&response, &issuer, &issuer, now, .{}),
    );

    statuses = .{ .revoked, .unknown };
    const missing = [_][]const u8{ &leaf1, &issuer };
    try std.testing.expectError(
        error.CertificateStatusNotFound,
        verifyMany(
            &statuses,
            &response,
            &missing,
            &issuer,
            now,
            .{},
        ),
    );
    try std.testing.expectEqualSlices(
        Status,
        &.{ .revoked, .unknown },
        &statuses,
    );

    const duplicate_response = decodeHex(
        path_vectors.ocsp_batch_duplicate_response_hex,
    );
    var one_status: [1]Status = .{.unknown};
    try std.testing.expectError(
        error.DuplicateCertificateStatus,
        verifyMany(
            &one_status,
            &duplicate_response,
            &.{&leaf1},
            &issuer,
            now,
            .{},
        ),
    );
    try std.testing.expectEqual(Status.unknown, one_status[0]);

    var tampered = response;
    tampered[tampered.len - 1] ^= 1;
    statuses = .{ .unknown, .good };
    try std.testing.expectError(
        error.InvalidOcspSignature,
        verifyMany(
            &statuses,
            &tampered,
            &certificates,
            &issuer,
            now,
            .{},
        ),
    );
    try std.testing.expectEqualSlices(
        Status,
        &.{ .unknown, .good },
        &statuses,
    );
}

test "issuer-signed OCSP verifies OpenSSL RSA SHA-2 responses" {
    const issuer = @embedFile("testdata/rsa-pss-crl-ca.der");
    const leaf = @embedFile("testdata/rsa-pss-ocsp-leaf.der");
    const responses = [_][]const u8{
        @embedFile("testdata/rsa-pkcs1-sha384.ocsp.der"),
        @embedFile("testdata/rsa-pkcs1-sha512.ocsp.der"),
        @embedFile("testdata/rsa-pss-sha256.ocsp.der"),
        @embedFile("testdata/rsa-pss-sha384.ocsp.der"),
        @embedFile("testdata/rsa-pss-sha512.ocsp.der"),
    };
    const now = 1_790_751_000;
    for (responses) |response| {
        try std.testing.expectEqual(
            Status.good,
            try verify(response, leaf, issuer, now, .{}),
        );
    }

    const tampered = try std.testing.allocator.dupe(u8, responses[1]);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOcspSignature,
        verify(tampered, leaf, issuer, now, .{}),
    );

    const nonce_response = @embedFile(
        "testdata/rsa-pss-sha256-nonce.ocsp.der",
    );
    const nonce = [_]u8{
        0x49, 0x4a, 0x9a, 0x78, 0xe5, 0xaa, 0x73, 0x40,
        0xa1, 0x5b, 0xce, 0x19, 0xb1, 0xa0, 0x87, 0xad,
    };
    try std.testing.expectEqual(
        Status.good,
        try verify(nonce_response, leaf, issuer, now, .{}),
    );
    try std.testing.expectEqual(
        Status.good,
        try verify(nonce_response, leaf, issuer, now, .{
            .expected_nonce = &nonce,
        }),
    );
    var wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    try std.testing.expectError(
        error.NonceMismatch,
        verify(nonce_response, leaf, issuer, now, .{
            .expected_nonce = &wrong_nonce,
        }),
    );
    try std.testing.expectError(
        error.MissingNonce,
        verify(responses[0], leaf, issuer, now, .{
            .expected_nonce = &nonce,
        }),
    );
}

test "OCSP CertID accepts every OpenSSL SHA-2 and SHA-3 issuer hash" {
    const issuer_der = @embedFile("testdata/rsa-pss-crl-ca.der");
    const leaf_der = @embedFile("testdata/rsa-pss-ocsp-leaf.der");
    const other_leaf_der = @embedFile("testdata/rsa-pss-leaf.der");
    const issuer = (try certificate_compat.parse(issuer_der)).standard;
    const leaf = (try certificate_compat.parse(leaf_der)).standard;
    const other_leaf = (try certificate_compat.parse(other_leaf_der)).standard;

    // Generated independently with OpenSSL 3.6:
    // openssl ocsp -issuer issuer.pem -<digest> -cert leaf.pem -reqout ...
    inline for (.{
        "304f300d06096086480165030402040500041c" ++
            "bafd9d80747cd0aed41e6009d4d4da0bbbcd8c41fa72b783ded31474" ++
            "041c87513d0c6883e389e6622d6b6be917f46f0a3e648c11ee4fd683e6bd" ++
            "02022000",
        "304f300d06096086480165030402050500041c" ++
            "d287c241a0b6bc1d4f85cdc8f22d2b54e2a1d97f9d9dde72169dbd79" ++
            "041c26140cbe80cb3c4c5d6b473e6de1ac731391c951c153b255738a4bd3" ++
            "02022000",
        "3057300d060960864801650304020605000420" ++
            "4bb41117cd78eb690e7651eb47fa52e5ba363ec3e8717a08ffd717e364e5a5f8" ++
            "0420fa1ff2bacfede45213f04a7959e292e6583471a2ae4c116bdf0769a491048456" ++
            "02022000",
        "304f300d06096086480165030402070500041c" ++
            "3ad1e52be70c6f98d07afeb62bf9d8e89fa8f686384754fd46217e46" ++
            "041c743776f7722233760ffd6253a5d9d3986df69299ae771cf2a11b16df" ++
            "02022000",
        "3057300d060960864801650304020805000420" ++
            "b0fcf16ba5ba6c6c87b3ab71db45bf0d45aae289889f9189c49708a1ef0603af" ++
            "0420578be2a36cd062d5877228d5e51ef7c81ba32004e0289bd8c51318439ae50bbc" ++
            "02022000",
        "3077300d060960864801650304020905000430" ++
            "47fd5becd0d927116bcd7afb9030fcc3c955c8c0a5c5bd68e11b6208739f3cec" ++
            "b36906aef99c449dd6e9ec4b1d28dcfe" ++
            "0430467f48f3f6145cef87180f1a8a9dd1322655db5b53d866515866f0fefc868" ++
            "9eef3ab468233fad1a34700394dbb7418dc02022000",
        "308197300d060960864801650304020a05000440" ++
            "b4dbe9005c9d09e507a903786986b931156571835dd4dc67acae75f2b6182b3e" ++
            "f7b01097c47dd5ebc17ccca70f7c893551fcb27d170b10ba5b9b9758ab4dbde4" ++
            "044000b3c8329e3133a29a015c5881dbb3b926dd69b1cc87b68d23852f44d5e4f" ++
            "10cf117a0124b1670bd40e73599b5cf1b5a3271337a8149d9190a8f870d32cbb3ee" ++
            "02022000",
        "3077300d060960864801650304020205000430" ++
            "926c4ad3c5d20f3022b34fd24bcea6a00d8d8aa643d4c4c2cdc4598d4752ff" ++
            "7847fa07ee654b857d8207d90c08ddc7d3" ++
            "04309d6317ae938c27125106ef193ebaecceee6c7e377cb55c86498fcefaf52f" ++
            "649690ecf73168d70695ec473d96bbd346cf02022000",
        "308197300d060960864801650304020305000440" ++
            "440f77c4c3db1acc3f62b420cc257f1243f825b138185881af0ed8ac8773ac85" ++
            "2a3b37c89c4d65744ca9c3d0cf9ee3444c9ccc63c06cda14f129c92af9c87b67" ++
            "0440d1c3333e76963b706a5451a1156a76682a63910ca01f872167e309a42c02d139" ++
            "e2e069d287aa5f04268d9ccb85471478af11f7036dfd1d0020806c2d7672d87b" ++
            "02022000",
    }) |encoded| {
        const cert_id_der = decodeHex(encoded);
        var reader = Reader{ .bytes = &cert_id_der };
        const cert_id = try reader.require(0x30);
        try std.testing.expect(reader.done());
        try std.testing.expect(try certIdMatches(
            cert_id,
            leaf_der,
            leaf,
            issuer_der,
            issuer,
        ));
        try std.testing.expect(!(try certIdMatches(
            cert_id,
            other_leaf_der,
            other_leaf,
            issuer_der,
            issuer,
        )));

        var tampered = cert_id_der;
        var fields = Reader{ .bytes = cert_id.value };
        _ = try fields.require(0x30);
        const name_hash = try fields.require(0x04);
        const hash_offset = @intFromPtr(name_hash.value.ptr) -
            @intFromPtr(&cert_id_der);
        tampered[hash_offset] ^= 1;
        var tampered_reader = Reader{ .bytes = &tampered };
        try std.testing.expect(!(try certIdMatches(
            try tampered_reader.require(0x30),
            leaf_der,
            leaf,
            issuer_der,
            issuer,
        )));
    }
}

test "OCSP CertID rejects unknown hashes and non-NULL parameters" {
    const unknown = decodeHex("300d060960864801650304020b0500");
    var unknown_reader = Reader{ .bytes = &unknown };
    try std.testing.expectError(
        error.UnsupportedHashAlgorithm,
        parseCertIdHash(try unknown_reader.require(0x30)),
    );

    const bad_parameters = decodeHex("300d06096086480165030402020400");
    var bad_reader = Reader{ .bytes = &bad_parameters };
    try std.testing.expectError(
        error.InvalidCertId,
        parseCertIdHash(try bad_reader.require(0x30)),
    );
}

test "OCSP request encoding matches OpenSSL and every supported hash" {
    const issuer_der = @embedFile("testdata/rsa-pss-crl-ca.der");
    const leaf_der = @embedFile("testdata/rsa-pss-ocsp-leaf.der");
    const issuer = (try certificate_compat.parse(issuer_der)).standard;
    const leaf = (try certificate_compat.parse(leaf_der)).standard;
    var output: [max_request_len]u8 = undefined;

    const expected_sha256 = decodeHex(
        "305f305d305b30593057300d06096086480165030402010500" ++
            "0420ace57fdc8488609fa0a19ba793e2c9f20f9fe5b36d6817152a53bc1fc2655cda" ++
            "04200f77c2263b56876cf9e53348eef3cbfe2c131c46a959559991a8e04b31c9117a" ++
            "02022000",
    );
    const sha256_len = try createRequest(
        &output,
        leaf_der,
        issuer_der,
        .{ .hash = .sha256 },
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_sha256,
        output[0..sha256_len],
    );

    inline for ([_]CertIdHash{
        .sha1,
        .sha224,
        .sha256,
        .sha384,
        .sha512,
        .sha512_224,
        .sha512_256,
        .sha3_224,
        .sha3_256,
        .sha3_384,
        .sha3_512,
    }) |hash| {
        const len = try createRequest(
            &output,
            leaf_der,
            issuer_der,
            .{ .hash = hash },
        );
        var outer = Reader{ .bytes = output[0..len] };
        const request = try outer.require(0x30);
        try std.testing.expect(outer.done());
        var request_fields = Reader{ .bytes = request.value };
        const tbs = try request_fields.require(0x30);
        try std.testing.expect(request_fields.done());
        var tbs_fields = Reader{ .bytes = tbs.value };
        const request_list = try tbs_fields.require(0x30);
        try std.testing.expect(tbs_fields.done());
        var list_fields = Reader{ .bytes = request_list.value };
        const single_request = try list_fields.require(0x30);
        try std.testing.expect(list_fields.done());
        var single_fields = Reader{ .bytes = single_request.value };
        const cert_id = try single_fields.require(0x30);
        try std.testing.expect(single_fields.done());
        try std.testing.expect(try certIdMatches(
            cert_id,
            leaf_der,
            leaf,
            issuer_der,
            issuer,
        ));
    }
}

test "batched OCSP request encoding matches OpenSSL and mixed issuers" {
    const issuer_der = @embedFile("testdata/rsa-pss-crl-ca.der");
    const leaf1_der = @embedFile("testdata/rsa-pss-ocsp-leaf.der");
    const leaf2_der = @embedFile("testdata/rsa-pss-leaf.der");
    const targets = [_]RequestTarget{
        .{ .certificate_der = leaf1_der, .issuer_der = issuer_der },
        .{ .certificate_der = leaf2_der, .issuer_der = issuer_der },
    };
    const expected = decodeHex(
        "3081bc3081b93081b630593057300d06096086480165030402010500" ++
            "0420ace57fdc8488609fa0a19ba793e2c9f20f9fe5b36d6817152a53bc1fc2655cda" ++
            "04200f77c2263b56876cf9e53348eef3cbfe2c131c46a959559991a8e04b31c9117a" ++
            "0202200030593057300d06096086480165030402010500" ++
            "0420ace57fdc8488609fa0a19ba793e2c9f20f9fe5b36d6817152a53bc1fc2655cda" ++
            "04200f77c2263b56876cf9e53348eef3cbfe2c131c46a959559991a8e04b31c9117a" ++
            "02022003",
    );
    var output: [max_batch_request_len]u8 = undefined;
    const len = try createRequests(&output, &targets, .{ .hash = .sha256 });
    try std.testing.expectEqualSlices(u8, &expected, output[0..len]);
    try std.testing.expectError(
        error.BufferTooSmall,
        createRequests(output[0 .. len - 1], &targets, .{ .hash = .sha256 }),
    );
    try std.testing.expectError(
        error.InvalidRequestCount,
        createRequests(&output, &.{}, .{}),
    );
    const maximum = [_]RequestTarget{targets[0]} ** max_request_entries;
    const maximum_len = try createRequests(&output, &maximum, .{});
    try std.testing.expect(maximum_len <= max_batch_request_len);
    const too_many = [_]RequestTarget{targets[0]} ** (max_request_entries + 1);
    try std.testing.expectError(
        error.InvalidRequestCount,
        createRequests(&output, &too_many, .{}),
    );

    const vectors = @import("testdata/path_vectors.zig");
    const p256_issuer_der = decodeHex(vectors.intermediate_hex);
    const p256_leaf_der = decodeHex(vectors.leaf_hex);
    const mixed_targets = [_]RequestTarget{
        targets[0],
        .{
            .certificate_der = &p256_leaf_der,
            .issuer_der = &p256_issuer_der,
        },
    };
    const mixed_len = try createRequests(
        &output,
        &mixed_targets,
        .{ .hash = .sha384 },
    );
    var outer = Reader{ .bytes = output[0..mixed_len] };
    const request = try outer.require(0x30);
    try std.testing.expect(outer.done());
    var request_fields = Reader{ .bytes = request.value };
    const tbs = try request_fields.require(0x30);
    try std.testing.expect(request_fields.done());
    var tbs_fields = Reader{ .bytes = tbs.value };
    const request_list = try tbs_fields.require(0x30);
    try std.testing.expect(tbs_fields.done());
    var entries = Reader{ .bytes = request_list.value };

    const rsa_leaf = (try certificate_compat.parse(leaf1_der)).standard;
    const rsa_issuer = (try certificate_compat.parse(issuer_der)).standard;
    const first_request = try entries.require(0x30);
    var first_fields = Reader{ .bytes = first_request.value };
    const first_id = try first_fields.require(0x30);
    try std.testing.expect(first_fields.done());
    try std.testing.expect(try certIdMatches(
        first_id,
        leaf1_der,
        rsa_leaf,
        issuer_der,
        rsa_issuer,
    ));

    const p256_leaf = (try certificate_compat.parse(&p256_leaf_der)).standard;
    const p256_issuer = (try certificate_compat.parse(&p256_issuer_der)).standard;
    const second_request = try entries.require(0x30);
    var second_fields = Reader{ .bytes = second_request.value };
    const second_id = try second_fields.require(0x30);
    try std.testing.expect(second_fields.done());
    try std.testing.expect(try certIdMatches(
        second_id,
        &p256_leaf_der,
        p256_leaf,
        &p256_issuer_der,
        p256_issuer,
    ));
    try std.testing.expect(entries.done());
}

test "OCSP request encoding matches OpenSSL RFC 8954 nonce framing" {
    const issuer_der = @embedFile("testdata/rsa-pss-crl-ca.der");
    const leaf_der = @embedFile("testdata/rsa-pss-ocsp-leaf.der");
    const nonce = decodeHex("fea7f91c44725ddc328a8a25d757746f");
    const expected = decodeHex(
        "3081a53081a2307b30793077300d06096086480165030402020500" ++
            "0430926c4ad3c5d20f3022b34fd24bcea6a00d8d8aa643d4c4c2cdc4598d4752ff" ++
            "7847fa07ee654b857d8207d90c08ddc7d3" ++
            "04309d6317ae938c27125106ef193ebaecceee6c7e377cb55c86498fcefaf52f" ++
            "649690ecf73168d70695ec473d96bbd346cf02022000" ++
            "a2233021301f06092b060105050730010204120410fea7f91c44725ddc328a8a25d757746f",
    );
    var output: [max_request_len]u8 = undefined;
    const len = try createRequest(
        &output,
        leaf_der,
        issuer_der,
        .{ .hash = .sha384, .nonce = &nonce },
    );
    try std.testing.expectEqualSlices(u8, &expected, output[0..len]);
    try std.testing.expectError(
        error.BufferTooSmall,
        createRequest(output[0 .. len - 1], leaf_der, issuer_der, .{
            .hash = .sha384,
            .nonce = &nonce,
        }),
    );
    try std.testing.expectError(
        error.InvalidNonce,
        createRequest(&output, leaf_der, issuer_der, .{ .nonce = "" }),
    );
    try std.testing.expectError(
        error.InvalidNonce,
        createRequest(&output, leaf_der, issuer_der, .{
            .nonce = &([_]u8{0} ** (max_nonce_len + 1)),
        }),
    );
}

test "OCSP accepts an RSA-PSS-signed certificate subject" {
    const issuer = @embedFile("testdata/rsa-pss-crl-ca.der");
    const leaf = @embedFile("testdata/rsa-pss-leaf.der");
    const response = @embedFile("testdata/rsa-pss-certificate.ocsp.der");
    try std.testing.expectEqual(
        Status.good,
        try verify(response, leaf, issuer, 1_800_000_000, .{}),
    );
}

test "OCSP extensions ignore unknown non-critical values and bound each scope" {
    const unknown_noncritical = [_]u8{
        0x30, 0x0a,
        0x30, 0x08,
        0x06, 0x03,
        0x2a, 0x03,
        0x04, 0x04,
        0x01, 0x00,
    };
    try std.testing.expect((try parseExtensions(
        &unknown_noncritical,
        max_extensions_per_scope,
        true,
    )) == null);
    try std.testing.expectError(
        error.TooManyExtensions,
        parseExtensions(&unknown_noncritical, 0, true),
    );
    const duplicate = [_]u8{
        0x30, 0x14,
        0x30, 0x08,
        0x06, 0x03,
        0x2a, 0x03,
        0x04, 0x04,
        0x01, 0x00,
        0x30, 0x08,
        0x06, 0x03,
        0x2a, 0x03,
        0x04, 0x04,
        0x01, 0x01,
    };
    try std.testing.expectError(
        error.InvalidOcspResponse,
        parseExtensions(&duplicate, max_extensions_per_scope, true),
    );

    const unknown_critical = [_]u8{
        0x30, 0x0d,
        0x30, 0x0b,
        0x06, 0x03,
        0x2a, 0x03,
        0x04, 0x01,
        0x01, 0xff,
        0x04, 0x01,
        0x00,
    };
    try std.testing.expectError(
        error.UnsupportedExtension,
        parseExtensions(
            &unknown_critical,
            max_extensions_per_scope,
            true,
        ),
    );

    const nonce = [_]u8{
        0x30, 0x13,
        0x30, 0x11,
        0x06, 0x09,
        0x2b, 0x06,
        0x01, 0x05,
        0x05, 0x07,
        0x30, 0x01,
        0x02, 0x04,
        0x04, 0x04,
        0x02, 0xaa,
        0xbb,
    };
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xaa, 0xbb },
        (try parseExtensions(
            &nonce,
            max_extensions_per_scope,
            true,
        )).?,
    );
    try std.testing.expectError(
        error.UnsupportedExtension,
        parseExtensions(&nonce, max_extensions_per_scope, false),
    );
}

test "delegated OCSP responder requires direct issuer authorization and EKU" {
    const vectors = @import("testdata/path_vectors.zig");
    const issuer = decodeHex(vectors.delegated_ocsp_ca_hex);
    const leaf = decodeHex(vectors.delegated_ocsp_leaf_hex);
    const unknown_leaf = decodeHex(vectors.delegated_ocsp_unknown_leaf_hex);
    const good = decodeHex(vectors.delegated_ocsp_good_hex);
    const unknown = decodeHex(vectors.delegated_ocsp_unknown_hex);
    const unauthorized = decodeHex(
        vectors.delegated_ocsp_unauthorized_hex,
    );
    const now = 1_790_664_300;

    try std.testing.expectEqual(
        Status.good,
        try verify(&good, &leaf, &issuer, now, .{}),
    );
    try std.testing.expectEqual(
        Status.unknown,
        try verify(&unknown, &unknown_leaf, &issuer, now, .{}),
    );
    try std.testing.expectError(
        error.UnauthorizedResponder,
        verify(&unauthorized, &leaf, &issuer, now, .{}),
    );
    try std.testing.expectError(
        error.UnauthorizedResponder,
        verify(&good, &leaf, &issuer, 1_790_837_100, .{}),
    );
    try std.testing.expectError(
        error.TooManyResponderCertificates,
        verify(&good, &leaf, &issuer, now, .{
            .max_embedded_responder_certificates = 0,
        }),
    );
    try std.testing.expectError(
        error.OcspResponseTooLarge,
        verify(&good, &leaf, &issuer, now, .{
            .max_response_bytes = good.len - 1,
        }),
    );

    var tampered = good;
    var outer = Reader{ .bytes = &tampered };
    const response = try outer.require(0x30);
    var response_fields = Reader{ .bytes = response.value };
    _ = try response_fields.require(0x0a);
    const response_bytes = try response_fields.require(0xa0);
    var response_explicit = Reader{ .bytes = response_bytes.value };
    const response_sequence = try response_explicit.require(0x30);
    var encoded_response = Reader{ .bytes = response_sequence.value };
    _ = try encoded_response.require(0x06);
    const basic_octets = try encoded_response.require(0x04);
    var basic_reader = Reader{ .bytes = basic_octets.value };
    const basic = try basic_reader.require(0x30);
    var basic_fields = Reader{ .bytes = basic.value };
    _ = try basic_fields.require(0x30);
    _ = try basic_fields.require(0x30);
    const signature = try basic_fields.require(0x03);
    const signature_offset = @intFromPtr(signature.value.ptr) -
        @intFromPtr(&tampered);
    tampered[signature_offset + signature.value.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOcspSignature,
        verify(&tampered, &leaf, &issuer, now, .{}),
    );
}

test "OCSP responder byName uses RFC 5280 distinguished-name equality" {
    const vectors = @import("testdata/path_vectors.zig");
    const utf8 = decodeHex(vectors.dn_equivalent_issuer_utf8_hex);
    const printable = decodeHex(vectors.dn_equivalent_issuer_printable_hex);
    const unrelated = decodeHex(vectors.dn_equivalent_root_hex);
    const responder_name = try certificateSubjectDer(&utf8);
    const responder = Element{
        .tag = 0xa1,
        .start = 0,
        .value_start = 0,
        .end = responder_name.len,
        .value = responder_name,
    };
    try std.testing.expect(try responderMatches(
        responder,
        &printable,
        try parseCertificate(&printable),
    ));
    try std.testing.expect(!(try responderMatches(
        responder,
        &unrelated,
        try parseCertificate(&unrelated),
    )));

    var name = Reader{ .bytes = responder_name };
    const sequence = try name.require(0x30);
    try std.testing.expect(name.done());
    try std.testing.expect(try responderMatches(
        .{
            .tag = 0xa1,
            .start = 0,
            .value_start = 0,
            .end = sequence.value.len,
            .value = sequence.value,
        },
        &printable,
        try parseCertificate(&printable),
    ));

    const issuer = decodeHex(vectors.crl_dn_issuer_utf8_hex);
    const target = decodeHex(vectors.ocsp_dn_ocsp_target_hex);
    const response = decodeHex(vectors.ocsp_dn_response_hex);
    try std.testing.expectEqual(
        Status.good,
        try verify(&response, &target, &issuer, 1_790_842_500, .{}),
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
