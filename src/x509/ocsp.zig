//! Strict issuer- and delegated-responder-signed RFC 6960
//! BasicOCSPResponse verification.
//!
//! A result is returned only after CertID binding, responder identity,
//! responder authorization, signature, and time-window verification succeed.
//! Response and SingleResponse extensions are bounded, unknown critical
//! extensions fail closed, and RFC 8954 response nonces can be matched exactly.

const std = @import("std");
const x509_signature = @import("signature.zig");

const Certificate = std.crypto.Certificate;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;

const oid_basic_response = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
};
const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
const oid_sha256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
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
const max_extensions_per_scope = 32;
const max_nonce_len = 32;

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
};

pub fn verify(
    response_der: []const u8,
    certificate_der: []const u8,
    issuer_der: []const u8,
    now_seconds: i64,
    policy: Policy,
) Error!Status {
    if (now_seconds < 0) return error.OcspResponseNotYetValid;
    if (response_der.len > policy.max_response_bytes) {
        return error.OcspResponseTooLarge;
    }
    if (policy.expected_nonce) |nonce| {
        if (nonce.len == 0 or nonce.len > max_nonce_len) {
            return error.InvalidNonce;
        }
    }
    const certificate = parseCertificate(certificate_der) catch
        return error.InvalidOcspResponse;
    const issuer = parseCertificate(issuer_der) catch
        return error.InvalidIssuer;
    certificate.verify(issuer, now_seconds) catch
        return error.InvalidIssuer;
    if (now_seconds < issuer.validity.not_before or
        now_seconds > issuer.validity.not_after)
    {
        return error.InvalidIssuer;
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

    const result = try verifyResponseData(
        response_data,
        certificate_der,
        certificate,
        issuer_der,
        issuer,
        @intCast(now_seconds),
        &policy,
    );
    const signature_algorithm = try parseSignatureAlgorithm(
        signature_algorithm_element,
    );
    try verifyAuthorizedResponderSignature(
        result.responder,
        issuer_der,
        issuer,
        embedded_certificates,
        now_seconds,
        &policy,
        signature_algorithm,
        basic.value[response_data.start..response_data.end],
        signature_value.value[1..],
    );
    return result.status;
}

const ResponseDataResult = struct {
    status: Status,
    responder: Element,
};

fn verifyResponseData(
    response_data: Element,
    certificate_der: []const u8,
    certificate: Certificate.Parsed,
    issuer_der: []const u8,
    issuer: Certificate.Parsed,
    now: u64,
    policy: *const Policy,
) Error!ResponseDataResult {
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

    var matches: usize = 0;
    var matched_status: Status = .unknown;
    var singles = Reader{ .bytes = responses.value };
    while (singles.next() catch return error.InvalidOcspResponse) |single| {
        if (single.tag != 0x30) return error.InvalidOcspResponse;
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
            matches += 1;
            if (matches != 1) return error.DuplicateCertificateStatus;
            matched_status = certificate_status;
        }
    }
    if (matches == 0) return error.CertificateStatusNotFound;
    return .{ .status = matched_status, .responder = responder };
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
            if (!std.mem.eql(u8, responder.value, subject_der)) {
                // Some encoders apply the context tag implicitly to Name.
                var name = Reader{ .bytes = subject_der };
                const sequence = name.require(0x30) catch
                    return error.InvalidOcspResponse;
                if (!name.done()) return error.InvalidOcspResponse;
                break :blk std.mem.eql(
                    u8,
                    responder.value,
                    sequence.value,
                );
            }
            break :blk true;
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
) Error!void {
    var identity_matches: usize = 0;
    var authorized_matches: usize = 0;
    var verified_matches: usize = 0;
    var signature_error: ?Error = null;

    if (try responderMatches(responder_id, issuer_der, issuer)) {
        identity_matches += 1;
        authorized_matches += 1;
        verifySignature(
            signature_algorithm,
            issuer,
            message,
            signature,
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
            const candidate = parseCertificate(certificate_der) catch
                return error.InvalidOcspResponse;
            if (!try responderMatches(
                responder_id,
                certificate_der,
                candidate,
            )) continue;
            identity_matches += 1;
            candidate.verify(issuer, now_seconds) catch continue;
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

const CertIdHash = enum { sha1, sha256 };

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
        .sha256 => Sha256.digest_length,
    };
    if (name_hash.value.len != expected_len or
        key_hash.value.len != expected_len)
    {
        return error.InvalidCertId;
    }
    var expected_name: [Sha256.digest_length]u8 = undefined;
    var expected_key: [Sha256.digest_length]u8 = undefined;
    const issuer_name_der = certificateSubjectDer(issuer_der) catch
        return error.InvalidIssuer;
    switch (hash) {
        .sha1 => {
            Sha1.hash(issuer_name_der, expected_name[0..20], .{});
            Sha1.hash(issuer.pubKey(), expected_key[0..20], .{});
        },
        .sha256 => {
            Sha256.hash(issuer_name_der, &expected_name, .{});
            Sha256.hash(issuer.pubKey(), &expected_key, .{});
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
    else if (std.mem.eql(u8, oid.value, &oid_sha256))
        .sha256
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
    return Certificate.parse(.{ .buffer = der, .index = 0 });
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

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
