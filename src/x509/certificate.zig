//! Compatibility parser for X.509 certificates whose signature
//! AlgorithmIdentifier is not yet understood by `std.crypto.Certificate`.
//!
//! The fast path is exactly Zig std's parser. The fallback accepts the strict
//! RSA-PSS profile and NIST ECDSA-with-SHA3 AlgorithmIdentifiers shared with
//! Vail's CRL and OCSP verifiers, then constructs the same borrowed field view
//! used by the trust-path engine.

const std = @import("std");
const x509_signature = @import("signature.zig");

const Certificate = std.crypto.Certificate;
pub const SignatureAlgorithm = x509_signature.Algorithm;

pub const Parsed = struct {
    standard: Certificate.Parsed,
    signature_algorithm: ?x509_signature.Algorithm = null,

    pub fn issuer(self: Parsed) []const u8 {
        return self.standard.issuer();
    }

    pub fn subject(self: Parsed) []const u8 {
        return self.standard.subject();
    }

    pub fn commonName(self: Parsed) []const u8 {
        return self.standard.commonName();
    }

    pub fn pubKey(self: Parsed) []const u8 {
        return self.standard.pubKey();
    }

    pub fn message(self: Parsed) []const u8 {
        return self.standard.message();
    }

    pub fn signature(self: Parsed) []const u8 {
        return self.standard.signature();
    }

    pub fn subjectAltName(self: Parsed) []const u8 {
        return self.standard.subjectAltName();
    }

    pub fn verifyHostName(self: Parsed, host_name: []const u8) !void {
        return self.standard.verifyHostName(host_name);
    }

    pub fn verify(self: Parsed, issuer_certificate: Parsed, now_seconds: i64) !void {
        if (self.signature_algorithm) |algorithm| {
            return verifyWithAlgorithm(
                self.standard,
                algorithm,
                issuer_certificate.standard,
                now_seconds,
            );
        }
        if (issuerUsesP521(issuer_certificate.standard)) {
            if (!std.mem.eql(
                u8,
                self.standard.issuer(),
                issuer_certificate.standard.subject(),
            )) {
                return error.CertificateIssuerMismatch;
            }
            return verifySignatureAndValidity(
                self.standard,
                null,
                issuer_certificate.standard,
                now_seconds,
            );
        }
        return self.standard.verify(issuer_certificate.standard, now_seconds);
    }
};

fn issuerUsesP521(issuer: Certificate.Parsed) bool {
    return switch (issuer.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| curve == .secp521r1,
        else => false,
    };
}

fn issuerUsesP256(issuer: Certificate.Parsed) bool {
    return switch (issuer.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| curve == .X9_62_prime256v1,
        else => false,
    };
}

fn issuerUsesEd25519(issuer: Certificate.Parsed) bool {
    return issuer.pub_key_algo == .curveEd25519 and
        issuer.pubKey().len == std.crypto.sign.Ed25519.PublicKey.encoded_length;
}

pub fn verifyWithAlgorithm(
    subject: Certificate.Parsed,
    algorithm: SignatureAlgorithm,
    issuer: Certificate.Parsed,
    now_seconds: i64,
) !void {
    if (!std.mem.eql(u8, subject.issuer(), issuer.subject())) {
        return error.CertificateIssuerMismatch;
    }
    return verifySignatureAndValidity(subject, algorithm, issuer, now_seconds);
}

/// Verify validity and signature after the caller has established issuer-name
/// equality. This is used when RFC 5280 section 7.1 says two Names are equal
/// even though their DER string encodings differ.
pub fn verifySignatureAndValidity(
    subject: Certificate.Parsed,
    override_algorithm: ?SignatureAlgorithm,
    issuer: Certificate.Parsed,
    now_seconds: i64,
) !void {
    if (now_seconds < subject.validity.not_before) {
        return error.CertificateNotYetValid;
    }
    if (now_seconds > subject.validity.not_after) {
        return error.CertificateExpired;
    }
    const algorithm = try signatureAlgorithm(subject, override_algorithm);
    x509_signature.verify(
        algorithm,
        issuer,
        subject.message(),
        subject.signature(),
    ) catch |err| return mapSignatureError(err);
}

/// Verify a certificate signed by a P-521 issuer while reusing a caller-owned
/// prepared public-key table.
pub fn verifySignatureAndValidityWithP521(
    subject: Certificate.Parsed,
    override_algorithm: ?SignatureAlgorithm,
    issuer: Certificate.Parsed,
    now_seconds: i64,
    verifier: *const x509_signature.P521Verifier,
) !void {
    if (!issuerUsesP521(issuer)) {
        return error.CertificateSignatureAlgorithmUnsupported;
    }
    if (now_seconds < subject.validity.not_before) {
        return error.CertificateNotYetValid;
    }
    if (now_seconds > subject.validity.not_after) {
        return error.CertificateExpired;
    }
    const algorithm = try signatureAlgorithm(subject, override_algorithm);
    x509_signature.verifyWithP521(
        algorithm,
        verifier,
        subject.message(),
        subject.signature(),
    ) catch |err| return mapSignatureError(err);
}

/// Verify validity and a P-256 signature with a caller-retained issuer table.
pub fn verifySignatureAndValidityWithP256(
    subject: Certificate.Parsed,
    override_algorithm: ?SignatureAlgorithm,
    issuer: Certificate.Parsed,
    now_seconds: i64,
    verifier: *const x509_signature.P256Verifier,
) !void {
    if (!issuerUsesP256(issuer)) {
        return error.CertificateSignatureAlgorithmUnsupported;
    }
    const public_key = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey
        .fromSec1(issuer.pubKey()) catch return error.CertificatePublicKeyInvalid;
    if (!verifier.matchesPublicKey(public_key.p)) {
        return error.CertificatePublicKeyInvalid;
    }
    if (now_seconds < subject.validity.not_before) {
        return error.CertificateNotYetValid;
    }
    if (now_seconds > subject.validity.not_after) {
        return error.CertificateExpired;
    }
    const algorithm = try signatureAlgorithm(subject, override_algorithm);
    x509_signature.verifyWithP256(
        algorithm,
        verifier,
        subject.message(),
        subject.signature(),
    ) catch |err| return mapSignatureError(err);
}

/// Verify validity and an Ed25519 signature with a caller-retained issuer
/// table. This is intended for paths that reuse one issuer for several signed
/// objects.
pub fn verifySignatureAndValidityWithEd25519(
    subject: Certificate.Parsed,
    override_algorithm: ?SignatureAlgorithm,
    issuer: Certificate.Parsed,
    now_seconds: i64,
    verifier: *const x509_signature.Ed25519Verifier,
) !void {
    if (!issuerUsesEd25519(issuer)) {
        return error.CertificateSignatureAlgorithmUnsupported;
    }
    const issuer_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(
        issuer.pubKey()[0..std.crypto.sign.Ed25519.PublicKey.encoded_length].*,
    ) catch return error.CertificatePublicKeyInvalid;
    if (!verifier.matchesPublicKey(issuer_key)) {
        return error.CertificatePublicKeyInvalid;
    }
    if (now_seconds < subject.validity.not_before) {
        return error.CertificateNotYetValid;
    }
    if (now_seconds > subject.validity.not_after) {
        return error.CertificateExpired;
    }
    const algorithm = try signatureAlgorithm(subject, override_algorithm);
    x509_signature.verifyWithEd25519(
        algorithm,
        verifier,
        subject.message(),
        subject.signature(),
    ) catch |err| return mapSignatureError(err);
}

fn signatureAlgorithm(
    subject: Certificate.Parsed,
    override_algorithm: ?SignatureAlgorithm,
) !SignatureAlgorithm {
    return override_algorithm orelse switch (subject.signature_algorithm) {
        .sha1WithRSAEncryption => .rsa_pkcs1_sha1,
        .sha224WithRSAEncryption => .rsa_pkcs1_sha224,
        .sha256WithRSAEncryption => .rsa_pkcs1_sha256,
        .sha384WithRSAEncryption => .rsa_pkcs1_sha384,
        .sha512WithRSAEncryption => .rsa_pkcs1_sha512,
        .ecdsa_with_SHA224 => .ecdsa_sha224,
        .ecdsa_with_SHA256 => .ecdsa_p256_sha256,
        .ecdsa_with_SHA384 => .ecdsa_p384_sha384,
        .ecdsa_with_SHA512 => .ecdsa_sha512,
        .curveEd25519 => .ed25519,
        .md2WithRSAEncryption,
        .md5WithRSAEncryption,
        => return error.CertificateSignatureAlgorithmUnsupported,
    };
}

fn mapSignatureError(err: x509_signature.Error) anyerror {
    return switch (err) {
        error.InvalidSignature => return error.CertificateSignatureInvalid,
        error.InvalidIssuer => return error.CertificatePublicKeyInvalid,
        error.UnsupportedSignatureAlgorithm => return error.CertificateSignatureAlgorithmUnsupported,
        error.InvalidAlgorithmIdentifier => return error.CertificateSignatureAlgorithmUnsupported,
    };
}

pub fn parse(der: []const u8) !Parsed {
    const certificate = Certificate{ .buffer = der, .index = 0 };
    if (Certificate.parse(certificate)) |standard| {
        return .{ .standard = standard };
    } else |_| {
        return parseExtendedSignature(certificate);
    }
}

fn parseExtendedSignature(certificate: Certificate) !Parsed {
    const bytes = certificate.buffer;
    const outer = try Certificate.der.Element.parse(bytes, certificate.index);
    if (outer.identifier.tag != .sequence or outer.slice.end != bytes.len) {
        return error.InvalidCertificate;
    }
    const tbs = try Certificate.der.Element.parse(bytes, outer.slice.start);
    if (tbs.identifier.tag != .sequence) return error.InvalidCertificate;
    const version_element = try Certificate.der.Element.parse(
        bytes,
        tbs.slice.start,
    );
    const version = try Certificate.parseVersion(bytes, version_element);
    const serial = if (@as(u8, @bitCast(version_element.identifier)) == 0xa0)
        try Certificate.der.Element.parse(bytes, version_element.slice.end)
    else
        version_element;
    if (serial.identifier.tag != .integer) return error.InvalidCertificate;

    const tbs_algorithm_start = serial.slice.end;
    const tbs_algorithm = try Certificate.der.Element.parse(
        bytes,
        tbs_algorithm_start,
    );
    if (tbs_algorithm.identifier.tag != .sequence) {
        return error.InvalidCertificate;
    }
    const issuer = try Certificate.der.Element.parse(
        bytes,
        tbs_algorithm.slice.end,
    );
    if (issuer.identifier.tag != .sequence) return error.InvalidCertificate;
    const validity = try Certificate.der.Element.parse(bytes, issuer.slice.end);
    if (validity.identifier.tag != .sequence) return error.InvalidCertificate;
    const not_before = try Certificate.der.Element.parse(
        bytes,
        validity.slice.start,
    );
    const not_after = try Certificate.der.Element.parse(
        bytes,
        not_before.slice.end,
    );
    if (not_after.slice.end != validity.slice.end) {
        return error.InvalidCertificate;
    }
    const not_before_seconds = try Certificate.parseTime(
        certificate,
        not_before,
    );
    const not_after_seconds = try Certificate.parseTime(
        certificate,
        not_after,
    );
    const subject = try Certificate.der.Element.parse(bytes, validity.slice.end);
    if (subject.identifier.tag != .sequence) return error.InvalidCertificate;
    const public_key_info = try Certificate.der.Element.parse(
        bytes,
        subject.slice.end,
    );
    if (public_key_info.identifier.tag != .sequence) {
        return error.InvalidCertificate;
    }
    const public_key_algorithm = try Certificate.der.Element.parse(
        bytes,
        public_key_info.slice.start,
    );
    if (public_key_algorithm.identifier.tag != .sequence) {
        return error.InvalidCertificate;
    }
    const public_key_oid = try Certificate.der.Element.parse(
        bytes,
        public_key_algorithm.slice.start,
    );
    var extended_public_key = false;
    const public_key_category = Certificate.parseAlgorithmCategory(
        bytes,
        public_key_oid,
    ) catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => category: {
            _ = try x509_signature.parsePssPublicKeyAlgorithmIdentifier(
                bytes[public_key_algorithm.slice.start..public_key_algorithm.slice.end],
            );
            extended_public_key = true;
            break :category Certificate.AlgorithmCategory.rsassa_pss;
        },
        else => |parse_error| return parse_error,
    };
    const public_key_kind: Certificate.Parsed.PubKeyAlgo = switch (public_key_category) {
        inline else => |tag| @unionInit(
            Certificate.Parsed.PubKeyAlgo,
            @tagName(tag),
            {},
        ),
        .X9_62_id_ecPublicKey => curve: {
            const parameters = try Certificate.der.Element.parse(
                bytes,
                public_key_oid.slice.end,
            );
            if (parameters.slice.end != public_key_algorithm.slice.end) {
                return error.InvalidCertificate;
            }
            break :curve .{
                .X9_62_id_ecPublicKey = try Certificate.parseNamedCurve(
                    bytes,
                    parameters,
                ),
            };
        },
    };
    const public_key_element = try Certificate.der.Element.parse(
        bytes,
        public_key_algorithm.slice.end,
    );
    if (public_key_element.slice.end != public_key_info.slice.end) {
        return error.InvalidCertificate;
    }
    const public_key = try Certificate.parseBitString(
        certificate,
        public_key_element,
    );

    const outer_algorithm_start = tbs.slice.end;
    const outer_algorithm = try Certificate.der.Element.parse(
        bytes,
        outer_algorithm_start,
    );
    if (outer_algorithm.identifier.tag != .sequence or
        !std.mem.eql(
            u8,
            bytes[tbs_algorithm_start..tbs_algorithm.slice.end],
            bytes[outer_algorithm_start..outer_algorithm.slice.end],
        ))
    {
        return error.InvalidCertificate;
    }
    const algorithm = try x509_signature.parseAlgorithmIdentifier(
        bytes[outer_algorithm.slice.start..outer_algorithm.slice.end],
    );
    if (!extended_public_key) {
        switch (algorithm) {
            .rsa_pss_sha224,
            .rsa_pss_sha256,
            .rsa_pss_sha384,
            .rsa_pss_sha512,
            .rsa_pss_sha512_224,
            .rsa_pss_sha512_256,
            .rsa_pss_sha3_224,
            .rsa_pss_sha3_256,
            .rsa_pss_sha3_384,
            .rsa_pss_sha3_512,
            .rsa_pss_shake128,
            .rsa_pss_shake256,
            .rsa_pkcs1_sha3_224,
            .rsa_pkcs1_sha3_256,
            .rsa_pkcs1_sha3_384,
            .rsa_pkcs1_sha3_512,
            .rsa_pkcs1_sha512_224,
            .rsa_pkcs1_sha512_256,
            .ecdsa_sha3_224,
            .ecdsa_sha3_256,
            .ecdsa_sha3_384,
            .ecdsa_sha3_512,
            .ecdsa_shake128,
            .ecdsa_shake256,
            => {},
            else => return error.UnsupportedSignatureAlgorithm,
        }
    }
    const signature_element = try Certificate.der.Element.parse(
        bytes,
        outer_algorithm.slice.end,
    );
    if (signature_element.slice.end != outer.slice.end) {
        return error.InvalidCertificate;
    }
    const signature = try Certificate.parseBitString(
        certificate,
        signature_element,
    );

    var common_name = Certificate.Parsed.Slice.empty;
    var name_offset = subject.slice.start;
    while (name_offset < subject.slice.end) {
        const rdn = try Certificate.der.Element.parse(bytes, name_offset);
        if (rdn.identifier.tag != .sequence_of) return error.InvalidCertificate;
        var attribute_offset = rdn.slice.start;
        while (attribute_offset < rdn.slice.end) {
            const attribute = try Certificate.der.Element.parse(
                bytes,
                attribute_offset,
            );
            if (attribute.identifier.tag != .sequence) {
                return error.InvalidCertificate;
            }
            const attribute_oid = try Certificate.der.Element.parse(
                bytes,
                attribute.slice.start,
            );
            const attribute_value = try Certificate.der.Element.parse(
                bytes,
                attribute_oid.slice.end,
            );
            if (attribute_value.slice.end != attribute.slice.end) {
                return error.InvalidCertificate;
            }
            const kind = Certificate.parseAttribute(
                bytes,
                attribute_oid,
            ) catch |err| switch (err) {
                error.CertificateHasUnrecognizedObjectId => {
                    attribute_offset = attribute.slice.end;
                    continue;
                },
                else => |parse_error| return parse_error,
            };
            if (kind == .commonName) common_name = attribute_value.slice;
            attribute_offset = attribute.slice.end;
        }
        name_offset = rdn.slice.end;
    }

    var subject_alt_name = Certificate.Parsed.Slice.empty;
    var optional_offset = public_key_info.slice.end;
    var previous_optional_tag: u8 = 0x80;
    while (version != .v1 and optional_offset < tbs.slice.end) {
        const optional = try Certificate.der.Element.parse(bytes, optional_offset);
        const optional_tag: u8 = @bitCast(optional.identifier);
        if (optional_tag <= previous_optional_tag) {
            return error.InvalidCertificate;
        }
        previous_optional_tag = optional_tag;
        switch (optional_tag) {
            0x81, 0x82 => {
                const unique_id = bytes[optional.slice.start..optional.slice.end];
                if (unique_id.len == 0 or unique_id[0] > 7 or
                    (unique_id[0] != 0 and
                        (unique_id[unique_id.len - 1] &
                            ((@as(u8, 1) << @intCast(unique_id[0])) - 1)) != 0))
                {
                    return error.InvalidCertificate;
                }
                optional_offset = optional.slice.end;
                continue;
            },
            0xa3 => {
                if (version != .v3) return error.InvalidCertificate;
                const extensions = try Certificate.der.Element.parse(
                    bytes,
                    optional.slice.start,
                );
                if (extensions.identifier.tag != .sequence or
                    extensions.slice.end != optional.slice.end)
                {
                    return error.InvalidCertificate;
                }
                var extension_offset = extensions.slice.start;
                while (extension_offset < extensions.slice.end) {
                    const extension = try Certificate.der.Element.parse(
                        bytes,
                        extension_offset,
                    );
                    if (extension.identifier.tag != .sequence) {
                        return error.InvalidCertificate;
                    }
                    const oid = try Certificate.der.Element.parse(
                        bytes,
                        extension.slice.start,
                    );
                    var value = try Certificate.der.Element.parse(
                        bytes,
                        oid.slice.end,
                    );
                    if (value.identifier.tag == .boolean) {
                        value = try Certificate.der.Element.parse(
                            bytes,
                            value.slice.end,
                        );
                    }
                    if (value.identifier.tag != .octetstring or
                        value.slice.end != extension.slice.end)
                    {
                        return error.InvalidCertificate;
                    }
                    const extension_kind = Certificate.parseExtensionId(
                        bytes,
                        oid,
                    ) catch |err| switch (err) {
                        error.CertificateHasUnrecognizedObjectId => {
                            extension_offset = extension.slice.end;
                            continue;
                        },
                        else => |parse_error| return parse_error,
                    };
                    if (extension_kind == .subject_alt_name) {
                        subject_alt_name = value.slice;
                    }
                    extension_offset = extension.slice.end;
                }
                optional_offset = optional.slice.end;
            },
            else => return error.InvalidCertificate,
        }
    }
    if (optional_offset != tbs.slice.end) return error.InvalidCertificate;

    return .{
        .standard = .{
            .certificate = certificate,
            .issuer_slice = issuer.slice,
            .subject_slice = subject.slice,
            .common_name_slice = common_name,
            .signature_slice = signature,
            // Only the compatibility verifier reads the actual algorithm.
            .signature_algorithm = .sha256WithRSAEncryption,
            .pub_key_algo = public_key_kind,
            .pub_key_slice = public_key,
            .message_slice = .{
                .start = outer.slice.start,
                .end = tbs.slice.end,
            },
            .subject_alt_name_slice = subject_alt_name,
            .validity = .{
                .not_before = not_before_seconds,
                .not_after = not_after_seconds,
            },
            .version = version,
        },
        .signature_algorithm = algorithm,
    };
}

test "compatibility parser verifies SHA-512 truncated RSA certificates" {
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    inline for (.{
        .{
            vectors.pkcs1_sha512_224_certificate_hex,
            SignatureAlgorithm.rsa_pkcs1_sha512_224,
        },
        .{
            vectors.pss_sha512_256_certificate_hex,
            SignatureAlgorithm.rsa_pss_sha512_256,
        },
    }) |case| {
        var encoded: [case[0].len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&encoded, case[0]);
        const certificate = try parse(&encoded);
        try std.testing.expectEqual(
            case[1],
            certificate.signature_algorithm.?,
        );
        try certificate.verify(
            certificate,
            @intCast(certificate.standard.validity.not_before),
        );

        encoded[encoded.len - 1] ^= 1;
        const tampered = try parse(&encoded);
        try std.testing.expectError(
            error.CertificateSignatureInvalid,
            tampered.verify(
                tampered,
                @intCast(tampered.standard.validity.not_before),
            ),
        );
    }
}

test "compatibility parser verifies an RFC 8692 PSS-SHAKE certificate" {
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    var encoded: [vectors.pss_shake128_certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &encoded,
        vectors.pss_shake128_certificate_hex,
    );
    const certificate = try parse(&encoded);
    try std.testing.expectEqual(
        SignatureAlgorithm.rsa_pss_shake128,
        certificate.signature_algorithm.?,
    );
    try std.testing.expect(certificate.standard.pub_key_algo == .rsassa_pss);
    const constraints = try x509_signature.pssConstraintsForCertificate(
        certificate.standard,
    );
    try std.testing.expect(constraints.permits(.rsa_pss_shake128));
    try std.testing.expect(!constraints.permits(.rsa_pss_shake256));
    try certificate.verify(
        certificate,
        @intCast(certificate.standard.validity.not_before),
    );

    encoded[encoded.len - 1] ^= 1;
    const tampered = try parse(&encoded);
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        tampered.verify(
            tampered,
            @intCast(tampered.standard.validity.not_before),
        ),
    );
}
