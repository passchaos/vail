//! TLS 1.3 server Certificate and CertificateVerify helpers.
//!
//! The handshake codec is certificate-format agnostic. Built-in possession
//! verification supports Ed25519, ECDSA P-256/P-384/P-521, ML-DSA-44/65/87,
//! SM2, RSA-PSS, and the TLS 1.2 RSA PKCS#1 v1.5 schemes. An allocation-free signer
//! callback supports additional pure-Zig or hardware-backed private-key
//! implementations.
//! Applications can separately provide a trust callback for chain, validity,
//! EKU, and policy.

const std = @import("std");

const crypto_ed25519 = @import("../crypto/ed25519.zig");
const crypto_mldsa = @import("../crypto/mldsa.zig");
const p521 = @import("../crypto/p521.zig");
const p256 = @import("../crypto/p256.zig");
const p384 = @import("../crypto/p384.zig");
const rsa = @import("../crypto/rsa.zig");
const sm2 = @import("../crypto/sm2.zig");
const x509 = @import("../x509/mod.zig");
const x509_certificate = x509.certificate;
const x509_signature = x509.signature;
const x509_verifier = x509.verifier;
const Certificate = std.crypto.Certificate;
const Ed25519 = std.crypto.sign.Ed25519;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;
const MlDsa65 = std.crypto.sign.mldsa.MLDSA65;
const MlDsa87 = std.crypto.sign.mldsa.MLDSA87;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const EcdsaP256Sha384 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    std.crypto.hash.sha2.Sha384,
);
const EcdsaP256Sha512 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    std.crypto.hash.sha2.Sha512,
);
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const signature_scheme_ecdsa_secp256r1_sha256: u16 = 0x0403;
pub const signature_scheme_ecdsa_secp384r1_sha384: u16 = 0x0503;
pub const signature_scheme_ecdsa_secp521r1_sha512: u16 = 0x0603;
pub const signature_scheme_rsa_pkcs1_sha256: u16 = 0x0401;
pub const signature_scheme_rsa_pkcs1_sha384: u16 = 0x0501;
pub const signature_scheme_rsa_pkcs1_sha512: u16 = 0x0601;
pub const signature_scheme_rsa_pss_rsae_sha256: u16 = 0x0804;
pub const signature_scheme_rsa_pss_rsae_sha384: u16 = 0x0805;
pub const signature_scheme_rsa_pss_rsae_sha512: u16 = 0x0806;
pub const signature_scheme_ed25519: u16 = 0x0807;
pub const signature_scheme_rsa_pss_pss_sha256: u16 = 0x0809;
pub const signature_scheme_rsa_pss_pss_sha384: u16 = 0x080a;
pub const signature_scheme_rsa_pss_pss_sha512: u16 = 0x080b;
pub const signature_scheme_sm2sig_sm3: u16 = 0x0708;
pub const signature_scheme_ml_dsa_44: u16 = 0x0904;
pub const signature_scheme_ml_dsa_65: u16 = 0x0905;
pub const signature_scheme_ml_dsa_87: u16 = 0x0906;
pub const handshake_type_certificate: u8 = 0x0b;
pub const handshake_type_certificate_verify: u8 = 0x0f;

pub const CertificateType = enum(u8) {
    x509 = 0,
    raw_public_key = 2,
};
const server_certificate_verify_context =
    "TLS 1.3, server CertificateVerify";
const client_certificate_verify_context =
    "TLS 1.3, client CertificateVerify";

pub const EndpointRole = enum {
    server,
    client,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidCertificate,
    EmptyCertificateChain,
    CertificateTooLarge,
    UnsupportedCertificateKey,
    UnsupportedSignatureScheme,
    InvalidCertificateVerify,
    BadCertificateVerify,
    CertificateUntrusted,
};

pub const max_classical_signature_len: usize = 512;
pub const max_certificate_verify_signature_len: usize =
    MlDsa87.Signature.encoded_length;

pub const CertificateSignatureSchemes = struct {
    primary: u16,
    alternate: ?u16 = null,
    self_issued: bool,
};

/// Return the TLS SignatureScheme values that describe one certificate's
/// signature. RSA-PSS needs the issuer's SPKI category to distinguish the
/// rsae and pss codepoints; when the issuer is omitted (normally the final
/// intermediate), both encodings remain possible so trust-anchor choice does
/// not become part of server identity selection.
pub fn certificateSignatureSchemes(
    certificate_der: []const u8,
    issuer_der: ?[]const u8,
) Error!CertificateSignatureSchemes {
    const metadata = try certificateSignatureMetadata(certificate_der);
    const self_issued = metadata.self_issued;
    if (self_issued) return .{
        .primary = 0,
        .self_issued = true,
    };
    return switch (metadata.algorithm) {
        .ecdsa_sha224,
        .ecdsa_sha3_224,
        .ecdsa_sha3_256,
        .ecdsa_sha3_384,
        .ecdsa_sha3_512,
        .ecdsa_shake128,
        .ecdsa_shake256,
        => error.UnsupportedSignatureScheme,
        .rsa_pkcs1_sha1,
        .rsa_pss_sha224,
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
        .rsa_pkcs1_sha224,
        .rsa_pkcs1_sha512_224,
        .rsa_pkcs1_sha512_256,
        => error.UnsupportedSignatureScheme,
        .rsa_pss_sha256 => pssCertificateSchemes(
            signature_scheme_rsa_pss_rsae_sha256,
            signature_scheme_rsa_pss_pss_sha256,
            issuer_der,
        ),
        .rsa_pss_sha384 => pssCertificateSchemes(
            signature_scheme_rsa_pss_rsae_sha384,
            signature_scheme_rsa_pss_pss_sha384,
            issuer_der,
        ),
        .rsa_pss_sha512 => pssCertificateSchemes(
            signature_scheme_rsa_pss_rsae_sha512,
            signature_scheme_rsa_pss_pss_sha512,
            issuer_der,
        ),
        .ecdsa_p256_sha256 => exactCertificateScheme(
            signature_scheme_ecdsa_secp256r1_sha256,
            .p256,
            issuer_der,
        ),
        .ecdsa_p384_sha384 => exactCertificateScheme(
            signature_scheme_ecdsa_secp384r1_sha384,
            .p384,
            issuer_der,
        ),
        .ecdsa_sha512 => exactCertificateScheme(
            signature_scheme_ecdsa_secp521r1_sha512,
            .p521,
            issuer_der,
        ),
        .rsa_pkcs1_sha256 => exactCertificateScheme(
            signature_scheme_rsa_pkcs1_sha256,
            .rsa_encryption,
            issuer_der,
        ),
        .rsa_pkcs1_sha384 => exactCertificateScheme(
            signature_scheme_rsa_pkcs1_sha384,
            .rsa_encryption,
            issuer_der,
        ),
        .rsa_pkcs1_sha512 => exactCertificateScheme(
            signature_scheme_rsa_pkcs1_sha512,
            .rsa_encryption,
            issuer_der,
        ),
        .ed25519 => exactCertificateScheme(
            signature_scheme_ed25519,
            .ed25519,
            issuer_der,
        ),
    };
}

pub fn certificateChainSupportsSchemes(
    chain: []const []const u8,
    encoded_schemes: []const u8,
) Error!bool {
    if (encoded_schemes.len == 0 or encoded_schemes.len % 2 != 0) {
        return false;
    }
    for (chain, 0..) |certificate, index| {
        const issuer = if (index + 1 < chain.len)
            chain[index + 1]
        else
            null;
        const schemes = certificateSignatureSchemes(
            certificate,
            issuer,
        ) catch |err| switch (err) {
            error.UnsupportedSignatureScheme => return false,
            else => return err,
        };
        if (index + 1 == chain.len and schemes.self_issued) continue;
        if (encodedSchemeListContains(encoded_schemes, schemes.primary)) {
            continue;
        }
        if (schemes.alternate) |alternate| {
            if (encodedSchemeListContains(encoded_schemes, alternate)) {
                continue;
            }
        }
        return false;
    }
    return true;
}

pub fn certificateChainSupportsSchemeValues(
    chain: []const []const u8,
    supported_schemes: []const u16,
) Error!bool {
    if (supported_schemes.len == 0) return false;
    for (chain, 0..) |certificate, index| {
        const issuer = if (index + 1 < chain.len)
            chain[index + 1]
        else
            null;
        const schemes = certificateSignatureSchemes(
            certificate,
            issuer,
        ) catch |err| switch (err) {
            error.UnsupportedSignatureScheme => return false,
            else => return err,
        };
        if (index + 1 == chain.len and schemes.self_issued) continue;
        if (schemeListContains(supported_schemes, schemes.primary)) continue;
        if (schemes.alternate) |alternate| {
            if (schemeListContains(supported_schemes, alternate)) continue;
        }
        return false;
    }
    return true;
}

fn encodedSchemeListContains(encoded: []const u8, target: u16) bool {
    var pos: usize = 0;
    while (pos < encoded.len) : (pos += 2) {
        if (std.mem.readInt(u16, encoded[pos..][0..2], .big) == target) {
            return true;
        }
    }
    return false;
}

fn schemeListContains(schemes: []const u16, target: u16) bool {
    for (schemes) |scheme| {
        if (scheme == target) return true;
    }
    return false;
}

fn exactCertificateScheme(
    scheme: u16,
    expected_issuer_key: CertificatePublicKeyKind,
    issuer_der: ?[]const u8,
) Error!CertificateSignatureSchemes {
    if (issuer_der) |issuer| {
        if (try certificatePublicKeyKind(issuer) != expected_issuer_key) {
            return error.UnsupportedSignatureScheme;
        }
    }
    return .{ .primary = scheme, .self_issued = false };
}

fn pssCertificateSchemes(
    rsae_scheme: u16,
    pss_scheme: u16,
    issuer_der: ?[]const u8,
) Error!CertificateSignatureSchemes {
    const encoded_issuer = issuer_der orelse return .{
        .primary = rsae_scheme,
        .alternate = pss_scheme,
        .self_issued = false,
    };
    return switch (try certificatePublicKeyKind(encoded_issuer)) {
        .rsa_encryption => .{
            .primary = rsae_scheme,
            .self_issued = false,
        },
        .rsa_pss => .{
            .primary = pss_scheme,
            .self_issued = false,
        },
        else => error.UnsupportedSignatureScheme,
    };
}

const CertificateMetadata = struct {
    algorithm: x509_signature.Algorithm,
    self_issued: bool,
};

const CertificateLayout = struct {
    tbs_signature: DerElement,
    issuer: DerElement,
    subject: DerElement,
    subject_public_key_info: DerElement,
    outer_signature: DerElement,
};

const CertificatePublicKeyKind = enum {
    rsa_encryption,
    rsa_pss,
    p256,
    p384,
    p521,
    ed25519,
    other,
};

fn certificateSignatureMetadata(
    certificate_der: []const u8,
) Error!CertificateMetadata {
    const layout = try certificateLayout(certificate_der);
    if (!std.mem.eql(
        u8,
        certificate_der[layout.tbs_signature.content_start..layout.tbs_signature.end],
        certificate_der[layout.outer_signature.content_start..layout.outer_signature.end],
    )) return error.InvalidCertificate;
    const algorithm = x509_signature.parseAlgorithmIdentifier(
        certificate_der[layout.outer_signature.content_start..layout.outer_signature.end],
    ) catch |err| switch (err) {
        error.UnsupportedSignatureAlgorithm => return error.UnsupportedSignatureScheme,
        else => return error.InvalidCertificate,
    };
    return .{
        .algorithm = algorithm,
        .self_issued = std.mem.eql(
            u8,
            certificate_der[layout.issuer.content_start..layout.issuer.end],
            certificate_der[layout.subject.content_start..layout.subject.end],
        ),
    };
}

fn certificatePublicKeyKind(
    certificate_der: []const u8,
) Error!CertificatePublicKeyKind {
    const layout = try certificateLayout(certificate_der);
    var pos = layout.subject_public_key_info.content_start;
    const algorithm = try nextCertificateElement(
        certificate_der,
        &pos,
        layout.subject_public_key_info.end,
    );
    if (algorithm.tag != 0x30) return error.InvalidCertificate;
    var algorithm_pos = algorithm.content_start;
    const oid = try nextCertificateElement(
        certificate_der,
        &algorithm_pos,
        algorithm.end,
    );
    if (oid.tag != 0x06) return error.InvalidCertificate;
    const value = certificate_der[oid.content_start..oid.end];
    if (std.mem.eql(u8, value, &oid_rsa_encryption)) return .rsa_encryption;
    if (std.mem.eql(u8, value, &oid_rsassa_pss)) return .rsa_pss;
    if (std.mem.eql(u8, value, &oid_ed25519)) {
        return if (algorithm_pos == algorithm.end)
            .ed25519
        else
            error.InvalidCertificate;
    }
    if (std.mem.eql(u8, value, &oid_id_ec_public_key)) {
        const parameters = try nextCertificateElement(
            certificate_der,
            &algorithm_pos,
            algorithm.end,
        );
        if (parameters.tag != 0x06 or algorithm_pos != algorithm.end) {
            return error.InvalidCertificate;
        }
        const curve = certificate_der[parameters.content_start..parameters.end];
        if (std.mem.eql(u8, curve, &oid_p256)) return .p256;
        if (std.mem.eql(u8, curve, &oid_p384)) return .p384;
        if (std.mem.eql(u8, curve, &oid_p521)) return .p521;
    }
    return .other;
}

fn certificateLayout(certificate_der: []const u8) Error!CertificateLayout {
    const certificate = try DerElement.parse(certificate_der, 0);
    if (certificate.tag != 0x30 or certificate.end != certificate_der.len) {
        return error.InvalidCertificate;
    }
    var outer_pos = certificate.content_start;
    const tbs = try nextCertificateElement(
        certificate_der,
        &outer_pos,
        certificate.end,
    );
    if (tbs.tag != 0x30) return error.InvalidCertificate;
    const outer_signature = try nextCertificateElement(
        certificate_der,
        &outer_pos,
        certificate.end,
    );
    if (outer_signature.tag != 0x30) return error.InvalidCertificate;
    const signature = try nextCertificateElement(
        certificate_der,
        &outer_pos,
        certificate.end,
    );
    if (signature.tag != 0x03 or outer_pos != certificate.end) {
        return error.InvalidCertificate;
    }

    var tbs_pos = tbs.content_start;
    var serial = try nextCertificateElement(
        certificate_der,
        &tbs_pos,
        tbs.end,
    );
    if (serial.tag == 0xa0) {
        serial = try nextCertificateElement(
            certificate_der,
            &tbs_pos,
            tbs.end,
        );
    }
    if (serial.tag != 0x02) return error.InvalidCertificate;
    const tbs_signature = try nextCertificateElement(
        certificate_der,
        &tbs_pos,
        tbs.end,
    );
    const issuer = try nextCertificateElement(
        certificate_der,
        &tbs_pos,
        tbs.end,
    );
    const validity = try nextCertificateElement(
        certificate_der,
        &tbs_pos,
        tbs.end,
    );
    const subject = try nextCertificateElement(
        certificate_der,
        &tbs_pos,
        tbs.end,
    );
    const subject_public_key_info = try nextCertificateElement(
        certificate_der,
        &tbs_pos,
        tbs.end,
    );
    if (tbs_signature.tag != 0x30 or issuer.tag != 0x30 or
        validity.tag != 0x30 or subject.tag != 0x30 or
        subject_public_key_info.tag != 0x30)
    {
        return error.InvalidCertificate;
    }
    return .{
        .tbs_signature = tbs_signature,
        .issuer = issuer,
        .subject = subject,
        .subject_public_key_info = subject_public_key_info,
        .outer_signature = outer_signature,
    };
}

fn nextCertificateElement(
    bytes: []const u8,
    pos: *usize,
    limit: usize,
) Error!DerElement {
    if (pos.* >= limit) return error.InvalidCertificate;
    const element = try DerElement.parse(bytes, pos.*);
    if (element.end > limit) return error.InvalidCertificate;
    pos.* = element.end;
    return element;
}

pub fn MlDsaSigner(comptime MlDsa: type) type {
    return struct {
        key_pair: *const MlDsa.KeyPair,
        /// Fresh hedging randomness is recommended for each signature.
        noise: ?[MlDsa.noise_length]u8 = null,
    };
}

pub const MlDsa44Signer = MlDsaSigner(MlDsa44);
pub const MlDsa65Signer = MlDsaSigner(MlDsa65);
pub const MlDsa87Signer = MlDsaSigner(MlDsa87);

pub const ServerIdentity = struct {
    /// DER-encoded leaf-first certificate chain. Raw Ed25519 and uncompressed
    /// P-256 SEC1 public keys are accepted for compact pinned-key deployments.
    certificate_chain: []const []const u8,
    signer: Signer,
    certificate_type: CertificateType = .x509,

    pub fn validate(self: ServerIdentity) Error!void {
        if (self.certificate_chain.len == 0) {
            return error.EmptyCertificateChain;
        }
        if (self.certificate_type == .raw_public_key and
            (self.certificate_chain.len != 1 or
                (try parseRawSpki(self.certificate_chain[0])) == null))
        {
            return error.InvalidCertificate;
        }
        try self.signer.validateCertificate(self.certificate_chain[0]);
    }
};

pub const Signer = union(enum) {
    ed25519: struct {
        key_pair: Ed25519.KeyPair,
        /// Optional caller-retained expanded state for repeated signatures.
        prepared: ?*const crypto_ed25519.PreparedSigner = null,
        /// Must be fresh per signature when non-null.
        noise: ?[Ed25519.noise_length]u8 = null,
    },
    ecdsa_p256_sha256: struct {
        key_pair: EcdsaP256Sha256.KeyPair,
        /// Must be fresh per signature when non-null.
        noise: ?[EcdsaP256Sha256.noise_length]u8 = null,
    },
    ecdsa_p384_sha384: struct {
        key_pair: EcdsaP384Sha384.KeyPair,
        /// Must be fresh per signature when non-null.
        noise: ?[EcdsaP384Sha384.noise_length]u8 = null,
    },
    ecdsa_p521_sha512: struct {
        key_pair: *const p521.KeyPair,
        /// Used to obtain a fresh secret nonce for every signature.
        io: std.Io,
    },
    ecdsa_p521_sha512_prepared: struct {
        key_pair: *const p521.KeyPair,
        /// Consumed and wiped by the first signature attempt.
        nonce: *p521.PreparedNonce,
    },
    sm2sig_sm3: struct {
        key_pair: sm2.KeyPair,
        /// Must be fresh for each SM2 signature.
        nonce: [sm2.scalar_len]u8,
    },
    ml_dsa_44: MlDsa44Signer,
    ml_dsa_65: MlDsa65Signer,
    ml_dsa_87: MlDsa87Signer,
    rsa_pss: RsaPssSigner,
    rsa_pkcs1: RsaPkcs1Signer,
    /// Allocation-free extension point for pure-Zig software keys, hardware
    /// keys, or signature schemes whose private-key operation is not provided
    /// by Zig std. TLS framing and transcript construction remain inside Vail.
    custom: CustomSigner,

    pub fn scheme(self: Signer) u16 {
        return switch (self) {
            .ed25519 => signature_scheme_ed25519,
            .ecdsa_p256_sha256 => signature_scheme_ecdsa_secp256r1_sha256,
            .ecdsa_p384_sha384 => signature_scheme_ecdsa_secp384r1_sha384,
            .ecdsa_p521_sha512 => signature_scheme_ecdsa_secp521r1_sha512,
            .ecdsa_p521_sha512_prepared => signature_scheme_ecdsa_secp521r1_sha512,
            .sm2sig_sm3 => signature_scheme_sm2sig_sm3,
            .ml_dsa_44 => signature_scheme_ml_dsa_44,
            .ml_dsa_65 => signature_scheme_ml_dsa_65,
            .ml_dsa_87 => signature_scheme_ml_dsa_87,
            .rsa_pss => |rsa_signer| rsa_signer.signature_scheme,
            .rsa_pkcs1 => |rsa_signer| rsa_signer.signature_scheme,
            .custom => |custom| custom.signature_scheme,
        };
    }

    pub fn maxSignatureLen(self: Signer) usize {
        return switch (self) {
            .ed25519 => Ed25519.Signature.encoded_length,
            .ecdsa_p256_sha256 => EcdsaP256Sha256.Signature.der_encoded_length_max,
            .ecdsa_p384_sha384 => EcdsaP384Sha384.Signature.der_encoded_length_max,
            .ecdsa_p521_sha512 => p521.Signature.der_encoded_length_max,
            .ecdsa_p521_sha512_prepared => p521.Signature.der_encoded_length_max,
            .sm2sig_sm3 => sm2.Signature.der_encoded_length_max,
            .ml_dsa_44 => MlDsa44.Signature.encoded_length,
            .ml_dsa_65 => MlDsa65.Signature.encoded_length,
            .ml_dsa_87 => MlDsa87.Signature.encoded_length,
            .rsa_pss => |signer| signer.prepared_key.signatureLength(),
            .rsa_pkcs1 => |signer| signer.prepared_key.signatureLength(),
            .custom => |custom| custom.max_signature_len,
        };
    }

    fn validateCertificate(
        self: Signer,
        certificate: []const u8,
    ) Error!void {
        switch (self) {
            .ed25519 => |signer| {
                if (signer.prepared) |prepared| {
                    if (!prepared.matchesPublicKey(signer.key_pair.public_key)) {
                        return error.InvalidCertificate;
                    }
                }
                const leaf_key = try ed25519CertificatePublicKey(certificate);
                if (!std.mem.eql(
                    u8,
                    &leaf_key,
                    &signer.key_pair.public_key.toBytes(),
                )) return error.InvalidCertificate;
            },
            .ecdsa_p256_sha256 => |signer| {
                const leaf_key = try p256CertificatePublicKey(certificate);
                const signing_key =
                    signer.key_pair.public_key.toUncompressedSec1();
                if (!std.mem.eql(u8, &leaf_key, &signing_key)) {
                    return error.InvalidCertificate;
                }
            },
            .ecdsa_p384_sha384 => |signer| {
                const leaf_key = try p384CertificatePublicKey(certificate);
                const signing_key =
                    signer.key_pair.public_key.toUncompressedSec1();
                if (!std.mem.eql(u8, &leaf_key, &signing_key)) {
                    return error.InvalidCertificate;
                }
            },
            .ecdsa_p521_sha512 => |signer| {
                try validateP521Signer(signer.key_pair, certificate);
            },
            .ecdsa_p521_sha512_prepared => |signer| {
                try validateP521Signer(signer.key_pair, certificate);
            },
            .sm2sig_sm3 => |signer| {
                const leaf_key = try sm2CertificatePublicKey(certificate);
                const signing_key =
                    signer.key_pair.public_key.toUncompressedSec1();
                if (!std.mem.eql(u8, &leaf_key, &signing_key)) {
                    return error.InvalidCertificate;
                }
            },
            .ml_dsa_44 => |signer| try validateMlDsaCertificate(
                MlDsa44,
                .ml_dsa_44,
                signer.key_pair,
                certificate,
            ),
            .ml_dsa_65 => |signer| try validateMlDsaCertificate(
                MlDsa65,
                .ml_dsa_65,
                signer.key_pair,
                certificate,
            ),
            .ml_dsa_87 => |signer| try validateMlDsaCertificate(
                MlDsa87,
                .ml_dsa_87,
                signer.key_pair,
                certificate,
            ),
            .rsa_pss => |signer| {
                const expected_key_algorithm: Certificate.AlgorithmCategory =
                    switch (signer.signature_scheme) {
                        signature_scheme_rsa_pss_rsae_sha256,
                        signature_scheme_rsa_pss_rsae_sha384,
                        signature_scheme_rsa_pss_rsae_sha512,
                        => .rsaEncryption,
                        signature_scheme_rsa_pss_pss_sha256,
                        signature_scheme_rsa_pss_pss_sha384,
                        signature_scheme_rsa_pss_pss_sha512,
                        => .rsassa_pss,
                        else => return error.UnsupportedSignatureScheme,
                    };
                const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
                    certificate,
                    expected_key_algorithm,
                    if (expected_key_algorithm == .rsassa_pss)
                        try x509PssAlgorithmForScheme(signer.signature_scheme)
                    else
                        null,
                );
                const public_key = Certificate.rsa.PublicKey.parseDer(
                    public_key_der,
                ) catch return error.InvalidCertificate;
                if (!signer.prepared_key.matchesPublicKey(
                    public_key.modulus,
                    public_key.exponent,
                )) return error.InvalidCertificate;
            },
            .rsa_pkcs1 => |signer| {
                if (!isRsaPkcs1Scheme(signer.signature_scheme)) {
                    return error.UnsupportedSignatureScheme;
                }
                const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
                    certificate,
                    .rsaEncryption,
                    null,
                );
                const public_key = Certificate.rsa.PublicKey.parseDer(
                    public_key_der,
                ) catch return error.InvalidCertificate;
                if (!signer.prepared_key.matchesPublicKey(
                    public_key.modulus,
                    public_key.exponent,
                )) return error.InvalidCertificate;
            },
            .custom => |custom| {
                if (!isTls13CertificateVerifyScheme(
                    custom.signature_scheme,
                ) or custom.max_signature_len == 0 or
                    custom.max_signature_len >
                        max_certificate_verify_signature_len)
                {
                    return error.UnsupportedSignatureScheme;
                }
                custom.validate_certificate(
                    custom.context,
                    certificate,
                ) catch return error.InvalidCertificate;
            },
        }
    }

    /// Sign protocol-defined content into caller-provided storage.
    pub fn sign(
        self: Signer,
        content: []const u8,
        output: []u8,
    ) Error!usize {
        return switch (self) {
            .ed25519 => |ed| blk: {
                if (output.len < Ed25519.Signature.encoded_length) {
                    return error.InvalidCertificateVerify;
                }
                const signature = if (ed.prepared) |prepared|
                    if (ed.noise) |noise|
                        prepared.sign(content, noise) catch
                            return error.InvalidCertificateVerify
                    else
                        prepared.signDeterministic(content) catch
                            return error.InvalidCertificateVerify
                else
                    crypto_ed25519.sign(
                        ed.key_pair,
                        content,
                        ed.noise,
                    ) catch return error.InvalidCertificateVerify;
                const bytes = signature.toBytes();
                @memcpy(output[0..bytes.len], &bytes);
                break :blk bytes.len;
            },
            .ecdsa_p256_sha256 => |ecdsa| blk: {
                const signature = p256.sign(
                    Sha256,
                    ecdsa.key_pair,
                    content,
                    ecdsa.noise,
                ) catch return error.InvalidCertificateVerify;
                var der: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 =
                    undefined;
                const encoded = p256.signatureToDer(Sha256, signature, &der);
                if (output.len < encoded.len) {
                    return error.InvalidCertificateVerify;
                }
                @memcpy(output[0..encoded.len], encoded);
                break :blk encoded.len;
            },
            .ecdsa_p384_sha384 => |ecdsa| blk: {
                const signature = p384.sign(
                    Sha384,
                    ecdsa.key_pair,
                    content,
                    ecdsa.noise,
                ) catch return error.InvalidCertificateVerify;
                var der: [EcdsaP384Sha384.Signature.der_encoded_length_max]u8 =
                    undefined;
                const encoded = signature.toDer(&der);
                if (output.len < encoded.len) {
                    return error.InvalidCertificateVerify;
                }
                @memcpy(output[0..encoded.len], encoded);
                break :blk encoded.len;
            },
            .ecdsa_p521_sha512 => |ecdsa| blk: {
                if (output.len < p521.Signature.der_encoded_length_max) {
                    return error.InvalidCertificateVerify;
                }
                var nonce = ecdsa.key_pair.prepareRandomNonce(ecdsa.io) catch
                    return error.InvalidCertificateVerify;
                defer nonce.deinit();
                const signature = ecdsa.key_pair.signPrepared(
                    Sha512,
                    content,
                    &nonce,
                ) catch return error.InvalidCertificateVerify;
                var der: [p521.Signature.der_encoded_length_max]u8 = undefined;
                const encoded = signature.toDer(&der);
                @memcpy(output[0..encoded.len], encoded);
                break :blk encoded.len;
            },
            .ecdsa_p521_sha512_prepared => |ecdsa| blk: {
                if (output.len < p521.Signature.der_encoded_length_max) {
                    return error.InvalidCertificateVerify;
                }
                const signature = ecdsa.key_pair.signPrepared(
                    Sha512,
                    content,
                    ecdsa.nonce,
                ) catch return error.InvalidCertificateVerify;
                var der: [p521.Signature.der_encoded_length_max]u8 = undefined;
                const encoded = signature.toDer(&der);
                @memcpy(output[0..encoded.len], encoded);
                break :blk encoded.len;
            },
            .sm2sig_sm3 => |sm2_signer| blk: {
                const signature = sm2_signer.key_pair.sign(
                    sm2.default_user_id,
                    content,
                    sm2_signer.nonce,
                ) catch return error.InvalidCertificateVerify;
                var der: [sm2.Signature.der_encoded_length_max]u8 =
                    undefined;
                const encoded = signature.toDer(&der);
                if (output.len < encoded.len) {
                    return error.InvalidCertificateVerify;
                }
                @memcpy(output[0..encoded.len], encoded);
                break :blk encoded.len;
            },
            .ml_dsa_44 => |signer| signMlDsa(
                MlDsa44,
                signer,
                content,
                output,
            ),
            .ml_dsa_65 => |signer| signMlDsa(
                MlDsa65,
                signer,
                content,
                output,
            ),
            .ml_dsa_87 => |signer| signMlDsa(
                MlDsa87,
                signer,
                content,
                output,
            ),
            .rsa_pss => |rsa_signer| blk: {
                const hash_len = rsa_signer.hashLength();
                if (hash_len == 0 or output.len <
                    rsa_signer.prepared_key.signatureLength())
                {
                    return error.UnsupportedSignatureScheme;
                }
                var salt: [Sha512.digest_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &salt);
                rsa_signer.io.randomSecure(salt[0..hash_len]) catch
                    return error.InvalidCertificateVerify;
                break :blk switch (rsa_signer.signature_scheme) {
                    signature_scheme_rsa_pss_rsae_sha256,
                    signature_scheme_rsa_pss_pss_sha256,
                    => rsa_signer.prepared_key.signPssSha256(
                        content,
                        salt[0..hash_len],
                        output,
                    ),
                    signature_scheme_rsa_pss_rsae_sha384,
                    signature_scheme_rsa_pss_pss_sha384,
                    => rsa_signer.prepared_key.signPssSha384(
                        content,
                        salt[0..hash_len],
                        output,
                    ),
                    signature_scheme_rsa_pss_rsae_sha512,
                    signature_scheme_rsa_pss_pss_sha512,
                    => rsa_signer.prepared_key.signPssSha512(
                        content,
                        salt[0..hash_len],
                        output,
                    ),
                    else => error.UnsupportedSignatureScheme,
                } catch return error.InvalidCertificateVerify;
            },
            .rsa_pkcs1 => |rsa_signer| blk: {
                if (output.len < rsa_signer.prepared_key.signatureLength()) {
                    return error.InvalidCertificateVerify;
                }
                break :blk switch (rsa_signer.signature_scheme) {
                    signature_scheme_rsa_pkcs1_sha256 => rsa_signer.prepared_key.signPkcs1v15Sha256(
                        content,
                        output,
                    ),
                    signature_scheme_rsa_pkcs1_sha384 => rsa_signer.prepared_key.signPkcs1v15Sha384(
                        content,
                        output,
                    ),
                    signature_scheme_rsa_pkcs1_sha512 => rsa_signer.prepared_key.signPkcs1v15Sha512(
                        content,
                        output,
                    ),
                    else => error.UnsupportedSignatureScheme,
                } catch return error.InvalidCertificateVerify;
            },
            .custom => |custom| blk: {
                if (!isTls13CertificateVerifyScheme(
                    custom.signature_scheme,
                ) or custom.max_signature_len == 0 or
                    custom.max_signature_len > output.len)
                {
                    return error.UnsupportedSignatureScheme;
                }
                const signature_len = custom.sign(
                    custom.context,
                    content,
                    output[0..custom.max_signature_len],
                ) catch return error.InvalidCertificateVerify;
                if (signature_len == 0 or
                    signature_len > custom.max_signature_len)
                {
                    return error.InvalidCertificateVerify;
                }
                break :blk signature_len;
            },
        };
    }
};

fn signMlDsa(
    comptime MlDsa: type,
    signer: MlDsaSigner(MlDsa),
    content: []const u8,
    output: []u8,
) Error!usize {
    if (output.len < MlDsa.Signature.encoded_length) {
        return error.InvalidCertificateVerify;
    }
    if (comptime (MlDsa == MlDsa44 or MlDsa == MlDsa65 or MlDsa == MlDsa87) and
        crypto_mldsa.mldsa_accelerated)
    {
        const PreparedSigner = if (MlDsa == MlDsa44)
            crypto_mldsa.PreparedSigner44
        else if (MlDsa == MlDsa65)
            crypto_mldsa.PreparedSigner65
        else
            crypto_mldsa.PreparedSigner87;
        var prepared = PreparedSigner.init(
            &signer.key_pair.secret_key,
        );
        defer prepared.deinit();
        const encoded = prepared.sign(
            content,
            signer.noise orelse .{0} ** MlDsa.noise_length,
        );
        @memcpy(output[0..encoded.len], &encoded);
        return encoded.len;
    }
    var state = signer.key_pair.signer(signer.noise) catch
        return error.InvalidCertificateVerify;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&state.h));
    defer std.crypto.secureZero(u8, &state.rnd);
    state.update(content);
    const signature = state.finalize();
    const encoded = signature.toBytes();
    @memcpy(output[0..encoded.len], &encoded);
    return encoded.len;
}

pub const RsaPssSigner = struct {
    prepared_key: *const rsa.PreparedPrivateKey,
    signature_scheme: u16 = signature_scheme_rsa_pss_rsae_sha256,
    /// Used to obtain a fresh RFC 8017 salt for every signature.
    io: std.Io,

    pub fn hashLength(self: RsaPssSigner) usize {
        return switch (self.signature_scheme) {
            signature_scheme_rsa_pss_rsae_sha256,
            signature_scheme_rsa_pss_pss_sha256,
            => Sha256.digest_length,
            signature_scheme_rsa_pss_rsae_sha384,
            signature_scheme_rsa_pss_pss_sha384,
            => Sha384.digest_length,
            signature_scheme_rsa_pss_rsae_sha512,
            signature_scheme_rsa_pss_pss_sha512,
            => Sha512.digest_length,
            else => 0,
        };
    }
};

pub const RsaPkcs1Signer = struct {
    prepared_key: *const rsa.PreparedPrivateKey,
    signature_scheme: u16 = signature_scheme_rsa_pkcs1_sha256,
};

pub const CustomSigner = struct {
    context: ?*anyopaque,
    signature_scheme: u16,
    max_signature_len: usize,
    validate_certificate: *const fn (
        context: ?*anyopaque,
        certificate: []const u8,
    ) anyerror!void,
    sign: *const fn (
        context: ?*anyopaque,
        signed_content: []const u8,
        output: []u8,
    ) anyerror!usize,
};

pub const TrustContext = x509_verifier.TrustContext;
pub const TrustCallback = x509_verifier.TrustCallback;

/// Reusable RSA-2048/65537 public-key context for repeated TLS signature
/// checks. Certificate matching remains enforced on every use, while
/// Montgomery setup is paid only once with the trust configuration.
pub const PreparedRsaVerifier = struct {
    public_key: rsa.PreparedPublicKey,
    public_key_fingerprint: [Sha256.digest_length]u8,
    signature_scheme: u16,

    pub fn init(
        certificate: []const u8,
        signature_scheme: u16,
    ) Error!PreparedRsaVerifier {
        const expected_key_algorithm = rsaKeyAlgorithmForScheme(
            signature_scheme,
        ) orelse return error.UnsupportedSignatureScheme;
        const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
            certificate,
            expected_key_algorithm,
            if (isRsaPkcs1Scheme(signature_scheme))
                null
            else
                try x509PssAlgorithmForScheme(signature_scheme),
        );
        const components = Certificate.rsa.PublicKey.parseDer(
            public_key_der,
        ) catch return error.InvalidCertificate;
        var fingerprint: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(public_key_der, &fingerprint, .{});
        return .{
            .public_key = rsa.PreparedPublicKey.init(
                components.exponent,
                components.modulus,
            ) catch |err| switch (err) {
                error.InvalidPublicKey => return error.InvalidCertificate,
                else => return error.UnsupportedCertificateKey,
            },
            .public_key_fingerprint = fingerprint,
            .signature_scheme = signature_scheme,
        };
    }

    fn verify(
        self: *const PreparedRsaVerifier,
        certificate: []const u8,
        parsed: ParsedCertificateVerify,
        transcript_hash: []const u8,
        role: EndpointRole,
    ) Error!void {
        if (parsed.scheme != self.signature_scheme) {
            return error.UnsupportedSignatureScheme;
        }
        if (transcript_hash.len != Sha256.digest_length and
            transcript_hash.len != Sha384.digest_length and
            transcript_hash.len != Sha512.digest_length)
        {
            return error.InvalidCertificateVerify;
        }
        const expected_key_algorithm = rsaKeyAlgorithmForScheme(
            parsed.scheme,
        ) orelse return error.UnsupportedSignatureScheme;
        const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
            certificate,
            expected_key_algorithm,
            try x509PssAlgorithmForScheme(parsed.scheme),
        );
        var fingerprint: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(public_key_der, &fingerprint, .{});
        if (!std.crypto.timing_safe.eql(
            [Sha256.digest_length]u8,
            fingerprint,
            self.public_key_fingerprint,
        )) return error.InvalidCertificate;

        const separator = [_]u8{0};
        const message_parts = [_][]const u8{
            " " ** 64,
            certificateVerifyContext(role),
            &separator,
            transcript_hash,
        };
        const verification = switch (parsed.scheme) {
            signature_scheme_rsa_pss_rsae_sha256,
            signature_scheme_rsa_pss_pss_sha256,
            => self.public_key.verifyPssSha256(
                &message_parts,
                parsed.signature,
            ),
            signature_scheme_rsa_pss_rsae_sha384,
            signature_scheme_rsa_pss_pss_sha384,
            => self.public_key.verifyPssSha384(
                &message_parts,
                parsed.signature,
            ),
            signature_scheme_rsa_pss_rsae_sha512,
            signature_scheme_rsa_pss_pss_sha512,
            => self.public_key.verifyPssSha512(
                &message_parts,
                parsed.signature,
            ),
            else => return error.UnsupportedSignatureScheme,
        };
        verification catch |err| switch (err) {
            error.InvalidSignature => return error.BadCertificateVerify,
            else => return error.InvalidCertificate,
        };
    }

    fn verifyTls12(
        self: *const PreparedRsaVerifier,
        certificate: []const u8,
        parsed: ParsedCertificateVerify,
        content: []const u8,
    ) Error!void {
        if (parsed.scheme != self.signature_scheme) {
            return error.UnsupportedSignatureScheme;
        }
        const expected_key_algorithm = rsaKeyAlgorithmForScheme(
            parsed.scheme,
        ) orelse return error.UnsupportedSignatureScheme;
        const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
            certificate,
            expected_key_algorithm,
            if (isRsaPkcs1Scheme(parsed.scheme))
                null
            else
                try x509PssAlgorithmForScheme(parsed.scheme),
        );
        var fingerprint: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(public_key_der, &fingerprint, .{});
        if (!std.crypto.timing_safe.eql(
            [Sha256.digest_length]u8,
            fingerprint,
            self.public_key_fingerprint,
        )) return error.InvalidCertificate;

        const message_parts = [_][]const u8{content};
        const verification = switch (parsed.scheme) {
            signature_scheme_rsa_pkcs1_sha256 => self.public_key.verifyPkcs1v15Sha256(
                &message_parts,
                parsed.signature,
            ),
            signature_scheme_rsa_pkcs1_sha384 => self.public_key.verifyPkcs1v15Sha384(
                &message_parts,
                parsed.signature,
            ),
            signature_scheme_rsa_pkcs1_sha512 => self.public_key.verifyPkcs1v15Sha512(
                &message_parts,
                parsed.signature,
            ),
            signature_scheme_rsa_pss_rsae_sha256,
            signature_scheme_rsa_pss_pss_sha256,
            => self.public_key.verifyPssSha256(
                &message_parts,
                parsed.signature,
            ),
            signature_scheme_rsa_pss_rsae_sha384,
            signature_scheme_rsa_pss_pss_sha384,
            => self.public_key.verifyPssSha384(
                &message_parts,
                parsed.signature,
            ),
            signature_scheme_rsa_pss_rsae_sha512,
            signature_scheme_rsa_pss_pss_sha512,
            => self.public_key.verifyPssSha512(
                &message_parts,
                parsed.signature,
            ),
            else => return error.UnsupportedSignatureScheme,
        };
        verification catch |err| switch (err) {
            error.InvalidSignature => return error.BadCertificateVerify,
            else => return error.InvalidCertificate,
        };
    }
};

fn rsaKeyAlgorithmForScheme(
    signature_scheme: u16,
) ?Certificate.AlgorithmCategory {
    return switch (signature_scheme) {
        signature_scheme_rsa_pkcs1_sha256,
        signature_scheme_rsa_pkcs1_sha384,
        signature_scheme_rsa_pkcs1_sha512,
        signature_scheme_rsa_pss_rsae_sha256,
        signature_scheme_rsa_pss_rsae_sha384,
        signature_scheme_rsa_pss_rsae_sha512,
        => .rsaEncryption,
        signature_scheme_rsa_pss_pss_sha256,
        signature_scheme_rsa_pss_pss_sha384,
        signature_scheme_rsa_pss_pss_sha512,
        => .rsassa_pss,
        else => null,
    };
}

pub const ClientVerifier = struct {
    /// The callback owns X.509 chain/path/time/hostname/EKU policy. The codec
    /// always verifies CertificateVerify possession independently afterward.
    verify_trust: ?TrustCallback = null,
    context: ?*anyopaque = null,
    pinned_ed25519_public_key: ?[Ed25519.PublicKey.encoded_length]u8 = null,
    pinned_ecdsa_p256_public_key: ?[EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 = null,
    pinned_ecdsa_p384_public_key: ?[EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length]u8 = null,
    pinned_ecdsa_p521_public_key: ?[p521.uncompressed_sec1_encoded_length]u8 = null,
    pinned_sm2_public_key: ?[sm2.public_key_len]u8 = null,
    /// DER RSAPublicKey bytes from X.509 SubjectPublicKeyInfo's BIT STRING
    /// payload (not the complete SubjectPublicKeyInfo). The caller retains
    /// ownership.
    pinned_rsa_public_key: ?[]const u8 = null,
    /// Exact DER SubjectPublicKeyInfo pin used with RFC 7250.
    pinned_raw_public_key: ?[]const u8 = null,
    /// Optional reusable Ed25519 table. This accelerates CertificateVerify
    /// across connections while remaining independent from trust policy.
    prepared_ed25519_verifier: ?*const crypto_ed25519.PreparedVerifier = null,
    /// Optional reusable P-256 table for repeated CertificateVerify checks.
    prepared_p256_verifier: ?*const p256.PreparedVerifier = null,
    /// Optional reusable RSA-2048/65537 Montgomery context for TLS 1.3
    /// CertificateVerify or TLS 1.2 signed-handshake verification.
    prepared_rsa_verifier: ?*const PreparedRsaVerifier = null,

    /// Wrap the callback/context pair returned by an X.509 trust store.
    pub fn fromTrustVerifier(
        trust: x509_verifier.TrustVerifier,
    ) ClientVerifier {
        return .{
            .verify_trust = trust.verify_trust,
            .context = trust.context,
        };
    }

    pub fn verifyTrust(
        self: ClientVerifier,
        server_name: ?[]const u8,
        chain: []const []const u8,
    ) Error!void {
        return self.verifyTrustWithOcsp(server_name, chain, null);
    }

    pub fn verifyTrustWithOcsp(
        self: ClientVerifier,
        server_name: ?[]const u8,
        chain: []const []const u8,
        ocsp_response: ?[]const u8,
    ) Error!void {
        return self.verifyTrustContext(.{
            .server_name = server_name,
            .chain = chain,
            .ocsp_response = ocsp_response,
        });
    }

    pub fn verifyTrustWithOcspResponses(
        self: ClientVerifier,
        server_name: ?[]const u8,
        chain: []const []const u8,
        ocsp_responses: []const ?[]const u8,
    ) Error!void {
        if (ocsp_responses.len != chain.len) {
            return error.InvalidCertificate;
        }
        return self.verifyTrustContext(.{
            .server_name = server_name,
            .chain = chain,
            .ocsp_response = if (ocsp_responses.len == 0)
                null
            else
                ocsp_responses[0],
            .ocsp_responses = ocsp_responses,
        });
    }

    fn verifyTrustContext(
        self: ClientVerifier,
        trust: TrustContext,
    ) Error!void {
        const chain = trust.chain;
        if (chain.len == 0) return error.EmptyCertificateChain;
        if (self.verify_trust) |verify| {
            verify(self.context, trust) catch return error.CertificateUntrusted;
            return;
        }
        if (self.pinned_ed25519_public_key) |pinned| {
            const actual = try ed25519CertificatePublicKey(chain[0]);
            if (!std.crypto.timing_safe.eql(
                [Ed25519.PublicKey.encoded_length]u8,
                actual,
                pinned,
            )) {
                return error.CertificateUntrusted;
            }
            return;
        }
        if (self.pinned_ecdsa_p256_public_key) |pinned| {
            const actual = try p256CertificatePublicKey(chain[0]);
            if (!std.crypto.timing_safe.eql(
                [EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8,
                actual,
                pinned,
            )) {
                return error.CertificateUntrusted;
            }
            return;
        }
        if (self.pinned_ecdsa_p384_public_key) |pinned| {
            const actual = try p384CertificatePublicKey(chain[0]);
            if (!std.crypto.timing_safe.eql(
                [
                    EcdsaP384Sha384.PublicKey
                        .uncompressed_sec1_encoded_length
                ]u8,
                actual,
                pinned,
            )) {
                return error.CertificateUntrusted;
            }
            return;
        }
        if (self.pinned_ecdsa_p521_public_key) |pinned| {
            const actual = try p521CertificatePublicKey(chain[0]);
            if (!timingSafeEqlBytes(actual, &pinned)) {
                return error.CertificateUntrusted;
            }
            return;
        }
        if (self.pinned_sm2_public_key) |pinned| {
            const actual = try sm2CertificatePublicKey(chain[0]);
            if (!std.crypto.timing_safe.eql(
                [sm2.public_key_len]u8,
                actual,
                pinned,
            )) {
                return error.CertificateUntrusted;
            }
            return;
        }
        if (self.pinned_rsa_public_key) |pinned| {
            const actual = try rsaCertificatePublicKey(chain[0]);
            if (!timingSafeEqlBytes(actual, pinned)) {
                return error.CertificateUntrusted;
            }
            return;
        }
        return error.CertificateUntrusted;
    }

    pub fn verifyRawPublicKey(
        self: ClientVerifier,
        server_name: ?[]const u8,
        chain: []const []const u8,
    ) Error!void {
        if (chain.len != 1 or (try parseRawSpki(chain[0])) == null) {
            return error.InvalidCertificate;
        }
        if (self.pinned_raw_public_key) |pinned| {
            if (!timingSafeEqlBytes(chain[0], pinned)) {
                return error.CertificateUntrusted;
            }
            return;
        }
        return self.verifyTrustWithOcsp(server_name, chain, null);
    }

    pub fn verifyPeerCertificateVerify(
        self: ClientVerifier,
        certificate: []const u8,
        parsed: ParsedCertificateVerify,
        transcript_hash: []const u8,
        role: EndpointRole,
    ) Error!void {
        if (self.prepared_ed25519_verifier) |prepared| {
            if (parsed.scheme == signature_scheme_ed25519) {
                return verifyCertificateVerifyForRoleWithEd25519(
                    certificate,
                    parsed,
                    transcript_hash,
                    role,
                    prepared,
                );
            }
        }
        if (self.prepared_p256_verifier) |prepared| {
            if (parsed.scheme == signature_scheme_ecdsa_secp256r1_sha256) {
                return verifyCertificateVerifyForRoleWithP256(
                    certificate,
                    parsed,
                    transcript_hash,
                    role,
                    prepared,
                );
            }
        }
        if (self.prepared_rsa_verifier) |prepared| {
            if (parsed.scheme == prepared.signature_scheme) {
                return prepared.verify(
                    certificate,
                    parsed,
                    transcript_hash,
                    role,
                );
            }
        }
        return verifyCertificateVerifyForRole(
            certificate,
            parsed,
            transcript_hash,
            role,
        );
    }

    pub fn verifyTls12Signature(
        self: ClientVerifier,
        certificate: []const u8,
        parsed: ParsedCertificateVerify,
        content: []const u8,
    ) Error!void {
        if (self.prepared_rsa_verifier) |prepared| {
            if (parsed.scheme == prepared.signature_scheme) {
                return prepared.verifyTls12(
                    certificate,
                    parsed,
                    content,
                );
            }
        }
        return verifyTls12SignedContent(certificate, parsed, content);
    }
};

pub const ParsedCertificate = struct {
    entries: [][]const u8,
    /// TLS 1.3 CertificateEntry status_request responses aligned with entries.
    ocsp_responses: ?[]?[]const u8 = null,
    /// Backward-compatible view of `ocsp_responses[0]`.
    ocsp_response: ?[]const u8 = null,

    pub fn deinit(self: *ParsedCertificate, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        if (self.ocsp_responses) |responses| allocator.free(responses);
        self.* = undefined;
    }
};

pub const ParsedCertificateVerify = struct {
    scheme: u16,
    signature: []const u8,
};

pub fn writeCertificate(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
) Error!void {
    return writeCertificateWithContext(list, allocator, chain, &.{});
}

pub fn writeCertificateWithContext(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    request_context: []const u8,
) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    return writeCertificateEntriesWithContext(
        list,
        allocator,
        chain,
        request_context,
        null,
        null,
    );
}

pub fn writeCertificateWithOcsp(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    ocsp_response: []const u8,
) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    if (ocsp_response.len == 0 or
        ocsp_response.len > std.math.maxInt(u16) - 8)
    {
        return error.InvalidCertificate;
    }
    return writeCertificateEntriesWithContext(
        list,
        allocator,
        chain,
        &.{},
        ocsp_response,
        null,
    );
}

/// Encode RFC 8446 status_request extensions for arbitrary certificate-chain
/// entries. `ocsp_responses` is aligned with `chain`; null entries emit an
/// empty CertificateEntry extension vector.
pub fn writeCertificateWithOcspResponses(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    ocsp_responses: []const ?[]const u8,
) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    if (ocsp_responses.len != chain.len) {
        return error.InvalidCertificate;
    }
    return writeCertificateEntriesWithContext(
        list,
        allocator,
        chain,
        &.{},
        null,
        ocsp_responses,
    );
}

/// Encode a TLS 1.3 client Certificate response.
///
/// Unlike a server Certificate, a client response may carry an empty chain
/// when the server requested but did not require authentication.
pub fn writeClientCertificateWithContext(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    request_context: []const u8,
) Error!void {
    return writeCertificateEntriesWithContext(
        list,
        allocator,
        chain,
        request_context,
        null,
        null,
    );
}

/// Encode a TLS 1.3 client Certificate response with a leaf OCSP staple.
pub fn writeClientCertificateWithContextAndOcsp(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    request_context: []const u8,
    ocsp_response: []const u8,
) Error!void {
    if (chain.len == 0 or ocsp_response.len == 0 or
        ocsp_response.len > std.math.maxInt(u16) - 8)
    {
        return error.InvalidCertificate;
    }
    return writeCertificateEntriesWithContext(
        list,
        allocator,
        chain,
        request_context,
        ocsp_response,
        null,
    );
}

/// Encode TLS 1.3 client CertificateEntry OCSP staples while preserving the
/// CertificateRequest context. Responses are aligned with `chain`.
pub fn writeClientCertificateWithContextAndOcspResponses(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    request_context: []const u8,
    ocsp_responses: []const ?[]const u8,
) Error!void {
    if (chain.len == 0 or ocsp_responses.len != chain.len) {
        return error.InvalidCertificate;
    }
    return writeCertificateEntriesWithContext(
        list,
        allocator,
        chain,
        request_context,
        null,
        ocsp_responses,
    );
}

fn writeCertificateEntriesWithContext(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    request_context: []const u8,
    leaf_ocsp_response: ?[]const u8,
    entry_ocsp_responses: ?[]const ?[]const u8,
) Error!void {
    if (request_context.len > std.math.maxInt(u8)) {
        return error.InvalidCertificate;
    }
    std.debug.assert(leaf_ocsp_response == null or
        entry_ocsp_responses == null);
    std.debug.assert(entry_ocsp_responses == null or
        entry_ocsp_responses.?.len == chain.len);
    const original_len = list.items.len;
    errdefer list.items.len = original_len;

    var entries: std.ArrayList(u8) = .empty;
    defer entries.deinit(allocator);
    for (chain, 0..) |cert, index| {
        if (cert.len == 0 or cert.len > std.math.maxInt(u24)) {
            return error.CertificateTooLarge;
        }
        var cert_len: [3]u8 = undefined;
        writeU24(&cert_len, @intCast(cert.len));
        try entries.appendSlice(allocator, &cert_len);
        try entries.appendSlice(allocator, cert);
        const response = if (entry_ocsp_responses) |responses|
            responses[index]
        else if (index == 0)
            leaf_ocsp_response
        else
            null;
        if (response) |staple| {
            if (staple.len == 0 or
                staple.len > std.math.maxInt(u16) - 8)
            {
                return error.InvalidCertificate;
            }
            try appendInt(
                &entries,
                allocator,
                u16,
                2 + 2 + 1 + 3 + staple.len,
            );
            try appendInt(&entries, allocator, u16, 0x0005);
            try appendInt(
                &entries,
                allocator,
                u16,
                1 + 3 + staple.len,
            );
            try entries.append(allocator, 1);
            var response_len: [3]u8 = undefined;
            writeU24(&response_len, @intCast(staple.len));
            try entries.appendSlice(allocator, &response_len);
            try entries.appendSlice(allocator, staple);
        } else {
            try entries.appendSlice(allocator, &.{ 0, 0 });
        }
    }
    if (entries.items.len > std.math.maxInt(u24)) {
        return error.CertificateTooLarge;
    }

    const body_len = 1 + request_context.len + 3 + entries.items.len;
    if (body_len > std.math.maxInt(u24)) return error.CertificateTooLarge;
    try list.append(allocator, handshake_type_certificate);
    var body_len_bytes: [3]u8 = undefined;
    writeU24(&body_len_bytes, @intCast(body_len));
    try list.appendSlice(allocator, &body_len_bytes);
    try list.append(allocator, @intCast(request_context.len));
    try list.appendSlice(allocator, request_context);
    var entries_len: [3]u8 = undefined;
    writeU24(&entries_len, @intCast(entries.items.len));
    try list.appendSlice(allocator, &entries_len);
    try list.appendSlice(allocator, entries.items);
}

pub fn parseCertificate(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!ParsedCertificate {
    return parseCertificateWithContext(allocator, bytes, &.{});
}

pub fn parseCertificateWithContext(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_context: []const u8,
) Error!ParsedCertificate {
    return parseCertificateEntriesWithContext(
        allocator,
        bytes,
        expected_context,
        false,
    );
}

/// Parse a client Certificate response, including the RFC 8446 empty-list
/// representation used when client authentication is optional.
pub fn parseClientCertificateWithContext(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_context: []const u8,
) Error!ParsedCertificate {
    return parseCertificateEntriesWithContext(
        allocator,
        bytes,
        expected_context,
        true,
    );
}

fn parseCertificateEntriesWithContext(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_context: []const u8,
    allow_empty: bool,
) Error!ParsedCertificate {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_certificate) {
        return error.InvalidCertificate;
    }
    const body_len = try readU24At(bytes, &pos);
    if (body_len != bytes.len - pos) return error.InvalidCertificate;
    const context_len = try readByte(bytes, &pos);
    const context = try readSlice(bytes, &pos, context_len);
    if (!std.mem.eql(u8, context, expected_context)) {
        return error.InvalidCertificate;
    }
    const entries_len = try readU24At(bytes, &pos);
    const entries_end = std.math.add(usize, pos, entries_len) catch
        return error.InvalidCertificate;
    if (entries_end != bytes.len) return error.InvalidCertificate;

    var entries: std.ArrayList([]const u8) = .empty;
    errdefer entries.deinit(allocator);
    var ocsp_responses: std.ArrayList(?[]const u8) = .empty;
    errdefer ocsp_responses.deinit(allocator);
    while (pos < entries_end) {
        const cert_len = try readU24At(bytes, &pos);
        if (cert_len == 0) return error.InvalidCertificate;
        const cert = try readSlice(bytes, &pos, cert_len);
        const extensions_len = try readInt(u16, bytes, &pos);
        const extensions = try readSlice(bytes, &pos, extensions_len);
        const ocsp_response = try parseCertificateEntryExtensions(extensions);
        try entries.append(allocator, cert);
        errdefer _ = entries.pop();
        try ocsp_responses.append(allocator, ocsp_response);
    }
    if (!allow_empty and entries.items.len == 0) {
        return error.EmptyCertificateChain;
    }
    const owned_entries = try entries.toOwnedSlice(allocator);
    errdefer allocator.free(owned_entries);
    const owned_ocsp_responses = try ocsp_responses.toOwnedSlice(allocator);
    return .{
        .entries = owned_entries,
        .ocsp_responses = owned_ocsp_responses,
        .ocsp_response = if (owned_ocsp_responses.len == 0)
            null
        else
            owned_ocsp_responses[0],
    };
}

fn parseCertificateEntryExtensions(
    extensions: []const u8,
) Error!?[]const u8 {
    var pos: usize = 0;
    var ocsp_response: ?[]const u8 = null;
    while (pos < extensions.len) {
        const extension_type = try readInt(u16, extensions, &pos);
        const extension_len = try readInt(u16, extensions, &pos);
        const payload = try readSlice(extensions, &pos, extension_len);
        if (extension_type != 0x0005) continue;
        if (ocsp_response != null or payload.len < 4 or payload[0] != 1) {
            return error.InvalidCertificate;
        }
        var payload_pos: usize = 1;
        const response_len = try readU24At(payload, &payload_pos);
        const response = try readSlice(payload, &payload_pos, response_len);
        if (response.len == 0 or payload_pos != payload.len) {
            return error.InvalidCertificate;
        }
        ocsp_response = response;
    }
    return ocsp_response;
}

pub fn writeCertificateVerify(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    signer: Signer,
    transcript_hash: []const u8,
) Error!void {
    return writeCertificateVerifyForRole(
        list,
        allocator,
        signer,
        transcript_hash,
        .server,
    );
}

pub fn writeCertificateVerifyForRole(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    signer: Signer,
    transcript_hash: []const u8,
    role: EndpointRole,
) Error!void {
    if (!isTls13CertificateVerifyScheme(signer.scheme())) {
        return error.UnsupportedSignatureScheme;
    }
    if (transcript_hash.len != Sha256.digest_length and
        transcript_hash.len != Sha384.digest_length and
        transcript_hash.len != Sha512.digest_length)
    {
        return error.InvalidCertificateVerify;
    }
    const context = certificateVerifyContext(role);
    var signed_content: [
        64 + client_certificate_verify_context.len + 1 +
            Sha512.digest_length
    ]u8 = undefined;
    @memset(signed_content[0..64], 0x20);
    @memcpy(signed_content[64 .. 64 + context.len], context);
    const separator = 64 + context.len;
    signed_content[separator] = 0;
    @memcpy(
        signed_content[separator + 1 ..][0..transcript_hash.len],
        transcript_hash,
    );
    const content = signed_content[0 .. separator + 1 +
        transcript_hash.len];
    const signature_capacity = signer.maxSignatureLen();
    if (signature_capacity == 0 or
        signature_capacity > max_certificate_verify_signature_len)
    {
        return error.UnsupportedSignatureScheme;
    }
    var stack_signature: [max_classical_signature_len]u8 = undefined;
    const heap_signature = if (signature_capacity > stack_signature.len)
        try allocator.alloc(u8, signature_capacity)
    else
        null;
    defer if (heap_signature) |bytes| allocator.free(bytes);
    const signature_storage = heap_signature orelse
        stack_signature[0..signature_capacity];
    const signature_len = try signer.sign(content, signature_storage);
    const signature_bytes = signature_storage[0..signature_len];

    const body_len = 2 + 2 + signature_bytes.len;
    try list.append(allocator, handshake_type_certificate_verify);
    var body_len_bytes: [3]u8 = undefined;
    writeU24(&body_len_bytes, @intCast(body_len));
    try list.appendSlice(allocator, &body_len_bytes);
    try appendInt(list, allocator, u16, signer.scheme());
    try appendInt(list, allocator, u16, signature_bytes.len);
    try list.appendSlice(allocator, signature_bytes);
}

fn isTls13CertificateVerifyScheme(scheme: u16) bool {
    return scheme == signature_scheme_ed25519 or
        scheme == signature_scheme_ecdsa_secp256r1_sha256 or
        scheme == signature_scheme_ecdsa_secp384r1_sha384 or
        scheme == signature_scheme_ecdsa_secp521r1_sha512 or
        scheme == signature_scheme_rsa_pss_rsae_sha256 or
        scheme == signature_scheme_rsa_pss_rsae_sha384 or
        scheme == signature_scheme_rsa_pss_rsae_sha512 or
        scheme == signature_scheme_rsa_pss_pss_sha256 or
        scheme == signature_scheme_rsa_pss_pss_sha384 or
        scheme == signature_scheme_rsa_pss_pss_sha512 or
        scheme == signature_scheme_sm2sig_sm3 or
        scheme == signature_scheme_ml_dsa_44 or
        scheme == signature_scheme_ml_dsa_65 or
        scheme == signature_scheme_ml_dsa_87;
}

fn isRsaPkcs1Scheme(scheme: u16) bool {
    return scheme == signature_scheme_rsa_pkcs1_sha256 or
        scheme == signature_scheme_rsa_pkcs1_sha384 or
        scheme == signature_scheme_rsa_pkcs1_sha512;
}

fn isMlDsaScheme(scheme: u16) bool {
    return scheme == signature_scheme_ml_dsa_44 or
        scheme == signature_scheme_ml_dsa_65 or
        scheme == signature_scheme_ml_dsa_87;
}

pub fn parseCertificateVerify(
    bytes: []const u8,
) Error!ParsedCertificateVerify {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_certificate_verify) {
        return error.InvalidCertificateVerify;
    }
    const body_len = try readU24At(bytes, &pos);
    if (body_len != bytes.len - pos) return error.InvalidCertificateVerify;
    const scheme = try readInt(u16, bytes, &pos);
    if (scheme != signature_scheme_ed25519 and
        scheme != signature_scheme_ecdsa_secp256r1_sha256 and
        scheme != signature_scheme_ecdsa_secp384r1_sha384 and
        scheme != signature_scheme_ecdsa_secp521r1_sha512 and
        scheme != signature_scheme_rsa_pkcs1_sha256 and
        scheme != signature_scheme_rsa_pkcs1_sha384 and
        scheme != signature_scheme_rsa_pkcs1_sha512 and
        scheme != signature_scheme_rsa_pss_rsae_sha256 and
        scheme != signature_scheme_rsa_pss_rsae_sha384 and
        scheme != signature_scheme_rsa_pss_rsae_sha512 and
        scheme != signature_scheme_rsa_pss_pss_sha256 and
        scheme != signature_scheme_rsa_pss_pss_sha384 and
        scheme != signature_scheme_rsa_pss_pss_sha512 and
        scheme != signature_scheme_sm2sig_sm3 and
        scheme != signature_scheme_ml_dsa_44 and
        scheme != signature_scheme_ml_dsa_65 and
        scheme != signature_scheme_ml_dsa_87)
    {
        return error.UnsupportedSignatureScheme;
    }
    const signature_len = try readInt(u16, bytes, &pos);
    const fixed_signature_len: ?usize = switch (scheme) {
        signature_scheme_ed25519 => Ed25519.Signature.encoded_length,
        signature_scheme_ml_dsa_44 => MlDsa44.Signature.encoded_length,
        signature_scheme_ml_dsa_65 => MlDsa65.Signature.encoded_length,
        signature_scheme_ml_dsa_87 => MlDsa87.Signature.encoded_length,
        else => null,
    };
    if ((fixed_signature_len != null and
        signature_len != fixed_signature_len.?) or
        signature_len == 0)
    {
        return error.InvalidCertificateVerify;
    }
    const signature = try readSlice(bytes, &pos, signature_len);
    if (pos != bytes.len) return error.InvalidCertificateVerify;
    return .{ .scheme = scheme, .signature = signature };
}

/// Verify a TLS signature over protocol-defined bytes without applying the
/// TLS 1.3 CertificateVerify context prefix. TLS 1.2 ServerKeyExchange uses
/// this form for `client_random || server_random || ServerECDHParams`.
pub fn verifySignedContent(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    content: []const u8,
) Error!void {
    switch (parsed.scheme) {
        signature_scheme_ed25519 => {
            if (parsed.signature.len != Ed25519.Signature.encoded_length) {
                return error.InvalidCertificateVerify;
            }
            const public_key_bytes =
                try ed25519CertificatePublicKey(certificate);
            const public_key = Ed25519.PublicKey.fromBytes(
                public_key_bytes,
            ) catch return error.InvalidCertificate;
            const signature = Ed25519.Signature.fromBytes(
                parsed.signature[0..Ed25519.Signature.encoded_length].*,
            );
            crypto_ed25519.verify(signature, content, public_key) catch
                return error.BadCertificateVerify;
        },
        signature_scheme_ecdsa_secp256r1_sha256 => {
            const public_key_bytes =
                try p256CertificatePublicKey(certificate);
            try verifyP256Content(
                Sha256,
                &public_key_bytes,
                parsed.signature,
                content,
            );
        },
        signature_scheme_ecdsa_secp384r1_sha384 => {
            const public_key_bytes =
                try p384CertificatePublicKey(certificate);
            try verifyP384Content(
                Sha384,
                &public_key_bytes,
                parsed.signature,
                content,
            );
        },
        signature_scheme_ecdsa_secp521r1_sha512 => p521.verify(
            Sha512,
            content,
            parsed.signature,
            try p521CertificatePublicKey(certificate),
        ) catch |err| switch (err) {
            error.InvalidPublicKey => return error.InvalidCertificate,
            error.InvalidSignature => return error.BadCertificateVerify,
        },
        signature_scheme_ml_dsa_44 => try verifyMlDsaContent(
            MlDsa44,
            .ml_dsa_44,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_ml_dsa_65 => try verifyMlDsaContent(
            MlDsa65,
            .ml_dsa_65,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_ml_dsa_87 => try verifyMlDsaContent(
            MlDsa87,
            .ml_dsa_87,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_rsae_sha256 => try verifyRsaPssContent(
            Sha256,
            .rsaEncryption,
            .rsa_pss_sha256,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_rsae_sha384 => try verifyRsaPssContent(
            Sha384,
            .rsaEncryption,
            .rsa_pss_sha384,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_rsae_sha512 => try verifyRsaPssContent(
            Sha512,
            .rsaEncryption,
            .rsa_pss_sha512,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_pss_sha256 => try verifyRsaPssContent(
            Sha256,
            .rsassa_pss,
            .rsa_pss_sha256,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_pss_sha384 => try verifyRsaPssContent(
            Sha384,
            .rsassa_pss,
            .rsa_pss_sha384,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_pss_sha512 => try verifyRsaPssContent(
            Sha512,
            .rsassa_pss,
            .rsa_pss_sha512,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_sm2sig_sm3 => {
            const public_key = sm2.PublicKey.fromUncompressedSec1(
                &try sm2CertificatePublicKey(certificate),
            ) catch return error.InvalidCertificate;
            const signature = sm2.Signature.fromDer(parsed.signature) catch
                return error.InvalidCertificateVerify;
            sm2.verify(
                sm2.default_user_id,
                public_key,
                content,
                signature,
            ) catch return error.BadCertificateVerify;
        },
        else => return error.UnsupportedSignatureScheme,
    }
}

fn verifyP521CertificateVerify(
    certificate: []const u8,
    signature: []const u8,
    transcript_hash: []const u8,
    role: EndpointRole,
) Error!void {
    const context = certificateVerifyContext(role);
    var signed_content: [
        64 + client_certificate_verify_context.len + 1 +
            Sha512.digest_length
    ]u8 = undefined;
    @memset(signed_content[0..64], 0x20);
    @memcpy(signed_content[64 .. 64 + context.len], context);
    const separator = 64 + context.len;
    signed_content[separator] = 0;
    @memcpy(
        signed_content[separator + 1 ..][0..transcript_hash.len],
        transcript_hash,
    );
    p521.verify(
        Sha512,
        signed_content[0 .. separator + 1 + transcript_hash.len],
        signature,
        try p521CertificatePublicKey(certificate),
    ) catch |err| switch (err) {
        error.InvalidPublicKey => return error.InvalidCertificate,
        error.InvalidSignature => return error.BadCertificateVerify,
    };
}

/// TLS 1.2 ECDSA SignatureScheme values bind only the hash and signature
/// algorithm; unlike TLS 1.3, they do not constrain the certificate curve.
/// RSA-PSS, RSA PKCS#1 v1.5, and Ed25519 retain their ordinary scheme
/// semantics. PKCS#1 v1.5 is deliberately accepted only by this TLS 1.2 path.
pub fn verifyTls12SignedContent(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    content: []const u8,
) Error!void {
    if (isMlDsaScheme(parsed.scheme)) {
        return error.UnsupportedSignatureScheme;
    }
    switch (parsed.scheme) {
        signature_scheme_rsa_pkcs1_sha256 => try verifyRsaPkcs1Content(
            Sha256,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pkcs1_sha384 => try verifyRsaPkcs1Content(
            Sha384,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pkcs1_sha512 => try verifyRsaPkcs1Content(
            Sha512,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_ecdsa_secp256r1_sha256 => {
            const curve = try certificateCurve(certificate);
            switch (curve) {
                .p256 => try verifyP256Content(
                    Sha256,
                    &try p256CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p384 => try verifyP384Content(
                    Sha256,
                    &try p384CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p521 => p521.verify(
                    Sha256,
                    content,
                    parsed.signature,
                    try p521CertificatePublicKey(certificate),
                ) catch |err| switch (err) {
                    error.InvalidPublicKey => return error.InvalidCertificate,
                    error.InvalidSignature => return error.BadCertificateVerify,
                },
            }
        },
        signature_scheme_ecdsa_secp384r1_sha384 => {
            const curve = try certificateCurve(certificate);
            switch (curve) {
                .p256 => try verifyP256Content(
                    Sha384,
                    &try p256CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p384 => try verifyP384Content(
                    Sha384,
                    &try p384CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p521 => p521.verify(
                    Sha384,
                    content,
                    parsed.signature,
                    try p521CertificatePublicKey(certificate),
                ) catch |err| switch (err) {
                    error.InvalidPublicKey => return error.InvalidCertificate,
                    error.InvalidSignature => return error.BadCertificateVerify,
                },
            }
        },
        signature_scheme_ecdsa_secp521r1_sha512 => {
            const curve = try certificateCurve(certificate);
            switch (curve) {
                .p256 => try verifyP256Content(
                    Sha512,
                    &try p256CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p384 => try verifyP384Content(
                    Sha512,
                    &try p384CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p521 => p521.verify(
                    Sha512,
                    content,
                    parsed.signature,
                    try p521CertificatePublicKey(certificate),
                ) catch |err| switch (err) {
                    error.InvalidPublicKey => return error.InvalidCertificate,
                    error.InvalidSignature => return error.BadCertificateVerify,
                },
            }
        },
        else => try verifySignedContent(certificate, parsed, content),
    }
}

fn verifyRsaPkcs1Content(
    comptime Hash: type,
    certificate: []const u8,
    signature_bytes: []const u8,
    content: []const u8,
) Error!void {
    const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
        certificate,
        .rsaEncryption,
        null,
    );
    const components = Certificate.rsa.PublicKey.parseDer(
        public_key_der,
    ) catch return error.InvalidCertificate;
    switch (components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (signature_bytes.len != modulus_len) {
                return error.InvalidCertificateVerify;
            }
            const public_key = Certificate.rsa.PublicKey.fromBytes(
                components.exponent,
                components.modulus,
            ) catch return error.InvalidCertificate;
            const signature = Certificate.rsa.PKCS1v1_5Signature.fromBytes(
                modulus_len,
                signature_bytes,
            );
            Certificate.rsa.PKCS1v1_5Signature.verify(
                modulus_len,
                signature,
                content,
                public_key,
                Hash,
            ) catch return error.BadCertificateVerify;
        },
        else => return error.UnsupportedCertificateKey,
    }
}

const CertificateCurve = enum { p256, p384, p521 };

fn certificateCurve(certificate: []const u8) Error!CertificateCurve {
    if (certificate.len ==
        EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length)
    {
        _ = EcdsaP256Sha256.PublicKey.fromSec1(certificate) catch
            return error.InvalidCertificate;
        return .p256;
    }
    if (certificate.len ==
        EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length)
    {
        _ = EcdsaP384Sha384.PublicKey.fromSec1(certificate) catch
            return error.InvalidCertificate;
        return .p384;
    }
    if (certificate.len == p521.uncompressed_sec1_encoded_length or
        certificate.len == p521.compressed_sec1_encoded_length)
    {
        p521.validatePublicKey(certificate) catch
            return error.InvalidCertificate;
        return .p521;
    }
    if (try parseRawSpki(certificate)) |spki| {
        return switch (spki.kind) {
            .p256 => .p256,
            .p384 => .p384,
            .p521 => .p521,
            else => error.UnsupportedCertificateKey,
        };
    }
    const parsed_certificate = try parseX509(certificate);
    if (parsed_certificate.pub_key_algo != .X9_62_id_ecPublicKey) {
        return error.UnsupportedCertificateKey;
    }
    return switch (parsed_certificate.pub_key_algo.X9_62_id_ecPublicKey) {
        .X9_62_prime256v1 => .p256,
        .secp384r1 => .p384,
        .secp521r1 => .p521,
    };
}

fn verifyP256Content(
    comptime Hash: type,
    public_key_bytes: []const u8,
    signature_bytes: []const u8,
    content: []const u8,
) Error!void {
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(
        std.crypto.ecc.P256,
        Hash,
    );
    const public_key = Ecdsa.PublicKey.fromSec1(public_key_bytes) catch
        return error.InvalidCertificate;
    const signature = Ecdsa.Signature.fromDer(signature_bytes) catch
        return error.InvalidCertificateVerify;
    p256.verify(Hash, content, signature, public_key) catch
        return error.BadCertificateVerify;
}

fn verifyP384Content(
    comptime Hash: type,
    public_key_bytes: []const u8,
    signature_bytes: []const u8,
    content: []const u8,
) Error!void {
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(
        std.crypto.ecc.P384,
        Hash,
    );
    const public_key = Ecdsa.PublicKey.fromSec1(public_key_bytes) catch
        return error.InvalidCertificate;
    const signature = Ecdsa.Signature.fromDer(signature_bytes) catch
        return error.InvalidCertificateVerify;
    p384.verify(Hash, content, signature, public_key) catch
        return error.BadCertificateVerify;
}

fn validateMlDsaCertificate(
    comptime MlDsa: type,
    comptime expected_kind: RawSpkiKind,
    key_pair: *const MlDsa.KeyPair,
    certificate: []const u8,
) Error!void {
    const certificate_key = try mlDsaCertificatePublicKey(
        MlDsa,
        expected_kind,
        certificate,
    );
    const signer_key = key_pair.public_key.toBytes();
    if (!std.mem.eql(u8, &certificate_key, &signer_key)) {
        return error.InvalidCertificate;
    }
}

fn mlDsaCertificatePublicKey(
    comptime MlDsa: type,
    comptime expected_kind: RawSpkiKind,
    certificate: []const u8,
) Error![MlDsa.PublicKey.encoded_length]u8 {
    if (certificate.len == MlDsa.PublicKey.encoded_length) {
        return certificate[0..MlDsa.PublicKey.encoded_length].*;
    }
    const spki = (try parseRawSpki(certificate)) orelse
        return error.UnsupportedCertificateKey;
    if (spki.kind != expected_kind or
        spki.public_key.len != MlDsa.PublicKey.encoded_length)
    {
        return error.UnsupportedCertificateKey;
    }
    return spki.public_key[0..MlDsa.PublicKey.encoded_length].*;
}

fn verifyMlDsaContent(
    comptime MlDsa: type,
    comptime expected_kind: RawSpkiKind,
    certificate: []const u8,
    signature_bytes: []const u8,
    content: []const u8,
) Error!void {
    if (signature_bytes.len != MlDsa.Signature.encoded_length) {
        return error.InvalidCertificateVerify;
    }
    const encoded = try mlDsaCertificatePublicKey(
        MlDsa,
        expected_kind,
        certificate,
    );
    if (comptime MlDsa == MlDsa44 or MlDsa == MlDsa65 or MlDsa == MlDsa87) {
        const PreparedVerifier = if (MlDsa == MlDsa44)
            crypto_mldsa.PreparedVerifier44
        else if (MlDsa == MlDsa65)
            crypto_mldsa.PreparedVerifier65
        else
            crypto_mldsa.PreparedVerifier87;
        const PreparedSignature = if (MlDsa == MlDsa44)
            crypto_mldsa.PreparedSignature44
        else if (MlDsa == MlDsa65)
            crypto_mldsa.PreparedSignature65
        else
            crypto_mldsa.PreparedSignature87;
        const prepared = PreparedVerifier.fromBytes(encoded) catch
            return error.InvalidCertificate;
        const signature = PreparedSignature.fromBytes(
            signature_bytes[0..MlDsa.Signature.encoded_length],
        ) catch return error.InvalidCertificateVerify;
        prepared.verifyPrepared(&signature, content) catch
            return error.BadCertificateVerify;
    } else {
        const signature = MlDsa.Signature.fromBytes(
            signature_bytes[0..MlDsa.Signature.encoded_length].*,
        ) catch return error.InvalidCertificateVerify;
        const public_key = parseMlDsaPublicKey(MlDsa, encoded) catch
            return error.InvalidCertificate;
        signature.verify(content, public_key) catch
            return error.BadCertificateVerify;
    }
}

fn verifyMlDsaCertificateVerify(
    comptime MlDsa: type,
    comptime expected_kind: RawSpkiKind,
    certificate: []const u8,
    signature_bytes: []const u8,
    transcript_hash: []const u8,
    role: EndpointRole,
) Error!void {
    if (signature_bytes.len != MlDsa.Signature.encoded_length) {
        return error.InvalidCertificateVerify;
    }
    const encoded = try mlDsaCertificatePublicKey(
        MlDsa,
        expected_kind,
        certificate,
    );
    if (comptime MlDsa == MlDsa44 or MlDsa == MlDsa65 or MlDsa == MlDsa87) {
        const PreparedVerifier = if (MlDsa == MlDsa44)
            crypto_mldsa.PreparedVerifier44
        else if (MlDsa == MlDsa65)
            crypto_mldsa.PreparedVerifier65
        else
            crypto_mldsa.PreparedVerifier87;
        const PreparedSignature = if (MlDsa == MlDsa44)
            crypto_mldsa.PreparedSignature44
        else if (MlDsa == MlDsa65)
            crypto_mldsa.PreparedSignature65
        else
            crypto_mldsa.PreparedSignature87;
        const prepared = PreparedVerifier.fromBytes(encoded) catch
            return error.InvalidCertificate;
        const signature = PreparedSignature.fromBytes(
            signature_bytes[0..MlDsa.Signature.encoded_length],
        ) catch return error.InvalidCertificateVerify;
        var content: [64 + server_certificate_verify_context.len + 1 + 64]u8 =
            undefined;
        @memset(content[0..64], ' ');
        const context = certificateVerifyContext(role);
        @memcpy(content[64..][0..context.len], context);
        content[64 + context.len] = 0;
        @memcpy(
            content[64 + context.len + 1 ..][0..transcript_hash.len],
            transcript_hash,
        );
        prepared.verifyPrepared(
            &signature,
            content[0 .. 64 + context.len + 1 + transcript_hash.len],
        ) catch return error.BadCertificateVerify;
        return;
    }
    const signature = MlDsa.Signature.fromBytes(
        signature_bytes[0..MlDsa.Signature.encoded_length].*,
    ) catch return error.InvalidCertificateVerify;
    const public_key = parseMlDsaPublicKey(MlDsa, encoded) catch
        return error.InvalidCertificate;
    var verifier = signature.verifier(public_key) catch
        return error.BadCertificateVerify;
    updateCertificateVerifyInput(&verifier, transcript_hash, role);
    verifier.verify() catch return error.BadCertificateVerify;
}

fn parseMlDsaPublicKey(
    comptime MlDsa: type,
    encoded: [MlDsa.PublicKey.encoded_length]u8,
) !MlDsa.PublicKey {
    if (comptime MlDsa == MlDsa44) {
        return crypto_mldsa.publicKey44FromBytes(encoded);
    }
    return MlDsa.PublicKey.fromBytes(encoded);
}

pub fn verifyCertificateVerify(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    transcript_hash: []const u8,
) Error!void {
    return verifyCertificateVerifyForRole(
        certificate,
        parsed,
        transcript_hash,
        .server,
    );
}

pub fn verifyCertificateVerifyForRole(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    transcript_hash: []const u8,
    role: EndpointRole,
) Error!void {
    if (transcript_hash.len != Sha256.digest_length and
        transcript_hash.len != Sha384.digest_length and
        transcript_hash.len != Sha512.digest_length)
    {
        return error.InvalidCertificateVerify;
    }
    switch (parsed.scheme) {
        signature_scheme_ed25519 => {
            if (parsed.signature.len != Ed25519.Signature.encoded_length) {
                return error.InvalidCertificateVerify;
            }
            const public_key_bytes =
                try ed25519CertificatePublicKey(certificate);
            const public_key = Ed25519.PublicKey.fromBytes(public_key_bytes) catch
                return error.InvalidCertificate;
            const signature = Ed25519.Signature.fromBytes(
                parsed.signature[0..Ed25519.Signature.encoded_length].*,
            );
            verifyEd25519CertificateVerify(
                signature,
                public_key,
                transcript_hash,
                role,
            ) catch return error.BadCertificateVerify;
        },
        signature_scheme_ml_dsa_44 => try verifyMlDsaCertificateVerify(
            MlDsa44,
            .ml_dsa_44,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_ml_dsa_65 => try verifyMlDsaCertificateVerify(
            MlDsa65,
            .ml_dsa_65,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_ml_dsa_87 => try verifyMlDsaCertificateVerify(
            MlDsa87,
            .ml_dsa_87,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_ecdsa_secp256r1_sha256 => {
            const public_key_bytes =
                try p256CertificatePublicKey(certificate);
            const public_key = EcdsaP256Sha256.PublicKey.fromSec1(
                &public_key_bytes,
            ) catch return error.InvalidCertificate;
            const signature = EcdsaP256Sha256.Signature.fromDer(
                parsed.signature,
            ) catch return error.InvalidCertificateVerify;
            verifyP256CertificateVerify(
                signature,
                public_key,
                transcript_hash,
                role,
            ) catch return error.BadCertificateVerify;
        },
        signature_scheme_ecdsa_secp384r1_sha384 => {
            const public_key_bytes =
                try p384CertificatePublicKey(certificate);
            const public_key = EcdsaP384Sha384.PublicKey.fromSec1(
                &public_key_bytes,
            ) catch return error.InvalidCertificate;
            const signature = EcdsaP384Sha384.Signature.fromDer(
                parsed.signature,
            ) catch return error.InvalidCertificateVerify;
            verifyP384CertificateVerify(
                signature,
                public_key,
                transcript_hash,
                role,
            ) catch return error.BadCertificateVerify;
        },
        signature_scheme_ecdsa_secp521r1_sha512 => try verifyP521CertificateVerify(
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_rsae_sha256 => try verifyRsaPss(
            Sha256,
            .rsaEncryption,
            .rsa_pss_sha256,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_rsae_sha384 => try verifyRsaPss(
            Sha384,
            .rsaEncryption,
            .rsa_pss_sha384,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_rsae_sha512 => try verifyRsaPss(
            Sha512,
            .rsaEncryption,
            .rsa_pss_sha512,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_pss_sha256 => try verifyRsaPss(
            Sha256,
            .rsassa_pss,
            .rsa_pss_sha256,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_pss_sha384 => try verifyRsaPss(
            Sha384,
            .rsassa_pss,
            .rsa_pss_sha384,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_pss_sha512 => try verifyRsaPss(
            Sha512,
            .rsassa_pss,
            .rsa_pss_sha512,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_sm2sig_sm3 => try verifySm2(
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        else => return error.UnsupportedSignatureScheme,
    }
}

/// Verify Ed25519 CertificateVerify with a caller-retained public-key table.
/// The prepared key is checked against the certificate before it is used.
pub fn verifyCertificateVerifyForRoleWithEd25519(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    transcript_hash: []const u8,
    role: EndpointRole,
    prepared: *const crypto_ed25519.PreparedVerifier,
) Error!void {
    if (parsed.scheme != signature_scheme_ed25519) {
        return error.UnsupportedSignatureScheme;
    }
    if (parsed.signature.len != Ed25519.Signature.encoded_length or
        (transcript_hash.len != Sha256.digest_length and
            transcript_hash.len != Sha384.digest_length and
            transcript_hash.len != Sha512.digest_length))
    {
        return error.InvalidCertificateVerify;
    }
    const public_key = Ed25519.PublicKey.fromBytes(
        try ed25519CertificatePublicKey(certificate),
    ) catch return error.InvalidCertificate;
    if (!prepared.matchesPublicKey(public_key)) {
        return error.InvalidCertificate;
    }
    const signature = Ed25519.Signature.fromBytes(
        parsed.signature[0..Ed25519.Signature.encoded_length].*,
    );

    const context = certificateVerifyContext(role);
    var signed_content: [
        64 + client_certificate_verify_context.len + 1 +
            Sha512.digest_length
    ]u8 = undefined;
    @memset(signed_content[0..64], 0x20);
    @memcpy(signed_content[64 .. 64 + context.len], context);
    const separator = 64 + context.len;
    signed_content[separator] = 0;
    @memcpy(
        signed_content[separator + 1 ..][0..transcript_hash.len],
        transcript_hash,
    );
    prepared.verify(
        signature,
        signed_content[0 .. separator + 1 + transcript_hash.len],
    ) catch return error.BadCertificateVerify;
}

/// Verify P-256 CertificateVerify with a caller-retained public-key table.
/// The prepared key is checked against the certificate before it is used.
pub fn verifyCertificateVerifyForRoleWithP256(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    transcript_hash: []const u8,
    role: EndpointRole,
    prepared: *const p256.PreparedVerifier,
) Error!void {
    if (parsed.scheme != signature_scheme_ecdsa_secp256r1_sha256) {
        return error.UnsupportedSignatureScheme;
    }
    if (transcript_hash.len != Sha256.digest_length) {
        return error.InvalidCertificateVerify;
    }
    const public_key = EcdsaP256Sha256.PublicKey.fromSec1(
        &try p256CertificatePublicKey(certificate),
    ) catch return error.InvalidCertificate;
    if (!prepared.matchesPublicKey(public_key.p)) {
        return error.InvalidCertificate;
    }
    const signature = EcdsaP256Sha256.Signature.fromDer(
        parsed.signature,
    ) catch return error.InvalidCertificateVerify;

    const context = certificateVerifyContext(role);
    var signed_content: [
        64 + client_certificate_verify_context.len + 1 +
            Sha256.digest_length
    ]u8 = undefined;
    @memset(signed_content[0..64], 0x20);
    @memcpy(signed_content[64 .. 64 + context.len], context);
    const separator = 64 + context.len;
    signed_content[separator] = 0;
    @memcpy(
        signed_content[separator + 1 ..][0..transcript_hash.len],
        transcript_hash,
    );
    prepared.verify(
        Sha256,
        signed_content[0 .. separator + 1 + transcript_hash.len],
        signature,
    ) catch return error.BadCertificateVerify;
}

fn verifySm2(
    certificate: []const u8,
    signature_bytes: []const u8,
    transcript_hash: []const u8,
    role: EndpointRole,
) Error!void {
    if (transcript_hash.len != sm3DigestLen()) {
        return error.InvalidCertificateVerify;
    }
    const public_key = sm2.PublicKey.fromUncompressedSec1(
        &try sm2CertificatePublicKey(certificate),
    ) catch return error.InvalidCertificate;
    const signature = sm2.Signature.fromDer(signature_bytes) catch
        return error.InvalidCertificateVerify;
    const separator = [_]u8{0};
    var message: [
        64 + client_certificate_verify_context.len + 1 +
            sm3DigestLen()
    ]u8 = undefined;
    @memset(message[0..64], 0x20);
    const context = certificateVerifyContext(role);
    @memcpy(message[64 .. 64 + context.len], context);
    message[64 + context.len] = separator[0];
    @memcpy(
        message[64 + context.len + 1 ..][0..transcript_hash.len],
        transcript_hash,
    );
    sm2.verify(
        sm2.default_user_id,
        public_key,
        message[0 .. 64 + context.len + 1 + transcript_hash.len],
        signature,
    ) catch return error.BadCertificateVerify;
}

fn verifyRsaPss(
    comptime Hash: type,
    comptime expected_key_algorithm: Certificate.AlgorithmCategory,
    comptime pss_algorithm: x509_signature.Algorithm,
    certificate: []const u8,
    signature_bytes: []const u8,
    transcript_hash: []const u8,
    role: EndpointRole,
) Error!void {
    const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
        certificate,
        expected_key_algorithm,
        pss_algorithm,
    );
    const components = Certificate.rsa.PublicKey.parseDer(
        public_key_der,
    ) catch return error.InvalidCertificate;
    const modulus = components.modulus;
    const exponent = components.exponent;
    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (signature_bytes.len != modulus_len) {
                return error.InvalidCertificateVerify;
            }
            const public_key = Certificate.rsa.PublicKey.fromBytes(
                exponent,
                modulus,
            ) catch return error.InvalidCertificate;
            const signature = Certificate.rsa.PSSSignature.fromBytes(
                modulus_len,
                signature_bytes,
            );
            const separator = [_]u8{0};
            Certificate.rsa.PSSSignature.concatVerify(
                modulus_len,
                signature,
                &.{
                    " " ** 64,
                    certificateVerifyContext(role),
                    &separator,
                    transcript_hash,
                },
                public_key,
                Hash,
            ) catch return error.BadCertificateVerify;
        },
        else => return error.UnsupportedCertificateKey,
    }
}

fn verifyRsaPssContent(
    comptime Hash: type,
    comptime expected_key_algorithm: Certificate.AlgorithmCategory,
    comptime pss_algorithm: x509_signature.Algorithm,
    certificate: []const u8,
    signature_bytes: []const u8,
    content: []const u8,
) Error!void {
    const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
        certificate,
        expected_key_algorithm,
        pss_algorithm,
    );
    const components = Certificate.rsa.PublicKey.parseDer(
        public_key_der,
    ) catch return error.InvalidCertificate;
    switch (components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (signature_bytes.len != modulus_len) {
                return error.InvalidCertificateVerify;
            }
            const public_key = Certificate.rsa.PublicKey.fromBytes(
                components.exponent,
                components.modulus,
            ) catch return error.InvalidCertificate;
            const signature = Certificate.rsa.PSSSignature.fromBytes(
                modulus_len,
                signature_bytes,
            );
            Certificate.rsa.PSSSignature.verify(
                modulus_len,
                signature,
                content,
                public_key,
                Hash,
            ) catch return error.BadCertificateVerify;
        },
        else => return error.UnsupportedCertificateKey,
    }
}

fn updateCertificateVerifyInput(
    verifier: anytype,
    transcript_hash: []const u8,
    role: EndpointRole,
) void {
    verifier.update(" " ** 64);
    verifier.update(certificateVerifyContext(role));
    verifier.update(&.{0});
    verifier.update(transcript_hash);
}

fn verifyP256CertificateVerify(
    signature: EcdsaP256Sha256.Signature,
    public_key: EcdsaP256Sha256.PublicKey,
    transcript_hash: []const u8,
    role: EndpointRole,
) !void {
    var hasher = Sha256.init(.{});
    updateCertificateVerifyInput(&hasher, transcript_hash, role);
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return p256.verifyPrehashed(Sha256, signature, digest, public_key);
}

fn verifyEd25519CertificateVerify(
    signature: Ed25519.Signature,
    public_key: Ed25519.PublicKey,
    transcript_hash: []const u8,
    role: EndpointRole,
) !void {
    const context = certificateVerifyContext(role);
    var signed_content: [
        64 + client_certificate_verify_context.len + 1 +
            Sha512.digest_length
    ]u8 = undefined;
    @memset(signed_content[0..64], 0x20);
    @memcpy(signed_content[64 .. 64 + context.len], context);
    const separator = 64 + context.len;
    signed_content[separator] = 0;
    @memcpy(
        signed_content[separator + 1 ..][0..transcript_hash.len],
        transcript_hash,
    );
    return crypto_ed25519.verify(
        signature,
        signed_content[0 .. separator + 1 + transcript_hash.len],
        public_key,
    );
}

fn verifyP384CertificateVerify(
    signature: EcdsaP384Sha384.Signature,
    public_key: EcdsaP384Sha384.PublicKey,
    transcript_hash: []const u8,
    role: EndpointRole,
) !void {
    var hasher = Sha384.init(.{});
    updateCertificateVerifyInput(&hasher, transcript_hash, role);
    var digest: [Sha384.digest_length]u8 = undefined;
    hasher.final(&digest);
    return p384.verifyPrehashed(Sha384, signature, digest, public_key);
}

fn certificateVerifyContext(role: EndpointRole) []const u8 {
    return switch (role) {
        .server => server_certificate_verify_context,
        .client => client_certificate_verify_context,
    };
}

fn ed25519CertificatePublicKey(certificate: []const u8) Error![32]u8 {
    if (certificate.len == Ed25519.PublicKey.encoded_length) {
        _ = Ed25519.PublicKey.fromBytes(
            certificate[0..Ed25519.PublicKey.encoded_length].*,
        ) catch return error.InvalidCertificate;
        return certificate[0..Ed25519.PublicKey.encoded_length].*;
    }
    if (try parseRawSpki(certificate)) |spki| {
        if (spki.kind != .ed25519 or
            spki.public_key.len != Ed25519.PublicKey.encoded_length)
        {
            return error.UnsupportedCertificateKey;
        }
        return spki.public_key[0..Ed25519.PublicKey.encoded_length].*;
    }
    const parsed = try parseX509(certificate);
    if (parsed.pub_key_algo != .curveEd25519) {
        return error.UnsupportedCertificateKey;
    }
    const public_key = parsed.pubKey();
    if (public_key.len != Ed25519.PublicKey.encoded_length) {
        return error.InvalidCertificate;
    }
    return public_key[0..Ed25519.PublicKey.encoded_length].*;
}

fn p256CertificatePublicKey(
    certificate: []const u8,
) Error![EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 {
    if (certificate.len ==
        EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length)
    {
        _ = EcdsaP256Sha256.PublicKey.fromSec1(certificate) catch
            return error.InvalidCertificate;
        return certificate[0..EcdsaP256Sha256.PublicKey
            .uncompressed_sec1_encoded_length].*;
    }
    if (try parseRawSpki(certificate)) |spki| {
        if (spki.kind != .p256 or spki.public_key.len !=
            EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length)
        {
            return error.UnsupportedCertificateKey;
        }
        return spki.public_key[0..EcdsaP256Sha256.PublicKey
            .uncompressed_sec1_encoded_length].*;
    }
    const parsed = try parseX509(certificate);
    if (parsed.pub_key_algo != .X9_62_id_ecPublicKey or
        parsed.pub_key_algo.X9_62_id_ecPublicKey != .X9_62_prime256v1)
    {
        return error.UnsupportedCertificateKey;
    }
    const public_key = parsed.pubKey();
    if (public_key.len !=
        EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length)
    {
        return error.InvalidCertificate;
    }
    return public_key[0..EcdsaP256Sha256.PublicKey
        .uncompressed_sec1_encoded_length].*;
}

fn p384CertificatePublicKey(
    certificate: []const u8,
) Error![EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length]u8 {
    if (certificate.len ==
        EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length)
    {
        _ = EcdsaP384Sha384.PublicKey.fromSec1(certificate) catch
            return error.InvalidCertificate;
        return certificate[0..EcdsaP384Sha384.PublicKey
            .uncompressed_sec1_encoded_length].*;
    }
    if (try parseRawSpki(certificate)) |spki| {
        if (spki.kind != .p384 or spki.public_key.len !=
            EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length)
        {
            return error.UnsupportedCertificateKey;
        }
        return spki.public_key[0..EcdsaP384Sha384.PublicKey
            .uncompressed_sec1_encoded_length].*;
    }
    const parsed = try parseX509(certificate);
    if (parsed.pub_key_algo != .X9_62_id_ecPublicKey or
        parsed.pub_key_algo.X9_62_id_ecPublicKey != .secp384r1)
    {
        return error.UnsupportedCertificateKey;
    }
    const public_key = parsed.pubKey();
    if (public_key.len !=
        EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length)
    {
        return error.InvalidCertificate;
    }
    return public_key[0..EcdsaP384Sha384.PublicKey
        .uncompressed_sec1_encoded_length].*;
}

fn p521CertificatePublicKey(certificate: []const u8) Error![]const u8 {
    if (certificate.len == p521.uncompressed_sec1_encoded_length or
        certificate.len == p521.compressed_sec1_encoded_length)
    {
        p521.validatePublicKey(certificate) catch
            return error.InvalidCertificate;
        return certificate;
    }
    if (try parseRawSpki(certificate)) |spki| {
        if (spki.kind != .p521) return error.UnsupportedCertificateKey;
        p521.validatePublicKey(spki.public_key) catch
            return error.InvalidCertificate;
        return spki.public_key;
    }
    const parsed = try parseX509(certificate);
    if (parsed.pub_key_algo != .X9_62_id_ecPublicKey or
        parsed.pub_key_algo.X9_62_id_ecPublicKey != .secp521r1)
    {
        return error.UnsupportedCertificateKey;
    }
    p521.validatePublicKey(parsed.pubKey()) catch
        return error.InvalidCertificate;
    return parsed.pubKey();
}

fn validateP521Signer(
    key_pair: *const p521.KeyPair,
    certificate: []const u8,
) Error!void {
    const leaf_key = try p521CertificatePublicKey(certificate);
    const parsed_key = p521.PublicKey.fromSec1(leaf_key) catch
        return error.InvalidCertificate;
    const expected = parsed_key.toUncompressedSec1();
    const actual = key_pair.public_key.toUncompressedSec1();
    if (!std.mem.eql(u8, &expected, &actual)) {
        return error.InvalidCertificate;
    }
}

fn sm2CertificatePublicKey(
    certificate: []const u8,
) Error![sm2.public_key_len]u8 {
    if (certificate.len == sm2.public_key_len) {
        _ = sm2.PublicKey.fromUncompressedSec1(certificate) catch
            return error.InvalidCertificate;
        return certificate[0..sm2.public_key_len].*;
    }
    if (try parseRawSpki(certificate)) |spki| {
        if (spki.kind != .sm2 or spki.public_key.len != sm2.public_key_len) {
            return error.UnsupportedCertificateKey;
        }
        _ = sm2.PublicKey.fromUncompressedSec1(spki.public_key) catch
            return error.InvalidCertificate;
        return spki.public_key[0..sm2.public_key_len].*;
    }
    return sm2X509PublicKey(certificate);
}

fn sm2X509PublicKey(certificate: []const u8) Error![sm2.public_key_len]u8 {
    const cert = try DerElement.parse(certificate, 0);
    if (cert.tag != 0x30 or cert.end != certificate.len) {
        return error.InvalidCertificate;
    }
    var pos = cert.content_start;
    const tbs = try DerElement.parse(certificate, pos);
    if (tbs.tag != 0x30) return error.InvalidCertificate;
    pos = tbs.content_start;
    const first = try DerElement.parse(certificate, pos);
    pos = first.end;
    if (first.tag == 0xa0) {
        const serial = try DerElement.parse(certificate, pos);
        pos = serial.end;
    }
    inline for (0..4) |_| {
        const elem = try DerElement.parse(certificate, pos);
        pos = elem.end;
    }
    const spki = try DerElement.parse(certificate, pos);
    if (spki.tag != 0x30) return error.InvalidCertificate;
    var spki_pos = spki.content_start;
    const algorithm = try DerElement.parse(certificate, spki_pos);
    if (algorithm.tag != 0x30) return error.InvalidCertificate;
    spki_pos = algorithm.end;
    var alg_pos = algorithm.content_start;
    const algorithm_oid = try DerElement.parse(certificate, alg_pos);
    alg_pos = algorithm_oid.end;
    const parameters_oid = try DerElement.parse(certificate, alg_pos);
    if (!oidEquals(certificate, algorithm_oid, &oid_id_ec_public_key) or
        !oidEquals(certificate, parameters_oid, &oid_sm2))
    {
        return error.UnsupportedCertificateKey;
    }
    const key_bits = try DerElement.parse(certificate, spki_pos);
    if (key_bits.tag != 0x03 or
        key_bits.content_start >= key_bits.end or
        certificate[key_bits.content_start] != 0)
    {
        return error.InvalidCertificate;
    }
    const public_key = certificate[key_bits.content_start + 1 .. key_bits.end];
    if (public_key.len != sm2.public_key_len) return error.InvalidCertificate;
    _ = sm2.PublicKey.fromUncompressedSec1(public_key) catch
        return error.InvalidCertificate;
    return public_key[0..sm2.public_key_len].*;
}

const DerElement = struct {
    tag: u8,
    content_start: usize,
    end: usize,

    fn parse(bytes: []const u8, offset: usize) Error!DerElement {
        if (offset + 2 > bytes.len) return error.InvalidCertificate;
        const tag = bytes[offset];
        var pos = offset + 1;
        const first_len = bytes[pos];
        pos += 1;
        const len: usize = if (first_len < 0x80)
            first_len
        else blk: {
            const len_len = first_len & 0x7f;
            if (len_len == 0 or len_len > 4 or pos + len_len > bytes.len) {
                return error.InvalidCertificate;
            }
            var value: usize = 0;
            for (0..len_len) |_| {
                value = (value << 8) | bytes[pos];
                pos += 1;
            }
            if (value < 0x80) return error.InvalidCertificate;
            break :blk value;
        };
        const end = std.math.add(usize, pos, len) catch
            return error.InvalidCertificate;
        if (end > bytes.len) return error.InvalidCertificate;
        return .{ .tag = tag, .content_start = pos, .end = end };
    }
};

fn oidEquals(bytes: []const u8, elem: DerElement, expected: []const u8) bool {
    if (elem.tag != 0x06) return false;
    return std.mem.eql(u8, bytes[elem.content_start..elem.end], expected);
}

const oid_id_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_sm2 = [_]u8{ 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d };
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_rsassa_pss = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
const oid_ml_dsa_44 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
const oid_ml_dsa_65 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
const oid_ml_dsa_87 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };
const oid_p256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_p384 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_p521 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x23 };

const RawSpkiKind = enum {
    rsa_encryption,
    rsa_pss,
    ed25519,
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
    p256,
    p384,
    p521,
    sm2,
};

const RawSpki = struct {
    kind: RawSpkiKind,
    public_key: []const u8,
    pss_constraints: ?x509_signature.PssKeyConstraints = null,
};

fn parseRawSpki(bytes: []const u8) Error!?RawSpki {
    const top = DerElement.parse(bytes, 0) catch return null;
    if (top.tag != 0x30 or top.end != bytes.len) return null;
    const algorithm = DerElement.parse(bytes, top.content_start) catch
        return null;
    if (algorithm.tag != 0x30) return null;
    const key_bits = DerElement.parse(bytes, algorithm.end) catch return null;
    if (key_bits.tag != 0x03 or key_bits.end != top.end or
        key_bits.content_start >= key_bits.end or
        bytes[key_bits.content_start] != 0)
    {
        return null;
    }
    var pos = algorithm.content_start;
    const oid = DerElement.parse(bytes, pos) catch return null;
    if (oid.tag != 0x06) return null;
    pos = oid.end;
    const kind: RawSpkiKind = if (oidEquals(bytes, oid, &oid_rsa_encryption))
        .rsa_encryption
    else if (oidEquals(bytes, oid, &oid_rsassa_pss))
        .rsa_pss
    else if (oidEquals(bytes, oid, &oid_ed25519))
        .ed25519
    else if (oidEquals(bytes, oid, &oid_ml_dsa_44))
        .ml_dsa_44
    else if (oidEquals(bytes, oid, &oid_ml_dsa_65))
        .ml_dsa_65
    else if (oidEquals(bytes, oid, &oid_ml_dsa_87))
        .ml_dsa_87
    else if (oidEquals(bytes, oid, &oid_id_ec_public_key)) blk: {
        const parameters = DerElement.parse(bytes, pos) catch
            return error.InvalidCertificate;
        if (parameters.tag != 0x06) return error.InvalidCertificate;
        pos = parameters.end;
        if (oidEquals(bytes, parameters, &oid_p256)) break :blk .p256;
        if (oidEquals(bytes, parameters, &oid_p384)) break :blk .p384;
        if (oidEquals(bytes, parameters, &oid_p521)) break :blk .p521;
        if (oidEquals(bytes, parameters, &oid_sm2)) break :blk .sm2;
        return error.UnsupportedCertificateKey;
    } else return null;
    const pss_constraints = if (kind == .rsa_pss)
        x509_signature.parsePssPublicKeyAlgorithmIdentifier(
            bytes[algorithm.content_start..algorithm.end],
        ) catch |err| switch (err) {
            error.InvalidAlgorithmIdentifier => return error.InvalidCertificate,
            error.UnsupportedSignatureAlgorithm => return error.UnsupportedCertificateKey,
        }
    else
        null;
    while (pos < algorithm.end) {
        const parameter = try DerElement.parse(bytes, pos);
        pos = parameter.end;
        if (kind == .ed25519 or kind == .ml_dsa_44 or
            kind == .ml_dsa_65 or kind == .ml_dsa_87 or
            kind == .p256 or kind == .p384 or kind == .p521 or
            kind == .sm2)
        {
            return error.InvalidCertificate;
        }
        if (kind == .rsa_encryption and
            (parameter.tag != 0x05 or parameter.content_start != parameter.end))
        {
            return error.InvalidCertificate;
        }
    }
    if (pos != algorithm.end) return error.InvalidCertificate;
    return .{
        .kind = kind,
        .public_key = bytes[key_bits.content_start + 1 .. key_bits.end],
        .pss_constraints = pss_constraints,
    };
}

fn rsaCertificatePublicKey(certificate: []const u8) Error![]const u8 {
    return rsaCertificatePublicKeyForAlgorithm(
        certificate,
        .rsaEncryption,
        null,
    );
}

fn x509PssAlgorithmForScheme(
    scheme: u16,
) Error!x509_signature.Algorithm {
    return switch (scheme) {
        signature_scheme_rsa_pss_rsae_sha256,
        signature_scheme_rsa_pss_pss_sha256,
        => .rsa_pss_sha256,
        signature_scheme_rsa_pss_rsae_sha384,
        signature_scheme_rsa_pss_pss_sha384,
        => .rsa_pss_sha384,
        signature_scheme_rsa_pss_rsae_sha512,
        signature_scheme_rsa_pss_pss_sha512,
        => .rsa_pss_sha512,
        else => error.UnsupportedSignatureScheme,
    };
}

fn sm3DigestLen() usize {
    return @import("../crypto/sm3.zig").digest_len;
}

fn rsaCertificatePublicKeyForAlgorithm(
    certificate: []const u8,
    expected: Certificate.AlgorithmCategory,
    pss_algorithm: ?x509_signature.Algorithm,
) Error![]const u8 {
    if (try parseRawSpki(certificate)) |spki| {
        const matches = switch (expected) {
            .rsaEncryption => spki.kind == .rsa_encryption,
            .rsassa_pss => spki.kind == .rsa_pss,
            else => false,
        };
        if (!matches) return error.UnsupportedCertificateKey;
        if (expected == .rsassa_pss and
            !spki.pss_constraints.?.permits(
                pss_algorithm orelse return error.UnsupportedCertificateKey,
            ))
        {
            return error.UnsupportedCertificateKey;
        }
        _ = Certificate.rsa.PublicKey.parseDer(spki.public_key) catch
            return error.InvalidCertificate;
        return spki.public_key;
    }
    const parsed = try parseX509(certificate);
    if (std.meta.activeTag(parsed.pub_key_algo) != expected) {
        return error.UnsupportedCertificateKey;
    }
    if (expected == .rsassa_pss) {
        const constraints = x509_signature.pssConstraintsForCertificate(
            parsed,
        ) catch |err| switch (err) {
            error.InvalidAlgorithmIdentifier => return error.InvalidCertificate,
            else => return error.UnsupportedCertificateKey,
        };
        if (!constraints.permits(
            pss_algorithm orelse return error.UnsupportedCertificateKey,
        )) return error.UnsupportedCertificateKey;
    }
    const public_key = parsed.pubKey();
    // Parse now so malformed or non-canonical DER cannot be accepted merely
    // because a caller uses trust callbacks instead of the built-in pin.
    _ = Certificate.rsa.PublicKey.parseDer(public_key) catch
        return error.InvalidCertificate;
    return public_key;
}

fn timingSafeEqlBytes(a: []const u8, b: []const u8) bool {
    // Length is public key metadata. Once equal, visit every byte and avoid
    // data-dependent early exits so pin mismatch position is not observable.
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |lhs, rhs| difference |= lhs ^ rhs;
    return difference == 0;
}

fn parseX509(certificate: []const u8) Error!Certificate.Parsed {
    return (x509_certificate.parse(certificate) catch
        return error.InvalidCertificate).standard;
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
    if (pos.* >= bytes.len) return error.InvalidCertificate;
    const value = bytes[pos.*];
    pos.* += 1;
    return value;
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
        return error.InvalidCertificate;
    if (end > bytes.len) return error.InvalidCertificate;
    const result = bytes[pos.*..end];
    pos.* = end;
    return result;
}

fn readU24At(bytes: []const u8, pos: *usize) Error!usize {
    const slice = try readSlice(bytes, pos, 3);
    return readU24(slice[0..3]);
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn writeU24(bytes: *[3]u8, value: u24) void {
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}

test "certificate signatures map to TLS signature schemes" {
    try std.testing.expectError(
        error.InvalidCertificate,
        certificateSignatureSchemes(&.{ 0x30, 0x00 }, null),
    );
    const path_vectors = @import("../x509/testdata/path_vectors.zig");
    const leaf = decodeHex(path_vectors.leaf_hex);
    const intermediate = decodeHex(path_vectors.intermediate_hex);
    const ecdsa = try certificateSignatureSchemes(&leaf, &intermediate);
    try std.testing.expectEqual(
        signature_scheme_ecdsa_secp256r1_sha256,
        ecdsa.primary,
    );
    try std.testing.expect(ecdsa.alternate == null);
    try std.testing.expect(!ecdsa.self_issued);
    try std.testing.expect(try certificateChainSupportsSchemeValues(
        &.{ &leaf, &intermediate },
        &.{signature_scheme_ecdsa_secp256r1_sha256},
    ));
    try std.testing.expect(!try certificateChainSupportsSchemeValues(
        &.{ &leaf, &intermediate },
        &.{signature_scheme_rsa_pss_rsae_sha256},
    ));

    const rsae_pss = try certificateSignatureSchemes(
        @embedFile("../x509/testdata/rsa-pss-intermediate.der"),
        @embedFile("../x509/testdata/rsa-pss-crl-ca.der"),
    );
    try std.testing.expectEqual(
        signature_scheme_rsa_pss_rsae_sha512,
        rsae_pss.primary,
    );
    try std.testing.expect(rsae_pss.alternate == null);

    const constrained_pss = try certificateSignatureSchemes(
        @embedFile("../x509/testdata/rsa-pss-constrained-child.der"),
        @embedFile("../x509/testdata/rsa-pss-constrained-intermediate.der"),
    );
    try std.testing.expectEqual(
        signature_scheme_rsa_pss_pss_sha384,
        constrained_pss.primary,
    );
    try std.testing.expect(constrained_pss.alternate == null);

    const omitted_issuer = try certificateSignatureSchemes(
        @embedFile("../x509/testdata/rsa-pss-intermediate.der"),
        null,
    );
    try std.testing.expectEqual(
        signature_scheme_rsa_pss_rsae_sha512,
        omitted_issuer.primary,
    );
    try std.testing.expectEqual(
        signature_scheme_rsa_pss_pss_sha512,
        omitted_issuer.alternate.?,
    );
}

test "P-521 verifies TLS 1.2 and TLS 1.3 signatures" {
    const vectors = @import("../x509/testdata/path_vectors.zig");
    const root = decodeHex(vectors.p521_root_hex);
    const leaf = decodeHex(vectors.p521_leaf_hex);
    const content_signature = decodeHex(vectors.p521_sha512_signature_hex);
    const server_signature = decodeHex(
        vectors.p521_tls13_server_signature_hex,
    );
    const client_signature = decodeHex(
        vectors.p521_tls13_client_signature_hex,
    );

    const certificate_scheme = try certificateSignatureSchemes(&leaf, &root);
    try std.testing.expectEqual(
        signature_scheme_ecdsa_secp521r1_sha512,
        certificate_scheme.primary,
    );
    try verifySignedContent(
        &root,
        .{
            .scheme = signature_scheme_ecdsa_secp521r1_sha512,
            .signature = &content_signature,
        },
        "Vail pure Zig P-521 oracle",
    );
    try verifyTls12SignedContent(
        &root,
        .{
            .scheme = signature_scheme_ecdsa_secp521r1_sha512,
            .signature = &content_signature,
        },
        "Vail pure Zig P-521 oracle",
    );

    const transcript_hash = [_]u8{0x42} ** Sha512.digest_length;
    try verifyCertificateVerifyForRole(
        &root,
        .{
            .scheme = signature_scheme_ecdsa_secp521r1_sha512,
            .signature = &server_signature,
        },
        &transcript_hash,
        .server,
    );
    try verifyCertificateVerifyForRole(
        &root,
        .{
            .scheme = signature_scheme_ecdsa_secp521r1_sha512,
            .signature = &client_signature,
        },
        &transcript_hash,
        .client,
    );

    var altered = server_signature;
    altered[altered.len - 1] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        verifyCertificateVerifyForRole(
            &root,
            .{
                .scheme = signature_scheme_ecdsa_secp521r1_sha512,
                .signature = &altered,
            },
            &transcript_hash,
            .server,
        ),
    );
}

test "Certificate codec round-trips a leaf OCSP staple" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCertificateWithOcsp(
        &encoded,
        allocator,
        &.{ "leaf", "issuer" },
        "ocsp-response",
    );

    var parsed = try parseCertificate(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed.entries.len);
    try std.testing.expectEqualStrings("leaf", parsed.entries[0]);
    try std.testing.expectEqualStrings("issuer", parsed.entries[1]);
    try std.testing.expectEqualStrings(
        "ocsp-response",
        parsed.ocsp_response.?,
    );
    try std.testing.expectEqual(@as(usize, 2), parsed.ocsp_responses.?.len);
    try std.testing.expectEqualStrings(
        "ocsp-response",
        parsed.ocsp_responses.?[0].?,
    );
    try std.testing.expect(parsed.ocsp_responses.?[1] == null);

    encoded.clearRetainingCapacity();
    try writeCertificateWithOcspResponses(
        &encoded,
        allocator,
        &.{ "leaf", "issuer" },
        &.{ "leaf-response", "issuer-response" },
    );
    var parsed_multi = try parseCertificate(allocator, encoded.items);
    defer parsed_multi.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed_multi.entries.len);
    try std.testing.expectEqualStrings(
        "leaf-response",
        parsed_multi.ocsp_response.?,
    );
    try std.testing.expectEqualStrings(
        "leaf-response",
        parsed_multi.ocsp_responses.?[0].?,
    );
    try std.testing.expectEqualStrings(
        "issuer-response",
        parsed_multi.ocsp_responses.?[1].?,
    );

    encoded.clearRetainingCapacity();
    try writeClientCertificateWithContextAndOcsp(
        &encoded,
        allocator,
        &.{ "client-leaf", "client-issuer" },
        "request-context",
        "client-ocsp-response",
    );
    var parsed_client = try parseClientCertificateWithContext(
        allocator,
        encoded.items,
        "request-context",
    );
    defer parsed_client.deinit(allocator);
    try std.testing.expectEqualStrings(
        "client-ocsp-response",
        parsed_client.ocsp_response.?,
    );

    encoded.clearRetainingCapacity();
    try writeClientCertificateWithContextAndOcspResponses(
        &encoded,
        allocator,
        &.{ "client-leaf", "client-issuer" },
        "request-context",
        &.{ "client-leaf-response", "client-issuer-response" },
    );
    var parsed_client_multi = try parseClientCertificateWithContext(
        allocator,
        encoded.items,
        "request-context",
    );
    defer parsed_client_multi.deinit(allocator);
    try std.testing.expectEqualStrings(
        "client-leaf-response",
        parsed_client_multi.ocsp_responses.?[0].?,
    );
    try std.testing.expectEqualStrings(
        "client-issuer-response",
        parsed_client_multi.ocsp_responses.?[1].?,
    );

    try std.testing.expectError(
        error.InvalidCertificate,
        writeCertificateWithOcsp(
            &encoded,
            allocator,
            &.{"leaf"},
            &.{},
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificate,
        writeCertificateWithOcspResponses(
            &encoded,
            allocator,
            &.{ "leaf", "issuer" },
            &.{"leaf-response"},
        ),
    );
}

const TestCustomSignerContext = struct {
    key_pair: Ed25519.KeyPair,
};

fn validateTestCustomSigner(
    opaque_context: ?*anyopaque,
    certificate: []const u8,
) !void {
    const context: *const TestCustomSignerContext = @ptrCast(@alignCast(
        opaque_context orelse return error.MissingSignerContext,
    ));
    const actual = try ed25519CertificatePublicKey(certificate);
    if (!std.crypto.timing_safe.eql(
        [Ed25519.PublicKey.encoded_length]u8,
        actual,
        context.key_pair.public_key.toBytes(),
    )) return error.KeyMismatch;
}

fn signWithTestCustomSigner(
    opaque_context: ?*anyopaque,
    content: []const u8,
    output: []u8,
) !usize {
    const context: *const TestCustomSignerContext = @ptrCast(@alignCast(
        opaque_context orelse return error.MissingSignerContext,
    ));
    if (output.len < Ed25519.Signature.encoded_length) {
        return error.SignatureBufferTooSmall;
    }
    const signature = try context.key_pair.sign(content, null);
    const encoded = signature.toBytes();
    @memcpy(output[0..encoded.len], &encoded);
    return encoded.len;
}

test "built-in Ed25519 signer emits verifiable CertificateVerify" {
    const allocator = std.testing.allocator;
    const key_pair = try crypto_ed25519.generateKeyPairDeterministic(
        [_]u8{0x71} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    const signer = Signer{ .ed25519 = .{ .key_pair = key_pair } };
    try (ServerIdentity{
        .certificate_chain = &.{&public_key},
        .signer = signer,
    }).validate();

    const transcript_hash = [_]u8{0x72} ** Sha256.digest_length;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCertificateVerify(
        &encoded,
        allocator,
        signer,
        &transcript_hash,
    );
    const parsed = try parseCertificateVerify(encoded.items);
    try std.testing.expectEqual(signature_scheme_ed25519, parsed.scheme);
    try verifyCertificateVerify(&public_key, parsed, &transcript_hash);

    const prepared = try crypto_ed25519.PreparedVerifier.init(
        key_pair.public_key,
    );
    const verifier = ClientVerifier{
        .pinned_ed25519_public_key = public_key,
        .prepared_ed25519_verifier = &prepared,
    };
    try verifier.verifyPeerCertificateVerify(
        &public_key,
        parsed,
        &transcript_hash,
        .server,
    );

    var prepared_signer = try crypto_ed25519.PreparedSigner.init(key_pair);
    defer prepared_signer.deinit();
    const reusable_signer = Signer{ .ed25519 = .{
        .key_pair = key_pair,
        .prepared = &prepared_signer,
    } };
    encoded.clearRetainingCapacity();
    try writeCertificateVerify(
        &encoded,
        allocator,
        reusable_signer,
        &transcript_hash,
    );
    const prepared_signature = try parseCertificateVerify(encoded.items);
    try verifier.verifyPeerCertificateVerify(
        &public_key,
        prepared_signature,
        &transcript_hash,
        .server,
    );

    const other_key_pair = try crypto_ed25519.generateKeyPairDeterministic(
        [_]u8{0x73} ** Ed25519.KeyPair.seed_length,
    );
    const mismatched_prepared = try crypto_ed25519.PreparedVerifier.init(
        other_key_pair.public_key,
    );
    try std.testing.expectError(
        error.InvalidCertificate,
        verifyCertificateVerifyForRoleWithEd25519(
            &public_key,
            parsed,
            &transcript_hash,
            .server,
            &mismatched_prepared,
        ),
    );
    var mismatched_signer = try crypto_ed25519.PreparedSigner.init(
        other_key_pair,
    );
    defer mismatched_signer.deinit();
    try std.testing.expectError(
        error.InvalidCertificate,
        (ServerIdentity{
            .certificate_chain = &.{&public_key},
            .signer = .{ .ed25519 = .{
                .key_pair = key_pair,
                .prepared = &mismatched_signer,
            } },
        }).validate(),
    );
}

test "prepared P-256 verifier authenticates CertificateVerify" {
    const allocator = std.testing.allocator;
    const key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0x74} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toUncompressedSec1();
    const signer = Signer{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } };
    const transcript_hash = [_]u8{0x75} ** Sha256.digest_length;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCertificateVerify(
        &encoded,
        allocator,
        signer,
        &transcript_hash,
    );
    const parsed = try parseCertificateVerify(encoded.items);
    const prepared = try p256.PreparedVerifier.init(key_pair.public_key.p);
    const verifier = ClientVerifier{
        .pinned_ecdsa_p256_public_key = public_key,
        .prepared_p256_verifier = &prepared,
    };
    try verifier.verifyPeerCertificateVerify(
        &public_key,
        parsed,
        &transcript_hash,
        .server,
    );

    const other_key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0x76} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
    const mismatched = try p256.PreparedVerifier.init(other_key_pair.public_key.p);
    try std.testing.expectError(
        error.InvalidCertificate,
        verifyCertificateVerifyForRoleWithP256(
            &public_key,
            parsed,
            &transcript_hash,
            .server,
            &mismatched,
        ),
    );
}

test "custom signer preserves CertificateVerify construction and validation" {
    const allocator = std.testing.allocator;
    var context = TestCustomSignerContext{
        .key_pair = try Ed25519.KeyPair.generateDeterministic(
            [_]u8{0x91} ** Ed25519.KeyPair.seed_length,
        ),
    };
    const public_key = context.key_pair.public_key.toBytes();
    const signer = Signer{ .custom = .{
        .context = @ptrCast(&context),
        .signature_scheme = signature_scheme_ed25519,
        .max_signature_len = Ed25519.Signature.encoded_length,
        .validate_certificate = validateTestCustomSigner,
        .sign = signWithTestCustomSigner,
    } };
    try (ServerIdentity{
        .certificate_chain = &.{&public_key},
        .signer = signer,
    }).validate();

    const transcript_hash = [_]u8{0x92} ** Sha512.digest_length;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCertificateVerify(
        &encoded,
        allocator,
        signer,
        &transcript_hash,
    );
    const parsed = try parseCertificateVerify(encoded.items);
    try std.testing.expectEqual(
        signature_scheme_ed25519,
        parsed.scheme,
    );
    try verifyCertificateVerify(&public_key, parsed, &transcript_hash);

    var wrong_public_key = public_key;
    wrong_public_key[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCertificate,
        (ServerIdentity{
            .certificate_chain = &.{&wrong_public_key},
            .signer = signer,
        }).validate(),
    );
}

test "RFC 7250 ML-DSA CertificateVerify covers all registered schemes" {
    try testMlDsaCertificateVerify(
        MlDsa44,
        signature_scheme_ml_dsa_44,
        &oid_ml_dsa_44,
        0x94,
    );
    try testMlDsaCertificateVerify(
        MlDsa65,
        signature_scheme_ml_dsa_65,
        &oid_ml_dsa_65,
        0x95,
    );
    try testMlDsaCertificateVerify(
        MlDsa87,
        signature_scheme_ml_dsa_87,
        &oid_ml_dsa_87,
        0x96,
    );
}

fn testMlDsaCertificateVerify(
    comptime MlDsa: type,
    comptime scheme: u16,
    comptime oid: *const [9]u8,
    comptime seed_byte: u8,
) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(
        [_]u8{seed_byte} ** MlDsa.KeyPair.seed_length,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    const spki = mlDsaSubjectPublicKeyInfo(
        MlDsa,
        oid,
        key_pair.public_key.toBytes(),
    );
    const signer: Signer = if (scheme == signature_scheme_ml_dsa_44)
        .{ .ml_dsa_44 = .{
            .key_pair = &key_pair,
            .noise = [_]u8{seed_byte +% 1} ** MlDsa.noise_length,
        } }
    else if (scheme == signature_scheme_ml_dsa_65)
        .{ .ml_dsa_65 = .{
            .key_pair = &key_pair,
            .noise = [_]u8{seed_byte +% 1} ** MlDsa.noise_length,
        } }
    else
        .{ .ml_dsa_87 = .{
            .key_pair = &key_pair,
            .noise = [_]u8{seed_byte +% 1} ** MlDsa.noise_length,
        } };
    try std.testing.expectEqual(scheme, signer.scheme());
    try std.testing.expectEqual(
        MlDsa.Signature.encoded_length,
        signer.maxSignatureLen(),
    );
    try (ServerIdentity{
        .certificate_chain = &.{&spki},
        .signer = signer,
        .certificate_type = .raw_public_key,
    }).validate();

    const transcript_hash = [_]u8{seed_byte +% 2} ** Sha256.digest_length;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try writeCertificateVerify(
        &encoded,
        std.testing.allocator,
        signer,
        &transcript_hash,
    );
    const parsed = try parseCertificateVerify(encoded.items);
    try std.testing.expectEqual(scheme, parsed.scheme);
    try std.testing.expectEqual(
        MlDsa.Signature.encoded_length,
        parsed.signature.len,
    );
    try verifyCertificateVerify(&spki, parsed, &transcript_hash);
    try std.testing.expectError(
        error.UnsupportedSignatureScheme,
        verifyTls12SignedContent(&spki, parsed, "tls12"),
    );

    encoded.items[encoded.items.len - 1] ^= 1;
    const tampered = try parseCertificateVerify(encoded.items);
    verifyCertificateVerify(&spki, tampered, &transcript_hash) catch |err| {
        try std.testing.expect(err == error.InvalidCertificateVerify or
            err == error.BadCertificateVerify);
        return;
    };
    return error.TestUnexpectedResult;
}

test "RFC 7250 RSA SubjectPublicKeyInfo signs and verifies" {
    const allocator = std.testing.allocator;
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const spki = decodeHex(vectors.public_key_spki_hex);
    const private = try rsa.PrivateKey.fromDer(&private_der);
    var prepared = try private.prepare();
    defer prepared.deinit();
    const signer = Signer{ .rsa_pss = .{
        .prepared_key = &prepared,
        .io = std.testing.io,
    } };
    try (ServerIdentity{
        .certificate_chain = &.{&spki},
        .signer = signer,
        .certificate_type = .raw_public_key,
    }).validate();
    const message = "rfc7250 possession";
    var signature: [max_certificate_verify_signature_len]u8 = undefined;
    const signature_len = try signer.sign(message, &signature);
    try verifySignedContent(
        &spki,
        .{
            .scheme = signer.scheme(),
            .signature = signature[0..signature_len],
        },
        message,
    );
    try (ClientVerifier{ .pinned_raw_public_key = &spki })
        .verifyRawPublicKey("localhost", &.{&spki});
    var wrong = spki;
    wrong[wrong.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateUntrusted,
        (ClientVerifier{ .pinned_raw_public_key = &spki })
            .verifyRawPublicKey("localhost", &.{&wrong}),
    );
    _ = allocator;
}

test "prepared RSA verifier matches generic TLS CertificateVerify" {
    const allocator = std.testing.allocator;
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate = decodeHex(vectors.certificate_hex);
    const private = try rsa.PrivateKey.fromDer(&private_der);
    var prepared_private = try private.prepare();
    defer prepared_private.deinit();
    const signer = Signer{ .rsa_pss = .{
        .prepared_key = &prepared_private,
        .signature_scheme = signature_scheme_rsa_pss_rsae_sha256,
        .io = std.testing.io,
    } };
    const transcript_hash = [_]u8{0x5c} ** Sha256.digest_length;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCertificateVerify(
        &encoded,
        allocator,
        signer,
        &transcript_hash,
    );
    const parsed = try parseCertificateVerify(encoded.items);
    try verifyCertificateVerify(
        &certificate,
        parsed,
        &transcript_hash,
    );

    const prepared = try PreparedRsaVerifier.init(
        &certificate,
        signature_scheme_rsa_pss_rsae_sha256,
    );
    try (ClientVerifier{ .prepared_rsa_verifier = &prepared })
        .verifyPeerCertificateVerify(
        &certificate,
        parsed,
        &transcript_hash,
        .server,
    );

    encoded.items[encoded.items.len - 1] ^= 1;
    const tampered = try parseCertificateVerify(encoded.items);
    try std.testing.expectError(
        error.BadCertificateVerify,
        (ClientVerifier{ .prepared_rsa_verifier = &prepared })
            .verifyPeerCertificateVerify(
            &certificate,
            tampered,
            &transcript_hash,
            .server,
        ),
    );
}

test "prepared RSA verifier matches generic TLS 1.2 PKCS1 verification" {
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate = decodeHex(vectors.certificate_hex);
    const private = try rsa.PrivateKey.fromDer(&private_der);
    var prepared_private = try private.prepare();
    defer prepared_private.deinit();
    const signer = Signer{ .rsa_pkcs1 = .{
        .prepared_key = &prepared_private,
        .signature_scheme = signature_scheme_rsa_pkcs1_sha256,
    } };
    const content = "TLS 1.2 signed handshake content";
    var signature: [max_classical_signature_len]u8 = undefined;
    const signature_len = try signer.sign(content, &signature);
    const parsed = ParsedCertificateVerify{
        .scheme = signature_scheme_rsa_pkcs1_sha256,
        .signature = signature[0..signature_len],
    };
    try verifyTls12SignedContent(&certificate, parsed, content);

    const prepared = try PreparedRsaVerifier.init(
        &certificate,
        signature_scheme_rsa_pkcs1_sha256,
    );
    try (ClientVerifier{ .prepared_rsa_verifier = &prepared })
        .verifyTls12Signature(&certificate, parsed, content);

    signature[signature_len - 1] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        (ClientVerifier{ .prepared_rsa_verifier = &prepared })
            .verifyTls12Signature(
            &certificate,
            .{
                .scheme = signature_scheme_rsa_pkcs1_sha256,
                .signature = signature[0..signature_len],
            },
            content,
        ),
    );
}

test "RFC 4055 constrained RSA-PSS SubjectPublicKeyInfo enforces its profile" {
    const allocator = std.testing.allocator;
    const spki = @embedFile(
        "../x509/testdata/rsa-pss-constrained.spki.der",
    );
    const signature_bytes = @embedFile(
        "../x509/testdata/rsa-pss-constrained-sha384.sig",
    );
    const message = "vail constrained RSA-PSS verification vector";
    try verifySignedContent(
        spki,
        .{
            .scheme = signature_scheme_rsa_pss_pss_sha384,
            .signature = signature_bytes,
        },
        message,
    );
    try std.testing.expectError(
        error.UnsupportedCertificateKey,
        verifySignedContent(
            spki,
            .{
                .scheme = signature_scheme_rsa_pss_pss_sha256,
                .signature = signature_bytes,
            },
            message,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedCertificateKey,
        verifySignedContent(
            spki,
            .{
                .scheme = signature_scheme_rsa_pss_rsae_sha384,
                .signature = signature_bytes,
            },
            message,
        ),
    );

    const excessive_salt = try allocator.dupe(u8, spki);
    defer allocator.free(excessive_salt);
    const encoded_salt = [_]u8{ 0xa2, 0x03, 0x02, 0x01, 0x20 };
    const salt_at = std.mem.indexOf(u8, excessive_salt, &encoded_salt) orelse
        return error.TestUnexpectedResult;
    excessive_salt[salt_at + encoded_salt.len - 1] = 64;
    try std.testing.expectError(
        error.UnsupportedCertificateKey,
        verifySignedContent(
            excessive_salt,
            .{
                .scheme = signature_scheme_rsa_pss_pss_sha384,
                .signature = signature_bytes,
            },
            message,
        ),
    );

    const certificate = @embedFile(
        "../x509/testdata/rsa-pss-constrained-leaf.der",
    );
    const private_key_der = @embedFile(
        "../crypto/testdata/rsa-pss-constrained-private.pkcs8.der",
    );
    const private_key = try rsa.PrivateKey.fromDer(private_key_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    try (ServerIdentity{
        .certificate_chain = &.{certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .signature_scheme = signature_scheme_rsa_pss_pss_sha384,
            .io = std.testing.io,
        } },
    }).validate();
    try std.testing.expectError(
        error.UnsupportedCertificateKey,
        (ServerIdentity{
            .certificate_chain = &.{certificate},
            .signer = .{ .rsa_pss = .{
                .prepared_key = &prepared_key,
                .signature_scheme = signature_scheme_rsa_pss_pss_sha256,
                .io = std.testing.io,
            } },
        }).validate(),
    );
}

test "TLS 1.2 RSA PKCS1 v1.5 signer supports SHA-256 SHA-384 and SHA-512" {
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate = decodeHex(vectors.certificate_hex);
    const private = try rsa.PrivateKey.fromDer(&private_der);
    var prepared = try private.prepare();
    defer prepared.deinit();
    const message = "tls12 rsa pkcs1 server key exchange";

    inline for (.{
        signature_scheme_rsa_pkcs1_sha256,
        signature_scheme_rsa_pkcs1_sha384,
        signature_scheme_rsa_pkcs1_sha512,
    }) |scheme| {
        const signer = Signer{ .rsa_pkcs1 = .{
            .prepared_key = &prepared,
            .signature_scheme = scheme,
        } };
        try (ServerIdentity{
            .certificate_chain = &.{&certificate},
            .signer = signer,
        }).validate();
        var signature: [max_certificate_verify_signature_len]u8 = undefined;
        const signature_len = try signer.sign(message, &signature);
        try verifyTls12SignedContent(
            &certificate,
            .{
                .scheme = scheme,
                .signature = signature[0..signature_len],
            },
            message,
        );
        signature[signature_len - 1] ^= 1;
        try std.testing.expectError(
            error.BadCertificateVerify,
            verifyTls12SignedContent(
                &certificate,
                .{
                    .scheme = scheme,
                    .signature = signature[0..signature_len],
                },
                message,
            ),
        );
    }

    var tls13_message: std.ArrayList(u8) = .empty;
    defer tls13_message.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.UnsupportedSignatureScheme,
        writeCertificateVerify(
            &tls13_message,
            std.testing.allocator,
            .{ .rsa_pkcs1 = .{ .prepared_key = &prepared } },
            &([_]u8{0x41} ** Sha256.digest_length),
        ),
    );
}

test "RFC 7250 elliptic-curve SubjectPublicKeyInfo signs and verifies" {
    const message = "rfc7250 elliptic curve possession";
    var signature: [max_certificate_verify_signature_len]u8 = undefined;

    const p256_key = try EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0xa1} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
    const p256_spki = p256SubjectPublicKeyInfo(
        p256_key.public_key.toUncompressedSec1(),
    );
    const p256_signer = Signer{ .ecdsa_p256_sha256 = .{
        .key_pair = p256_key,
    } };
    try (ServerIdentity{
        .certificate_chain = &.{&p256_spki},
        .signer = p256_signer,
        .certificate_type = .raw_public_key,
    }).validate();
    const p256_signature_len = try p256_signer.sign(message, &signature);
    try verifySignedContent(
        &p256_spki,
        .{
            .scheme = p256_signer.scheme(),
            .signature = signature[0..p256_signature_len],
        },
        message,
    );

    const p384_key = try EcdsaP384Sha384.KeyPair.generateDeterministic(
        [_]u8{0xa2} ** EcdsaP384Sha384.KeyPair.seed_length,
    );
    const p384_spki = p384SubjectPublicKeyInfo(
        p384_key.public_key.toUncompressedSec1(),
    );
    const p384_signer = Signer{ .ecdsa_p384_sha384 = .{
        .key_pair = p384_key,
    } };
    try (ServerIdentity{
        .certificate_chain = &.{&p384_spki},
        .signer = p384_signer,
        .certificate_type = .raw_public_key,
    }).validate();
    const p384_signature_len = try p384_signer.sign(message, &signature);
    try verifySignedContent(
        &p384_spki,
        .{
            .scheme = p384_signer.scheme(),
            .signature = signature[0..p384_signature_len],
        },
        message,
    );

    var p521_secret = try p521.SecretKey.fromBytes(decodeHex(
        "00123456789abcdef00112233445566778899aabbccddeeff1021324354657687" ++
            "98a9bacbdcedfe0f112233445566778899aabbccddeeff00123456789abcdef1234",
    ));
    defer p521_secret.deinit();
    var p521_key = try p521.KeyPair.fromSecretKey(p521_secret);
    defer p521_key.deinit();
    const p521_spki = p521SubjectPublicKeyInfo(
        p521_key.public_key.toUncompressedSec1(),
    );
    const p521_signer = Signer{ .ecdsa_p521_sha512 = .{
        .key_pair = &p521_key,
        .io = std.testing.io,
    } };
    try (ServerIdentity{
        .certificate_chain = &.{&p521_spki},
        .signer = p521_signer,
        .certificate_type = .raw_public_key,
    }).validate();
    const p521_signature_len = try p521_signer.sign(message, &signature);
    try verifySignedContent(
        &p521_spki,
        .{
            .scheme = p521_signer.scheme(),
            .signature = signature[0..p521_signature_len],
        },
        message,
    );

    const sm2_secret = try sm2.SecretKey.fromBytes(decodeHex(
        "3945208f7b2133b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
    ));
    const sm2_key = try sm2.KeyPair.fromSecretKey(sm2_secret);
    const sm2_spki = sm2SubjectPublicKeyInfo(
        sm2_key.public_key.toUncompressedSec1(),
    );
    const sm2_signer = Signer{ .sm2sig_sm3 = .{
        .key_pair = sm2_key,
        .nonce = decodeHex(
            "59276e27d506861a16680f3ad9c02dccccef3cc1fa3cdbe4ce6d54b80deac1bc",
        ),
    } };
    try (ServerIdentity{
        .certificate_chain = &.{&sm2_spki},
        .signer = sm2_signer,
        .certificate_type = .raw_public_key,
    }).validate();
    const sm2_signature_len = try sm2_signer.sign(message, &signature);
    try verifySignedContent(
        &sm2_spki,
        .{
            .scheme = sm2_signer.scheme(),
            .signature = signature[0..sm2_signature_len],
        },
        message,
    );
}

fn mlDsaSubjectPublicKeyInfo(
    comptime MlDsa: type,
    comptime oid: *const [9]u8,
    public_key: [MlDsa.PublicKey.encoded_length]u8,
) [22 + MlDsa.PublicKey.encoded_length]u8 {
    const body_len = 18 + MlDsa.PublicKey.encoded_length;
    const bit_string_len = 1 + MlDsa.PublicKey.encoded_length;
    comptime {
        std.debug.assert(body_len <= std.math.maxInt(u16));
        std.debug.assert(bit_string_len <= std.math.maxInt(u16));
    }
    var spki: [22 + MlDsa.PublicKey.encoded_length]u8 = undefined;
    spki[0] = 0x30;
    spki[1] = 0x82;
    std.mem.writeInt(u16, spki[2..4], body_len, .big);
    spki[4] = 0x30;
    spki[5] = 0x0b;
    spki[6] = 0x06;
    spki[7] = oid.len;
    @memcpy(spki[8..17], oid);
    spki[17] = 0x03;
    spki[18] = 0x82;
    std.mem.writeInt(u16, spki[19..21], bit_string_len, .big);
    spki[21] = 0;
    @memcpy(spki[22..], &public_key);
    return spki;
}

fn p256SubjectPublicKeyInfo(public_key: [65]u8) [91]u8 {
    var spki = [_]u8{
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07,
        0x2a, 0x86,
        0x48, 0xce,
        0x3d, 0x02,
        0x01, 0x06,
        0x08, 0x2a,
        0x86, 0x48,
        0xce, 0x3d,
        0x03, 0x01,
        0x07, 0x03,
        0x42, 0x00,
    } ++ ([_]u8{0} ** 65);
    @memcpy(spki[26..], &public_key);
    return spki;
}

fn p384SubjectPublicKeyInfo(public_key: [97]u8) [120]u8 {
    var spki = [_]u8{
        0x30, 0x76,
        0x30, 0x10,
        0x06, 0x07,
        0x2a, 0x86,
        0x48, 0xce,
        0x3d, 0x02,
        0x01, 0x06,
        0x05, 0x2b,
        0x81, 0x04,
        0x00, 0x22,
        0x03, 0x62,
        0x00,
    } ++ ([_]u8{0} ** 97);
    @memcpy(spki[23..], &public_key);
    return spki;
}

fn p521SubjectPublicKeyInfo(
    public_key: [p521.uncompressed_sec1_encoded_length]u8,
) [158]u8 {
    var spki = [_]u8{
        0x30, 0x81, 0x9b,
        0x30, 0x10, 0x06,
        0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06,
        0x05, 0x2b, 0x81,
        0x04, 0x00, 0x23,
        0x03, 0x81, 0x86,
        0x00,
    } ++ ([_]u8{0} ** p521.uncompressed_sec1_encoded_length);
    @memcpy(spki[25..], &public_key);
    return spki;
}

fn sm2SubjectPublicKeyInfo(public_key: [65]u8) [91]u8 {
    var spki = [_]u8{
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07,
        0x2a, 0x86,
        0x48, 0xce,
        0x3d, 0x02,
        0x01, 0x06,
        0x08, 0x2a,
        0x81, 0x1c,
        0xcf, 0x55,
        0x01, 0x82,
        0x2d, 0x03,
        0x42, 0x00,
    } ++ ([_]u8{0} ** 65);
    @memcpy(spki[26..], &public_key);
    return spki;
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var decoded: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, encoded) catch unreachable;
    return decoded;
}
