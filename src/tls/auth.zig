//! TLS 1.3 server Certificate and CertificateVerify helpers.
//!
//! The handshake codec is certificate-format agnostic. Built-in possession
//! verification supports Ed25519, ECDSA P-256/P-384, SM2, and RSA-PSS X.509
//! CertificateVerify. An allocation-free signer callback supports additional
//! pure-Zig or hardware-backed private-key implementations. Applications can
//! separately provide a trust callback for chain, validity, EKU, and policy.

const std = @import("std");

const rsa = @import("../crypto/rsa.zig");
const sm2 = @import("../crypto/sm2.zig");
const Certificate = std.crypto.Certificate;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const EcdsaP256Sha384 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    std.crypto.hash.sha2.Sha384,
);
const EcdsaP384Sha256 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P384,
    std.crypto.hash.sha2.Sha256,
);
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const signature_scheme_ecdsa_secp256r1_sha256: u16 = 0x0403;
pub const signature_scheme_ecdsa_secp384r1_sha384: u16 = 0x0503;
pub const signature_scheme_rsa_pss_rsae_sha256: u16 = 0x0804;
pub const signature_scheme_rsa_pss_rsae_sha384: u16 = 0x0805;
pub const signature_scheme_rsa_pss_rsae_sha512: u16 = 0x0806;
pub const signature_scheme_ed25519: u16 = 0x0807;
pub const signature_scheme_rsa_pss_pss_sha256: u16 = 0x0809;
pub const signature_scheme_rsa_pss_pss_sha384: u16 = 0x080a;
pub const signature_scheme_rsa_pss_pss_sha512: u16 = 0x080b;
pub const signature_scheme_sm2sig_sm3: u16 = 0x0708;
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

pub const max_certificate_verify_signature_len: usize = 512;

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
    sm2sig_sm3: struct {
        key_pair: sm2.KeyPair,
        /// Must be fresh for each SM2 signature.
        nonce: [sm2.scalar_len]u8,
    },
    rsa_pss: RsaPssSigner,
    /// Allocation-free extension point for pure-Zig software keys, hardware
    /// keys, or signature schemes whose private-key operation is not provided
    /// by Zig std. TLS framing and transcript construction remain inside Vail.
    custom: CustomSigner,

    pub fn scheme(self: Signer) u16 {
        return switch (self) {
            .ed25519 => signature_scheme_ed25519,
            .ecdsa_p256_sha256 => signature_scheme_ecdsa_secp256r1_sha256,
            .ecdsa_p384_sha384 => signature_scheme_ecdsa_secp384r1_sha384,
            .sm2sig_sm3 => signature_scheme_sm2sig_sm3,
            .rsa_pss => |rsa_signer| rsa_signer.signature_scheme,
            .custom => |custom| custom.signature_scheme,
        };
    }

    fn validateCertificate(
        self: Signer,
        certificate: []const u8,
    ) Error!void {
        switch (self) {
            .ed25519 => |signer| {
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
            .sm2sig_sm3 => |signer| {
                const leaf_key = try sm2CertificatePublicKey(certificate);
                const signing_key =
                    signer.key_pair.public_key.toUncompressedSec1();
                if (!std.mem.eql(u8, &leaf_key, &signing_key)) {
                    return error.InvalidCertificate;
                }
            },
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
                const signature = ed.key_pair.sign(
                    content,
                    ed.noise,
                ) catch return error.InvalidCertificateVerify;
                const bytes = signature.toBytes();
                @memcpy(output[0..bytes.len], &bytes);
                break :blk bytes.len;
            },
            .ecdsa_p256_sha256 => |ecdsa| blk: {
                const signature = ecdsa.key_pair.sign(
                    content,
                    ecdsa.noise,
                ) catch return error.InvalidCertificateVerify;
                var der: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 =
                    undefined;
                const encoded = signature.toDer(&der);
                if (output.len < encoded.len) {
                    return error.InvalidCertificateVerify;
                }
                @memcpy(output[0..encoded.len], encoded);
                break :blk encoded.len;
            },
            .ecdsa_p384_sha384 => |ecdsa| blk: {
                const signature = ecdsa.key_pair.sign(
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

pub const TrustContext = struct {
    server_name: ?[]const u8,
    chain: []const []const u8,
    ocsp_response: ?[]const u8 = null,
};

pub const TrustCallback = *const fn (
    context: ?*anyopaque,
    trust: TrustContext,
) anyerror!void;

pub const ClientVerifier = struct {
    /// The callback owns X.509 chain/path/time/hostname/EKU policy. The codec
    /// always verifies CertificateVerify possession independently afterward.
    verify_trust: ?TrustCallback = null,
    context: ?*anyopaque = null,
    pinned_ed25519_public_key: ?[Ed25519.PublicKey.encoded_length]u8 = null,
    pinned_ecdsa_p256_public_key: ?[EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 = null,
    pinned_ecdsa_p384_public_key: ?[EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length]u8 = null,
    pinned_sm2_public_key: ?[sm2.public_key_len]u8 = null,
    /// DER RSAPublicKey bytes from X.509 SubjectPublicKeyInfo's BIT STRING
    /// payload (not the complete SubjectPublicKeyInfo). The caller retains
    /// ownership.
    pinned_rsa_public_key: ?[]const u8 = null,
    /// Exact DER SubjectPublicKeyInfo pin used with RFC 7250.
    pinned_raw_public_key: ?[]const u8 = null,

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
        if (chain.len == 0) return error.EmptyCertificateChain;
        if (self.verify_trust) |verify| {
            verify(self.context, .{
                .server_name = server_name,
                .chain = chain,
                .ocsp_response = ocsp_response,
            }) catch return error.CertificateUntrusted;
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
};

pub const ParsedCertificate = struct {
    entries: [][]const u8,
    ocsp_response: ?[]const u8 = null,

    pub fn deinit(self: *ParsedCertificate, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
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
    );
}

pub fn writeCertificateWithOcsp(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    ocsp_response: []const u8,
) Error!void {
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
    );
}

fn writeCertificateEntriesWithContext(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
    request_context: []const u8,
    leaf_ocsp_response: ?[]const u8,
) Error!void {
    if (request_context.len > std.math.maxInt(u8)) {
        return error.InvalidCertificate;
    }
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
        if (index == 0 and leaf_ocsp_response != null) {
            const response = leaf_ocsp_response.?;
            try appendInt(
                &entries,
                allocator,
                u16,
                2 + 2 + 1 + 3 + response.len,
            );
            try appendInt(&entries, allocator, u16, 0x0005);
            try appendInt(
                &entries,
                allocator,
                u16,
                1 + 3 + response.len,
            );
            try entries.append(allocator, 1);
            var response_len: [3]u8 = undefined;
            writeU24(&response_len, @intCast(response.len));
            try entries.appendSlice(allocator, &response_len);
            try entries.appendSlice(allocator, response);
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
    var ocsp_response: ?[]const u8 = null;
    errdefer entries.deinit(allocator);
    while (pos < entries_end) {
        const cert_len = try readU24At(bytes, &pos);
        if (cert_len == 0) return error.InvalidCertificate;
        const cert = try readSlice(bytes, &pos, cert_len);
        const extensions_len = try readInt(u16, bytes, &pos);
        const extensions = try readSlice(bytes, &pos, extensions_len);
        if (entries.items.len == 0) {
            ocsp_response = try parseCertificateEntryExtensions(extensions);
        } else if (try parseCertificateEntryExtensions(extensions) != null) {
            return error.InvalidCertificate;
        }
        try entries.append(allocator, cert);
    }
    if (!allow_empty and entries.items.len == 0) {
        return error.EmptyCertificateChain;
    }
    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .ocsp_response = ocsp_response,
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
    var signature_storage: [max_certificate_verify_signature_len]u8 =
        undefined;
    const signature_len = try signer.sign(content, &signature_storage);
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
        scheme == signature_scheme_rsa_pss_rsae_sha256 or
        scheme == signature_scheme_rsa_pss_rsae_sha384 or
        scheme == signature_scheme_rsa_pss_rsae_sha512 or
        scheme == signature_scheme_rsa_pss_pss_sha256 or
        scheme == signature_scheme_rsa_pss_pss_sha384 or
        scheme == signature_scheme_rsa_pss_pss_sha512 or
        scheme == signature_scheme_sm2sig_sm3;
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
        scheme != signature_scheme_rsa_pss_rsae_sha256 and
        scheme != signature_scheme_rsa_pss_rsae_sha384 and
        scheme != signature_scheme_rsa_pss_rsae_sha512 and
        scheme != signature_scheme_rsa_pss_pss_sha256 and
        scheme != signature_scheme_rsa_pss_pss_sha384 and
        scheme != signature_scheme_rsa_pss_pss_sha512 and
        scheme != signature_scheme_sm2sig_sm3)
    {
        return error.UnsupportedSignatureScheme;
    }
    const signature_len = try readInt(u16, bytes, &pos);
    if ((scheme == signature_scheme_ed25519 and
        signature_len != Ed25519.Signature.encoded_length) or
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
            signature.verify(content, public_key) catch
                return error.BadCertificateVerify;
        },
        signature_scheme_ecdsa_secp256r1_sha256 => {
            const public_key_bytes =
                try p256CertificatePublicKey(certificate);
            const public_key = EcdsaP256Sha256.PublicKey.fromSec1(
                &public_key_bytes,
            ) catch return error.InvalidCertificate;
            const signature = EcdsaP256Sha256.Signature.fromDer(
                parsed.signature,
            ) catch return error.InvalidCertificateVerify;
            var verifier = signature.verifier(public_key) catch
                return error.BadCertificateVerify;
            verifier.update(content);
            verifier.verify() catch return error.BadCertificateVerify;
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
            var verifier = signature.verifier(public_key) catch
                return error.BadCertificateVerify;
            verifier.update(content);
            verifier.verify() catch return error.BadCertificateVerify;
        },
        signature_scheme_rsa_pss_rsae_sha256 => try verifyRsaPssContent(
            Sha256,
            .rsaEncryption,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_rsae_sha384 => try verifyRsaPssContent(
            Sha384,
            .rsaEncryption,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_rsae_sha512 => try verifyRsaPssContent(
            Sha512,
            .rsaEncryption,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_pss_sha256 => try verifyRsaPssContent(
            Sha256,
            .rsassa_pss,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_pss_sha384 => try verifyRsaPssContent(
            Sha384,
            .rsassa_pss,
            certificate,
            parsed.signature,
            content,
        ),
        signature_scheme_rsa_pss_pss_sha512 => try verifyRsaPssContent(
            Sha512,
            .rsassa_pss,
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

/// TLS 1.2 ECDSA SignatureScheme values bind only the hash and signature
/// algorithm; unlike TLS 1.3, they do not constrain the certificate curve.
/// RSA-PSS and Ed25519 retain their ordinary scheme semantics.
pub fn verifyTls12SignedContent(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    content: []const u8,
) Error!void {
    switch (parsed.scheme) {
        signature_scheme_ecdsa_secp256r1_sha256 => {
            const curve = try certificateCurve(certificate);
            switch (curve) {
                .p256 => try verifyEcdsaContent(
                    EcdsaP256Sha256,
                    &try p256CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p384 => try verifyEcdsaContent(
                    EcdsaP384Sha256,
                    &try p384CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
            }
        },
        signature_scheme_ecdsa_secp384r1_sha384 => {
            const curve = try certificateCurve(certificate);
            switch (curve) {
                .p256 => try verifyEcdsaContent(
                    EcdsaP256Sha384,
                    &try p256CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
                .p384 => try verifyEcdsaContent(
                    EcdsaP384Sha384,
                    &try p384CertificatePublicKey(certificate),
                    parsed.signature,
                    content,
                ),
            }
        },
        else => try verifySignedContent(certificate, parsed, content),
    }
}

const CertificateCurve = enum { p256, p384 };

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
    if (try parseRawSpki(certificate)) |spki| {
        return switch (spki.kind) {
            .p256 => .p256,
            .p384 => .p384,
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
        else => error.UnsupportedCertificateKey,
    };
}

fn verifyEcdsaContent(
    comptime Ecdsa: type,
    public_key_bytes: []const u8,
    signature_bytes: []const u8,
    content: []const u8,
) Error!void {
    const public_key = Ecdsa.PublicKey.fromSec1(public_key_bytes) catch
        return error.InvalidCertificate;
    const signature = Ecdsa.Signature.fromDer(signature_bytes) catch
        return error.InvalidCertificateVerify;
    signature.verify(content, public_key) catch
        return error.BadCertificateVerify;
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
            var verifier = signature.verifier(public_key) catch
                return error.BadCertificateVerify;
            updateCertificateVerifyInput(&verifier, transcript_hash, role);
            verifier.verify() catch return error.BadCertificateVerify;
        },
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
            var verifier = signature.verifier(public_key) catch
                return error.BadCertificateVerify;
            updateCertificateVerifyInput(&verifier, transcript_hash, role);
            verifier.verify() catch return error.BadCertificateVerify;
        },
        signature_scheme_rsa_pss_rsae_sha256 => try verifyRsaPss(
            Sha256,
            .rsaEncryption,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_rsae_sha384 => try verifyRsaPss(
            Sha384,
            .rsaEncryption,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_rsae_sha512 => try verifyRsaPss(
            Sha512,
            .rsaEncryption,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_pss_sha256 => try verifyRsaPss(
            Sha256,
            .rsassa_pss,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_pss_sha384 => try verifyRsaPss(
            Sha384,
            .rsassa_pss,
            certificate,
            parsed.signature,
            transcript_hash,
            role,
        ),
        signature_scheme_rsa_pss_pss_sha512 => try verifyRsaPss(
            Sha512,
            .rsassa_pss,
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
    certificate: []const u8,
    signature_bytes: []const u8,
    transcript_hash: []const u8,
    role: EndpointRole,
) Error!void {
    const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
        certificate,
        expected_key_algorithm,
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
    certificate: []const u8,
    signature_bytes: []const u8,
    content: []const u8,
) Error!void {
    const public_key_der = try rsaCertificatePublicKeyForAlgorithm(
        certificate,
        expected_key_algorithm,
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
    const P256 = std.crypto.ecc.P256;
    const Scalar = P256.scalar.Scalar;

    const r = try Scalar.fromBytes(signature.r, .big);
    const s = try Scalar.fromBytes(signature.s, .big);
    if (r.isZero() or s.isZero()) return error.IdentityElement;

    var hasher = Sha256.init(.{});
    updateCertificateVerifyInput(&hasher, transcript_hash, role);
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    const z = scalarFromDigest(digest);
    if (z.isZero()) return error.SignatureVerificationFailed;

    const s_inv = s.invert();
    const v1 = z.mul(s_inv).toBytes(.little);
    const v2 = r.mul(s_inv).toBytes(.little);
    const point = try P256.mulDoubleBasePublic(
        P256.basePoint,
        v1,
        public_key.p,
        v2,
        .little,
    );
    const x = point.affineCoordinates().x.toBytes(.big);
    if (!r.equivalent(scalarFromDigest(x))) {
        return error.SignatureVerificationFailed;
    }
}

fn scalarFromDigest(bytes: [32]u8) std.crypto.ecc.P256.scalar.Scalar {
    return std.crypto.ecc.P256.scalar.Scalar.fromBytes48(
        [_]u8{0} ** 16 ++ bytes,
        .big,
    );
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
const oid_p256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_p384 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };

const RawSpkiKind = enum {
    rsa_encryption,
    rsa_pss,
    ed25519,
    p256,
    p384,
    sm2,
};

const RawSpki = struct {
    kind: RawSpkiKind,
    public_key: []const u8,
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
    else if (oidEquals(bytes, oid, &oid_id_ec_public_key)) blk: {
        const parameters = DerElement.parse(bytes, pos) catch
            return error.InvalidCertificate;
        if (parameters.tag != 0x06) return error.InvalidCertificate;
        pos = parameters.end;
        if (oidEquals(bytes, parameters, &oid_p256)) break :blk .p256;
        if (oidEquals(bytes, parameters, &oid_p384)) break :blk .p384;
        if (oidEquals(bytes, parameters, &oid_sm2)) break :blk .sm2;
        return error.UnsupportedCertificateKey;
    } else return null;
    while (pos < algorithm.end) {
        const parameter = try DerElement.parse(bytes, pos);
        pos = parameter.end;
        if (kind == .ed25519 or kind == .p256 or kind == .p384 or
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
    };
}

fn rsaCertificatePublicKey(certificate: []const u8) Error![]const u8 {
    return rsaCertificatePublicKeyForAlgorithm(
        certificate,
        .rsaEncryption,
    );
}

fn sm3DigestLen() usize {
    return @import("../crypto/sm3.zig").digest_len;
}

fn rsaCertificatePublicKeyForAlgorithm(
    certificate: []const u8,
    expected: Certificate.AlgorithmCategory,
) Error![]const u8 {
    if (try parseRawSpki(certificate)) |spki| {
        const matches = switch (expected) {
            .rsaEncryption => spki.kind == .rsa_encryption,
            .rsassa_pss => spki.kind == .rsa_pss,
            else => false,
        };
        if (!matches) return error.UnsupportedCertificateKey;
        _ = Certificate.rsa.PublicKey.parseDer(spki.public_key) catch
            return error.InvalidCertificate;
        return spki.public_key;
    }
    const parsed = try parseX509(certificate);
    if (std.meta.activeTag(parsed.pub_key_algo) != expected) {
        return error.UnsupportedCertificateKey;
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
    return Certificate.parse(.{
        .buffer = certificate,
        .index = 0,
    }) catch return error.InvalidCertificate;
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

    try std.testing.expectError(
        error.InvalidCertificate,
        writeCertificateWithOcsp(
            &encoded,
            allocator,
            &.{"leaf"},
            &.{},
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
