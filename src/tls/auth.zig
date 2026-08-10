//! TLS 1.3 server Certificate and CertificateVerify helpers.
//!
//! The handshake codec is certificate-format agnostic, while the built-in
//! Built-in possession verification supports Ed25519, ECDSA P-256, and
//! RSA-PSS/RSAE SHA-256 X.509 leaves. Applications can additionally provide a
//! trust callback for chain, validity, EKU, and policy validation.

const std = @import("std");

const sm2 = @import("../crypto/sm2.zig");
const Certificate = std.crypto.Certificate;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
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

pub const ServerIdentity = struct {
    /// DER-encoded leaf-first certificate chain. Raw Ed25519 and uncompressed
    /// P-256 SEC1 public keys are accepted for compact pinned-key deployments.
    certificate_chain: []const []const u8,
    signer: Signer,

    pub fn validate(self: ServerIdentity) Error!void {
        if (self.certificate_chain.len == 0) {
            return error.EmptyCertificateChain;
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

    pub fn scheme(self: Signer) u16 {
        return switch (self) {
            .ed25519 => signature_scheme_ed25519,
            .ecdsa_p256_sha256 => signature_scheme_ecdsa_secp256r1_sha256,
            .ecdsa_p384_sha384 => signature_scheme_ecdsa_secp384r1_sha384,
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
        }
    }
};

pub const TrustContext = struct {
    server_name: ?[]const u8,
    chain: []const []const u8,
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

    pub fn verifyTrust(
        self: ClientVerifier,
        server_name: ?[]const u8,
        chain: []const []const u8,
    ) Error!void {
        if (chain.len == 0) return error.EmptyCertificateChain;
        if (self.verify_trust) |verify| {
            verify(self.context, .{
                .server_name = server_name,
                .chain = chain,
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
};

pub const ParsedCertificate = struct {
    entries: [][]const u8,

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
    if (request_context.len > std.math.maxInt(u8)) {
        return error.InvalidCertificate;
    }
    const original_len = list.items.len;
    errdefer list.items.len = original_len;

    var entries: std.ArrayList(u8) = .empty;
    defer entries.deinit(allocator);
    for (chain) |cert| {
        if (cert.len == 0 or cert.len > std.math.maxInt(u24)) {
            return error.CertificateTooLarge;
        }
        var cert_len: [3]u8 = undefined;
        writeU24(&cert_len, @intCast(cert.len));
        try entries.appendSlice(allocator, &cert_len);
        try entries.appendSlice(allocator, cert);
        // Per-certificate extensions are intentionally empty.
        try entries.appendSlice(allocator, &.{ 0, 0 });
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
    while (pos < entries_end) {
        const cert_len = try readU24At(bytes, &pos);
        if (cert_len == 0) return error.InvalidCertificate;
        const cert = try readSlice(bytes, &pos, cert_len);
        const extensions_len = try readInt(u16, bytes, &pos);
        _ = try readSlice(bytes, &pos, extensions_len);
        try entries.append(allocator, cert);
    }
    if (entries.items.len == 0) return error.EmptyCertificateChain;
    return .{ .entries = try entries.toOwnedSlice(allocator) };
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
            std.crypto.hash.sha2.Sha384.digest_length
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
    var signature_storage: [
        @max(
            EcdsaP256Sha256.Signature.der_encoded_length_max,
            EcdsaP384Sha384.Signature.der_encoded_length_max,
        )
    ]u8 = undefined;
    const signature_bytes: []const u8 = switch (signer) {
        .ed25519 => |ed| blk: {
            const signature = ed.key_pair.sign(
                content,
                ed.noise,
            ) catch return error.InvalidCertificateVerify;
            const bytes = signature.toBytes();
            @memcpy(signature_storage[0..bytes.len], &bytes);
            break :blk signature_storage[0..bytes.len];
        },
        .ecdsa_p256_sha256 => |ecdsa| blk: {
            const signature = ecdsa.key_pair.sign(
                content,
                ecdsa.noise,
            ) catch return error.InvalidCertificateVerify;
            var der: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 =
                undefined;
            const encoded = signature.toDer(&der);
            @memcpy(signature_storage[0..encoded.len], encoded);
            break :blk signature_storage[0..encoded.len];
        },
        .ecdsa_p384_sha384 => |ecdsa| blk: {
            const signature = ecdsa.key_pair.sign(
                content,
                ecdsa.noise,
            ) catch return error.InvalidCertificateVerify;
            var der: [EcdsaP384Sha384.Signature.der_encoded_length_max]u8 =
                undefined;
            const encoded = signature.toDer(&der);
            @memcpy(signature_storage[0..encoded.len], encoded);
            break :blk signature_storage[0..encoded.len];
        },
    };

    const body_len = 2 + 2 + signature_bytes.len;
    try list.append(allocator, handshake_type_certificate_verify);
    var body_len_bytes: [3]u8 = undefined;
    writeU24(&body_len_bytes, @intCast(body_len));
    try list.appendSlice(allocator, &body_len_bytes);
    try appendInt(list, allocator, u16, signer.scheme());
    try appendInt(list, allocator, u16, signature_bytes.len);
    try list.appendSlice(allocator, signature_bytes);
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
            var verifier = signature.verifier(public_key) catch
                return error.BadCertificateVerify;
            updateCertificateVerifyInput(&verifier, transcript_hash, role);
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
