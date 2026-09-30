//! Shared X.509-family signature AlgorithmIdentifier parsing and verification.
//!
//! RSA-PSS parameters are deliberately constrained to the interoperable
//! SHA-2 profile implemented by Zig's standard library: MGF1 uses the same
//! hash, the salt is one digest long, and trailerField is the default value 1.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

const oid_ecdsa_sha256 = [_]u8{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
};
const oid_ecdsa_sha384 = [_]u8{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
};
const oid_rsa_sha256 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
};
const oid_rsa_sha384 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
};
const oid_rsa_sha512 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
};
const oid_rsassa_pss = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
};
const oid_mgf1 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
};
const oid_sha256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
};
const oid_sha384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
};
const oid_sha512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
};
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

pub const Error = error{
    InvalidAlgorithmIdentifier,
    UnsupportedSignatureAlgorithm,
    InvalidIssuer,
    InvalidSignature,
};

pub const Algorithm = enum {
    ecdsa_p256_sha256,
    ecdsa_p384_sha384,
    rsa_pkcs1_sha256,
    rsa_pkcs1_sha384,
    rsa_pkcs1_sha512,
    rsa_pss_sha256,
    rsa_pss_sha384,
    rsa_pss_sha512,
    ed25519,
};

const PssHash = enum {
    sha256,
    sha384,
    sha512,

    fn digestLength(self: PssHash) usize {
        return switch (self) {
            .sha256 => Sha256.digest_length,
            .sha384 => Sha384.digest_length,
            .sha512 => Sha512.digest_length,
        };
    }

    fn signatureAlgorithm(self: PssHash) Algorithm {
        return switch (self) {
            .sha256 => .rsa_pss_sha256,
            .sha384 => .rsa_pss_sha384,
            .sha512 => .rsa_pss_sha512,
        };
    }
};

/// Parse the contents of an ASN.1 AlgorithmIdentifier SEQUENCE.
pub fn parseAlgorithmIdentifier(encoded: []const u8) Error!Algorithm {
    var fields = Reader{ .bytes = encoded };
    const oid = fields.require(0x06) catch
        return error.InvalidAlgorithmIdentifier;
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha256)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_p256_sha256;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha384)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_p384_sha384;
    }
    if (std.mem.eql(u8, oid.value, &oid_rsa_sha256) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha384) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha512))
    {
        const parameters = (fields.next() catch
            return error.InvalidAlgorithmIdentifier) orelse
            return error.InvalidAlgorithmIdentifier;
        if (parameters.tag != 0x05 or parameters.value.len != 0 or
            !fields.done())
        {
            return error.InvalidAlgorithmIdentifier;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha256)) {
            return .rsa_pkcs1_sha256;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha384)) {
            return .rsa_pkcs1_sha384;
        }
        return .rsa_pkcs1_sha512;
    }
    if (std.mem.eql(u8, oid.value, &oid_rsassa_pss)) {
        const parameters = (fields.next() catch
            return error.InvalidAlgorithmIdentifier) orelse
            return error.InvalidAlgorithmIdentifier;
        if (parameters.tag != 0x30 or !fields.done()) {
            return error.InvalidAlgorithmIdentifier;
        }
        return parsePssParameters(parameters.value);
    }
    if (std.mem.eql(u8, oid.value, &oid_ed25519)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ed25519;
    }
    return error.UnsupportedSignatureAlgorithm;
}

pub fn verify(
    algorithm: Algorithm,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    switch (algorithm) {
        .ecdsa_p256_sha256 => try verifyEcdsa(
            EcdsaP256Sha256,
            .X9_62_prime256v1,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_p384_sha384 => try verifyEcdsa(
            EcdsaP384Sha384,
            .secp384r1,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha256 => try verifyRsaPkcs1(
            Sha256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha384 => try verifyRsaPkcs1(
            Sha384,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha512 => try verifyRsaPkcs1(
            Sha512,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha256 => try verifyRsaPss(
            Sha256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha384 => try verifyRsaPss(
            Sha384,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha512 => try verifyRsaPss(
            Sha512,
            issuer,
            message,
            signature_bytes,
        ),
        .ed25519 => try verifyEd25519(issuer, message, signature_bytes),
    }
}

fn parsePssParameters(encoded: []const u8) Error!Algorithm {
    var fields = Reader{ .bytes = encoded };
    var hash: ?PssHash = null;
    var mask_hash: ?PssHash = null;
    var salt_length: usize = 20;
    var trailer_field: usize = 1;
    var previous_tag: u8 = 0x9f;
    while (fields.next() catch
        return error.InvalidAlgorithmIdentifier) |field|
    {
        if (field.tag < 0xa0 or field.tag > 0xa3 or
            (previous_tag != 0x9f and field.tag <= previous_tag))
        {
            return error.InvalidAlgorithmIdentifier;
        }
        previous_tag = field.tag;
        switch (field.tag) {
            0xa0 => hash = try parseExplicitHashAlgorithm(field),
            0xa1 => mask_hash = try parseExplicitMaskAlgorithm(field),
            0xa2 => salt_length = try parseExplicitSmallInteger(field),
            0xa3 => trailer_field = try parseExplicitSmallInteger(field),
            else => unreachable,
        }
    }
    const selected_hash = hash orelse
        return error.UnsupportedSignatureAlgorithm;
    const selected_mask_hash = mask_hash orelse
        return error.UnsupportedSignatureAlgorithm;
    if (selected_mask_hash != selected_hash or
        salt_length != selected_hash.digestLength() or trailer_field != 1)
    {
        return error.UnsupportedSignatureAlgorithm;
    }
    return selected_hash.signatureAlgorithm();
}

fn parseExplicitHashAlgorithm(field: Element) Error!PssHash {
    var explicit = Reader{ .bytes = field.value };
    const algorithm = explicit.require(0x30) catch
        return error.InvalidAlgorithmIdentifier;
    if (!explicit.done()) return error.InvalidAlgorithmIdentifier;
    return parseHashAlgorithm(algorithm.value);
}

fn parseExplicitMaskAlgorithm(field: Element) Error!PssHash {
    var explicit = Reader{ .bytes = field.value };
    const algorithm = explicit.require(0x30) catch
        return error.InvalidAlgorithmIdentifier;
    if (!explicit.done()) return error.InvalidAlgorithmIdentifier;
    var fields = Reader{ .bytes = algorithm.value };
    const oid = fields.require(0x06) catch
        return error.InvalidAlgorithmIdentifier;
    if (!std.mem.eql(u8, oid.value, &oid_mgf1)) {
        return error.UnsupportedSignatureAlgorithm;
    }
    const parameters = fields.require(0x30) catch
        return error.InvalidAlgorithmIdentifier;
    if (!fields.done()) return error.InvalidAlgorithmIdentifier;
    return parseHashAlgorithm(parameters.value);
}

fn parseHashAlgorithm(encoded: []const u8) Error!PssHash {
    var fields = Reader{ .bytes = encoded };
    const oid = fields.require(0x06) catch
        return error.InvalidAlgorithmIdentifier;
    const hash: PssHash = if (std.mem.eql(u8, oid.value, &oid_sha256))
        .sha256
    else if (std.mem.eql(u8, oid.value, &oid_sha384))
        .sha384
    else if (std.mem.eql(u8, oid.value, &oid_sha512))
        .sha512
    else
        return error.UnsupportedSignatureAlgorithm;
    if (fields.next() catch return error.InvalidAlgorithmIdentifier) |parameters| {
        if (parameters.tag != 0x05 or parameters.value.len != 0 or
            !fields.done())
        {
            return error.InvalidAlgorithmIdentifier;
        }
    }
    return hash;
}

fn parseExplicitSmallInteger(field: Element) Error!usize {
    var explicit = Reader{ .bytes = field.value };
    const integer = explicit.require(0x02) catch
        return error.InvalidAlgorithmIdentifier;
    if (!explicit.done() or integer.value.len == 0 or
        (integer.value[0] & 0x80) != 0 or
        (integer.value.len > 1 and integer.value[0] == 0 and
            (integer.value[1] & 0x80) == 0) or
        integer.value.len > @sizeOf(usize))
    {
        return error.InvalidAlgorithmIdentifier;
    }
    var result: usize = 0;
    for (integer.value) |byte| {
        result = std.math.mul(usize, result, 256) catch
            return error.InvalidAlgorithmIdentifier;
        result = std.math.add(usize, result, byte) catch
            return error.InvalidAlgorithmIdentifier;
    }
    return result;
}

fn verifyEcdsa(
    comptime Scheme: type,
    comptime expected_curve: Certificate.NamedCurve,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    const public_key = switch (issuer.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| if (curve == expected_curve)
            Scheme.PublicKey.fromSec1(issuer.pubKey()) catch
                return error.InvalidIssuer
        else
            return error.UnsupportedSignatureAlgorithm,
        else => return error.UnsupportedSignatureAlgorithm,
    };
    const signature = Scheme.Signature.fromDer(signature_bytes) catch
        return error.InvalidSignature;
    signature.verify(message, public_key) catch
        return error.InvalidSignature;
}

fn verifyRsaPkcs1(
    comptime Hash: type,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    if (issuer.pub_key_algo != .rsaEncryption) {
        return error.UnsupportedSignatureAlgorithm;
    }
    const public_key = try rsaPublicKey(issuer);
    switch (public_key.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (signature_bytes.len != modulus_len) {
                return error.InvalidSignature;
            }
            const parsed = Certificate.rsa.PublicKey.fromBytes(
                public_key.exponent,
                public_key.modulus,
            ) catch return error.InvalidIssuer;
            Certificate.rsa.PKCS1v1_5Signature.verify(
                modulus_len,
                signature_bytes[0..modulus_len].*,
                message,
                parsed,
                Hash,
            ) catch return error.InvalidSignature;
        },
        else => return error.UnsupportedSignatureAlgorithm,
    }
}

fn verifyRsaPss(
    comptime Hash: type,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    // RSASSA-PSS SubjectPublicKeyInfo can carry independent hash/MGF/salt
    // restrictions. Until those key parameters are retained by the standard
    // certificate parser, accept PSS signatures only with unrestricted
    // rsaEncryption keys rather than silently bypassing key constraints.
    if (issuer.pub_key_algo != .rsaEncryption) {
        return error.UnsupportedSignatureAlgorithm;
    }
    const public_key = try rsaPublicKey(issuer);
    switch (public_key.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (signature_bytes.len != modulus_len) {
                return error.InvalidSignature;
            }
            const parsed = Certificate.rsa.PublicKey.fromBytes(
                public_key.exponent,
                public_key.modulus,
            ) catch return error.InvalidIssuer;
            const signature = Certificate.rsa.PSSSignature.fromBytes(
                modulus_len,
                signature_bytes,
            );
            Certificate.rsa.PSSSignature.verify(
                modulus_len,
                signature,
                message,
                parsed,
                Hash,
            ) catch return error.InvalidSignature;
        },
        else => return error.UnsupportedSignatureAlgorithm,
    }
}

fn rsaPublicKey(
    issuer: Certificate.Parsed,
) Error!RsaPublicKeyParts {
    const parsed = Certificate.rsa.PublicKey.parseDer(issuer.pubKey()) catch
        return error.InvalidIssuer;
    return .{ .modulus = parsed.modulus, .exponent = parsed.exponent };
}

const RsaPublicKeyParts = struct {
    modulus: []const u8,
    exponent: []const u8,
};

fn verifyEd25519(
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    if (issuer.pub_key_algo != .curveEd25519 or
        issuer.pubKey().len != Ed25519.PublicKey.encoded_length or
        signature_bytes.len != Ed25519.Signature.encoded_length)
    {
        return error.UnsupportedSignatureAlgorithm;
    }
    const public_key = Ed25519.PublicKey.fromBytes(
        issuer.pubKey()[0..Ed25519.PublicKey.encoded_length].*,
    ) catch return error.InvalidIssuer;
    const signature = Ed25519.Signature.fromBytes(
        signature_bytes[0..Ed25519.Signature.encoded_length].*,
    );
    signature.verify(message, public_key) catch
        return error.InvalidSignature;
}

const Element = struct {
    tag: u8,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn require(self: *Reader, tag: u8) !Element {
        const value = (try self.next()) orelse return error.InvalidDer;
        if (value.tag != tag) return error.InvalidDer;
        return value;
    }

    fn next(self: *Reader) !?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidDer;
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
        const value = self.bytes[self.offset .. self.offset + length];
        self.offset += length;
        return .{ .tag = tag, .value = value };
    }

    fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

test "RSA-PSS AlgorithmIdentifier requires a matching digest-length MGF1 profile" {
    const sha256_pss = [_]u8{
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60,
        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60,
        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0xa2, 0x03, 0x02, 0x01, 0x20,
    };
    try std.testing.expectEqual(
        Algorithm.rsa_pss_sha256,
        try parseAlgorithmIdentifier(&sha256_pss),
    );
    var wrong_salt = sha256_pss;
    wrong_salt[wrong_salt.len - 1] = 31;
    try std.testing.expectError(
        error.UnsupportedSignatureAlgorithm,
        parseAlgorithmIdentifier(&wrong_salt),
    );
    var wrong_mgf = sha256_pss;
    wrong_mgf[57] = 2;
    try std.testing.expectError(
        error.UnsupportedSignatureAlgorithm,
        parseAlgorithmIdentifier(&wrong_mgf),
    );
}
