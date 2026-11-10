//! Shared X.509-family signature AlgorithmIdentifier parsing and verification.
//!
//! RSA-PSS parameters are deliberately constrained to interoperable profiles:
//! traditional PSS uses MGF1 with the same hash, RFC 8692 PSS uses SHAKE
//! natively as its MGF, salts are one digest long, and trailerField is 1.

const std = @import("std");
const ed25519 = @import("../crypto/ed25519.zig");
const p256 = @import("../crypto/p256.zig");
const p384 = @import("../crypto/p384.zig");
const p521 = @import("../crypto/p521.zig");
const rsa_pss = @import("../crypto/rsa_pss.zig");
const signature_algorithm = @import("../crypto/signature_algorithm.zig");

const Certificate = std.crypto.Certificate;
const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFieldElement = RsaModulus.Fe;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha224 = std.crypto.hash.sha2.Sha224;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha512_224 = std.crypto.hash.sha2.Sha512_224;
const Sha512_256 = std.crypto.hash.sha2.Sha512_256;
const Sha3_224 = std.crypto.hash.sha3.Sha3_224;
const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const Sha3_384 = std.crypto.hash.sha3.Sha3_384;
const Sha3_512 = std.crypto.hash.sha3.Sha3_512;
const Shake128 = std.crypto.hash.sha3.Shake128;
const Shake256 = std.crypto.hash.sha3.Shake256;
const EcdsaP256Sha384 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    Sha384,
);
const EcdsaP384Sha256 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P384,
    Sha256,
);
const EcdsaP256Sha224 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    Sha224,
);
const EcdsaP384Sha224 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P384,
    Sha224,
);
const EcdsaP256Sha512 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    Sha512,
);
const EcdsaP384Sha512 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P384,
    Sha512,
);
const EcdsaP256Shake128 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    Shake128,
);
const EcdsaP384Shake256 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P384,
    Shake256,
);

const oid_ecdsa_sha256 = [_]u8{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
};
const oid_ecdsa_sha224 = [_]u8{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01,
};
const oid_ecdsa_sha384 = [_]u8{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
};
const oid_ecdsa_sha512 = [_]u8{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
};
const oid_ecdsa_sha3_224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09,
};
const oid_ecdsa_sha3_256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0a,
};
const oid_ecdsa_sha3_384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0b,
};
const oid_ecdsa_sha3_512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0c,
};
const oid_rsassa_pss_shake128 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e,
};
const oid_rsassa_pss_shake256 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f,
};
const oid_ecdsa_shake128 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20,
};
const oid_ecdsa_shake256 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x21,
};
const oid_rsa_sha256 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
};
const oid_rsa_sha1 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
};
const oid_rsa_sha224 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e,
};
const oid_rsa_sha384 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
};
const oid_rsa_sha512 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
};
const oid_rsa_sha512_224 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0f,
};
const oid_rsa_sha512_256 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x10,
};
const oid_rsa_sha3_224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0d,
};
const oid_rsa_sha3_256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0e,
};
const oid_rsa_sha3_384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0f,
};
const oid_rsa_sha3_512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10,
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
const oid_sha224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
};
const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
const oid_sha384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
};
const oid_sha512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
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
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

const sha256_pss_algorithm_identifier = [_]u8{
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0xa2, 0x03, 0x02, 0x01, 0x20,
};

pub const Error = error{
    InvalidAlgorithmIdentifier,
    UnsupportedSignatureAlgorithm,
    InvalidIssuer,
    InvalidSignature,
};

pub const P521Verifier = p521.CompactPreparedVerifier;
pub const P256Verifier = p256.PreparedVerifier;
pub const Ed25519Verifier = ed25519.PreparedVerifier;

pub const Algorithm = signature_algorithm.Algorithm;
pub const PssHash = rsa_pss.PssHash;
pub const PssProfile = rsa_pss.PssProfile;
pub const PssKeyConstraints = rsa_pss.PssKeyConstraints;
pub const pssProfileForAlgorithm = rsa_pss.pssProfileForAlgorithm;
pub const parsePssPublicKeyAlgorithmIdentifier =
    rsa_pss.parsePssPublicKeyAlgorithmIdentifier;

/// Parse the contents of an ASN.1 AlgorithmIdentifier SEQUENCE.
pub fn parseAlgorithmIdentifier(encoded: []const u8) Error!Algorithm {
    var fields = Reader{ .bytes = encoded };
    const oid = fields.require(0x06) catch
        return error.InvalidAlgorithmIdentifier;
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha224)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_sha224;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha256)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_p256_sha256;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha384)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_p384_sha384;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha512)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_sha512;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha3_224)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_sha3_224;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha3_256)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_sha3_256;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha3_384)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_sha3_384;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_sha3_512)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_sha3_512;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_shake128)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_shake128;
    }
    if (std.mem.eql(u8, oid.value, &oid_ecdsa_shake256)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .ecdsa_shake256;
    }
    if (std.mem.eql(u8, oid.value, &oid_rsa_sha1) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha256) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha224) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha384) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha512) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha512_224) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha512_256))
    {
        const parameters = (fields.next() catch
            return error.InvalidAlgorithmIdentifier) orelse
            return error.InvalidAlgorithmIdentifier;
        if (parameters.tag != 0x05 or parameters.value.len != 0 or
            !fields.done())
        {
            return error.InvalidAlgorithmIdentifier;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha1)) {
            return .rsa_pkcs1_sha1;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha224)) {
            return .rsa_pkcs1_sha224;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha256)) {
            return .rsa_pkcs1_sha256;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha384)) {
            return .rsa_pkcs1_sha384;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha512)) {
            return .rsa_pkcs1_sha512;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha512_224)) {
            return .rsa_pkcs1_sha512_224;
        }
        return .rsa_pkcs1_sha512_256;
    }
    if (std.mem.eql(u8, oid.value, &oid_rsa_sha3_224) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha3_256) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha3_384) or
        std.mem.eql(u8, oid.value, &oid_rsa_sha3_512))
    {
        if (fields.next() catch return error.InvalidAlgorithmIdentifier) |parameters| {
            if (parameters.tag != 0x05 or parameters.value.len != 0 or
                !fields.done())
            {
                return error.InvalidAlgorithmIdentifier;
            }
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha3_224)) {
            return .rsa_pkcs1_sha3_224;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha3_256)) {
            return .rsa_pkcs1_sha3_256;
        }
        if (std.mem.eql(u8, oid.value, &oid_rsa_sha3_384)) {
            return .rsa_pkcs1_sha3_384;
        }
        return .rsa_pkcs1_sha3_512;
    }
    if (std.mem.eql(u8, oid.value, &oid_rsassa_pss)) {
        const parameters = (fields.next() catch
            return error.InvalidAlgorithmIdentifier) orelse
            return error.InvalidAlgorithmIdentifier;
        if (parameters.tag != 0x30 or !fields.done()) {
            return error.InvalidAlgorithmIdentifier;
        }
        const profile = try rsa_pss.parsePssProfile(parameters.value);
        if (profile.hash != profile.mgf_hash or
            profile.salt_length != profile.hash.digestLength() or
            profile.trailer_field != 1)
        {
            return error.UnsupportedSignatureAlgorithm;
        }
        return profile.hash.signatureAlgorithm();
    }
    if (std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake128)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .rsa_pss_shake128;
    }
    if (std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake256)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .rsa_pss_shake256;
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
    return switch (algorithm) {
        .ecdsa_sha224 => try verifyEcdsa(
            Sha224,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_p256_sha256 => try verifyEcdsa(
            Sha256,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_p384_sha384 => try verifyEcdsa(
            Sha384,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_sha512 => try verifyEcdsa(
            Sha512,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_224 => try verifyEcdsa(
            Sha3_224,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_256 => try verifyEcdsa(
            Sha3_256,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_384 => try verifyEcdsa(
            Sha3_384,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_512 => try verifyEcdsa(
            Sha3_512,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_shake128 => try verifyEcdsa(
            Shake128,
            issuer,
            message,
            signature_bytes,
        ),
        .ecdsa_shake256 => try verifyEcdsa(
            Shake256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha1 => try verifyRsaPkcs1(
            Sha1,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha224 => try verifyRsaPkcs1(
            Sha224,
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
        .rsa_pkcs1_sha512_224 => try verifyRsaPkcs1Custom(
            Sha512_224,
            &oid_sha512_224,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha512_256 => try verifyRsaPkcs1Custom(
            Sha512_256,
            &oid_sha512_256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha3_224 => try verifyRsaPkcs1Custom(
            Sha3_224,
            &oid_sha3_224,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha3_256 => try verifyRsaPkcs1Custom(
            Sha3_256,
            &oid_sha3_256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha3_384 => try verifyRsaPkcs1Custom(
            Sha3_384,
            &oid_sha3_384,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pkcs1_sha3_512 => try verifyRsaPkcs1Custom(
            Sha3_512,
            &oid_sha3_512,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha224 => try verifyRsaPss(
            Sha224,
            .rsa_pss_sha224,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha256 => try verifyRsaPss(
            Sha256,
            .rsa_pss_sha256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha384 => try verifyRsaPss(
            Sha384,
            .rsa_pss_sha384,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha512 => try verifyRsaPss(
            Sha512,
            .rsa_pss_sha512,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha512_224 => try verifyRsaPss(
            Sha512_224,
            .rsa_pss_sha512_224,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha512_256 => try verifyRsaPss(
            Sha512_256,
            .rsa_pss_sha512_256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha3_224 => try verifyRsaPss(
            Sha3_224,
            .rsa_pss_sha3_224,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha3_256 => try verifyRsaPss(
            Sha3_256,
            .rsa_pss_sha3_256,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha3_384 => try verifyRsaPss(
            Sha3_384,
            .rsa_pss_sha3_384,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_sha3_512 => try verifyRsaPss(
            Sha3_512,
            .rsa_pss_sha3_512,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_shake128 => try verifyRsaPssShake(
            Shake128,
            .rsa_pss_shake128,
            issuer,
            message,
            signature_bytes,
        ),
        .rsa_pss_shake256 => try verifyRsaPssShake(
            Shake256,
            .rsa_pss_shake256,
            issuer,
            message,
            signature_bytes,
        ),
        .ed25519 => try verifyEd25519(issuer, message, signature_bytes),
    };
}

/// Verify a P-521 ECDSA signature with a caller-retained public-key table.
/// This is useful when one issuer authenticates several objects in a path.
pub fn verifyWithP521(
    algorithm: Algorithm,
    verifier: *const P521Verifier,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    switch (algorithm) {
        .ecdsa_sha224 => verifier.verify(
            Sha224,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_p256_sha256 => verifier.verify(
            Sha256,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_p384_sha384 => verifier.verify(
            Sha384,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_sha512 => verifier.verify(
            Sha512,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_sha3_224 => verifier.verify(
            Sha3_224,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_sha3_256 => verifier.verify(
            Sha3_256,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_sha3_384 => verifier.verify(
            Sha3_384,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_sha3_512 => verifier.verify(
            Sha3_512,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_shake128 => verifier.verify(
            Shake128,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        .ecdsa_shake256 => verifier.verify(
            Shake256,
            message,
            signature_bytes,
        ) catch return error.InvalidSignature,
        else => return error.UnsupportedSignatureAlgorithm,
    }
}

/// Verify a P-256 ECDSA signature with a caller-retained public-key table.
pub fn verifyWithP256(
    algorithm: Algorithm,
    verifier: *const P256Verifier,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    return switch (algorithm) {
        .ecdsa_sha224 => verifyPreparedP256(
            Sha224,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_p256_sha256 => verifyPreparedP256(
            Sha256,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_p384_sha384 => verifyPreparedP256(
            Sha384,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_sha512 => verifyPreparedP256(
            Sha512,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_224 => verifyPreparedP256(
            Sha3_224,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_256 => verifyPreparedP256(
            Sha3_256,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_384 => verifyPreparedP256(
            Sha3_384,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_sha3_512 => verifyPreparedP256(
            Sha3_512,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_shake128 => verifyPreparedP256(
            Shake128,
            verifier,
            message,
            signature_bytes,
        ),
        .ecdsa_shake256 => verifyPreparedP256(
            Shake256,
            verifier,
            message,
            signature_bytes,
        ),
        else => error.UnsupportedSignatureAlgorithm,
    };
}

fn verifyPreparedP256(
    comptime Hash: type,
    verifier: *const P256Verifier,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    const signature = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Hash).Signature
        .fromDer(signature_bytes) catch return error.InvalidSignature;
    verifier.verify(Hash, message, signature) catch
        return error.InvalidSignature;
}

/// Verify an Ed25519 signature with a caller-retained public-key table.
pub fn verifyWithEd25519(
    algorithm: Algorithm,
    verifier: *const Ed25519Verifier,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    if (algorithm != .ed25519) {
        return error.UnsupportedSignatureAlgorithm;
    }
    if (signature_bytes.len != Ed25519.Signature.encoded_length) {
        return error.UnsupportedSignatureAlgorithm;
    }
    const signature = Ed25519.Signature.fromBytes(
        signature_bytes[0..Ed25519.Signature.encoded_length].*,
    );
    verifier.verify(signature, message) catch
        return error.InvalidSignature;
}

fn verifyEcdsa(
    comptime Hash: type,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    const named_curve = switch (issuer.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| curve,
        else => return error.UnsupportedSignatureAlgorithm,
    };
    switch (named_curve) {
        .secp521r1 => p521.verify(
            Hash,
            message,
            signature_bytes,
            issuer.pubKey(),
        ) catch |err| switch (err) {
            error.InvalidPublicKey => return error.InvalidIssuer,
            error.InvalidSignature => return error.InvalidSignature,
        },
        .X9_62_prime256v1 => {
            const Scheme = std.crypto.sign.ecdsa.Ecdsa(
                std.crypto.ecc.P256,
                Hash,
            );
            const public_key = Scheme.PublicKey.fromSec1(issuer.pubKey()) catch
                return error.InvalidIssuer;
            const signature = Scheme.Signature.fromDer(signature_bytes) catch
                return error.InvalidSignature;
            p256.verify(Hash, message, signature, public_key) catch
                return error.InvalidSignature;
        },
        .secp384r1 => {
            const Scheme = std.crypto.sign.ecdsa.Ecdsa(
                std.crypto.ecc.P384,
                Hash,
            );
            const public_key = Scheme.PublicKey.fromSec1(issuer.pubKey()) catch
                return error.InvalidIssuer;
            const signature = Scheme.Signature.fromDer(signature_bytes) catch
                return error.InvalidSignature;
            p384.verify(Hash, message, signature, public_key) catch
                return error.InvalidSignature;
        },
    }
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

fn verifyRsaPkcs1Custom(
    comptime Hash: type,
    comptime hash_oid: []const u8,
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
            _ = Certificate.rsa.PublicKey.fromBytes(
                public_key.exponent,
                public_key.modulus,
            ) catch return error.InvalidIssuer;
            const modulus = RsaModulus.fromBytes(
                public_key.modulus,
                .big,
            ) catch return error.InvalidIssuer;
            const signature = RsaFieldElement.fromBytes(
                modulus,
                signature_bytes,
                .big,
            ) catch return error.InvalidSignature;
            const decoded = modulus.powWithEncodedPublicExponent(
                signature,
                public_key.exponent,
                .big,
            ) catch return error.InvalidIssuer;
            var encoded_message: [modulus_len]u8 = undefined;
            decoded.toBytes(&encoded_message, .big) catch
                return error.InvalidSignature;
            try verifyPkcs1CustomEncoding(
                Hash,
                hash_oid,
                message,
                &encoded_message,
            );
        },
        else => return error.UnsupportedSignatureAlgorithm,
    }
}

fn verifyPkcs1CustomEncoding(
    comptime Hash: type,
    comptime hash_oid: []const u8,
    message: []const u8,
    encoded: []const u8,
) Error!void {
    if (encoded.len < 11 or encoded[0] != 0 or encoded[1] != 1) {
        return error.InvalidSignature;
    }
    var separator: usize = 2;
    while (separator < encoded.len and encoded[separator] == 0xff) {
        separator += 1;
    }
    if (separator < 10 or separator >= encoded.len or
        encoded[separator] != 0)
    {
        return error.InvalidSignature;
    }

    var digest_info = Reader{ .bytes = encoded[separator + 1 ..] };
    const sequence = digest_info.require(0x30) catch
        return error.InvalidSignature;
    if (!digest_info.done()) return error.InvalidSignature;
    var fields = Reader{ .bytes = sequence.value };
    const algorithm = fields.require(0x30) catch
        return error.InvalidSignature;
    const digest = fields.require(0x04) catch
        return error.InvalidSignature;
    if (!fields.done() or digest.value.len != Hash.digest_length) {
        return error.InvalidSignature;
    }
    var algorithm_fields = Reader{ .bytes = algorithm.value };
    const oid = algorithm_fields.require(0x06) catch
        return error.InvalidSignature;
    if (!std.mem.eql(u8, oid.value, hash_oid)) {
        return error.InvalidSignature;
    }
    if (algorithm_fields.next() catch return error.InvalidSignature) |parameters| {
        if (parameters.tag != 0x05 or parameters.value.len != 0 or
            !algorithm_fields.done())
        {
            return error.InvalidSignature;
        }
    }
    var expected: [Hash.digest_length]u8 = undefined;
    Hash.hash(message, &expected, .{});
    if (!std.crypto.timing_safe.eql(
        [Hash.digest_length]u8,
        digest.value[0..Hash.digest_length].*,
        expected,
    )) return error.InvalidSignature;
}

fn verifyRsaPss(
    comptime Hash: type,
    algorithm: Algorithm,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    switch (issuer.pub_key_algo) {
        .rsaEncryption => {},
        .rsassa_pss => {
            const constraints = try pssConstraintsForCertificate(issuer);
            if (!constraints.permits(algorithm)) {
                return error.UnsupportedSignatureAlgorithm;
            }
        },
        else => return error.UnsupportedSignatureAlgorithm,
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

fn verifyRsaPssShake(
    comptime Hash: type,
    algorithm: Algorithm,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    switch (issuer.pub_key_algo) {
        .rsaEncryption => {},
        .rsassa_pss => {
            const constraints = try pssConstraintsForCertificate(issuer);
            if (!constraints.permits(algorithm)) {
                return error.UnsupportedSignatureAlgorithm;
            }
        },
        else => return error.UnsupportedSignatureAlgorithm,
    }
    const public_key = try rsaPublicKey(issuer);
    switch (public_key.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (signature_bytes.len != modulus_len) {
                return error.InvalidSignature;
            }
            _ = Certificate.rsa.PublicKey.fromBytes(
                public_key.exponent,
                public_key.modulus,
            ) catch return error.InvalidIssuer;
            const modulus = RsaModulus.fromBytes(
                public_key.modulus,
                .big,
            ) catch return error.InvalidIssuer;
            const signature = RsaFieldElement.fromBytes(
                modulus,
                signature_bytes,
                .big,
            ) catch return error.InvalidSignature;
            const decoded = modulus.powWithEncodedPublicExponent(
                signature,
                public_key.exponent,
                .big,
            ) catch return error.InvalidIssuer;
            var encoded_message: [modulus_len]u8 = undefined;
            decoded.toBytes(&encoded_message, .big) catch
                return error.InvalidSignature;
            try verifyPssShakeEncoding(
                Hash,
                message,
                &encoded_message,
                modulus.bits() - 1,
            );
        },
        else => return error.UnsupportedSignatureAlgorithm,
    }
}

fn verifyPssShakeEncoding(
    comptime Hash: type,
    message: []const u8,
    encoded: []const u8,
    encoded_bits: usize,
) Error!void {
    const encoded_len = (encoded_bits + 7) / 8;
    if (encoded_len > encoded.len or
        encoded_len < 2 * Hash.digest_length + 2)
    {
        return error.InvalidSignature;
    }
    for (encoded[0 .. encoded.len - encoded_len]) |byte| {
        if (byte != 0) return error.InvalidSignature;
    }
    const em = encoded[encoded.len - encoded_len ..];
    if (em[em.len - 1] != 0xbc) return error.InvalidSignature;
    const data_block_len = em.len - Hash.digest_length - 1;
    const masked_data_block = em[0..data_block_len];
    const encoded_hash = em[data_block_len .. em.len - 1];
    const unused_bits: u3 = @intCast(encoded_len * 8 - encoded_bits);
    if (masked_data_block[0] &
        ~(@as(u8, 0xff) >> unused_bits) != 0)
    {
        return error.InvalidSignature;
    }

    var data_block_storage: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &data_block_storage);
    const data_block = data_block_storage[0..data_block_len];
    @memcpy(data_block, masked_data_block);
    shakeXor(Hash, data_block, encoded_hash);
    data_block[0] &= @as(u8, 0xff) >> unused_bits;

    const salt_start = data_block.len - Hash.digest_length;
    var invalid: u8 = 0;
    for (data_block[0 .. salt_start - 1]) |byte| invalid |= byte;
    invalid |= data_block[salt_start - 1] ^ 1;
    if (invalid != 0) return error.InvalidSignature;

    var message_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(message, &message_hash, .{});
    var hash_input: [8 + 2 * Shake256.digest_length]u8 = undefined;
    @memset(hash_input[0..8], 0);
    @memcpy(hash_input[8..][0..Hash.digest_length], &message_hash);
    @memcpy(
        hash_input[8 + Hash.digest_length ..][0..Hash.digest_length],
        data_block[salt_start..],
    );
    var expected_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(
        hash_input[0 .. 8 + 2 * Hash.digest_length],
        &expected_hash,
        .{},
    );
    if (!std.crypto.timing_safe.eql(
        [Hash.digest_length]u8,
        encoded_hash[0..Hash.digest_length].*,
        expected_hash,
    )) return error.InvalidSignature;
}

fn shakeXor(
    comptime Hash: type,
    output: []u8,
    seed: []const u8,
) void {
    var mask: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &mask);
    var xof = Hash.init(.{});
    xof.update(seed);
    xof.final(mask[0..output.len]);
    for (output, mask[0..output.len]) |*byte, mask_byte| {
        byte.* ^= mask_byte;
    }
}

pub fn pssConstraintsForCertificate(
    certificate: Certificate.Parsed,
) Error!PssKeyConstraints {
    if (certificate.pub_key_algo != .rsassa_pss) {
        return error.UnsupportedSignatureAlgorithm;
    }
    const bytes = certificate.certificate.buffer;
    const subject_end = certificate.subject_slice.end;
    const public_key_info = Certificate.der.Element.parse(
        bytes,
        subject_end,
    ) catch return error.InvalidAlgorithmIdentifier;
    if (public_key_info.identifier.tag != .sequence) {
        return error.InvalidAlgorithmIdentifier;
    }
    const algorithm = Certificate.der.Element.parse(
        bytes,
        public_key_info.slice.start,
    ) catch return error.InvalidAlgorithmIdentifier;
    if (algorithm.identifier.tag != .sequence) {
        return error.InvalidAlgorithmIdentifier;
    }
    return parsePssPublicKeyAlgorithmIdentifier(
        bytes[algorithm.slice.start..algorithm.slice.end],
    );
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
    ed25519.verify(signature, message, public_key) catch
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

fn testEcdsaHashCurveCombination(
    comptime Scheme: type,
    algorithm: Algorithm,
    wrong_hash_algorithm: Algorithm,
    issuer_der: []u8,
) !void {
    const original_issuer = try Certificate.parse(.{
        .buffer = issuer_der,
        .index = 0,
    });
    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0xb7} ** Scheme.KeyPair.seed_length,
    );
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key_offset = std.mem.indexOf(
        u8,
        issuer_der,
        original_issuer.pubKey(),
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        original_issuer.pubKey().len,
        encoded_public_key.len,
    );
    @memcpy(
        issuer_der[public_key_offset..][0..encoded_public_key.len],
        &encoded_public_key,
    );
    const issuer = try Certificate.parse(.{
        .buffer = issuer_der,
        .index = 0,
    });

    const message = "ECDSA hash and issuer curve are independent";
    const signature = try key_pair.sign(message, null);
    var encoded_signature: [Scheme.Signature.der_encoded_length_max]u8 =
        undefined;
    const der = signature.toDer(&encoded_signature);
    try verify(algorithm, issuer, message, der);
    try std.testing.expectError(
        error.InvalidSignature,
        verify(wrong_hash_algorithm, issuer, message, der),
    );

    encoded_signature[der.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(
            algorithm,
            issuer,
            message,
            encoded_signature[0..der.len],
        ),
    );
}

test "ECDSA verifier selects P-256 or P-384 independently from SHA-2 OID" {
    const vectors = @import("testdata/path_vectors.zig");
    var p256_issuer: [vectors.multi_staple_root_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &p256_issuer,
        vectors.multi_staple_root_hex,
    );
    try testEcdsaHashCurveCombination(
        EcdsaP256Sha384,
        .ecdsa_p384_sha384,
        .ecdsa_p256_sha256,
        &p256_issuer,
    );

    const p384_fixture = @embedFile("testdata/p384-crl-ca.der");
    var p384_issuer: [p384_fixture.len]u8 =
        p384_fixture[0..p384_fixture.len].*;
    try testEcdsaHashCurveCombination(
        EcdsaP384Sha256,
        .ecdsa_p256_sha256,
        .ecdsa_p384_sha384,
        &p384_issuer,
    );
    try testEcdsaHashCurveCombination(
        EcdsaP256Sha224,
        .ecdsa_sha224,
        .ecdsa_p256_sha256,
        &p256_issuer,
    );
    try testEcdsaHashCurveCombination(
        EcdsaP384Sha224,
        .ecdsa_sha224,
        .ecdsa_p256_sha256,
        &p384_issuer,
    );
    try testEcdsaHashCurveCombination(
        EcdsaP256Sha512,
        .ecdsa_sha512,
        .ecdsa_p256_sha256,
        &p256_issuer,
    );
    try testEcdsaHashCurveCombination(
        EcdsaP384Sha512,
        .ecdsa_sha512,
        .ecdsa_p384_sha384,
        &p384_issuer,
    );

    const sha512_algorithm = [_]u8{
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x04,
    };
    try std.testing.expectEqual(
        Algorithm.ecdsa_sha512,
        try parseAlgorithmIdentifier(&sha512_algorithm),
    );
    try std.testing.expectError(
        error.InvalidAlgorithmIdentifier,
        parseAlgorithmIdentifier(&(sha512_algorithm ++ [_]u8{ 0x05, 0x00 })),
    );
    const sha224_algorithm = [_]u8{
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x01,
    };
    try std.testing.expectEqual(
        Algorithm.ecdsa_sha224,
        try parseAlgorithmIdentifier(&sha224_algorithm),
    );
    try std.testing.expectError(
        error.InvalidAlgorithmIdentifier,
        parseAlgorithmIdentifier(&(sha224_algorithm ++ [_]u8{ 0x05, 0x00 })),
    );
}

test "ECDSA SHA-224 verifies an independent OpenSSL signature" {
    const vectors = @import("testdata/path_vectors.zig");
    var issuer_der: [vectors.ecdsa_sha224_issuer_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &issuer_der,
        vectors.ecdsa_sha224_issuer_hex,
    );
    var signature: [vectors.ecdsa_sha224_signature_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &signature,
        vectors.ecdsa_sha224_signature_hex,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail RFC 5758 SHA-224 oracle";
    try verify(.ecdsa_sha224, issuer, message, &signature);

    signature[signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.ecdsa_sha224, issuer, message, &signature),
    );
}

test "ECDSA SHA3 verifies independent OpenSSL signatures" {
    const vectors = @import("testdata/path_vectors.zig");
    const issuer_der = decodeHex(vectors.ecdsa_sha3_issuer_hex);
    const sha3_224_signature = decodeHex(
        vectors.ecdsa_sha3_224_signature_hex,
    );
    const sha3_256_signature = decodeHex(
        vectors.ecdsa_sha3_256_signature_hex,
    );
    const sha3_384_signature = decodeHex(
        vectors.ecdsa_sha3_384_signature_hex,
    );
    var sha3_512_signature = decodeHex(
        vectors.ecdsa_sha3_512_signature_hex,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail ECDSA SHA3 oracle";
    try verify(.ecdsa_sha3_224, issuer, message, &sha3_224_signature);
    try verify(.ecdsa_sha3_256, issuer, message, &sha3_256_signature);
    try verify(.ecdsa_sha3_384, issuer, message, &sha3_384_signature);
    try verify(.ecdsa_sha3_512, issuer, message, &sha3_512_signature);

    const algorithm_identifiers = [_]struct {
        algorithm: Algorithm,
        encoded: []const u8,
    }{
        .{ .algorithm = .ecdsa_sha3_224, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x09" },
        .{ .algorithm = .ecdsa_sha3_256, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0a" },
        .{ .algorithm = .ecdsa_sha3_384, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0b" },
        .{ .algorithm = .ecdsa_sha3_512, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0c" },
    };
    for (algorithm_identifiers) |item| {
        try std.testing.expectEqual(
            item.algorithm,
            try parseAlgorithmIdentifier(item.encoded),
        );
    }
    try std.testing.expectError(
        error.InvalidAlgorithmIdentifier,
        parseAlgorithmIdentifier(
            "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0c\x05\x00",
        ),
    );

    sha3_512_signature[sha3_512_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.ecdsa_sha3_512, issuer, message, &sha3_512_signature),
    );
}

test "RSA SHA-224 verifies independent OpenSSL PKCS1 and PSS signatures" {
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    var issuer_der: [vectors.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&issuer_der, vectors.certificate_hex);
    var pkcs1_signature: [vectors.pkcs1_sha224_signature_hex.len / 2]u8 =
        undefined;
    _ = try std.fmt.hexToBytes(
        &pkcs1_signature,
        vectors.pkcs1_sha224_signature_hex,
    );
    var pss_signature: [vectors.pss_sha224_signature_hex.len / 2]u8 =
        undefined;
    _ = try std.fmt.hexToBytes(
        &pss_signature,
        vectors.pss_sha224_signature_hex,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail RFC 4055 SHA-224 oracle";
    try verify(.rsa_pkcs1_sha224, issuer, message, &pkcs1_signature);
    try verify(.rsa_pss_sha224, issuer, message, &pss_signature);

    pkcs1_signature[pkcs1_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.rsa_pkcs1_sha224, issuer, message, &pkcs1_signature),
    );
    pss_signature[pss_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.rsa_pss_sha224, issuer, message, &pss_signature),
    );
}

test "RSA SHA-512 truncated verifies independent OpenSSL signatures" {
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const issuer_der = decodeHex(vectors.certificate_hex);
    const pkcs1_sha512_224 = decodeHex(
        vectors.pkcs1_sha512_224_signature_hex,
    );
    const pss_sha512_224 = decodeHex(
        vectors.pss_sha512_224_signature_hex,
    );
    const pkcs1_sha512_256 = decodeHex(
        vectors.pkcs1_sha512_256_signature_hex,
    );
    var pss_sha512_256 = decodeHex(
        vectors.pss_sha512_256_signature_hex,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail RFC 8017 SHA-512 truncated oracle";
    try verify(
        .rsa_pkcs1_sha512_224,
        issuer,
        message,
        &pkcs1_sha512_224,
    );
    try verify(.rsa_pss_sha512_224, issuer, message, &pss_sha512_224);
    try verify(
        .rsa_pkcs1_sha512_256,
        issuer,
        message,
        &pkcs1_sha512_256,
    );
    try verify(.rsa_pss_sha512_256, issuer, message, &pss_sha512_256);

    pss_sha512_256[pss_sha512_256.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.rsa_pss_sha512_256, issuer, message, &pss_sha512_256),
    );

    const pkcs1_algorithms = [_]struct {
        algorithm: Algorithm,
        encoded: []const u8,
    }{
        .{
            .algorithm = .rsa_pkcs1_sha512_224,
            .encoded = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0f\x05\x00",
        },
        .{
            .algorithm = .rsa_pkcs1_sha512_256,
            .encoded = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x10\x05\x00",
        },
    };
    for (pkcs1_algorithms) |item| {
        try std.testing.expectEqual(
            item.algorithm,
            try parseAlgorithmIdentifier(item.encoded),
        );
        try std.testing.expectError(
            error.InvalidAlgorithmIdentifier,
            parseAlgorithmIdentifier(item.encoded[0 .. item.encoded.len - 2]),
        );
    }

    var sha512_224_pss = sha256_pss_algorithm_identifier;
    var sha512_256_pss = sha256_pss_algorithm_identifier;
    inline for (.{
        .{ &sha512_224_pss, &oid_sha512_224, Sha512_224.digest_length, Algorithm.rsa_pss_sha512_224 },
        .{ &sha512_256_pss, &oid_sha512_256, Sha512_256.digest_length, Algorithm.rsa_pss_sha512_256 },
    }) |case| {
        var search_from: usize = 0;
        var replacements: usize = 0;
        while (std.mem.indexOfPos(
            u8,
            case[0],
            search_from,
            &oid_sha256,
        )) |offset| {
            @memcpy(case[0][offset..][0..oid_sha256.len], case[1]);
            search_from = offset + oid_sha256.len;
            replacements += 1;
        }
        try std.testing.expectEqual(@as(usize, 2), replacements);
        case[0][case[0].len - 1] = case[2];
        try std.testing.expectEqual(
            case[3],
            try parseAlgorithmIdentifier(case[0]),
        );
        const constraints = try parsePssPublicKeyAlgorithmIdentifier(case[0]);
        try std.testing.expect(constraints.permits(case[3]));
    }
}

test "RFC 8692 SHAKE AlgorithmIdentifiers omit parameters" {
    const identifiers = [_]struct {
        algorithm: Algorithm,
        encoded: []const u8,
    }{
        .{ .algorithm = .rsa_pss_shake128, .encoded = "\x06\x08\x2b\x06\x01\x05\x05\x07\x06\x1e" },
        .{ .algorithm = .rsa_pss_shake256, .encoded = "\x06\x08\x2b\x06\x01\x05\x05\x07\x06\x1f" },
        .{ .algorithm = .ecdsa_shake128, .encoded = "\x06\x08\x2b\x06\x01\x05\x05\x07\x06\x20" },
        .{ .algorithm = .ecdsa_shake256, .encoded = "\x06\x08\x2b\x06\x01\x05\x05\x07\x06\x21" },
    };
    for (identifiers) |item| {
        try std.testing.expectEqual(
            item.algorithm,
            try parseAlgorithmIdentifier(item.encoded),
        );
        var with_parameters: [12]u8 = undefined;
        @memcpy(with_parameters[0..item.encoded.len], item.encoded);
        with_parameters[10..].* = .{ 0x05, 0x00 };
        try std.testing.expectError(
            error.InvalidAlgorithmIdentifier,
            parseAlgorithmIdentifier(&with_parameters),
        );
    }

    const shake128_key = try parsePssPublicKeyAlgorithmIdentifier(
        identifiers[0].encoded,
    );
    try std.testing.expect(shake128_key.permits(.rsa_pss_shake128));
    try std.testing.expect(!shake128_key.permits(.rsa_pss_shake256));
    const shake256_key = try parsePssPublicKeyAlgorithmIdentifier(
        identifiers[1].encoded,
    );
    try std.testing.expect(shake256_key.permits(.rsa_pss_shake256));
    try std.testing.expect(!shake256_key.permits(.rsa_pss_shake128));
    var invalid_key_identifier: [12]u8 = undefined;
    @memcpy(
        invalid_key_identifier[0..identifiers[0].encoded.len],
        identifiers[0].encoded,
    );
    invalid_key_identifier[10..].* = .{ 0x05, 0x00 };
    try std.testing.expectError(
        error.InvalidAlgorithmIdentifier,
        parsePssPublicKeyAlgorithmIdentifier(&invalid_key_identifier),
    );
}

test "RSA-PSS-SHAKE verifies an independent native-XOF encoding" {
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const issuer_der = decodeHex(vectors.certificate_hex);
    const shake128_signature = decodeHex(
        vectors.pss_shake128_signature_hex,
    );
    var shake256_signature = decodeHex(
        vectors.pss_shake256_signature_hex,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail RFC 8692 RSA-PSS-SHAKE oracle";
    try verify(
        .rsa_pss_shake128,
        issuer,
        message,
        &shake128_signature,
    );
    try verify(
        .rsa_pss_shake256,
        issuer,
        message,
        &shake256_signature,
    );

    shake256_signature[shake256_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(
            .rsa_pss_shake256,
            issuer,
            message,
            &shake256_signature,
        ),
    );
}

test "ECDSA SHAKE verifies independent OpenSSL prehashed signatures" {
    const vectors = @import("testdata/path_vectors.zig");
    const public_key = decodeHex(vectors.p521_shake_public_key_hex);
    const shake128_signature = decodeHex(
        vectors.p521_shake128_signature_hex,
    );
    var shake256_signature = decodeHex(
        vectors.p521_shake256_signature_hex,
    );
    var issuer_der = decodeHex(vectors.p521_root_hex);
    const original_issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const public_key_offset = std.mem.indexOf(
        u8,
        &issuer_der,
        original_issuer.pubKey(),
    ) orelse return error.TestUnexpectedResult;
    @memcpy(
        issuer_der[public_key_offset..][0..public_key.len],
        &public_key,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail RFC 8692 ECDSA SHAKE oracle";
    try verify(.ecdsa_shake128, issuer, message, &shake128_signature);
    try verify(.ecdsa_shake256, issuer, message, &shake256_signature);

    shake256_signature[shake256_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.ecdsa_shake256, issuer, message, &shake256_signature),
    );
}

test "ECDSA SHAKE verifies signatures and selects the issuer curve" {
    const vectors = @import("testdata/path_vectors.zig");
    var p256_issuer: [vectors.multi_staple_root_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &p256_issuer,
        vectors.multi_staple_root_hex,
    );
    try testEcdsaHashCurveCombination(
        EcdsaP256Shake128,
        .ecdsa_shake128,
        .ecdsa_shake256,
        &p256_issuer,
    );

    const p384_fixture = @embedFile("testdata/p384-crl-ca.der");
    var p384_issuer: [p384_fixture.len]u8 =
        p384_fixture[0..p384_fixture.len].*;
    try testEcdsaHashCurveCombination(
        EcdsaP384Shake256,
        .ecdsa_shake256,
        .ecdsa_shake128,
        &p384_issuer,
    );
}

test "RSA-PSS SHA3 verifies independent OpenSSL signatures" {
    const vectors = @import("testdata/path_vectors.zig");
    const issuer_der = decodeHex(vectors.rsa_pss_sha3_issuer_hex);
    const sha3_224_signature = decodeHex(
        vectors.rsa_pss_sha3_224_signature_hex,
    );
    const sha3_256_signature = decodeHex(
        vectors.rsa_pss_sha3_256_signature_hex,
    );
    const sha3_384_signature = decodeHex(
        vectors.rsa_pss_sha3_384_signature_hex,
    );
    var sha3_512_signature = decodeHex(
        vectors.rsa_pss_sha3_512_signature_hex,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail RSA-PSS SHA3 oracle";
    try verify(.rsa_pss_sha3_224, issuer, message, &sha3_224_signature);
    try verify(.rsa_pss_sha3_256, issuer, message, &sha3_256_signature);
    try verify(.rsa_pss_sha3_384, issuer, message, &sha3_384_signature);
    try verify(.rsa_pss_sha3_512, issuer, message, &sha3_512_signature);

    sha3_512_signature[sha3_512_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.rsa_pss_sha3_512, issuer, message, &sha3_512_signature),
    );

    var sha3_256_parameters = sha256_pss_algorithm_identifier;
    var search_from: usize = 0;
    var replacements: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        &sha3_256_parameters,
        search_from,
        &oid_sha256,
    )) |offset| {
        sha3_256_parameters[offset + oid_sha256.len - 1] =
            oid_sha3_256[oid_sha3_256.len - 1];
        search_from = offset + oid_sha256.len;
        replacements += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), replacements);
    try std.testing.expectEqual(
        Algorithm.rsa_pss_sha3_256,
        try parseAlgorithmIdentifier(&sha3_256_parameters),
    );
}

test "RSA PKCS1 SHA3 verifies independent OpenSSL signatures" {
    const vectors = @import("testdata/path_vectors.zig");
    const issuer_der = decodeHex(vectors.rsa_pss_sha3_issuer_hex);
    const sha3_224_signature = decodeHex(
        vectors.rsa_pkcs1_sha3_224_signature_hex,
    );
    const sha3_256_signature = decodeHex(
        vectors.rsa_pkcs1_sha3_256_signature_hex,
    );
    const sha3_384_signature = decodeHex(
        vectors.rsa_pkcs1_sha3_384_signature_hex,
    );
    var sha3_512_signature = decodeHex(
        vectors.rsa_pkcs1_sha3_512_signature_hex,
    );
    const absent_parameters_signature = decodeHex(
        vectors.rsa_pkcs1_sha3_256_absent_parameters_signature_hex,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });
    const message = "Vail RSA-PKCS1 SHA3 oracle";
    try verify(.rsa_pkcs1_sha3_224, issuer, message, &sha3_224_signature);
    try verify(.rsa_pkcs1_sha3_256, issuer, message, &sha3_256_signature);
    try verify(.rsa_pkcs1_sha3_384, issuer, message, &sha3_384_signature);
    try verify(.rsa_pkcs1_sha3_512, issuer, message, &sha3_512_signature);
    try verify(
        .rsa_pkcs1_sha3_256,
        issuer,
        message,
        &absent_parameters_signature,
    );

    const algorithm_identifiers = [_]struct {
        algorithm: Algorithm,
        encoded: []const u8,
    }{
        .{ .algorithm = .rsa_pkcs1_sha3_224, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0d" },
        .{ .algorithm = .rsa_pkcs1_sha3_256, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0e" },
        .{ .algorithm = .rsa_pkcs1_sha3_384, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0f" },
        .{ .algorithm = .rsa_pkcs1_sha3_512, .encoded = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x10" },
    };
    for (algorithm_identifiers) |item| {
        try std.testing.expectEqual(
            item.algorithm,
            try parseAlgorithmIdentifier(item.encoded),
        );
    }
    try std.testing.expectEqual(
        Algorithm.rsa_pkcs1_sha3_256,
        try parseAlgorithmIdentifier(
            "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0e\x05\x00",
        ),
    );
    try std.testing.expectError(
        error.InvalidAlgorithmIdentifier,
        parseAlgorithmIdentifier(
            "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x0e\x01\x01\xff",
        ),
    );

    sha3_512_signature[sha3_512_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(.rsa_pkcs1_sha3_512, issuer, message, &sha3_512_signature),
    );
}

test "ECDSA verifier accepts canonical high-bit integer padding" {
    const vectors = @import("testdata/path_vectors.zig");
    var issuer_der: [vectors.multi_staple_root_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &issuer_der,
        vectors.multi_staple_root_hex,
    );
    const original_issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });

    const key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0xa6} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key_offset = std.mem.indexOf(
        u8,
        &issuer_der,
        original_issuer.pubKey(),
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        original_issuer.pubKey().len,
        encoded_public_key.len,
    );
    @memcpy(
        issuer_der[public_key_offset..][0..encoded_public_key.len],
        &encoded_public_key,
    );
    const issuer = try Certificate.parse(.{
        .buffer = &issuer_der,
        .index = 0,
    });

    var message: [2]u8 = undefined;
    var selected_signature: ?EcdsaP256Sha256.Signature = null;
    for (0..std.math.maxInt(u16) + 1) |counter| {
        std.mem.writeInt(u16, &message, @intCast(counter), .big);
        const candidate = try key_pair.sign(&message, null);
        if ((candidate.toBytes()[0] & 0x80) != 0) {
            selected_signature = candidate;
            break;
        }
    }
    const signature = selected_signature orelse
        return error.TestUnexpectedResult;
    var encoded_signature: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 =
        undefined;
    const der = signature.toDer(&encoded_signature);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x30, der[1], 0x02, 0x21, 0x00 },
        der[0..5],
    );
    try verify(.ecdsa_p256_sha256, issuer, &message, der);

    encoded_signature[der.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(
            .ecdsa_p256_sha256,
            issuer,
            &message,
            encoded_signature[0..der.len],
        ),
    );
}

test "RSA-PSS AlgorithmIdentifier requires a matching digest-length MGF1 profile" {
    const sha256_pss = sha256_pss_algorithm_identifier;
    try std.testing.expectEqual(
        Algorithm.rsa_pss_sha256,
        try parseAlgorithmIdentifier(&sha256_pss),
    );
    const restricted = try parsePssPublicKeyAlgorithmIdentifier(&sha256_pss);
    try std.testing.expect(restricted.permits(.rsa_pss_sha256));
    try std.testing.expect(!restricted.permits(.rsa_pss_sha384));

    var sha224_pss = sha256_pss;
    const first_sha256 = std.mem.indexOf(
        u8,
        &sha224_pss,
        &oid_sha256,
    ) orelse return error.TestUnexpectedResult;
    sha224_pss[first_sha256 + oid_sha256.len - 1] = oid_sha224[oid_sha224.len - 1];
    const second_sha256 = std.mem.indexOfPos(
        u8,
        &sha224_pss,
        first_sha256 + oid_sha256.len,
        &oid_sha256,
    ) orelse return error.TestUnexpectedResult;
    sha224_pss[second_sha256 + oid_sha256.len - 1] = oid_sha224[oid_sha224.len - 1];
    sha224_pss[sha224_pss.len - 1] = Sha224.digest_length;
    try std.testing.expectEqual(
        Algorithm.rsa_pss_sha224,
        try parseAlgorithmIdentifier(&sha224_pss),
    );

    const sha224_pkcs1 = [_]u8{
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x0e, 0x05,
        0x00,
    };
    try std.testing.expectEqual(
        Algorithm.rsa_pkcs1_sha224,
        try parseAlgorithmIdentifier(&sha224_pkcs1),
    );
    const sha1_pkcs1 = [_]u8{
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05,
        0x00,
    };
    try std.testing.expectEqual(
        Algorithm.rsa_pkcs1_sha1,
        try parseAlgorithmIdentifier(&sha1_pkcs1),
    );
    try std.testing.expectError(
        error.InvalidAlgorithmIdentifier,
        parseAlgorithmIdentifier(sha224_pkcs1[0 .. sha224_pkcs1.len - 2]),
    );
    const pss_oid_only = sha256_pss[0..11];
    const unrestricted = try parsePssPublicKeyAlgorithmIdentifier(pss_oid_only);
    try std.testing.expect(unrestricted.permits(.rsa_pss_sha256));
    try std.testing.expect(unrestricted.permits(.rsa_pss_sha512));
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
    var wrong_trailer = sha256_pss;
    wrong_trailer[wrong_trailer.len - 5] = 0xa3;
    try std.testing.expectError(
        error.UnsupportedSignatureAlgorithm,
        parsePssPublicKeyAlgorithmIdentifier(&wrong_trailer),
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
