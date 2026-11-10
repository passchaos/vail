//! Signature algorithm identifiers shared by cryptographic and X.509 layers.
//!
//! Keeping this enum independent of both layers lets RSA key parsing and
//! certificate signature verification agree on the same wire-level names
//! without creating a dependency cycle.

pub const Algorithm = enum {
    /// RFC 5758 `ecdsa-with-SHA224`, using the issuer's P-256 or P-384 key.
    ecdsa_sha224,
    /// `ecdsa-with-SHA256`. The historical name is retained for API
    /// compatibility; verification selects P-256 or P-384 from the issuer key.
    ecdsa_p256_sha256,
    /// `ecdsa-with-SHA384`. The historical name is retained for API
    /// compatibility; verification selects P-256 or P-384 from the issuer key.
    ecdsa_p384_sha384,
    /// RFC 5758 `ecdsa-with-SHA512`, using the issuer's P-256 or P-384 key.
    ecdsa_sha512,
    ecdsa_sha3_224,
    ecdsa_sha3_256,
    ecdsa_sha3_384,
    ecdsa_sha3_512,
    ecdsa_shake128,
    ecdsa_shake256,
    rsa_pkcs1_sha1,
    rsa_pkcs1_sha224,
    rsa_pkcs1_sha256,
    rsa_pkcs1_sha384,
    rsa_pkcs1_sha512,
    rsa_pkcs1_sha512_224,
    rsa_pkcs1_sha512_256,
    rsa_pkcs1_sha3_224,
    rsa_pkcs1_sha3_256,
    rsa_pkcs1_sha3_384,
    rsa_pkcs1_sha3_512,
    rsa_pss_sha224,
    rsa_pss_sha256,
    rsa_pss_sha384,
    rsa_pss_sha512,
    rsa_pss_sha512_224,
    rsa_pss_sha512_256,
    rsa_pss_sha3_224,
    rsa_pss_sha3_256,
    rsa_pss_sha3_384,
    rsa_pss_sha3_512,
    rsa_pss_shake128,
    rsa_pss_shake256,
    ed25519,
};
