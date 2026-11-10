//! Test fixtures used by Vail's own tools and benchmarks.
//!
//! This namespace is not a stable public API. Production code should not
//! depend on these values.

pub const crypto = struct {
    pub const rsa_signing = @import("crypto/testdata/rsa_signing.zig");
};

pub const x509 = struct {
    pub const path_vectors = @import("x509/testdata/path_vectors.zig");
    pub const rsa_pss_root = @embedFile("x509/testdata/rsa-pss-crl-ca.der");
    pub const rsa_pss_constrained_leaf = @embedFile(
        "x509/testdata/rsa-pss-constrained-leaf.der",
    );
    pub const rsa_pss_constrained_private_key = @embedFile(
        "crypto/testdata/rsa-pss-constrained-private.pkcs8.der",
    );
};
