//! X.509 trust stores and verification policy.

pub const trust = @import("trust.zig");
pub const identity = @import("identity.zig");
pub const crl = @import("crl.zig");
pub const ocsp = @import("ocsp.zig");

pub const testing = struct {
    pub const path_vectors = @import("testdata/path_vectors.zig");
    pub const rsa_pss_root = @embedFile("testdata/rsa-pss-crl-ca.der");
    pub const rsa_pss_constrained_leaf = @embedFile(
        "testdata/rsa-pss-constrained-leaf.der",
    );
    pub const rsa_pss_constrained_private_key = @embedFile(
        "../crypto/testdata/rsa-pss-constrained-private.pkcs8.der",
    );
};

test {
    _ = crl;
    _ = identity;
    _ = ocsp;
    _ = @import("tests.zig");
}
