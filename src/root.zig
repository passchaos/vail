//! Vail cryptographic protocol library.
//!
//! Vail owns TLS, X.509, signatures, key schedules, and cryptographic state.
//! Transport libraries such as netz should depend on these protocol APIs
//! rather than embedding cryptographic logic.

pub const tls = @import("tls/mod.zig");
pub const x509 = @import("x509/mod.zig");
pub const crypto = @import("crypto/mod.zig");
pub const quic = @import("quic/mod.zig");
pub const testdata = @import("testdata.zig");

test {
    _ = crypto;
    _ = tls;
    _ = x509;
    _ = quic;
    _ = testdata;
}
