//! Vail cryptographic protocol library.
//!
//! Vail owns TLS, X.509, signatures, key schedules, and cryptographic state.
//! Transport libraries such as netz should depend on these protocol APIs
//! rather than embedding cryptographic logic.

pub const tls = @import("tls/mod.zig");
pub const x509 = @import("x509/mod.zig");

test {
    _ = tls.auth;
    _ = tls.client_auth;
    _ = tls.key_schedule;
    _ = tls.psk;
    _ = tls.ticket;
    _ = x509.trust;
}
