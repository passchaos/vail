//! Vail cryptographic protocol library.
//!
//! Vail owns TLS, X.509, signatures, key schedules, and cryptographic state.
//! Transport libraries such as netz should depend on these protocol APIs
//! rather than embedding cryptographic logic.

pub const tls = @import("tls/mod.zig");
pub const x509 = @import("x509/mod.zig");
pub const crypto = @import("crypto/mod.zig");
pub const quic = @import("quic/mod.zig");

test {
    _ = crypto.backend;
    _ = crypto.mac;
    _ = crypto.memory;
    _ = crypto.sha256;
    _ = crypto.sm2;
    _ = crypto.sm3;
    _ = crypto.sm4;
    _ = quic.initial;
    _ = quic.retry;
    _ = quic.tls_handshake;
    _ = quic.tls_secrets;
    _ = quic.traffic_crypto;
    _ = quic.transport_parameters;
    _ = tls.auth;
    _ = tls.cipher_suite;
    _ = tls.client_auth;
    _ = tls.client_hello;
    _ = tls.key_exchange;
    _ = tls.key_schedule;
    _ = tls.psk;
    _ = tls.record;
    _ = tls.secret;
    _ = tls.server_hello;
    _ = tls.server_handshake;
    _ = tls.server_flight;
    _ = tls.ticket;
    _ = tls.ticket_keyring;
    _ = tls.transcript;
    _ = x509.trust;
}
