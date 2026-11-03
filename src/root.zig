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
    _ = crypto.aes_gcm;
    _ = crypto.blake2s;
    _ = crypto.chacha20_poly1305;
    _ = crypto.ed25519;
    _ = crypto.hpke;
    _ = crypto.mac;
    _ = crypto.memory;
    _ = crypto.p256;
    _ = crypto.rsa;
    _ = crypto.sha256;
    _ = crypto.sm2;
    _ = crypto.sm3;
    _ = crypto.sm4;
    _ = crypto.x25519;
    _ = crypto.xchacha20_poly1305;
    _ = quic.initial;
    _ = quic.retry;
    _ = quic.tls_handshake;
    _ = quic.tls_secrets;
    _ = quic.traffic_crypto;
    _ = quic.transport_parameters;
    _ = tls.alert;
    _ = tls.auth;
    _ = tls.certificate_compression;
    _ = tls.cipher_suite;
    _ = tls.client_auth;
    _ = tls.client_connection;
    _ = tls.client_hello;
    _ = tls.connection;
    _ = tls.early_data;
    _ = tls.ech;
    _ = tls.key_exchange;
    _ = tls.key_schedule;
    _ = tls.key_update;
    _ = tls.psk;
    _ = tls.record;
    _ = tls.secret;
    _ = tls.stream;
    _ = tls.traffic;
    _ = tls.versioned_server_connection;
    _ = tls.versioned_client_connection;
    _ = tls.server_hello;
    _ = tls.server_handshake;
    _ = tls.server_connection;
    _ = tls.server_flight;
    _ = tls.ticket;
    _ = tls.ticket_keyring;
    _ = tls.tls12;
    _ = tls.tls12_client_connection;
    _ = tls.tls12_handshake;
    _ = tls.tls12_server_connection;
    _ = tls.tls12_ticket;
    _ = tls.transcript;
    _ = x509.trust;
    _ = x509.ocsp;
}
