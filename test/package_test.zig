const std = @import("std");
const vail = @import("vail");

test "public modules are reachable" {
    try std.testing.expect(@hasDecl(vail, "crypto"));
    try std.testing.expect(@hasDecl(vail.crypto, "backend"));
    try std.testing.expect(@hasDecl(vail.crypto.backend, "selected"));
    try std.testing.expect(@hasDecl(
        vail.crypto.backend,
        "shangmi_provider",
    ));
    try std.testing.expect(@hasDecl(vail.crypto, "mac"));
    try std.testing.expect(@hasDecl(vail.crypto, "memory"));
    try std.testing.expect(@hasDecl(vail.crypto, "sha256"));
    try std.testing.expect(@hasDecl(vail.crypto, "sm2"));
    try std.testing.expect(@hasDecl(vail.crypto, "sm3"));
    try std.testing.expect(@hasDecl(vail.crypto, "sm4"));
    try std.testing.expect(@hasDecl(vail, "quic"));
    try std.testing.expect(@hasDecl(vail.quic, "initial"));
    try std.testing.expect(@hasDecl(vail.quic.initial, "deriveKeysForVersion"));
    try std.testing.expect(@hasDecl(vail.quic, "retry"));
    try std.testing.expect(@hasDecl(vail.quic.retry, "computeIntegrityTagForVersion"));
    try std.testing.expect(@hasDecl(vail.quic, "tls_handshake"));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "writeServerCryptoFlight"));
    try std.testing.expect(@hasDecl(vail.quic, "tls_secrets"));
    try std.testing.expect(@hasDecl(vail.quic.tls_secrets, "applicationKeys"));
    try std.testing.expect(@hasDecl(vail.quic, "traffic_crypto"));
    try std.testing.expect(@hasDecl(
        vail.quic.traffic_crypto,
        "aes256_sha384",
    ));
    try std.testing.expect(@hasDecl(vail.quic.traffic_crypto, "nextTrafficSecret"));
    try std.testing.expect(@hasDecl(vail.quic, "transport_parameters"));
    try std.testing.expect(@hasDecl(vail, "tls"));
    try std.testing.expect(@hasDecl(vail.tls, "auth"));
    try std.testing.expect(@hasDecl(vail.tls, "client_auth"));
    try std.testing.expect(@hasDecl(vail.tls, "client_handshake"));
    try std.testing.expect(@hasDecl(vail.tls, "client_hello"));
    try std.testing.expect(@hasDecl(vail.tls, "key_schedule"));
    try std.testing.expect(@hasDecl(
        vail.tls.key_schedule,
        "deriveExporterMasterSecretFor",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.key_schedule,
        "exportKeyingMaterialFor",
    ));
    try std.testing.expect(@hasDecl(vail.tls, "key_exchange"));
    try std.testing.expect(@hasDecl(vail.tls, "psk"));
    try std.testing.expect(@hasDecl(vail.tls, "record"));
    try std.testing.expect(@hasDecl(vail.tls, "secret"));
    try std.testing.expect(@hasDecl(vail.tls, "server_hello"));
    try std.testing.expect(@hasDecl(vail.tls, "server_handshake"));
    try std.testing.expect(@hasDecl(vail.tls, "server_flight"));
    try std.testing.expect(@hasDecl(vail.tls, "ticket"));
    try std.testing.expect(@hasDecl(vail.tls, "ticket_keyring"));
    try std.testing.expect(@hasDecl(vail.tls, "transcript"));
    try std.testing.expect(@hasDecl(vail, "x509"));
    try std.testing.expect(@hasDecl(vail.x509, "trust"));
    try std.testing.expect(@hasDecl(vail.x509, "identity"));
    try std.testing.expect(@hasDecl(vail.x509, "crl"));
    try std.testing.expect(@hasDecl(vail.x509.crl, "parseAndVerify"));
    try std.testing.expect(@hasDecl(
        vail.x509.identity,
        "commonNameAlloc",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.identity,
        "subjectNameAlloc",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust,
        "ClientCertificateBundleVerifier",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust,
        "validateClientCertificateAuthority",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust,
        "validateClientCertificateRevocationListIssuer",
    ));
    try std.testing.expect(@hasDecl(vail.tls.auth, "ServerIdentity"));
    try std.testing.expect(@hasDecl(vail.tls.auth, "Signer"));
    try std.testing.expect(@hasDecl(
        vail.tls.auth,
        "writeClientCertificateWithContext",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.auth,
        "parseClientCertificateWithContext",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.client_auth,
        "verifyClientFlight",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.client_hello,
        "write",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.server_hello,
        "parseServerHello",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.server_hello,
        "parseEncryptedExtensions",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.client_handshake,
        "verifyServerAndWriteClientFlight",
    ));
    try std.testing.expect(@hasField(
        vail.tls.client_auth.ServerPolicy,
        "requirement",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.transcript,
        "State",
    ));
}
