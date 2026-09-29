const std = @import("std");
const vail = @import("vail");

test "public modules are reachable" {
    try std.testing.expect(@hasDecl(vail, "crypto"));
    try std.testing.expect(@hasDecl(vail.crypto, "aes_gcm"));
    try std.testing.expect(@hasDecl(vail.crypto.aes_gcm, "Context"));
    try std.testing.expect(@hasDecl(vail.crypto, "hpke"));
    try std.testing.expect(@hasDecl(vail.crypto.hpke, "setupBaseSender"));
    try std.testing.expect(@hasDecl(vail.crypto.hpke, "setupBaseReceiver"));
    try std.testing.expect(@hasDecl(
        vail.crypto.hpke,
        "setupBaseReceiverWithKeyPair",
    ));
    try std.testing.expect(@hasDecl(vail.crypto.hpke, "SenderContext"));
    try std.testing.expect(@hasDecl(vail.crypto.hpke, "ReceiverContext"));
    try std.testing.expect(@hasDecl(
        vail.crypto.hpke.SenderContext,
        "exportSecret",
    ));
    try std.testing.expect(@hasDecl(vail.crypto, "mac"));
    try std.testing.expect(@hasDecl(vail.crypto, "memory"));
    try std.testing.expect(@hasDecl(vail.crypto, "rsa"));
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
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "writeClientCryptoFlight"));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "verifyClientCryptoFlight"));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "ClientResult"));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "ClientFlightResult"));
    try std.testing.expect(@hasDecl(
        vail.quic.tls_handshake.ClientResult,
        "deinit",
    ));
    try std.testing.expect(@hasDecl(
        vail.quic.tls_handshake.Result,
        "deinit",
    ));
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
    try std.testing.expect(@hasDecl(vail.tls, "certificate_compression"));
    try std.testing.expect(
        vail.tls.certificate_compression.Algorithm.brotli.supported(),
    );
    try std.testing.expect(@hasDecl(
        vail.tls.certificate_compression.Prepared,
        "initBrotli",
    ));
    try std.testing.expect(@hasDecl(vail.tls, "client_auth"));
    try std.testing.expect(@hasDecl(vail.tls, "client_handshake"));
    try std.testing.expect(@hasDecl(vail.tls, "client_hello"));
    try std.testing.expect(@hasField(
        vail.tls.client_hello.WriteOptions,
        "quic_transport_parameters",
    ));
    try std.testing.expect(@hasDecl(vail.tls, "ech"));
    try std.testing.expect(@hasDecl(vail.tls.ech, "selectConfig"));
    try std.testing.expect(@hasDecl(vail.tls.ech, "writeConfig"));
    try std.testing.expect(@hasDecl(vail.tls.ech, "ClientContext"));
    try std.testing.expect(@hasDecl(vail.tls.ech, "ServerContext"));
    try std.testing.expect(@hasDecl(vail.tls.ech, "ServerConfig"));
    try std.testing.expect(@hasDecl(vail.tls.ech, "openInitial"));
    try std.testing.expect(@hasDecl(vail.tls.ech, "acceptConfirmation"));
    try std.testing.expect(@hasDecl(
        vail.tls.ech,
        "appendGreasePskFromInner",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.client_connection,
        "EchClientConfig",
    ));
    try std.testing.expect(@hasField(
        vail.tls.client_connection.Config,
        "ech",
    ));
    try std.testing.expect(@hasField(
        vail.tls.server_connection.Config,
        "ech",
    ));
    try std.testing.expect(@hasField(
        vail.tls.client_connection.ClientConnection(1024, 256).Established,
        "ech_accepted",
    ));
    const Tls13Client = vail.tls.client_connection.ClientConnection(1024, 256);
    try std.testing.expect(@hasDecl(Tls13Client, "EchRejection"));
    try std.testing.expect(@hasField(Tls13Client.EchRejection, "retry_configs"));
    try std.testing.expect(@hasField(Tls13Client.Event, "ech_rejected"));
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
    try std.testing.expect(@hasDecl(vail.tls, "tls12"));
    try std.testing.expect(@hasDecl(
        vail.tls.tls12,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(vail.tls.tls12, "Session"));
    try std.testing.expect(@hasDecl(
        vail.tls,
        "tls12_client_connection",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_client_connection,
        "ClientConnection",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls,
        "tls12_server_connection",
    ));
    try std.testing.expect(@hasDecl(vail.tls, "tls12_ticket"));
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_server_connection,
        "ServerConnection",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_handshake,
        "parseCertificateStatus",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_ticket,
        "Cached",
    ));
    try std.testing.expect(@hasField(
        vail.tls.tls12_client_connection.Config,
        "ticket_resumption",
    ));
    try std.testing.expect(@hasField(
        vail.tls.tls12_client_connection.Config,
        "request_session_ticket",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_client_connection.Established,
        "createTicketSession",
    ));
    try std.testing.expect(@hasField(
        vail.tls.tls12_server_connection.Config,
        "session_tickets",
    ));
    try std.testing.expect(@hasField(
        vail.tls.client_connection.Config,
        "tls12_session_ticket",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.ticket_keyring.Keyring,
        "sealTls12",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.ticket_keyring.Keyring,
        "openTls12",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_server_connection,
        "SessionTicketPolicy",
    ));
    try std.testing.expect(@hasDecl(vail.tls, "transcript"));
    try std.testing.expect(@hasDecl(
        vail.tls.versioned_server_connection,
        "ServerConnection",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.versioned_client_connection,
        "ClientConnection",
    ));
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
    try std.testing.expect(@hasDecl(vail.tls.auth, "CertificateType"));
    try std.testing.expect(@hasDecl(vail.tls.auth, "Signer"));
    try std.testing.expect(@hasDecl(vail.tls.auth, "CustomSigner"));
    try std.testing.expect(@hasDecl(vail.tls.auth, "RsaPssSigner"));
    try std.testing.expect(@hasDecl(vail.tls.auth, "RsaPkcs1Signer"));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPkcs1v15Sha256",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.auth,
        "verifySignedContent",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.auth,
        "verifyTls12SignedContent",
    ));
    try std.testing.expect(@hasDecl(
        vail.tls.server_connection,
        "IdentityResolver",
    ));
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
        vail.tls.auth.ClientVerifier,
        "verifyRawPublicKey",
    ));
    try std.testing.expect(@hasField(
        vail.tls.auth.ClientVerifier,
        "pinned_raw_public_key",
    ));
    try std.testing.expect(@hasField(
        vail.tls.client_auth.ClientIdentity,
        "certificate_type",
    ));
    try std.testing.expect(@hasField(
        vail.tls.client_auth.ServerPolicy,
        "certificate_type",
    ));
    try std.testing.expect(@hasField(
        vail.tls.client_connection.Config,
        "server_certificate_type",
    ));
    try std.testing.expect(@hasField(
        vail.tls.server_connection.Config,
        "server_certificate_type",
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
