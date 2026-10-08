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
    try std.testing.expect(@hasDecl(vail.crypto, "p256"));
    try std.testing.expect(@hasDecl(vail.crypto.p256, "verify"));
    try std.testing.expect(@hasDecl(
        vail.crypto.p256,
        "PreparedVerifier",
    ));
    try std.testing.expect(@hasDecl(vail.crypto, "p521"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "verify"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "PublicKey"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "SecretKey"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "KeyPair"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "Signature"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "PreparedNonce"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "SigningError"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "GenerateError"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "KeyAgreementError"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "ecdhPublicKey"));
    try std.testing.expect(@hasDecl(vail.crypto.p521, "ecdhSharedSecret"));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.SecretKey,
        "fromBytes",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.KeyPair,
        "fromSecretKey",
    ));
    try std.testing.expect(@hasDecl(vail.crypto.p521.KeyPair, "fromDer"));
    try std.testing.expect(@hasDecl(vail.crypto.p521.KeyPair, "generate"));
    try std.testing.expect(@hasDecl(vail.crypto.p521.KeyPair, "sign"));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.KeyPair,
        "prepareNonce",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.KeyPair,
        "prepareRandomNonce",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.KeyPair,
        "prepareNonceBatch",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.KeyPair,
        "prepareRandomNonceBatch",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.KeyPair,
        "signPrepared",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.Signature,
        "toDer",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.PublicKey,
        "fromSec1",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521.PublicKey,
        "verify",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521,
        "PreparedVerifier",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521,
        "ThroughputPreparedVerifier",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521,
        "CompactPreparedVerifier",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.p521,
        "validatePublicKey",
    ));
    try std.testing.expect(@hasDecl(vail.crypto, "rsa"));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPssSha3_256",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPkcs1v15Sha3_256",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPssSha3_512",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPkcs1v15Sha3_512",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPssSha512_224",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPssSha512_256",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPkcs1v15Sha512_224",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPkcs1v15Sha512_256",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPssSha512_224",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPssSha512_256",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPkcs1v15Sha512_224",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPkcs1v15Sha512_256",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPssShake128",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PrivateKey,
        "signPssShake256",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPssShake128",
    ));
    try std.testing.expect(@hasDecl(
        vail.crypto.rsa.PreparedPrivateKey,
        "signPssShake256",
    ));
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
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "prepareRetryState"));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "clientEarlyPacketKeys"));
    try std.testing.expect(@hasDecl(
        vail.quic.tls_handshake,
        "authenticateEchRejection",
    ));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "EchRejection"));
    try std.testing.expect(@hasDecl(
        vail.quic.tls_handshake.EchRejection,
        "deinit",
    ));
    try std.testing.expectEqual(
        @as(u64, 0x179),
        vail.quic.tls_handshake.ech_required_crypto_error,
    );
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "ClientResult"));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "ClientFlightResult"));
    try std.testing.expect(@hasDecl(vail.quic.tls_handshake, "ResumptionPsk"));
    try std.testing.expect(@hasDecl(
        vail.quic.tls_handshake.ClientResult,
        "deinit",
    ));
    try std.testing.expect(@hasDecl(
        vail.quic.tls_handshake.Result,
        "deinit",
    ));
    try std.testing.expect(@hasField(
        vail.quic.tls_handshake.Result,
        "resumed",
    ));
    try std.testing.expect(@hasField(
        vail.quic.tls_handshake.Result,
        "client_early_packet_keys",
    ));
    try std.testing.expect(@hasField(
        vail.quic.tls_handshake.Result,
        "ech_accepted",
    ));
    try std.testing.expect(@hasField(
        vail.quic.tls_handshake.Result,
        "ech_rejected",
    ));
    try std.testing.expect(@hasField(
        vail.quic.tls_handshake.ClientResult,
        "ech_accepted",
    ));
    try std.testing.expect(@hasDecl(vail.quic, "tls_secrets"));
    try std.testing.expect(@hasDecl(vail.quic.tls_secrets, "applicationKeys"));
    try std.testing.expect(@hasDecl(
        vail.quic.tls_secrets.DirectionalKeys,
        "deinit",
    ));
    try std.testing.expect(@hasDecl(vail.quic, "traffic_crypto"));
    try std.testing.expect(@hasDecl(
        vail.quic.traffic_crypto,
        "aes256_sha384",
    ));
    try std.testing.expect(@hasDecl(vail.quic.traffic_crypto, "nextTrafficSecret"));
    try std.testing.expect(@hasDecl(vail.quic.traffic_crypto.Keys, "deinit"));
    try std.testing.expect(@hasDecl(vail.quic, "transport_parameters"));
    try std.testing.expect(@hasDecl(vail, "tls"));
    try std.testing.expect(@hasDecl(vail.tls, "auth"));
    try std.testing.expect(@hasField(vail.tls.auth.Signer, "ml_dsa_44"));
    try std.testing.expect(@hasField(vail.tls.auth.Signer, "ml_dsa_65"));
    try std.testing.expect(@hasField(vail.tls.auth.Signer, "ml_dsa_87"));
    try std.testing.expect(@hasField(
        vail.tls.auth.Signer,
        "ecdsa_p521_sha512",
    ));
    try std.testing.expect(@hasField(
        vail.tls.auth.Signer,
        "ecdsa_p521_sha512_prepared",
    ));
    try std.testing.expectEqual(
        @as(u16, 0x0904),
        vail.tls.auth.signature_scheme_ml_dsa_44,
    );
    try std.testing.expectEqual(
        @as(u16, 0x0603),
        vail.tls.auth.signature_scheme_ecdsa_secp521r1_sha512,
    );
    try std.testing.expect(@hasField(
        vail.tls.auth.ClientVerifier,
        "pinned_ecdsa_p521_public_key",
    ));
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
    try std.testing.expect(@hasDecl(
        vail.tls.client_hello,
        "validateSecondClientHello",
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
    try std.testing.expect(@hasDecl(
        Tls13Client.Established,
        "exportKeyingMaterial",
    ));
    const Tls13Server = vail.tls.server_connection.ServerConnection(1024, 256);
    try std.testing.expect(@hasDecl(
        Tls13Server.Established,
        "exportKeyingMaterial",
    ));
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
    try std.testing.expect(@hasDecl(vail.tls.key_exchange, "mlkem768"));
    try std.testing.expect(@hasDecl(vail.tls.key_exchange, "mlkem1024"));
    try std.testing.expect(@hasDecl(vail.tls.key_exchange, "p521"));
    try std.testing.expectEqual(
        @as(u16, 0x0019),
        vail.tls.key_exchange.named_group_secp521r1,
    );
    try std.testing.expect(@hasField(
        vail.tls.key_exchange.ClientKeyMaterial,
        "secp521r1",
    ));
    try std.testing.expect(@hasField(
        vail.tls.key_exchange.ServerKeyMaterial,
        "secp521r1",
    ));
    try std.testing.expect(@hasField(
        vail.tls.key_exchange.ClientKeyMaterial,
        "mlkem768",
    ));
    try std.testing.expect(@hasField(
        vail.tls.key_exchange.ServerKeyMaterial,
        "mlkem768",
    ));
    try std.testing.expect(@hasField(
        vail.tls.key_exchange.ClientKeyMaterial,
        "mlkem1024",
    ));
    try std.testing.expect(@hasField(
        vail.tls.key_exchange.ServerKeyMaterial,
        "mlkem1024",
    ));
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
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_client_connection.Established,
        "exportKeyingMaterial",
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
    try std.testing.expect(@hasDecl(
        vail.tls.tls12_server_connection.Established,
        "exportKeyingMaterial",
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
        "CrlSignerBundleVerifier",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust,
        "CertificateAuthorityBundleVerifier",
    ));
    try std.testing.expect(@hasField(
        vail.x509.trust.BundleVerifier,
        "compatible_trust_anchors",
    ));
    try std.testing.expect(@hasField(
        vail.x509.trust.PathLimits,
        "max_compatible_trust_anchors",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.SystemStore,
        "initEmpty",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.SystemStore,
        "addCompatibleCertificate",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.SystemStore,
        "addCompatiblePem",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.SystemStore,
        "addUnsupportedPem",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.SystemStore,
        "addCompatiblePemFile",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.SystemStore,
        "addCompatiblePemFileAbsolute",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.SystemStore,
        "PemFileOptions",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust,
        "validateClientCertificateAuthority",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust,
        "validateClientCertificateRevocationListIssuer",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust,
        "validateCertificateRevocationListSigner",
    ));
    try std.testing.expect(@hasDecl(vail.x509.crl, "CombinedList"));
    try std.testing.expect(@hasDecl(
        vail.x509.crl,
        "DistributionPointUrls",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.crl,
        "distributionPointUrls",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.crl,
        "certificateFreshestCrlUrls",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.crl,
        "listFreshestCrlUrls",
    ));
    try std.testing.expect(@hasDecl(vail.x509.crl, "Fetcher"));
    try std.testing.expect(@hasDecl(vail.x509.crl, "fetchLatestDelta"));
    try std.testing.expect(@hasDecl(vail.x509.crl, "ConditionalFetcher"));
    try std.testing.expect(@hasDecl(vail.x509.crl, "DeltaCache"));
    try std.testing.expect(@hasDecl(vail.x509.crl, "refreshDeltaCache"));
    try std.testing.expect(@hasDecl(vail.x509.crl, "SignerPathOptions"));
    try std.testing.expect(@hasDecl(
        vail.x509.crl,
        "SharedAnchorPathOptions",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.crl,
        "AuthorizedIndirectList",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.crl,
        "AuthorizedIndirectCombinedList",
    ));
    try std.testing.expect(@hasDecl(vail.x509, "distinguished_name"));
    try std.testing.expect(@hasDecl(vail.x509, "policy"));
    try std.testing.expect(@hasDecl(vail.x509, "certificate_set"));
    try std.testing.expect(@hasDecl(vail.x509, "issuer_fetch"));
    try std.testing.expect(@hasDecl(
        vail.x509.certificate_set,
        "Certificates",
    ));
    try std.testing.expect(@hasDecl(vail.x509.certificate_set, "parse"));
    try std.testing.expect(@hasDecl(vail.x509.certificate_set, "parseBer"));
    try std.testing.expect(@hasDecl(vail.x509.issuer_fetch, "Fetcher"));
    try std.testing.expect(@hasDecl(vail.x509.issuer_fetch, "Options"));
    try std.testing.expect(@hasDecl(vail.x509.issuer_fetch, "resolve"));
    try std.testing.expect(@hasField(
        vail.x509.issuer_fetch.Options,
        "allow_ber_certs_only",
    ));
    try std.testing.expect(@hasDecl(
        vail.x509.trust.BundleVerifier,
        "verifyWithFetchedIssuers",
    ));
    try std.testing.expect(@hasDecl(vail.x509.ocsp, "responderUrls"));
    try std.testing.expect(@hasDecl(vail.x509.ocsp, "caIssuerUrls"));
    try std.testing.expect(@hasDecl(vail.x509.ocsp, "verifyWithP521"));
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
