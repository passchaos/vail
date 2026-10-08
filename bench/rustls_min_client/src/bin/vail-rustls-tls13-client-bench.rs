use aws_lc_rs::agreement;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, NamedGroup, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme,
};
use std::hint::black_box;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

const RPK_ITERATIONS: usize = 5_000;
const X509_ITERATIONS: usize = 2_000;
const PAIR_ITERATIONS: usize = 1_000;
const RESUMPTION_ITERATIONS: usize = 2_000;

const ED25519_PKCS8: [u8; 48] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
];

#[derive(Debug)]
struct FixedRandom(u8);

impl SecureRandom for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        output.fill(self.0);
        Ok(())
    }
}

static CLIENT_RANDOM: FixedRandom = FixedRandom(0x32);
static SERVER_RANDOM: FixedRandom = FixedRandom(0x35);

#[derive(Debug)]
struct FixedX25519 {
    secret: [u8; 32],
}

static CLIENT_X25519: FixedX25519 = FixedX25519 { secret: [0x31; 32] };
static SERVER_X25519: FixedX25519 = FixedX25519 { secret: [0x34; 32] };

struct FixedActiveX25519 {
    private_key: agreement::PrivateKey,
    public_key: Vec<u8>,
}

impl SupportedKxGroup for FixedX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &self.secret)
            .map_err(|_| Error::General("fixed X25519 private key rejected".into()))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| Error::General("fixed X25519 public key failed".into()))?
            .as_ref()
            .to_vec();
        Ok(Box::new(FixedActiveX25519 {
            private_key,
            public_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for FixedActiveX25519 {
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key);
        agreement::agree(
            &self.private_key,
            peer,
            Error::General("X25519 agreement failed".into()),
            |secret| Ok(SharedSecret::from(secret)),
        )
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[derive(Debug)]
struct RawServerVerifier {
    expected_spki: Vec<u8>,
}

impl ServerCertVerifier for RawServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref() != self.expected_spki
            || !intermediates.is_empty()
            || !ocsp_response.is_empty()
        {
            return Err(Error::General("unexpected server raw public key".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        spki: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(spki.as_ref()),
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn main() {
    let mode = match std::env::args().nth(1).as_deref() {
        None => Mode::Rpk,
        Some("x509") => Mode::X509,
        Some("pair-x509") => Mode::PairX509,
        Some("pair-x509-auto") => Mode::PairX509Auto,
        Some("resume") => Mode::Resume,
        Some(_) => panic!("expected x509, pair-x509, pair-x509-auto, or resume mode"),
    };
    let x509 = mode != Mode::Rpk;
    let (client_config, server_config) = match mode {
        Mode::Rpk => rpk_configs(),
        Mode::PairX509Auto => x509_auto_configs(),
        _ => x509_configs(mode == Mode::Resume),
    };
    let server_name =
        ServerName::try_from(if x509 { "localhost" } else { "example.com" }).expect("server name");
    if mode == Mode::PairX509 || mode == Mode::PairX509Auto {
        benchmark_pair(client_config, server_config, server_name);
        return;
    }
    if mode == Mode::Resume {
        benchmark_resumption(client_config, server_config, server_name);
        return;
    }
    let iterations = if x509 {
        X509_ITERATIONS
    } else {
        RPK_ITERATIONS
    };
    let (fixed_hello, server_flight) =
        build_and_validate_fixture(client_config.clone(), server_config, server_name.clone());

    let mut client_hello = Vec::with_capacity(fixed_hello.len());
    let mut client_finished = Vec::with_capacity(128);
    let mut checksum = 0u64;
    let mut finished_len = 0usize;

    let start = Instant::now();
    for _ in 0..iterations {
        client_hello.clear();
        client_finished.clear();
        let mut client = ClientConnection::new(client_config.clone(), server_name.clone())
            .expect("client connection");
        while client.wants_write() {
            client
                .write_tls(&mut client_hello)
                .expect("write ClientHello");
        }
        let mut input = Cursor::new(server_flight.as_slice());
        let consumed = client.read_tls(&mut input).expect("read server flight");
        assert_eq!(consumed, server_flight.len());
        client.process_new_packets().expect("verify server flight");
        assert!(!client.is_handshaking());
        while client.wants_write() {
            client
                .write_tls(&mut client_finished)
                .expect("write client Finished");
        }
        finished_len = client_finished.len();
        checksum =
            checksum.wrapping_add(u64::from(*client_finished.last().expect("client Finished")));
        black_box(client_hello.len());
    }
    let elapsed = start.elapsed();

    println!(
        "x25519_{}_aes128={} ns/rustls-client-{}-handshake hello={} server-flight={} finished={finished_len} checksum={checksum}",
        if x509 { "rsapss" } else { "ed25519" },
        elapsed.as_nanos() / iterations as u128,
        if x509 { "x509" } else { "connection" },
        fixed_hello.len(),
        server_flight.len(),
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Rpk,
    X509,
    PairX509,
    PairX509Auto,
    Resume,
}

struct PairBuffers {
    client_hello: Vec<u8>,
    server_flight: Vec<u8>,
    client_finished: Vec<u8>,
    ticket: Vec<u8>,
}

impl PairBuffers {
    fn new() -> Self {
        Self {
            client_hello: Vec::with_capacity(512),
            server_flight: Vec::with_capacity(1_536),
            client_finished: Vec::with_capacity(128),
            ticket: Vec::with_capacity(512),
        }
    }

    fn clear(&mut self) {
        self.client_hello.clear();
        self.server_flight.clear();
        self.client_finished.clear();
        self.ticket.clear();
    }
}

fn benchmark_resumption(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    server_name: ServerName<'static>,
) {
    let mut buffers = PairBuffers::new();
    run_pair_with_ticket(
        client_config.clone(),
        server_config.clone(),
        server_name.clone(),
        rustls::HandshakeKind::Full,
        &mut buffers,
    );

    let mut checksum = 0u64;
    let start = Instant::now();
    for _ in 0..RESUMPTION_ITERATIONS {
        run_pair_with_ticket(
            client_config.clone(),
            server_config.clone(),
            server_name.clone(),
            rustls::HandshakeKind::Resumed,
            &mut buffers,
        );
        checksum = checksum.wrapping_add(u64::from(
            *buffers.client_hello.last().expect("resumed ClientHello"),
        ));
        checksum = checksum.wrapping_add(u64::from(
            *buffers.server_flight.last().expect("resumed server flight"),
        ));
        checksum = checksum.wrapping_add(u64::from(
            *buffers.client_finished.last().expect("resumed Finished"),
        ));
        checksum = checksum.wrapping_add(u64::from(
            *buffers.ticket.last().expect("replacement ticket"),
        ));
    }
    let elapsed = start.elapsed();
    println!(
        "x25519_psk_aes128={} ns/rustls-resumed-handshake-ticket-rollover hello={} server-flight={} client-finished={} ticket={} checksum={checksum}",
        elapsed.as_nanos() / RESUMPTION_ITERATIONS as u128,
        buffers.client_hello.len(),
        buffers.server_flight.len(),
        buffers.client_finished.len(),
        buffers.ticket.len(),
    );
}

fn run_pair_with_ticket(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    server_name: ServerName<'static>,
    expected_kind: rustls::HandshakeKind,
    buffers: &mut PairBuffers,
) {
    buffers.clear();
    let mut client = ClientConnection::new(client_config, server_name).expect("client connection");
    while client.wants_write() {
        client
            .write_tls(&mut buffers.client_hello)
            .expect("write ClientHello");
    }
    let mut server = ServerConnection::new(server_config).expect("server connection");
    let mut input = Cursor::new(buffers.client_hello.as_slice());
    assert_eq!(
        server
            .read_tls(&mut input)
            .expect("server read ClientHello"),
        buffers.client_hello.len(),
    );
    server
        .process_new_packets()
        .expect("server process ClientHello");
    while server.wants_write() {
        server
            .write_tls(&mut buffers.server_flight)
            .expect("write server flight");
    }

    let mut input = Cursor::new(buffers.server_flight.as_slice());
    assert_eq!(
        client
            .read_tls(&mut input)
            .expect("client read server flight"),
        buffers.server_flight.len(),
    );
    client
        .process_new_packets()
        .expect("client process server flight");
    while client.wants_write() {
        client
            .write_tls(&mut buffers.client_finished)
            .expect("write client Finished");
    }

    let mut input = Cursor::new(buffers.client_finished.as_slice());
    assert_eq!(
        server.read_tls(&mut input).expect("server read Finished"),
        buffers.client_finished.len(),
    );
    server
        .process_new_packets()
        .expect("server process Finished");
    assert_eq!(client.handshake_kind(), Some(expected_kind));
    assert_eq!(server.handshake_kind(), Some(expected_kind));

    while server.wants_write() {
        server
            .write_tls(&mut buffers.ticket)
            .expect("write replacement ticket");
    }
    assert!(!buffers.ticket.is_empty());
    let mut input = Cursor::new(buffers.ticket.as_slice());
    assert_eq!(
        client.read_tls(&mut input).expect("client read ticket"),
        buffers.ticket.len(),
    );
    client
        .process_new_packets()
        .expect("client cache replacement ticket");
}

fn benchmark_pair(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    server_name: ServerName<'static>,
) {
    let mut client_hello = Vec::with_capacity(512);
    let mut server_flight = Vec::with_capacity(1_536);
    let mut client_finished = Vec::with_capacity(128);
    let mut checksum = 0u64;
    let mut hello_len = 0usize;
    let mut server_flight_len = 0usize;
    let mut client_finished_len = 0usize;

    let start = Instant::now();
    for _ in 0..PAIR_ITERATIONS {
        client_hello.clear();
        server_flight.clear();
        client_finished.clear();

        let mut client = ClientConnection::new(client_config.clone(), server_name.clone())
            .expect("client connection");
        while client.wants_write() {
            client
                .write_tls(&mut client_hello)
                .expect("write ClientHello");
        }
        let mut server = ServerConnection::new(server_config.clone()).expect("server connection");
        let mut input = Cursor::new(client_hello.as_slice());
        assert_eq!(
            server
                .read_tls(&mut input)
                .expect("server read ClientHello"),
            client_hello.len(),
        );
        server
            .process_new_packets()
            .expect("server process ClientHello");
        while server.wants_write() {
            server
                .write_tls(&mut server_flight)
                .expect("write server flight");
        }

        let mut input = Cursor::new(server_flight.as_slice());
        assert_eq!(
            client
                .read_tls(&mut input)
                .expect("client read server flight"),
            server_flight.len(),
        );
        client
            .process_new_packets()
            .expect("client process server flight");
        while client.wants_write() {
            client
                .write_tls(&mut client_finished)
                .expect("write client Finished");
        }

        let mut input = Cursor::new(client_finished.as_slice());
        assert_eq!(
            server.read_tls(&mut input).expect("server read Finished"),
            client_finished.len(),
        );
        server
            .process_new_packets()
            .expect("server process Finished");
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert_eq!(
            client.negotiated_cipher_suite().unwrap().suite(),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        );
        assert_eq!(
            server.negotiated_cipher_suite().unwrap().suite(),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        );

        hello_len = client_hello.len();
        server_flight_len = server_flight.len();
        client_finished_len = client_finished.len();
        checksum = checksum.wrapping_add(u64::from(client_hello[hello_len - 1]));
        checksum = checksum.wrapping_add(u64::from(server_flight[server_flight_len - 1]));
        checksum = checksum.wrapping_add(u64::from(client_finished[client_finished_len - 1]));
        black_box((&client, &server));
    }
    let elapsed = start.elapsed();
    println!(
        "x25519_rsapss_aes128={} ns/rustls-full-x509-handshake hello={hello_len} server-flight={server_flight_len} client-finished={client_finished_len} checksum={checksum}",
        elapsed.as_nanos() / PAIR_ITERATIONS as u128,
    );
}

fn rpk_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let private_key = PrivatePkcs8KeyDer::from(ED25519_PKCS8.to_vec());
    let signing_key =
        rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&private_key).expect("Ed25519 signing key");
    let spki = signing_key
        .public_key()
        .expect("Ed25519 SPKI")
        .as_ref()
        .to_vec();
    let certified_key = CertifiedKey::new(vec![CertificateDer::from(spki.clone())], signing_key);

    let client_provider = fixed_provider(&CLIENT_X25519, &CLIENT_RANDOM);
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(client_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 client provider")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RawServerVerifier {
            expected_spki: spki,
        }))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    client_config.cert_decompressors.clear();

    let server_provider = fixed_provider(&SERVER_X25519, &SERVER_RANDOM);
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 server provider")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            certified_key,
        ))));
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    server_config.max_tls13_tickets = 0;

    (Arc::new(client_config), Arc::new(server_config))
}

fn x509_configs(enable_tickets: bool) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut certificate_reader = Cursor::new(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../src/crypto/testdata/rsa_signing_cert.pem"
    )));
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("X.509 certificate");
    let mut key_reader = Cursor::new(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../src/crypto/testdata/rsa_signing_key.pem"
    )));
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("private-key PEM")
        .expect("private key");

    let mut roots = RootCertStore::empty();
    roots
        .add(certificates[0].clone())
        .expect("X.509 trust anchor");
    let client_provider = fixed_provider(&CLIENT_X25519, &CLIENT_RANDOM);
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(client_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 client provider")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    client_config.cert_decompressors.clear();
    if enable_tickets {
        client_config.resumption = rustls::client::Resumption::in_memory_sessions(256);
    }

    let server_provider = fixed_provider(&SERVER_X25519, &SERVER_RANDOM);
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 server provider")
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .expect("matching X.509 identity");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    if enable_tickets {
        server_config.ticketer =
            rustls::crypto::aws_lc_rs::Ticketer::new().expect("TLS 1.3 ticket key");
        server_config.send_tls13_tickets = 1;
    } else {
        server_config.max_tls13_tickets = 0;
    }

    (Arc::new(client_config), Arc::new(server_config))
}

fn x509_auto_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut certificate_reader = Cursor::new(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../src/crypto/testdata/rsa_signing_cert.pem"
    )));
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("X.509 certificate");
    let mut key_reader = Cursor::new(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../src/crypto/testdata/rsa_signing_key.pem"
    )));
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("private-key PEM")
        .expect("private key");

    let mut roots = RootCertStore::empty();
    roots
        .add(certificates[0].clone())
        .expect("X.509 trust anchor");
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(fixed_auto_provider(
        &CLIENT_X25519,
        &CLIENT_RANDOM,
    )))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("TLS 1.2/1.3 client provider")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    client_config.cert_decompressors.clear();

    let mut server_config = ServerConfig::builder_with_provider(Arc::new(fixed_auto_provider(
        &SERVER_X25519,
        &SERVER_RANDOM,
    )))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("TLS 1.2/1.3 server provider")
    .with_no_client_auth()
    .with_single_cert(certificates, private_key)
    .expect("matching X.509 identity");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    server_config.cert_compressors.clear();
    server_config.max_tls13_tickets = 0;

    (Arc::new(client_config), Arc::new(server_config))
}

fn fixed_provider(
    key_exchange: &'static dyn SupportedKxGroup,
    random: &'static dyn SecureRandom,
) -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![key_exchange];
    provider.secure_random = random;
    provider
}

fn fixed_auto_provider(
    key_exchange: &'static dyn SupportedKxGroup,
    random: &'static dyn SecureRandom,
) -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![key_exchange, rustls::crypto::aws_lc_rs::kx_group::SECP256R1];
    provider.secure_random = random;
    provider
}

fn build_and_validate_fixture(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    server_name: ServerName<'static>,
) -> (Vec<u8>, Vec<u8>) {
    let mut client = ClientConnection::new(client_config, server_name).expect("fixture client");
    let mut client_hello = Vec::with_capacity(512);
    while client.wants_write() {
        client
            .write_tls(&mut client_hello)
            .expect("fixture ClientHello");
    }

    let mut server = ServerConnection::new(server_config).expect("fixture server");
    let mut input = Cursor::new(client_hello.as_slice());
    let consumed = server.read_tls(&mut input).expect("fixture server read");
    assert_eq!(consumed, client_hello.len());
    server
        .process_new_packets()
        .expect("fixture server process");
    let mut server_flight = Vec::with_capacity(512);
    while server.wants_write() {
        server
            .write_tls(&mut server_flight)
            .expect("fixture server flight");
    }

    let mut input = Cursor::new(server_flight.as_slice());
    let consumed = client.read_tls(&mut input).expect("fixture client read");
    assert_eq!(consumed, server_flight.len());
    client
        .process_new_packets()
        .expect("fixture client process");
    assert!(!client.is_handshaking());
    let mut client_finished = Vec::with_capacity(128);
    while client.wants_write() {
        client
            .write_tls(&mut client_finished)
            .expect("fixture client Finished");
    }
    let mut input = Cursor::new(client_finished.as_slice());
    let consumed = server.read_tls(&mut input).expect("fixture Finished read");
    assert_eq!(consumed, client_finished.len());
    server
        .process_new_packets()
        .expect("fixture Finished process");
    assert!(!server.is_handshaking());

    (client_hello, server_flight)
}
