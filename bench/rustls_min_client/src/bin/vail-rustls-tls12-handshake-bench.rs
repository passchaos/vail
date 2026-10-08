use aws_lc_rs::agreement;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, HandshakeKind, NamedGroup,
    ServerConfig, ServerConnection, SignatureScheme,
};
use std::hint::black_box;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

const ITERATIONS: usize = 500;
const RESUMPTION_ITERATIONS: usize = 20_000;

#[derive(Debug)]
struct FixedRandom(u8);

impl SecureRandom for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        output.fill(self.0);
        Ok(())
    }
}

static CLIENT_RANDOM: FixedRandom = FixedRandom(0xa1);
static SERVER_RANDOM: FixedRandom = FixedRandom(0xa2);

#[derive(Debug)]
struct FixedP256 {
    secret: [u8; 32],
}

static CLIENT_P256: FixedP256 = FixedP256 {
    secret: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ],
};
static SERVER_P256: FixedP256 = FixedP256 {
    secret: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 5,
    ],
};

struct FixedActiveP256 {
    private_key: agreement::PrivateKey,
    public_key: Vec<u8>,
}

impl SupportedKxGroup for FixedP256 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let private_key =
            agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, &self.secret)
                .map_err(|_| Error::General("fixed P-256 private key rejected".into()))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| Error::General("fixed P-256 public key failed".into()))?
            .as_ref()
            .to_vec();
        Ok(Box::new(FixedActiveP256 {
            private_key,
            public_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

impl ActiveKeyExchange for FixedActiveP256 {
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key);
        agreement::agree(
            &self.private_key,
            peer,
            Error::General("P-256 agreement failed".into()),
            |secret| Ok(SharedSecret::from(secret)),
        )
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

#[derive(Debug)]
struct NoTrustVerifier {
    signature_scheme: SignatureScheme,
}

impl ServerCertVerifier for NoTrustVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() || !ocsp_response.is_empty() {
            return Err(Error::General("unexpected certificate metadata".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != self.signature_scheme {
            return Err(Error::General("unexpected TLS 1.2 signature scheme".into()));
        }
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.3 is disabled".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![self.signature_scheme]
    }
}

struct Buffers {
    client_hello: Vec<u8>,
    server_flight: Vec<u8>,
    client_flight: Vec<u8>,
    server_finished: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Self {
            client_hello: Vec::with_capacity(512),
            server_flight: Vec::with_capacity(1_536),
            client_flight: Vec::with_capacity(256),
            server_finished: Vec::with_capacity(128),
        }
    }

    fn clear(&mut self) {
        self.client_hello.clear();
        self.server_flight.clear();
        self.client_flight.clear();
        self.server_finished.clear();
    }
}

fn main() {
    let mode = std::env::args().nth(1);
    let (use_pss, use_aes256, resume, use_session_id) = match mode.as_deref() {
        None | Some("pkcs1") => (false, false, false, false),
        Some("pss") => (true, false, false, false),
        Some("aes256") => (false, true, false, false),
        Some("resume") => (false, false, true, false),
        Some("resume-session") => (false, false, true, true),
        Some(_) => panic!("expected pkcs1, pss, aes256, resume, or resume-session mode"),
    };
    let (client_config, server_config) = configs(use_pss, use_aes256, resume, use_session_id);
    let expected_suite = if use_aes256 {
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    } else {
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    };
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut buffers = Buffers::new();
    let mut checksum = 0u64;

    run_pair(
        client_config.clone(),
        server_config.clone(),
        server_name.clone(),
        HandshakeKind::Full,
        expected_suite,
        &mut buffers,
    );
    if resume {
        let mut previous_server_flight = buffers.server_flight.clone();
        let start = Instant::now();
        for iteration in 0..RESUMPTION_ITERATIONS {
            run_pair(
                client_config.clone(),
                server_config.clone(),
                server_name.clone(),
                HandshakeKind::Resumed,
                expected_suite,
                &mut buffers,
            );
            if !use_session_id {
                assert_ne!(buffers.server_flight, previous_server_flight);
            }
            previous_server_flight.clone_from(&buffers.server_flight);
            checksum = checksum.wrapping_add(u64::from(*buffers.client_hello.last().unwrap()));
            checksum = checksum.wrapping_add(u64::from(*buffers.server_flight.last().unwrap()));
            checksum = checksum.wrapping_add(u64::from(*buffers.client_flight.last().unwrap()));
            checksum = checksum.wrapping_add(iteration as u64);
        }
        let elapsed = start.elapsed();
        println!(
            "tls12-{}-aes128={} ns/rustls-resumed-handshake-{} hello={} server-flight={} client-finished={} checksum={checksum}",
            if use_session_id { "session" } else { "ticket" },
            elapsed.as_nanos() / RESUMPTION_ITERATIONS as u128,
            if use_session_id { "session-reuse" } else { "ticket-rollover" },
            buffers.client_hello.len(),
            buffers.server_flight.len(),
            buffers.client_flight.len(),
        );
        return;
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        run_pair(
            client_config.clone(),
            server_config.clone(),
            server_name.clone(),
            HandshakeKind::Full,
            expected_suite,
            &mut buffers,
        );
        checksum = checksum.wrapping_add(u64::from(*buffers.client_hello.last().unwrap()));
        checksum = checksum.wrapping_add(u64::from(*buffers.server_flight.last().unwrap()));
        checksum = checksum.wrapping_add(u64::from(*buffers.client_flight.last().unwrap()));
        checksum = checksum.wrapping_add(u64::from(*buffers.server_finished.last().unwrap()));
        checksum = checksum.wrapping_add(iteration as u64);
    }
    let elapsed = start.elapsed();
    println!(
        "p256-rsa2048-{}-{}={} ns/rustls-full-tls12-handshake hello={} server-flight={} client-flight={} server-finished={} checksum={checksum}",
        if use_pss { "pss" } else { "pkcs1" },
        if use_aes256 { "aes256" } else { "aes128" },
        elapsed.as_nanos() / ITERATIONS as u128,
        buffers.client_hello.len(),
        buffers.server_flight.len(),
        buffers.client_flight.len(),
        buffers.server_finished.len(),
    );
}

fn run_pair(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    server_name: ServerName<'static>,
    expected_kind: HandshakeKind,
    expected_suite: rustls::CipherSuite,
    buffers: &mut Buffers,
) {
    buffers.clear();
    let mut client = ClientConnection::new(client_config, server_name).expect("client connection");
    while client.wants_write() {
        client
            .write_tls(&mut buffers.client_hello)
            .expect("write ClientHello");
    }

    let mut server = ServerConnection::new(server_config).expect("server connection");
    read_and_process_server(
        &mut server,
        &buffers.client_hello,
        "server process ClientHello",
    );
    while server.wants_write() {
        server
            .write_tls(&mut buffers.server_flight)
            .expect("write server flight");
    }

    read_and_process_client(
        &mut client,
        &buffers.server_flight,
        "client process server flight",
    );
    while client.wants_write() {
        client
            .write_tls(&mut buffers.client_flight)
            .expect("write client flight");
    }

    read_and_process_server(
        &mut server,
        &buffers.client_flight,
        "server process client flight",
    );
    while server.wants_write() {
        server
            .write_tls(&mut buffers.server_finished)
            .expect("write server Finished");
    }

    read_and_process_client(
        &mut client,
        &buffers.server_finished,
        "client process server Finished",
    );
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(client.handshake_kind(), Some(expected_kind));
    assert_eq!(server.handshake_kind(), Some(expected_kind));
    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        expected_suite,
    );
    assert_eq!(
        server.negotiated_cipher_suite().unwrap().suite(),
        expected_suite,
    );
    black_box((&client, &server));
}

fn read_and_process_client(connection: &mut ClientConnection, input: &[u8], context: &str) {
    let mut input = Cursor::new(input);
    assert_eq!(
        connection.read_tls(&mut input).expect("read TLS bytes"),
        input.get_ref().len(),
    );
    connection.process_new_packets().expect(context);
}

fn read_and_process_server(connection: &mut ServerConnection, input: &[u8], context: &str) {
    let mut input = Cursor::new(input);
    assert_eq!(
        connection.read_tls(&mut input).expect("read TLS bytes"),
        input.get_ref().len(),
    );
    connection.process_new_packets().expect(context);
}

fn configs(
    use_pss: bool,
    use_aes256: bool,
    enable_resumption: bool,
    use_session_id: bool,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
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

    let client_provider = fixed_provider(&CLIENT_P256, &CLIENT_RANDOM, use_aes256);
    let signature_scheme = if use_pss {
        SignatureScheme::RSA_PSS_SHA256
    } else {
        SignatureScheme::RSA_PKCS1_SHA256
    };
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(client_provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 client provider")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoTrustVerifier { signature_scheme }))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    client_config.resumption = if enable_resumption {
        rustls::client::Resumption::in_memory_sessions(256)
    } else {
        rustls::client::Resumption::disabled()
    };

    let server_provider = fixed_provider(&SERVER_P256, &SERVER_RANDOM, use_aes256);
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 server provider")
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .expect("matching X.509 identity");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    if enable_resumption && use_session_id {
        server_config.session_storage = ServerSessionMemoryCache::new(256);
    } else if enable_resumption {
        server_config.session_storage = Arc::new(NoServerSessionStorage {});
        server_config.ticketer =
            rustls::crypto::aws_lc_rs::Ticketer::new().expect("TLS 1.2 ticket key");
    }

    (Arc::new(client_config), Arc::new(server_config))
}

fn fixed_provider(
    key_exchange: &'static dyn SupportedKxGroup,
    random: &'static dyn SecureRandom,
    use_aes256: bool,
) -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![if use_aes256 {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    } else {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    }];
    provider.kx_groups = vec![key_exchange];
    provider.secure_random = random;
    provider
}
