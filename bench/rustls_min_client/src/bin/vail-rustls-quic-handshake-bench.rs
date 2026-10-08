use aws_lc_rs::agreement;
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::ServerName;
use rustls::quic::{ClientConnection, KeyChange, ServerConnection, Version};
use rustls::server::ServerSessionMemoryCache;
use rustls::{ClientConfig, Error, HandshakeKind, NamedGroup, RootCertStore, ServerConfig};
use std::hint::black_box;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const ITERATIONS: usize = 1_000;
const RESUMPTION_ITERATIONS: usize = 2_000;
const CLIENT_TRANSPORT_PARAMETERS: &[u8] = &[0x01, 0x02, 0x03];
const SERVER_TRANSPORT_PARAMETERS: &[u8] = &[0x04, 0x05, 0x06];
const EARLY_HEADER: &[u8] = b"quic-0rtt-header";
const EARLY_PLAINTEXT: [u8; 1_200] = [0x5a; 1_200];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Full,
    Resume,
    Early,
}

#[derive(Debug)]
struct FixedRandom(u8);

impl SecureRandom for FixedRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        output.fill(self.0);
        Ok(())
    }
}

static CLIENT_RANDOM: FixedRandom = FixedRandom(0xd2);
static SERVER_RANDOM: FixedRandom = FixedRandom(0xc2);

#[derive(Debug)]
struct SequencedRandom {
    counter: AtomicU64,
}

impl SecureRandom for SequencedRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        let sequence = self.counter.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        output.fill(0xc2);
        for (dst, src) in output.iter_mut().rev().take(sequence.len()).zip(sequence) {
            *dst ^= src;
        }
        Ok(())
    }
}

static SERVER_EARLY_RANDOM: SequencedRandom = SequencedRandom {
    counter: AtomicU64::new(0),
};

#[derive(Debug)]
struct FixedX25519 {
    secret: [u8; 32],
}

static CLIENT_X25519: FixedX25519 = FixedX25519 { secret: [0xd1; 32] };
static SERVER_X25519: FixedX25519 = FixedX25519 { secret: [0xc1; 32] };

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

struct Buffers {
    client_initial: Vec<u8>,
    server_initial: Vec<u8>,
    server_handshake: Vec<u8>,
    client_handshake: Vec<u8>,
    ticket: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Self {
            client_initial: Vec::with_capacity(512),
            server_initial: Vec::with_capacity(128),
            server_handshake: Vec::with_capacity(1_536),
            client_handshake: Vec::with_capacity(128),
            ticket: Vec::with_capacity(512),
        }
    }

    fn clear(&mut self) {
        self.client_initial.clear();
        self.server_initial.clear();
        self.server_handshake.clear();
        self.client_handshake.clear();
        self.ticket.clear();
    }
}

struct HandshakeStats {
    client_initial_len: usize,
    server_initial_len: usize,
    server_handshake_len: usize,
    client_handshake_len: usize,
    ticket_len: usize,
    checksum: u64,
}

fn main() {
    let mode = match std::env::args().nth(1).as_deref() {
        None => Mode::Full,
        Some("resume") => Mode::Resume,
        Some("early") => Mode::Early,
        Some(_) => panic!("expected optional resume or early mode"),
    };
    let (client_config, server_config) = configs(mode);
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut buffers = Buffers::new();

    // Validate every QUIC encryption-level transition once before timing and
    // populate the reusable output buffers.
    run_handshake(
        &client_config,
        &server_config,
        &server_name,
        HandshakeKind::Full,
        mode != Mode::Full,
        false,
        &mut buffers,
    );

    if mode != Mode::Full {
        let mut previous_ticket = buffers.ticket.clone();
        let mut checksum = 0u64;
        let mut stats = HandshakeStats {
            client_initial_len: 0,
            server_initial_len: 0,
            server_handshake_len: 0,
            client_handshake_len: 0,
            ticket_len: 0,
            checksum: 0,
        };
        let start = Instant::now();
        for iteration in 0..RESUMPTION_ITERATIONS {
            stats = run_handshake(
                &client_config,
                &server_config,
                &server_name,
                HandshakeKind::Resumed,
                true,
                mode == Mode::Early,
                &mut buffers,
            );
            assert_ne!(buffers.ticket, previous_ticket);
            previous_ticket.clone_from(&buffers.ticket);
            checksum = checksum
                .wrapping_add(stats.checksum)
                .wrapping_add(iteration as u64);
            black_box(stats.checksum);
        }
        let elapsed = start.elapsed();
        println!(
            "x25519-psk-aes128={} ns/rustls-{}-quic-tls13-ticket-rollover client-initial={} server-initial={} server-handshake={} client-handshake={} ticket={} checksum={checksum}",
            elapsed.as_nanos() / RESUMPTION_ITERATIONS as u128,
            if mode == Mode::Early { "0rtt" } else { "resumed" },
            stats.client_initial_len,
            stats.server_initial_len,
            stats.server_handshake_len,
            stats.client_handshake_len,
            stats.ticket_len,
        );
        return;
    }

    let mut checksum = 0u64;
    let mut stats = HandshakeStats {
        client_initial_len: 0,
        server_initial_len: 0,
        server_handshake_len: 0,
        client_handshake_len: 0,
        ticket_len: 0,
        checksum: 0,
    };
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        stats = run_handshake(
            &client_config,
            &server_config,
            &server_name,
            HandshakeKind::Full,
            false,
            false,
            &mut buffers,
        );
        checksum = checksum
            .wrapping_add(stats.checksum)
            .wrapping_add(iteration as u64);
        black_box(stats.checksum);
    }
    let elapsed = start.elapsed();
    println!(
        "x25519-rsapss-aes128={} ns/rustls-full-quic-tls13-handshake client-initial={} server-initial={} server-handshake={} client-handshake={} checksum={checksum}",
        elapsed.as_nanos() / ITERATIONS as u128,
        stats.client_initial_len,
        stats.server_initial_len,
        stats.server_handshake_len,
        stats.client_handshake_len,
    );
}

fn run_handshake(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
    server_name: &ServerName<'static>,
    expected_kind: HandshakeKind,
    issue_ticket: bool,
    use_early_data: bool,
    buffers: &mut Buffers,
) -> HandshakeStats {
    buffers.clear();

    let mut client = ClientConnection::new(
        client_config.clone(),
        Version::V1,
        server_name.clone(),
        CLIENT_TRANSPORT_PARAMETERS.to_vec(),
    )
    .expect("QUIC client connection");
    let mut server = ServerConnection::new(
        server_config.clone(),
        Version::V1,
        SERVER_TRANSPORT_PARAMETERS.to_vec(),
    )
    .expect("QUIC server connection");

    assert!(drain_client(&mut client, &mut buffers.client_initial).is_none());
    assert!(!buffers.client_initial.is_empty());
    let client_early_keys = if use_early_data {
        Some(client.zero_rtt_keys().expect("client 0-RTT keys"))
    } else {
        None
    };
    let mut early_payload = EARLY_PLAINTEXT.to_vec();
    let early_tag = client_early_keys.as_ref().map(|keys| {
        keys.packet
            .encrypt_in_place(7, EARLY_HEADER, &mut early_payload)
            .expect("protect 0-RTT payload")
    });
    if let Some(tag) = early_tag {
        early_payload.extend_from_slice(tag.as_ref());
    }
    server
        .read_hs(&buffers.client_initial)
        .expect("server read ClientHello");
    if use_early_data {
        let server_early_keys = server.zero_rtt_keys().expect("server 0-RTT keys");
        let opened = server_early_keys
            .packet
            .decrypt_in_place(7, EARLY_HEADER, &mut early_payload)
            .expect("open 0-RTT payload");
        assert_eq!(opened, EARLY_PLAINTEXT);
    } else {
        assert!(client_early_keys.is_none());
        assert!(server.zero_rtt_keys().is_none());
    }

    let server_handshake_keys =
        drain_server(&mut server, &mut buffers.server_initial).expect("server handshake keys");
    assert!(matches!(
        &server_handshake_keys,
        KeyChange::Handshake { .. }
    ));
    assert!(!buffers.server_initial.is_empty());

    let server_one_rtt =
        drain_server(&mut server, &mut buffers.server_handshake).expect("server 1-RTT keys");
    assert!(matches!(&server_one_rtt, KeyChange::OneRtt { .. }));
    assert!(!buffers.server_handshake.is_empty());

    client
        .read_hs(&buffers.server_initial)
        .expect("client read ServerHello");
    let client_handshake_keys =
        drain_client(&mut client, &mut Vec::new()).expect("client handshake keys");
    assert!(matches!(
        &client_handshake_keys,
        KeyChange::Handshake { .. }
    ));

    client
        .read_hs(&buffers.server_handshake)
        .expect("client read server Handshake");
    let client_one_rtt =
        drain_client(&mut client, &mut buffers.client_handshake).expect("client 1-RTT keys");
    assert!(matches!(&client_one_rtt, KeyChange::OneRtt { .. }));
    assert!(!buffers.client_handshake.is_empty());

    server
        .read_hs(&buffers.client_handshake)
        .expect("server verify client Finished");
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(client.alpn_protocol(), Some(&b"h3"[..]));
    assert_eq!(server.alpn_protocol(), Some(&b"h3"[..]));
    assert_eq!(
        client.quic_transport_parameters(),
        Some(SERVER_TRANSPORT_PARAMETERS)
    );
    assert_eq!(
        server.quic_transport_parameters(),
        Some(CLIENT_TRANSPORT_PARAMETERS)
    );
    assert_eq!(
        client
            .negotiated_cipher_suite()
            .expect("client suite")
            .suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    );
    assert_eq!(
        server
            .negotiated_cipher_suite()
            .expect("server suite")
            .suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    );
    assert_eq!(client.handshake_kind(), Some(expected_kind));
    assert_eq!(server.handshake_kind(), Some(expected_kind));
    assert_eq!(client.is_early_data_accepted(), use_early_data);

    if issue_ticket {
        drain_server_post_handshake(&mut server, &mut buffers.ticket);
        assert!(!buffers.ticket.is_empty());
        client
            .read_hs(&buffers.ticket)
            .expect("client cache replacement ticket");
    }

    let stats = HandshakeStats {
        client_initial_len: buffers.client_initial.len(),
        server_initial_len: buffers.server_initial.len(),
        server_handshake_len: buffers.server_handshake.len(),
        client_handshake_len: buffers.client_handshake.len(),
        ticket_len: buffers.ticket.len(),
        checksum: u64::from(*buffers.client_initial.last().unwrap())
            .wrapping_add(u64::from(*buffers.server_initial.last().unwrap()))
            .wrapping_add(u64::from(*buffers.server_handshake.last().unwrap()))
            .wrapping_add(u64::from(*buffers.client_handshake.last().unwrap()))
            .wrapping_add(buffers.ticket.last().copied().map(u64::from).unwrap_or(0))
            .wrapping_add(if use_early_data {
                u64::from(early_payload[0])
            } else {
                0
            }),
    };
    black_box((
        &client,
        &server,
        &server_handshake_keys,
        &server_one_rtt,
        &client_handshake_keys,
        &client_one_rtt,
    ));
    stats
}

fn drain_client(connection: &mut ClientConnection, output: &mut Vec<u8>) -> Option<KeyChange> {
    loop {
        let before = output.len();
        if let Some(change) = connection.write_hs(output) {
            return Some(change);
        }
        if output.len() == before {
            return None;
        }
    }
}

fn drain_server(connection: &mut ServerConnection, output: &mut Vec<u8>) -> Option<KeyChange> {
    loop {
        let before = output.len();
        if let Some(change) = connection.write_hs(output) {
            return Some(change);
        }
        if output.len() == before {
            return None;
        }
    }
}

fn drain_server_post_handshake(connection: &mut ServerConnection, output: &mut Vec<u8>) {
    loop {
        let before = output.len();
        assert!(connection.write_hs(output).is_none());
        if output.len() == before {
            return;
        }
    }
}

fn configs(mode: Mode) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
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
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(fixed_provider(
        &CLIENT_X25519,
        &CLIENT_RANDOM,
    )))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 client provider")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h3".to_vec()];
    client_config.cert_decompressors.clear();
    if mode != Mode::Full {
        client_config.resumption = rustls::client::Resumption::in_memory_sessions(256);
    }
    client_config.enable_early_data = mode == Mode::Early;

    let server_random: &'static dyn SecureRandom = if mode == Mode::Early {
        &SERVER_EARLY_RANDOM
    } else {
        &SERVER_RANDOM
    };
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(fixed_provider(
        &SERVER_X25519,
        server_random,
    )))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 server provider")
    .with_no_client_auth()
    .with_single_cert(certificates, private_key)
    .expect("matching X.509 identity");
    server_config.alpn_protocols = vec![b"h3".to_vec()];
    server_config.cert_compressors.clear();
    if mode == Mode::Resume {
        server_config.ticketer =
            rustls::crypto::aws_lc_rs::Ticketer::new().expect("TLS 1.3 ticket key");
        server_config.send_tls13_tickets = 1;
    } else if mode == Mode::Early {
        server_config.session_storage = ServerSessionMemoryCache::new(256);
        server_config.send_tls13_tickets = 1;
        server_config.max_early_data_size = u32::MAX;
    } else {
        server_config.max_tls13_tickets = 0;
    }

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
