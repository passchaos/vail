use rustls::{ClientConfig, ClientConnection, HandshakeKind, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const RESPONSE: &[u8] = b"vail resumed tls13 ok\n";
const EARLY_DATA: &[u8] = b"rustls zero-rtt";

fn main() {
    let certificate_path = std::env::args().nth(1).expect("certificate path");
    let mut certificate_reader = BufReader::new(File::open(certificate_path).unwrap());
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificates[0].clone()).unwrap();

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols.push(b"h2".to_vec());
    config.enable_early_data = true;
    let config = Arc::new(config);

    run(config.clone(), HandshakeKind::Full, false);
    run(config, HandshakeKind::Resumed, true);
    println!("rustls/AWS-LC TLS 1.3 resumption and 0-RTT verified");
}

fn run(config: Arc<ClientConfig>, expected: HandshakeKind, send_early_data: bool) {
    let name = ServerName::try_from("localhost").unwrap();
    let mut connection = ClientConnection::new(config, name).unwrap();
    let mut socket = TcpStream::connect("127.0.0.1:24458").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    if send_early_data {
        let mut early = connection.early_data().expect("0-RTT-capable ticket");
        assert!(early.bytes_left() >= EARLY_DATA.len());
        early.write_all(EARLY_DATA).unwrap();
    } else {
        assert!(connection.early_data().is_none());
    }
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).unwrap();
    }
    assert_eq!(connection.handshake_kind(), Some(expected));
    assert_eq!(connection.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(connection.is_early_data_accepted(), send_early_data);

    let mut tls = StreamOwned::new(connection, socket);
    tls.write_all(b"ping").unwrap();
    tls.flush().unwrap();
    let mut response = vec![0u8; RESPONSE.len()];
    tls.read_exact(&mut response).unwrap();
    assert_eq!(response, RESPONSE);
}
