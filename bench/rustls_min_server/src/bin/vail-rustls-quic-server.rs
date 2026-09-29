use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::quic::{KeyChange, ServerConnection, Version};
use rustls::ServerConfig;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

const MAX_CRYPTO_FLIGHT: usize = 64 * 1024;
const CLIENT_TRANSPORT_PARAMETERS: &[u8] = &[0x01, 0x02, 0x03];
const SERVER_TRANSPORT_PARAMETERS: &[u8] = &[0x04, 0x05, 0x06];

fn main() {
    let mut args = std::env::args();
    let _executable = args.next();
    let certificate_path = args.next().expect("certificate path");
    let key_path = args.next().expect("private-key path");
    assert!(args.next().is_none());

    let mut certificate_reader = BufReader::new(File::open(certificate_path).unwrap());
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = BufReader::new(File::open(key_path).unwrap());
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .unwrap()
        .expect("private key");

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .unwrap();
    config.alpn_protocols.push(b"h3".to_vec());

    let listener = TcpListener::bind("127.0.0.1:24457").unwrap();
    let (mut socket, _) = listener.accept().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut connection = ServerConnection::new(
        Arc::new(config),
        Version::V1,
        SERVER_TRANSPORT_PARAMETERS.to_vec(),
    )
    .unwrap();

    let client_initial = read_frame(&mut socket);
    connection.read_hs(&client_initial).unwrap();
    let mut server_initial = Vec::new();
    assert!(matches!(
        drain_until_key_change(&mut connection, &mut server_initial),
        Some(KeyChange::Handshake { .. })
    ));
    assert!(!server_initial.is_empty());
    write_frame(&mut socket, &server_initial);

    let mut server_handshake = Vec::new();
    assert!(matches!(
        drain_until_key_change(&mut connection, &mut server_handshake),
        Some(KeyChange::OneRtt { .. })
    ));
    assert!(!server_handshake.is_empty());
    write_frame(&mut socket, &server_handshake);

    let client_handshake = read_frame(&mut socket);
    connection.read_hs(&client_handshake).unwrap();
    assert!(!connection.is_handshaking());
    assert_eq!(connection.alpn_protocol(), Some(&b"h3"[..]));
    assert_eq!(
        connection.quic_transport_parameters(),
        Some(CLIENT_TRANSPORT_PARAMETERS)
    );
    println!("rustls/AWS-LC QUIC server verified Vail client");
}

fn drain_until_key_change(
    connection: &mut ServerConnection,
    output: &mut Vec<u8>,
) -> Option<KeyChange> {
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

fn write_frame(stream: &mut std::net::TcpStream, bytes: &[u8]) {
    assert!(!bytes.is_empty());
    assert!(bytes.len() <= MAX_CRYPTO_FLIGHT);
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}

fn read_frame(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length != 0 && length <= MAX_CRYPTO_FLIGHT);
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}
