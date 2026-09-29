use rustls::quic::{ClientConnection, KeyChange, Version};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const MAX_CRYPTO_FLIGHT: usize = 64 * 1024;
const CLIENT_TRANSPORT_PARAMETERS: &[u8] = &[0x01, 0x02, 0x03];
const SERVER_TRANSPORT_PARAMETERS: &[u8] = &[0x04, 0x05, 0x06];

#[derive(Clone, Copy)]
enum GroupMode {
    X25519,
    Hybrid,
    MlKem768,
    MlKem1024,
}

fn main() {
    let mut args = std::env::args();
    let _executable = args.next();
    let certificate_path = args.next().expect("certificate path");
    let mode = match args.next().as_deref() {
        None => GroupMode::X25519,
        Some("hybrid") => GroupMode::Hybrid,
        Some("mlkem") => GroupMode::MlKem768,
        Some("mlkem1024") => GroupMode::MlKem1024,
        Some(_) => panic!("expected optional hybrid, mlkem, or mlkem1024 mode"),
    };
    assert!(args.next().is_none());
    let mut certificate_reader = BufReader::new(File::open(certificate_path).unwrap());
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificates[0].clone()).unwrap();

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = match mode {
        GroupMode::X25519 => vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
        GroupMode::Hybrid => {
            vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768]
        }
        GroupMode::MlKem768 => vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM768],
        GroupMode::MlKem1024 => vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM1024],
    };
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols.push(b"h3".to_vec());

    let mut connection = ClientConnection::new(
        Arc::new(config),
        Version::V1,
        ServerName::try_from("localhost").unwrap(),
        CLIENT_TRANSPORT_PARAMETERS.to_vec(),
    )
    .unwrap();
    let mut socket = TcpStream::connect(match mode {
        GroupMode::X25519 => "127.0.0.1:24456",
        GroupMode::Hybrid => "127.0.0.1:24460",
        GroupMode::MlKem768 => "127.0.0.1:24462",
        GroupMode::MlKem1024 => "127.0.0.1:24464",
    })
    .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(8)))
        .unwrap();

    let mut client_initial = Vec::new();
    assert!(drain_until_key_change(&mut connection, &mut client_initial).is_none());
    assert!(!client_initial.is_empty());
    write_frame(&mut socket, &client_initial);

    let server_initial = read_frame(&mut socket);
    connection.read_hs(&server_initial).unwrap();
    let mut unexpected = Vec::new();
    assert!(matches!(
        drain_until_key_change(&mut connection, &mut unexpected),
        Some(KeyChange::Handshake { .. })
    ));
    assert!(unexpected.is_empty());

    let server_handshake = read_frame(&mut socket);
    connection.read_hs(&server_handshake).unwrap();
    let mut client_handshake = Vec::new();
    assert!(matches!(
        drain_until_key_change(&mut connection, &mut client_handshake),
        Some(KeyChange::OneRtt { .. })
    ));
    assert!(!client_handshake.is_empty());
    write_frame(&mut socket, &client_handshake);

    assert!(!connection.is_handshaking());
    assert_eq!(connection.alpn_protocol(), Some(&b"h3"[..]));
    assert_eq!(
        connection.quic_transport_parameters(),
        Some(SERVER_TRANSPORT_PARAMETERS)
    );
    println!(
        "rustls/AWS-LC QUIC client completed group={}",
        match mode {
            GroupMode::X25519 => "X25519",
            GroupMode::Hybrid => "X25519MLKEM768",
            GroupMode::MlKem768 => "MLKEM768",
            GroupMode::MlKem1024 => "MLKEM1024",
        }
    );
}

fn drain_until_key_change(
    connection: &mut ClientConnection,
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

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) {
    assert!(!bytes.is_empty());
    assert!(bytes.len() <= MAX_CRYPTO_FLIGHT);
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length != 0 && length <= MAX_CRYPTO_FLIGHT);
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}
