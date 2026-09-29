use rustls::{HandshakeKind, ServerConfig, ServerConnection, StreamOwned};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const RESPONSE: &[u8] = b"rustls resumed tls13 ok\n";

fn main() {
    let mut args = std::env::args();
    let _executable = args.next();
    let certificate_path = args.next().expect("certificate path");
    let key_path = args.next().expect("private-key path");
    assert!(args.next().is_none());

    let mut certificate_reader = BufReader::new(File::open(certificate_path).unwrap());
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = BufReader::new(File::open(key_path).unwrap());
    let private_key = rustls_pemfile::private_key(&mut key_reader)
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
    config.alpn_protocols.push(b"h2".to_vec());
    config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().unwrap();
    config.send_tls13_tickets = 1;
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:24459").unwrap();
    run(&listener, config.clone(), HandshakeKind::Full);
    run(&listener, config, HandshakeKind::Resumed);
    println!("rustls/AWS-LC TLS 1.3 server ticket resumption verified");
}

fn run(listener: &TcpListener, config: Arc<ServerConfig>, expected: HandshakeKind) {
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(config).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 4];
    tls.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"ping");
    assert_eq!(tls.conn.handshake_kind(), Some(expected));
    assert_eq!(tls.conn.alpn_protocol(), Some(&b"h2"[..]));
    tls.write_all(RESPONSE).unwrap();
    tls.flush().unwrap();
    tls.conn.send_close_notify();
    let _ = tls.conn.write_tls(&mut tls.sock);
}
