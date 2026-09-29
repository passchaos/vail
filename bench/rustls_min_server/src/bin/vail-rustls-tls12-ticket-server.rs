use rustls::server::NoServerSessionStorage;
use rustls::{HandshakeKind, ServerConfig, ServerConnection, StreamOwned};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

fn main() {
    let mut args = std::env::args();
    let _exe = args.next();
    let cert_path = args.next().expect("certificate path");
    let key_path = args.next().expect("private-key path");
    let mut cert_reader = BufReader::new(File::open(cert_path).unwrap());
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = BufReader::new(File::open(key_path).unwrap());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .unwrap()
        .expect("private key");
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    config.alpn_protocols.push(b"http/1.1".to_vec());
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:24455").unwrap();
    run(&listener, config.clone(), HandshakeKind::Full);
    run(&listener, config, HandshakeKind::Resumed);
    println!("rustls/AWS-LC TLS 1.2 ticket resumption verified");
}

fn run(listener: &TcpListener, config: Arc<ServerConfig>, expected: HandshakeKind) {
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(config).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 128];
    let received = tls.read(&mut request).unwrap();
    assert_ne!(received, 0);
    assert_eq!(tls.conn.handshake_kind(), Some(expected));
    tls.write_all(b"rustls ticket tls12 ok\n").unwrap();
    tls.flush().unwrap();
}
