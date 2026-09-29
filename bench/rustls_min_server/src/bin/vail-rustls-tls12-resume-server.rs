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
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:24448").unwrap();
    run(&listener, config.clone(), HandshakeKind::Full);
    run(&listener, config, HandshakeKind::Resumed);
    println!("rustls TLS 1.2 session resumption verified");
}

fn run(listener: &TcpListener, config: Arc<ServerConfig>, expected: HandshakeKind) {
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(config).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 1024];
    assert_ne!(tls.read(&mut request).unwrap(), 0);
    assert_eq!(tls.conn.handshake_kind(), Some(expected));
    tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .unwrap();
    tls.flush().unwrap();
    tls.conn.send_close_notify();
    let _ = tls.conn.write_tls(&mut tls.sock);
}
