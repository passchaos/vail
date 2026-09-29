use rustls::{ServerConfig, ServerConnection, StreamOwned};
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

    let mut config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .unwrap();
    config.alpn_protocols.push(b"http/1.1".to_vec());

    let listener = TcpListener::bind("127.0.0.1:24447").unwrap();
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(Arc::new(config)).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 1024];
    let received = tls.read(&mut request).unwrap();
    assert!(received != 0);
    assert_eq!(tls.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
    assert_eq!(
        tls.conn.negotiated_cipher_suite().unwrap().suite(),
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    );
    tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .unwrap();
    tls.flush().unwrap();
    tls.conn.send_close_notify();
    let _ = tls.conn.write_tls(&mut tls.sock);
    println!("rustls TLS 1.2 server completed");
}
