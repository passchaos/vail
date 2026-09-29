use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

fn main() {
    let mut args = std::env::args();
    let _exe = args.next();
    let cert_path = args.next().expect("certificate path");
    let key_path = args.next().expect("private-key path");
    let extra = args.next();
    let staple_ocsp = extra.as_deref() == Some("ocsp");
    let client_ca_path = if staple_ocsp { None } else { extra };

    let mut cert_reader = BufReader::new(File::open(cert_path).unwrap());
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = BufReader::new(File::open(key_path).unwrap());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .unwrap()
        .expect("private key");

    let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12]);
    let builder = if let Some(client_ca_path) = client_ca_path {
        let mut roots = RootCertStore::empty();
        let mut reader = BufReader::new(File::open(client_ca_path).unwrap());
        for certificate in rustls_pemfile::certs(&mut reader) {
            roots.add(certificate.unwrap()).unwrap();
        }
        builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let mut config = if staple_ocsp {
        builder
            .with_single_cert_with_ocsp(certificates, key, b"rustls-tls12-ocsp".to_vec())
            .unwrap()
    } else {
        builder.with_single_cert(certificates, key).unwrap()
    };
    config.alpn_protocols.push(b"http/1.1".to_vec());

    let listener = TcpListener::bind("127.0.0.1:24447").unwrap();
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(Arc::new(config)).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 1024];
    let received = tls.read(&mut request).unwrap();
    assert!(received != 0);
    assert_eq!(
        tls.conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    if tls.conn.peer_certificates().is_some() {
        println!("rustls TLS 1.2 client certificate verified");
    }
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
