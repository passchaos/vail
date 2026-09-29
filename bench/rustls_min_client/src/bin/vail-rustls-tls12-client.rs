use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct NoVerifier {
    pkcs1: bool,
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if self.pkcs1 {
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        } else {
            vec![
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        }
    }
}

fn main() {
    let mut args = std::env::args();
    let _exe = args.next();
    let mode = args.next();
    let pkcs1 = matches!(mode.as_deref(), Some("pkcs1" | "mtls-pkcs1"));
    let mtls = mode.as_deref() == Some("mtls-pkcs1");
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier { pkcs1 }));
    let mut config = if mtls {
        let cert_path = args.next().expect("client certificate path");
        let key_path = args.next().expect("client private-key path");
        let mut cert_reader = BufReader::new(File::open(cert_path).unwrap());
        let certificates = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut key_reader = BufReader::new(File::open(key_path).unwrap());
        let key = rustls_pemfile::private_key(&mut key_reader)
            .unwrap()
            .expect("private key");
        builder.with_client_auth_cert(certificates, key).unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols.push(b"h2".to_vec());

    let name = ServerName::try_from("localhost").unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
    let mut socket = TcpStream::connect("127.0.0.1:24446").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(4)))
        .unwrap();

    while conn.is_handshaking() {
        while conn.wants_write() {
            conn.write_tls(&mut socket).unwrap();
        }
        if conn.wants_read() {
            let count = conn.read_tls(&mut socket).unwrap();
            assert!(count != 0, "server closed during handshake");
            conn.process_new_packets().unwrap();
        }
    }
    while conn.wants_write() {
        conn.write_tls(&mut socket).unwrap();
    }
    println!("rustls TLS 1.2 connected");

    conn.writer().write_all(b"ping").unwrap();
    while conn.wants_write() {
        conn.write_tls(&mut socket).unwrap();
    }
    let mut plaintext = [0u8; 128];
    loop {
        let count = conn.read_tls(&mut socket).unwrap();
        assert!(count != 0, "server closed before application data");
        conn.process_new_packets().unwrap();
        match conn.reader().read(&mut plaintext) {
            Ok(0) => continue,
            Ok(length) => {
                assert_eq!(&plaintext[..length], b"vail tls12 ok\n");
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => panic!("application read failed: {error}"),
        }
    }
    println!("rustls TLS 1.2 application data verified");
}
