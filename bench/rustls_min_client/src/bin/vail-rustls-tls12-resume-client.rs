use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, HandshakeKind, RootCertStore,
    SignatureScheme, StreamOwned,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct NoVerifier;

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
        vec![SignatureScheme::RSA_PSS_SHA256]
    }
}

fn main() {
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));
    config.alpn_protocols.push(b"http/1.1".to_vec());
    let config = Arc::new(config);
    run(config.clone(), HandshakeKind::Full);
    run(config, HandshakeKind::Resumed);
    println!("rustls TLS 1.2 session resumption verified");
}

fn run(config: Arc<ClientConfig>, expected: HandshakeKind) {
    let name = ServerName::try_from("localhost").unwrap();
    let mut conn = ClientConnection::new(config, name).unwrap();
    let mut socket = TcpStream::connect("127.0.0.1:24449").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut socket).unwrap();
    }
    assert_eq!(conn.handshake_kind(), Some(expected));
    let mut tls = StreamOwned::new(conn, socket);
    tls.write_all(b"ping").unwrap();
    tls.flush().unwrap();
    let mut plaintext = [0u8; 22];
    tls.read_exact(&mut plaintext).unwrap();
    assert_eq!(&plaintext, b"vail resumed tls12 ok\n");
}
