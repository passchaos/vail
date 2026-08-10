use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn main() {
    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));
    config.alpn_protocols.push(b"h2".to_vec());

    let name = ServerName::try_from("localhost").unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
    let mut sock = TcpStream::connect("127.0.0.1:24444").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    while conn.is_handshaking() {
        while conn.wants_write() {
            conn.write_tls(&mut sock).unwrap();
        }
        if conn.wants_read() {
            let n = conn.read_tls(&mut sock).unwrap_or(0);
            if n == 0 {
                break;
            }
            let _ = conn.process_new_packets();
        }
    }

    if conn.is_handshaking() {
        panic!("rustls did not complete handshake");
    }
    while conn.wants_write() {
        conn.write_tls(&mut sock).unwrap();
    }
    println!(
        "rustls connected: suite={:?} alpn={:?}",
        conn.negotiated_cipher_suite(),
        conn.alpn_protocol()
    );
}
