use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct RawServerVerifier {
    expected_spki: Vec<u8>,
}

impl ServerCertVerifier for RawServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref() != self.expected_spki
            || !intermediates.is_empty()
            || !ocsp_response.is_empty()
        {
            return Err(Error::General("unexpected server raw public key".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        spki: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(spki.as_ref()),
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::RSA_PSS_SHA256]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn main() {
    let key_path = std::env::args().nth(1).expect("private-key path");
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut key_reader = BufReader::new(File::open(key_path).unwrap());
    let key_der = rustls_pemfile::private_key(&mut key_reader)
        .unwrap()
        .expect("private key");
    let signing_key = provider.key_provider.load_private_key(key_der).unwrap();
    let spki = signing_key.public_key().unwrap().as_ref().to_vec();
    let certified_key = CertifiedKey::new(vec![CertificateDer::from(spki.clone())], signing_key);
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RawServerVerifier {
            expected_spki: spki,
        }))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
            certified_key,
        ))));
    config.alpn_protocols.push(b"h2".to_vec());

    let name = ServerName::try_from("localhost").unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
    let mut socket = TcpStream::connect("127.0.0.1:24452").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(8)))
        .unwrap();

    while conn.is_handshaking() {
        while conn.wants_write() {
            conn.write_tls(&mut socket).unwrap();
        }
        if conn.wants_read() {
            let count = conn.read_tls(&mut socket).unwrap();
            assert!(count != 0, "Vail server closed during RPK handshake");
            conn.process_new_packets().unwrap();
        }
    }
    while conn.wants_write() {
        conn.write_tls(&mut socket).unwrap();
    }

    conn.writer().write_all(b"ping").unwrap();
    while conn.wants_write() {
        conn.write_tls(&mut socket).unwrap();
    }
    let mut plaintext = [0u8; 128];
    loop {
        let count = conn.read_tls(&mut socket).unwrap();
        assert!(count != 0, "Vail server closed before application data");
        conn.process_new_packets().unwrap();
        match conn.reader().read(&mut plaintext) {
            Ok(0) => continue,
            Ok(length) => {
                assert_eq!(&plaintext[..length], b"vail rpk ok\n");
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => panic!("application read failed: {error}"),
        }
    }
    println!("rustls/AWS-LC client verified mutual RFC 7250 RPK");
}
