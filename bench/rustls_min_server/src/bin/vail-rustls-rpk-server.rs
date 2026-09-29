use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, ServerConfig, ServerConnection,
    SignatureScheme, StreamOwned,
};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

#[derive(Debug)]
struct RawClientVerifier {
    expected_spki: Vec<u8>,
}

impl ClientCertVerifier for RawClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if end_entity.as_ref() != self.expected_spki || !intermediates.is_empty() {
            return Err(Error::General("unexpected client raw public key".into()));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        spki: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
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
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(RawClientVerifier {
            expected_spki: spki,
        }))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            certified_key,
        ))));
    config.alpn_protocols.push(b"h2".to_vec());

    let listener = TcpListener::bind("127.0.0.1:24453").unwrap();
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(Arc::new(config)).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 128];
    let received = tls.read(&mut request).unwrap();
    assert_eq!(&request[..received], b"ping");
    tls.write_all(b"rustls rpk ok\n").unwrap();
    tls.flush().unwrap();
    println!("rustls/AWS-LC server verified mutual RFC 7250 RPK");
}
