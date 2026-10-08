use aws_lc_rs::signature::{
    PqdsaKeyPair, PqdsaSigningAlgorithm, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING,
};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};
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

#[derive(Clone, Copy)]
enum Mode {
    Rsa,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Mode {
    fn parse(value: Option<&str>) -> Self {
        match value {
            None => Self::Rsa,
            Some("mldsa44") => Self::MlDsa44,
            Some("mldsa65") => Self::MlDsa65,
            Some("mldsa87") => Self::MlDsa87,
            Some(_) => panic!("expected optional mldsa44, mldsa65, or mldsa87 mode"),
        }
    }

    fn signing_algorithm(self) -> Option<&'static PqdsaSigningAlgorithm> {
        match self {
            Self::Rsa => None,
            Self::MlDsa44 => Some(&ML_DSA_44_SIGNING),
            Self::MlDsa65 => Some(&ML_DSA_65_SIGNING),
            Self::MlDsa87 => Some(&ML_DSA_87_SIGNING),
        }
    }

    fn signature_scheme(self) -> SignatureScheme {
        match self {
            Self::Rsa => SignatureScheme::RSA_PSS_SHA256,
            Self::MlDsa44 => SignatureScheme::ML_DSA_44,
            Self::MlDsa65 => SignatureScheme::ML_DSA_65,
            Self::MlDsa87 => SignatureScheme::ML_DSA_87,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Rsa => "RSA_PSS_SHA256",
            Self::MlDsa44 => "ML_DSA_44",
            Self::MlDsa65 => "ML_DSA_65",
            Self::MlDsa87 => "ML_DSA_87",
        }
    }

    fn port(self) -> u16 {
        match self {
            Self::Rsa => 24453,
            Self::MlDsa44 => 24469,
            Self::MlDsa65 => 24471,
            Self::MlDsa87 => 24473,
        }
    }
}

#[derive(Debug)]
struct RawClientVerifier {
    expected_spki: Vec<u8>,
    scheme: SignatureScheme,
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
        vec![self.scheme]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn main() {
    let mut args = std::env::args();
    let _executable = args.next();
    let key_path = args.next().expect("private-key path");
    let mode = Mode::parse(args.next().as_deref());
    assert!(args.next().is_none());
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let key_der = if let Some(signing_algorithm) = mode.signing_algorithm() {
        let generated = PqdsaKeyPair::from_seed(signing_algorithm, &[0x5a; 32]).unwrap();
        let encoded = generated.to_pkcs8v1().unwrap();
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(encoded.as_ref().to_vec()))
    } else {
        let mut key_reader = BufReader::new(File::open(key_path).unwrap());
        rustls_pemfile::private_key(&mut key_reader)
            .unwrap()
            .expect("private key")
    };
    let signing_key = provider.key_provider.load_private_key(key_der).unwrap();
    let spki = signing_key.public_key().unwrap().as_ref().to_vec();
    let signature_scheme = mode.signature_scheme();
    let certified_key = CertifiedKey::new(vec![CertificateDer::from(spki.clone())], signing_key);
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(RawClientVerifier {
            expected_spki: spki,
            scheme: signature_scheme,
        }))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            certified_key,
        ))));
    config.alpn_protocols.push(b"h2".to_vec());

    let listener = TcpListener::bind(("127.0.0.1", mode.port())).unwrap();
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(Arc::new(config)).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 128];
    let received = tls.read(&mut request).unwrap();
    assert_eq!(&request[..received], b"ping");
    tls.write_all(b"rustls rpk ok\n").unwrap();
    tls.flush().unwrap();
    println!(
        "rustls/AWS-LC server verified mutual RFC 7250 RPK scheme={}",
        mode.label()
    );
}
