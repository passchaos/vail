use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::EchConfig;
use rustls::compress::{CertDecompressor, DecompressionFailed};
use rustls::{
    CertificateCompressionAlgorithm, ClientConfig, ClientConnection, ConnectionTrafficSecrets,
    DigitallySignedStruct, Error, KeyLog, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct NoVerifier;

#[derive(Debug)]
struct ZstdDecompressor;

static ZSTD_DECOMPRESSOR: ZstdDecompressor = ZstdDecompressor;

#[derive(Debug)]
struct StdoutKeyLog;

impl KeyLog for StdoutKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        print!("RUSTLS_KEY_LOG {label} ");
        for byte in client_random {
            print!("{byte:02x}");
        }
        print!(" ");
        for byte in secret {
            print!("{byte:02x}");
        }
        println!();
    }
}

impl CertDecompressor for ZstdDecompressor {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let decoded = zstd::stream::decode_all(input).map_err(|_| DecompressionFailed)?;
        if decoded.len() != output.len() {
            return Err(DecompressionFailed);
        }
        output.copy_from_slice(&decoded);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}

const ECH_CONFIG_LIST: &[u8] = &[
    0x00, 0x41, 0xfe, 0x0d, 0x00, 0x3d, 0x01, 0x00, 0x20, 0x00, 0x20, 0xa6, 0x9a, 0x41, 0x48, 0x5d,
    0x32, 0x96, 0xa4, 0xe0, 0xc3, 0x6a, 0xee, 0xf6, 0x63, 0x0f, 0x59, 0x32, 0x6f, 0xdc, 0xff, 0x81,
    0x29, 0x59, 0xa5, 0x85, 0xd3, 0x9b, 0x3b, 0xde, 0x98, 0x55, 0x5c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x10, 0x0e, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x00, 0x00,
];

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
    let mode = std::env::args().nth(1);
    let ech_enabled = mode.as_deref() == Some("ech");
    let zstd_enabled = mode.as_deref() == Some("zstd");
    let key_log_enabled = mode.as_deref() == Some("keylog");
    let extract_secrets = mode.as_deref() == Some("extract-secrets");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider);
    let builder = if ech_enabled {
        let ech_config = EchConfig::new(
            EchConfigListBytes::from(ECH_CONFIG_LIST),
            &[rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128],
        )
        .unwrap();
        builder.with_ech(ech_config.into()).unwrap()
    } else {
        builder.with_safe_default_protocol_versions().unwrap()
    };
    let mut config = builder
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));
    config.alpn_protocols.push(b"h2".to_vec());
    if zstd_enabled {
        config.cert_decompressors = vec![&ZSTD_DECOMPRESSOR];
    }
    if key_log_enabled {
        config.key_log = Arc::new(StdoutKeyLog);
    }
    config.enable_secret_extraction = extract_secrets;

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
    if extract_secrets {
        let secrets = conn.dangerous_extract_secrets().unwrap();
        print_traffic_secret("client", secrets.tx);
        print_traffic_secret("server", secrets.rx);
        return;
    }
    println!(
        "rustls connected: suite={:?} alpn={:?} ech={:?}",
        conn.negotiated_cipher_suite(),
        conn.alpn_protocol(),
        conn.ech_status(),
    );
}

fn print_traffic_secret(direction: &str, (sequence, secret): (u64, ConnectionTrafficSecrets)) {
    let (key, iv) = match secret {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (key, iv),
        _ => panic!("unsupported extracted traffic secret"),
    };
    print!("RUSTLS_TRAFFIC {direction} {sequence} ");
    for byte in key.as_ref() {
        print!("{byte:02x}");
    }
    print!(" ");
    for byte in iv.as_ref() {
        print!("{byte:02x}");
    }
    println!();
}
