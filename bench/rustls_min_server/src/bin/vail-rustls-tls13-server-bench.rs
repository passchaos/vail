use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ServerConfig, ServerConnection};
use std::hint::black_box;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

const RPK_ITERATIONS: usize = 5_000;
const X509_ITERATIONS: usize = 2_000;

// RFC 8410 PKCS#8 wrapper around the same deterministic 0x33 Ed25519 seed
// used by bench/tls_server_connection.zig.
const ED25519_PKCS8: [u8; 48] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
];

// The matching Ed25519 public key is intentionally used as the certificate
// body. Vail's benchmark does the same: this is a server-flight throughput
// fixture, not an X.509 validation fixture.
const CERTIFICATE: [u8; 32] = [
    0x17, 0xcb, 0x79, 0xfb, 0x2b, 0x41, 0x20, 0xf2, 0xb1, 0xec, 0x65, 0xe4, 0x19, 0x8d, 0x6e, 0x08,
    0xb2, 0x8e, 0x81, 0x3f, 0xeb, 0x01, 0xe4, 0xa4, 0x00, 0x83, 0x9b, 0x85, 0xe1, 0x80, 0x80, 0xce,
];

const X25519_PUBLIC: [u8; 32] = [
    0x04, 0xf5, 0xf2, 0x91, 0x62, 0xc3, 0x1a, 0x8d, 0xef, 0xa1, 0x8e, 0x6e, 0x74, 0x22, 0x24, 0xee,
    0x80, 0x6f, 0xc1, 0x71, 0x8a, 0x27, 0x8b, 0xe8, 0x59, 0xba, 0x56, 0x20, 0x40, 0x2b, 0x8f, 0x3a,
];

const SIGNATURE_SCHEMES: [u16; 14] = [
    0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b, 0x0401, 0x0501,
    0x0601, 0x0708,
];

fn main() {
    let x509 = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("x509") => true,
        Some(_) => panic!("expected optional x509 mode"),
    };
    let iterations = if x509 {
        X509_ITERATIONS
    } else {
        RPK_ITERATIONS
    };
    let client_record = fixed_client_record(x509);
    let config = server_config(x509);
    let mut output = Vec::with_capacity(4_096);
    let mut checksum = 0u64;
    let mut flight_len = 0usize;

    let start = Instant::now();
    for _ in 0..iterations {
        output.clear();
        let mut server = ServerConnection::new(config.clone()).expect("server connection");
        let mut input = Cursor::new(client_record.as_slice());
        let consumed = server
            .read_tls(&mut input)
            .expect("read ClientHello record");
        assert_eq!(consumed, client_record.len());
        server.process_new_packets().expect("process ClientHello");
        while server.wants_write() {
            server.write_tls(&mut output).expect("write server flight");
        }
        flight_len = output.len();
        checksum = checksum.wrapping_add(u64::from(*output.last().expect("server flight")));
        black_box(output.len());
    }
    let elapsed = start.elapsed();

    println!(
        "x25519_{}_aes128={} ns/rustls-server-{}-flight input={} output={flight_len} checksum={checksum}",
        if x509 { "rsapss" } else { "ed25519" },
        elapsed.as_nanos() / iterations as u128,
        if x509 { "x509" } else { "connection" },
        client_record.len(),
    );
    println!("records={:?}", record_layout(&output));
}

fn record_layout(wire: &[u8]) -> Vec<(u8, usize)> {
    let mut records = Vec::new();
    let mut offset = 0;
    while wire.len() - offset >= 5 {
        let payload_len = u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize;
        if payload_len > wire.len() - offset - 5 {
            break;
        }
        records.push((wire[offset], payload_len));
        offset += 5 + payload_len;
    }
    assert_eq!(offset, wire.len());
    records
}

fn server_config(x509: bool) -> Arc<ServerConfig> {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];

    let mut config = if x509 {
        let mut certificate_reader = Cursor::new(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../src/crypto/testdata/rsa_signing_cert.pem"
        )));
        let certificates = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("X.509 certificate");
        let mut key_reader = Cursor::new(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../src/crypto/testdata/rsa_signing_key.pem"
        )));
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .expect("private-key PEM")
            .expect("private key");
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 provider")
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .expect("matching X.509 identity")
    } else {
        let private_key = PrivatePkcs8KeyDer::from(ED25519_PKCS8.to_vec());
        let signing_key = aws_lc_rs::sign::any_eddsa_type(&private_key).expect("Ed25519 key");
        let certified_key = CertifiedKey::new(
            vec![CertificateDer::from(CERTIFICATE.to_vec())],
            signing_key,
        );
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 provider")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)))
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.max_tls13_tickets = 0;
    Arc::new(config)
}

fn fixed_client_record(x509: bool) -> Vec<u8> {
    let mut extensions = Vec::with_capacity(160);

    let mut server_name = Vec::with_capacity(16);
    let hostname = if x509 {
        b"localhost".as_slice()
    } else {
        b"example.com".as_slice()
    };
    put_u16(&mut server_name, 3 + hostname.len() as u16);
    server_name.push(0);
    put_u16(&mut server_name, hostname.len() as u16);
    server_name.extend_from_slice(hostname);
    put_extension(&mut extensions, 0x0000, &server_name);

    let mut groups = Vec::with_capacity(4);
    put_u16(&mut groups, 2);
    put_u16(&mut groups, 0x001d);
    put_extension(&mut extensions, 0x000a, &groups);

    let mut signatures = Vec::with_capacity(30);
    let signature_schemes = if x509 {
        &[0x0804][..]
    } else {
        &SIGNATURE_SCHEMES
    };
    put_u16(&mut signatures, (signature_schemes.len() * 2) as u16);
    for &scheme in signature_schemes {
        put_u16(&mut signatures, scheme);
    }
    put_extension(&mut extensions, 0x000d, &signatures);
    if x509 {
        put_extension(&mut extensions, 0x0032, &[0, 2, 0x04, 0x01]);
    }

    put_extension(&mut extensions, 0x0010, &[0, 3, 2, b'h', b'2']);
    put_extension(&mut extensions, 0x002b, &[2, 0x03, 0x04]);

    let mut key_share = Vec::with_capacity(38);
    put_u16(&mut key_share, 36);
    put_u16(&mut key_share, 0x001d);
    put_u16(&mut key_share, X25519_PUBLIC.len() as u16);
    key_share.extend_from_slice(&X25519_PUBLIC);
    put_extension(&mut extensions, 0x0033, &key_share);

    let body_len = 2 + 32 + 1 + 2 + 2 + 2 + 2 + extensions.len();
    let mut hello = Vec::with_capacity(4 + body_len);
    hello.push(1);
    put_u24(&mut hello, body_len as u32);
    put_u16(&mut hello, 0x0303);
    hello.extend_from_slice(&[0x32; 32]);
    hello.push(0);
    put_u16(&mut hello, 2);
    put_u16(&mut hello, 0x1301);
    hello.extend_from_slice(&[1, 0]);
    put_u16(&mut hello, extensions.len() as u16);
    hello.extend_from_slice(&extensions);

    let mut record = Vec::with_capacity(5 + hello.len());
    record.extend_from_slice(&[22, 3, 1]);
    put_u16(&mut record, hello.len() as u16);
    record.extend_from_slice(&hello);
    record
}

fn put_extension(output: &mut Vec<u8>, extension_type: u16, payload: &[u8]) {
    put_u16(output, extension_type);
    put_u16(output, payload.len() as u16);
    output.extend_from_slice(payload);
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u24(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes()[1..]);
}
