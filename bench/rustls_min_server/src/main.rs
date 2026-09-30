use rustls::compress::{CertCompressor, CompressionFailed, CompressionLevel};
use rustls::{CertificateCompressionAlgorithm, ServerConfig, ServerConnection, StreamOwned};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

#[derive(Debug)]
struct ZstdCompressor;

static ZSTD_COMPRESSOR: ZstdCompressor = ZstdCompressor;

impl CertCompressor for ZstdCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        zstd::stream::encode_all(
            input.as_slice(),
            match level {
                CompressionLevel::Interactive => 1,
                CompressionLevel::Amortized => 9,
            },
        )
        .map_err(|_| CompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}

fn main() {
    let mut args = std::env::args();
    let _exe = args.next();
    let cert_path = args.next().expect("certificate path");
    let key_path = args.next().expect("private-key path");
    let mode = args.next();
    let zstd_enabled = mode.as_deref() == Some("zstd");
    let ticket_request_enabled = mode.as_deref() == Some("ticket-request");

    let mut cert_reader = BufReader::new(File::open(cert_path).unwrap());
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = BufReader::new(File::open(key_path).unwrap());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .unwrap()
        .expect("private key");

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    config.alpn_protocols.push(b"h2".to_vec());
    if zstd_enabled {
        config.cert_compressors = vec![&ZSTD_COMPRESSOR];
    }
    if ticket_request_enabled {
        config.max_tls13_tickets = 2;
    }

    let listener = TcpListener::bind("127.0.0.1:24445").unwrap();
    let (socket, _) = listener.accept().unwrap();
    let connection = ServerConnection::new(Arc::new(config)).unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = [0u8; 1024];
    let received = tls.read(&mut request).unwrap();
    assert!(received != 0);
    tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .unwrap();
    tls.flush().unwrap();
    tls.conn.send_close_notify();
    let _ = tls.conn.write_tls(&mut tls.sock);
    println!("rustls server completed");
}
