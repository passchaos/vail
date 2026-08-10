use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;
use std::io::{self, Write};
use std::sync::Arc;

fn main() {
    let config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let name = ServerName::try_from("example.com").unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    let handshake = &out[5..];
    for byte in handshake {
        write!(io::stdout(), "{byte:02x}").unwrap();
    }
    println!();
}
