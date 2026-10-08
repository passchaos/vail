use aws_lc_rs::{
    rand::SystemRandom,
    signature::{RsaEncoding, RsaKeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA256},
};
use std::{fs::File, hint::black_box, io::BufReader, time::Instant};

const ITERATIONS: usize = 500;
const WARMUP_ITERATIONS: usize = 16;

fn benchmark(name: &str, key_pair: &RsaKeyPair, algorithm: &'static dyn RsaEncoding) {
    let random = SystemRandom::new();
    let message = [0x42u8; 130];
    let mut signature = vec![0u8; key_pair.public_modulus_len()];

    for _ in 0..WARMUP_ITERATIONS {
        key_pair
            .sign(algorithm, &random, black_box(&message), &mut signature)
            .expect("RSA warmup signature");
    }

    let mut checksum = 0u64;
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        key_pair
            .sign(algorithm, &random, black_box(&message), &mut signature)
            .expect("RSA signature");
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("{name}={elapsed} ns/sign checksum={checksum}");
}

fn main() {
    let key_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "src/crypto/testdata/rsa_signing_key.pem".to_owned());
    let mut reader = BufReader::new(File::open(key_path).expect("open RSA key"));
    let key_der = rustls_pemfile::private_key(&mut reader)
        .expect("parse PEM")
        .expect("private key PEM block");
    let key_pair = RsaKeyPair::from_pkcs8(key_der.secret_der()).expect("PKCS#8 RSA key");

    benchmark("aws-lc-rsa-2048-pss-sha256", &key_pair, &RSA_PSS_SHA256);
    benchmark("aws-lc-rsa-2048-pkcs1-sha256", &key_pair, &RSA_PKCS1_SHA256);
}
