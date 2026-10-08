use aws_lc_rs::signature::{ParsedPublicKey, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 20_000;
const WARMUP_ITERATIONS: usize = 32;
const MESSAGE: &[u8] = b"Vail P-256 verification benchmark input";
const PUBLIC_KEY_HEX: &str = concat!(
    "042ca00e33928e5b66cc63a70e91c78f5d9e0db34711f9108778151912d389c5",
    "89c6c886572fd6dad9d01e0b98c5fec3276e9a2e4b89705140f564f7eb65016b95",
);
const SIGNATURE_HEX: &str = concat!(
    "304502207dceeb937f45830524392b71592522427449295e473662fc05ddaf24a190",
    "d0a0022100f2484127a1165596d1a8dfe11a3d1e2a4b0d6983dde8af7fcd065d664",
    "cbc576c",
);

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn main() {
    let public_key = decode_hex(PUBLIC_KEY_HEX);
    let signature = decode_hex(SIGNATURE_HEX);
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key);
    let parsed = ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key)
        .expect("parse AWS-LC P-256 public key");

    for _ in 0..WARMUP_ITERATIONS {
        verifier
            .verify(black_box(MESSAGE), black_box(&signature))
            .expect("AWS-LC P-256 warmup verification");
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        verifier
            .verify(black_box(MESSAGE), black_box(&signature))
            .expect("AWS-LC P-256 verification");
    }
    let unparsed_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    for _ in 0..WARMUP_ITERATIONS {
        parsed
            .verify_sig(black_box(MESSAGE), black_box(&signature))
            .expect("AWS-LC prepared P-256 warmup verification");
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        parsed
            .verify_sig(black_box(MESSAGE), black_box(&signature))
            .expect("AWS-LC prepared P-256 verification");
    }
    let parsed_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    for _ in 0..WARMUP_ITERATIONS {
        black_box(
            ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, black_box(&public_key))
                .expect("prepare AWS-LC P-256 public key"),
        );
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(
            ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, black_box(&public_key))
                .expect("prepare AWS-LC P-256 public key"),
        );
    }
    let prepare_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    println!(
        "aws-lc-p256-sha256={unparsed_ns} ns/verify parsed={parsed_ns} ns/verify \
         prepare={prepare_ns} ns/op"
    );
}
