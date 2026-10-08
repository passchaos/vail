use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair, ParsedPublicKey, ECDSA_P384_SHA384_ASN1,
        ECDSA_P384_SHA384_ASN1_SIGNING,
    },
};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 10_000;
const SIGN_ITERATIONS: usize = 1_000;
const WARMUP_ITERATIONS: usize = 32;
const MESSAGE: &[u8] = b"Vail P-384 verification benchmark input";

fn main() {
    let random = SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING).expect("generate AWS-LC P-384 key");
    let signature = key_pair
        .sign(&random, MESSAGE)
        .expect("sign AWS-LC P-384 benchmark message");
    let public_key = ParsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key_pair.public_key().as_ref())
        .expect("parse AWS-LC P-384 public key");

    for _ in 0..WARMUP_ITERATIONS {
        public_key
            .verify_sig(black_box(MESSAGE), black_box(signature.as_ref()))
            .expect("AWS-LC P-384 warmup verification");
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        public_key
            .verify_sig(black_box(MESSAGE), black_box(signature.as_ref()))
            .expect("AWS-LC P-384 verification");
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;

    for _ in 0..WARMUP_ITERATIONS {
        black_box(
            key_pair
                .sign(&random, black_box(MESSAGE))
                .expect("AWS-LC P-384 warmup signature"),
        );
    }
    let mut checksum = 0u64;
    let sign_start = Instant::now();
    for iteration in 0..SIGN_ITERATIONS {
        let generated = key_pair
            .sign(&random, black_box(MESSAGE))
            .expect("AWS-LC P-384 signature");
        checksum =
            checksum.wrapping_add(generated.as_ref()[iteration % generated.as_ref().len()] as u64);
    }
    let sign_ns = sign_start.elapsed().as_nanos() / SIGN_ITERATIONS as u128;
    println!("aws-lc-p384-sha384={elapsed} ns/verify sign={sign_ns} ns/op checksum={checksum}");
}
