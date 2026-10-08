use aws_lc_rs::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 5_000;
const WARMUP_ITERATIONS: usize = 64;
const MESSAGE: &[u8] = b"Vail P-256 signing benchmark input";

fn main() {
    let random = SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("generate AWS-LC P-256 key");

    for _ in 0..WARMUP_ITERATIONS {
        black_box(
            key_pair
                .sign(&random, black_box(MESSAGE))
                .expect("AWS-LC P-256 warmup signature"),
        );
    }
    let mut checksum = 0u64;
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        let signature = key_pair
            .sign(&random, black_box(MESSAGE))
            .expect("AWS-LC P-256 signature");
        checksum =
            checksum.wrapping_add(signature.as_ref()[iteration % signature.as_ref().len()] as u64);
        black_box(signature);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-p256-sha256={elapsed} ns/sign checksum={checksum}");
}
