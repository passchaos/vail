use aws_lc_rs::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P521_SHA512_ASN1_SIGNING},
};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 10_000;
const WARMUP_ITERATIONS: usize = 32;
const MESSAGE: &[u8] = b"Vail pure Zig P-521 signing benchmark";

fn main() {
    let random = SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::generate(&ECDSA_P521_SHA512_ASN1_SIGNING).expect("generate AWS-LC P-521 key");

    for _ in 0..WARMUP_ITERATIONS {
        black_box(
            key_pair
                .sign(&random, black_box(MESSAGE))
                .expect("AWS-LC P-521 warmup signature"),
        );
    }
    let mut checksum = 0u64;
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        let signature = key_pair
            .sign(&random, black_box(MESSAGE))
            .expect("AWS-LC P-521 signature");
        checksum =
            checksum.wrapping_add(signature.as_ref()[iteration % signature.as_ref().len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-p521-sha512-random-end-to-end={elapsed} ns/sign checksum={checksum}");
}
