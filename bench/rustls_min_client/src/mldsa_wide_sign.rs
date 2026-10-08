use aws_lc_rs::signature::{PqdsaKeyPair, PqdsaSigningAlgorithm};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 5_000;
const WARMUP_ITERATIONS: usize = 32;

pub fn run(signing: &'static PqdsaSigningAlgorithm, name: &str) {
    let message = benchmark_input::<128>();
    let key_pair = PqdsaKeyPair::from_seed(signing, &[0x5a; 32]).unwrap();
    let mut signature = vec![0u8; signing.signature_len()];
    let mut checksum = 0u64;

    for iteration in 0..WARMUP_ITERATIONS {
        let len = key_pair.sign(black_box(&message), &mut signature).unwrap();
        assert_eq!(len, signature.len());
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        let len = key_pair.sign(black_box(&message), &mut signature).unwrap();
        assert_eq!(len, signature.len());
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-{name}-random-sign={elapsed} ns/op checksum={checksum}");
}

fn benchmark_input<const LEN: usize>() -> [u8; LEN] {
    let mut input = [0u8; LEN];
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(131).wrapping_add(17);
    }
    input
}
