use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_44_SIGNING};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 5_000;
const WARMUP_ITERATIONS: usize = 32;

fn main() {
    let mut seed = [0x5au8; 32];
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        seed[0] = iteration as u8;
        let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, black_box(&seed)).unwrap();
        let public_key = key_pair.public_key().as_ref();
        checksum = checksum.wrapping_add(public_key[iteration % public_key.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        seed[0] = iteration as u8;
        let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, black_box(&seed)).unwrap();
        let public_key = key_pair.public_key().as_ref();
        checksum = checksum.wrapping_add(public_key[iteration % public_key.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-mldsa44-keygen-from-seed={elapsed} ns/op checksum={checksum}");
}
