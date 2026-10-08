use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 100_000;
const WARMUP_ITERATIONS: usize = 64;

fn main() {
    let mut secret = [0x42u8; 32];
    let mut public_key = [0u8; 32];
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        secret[0] = iteration as u8;
        unsafe {
            aws_lc_sys::X25519_public_from_private(public_key.as_mut_ptr(), secret.as_ptr());
        }
        checksum = checksum.wrapping_add(public_key[iteration % public_key.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        secret[0] = iteration as u8;
        unsafe {
            aws_lc_sys::X25519_public_from_private(public_key.as_mut_ptr(), secret.as_ptr());
        }
        checksum = checksum.wrapping_add(public_key[iteration % public_key.len()] as u64);
        black_box(&public_key);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-x25519-public={elapsed} ns/op checksum={checksum}");
}
