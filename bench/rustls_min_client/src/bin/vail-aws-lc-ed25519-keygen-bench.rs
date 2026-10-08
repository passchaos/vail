use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 100_000;
const WARMUP_ITERATIONS: usize = 128;

fn main() {
    let mut seed = [0x42u8; 32];
    let mut public_key = [0u8; 32];
    let mut private_key = [0u8; 64];
    let mut checksum = 0u64;

    for iteration in 0..WARMUP_ITERATIONS {
        seed[0] = iteration as u8;
        unsafe {
            aws_lc_sys::ED25519_keypair_from_seed(
                public_key.as_mut_ptr(),
                private_key.as_mut_ptr(),
                seed.as_ptr(),
            );
        }
        black_box(&private_key);
        checksum = checksum.wrapping_add(public_key[iteration % 32] as u64);
    }

    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        seed[0] = iteration as u8;
        unsafe {
            aws_lc_sys::ED25519_keypair_from_seed(
                public_key.as_mut_ptr(),
                private_key.as_mut_ptr(),
                seed.as_ptr(),
            );
        }
        black_box(&private_key);
        checksum = checksum.wrapping_add(public_key[iteration % 32] as u64);
    }
    const ELAPSED_LABEL: &str = "aws-lc-ed25519-keygen";
    println!(
        "{ELAPSED_LABEL}={} ns/op checksum={checksum}",
        start.elapsed().as_nanos() / ITERATIONS as u128,
    );
    for byte in &mut private_key {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}
