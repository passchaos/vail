use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 100_000;
const WARMUP_ITERATIONS: usize = 64;
const MESSAGE: &[u8] = b"Vail Ed25519 benchmark input";

fn main() {
    let seed = [0x42u8; 32];
    let mut public_key = [0u8; 32];
    let mut private_key = [0u8; 64];
    let mut signature = [0u8; 64];
    unsafe {
        aws_lc_sys::ED25519_keypair_from_seed(
            public_key.as_mut_ptr(),
            private_key.as_mut_ptr(),
            seed.as_ptr(),
        );
    }
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        let ok = unsafe {
            aws_lc_sys::ED25519_sign(
                signature.as_mut_ptr(),
                black_box(MESSAGE).as_ptr(),
                MESSAGE.len(),
                private_key.as_ptr(),
            )
        };
        assert_eq!(ok, 1);
        checksum = checksum.wrapping_add(signature[iteration % 64] as u64);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        let ok = unsafe {
            aws_lc_sys::ED25519_sign(
                signature.as_mut_ptr(),
                black_box(MESSAGE).as_ptr(),
                MESSAGE.len(),
                private_key.as_ptr(),
            )
        };
        assert_eq!(ok, 1);
        checksum = checksum.wrapping_add(signature[iteration % 64] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;

    let mut digest = [0u8; 64];
    for _ in 0..WARMUP_ITERATIONS {
        unsafe {
            aws_lc_sys::SHA512(seed.as_ptr(), seed.len(), digest.as_mut_ptr());
        }
        black_box(&digest);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        unsafe {
            aws_lc_sys::SHA512(seed.as_ptr(), seed.len(), digest.as_mut_ptr());
        }
        checksum = checksum.wrapping_add(digest[iteration % digest.len()] as u64);
    }
    let sha512_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    println!("aws-lc-ed25519-sign={elapsed} ns/op sha512={sha512_ns} ns/op checksum={checksum}");
}
