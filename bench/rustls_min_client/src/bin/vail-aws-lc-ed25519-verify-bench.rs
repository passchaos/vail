use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 50_000;
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
        assert_eq!(
            aws_lc_sys::ED25519_sign(
                signature.as_mut_ptr(),
                MESSAGE.as_ptr(),
                MESSAGE.len(),
                private_key.as_ptr(),
            ),
            1,
        );
    }

    for _ in 0..WARMUP_ITERATIONS {
        assert_eq!(
            unsafe {
                aws_lc_sys::ED25519_verify(
                    black_box(MESSAGE).as_ptr(),
                    MESSAGE.len(),
                    signature.as_ptr(),
                    public_key.as_ptr(),
                )
            },
            1,
        );
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        assert_eq!(
            unsafe {
                aws_lc_sys::ED25519_verify(
                    black_box(MESSAGE).as_ptr(),
                    MESSAGE.len(),
                    signature.as_ptr(),
                    public_key.as_ptr(),
                )
            },
            1,
        );
        black_box(&signature);
    }
    println!(
        "aws-lc-ed25519={} ns/verify",
        start.elapsed().as_nanos() / ITERATIONS as u128,
    );
}
