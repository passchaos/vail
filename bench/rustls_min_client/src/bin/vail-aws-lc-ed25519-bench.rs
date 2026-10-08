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
        assert_eq!(
            aws_lc_sys::ED25519_verify(
                MESSAGE.as_ptr(),
                MESSAGE.len(),
                signature.as_ptr(),
                public_key.as_ptr(),
            ),
            1,
        );
    }
    let mut checksum = 0u64;

    let mut mutable_seed = seed;
    for iteration in 0..WARMUP_ITERATIONS {
        mutable_seed[0] = iteration as u8;
        unsafe {
            aws_lc_sys::ED25519_keypair_from_seed(
                public_key.as_mut_ptr(),
                private_key.as_mut_ptr(),
                mutable_seed.as_ptr(),
            );
        }
        checksum = checksum.wrapping_add(public_key[iteration % 32] as u64);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        mutable_seed[0] = iteration as u8;
        unsafe {
            aws_lc_sys::ED25519_keypair_from_seed(
                public_key.as_mut_ptr(),
                private_key.as_mut_ptr(),
                mutable_seed.as_ptr(),
            );
        }
        checksum = checksum.wrapping_add(public_key[iteration % 32] as u64);
    }
    let key_pair_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    unsafe {
        aws_lc_sys::ED25519_keypair_from_seed(
            public_key.as_mut_ptr(),
            private_key.as_mut_ptr(),
            seed.as_ptr(),
        );
    }
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
    let sign_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

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
    let verify_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    println!(
        "aws-lc-ed25519-keypair={key_pair_ns} ns/op sign={sign_ns} ns/op \
         verify={verify_ns} ns/op checksum={checksum}"
    );
}
