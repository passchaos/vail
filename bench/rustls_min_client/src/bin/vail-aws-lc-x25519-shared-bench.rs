use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 100_000;
const WARMUP_ITERATIONS: usize = 64;

fn main() {
    let mut secret = [0x42u8; 32];
    let peer_secret = [0x69u8; 32];
    let mut peer_public = [0u8; 32];
    let mut output = [0u8; 32];
    unsafe {
        aws_lc_sys::X25519_public_from_private(peer_public.as_mut_ptr(), peer_secret.as_ptr());
    }
    let mut checksum = 0u64;

    for iteration in 0..WARMUP_ITERATIONS {
        secret[0] = iteration as u8;
        let ok = unsafe {
            aws_lc_sys::X25519(output.as_mut_ptr(), secret.as_ptr(), peer_public.as_ptr())
        };
        assert_eq!(ok, 1);
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        secret[0] = iteration as u8;
        let ok = unsafe {
            aws_lc_sys::X25519(output.as_mut_ptr(), secret.as_ptr(), peer_public.as_ptr())
        };
        assert_eq!(ok, 1);
        checksum = checksum.wrapping_add(output[iteration % output.len()] as u64);
        black_box(&output);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-x25519-shared={elapsed} ns/op checksum={checksum}");
}
