use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 5_000;
const WARMUP_ITERATIONS: usize = 32;

fn main() {
    let key = DecapsulationKey::generate(&ML_KEM_768).expect("generate ML-KEM-768 key");
    let public = key
        .encapsulation_key()
        .expect("extract ML-KEM-768 public key");
    let (ciphertext, _) = public.encapsulate().expect("encapsulate ML-KEM-768 secret");
    let mut checksum = 0u64;

    for _ in 0..WARMUP_ITERATIONS {
        black_box(DecapsulationKey::generate(&ML_KEM_768).expect("generate ML-KEM-768 key"));
    }
    let mut start = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(DecapsulationKey::generate(&ML_KEM_768).expect("generate ML-KEM-768 key"));
    }
    let keygen_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    for _ in 0..WARMUP_ITERATIONS {
        black_box(public.encapsulate().expect("encapsulate ML-KEM-768 secret"));
    }
    start = Instant::now();
    for iteration in 0..ITERATIONS {
        let (generated, shared) = public.encapsulate().expect("encapsulate ML-KEM-768 secret");
        checksum =
            checksum.wrapping_add(generated.as_ref()[iteration % generated.as_ref().len()] as u64);
        black_box(shared);
    }
    let encaps_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    for _ in 0..WARMUP_ITERATIONS {
        black_box(
            key.decapsulate(Ciphertext::from(ciphertext.as_ref()))
                .expect("decapsulate ML-KEM-768 secret"),
        );
    }
    start = Instant::now();
    for iteration in 0..ITERATIONS {
        let shared = key
            .decapsulate(Ciphertext::from(ciphertext.as_ref()))
            .expect("decapsulate ML-KEM-768 secret");
        checksum = checksum.wrapping_add(shared.as_ref()[iteration % shared.as_ref().len()] as u64);
        black_box(shared);
    }
    let decaps_ns = start.elapsed().as_nanos() / ITERATIONS as u128;

    println!(
        "aws-lc-mlkem768-keygen={keygen_ns} ns/op encaps={encaps_ns} ns/op \
         decaps={decaps_ns} ns/op checksum={checksum}"
    );
}
