use aws_lc_rs::kem::{Algorithm, Ciphertext, DecapsulationKey};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 5_000;
const WARMUP_ITERATIONS: usize = 32;

pub fn run(algorithm: &'static Algorithm, name: &str) {
    let key = DecapsulationKey::generate(algorithm).expect("generate ML-KEM key");
    let public = key.encapsulation_key().expect("extract ML-KEM public key");
    let (ciphertext, _) = public.encapsulate().expect("encapsulate ML-KEM secret");
    let mut checksum = 0u64;

    for _ in 0..WARMUP_ITERATIONS {
        black_box(DecapsulationKey::generate(algorithm).expect("generate ML-KEM key"));
    }
    let mut start = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(DecapsulationKey::generate(algorithm).expect("generate ML-KEM key"));
    }
    let mut elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-{name}-random-keygen={elapsed} ns/op");

    for _ in 0..WARMUP_ITERATIONS {
        black_box(public.encapsulate().expect("encapsulate ML-KEM secret"));
    }
    start = Instant::now();
    for iteration in 0..ITERATIONS {
        let (generated, shared) = public.encapsulate().expect("encapsulate ML-KEM secret");
        checksum =
            checksum.wrapping_add(generated.as_ref()[iteration % generated.as_ref().len()] as u64);
        black_box(shared);
    }
    elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-{name}-random-encaps={elapsed} ns/op checksum={checksum}");

    checksum = 0;
    for _ in 0..WARMUP_ITERATIONS {
        black_box(
            key.decapsulate(Ciphertext::from(ciphertext.as_ref()))
                .expect("decapsulate ML-KEM secret"),
        );
    }
    start = Instant::now();
    for iteration in 0..ITERATIONS {
        let shared = key
            .decapsulate(Ciphertext::from(ciphertext.as_ref()))
            .expect("decapsulate ML-KEM secret");
        checksum = checksum.wrapping_add(shared.as_ref()[iteration % shared.as_ref().len()] as u64);
        black_box(shared);
    }
    elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-{name}-decaps={elapsed} ns/op checksum={checksum}");
}
