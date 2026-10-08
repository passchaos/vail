use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use std::hint::black_box;
use std::time::Instant;

const ITERATIONS: usize = 200_000;
const WARMUP_ITERATIONS: usize = 256;

fn benchmark(name: &str, key_bytes: &[u8], algorithm: &'static Algorithm) {
    let key = LessSafeKey::new(UnboundKey::new(algorithm, key_bytes).expect("valid key"));
    let iv = black_box([0x43u8; 12]);
    let aad = black_box(*b"quic short header");
    let plaintext = black_box([0x51u8; 1200]);
    let mut ciphertext = [0u8; 1200];
    let mut tag = [0u8; 16];
    let mut opened = [0u8; 1200];
    let mut checksum: u64 = 0;

    for _ in 0..WARMUP_ITERATIONS {
        key.seal_out_of_place_scatter(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_slice()),
            &plaintext,
            &mut ciphertext,
            &[],
            &mut tag,
        )
        .expect("seal");
        checksum = checksum.wrapping_add(ciphertext[0] as u64);
        checksum = checksum.wrapping_add(tag[0] as u64);
    }
    let seal_start = Instant::now();
    for _ in 0..ITERATIONS {
        key.seal_out_of_place_scatter(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_slice()),
            &plaintext,
            &mut ciphertext,
            &[],
            &mut tag,
        )
        .expect("seal");
        checksum = checksum.wrapping_add(ciphertext[0] as u64);
        checksum = checksum.wrapping_add(tag[0] as u64);
    }
    let seal_elapsed = seal_start.elapsed().as_nanos();
    let seal_ns = seal_elapsed / ITERATIONS as u128;

    for _ in 0..WARMUP_ITERATIONS {
        key.open_separate_gather(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_slice()),
            &ciphertext,
            &tag,
            &mut opened,
        )
        .expect("open");
        checksum = checksum.wrapping_add(opened[0] as u64);
    }
    let open_start = Instant::now();
    for _ in 0..ITERATIONS {
        key.open_separate_gather(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_slice()),
            &ciphertext,
            &tag,
            &mut opened,
        )
        .expect("open");
        checksum = checksum.wrapping_add(opened[0] as u64);
    }
    let open_elapsed = open_start.elapsed().as_nanos();
    let open_ns = open_elapsed / ITERATIONS as u128;

    for _ in 0..WARMUP_ITERATIONS {
        key.seal_out_of_place_scatter(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_slice()),
            &plaintext,
            &mut ciphertext,
            &[],
            &mut tag,
        )
        .expect("seal");
        key.open_separate_gather(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_slice()),
            &ciphertext,
            &tag,
            &mut opened,
        )
        .expect("open");
        checksum = checksum.wrapping_add(opened[0] as u64);
    }
    let round_trip_start = Instant::now();
    for _ in 0..ITERATIONS {
        let nonce = iv;
        key.seal_out_of_place_scatter(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_slice()),
            &plaintext,
            &mut ciphertext,
            &[],
            &mut tag,
        )
        .expect("seal");
        key.open_separate_gather(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_slice()),
            &ciphertext,
            &tag,
            &mut opened,
        )
        .expect("open");
        checksum = checksum.wrapping_add(opened[0] as u64);
    }
    let round_trip_elapsed = round_trip_start.elapsed().as_nanos();
    let round_trip_ns = round_trip_elapsed / ITERATIONS as u128;

    let seal_ps = seal_elapsed * 1_000 / ITERATIONS as u128;
    let open_ps = open_elapsed * 1_000 / ITERATIONS as u128;
    let round_trip_ps = round_trip_elapsed * 1_000 / ITERATIONS as u128;
    println!(
        "{name}: seal={seal_ns} ns/op ({seal_ps} ps/op) open={open_ns} ns/op ({open_ps} ps/op) open+seal={round_trip_ns} ns/op ({round_trip_ps} ps/op) checksum={checksum}"
    );
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("chacha20_poly1305") {
        benchmark("chacha20_poly1305", &[0x42; 32], &CHACHA20_POLY1305);
        return;
    }
    benchmark("aes_128_gcm", &[0x42; 16], &AES_128_GCM);
    benchmark("aes_256_gcm", &[0x42; 32], &AES_256_GCM);
    benchmark("chacha20_poly1305", &[0x42; 32], &CHACHA20_POLY1305);
}
