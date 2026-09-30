use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use std::time::Instant;

const ITERATIONS: usize = 200_000;

fn packet_nonce(iv: [u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = iv;
    let encoded = packet_number.to_be_bytes();
    for (index, byte) in encoded.iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    nonce
}

fn benchmark(name: &str, key_bytes: &[u8], algorithm: &'static Algorithm) {
    let key = LessSafeKey::new(UnboundKey::new(algorithm, key_bytes).expect("valid key"));
    let iv = [0x42u8; 12];
    let aad = b"quic short header";
    let plaintext = [0x51u8; 1200];
    let mut ciphertext = [0u8; 1216];
    let mut opened = [0u8; 1216];
    let mut checksum: u64 = 0;

    let seal_start = Instant::now();
    for packet_number in 0..ITERATIONS as u64 {
        ciphertext[..plaintext.len()].copy_from_slice(&plaintext);
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(packet_nonce(iv, packet_number)),
                Aad::from(aad.as_slice()),
                &mut ciphertext[..plaintext.len()],
            )
            .expect("seal");
        ciphertext[plaintext.len()..].copy_from_slice(tag.as_ref());
        checksum = checksum.wrapping_add(ciphertext[0] as u64);
    }
    let seal_ns = seal_start.elapsed().as_nanos() / ITERATIONS as u128;

    let round_trip_start = Instant::now();
    for packet_number in 0..ITERATIONS as u64 {
        ciphertext[..plaintext.len()].copy_from_slice(&plaintext);
        let nonce = packet_nonce(iv, packet_number);
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext[..plaintext.len()],
            )
            .expect("seal");
        ciphertext[plaintext.len()..].copy_from_slice(tag.as_ref());
        opened.copy_from_slice(&ciphertext);
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut opened,
            )
            .expect("open");
        checksum = checksum.wrapping_add(plain[0] as u64);
    }
    let round_trip_ns = round_trip_start.elapsed().as_nanos() / ITERATIONS as u128;

    println!("{name}: seal={seal_ns} ns/op open+seal={round_trip_ns} ns/op checksum={checksum}");
}

fn main() {
    benchmark("aes_128_gcm", &[0x42; 16], &AES_128_GCM);
    benchmark("aes_256_gcm", &[0x42; 32], &AES_256_GCM);
    benchmark("chacha20_poly1305", &[0x42; 32], &CHACHA20_POLY1305);
}
