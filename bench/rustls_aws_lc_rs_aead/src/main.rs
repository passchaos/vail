use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use std::time::Instant;

const ITERATIONS: usize = 200_000;

fn packet_nonce(iv: [u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = iv;
    let pn = packet_number.to_be_bytes();
    for (idx, byte) in pn.iter().enumerate() {
        nonce[12 - pn.len() + idx] ^= byte;
    }
    nonce
}

fn bench(name: &str, key_bytes: &[u8], alg: &'static aws_lc_rs::aead::Algorithm) {
    let key = LessSafeKey::new(UnboundKey::new(alg, key_bytes).expect("key"));
    let iv = [0x42u8; 12];
    let aad_bytes = b"quic short header".as_slice();
    let plaintext = [0x51u8; 1200];
    let mut buffer = [0u8; 1216];
    let mut opened = [0u8; 1216];
    let mut checksum: u64 = 0;

    let seal_start = Instant::now();
    for packet_number in 0..ITERATIONS as u64 {
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        let nonce = Nonce::assume_unique_for_key(packet_nonce(iv, packet_number));
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad_bytes), &mut buffer[..plaintext.len()])
            .expect("seal");
        buffer[plaintext.len()..plaintext.len() + tag.as_ref().len()].copy_from_slice(tag.as_ref());
        checksum = checksum.wrapping_add(buffer[0] as u64);
    }
    let seal_ns = seal_start.elapsed().as_nanos() / ITERATIONS as u128;

    let open_start = Instant::now();
    for packet_number in 0..ITERATIONS as u64 {
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        let nonce = Nonce::assume_unique_for_key(packet_nonce(iv, packet_number));
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad_bytes), &mut buffer[..plaintext.len()])
            .expect("seal");
        buffer[plaintext.len()..plaintext.len() + tag.as_ref().len()].copy_from_slice(tag.as_ref());

        opened[..plaintext.len()].copy_from_slice(&buffer[..plaintext.len()]);
        opened[plaintext.len()..plaintext.len() + tag.as_ref().len()].copy_from_slice(tag.as_ref());
        let nonce = Nonce::assume_unique_for_key(packet_nonce(iv, packet_number));
        let plain = key
            .open_in_place(
                nonce,
                Aad::from(aad_bytes),
                &mut opened[..plaintext.len() + tag.as_ref().len()],
            )
            .expect("open");
        checksum = checksum.wrapping_add(plain[0] as u64);
    }
    let open_ns = open_start.elapsed().as_nanos() / ITERATIONS as u128;

    println!("{name}: seal={seal_ns} ns/op open+seal={open_ns} ns/op checksum={checksum}");
}

fn main() {
    bench("aws_lc_rs_aes_128_gcm", &[0x42u8; 16], &AES_128_GCM);
    bench("aws_lc_rs_aes_256_gcm", &[0x42u8; 32], &AES_256_GCM);
}
