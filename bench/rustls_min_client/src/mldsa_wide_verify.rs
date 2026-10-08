use aws_lc_rs::signature::{
    KeyPair, ParsedPublicKey, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm,
    UnparsedPublicKey,
};
use std::{hint::black_box, time::Instant};

const PREPARED_ITERATIONS: usize = 10_000;
const RAW_ITERATIONS: usize = 2_000;
const WARMUP_ITERATIONS: usize = 32;

pub fn run<const SIGNATURE_LEN: usize>(
    verification: &'static PqdsaVerificationAlgorithm,
    signing: &'static PqdsaSigningAlgorithm,
    seed_byte: u8,
    name: &str,
    encoded_signature: &str,
) {
    let message = benchmark_input::<128>();
    let key_pair = PqdsaKeyPair::from_seed(signing, &[seed_byte; 32]).unwrap();
    let public_bytes = key_pair.public_key().as_ref().to_vec();
    let signature = decode_hex::<SIGNATURE_LEN>(encoded_signature);
    let parsed = ParsedPublicKey::new(verification, &public_bytes).unwrap();
    parsed.verify_sig(&message, &signature).unwrap();

    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        parsed
            .verify_sig(black_box(&message), black_box(&signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let mut start = Instant::now();
    for iteration in 0..PREPARED_ITERATIONS {
        parsed
            .verify_sig(black_box(&message), black_box(&signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let mut elapsed = start.elapsed().as_nanos() / PREPARED_ITERATIONS as u128;
    println!("aws-lc-{name}-prepared-key-verify={elapsed} ns/op checksum={checksum}");

    let raw = UnparsedPublicKey::new(verification, &public_bytes);
    checksum = 0;
    for iteration in 0..WARMUP_ITERATIONS {
        raw.verify(black_box(&message), black_box(&signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    start = Instant::now();
    for iteration in 0..RAW_ITERATIONS {
        raw.verify(black_box(&message), black_box(&signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    elapsed = start.elapsed().as_nanos() / RAW_ITERATIONS as u128;
    println!("aws-lc-{name}-raw-verify={elapsed} ns/op checksum={checksum}");
}

fn benchmark_input<const LEN: usize>() -> [u8; LEN] {
    let mut input = [0u8; LEN];
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(131).wrapping_add(17);
    }
    input
}

fn decode_hex<const LEN: usize>(encoded: &str) -> [u8; LEN] {
    let mut result = [0u8; LEN];
    let mut high = None;
    let mut output_index = 0;
    for byte in encoded.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex digit"),
        };
        if let Some(value) = high {
            assert!(output_index < result.len());
            result[output_index] = value << 4 | nibble;
            output_index += 1;
            high = None;
        } else {
            high = Some(nibble);
        }
    }
    assert!(high.is_none());
    assert_eq!(output_index, result.len());
    result
}
