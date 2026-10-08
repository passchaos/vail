use aws_lc_rs::signature::{
    KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_44, ML_DSA_44_SIGNING,
};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 10_000;
const WARMUP_ITERATIONS: usize = 32;

fn main() {
    let message = benchmark_input::<128>();
    let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, &[0x5a; 32]).unwrap();
    let public_bytes = key_pair.public_key().as_ref().to_vec();
    let public_key = UnparsedPublicKey::new(&ML_DSA_44, &public_bytes);
    let signature = decode_hex::<2420>(include_str!("../../../testdata/mldsa44_signature.hex"));
    public_key.verify(&message, &signature).unwrap();

    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        public_key
            .verify(black_box(&message), black_box(&signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        public_key
            .verify(black_box(&message), black_box(&signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-mldsa44-raw-verify={elapsed} ns/op checksum={checksum}");
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
