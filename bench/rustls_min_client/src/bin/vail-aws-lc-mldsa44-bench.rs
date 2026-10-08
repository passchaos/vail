use aws_lc_rs::signature::{
    KeyPair, ParsedPublicKey, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_44, ML_DSA_44_SIGNING,
};
use std::{hint::black_box, time::Instant};

const KEYGEN_ITERATIONS: usize = 2_000;
const PREPARE_ITERATIONS: usize = 2_000;
const SIGN_ITERATIONS: usize = 5_000;
const VERIFY_ITERATIONS: usize = 10_000;
const RAW_VERIFY_ITERATIONS: usize = 2_000;
const WARMUP_ITERATIONS: usize = 16;

fn main() {
    let kat_seed =
        decode_hex::<32>("f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68");
    let expected_prefix =
        decode_hex::<32>("bd4e96f9a038ab5e36214fe69c0b1cb835ef9d7c8417e76aecd152f5cddebec8");
    let kat = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, &kat_seed).unwrap();
    assert_eq!(
        &kat.public_key().as_ref()[..expected_prefix.len()],
        &expected_prefix
    );

    let message = benchmark_input::<128>();
    let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, &[0x5a; 32]).unwrap();
    let public_bytes = key_pair.public_key().as_ref().to_vec();
    let signature = decode_hex::<2420>(include_str!("../../../testdata/mldsa44_signature.hex"));
    let parsed_public = ParsedPublicKey::new(&ML_DSA_44, &public_bytes).unwrap();
    parsed_public.verify_sig(&message, &signature).unwrap();

    benchmark_keygen();
    benchmark_public_key_preparation(&public_bytes);
    benchmark_randomized_signing(&key_pair, &message);
    benchmark_prepared_key_verification(&parsed_public, &message, &signature);
    benchmark_raw_verification(&public_bytes, &message, &signature);
}

fn benchmark_keygen() {
    let mut seed = [0x5au8; 32];
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        seed[0] = iteration as u8;
        let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, black_box(&seed)).unwrap();
        let public_key = key_pair.public_key().as_ref();
        checksum = checksum.wrapping_add(public_key[iteration % public_key.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..KEYGEN_ITERATIONS {
        seed[0] = iteration as u8;
        let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, black_box(&seed)).unwrap();
        let public_key = key_pair.public_key().as_ref();
        checksum = checksum.wrapping_add(public_key[iteration % public_key.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / KEYGEN_ITERATIONS as u128;
    println!("aws-lc-mldsa44-keygen-from-seed={elapsed} ns/op checksum={checksum}");
}

fn benchmark_public_key_preparation(public_bytes: &[u8]) {
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        let public_key = ParsedPublicKey::new(&ML_DSA_44, black_box(public_bytes)).unwrap();
        checksum = checksum
            .wrapping_add(public_key.as_ref()[iteration % public_key.as_ref().len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..PREPARE_ITERATIONS {
        let public_key = ParsedPublicKey::new(&ML_DSA_44, black_box(public_bytes)).unwrap();
        checksum = checksum
            .wrapping_add(public_key.as_ref()[iteration % public_key.as_ref().len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / PREPARE_ITERATIONS as u128;
    println!("aws-lc-mldsa44-public-key-prepare={elapsed} ns/op checksum={checksum}");
}

fn benchmark_randomized_signing(key_pair: &PqdsaKeyPair, message: &[u8; 128]) {
    let mut signature = vec![0u8; ML_DSA_44_SIGNING.signature_len()];
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        let len = key_pair.sign(black_box(message), &mut signature).unwrap();
        assert_eq!(len, signature.len());
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..SIGN_ITERATIONS {
        let len = key_pair.sign(black_box(message), &mut signature).unwrap();
        assert_eq!(len, signature.len());
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / SIGN_ITERATIONS as u128;
    println!("aws-lc-mldsa44-random-sign={elapsed} ns/op checksum={checksum}");
}

fn benchmark_prepared_key_verification(
    public_key: &ParsedPublicKey,
    message: &[u8; 128],
    signature: &[u8],
) {
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        public_key
            .verify_sig(black_box(message), black_box(signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..VERIFY_ITERATIONS {
        public_key
            .verify_sig(black_box(message), black_box(signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / VERIFY_ITERATIONS as u128;
    println!("aws-lc-mldsa44-prepared-key-verify={elapsed} ns/op checksum={checksum}");
}

fn benchmark_raw_verification(public_bytes: &[u8], message: &[u8; 128], signature: &[u8]) {
    let public_key = UnparsedPublicKey::new(&ML_DSA_44, public_bytes);
    let mut checksum = 0u64;
    for iteration in 0..WARMUP_ITERATIONS {
        public_key
            .verify(black_box(message), black_box(signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let start = Instant::now();
    for iteration in 0..RAW_VERIFY_ITERATIONS {
        public_key
            .verify(black_box(message), black_box(signature))
            .unwrap();
        checksum = checksum.wrapping_add(signature[iteration % signature.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / RAW_VERIFY_ITERATIONS as u128;
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
