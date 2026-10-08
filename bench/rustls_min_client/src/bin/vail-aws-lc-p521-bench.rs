use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P521_SHA512_ASN1};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P521_SHA512_ASN1_SIGNING},
};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 5_000;
const WARMUP_ITERATIONS: usize = 32;
const SIGN_ITERATIONS: usize = 1_000;
const VERIFY_MESSAGE: &[u8] = b"Vail pure Zig P-521 oracle";
const SIGN_MESSAGE: &[u8] = b"Vail pure Zig P-521 signing benchmark";
const PUBLIC_KEY_HEX: &str = concat!(
    "040046a8b6b07a8b3f6297aef1a827ac7bada74f5b9d8743409e1bb84e437657",
    "e4c34c14b21c2ce9fe54de5dd7ef65dd9e9abf30e4ec9f12003110f49254aa1f",
    "69d1f8013c078f6bb12f820abbbba183230803bea0d050b75a07540f68fb75e68",
    "c4551131e18a4d61723459c31ab4ec75dfae9646b4741237e5c39493cae6cab7d",
    "b546efbb",
);
const SIGNATURE_HEX: &str = concat!(
    "3081870242019338c3cd65f87461f34e8c12ca0e5ed10e4b3a38e0874f18125a0",
    "83c918d29a372a34c8ef968151b43a8fff9ecf0528507d22c600a40c4f743b68b",
    "2875715164ae02411f45257d2da561e4a3492f8dfc1908b82d09d0eab0151d3076",
    "fefce5cbf37cbb58757fb5baa6d9c8e634361a764a44554f89b36893ffba5357f5",
    "75878664fca001",
);

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn main() {
    let public_key = decode_hex(PUBLIC_KEY_HEX);
    let signature = decode_hex(SIGNATURE_HEX);
    let verifier = UnparsedPublicKey::new(&ECDSA_P521_SHA512_ASN1, &public_key);

    for _ in 0..WARMUP_ITERATIONS {
        verifier
            .verify(black_box(VERIFY_MESSAGE), black_box(&signature))
            .expect("AWS-LC P-521 warmup verification");
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        verifier
            .verify(black_box(VERIFY_MESSAGE), black_box(&signature))
            .expect("AWS-LC P-521 verification");
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-p521-sha512={elapsed} ns/verify");

    let random = SystemRandom::new();
    let signing_key =
        EcdsaKeyPair::generate(&ECDSA_P521_SHA512_ASN1_SIGNING).expect("generate AWS-LC P-521 key");
    for _ in 0..WARMUP_ITERATIONS {
        black_box(
            signing_key
                .sign(&random, black_box(SIGN_MESSAGE))
                .expect("AWS-LC P-521 warmup signature"),
        );
    }
    let mut checksum = 0u64;
    let sign_start = Instant::now();
    for iteration in 0..SIGN_ITERATIONS {
        let signature = signing_key
            .sign(&random, black_box(SIGN_MESSAGE))
            .expect("AWS-LC P-521 signature");
        checksum =
            checksum.wrapping_add(signature.as_ref()[iteration % signature.as_ref().len()] as u64);
    }
    let sign_elapsed = sign_start.elapsed().as_nanos() / SIGN_ITERATIONS as u128;
    println!("aws-lc-p521-sha512={sign_elapsed} ns/sign checksum={checksum}");
}
