use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, ECDH_P384};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 1_000;
const WARMUP_ITERATIONS: usize = 32;

fn main() {
    let mut local_secret = [0u8; 48];
    local_secret[47] = 7;
    let mut peer_secret = [0u8; 48];
    peer_secret[47] = 11;
    let peer = PrivateKey::from_private_key(&ECDH_P384, &peer_secret)
        .expect("parse peer P-384 private key");
    let peer_public = peer
        .compute_public_key()
        .expect("derive peer P-384 public key");
    let mut checksum = 0u64;

    for iteration in 0..WARMUP_ITERATIONS {
        let private = PrivateKey::from_private_key(&ECDH_P384, black_box(&local_secret))
            .expect("parse P-384 private key");
        let public = private
            .compute_public_key()
            .expect("derive P-384 public key");
        checksum = checksum.wrapping_add(public.as_ref()[iteration % public.as_ref().len()] as u64);
    }
    let public_start = Instant::now();
    for iteration in 0..ITERATIONS {
        let private = PrivateKey::from_private_key(&ECDH_P384, black_box(&local_secret))
            .expect("parse P-384 private key");
        let public = private
            .compute_public_key()
            .expect("derive P-384 public key");
        checksum = checksum.wrapping_add(public.as_ref()[iteration % public.as_ref().len()] as u64);
        black_box(public);
    }
    let public_ns = public_start.elapsed().as_nanos() / ITERATIONS as u128;

    for iteration in 0..WARMUP_ITERATIONS {
        let local = PrivateKey::from_private_key(&ECDH_P384, black_box(&local_secret))
            .expect("parse P-384 private key");
        let peer_key = UnparsedPublicKey::new(&ECDH_P384, peer_public.as_ref());
        let byte = agreement::agree(&local, peer_key, (), |secret| {
            Ok::<u8, ()>(secret[iteration % secret.len()])
        })
        .expect("P-384 agreement");
        checksum = checksum.wrapping_add(byte as u64);
    }
    let shared_start = Instant::now();
    for iteration in 0..ITERATIONS {
        let local = PrivateKey::from_private_key(&ECDH_P384, black_box(&local_secret))
            .expect("parse P-384 private key");
        let peer_key = UnparsedPublicKey::new(&ECDH_P384, black_box(peer_public.as_ref()));
        let byte = agreement::agree(&local, peer_key, (), |secret| {
            Ok::<u8, ()>(secret[iteration % secret.len()])
        })
        .expect("P-384 agreement");
        checksum = checksum.wrapping_add(byte as u64);
    }
    let shared_ns = shared_start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-p384-public={public_ns} ns/op shared={shared_ns} ns/op checksum={checksum}");
}
