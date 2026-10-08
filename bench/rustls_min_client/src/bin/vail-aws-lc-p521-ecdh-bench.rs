use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, ECDH_P521};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 1_000;
const WARMUP_ITERATIONS: usize = 32;

fn main() {
    let mut local_secret = [0u8; 66];
    local_secret[65] = 7;
    let mut peer_secret = [0u8; 66];
    peer_secret[65] = 11;
    let peer = PrivateKey::from_private_key(&ECDH_P521, &peer_secret)
        .expect("parse peer P-521 private key");
    let local = PrivateKey::from_private_key(&ECDH_P521, &local_secret)
        .expect("parse local P-521 private key");
    let peer_public = peer
        .compute_public_key()
        .expect("derive peer P-521 public key");
    let mut checksum = 0u64;

    for iteration in 0..WARMUP_ITERATIONS {
        let private = PrivateKey::from_private_key(&ECDH_P521, black_box(&local_secret))
            .expect("parse P-521 private key");
        let public = private
            .compute_public_key()
            .expect("derive P-521 public key");
        checksum = checksum.wrapping_add(public.as_ref()[iteration % public.as_ref().len()] as u64);
    }
    let public_start = Instant::now();
    for iteration in 0..ITERATIONS {
        let private = PrivateKey::from_private_key(&ECDH_P521, black_box(&local_secret))
            .expect("parse P-521 private key");
        let public = private
            .compute_public_key()
            .expect("derive P-521 public key");
        checksum = checksum.wrapping_add(public.as_ref()[iteration % public.as_ref().len()] as u64);
        black_box(public);
    }
    let public_ns = public_start.elapsed().as_nanos() / ITERATIONS as u128;

    for iteration in 0..WARMUP_ITERATIONS {
        let local = PrivateKey::from_private_key(&ECDH_P521, black_box(&local_secret))
            .expect("parse P-521 private key");
        let peer_key = UnparsedPublicKey::new(&ECDH_P521, peer_public.as_ref());
        let byte = agreement::agree(&local, peer_key, (), |secret| {
            Ok::<u8, ()>(secret[iteration % secret.len()])
        })
        .expect("P-521 agreement");
        checksum = checksum.wrapping_add(byte as u64);
    }
    let shared_start = Instant::now();
    for iteration in 0..ITERATIONS {
        let local = PrivateKey::from_private_key(&ECDH_P521, black_box(&local_secret))
            .expect("parse P-521 private key");
        let peer_key = UnparsedPublicKey::new(&ECDH_P521, black_box(peer_public.as_ref()));
        let byte = agreement::agree(&local, peer_key, (), |secret| {
            Ok::<u8, ()>(secret[iteration % secret.len()])
        })
        .expect("P-521 agreement");
        checksum = checksum.wrapping_add(byte as u64);
    }
    let shared_raw_ns = shared_start.elapsed().as_nanos() / ITERATIONS as u128;

    for iteration in 0..WARMUP_ITERATIONS {
        let peer_key = UnparsedPublicKey::new(&ECDH_P521, peer_public.as_ref());
        let byte = agreement::agree(&local, peer_key, (), |secret| {
            Ok::<u8, ()>(secret[iteration % secret.len()])
        })
        .expect("P-521 agreement");
        checksum = checksum.wrapping_add(byte as u64);
    }
    let shared_prepared_start = Instant::now();
    for iteration in 0..ITERATIONS {
        let peer_key = UnparsedPublicKey::new(&ECDH_P521, black_box(peer_public.as_ref()));
        let byte = agreement::agree(&local, peer_key, (), |secret| {
            Ok::<u8, ()>(secret[iteration % secret.len()])
        })
        .expect("P-521 agreement");
        checksum = checksum.wrapping_add(byte as u64);
    }
    let shared_prepared_ns = shared_prepared_start.elapsed().as_nanos() / ITERATIONS as u128;

    println!(
        "aws-lc-p521-public={public_ns} ns/op shared-raw={shared_raw_ns} ns/op \
         shared-prepared={shared_prepared_ns} ns/op checksum={checksum}"
    );
}
