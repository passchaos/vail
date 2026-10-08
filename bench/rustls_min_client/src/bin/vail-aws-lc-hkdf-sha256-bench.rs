use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 500_000;
const WARMUP_ITERATIONS: usize = 64;
const DIGEST_LEN: usize = 32;
const TLS13_PREFIX: &[u8] = b"tls13 ";

struct Material {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn expand_label<const N: usize>(secret: &[u8; DIGEST_LEN], label: &[u8]) -> [u8; N] {
    let mut info = [0u8; 32];
    info[0..2].copy_from_slice(&(N as u16).to_be_bytes());
    info[2] = (TLS13_PREFIX.len() + label.len()) as u8;
    let mut offset = 3;
    info[offset..offset + TLS13_PREFIX.len()].copy_from_slice(TLS13_PREFIX);
    offset += TLS13_PREFIX.len();
    info[offset..offset + label.len()].copy_from_slice(label);
    offset += label.len();
    info[offset] = 0;
    offset += 1;

    let mut output = [0u8; N];
    let ok = unsafe {
        aws_lc_sys::HKDF_expand(
            output.as_mut_ptr(),
            output.len(),
            aws_lc_sys::EVP_sha256(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            offset,
        )
    };
    assert_eq!(ok, 1);
    output
}

fn derive(secret: &[u8; DIGEST_LEN]) -> Material {
    Material {
        key: expand_label(secret, b"quic key"),
        iv: expand_label(secret, b"quic iv"),
        hp: expand_label(secret, b"quic hp"),
    }
}

fn main() {
    let mut secret = [0x42u8; DIGEST_LEN];
    let mut checksum = 0u64;
    let expected = Material {
        key: [
            0xda, 0x4f, 0x3a, 0x4c, 0xdd, 0xb4, 0xf2, 0x2a, 0x0a, 0x34, 0x80, 0xaa, 0x02, 0xd2,
            0x3e, 0x16,
        ],
        iv: [
            0x55, 0xc9, 0x37, 0xe2, 0x67, 0x13, 0x04, 0x10, 0x1f, 0xac, 0xd1, 0x92,
        ],
        hp: [
            0x1f, 0xa5, 0xfd, 0xcb, 0x25, 0x78, 0xe7, 0xf3, 0xbc, 0x03, 0xe9, 0x96, 0x54, 0x73,
            0xaa, 0x42,
        ],
    };
    let actual = derive(&secret);
    assert_eq!(actual.key, expected.key);
    assert_eq!(actual.iv, expected.iv);
    assert_eq!(actual.hp, expected.hp);

    for iteration in 0..WARMUP_ITERATIONS {
        secret[0] = iteration as u8;
        let material = derive(black_box(&secret));
        let warmup_byte = material.key[0]
            .wrapping_add(material.iv[0])
            .wrapping_add(material.hp[0]);
        checksum = checksum.wrapping_add(warmup_byte as u64);
    }

    let start = Instant::now();
    for iteration in 0..ITERATIONS {
        secret[0] = iteration as u8;
        let material = derive(black_box(&secret));
        checksum = checksum.wrapping_add(material.key[iteration % material.key.len()] as u64);
        checksum = checksum.wrapping_add(material.iv[iteration % material.iv.len()] as u64);
        checksum = checksum.wrapping_add(material.hp[iteration % material.hp.len()] as u64);
    }
    let elapsed = start.elapsed().as_nanos() / ITERATIONS as u128;
    println!("aws-lc-hkdf-sha256-three-labels={elapsed} ns/op checksum={checksum}");
}
