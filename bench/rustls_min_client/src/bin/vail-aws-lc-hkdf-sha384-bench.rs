use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 250_000;
const WARMUP_ITERATIONS: usize = 64;
const DIGEST_LEN: usize = 48;
const TLS13_PREFIX: &[u8] = b"tls13 ";

struct Material {
    key: [u8; 32],
    iv: [u8; 12],
    hp: [u8; 32],
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
            aws_lc_sys::EVP_sha384(),
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
            0xfb, 0x68, 0x81, 0x1e, 0x87, 0x5a, 0x2d, 0x8f, 0x74, 0x6b, 0x0b, 0x7d, 0x08, 0x94,
            0xd9, 0xc7, 0xf5, 0xd7, 0x48, 0x80, 0x84, 0x75, 0x5a, 0x4c, 0x2f, 0x3e, 0x05, 0xaf,
            0xbc, 0xb6, 0xa6, 0xe8,
        ],
        iv: [
            0xfc, 0x70, 0x00, 0xd2, 0x21, 0x22, 0xc0, 0x58, 0x70, 0xb4, 0xff, 0x40,
        ],
        hp: [
            0x8e, 0x2f, 0x23, 0x23, 0x74, 0xc7, 0x1f, 0xfe, 0x78, 0xa7, 0x24, 0xbc, 0xb0, 0x55,
            0x05, 0x10, 0x1d, 0x86, 0x61, 0x3c, 0x51, 0xb9, 0x18, 0x17, 0x68, 0xe9, 0xec, 0x75,
            0xf2, 0x06, 0x25, 0x93,
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
    println!("aws-lc-hkdf-sha384-three-labels={elapsed} ns/op checksum={checksum}");
}
