# Compatibility matrix

This is a concise summary. The exhaustive feature inventory is in
[`features.md`](features.md).

## TLS

| Feature | TLS 1.3 | TLS 1.2 |
| --- | --- | --- |
| Client and server state machines | Yes | Yes |
| HelloRetryRequest / cookies | Yes | n/a |
| PSK-DHE resumption | Yes | n/a |
| 0-RTT early data | Yes | n/a |
| Session IDs | n/a | Yes |
| RFC 5077 stateless tickets | Yes | Yes |
| KeyUpdate | Yes | n/a |
| Record-size limit (RFC 8449) | Yes | Yes |
| Raw public keys (RFC 7250) | Yes | — |
| mTLS / CertificateRequest | Yes | Yes |
| ECH (RFC 9849) | Yes | n/a |
| ALPS (`application_settings`) | Yes | n/a |
| Certificate compression (RFC 8879) | Yes | — |
| Extended master secret | n/a | Yes |

### Cipher suites

- TLS 1.3: AES-128-GCM, AES-256-GCM, AES-128-CCM, AES-128-CCM-8,
  ChaCha20-Poly1305.
- TLS 1.2: ECDHE-RSA/ECDHE-ECDSA with AES-128/256-GCM and
  ChaCha20-Poly1305, plus the AES-256-GCM/SHA-384 variant.

### Key exchange groups

- X25519
- secp256r1, secp384r1, secp521r1
- X25519MLKEM768
- ML-KEM-768, ML-KEM-1024
- secp256r1MLKEM768, secp384r1MLKEM1024

### Signature schemes

- Ed25519
- ECDSA P-256/P-384/P-521 with SHA-2, SHA-3, and SHAKE variants
- RSA PKCS#1 v1.5 and RSA-PSS with SHA-2, SHA-3, and SHAKE variants
- ML-DSA-44/65/87 (opt-in TLS raw public keys)
- SM2/SM3

## X.509

- Bounded path construction over unordered intermediates.
- Validity, hostname/IP identity, KeyUsage, EKU, and name constraints.
- RFC 5280/RFC 9618 certificate policy handling.
- CRL and OCSP verification, including delta CRLs and stapled OCSP.
- Platform system trust stores plus caller-supplied compatible anchors.
- RFC 2253 distinguished names and RFC 4518 case-ignore matching.
- Certificate sets for caller-managed trust material.

## QUIC

- QUIC v1 Initial and Retry secrets.
- TLS handshake adapters for client and server roles.
- Transport-parameter extension plumbing.
- Traffic-key derivation and packet protection.

## Archive cryptography (`archive_crypto`)

- Traditional PKZIP/ZipCrypto.
- WinZip AE-1/AE-2.
- Password-based PKWARE Strong Encryption AES subset.
- RAR4, RAR5, and legacy RAR.
- 7zAES.
- ARJ, ESD, CryptoAPI RSA, and Android OTA helpers.

## Platforms

| Platform | Status |
| --- | --- |
| Linux x86_64 | Primary optimized target |
| Linux AArch64 | Optimized AES/PMULL, s2n-bignum P-256/P-384/X25519, and runtime-gated SHA-512 paths (portable fallback without `HWCAP_SHA512`) |
| Other Zig targets | Portable implementations; acceleration is currently Linux-targeted |
| Windows/macOS | Portable paths; target-specific accelerated kernels are not currently provided |

### Kernel coverage

| Primitive | Linux x86_64 | Linux AArch64 |
| --- | --- | --- |
| AES-GCM | AES-NI/VAES/VPCLMULQDQ | AES/PMULL |
| ChaCha20-Poly1305 | AVX2 | NEON |
| SHA-256 | SHA-NI/AVX2 | ARM SHA2 via Zig std |
| SHA-384/SHA-512 | AVX | ARMv8.2 SHA-512, runtime-gated on `HWCAP_SHA512` |
| X25519 | ADX/AVX2 | s2n-bignum |
| P-256 | ADX/AVX2 | s2n-bignum |
| P-384 | ADX | s2n-bignum |
| P-521 | ADX | Portable |
| Ed25519 | ADX | Portable |
| RSA | ADX Montgomery | Portable |
| Keccak/SHA-3 | AVX2 | s2n-bignum (single- and four-way) |
| ML-KEM | AVX2 | Portable |
| ML-DSA | AVX2 | Portable |

## Not claimed

- FIPS certification.
- TLS 1.0/1.1 or SSLv3.
- A universal performance lead across every primitive and platform. Benchmark
  results are host- and workload-specific; see [`benchmarks.md`](benchmarks.md).
