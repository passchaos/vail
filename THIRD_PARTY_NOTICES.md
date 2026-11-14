# Third-party notices

Vail itself is licensed under the MIT License (see `LICENSE`). The following
third-party components are embedded or derived from upstream projects. Per-file
SPDX headers are authoritative; this file is a summary.

## s2n-bignum

- License: Apache-2.0 OR ISC OR MIT-0
- Copyright: Amazon.com, Inc. or its affiliates
- Used for: formally verified P-256, P-384, P-521, X25519, Ed25519, Keccak, and
  ML-DSA instruction schedules.
- Locations: `src/crypto/*_adx.zig`, `src/crypto/*_x86.zig`,
  `src/crypto/*_arm64.S`, `src/crypto/keccak*_avx2.S`,
  `src/crypto/mldsa_*_avx2.S`.
- Pinned revisions are recorded in the relevant file headers.

## mlkem-native / s2n-bignum

- License: Apache-2.0 OR ISC OR MIT
- Copyright: The mlkem-native project authors; Amazon.com, Inc. or its
  affiliates
- Used for: ML-KEM AVX2 kernels and AArch64 NTT/INTT/basemul/reduction
  kernels.
- Locations: `src/crypto/pq/mlkem/*.S` (x86_64 and AArch64). The AArch64
  twiddle-factor tables in `src/crypto/pq/mlkem/zetas_arm64.zig` are extracted
  from the same upstream `aarch64_zetas.c`.
- These files are vendored and preprocessed for the ELF x86_64 or AArch64 SysV
  ABI.

## OpenSSL SHA-2 assembly

- License: Apache-2.0
- Copyright: The OpenSSL Project Authors
- Used for: SHA-512/SHA-384 compressors.
- Locations:
  - `src/crypto/hash/sha512/avx.S` — x86_64, derived from
    `sha512-x86_64.pl`;
  - `src/crypto/hash/sha512/arm64.S` — AArch64, derived from
    `sha512-armv8.pl`.
- Preprocessed for the ELF x86_64 or AArch64 SysV ABI. The AArch64 hardware
  path is runtime-gated on `HWCAP_SHA512` and falls back to a portable
  compressor when the extension is unavailable.

## BoringSSL / AWS-LC BEEU

- License: ISC
- Copyright: The BoringSSL Authors; Amazon.com, Inc. or its affiliates
- Used for: P-256 public ECDSA scalar inverse.
- Location: `src/crypto/ec/p256_scalar_inv_arm64.S` and related wrappers.
- Pinned at BoringSSL `7eab8046` where noted.

## Unicode data

- License: Unicode Data Files and Software License
  (https://www.unicode.org/license.txt)
- Copyright: Unicode, Inc.
- Used for: RFC 4518 case-ignore matching data.
- Location: `src/x509/stringprep_data.zig`.
- Generated from Unicode 3.2 and RFC 3454 tables.

## Zig standard library

- License: MIT
- Used for: SHA-256, SHA-1, SHA-3/SHAKE, AES core, and other primitives where
  Vail does not provide a dedicated accelerated implementation.

## Vort

- License: see the sibling Vort repository
- Used for: RFC 8879 Brotli certificate compression.
- Resolved through `build.zig.zon` as a sibling path dependency.

## Updating this file

When adding or updating embedded third-party code:

1. Preserve or add the SPDX header and upstream revision.
2. Update this file and `docs/third-party.md`.
3. Re-run the relevant differential, fixed-vector, and interoperability tests.
