# Changelog

All notable changes to Vail are documented here. The project is pre-1.0, so
minor releases may contain API changes.

## Unreleased

### Changed

- Separated shared signature-algorithm and RSA-PSS parsing from X.509 into the
  crypto layer, removing `crypto -> x509` reverse dependencies.
- Moved trust callback/context types into `x509/verifier.zig`, removing the
  `x509 -> tls` reverse dependency.
- Routed TLS X.509 imports through `x509/mod.zig`.
- Added `test-all`, `bench`, `interop`, `fmt`, and `check` build steps.
- Extracted the benchmark and interoperability graphs into
  `build_support/benches.zig` and `build_support/interop.zig`.
- Added `-Dbench`, `-Dinterop`, `-Darchive`, and `-Dexamples` build flags.
- Split crypto into `aead/`, `block/`, `hash/`, `ec/`, `pq/`, `sign/`, and
  `kex/` modules; split TLS into `connection/`, `handshake/`, `crypto/`, and
  `tls12/` modules.
- Split P-521 field, P-256 field/scalar, P-384 scalar, and RSA Montgomery
  arithmetic into dedicated modules.
- Split QUIC TLS handshake into `quic/handshake/{common,client,server}.zig`.
- Split X.509 and TLS tests into topic files with shared helpers.
- Added a generated-file SHA-256 manifest and `zig build check-generated`.
- Added `tools/generate_stringprep_data.zig` and `tools/stringprep_input.txt`
  for reproducible stringprep table regeneration.
- Added `zig build check-docs` to verify relative Markdown links.
- Added the 5,000-line guideline for hand-written source files; generated
  tables and embedded assembly are documented exceptions.
- Added `archive_crypto` to the root `test-all` suite.
- Relaxed the Zig version check to accept `0.16.x` patch releases.
- Added `build`, `tools`, `archive_crypto`, and `docs` to the package paths.
- Split the README feature catalog and performance log into `docs/`.
- Added architecture, building, compatibility, security, benchmarks,
  third-party, evidence, contribution, and security-policy documentation.

## 0.1.0

Initial public development snapshot.

### Added

- TLS 1.3 client/server state machines, PSK-DHE and 0-RTT resumption, ECH,
  ALPS, certificate compression, raw public keys, mTLS, and record protection.
- TLS 1.2 client/server with ECDHE-RSA/ECDSA, AES-GCM, ChaCha20-Poly1305,
  extended master secret, session IDs, and RFC 5077 tickets.
- X.509 path building, policy, name constraints, CRL, OCSP, and system trust
  stores.
- QUIC Initial/Retry secrets, TLS handshake adapters, transport parameters, and
  traffic crypto.
- AES-GCM/CCM/CBC/CTR, ChaCha20-Poly1305, XChaCha20-Poly1305, SHA-2, SHA-3,
  BLAKE2s, HMAC, HKDF, HPKE, X25519, P-256/P-384/P-521, Ed25519, RSA,
  ML-KEM, ML-DSA, SM2/SM3/SM4.
- `archive_crypto` package for ZipCrypto, WinZip AES, PKWARE Strong Encryption,
  RAR4/RAR5, 7zAES, ARJ, ESD, CryptoAPI RSA, and Android OTA helpers.
