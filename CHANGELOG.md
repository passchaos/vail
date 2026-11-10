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
