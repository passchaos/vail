# archive_crypto

`archive_crypto` is a dependency-free subpackage for password-based archive
cryptography. It is intentionally separate from the main Vail module so archive
consumers do not pull in the TLS/X.509 graph.

## Scope

- Traditional PKZIP/ZipCrypto byte-stream state and one-shot helpers.
- WinZip AE-1/AE-2 key derivation, AES-CTR, and HMAC-SHA1-80 authentication.
- Password-based PKWARE Strong Encryption AES subset.
- RAR4, RAR5, and legacy RAR helpers.
- 7zAES key derivation and AES-CBC streaming.
- ARJ, ESD, CryptoAPI RSA, and Android OTA helpers.

Wire records, padding policy, IV allocation, and archive integrity checks remain
the caller's responsibility unless an API explicitly owns them.

## Build and test

```sh
cd archive_crypto
zig build test
```

The root `zig build test-all` also compiles and runs this suite.

## Design notes

- The package uses `std.crypto` directly and does not import `src/crypto`.
  This keeps the dependency graph small but means shared algorithms can diverge.
  Changes affecting AES, SHA, HMAC, or PBKDF2 should be checked against the main
  Vail implementations with differential tests.
- Callers supply passwords, salts, header entropy, and output buffers.
- Temporary keys and stream state are explicitly wiped where the API owns them.
- These APIs implement cryptographic subsets, not complete archive parsers.
