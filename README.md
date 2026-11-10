# vail

`vail` is a Zig 0.16 cryptographic protocol library. Its target is a pure-Zig
TLS/X.509 stack whose safety, protocol coverage, modularity, and performance
exceed mature stacks such as s2n-tls and rustls.

Vail owns TLS, X.509, QUIC TLS adapters, signature verification, key schedules,
and cryptographic state. Transport libraries such as `netz` depend on these
protocol APIs rather than embedding cryptographic logic.

## Status

- Zig `0.16.x` is required.
- The project is pre-1.0; public APIs may still change between minor releases.
- There is no C, C++, or Rust runtime dependency. Some accelerated paths embed
  formally verified s2n-bignum, BoringSSL/AWS-LC, or OpenSSL assembly; see
  [`docs/third-party.md`](docs/third-party.md).
- The detailed feature inventory lives in
  [`docs/features.md`](docs/features.md). Current benchmark results and their
  methodology live in [`docs/benchmarks.md`](docs/benchmarks.md).

## Feature matrix

| Area | Highlights |
| --- | --- |
| TLS 1.3 | Client/server state machines, HelloRetryRequest, PSK-DHE and 0-RTT resumption, KeyUpdate, record-size limits, raw public keys, mTLS, ECH, ALPS, certificate compression, stateless tickets |
| TLS 1.2 | Client/server, ECDHE-RSA/ECDSA, AES-GCM, ChaCha20-Poly1305, extended master secret, session IDs, RFC 5077 tickets, P-521, AES-256-GCM/SHA-384 |
| X.509 | Bounded path building, policy and name constraints, CRL and OCSP verification, system trust stores, RFC 2253 names, certificate sets |
| QUIC | Initial/Retry secrets, TLS handshake adapters, transport parameters, traffic-key derivation and packet protection |
| AEAD and hashing | AES-128/256-GCM, AES-CCM, AES-CBC/CTR, ChaCha20-Poly1305, XChaCha20-Poly1305, SHA-256/384/512, SHA-3/SHAKE signature support, BLAKE2s, SM3, HMAC, HKDF |
| Key exchange | X25519, P-256, P-384, P-521, hybrid X25519MLKEM768, pure ML-KEM-768/1024, secp256r1MLKEM768, secp384r1MLKEM1024 |
| Signatures | Ed25519, ECDSA P-256/P-384/P-521, RSA PKCS#1 v1.5 and PSS, ML-DSA-44/65/87, SM2 |
| Symmetric | SM4 block/GCM/CCM, AES-CBC with PKCS#7, prepared AEAD contexts |
| Archive (`archive_crypto`) | ZipCrypto, WinZip AE-1/AE-2, PKWARE Strong Encryption, RAR4/RAR5, 7zAES, ARJ, ESD, CryptoAPI RSA, Android OTA |

## Quick start

The package currently resolves the sibling `vort` package through
`build.zig.zon`. Clone `vort` next to `vail` before building:

```sh
git clone <vort-repository> ../vort
```

A minimal primitive example:

```zig
const std = @import("std");
const vail = @import("vail");

pub fn main() !void {
    const digest = vail.crypto.sha256.hash("hello vail");
    std.debug.print("sha256={x}\n", .{digest});

    const key = [_]u8{0x42} ** vail.crypto.aes_gcm.Aes128Gcm.key_length;
    var gcm = vail.crypto.aes_gcm.Aes128Gcm.init(key);
    defer gcm.deinit();

    const plaintext = "hello vail";
    const nonce = [_]u8{0x01} ** vail.crypto.aes_gcm.Aes128Gcm.nonce_length;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [vail.crypto.aes_gcm.Aes128Gcm.tag_length]u8 = undefined;
    gcm.encrypt(&ciphertext, &tag, plaintext, "", nonce);

    var decrypted: [plaintext.len]u8 = undefined;
    try gcm.decrypt(&decrypted, &ciphertext, tag, "", nonce);
    std.debug.assert(std.mem.eql(u8, plaintext, &decrypted));
}
```

More examples are under [`examples/`](examples/).

## Build and test

```sh
zig build                 # build the static library
zig build test            # Vail + package API tests
zig build test-all        # Vail, package, signature-primitive, and archive tests
zig build test-compile    # compile tests without running them
zig build check           # zig fmt --check + test-all
zig build fmt             # format Zig sources
```

Benchmarks and interoperability checks are opt-in:

```sh
zig build bench           # all benchmarks
zig build interop         # all interoperability checks
zig build bench-tls-client-connection
zig build interop-openssl-p384-sign
```

The AWS-LC and rustls reference harnesses require Cargo and their native build
prerequisites. See [`bench/README.md`](bench/README.md) and
[`docs/building.md`](docs/building.md).

The `archive_crypto` subpackage can also be built independently:

```sh
cd archive_crypto
zig build test
```

## Platform and acceleration

| Target | Accelerated paths | Fallback |
| --- | --- | --- |
| Linux x86_64 | AVX2/BMI2/ADX kernels, AES-NI/VAES/VPCLMULQDQ, SHA-NI where available | Pure-Zig portable formulas |
| Linux AArch64 | AES/PMULL, s2n-bignum P-256/X25519 schedules | Pure-Zig portable formulas |
| Debug / ReleaseSmall | Portable implementations retained as independent oracles | — |

Acceleration is selected at compile time from the target CPU features. Secret
paths use constant-schedule selection and explicit zeroization; see
[`docs/security.md`](docs/security.md).

## Security

- Report vulnerabilities through the process in [`SECURITY.md`](SECURITY.md).
- Secret-dependent code paths avoid data-dependent branches and table indices.
- Callers own randomness, buffers, and long-lived key material; prepared
  contexts document their wiping behavior.
- Vail is not FIPS-certified. Do not assume FIPS compliance without an
  independent validation effort.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — module boundaries, ownership, and data flow
- [`docs/api.md`](docs/api.md) — stable, advanced, and test-only API tiers
- [`docs/compatibility.md`](docs/compatibility.md) — concise protocol and algorithm matrix
- [`docs/building.md`](docs/building.md) — toolchain, build, test, and benchmark setup
- [`docs/security.md`](docs/security.md) — threat model, constant-time policy, and limitations
- [`docs/benchmarks.md`](docs/benchmarks.md) — benchmark methodology and results index
- [`docs/features.md`](docs/features.md) — full feature catalog
- [`docs/third-party.md`](docs/third-party.md) — embedded third-party code and licenses
- [`docs/evidence/README.md`](docs/evidence/README.md) — dated verification evidence

## License

Vail is released under the MIT License. Embedded third-party code is covered by
its own licenses; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
