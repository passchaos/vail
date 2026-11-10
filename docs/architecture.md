# Architecture

Vail is organized as a small protocol stack rather than a single flat crypto
library. The intended dependency direction is:

```text
crypto  <-  x509  <-  tls  <-  quic
```

`archive_crypto` is a separate, dependency-free package that intentionally does
not import the main `crypto` module.

## Layers

### `src/crypto`

Reusable cryptographic primitives and prepared contexts. This layer must not
depend on X.509 or TLS.

- AEAD: `crypto/aead/` (`aes_gcm`, `aes_ccm`, `chacha20_poly1305`,
  `xchacha20_poly1305`, `ghash`)
- Block/counter modes: `crypto/block/` (`aes_cbc`, `aes_ctr`, `sm4`)
- Hashes and MACs: `crypto/hash/` (`sha256`, `sha512`, `sm3`, `blake2s`,
  `keccak*`) and `crypto/mac.zig`
- Elliptic curves: `crypto/ec/` (`p256`, `p384`, `p521` and their platform
  kernels/tables)
- PQ KEM and signatures: `crypto/pq/` (`mlkem`, `mldsa`)
- Signatures: `crypto/sign/` (`ed25519`, `rsa`, `sm2`)
- Key exchange: `crypto/kex/` (`x25519`, `hpke`)
- Shared parsing: `src/der.zig`, `crypto/signature_algorithm.zig`,
  `crypto/rsa_pss.zig`
- Secure memory: `crypto/memory.zig`

`crypto/sign/rsa.zig` parses RSA-PSS key constraints through
`crypto/rsa_pss.zig`; it does not import X.509.

### `src/x509`

Certificate parsing, trust stores, path building, policy, CRL, and OCSP. This
layer depends on `crypto` but must not depend on TLS.

- `certificate`, `distinguished_name`, `rfc2253`, `stringprep`
- `trust`, `policy`, `identity`
- `crl`, `ocsp`, `issuer_fetch`, `certificate_set`
- `verifier` — shared `TrustContext`, `TrustCallback`, and `TrustVerifier`

X.509 trust stores return a `TrustVerifier` callback/context pair. TLS wraps
that pair with its own CertificateVerify state; X.509 does not import TLS.

### `src/tls`

TLS 1.3 and TLS 1.2 handshake and record state machines, certificate
authentication, PSK/resumption, ECH, ALPS, and record protection. TLS may depend
on both `crypto` and `x509`.

- `tls/connection/` — client/server/versioned connection state and stream helpers
- `tls/handshake/` — ClientHello/ServerHello, flights, authentication, ECH,
  ALPS, and handshake extensions
- `tls/crypto/` — key schedule, transcript, traffic secrets, PSK, tickets, and
  cipher-suite identities
- `tls/tls12/` — TLS 1.2 handshake and connection state
- Root TLS files — alerts, record protection, record fragmentation, key
  exchange, and test vectors

Public entry points live in `tls/mod.zig`. Lower-level codecs and state remain
available for transports that need them, but new code should prefer the stable
connection and authentication APIs.

### `src/quic`

QUIC-specific TLS adapters, Initial/Retry secrets, transport parameters, and
traffic-key derivation. QUIC depends on `tls` and `crypto`.

- `quic/handshake/common.zig` — shared handshake types and helpers;
- `quic/handshake/client.zig` — client flight processing;
- `quic/handshake/server.zig` — server flight processing;
- `quic/tls_handshake.zig` — public re-exports and handshake tests.

### `archive_crypto`

A standalone package for archive-specific password-based cryptography. It uses
`std.crypto` directly and is intentionally independent of the main module so
archive consumers do not pull in the TLS graph. Changes that affect shared
algorithms should be checked against the main `crypto` implementations with
differential tests.

## Dependency rules

1. `crypto` must not import `x509` or `tls`.
2. `x509` must not import `tls`.
3. `tls` and `quic` may import lower layers.
4. Cross-module consumers should use the owning module's public entry point
   (`crypto/mod.zig`, `x509/mod.zig`, `tls/mod.zig`, `quic/mod.zig`) rather than
   reaching into another layer's internal files.
5. Test-only imports are allowed but should be local to test blocks and must not
   become production dependencies.

The build graph is currently one Zig module, so these rules are conventions
rather than compiler-enforced boundaries. Splitting the graph into explicit
submodules is a planned follow-up.

## Build graph

`build.zig` contains the library, test, example, formatting, and umbrella
steps. The large benchmark and interoperability graphs live in
`build_support/`:

- `build_support/benches.zig` — all `bench-*` targets;
- `build_support/interop.zig` — all `interop-*` targets;
- `build_support/mldsa_benchmarks.zig` and `mlkem_benchmarks.zig` — shared
  parameter-set benchmark helpers.

`zig build bench` and `zig build interop` iterate the top-level steps after the
helper modules have registered them.

## Ownership and allocation

- Hot paths are allocation-free. Callers provide output buffers and, where
  needed, scratch storage.
- Prepared verifiers and AEAD contexts cache key-dependent state and document
  their preparation cost and lifetime.
- Long-lived secrets are owned by the caller. Temporary secrets are explicitly
  wiped with `crypto/memory.zig` or `std.crypto.secureZero`.
- TLS and QUIC states transfer owned certificate chains and secrets explicitly;
  socket ownership remains a downstream transport concern.

## Testing

- Unit tests live next to the implementation they exercise.
- Module-level `tests.zig` files cover cross-file behavior within a layer.
- X.509 tests are grouped under `src/x509/tests/` with shared helpers in
  `common.zig`.
- `test/package_test.zig` checks that the public module surface is reachable.
- `zig build test-all` runs the Vail, package, signature-primitive, and
  `archive_crypto` suites.

## Generated code and assembly

- Generated tables carry a `Generated by tools/...` header and are excluded
  from `zig build fmt`/`check`.
- Embedded `.S` files carry SPDX headers and are included through
  `asm(@embedFile(...))`.
- See [`third-party.md`](third-party.md) for provenance and licensing.
