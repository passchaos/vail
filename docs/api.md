# API tiers

Vail is pre-1.0, but not every exported symbol has the same stability
expectation. Use the following tiers when deciding what to depend on.

## Stable API

These are the intended public entry points:

- `vail.crypto` — primitives and prepared contexts.
- `vail.x509` — certificate parsing, trust stores, policy, CRL, and OCSP.
- `vail.tls` — connection, handshake, authentication, and configuration APIs.
- `vail.quic` — QUIC TLS adapters and traffic crypto.

Prefer the connection-level APIs (`tls.client_connection`,
`tls.server_connection`, version-selecting variants) and the documented
`Config`/`ClientVerifier` types over lower-level codecs.

## Advanced API

Some lower-level modules are exported because transports and specialized
callers need them:

- TLS record/handshake codecs, key schedule, transcript, PSK, ticket, and
  traffic-secret types.
- X.509 certificate/signature parsers and individual revocation helpers.
- QUIC Initial/Retry and transport-parameter codecs.

These APIs follow the same review process but may change more often than the
connection-level surface. Pin a commit or release if you depend on them.

## Lightweight modules

- `vail_sm` exposes `sm2` and `sm3` without the TLS graph.
- `vail_signature_primitives` exposes P-521, SM2, and SM3 standalone
  verification/hashing.

These modules intentionally have a smaller dependency graph and are suitable for
consumers that only need public-data signature verification.

## Test-only namespace

`vail.testdata` contains fixed certificates, keys, signatures, and path vectors
used by Vail's tools and benchmarks. It is **not** a stable API. Do not ship or
depend on these values in production.

## Internal

Anything not exported by the module entry points (`crypto/mod.zig`,
`x509/mod.zig`, `tls/mod.zig`, `quic/mod.zig`) is internal. Generated tables and
embedded assembly are implementation details; their headers document provenance
and regeneration commands.

## Importing

```zig
const vail = @import("vail");

const digest = vail.crypto.sha256.hash("message");
const trust = vail.x509.trust;
const tls = vail.tls;
```

Consumers that only need ShangMi primitives can import the `vail_sm` build
module instead of the full `vail` module.
