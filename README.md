# vail

`vail` is a Zig 0.16 cryptographic protocol library. Its target is to provide
a pure-Zig TLS/X.509 stack whose safety, protocol coverage, modularity, and
performance exceed mature stacks such as s2n-tls and rustls.

The current foundation provides:

- domain-separated HMAC-SHA256 and constant-time tag verification;
- fixed-size SHA-256 digests and explicit secure-memory wiping;
- TLS 1.3 Certificate and CertificateVerify codecs;
- Ed25519, ECDSA P-256, and ECDSA P-384 signer/verifier implementations, plus
  RSA-PSS/RSAE SHA-256 X.509 CertificateVerify and DER RSAPublicKey pin
  verification;
- type-safe server identities and pinned-key client verification;
- CertificateRequest codec and mTLS policy types;
- X.509 chain, hostname, validity, custom-bundle, and system-CA verification.
- TLS 1.3 SHA-256 early, handshake, application, resumption, PSK binder,
  Finished, 0-RTT, and traffic-update key scheduling.
- X25519 plus constant-time secp256r1 and secp384r1 ECDH key exchange, with
  uncompressed SEC1 validation and incremental SHA-256/SHA-384 transcript
  hashing.
- TLS 1.3 PSK-DHE ClientHello/ServerHello extensions, constant-time binders,
  early-data signaling, ticket-age validation, and NewSessionTicket codec.
- Allocation-free AES-256-GCM stateless session tickets with origin/ALPN
  associated-data binding and bounded current/history key rotation.
- Allocation-free QUIC traffic-secret protection for AES-128-GCM,
  AES-256-GCM, and ChaCha20-Poly1305, including nonce derivation, header
  protection, and suite confidentiality/integrity limits.
- Compile-time-specialized SHA-256/SHA-384 TLS 1.3 schedules, runtime
  hash-bound secrets/transcripts, 32/48-byte PSK binders, CertificateVerify,
  Finished, resumption PSKs, and stateless tickets.
- Canonical TLS 1.3 cipher-suite identities and validated client/server
  preference selection, with stateless tickets bound to their issuing suite.

Transport integration belongs in downstream libraries such as `netz`; reusable
cryptography and TLS state belong here.
