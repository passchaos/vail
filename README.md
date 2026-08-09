# vail

`vail` is a Zig 0.16 cryptographic protocol library. Its target is to provide
a pure-Zig TLS/X.509 stack whose safety, protocol coverage, modularity, and
performance exceed mature stacks such as s2n-tls and rustls.

The current foundation provides:

- TLS 1.3 Certificate and CertificateVerify codecs;
- Ed25519 and ECDSA P-256 signer/verifier implementations;
- type-safe server identities and pinned-key client verification;
- CertificateRequest codec and mTLS policy types;
- X.509 chain, hostname, validity, custom-bundle, and system-CA verification.

Transport integration belongs in downstream libraries such as `netz`; reusable
cryptography and TLS state belong here.
