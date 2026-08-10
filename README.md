# vail

`vail` is a Zig 0.16 cryptographic protocol library. Its target is to provide
a pure-Zig TLS/X.509 stack whose safety, protocol coverage, modularity, and
performance exceed mature stacks such as s2n-tls and rustls.

The current foundation provides:

- domain-separated HMAC-SHA256 and constant-time tag verification;
- fixed-size SHA-256 and SM3 digests, portable SM2 signing/verification,
  SM4 block/SM4-GCM primitives, and explicit secure-memory wiping;
- TLS 1.3 Certificate and CertificateVerify codecs;
- Ed25519, ECDSA P-256, ECDSA P-384, and SM2/SM3 verifier
  implementations, plus RSA-PSS/RSAE SHA-256 X.509 CertificateVerify and DER
  RSAPublicKey pin verification;
- type-safe server identities and pinned-key client verification;
- CertificateRequest codec and mTLS policy types;
- X.509 chain, hostname, validity, custom-bundle, and system-CA verification.
- TLS 1.3 SHA-256 early, handshake, application, resumption, PSK binder,
  Finished, 0-RTT, and traffic-update key scheduling.
- X25519 plus constant-time secp256r1 and secp384r1 ECDH key exchange, with
  uncompressed SEC1 validation and incremental SHA-256/SHA-384 transcript
  hashing.
- Standards-aligned X25519MLKEM768 hybrid post-quantum key exchange with the
  registered `0x11ec` ML-KEM-first TLS share layout, compact seeded client
  state, explicit secret wiping, and full 64-byte hybrid HKDF input.
- Registered classical-first secp256r1MLKEM768 (`0x11eb`) and
  secp384r1MLKEM1024 (`0x11ed`) TLS groups, including exact SEC1/ML-KEM wire
  layouts, 64/80-byte hybrid HKDF inputs, and shared generic secret handling.
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
- ShangMi coverage: SM2 signs and verifies ZA-bound raw/DER signatures against
  SEC1 public keys and SM2 X.509 SubjectPublicKeyInfo, and is wired into TLS
  CertificateVerify generation/verification for raw and X.509 SM2 keys,
  SM3 implements Zig Hash/HMAC-compatible one-shot and streaming hashing, SM4
  exposes allocation-free block and 96-bit-nonce GCM APIs, and TLS/QUIC can
  negotiate the RFC 8998 TLS_SM4_GCM_SM3 (`0x00c6`) suite with SM3
  HKDF/transcripts, PSK binders, tickets, packet protection, and SM4 header
  protection. These are intentionally present even though the local
  `~/Work/aws-lc` checkout currently defines `OPENSSL_NO_SM2`, `OPENSSL_NO_SM3`,
  and `OPENSSL_NO_SM4`, so higher-level TLS/GMSSL work can proceed while an
  AWS-LC provider/backend is developed.

## AWS-LC backend configuration

Vail defaults to its pure-Zig primitives, including SM2/SM3/SM4. Builds can
record an AWS-LC checkout with `-Daws-lc-path=/home/passchaos/Work/aws-lc`;
`vail.crypto.backend` then reports `.aws_lc` and whether that checkout exposes
ShangMi support. Passing `-Daws-lc-link=true` additionally links
`<aws-lc-path>/build/crypto/libcrypto.a` and enables the
`vail.crypto.backend.sha256AwsLc` smoke API; the public
`vail.crypto.sha256.hash` helper routes through AWS-LC in linked builds and
falls back to Zig otherwise. The build fails early if AWS-LC has not been built.
The current local checkout defines `OPENSSL_NO_SM2`, `OPENSSL_NO_SM3`, and
`OPENSSL_NO_SM4`, so SM2/SM3/SM4 continue to come from Vail's Zig modules
until an AWS-LC provider/backend with those algorithms is available.

Transport integration belongs in downstream libraries such as `netz`; reusable
cryptography and TLS state belong here.
