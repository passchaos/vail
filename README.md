# vail

`vail` is a Zig 0.16 cryptographic protocol library. Its target is to provide
a pure-Zig TLS/X.509 stack whose safety, protocol coverage, modularity, and
performance exceed mature stacks such as s2n-tls and rustls.

The current foundation provides:

- domain-separated HMAC-SHA256 and constant-time tag verification;
- fixed-size SHA-256 and SM3 digests, portable SM2 signing/verification,
  SM4 block/SM4-GCM primitives, and explicit secure-memory wiping;
- TLS 1.3 ClientHello parsing, encrypted server-handshake flight construction,
  ServerHello/EncryptedExtensions, Certificate, CertificateVerify, Finished, and
  AEAD record-protection codecs;
- Ed25519, ECDSA P-256, ECDSA P-384, and SM2/SM3 verifier
  implementations, plus RSA-PSS/RSAE SHA-256 X.509 CertificateVerify and DER
  RSAPublicKey pin verification. TLS P-256 verification uses the curve's public
  double-scalar primitive for the ECDSA verification equation, with
  deterministic equivalence and malformed-scalar tests against Zig's generic
  verifier;
- type-safe server identities and pinned-key client verification;
- CertificateRequest codec and mTLS policy types;
- X.509 chain, hostname, validity, custom-bundle, and system-CA verification,
  plus a client-certificate bundle verifier that omits hostname matching and
  enforces the clientAuth endpoint purpose for mTLS server policy.
  Strict subject identity extraction returns either an owned, unambiguous UTF-8
  common name or an OpenSSL-compatible RFC 2253 full Subject for the standard
  X.509 attribute vocabulary and converts supported DirectoryString encodings;
- verified RFC 5280 certificate-revocation lists for Ed25519, P-256
  ECDSA/SHA-256, P-384 ECDSA/SHA-384, and 1024-4096-bit RSA PKCS#1
  v1.5/SHA-256 client CAs,
  including issuer and
  cRLSign checks, strict DER/extensions, update windows, authenticated
  signatures, and leaf serial lookup;
  An exact certificate or cross-signed form with the same Subject and complete
  SubjectPublicKeyInfo is recognized as a configured trust anchor without
  verifying the anchor's issuer signature. Hostname and validity remain
  mandatory for server authentication; leaves enforce optional
  digitalSignature plus endpoint-specific serverAuth/clientAuth usage, and
  presented intermediates require CA=true, optional keyCertSign, pathLen, and
  supported critical extensions;
- TLS 1.3 SHA-256 early, handshake, application, exporter, resumption, PSK
  binder, Finished, 0-RTT, and traffic-update key scheduling, including
  allocation-free caller-buffer RFC 8446 exporter output; runtime traffic-
  secret updates dispatch across SHA-256, SHA-384, and SM3 rather than assuming
  the default suite.
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
- TLS 1.3 record protection for AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305,
  and SM4-GCM, plus allocation-free QUIC Initial, Handshake, 0-RTT, 1-RTT,
  Retry integrity, traffic-secret, and key-update crypto helpers, including
  version-specific QUIC v1/v2 labels, nonce derivation, header protection, and
  suite confidentiality/integrity limits.
- Compile-time-specialized SHA-256/SHA-384 TLS 1.3 schedules, runtime
  hash-bound secrets/transcripts, 32/48-byte PSK binders, CertificateVerify,
  Finished, exporter keying material, resumption PSKs, and stateless tickets.
- Canonical TLS 1.3 cipher-suite identities and validated client/server
  preference selection, with stateless tickets bound to their issuing suite.
- QUIC transport-parameter TLS extension plumbing: ClientHello extraction,
  EncryptedExtensions emission, and opaque extension helpers so transport
  libraries can own parameter semantics while Vail owns TLS framing.
- A TLS-over-QUIC server-flight adapter that emits plaintext CRYPTO-stream
  handshake bytes by encryption level and returns Handshake/1-RTT QUIC packet
  keys, leaving packetization, retransmission, packet-number spaces, and
  congestion/recovery state to the transport.
- ShangMi coverage: SM2 signs and verifies ZA-bound raw/DER signatures against
  SEC1 public keys and SM2 X.509 SubjectPublicKeyInfo, and is wired into TLS
  CertificateVerify generation/verification for raw and X.509 SM2 keys,
  SM3 implements Zig Hash/HMAC-compatible one-shot and streaming hashing, SM4
  exposes allocation-free block and 96-bit-nonce GCM APIs, and TLS/QUIC can
  negotiate the RFC 8998 TLS_SM4_GCM_SM3 (`0x00c6`) suite with SM3
  HKDF/transcripts, PSK binders, tickets, packet protection, and SM4 header
  protection.

## Pure-Zig cryptography

Vail's cryptographic implementation is self-contained Zig and does not require
an external crypto library. SHA-256 uses Zig's standard implementation. TLS and
QUIC AES-128-GCM/AES-256-GCM keys retain a reusable pure-Zig context that caches
the expanded AES key and GHASH table, avoiding per-record key-dependent setup.
SM2, SM3, and SM4 are implemented in Vail.

On x86_64 targets with AVX2, VAES, and VPCLMULQDQ, the prepared AES-GCM path
uses two-lane AES-CTR and 16-block aggregated GHASH. Other targets retain the
portable Zig standard-library path. On an Intel Core i9-13900K pinned to CPU 0,
seven alternating ReleaseFast runs over 1,200-byte QUIC payloads produced these
median times against the former AWS-LC backend:

| Operation | Pure Zig | AWS-LC | Speedup |
| --- | ---: | ---: | ---: |
| AES-128-GCM seal | 188 ns | 237 ns | 1.26x |
| AES-128-GCM open+seal | 383 ns | 487 ns | 1.27x |
| AES-256-GCM seal | 207 ns | 275 ns | 1.33x |
| AES-256-GCM open+seal | 421 ns | 550 ns | 1.31x |

The reusable AES-GCM context is checked against NIST AES-128-GCM and
AES-256-GCM vectors, Zig's one-shot implementations across block-boundary
message lengths, authentication-failure cases, TLS record round trips, and
QUIC packet vectors.
Run `zig build -Doptimize=ReleaseFast bench-quic-traffic-crypto` for the local
QUIC traffic-protection benchmark.

ClientHello interop checks are available with `zig build interop-openssl-clienthello`
and `zig build interop-rustls-clienthello`; both feed real OpenSSL/rustls
ClientHello wire bytes into Vail's parser and verify TLS 1.3, SNI, cipher-suite,
and key-share extraction.

`zig build interop-openssl-min-server` runs the experimental minimal TLS 1.3
server harness against `openssl s_client` and verifies that OpenSSL reaches
`New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256` and sends its encrypted client
Finished after parsing Vail's ServerHello, encrypted EncryptedExtensions,
Certificate, CertificateVerify, and Finished. The Vail harness decrypts and
verifies that client Finished, sends encrypted `close_notify`, and requires
OpenSSL to observe warning `close_notify`. `zig build interop-rustls-min-server`
performs the same minimal-server check with rustls and requires both rustls
connected state and Vail-side client Finished verification.

TLS 1.3 server flights can also emit CertificateRequest and retain an
incremental negotiated-hash transcript. `tls.client_auth.verifyClientFlight`
verifies required or optional client Certificate, CertificateVerify
possession, trust policy, and Finished messages; stream/QUIC adapters remain
responsible for record reassembly and alert policy.

For the client role, `tls.client_hello.write` emits a stream-oriented TLS 1.3
ClientHello without QUIC-only extensions, while
`tls.client_handshake.verifyServerAndWriteClientFlight` verifies the server
chain, CertificateVerify and Finished and builds an optional client-certificate
response. Its result deep-owns the authenticated server certificate chain so a
downstream transport can preserve peer identity after releasing its encrypted
handshake buffer. The same result retains the authenticated negotiated cipher
suite, allowing a transport to expose both its AEAD choice and transcript hash
without reparsing released ServerHello bytes. Socket ownership and encrypted-
record reassembly remain downstream transport concerns.

Transport integration belongs in downstream libraries such as `netz`; reusable
cryptography and TLS state belong here.

Consumers that only need ShangMi primitives can import the lightweight
`vail_sm` build module. It exposes `sm2` and `sm3` without pulling the TLS graph
into the consumer.
