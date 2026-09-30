# vail

`vail` is a Zig 0.16 cryptographic protocol library. Its target is to provide
a pure-Zig TLS/X.509 stack whose safety, protocol coverage, modularity, and
performance exceed mature stacks such as s2n-tls and rustls.

The current foundation provides:

- domain-separated HMAC-SHA256 and constant-time tag verification;
- fixed-size SHA-256 and SM3 digests, portable SM2 signing/verification,
  SM4 block/SM4-GCM primitives, and explicit secure-memory wiping;
- allocation-free RFC 9180 HPKE base mode with the ECH mandatory suite:
  DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM. Sender and
  receiver contexts retain prepared AEAD state, implement the complete 96-bit
  nonce sequence space, reject weak X25519 inputs and authentication failures,
  expose RFC exporters, and explicitly wipe ephemeral and derived secrets;
- RFC 9849 ECH client and server handshakes with strict ECHConfigList
  selection, public-name and mandatory-extension validation,
  ClientHelloInner padding, linear-time `ech_outer_extensions`
  reconstruction, authenticated ClientHelloOuter encryption/decryption,
  retained HPKE state and acceptance confirmation across HRR, authenticated
  rejection fallback to the ClientHelloOuter transcript and public name,
  owned retry-config reporting plus an encrypted `ech_required` alert,
  private-SNI identity selection, SHA-256/SHA-384/SM3 confirmation derivation,
  and PSK-DHE/0-RTT resumption with real binders confined to ClientHelloInner and
  independently randomized, length-matched GREASE PSKs in ClientHelloOuter;
- TLS 1.3 ClientHello parsing, encrypted server-handshake flight construction,
  ServerHello/EncryptedExtensions, Certificate, CertificateVerify, Finished, and
  AEAD record-protection codecs;
- deployed draft ALPS (`application_settings`) with both AWS-LC codepoints,
  ALPN-bound protocol offers, mutually authenticated opaque settings, the
  transcript-required client EncryptedExtensions message, ECH privacy, and
  ALPN-bound client/server settings persisted in authenticated session caches
  and bounded stateless tickets so 0-RTT is enabled only on exact matches;
- incremental TLS 1.3 client/server stream states with record and handshake
  reassembly, internally owned classical/hybrid key exchange, authenticated
  transition to application traffic, HelloRetryRequest with RFC 8446
  `message_hash` transcripts and cookies, automatic sequence numbers and AEAD
  usage limits, RFC 8449 TLS 1.2/1.3 bidirectional record-size negotiation
  with bounded handshake/application fragmentation and pre-decryption enforcement,
  KeyUpdate generations, and bidirectional `close_notify`;
- unified incremental client and server frontends that emit/consume one
  ClientHello, prefer TLS 1.3 when both peers support it, otherwise select TLS
  1.2 without reconstructing transcript bytes, and wipe the unused version's
  one-shot key material;
- Ed25519, ECDSA P-256, ECDSA P-384, and SM2/SM3 verifier
  implementations, plus opt-in FIPS 204 ML-DSA-44/65/87 for TLS 1.3 Raw
  Public Keys, RSA-PSS/RSAE, TLS 1.2 RSA PKCS#1 v1.5 SHA-256/384/512
  signatures, and DER RSAPublicKey pin verification. A built-in pure-Zig RSA
  signer accepts strict PKCS#1 or unencrypted PKCS#8 keys, including RFC 4055
  constrained `id-RSASSA-PSS` keys, retains their hash/MGF/minimum-salt
  restrictions, prohibits PKCS#1 v1.5 use of PSS-only keys, uses fresh
  per-signature PSS salt, and performs CRT private operations through Zig
  std's constant-time finite-field implementation. TLS P-256 verification uses the curve's public
  double-scalar primitive for the ECDSA verification equation, with
  deterministic equivalence and malformed-scalar tests against Zig's generic
  verifier;
- type-safe server identities, allocation-free custom signer callbacks, and
  pinned-key client verification; the server can select identities by exact or
  one-label wildcard SNI, client signature-scheme compatibility, and TLS 1.3
  `certificate_authorities` DER DistinguishedName hints, while keeping
  per-identity OCSP and precompressed Certificate variants together;
- TLS 1.3 RFC 7250 Raw Public Key authentication in both directions, including
  strict ClientHello/EncryptedExtensions certificate-type negotiation, exact
  DER SubjectPublicKeyInfo pins, single-key Certificate messages, RPK mTLS,
  HelloRetryRequest consistency, and RSA, Ed25519, P-256, P-384, and SM2 SPKI
  decoding without an external PKI or crypto library;
- CertificateRequest codec and mTLS policy types;
- RFC 8879 TLS 1.3 certificate compression in both directions using Zig std's
  zlib implementation and Vort's pure-Zig Brotli and Zstandard codecs, with
  reusable server/client precompression, transcript-correct
  CompressedCertificate processing, exact decompressed lengths, checksum
  verification, and configurable decompression limits. The default offer keeps
  zlib first for preparation speed, followed by Brotli and Zstandard;
- X.509 bounded path construction over unordered intermediates, alternate
  issuers and cross-signs, with hostname, validity, custom-bundle, and
  system-CA verification. Strict Authority Key Identifier and Subject Key
  Identifier decoding prioritizes exact same-subject issuer matches before
  missing or explicitly mismatched identifiers, while retaining signature-
  verified fallback compatibility for non-conforming chains. SHA-2
  RSASSA-PSS-signed leaves and intermediate CAs
  use a strict pure-Zig compatibility parser when Zig std does not recognize
  their signature AlgorithmIdentifier. RFC 4055 PSS SubjectPublicKeyInfo
  restrictions are enforced for certificate, CRL, OCSP, and TLS
  CertificateVerify signatures; explicit depth/candidate/certificate
  budgets prevent attacker-controlled path explosion, DNS and IPv4/IPv6 Name
  Constraints intersect across the chosen server path, and literal IP server
  identities match only exact iPAddress SAN values rather than falling back to
  CN/dNSName;
  plus a client-certificate bundle verifier that omits hostname matching and
  enforces the clientAuth endpoint purpose for mTLS server policy.
  Strict subject identity extraction returns either an owned, unambiguous UTF-8
  common name or an OpenSSL-compatible RFC 2253 full Subject for the standard
  X.509 attribute vocabulary and converts supported DirectoryString encodings;
- verified RFC 5280 certificate-revocation lists for Ed25519, P-256
  ECDSA/SHA-256, P-384 ECDSA/SHA-384, and 1024-4096-bit RSA PKCS#1 v1.5 or
  RSA-PSS with SHA-256/384/512 client CAs; PSS AlgorithmIdentifiers enforce
  matching MGF1 hashes, digest-length salts, and the default trailer field,
  including issuer and
  cRLSign checks, strict DER/extensions, update windows, authenticated
  signatures, and leaf serial lookup. Authenticated CRL sets plug directly into
  server/client trust policy with fail-open-if-absent or require-status modes
  and are bound to both issuer Subject and public key;
- strict RFC 6960 BasicOCSPResponse verification for issuer-signed responses
  and directly issued delegated responders with mandatory OCSPSigning EKU,
  including CertID binding, responder identity, responder certificate
  validity/KeyUsage, SHA-1/SHA-256 issuer hashes, ECDSA/Ed25519 signatures,
  and RSA PKCS#1 v1.5 or RSA-PSS signatures with SHA-256/384/512,
  bounded embedded certificates, response time windows, and
  good/revoked/unknown handling, RFC 8954 response nonce matching, bounded
  extension parsing, non-critical extension tolerance, and fail-closed unknown
  critical extensions. TLS 1.2 and TLS 1.3 clients can request
  stapling, servers attach the configured response only when requested, and
  bundle trust policy supports ignore/if-present/require modes. TLS 1.2 binds
  the RFC 6066 CertificateStatus message into the Finished transcript and
  rejects unsolicited, missing, duplicated, or malformed status messages.
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
- Opt-in, allocation-free NSS key-log callbacks cover TLS 1.3 early,
  handshake, generation-zero application and exporter secrets plus the TLS 1.2
  `CLIENT_RANDOM` master secret. A caller-owned writer helper emits exact
  `SSLKEYLOGFILE` lines without giving the library implicit filesystem access.
- X25519 plus constant-time secp256r1 and secp384r1 ECDH key exchange, with
  uncompressed SEC1 validation and incremental SHA-256/SHA-384 transcript
  hashing.
- Standards-aligned X25519MLKEM768 hybrid post-quantum key exchange with the
  registered `0x11ec` ML-KEM-first TLS share layout, compact seeded client
  state, explicit secret wiping, and full 64-byte hybrid HKDF input.
- Explicit pure ML-KEM-768 key exchange with registered TLS group `0x0201`,
  compact seeded client state, implicit ciphertext rejection, and direct
  32-byte KEM output into the TLS 1.3 key schedule.
- Explicit pure ML-KEM-1024 key exchange with registered TLS group `0x0202`
  and the same bounded, seed-backed state and implicit-rejection semantics.
- Registered classical-first secp256r1MLKEM768 (`0x11eb`) and
  secp384r1MLKEM1024 (`0x11ed`) TLS groups, including exact SEC1/ML-KEM wire
  layouts, 64/80-byte hybrid HKDF inputs, and shared generic secret handling.
- TLS 1.3 PSK-DHE resumption integrated into client/server states, including
  constant-time SHA-256/SHA-384/SM3 binders, HRR binder transcripts,
  ServerHello identity selection, ticket-age validation, and stateless tickets
  bound to their issuing suite, server identity, and ALPN. Authenticated
  NewSessionTicket messages can be converted directly into owned client cache
  entries. RFC 9149 ticket requests distinguish new and resumed handshakes,
  advertise the server's bounded expected count, and expose a decrementing
  issuance budget. Stream 0-RTT installs separate early traffic keys, enforces the
  authenticated ticket byte limit, fails closed without an anti-replay guard,
  handles accepted/rejected early records, emits EndOfEarlyData, and disables
  early data after HelloRetryRequest.
- Allocation-free AES-256-GCM stateless session tickets with origin/ALPN
  associated-data binding and bounded current/history key rotation.
- TLS 1.3 record protection for AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305,
  and SM4-GCM, plus allocation-free QUIC Initial, Handshake, 0-RTT, 1-RTT,
  Retry integrity, traffic-secret, and key-update crypto helpers, including
  version-specific QUIC v1/v2 labels, nonce derivation, header protection, and
  suite confidentiality/integrity limits.
- Established TLS 1.3 and TLS 1.2 connections expose allocation-free,
  configurable application-record fragmentation with explicit plaintext
  consumed/output written progress. Each call seals exactly one record, so
  output failures remain retryable without hidden buffering or nonce reuse.
- Established TLS 1.3 and TLS 1.2 record layers can be consumed into owned
  transmit/receive AEAD keys, 12-byte nonce bases, current sequence numbers,
  and TLS 1.3 key generations for kTLS or user-space offload. Successful
  extraction permanently disables Vail record I/O and the returned material
  has an explicit wiping `deinit`.
- TLS 1.2 cryptographic foundations for ECDHE-ECDSA/ECDHE-RSA AES-GCM and
  ChaCha20-Poly1305 suites: SHA-256/SHA-384 PRFs, ordinary and RFC 7627
  extended master secrets, Finished values, key-block separation, explicit
  AES-GCM and XOR ChaCha nonces, authenticated record headers, automatic
  sequence numbers, conservative AEAD usage limits, and allocation-free RFC
  5705 exporters. Incremental client and server states negotiate all six modern
  ECDHE-RSA/ECDHE-ECDSA AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 suites
  over P-256 or P-384, require Extended Master Secret and RFC 5746 signaling,
  authenticate ephemeral parameters with RSA-PSS or ECDSA using TLS 1.2's
  hash-only signature-scheme semantics; RSA PKCS#1 v1.5 remains available for
  compatible TLS 1.2 peers while being rejected in TLS 1.3. The states verify
  both Finished messages, retain
  authenticated peer identity/ALPN on the client, and transition to
  bidirectional application records. Handshake-time TLS 1.2 client
  authentication supports required or optional certificates, authenticates
  the client chain through the configured trust policy, verifies
  CertificateVerify possession, and transfers an owned peer chain into the
  established server state. Stateful TLS 1.2 session-ID resumption uses the
  abbreviated ServerHello/CCS/Finished exchange and binds cached master
  secrets to their suite, server identity, ALPN, and expiration time. RFC 5077
  stateless session tickets are supported in both client and server roles,
  including ticket renewal, invalid-ticket fallback, bounded lifetime and key
  rotation, and AES-256-GCM sealing bound to the server identity and ALPN;
- Compile-time-specialized SHA-256/SHA-384 TLS 1.3 schedules, runtime
  hash-bound secrets/transcripts, 32/48-byte PSK binders, CertificateVerify,
  Finished, exporter keying material, resumption PSKs, and stateless tickets.
- Canonical TLS 1.3 cipher-suite identities and validated client/server
  preference selection, with stateless tickets bound to their issuing suite.
- QUIC transport-parameter TLS extension plumbing: ClientHello extraction,
  EncryptedExtensions emission, and opaque extension helpers so transport
  libraries can own parameter semantics while Vail owns TLS framing.
- TLS-over-QUIC full and PSK-DHE handshake adapters for both endpoints. The server
  emits plaintext CRYPTO-stream flights by encryption level; the client
  authenticates the server flight, returns owned ALPN/transport parameters,
  emits its plaintext Finished flight, and derives matching Handshake/1-RTT
  packet keys. Resumption authenticates the one-identity PSK binder and can
  fall back to a full certificate handshake. QUIC 0-RTT derives matching
  client early packet keys, requires explicit server acceptance, and returns
  the ticket byte limit for transport enforcement without emitting TLS's
  stream-only EndOfEarlyData message. Validated HelloRetryRequest state
  preserves the synthetic `message_hash` transcript, verifies the second
  binder, disables 0-RTT, and enforces ClientHello2 consistency on both
  endpoints. Accepted ECH uses the reconstructed ClientHelloInner transcript
  and authenticates both ordinary and HRR acceptance confirmations, including
  combinations with PSK and rejected 0-RTT. Rejected ECH switches to the Outer
  transcript, authenticates the public name before returning owned retry
  configs, and reports the RFC 9001 `CRYPTO_ERROR` code for `ech_required`
  without exposing application keys. The server can request and authenticate
  mTLS and verifies the client's Finished before returning an owned peer chain.
  Both sides require QUIC transport parameters and a common ALPN, while
  packetization, retransmission, packet-number spaces, and congestion/recovery
  remain transport responsibilities. QUIC certificate flights use the same
  reusable RFC 8879 zlib/Brotli/Zstandard preparations as stream TLS, including
  Vort's pure-Zig Brotli and Zstandard encoders.
- ShangMi coverage: SM2 signs and verifies ZA-bound raw/DER signatures against
  SEC1 public keys and SM2 X.509 SubjectPublicKeyInfo, and is wired into TLS
  CertificateVerify generation/verification for raw and X.509 SM2 keys,
  SM3 implements Zig Hash/HMAC-compatible one-shot and streaming hashing, SM4
  exposes allocation-free block and 96-bit-nonce GCM APIs, and TLS/QUIC can
  negotiate the RFC 8998 TLS_SM4_GCM_SM3 (`0x00c6`) suite with SM3
  HKDF/transcripts, PSK binders, tickets, packet protection, and SM4 header
  protection.

## Pure-Zig cryptography

Vail's cryptographic implementation is entirely Zig and does not require a C,
C++, or Rust crypto library. SHA-256 uses Zig's standard implementation, while
RFC 8879 Brotli uses the sibling pure-Zig Vort package. TLS and
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

ChaCha20-Poly1305 uses a prepared pure-Zig core on x86_64 AVX2 and aarch64
NEON targets. It emits eight ChaCha blocks together on AVX2 and four on NEON,
derives the Poly1305 one-time key in the first wide batch, and authenticates
four 16-byte blocks at once with 26-bit limbs. The Poly1305 front end
transposes four input blocks directly with Zig vectors and combines short
padded TLS/QUIC headers with ciphertext whenever that removes serial tail
multiplications; other targets retain Zig std. On the same 1,200-byte QUIC
workload pinned to one CPU, seven alternating
independent-binary runs gave:

| Operation | Zig std | Prepared Zig | Speedup |
| --- | ---: | ---: | ---: |
| ChaCha20-Poly1305 seal | 1,918 ns | 782 ns | 2.45x |
| ChaCha20-Poly1305 open+seal | 3,866 ns | 1,656 ns | 2.33x |

The independent test-only AWS-LC binary currently measures 638 ns and
1,278 ns respectively, so ChaCha remains a known optimization target rather
than a claimed performance win over AWS-LC. AES-GCM medians and the 736-byte
prepared-key footprint remain unchanged by the ChaCha path.

The reusable AES-GCM context is checked against NIST AES-128-GCM and
AES-256-GCM vectors, Zig's one-shot implementations across block-boundary
message lengths, authentication-failure cases, TLS record round trips, and
QUIC packet vectors.
Run `zig build -Doptimize=ReleaseFast bench-quic-traffic-crypto` for the local
QUIC traffic-protection benchmark, or
`zig build -Doptimize=ReleaseFast bench-tls-record-crypto` for the stateful TLS
record benchmark with automatic nonce sequencing and AEAD usage limits.
`bench-chacha-components` separates stream, Poly1305, and complete AEAD costs
across payload sizes; `bench-aws-lc-aead` runs the test-only AWS-LC comparison.
`zig build -Doptimize=ReleaseFast bench-tls-server-handshake` measures managed
X25519/Ed25519 TLS 1.3 server flights, including key exchange, signing, and
record protection.
`zig build -Doptimize=ReleaseFast bench-tls-server-connection` includes the
high-level incremental server state, ClientHello framing, and default-disabled
diagnostic hooks in the same first-flight benchmark.
`zig build -Doptimize=ReleaseFast bench-x509-path` measures bounded unordered
AKI/SKI-routed and cross-signed certificate-path construction plus
issuer/delegated OCSP.
`zig build -Doptimize=ReleaseFast bench-certificate-compression` compares the
RFC 8879 zlib, Brotli, and Zstandard wire-size ratios, amortized preparation
costs, and per-handshake decompression costs.
`zig build -Doptimize=ReleaseFast interop-rustls-brotli-server` verifies Vort
Brotli output with a rustls decoder; `interop-rustls-min-client` verifies the
Vort decoder against rustls's independent Brotli encoder.
`interop-rustls-zstd-server` and `interop-rustls-zstd-client` perform the same
two directions for RFC 8879 Zstandard using rustls's public custom compression
interfaces and libzstd only as the independent test oracle.
`zig build interop-rustls-keylog-server` compares all five TLS 1.3 NSS key-log
lines byte-for-byte between a Vail server and rustls/AWS-LC client;
`interop-rustls-tls12-keylog-server` performs the corresponding TLS 1.2
`CLIENT_RANDOM` comparison.
`zig build interop-rustls-traffic-secrets-server` consumes both established
record layers and compares their transmit/receive AES-GCM key, IV, and current
sequence values byte-for-byte.
`zig build -Doptimize=ReleaseFast bench-rsa-pss` measures the built-in
constant-time RSA-2048 PSS and PKCS#1 v1.5 signing paths.
`zig build -Doptimize=ReleaseFast bench-hpke` measures RFC 9180 sender/receiver
setup plus stateful AES-128-GCM sealing and opening for ECH-sized payloads.
`zig build -Doptimize=ReleaseFast bench-ech` measures complete RFC 9849
ClientHelloInner encoding, HPKE protection, and server reconstruction.
`zig build -Doptimize=ReleaseFast interop-rustls-ech-server` exercises an
accepted ECH handshake from a rustls/AWS-LC client to the Vail server;
`interop-rustls-ech-hrr-server` repeats it across HelloRetryRequest.
When a Vail client receives no valid ECH acceptance confirmation, it switches
to the outer transcript, authenticates the ECH public name and server Finished,
then returns an owning `ech_rejected` event with any authenticated
`retry_configs`; callers must call `deinit()` on that event value. The client
also emits the RFC 9849 fatal `ech_required` alert and never exposes an
application connection for the rejected attempt.
`zig build -Doptimize=ReleaseFast bench-tls12-record-crypto` measures the
TLS 1.2 AES-GCM and ChaCha20-Poly1305 record paths.
`zig build -Doptimize=ReleaseFast bench-tls12-server-handshake` measures the
TLS 1.2 P-256/RSA-2048-PSS authenticated server flight.
`zig build -Doptimize=ReleaseFast bench-tls12-client-handshake` measures TLS
1.2 ClientHello generation, RSA-PSS ServerKeyExchange verification, P-256
ECDHE, EMS derivation, and the encrypted client flight.

ClientHello interop checks are available with `zig build interop-openssl-clienthello`
and `zig build interop-rustls-clienthello`; both feed real OpenSSL/rustls
ClientHello wire bytes into Vail's parser and verify TLS 1.3, SNI, cipher-suite,
key-share, and OCSP `status_request` extraction.

`zig build interop-openssl-min-server` runs the experimental minimal TLS 1.3
server harness against `openssl s_client` and verifies that OpenSSL reaches
`New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256` and sends its encrypted client
Finished after parsing Vail's ServerHello, encrypted EncryptedExtensions,
Certificate, CertificateVerify, and Finished. The Vail harness decrypts and
verifies that client Finished, sends encrypted `close_notify`, and requires
OpenSSL to observe warning `close_notify`. `zig build interop-rustls-min-server`
performs the same minimal-server check with a zlib-enabled rustls client,
requires RFC 8879 certificate compression to be negotiated, and checks both
rustls connected state and Vail-side client Finished verification.
`zig build interop-rustls-tls13-resumption-server` keeps one rustls/AWS-LC
client session cache across two connections to Vail, processes Vail's
encrypted NewSessionTicket, and requires the second connection to complete as
an authenticated PSK-DHE resumed handshake. It also sends application data
before ServerHello and requires Vail's bounded anti-replay path to accept it.
`interop-rustls-tls13-resumption-client` covers the reverse direction: Vail
caches a rustls/AWS-LC ticket, emits the second ClientHello and binder, and
requires both peers to report a resumed handshake.
`interop-rustls-ticket-request-server` and
`interop-rustls-ticket-request-client` exercise RFC 9149 request and response
hints in both directions against rustls.
`interop-aws-lc-alps-client` and `interop-aws-lc-alps-new-client` exchange both
client and server ALPS settings against an independent test-only AWS-LC TLS
endpoint using the deployed old and new codepoints respectively.
`zig build interop-openssl-min-client` exercises the reverse direction: Vail's
incremental client state authenticates an OpenSSL server and its Finished,
sends its encrypted Finished, and verifies encrypted application data. The
server and client interop paths deliberately force a P-256
HelloRetryRequest, covering both directions of the retry state machine.
`zig build interop-rustls-min-client` exercises Vail's client against a
zlib-enabled rustls server and requires Vail to authenticate a compressed
Certificate message before exchanging application data.
`zig build interop-rustls-rpk-server` and
`zig build interop-rustls-rpk-client` exercise mutual TLS 1.3 RFC 7250 Raw
Public Key authentication in both directions against rustls 0.23 with its
AWS-LC provider. Both peers send a single DER SubjectPublicKeyInfo, verify
RSA-PSS CertificateVerify possession, pin the peer SPKI exactly, and exchange
encrypted application data.
`interop-rustls-mldsa-rpk-server` and
`interop-rustls-mldsa-rpk-client` repeat mutual RPK authentication with
ML-DSA-44, using identical deterministic FIPS 204 seeds to cross-check Zig
std's public keys and signatures against AWS-LC.
`zig build interop-rustls-quic-client` drives a rustls/AWS-LC QUIC client
against Vail's server adapter, while `interop-rustls-quic-server` exercises the
reverse direction. Both checks exchange raw CRYPTO-stream handshake bytes,
perform real X25519 key exchange, authenticate RSA-PSS CertificateVerify and
both Finished messages, and require matching `h3` ALPN and opaque transport
parameters without linking Rust code into Vail.
`interop-rustls-quic-hybrid-client` and
`interop-rustls-quic-hybrid-server` repeat both directions with registered
X25519MLKEM768 (`0x11ec`), proving that Zig std's ML-KEM implementation and
AWS-LC agree on the complete hybrid wire shares and derived handshake secrets.
The corresponding `interop-rustls-quic-mlkem-client` and
`interop-rustls-quic-mlkem-server` checks cover the explicit pure ML-KEM-768
group (`0x0201`) in both directions.
`interop-rustls-quic-mlkem1024-client` and
`interop-rustls-quic-mlkem1024-server` cover pure ML-KEM-1024 (`0x0202`).
`zig build interop-openssl-tls12-server` and
`zig build interop-rustls-tls12-server` exercise Vail's incremental TLS 1.2
server, requiring ECDHE-RSA-AES128-GCM-SHA256, Extended Master Secret,
RSA-PSS-authenticated ephemeral P-256 parameters, verified client/server
Finished messages, and bidirectional application data.
`zig build interop-openssl-tls12-client` and
`zig build interop-rustls-tls12-client` exercise the reverse direction and
require the Vail client to authenticate the server's certificate-bound
ServerKeyExchange, verify the server Finished, negotiate `http/1.1`, and
exchange application data. Rust interoperability fixtures use rustls 0.23's
AWS-LC provider and remain test-only dependencies; Vail itself links no
external cryptographic library.
`zig build interop-openssl-tls12-client-matrix` additionally forces all six
TLS 1.2 AEAD suites, both RSA and ECDSA authentication, and P-256/P-384 ECDHE.
`interop-openssl-tls12-rsa-pkcs1-client`,
`interop-openssl-tls12-rsa-pkcs1-server`,
`interop-rustls-tls12-rsa-pkcs1-client`, and
`interop-rustls-tls12-rsa-pkcs1-server` force RSA PKCS#1 v1.5 SHA-256
handshake signatures in both directions instead of accepting a PSS fallback.
`interop-rustls-tls12-ocsp-client` and
`interop-rustls-tls12-ocsp-server` require an exact stapled response to cross
the Vail/rustls trust callbacks in both directions.
`zig build interop-openssl-tls12-mtls-client` and
`zig build interop-openssl-tls12-mtls-server` cover CertificateRequest,
client Certificate/CertificateVerify possession, mandatory-certificate policy,
and application data in both mTLS directions.
`zig build interop-openssl-tls12-resumption-client` and
`zig build interop-openssl-tls12-resumption-server` run a full connection and
a second abbreviated session-ID connection in each direction, verify the
resumed Finished transcript, and exchange application data under fresh record
keys.
The equivalent `interop-rustls-tls12-resumption-client` and
`interop-rustls-tls12-resumption-server` steps require rustls with AWS-LC to
report the second connection as `Resumed`.
`interop-openssl-tls12-ticket-client`,
`interop-openssl-tls12-ticket-server`,
`interop-rustls-tls12-ticket-client`, and
`interop-rustls-tls12-ticket-server` repeat the two-connection check with RFC
5077 stateless tickets and disable or omit server-side session-ID storage so a
false-positive cache hit cannot satisfy the gate.
Applications enable client-side RFC 5077 discovery with
`tls12_client_connection.Config.request_session_ticket`, turn an authenticated
ticket-bearing connection into owned cache state with
`Established.createTicketSession`, and offer that state through
`Config.ticket_resumption`. Servers configure a rotating
`ticket_keyring.Keyring` through
`tls12_server_connection.Config.session_tickets`. The unified client forwards
the same ticket in its shared TLS 1.2/TLS 1.3 ClientHello.
`interop-openssl-versioned-server-tls13`,
`interop-openssl-versioned-server-tls12`,
`interop-openssl-versioned-client-tls13`, and
`interop-openssl-versioned-client-tls12` exercise the unified version-selecting
entry points against real peers.

TLS 1.3 server flights can also emit CertificateRequest and retain an
incremental negotiated-hash transcript. `tls.client_auth.verifyClientFlight`
verifies required or optional client Certificate, CertificateVerify
possession, trust policy, and Finished messages. `tls.server_connection`
integrates both required authenticated mTLS and optional anonymous client
flights, enforces message ordering across arbitrary record fragmentation, and
transfers an owned authenticated client chain into established state. Lower-
level transports may still use the codecs directly.

For the client role, `tls.client_hello.write` emits a stream-oriented TLS 1.3
ClientHello without QUIC-only extensions, while
`tls.client_handshake.verifyServerAndWriteClientFlight` verifies the server
chain, CertificateVerify and Finished and builds an optional client-certificate
response. Its result deep-owns the authenticated server certificate chain so a
downstream transport can preserve peer identity after releasing its encrypted
handshake buffer. The same result retains the authenticated negotiated cipher
suite, allowing a transport to expose both its AEAD choice and transcript hash
without reparsing released ServerHello bytes. `tls.client_connection` composes
that verifier with incremental record processing; socket ownership remains a
downstream transport concern.

Transport integration belongs in downstream libraries such as `netz`; reusable
cryptography and TLS state belong here.

Consumers that only need ShangMi primitives can import the lightweight
`vail_sm` build module. It exposes `sm2` and `sm3` without pulling the TLS graph
into the consumer.
