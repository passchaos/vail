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
  per-signature PSS salt, and performs constant-time CRT private operations
  through dedicated pure-Zig fixed-width arithmetic with an embedded x86_64
  assembly specialization. TLS P-256 verification uses the curve's public
  double-scalar primitive for the ECDSA verification equation, with
  deterministic equivalence and malformed-scalar tests against Zig's generic
  verifier;
- type-safe server identities, allocation-free custom signer callbacks, and
  pinned-key client verification; the server can select identities by exact or
  one-label wildcard SNI, client signature-scheme compatibility, and TLS 1.3
  `certificate_authorities` DER DistinguishedName hints. TLS 1.3
  `signature_algorithms_cert` is encoded and strictly parsed in ClientHello
  and CertificateRequest, preserved across HRR/ECH, and enforced independently
  from CertificateVerify when selecting or authenticating X.509 chains, while
  keeping per-identity OCSP and precompressed Certificate variants together;
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
  Identifier decoding prioritizes exact same-subject issuer matches by either
  key identifier or the authority-certificate issuer/serial pair before
  missing or explicitly mismatched identifiers, while retaining signature-
  verified fallback compatibility for non-conforming chains. SHA-2
  RSASSA-PSS-signed leaves and intermediate CAs
  use a strict pure-Zig compatibility parser when Zig std does not recognize
  their signature AlgorithmIdentifier. RFC 4055 PSS SubjectPublicKeyInfo
  restrictions are enforced for certificate, CRL, OCSP, and TLS
  CertificateVerify signatures; explicit depth/candidate/certificate
  budgets prevent attacker-controlled path explosion. DNS, IPv4/IPv6,
  rfc822Name, URI, and directoryName constraints intersect across the chosen
  server- or client-auth path and cover every subordinate certificate except
  non-final self-issued rollover certificates. Email constraints support exact
  mailbox, exact host, and leading-dot domain forms, including subject
  `emailAddress` fallback when no SAN is present. URI constraints operate only
  on a validated authority DNS host and reject relative, hostless, or IP-host
  URIs as required by RFC 5280. Directory-name constraints cover both the
  subject DN and directoryName SAN values, compare RDN subtrees and multi-valued
  RDNs structurally, and use allocation-free Unicode 3.2 RFC 4518
  caseIgnoreMatch preparation for UTF8String, PrintableString, BMPString, and
  UniversalString attributes. Literal IP server identities match only exact
  iPAddress SAN values rather than falling back to CN/dNSName. A bounded,
  allocation-free RFC 5280/RFC 9618 certificate-policy graph processes
  `certificatePolicies`, `policyMappings`, `policyConstraints`, and
  `inhibitAnyPolicy`, including anyPolicy/self-issued exceptions, explicit
  policy requirements, caller-selected initial policy sets, CPS/user-notice
  qualifiers, and policy-aware path backtracking. Issuer discovery,
  authorityCertIssuer routing, self-issued detection, and trust-anchor matching
  use the same RFC 4518 DN equality with a raw-DER fast path, so equivalent
  UTF8String/PrintableString names link without weakening the SPKI/signature
  checks. In addition to Zig std's indexed system bundle, every bundle verifier
  accepts a bounded borrowed `compatible_trust_anchors` slice. These anchors
  use Vail's compatibility parser, allowing SHA3- and RSA-PSS-signed roots that
  Zig std cannot index to participate directly in exact and equivalent-name
  issuer backtracking. `SystemStore` can own these anchors from individual DER
  certificates or multi-certificate PEM buffers, deduplicates them, filters
  expired inputs, and rolls back an entire PEM import on any malformed block;
  bounded relative/absolute file loaders are also available. An
  `only_std_unsupported` mode scans a PEM already given to Zig std and retains
  only certificates that require Vail's parser, avoiding duplicate linear
  searches. Its verifier attaches the resulting slices without
  per-verification allocation. CRL issuer binding, authenticated CRL-set routing, delegated OCSP
  issuer authorization, and OCSP responder-byName matching reuse that same
  comparison instead of requiring byte-identical Name encodings. Delegated
  responder selection continues past an identity match that lacks OCSPSigning
  authorization and can select an equivalent-name certificate with the same
  response-signing key;
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
  signatures, and leaf serial lookup. OCSP CertID issuer bindings accept
  SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256
  plus SHA3-224/256/384/512, with exact digest-length enforcement.
  A strict allocation-free RFC 5280 Authority Information Access iterator
  exposes every ordered `id-ad-ocsp` or `id-ad-caIssuers` absolute IA5 URI,
  with a first-responder convenience API, and rejects malformed, duplicate,
  or critical AIA extensions before yielding any result. Strict zero-copy
  caIssuers response parsing accepts either one DER Certificate or a
  definite-length DER CMS SignedData certs-only object, validates its empty
  digest/signer sets and absent content, accepts only X.509 CertificateChoices,
  and deduplicates a bounded certificate set. A separate `parseBer` entry point
  accepts indefinite-length constructed CMS wrappers with depth and element
  budgets while keeping embedded certificates strict DER; issuer fetching
  requires explicit `allow_ber_certs_only` opt-in. An allocation-free
  resolver recursively follows unique caIssuers URIs under caller-selected
  fetch/response/certificate budgets, copies results only into caller-owned
  buffers, and delegates scheme, redirect, transport, and network-access
  policy to the fetch callback. `BundleVerifier.verifyWithFetchedIssuers`
  feeds those certificates into the existing bounded unordered path search
  while preserving per-presented-certificate OCSP alignment.
  An allocation-free caller-buffer encoder creates single-certificate or
  bounded 16-certificate RFC 6960 requests with any supported CertID hash and
  optional RFC 8954 nonce; both single and batched DER output are checked
  byte-for-byte against OpenSSL-generated requests. A matching transactional
  batch verifier authenticates one BasicOCSPResponse signature once and returns
  all requested statuses only after every CertID is present exactly once. For
  two RSA certificates, this reduces verification from roughly 0.94-0.95 ms
  with two independent calls to 0.70-0.72 ms in the ReleaseFast path benchmark.
  Authenticated CRL sets plug directly into server/client trust policy with
  fail-open-if-absent or require-status modes and are bound to both issuer
  Subject and public key. RFC 5280 base and delta CRLs are combined only after
  issuer, signing key, AKI, issuing-distribution-point scope, and CRL-number
  ordering agree; delta entries override the base, including `removeFromCRL`.
  Indirect CRLs require the critical indirectCRL marker, an explicit matching
  cRLIssuer distribution point in the target certificate, and either the
  selected certificate issuer itself or a directly signed cRLSign delegate.
  Per-entry certificateIssuer state is inherited exactly as specified, while
  partial-reason lists can prove revocation immediately and complementary
  CRLs aggregate their DP/IDP reason masks before producing `good`;
  indirect base/delta pairs use the same scope and override rules, and CRL
  signer chains of arbitrary configured depth are validated either against the
  selected certificate issuer or, together with the issuer's own chain,
  against the same explicit trust anchor through the ordinary bounded X.509
  path engine. A `freshestCRL` advertisement automatically selects the newest
  compatible caller-supplied delta by `thisUpdate` and CRL number. CRL signer
  and certificate-issuer paths can use separate, explicitly supplied
  revocation policies, avoiding self-referential CRL validation. Full and
  relative distribution-point names are parsed structurally; relative RDNs
  can be compared in their CRL-issuer context without constructing temporary
  DER names. Allocation-free iterators expose ordered, deduplicated absolute
  CRLDP and Freshest CRL URIs. A bounded callback API fetches into caller-owned
  buffers, rejects incompatible or invalid responses, and retains the newest
  current delta without coupling the library to an HTTP implementation. A
  caller-owned conditional cache carries URI-scoped ETag and Last-Modified
  validators, revalidates cached DER and time windows after `not modified`,
  atomically replaces only authenticated compatible deltas, and applies
  bounded exponential retry backoff without discarding the last valid entry;
- strict RFC 6960 BasicOCSPResponse verification for issuer-signed responses
  and directly issued delegated responders with mandatory OCSPSigning EKU,
  including CertID binding, responder identity, responder certificate
  validity/KeyUsage, SHA-1/SHA-256 issuer hashes, ECDSA/Ed25519 signatures,
  and RSA PKCS#1 v1.5 or RSA-PSS signatures with SHA-256/384/512. Shared
  X.509-family ECDSA verification selects P-256 or P-384 from the issuer key
  independently of the RFC 5758 SHA-224/SHA-256/SHA-384/SHA-512 signature OID,
  covering valid cross-curve/hash CRL and OCSP signatures. RFC 4055 RSA-PSS
  and PKCS#1 v1.5 verification and signing additionally cover SHA-224 with a
  digest-length PSS salt. RFC 8017 SHA-512/224 and SHA-512/256 are available
  for RSA-PSS and PKCS#1 v1.5 signing and X.509-family verification. The OCSP
  verifier also supports bounded embedded certificates, response time windows,
  and good/revoked/unknown handling, RFC 8954 response nonce matching, bounded
  extension parsing, non-critical extension tolerance, and fail-closed unknown
  critical extensions. High-level TLS 1.2 and TLS 1.3 clients request stapling
  by default with an explicit opt-out; TLS 1.2 additionally advertises RFC 6961
  `status_request_v2` multi-stapling while retaining the legacy request as a
  fallback. ECH preserves the TLS 1.3 capability in the outer ClientHello and
  across HRR or authenticated rejection. TLS 1.3 servers
  can attach chain-aligned OCSP responses to individual `CertificateEntry`
  values only when requested, while retaining the legacy leaf-only
  configuration. Clients preserve that alignment through parsing and validate
  every supplied staple on the selected trust path against its actual issuer;
  raw-public-key handshakes reject staples. Bundle trust policy supports
  ignore/if-present/require modes. Strict RFC
  7633 TLS Feature parsing automatically upgrades a leaf containing
  `status_request(5)` to require a valid staple, even when caller policy is
  `ignore`; duplicate, negative, non-minimal, and unsupported critical feature
  encodings fail closed. TLS 1.2 servers can return either RFC 6066 leaf-only
  status or RFC 6961 chain-aligned response lists, including explicit empty
  entries and omitted trailing responses. Both forms are bound into the
  Finished transcript; clients reject unsolicited, missing, conflicting,
  oversized, or malformed status messages and validate supplied responses
  against the selected certificate path.
  An exact certificate or cross-signed form with the same Subject and complete
  SubjectPublicKeyInfo is recognized as a configured trust anchor without
  verifying the anchor's issuer signature. Hostname and validity remain
  mandatory for server authentication; leaves enforce optional
  digitalSignature plus endpoint-specific serverAuth/clientAuth usage, and
  presented intermediates require CA=true, optional keyCertSign, pathLen, and
  supported critical extensions;
- TLS 1.3 SHA-256 early, handshake, application, exporter, resumption, PSK
  binder, Finished, 0-RTT, and traffic-update key scheduling, including
  allocation-free caller-buffer RFC 8446 exporter output from established
  client and server connections; exporter master secrets are derived from the
  ServerFinished transcript, retained independently, and wiped with the
  connection. SHA-256 paths reuse precompressed HMAC ipad/opad states for
  paired traffic secrets and grouped record/QUIC key derivation; internal
  HkdfLabel messages up to 55 bytes use one explicitly padded SHA-256 block.
  Runtime traffic-secret updates dispatch across SHA-256, SHA-384, and SM3
  rather than assuming the default suite.
- Opt-in, allocation-free NSS key-log callbacks cover TLS 1.3 early,
  handshake, generation-zero application and exporter secrets plus the TLS 1.2
  `CLIENT_RANDOM` master secret. A caller-owned writer helper emits exact
  `SSLKEYLOGFILE` lines without giving the library implicit filesystem access.
- X25519 plus constant-time secp256r1, secp384r1, and native pure-Zig
  secp521r1 ECDH key exchange, with uncompressed SEC1 validation and
  incremental SHA-256/SHA-384 transcript hashing.
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
- TLS 1.3 record protection for AES-128-GCM, AES-256-GCM, AES-128-CCM,
  AES-128-CCM-8, ChaCha20-Poly1305, SM4-GCM, and SM4-CCM, plus
  allocation-free QUIC Initial, Handshake, 0-RTT, 1-RTT,
  Retry integrity, traffic-secret, and key-update crypto helpers, including
  version-specific QUIC v1/v2 labels, nonce derivation, header protection, and
  suite confidentiality/integrity limits.
- Established TLS 1.3 and TLS 1.2 connections expose allocation-free,
  configurable application-record fragmentation with explicit plaintext
  consumed/output written progress. Each call seals exactly one record, so
  output failures remain retryable without hidden buffering or nonce reuse.
- TLS 1.3 and TLS 1.2 client/server handshake states expose caller-owned
  `receiveInto` transitions. Their compact events do not inline and copy the
  roughly 35 KiB established record state; the original value-returning
  `receive` APIs remain compatibility wrappers. The dual-version client and
  server expose the same interface with a tagged caller-owned established
  union, so automatic TLS 1.2/TLS 1.3 selection preserves this property.
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
  over P-256, P-384, or native P-521, require Extended Master Secret and RFC
  5746 signaling,
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
  exposes allocation-free block and 96-bit-nonce GCM/CCM APIs, and TLS/QUIC
  can negotiate the RFC 8998 TLS_SM4_GCM_SM3 (`0x00c6`) and
  TLS_SM4_CCM_SM3 (`0x00c7`) suites with SM3 HKDF/transcripts, PSK binders,
  tickets, packet protection, and SM4 header protection. SM4-CCM is checked
  against RFC 8998 Appendix A.2. Prepared SM4-GCM state caches both the
  32-round key schedule and GHASH table. Its AVX2 CTR path encrypts eight
  counter blocks together, while a portable four-block path remains available;
  a two-block SM4 core evaluates CCM's dependent authentication and independent
  counter blocks together. On 1,200-byte TLS records this reduced SM4-GCM from
  about 12.0 to 4.86 microseconds per seal and SM4-CCM from about 24.6 to
  22.2 microseconds per seal.

## Pure-Zig cryptography

Vail's cryptographic implementation is entirely Zig and does not require a C,
C++, or Rust crypto library. SHA-256 uses Zig's standard implementation, while
RFC 8879 Brotli uses the sibling pure-Zig Vort package. TLS and
QUIC AES-128-GCM/AES-256-GCM keys retain a reusable pure-Zig context that caches
the expanded AES key and GHASH table, avoiding per-record key-dependent setup.
SM2, SM3, and SM4 are implemented in Vail. P-384 ECDSA verification uses a
specialized public-input width-10/width-6 wNAF path with bounded sparse
entries read directly from six scalar limbs, a binary-GCD scalar inverse, and
a projective final `r`/`r+n` check. Positive affine and Jacobian wNAF table
entries are passed by pointer, materializing a temporary only when the Y
coordinate must be negated. Linux x86_64 BMI2/ADX builds embed
s2n-bignum-derived Montgomery-Jacobian add, mixed-add, and doubling schedules;
other targets use the corresponding pure-Zig formulas. P-384
signing uses a constant-schedule four-table 6-bit fixed-base comb with
full-table selection, fixed-work deterministic-nonce candidate handling, a
fixed-width scalar inverse, and explicit temporary/register wiping. The
x86_64 path embeds the formally verified s2n-bignum P-384 Montgomery field
inverse and generic six-limb modular inverse schedules; the portable fallback
uses fixed-window Fermat inversion and the same pure-Zig Montgomery scalar
kernel. SHA-384 uses the same in-tree AVX compressor as SHA-512 with its own IV
and 48-byte output, while RFC 6979 retains each derived HMAC ipad/opad state
across adjacent K/V operations. Fixed-width nonce, digest, private-key, and
affine-x conversion bypass the generic wide field decoder. With fresh secure
nonce noise inside both timed loops, a direct old/new comparison reduced the
Vail median from 43,894 ns to 38,420 ns, or 12.47%. Sixteen fixed-CPU,
order-balanced samples then measured 38,490 ns for Vail signing against
66,210 ns for AWS-LC, a 41.87% latency reduction or 1.72x throughput. A
six-quartet fixed-CPU-14 comparison reduced verification from 124,854.2 ns to
123,971.9 ns when dense digit arrays were replaced with sparse limb-window
recoding, a 0.707% improvement. Passing positive table entries by pointer then
reduced 123,988.2 ns to 123,251.6 ns, another 0.594%, with all six quartets
favoring each retained change. Six clean final A-B-B-A quartets measured
123,352.0 ns for Vail against 155,349.4 ns for AWS-LC with a parsed public key,
giving Vail 20.597% lower latency and about 1.2594x throughput.
`interop-openssl-p384-sign` independently verifies a Vail-generated signature
with OpenSSL. Run `zig build -Doptimize=ReleaseFast bench-p384-sign` and
`zig build bench-aws-lc-p384-sign` for the isolated signing comparison,
`zig build -Doptimize=ReleaseFast bench-p384-one-shot` for the isolated
verifier, or `bench-p384-verify` and `bench-aws-lc-p384` for the component
matrix.
P-384 ECDH reuses the signer comb for fixed-base public-key recovery and an
embedded, formally verified s2n-bignum Montgomery-Jacobian scalar multiplier
for arbitrary peer points. On AVX2/BMI2/ADX targets, each signed 5-bit window
still reads all 16 Jacobian table entries in order, while YMM equality masks and
`vpblendvb` select all 18 limbs; BMI2/ADX-only targets retain the scalar
`cmov` scan. Both paths remain constant-time in the private scalar and
explicitly clear secret temporaries, vector registers, and assembly stack
frames. A fair raw-private-key comparison includes canonical parsing inside
both implementations' timed public and shared operations. Sixteen fixed-CPU,
ABBA-order samples measured 28,957.8 ns for Vail public-key recovery versus
81,472.4 ns for AWS-LC, a 64.457% latency reduction. One-shot shared-secret
derivation measured 113,664.5 ns for Vail versus 196,926.2 ns for AWS-LC, a
42.281% latency reduction. The vector table selection itself reduced Vail's prior
116,275.5 ns median by 2.5%. A direct six-limb private-key decode candidate
regressed public-key recovery by 2.33% and was removed. Run `bench-p384-ecdh`
and `bench-aws-lc-p384-ecdh` for the isolated comparison.

A fixed-width, allocation-free
P-521 verifier fills the curve left unimplemented by Zig std 0.16: it uses
9×58-bit reduction modulo the `2^521-1` field prime, Montgomery arithmetic
modulo the subgroup order, and Jacobian joint scalar multiplication. The final
ECDSA x-coordinate check stays projective and uses the P-521 `n < p < 2n`
relation to avoid an otherwise mandatory field inversion; scalar loops update
their 216-byte projective accumulator in place. Field squaring evaluates its 45
unique products in output-coefficient order, keeping one `u128` accumulator
live at a time, and uses the proven 62-bit radix carry bound instead of
maintaining unnecessary wide carry words. The public square is shared across
point formulas to keep the hot verifier below the instruction-cache footprint
of fully inlined copies; the private square uses the same schedule with fixed
folding passes and no secret-dependent branches. Public scalar inversion batches
binary-GCD trailing-zero removal and divides its modular coefficients by up to
64 powers of two per pass. Verification stores only bounded non-zero wNAF
digits and reads each window directly from the nine scalar limbs, avoiding two
522-entry zero-filled arrays and whole-value shifts on every bit. One-shot
verification combines
the shared width-12 generator table with a 16-entry width-6 cached-Jacobian
table for the supplied public key; table construction reuses both the fixed
`2Q` point's and each preceding odd multiple's `Z²` and `Z³`, while the same
cached powers avoid recomputation during joint scalar multiplication. Signed
wNAF selection passes positive affine and cached table entries by reference and
materializes only a negated Y coordinate, avoiding whole-entry copies. The
recurrence adds `(2i-1)Q` to `2Q`; because a validated non-identity P-521 point
has prime order far above every table coefficient, these operands cannot be
identities, equal, or inverses. ReleaseFast therefore uses the incomplete
cached addition while ReleaseSafe asserts those public invariants. It accepts
compressed or uncompressed SEC1 keys and verifies SHA-224/256/384/512 ECDSA
signatures used by certificates, CRLs, OCSP responses, and TLS 1.2/1.3
CertificateVerify. A 216-byte `PublicKey` validates and decodes SEC1 once while
retaining one-shot table construction, providing a low-memory repeated-use
option. A caller-owned 38 KiB `PreparedVerifier` retains the public
key's width-10 wNAF odd multiples while sharing a compile-time fixed-generator
table for repeated verification and prepares in about 0.230 ms. An explicit
608 KiB `ThroughputPreparedVerifier` uses width-14 tables and about 3.88 ms of
preparation for maximum long-lived-key throughput. A 5.75 KiB
`CompactPreparedVerifier` retains a width-6 cached-Jacobian table, prepares in
about 0.0095 ms, and reduces setup cost for short batches.
Bundle path verification uses the compact form to share one P-521 table across
certificate and issuer-signed OCSP authentication without allocation.
The same validated point and constant-time full-table comb implementation now
provides P-521 public-key recovery and ECDH shared-secret derivation. TLS 1.2
and TLS 1.3 can negotiate the standard `secp521r1` (`0x0019`) named group in
either role;
`interop-openssl-p521-kx-server` and `interop-openssl-p521-kx-client` force
OpenSSL to use P-521 for TLS 1.3, while the corresponding
`interop-openssl-tls12-p521-kx-*` gates check both TLS 1.2 directions.
Public-key recovery reuses a compile-time generator table and measures about
70.0 us. One-shot ECDH uses a dedicated four-table 3-bit comb with only 32
precomputed public points and measures about 290.1 us, including construction
of that table, versus roughly 1.206 ms for this machine's OpenSSL
`speed ecdhp521`, or about a 4.16x lead. An earlier eleven-round 3-bit/4-bit
comparison selected the smaller table in ten rounds. Signing keys
retain a caller-owned 6-bit hot table because an eleven-round A/B showed that
forcing signing onto the shared read-only table regressed its hot path by about
3%.
Clients advertise `ecdsa_secp521r1_sha512`, and the built-in TLS signer now
supports caller-owned P-521 key pairs. Private operations use a four-table,
6-bit fixed-base comb, branchless Jacobian doubling and mixed addition under
the comb's disjoint-bit invariant, full-table masked selection, weakly reduced
Mersenne-field values with canonicalization only at the public boundary, and
constant-time scalar Montgomery arithmetic. TLS obtains a fresh 521-bit nonce
from the caller's `std.Io` for every signature. The direct allocation-free
signing API also accepts an explicit canonical nonce for deterministic vectors
and controlled callers. A single-use `PreparedNonce` can move `k·G` and
`k⁻¹` off the online signing path; `signPrepared` consumes and wipes it before
hashing the message and rejects every reuse attempt. A matching one-use TLS
Signer variant brings the same behavior to CertificateVerify; callers must
replace its consumed nonce before another handshake. Key pairs can be loaded
from strict RFC 5915
ECPrivateKey or PKCS#8 `id-ecPublicKey`/`secp521r1` DER, with any embedded
public point checked against the derived key. Public verification retains its
faster variable-time wNAF path.
The shared X.509-family verifier additionally accepts the parameter-free NIST
ECDSA-with-SHA3-224/256/384/512 AlgorithmIdentifiers for P-256, P-384, and
P-521 issuers. This covers certificate, CRL, and OCSP signatures through the
same strict compatibility parser; these algorithms are not advertised as TLS
CertificateVerify schemes because TLS defines no corresponding codepoints.
RSA-PSS with SHA3-224/256/384/512 is supported with matching MGF1 hashes and
digest-length salts. RSA PKCS#1 v1.5 supports the four corresponding NIST
signature OIDs and strictly validates the recovered EMSA padding and
DigestInfo; both the parameter-free standard form and OpenSSL's empty-NULL
DigestInfo/SignatureAlgorithm encoding are accepted.
RSA-PSS and PKCS#1 v1.5 additionally support SHA-512/224 and SHA-512/256 for
the direct RSA API and the shared X.509-family certificate, CRL, and OCSP
verifier. PSS requires matching MGF1 and digest-length salts, while PKCS#1
v1.5 uses the RFC 8017 DigestInfo OIDs. These algorithms are intentionally not
offered for TLS CertificateVerify because TLS defines no SignatureScheme
codepoints for them.
RFC 8692 RSA-PSS-SHAKE128/256 and ECDSA-SHAKE128/256 AlgorithmIdentifiers are
also supported with strictly absent parameters. RSA-PSS uses 32/64-byte
message digests and salts and applies SHAKE natively as its variable-length
MGF rather than wrapping it in MGF1. Dedicated SHAKE-constrained RSA public and
private keys retain that exact profile. These algorithms are X.509-family and
direct RSA API capabilities only; TLS defines no corresponding
SignatureScheme codepoints.
TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_8_SHA256, and TLS_SM4_CCM_SM3 use a
generic 12-byte-nonce pure-Zig CCM core. AES-CCM shares one expanded AES key
between CBC-MAC and counter-mode encryption, and its fused payload loop
evaluates one CBC-MAC block and one counter block together with Zig's
two-block AES primitive. On the same
1,200-byte QUIC workload, this reduced seal from 1,730 ns to 1,120 ns and
open+seal from 3,465 ns to 2,170 ns relative to separate MAC/CTR passes. TLS
enforces conservative key-usage limits, while QUIC accepts only full-tag CCM.
OpenSSL 3.6.3 exercises both AES-CCM suites in client and server directions.
rustls's AWS-LC provider does not instantiate either TLS suite, and AWS-LC's
public CCM AEADs are the Bluetooth/Matter `L=2`, 13-byte-nonce variants rather
than TLS's `L=3`, 12-byte-nonce construction, so no mismatched primitive timing
is presented as an AWS-LC comparison.

On x86_64 targets with AVX2, VAES, and VPCLMULQDQ, the prepared AES-GCM path
uses two-lane AES-CTR and 16-block aggregated GHASH. AArch64 targets with the
AES/PMULL extension use the same 16-block reduction schedule with independent
PMULL products; other targets retain the portable Zig standard-library path.
Clean, order-balanced ReleaseFast runs on an Intel Core i9-13900K pinned to
CPU 14 produced these medians over 1,200-byte QUIC payloads. The AWS-LC side
uses its out-of-place scatter/gather APIs, so neither implementation is charged
an extra plaintext, ciphertext, or tag copy:

| Operation | Pure Zig | AWS-LC | Speedup |
| --- | ---: | ---: | ---: |
| AES-128-GCM seal | 187.5 ns | 241 ns | 1.29x |
| AES-128-GCM open+seal | 378 ns | 480 ns | 1.27x |
| AES-256-GCM seal | 206.5 ns | 276 ns | 1.34x |
| AES-256-GCM open+seal | 418 ns | 545 ns | 1.30x |

On an ARM64 host, seven fixed-binary pairs over 85-byte short packets reduced
prepared AES-128 seal/open medians from 206/283 to 135/217 ns and AES-256 from
220/334 to 166/270 ns, with every pair faster. Nine fixed-binary 1,149-byte
QUIC DATAGRAM receive pairs reduced the median from 2,752 to 2,606 ns/packet
(5.31%, 9/9 wins). The compact runtime-loop implementation adds about 23 KiB
to the complete netz receive benchmark, rather than the roughly 301 KiB of the
rejected fully unrolled prototype.

ChaCha20-Poly1305 uses a prepared pure-Zig core on x86_64 AVX2 and aarch64
NEON targets. It emits eight ChaCha blocks together on AVX2 and four on NEON,
derives the Poly1305 one-time key in the first wide batch, and uses a
word-transposed eight-lane state plus a vectorized output transpose that XORs
payload bytes without materializing a separate 512-byte keystream. It
authenticates up to eight 16-byte blocks at once with 26-bit limbs. The
Poly1305 front end decodes input through paired 64-bit Zig vectors, computes
`r^3`/`r^4` and `r^5` through `r^8` in parallel groups, combines short padded
TLS/QUIC headers with ciphertext, stores `r^1` through `r^4` directly in the
limb-major SIMD layout consumed by the four- and eight-block kernels, and
batches a final ciphertext block with the length block whenever that removes
serial tail multiplications. For the common 1,200-byte QUIC payload with a
17-to-32-byte header, it assembles the combined `r^1` through `r^8` eight-lane
vector once per packet. Message and power lanes retain AVX2's native
`0,2,1,3` unpack order within each four-block half, removing four `vpermq`
instructions from every eight-block batch. The 78 authenticated blocks are
scheduled as one six-block prefix and nine eight-block batches, all reusing
that combined power vector. The prefix and final batch load their two 64-byte
halves directly, avoiding 128 bytes of staging copies while performing the
minimum ten polynomial reductions. Both the four-block prefix core and
eight-block bulk core execute two ChaCha double rounds per loop iteration, and
prepared QUIC keys retain the parsed ChaCha key words across packets. Tag
finalization uses two native 64-bit carry chains. Exact in-place opening retains
the first three payload keystream blocks generated beside the one-time Poly1305
key and reuses them only after tag verification. Disjoint-buffer opening uses
the faster encryption traversal for tentative plaintext and securely clears
the complete output before reporting authentication failure. QUIC nonce
construction XORs the packet number as one native 64-bit word, and keeping
authentication in a separate call bounds register pressure in the ChaCha hot
path. Other targets retain Zig std. Current ReleaseFast measurements on the
same 1,200-byte QUIC workload pinned to one CPU are:

| Operation | Zig std | Prepared Zig | Speedup |
| --- | ---: | ---: | ---: |
| ChaCha20-Poly1305 seal | 1,906.0 ns | 609.8 ns | 3.13x |
| ChaCha20-Poly1305 open+seal | 3,822.5 ns | 1,222.5 ns | 3.13x |

Twelve measurements per implementation, grouped into six clean CPU14 A-B-B-A
quartets, measured means of 617.675 ns for Vail versus 620.179 ns for AWS-LC
seal, 618.384 ns versus 618.816 ns for open, and 1,235.397 ns versus 1,242.060
ns for open+seal. The pure-Zig seal and round-trip paths led by 0.404% and
0.536%; the 0.070% open-only difference is treated as noise rather than a
performance claim. Both harnesses perform the same warmup, keep nonce
construction outside the timed primitive, use identical key, nonce, AAD, and
payload bytes, and consume the same ciphertext, tag, and plaintext bytes inside
the timed loops. All inputs are hidden behind optimization barriers and the
complete-run checksums agree. The corrected AWS-LC benchmark uses
`seal_out_of_place_scatter` and `open_separate_gather`; older results that
included three extra AWS-side buffer copies or asymmetric nonce construction
are no longer used. The retained
Poly1305 batching reduced a clean 629/1,264 ns Vail baseline to about
620/1,241 ns. Reusing the combined eight-lane powers first reduced
621.2/1,242.8 to 619.8/1,241.6 ns; retaining the hardware-native lane order then
reduced that to 612.8/1,226.8 ns in a separate 12-sample old/new comparison.
A fixed 192 + 512 + 496 byte ChaCha traversal regressed seal by 4--6 ns, while
precomputing the scaled `5r` limbs changed seal by 0.000% and open+seal by only
0.081%. Splitting each eight-lane product into serial four-lane halves was about
2.7% slower, and a five-by-sixteen-block schedule nearly doubled the hot
function's code size and also regressed in paired trials; all four candidates
were removed. Constructing the final 48-byte ciphertext tail and length block
directly as eight 64-bit lanes added about 23 retired instructions per seal and
regressed a six-quartet mean from 615.333 ns to 615.667 ns. Splitting the
1,200-byte authenticator out of the generic function produced the same
hot-path instructions, while a two-batch Poly1305 loop unroll grew that
function by about 1.4 KiB and added about 14 instructions per seal. These
candidates were also removed. Full, five-double-round, and single-double-round
ChaCha unrolls, 64-byte function alignment, a 17-byte AAD special case, and a
larger context with pre-broadcast key lanes likewise failed paired gates and
were removed. Splitting disjoint and in-place opening, returning the computed
tag in a vector register, and marking authentication failure unlikely all
passed the correctness oracle but failed the paired performance gate and were
removed. AES-GCM medians and the 736-byte prepared-key footprint remain
unchanged by the ChaCha path.

X25519 public-key recovery uses an in-tree fixed-base kernel on Linux x86_64
AVX2/BMI2/ADX targets. Other targets use a four-group, five-column
Edwards25519 comb with 13 windows. Every secret digit in that portable path
scans all 32 entries in a limb-major vector layout, the first selected point
initializes the accumulator directly, and the final point is projected with
`u = (Z + Y) / (Z - Y)`. The 18.75 KiB affine/cached table is generated by a
checked-in pure-Zig tool and stored as constants so ordinary builds do not
evaluate curve inversions at compile time. RFC 7748 key pairs, the 1,000-step
iterated vector, and deterministic differential cases are checked against
Zig's Montgomery ladder. Fixed-CPU independent-binary measurements on the same
i9-13900K produced these representative medians:

| X25519 operation | Zig std | Vail | AWS-LC |
| --- | ---: | ---: | ---: |
| Public-key recovery | 32,733 ns | 5,497 ns | 6,117 ns |
| Arbitrary-point shared secret | 35,965 ns | 18,712 ns | 18,960 ns |

The fixed-base path is about 5.95x faster than Zig std and has 10.14% lower
latency than AWS-LC at the median. Its signed radix-16 recoder derives each
carry-out directly from the current nibble's high bit, avoiding a comparison
dependency on the previous digit. The eight-entry table selection still scans
every entry, but combines each YMM equality mask with three memory-source
`vpand` operations and accumulates with `vpor`; the first entry initializes the
accumulators directly, and the vector one constant is hoisted out of the loop.
The complete secret stack, vector state, and secret-bearing caller-saved
registers are explicitly cleared. A fixed-CPU old/new binary comparison
measured 5,778.5 ns before these changes and 5,499 ns after, a 4.84%
reduction. Linux x86_64 AVX2/BMI2/ADX builds use this in-tree constant-time
four-limb implementation derived from the formally verified s2n-bignum
instruction schedule. An output-buffer API lets TLS, HPKE, and hybrid key
exchange avoid an intermediate result copy; other targets retain the Zig std
implementation.
Sixteen fixed-CPU-14 samples per implementation, grouped into eight A-B-B-A
quartets, put this arbitrary-point path about 1.31% ahead of AWS-LC at the
median while making it about 1.92x faster than the previous Zig std path.
Every retained run observed zero non-idle scheduler ticks on sibling CPU 15;
contaminated quartets were discarded. A separate old/new comparison measured
18,786.6 ns before replacing the public loop counter's load/subtract/store plus
reload/compare sequence and 18,714.3 ns after, a 0.385% reduction across six
clean quartets. The memory `decq`/`cmpq` pair removes about 752.5 retired
instructions per shared secret without changing the fixed iteration count or
secret-dependent instruction and address trace. An earlier hardening A/B
measured 18,755.5 ns before full-frame/register clearing and 18,746 ns after,
which is within run-to-run noise. Reusing one ladder-step body
instead of alternating between two identical expanded bodies reduced the
complete assembly routine from about 31.0 KiB to 25.8 KiB and improved its
instruction-cache locality without changing its fixed iteration count. Run
`zig build -Doptimize=ReleaseFast bench-x25519` and
`zig build bench-aws-lc-x25519` for the full comparison, or
`bench-x25519-shared` and `bench-aws-lc-x25519-shared` for isolated
arbitrary-point measurements.

Additional fixed-CPU experiments kept the scalar `cmov` schedule. Replacing
the eight per-step selections with fixed-address AVX2 XOR-mask selections
increased the median from 18,777 ns to 18,838.5 ns across eight clean A-B-B-A
quartets. Folding each explicit candidate load into a memory-source `cmov`
increased a four-quartet median from 18,781.5 ns to 18,863.5 ns. Precomputing
adjacent-bit equality and consuming it with a public-index memory `bt` passed
the X25519 differential oracles, but raised isolated latency to 21,099 ns.
These candidates and an earlier direct memory-`bt` bit extractor were removed;
the latter was also slightly slower in eight clean quartets. Biasing the loop
counter by pre-shifting the scalar retired another 246 instructions but
regressed latency by about 1.1%; retaining the counter in a register for the
loop comparison was about 1.3% slower. Replacing the reduction's fixed
multiplication by 19 with two dependent LEAs shortened the assembly core by 40
bytes but was roughly 1.6% slower. Aligning the main ladder loop to a 16-byte
boundary changed a 12-sample mean by only +0.004%. All of these candidates were
removed. The retained scalar schedule keeps every secret-path address fixed
and remains the fastest measured variant on the primary target.

ML-KEM-512/768/1024 are implemented in-tree from the Zig standard-library
construction; none links a C or Rust cryptographic runtime. On Linux x86_64
with AVX2, the hot paths use embedded, formally verified
s2n-bignum/mlkem-native instruction schedules for native-order NTT/INTT,
cached k=2/k=3/k=4 pointwise products, serialization, Montgomery
conversion, modular normalization, public-matrix rejection sampling, and
ciphertext d4/d5/d10/d11 compression and decompression. The compression ABI,
constant tables, and generated assembly schedules are isolated in their own
module; the portable Zig implementation remains both the non-AVX2 fallback and
the differential oracle. SHA3-256, SHA3-512, and the long-input SHAKE256 KDF
share the same in-tree, formally verified single-lane AVX2 Keccak permutation;
ML-KEM-512 encapsulation keeps Zig std's faster one-block SHA3-512 path. The
SHAKE128 matrix expansion and eta=2/eta=3 noise generation use the tuned
four-way Keccak-f1600 schedule, while the unavoidable single matrix lane for
k=3 uses the shared AVX2 sponge and centered-binomial decoding is vectorized.
ML-KEM-512 samples its contiguous secret and error polynomials in one four-lane
eta=3 batch. For a 3x3 matrix, two complete four-lane batches are followed by
one scalar Keccak lane with AVX2 rejection sampling instead of computing three
duplicate padding lanes; the 2x2 and 4x4 matrices map exactly to complete
batches. Public matrix-expansion states are not needlessly scrubbed; secret
Keccak states, noise buffers, point-product caches, and secret polynomials are
explicitly wiped. Public rejection sampling remains variable-time. Other
targets retain the portable Zig implementation.

Twelve measurements per implementation from six clean CPU14 A-B-B-A quartets
produced these means. Key generation and encapsulation obtain fresh operating-
system randomness inside both timed loops; decapsulation uses the same valid
fixed ciphertext throughout each process:

| Parameter set and operation | Vail | AWS-LC | Vail latency reduction |
| --- | ---: | ---: | ---: |
| ML-KEM-512 random key generation | 6,409.083 ns | 7,501.333 ns | 14.561% |
| ML-KEM-512 random encapsulation | 3,126.417 ns | 8,528.000 ns | 63.339% |
| ML-KEM-512 decapsulation | 5,120.083 ns | 8,690.917 ns | 41.087% |
| ML-KEM-768 random key generation | 9,400.833 ns | 11,089.167 ns | 15.225% |
| ML-KEM-768 random encapsulation | 2,989.833 ns | 12,148.667 ns | 75.390% |
| ML-KEM-768 decapsulation | 6,055.333 ns | 13,036.083 ns | 53.549% |
| ML-KEM-1024 random key generation | 13,459.750 ns | 15,132.750 ns | 11.055% |
| ML-KEM-1024 random encapsulation | 3,932.250 ns | 16,816.333 ns | 76.616% |
| ML-KEM-1024 decapsulation | 7,802.333 ns | 18,305.750 ns | 57.378% |

The compression change was also measured against an independent binary using
the portable codec. Six clean CPU14 A-B-B-A quartets reduced encapsulation by
6.647%, 12.993%, and 16.560%, and decapsulation by 11.367%, 15.224%, and
16.922% for ML-KEM-512, ML-KEM-768, and ML-KEM-1024 respectively. Both sides
of this isolation included the AVX2 normalization-path return fix. The sibling
CPU15 had zero non-idle scheduler ticks in every retained quartet; contaminated
or out-of-envelope quartets were discarded in full. Differential tests cover
every normalized field coefficient for all four compression widths,
independent arbitrary encoded inputs for decompression, and the full i16 input
domain for modular normalization.

Moving the formerly ML-DSA-local SHAKE256 state machine into the shared
Keccak module also enabled the single-lane ML-KEM hashes without duplicating
sponge code. Eight clean old/new quartets measured key-generation reductions
of 2.126%, 3.368%, and 2.292%; encapsulation reductions of 1.327%, 0.839%, and
0.525%; and decapsulation reductions of 2.138%, 3.887%, and 2.990% for the
512, 768, and 1024 parameter sets. An all-AVX2 SHA3-512 encapsulation candidate
was rejected for ML-KEM-512 because its one-block case was slower; the retained
hybrid dispatch is faster for every measured operation and parameter set.

The native encryption and decapsulation data flow now mutates aligned
polynomials and vectors in place instead of returning each 512--2,048-byte
intermediate through chained value APIs. Direct decompression writes into its
final `Poly`/`PolyVec` destination, and matrix/noise expansion can likewise
populate caller-owned storage. In a profile of the ML-KEM-768 benchmark this
reduced `memcpy` from about 6.2% to 1.9% of sampled cycles. Eight clean A-B-B-A
quartets reduced encapsulation by 1.096%, 1.923%, and 3.290%. Decapsulation
improved by 1.984% and 4.970% for the 768 and 1024 parameter sets; the 512
result changed by a noise-level +0.186%, while a follow-up clean quartet
favored the new path by 0.809%.

Encryption now fills the temporary `r`, `e1`, and `e2` polynomials from shared
four-lane SHAKE batches. ML-KEM-512 maps its two eta=3 `r` streams and two
eta=2 `e1` streams into one two-block batch; ML-KEM-768 maps its seven streams
into two batches. Eight clean old/new quartets reduced 512 encapsulation and
decapsulation by 20.986% and 15.326%, and reduced 768 encapsulation and
decapsulation by 8.368% and 2.650%. ML-KEM-1024 retains the previous schedule;
its generated `.text` is byte-identical across this change.

Ephemeral plaintext, hash/KDF, noise, point-product, and uncompressed
ciphertext-polynomial temporaries are explicitly erased after their last use.
Large aligned values use fixed-address volatile 32-byte vector stores instead
of the byte-at-a-time secure-zero fallback. Against otherwise identical
explicit-wipe binaries, eight clean quartets reduced keygen by 8.811%, 4.797%,
and 4.039%; encapsulation by 10.749%, 18.358%, and 18.642%; and decapsulation
by 8.138%, 10.673%, and 10.909% for the three parameter sets.

The Vail key-generation result is an expanded decapsulation key with its public
matrix cached; this is the representation consumed directly by its faster
decapsulation path. The same run measured 15,810.5 ns for the complete
X25519MLKEM768 client-start operation, including X25519 public-key recovery and
the encoded 1,216-byte TLS key share. Run
`zig build -Doptimize=ReleaseFast -Dcpu=native bench-mlkem512`,
`bench-mlkem768-random`, and `bench-mlkem1024` reproduce the pure-Zig
comparisons; the corresponding `bench-aws-lc-*-random` steps run the test-only
AWS-LC sides. `bench-mlkem768-keygen` retains the deterministic ML-KEM-768
key-generation microbenchmark.

ML-DSA-44 provides an in-tree pure-Zig FIPS 204 fast path, retains Zig std as
the portable fallback, and interoperates in both RFC 7250 TLS client/server
directions with rustls/AWS-LC. Its in-tree
public-key decoder expands the 4x4 public matrix in four parallel SHAKE128
lanes on x86_64 AVX2, with Zig std retained as the portable fallback. Six clean
CPU14 A-B-B-A old/new quartets reduced public-key preparation from 26,307.917
ns to 17,110.333 ns, raw verification from 55,099.917 ns to 39,808.833 ns, and
the TLS raw-key verification boundary from 55,097.917 ns to 39,635.333 ns:
34.961%, 27.752%, and 28.064% reductions respectively. Before that comparison,
removing a redundant second public-matrix expansion had reduced the TLS path
from 84,808.333 ns to 54,713.917 ns. The signer also explicitly wipes its
SHAKE state and per-signature randomizer after producing CertificateVerify.

The x86_64 path now also embeds the formally verified s2n-bignum/mldsa-native
AVX2 NTT, inverse NTT, L=4 pointwise accumulation, pointwise multiplication,
NTT-order permutation, rejection sampling, `useHint`, `z` unpacking, norm
checking, eta=2 sampling, decomposition, and Keccak-f1600 schedules directly in
Zig source. It retains signed
custom NTT order between transforms and materializes a self-contained prepared
key directly from wire bytes. Portable targets continue through the auditable
scalar Zig implementation. A six-quartet old/new comparison before the final
packing refinements reduced
prepared verification from 19,674.500 ns to 7,759.500 ns, raw verification from
36,378.667 ns to 22,456.000 ns, and the TLS raw-key boundary from 36,325.167 ns
to 22,491.250 ns: 60.561%, 38.272%, and 38.084% respectively.

Independent ML-DSA-44 benchmarks use the same deterministic FIPS seed and a
shared 2,420-byte signature generated by pure Zig and accepted by AWS-LC. The
key-generation, signing, and raw-verification rows are means of twelve samples
per implementation from six CPU14 A-B-B-A quartets. The prepared-verification
row is a newer dedicated comparison with the same sample count and ordering:

| ML-DSA-44 operation | Vail | AWS-LC | Current gap |
| --- | ---: | ---: | ---: |
| Key generation from seed | 22,331.083 ns | 22,981.000 ns | Vail 2.828% faster |
| Prepared randomized sign | 56,029.000 ns | 80,120.333 ns | Vail 30.069% faster |
| Prepared-key verify | 7,696.500 ns | 22,480.583 ns | Vail 2.921x faster |
| Raw-key verify | 22,223.333 ns | 22,622.583 ns | Vail 1.765% faster |

The same accelerated design is parameterized for ML-DSA-65 and ML-DSA-87.
Their x86_64 kernels add L=5/L=7 pointwise accumulation, 19-bit `z` packing
and unpacking, gamma2=(q-1)/32 decomposition and `useHint`, four-way mask and
eta expansion, and compact standard-wire-format key generation while
retaining strict decoding and the portable fallback. Independent 3,309-byte
and 4,627-byte signatures generated by pure Zig are accepted by AWS-LC, and
full signature-byte mutation differential tests agree for both parameter
sets. Twelve samples per implementation from six clean CPU14 A-B-B-A quartets
measured:

| Parameter set and operation | Vail | AWS-LC | Current gap |
| --- | ---: | ---: | ---: |
| ML-DSA-65 key generation from seed | 37,877.667 ns | 39,356.417 ns | Vail 3.757% faster |
| ML-DSA-65 prepared randomized sign | 94,767.167 ns | 130,035.333 ns | Vail 27.122% faster |
| ML-DSA-65 prepared-key verify | 9,361.333 ns | 38,128.167 ns | Vail 4.073x faster |
| ML-DSA-65 raw-key verify | 36,519.083 ns | 38,305.167 ns | Vail 4.663% faster |
| ML-DSA-87 key generation from seed | 58,979.583 ns | 61,816.333 ns | Vail 4.589% faster |
| ML-DSA-87 prepared randomized sign | 92,881.750 ns | 159,880.167 ns | Vail 41.905% faster |
| ML-DSA-87 prepared-key verify | 12,574.333 ns | 59,167.750 ns | Vail 4.705x faster |
| ML-DSA-87 raw-key verify | 57,664.000 ns | 59,363.917 ns | Vail 2.864% faster |

Key-generation outputs and verification checksums match across implementations.
Both signing loops obtain fresh operating-system randomness inside the timed
region. Every retained ML-DSA-65 and ML-DSA-87 quartet observed zero non-idle
scheduler ticks on sibling CPU 15; contaminated or out-of-envelope quartets
were discarded in full. For ML-DSA-65 key generation, scanning both 136-byte
eta=4 SHAKE blocks through one capacity-bounded AVX2 call reduced a separate
six-quartet old/new mean from 38,696.667 ns to 38,325.167 ns, or 0.960%.

`PreparedVerifier44` caches the public-key-only `NTT(2^D * t1)` term and the
matrix in the AVX2 kernel's custom order. The initial fixed-term cache alone
reduced 24,792.750 ns to 20,130.667 ns; the complete arithmetic path accounts
for the final result above. `PreparedSignature44` preserves strict norm and
canonical Hint checks while decoding directly into the accelerated signed
representation. Every retained sample in the final prepared, raw, signing, and
key-generation comparisons observed zero non-idle scheduler ticks on CPU15;
contaminated or out-of-envelope quartets were discarded in full.

`PreparedSigner44` caches the secret NTT vectors and public matrix, accepts a
fresh 32-byte randomizer per signature, and erases all rejection-loop scratch
plus the copied randomizer. Its deterministic output matches Zig std byte for
byte, while signatures from several non-zero randomizers verify with Zig std.
The compact `KeyPair44` generator emits the standard 1,312-byte public key and
2,560-byte secret key without constructing unused Zig std caches, and can
prepare its signer directly from those bytes; all three tested seeds match Zig
std byte for byte. Six clean old/new quartets reduced compact keygen from
72,861.333 ns to 22,380.167 ns before the final packing refinements. Hint
generation computes and counts all 1,024 positions with fixed memory access,
only performing sparse encoding after all rejection checks have passed.

Random generation and signature encoding are included for both signing paths;
public-key setup is excluded from prepared verification and included in raw
verification. AWS-LC's nominal 177.250 ns public-key parse is lazy, whereas
Vail's preparation eagerly computes the complete public matrix, so those setup
figures are not treated as equivalent standalone operations.
Every retained quartet observed zero non-idle scheduler ticks on sibling CPU
15. Key generation, prepared randomized signing, prepared-key verification,
and raw-key verification now lead AWS-LC for all three parameter sets. Use
`bench-mldsa44` and `bench-aws-lc-mldsa44` to reproduce the full comparison;
`bench-mldsa44-prepared-cached` and `bench-aws-lc-mldsa44-prepared` isolate the
prepared paths, while `bench-mldsa44-prepared-std` preserves the old Zig std
baseline. `bench-mldsa44-raw` and `bench-aws-lc-mldsa44-raw` provide the
same-input raw-key comparison. `bench-mldsa44-sign-std`,
`bench-mldsa44-sign-prepared`, and `bench-aws-lc-mldsa44-sign` isolate
randomized signing; `bench-mldsa44-keygen-std`,
`bench-mldsa44-keygen-accelerated`, and `bench-aws-lc-mldsa44-keygen` isolate
deterministic key generation. `bench-mldsa65`, `bench-aws-lc-mldsa65`,
`bench-mldsa87`, and `bench-aws-lc-mldsa87` reproduce the corresponding
prepared-key and same-input raw-key verification comparisons. The
`bench-mldsa65-sign-prepared`, `bench-mldsa87-sign-prepared`,
`bench-aws-lc-mldsa65-sign`, and `bench-aws-lc-mldsa87-sign` steps isolate
randomized signing; the corresponding `*-keygen-*` steps isolate deterministic
key generation.

Ed25519 deterministic key derivation and signing use an in-tree fixed-base
kernel on Linux x86_64 AVX2/BMI2/ADX targets, together with an AVX SHA-512
compressor and formally verified ADX scalar reduction/multiply-add schedules;
one-shot verification on those targets uses formally verified Edwards point
decoding and add/double schedules with a public-input width-12/width-6 wNAF
double-scalar path. That public-input path starts at the highest occupied wNAF
column instead of doubling the identity through fixed-size leading padding.
It stores only the at-most-22/43 non-zero width-12/width-6 digits instead of
zero-filling and rescanning two 257-entry dense arrays. Recoding reads only the
affected 64-bit scalar limbs, tracks the one-bit carry explicitly, and skips a
whole window after emitting a digit instead of shifting a 256-bit integer once
per bit. Between non-zero columns, projective-only doublings omit the independent
T-coordinate field product; the full extended coordinate is generated only
when the next column requires an addition. The same projective-only form is
used for the five cofactor-clear doublings whose T output is never consumed,
and writes each odd public-key multiple directly from its preceding table entry
instead of staging a redundant 128-byte copy. Low-order rejection compares the
canonical ADX projective coordinates directly, while the final projective
equivalence check reuses the decoder's formally verified 4x64-bit p25519
multiplication kernel instead of converting through the portable radix-51
representation. The affine decoder supplies X and Y to an initial projective
doubling that only consumes X/Y/Z, so this path also avoids computing the two
otherwise-unused extended T coordinates.
Other targets reuse the portable implementations. The signing path preserves
Zig std's seed, optional-noise, and public-key mismatch semantics, explicitly
clears expanded secret, hash schedule, scalar, nonce, and fixed-base
intermediate state, and is now the default TLS 1.2/1.3 Ed25519 CertificateVerify
signer. RFC 8032,
randomized differential vectors, and independent OpenSSL verification cover
key derivation and signatures. The portable limb-major table scan still reads
all 32 entries for every secret digit. The Linux x86_64 path uses 51 signed
5-bit windows and scans all sixteen entries in each 64-byte-aligned table row.
YMM equality masks plus `vpblendvb` select all twelve cached-point limbs
without secret-indexed loads or branches. A 42-window signed 6-bit candidate
increased the scanned table to 129,024 bytes and regressed key generation by
3.94%, so it was removed. Fixed-CPU, order-balanced runs of independent
ReleaseFast binaries produced these medians:

| Ed25519 operation | Zig std | Vail fixed base | AWS-LC |
| --- | ---: | ---: | ---: |
| Deterministic key pair | 38,847 ns | 5,713 ns | 6,368 ns |
| Sign | 39,400 ns | 6,172.5 ns | 6,870.5 ns |
| Prepared sign | — | 5,976.5 ns | 6,870.5 ns |
| One-shot verify | 48,092 ns | 26,163.2 ns | 29,923.2 ns |
| Prepared online verify | — | 18,553 ns | 29,880 ns |

Against the previous signed 4-bit kernel, independent old/new A-B-B-A runs
reduced deterministic key generation from 6,089 ns to 5,712 ns (6.19%),
one-shot signing from 6,610.5 ns to 6,168.5 ns (6.69%), and prepared signing
from 6,386 ns to 5,976 ns (6.42%). Regenerate the checked-in radix-32 table
with `zig run tools/generate_ed25519_base_table.zig`.

The retained key-pair and one-shot signing paths are about 6.80x and 6.38x
faster than Zig std. Key generation and one-shot signing are about 10.3% and
10.2% faster than AWS-LC at the median, while the 320-byte
`ed25519.PreparedSigner` path is about 13.0% faster
and can be attached to the TLS Ed25519 signer for repeated handshakes. Twelve
clean fixed-CPU-14 measurements per implementation, grouped into six
order-balanced A-B-B-A quartets of isolated one-shot verification binaries,
put Vail at 26,163.2 ns and AWS-LC at 29,923.2 ns, a 12.57% latency reduction or
about 1.14x throughput. Removing the table-entry staging copies reduced the
previous Vail binary from 28,202.3 ns to 28,171.8 ns in one six-quartet
old/new comparison. Direct canonical-coordinate identity checks and the ADX
final field products then reduced 28,155.7 ns to 28,096.8 ns in another, with
all six quartets favoring the new path. Omitting the dead affine T coordinates
further reduced 28,109.6 ns to 28,030.2 ns (0.283%) across six clean quartets.
Replacing the dense wNAF digit arrays with bounded sparse entries then reduced
28,029.8 ns to 27,930.4 ns (0.354%) across six clean quartets.
Reading scalar windows directly from four limbs and skipping each emitted
window reduced that implementation from 27,920.2 ns to 27,426.0 ns (1.77%) in
another six clean quartets. Skipping the T-coordinate multiplication on
doublings not immediately followed by an addition then reduced 27,423.8 ns to
26,179.4 ns (4.54%) and retired about 13,993 fewer instructions per
verification. Extending that optimization to five dead T outputs in cofactor
clearing reduced 26,185.7 ns to 26,155.4 ns (0.116%) in six more clean
quartets.
A width-5 public wNAF candidate reduced table construction by eight additions
but added enough online additions to regress 28,175.0 ns to 28,216.3 ns across
three clean CPU14 quartets, so it was removed. Branching around positive wNAF
table copies changed latency by less than 0.04%, while moving the public-key
cofactor into its scalar changed it by only 0.054%; both noise-level candidates
were also removed. The
15,392-byte `ed25519.PreparedVerifier` costs 60,439 ns to build and makes the complete
online verification about 1.60x faster than AWS-LC; including preparation, it
overtakes repeated AWS-LC after six verifications under the same public key. TLS
exposes this as an opt-in reusable verifier so one-shot handshakes do not pay
the preparation cost. The optimized one-shot path preserves Zig std's
cofactored mixed-torsion semantics and is now used by ordinary TLS and X.509
verification. Run `zig build -Doptimize=ReleaseFast bench-ed25519-keygen`
and `zig build bench-aws-lc-ed25519-keygen` for the isolated key-generation
comparison, `zig build -Doptimize=ReleaseFast bench-ed25519-verify` and
`zig build bench-aws-lc-ed25519-verify` for the isolated comparison, or
`bench-ed25519` and `bench-aws-lc-ed25519` for the component matrix.

P-256 ECDSA verification uses a variable-time public-input path with a
width-10 fixed-generator wNAF table, a width-6 cached-Jacobian public-key
table, bounded sparse recoding that reads four scalar limbs directly and
skips each emitted window, `a=-3` Jacobian formulas, binary-GCD inversion of
the public signature scalar, and a projective `r`/`r+n` final check. Linux
x86_64 AVX2/BMI2/ADX builds use fixed four-limb Montgomery field kernels and
whole-point Montgomery-Jacobian add/double instruction schedules derived from
formally verified s2n-bignum routines and embedded in the Zig source; other
targets retain pure-Zig portable formulas. A fixed-CPU-14 old/new comparison
over six clean A-B-B-A quartets reduced the one-shot mean from 41,670.9 ns to
41,148.8 ns, a 1.253% latency improvement, with all six quartets favoring the
sparse path and about 8,659 fewer retired instructions per verification. Six
more clean quartets over the same key, DER signature, and message measured
41,204.8 ns for Vail versus 47,367.8 ns for AWS-LC with a parsed public key.
Vail therefore has 13.011% lower latency and about 1.1496x its verification
throughput; it is also about 7.1x faster than Vail's previous 294 us
double-scalar path.

For repeated verification with one public key, the 64 KiB
`p256.PreparedVerifier` moves scalar doublings into a caller-retained 4x8-bit
comb table. Its seven-run medians were 388,923 ns to prepare and 23,087 ns per
complete SHA-256 verification, versus 730 ns and 47,443 ns for AWS-LC's parsed
key. Thus Vail's online prepared path is about 2.05x faster, while its total
cost overtakes repeated AWS-LC at approximately the 16th verification; the
prepared number is not an end-to-end one-shot claim. It continues to use the
comb path and is unaffected by the one-shot sparse recoder. TLS
`ClientVerifier` and the X.509 certificate API expose caller-retained
prepared-key paths without forcing one-shot validation to pay the setup cost.
Run `zig build -Doptimize=ReleaseFast bench-p256-one-shot`,
`zig build -Doptimize=ReleaseFast bench-p256-prepared`, and
`zig build bench-aws-lc-p256` to reproduce the comparison.

P-256 signing and ECDH now share a constant-schedule fixed-base path, while
ECDH arbitrary-peer multiplication uses a constant-schedule
Montgomery-Jacobian path on Linux x86_64 BMI2/ADX systems. These instruction
schedules are derived from formally verified s2n-bignum routines and embedded
in Zig. The fixed-base path uses a checked-in 86 KiB, 43-block radix-64 table
covering the signed-recoding carry bit. Signing adds fixed-work RFC 6979 nonce
derivation, constant-time subgroup-order inversion, and explicit secret
cleanup. It evaluates four RFC 6979 candidates without secret-dependent
control flow; the probability that all four are non-canonical is below
2^-128, and that case uses a nonzero 512-bit-reduced fallback instead of
looping on secret data. Candidate, digest, private-key, and wide-fallback
conversion reuse the fixed-schedule four-limb Montgomery kernel instead of
entering Zig std's generic 384-/512-bit field decoder. Every 256-bit half is
below twice the P-256 subgroup order, so a single final subtraction remains
sufficient. The SHA-256 RFC 6979 path also retains each derived HMAC ipad/opad
state across the adjacent K/V operations that share its key. Its 32- and
33-byte messages use the explicit single-block padding path; SHA-224, SHA-384,
SHA-512, and SHA3 retain the generic implementation. A direct old/new
comparison, with fresh secure nonce noise inside the timed loop on both sides,
reduced the Vail median from 15,689 ns to 12,650.5 ns, or 19.37%. Sixteen
fixed-CPU, order-balanced samples of independent binaries then measured
12,664 ns per Vail signature versus 16,037 ns for AWS-LC. Vail led every
retained round, with a 21.03% median latency reduction, while the original Zig
std path took about 249 us. `interop-openssl-p256-sign`
independently verifies a Vail-generated signature with OpenSSL.

The shared-secret path uses an embedded constant-time Montgomery field inverse,
and all assembly routines clear their secret stack workspaces and
caller-visible registers before returning. Other targets retain Zig std's
constant-time implementation. The accelerated public-key path decodes and
validates its ordinary big-endian scalar limbs directly instead of converting
to Montgomery form and immediately encoding them again; a fixed-CPU old/new
comparison reduced its median from 8,023.5 ns to 7,956.5 ns without changing
the shared-secret path. In a fair raw-private-key comparison that includes
canonical parsing on both sides, six clean CPU14 A-B-B-A quartets measured
8,098.8 ns for Vail public-key recovery versus 17,055.3 ns for AWS-LC, and
35,915.5 ns for Vail shared-secret derivation versus 52,475.2 ns for AWS-LC.
Vail therefore has 52.515% and 31.557% lower latency respectively. Run
`zig build -Doptimize=ReleaseFast -Dcpu=native bench-p256-sign` and
`zig build -Dcpu=native bench-aws-lc-p256-sign` for signing.
Run `zig build -Doptimize=ReleaseFast -Dcpu=native bench-p256-ecdh` and
`zig build -Dcpu=native bench-aws-lc-p256-ecdh` to reproduce the comparison.

The reusable AES-GCM context is checked against NIST AES-128-GCM and
AES-256-GCM vectors, Zig's one-shot implementations across block-boundary
message lengths, authentication-failure cases, TLS record round trips, and
QUIC packet vectors.
Run `zig build -Doptimize=ReleaseFast bench-quic-traffic-crypto` for the local
QUIC traffic-protection benchmark, or
`zig build -Doptimize=ReleaseFast bench-tls-record-crypto` for the stateful TLS
record benchmark with automatic nonce sequencing and AEAD usage limits.
`bench-chacha20-poly1305` isolates prepared 1,200-byte sealing,
`bench-chacha-components` separates stream, Poly1305, and complete AEAD costs
across payload sizes, and `bench-aws-lc-aead` runs the test-only AWS-LC
comparison.
`zig build -Doptimize=ReleaseFast bench-tls-server-handshake` measures managed
X25519/Ed25519 TLS 1.3 server flights, including key exchange, signing, and
record protection.
`zig build -Doptimize=ReleaseFast bench-tls-server-connection` includes the
high-level incremental server state, ClientHello framing, and default-disabled
diagnostic hooks in the same first-flight benchmark.
`zig build bench-rustls-tls-server-connection` runs the matching test-only
rustls 0.23.45/AWS-LC 1.18.1 in-process benchmark. Both sides reuse parsed
server configuration and signing-key preparation, consume the same fixed
172-byte ClientHello, create and destroy a fresh server connection, parse its
TLS record, perform X25519 and Ed25519, derive TLS 1.3 handshake keys, and drain
the encoded first flight on every timed iteration. The Vail measurement also
includes framing its cleartext ServerHello as a TLS record. rustls emits an
optional six-byte compatibility CCS, so its output is 295 bytes versus Vail's
289 bytes; both implementations emit the same 90-byte ServerHello record and
189-byte encrypted-handshake record.

Sixteen fixed-CPU-14, order-balanced A-B-B-A runs of independent ReleaseFast
binaries produced these medians:

| TLS 1.3 X25519/Ed25519/AES-128-GCM server first flight | Median |
| --- | ---: |
| Vail server connection | 37,182.5 ns |
| rustls/AWS-LC server connection | 50,493 ns |

Vail therefore has 26.36% lower first-flight latency, or about 1.358x the
throughput, under this connection-level boundary. Its lower-level managed
server-flight median is 35,099 ns. Coalescing EncryptedExtensions,
Certificate, CertificateVerify, and Finished into one encrypted record removes
three redundant TLSCiphertext overheads (66 wire bytes). Avoiding implicit
initialization and destruction of inactive, tens-of-KiB inline receive buffers,
while continuing to wipe live traffic and handshake secrets, reduced the
same-wire Vail connection median from 67,570 ns to 37,182.5 ns (45.0%).
`zig build -Doptimize=ReleaseFast -Dcpu=native bench-tls-client-connection`
and `zig build bench-rustls-tls-client-connection` measure the corresponding
client path through its encrypted Finished. Each benchmark constructs and
authenticates a complete RFC 7250 Ed25519 raw-public-key server flight once
outside the timer, then measures a fresh client connection generating its
ClientHello, parsing and decrypting the fixed server flight, checking the raw
key pin and CertificateVerify, deriving application secrets, sealing Finished,
and destroying the resulting states. Both fixtures use a 344-byte server
flight with X25519, Ed25519, AES-128-GCM, SNI, and `h2`; rustls's 64-byte
client response contains an optional six-byte compatibility CCS in addition to
the same 58-byte encrypted Finished emitted by Vail. The test-only rustls key
exchange adapter supplies fixed private bytes to AWS-LC so every newly-created
client has the same replayable transcript. Vail reuses its caller-owned
Ed25519 public-key table, just as both sides reuse their client configuration
and parsed trust material outside the timed loop.

Sixteen fixed-CPU-14, order-balanced A-B-B-A runs of independent ReleaseFast
binaries produced these medians:

| TLS 1.3 X25519/Ed25519/AES-128-GCM client through Finished | Median |
| --- | ---: |
| Vail client connection | 53,428 ns |
| rustls/AWS-LC client connection | 70,024 ns |

Vail has 23.70% lower client-handshake latency, or about 1.311x the throughput,
under this boundary. Caller-owned connection initialization and established
state transfer, lazy paged extension duplicate detection, inactive-state
initialization removal, and the reusable Ed25519 verifier reduced Vail's
independently measured median from 103,950 ns to 53,428 ns (48.6%). The latest
caller-owned receive path alone reduced the prior 62,622 ns median by 14.68%.

The `bench-tls-client-x509` and `bench-rustls-tls-client-x509` steps replace
the raw public key with the same RSA-2048 `localhost` certificate, matching
private key, and explicit trust anchor. The timed boundary additionally covers
X.509 parsing, validity, hostname, KeyUsage, EKU, trust-anchor policy, and an
RSA-PSS/SHA-256 CertificateVerify. Both clients consume a 1,326-byte server
flight; Vail emits a 184-byte ClientHello and 58-byte encrypted Finished, while
rustls emits 225 and 64 bytes respectively, the latter again including its
optional compatibility CCS. Sixteen fixed-CPU-14 A-B-B-A samples measured:

| TLS 1.3 X25519/RSA-PSS/AES-128-GCM client with X.509 | Median |
| --- | ---: |
| Vail client connection | 59,753 ns |
| rustls/AWS-LC client connection | 74,360.5 ns |

Vail has 19.64% lower latency, or about 1.244x the throughput. The reusable
`auth.PreparedRsaVerifier` caches the public RSA-2048/65537 Montgomery context
while still checking that each presented certificate contains the configured
key and permits the negotiated PSS scheme. Replacing per-handshake generic
4,096-bit finite-field construction and exponentiation reduced Vail's median
from 279,476 ns to 68,484 ns (75.5%); direct caller-owned established-state
transfer then reduced the prior 68,399.5 ns measured result by another 12.64%.

The matching `bench-tls-server-x509` and
`bench-rustls-tls-server-x509` steps measure a fresh server connection parsing
the same 152-byte ClientHello and producing an X25519/RSA-PSS/AES-128-GCM
first flight with that certificate. Vail emits 1,288 bytes and rustls emits
1,294 bytes; the difference is solely rustls's optional six-byte compatibility
CCS. Sixteen fixed-CPU-14 A-B-B-A samples measured 485,906.5 ns for Vail and
530,194 ns for rustls/AWS-LC. Vail therefore has 8.35% lower latency, or about
1.091x the throughput, for the RSA-authenticated server flight.

`bench-tls-x509-handshake` and `bench-rustls-tls-x509-handshake` extend the
same fixture through a complete in-process handshake: both fresh endpoints are
created, ClientHello and server flight are encoded and consumed, the client
performs full X.509 and CertificateVerify authentication, the client Finished
is protected, and the server verifies it before both application states are
destroyed. The Vail and rustls/AWS-LC wire sizes are respectively 184/225-byte
ClientHellos, identical 1,326-byte server flights, and identical 64-byte client
flights including compatibility CCS. Sixteen fixed-CPU-14 A-B-B-A samples
measured 565,360 ns for Vail and 620,251 ns for rustls/AWS-LC: 8.85% lower
latency and about 1.097x the throughput for Vail.

`bench-versioned-tls-handshake` and
`bench-rustls-versioned-tls-handshake` measure the corresponding full
X.509 handshake with TLS 1.2 and TLS 1.3 enabled at both endpoints. The timed
boundary includes construction and destruction of the version-selecting
states, parsing the shared dual-version ClientHello, discarding the unused TLS
1.2 state and key material, and completing the selected TLS 1.3 handshake.
Both sides negotiate X25519, RSA-PSS/SHA-256, AES-128-GCM, and `h2`; reusable
RSA and trust configuration remains outside the timer. Vail emits a 196-byte
ClientHello while rustls emits 237 bytes, followed by identical 1,326-byte
server and 64-byte client flights.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples measured 560,230.5 ns for
Vail and 620,123 ns for rustls/AWS-LC. Vail therefore has 9.66% lower
dual-version handshake latency, or about 1.107x the throughput. The wrapper
stores both negotiation engines in fixed slots behind a lightweight state tag;
selecting a protocol destroys the unused engine without moving the selected
one. A separate old/new binary A-B-B-A comparison measured 577,290.5 ns before
this layout change and 560,206 ns after it, a 2.96% reduction. Candidate
quartets were retained only when sibling CPU 15 stayed idle throughout and
both target processes stayed within the independently established
non-contended latency envelope.

`bench-quic-tls-handshake` and `bench-rustls-quic-tls-handshake` apply the
same complete-handshake boundary to plaintext QUIC CRYPTO streams. Every timed
iteration creates both endpoints, performs fixed-key X25519 with fixed
ClientRandom/ServerRandom values, authenticates the same RSA-2048 certificate
with RSA-PSS/SHA-256, derives both Handshake and 1-RTT packet-key generations,
exchanges and verifies the client Finished, and destroys both endpoint states.
Configuration, certificate/key parsing, trust anchors, and reusable RSA
private/public Montgomery state remain outside the timer. Both sides select
AES-128-GCM and `h3`, exchange the same fixed opaque transport parameters,
disable certificate compression, and validate completed client and server
states. Vail additionally checks that both endpoints derived identical
directional Handshake and 1-RTT keys. Vail emits 146/90/1,174/36
bytes across the client Initial, server Initial, server Handshake, and client
Handshake levels; rustls emits 195/90/1,178/36 bytes. The ClientHello difference
comes from the implementations' extension offers, not from a different
negotiated algorithm.

Prepared SHA-256 HKDF expansion retains the inner and outer HMAC states while
deriving several labels from the same PRK, and explicitly wipes those states
after the group. A fixed-CPU-14, independent-binary A-B-B-A benchmark of the
QUIC `key`/`iv`/`hp` label group measured 420 ns versus 600 ns for three
separate Zig std expansions, a 30.0% reduction. Use `bench-hkdf-sha256` and
`bench-hkdf-sha256-std` to reproduce that isolated comparison. A separate six-
quartet CPU14 comparison against three raw AWS-LC `HKDF_expand` calls measured
419.833 ns for Vail and 737.833 ns for AWS-LC, giving Vail 43.099% lower
latency and about 1.7574x throughput. Both benchmarks construct the same three
RFC 9001 HkdfLabel values inside the timed region and exclude erasure; their
full-run checksums and the three OpenSSL 3.6.3 fixed-vector outputs agree. Run
`bench-aws-lc-hkdf-sha256` for the test-only AWS-LC side. Each specialized
`Schedule(Hash)` also computes the fixed empty-transcript hash at compile time,
so handshake, application, binder, and exporter derivation do not hash an
empty message again at runtime.

On Linux x86_64 SHA-NI/AVX2 targets, Vail's SHA-256 wrapper retains the SIMD
working state across adjacent complete blocks instead of re-entering Zig std's
single-block compressor for every 64 bytes. One-shot inputs through 55 bytes
use a directly padded block, and larger one-shot inputs fold the final padding
block into the same multi-block loop when possible. The same streaming type is
used by TLS transcripts and the TLS 1.3 key schedule. Other targets and Debug
builds retain Zig std, and prepared HMAC continues to wipe copied keyed state
and intermediate blocks.

Six clean fixed-CPU-14 A-B-B-A old/new quartets measured 52.500 -> 45.500 ns
for a 32-byte digest, 671.250 -> 573.583 ns for a 1 KiB digest, and 738.667 ->
622.667 ns for a prepared 1 KiB HMAC: improvements of 13.333%, 14.550%, and
15.704%. The one-shot and prepared 32-byte HMAC paths were unchanged within
0.084% noise. A separate six-quartet comparison against AWS-LC measured:

| SHA-256 primitive | Vail | AWS-LC | Vail latency |
| --- | ---: | ---: | ---: |
| Digest, 32 B | 45.833 ns | 50.333 ns | 8.940% lower |
| Digest, 1 KiB | 573.667 ns | 581.833 ns | 1.404% lower |
| HMAC, one-shot 32 B | 186.917 ns | 234.917 ns | 20.433% lower |
| HMAC, prepared 32 B | 100.167 ns | 116.333 ns | 13.897% lower |
| HMAC, prepared 1 KiB | 621.500 ns | 648.250 ns | 4.126% lower |

Both independent binaries vary the first input byte on every iteration and
match complete-run checksums plus OpenSSL 3.6.3 fixed vectors. One-shot HMAC
includes key setup on both sides; prepared HMAC setup and destruction remain
outside the timer. Every retained quartet observed zero non-idle scheduler
ticks on sibling CPU 15, and all affected or out-of-envelope quartets were
discarded in full. Use `bench-sha256-primitives` and
`bench-aws-lc-sha256-primitives` to reproduce the comparison.

SHA-384 transcript hashing, TLS 1.2 PRF, TLS 1.3 HKDF, and TLS/QUIC AES-256
key derivation reuse the in-tree SHA-2x64 AVX compressor on supported x86_64
targets. Other targets retain Zig std. Prepared SHA-384 expansion derives the
QUIC `key`/`iv`/`hp` group from one cached ipad/opad pair; sixteen clean CPU14
samples measured 1,514.5 ns versus 3,191 ns for three independent Zig std
expansions, a 52.54% reduction. Use `bench-hkdf-sha384` and
`bench-hkdf-sha384-std` to reproduce that component comparison. Six clean
CPU14 A-B-B-A quartets against three raw AWS-LC `HKDF_expand` calls measured
1,526.333 ns for Vail and 2,507.000 ns for AWS-LC, giving Vail 39.117% lower
latency and about 1.6425x throughput. Both sides construct the same three RFC
9001 labels inside the timed region and match OpenSSL 3.6.3 fixed vectors plus
the complete-run checksum. Use `bench-aws-lc-hkdf-sha384` for the test-only
AWS-LC side.

The accelerated SHA-384/SHA-512 one-shot path feeds complete input blocks
directly to the shared AVX compressor and constructs only the final reusable
padding block. Non-empty whole-block inputs use a secondary internal entry that
keeps the chaining words live while consuming the non-contiguous padding block,
avoiding a second compression prologue, epilogue, and wipe. Prepared HMAC uses
the same fused boundary for its exact-block inner message. The AVX epilogue
wipes its 128-byte schedule with four aligned 32-byte stores. It explicitly
wipes the chaining state and any padding block that contains an input tail; an
exact-block final block contains only public padding and the public input
length. Streaming hashing and portable-target fallbacks are unchanged. Six
clean CPU14 A-B-B-A old/new quartets measured
183.500 -> 180.750 ns for a
64-byte SHA-384 digest, 1,521.583 -> 1,508.583 ns for a 1 KiB SHA-384 digest,
and 1,521.667 -> 1,508.833 ns for a 1 KiB SHA-512 digest, improvements of
1.499%, 0.854%, and 0.843%. The separate 32-byte SHA-512 seed-expansion path
was unchanged and remained within 0.046% noise. Across the complete benchmark,
the retained path also removed about 256.8 million instructions and 21.1
million branches.
Specializing the exact-block finalization boundary later reduced prepared
1 KiB HMAC-SHA-384 from 1,723.917 ns to 1,706.917 ns and HMAC-SHA-512 from
1,720.333 ns to 1,705.250 ns in six clean old/new quartets, improvements of
0.986% and 0.877%. The corresponding digest change was 0.066%, so it is
treated as noise-level rather than a separate throughput claim.

An independent AWS-LC primitive comparison used digest-sized HMAC keys,
varied the first input byte on every iteration, and checked every full-run
checksum plus OpenSSL 3.6.3 fixed vectors. One-shot HMAC includes key setup on
both sides; prepared HMAC initializes and destroys keyed state outside the
timer, then either copies Vail's prepared inner/outer states or resets an
AWS-LC `HMAC_CTX` for every operation. The mean of twelve retained samples per
side from six CPU14 A-B-B-A quartets was:

| SHA-2x64 primitive | Vail | AWS-LC | Vail latency |
| --- | ---: | ---: | ---: |
| SHA-384 digest, 64 B | 180.198 ns | 192.910 ns | 6.589% lower |
| SHA-384 digest, 1 KiB | 1,498.389 ns | 1,510.734 ns | 0.817% lower |
| SHA-512 digest, 32 B specialized | 180.201 ns | 195.165 ns | 7.668% lower |
| SHA-512 digest, 1 KiB | 1,498.367 ns | 1,511.192 ns | 0.849% lower |
| HMAC-SHA-384, one-shot 64 B | 746.750 ns | 816.745 ns | 8.570% lower |
| HMAC-SHA-384, prepared 64 B | 365.627 ns | 413.865 ns | 11.655% lower |
| HMAC-SHA-384, prepared 1 KiB | 1,695.612 ns | 1,729.005 ns | 1.931% lower |
| HMAC-SHA-512, one-shot 64 B | 749.404 ns | 818.886 ns | 8.485% lower |
| HMAC-SHA-512, prepared 64 B | 365.862 ns | 414.864 ns | 11.812% lower |
| HMAC-SHA-512, prepared 1 KiB | 1,691.825 ns | 1,730.433 ns | 2.231% lower |

Every retained quartet observed zero non-idle scheduler ticks on sibling CPU
15; all affected or out-of-envelope quartets were discarded in full. The
1 KiB SHA-384/SHA-512 digest rows now lead by 0.817%/0.849%, while the prepared
1 KiB HMAC rows lead by 1.931%/2.231%. Both harnesses also report picoseconds
per operation so sub-nanosecond differences are not hidden by integer
rounding. Use `bench-sha512-primitives` and `bench-aws-lc-sha512-primitives` to
reproduce the independent binaries.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples of independent
ReleaseFast binaries measured:

| QUIC TLS 1.3 X25519/RSA-PSS/AES-128-GCM full handshake | Median |
| --- | ---: |
| Vail client and server | 528,197 ns |
| rustls/AWS-LC client and server | 610,207 ns |

Vail has 13.44% lower latency, or about 1.155x the throughput. Every retained
sample observed zero non-idle scheduler ticks on sibling CPU 15; affected
A-B-B-A quartets were discarded and replaced in full. Sampling profiles put the
large majority of both implementations' time in their RSA-2048 private
operation, followed by the two X25519 operations, with no unexpected QUIC
adapter hotspot. A separate old/new binary comparison measured 542,495.5 ns
with runtime empty-transcript hashing and 541,962.5 ns with the compile-time
constant, a 0.10% reduction. Directly initializing the first RSA exponent
window, building even table powers with the dedicated square kernel, and
moving the post-CRT check to paired prime fields then reduced a separate
542,291 ns baseline to 528,411.5 ns, a further 2.56%.

`bench-quic-tls-resumption` and
`bench-rustls-quic-tls-resumption` measure a complete QUIC PSK-DHE resumed
handshake followed by plaintext 1-RTT CRYPTO NewSessionTicket rollover. The
initial ticket is prepared outside the timer. Each timed iteration opens and
authenticates the current ticket, verifies its binder and age, performs both
X25519 operations, derives matching Handshake and 1-RTT packet keys, exchanges
and verifies both Finished messages, derives a fresh resumption PSK, seals a
replacement ticket, and caches it for the next connection. Both sides require
every handshake to report resumption and every replacement identity to differ
from its predecessor. Vail emits 329/96/58/36/133 bytes across client Initial,
server Initial, server Handshake, client Handshake, and ticket CRYPTO data;
rustls emits 386/96/58/36/193 bytes.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples measured:

| QUIC TLS 1.3 X25519/PSK/AES-128-GCM resumption plus ticket rollover | Median |
| --- | ---: |
| Vail client and server | 67,334.5 ns |
| rustls/AWS-LC client and server | 99,844.5 ns |

Vail has 32.56% lower latency, or about 1.483x the throughput. All retained
samples observed zero non-idle scheduler ticks on sibling CPU 15. A separate
old/new binary comparison measured 69,843.5 ns before prepared SHA-256 label
groups and 68,248.5 ns after, a 2.28% reduction. The fixed-base update then
reduced 68,191.5 ns to 67,782.5 ns, a further 0.60%. The QUIC
adapter's `writeNewSessionTicket` API keeps resumption-master derivation,
ticket-key rotation, optional ALPS/0-RTT binding, and plaintext handshake
framing in Zig; packet encryption remains the QUIC transport's responsibility.

`bench-quic-tls-0rtt` and `bench-rustls-quic-tls-0rtt` extend that boundary
with accepted early data. Every timed connection derives its client and server
0-RTT packet keys, protects and authenticates a 1,200-byte payload with packet
number 7 and fixed associated data, verifies the plaintext, then completes the
PSK-DHE handshake and replacement-ticket flow above. Vail uses its stateless,
server-bound AES-256-GCM ticket keyring. rustls uses its stateful session cache
because rustls intentionally permits QUIC early data only with stateful
resumption. Both configurations therefore include their production ticket
lookup/refresh mechanism inside the timer. Vail emits 333/96/62/36/141-byte
CRYPTO flights and ticket; rustls emits 278/96/62/36/89 bytes.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples measured 71,630.5 ns for
Vail and 101,624.5 ns for rustls/AWS-LC. Vail has 29.51% lower accepted-0-RTT
latency, or about 1.419x the throughput. Quartets with sibling activity or a
sample outside the established non-contended latency envelope were discarded
in full; every retained sample observed zero non-idle scheduler ticks on CPU
15. Prepared SHA-256 label groups reduced 74,315 ns to 72,490.5 ns; the
fixed-base update then reduced 72,561.5 ns to 72,042.5 ns, a further 0.72%.
Moving the empty-transcript hash from each connection to the specialized
schedule type reduced a separate paired median from 71,922 ns to 71,478 ns,
another 0.62%.

`bench-tls-resumption` and `bench-rustls-tls-resumption` measure a complete
TLS 1.3 PSK-DHE resumed handshake followed by replacement-ticket rollover.
The initial ticket and shared configuration are prepared outside the timer.
Each timed iteration creates fresh client and server states, authenticates the
ticket and ClientHello binder, performs both X25519 operations, exchanges and
verifies both Finished messages, issues an encrypted replacement ticket, and
caches that ticket for the next iteration. Both implementations require every
iteration to report a resumed handshake. Vail emits a 361-byte ClientHello,
216-byte server flight, 64-byte client flight, and 155-byte ticket; rustls emits
416, 212, 64, and 215 bytes respectively.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples of independent
ReleaseFast binaries measured:

| TLS 1.3 X25519/PSK/AES-128-GCM resumption plus ticket rollover | Median |
| --- | ---: |
| Vail client and server | 71,199.5 ns |
| rustls/AWS-LC client and server | 89,091.5 ns |

Vail has 20.08% lower latency, or about 1.251x the throughput. Caller-owned
application-state initialization and the compact `receiveInto` event avoid
implicitly initializing or copying the inactive portions of each roughly 35
KiB inline protected-record receiver. A fixed-CPU old/new binary A-B-B-A
comparison measured 85,339.5 ns for the compatibility wrapper path and 72,847
ns for direct caller-owned transfer, a 14.64% reduction; sampling reduced
`memcpy` from about 15.0% to 3.0% of cycles. The compact single-body X25519
ladder is included in the current result. Prepared SHA-256 label groups reduced
the preceding 72,924.5 ns implementation to 72,007 ns; the fixed-base update
then reduced 72,015 ns to 71,439 ns, a further 0.80%. Compile-time
empty-transcript hashing reduced a separate paired median from 71,136.5 ns to
70,903 ns, another 0.33%.

`zig build -Doptimize=ReleaseFast bench-x509-path` measures bounded unordered
AKI/SKI- and AKI issuer/serial-routed certificate paths, cross-sign
backtracking, issuer/delegated OCSP, and IP or RFC 4518 directoryName-constrained
paths, plus mapped explicit-policy, equivalent-DN issuer, and equivalent-DN
delegated OCSP paths, recursive AIA certs-only issuer retrieval, delta/indirect
CRL selection, conditional CRL-cache refresh, and complete P-521 ECDSA,
RSA-PSS, or RSA PKCS#1 v1.5 SHA3 certificate-plus-OCSP paths. Current pinned
baseline measurements for the RSA-PSS/SHA3-256 and RSA-PKCS1/SHA3-256 paths
are approximately 0.858 ms and 1.365 ms per operation respectively.
`bench-p521-verify` covers all pure-Zig P-521/SHA-512 verifier modes, while
`bench-p521-one-shot` isolates the one-shot path for lower-noise optimization
A/B runs, `bench-p521-prepared` isolates the ordinary prepared path,
`bench-p521-sign` measures the constant-time pure-Zig signer,
`bench-p521-ecdh` separates public-key recovery from one-shot ECDH, and
`bench-aws-lc-p521` is the test-only AWS-LC comparison. Interleaved
ReleaseFast runs pinned to one performance core currently measured medians of
about 0.240 ms for Vail's raw one-shot API, 0.244 ms for its parsed-key API,
0.235 ms for its compact API, 0.202 ms for its ordinary prepared API, 0.199 ms
for its explicit throughput API, and 0.250 ms for AWS-LC. In fifteen
alternating independent-binary one-shot rounds, the earlier Vail path measured
242,144 ns versus 249,978 ns for AWS-LC. After specializing cached-table
construction for its guaranteed-distinct operands, six clean CPU-14 ABBA
quartets (twelve runs per implementation) reduced Vail from 242,227.5 ns to
241,878.3 ns (0.144%), while ten isolated compact-table initialization quartets
reduced 9,459.8 ns to 9,289.2 ns (1.80%). Recognizing that the first cached
point is already affine avoids recomputing its known `Z`, `Z^2`, and `Z^3`:
another ten clean initialization quartets measured 9,282.5 ns before and
9,198.8 ns after (0.90%), while six one-shot quartets measured 242,135.4 ns
before and 241,935.7 ns after (0.083%) and retired about 874 fewer instructions
per verification. Replacing dense wNAF arrays with bounded sparse entries
reduced one-shot verification from 241,790.9 ns to 239,763.0 ns (0.839%) and
ordinary prepared verification from 205,066.6 ns to 203,247.8 ns (0.887%) in
six clean quartets each. Passing cached and affine signed-wNAF entries by
reference then reduced one-shot verification from 239,659.0 ns to 239,264.5 ns
(0.165%) and ordinary prepared verification from 203,065.6 ns to 201,853.8 ns
(0.597%). A fresh six-quartet comparison measured 239,539.3 ns for Vail versus
249,757.6 ns for AWS-LC, a 4.09% lead. The prepared and throughput leads are
about 19.2% and 20.6% respectively. The width-12 fixed generator table
adds about 121 KiB to the benchmark ELF without increasing any caller-owned
verifier object. Since every `PublicKey` constructor stores normalized affine
coordinates with `Z=1`, SEC1 serialization now encodes X and Y directly instead
of performing a redundant projective inversion. Twelve clean CPU-14 A-B-B-A
samples reduced uncompressed encoding from 2,955.0 ns to 210.7 ns (92.87%) and
compressed encoding from 2,832.9 ns to 105.1 ns (96.29%), without increasing
the 216-byte public-key representation. Use `bench-p521-public-key` to
reproduce this comparison boundary.
The wNAF loops call their mixed/cached additions only for non-zero digits, so
ReleaseFast omits the redundant table-entry identity branch while ReleaseSafe
retains the contract assertion. Coefficient-ordered squaring and narrow carry
propagation reduced the previous roughly 294 us one-shot path by about 17%.
Alternative `2YZ`, forced-inline multiplication, branchless-identity doubling,
wider one-shot windows, and one-shot affine-table candidates were measured and
reverted. Shared `dblAssign`/`addCached` branch hints improved one-shot
verification by 0.435% but regressed ordinary prepared verification by 0.959%;
the `addCached`-only split was noise-level and both variants were removed.
P-521 ECDH uses the four-group constant-time comb on portable targets. Linux
x86_64 BMI2/ADX builds instead use an embedded, formally verified s2n-bignum
Jacobian scalar-multiplication schedule and normalize the shared x-coordinate
directly in the native 9-limb field representation. AVX2-capable builds scan
all 16 Jacobian table entries in order. YMM equality masks feed memory-source
`vpand` operations and `vpor` accumulation for all 27 limbs, avoiding the
shuffle-port pressure of `vpblendvb`; BMI2/ADX-only builds retain the scalar
`cmov` scan. The complete scratch region, caller-visible registers, and vector
registers are cleared before return. Six clean CPU14 A-B-B-A quartets measured
70,108.1 ns for Vail public-key recovery versus 129,103.3 ns for AWS-LC, a
45.696% latency reduction or about 1.84x throughput.
Replacing `vpblendvb` reduced one-shot shared-secret derivation from 169,114.2
ns to 168,294.5 ns (0.485%) across six clean CPU14 quartets. A fresh
six-quartet comparison separated both setup boundaries: the raw-private-key
path measured 168,083.1 ns for Vail versus 303,588.6 ns for AWS-LC, giving
Vail 44.635% lower latency. The caller-owned 72-byte `PreparedEcdhSecret`
measured 168,101.6 ns versus 175,707.6 ns for AWS-LC's parsed private key,
giving Vail 4.329% lower latency. The earlier vector table selection had
reduced Vail's prior 174,489 ns median by 3.1%. Removing the
post-multiplication identity check reduced code size but improved the clean mean
by only 0.045% after excluding an outlier and slightly increased retired
instructions, so the fault check remains.
Use `bench-p521-ecdh` and `bench-aws-lc-p521-ecdh` to reproduce these isolated
measurements.
The initial P-521 signing path was reduced from about 1.41 ms to a median of
109,601 ns through deferred canonical reduction, a four-table 6-bit fixed-base
comb, affine precomputation, branchless mixed additions, an explicit no-inline
boundary around the doubling kernel, and x-only nonce-point normalization. On
x86_64, nonce inversion now reuses the formally verified generic s2n-bignum
fixed-round modular-inverse schedule with a nine-limb invocation; its 27-limb
scratch space and the ordinary/Montgomery conversion temporaries are explicitly
cleared. Other targets retain the constant-time exponentiation chain that
builds the order exponent's leading 262 one-bits as a Mersenne block before
applying a width-5 tail window. A separate fixed 21-round divstep inversion
schedule derived from s2n-bignum accelerates P-521 field normalization used by
signing, key generation, ECDH, and prepared verification. SHA-512 signing and
verification reuse the same in-tree AVX compressor as Ed25519.
Linux
x86_64 builds with AVX2, BMI2, and ADX use a fixed 9-limb Montgomery kernel
embedded in the Zig source; its product and reduction rounds are fully expanded and
carry overflow is retained between reduction rows. Other targets use the
portable Zig constant-time kernel. Fixed-base tables use a limb-major
eight-lane Zig vector layout: selection still scans all 64 entries, while
contiguous compare/mask/OR operations replace scalar AoS loads without
introducing secret-indexed memory access.
The coefficient-ordered constant-time field square, narrow carry propagation,
and scalar Montgomery kernel first reduced the single-signature path from
about 154.5 us to 109,601 ns. Replacing the scalar exponentiation with the
generic fixed-round inverse then reduced a random-nonce end-to-end mean from
111,771.0 ns to 77,084.1 ns, or 31.034%, across six clean CPU14 A-B-B-A
quartets. The corrected comparison uses the same 10,000 iterations, message,
SHA-512 hashing, DER encoding, and fresh system randomness on both sides. Six
more clean quartets measured 76,400.5 ns for Vail and 126,686.6 ns for AWS-LC,
giving Vail 39.693% lower latency and about 1.6582x throughput.
`interop-openssl-p521-sign`
generates PKCS#8 with OpenSSL, parses and signs it in Zig, then independently
verifies the pure-Zig signature with OpenSSL.
`interop-openssl-p521-server` extends that oracle through a complete TLS 1.3
handshake: Vail loads the generated PKCS#8 key and X.509 certificate, emits
`ecdsa_secp521r1_sha512` CertificateVerify over a P-521 ECDH handshake, and
OpenSSL authenticates it.
`interop-openssl-tls12-p521-server` exercises the corresponding TLS 1.2
ECDHE-ECDSA server path with both the ephemeral share and certificate on
P-521.
`interop-rustls-p521-server` and `interop-rustls-tls12-p521-server` exercise
the same two server directions with rustls/AWS-LC. Their custom test trust
policy skips chain trust only; CertificateVerify is now authenticated by
rustls's actual AWS-LC signature verifier rather than an assertion stub.
The same benchmark reports deterministic nonce preparation separately at about
74.3 us and the online `signPrepared` portion at about 639 ns. Prepared inverses,
the cached private scalar, and batch prefix/suffix products remain in the
Montgomery domain until the final signature conversion; an isolated
eleven-round A/B reduced the online path from 1,141 ns by about 24%, with all
rounds faster. This is a latency mode for callers that maintain a pool of fresh
one-use nonces; the 76,400.5 ns random-nonce single-signature result remains the
direct comparison.
For sustained signing, `prepareNonceBatch` validates a bounded batch of up to
64 distinct nonces, computes every `r` with one field inversion, and derives
all scalar inverses with one Montgomery inversion plus prefix/suffix products.
Batch-8 deterministic preparation now measures about 68.6 us per nonce, while
the complete random-nonce prepare-plus-sign path measures about 69.8 us per
signature versus 126,686.6 ns for repeated AWS-LC signing, about a 1.81x
throughput lead. The field batch inversion and Montgomery-resident scalar chain
improve Vail's previous 110,592 ns/sign baseline by about 37%.
Duplicate or malformed nonces abort before committing any output;
`prepareRandomNonceBatch` fills the same transactional API directly from
`std.Io.randomSecure`.
An XYZZ secret-point candidate passed the group and signature oracles but made
single signing about 2.3% slower in all eleven paired rounds; its extra
doubling products outweighed the mixed-add square savings, so it was removed.
Unscaled Jacobian addition, reusing Karatsuba multiplication for squaring, a
Mersenne-specific subtraction correction, a wider 4x7-bit comb, and a grouped
low-register-pressure SIMD scan were also rejected after their focused
benchmarks regressed.
Run `zig build -Doptimize=ReleaseFast -Dcpu=native bench-p521-sign-one-shot`
and `zig build bench-aws-lc-p521-sign` for the symmetric random-nonce
single-signature comparison; `bench-p521-sign` reports the detailed prepared
and batch modes.
Computing the inverse directly from the Montgomery-domain nonce and correcting
it with one `R^3` multiplication retired about 1,294 more instructions per
signature, but a longer 10,000-signature A-B-B-A comparison regressed the mean
by 0.423% and only three of six quartets favored it, so that candidate was
removed.
Reusing the compact
verification table across a certificate and its issuer-signed OCSP response
reduces that complete path from roughly 1.56 ms to 0.92 ms.
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
constant-time RSA-2048 PSS and PKCS#1 v1.5 signing paths for SHA-2 and SHA3,
while `bench-aws-lc-rsa` is the independent test-only AWS-LC comparison.
`zig build interop-openssl-rsa-sha512-truncated-sign` checks pure-Zig
SHA-512/224 and SHA-512/256 PSS and PKCS#1 v1.5 signatures with OpenSSL; the
unit fixtures cover the reverse OpenSSL-to-Zig direction.
`zig build interop-openssl-rsa-shake-sign` uses OpenSSL's raw RSA operation to
recover pure-Zig RSA-PSS-SHAKE128/256 encodings and compares them byte-for-byte
with independently generated RFC 8692 fixtures.
SHA3-256 has essentially the same private-operation cost as SHA-256.
RSA-2048 CRT exponentiation uses a dedicated 16-limb, full-64-bit Montgomery
field. On Linux x86_64 targets with AVX2, BMI2, and ADX, fixed-shape assembly
embedded in the Zig source computes paired full products, coefficient-ordered squares,
Montgomery reductions, and final conditional reductions. Cross terms in a
square are multiplied once, while alternating ADX carry registers remove a
serial move from every reduction limb. Other targets retain the paired FIOS
kernel, which merges multiplication and Montgomery reduction into one limb
scan and interleaves the independent `mod p` and `mod q` chains. The retained
CIOS kernel serves as a differential oracle. A constant-time five-bit table is
selected in one paired full scan without changing its secret-independent access
pattern. Its leading four-bit window initializes the accumulator directly,
eliminating four identity squares and one identity multiply; dedicated squares
generate the even powers in the per-signature table.
Compiler barriers keep the selection and final modular reductions as mask
operations in optimized machine code instead of allowing LLVM to introduce
secret-dependent branches or table loads. The two final prime-field reductions
are interleaved, and reusable multiplication workspaces are reset between
products but securely wiped once at the private-operation boundary. Within
each FIOS limb, completing one residue's product/reduction chain before the
other reduces condition-flag spills while retaining inter-prime scheduling
freedom across the full loop. Prepared prime contexts also cache Montgomery
`1`, removing one full paired conversion from every signature. The mandatory
post-CRT fault check reduces the final recombined signature modulo both private
primes, evaluates the fixed 65537 addition chain with the same paired kernels,
and compares both residues with the original message. For canonical values
below `n = p*q`, this is equivalent to the former full-modulus check while
retaining detection of recombination faults. Uncommon public exponents and
3072- or 4096-bit keys retain the generic pure-Zig full-modulus path.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples of independent binaries
measured 439,614.5 ns for Vail RSA-PSS/SHA-256 against 479,391.5 ns for AWS-LC,
an 8.30% latency reduction. The PSS timing includes fresh secure-random salt
generation on both sides. The corresponding PKCS#1 v1.5 medians were 440,716 ns
and 477,349.5 ns, a 7.68% reduction. The earlier generic pure-Zig path measured
about 3.08 ms for either encoding. Fusing Montgomery reduction and final
conditional reduction improved an isolated long-run RSA median from 442,708 ns
to 440,320.5 ns, but regressed the complete QUIC handshake from 528,303.5 ns to
530,961 ns, so the smaller staged implementation remains. Register-resident
loop counters, an interleaved CRT power table, extra loop alignment, and
removing the intermediate `vzeroupper` were likewise rejected after paired
measurements failed to improve the end-to-end or low-noise result. Routing the
sparse wide-reduction multiply through the full-product ADX kernel regressed
the RSA median by about 0.5%; a hand-written AVX2 selector and a source-level
first-entry shortcut also failed their low-noise gates. The retained selector
therefore remains the compiler's compact mask-and-scan implementation, with an
exhaustive 0-through-31 index test alongside the multiplication oracle.
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
`bench-tls12-handshake` and `bench-rustls-tls12-handshake` measure a complete
fresh TLS 1.2 handshake in process. Their `-pss` variants select RSA-PSS instead
of RSA PKCS#1 v1.5. Both sides reuse parsed RSA-2048 identity and configuration
state, use fixed client/server randoms and P-256 private keys, negotiate
ECDHE-RSA with SHA-256, Extended Master Secret, `h2`, and AES-128-GCM,
authenticate ServerKeyExchange, exchange and verify both Finished messages,
and destroy both connection states inside the timed loop. Vail emits 108-,
1,263-, 126-, and 51-byte flights; rustls emits 123, 1,289, 126, and 51 bytes
respectively for either signature encoding.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples measured:

| Complete TLS 1.2 P-256/RSA-2048/AES-128-GCM handshake | Vail | rustls/AWS-LC |
| --- | ---: | ---: |
| RSA-PKCS1-SHA256 | 579,649 ns | 619,935 ns |
| RSA-PSS-SHA256 | 578,738.5 ns | 622,390 ns |

Vail has 6.50% lower PKCS#1 latency and 7.01% lower PSS latency, or about
1.070x and 1.075x the throughput. Reusing the certificate-bound
RSA-2048/65537 Montgomery verifier for TLS 1.2 and moving the roughly 24 KiB
handshake states plus 34 KiB established states through caller-owned
initialization/transition APIs reduced Vail's initial 813,887.5 ns PKCS#1
median by 28.78%.

The dedicated AES-256-GCM/SHA-384 variant keeps the same P-256/RSA-PKCS1
handshake boundary. Sixteen clean fixed-CPU-14 samples measured 561,726.5 ns
for Vail and 619,450.5 ns for rustls/AWS-LC, giving Vail 9.32% lower latency.
Switching Vail's transcript and PRF from Zig std SHA-384 to the shared AVX
backend reduced a separate 32-sample median from 564,936.5 ns to 562,325 ns
(0.46%); the much larger RSA private operation dominates this full-handshake
measurement. Use `bench-tls12-handshake-aes256` and
`bench-rustls-tls12-handshake-aes256` to reproduce it.

`bench-tls12-resumption` and `bench-rustls-tls12-resumption` measure stateless
RFC 5077 ticket resumption with replacement-ticket rollover.
`bench-tls12-session-resumption` and
`bench-rustls-tls12-session-resumption` measure stateful session-ID reuse. Initial
ticket or session state is prepared outside the timer, and both implementations
perform 20,000 resumed handshakes per process to keep frequency ramp and timer
noise below the comparison margin. Every timed iteration creates fresh client
and server states, derives new record keys from the cached master secret and
fresh randoms, and verifies both Finished messages. Ticket mode additionally
authenticates a ticket, issues a distinct replacement, and caches it for the
next iteration. Vail emits 240/275/51-byte ticket flights and a 96-byte opaque
ticket versus rustls's 319/329/51 bytes. Session-ID mode emits 140/160/51 bytes
for Vail and 159/150/51 bytes for rustls.

Sixteen fixed-CPU-14, order-balanced A-B-B-A samples measured:

| Complete TLS 1.2 resumed handshake | Vail | rustls/AWS-LC |
| --- | ---: | ---: |
| Ticket rollover | 9,901.5 ns | 14,380 ns |
| Session-ID reuse | 8,488.5 ns | 11,183.5 ns |

Vail has 31.14% lower ticket-rollover latency and 24.10% lower session-ID
latency, or about 1.452x and 1.317x the throughput. The client and server now
use their handshake stage as the ownership discriminator for already-destroyed
pending state. This removes a redundant whole-payload optional clear after the
owned secrets, traffic keys, transcript buffers, and peer data have already
been individually destroyed or transferred. An independent old/new binary
A-B-B-A check reduced session-ID latency by about 14.1%; the same change
reduced the previous 11,391 ns ticket median by about 13.1% without weakening
secret erasure.

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
`interop-openssl-ccm-server`, `interop-openssl-ccm-client`,
`interop-openssl-ccm8-server`, and `interop-openssl-ccm8-client` force the
16-byte- and 8-byte-tag AES-CCM suites in both directions and verify the
complete handshake and protected application-data exchange against OpenSSL.
CCM-8 remains explicit opt-in and is rejected by QUIC key derivation because
QUIC packet protection requires a 16-byte authentication tag.
`zig build interop-vail-sm4-ccm` performs a complete
`TLS_SM4_CCM_SM3` handshake and protected application-data exchange between
the pure-Zig client and server harnesses. The local OpenSSL 3.6 provider
exposes the SM4-CCM primitive but not this RFC 8998 TLS cipher suite, so the
independent primitive oracle remains the RFC 8998 Appendix A.2 vector.
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
`interop-openssl-p521-client` and `interop-openssl-tls12-p521-client` force
OpenSSL P-521/SHA-512 CertificateVerify in complete TLS 1.3 and TLS 1.2
connections respectively, exercising Vail's pure-Zig verifier rather than a
foreign crypto provider.
`zig build interop-rustls-min-client` exercises Vail's client against a
zlib-enabled rustls server and requires Vail to authenticate a compressed
Certificate message before exchanging application data.
`zig build interop-rustls-cert-signatures-client` additionally sends a
dedicated TLS 1.3 `signature_algorithms_cert` offer and requires the Vail
client to enforce it while completing a handshake with rustls/AWS-LC.
`zig build interop-openssl-cert-signatures-mtls-server` exercises the reverse
direction: Vail constrains signatures on the client certificate chain in its
CertificateRequest and authenticates the resulting OpenSSL mTLS flight.
`zig build interop-rustls-rpk-server` and
`zig build interop-rustls-rpk-client` exercise mutual TLS 1.3 RFC 7250 Raw
Public Key authentication in both directions against rustls 0.23 with its
AWS-LC provider. Both peers send a single DER SubjectPublicKeyInfo, verify
RSA-PSS CertificateVerify possession, pin the peer SPKI exactly, and exchange
encrypted application data.
`interop-rustls-mldsa-rpk-server` and
`interop-rustls-mldsa-rpk-client` repeat mutual RPK authentication with
ML-DSA-44/65/87, using identical deterministic FIPS 204 seeds to cross-check
Zig std's public keys and signatures against AWS-LC.
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
TLS 1.2 AEAD suites, both RSA and ECDSA authentication, and
P-256/P-384/P-521 ECDHE.
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
