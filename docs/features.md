# Feature catalog

This file preserves the detailed feature inventory that used to live in the README. It is intentionally exhaustive; see `docs/compatibility.md` for the concise matrix.

`vail` is a Zig 0.16 cryptographic protocol library. Its target is to provide
a pure-Zig TLS/X.509 stack whose safety, protocol coverage, modularity, and
performance exceed mature stacks such as s2n-tls and rustls.

The current foundation provides:

- domain-separated HMAC-SHA256 and constant-time tag verification;
- fixed-size SHA-256 and SM3 digests, portable SM2 signing/verification,
  SM4 block/SM4-GCM primitives, and explicit secure-memory wiping;
- `crypto.memory.zeroAlignedSlice32` for variable-length aligned scratch:
  volatile 32-byte stores clear complete blocks and the existing byte helper
  clears a partial tail, with canary checks covering the exact supplied span;
- the dependency-free `archive_crypto` subpackage, including resumable
  Traditional PKZIP/ZipCrypto byte-stream state with explicit
  caller-supplied header entropy, password verification, allocation-safe
  one-shot helpers, and key/header wiping, plus WinZip AE-1/AE-2
  PBKDF2-HMAC-SHA1 key derivation, AES-128/192/256 little-endian CTR,
  HMAC-SHA1-80 authentication, explicit caller salt, constant-time verifier/
  tag checks, allocation-safe helpers, and secure state clearing. The same
  subpackage also provides the password-based AES-128/192/256 subset of
  PKWARE Strong Encryption: SHA-1/CryptDeriveKey-compatible master and file
  keys, resumable AES-CBC, bounded block-streaming file encryption/decryption,
  final-block PKCS#7 withholding, explicit caller entropy, allocation-safe
  protocol helpers, and secure key/state clearing. Archive-specific modules
  additionally provide RAR4 SHA-1/AES-128-CBC, RAR5 extended
  PBKDF2-HMAC-SHA256/AES-256-CBC with keyed checksum transforms, and 7zAES
  UTF-16LE/SHA-256 key derivation plus resumable AES-256-CBC. Wire records,
  padding policy, IV allocation, and archive integrity checks remain owned by
  the calling archive library;
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
  from CertificateVerify when selecting or authenticating X.509 chains. A
  client sends its identity only when the signing algorithm, certificate chain,
  and acceptable CA names all match the request; otherwise it emits the
  RFC-required empty Certificate message. Unknown CertificateRequest
  extensions are ignored for forward compatibility, while duplicate extension
  types remain fatal across the complete 16-bit namespace without imposing an
  arbitrary extension-count ceiling; malformed known extensions also remain
  fatal. Repeated values inside TLS 1.2/1.3 ClientHello and TLS 1.3
  CertificateRequest signature-algorithm vectors remain acceptable as RFC 5246
  and RFC 8446 permit. A present certificate-authorities extension must contain
  at least one non-empty DistinguishedName; servers omit it when any issuer is
  acceptable. RFC 8446 OID filters are encoded with duplicate-OID rejection;
  clients reject repeated recognized filters, and recognized Key Usage and
  Extended Key Usage values constrain the end-entity certificate, including
  subset matching and the prohibition on requesting anyExtendedKeyUsage, while
  unknown OIDs are ignored. CertificateRequest accepts the standard empty
  status-request signal, rejects non-empty forms and every recognized extension
  prohibited in that message, and still ignores genuinely unknown extensions.
  Client identities may carry a leaf or per-chain-entry OCSP staple; clients
  send it only when requested, servers reject unsolicited staples, and requested
  responses reach the trust verifier with their certificate-entry association.
  Servers preflight all nested request-vector lengths
  and filter semantics before emitting ServerHello, so invalid configuration
  cannot leave a partial flight. Initial-handshake
  CertificateRequest context is required to be empty; the generic codec still
  preserves non-empty contexts for post-handshake authentication. Per-identity
  OCSP and precompressed Certificate variants remain attached to the selected identity;
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
  allocation-free multi-identity parsing, index-aligned binder validation,
  later-identity ServerHello selection, ticket-age validation, and stateless
  tickets bound to their issuing suite, server identity, and ALPN. Authenticated
  NewSessionTicket messages can be converted directly into owned client cache
  entries; their extension parser covers the complete 16-bit type namespace,
  rejects duplicates, the RFC-forbidden 65,535-byte vector, and recognized
  extensions misplaced outside their permitted messages, while retaining
  forward compatibility for genuinely unknown extensions. The shared TLS
  codec preserves any RFC 8446 `max_early_data_size`, including finite and zero
  limits, while QUIC entry points separately enforce RFC 9001's `0xffffffff`
  sentinel. A zero-lifetime ticket remains valid on the wire but returns a
  distinct discard result before any cache allocation. Client caches, PSK age
  validation, and both stateless ticket formats agree that a ticket expires at
  the exact advertised lifetime boundary and reject clocks before issuance;
  an otherwise live ticket whose reported age exceeds the configured skew
  tolerance still resumes at 1-RTT while 0-RTT is rejected. Resumption may
  likewise negotiate another cipher suite using the ticket's transcript hash,
  while 0-RTT additionally requires the original suite and ALPN context.
  RFC 9149 ticket
  requests distinguish new and resumed handshakes,
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
  over X25519, P-256, P-384, or native P-521, require Extended Master Secret
  and RFC 5746 signaling,
  authenticate ephemeral parameters with RSA-PSS or ECDSA using TLS 1.2's
  hash-only signature-scheme semantics; RSA PKCS#1 v1.5 remains available for
  compatible TLS 1.2 peers while being rejected in TLS 1.3. The states verify
  both Finished messages, retain
  authenticated peer identity/ALPN on the client, and transition to
  bidirectional application records. Handshake-time TLS 1.2 client
  authentication supports required or optional certificates, authenticates
  the client chain through the configured trust policy, verifies
  CertificateVerify possession, and transfers an owned peer chain into the
  established server state. Clients select an identity only when its signing
  key, TLS certificate type, and X.509 issuer match CertificateRequest; when
  none is suitable they send the RFC-required empty Certificate message.
  Server requests advertise P-521 alongside the other supported signing
  schemes and reject CertificateVerify messages using an algorithm outside
  that advertised set. Stateful TLS 1.2 session-ID resumption uses the
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
  packet keys. Resumption authenticates the selected PSK binder from a complete
  multi-identity offer and can fall back to a full certificate handshake.
  QUIC 0-RTT derives matching
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

