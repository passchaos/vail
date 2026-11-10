# Security model

Vail is a cryptographic protocol library. This document describes the security
properties the implementation aims to provide, the assumptions it makes, and
the areas that require independent review.

## Threat model

Vail assumes a network attacker who can read, modify, replay, drop, and reorder
traffic, and who may present arbitrary certificates or handshake messages. It
also assumes that peer inputs are untrusted and may be malformed, oversized, or
chosen to exercise edge cases.

Vail does not protect against:

- a compromised local process, allocator, or operating system;
- physical access to memory or hardware;
- faults injected into the CPU or memory;
- misuse of the API, such as reusing a nonce or exposing secret buffers;
- side channels outside the implemented constant-time boundaries.

## Constant-time policy

- Secret-dependent code paths use fixed-schedule arithmetic, full-table
  selection, and branchless masking.
- Secret-dependent branches and table indices are avoided in the reviewed
  secret paths.
- Public-input operations (for example, signature verification) may use
  variable-time algorithms.
- Embedded assembly is derived from formally verified schedules where noted in
  the file headers; local modifications must preserve the constant-time
  contract.

This is an engineering policy, not a formal verification of the entire library.
New code touching secrets requires targeted review and, where practical, paired
benchmarks or instruction-trace checks.

## Secret lifetime and zeroization

- Callers own long-lived keys and buffers.
- Temporary secrets are wiped with `crypto/memory.zig` or
  `std.crypto.secureZero`.
- Prepared contexts document what they cache and when it is wiped.
- Handshake states wipe unused version-specific key material when a protocol
  version is selected.

Zeroization reduces exposure but cannot guarantee that a compiler, runtime, or
hardware has not copied a secret elsewhere. Treat it as defense in depth.

## Randomness

Vail does not embed a global RNG. Callers provide randomness through explicit
APIs (for example, TLS signing nonces and ticket keys). Reusing a nonce or
providing predictable randomness breaks the security guarantees of the
corresponding algorithm.

## Platform and assembly

- x86_64 and AArch64 acceleration is selected at compile time from target CPU
  features.
- Debug and ReleaseSmall builds retain portable implementations as independent
  oracles.
- Embedded s2n-bignum, mlkem-native, BoringSSL/AWS-LC, and OpenSSL assembly is
  documented in [`third-party.md`](third-party.md) and in per-file SPDX headers.

## Limitations

- Vail is not FIPS-certified.
- The library does not claim TLS 1.0/1.1 or SSLv3 support.
- Some archive formats implement only the password-based cryptographic subset;
  archive integrity and container parsing remain the caller's responsibility.
- Benchmark results are not security evidence; see [`benchmarks.md`](benchmarks.md).

## Reporting vulnerabilities

See [`../SECURITY.md`](../SECURITY.md). Do not open a public issue for a
suspected vulnerability.
