# Benchmarks

Vail's benchmark claims are intentionally scoped. Results are host-, workload-,
and boundary-specific; they are not a universal "fastest library" claim.

## Methodology

- Independent ReleaseFast binaries for each implementation.
- Fixed CPU affinity and order-balanced A-B-B-A quartets where practical.
- Warmups and timed loops use identical inputs, nonce construction, and buffer
  ownership on both sides.
- Complete-run checksums, fixed vectors, and interoperability oracles verify
  that both sides compute the same output.
- Scheduler-contaminated samples are discarded; retained quartets record zero
  non-idle ticks on the sibling CPU where applicable.
- Candidate optimizations are kept only when paired measurements beat the
  noise envelope and correctness checks still pass.

## Commands

```sh
zig build bench
zig build bench-tls-client-connection
zig build bench-sha256-primitives
zig build bench-aws-lc-sha256-primitives
zig build bench-rustls-tls-client-connection
```

AWS-LC and rustls reference harnesses require Cargo and their native build
prerequisites. See [`../bench/README.md`](../bench/README.md).

## Representative results

These numbers are from the repository's current performance log. They are
representative medians, not a complete matrix.

| Boundary | Vail | Reference | Result |
| --- | ---: | ---: | --- |
| TLS 1.3 server first flight | 37,182.5 ns | rustls/AWS-LC 50,493 ns | 26.36% lower latency |
| TLS 1.3 client through Finished | 53,428 ns | rustls/AWS-LC 70,024 ns | 23.70% lower latency |
| TLS 1.3 client + X.509 | 59,753 ns | rustls/AWS-LC 74,360.5 ns | 19.64% lower latency |
| TLS 1.2 full handshake (PKCS#1) | 579,649 ns | rustls/AWS-LC 619,935 ns | 6.50% lower latency |
| AES-128-GCM seal (x86_64) | 187.5 ns | AWS-LC 241 ns | 1.29x |
| SHA-256 1 KiB | 573.7 ns | AWS-LC 581.8 ns | 1.4% lower latency |
| ARM64 X25519 fixed-base | 7,829 ns | AWS-LC 9,915 ns | 21.0% lower latency |
| ARM64 P-256 prepared verify | 15,520.5 ns | AWS-LC 49,135 ns | 68.4% lower latency |
| ML-DSA-44 prepared-key verify | 7,696.5 ns | AWS-LC 22,480.6 ns | 2.92x |

The full dated log, including rejected optimizations and noise analysis, is in
[`benchmarks/performance-log.md`](benchmarks/performance-log.md).

## Caveats

- Most measurements are from a Jetson AGX Thor ARM64 host or an i9-13900K
  x86_64 host, with fixed CPU affinity.
- Payload sizes and API boundaries are chosen per benchmark (for example,
  1,200-byte QUIC payloads or 1 KiB digests).
- Prepared-verifier results exclude preparation time; they are not one-shot
  claims.
- Cross-process and real-network results are sensitive to scheduling and are
  not used for causal performance claims.
- Small differences (roughly 1% or less) should be treated as noise unless a
  paired study says otherwise.

## Recording new results

Record the commit SHA, host, CPU, Zig version, optimize mode, benchmark step,
reference implementation version, payload, command, and raw output. Put dated
logs under `docs/benchmarks/` and keep this summary page short.
