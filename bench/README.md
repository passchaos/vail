# Benchmarks

This directory contains Vail's microbenchmarks and reference-implementation
harnesses.

## Layout

- Top-level `*.zig` files are individual benchmark programs.
- `mldsa/` and `mlkem/` contain shared benchmark helpers and parameter-set
  variants.
- `rustls_client_hello/`, `rustls_min_client/`, and `rustls_min_server/` are
  Rust reference projects. Their `target/` directories are local build
  artifacts and are ignored by Git.
- `testdata/` contains fixed inputs and signatures.

## Prerequisites

- Zig `0.16.x` and the sibling `vort` package.
- Cargo and a C toolchain for the rustls/AWS-LC reference harnesses.
- OpenSSL on `PATH` for interoperability steps.
- A quiet host with CPU affinity available for meaningful latency comparisons.

## Commands

```sh
zig build bench
zig build bench-tls-client-connection
zig build bench-sha256-primitives
zig build bench-aws-lc-sha256-primitives
zig build bench-rustls-tls-client-connection
```

The root `zig build bench` step depends on every step whose name starts with
`bench-`. Use individual steps when you want a focused measurement.

## Methodology

- Build independent ReleaseFast binaries for each side.
- Pin processes to a fixed CPU and use order-balanced A-B-B-A runs.
- Keep inputs, nonce construction, buffer ownership, and timed boundaries
  identical across implementations.
- Verify complete-run checksums and fixed vectors; use interoperability oracles
  where possible.
- Discard scheduler-contaminated samples and report the noise envelope.
- Treat prepared-verifier results as online-only; preparation time is separate.

## Recording results

Record the commit SHA, host, CPU, Zig version, optimize mode, payload, command,
reference version, and raw output. Add dated logs under `docs/benchmarks/` and
keep the summary in `docs/benchmarks.md`.
