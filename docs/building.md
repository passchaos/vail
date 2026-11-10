# Building and testing

## Requirements

- Zig `0.16.x`.
- The sibling `vort` package checked out next to this repository. The current
  `build.zig.zon` uses a path dependency at `../vort`.
- Cargo, a C toolchain, and OpenSSL only when building the optional AWS-LC,
  rustls, or OpenSSL interoperability/benchmark harnesses.

## Common commands

| Command | Purpose |
| --- | --- |
| `zig build` | Build and install the static library |
| `zig build test` | Run Vail and package API tests |
| `zig build test-compile` | Compile tests without running them |
| `zig build test-all` | Run Vail, package, signature-primitive, and archive tests |
| `zig build check` | Run `zig fmt --check` and `test-all` |
| `zig build fmt` | Format Zig sources |
| `zig build bench` | Run every benchmark step |
| `zig build interop` | Run every interoperability step |

Individual benchmark and interoperability steps are still available, for
example `zig build bench-tls-client-connection` or
`zig build interop-openssl-p384-sign`.

## Cross-compilation

Use the standard Zig target options:

```sh
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast
zig build -Dtarget=x86_64-linux-gnu -Dcpu=native -Doptimize=ReleaseFast
```

Accelerated kernels are selected from the target CPU features. Debug and
ReleaseSmall builds retain portable implementations as independent oracles.

## Archive subpackage

`archive_crypto` has its own `build.zig` and no dependencies:

```sh
cd archive_crypto
zig build test
```

The root `zig build test-all` also compiles and runs the archive tests.

## Benchmarks and interoperability

The reference harnesses under `bench/rustls_*` and the AWS-LC comparisons
require Cargo and their native build prerequisites. See
[`../bench/README.md`](../bench/README.md) for layout and commands.

OpenSSL interoperability steps assume an `openssl` executable on `PATH`. Some
steps use fixed local ports and should not run concurrently with another
interoperability job.

## Generated tables

Generated tables are checked in and must not be edited by hand:

```sh
zig run tools/generate_p256_tables.zig
zig run tools/generate_p384_tables.zig
zig run tools/generate_ed25519_base_table.zig
zig run tools/generate_ed25519_verify_table.zig
zig run tools/generate_x25519_tables.zig
```

`src/x509/stringprep_data.zig` is generated from the Unicode 3.2 database and
RFC 3454 tables; a checked-in generator is still pending.

## Troubleshooting

- **Missing `vort`**: clone it as a sibling directory or update the path
  dependency to a pinned URL and hash.
- **Zig version mismatch**: use a `0.16.x` toolchain. The build rejects other
  minor versions.
- **System-store tests**: `SystemStore` tests tolerate a missing host CA bundle,
  but CI should set `SSL_CERT_FILE` or `SSL_CERT_DIR` for deterministic runs.
- **Formatting failures**: generated tables are excluded from `fmt`/`check`;
  format source files with `zig build fmt`.
