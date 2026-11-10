# Verification evidence

This directory contains dated evidence for changes that need more than a normal
unit test: compiler failures, stack-size investigations, A/B measurements, or
platform-specific verification.

## Index

| Date | Topic | Contents |
| --- | --- | --- |
| 2026-11-10 | Aligned variable-length secure erasure | `2026-11-10-aligned-slice-wipe/` |
| 2026-11-10 | Destination-based Ed25519 verifier construction | `2026-11-10-ed25519-verifier-into/` |

## Convention

- Use a `YYYY-MM-DD-<short-topic>/` directory.
- Add a `README.md` explaining the question, the commands, and the conclusion.
- Store raw command output in `.txt` files; do not paste large logs into the
  README.
- Record the commit SHA, host, toolchain version, and whether the result is a
  correctness gate or a performance observation.
- Keep evidence reproducible: include exact commands and any required
  environment variables.
