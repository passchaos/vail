# Destination-based Ed25519 verifier construction

`PreparedVerifier.initInto` validates the public key before writing caller
storage, then builds its public comb table directly into that destination.
The existing `init` API delegates to it. Point validation, table ordering and
math, and signature verification behavior are unchanged.

The standalone Ed25519 module passed all 14 tests in ReleaseSafe and
ReleaseFast; Debug passed 12 with two ADX-only skips. The
[Debug](ed-debug.txt) and [ReleaseSafe](ed-release-safe.txt) logs include table/
verification equivalence, standard Ed25519 behavior, and exact destination
preservation on malformed, identity, and low-order key rejection.

Reproduce with `zig test src/crypto/ed25519.zig --test-filter Ed25519`, adding
`-O ReleaseSafe` or `-O ReleaseFast` for optimized modes. Formatting and patch
whitespace checks passed.

Full-root ReleaseSafe validation remains unresolved: the compiler terminated
with SIGSEGV before library tests in the [native backend](root-native-compiler-failure.txt),
the [LLVM replay](root-llvm-compiler-failure.txt), and LLVM with a
[64 MiB compiler stack](root-llvm-64m-stack-failure.txt). The unchanged
`a537559` baseline also [failed with the same LLVM command/stack/dependencies](baseline-llvm-64m-stack-failure.txt),
changing only the root source path. The failure predates this patch; its cause
has not been diagnosed. The package test in the initial build passed.

The owner API is used by e2ez to construct prepared verifier cache entries
without returning large temporary tables. Complete protocol and stack/timing
validation belongs to the e2ez integration checkpoint.
