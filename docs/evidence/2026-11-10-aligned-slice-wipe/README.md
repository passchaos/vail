# Aligned variable-length secure erasure

`crypto.memory.zeroAlignedSlice32` accepts a 32-byte-aligned slice of any
length. Full blocks use volatile 32-byte vector stores, and the partial tail
uses the existing byte erasure helper. A compiler memory barrier follows the
stores. The function writes only its supplied span and does not read contents.
Existing `zero`, `zeroValue`, and fixed-value `zeroAligned32` behavior is unchanged.

Standalone memory tests passed **3/3** in [Debug](debug.txt),
[ReleaseSafe](release-safe.txt), and [ReleaseFast](release-fast.txt). Canary
checks cover empty spans, every 1–127-byte length at aligned offsets 32/64,
and lengths 2,048/2,049/65,535/65,536/65,537 with untouched prefix/suffix bytes.
Run `zig test src/crypto/memory.zig`, adding the desired `-O` mode.

Full-root Vail validation retains the previously reproduced baseline compiler
failure described in [constructor evidence](../2026-11-10-ed25519-verifier-into/README.md).
These focused memory checks do not claim a completed full-root gate. E2ez's
signature scratch cleanup uses this API and records its own protocol/latency
integration evidence.
