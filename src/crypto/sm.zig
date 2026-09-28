//! Lightweight ShangMi hash and signature primitives.
//!
//! This module intentionally excludes TLS and optional backend plumbing so
//! consumers that only need public-data SM2 verification or SM3 hashing can
//! keep a small dependency graph. SM2 signing is exposed by the underlying
//! primitive but remains subject to its documented nonce and timing caveats.

pub const sm2 = @import("sm2.zig");
pub const sm3 = @import("sm3.zig");

test {
    _ = sm2;
    _ = sm3;
}
