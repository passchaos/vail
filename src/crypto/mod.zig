//! Reusable authenticated cryptographic primitives.

pub const aes_gcm = @import("aes_gcm.zig");
pub const aes_ccm = @import("aes_ccm.zig");
pub const blake2s = @import("blake2s.zig");
pub const chacha20_poly1305 = @import("chacha20_poly1305.zig");
pub const ed25519 = @import("ed25519.zig");
pub const hpke = @import("hpke.zig");
pub const mac = @import("mac.zig");
pub const memory = @import("memory.zig");
pub const mldsa = @import("mldsa.zig");
pub const mlkem = @import("mlkem.zig");
pub const p256 = @import("p256.zig");
pub const p384 = @import("p384.zig");
pub const p521 = @import("p521.zig");
pub const rsa = @import("rsa.zig");
pub const sha256 = @import("sha256.zig");
pub const sha512 = @import("sha512.zig");
pub const sm2 = @import("sm2.zig");
pub const sm3 = @import("sm3.zig");
pub const sm4 = @import("sm4.zig");
pub const x25519 = @import("x25519.zig");
pub const xchacha20_poly1305 = @import("xchacha20_poly1305.zig");

pub const testing = struct {
    pub const rsa_signing = @import("testdata/rsa_signing.zig");
};

test {
    _ = @import("tests.zig");
    _ = @import("mldsa_tests.zig");
    _ = aes_gcm;
    _ = aes_ccm;
    _ = chacha20_poly1305;
    _ = ed25519;
    _ = hpke;
    _ = mldsa;
    _ = mlkem;
    _ = p256;
    _ = p384;
    _ = p521;
    _ = rsa;
    _ = sha512;
    _ = sm2;
    _ = sm3;
    _ = sm4;
    _ = x25519;
    _ = xchacha20_poly1305;
}
