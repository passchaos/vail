//! TLS secp384r1MLKEM1024 registered hybrid named group (`0x11ed`).

const std = @import("std");
const ecdh_mlkem = @import("ecdh_mlkem.zig");

pub const implementation = ecdh_mlkem.Group(.{
    .named_group = 0x11ed,
    .Curve = std.crypto.ecc.P384,
    .MLKem = std.crypto.kem.ml_kem.MLKem1024,
});
