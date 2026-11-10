//! TLS secp384r1MLKEM1024 registered hybrid named group (`0x11ed`).

const std = @import("std");
const ecdh_mlkem = @import("ecdh_mlkem.zig");
const crypto_mlkem = @import("../../crypto/pq/mlkem.zig");

pub const implementation = ecdh_mlkem.Group(.{
    .named_group = 0x11ed,
    .Curve = std.crypto.ecc.P384,
    .MLKem = crypto_mlkem.nist.MLKem1024,
});
