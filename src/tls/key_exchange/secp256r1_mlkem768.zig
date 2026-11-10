//! TLS secp256r1MLKEM768 registered hybrid named group (`0x11eb`).

const std = @import("std");
const ecdh_mlkem = @import("ecdh_mlkem.zig");
const crypto_mlkem = @import("../../crypto/pq/mlkem.zig");

pub const implementation = ecdh_mlkem.Group(.{
    .named_group = 0x11eb,
    .Curve = std.crypto.ecc.P256,
    .MLKem = crypto_mlkem.nist.MLKem768,
});
