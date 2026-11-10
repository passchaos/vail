//! Dependency-light public-signature primitives.
//!
//! This module deliberately exposes only the standalone P-521, SM2, and SM3
//! implementations. Consumers that only validate signatures do not need to
//! import Vail's TLS, X.509 path, record, or protocol graph.

pub const p521 = @import("ec/p521.zig");
pub const sm2 = @import("sign/sm2.zig");
pub const sm3 = @import("hash/sm3.zig");

test "signature primitives expose compressed and uncompressed P-521 keys" {
    const generator_x = comptime decodeHex(
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d" ++
            "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    );
    const generator_y = comptime decodeHex(
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e" ++
            "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
    );
    const compressed = [_]u8{0x02} ++ generator_x;
    const uncompressed = [_]u8{0x04} ++ generator_x ++ generator_y;
    try p521.validatePublicKey(&compressed);
    try p521.validatePublicKey(&uncompressed);

    var invalid = uncompressed;
    invalid[0] = 0x05;
    try @import("std").testing.expectError(
        error.InvalidPublicKey,
        p521.validatePublicKey(&invalid),
    );
}

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var result: [hex.len / 2]u8 = undefined;
    _ = @import("std").fmt.hexToBytes(&result, hex) catch unreachable;
    return result;
}

test {
    _ = sm2;
    _ = sm3;
}
