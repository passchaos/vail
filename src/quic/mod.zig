//! QUIC cryptographic primitives shared with transport implementations.

pub const traffic_crypto = @import("traffic_crypto.zig");

test {
    _ = @import("tests.zig");
}
