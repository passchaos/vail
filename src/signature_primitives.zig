//! Package root for Vail's dependency-light signature primitives.

pub const primitives = @import("crypto/signature_primitives.zig");
pub const p521 = primitives.p521;
pub const sm2 = primitives.sm2;
pub const sm3 = primitives.sm3;

test {
    _ = primitives;
}
