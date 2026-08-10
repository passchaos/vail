//! Reusable authenticated cryptographic primitives.

pub const mac = @import("mac.zig");
pub const memory = @import("memory.zig");
pub const sha256 = @import("sha256.zig");
pub const sm3 = @import("sm3.zig");
pub const sm4 = @import("sm4.zig");

test {
    _ = @import("tests.zig");
    _ = sm3;
    _ = sm4;
}
