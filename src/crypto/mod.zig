//! Reusable authenticated cryptographic primitives.

pub const mac = @import("mac.zig");
pub const memory = @import("memory.zig");
pub const sha256 = @import("sha256.zig");

test {
    _ = @import("tests.zig");
}
