//! Reusable authenticated cryptographic primitives.

pub const mac = @import("mac.zig");

test {
    _ = @import("tests.zig");
}
