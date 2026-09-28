//! Reusable authenticated cryptographic primitives.

pub const aes_gcm = @import("aes_gcm.zig");
pub const mac = @import("mac.zig");
pub const memory = @import("memory.zig");
pub const sha256 = @import("sha256.zig");
pub const sm2 = @import("sm2.zig");
pub const sm3 = @import("sm3.zig");
pub const sm4 = @import("sm4.zig");

test {
    _ = @import("tests.zig");
    _ = aes_gcm;
    _ = sm2;
    _ = sm3;
    _ = sm4;
}
