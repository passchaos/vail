//! Dependency-free archive cryptography from Vail.

pub const zipcrypto = @import("zipcrypto.zig");
pub const winzip_aes = @import("winzip_aes.zig");

test {
    _ = zipcrypto;
    _ = winzip_aes;
}
