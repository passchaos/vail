//! Dependency-free archive cryptography from Vail.

pub const zipcrypto = @import("zipcrypto.zig");
pub const winzip_aes = @import("winzip_aes.zig");
pub const pkware_strong = @import("pkware_strong.zig");

test {
    _ = zipcrypto;
    _ = winzip_aes;
    _ = pkware_strong;
    _ = @import("pkware_strong_tests.zig");
}
