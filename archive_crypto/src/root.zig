//! Dependency-free archive cryptography from Vail.

pub const zipcrypto = @import("zipcrypto.zig");
pub const winzip_aes = @import("winzip_aes.zig");
pub const pkware_strong = @import("pkware_strong.zig");
pub const pkware_strong_stream = @import("pkware_strong_stream.zig");
pub const pkware_strong_decrypt_stream = @import("pkware_strong_decrypt_stream.zig");
pub const rar5 = @import("rar5.zig");

test {
    _ = zipcrypto;
    _ = winzip_aes;
    _ = pkware_strong;
    _ = pkware_strong_stream;
    _ = pkware_strong_decrypt_stream;
    _ = rar5;
    _ = @import("pkware_strong_tests.zig");
}
