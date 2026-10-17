//! Dependency-free archive cryptography from Vail.

pub const zipcrypto = @import("zipcrypto.zig");
pub const winzip_aes = @import("winzip_aes.zig");
pub const pkware_strong = @import("pkware_strong.zig");
pub const pkware_strong_stream = @import("pkware_strong_stream.zig");
pub const pkware_strong_decrypt_stream = @import("pkware_strong_decrypt_stream.zig");
pub const rar5 = @import("rar5.zig");
pub const rar4 = @import("rar4.zig");
pub const seven_zip = @import("seven_zip.zig");
pub const esd = @import("esd.zig");
pub const cryptoapi_rsa = @import("cryptoapi_rsa.zig");

test {
    _ = zipcrypto;
    _ = winzip_aes;
    _ = pkware_strong;
    _ = pkware_strong_stream;
    _ = pkware_strong_decrypt_stream;
    _ = rar5;
    _ = rar4;
    _ = seven_zip;
    _ = esd;
    _ = cryptoapi_rsa;
    _ = @import("pkware_strong_tests.zig");
}
