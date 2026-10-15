//! Dependency-free archive cryptography from Vail.

pub const zipcrypto = @import("zipcrypto.zig");

test {
    _ = zipcrypto;
}
