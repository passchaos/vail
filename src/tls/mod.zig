//! TLS 1.3 authentication and handshake-message primitives.

pub const auth = @import("auth.zig");
pub const client_auth = @import("client_auth.zig");

test {
    _ = @import("tests.zig");
}
