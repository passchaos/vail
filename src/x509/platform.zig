//! Platform-native TLS server certificate verification.
//!
//! macOS uses Security.framework and Windows uses CryptoAPI/WinTrust. Other
//! targets report `error.PlatformVerifierUnavailable`; callers can fall back to
//! `SystemStore` or compiled-in roots.

const std = @import("std");
const builtin = @import("builtin");

const implementation = switch (builtin.os.tag) {
    .macos => @import("platform/macos.zig"),
    .windows => @import("platform/windows.zig"),
    else => @import("platform/unsupported.zig"),
};

pub const Options = implementation.Options;
pub const Verifier = implementation.Verifier;

test "platform verifier rejects an untrusted self-signed chain" {
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
    const vectors = @import("../testdata.zig").x509.path_vectors;
    var der: [vectors.root_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&der, vectors.root_hex);

    var verifier = try Verifier.init(std.testing.allocator, .{});
    defer verifier.deinit();
    const trust_verifier = verifier.clientVerifier();
    const callback = trust_verifier.verify_trust orelse
        return error.MissingTrustContext;
    try std.testing.expectError(
        error.CertificateUntrusted,
        callback(trust_verifier.context, .{
            .server_name = "localhost",
            .chain = &.{&der},
        }),
    );
}
