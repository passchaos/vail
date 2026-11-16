//! Platform certificate verification is unavailable on this target.
//!
//! Callers can fall back to `SystemStore` (system root files) or the
//! compiled-in Mozilla roots.

const std = @import("std");
const x509_verifier = @import("../verifier.zig");

pub const Options = struct {
    verify_host: bool = true,
};

pub const Verifier = struct {
    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
    ) !Verifier {
        _ = allocator;
        _ = options;
        return error.PlatformVerifierUnavailable;
    }

    pub fn deinit(self: *Verifier) void {
        _ = self;
    }

    pub fn clientVerifier(self: *const Verifier) x509_verifier.TrustVerifier {
        _ = self;
        return .{ .verify_trust = verifyUnavailable };
    }

    fn verifyUnavailable(
        context: ?*anyopaque,
        trust: x509_verifier.TrustContext,
    ) anyerror!void {
        _ = context;
        _ = trust;
        return error.PlatformVerifierUnavailable;
    }
};
