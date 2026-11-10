//! Trust-verification types shared by X.509 stores and TLS frontends.
//!
//! X.509 owns trust policy and returns a `TrustVerifier`; TLS wraps that
//! verifier with its own CertificateVerify state instead of making the X.509
//! layer depend on TLS.

pub const TrustContext = struct {
    server_name: ?[]const u8,
    chain: []const []const u8,
    /// Backward-compatible view of the leaf CertificateEntry response.
    ocsp_response: ?[]const u8 = null,
    /// TLS 1.3 per-CertificateEntry OCSP responses, aligned with `chain`.
    /// Null indicates a caller using the legacy leaf-only API.
    ocsp_responses: ?[]const ?[]const u8 = null,
};

pub const TrustCallback = *const fn (
    context: ?*anyopaque,
    trust: TrustContext,
) anyerror!void;

/// Minimal callback/context pair returned by X.509 trust stores.
///
/// TLS layers can convert this into their richer client verifier without
/// making the X.509 module import TLS types.
pub const TrustVerifier = struct {
    verify_trust: ?TrustCallback = null,
    context: ?*anyopaque = null,
};
