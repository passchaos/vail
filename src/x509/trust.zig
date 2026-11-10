//! Built-in X.509 chain, validity, hostname, and endpoint-purpose policy.
//!
//! `SystemStore` loads the platform CA bundle once and then exposes a
//! zero-allocation verification callback suitable for `x509_verifier.TrustVerifier`.

const std = @import("std");
const builtin = @import("builtin");
const x509_verifier = @import("verifier.zig");
const p521 = @import("../crypto/p521.zig");
const certificate_compat = @import("certificate.zig");
const distinguished_name = @import("distinguished_name.zig");
const issuer_fetch = @import("issuer_fetch.zig");
const ocsp = @import("ocsp.zig");
const certificate_policy = @import("policy.zig");

const Certificate = std.crypto.Certificate;

pub const PathLimits = struct {
    max_depth: usize = 8,
    max_candidate_checks: usize = 64,
    max_presented_certificates: usize = 16,
    max_compatible_trust_anchors: usize = 32,
};

pub const CertificatePolicy = certificate_policy.Config;
pub const any_certificate_policy_oid = certificate_policy.any_policy_oid;

pub const RevocationStatus = enum {
    good,
    revoked,
    unknown,
};

pub const RevocationPolicy = struct {
    context: *const anyopaque,
    check: *const fn (
        context: *const anyopaque,
        certificate_der: []const u8,
        issuer_der: []const u8,
    ) anyerror!RevocationStatus,
    require_status: bool = false,

    pub fn verify(
        self: RevocationPolicy,
        certificate_der: []const u8,
        issuer_der: []const u8,
    ) !void {
        switch (try self.check(self.context, certificate_der, issuer_der)) {
            .good => {},
            .revoked => return error.CertificateRevoked,
            .unknown => if (self.require_status) {
                return error.CertificateRevocationStatusUnavailable;
            },
        }
    }
};

const hard_max_presented_certificates = 32;
const hard_max_depth = 16;
const hard_max_candidate_checks = 256;
const hard_max_compatible_trust_anchors = 64;
pub const max_compatible_certificate_bytes = 1024 * 1024;
pub const default_max_compatible_pem_bytes = 8 * 1024 * 1024;
const pem_certificate_begin = "-----BEGIN CERTIFICATE-----";
const pem_certificate_end = "-----END CERTIFICATE-----";
const pem_base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

/// Caller policy for a server leaf without an RFC 7633 requirement. A leaf
/// containing TLS Feature `status_request(5)` always upgrades this to
/// `.require`.
pub const StapledOcspPolicy = enum {
    ignore,
    if_present,
    require,
};

pub const BundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    /// Additional borrowed trust anchors parsed by Vail's compatibility
    /// parser, including algorithms not understood by Zig std's Bundle.
    compatible_trust_anchors: []const []const u8 = &.{},
    now_seconds: i64,
    path_limits: PathLimits = .{},
    revocation: ?RevocationPolicy = null,
    stapled_ocsp: StapledOcspPolicy = .ignore,
    ocsp_validation: ocsp.Policy = .{},
    /// RFC 5280/RFC 9618 certificate-policy inputs and resource bounds.
    certificate_policy: CertificatePolicy = .{},

    pub fn clientVerifier(
        self: *const BundleVerifier,
    ) x509_verifier.TrustVerifier {
        return .{
            .verify_trust = verifyCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    /// Verify a TLS server certificate path without matching its DNS/IP
    /// identity. CA trust, validity, signatures, serverAuth EKU, policy,
    /// revocation, and stapled OCSP remain enforced. This is intended only for
    /// explicit compatibility opt-outs such as Mosquitto `bridge_insecure`.
    pub fn serverChainVerifier(
        self: *const BundleVerifier,
    ) x509_verifier.TrustVerifier {
        return .{
            .verify_trust = verifyServerChainCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    pub fn verify(
        self: BundleVerifier,
        trust_context: x509_verifier.TrustContext,
    ) !void {
        if (trust_context.chain.len == 0) {
            return error.EmptyCertificateChain;
        }
        const leaf = try parseCertificate(trust_context.chain[0]);
        const server_name = trust_context.server_name orelse
            return error.MissingServerName;
        const server_identity = parseServerIdentity(server_name);
        try verifyServerIdentity(leaf, server_identity);
        try verifyChain(
            self.bundle,
            self.compatible_trust_anchors,
            self.now_seconds,
            trust_context.chain,
            .server_auth,
            self.path_limits,
            self.revocation,
            server_identity,
            trust_context.ocsp_response,
            trust_context.ocsp_responses,
            self.stapled_ocsp,
            self.ocsp_validation,
            self.certificate_policy,
        );
    }

    /// Direct counterpart to `serverChainVerifier` for callers that already
    /// own the parsed TLS trust context.
    pub fn verifyServerChain(
        self: BundleVerifier,
        trust_context: x509_verifier.TrustContext,
    ) !void {
        try verifyChain(
            self.bundle,
            self.compatible_trust_anchors,
            self.now_seconds,
            trust_context.chain,
            .server_auth,
            self.path_limits,
            self.revocation,
            null,
            trust_context.ocsp_response,
            trust_context.ocsp_responses,
            self.stapled_ocsp,
            self.ocsp_validation,
            self.certificate_policy,
        );
    }

    /// Resolve AIA id-ad-caIssuers references into caller-owned buffers, add
    /// the unique fetched certificates to the unordered presented set, and
    /// run the ordinary bounded path search. The fetch callback owns all URI,
    /// transport, redirect, and network-access policy.
    pub fn verifyWithFetchedIssuers(
        self: BundleVerifier,
        trust_context: x509_verifier.TrustContext,
        issuer_storage: []u8,
        fetch_scratch: []u8,
        fetched_output: [][]const u8,
        fetcher: issuer_fetch.Fetcher,
        fetch_options: issuer_fetch.Options,
    ) !issuer_fetch.Result {
        if (trust_context.chain.len == 0) {
            return error.EmptyCertificateChain;
        }
        try validatePathLimits(self.path_limits);
        try validateCompatibleTrustAnchors(
            self.compatible_trust_anchors,
            self.path_limits,
        );
        try certificate_policy.validateConfig(self.certificate_policy);
        if (trust_context.chain.len > hard_max_presented_certificates) {
            return error.CertificatePathTooManyCertificates;
        }
        if (trust_context.chain.len > self.path_limits.max_presented_certificates) {
            return error.CertificatePathTooManyCertificates;
        }
        if (trust_context.ocsp_responses) |responses| {
            if (responses.len != trust_context.chain.len) {
                return error.InvalidCertificateOcspResponses;
            }
        }
        const fetched = try issuer_fetch.resolve(
            issuer_storage,
            fetch_scratch,
            fetched_output,
            trust_context.chain,
            fetcher,
            fetch_options,
        );
        const combined_len = std.math.add(
            usize,
            trust_context.chain.len,
            fetched.certificates.len,
        ) catch return error.CertificatePathTooManyCertificates;
        if (combined_len > hard_max_presented_certificates) {
            return error.CertificatePathTooManyCertificates;
        }
        var combined: [hard_max_presented_certificates][]const u8 = undefined;
        @memcpy(combined[0..trust_context.chain.len], trust_context.chain);
        @memcpy(
            combined[trust_context.chain.len..combined_len],
            fetched.certificates,
        );

        var combined_responses: [hard_max_presented_certificates]?[]const u8 =
            @splat(null);
        const responses = if (trust_context.ocsp_responses) |presented| blk: {
            @memcpy(combined_responses[0..presented.len], presented);
            break :blk combined_responses[0..combined_len];
        } else null;
        try self.verify(.{
            .server_name = trust_context.server_name,
            .chain = combined[0..combined_len],
            .ocsp_response = trust_context.ocsp_response,
            .ocsp_responses = responses,
        });
        return fetched;
    }

    fn verifyCallback(
        context: ?*anyopaque,
        trust_context: x509_verifier.TrustContext,
    ) anyerror!void {
        const self: *const BundleVerifier = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        try self.verify(trust_context);
    }

    fn verifyServerChainCallback(
        context: ?*anyopaque,
        trust_context: x509_verifier.TrustContext,
    ) anyerror!void {
        const self: *const BundleVerifier = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        try self.verifyServerChain(trust_context);
    }
};

/// CA-bundle policy for certificates presented by TLS clients. It performs no
/// hostname check and enforces the RFC 5280 clientAuth purpose throughout the
/// supplied path. TLS separately verifies CertificateVerify possession.
pub const ClientCertificateBundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    compatible_trust_anchors: []const []const u8 = &.{},
    now_seconds: i64,
    path_limits: PathLimits = .{},
    revocation: ?RevocationPolicy = null,
    /// RFC 5280/RFC 9618 certificate-policy inputs and resource bounds.
    certificate_policy: CertificatePolicy = .{},

    pub fn clientVerifier(
        self: *const ClientCertificateBundleVerifier,
    ) x509_verifier.TrustVerifier {
        return .{
            .verify_trust = verifyCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    pub fn verify(
        self: ClientCertificateBundleVerifier,
        trust_context: x509_verifier.TrustContext,
    ) !void {
        try verifyChain(
            self.bundle,
            self.compatible_trust_anchors,
            self.now_seconds,
            trust_context.chain,
            .client_auth,
            self.path_limits,
            self.revocation,
            null,
            null,
            null,
            .ignore,
            .{},
            self.certificate_policy,
        );
    }

    fn verifyCallback(
        context: ?*anyopaque,
        trust_context: x509_verifier.TrustContext,
    ) anyerror!void {
        const self: *const ClientCertificateBundleVerifier =
            @ptrCast(@alignCast(
                context orelse return error.MissingTrustContext,
            ));
        try self.verify(trust_context);
    }
};

/// CA-bundle verifier for a certificate that signs CRLs. Unlike an endpoint
/// TLS certificate, the target may itself be a CA; KeyUsage, when present,
/// must authorize cRLSign. Intermediate CA, name-constraint, policy, and path
/// search rules are otherwise shared with ordinary certificate validation.
pub const CrlSignerBundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    compatible_trust_anchors: []const []const u8 = &.{},
    now_seconds: i64,
    path_limits: PathLimits = .{},
    certificate_policy: CertificatePolicy = .{},
    /// Optional independent revocation source for the CRL signer path. Do not
    /// point this at the CRL currently being authorized.
    revocation: ?RevocationPolicy = null,

    pub fn verify(
        self: CrlSignerBundleVerifier,
        chain: []const []const u8,
    ) !void {
        try verifyChain(
            self.bundle,
            self.compatible_trust_anchors,
            self.now_seconds,
            chain,
            .crl_signing,
            self.path_limits,
            self.revocation,
            null,
            null,
            null,
            .ignore,
            .{},
            self.certificate_policy,
        );
    }
};

/// Verify a CA certificate and its supplied issuer chain to a configured
/// anchor without imposing an endpoint EKU. This is intended for proving that
/// two independently validated infrastructure paths share a trust anchor.
pub const CertificateAuthorityBundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    compatible_trust_anchors: []const []const u8 = &.{},
    now_seconds: i64,
    path_limits: PathLimits = .{},
    certificate_policy: CertificatePolicy = .{},
    /// Optional independent revocation source for the CA path.
    revocation: ?RevocationPolicy = null,

    pub fn verify(
        self: CertificateAuthorityBundleVerifier,
        chain: []const []const u8,
    ) !void {
        try verifyChain(
            self.bundle,
            self.compatible_trust_anchors,
            self.now_seconds,
            chain,
            .certificate_authority,
            self.path_limits,
            self.revocation,
            null,
            null,
            null,
            .ignore,
            .{},
            self.certificate_policy,
        );
    }
};

const EndpointPurpose = enum {
    server_auth,
    client_auth,
    crl_signing,
    certificate_authority,
};

const Rfc822Name = struct {
    local: []const u8,
    domain: []const u8,
};

const ServerIdentity = union(enum) {
    dns: []const u8,
    rfc822: Rfc822Name,
    uri: []const u8,
    directory: []const u8,
    ip4: [4]u8,
    ip6: [16]u8,
};

/// Validate one DER certificate as a currently usable trust anchor for TLS
/// client authentication. This checks X.509 parsing, validity, CA constraints,
/// keyCertSign, clientAuth EKU restrictions, and supported critical
/// extensions; it deliberately does not verify the anchor's issuer signature.
pub fn validateClientCertificateAuthority(
    certificate_der: []const u8,
    now_seconds: i64,
) !void {
    const certificate = try parseCertificate(certificate_der);
    try verifyValidity(certificate, now_seconds);
    try validateIssuerUsageProfile(
        try certificateUsage(certificate_der),
        0,
        .client_auth,
    );
}

/// Validate a DER certificate as an issuer for a client-authentication CRL.
/// When KeyUsage is present, cRLSign is mandatory in addition to the ordinary
/// CA/path/purpose constraints.
pub fn validateClientCertificateRevocationListIssuer(
    certificate_der: []const u8,
    now_seconds: i64,
) !void {
    const certificate = try parseCertificate(certificate_der);
    try verifyValidity(certificate, now_seconds);
    const usage = try certificateUsage(certificate_der);
    try validateIssuerUsageProfile(usage, 0, .client_auth);
    if (usage.key_usage_present and !usage.crl_sign) {
        return error.InvalidCertificateUsage;
    }
}

/// Validate the certificate-level requirements for a CRL signing key. Trust
/// and authorization of a delegated indirect-CRL signer are established by
/// the caller against the selected certificate path.
pub fn validateCertificateRevocationListSigner(
    certificate_der: []const u8,
    now_seconds: i64,
) !void {
    const certificate = try parseCertificate(certificate_der);
    try verifyValidity(certificate, now_seconds);
    const usage = try certificateUsage(certificate_der);
    if (usage.unsupported_critical_extension or
        (usage.key_usage_present and !usage.crl_sign))
    {
        return error.InvalidCertificateUsage;
    }
}

fn verifyChain(
    bundle: *const Certificate.Bundle,
    compatible_trust_anchors: []const []const u8,
    now_seconds: i64,
    chain: []const []const u8,
    purpose: EndpointPurpose,
    limits: PathLimits,
    revocation: ?RevocationPolicy,
    constrained_identity: ?ServerIdentity,
    stapled_ocsp_response: ?[]const u8,
    stapled_ocsp_responses: ?[]const ?[]const u8,
    stapled_ocsp_policy: StapledOcspPolicy,
    ocsp_validation: ocsp.Policy,
    policy_config: CertificatePolicy,
) !void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    try validatePathLimits(limits);
    try validateCompatibleTrustAnchors(compatible_trust_anchors, limits);
    try certificate_policy.validateConfig(policy_config);
    if (chain.len > limits.max_presented_certificates) {
        return error.CertificatePathTooManyCertificates;
    }
    if (stapled_ocsp_responses) |responses| {
        if (responses.len != chain.len) {
            return error.InvalidCertificateOcspResponses;
        }
        if (stapled_ocsp_response) |legacy| {
            const leaf_response = responses[0] orelse
                return error.InvalidCertificateOcspResponses;
            if (!std.mem.eql(u8, legacy, leaf_response)) {
                return error.InvalidCertificateOcspResponses;
            }
        }
    }
    var parsed: [hard_max_presented_certificates]Certificate.Parsed = undefined;
    var custom_algorithms: [hard_max_presented_certificates]certificate_compat.SignatureAlgorithm = undefined;
    var custom_algorithm_mask: u32 = 0;
    var usage_cache: [hard_max_presented_certificates]UsageCache =
        @splat(.unparsed);
    for (chain, 0..) |certificate_der, index| {
        const compatible = try certificate_compat.parse(certificate_der);
        parsed[index] = compatible.standard;
        if (compatible.signature_algorithm) |algorithm| {
            custom_algorithms[index] = algorithm;
            custom_algorithm_mask |= @as(u32, 1) << @intCast(index);
        }
    }
    const leaf_usage = try certificateUsage(chain[0]);
    usage_cache[0] = .{ .valid = leaf_usage };
    try validateLeafUsageProfile(leaf_usage, purpose);
    var search = PathSearch{
        .bundle = bundle,
        .compatible_trust_anchors = compatible_trust_anchors,
        .now_seconds = now_seconds,
        .chain = chain,
        .parsed = parsed[0..chain.len],
        .custom_algorithms = custom_algorithms[0..chain.len],
        .custom_algorithm_mask = custom_algorithm_mask,
        .usage_cache = usage_cache[0..chain.len],
        .purpose = purpose,
        .limits = limits,
        .revocation = revocation,
        .constrained_identity = constrained_identity,
        .stapled_ocsp_response = stapled_ocsp_response,
        .stapled_ocsp_responses = stapled_ocsp_responses,
        .stapled_ocsp_policy = if (leaf_usage.must_staple)
            .require
        else
            stapled_ocsp_policy,
        .ocsp_validation = ocsp_validation,
        .policy_config = policy_config,
    };
    try search.verifyFrom(0, 1, 0, 0);
}

const PathSearch = struct {
    bundle: *const Certificate.Bundle,
    compatible_trust_anchors: []const []const u8,
    now_seconds: i64,
    chain: []const []const u8,
    parsed: []const Certificate.Parsed,
    custom_algorithms: []const certificate_compat.SignatureAlgorithm,
    custom_algorithm_mask: u32,
    usage_cache: []UsageCache,
    purpose: EndpointPurpose,
    limits: PathLimits,
    revocation: ?RevocationPolicy,
    constrained_identity: ?ServerIdentity,
    stapled_ocsp_response: ?[]const u8,
    stapled_ocsp_responses: ?[]const ?[]const u8,
    stapled_ocsp_policy: StapledOcspPolicy,
    ocsp_validation: ocsp.Policy,
    policy_config: CertificatePolicy,
    path_indices: [hard_max_depth]usize = undefined,
    candidate_checks: usize = 0,

    fn verifyFrom(
        self: *PathSearch,
        subject_index: usize,
        used: u32,
        ca_below: usize,
        depth: usize,
    ) !void {
        if (depth >= self.limits.max_depth) {
            return error.CertificatePathTooDeep;
        }
        self.path_indices[depth] = subject_index;
        const subject = self.parsed[subject_index];
        if (try trustedEquivalentAnchorExact(self.bundle, subject)) |anchor| {
            try self.acceptTrustedEquivalentAnchor(
                subject_index,
                subject,
                anchor,
                depth,
            );
            return;
        }
        if (try trustedEquivalentCompatibleAnchor(
            self.compatible_trust_anchors,
            subject,
            true,
        )) |anchor| {
            try self.acceptTrustedEquivalentAnchor(
                subject_index,
                subject,
                anchor,
                depth,
            );
            return;
        }

        var remembered_error: ?anyerror = null;
        const exact_anchor_index = self.bundle.find(subject.issuer());
        if (exact_anchor_index) |anchor_index| {
            try self.consumeCandidateBudget();
            self.verifyBundleAnchor(
                subject_index,
                subject,
                anchor_index,
                ca_below,
                used,
                depth,
            ) catch |err| {
                remembered_error = err;
            };
            if (remembered_error == null) return;
        }
        for (self.compatible_trust_anchors) |anchor_der| {
            const anchor = try parseCertificate(anchor_der);
            if (!std.mem.eql(u8, subject.issuer(), anchor.subject())) continue;
            try self.consumeCandidateBudget();
            self.verifyAnchorDer(
                subject_index,
                subject,
                anchor_der,
                anchor,
                ca_below,
                used,
                depth,
            ) catch |err| {
                remembered_error = err;
                continue;
            };
            return;
        }
        var anchors = self.bundle.map.iterator();
        while (anchors.next()) |entry| {
            const anchor_index = entry.value_ptr.*;
            if (exact_anchor_index != null and
                anchor_index == exact_anchor_index.?) continue;
            const anchor_der = try bundleCertificateDer(
                self.bundle,
                anchor_index,
            );
            const anchor = try parseCertificate(anchor_der);
            if (!(directoryNamesEqual(
                subject.issuer(),
                anchor.subject(),
            ) catch false)) continue;
            try self.consumeCandidateBudget();
            self.verifyBundleAnchor(
                subject_index,
                subject,
                anchor_index,
                ca_below,
                used,
                depth,
            ) catch |err| {
                remembered_error = err;
                continue;
            };
            return;
        }
        for (self.compatible_trust_anchors) |anchor_der| {
            const anchor = try parseCertificate(anchor_der);
            if (std.mem.eql(u8, subject.issuer(), anchor.subject())) continue;
            if (!(directoryNamesEqual(
                subject.issuer(),
                anchor.subject(),
            ) catch false)) continue;
            try self.consumeCandidateBudget();
            self.verifyAnchorDer(
                subject_index,
                subject,
                anchor_der,
                anchor,
                ca_below,
                used,
                depth,
            ) catch |err| {
                remembered_error = err;
                continue;
            };
            return;
        }

        const subject_usage = try self.usageFor(subject_index);
        const authority_issuer_serial = if (subject_usage.authority_key_identifier == null) blk: {
            const authority = try certificateAuthorityKeyIdentifier(
                self.chain[subject_index],
            ) orelse break :blk null;
            break :blk if (authority.authority_cert_serial_number != null)
                authority
            else
                null;
        } else null;
        var priorities: [hard_max_presented_certificates]u2 = @splat(3);
        for (self.parsed[1..], 1..) |issuer, issuer_index| {
            const bit = @as(u32, 1) << @intCast(issuer_index);
            if ((used & bit) != 0) continue;
            const issuer_name_matches = directoryNamesEqual(
                subject.issuer(),
                issuer.subject(),
            ) catch false;
            if (!issuer_name_matches) continue;
            if (subject_usage.authority_key_identifier) |authority_key| {
                const issuer_usage = self.usageFor(issuer_index) catch {
                    // A malformed same-name decoy must not consume the budget
                    // before a well-formed exact AKI/SKI match. It is still
                    // attempted in the fallback tier so its error is retained
                    // when no valid path exists.
                    priorities[issuer_index] = 2;
                    continue;
                };
                priorities[issuer_index] = issuerKeyPriority(
                    authority_key,
                    issuer_usage.subject_key_identifier,
                );
            } else if (authority_issuer_serial) |authority| {
                const issuer_usage = self.usageFor(issuer_index) catch {
                    priorities[issuer_index] = 2;
                    continue;
                };
                const issuer_serial = certificateSerialNumber(
                    self.chain[issuer_index],
                ) catch {
                    priorities[issuer_index] = 2;
                    continue;
                };
                priorities[issuer_index] = issuerIdentityPriority(
                    authority,
                    issuer_usage.subject_key_identifier,
                    issuer.issuer(),
                    issuer_serial,
                ) catch 2;
            } else {
                priorities[issuer_index] = 0;
            }
        }
        const priority_count: usize = if (subject_usage.authority_key_identifier != null or
            authority_issuer_serial != null) 3 else 1;
        for (0..priority_count) |priority| {
            for (self.parsed[1..], 1..) |issuer, issuer_index| {
                if (priorities[issuer_index] != priority) continue;
                const bit = @as(u32, 1) << @intCast(issuer_index);
                try self.consumeCandidateBudget();
                const issuer_usage = self.usageFor(issuer_index) catch |err| {
                    remembered_error = err;
                    continue;
                };
                self.validateIssuerUsageAndNameConstraints(
                    issuer_usage,
                    ca_below,
                    used,
                ) catch |err| {
                    remembered_error = err;
                    continue;
                };
                self.verifyIssuerEdge(
                    subject_index,
                    subject,
                    self.chain[issuer_index],
                    issuer,
                ) catch |err| {
                    remembered_error = err;
                    continue;
                };
                const next_ca_below = countCaBelow(
                    ca_below,
                    issuer,
                ) catch |err| {
                    remembered_error = err;
                    continue;
                };
                self.verifyFrom(
                    issuer_index,
                    used | bit,
                    next_ca_below,
                    depth + 1,
                ) catch |err| {
                    remembered_error = err;
                    continue;
                };
                return;
            }
        }
        if (try trustedEquivalentAnchorFallback(self.bundle, subject)) |anchor| {
            try self.acceptTrustedEquivalentAnchor(
                subject_index,
                subject,
                anchor,
                depth,
            );
            return;
        }
        if (try trustedEquivalentCompatibleAnchor(
            self.compatible_trust_anchors,
            subject,
            false,
        )) |anchor| {
            try self.acceptTrustedEquivalentAnchor(
                subject_index,
                subject,
                anchor,
                depth,
            );
            return;
        }
        return remembered_error orelse error.CertificateIssuerNotFound;
    }

    fn consumeCandidateBudget(self: *PathSearch) !void {
        if (self.candidate_checks >= self.limits.max_candidate_checks) {
            return error.CertificatePathSearchLimitExceeded;
        }
        self.candidate_checks += 1;
    }

    fn verifyBundleAnchor(
        self: *PathSearch,
        subject_index: usize,
        subject: Certificate.Parsed,
        anchor_index: u32,
        ca_below: usize,
        used: u32,
        depth: usize,
    ) !void {
        const anchor_der = try bundleCertificateDer(self.bundle, anchor_index);
        const anchor = try parseCertificate(anchor_der);
        return self.verifyAnchorDer(
            subject_index,
            subject,
            anchor_der,
            anchor,
            ca_below,
            used,
            depth,
        );
    }

    fn verifyAnchorDer(
        self: *PathSearch,
        subject_index: usize,
        subject: Certificate.Parsed,
        anchor_der: []const u8,
        anchor: Certificate.Parsed,
        ca_below: usize,
        used: u32,
        depth: usize,
    ) !void {
        try self.validateIssuerUsageAndNameConstraints(
            try certificateUsage(anchor_der),
            ca_below,
            used,
        );
        try self.verifyIssuerEdge(
            subject_index,
            subject,
            anchor_der,
            anchor,
        );
        try verifyValidity(anchor, self.now_seconds);
        try self.verifySelectedCertificatePolicies(depth + 1);
    }

    fn acceptTrustedEquivalentAnchor(
        self: *PathSearch,
        subject_index: usize,
        subject: Certificate.Parsed,
        anchor: Certificate.Parsed,
        depth: usize,
    ) !void {
        if (subject_index == 0 and self.stapled_ocsp_policy != .ignore) {
            if (self.stapledResponse(subject_index) != null) {
                return error.CertificateOcspIssuerUnavailable;
            }
            if (self.stapled_ocsp_policy == .require) {
                return error.CertificateOcspResponseRequired;
            }
        }
        try verifyValidity(subject, self.now_seconds);
        try verifyValidity(anchor, self.now_seconds);
        try self.verifySelectedCertificatePolicies(depth);
    }

    noinline fn verifySelectedCertificatePolicies(
        self: *PathSearch,
        count: usize,
    ) !void {
        var certificates: [hard_max_depth]certificate_policy.Certificate =
            undefined;
        for (0..count) |forward_index| {
            const path_index = self.path_indices[count - 1 - forward_index];
            const parsed = self.parsed[path_index];
            certificates[forward_index] = .{
                .extensions = (try self.usageFor(path_index)).policy_extensions,
                .self_issued = try directoryNamesEqual(
                    parsed.issuer(),
                    parsed.subject(),
                ),
            };
        }
        try certificate_policy.validatePath(
            self.policy_config,
            certificates[0..count],
        );
    }

    fn usageFor(
        self: *PathSearch,
        index: usize,
    ) !CertificateUsage {
        switch (self.usage_cache[index]) {
            .unparsed => {
                const usage = certificateUsage(self.chain[index]) catch |err| {
                    self.usage_cache[index] = .{ .invalid = err };
                    return err;
                };
                self.usage_cache[index] = .{ .valid = usage };
                return usage;
            },
            .valid => |usage| return usage,
            .invalid => |err| return err,
        }
    }

    // Keep the uncommon SAN/path walk out of the ordinary issuer-validation
    // frame; most public CAs do not carry Name Constraints.
    noinline fn validateIssuerUsageAndNameConstraints(
        self: *const PathSearch,
        usage: CertificateUsage,
        ca_below: usize,
        constrained_certificates: u32,
    ) !void {
        try validateIssuerUsageProfile(usage, ca_below, self.purpose);
        if (usage.name_constraints) |encoded| {
            @branchHint(.unlikely);
            return self.validateSelectedCertificateNameConstraints(
                encoded,
                constrained_certificates,
            );
        }
    }

    noinline fn validateSelectedCertificateNameConstraints(
        self: *const PathSearch,
        encoded: []const u8,
        constrained_certificates: u32,
    ) !void {
        if (self.constrained_identity) |identity| {
            try validateNameConstraints(encoded, identity);
        }
        var remaining = constrained_certificates;
        while (remaining != 0) {
            const index: usize = @intCast(@ctz(remaining));
            remaining &= remaining - 1;
            const certificate = &self.parsed[index];
            if (index != 0 and
                try directoryNamesEqual(
                    certificate.issuer(),
                    certificate.subject(),
                )) continue;
            try validateCertificateNamesAgainstConstraints(
                encoded,
                certificate,
            );
        }
    }

    fn verifyCertificateSignature(
        self: *const PathSearch,
        subject_index: usize,
        subject: Certificate.Parsed,
        issuer: Certificate.Parsed,
    ) !void {
        const bit = @as(u32, 1) << @intCast(subject_index);
        const p521_issuer = switch (issuer.pub_key_algo) {
            .X9_62_id_ecPublicKey => |curve| curve == .secp521r1,
            else => false,
        };
        if ((self.custom_algorithm_mask & bit) != 0 or p521_issuer) {
            return certificate_compat.verifySignatureAndValidity(
                subject,
                if ((self.custom_algorithm_mask & bit) != 0)
                    self.custom_algorithms[subject_index]
                else
                    null,
                issuer,
                self.now_seconds,
            );
        }
        if (std.mem.eql(u8, subject.issuer(), issuer.subject())) {
            return subject.verify(issuer, self.now_seconds);
        }
        return certificate_compat.verifySignatureAndValidity(
            subject,
            null,
            issuer,
            self.now_seconds,
        );
    }

    noinline fn verifyIssuerEdge(
        self: *PathSearch,
        subject_index: usize,
        subject: Certificate.Parsed,
        issuer_der: []const u8,
        issuer: Certificate.Parsed,
    ) !void {
        const p521_issuer = switch (issuer.pub_key_algo) {
            .X9_62_id_ecPublicKey => |curve| curve == .secp521r1,
            else => false,
        };
        if (p521_issuer) {
            var verifier = p521.CompactPreparedVerifier.init(issuer.pubKey()) catch
                return error.CertificatePublicKeyInvalid;
            const bit = @as(u32, 1) << @intCast(subject_index);
            try certificate_compat.verifySignatureAndValidityWithP521(
                subject,
                if ((self.custom_algorithm_mask & bit) != 0)
                    self.custom_algorithms[subject_index]
                else
                    null,
                issuer,
                self.now_seconds,
                &verifier,
            );
            if (self.revocation) |revocation| {
                try revocation.verify(
                    self.chain[subject_index],
                    issuer_der,
                );
            }
            return self.verifyStapledOcspWithP521(
                subject_index,
                self.chain[subject_index],
                issuer_der,
                &verifier,
            );
        }
        try self.verifyCertificateSignature(subject_index, subject, issuer);
        if (self.revocation) |revocation| {
            try revocation.verify(self.chain[subject_index], issuer_der);
        }
        try self.verifyStapledOcsp(
            subject_index,
            self.chain[subject_index],
            issuer_der,
        );
    }

    fn verifyStapledOcsp(
        self: *PathSearch,
        subject_index: usize,
        certificate_der: []const u8,
        issuer_der: []const u8,
    ) !void {
        if (self.stapled_ocsp_policy == .ignore) return;
        const encoded = self.stapledResponse(subject_index) orelse {
            if (subject_index == 0 and
                self.stapled_ocsp_policy == .require)
            {
                return error.CertificateOcspResponseRequired;
            }
            return;
        };
        switch (try ocsp.verify(
            encoded,
            certificate_der,
            issuer_der,
            self.now_seconds,
            self.ocsp_validation,
        )) {
            .good => {},
            .revoked => return error.CertificateRevoked,
            .unknown => return error.CertificateOcspStatusUnknown,
        }
    }

    fn verifyStapledOcspWithP521(
        self: *PathSearch,
        subject_index: usize,
        certificate_der: []const u8,
        issuer_der: []const u8,
        verifier: *const p521.CompactPreparedVerifier,
    ) !void {
        if (self.stapled_ocsp_policy == .ignore) return;
        const encoded = self.stapledResponse(subject_index) orelse {
            if (subject_index == 0 and
                self.stapled_ocsp_policy == .require)
            {
                return error.CertificateOcspResponseRequired;
            }
            return;
        };
        switch (try ocsp.verifyWithP521(
            encoded,
            certificate_der,
            issuer_der,
            self.now_seconds,
            self.ocsp_validation,
            verifier,
        )) {
            .good => {},
            .revoked => return error.CertificateRevoked,
            .unknown => return error.CertificateOcspStatusUnknown,
        }
    }

    fn stapledResponse(
        self: *const PathSearch,
        subject_index: usize,
    ) ?[]const u8 {
        if (self.stapled_ocsp_responses) |responses| {
            return responses[subject_index];
        }
        return if (subject_index == 0) self.stapled_ocsp_response else null;
    }
};

// This comparison is reached only for non-leaf certificates selected into a
// constrained path, so keep it out of the per-name validation loop.
noinline fn directoryNamesEqual(
    a: []const u8,
    b: []const u8,
) !bool {
    return distinguished_name.eql(a, b) catch |err| return switch (err) {
        error.InvalidName => error.InvalidCertificateExtension,
        error.UnsupportedDirectoryString => error.UnsupportedCertificateNameConstraint,
    };
}

fn validatePathLimits(limits: PathLimits) !void {
    if (limits.max_depth == 0 or
        limits.max_depth > hard_max_depth or
        limits.max_candidate_checks == 0 or
        limits.max_candidate_checks > hard_max_candidate_checks or
        limits.max_presented_certificates == 0 or
        limits.max_presented_certificates > hard_max_presented_certificates or
        limits.max_compatible_trust_anchors == 0 or
        limits.max_compatible_trust_anchors >
            hard_max_compatible_trust_anchors)
    {
        return error.InvalidCertificatePathLimits;
    }
}

fn validateCompatibleTrustAnchors(
    anchors: []const []const u8,
    limits: PathLimits,
) !void {
    if (anchors.len > limits.max_compatible_trust_anchors) {
        return error.CertificatePathTooManyTrustAnchors;
    }
    for (anchors, 0..) |anchor_der, index| {
        _ = try certificate_compat.parse(anchor_der);
        for (anchors[0..index]) |prior| {
            if (std.mem.eql(u8, prior, anchor_der)) {
                return error.DuplicateTrustAnchor;
            }
        }
    }
}

pub const SystemStore = struct {
    allocator: std.mem.Allocator,
    bundle: Certificate.Bundle = .empty,
    compatible_trust_anchors: std.ArrayList([]u8) = .empty,

    pub fn initEmpty(allocator: std.mem.Allocator) SystemStore {
        return .{ .allocator = allocator };
    }

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        now: std.Io.Timestamp,
    ) !SystemStore {
        return switch (builtin.os.tag) {
            .linux => initLinux(allocator, io, now),
            else => initPlatformRescan(allocator, io, now),
        };
    }

    fn initPlatformRescan(
        allocator: std.mem.Allocator,
        io: std.Io,
        now: std.Io.Timestamp,
    ) Certificate.Bundle.RescanError!SystemStore {
        var result = SystemStore{ .allocator = allocator };
        errdefer result.deinit();
        try result.bundle.rescan(allocator, io, now);
        return result;
    }

    /// Linux native roots with the same file/directory preference order as
    /// Zig std, but with per-certificate tolerance and compatibility anchors.
    fn initLinux(
        allocator: std.mem.Allocator,
        io: std.Io,
        now: std.Io.Timestamp,
    ) !SystemStore {
        const cert_file_paths = [_][]const u8{
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/tls/cacert.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/cert.pem",
        };
        const cert_dir_paths = [_][]const u8{
            "/etc/ssl/certs",
            "/etc/pki/tls/certs",
            "/system/etc/security/cacerts",
        };
        var result = SystemStore{ .allocator = allocator };
        errdefer result.deinit();
        var found_file = false;
        for (cert_file_paths) |path| {
            result.addPemFile(io, path, now.toSeconds()) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            found_file = true;
            break;
        }
        if (!found_file) {
            for (cert_dir_paths) |path| {
                result.addPemDirectory(io, path, now.toSeconds()) catch |err| switch (err) {
                    error.FileNotFound => continue,
                    else => return err,
                };
            }
        }
        return result;
    }

    pub const SystemPaths = struct {
        /// `SSL_CERT_FILE` equivalent: one PEM file containing any number of
        /// certificates. When this or `dirs` is provided, the platform store
        /// is not scanned, matching rustls-native-certs.
        file: ?[]const u8 = null,
        /// `SSL_CERT_DIR` equivalent: non-recursive PEM directories.
        dirs: []const []const u8 = &.{},
    };

    /// Load the platform store or caller-selected OpenSSL-style paths.
    ///
    /// With no paths this is `init`. With paths, only those paths are read:
    /// `file` first, then every regular file or symlink in each directory.
    /// Malformed certificate blocks are skipped so one bad CA file cannot
    /// reject the rest of the store, matching rustls-native-certs tolerance.
    pub fn initWithPaths(
        allocator: std.mem.Allocator,
        io: std.Io,
        now: std.Io.Timestamp,
        paths: SystemPaths,
    ) !SystemStore {
        if (paths.file == null and paths.dirs.len == 0) {
            return init(allocator, io, now);
        }
        var result = SystemStore{ .allocator = allocator };
        errdefer result.deinit();
        if (paths.file) |file| {
            if (file.len != 0) try result.addPemFile(io, file, now.toSeconds());
        }
        for (paths.dirs) |dir| {
            if (dir.len == 0) continue;
            try result.addPemDirectory(io, dir, now.toSeconds());
        }
        return result;
    }

    /// Load native roots with rustls-native-certs environment semantics.
    ///
    /// `SSL_CERT_FILE` and `SSL_CERT_DIR` take precedence over the platform
    /// store when either is present. `SSL_CERT_DIR` is split with the native
    /// path-list delimiter (`:` on Unix, `;` on Windows). Certificates from
    /// Vail's compatibility parser are added alongside Zig std's indexed
    /// bundle, so SHA3- and RSA-PSS-signed roots participate in trust paths.
    pub fn initWithEnviron(
        allocator: std.mem.Allocator,
        io: std.Io,
        now: std.Io.Timestamp,
        environ: std.process.Environ,
    ) !SystemStore {
        var map = try std.process.Environ.createMap(environ, allocator);
        defer map.deinit();
        const file = map.get("SSL_CERT_FILE");
        const dirs = map.get("SSL_CERT_DIR");
        if (file == null and dirs == null) return init(allocator, io, now);

        var result = SystemStore{ .allocator = allocator };
        errdefer result.deinit();
        if (file) |path| {
            if (path.len != 0) try result.addPemFile(io, path, now.toSeconds());
        }
        if (dirs) |dir_list| {
            var it = std.mem.splitScalar(
                u8,
                dir_list,
                std.fs.path.delimiter,
            );
            while (it.next()) |dir| {
                if (dir.len == 0) continue;
                try result.addPemDirectory(io, dir, now.toSeconds());
            }
        }
        return result;
    }

    pub fn deinit(self: *SystemStore) void {
        self.rollbackCompatibleAnchors(0);
        self.compatible_trust_anchors.deinit(self.allocator);
        self.bundle.deinit(self.allocator);
        self.* = undefined;
    }

    /// Copy one DER certificate into the compatibility store. Returns false
    /// for an exact duplicate or an anchor already expired at `now_seconds`.
    pub fn addCompatibleCertificate(
        self: *SystemStore,
        certificate_der: []const u8,
        now_seconds: i64,
    ) !bool {
        if (certificate_der.len == 0 or
            certificate_der.len > max_compatible_certificate_bytes)
        {
            return error.CompatibleTrustAnchorTooLarge;
        }
        const parsed = try certificate_compat.parse(certificate_der);
        if (now_seconds >= 0 and
            @as(u64, @intCast(now_seconds)) > parsed.standard.validity.not_after)
        {
            return false;
        }
        for (self.compatible_trust_anchors.items) |existing| {
            if (std.mem.eql(u8, existing, certificate_der)) return false;
        }
        if (self.compatible_trust_anchors.items.len ==
            hard_max_compatible_trust_anchors)
        {
            return error.CertificatePathTooManyTrustAnchors;
        }
        const owned = try self.allocator.dupe(u8, certificate_der);
        errdefer self.allocator.free(owned);
        try self.compatible_trust_anchors.append(self.allocator, owned);
        return true;
    }

    /// Decode and add every CERTIFICATE block in a PEM buffer atomically.
    /// Bytes outside certificate blocks are ignored, matching common CA files.
    pub fn addCompatiblePem(
        self: *SystemStore,
        pem: []const u8,
        now_seconds: i64,
    ) !usize {
        return self.addPemInternal(pem, now_seconds, false);
    }

    /// Add only certificates that Zig std's parser cannot represent but
    /// Vail's compatibility parser accepts. This is useful when the same PEM
    /// has already been loaded into `bundle` through Zig std.
    pub fn addUnsupportedPem(
        self: *SystemStore,
        pem: []const u8,
        now_seconds: i64,
    ) !usize {
        return self.addPemInternal(pem, now_seconds, true);
    }

    pub const PemFileOptions = struct {
        max_bytes: usize = default_max_compatible_pem_bytes,
        only_std_unsupported: bool = false,
    };

    /// Load compatible certificate anchors from a PEM file relative to `dir`.
    pub fn addCompatiblePemFile(
        self: *SystemStore,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        now_seconds: i64,
        options: PemFileOptions,
    ) !usize {
        if (options.max_bytes == 0) return error.InvalidPemFileLimit;
        const pem = try dir.readFileAlloc(
            io,
            sub_path,
            self.allocator,
            .limited(options.max_bytes),
        );
        defer self.allocator.free(pem);
        return self.addPemInternal(
            pem,
            now_seconds,
            options.only_std_unsupported,
        );
    }

    /// Load compatible anchors from an absolute PEM path.
    pub fn addCompatiblePemFileAbsolute(
        self: *SystemStore,
        io: std.Io,
        absolute_path: []const u8,
        now_seconds: i64,
        options: PemFileOptions,
    ) !usize {
        if (options.max_bytes == 0) return error.InvalidPemFileLimit;
        var file = try std.Io.Dir.openFileAbsolute(io, absolute_path, .{});
        defer file.close(io);
        var reader = file.reader(io, &.{});
        const pem = try reader.interface.allocRemaining(
            self.allocator,
            .limited(options.max_bytes),
        );
        defer self.allocator.free(pem);
        return self.addPemInternal(
            pem,
            now_seconds,
            options.only_std_unsupported,
        );
    }

    fn addPemInternal(
        self: *SystemStore,
        pem: []const u8,
        now_seconds: i64,
        only_std_unsupported: bool,
    ) !usize {
        const original_count = self.compatible_trust_anchors.items.len;
        errdefer self.rollbackCompatibleAnchors(original_count);
        var added: usize = 0;
        var position: usize = 0;
        var found = false;
        while (std.mem.indexOfPos(
            u8,
            pem,
            position,
            pem_certificate_begin,
        )) |begin| {
            found = true;
            const encoded_start = begin + pem_certificate_begin.len;
            const end = std.mem.indexOfPos(
                u8,
                pem,
                encoded_start,
                pem_certificate_end,
            ) orelse return error.MissingEndCertificateMarker;
            const encoded = std.mem.trim(
                u8,
                pem[encoded_start..end],
                " \t\r\n",
            );
            var significant_len: usize = 0;
            for (encoded) |byte| switch (byte) {
                ' ', '\t', '\r', '\n' => {},
                else => significant_len += 1,
            };
            const decoded_capacity = try std.base64.standard.Decoder
                .calcSizeUpperBound(significant_len);
            if (decoded_capacity == 0 or
                decoded_capacity > max_compatible_certificate_bytes)
            {
                return error.CompatibleTrustAnchorTooLarge;
            }
            const decoded = try self.allocator.alloc(u8, decoded_capacity);
            defer self.allocator.free(decoded);
            const decoded_len = try pem_base64.decode(decoded, encoded);
            if (only_std_unsupported) {
                if (Certificate.parse(.{
                    .buffer = decoded[0..decoded_len],
                    .index = 0,
                })) |_| {
                    position = end + pem_certificate_end.len;
                    continue;
                } else |_| {}
            }
            if (try self.addCompatibleCertificate(
                decoded[0..decoded_len],
                now_seconds,
            )) added += 1;
            position = end + pem_certificate_end.len;
        }
        if (!found) return error.MissingCertificateMarker;
        return added;
    }

    fn addPemFile(
        self: *SystemStore,
        io: std.Io,
        path: []const u8,
        now_seconds: i64,
    ) !void {
        const pem = if (std.fs.path.isAbsolute(path)) blk: {
            var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
            defer file.close(io);
            var reader = file.reader(io, &.{});
            break :blk try reader.interface.allocRemaining(
                self.allocator,
                .limited(default_max_compatible_pem_bytes),
            );
        } else blk: {
            var file = try std.Io.Dir.cwd().openFile(io, path, .{});
            defer file.close(io);
            var reader = file.reader(io, &.{});
            break :blk try reader.interface.allocRemaining(
                self.allocator,
                .limited(default_max_compatible_pem_bytes),
            );
        };
        defer self.allocator.free(pem);
        _ = try self.addPemBuffer(pem, now_seconds);
    }

    fn addPemDirectory(
        self: *SystemStore,
        io: std.Io,
        path: []const u8,
        now_seconds: i64,
    ) !void {
        var dir = if (std.fs.path.isAbsolute(path))
            try std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true })
        else
            try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        defer dir.close(io);

        var iterator = dir.iterate();
        while (try iterator.next(io)) |entry| {
            switch (entry.kind) {
                .file, .sym_link => {},
                else => continue,
            }
            const pem = dir.readFileAlloc(
                io,
                entry.name,
                self.allocator,
                .limited(default_max_compatible_pem_bytes),
            ) catch |err| switch (err) {
                // Match rustls-native-certs: one unreadable or oversized
                // file does not reject the rest of the directory.
                error.FileNotFound,
                error.AccessDenied,
                error.IsDir,
                error.StreamTooLong,
                error.SymLinkLoop,
                error.NotDir,
                => continue,
                else => return err,
            };
            defer self.allocator.free(pem);
            _ = try self.addPemBuffer(pem, now_seconds);
        }
    }

    /// Decode a PEM buffer into the std-indexed bundle and the compatibility
    /// anchor list. Invalid blocks are skipped independently so a single bad
    /// CA file cannot fail the whole native store load.
    fn addPemBuffer(
        self: *SystemStore,
        pem: []const u8,
        now_seconds: i64,
    ) !usize {
        var added: usize = 0;
        var position: usize = 0;
        while (std.mem.indexOfPos(
            u8,
            pem,
            position,
            pem_certificate_begin,
        )) |begin| {
            const encoded_start = begin + pem_certificate_begin.len;
            const end = std.mem.indexOfPos(
                u8,
                pem,
                encoded_start,
                pem_certificate_end,
            ) orelse break;
            position = end + pem_certificate_end.len;
            const encoded = std.mem.trim(
                u8,
                pem[encoded_start..end],
                " \t\r\n",
            );
            var significant_len: usize = 0;
            for (encoded) |byte| switch (byte) {
                ' ', '\t', '\r', '\n' => {},
                else => significant_len += 1,
            };
            const decoded_capacity = std.base64.standard.Decoder
                .calcSizeUpperBound(significant_len) catch continue;
            if (decoded_capacity == 0 or
                decoded_capacity > max_compatible_certificate_bytes)
            {
                continue;
            }
            const decoded = try self.allocator.alloc(u8, decoded_capacity);
            defer self.allocator.free(decoded);
            const decoded_len = pem_base64.decode(decoded, encoded) catch
                continue;
            const certificate_der = decoded[0..decoded_len];

            if (Certificate.parse(.{
                .buffer = certificate_der,
                .index = 0,
            })) |_| {
                const start = self.bundle.bytes.items.len;
                if (start > std.math.maxInt(u32)) {
                    return error.CertificateAuthorityBundleTooBig;
                }
                try self.bundle.bytes.appendSlice(
                    self.allocator,
                    certificate_der,
                );
                self.bundle.parseCert(
                    self.allocator,
                    @intCast(start),
                    now_seconds,
                ) catch {
                    self.bundle.bytes.shrinkRetainingCapacity(start);
                    continue;
                };
                if (self.bundle.bytes.items.len != start) added += 1;
            } else |_| {
                const compatible = self.addCompatibleCertificate(
                    certificate_der,
                    now_seconds,
                ) catch continue;
                if (compatible) added += 1;
            }
        }
        return added;
    }

    pub fn compatibleAnchorCount(self: *const SystemStore) usize {
        return self.compatible_trust_anchors.items.len;
    }

    fn rollbackCompatibleAnchors(self: *SystemStore, retained: usize) void {
        for (self.compatible_trust_anchors.items[retained..]) |certificate| {
            self.allocator.free(certificate);
        }
        self.compatible_trust_anchors.shrinkRetainingCapacity(retained);
    }

    pub fn verifier(
        self: *const SystemStore,
        now_seconds: i64,
    ) BundleVerifier {
        // Like slices returned by Certificate.Bundle, this verifier is
        // invalidated by a subsequent add operation or by deinit.
        return .{
            .bundle = &self.bundle,
            .compatible_trust_anchors = self.compatible_trust_anchors.items,
            .now_seconds = now_seconds,
        };
    }
};

fn parseServerIdentity(name: []const u8) ServerIdentity {
    const address = std.Io.net.IpAddress.parse(name, 0) catch
        return .{ .dns = name };
    return switch (address) {
        .ip4 => |ip4| .{ .ip4 = ip4.bytes },
        .ip6 => |ip6| .{ .ip6 = ip6.bytes },
    };
}

fn verifyServerIdentity(
    certificate: Certificate.Parsed,
    identity: ServerIdentity,
) !void {
    switch (identity) {
        .dns => |name| try certificate.verifyHostName(name),
        .rfc822 => unreachable,
        .uri => unreachable,
        .directory => unreachable,
        .ip4 => |address| try verifyIpSubjectAltName(
            certificate,
            &address,
        ),
        .ip6 => |address| try verifyIpSubjectAltName(
            certificate,
            &address,
        ),
    }
}

/// Verify only the server-identity binding of one DER leaf certificate.
///
/// This is intended for an already authenticated TLS connection that is being
/// considered for another authority, such as HTTP connection coalescing. It
/// deliberately does not replace trust-path, validity, revocation, or EKU
/// verification: callers must have completed those checks when the connection
/// was established. DNS names use the certificate parser's RFC 6125 matching;
/// IPv4 and IPv6 literals require an exact iPAddress subjectAltName.
pub fn verifyServerCertificateIdentity(
    certificate_der: []const u8,
    server_name: []const u8,
) !void {
    const certificate = try parseCertificate(certificate_der);
    try verifyServerIdentity(
        certificate,
        parseServerIdentity(server_name),
    );
}

fn verifyIpSubjectAltName(
    certificate: Certificate.Parsed,
    address: []const u8,
) !void {
    const encoded = certificate.subjectAltName();
    if (encoded.len == 0) return error.CertificateHostMismatch;
    const names = singleInner(encoded, 0x30) catch
        return error.InvalidCertificateExtension;
    var reader = DerReader{ .bytes = names.value };
    while (try reader.next()) |name| {
        if (name.tag != 0x87) continue;
        if (name.value.len != 4 and name.value.len != 16) {
            return error.InvalidCertificateExtension;
        }
        if (std.mem.eql(u8, address, name.value)) return;
    }
    return error.CertificateHostMismatch;
}

fn parseCertificate(der: []const u8) !Certificate.Parsed {
    return (try certificate_compat.parse(der)).standard;
}

/// Match a server-supplied cross-certificate to a configured trust anchor.
/// Name equality alone is insufficient: the complete SubjectPublicKeyInfo
/// must also identify the same CA key and parameters.
fn trustedEquivalentAnchorExact(
    bundle: *const Certificate.Bundle,
    subject: Certificate.Parsed,
) !?Certificate.Parsed {
    const anchor_index = bundle.find(subject.subject()) orelse return null;
    const anchor_der = try bundleCertificateDer(bundle, anchor_index);
    const anchor = try parseCertificate(anchor_der);
    if (!std.mem.eql(
        u8,
        subjectPublicKeyInfo(subject),
        subjectPublicKeyInfo(anchor),
    )) return null;
    return anchor;
}

fn trustedEquivalentAnchorFallback(
    bundle: *const Certificate.Bundle,
    subject: Certificate.Parsed,
) !?Certificate.Parsed {
    const exact_anchor_index = bundle.find(subject.subject());
    var anchors = bundle.map.iterator();
    while (anchors.next()) |entry| {
        const anchor_index = entry.value_ptr.*;
        if (exact_anchor_index != null and
            anchor_index == exact_anchor_index.?) continue;
        const anchor_der = try bundleCertificateDer(bundle, anchor_index);
        const anchor = try parseCertificate(anchor_der);
        if (!(directoryNamesEqual(
            subject.subject(),
            anchor.subject(),
        ) catch false)) continue;
        if (std.mem.eql(
            u8,
            subjectPublicKeyInfo(subject),
            subjectPublicKeyInfo(anchor),
        )) return anchor;
    }
    return null;
}

fn trustedEquivalentCompatibleAnchor(
    anchors: []const []const u8,
    subject: Certificate.Parsed,
    exact_name: bool,
) !?Certificate.Parsed {
    for (anchors) |anchor_der| {
        const anchor = try parseCertificate(anchor_der);
        const name_matches = if (exact_name)
            std.mem.eql(u8, subject.subject(), anchor.subject())
        else
            directoryNamesEqual(
                subject.subject(),
                anchor.subject(),
            ) catch false;
        if (!name_matches) continue;
        if (std.mem.eql(
            u8,
            subjectPublicKeyInfo(subject),
            subjectPublicKeyInfo(anchor),
        )) return anchor;
    }
    return null;
}

fn bundleCertificateDer(
    bundle: *const Certificate.Bundle,
    anchor_index: u32,
) ![]const u8 {
    const anchor_element = Certificate.der.Element.parse(
        bundle.bytes.items,
        anchor_index,
    ) catch return error.InvalidCertificate;
    return bundle.bytes.items[anchor_index..anchor_element.slice.end];
}

fn subjectPublicKeyInfo(subject: Certificate.Parsed) []const u8 {
    const start = subject.subject_slice.end;
    const element = Certificate.der.Element.parse(
        subject.certificate.buffer,
        start,
    ) catch unreachable;
    return subject.certificate.buffer[start..element.slice.end];
}

fn verifyValidity(subject: Certificate.Parsed, now_seconds: i64) !void {
    if (now_seconds < subject.validity.not_before) {
        return error.CertificateNotYetValid;
    }
    if (now_seconds > subject.validity.not_after) {
        return error.CertificateExpired;
    }
}

/// RFC 5280 pathLenConstraint counts only non-self-issued intermediate CA
/// certificates below the constrained certificate. The target leaf and the
/// constrained certificate itself are not part of this count.
fn countCaBelow(
    current: usize,
    issuer: Certificate.Parsed,
) !usize {
    if (try directoryNamesEqual(
        issuer.issuer(),
        issuer.subject(),
    )) return current;
    return std.math.add(usize, current, 1) catch
        error.CertificatePathLengthExceeded;
}

const CertificateUsage = struct {
    basic_constraints_present: bool = false,
    is_ca: bool = false,
    path_len: ?usize = null,
    key_usage_present: bool = false,
    digital_signature: bool = false,
    key_cert_sign: bool = false,
    crl_sign: bool = false,
    extended_key_usage_present: bool = false,
    server_auth: bool = false,
    client_auth: bool = false,
    any_extended_key_usage: bool = false,
    must_staple: bool = false,
    unsupported_critical_extension: bool = false,
    name_constraints: ?[]const u8 = null,
    policy_extensions: certificate_policy.Extensions = .{},
    subject_key_identifier: ?[]const u8 = null,
    authority_key_identifier: ?[]const u8 = null,
};

const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f };
const oid_extended_key_usage = [_]u8{ 0x55, 0x1d, 0x25 };
const oid_any_extended_key_usage = [_]u8{ 0x55, 0x1d, 0x25, 0x00 };

pub const OidFilterMatch = enum {
    unrecognized,
    mismatch,
    match,
};

pub const OidFilterKind = enum {
    unrecognized,
    key_usage,
    extended_key_usage,
};

pub const OidFilterError = error{
    InvalidOidFilter,
    InvalidCertificate,
};

/// Validate an RFC 8446 certificate-extension filter understood by Vail.
/// Unknown extension OIDs are valid and reported separately so callers can
/// ignore them as the RFC requires.
pub fn validateOidFilter(
    oid: []const u8,
    values: []const u8,
) OidFilterError!OidFilterKind {
    validateOid(oid) catch return error.InvalidOidFilter;
    if (std.mem.eql(u8, oid, &oid_key_usage)) {
        if (values.len != 0) {
            _ = parseKeyUsage(values) catch return error.InvalidOidFilter;
        }
        return .key_usage;
    }
    if (std.mem.eql(u8, oid, &oid_extended_key_usage)) {
        if (values.len != 0) {
            const usage = parseExtendedKeyUsage(values) catch
                return error.InvalidOidFilter;
            if (usage.any) return error.InvalidOidFilter;
        }
        return .extended_key_usage;
    }
    return .unrecognized;
}

/// Match one RFC 8446 OID filter against an end-entity certificate. Unknown
/// extension OIDs are reported separately so the TLS caller can skip them.
pub fn matchOidFilter(
    certificate_der: []const u8,
    oid: []const u8,
    values: []const u8,
) OidFilterError!OidFilterMatch {
    const kind = try validateOidFilter(oid, values);
    if (kind == .unrecognized) return .unrecognized;
    const certificate_value = (certificateExtensionValue(
        certificate_der,
        oid,
    ) catch return error.InvalidCertificate) orelse return .mismatch;
    if (values.len == 0) return .match;

    if (kind == .key_usage) {
        const requested = parseKeyUsage(values) catch
            return error.InvalidOidFilter;
        const certificate = parseKeyUsage(certificate_value) catch
            return error.InvalidCertificate;
        return if ((certificate.bits & requested.bits) == requested.bits)
            .match
        else
            .mismatch;
    }
    return if (extendedKeyUsageContainsAll(
        certificate_value,
        values,
    ) catch return error.InvalidCertificate) .match else .mismatch;
}

const UsageCache = union(enum) {
    unparsed,
    valid: CertificateUsage,
    invalid: anyerror,
};

fn issuerIdentityPriority(
    authority: AuthorityKeyIdentifier,
    subject_key_identifier: ?[]const u8,
    candidate_issuer_name: []const u8,
    candidate_serial_number: []const u8,
) !u2 {
    var matched = false;
    if (authority.key_identifier) |key_identifier| {
        if (subject_key_identifier) |candidate| {
            if (!std.mem.eql(u8, key_identifier, candidate)) return 2;
            matched = true;
        }
    }
    if (authority.authority_cert_serial_number) |serial_number| {
        if (!std.mem.eql(u8, serial_number, candidate_serial_number)) {
            return 2;
        }
        matched = true;
        const issuer_names = authority.authority_cert_issuer orelse
            return error.InvalidCertificateExtension;
        if (try authorityIssuerMatches(
            issuer_names,
            candidate_issuer_name,
        )) |issuer_matches| {
            if (!issuer_matches) return 2;
        }
    }
    return if (matched) 0 else 1;
}

fn issuerKeyPriority(
    authority_key_identifier: []const u8,
    subject_key_identifier: ?[]const u8,
) u2 {
    const candidate = subject_key_identifier orelse return 1;
    return if (std.mem.eql(u8, authority_key_identifier, candidate)) 0 else 2;
}

fn validateLeafUsage(
    certificate_der: []const u8,
    purpose: EndpointPurpose,
) !void {
    return validateLeafUsageProfile(
        try certificateUsage(certificate_der),
        purpose,
    );
}

fn validateLeafUsageProfile(
    usage: CertificateUsage,
    purpose: EndpointPurpose,
) !void {
    if (purpose == .certificate_authority) {
        return validateIssuerUsageProfile(usage, 0, purpose);
    }
    const crl_signing = purpose == .crl_signing;
    if (usage.unsupported_critical_extension or
        (!crl_signing and usage.basic_constraints_present and usage.is_ca) or
        (!crl_signing and usage.name_constraints != null) or
        (usage.key_usage_present and if (crl_signing)
            !usage.crl_sign
        else
            !usage.digital_signature) or
        (usage.extended_key_usage_present and
            !purposeAllowed(usage, purpose) and
            !usage.any_extended_key_usage))
    {
        return error.InvalidCertificateUsage;
    }
}

fn validateIssuerUsage(
    certificate_der: []const u8,
    ca_below: usize,
    purpose: EndpointPurpose,
) !void {
    return validateIssuerUsageProfile(
        try certificateUsage(certificate_der),
        ca_below,
        purpose,
    );
}

fn validateIssuerUsageProfile(
    usage: CertificateUsage,
    ca_below: usize,
    purpose: EndpointPurpose,
) !void {
    if (usage.unsupported_critical_extension or
        !usage.basic_constraints_present or
        !usage.is_ca or
        (usage.key_usage_present and !usage.key_cert_sign) or
        (usage.extended_key_usage_present and
            !purposeAllowed(usage, purpose) and
            !usage.any_extended_key_usage))
    {
        return error.InvalidCertificateUsage;
    }
    if (usage.path_len) |limit| {
        if (ca_below > limit) return error.CertificatePathLengthExceeded;
    }
}

fn purposeAllowed(
    usage: CertificateUsage,
    purpose: EndpointPurpose,
) bool {
    return switch (purpose) {
        .server_auth => usage.server_auth,
        .client_auth => usage.client_auth,
        .crl_signing => false,
        .certificate_authority => true,
    };
}

fn certificateUsage(certificate_der: []const u8) !CertificateUsage {
    const extensions = try certificateExtensions(certificate_der) orelse
        return .{};
    var result: CertificateUsage = .{};
    var reader = DerReader{ .bytes = extensions.value };
    while (reader.pos < reader.bytes.len) {
        const extension_offset = reader.pos;
        const extension = (try reader.next()) orelse unreachable;
        if (extension.tag != 0x30) return error.InvalidCertificateExtension;
        var fields = DerReader{ .bytes = extension.value };
        const oid = try fields.require(0x06);
        try validateOid(oid.value);
        var prior = DerReader{
            .bytes = extensions.value[0..extension_offset],
        };
        while (try prior.next()) |prior_extension| {
            if (prior_extension.tag != 0x30) {
                return error.InvalidCertificateExtension;
            }
            var prior_fields = DerReader{ .bytes = prior_extension.value };
            const prior_oid = try prior_fields.require(0x06);
            if (std.mem.eql(u8, prior_oid.value, oid.value)) {
                return error.InvalidCertificateExtension;
            }
        }

        var value = (try fields.next()) orelse
            return error.InvalidCertificateExtension;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidCertificateExtension;
            }
            critical = true;
            value = (try fields.next()) orelse
                return error.InvalidCertificateExtension;
        }
        if (value.tag != 0x04 or try fields.next() != null) {
            return error.InvalidCertificateExtension;
        }

        if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x13 })) {
            if (result.basic_constraints_present) {
                return error.InvalidCertificateExtension;
            }
            result.basic_constraints_present = true;
            const constraints = try parseBasicConstraints(value.value);
            result.is_ca = constraints.is_ca;
            result.path_len = constraints.path_len;
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x0f })) {
            if (result.key_usage_present) {
                return error.InvalidCertificateExtension;
            }
            result.key_usage_present = true;
            const key_usage = try parseKeyUsage(value.value);
            result.digital_signature = key_usage.digital_signature;
            result.key_cert_sign = key_usage.key_cert_sign;
            result.crl_sign = key_usage.crl_sign;
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x25 })) {
            if (result.extended_key_usage_present) {
                return error.InvalidCertificateExtension;
            }
            result.extended_key_usage_present = true;
            const extended = try parseExtendedKeyUsage(value.value);
            result.server_auth = extended.server_auth;
            result.client_auth = extended.client_auth;
            result.any_extended_key_usage = extended.any;
        } else if (std.mem.eql(
            u8,
            oid.value,
            &.{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18 },
        )) {
            const features = try parseTlsFeatures(value.value);
            result.must_staple = features.status_request;
            if (critical and features.unsupported) {
                result.unsupported_critical_extension = true;
            }
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x11 })) {
            // Hostname verification above consumes subjectAltName.
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x0e })) {
            if (critical or result.subject_key_identifier != null) {
                return error.InvalidCertificateExtension;
            }
            result.subject_key_identifier = try parseSubjectKeyIdentifier(
                value.value,
            );
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x23 })) {
            if (critical) {
                return error.InvalidCertificateExtension;
            }
            result.authority_key_identifier =
                try parseAuthorityKeyIdentifier(value.value);
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x1e })) {
            if (result.name_constraints != null) {
                return error.InvalidCertificateExtension;
            }
            try validateNameConstraintsSyntax(value.value);
            result.name_constraints = value.value;
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x20 })) {
            result.policy_extensions.certificate_policies = .{
                .encoded = value.value,
                .critical = critical,
            };
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x21 })) {
            result.policy_extensions.policy_mappings = .{
                .encoded = value.value,
                .critical = critical,
            };
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x24 })) {
            result.policy_extensions.policy_constraints = .{
                .encoded = value.value,
                .critical = critical,
            };
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x36 })) {
            result.policy_extensions.inhibit_any_policy = .{
                .encoded = value.value,
                .critical = critical,
            };
        } else if (critical) {
            result.unsupported_critical_extension = true;
        }
    }
    try certificate_policy.validateExtensions(result.policy_extensions);
    if (!result.is_ca and
        (result.policy_extensions.policy_mappings != null or
            result.policy_extensions.policy_constraints != null or
            result.policy_extensions.inhibit_any_policy != null))
    {
        return error.InvalidCertificatePolicy;
    }
    return result;
}

fn certificateExtensionValue(
    certificate_der: []const u8,
    target_oid: []const u8,
) !?[]const u8 {
    const extensions = try certificateExtensions(certificate_der) orelse
        return null;
    var result: ?[]const u8 = null;
    var reader = DerReader{ .bytes = extensions.value };
    while (try reader.next()) |extension| {
        if (extension.tag != 0x30) {
            return error.InvalidCertificateExtension;
        }
        var fields = DerReader{ .bytes = extension.value };
        const oid = try fields.require(0x06);
        try validateOid(oid.value);
        var value = (try fields.next()) orelse
            return error.InvalidCertificateExtension;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidCertificateExtension;
            }
            value = (try fields.next()) orelse
                return error.InvalidCertificateExtension;
        }
        if (value.tag != 0x04 or try fields.next() != null) {
            return error.InvalidCertificateExtension;
        }
        if (std.mem.eql(u8, oid.value, target_oid)) {
            if (result != null) return error.InvalidCertificateExtension;
            result = value.value;
        }
    }
    return result;
}

fn certificateAuthorityKeyIdentifier(
    certificate_der: []const u8,
) !?AuthorityKeyIdentifier {
    const extensions = try certificateExtensions(certificate_der) orelse
        return null;
    var reader = DerReader{ .bytes = extensions.value };
    while (try reader.next()) |extension| {
        if (extension.tag != 0x30) {
            return error.InvalidCertificateExtension;
        }
        var fields = DerReader{ .bytes = extension.value };
        const oid = try fields.require(0x06);
        var value = (try fields.next()) orelse
            return error.InvalidCertificateExtension;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidCertificateExtension;
            }
            critical = true;
            value = (try fields.next()) orelse
                return error.InvalidCertificateExtension;
        }
        if (value.tag != 0x04 or try fields.next() != null) {
            return error.InvalidCertificateExtension;
        }
        if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x23 })) {
            if (critical) return error.InvalidCertificateExtension;
            return @as(
                ?AuthorityKeyIdentifier,
                try parseAuthorityKeyIdentifierDetails(value.value),
            );
        }
    }
    return null;
}

fn parseSubjectKeyIdentifier(encoded: []const u8) ![]const u8 {
    const key_identifier = try singleInner(encoded, 0x04);
    if (key_identifier.value.len == 0) {
        return error.InvalidCertificateExtension;
    }
    return key_identifier.value;
}

const AuthorityKeyIdentifier = struct {
    key_identifier: ?[]const u8 = null,
    authority_cert_issuer: ?[]const u8 = null,
    authority_cert_serial_number: ?[]const u8 = null,
};

fn parseAuthorityKeyIdentifier(encoded: []const u8) !?[]const u8 {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCertificateExtension;
    var fields = DerReader{ .bytes = sequence.value };
    var key_identifier: ?[]const u8 = null;
    var saw_issuer = false;
    var saw_serial = false;
    var previous_tag_number: ?u8 = null;
    while (try fields.next()) |field| {
        const tag_number = field.tag & 0x1f;
        if ((field.tag != 0x80 and field.tag != 0xa1 and
            field.tag != 0x82) or
            (previous_tag_number != null and
                tag_number <= previous_tag_number.?))
        {
            return error.InvalidCertificateExtension;
        }
        previous_tag_number = tag_number;
        switch (field.tag) {
            0x80 => {
                if (field.value.len == 0) {
                    return error.InvalidCertificateExtension;
                }
                key_identifier = field.value;
            },
            0xa1 => {
                if (field.value.len == 0) {
                    return error.InvalidCertificateExtension;
                }
                var names = DerReader{ .bytes = field.value };
                var count: usize = 0;
                while (try names.next()) |name| {
                    if (!isGeneralNameTag(name.tag)) {
                        return error.InvalidCertificateExtension;
                    }
                    if (name.tag == 0xa4) {
                        _ = try singleInner(name.value, 0x30);
                    }
                    count += 1;
                }
                if (count == 0) return error.InvalidCertificateExtension;
                saw_issuer = true;
            },
            0x82 => {
                try validateCertificateSerialValue(field.value);
                saw_serial = true;
            },
            else => unreachable,
        }
    }
    if (saw_issuer != saw_serial or
        (key_identifier == null and !saw_issuer))
    {
        return error.InvalidCertificateExtension;
    }
    return key_identifier;
}

fn parseAuthorityKeyIdentifierDetails(
    encoded: []const u8,
) !AuthorityKeyIdentifier {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCertificateExtension;
    var fields = DerReader{ .bytes = sequence.value };
    var result: AuthorityKeyIdentifier = .{};
    var previous_tag_number: ?u8 = null;
    while (try fields.next()) |field| {
        const tag_number = field.tag & 0x1f;
        if ((field.tag != 0x80 and field.tag != 0xa1 and
            field.tag != 0x82) or
            (previous_tag_number != null and
                tag_number <= previous_tag_number.?))
        {
            return error.InvalidCertificateExtension;
        }
        previous_tag_number = tag_number;
        switch (field.tag) {
            0x80 => {
                if (field.value.len == 0) {
                    return error.InvalidCertificateExtension;
                }
                result.key_identifier = field.value;
            },
            0xa1 => {
                if (field.value.len == 0) {
                    return error.InvalidCertificateExtension;
                }
                var names = DerReader{ .bytes = field.value };
                var count: usize = 0;
                while (try names.next()) |name| {
                    if (!isGeneralNameTag(name.tag)) {
                        return error.InvalidCertificateExtension;
                    }
                    if (name.tag == 0xa4) {
                        _ = try singleInner(name.value, 0x30);
                    }
                    count += 1;
                }
                if (count == 0) return error.InvalidCertificateExtension;
                result.authority_cert_issuer = field.value;
            },
            0x82 => {
                try validateCertificateSerialValue(field.value);
                result.authority_cert_serial_number = field.value;
            },
            else => unreachable,
        }
    }
    if ((result.authority_cert_issuer == null) !=
        (result.authority_cert_serial_number == null) or
        (result.key_identifier == null and
            result.authority_cert_issuer == null))
    {
        return error.InvalidCertificateExtension;
    }
    return result;
}

fn authorityIssuerMatches(
    encoded_names: []const u8,
    candidate_issuer_name: []const u8,
) !?bool {
    var names = DerReader{ .bytes = encoded_names };
    var saw_directory_name = false;
    while (try names.next()) |name| {
        if (name.tag != 0xa4) continue;
        const directory_name = try singleInner(name.value, 0x30);
        saw_directory_name = true;
        if (try directoryNamesEqual(
            directory_name.value,
            candidate_issuer_name,
        )) return true;
    }
    return if (saw_directory_name) false else null;
}

fn certificateSerialNumber(certificate_der: []const u8) ![]const u8 {
    const certificate = try singleInner(certificate_der, 0x30);
    var certificate_fields = DerReader{ .bytes = certificate.value };
    const tbs = try certificate_fields.require(0x30);
    var tbs_fields = DerReader{ .bytes = tbs.value };
    var serial = (try tbs_fields.next()) orelse
        return error.InvalidCertificate;
    if (serial.tag == 0xa0) {
        serial = try tbs_fields.require(0x02);
    } else if (serial.tag != 0x02) {
        return error.InvalidCertificate;
    }
    try validateCertificateSerialValue(serial.value);
    return serial.value;
}

fn isGeneralNameTag(tag: u8) bool {
    return switch (tag) {
        // Constructed: otherName, x400Address, directoryName, ediPartyName.
        0xa0,
        0xa3,
        0xa4,
        0xa5,
        // Primitive: rfc822Name, dNSName, URI, iPAddress, registeredID.
        0x81,
        0x82,
        0x86,
        0x87,
        0x88,
        => true,
        else => false,
    };
}

fn validateCertificateSerialValue(value: []const u8) !void {
    if (value.len == 0 or value.len > 20 or (value[0] & 0x80) != 0 or
        (value.len > 1 and value[0] == 0 and (value[1] & 0x80) == 0))
    {
        return error.InvalidCertificateExtension;
    }
    var nonzero = false;
    for (value) |byte| nonzero = nonzero or byte != 0;
    if (!nonzero) return error.InvalidCertificateExtension;
}

fn validateNameConstraintsSyntax(encoded: []const u8) !void {
    _ = try parseNameConstraints(encoded, null, false);
}

fn validateDnsNameConstraints(
    encoded: []const u8,
    dns_name: []const u8,
) !void {
    return validateNameConstraints(encoded, .{ .dns = dns_name });
}

fn validateNameConstraints(
    encoded: []const u8,
    identity: ServerIdentity,
) !void {
    const result = try parseNameConstraints(encoded, identity, true);
    if (result.excluded_match or
        (result.saw_permitted and !result.permitted_match))
    {
        return error.CertificateNameConstraintViolation;
    }
}

fn validateCertificateNamesAgainstConstraints(
    constraints: []const u8,
    certificate: *const Certificate.Parsed,
) !void {
    const subject = certificate.subject();
    if (subject.len != 0) {
        try validateNameConstraints(
            constraints,
            .{ .directory = subject },
        );
    }
    const encoded_names = certificate.subjectAltName();
    if (encoded_names.len == 0) {
        return validateSubjectEmailAddresses(
            constraints,
            certificate.subject(),
        );
    }
    const names = singleInner(encoded_names, 0x30) catch
        return error.InvalidCertificateExtension;
    var reader = DerReader{ .bytes = names.value };
    while (try reader.next()) |name| {
        switch (name.tag) {
            0x81 => try validateNameConstraints(
                constraints,
                .{ .rfc822 = try parseRfc822Name(name.value) },
            ),
            0x82 => {
                if (name.value.len == 0) {
                    return error.InvalidCertificateExtension;
                }
                try validateNameConstraints(
                    constraints,
                    .{ .dns = name.value },
                );
            },
            0x86 => try validateNameConstraints(
                constraints,
                .{ .uri = try parseUriHost(name.value) },
            ),
            0x87 => {
                if (name.value.len == 4) {
                    try validateNameConstraints(
                        constraints,
                        .{ .ip4 = name.value[0..4].* },
                    );
                } else if (name.value.len == 16) {
                    try validateNameConstraints(
                        constraints,
                        .{ .ip6 = name.value[0..16].* },
                    );
                } else {
                    return error.InvalidCertificateExtension;
                }
            },
            0xa4 => {
                const directory_name = try singleInner(name.value, 0x30);
                try validateNameConstraints(
                    constraints,
                    .{ .directory = directory_name.value },
                );
            },
            else => {},
        }
    }
}

const oid_email_address = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01,
};

fn validateSubjectEmailAddresses(
    constraints: []const u8,
    subject: []const u8,
) !void {
    var rdns = DerReader{ .bytes = subject };
    while (try rdns.next()) |rdn| {
        if (rdn.tag != 0x31) return error.InvalidCertificateExtension;
        var attributes = DerReader{ .bytes = rdn.value };
        while (try attributes.next()) |attribute| {
            if (attribute.tag != 0x30) {
                return error.InvalidCertificateExtension;
            }
            var fields = DerReader{ .bytes = attribute.value };
            const oid = try fields.require(0x06);
            const value = (try fields.next()) orelse
                return error.InvalidCertificateExtension;
            if (try fields.next() != null) {
                return error.InvalidCertificateExtension;
            }
            if (!std.mem.eql(u8, oid.value, &oid_email_address)) continue;
            if (value.tag != 0x16) return error.InvalidCertificateExtension;
            try validateNameConstraints(
                constraints,
                .{ .rfc822 = try parseRfc822Name(value.value) },
            );
        }
    }
}

const NameConstraintResult = struct {
    saw_permitted: bool = false,
    permitted_match: bool = false,
    excluded_match: bool = false,
};

fn parseNameConstraints(
    encoded: []const u8,
    identity: ?ServerIdentity,
    evaluate: bool,
) !NameConstraintResult {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCertificateExtension;
    var fields = DerReader{ .bytes = sequence.value };
    var result: NameConstraintResult = .{};
    var saw_permitted_field = false;
    var saw_excluded_field = false;
    while (try fields.next()) |field| {
        const excluded = switch (field.tag) {
            0xa0 => false,
            0xa1 => true,
            else => return error.UnsupportedCertificateNameConstraint,
        };
        if (excluded) {
            if (saw_excluded_field) return error.InvalidCertificateExtension;
            saw_excluded_field = true;
        } else {
            if (saw_permitted_field) return error.InvalidCertificateExtension;
            saw_permitted_field = true;
        }
        if (field.value.len == 0) return error.InvalidCertificateExtension;
        var subtrees = DerReader{ .bytes = field.value };
        while (try subtrees.next()) |subtree| {
            if (subtree.tag != 0x30) {
                return error.InvalidCertificateExtension;
            }
            var subtree_fields = DerReader{ .bytes = subtree.value };
            const base = (try subtree_fields.next()) orelse
                return error.InvalidCertificateExtension;
            const relevant = switch (base.tag) {
                0x81 => blk: {
                    if (!validRfc822Constraint(base.value)) {
                        return error.InvalidCertificateExtension;
                    }
                    break :blk if (identity) |name| switch (name) {
                        .rfc822 => true,
                        else => false,
                    } else false;
                },
                0x82 => blk: {
                    if (!validDnsConstraint(base.value)) {
                        return error.InvalidCertificateExtension;
                    }
                    break :blk if (identity) |name| switch (name) {
                        .dns => true,
                        else => false,
                    } else false;
                },
                0x86 => blk: {
                    if (!validUriConstraint(base.value)) {
                        return error.InvalidCertificateExtension;
                    }
                    break :blk if (identity) |name| switch (name) {
                        .uri => true,
                        else => false,
                    } else false;
                },
                0x87 => blk: {
                    try validateIpConstraint(base.value);
                    break :blk if (identity) |name| switch (name) {
                        .ip4 => base.value.len == 8,
                        .ip6 => base.value.len == 32,
                        else => false,
                    } else false;
                },
                0xa4 => blk: {
                    const directory_name = try singleInner(
                        base.value,
                        0x30,
                    );
                    try validateDirectoryName(directory_name.value);
                    break :blk if (identity) |name| switch (name) {
                        .directory => true,
                        else => false,
                    } else false;
                },
                else => return error.UnsupportedCertificateNameConstraint,
            };
            while (try subtree_fields.next()) |distance| {
                // minimum [0] is permitted only when explicitly zero;
                // maximum [1] and non-zero minimum are unsupported.
                if (distance.tag != 0x80 or distance.value.len != 1 or
                    distance.value[0] != 0)
                {
                    return error.UnsupportedCertificateNameConstraint;
                }
            }
            if (relevant and !excluded) result.saw_permitted = true;
            if (evaluate and relevant and try identityMatchesConstraint(
                identity.?,
                base,
            )) {
                if (excluded) {
                    result.excluded_match = true;
                } else {
                    result.permitted_match = true;
                }
            }
        }
    }
    return result;
}

fn validateIpConstraint(constraint: []const u8) !void {
    if (constraint.len != 8 and constraint.len != 32) {
        return error.InvalidCertificateExtension;
    }
    const half = constraint.len / 2;
    const address = constraint[0..half];
    const mask = constraint[half..];
    var saw_zero = false;
    for (mask) |byte| {
        var bit: u8 = 0x80;
        while (bit != 0) : (bit >>= 1) {
            if ((byte & bit) == 0) {
                saw_zero = true;
            } else if (saw_zero) {
                return error.InvalidCertificateExtension;
            }
        }
    }
    for (address, mask) |address_byte, mask_byte| {
        if ((address_byte & ~mask_byte) != 0) {
            return error.InvalidCertificateExtension;
        }
    }
}

fn validRfc822Constraint(value: []const u8) bool {
    if (std.mem.indexOfScalar(u8, value, '@') != null) {
        _ = parseRfc822Name(value) catch return false;
        return true;
    }
    return validDnsConstraint(value);
}

fn parseRfc822Name(value: []const u8) !Rfc822Name {
    if (value.len < 3) return error.InvalidCertificateExtension;
    var at: usize = 0;
    if (value[0] == '"') {
        var index: usize = 1;
        var closed = false;
        while (index < value.len) : (index += 1) {
            const byte = value[index];
            if (byte == '\\') {
                index += 1;
                if (index >= value.len or
                    value[index] < 0x20 or value[index] >= 0x7f)
                {
                    return error.InvalidCertificateExtension;
                }
                continue;
            }
            if (byte == '"') {
                at = index + 1;
                closed = true;
                break;
            }
            if (byte < 0x20 or byte >= 0x7f) {
                return error.InvalidCertificateExtension;
            }
        }
        if (!closed or at >= value.len or value[at] != '@') {
            return error.InvalidCertificateExtension;
        }
    } else {
        at = std.mem.indexOfScalar(u8, value, '@') orelse
            return error.InvalidCertificateExtension;
        if (at == 0) return error.InvalidCertificateExtension;
        var previous_dot = true;
        for (value[0..at]) |byte| {
            if (byte == '.') {
                if (previous_dot) return error.InvalidCertificateExtension;
                previous_dot = true;
            } else {
                if (!isRfc822Atext(byte)) {
                    return error.InvalidCertificateExtension;
                }
                previous_dot = false;
            }
        }
        if (previous_dot) return error.InvalidCertificateExtension;
    }
    if (at + 1 >= value.len or
        std.mem.indexOfScalar(u8, value[at + 1 ..], '@') != null)
    {
        return error.InvalidCertificateExtension;
    }
    const domain = value[at + 1 ..];
    if (domain[0] == '.' or !validDnsConstraint(domain)) {
        return error.InvalidCertificateExtension;
    }
    return .{ .local = value[0..at], .domain = domain };
}

fn isRfc822Atext(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!',
        '#',
        '$',
        '%',
        '&',
        '\'',
        '*',
        '+',
        '-',
        '/',
        '=',
        '?',
        '^',
        '_',
        '`',
        '{',
        '|',
        '}',
        '~',
        => true,
        else => false,
    };
}

fn rfc822WithinConstraint(
    mailbox: Rfc822Name,
    constraint: []const u8,
) bool {
    if (std.mem.indexOfScalar(u8, constraint, '@') != null) {
        const required = parseRfc822Name(constraint) catch return false;
        return std.mem.eql(u8, mailbox.local, required.local) and
            std.ascii.eqlIgnoreCase(mailbox.domain, required.domain);
    }
    if (constraint[0] == '.') {
        return dnsWithinConstraint(mailbox.domain, constraint);
    }
    return std.ascii.eqlIgnoreCase(mailbox.domain, constraint);
}

fn validUriConstraint(value: []const u8) bool {
    if (!validDnsConstraint(value)) return false;
    const host = if (value[0] == '.') value[1..] else value;
    if (std.Io.net.IpAddress.parse(host, 0)) |_| return false else |_| {}
    return true;
}

fn parseUriHost(uri: []const u8) ![]const u8 {
    if (uri.len < 4 or !std.ascii.isAlphabetic(uri[0])) {
        return error.InvalidCertificateExtension;
    }
    var scheme_end: ?usize = null;
    for (uri[1..], 1..) |byte, index| {
        if (byte == ':') {
            scheme_end = index;
            break;
        }
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '+' and byte != '-' and byte != '.')
        {
            return error.InvalidCertificateExtension;
        }
    }
    const colon = scheme_end orelse return error.InvalidCertificateExtension;
    if (colon + 3 > uri.len or
        !std.mem.eql(u8, uri[colon + 1 ..][0..2], "//"))
    {
        return error.InvalidCertificateExtension;
    }
    for (uri) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) {
            return error.InvalidCertificateExtension;
        }
    }

    const authority_start = colon + 3;
    var authority_end = authority_start;
    while (authority_end < uri.len and
        uri[authority_end] != '/' and
        uri[authority_end] != '?' and
        uri[authority_end] != '#')
    {
        authority_end += 1;
    }
    if (authority_end == authority_start) {
        return error.InvalidCertificateExtension;
    }
    const authority = uri[authority_start..authority_end];
    const host_port = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| blk: {
        if (std.mem.indexOfScalar(u8, authority[0..at], '@') != null) {
            return error.InvalidCertificateExtension;
        }
        break :blk authority[at + 1 ..];
    } else authority;
    if (host_port.len == 0 or host_port[0] == '[') {
        return error.InvalidCertificateExtension;
    }

    const host = if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |port_separator| blk: {
        const port = host_port[port_separator + 1 ..];
        for (port) |byte| {
            if (!std.ascii.isDigit(byte)) {
                return error.InvalidCertificateExtension;
            }
        }
        break :blk host_port[0..port_separator];
    } else host_port;
    if (host.len == 0 or host[0] == '.' or !validDnsConstraint(host)) {
        return error.InvalidCertificateExtension;
    }
    if (std.Io.net.IpAddress.parse(host, 0)) |_| {
        return error.InvalidCertificateExtension;
    } else |_| {}
    return host;
}

fn uriWithinConstraint(host: []const u8, constraint: []const u8) bool {
    if (constraint[0] == '.') return dnsWithinConstraint(host, constraint);
    return std.ascii.eqlIgnoreCase(host, constraint);
}

fn validateDirectoryName(name: []const u8) !void {
    distinguished_name.validate(name) catch |err| return switch (err) {
        error.InvalidName => error.InvalidCertificateExtension,
        error.UnsupportedDirectoryString => error.UnsupportedCertificateNameConstraint,
    };
}

fn directoryNameWithinConstraint(
    name: []const u8,
    constraint: []const u8,
) !bool {
    return distinguished_name.withinSubtree(
        name,
        constraint,
    ) catch |err| return switch (err) {
        error.InvalidName => error.InvalidCertificateExtension,
        error.UnsupportedDirectoryString => error.UnsupportedCertificateNameConstraint,
    };
}

fn identityMatchesConstraint(
    identity: ServerIdentity,
    constraint: Tlv,
) !bool {
    return switch (identity) {
        .dns => |dns_name| constraint.tag == 0x82 and
            dnsWithinConstraint(dns_name, constraint.value),
        .rfc822 => |mailbox| constraint.tag == 0x81 and
            rfc822WithinConstraint(mailbox, constraint.value),
        .uri => |host| constraint.tag == 0x86 and
            uriWithinConstraint(host, constraint.value),
        .directory => |name| if (constraint.tag == 0xa4) blk: {
            const base = try singleInner(constraint.value, 0x30);
            break :blk try directoryNameWithinConstraint(name, base.value);
        } else false,
        .ip4 => |address| constraint.tag == 0x87 and
            ipWithinConstraint(&address, constraint.value),
        .ip6 => |address| constraint.tag == 0x87 and
            ipWithinConstraint(&address, constraint.value),
    };
}

fn ipWithinConstraint(
    address: []const u8,
    constraint: []const u8,
) bool {
    if (constraint.len != address.len * 2) return false;
    const subnet = constraint[0..address.len];
    const mask = constraint[address.len..];
    for (address, subnet, mask) |address_byte, subnet_byte, mask_byte| {
        if ((address_byte & mask_byte) != subnet_byte) return false;
    }
    return true;
}

fn validDnsConstraint(value: []const u8) bool {
    if (value.len == 0 or value[value.len - 1] == '.') return false;
    const name = if (value[0] == '.') value[1..] else value;
    if (name.len == 0 or name.len > 253) return false;
    var label_len: usize = 0;
    var previous: u8 = 0;
    for (name) |byte| {
        if (byte == '.') {
            if (label_len == 0 or previous == '-') return false;
            label_len = 0;
            previous = byte;
            continue;
        }
        if (!std.ascii.isAlphanumeric(byte) and byte != '-') {
            return false;
        }
        if (label_len == 0 and byte == '-') return false;
        label_len += 1;
        if (label_len > 63) return false;
        previous = byte;
    }
    return label_len != 0 and previous != '-';
}

fn dnsWithinConstraint(dns_name: []const u8, constraint: []const u8) bool {
    const subdomains_only = constraint[0] == '.';
    const base = if (subdomains_only) constraint[1..] else constraint;
    if (!subdomains_only and std.ascii.eqlIgnoreCase(dns_name, base)) {
        return true;
    }
    if (dns_name.len <= base.len or
        dns_name[dns_name.len - base.len - 1] != '.')
    {
        return false;
    }
    return std.ascii.eqlIgnoreCase(
        dns_name[dns_name.len - base.len ..],
        base,
    );
}

fn certificateExtensions(certificate_der: []const u8) !?Tlv {
    var top = DerReader{ .bytes = certificate_der };
    const certificate = try top.require(0x30);
    if (try top.next() != null) return error.InvalidCertificateExtension;
    var certificate_fields = DerReader{ .bytes = certificate.value };
    const tbs = try certificate_fields.require(0x30);
    _ = try certificate_fields.require(0x30);
    _ = try certificate_fields.require(0x03);
    if (try certificate_fields.next() != null) {
        return error.InvalidCertificateExtension;
    }

    var fields = DerReader{ .bytes = tbs.value };
    var first = (try fields.next()) orelse
        return error.InvalidCertificateExtension;
    if (first.tag == 0xa0) {
        first = (try fields.next()) orelse
            return error.InvalidCertificateExtension;
    }
    if (first.tag != 0x02) return error.InvalidCertificateExtension;
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    while (try fields.next()) |optional| {
        switch (optional.tag) {
            0x81, 0x82 => {},
            0xa3 => {
                const extensions = try singleInner(optional.value, 0x30);
                if (try fields.next() != null) {
                    return error.InvalidCertificateExtension;
                }
                return extensions;
            },
            else => return error.InvalidCertificateExtension,
        }
    }
    return null;
}

const BasicConstraints = struct {
    is_ca: bool = false,
    path_len: ?usize = null,
};

fn parseBasicConstraints(encoded: []const u8) !BasicConstraints {
    const sequence = try singleInner(encoded, 0x30);
    var fields = DerReader{ .bytes = sequence.value };
    var result: BasicConstraints = .{};
    if (try fields.next()) |first| {
        if (first.tag != 0x01 or
            first.value.len != 1 or
            first.value[0] != 0xff)
        {
            return error.InvalidCertificateExtension;
        }
        result.is_ca = true;
        if (try fields.next()) |path_len| {
            result.path_len = try nonNegativeInteger(path_len);
            if (try fields.next() != null) {
                return error.InvalidCertificateExtension;
            }
        }
    }
    return result;
}

const KeyUsage = struct {
    digital_signature: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    bits: u16,
};

fn parseKeyUsage(encoded: []const u8) !KeyUsage {
    const bits = try singleInner(encoded, 0x03);
    if (bits.value.len < 2 or bits.value.len > 3) {
        return error.InvalidCertificateExtension;
    }
    const unused = bits.value[0];
    if (unused > 7) return error.InvalidCertificateExtension;
    const last = bits.value[bits.value.len - 1];
    if (last == 0 or
        (unused != 0 and
            (last & ((@as(u8, 1) << @intCast(unused)) - 1)) != 0))
    {
        return error.InvalidCertificateExtension;
    }
    var trailing_zero_bits: u4 = 0;
    var shifted = last;
    while ((shifted & 1) == 0) : (shifted >>= 1) {
        trailing_zero_bits += 1;
    }
    if (unused != trailing_zero_bits or
        (bits.value.len == 3 and (bits.value[2] & 0x7f) != 0))
    {
        return error.InvalidCertificateExtension;
    }
    return .{
        .digital_signature = (bits.value[1] & 0x80) != 0,
        .key_cert_sign = (bits.value[1] & 0x04) != 0,
        .crl_sign = (bits.value[1] & 0x02) != 0,
        .bits = (@as(u16, bits.value[1]) << 8) |
            if (bits.value.len == 3) @as(u16, bits.value[2]) else 0,
    };
}

const ExtendedKeyUsage = struct {
    server_auth: bool = false,
    client_auth: bool = false,
    any: bool = false,
};

const TlsFeatures = struct {
    status_request: bool = false,
    unsupported: bool = false,
};

/// RFC 7633 encodes TLS features as a non-empty SEQUENCE OF INTEGER. This
/// parser accepts unknown non-negative feature numbers so a non-critical
/// extension remains forward compatible, while reporting them to the caller
/// for critical-extension handling.
fn parseTlsFeatures(encoded: []const u8) !TlsFeatures {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCertificateExtension;

    var result: TlsFeatures = .{};
    var features = DerReader{ .bytes = sequence.value };
    while (features.pos < features.bytes.len) {
        const feature_offset = features.pos;
        const feature = (try features.next()) orelse unreachable;
        if (feature.tag != 0x02 or feature.value.len == 0 or
            (feature.value[0] & 0x80) != 0 or
            (feature.value.len > 1 and feature.value[0] == 0 and
                (feature.value[1] & 0x80) == 0))
        {
            return error.InvalidCertificateExtension;
        }

        var prior = DerReader{
            .bytes = sequence.value[0..feature_offset],
        };
        while (try prior.next()) |prior_feature| {
            if (std.mem.eql(u8, prior_feature.value, feature.value)) {
                return error.InvalidCertificateExtension;
            }
        }

        if (feature.value.len == 1 and feature.value[0] == 5) {
            result.status_request = true;
        } else {
            result.unsupported = true;
        }
    }
    return result;
}

fn parseExtendedKeyUsage(encoded: []const u8) !ExtendedKeyUsage {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCertificateExtension;
    var purposes = DerReader{ .bytes = sequence.value };
    var result: ExtendedKeyUsage = .{};
    while (try purposes.next()) |purpose| {
        if (purpose.tag != 0x06) return error.InvalidCertificateExtension;
        try validateOid(purpose.value);
        result.server_auth = result.server_auth or std.mem.eql(
            u8,
            purpose.value,
            &.{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 },
        );
        result.client_auth = result.client_auth or std.mem.eql(
            u8,
            purpose.value,
            &.{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 },
        );
        result.any = result.any or std.mem.eql(
            u8,
            purpose.value,
            &.{ 0x55, 0x1d, 0x25, 0x00 },
        );
    }
    return result;
}

fn extendedKeyUsageContainsAll(
    certificate_encoded: []const u8,
    requested_encoded: []const u8,
) !bool {
    _ = try parseExtendedKeyUsage(certificate_encoded);
    const requested_usage = try parseExtendedKeyUsage(requested_encoded);
    if (requested_usage.any) return error.InvalidCertificateExtension;

    const certificate = try singleInner(certificate_encoded, 0x30);
    const requested = try singleInner(requested_encoded, 0x30);
    var requested_oids = DerReader{ .bytes = requested.value };
    while (try requested_oids.next()) |requested_oid| {
        var found = false;
        var certificate_oids = DerReader{ .bytes = certificate.value };
        while (try certificate_oids.next()) |certificate_oid| {
            if (std.mem.eql(
                u8,
                requested_oid.value,
                certificate_oid.value,
            )) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn nonNegativeInteger(integer: Tlv) !usize {
    if (integer.tag != 0x02 or integer.value.len == 0 or
        (integer.value[0] & 0x80) != 0 or
        (integer.value.len > 1 and integer.value[0] == 0 and
            (integer.value[1] & 0x80) == 0) or
        integer.value.len > @sizeOf(usize))
    {
        return error.InvalidCertificateExtension;
    }
    var result: usize = 0;
    for (integer.value) |byte| {
        result = std.math.mul(usize, result, 256) catch
            return error.InvalidCertificateExtension;
        result = std.math.add(usize, result, byte) catch
            return error.InvalidCertificateExtension;
    }
    return result;
}

fn validateOid(value: []const u8) !void {
    if (value.len == 0) return error.InvalidCertificateExtension;
    var at_subidentifier_start = true;
    for (value) |byte| {
        if (at_subidentifier_start and byte == 0x80) {
            return error.InvalidCertificateExtension;
        }
        at_subidentifier_start = (byte & 0x80) == 0;
    }
    if (!at_subidentifier_start) return error.InvalidCertificateExtension;
}

const Tlv = struct {
    tag: u8,
    value: []const u8,
};

fn singleInner(encoded: []const u8, tag: u8) !Tlv {
    var reader = DerReader{ .bytes = encoded };
    const value = try reader.require(tag);
    if (try reader.next() != null) return error.InvalidCertificateExtension;
    return value;
}

const DerReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn next(self: *DerReader) !?Tlv {
        if (self.pos == self.bytes.len) return null;
        if (self.pos > self.bytes.len) return error.InvalidCertificateExtension;
        const tag = self.bytes[self.pos];
        self.pos += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidCertificateExtension;
        const len = try self.readLength();
        const end = std.math.add(usize, self.pos, len) catch
            return error.InvalidCertificateExtension;
        if (end > self.bytes.len) return error.InvalidCertificateExtension;
        const value = self.bytes[self.pos..end];
        self.pos = end;
        return .{ .tag = tag, .value = value };
    }

    fn require(self: *DerReader, tag: u8) !Tlv {
        const value = (try self.next()) orelse
            return error.InvalidCertificateExtension;
        if (value.tag != tag) return error.InvalidCertificateExtension;
        return value;
    }

    fn readLength(self: *DerReader) !usize {
        if (self.pos >= self.bytes.len) return error.InvalidCertificateExtension;
        const first = self.bytes[self.pos];
        self.pos += 1;
        if ((first & 0x80) == 0) return first;
        const count: usize = first & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) {
            return error.InvalidCertificateExtension;
        }
        const end = std.math.add(usize, self.pos, count) catch
            return error.InvalidCertificateExtension;
        if (end > self.bytes.len or self.bytes[self.pos] == 0) {
            return error.InvalidCertificateExtension;
        }
        var len: usize = 0;
        for (self.bytes[self.pos..end]) |byte| {
            len = std.math.mul(usize, len, 256) catch
                return error.InvalidCertificateExtension;
            len = std.math.add(usize, len, byte) catch
                return error.InvalidCertificateExtension;
        }
        self.pos = end;
        if (len < 128) return error.InvalidCertificateExtension;
        return len;
    }
};

pub const testing = struct {
    pub const Usage = CertificateUsage;
    pub const AuthorityKeyIdentifierValue = AuthorityKeyIdentifier;
    pub const BasicConstraintsValue = BasicConstraints;
    pub const KeyUsageValue = KeyUsage;
    pub const ExtendedKeyUsageValue = ExtendedKeyUsage;
    pub const TlsFeaturesValue = TlsFeatures;

    pub fn certificateUsage(certificate_der: []const u8) !Usage {
        return @import("trust.zig").certificateUsage(certificate_der);
    }

    pub fn validateLeafUsage(usage: Usage) !void {
        return validateLeafUsageProfile(usage, .server_auth);
    }

    pub fn validateClientLeafUsage(usage: Usage) !void {
        return validateLeafUsageProfile(usage, .client_auth);
    }

    pub fn validateIssuerUsage(usage: Usage, ca_below: usize) !void {
        return validateIssuerUsageProfile(usage, ca_below, .server_auth);
    }

    pub fn validateClientIssuerUsage(
        usage: Usage,
        ca_below: usize,
    ) !void {
        return validateIssuerUsageProfile(usage, ca_below, .client_auth);
    }

    pub fn countCaBelow(
        current: usize,
        certificate_der: []const u8,
    ) !usize {
        return @import("trust.zig").countCaBelow(
            current,
            try parseCertificate(certificate_der),
        );
    }

    pub fn parseBasicConstraints(
        encoded: []const u8,
    ) !BasicConstraintsValue {
        return @import("trust.zig").parseBasicConstraints(encoded);
    }

    pub fn parseKeyUsage(encoded: []const u8) !KeyUsageValue {
        return @import("trust.zig").parseKeyUsage(encoded);
    }

    pub fn parseExtendedKeyUsage(
        encoded: []const u8,
    ) !ExtendedKeyUsageValue {
        return @import("trust.zig").parseExtendedKeyUsage(encoded);
    }

    pub fn parseTlsFeatures(encoded: []const u8) !TlsFeaturesValue {
        return @import("trust.zig").parseTlsFeatures(encoded);
    }

    pub fn parseSubjectKeyIdentifier(encoded: []const u8) ![]const u8 {
        return @import("trust.zig").parseSubjectKeyIdentifier(encoded);
    }

    pub fn parseAuthorityKeyIdentifier(
        encoded: []const u8,
    ) !AuthorityKeyIdentifierValue {
        return @import("trust.zig").parseAuthorityKeyIdentifierDetails(
            encoded,
        );
    }

    pub fn issuerIdentityPriority(
        authority: AuthorityKeyIdentifierValue,
        subject_key_identifier: ?[]const u8,
        candidate_issuer_name: []const u8,
        candidate_serial_number: []const u8,
    ) !u2 {
        return @import("trust.zig").issuerIdentityPriority(
            authority,
            subject_key_identifier,
            candidate_issuer_name,
            candidate_serial_number,
        );
    }

    pub fn authorityIssuerMatches(
        encoded_names: []const u8,
        candidate_issuer_name: []const u8,
    ) !?bool {
        return @import("trust.zig").authorityIssuerMatches(
            encoded_names,
            candidate_issuer_name,
        );
    }

    pub fn certificateSerialNumber(certificate_der: []const u8) ![]const u8 {
        return @import("trust.zig").certificateSerialNumber(certificate_der);
    }

    pub fn certificateAuthorityKeyIdentifier(
        certificate_der: []const u8,
    ) !?AuthorityKeyIdentifierValue {
        return @import("trust.zig").certificateAuthorityKeyIdentifier(
            certificate_der,
        );
    }

    pub fn validateDnsNameConstraints(
        encoded: []const u8,
        dns_name: []const u8,
    ) !void {
        return @import("trust.zig").validateDnsNameConstraints(
            encoded,
            dns_name,
        );
    }

    pub fn validateIpNameConstraints(
        encoded: []const u8,
        ip_address: []const u8,
    ) !void {
        const identity = parseServerIdentity(ip_address);
        switch (identity) {
            .dns => return error.InvalidIpAddress,
            else => return @import("trust.zig").validateNameConstraints(
                encoded,
                identity,
            ),
        }
    }

    pub fn validateRfc822NameConstraints(
        encoded: []const u8,
        mailbox: []const u8,
    ) !void {
        return @import("trust.zig").validateNameConstraints(
            encoded,
            .{ .rfc822 = try parseRfc822Name(mailbox) },
        );
    }

    pub fn validateUriNameConstraints(
        encoded: []const u8,
        uri: []const u8,
    ) !void {
        return @import("trust.zig").validateNameConstraints(
            encoded,
            .{ .uri = try parseUriHost(uri) },
        );
    }

    pub fn validateDirectoryNameConstraints(
        encoded: []const u8,
        name: []const u8,
    ) !void {
        return @import("trust.zig").validateNameConstraints(
            encoded,
            .{ .directory = name },
        );
    }

    pub fn directoryNamesEqual(a: []const u8, b: []const u8) !bool {
        return @import("trust.zig").directoryNamesEqual(a, b);
    }
};
