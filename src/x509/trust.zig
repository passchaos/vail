//! Built-in X.509 chain, validity, hostname, and endpoint-purpose policy.
//!
//! `SystemStore` loads the platform CA bundle once and then exposes a
//! zero-allocation verification callback suitable for `auth.ClientVerifier`.

const std = @import("std");
const auth = @import("../tls/auth.zig");
const certificate_compat = @import("certificate.zig");
const ocsp = @import("ocsp.zig");

const Certificate = std.crypto.Certificate;

pub const PathLimits = struct {
    max_depth: usize = 8,
    max_candidate_checks: usize = 64,
    max_presented_certificates: usize = 16,
};

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

pub const StapledOcspPolicy = enum {
    ignore,
    if_present,
    require,
};

pub const BundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    now_seconds: i64,
    path_limits: PathLimits = .{},
    revocation: ?RevocationPolicy = null,
    stapled_ocsp: StapledOcspPolicy = .ignore,
    ocsp_validation: ocsp.Policy = .{},

    pub fn clientVerifier(
        self: *const BundleVerifier,
    ) auth.ClientVerifier {
        return .{
            .verify_trust = verifyCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    pub fn verify(
        self: BundleVerifier,
        trust_context: auth.TrustContext,
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
            self.now_seconds,
            trust_context.chain,
            .server_auth,
            self.path_limits,
            self.revocation,
            server_identity,
            trust_context.ocsp_response,
            self.stapled_ocsp,
            self.ocsp_validation,
        );
    }

    fn verifyCallback(
        context: ?*anyopaque,
        trust_context: auth.TrustContext,
    ) anyerror!void {
        const self: *const BundleVerifier = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        try self.verify(trust_context);
    }
};

/// CA-bundle policy for certificates presented by TLS clients. It performs no
/// hostname check and enforces the RFC 5280 clientAuth purpose throughout the
/// supplied path. TLS separately verifies CertificateVerify possession.
pub const ClientCertificateBundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    now_seconds: i64,
    path_limits: PathLimits = .{},
    revocation: ?RevocationPolicy = null,

    pub fn clientVerifier(
        self: *const ClientCertificateBundleVerifier,
    ) auth.ClientVerifier {
        return .{
            .verify_trust = verifyCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    pub fn verify(
        self: ClientCertificateBundleVerifier,
        trust_context: auth.TrustContext,
    ) !void {
        try verifyChain(
            self.bundle,
            self.now_seconds,
            trust_context.chain,
            .client_auth,
            self.path_limits,
            self.revocation,
            null,
            null,
            .ignore,
            .{},
        );
    }

    fn verifyCallback(
        context: ?*anyopaque,
        trust_context: auth.TrustContext,
    ) anyerror!void {
        const self: *const ClientCertificateBundleVerifier =
            @ptrCast(@alignCast(
                context orelse return error.MissingTrustContext,
            ));
        try self.verify(trust_context);
    }
};

const EndpointPurpose = enum { server_auth, client_auth };

const ServerIdentity = union(enum) {
    dns: []const u8,
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
    try validateIssuerUsageAndNameConstraints(
        certificate_der,
        0,
        .client_auth,
        null,
        null,
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

fn verifyChain(
    bundle: *const Certificate.Bundle,
    now_seconds: i64,
    chain: []const []const u8,
    purpose: EndpointPurpose,
    limits: PathLimits,
    revocation: ?RevocationPolicy,
    constrained_identity: ?ServerIdentity,
    stapled_ocsp_response: ?[]const u8,
    stapled_ocsp_policy: StapledOcspPolicy,
    ocsp_validation: ocsp.Policy,
) !void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    try validatePathLimits(limits);
    if (chain.len > limits.max_presented_certificates) {
        return error.CertificatePathTooManyCertificates;
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
        .stapled_ocsp_policy = stapled_ocsp_policy,
        .ocsp_validation = ocsp_validation,
    };
    try search.verifyFrom(0, 1, 0, 0);
}

const PathSearch = struct {
    bundle: *const Certificate.Bundle,
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
    stapled_ocsp_policy: StapledOcspPolicy,
    ocsp_validation: ocsp.Policy,
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
        const subject = self.parsed[subject_index];
        if (trustedEquivalentAnchor(self.bundle, subject)) |anchor| {
            if (subject_index == 0 and self.stapled_ocsp_policy != .ignore) {
                if (self.stapled_ocsp_response != null) {
                    return error.CertificateOcspIssuerUnavailable;
                }
                if (self.stapled_ocsp_policy == .require) {
                    return error.CertificateOcspResponseRequired;
                }
            }
            try verifyValidity(subject, self.now_seconds);
            try verifyValidity(anchor, self.now_seconds);
            return;
        }

        var remembered_error: ?anyerror = null;
        if (self.bundle.find(subject.issuer())) |anchor_index| {
            try self.consumeCandidateBudget();
            const anchor_element = try Certificate.der.Element.parse(
                self.bundle.bytes.items,
                anchor_index,
            );
            const anchor_der = self.bundle.bytes.items[anchor_index..anchor_element.slice.end];
            const anchor = try parseCertificate(anchor_der);
            anchor_attempt: {
                validateIssuerUsageAndNameConstraints(
                    anchor_der,
                    ca_below,
                    self.purpose,
                    self.constrained_identity,
                    self.chain[0],
                ) catch |err| {
                    remembered_error = err;
                    break :anchor_attempt;
                };
                self.verifyCertificateSignature(
                    subject_index,
                    subject,
                    anchor,
                ) catch |err| {
                    remembered_error = err;
                    break :anchor_attempt;
                };
                if (self.revocation) |revocation| {
                    revocation.verify(
                        self.chain[subject_index],
                        anchor_der,
                    ) catch |err| {
                        remembered_error = err;
                        break :anchor_attempt;
                    };
                }
                self.verifyStapledOcsp(
                    subject_index,
                    self.chain[subject_index],
                    anchor_der,
                ) catch |err| {
                    remembered_error = err;
                    break :anchor_attempt;
                };
                verifyValidity(anchor, self.now_seconds) catch |err| {
                    remembered_error = err;
                    break :anchor_attempt;
                };
                return;
            }
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
            if ((used & bit) != 0 or !std.mem.eql(
                u8,
                subject.issuer(),
                issuer.subject(),
            )) continue;
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
                validateIssuerUsageAndNameConstraintsFromUsage(
                    issuer_usage,
                    ca_below,
                    self.purpose,
                    self.constrained_identity,
                    self.chain[0],
                ) catch |err| {
                    remembered_error = err;
                    continue;
                };
                self.verifyCertificateSignature(
                    subject_index,
                    subject,
                    issuer,
                ) catch |err| {
                    remembered_error = err;
                    continue;
                };
                if (self.revocation) |revocation| {
                    revocation.verify(
                        self.chain[subject_index],
                        self.chain[issuer_index],
                    ) catch |err| {
                        remembered_error = err;
                        continue;
                    };
                }
                self.verifyStapledOcsp(
                    subject_index,
                    self.chain[subject_index],
                    self.chain[issuer_index],
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
        return remembered_error orelse error.CertificateIssuerNotFound;
    }

    fn consumeCandidateBudget(self: *PathSearch) !void {
        if (self.candidate_checks >= self.limits.max_candidate_checks) {
            return error.CertificatePathSearchLimitExceeded;
        }
        self.candidate_checks += 1;
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

    fn verifyCertificateSignature(
        self: *const PathSearch,
        subject_index: usize,
        subject: Certificate.Parsed,
        issuer: Certificate.Parsed,
    ) !void {
        const bit = @as(u32, 1) << @intCast(subject_index);
        if ((self.custom_algorithm_mask & bit) != 0) {
            return certificate_compat.verifyWithAlgorithm(
                subject,
                self.custom_algorithms[subject_index],
                issuer,
                self.now_seconds,
            );
        }
        return subject.verify(issuer, self.now_seconds);
    }

    fn verifyStapledOcsp(
        self: *PathSearch,
        subject_index: usize,
        certificate_der: []const u8,
        issuer_der: []const u8,
    ) !void {
        if (subject_index != 0 or self.stapled_ocsp_policy == .ignore) {
            return;
        }
        const response = self.stapled_ocsp_response orelse {
            if (self.stapled_ocsp_policy == .require) {
                return error.CertificateOcspResponseRequired;
            }
            return;
        };
        switch (try ocsp.verify(
            response,
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
};

fn validatePathLimits(limits: PathLimits) !void {
    if (limits.max_depth == 0 or
        limits.max_depth > hard_max_depth or
        limits.max_candidate_checks == 0 or
        limits.max_candidate_checks > hard_max_candidate_checks or
        limits.max_presented_certificates == 0 or
        limits.max_presented_certificates > hard_max_presented_certificates)
    {
        return error.InvalidCertificatePathLimits;
    }
}

pub const SystemStore = struct {
    allocator: std.mem.Allocator,
    bundle: Certificate.Bundle = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        now: std.Io.Timestamp,
    ) Certificate.Bundle.RescanError!SystemStore {
        var result = SystemStore{ .allocator = allocator };
        errdefer result.deinit();
        try result.bundle.rescan(allocator, io, now);
        return result;
    }

    pub fn deinit(self: *SystemStore) void {
        self.bundle.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn verifier(
        self: *const SystemStore,
        now_seconds: i64,
    ) BundleVerifier {
        return .{
            .bundle = &self.bundle,
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
fn trustedEquivalentAnchor(
    bundle: *const Certificate.Bundle,
    subject: Certificate.Parsed,
) ?Certificate.Parsed {
    const anchor_index = bundle.find(subject.subject()) orelse return null;
    const anchor_element = Certificate.der.Element.parse(
        bundle.bytes.items,
        anchor_index,
    ) catch unreachable;
    const anchor = parseCertificate(
        bundle.bytes.items[anchor_index..anchor_element.slice.end],
    ) catch unreachable;
    if (!std.mem.eql(
        u8,
        subjectPublicKeyInfo(subject),
        subjectPublicKeyInfo(anchor),
    )) return null;
    return anchor;
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
    if (std.mem.eql(u8, issuer.issuer(), issuer.subject())) return current;
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
    unsupported_critical_extension: bool = false,
    name_constraints: ?[]const u8 = null,
    subject_key_identifier: ?[]const u8 = null,
    authority_key_identifier: ?[]const u8 = null,
};

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
    if (usage.unsupported_critical_extension or
        (usage.basic_constraints_present and usage.is_ca) or
        usage.name_constraints != null or
        (usage.key_usage_present and !usage.digital_signature) or
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

fn validateIssuerUsageAndNameConstraints(
    certificate_der: []const u8,
    ca_below: usize,
    purpose: EndpointPurpose,
    constrained_identity: ?ServerIdentity,
    leaf_der: ?[]const u8,
) !void {
    const usage = try certificateUsage(certificate_der);
    return validateIssuerUsageAndNameConstraintsFromUsage(
        usage,
        ca_below,
        purpose,
        constrained_identity,
        leaf_der,
    );
}

fn validateIssuerUsageAndNameConstraintsFromUsage(
    usage: CertificateUsage,
    ca_below: usize,
    purpose: EndpointPurpose,
    constrained_identity: ?ServerIdentity,
    leaf_der: ?[]const u8,
) !void {
    try validateIssuerUsageProfile(usage, ca_below, purpose);
    if (usage.name_constraints) |encoded| {
        if (purpose != .server_auth) {
            return error.UnsupportedCertificateNameConstraint;
        }
        try validateNameConstraints(
            encoded,
            constrained_identity orelse
                return error.MissingServerName,
        );
        try validateSubjectAlternativeNamesAgainstConstraints(
            encoded,
            leaf_der orelse return error.InvalidCertificate,
        );
    }
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
        } else if (critical) {
            result.unsupported_critical_extension = true;
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
        if (std.mem.eql(
            u8,
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

fn validateSubjectAlternativeNamesAgainstConstraints(
    constraints: []const u8,
    certificate_der: []const u8,
) !void {
    const certificate = try parseCertificate(certificate_der);
    const encoded_names = certificate.subjectAltName();
    if (encoded_names.len == 0) return;
    const names = singleInner(encoded_names, 0x30) catch
        return error.InvalidCertificateExtension;
    var reader = DerReader{ .bytes = names.value };
    while (try reader.next()) |name| {
        switch (name.tag) {
            0x82 => {
                if (name.value.len == 0) {
                    return error.InvalidCertificateExtension;
                }
                try validateNameConstraints(
                    constraints,
                    .{ .dns = name.value },
                );
            },
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
            else => {},
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
                0x82 => blk: {
                    if (!validDnsConstraint(base.value)) {
                        return error.InvalidCertificateExtension;
                    }
                    break :blk if (identity) |name| switch (name) {
                        .dns => true,
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
            if (evaluate and relevant and identityMatchesConstraint(
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

fn identityMatchesConstraint(
    identity: ServerIdentity,
    constraint: Tlv,
) bool {
    return switch (identity) {
        .dns => |dns_name| constraint.tag == 0x82 and
            dnsWithinConstraint(dns_name, constraint.value),
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
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '.') {
            return false;
        }
    }
    return true;
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
    };
}

const ExtendedKeyUsage = struct {
    server_auth: bool = false,
    client_auth: bool = false,
    any: bool = false,
};

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
};
