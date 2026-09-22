//! Built-in X.509 chain, validity, hostname, and endpoint-purpose policy.
//!
//! `SystemStore` loads the platform CA bundle once and then exposes a
//! zero-allocation verification callback suitable for `auth.ClientVerifier`.

const std = @import("std");
const auth = @import("../tls/auth.zig");

const Certificate = std.crypto.Certificate;

pub const BundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    now_seconds: i64,

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
        try leaf.verifyHostName(server_name);
        try verifyChain(
            self.bundle,
            self.now_seconds,
            trust_context.chain,
            .server_auth,
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

fn verifyChain(
    bundle: *const Certificate.Bundle,
    now_seconds: i64,
    chain: []const []const u8,
    purpose: EndpointPurpose,
) !void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    var subject = try parseCertificate(chain[0]);
    try validateLeafUsage(chain[0], purpose);
    var ca_below: usize = 0;
    for (chain[1..]) |issuer_der| {
        const issuer = try parseCertificate(issuer_der);
        try validateIssuerUsage(issuer_der, ca_below, purpose);
        try subject.verify(issuer, now_seconds);
        ca_below = try countCaBelow(ca_below, issuer);
        subject = issuer;
    }
    if (trustedEquivalentAnchor(bundle, subject)) |anchor| {
        try verifyValidity(subject, now_seconds);
        try verifyValidity(anchor, now_seconds);
        return;
    }
    try bundle.verify(subject, now_seconds);
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

fn parseCertificate(der: []const u8) !Certificate.Parsed {
    return Certificate.parse(.{
        .buffer = der,
        .index = 0,
    });
}

/// Match a server-supplied cross-certificate to a configured trust anchor.
/// Name equality alone is insufficient: the complete SubjectPublicKeyInfo
/// must also identify the same CA key and parameters.
fn trustedEquivalentAnchor(
    bundle: *const Certificate.Bundle,
    subject: Certificate.Parsed,
) ?Certificate.Parsed {
    const anchor_index = bundle.find(subject.subject()) orelse return null;
    const anchor = Certificate.parse(.{
        .buffer = bundle.bytes.items,
        .index = anchor_index,
    }) catch unreachable;
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
    extended_key_usage_present: bool = false,
    server_auth: bool = false,
    client_auth: bool = false,
    any_extended_key_usage: bool = false,
    unsupported_critical_extension: bool = false,
};

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
        } else if (critical) {
            result.unsupported_critical_extension = true;
        }
    }
    return result;
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
};
