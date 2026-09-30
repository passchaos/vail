//! Strict RFC 5280 certificate revocation lists.
//!
//! A list is returned only after issuer, signature, update-window, extension,
//! and revoked-entry validation succeeds. Supported signatures are Ed25519,
//! ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, and RSA PKCS#1
//! v1.5 or RSA-PSS with SHA-256/384/512 and 1024-4096-bit keys; other
//! algorithms fail explicitly.

const std = @import("std");
const x509_signature = @import("signature.zig");
const trust = @import("trust.zig");

const Certificate = std.crypto.Certificate;

pub const Error = error{
    InvalidCrl,
    InvalidCrlSignature,
    UnsupportedSignatureAlgorithm,
    InvalidIssuer,
    IssuerMismatch,
    CrlNotYetValid,
    CrlExpired,
    UnsupportedCriticalExtension,
    CertificateSerialInvalid,
};

const oid_delta_crl_indicator = [_]u8{ 0x55, 0x1d, 0x1b };
const oid_issuing_distribution_point = [_]u8{ 0x55, 0x1d, 0x1c };
const oid_certificate_issuer = [_]u8{ 0x55, 0x1d, 0x1d };

pub const List = struct {
    der: []const u8,
    issuer_certificate_der: []const u8,
    issuer_name: []const u8,
    revoked_entries: []const u8,
    this_update: u64,
    next_update: u64,

    pub fn isRevoked(
        self: List,
        certificate_der: []const u8,
    ) Error!bool {
        const certificate = parseCertificate(certificate_der) catch
            return error.CertificateSerialInvalid;
        if (!std.mem.eql(u8, certificate.issuer(), self.issuer_name)) {
            return error.IssuerMismatch;
        }
        const serial = certificateSerial(certificate_der) catch
            return error.CertificateSerialInvalid;
        var entries = Reader{ .bytes = self.revoked_entries };
        while (entries.next() catch return error.InvalidCrl) |entry| {
            const parsed = parseRevokedEntry(entry) catch
                return error.InvalidCrl;
            if (std.mem.eql(u8, parsed.serial, serial)) return true;
        }
        return false;
    }
};

/// A caller-owned set of already authenticated CRLs exposed as a trust-layer
/// revocation policy. Lists and their issuer certificates must outlive it.
pub const VerifiedSet = struct {
    lists: []const List,

    pub fn policy(
        self: *const VerifiedSet,
        require_status: bool,
    ) trust.RevocationPolicy {
        return .{
            .context = self,
            .check = check,
            .require_status = require_status,
        };
    }

    fn check(
        context: *const anyopaque,
        certificate_der: []const u8,
        issuer_der: []const u8,
    ) anyerror!trust.RevocationStatus {
        const self: *const VerifiedSet = @ptrCast(@alignCast(context));
        const certificate = try parseCertificate(certificate_der);
        const actual_issuer = try parseCertificate(issuer_der);
        for (self.lists) |list| {
            if (!std.mem.eql(u8, certificate.issuer(), list.issuer_name)) {
                continue;
            }
            const authenticated_issuer = try parseCertificate(
                list.issuer_certificate_der,
            );
            if (!std.mem.eql(
                u8,
                authenticated_issuer.subject(),
                actual_issuer.subject(),
            ) or !std.meta.eql(
                authenticated_issuer.pub_key_algo,
                actual_issuer.pub_key_algo,
            ) or !std.mem.eql(
                u8,
                authenticated_issuer.pubKey(),
                actual_issuer.pubKey(),
            )) continue;
            return if (try list.isRevoked(certificate_der))
                .revoked
            else
                .good;
        }
        return .unknown;
    }
};

pub fn parseAndVerify(
    crl_der: []const u8,
    issuer_certificate_der: []const u8,
    now_seconds: i64,
) Error!List {
    if (now_seconds < 0) return error.CrlNotYetValid;
    const now: u64 = @intCast(now_seconds);
    const issuer_certificate = parseCertificate(
        issuer_certificate_der,
    ) catch return error.InvalidIssuer;
    trust.validateClientCertificateRevocationListIssuer(
        issuer_certificate_der,
        now_seconds,
    ) catch return error.InvalidIssuer;

    var top = Reader{ .bytes = crl_der };
    const certificate_list = top.require(0x30) catch return error.InvalidCrl;
    if (!top.done()) return error.InvalidCrl;
    var fields = Reader{ .bytes = certificate_list.value };
    const tbs = fields.require(0x30) catch return error.InvalidCrl;
    const outer_algorithm = fields.require(0x30) catch return error.InvalidCrl;
    const signature_value = fields.require(0x03) catch return error.InvalidCrl;
    if (!fields.done()) return error.InvalidCrl;

    var tbs_fields = Reader{ .bytes = tbs.value };
    var first = (tbs_fields.next() catch return error.InvalidCrl) orelse
        return error.InvalidCrl;
    var version_two = false;
    if (first.tag == 0x02) {
        if (!std.mem.eql(u8, first.value, &.{0x01})) {
            return error.InvalidCrl;
        }
        version_two = true;
        first = (tbs_fields.next() catch return error.InvalidCrl) orelse
            return error.InvalidCrl;
    }
    if (first.tag != 0x30) return error.InvalidCrl;
    const inner_algorithm = first;
    const signature_algorithm = try parseSignatureAlgorithm(inner_algorithm);
    if (try parseSignatureAlgorithm(outer_algorithm) != signature_algorithm) {
        return error.InvalidCrl;
    }
    if (!std.mem.eql(
        u8,
        tbs.value[inner_algorithm.start..inner_algorithm.end],
        certificate_list.value[outer_algorithm.start..outer_algorithm.end],
    )) return error.InvalidCrl;

    const issuer = tbs_fields.require(0x30) catch return error.InvalidCrl;
    if (!std.mem.eql(u8, issuer.value, issuer_certificate.subject())) {
        return error.IssuerMismatch;
    }
    const this_update_element = (tbs_fields.next() catch
        return error.InvalidCrl) orelse return error.InvalidCrl;
    const this_update = parseTime(tbs.value, this_update_element) catch
        return error.InvalidCrl;
    const next_update_element = (tbs_fields.next() catch
        return error.InvalidCrl) orelse return error.InvalidCrl;
    const next_update = parseTime(tbs.value, next_update_element) catch
        return error.InvalidCrl;
    if (next_update <= this_update) return error.InvalidCrl;
    if (now < this_update) return error.CrlNotYetValid;
    if (now > next_update) return error.CrlExpired;

    var revoked_entries: []const u8 = &.{};
    var next = tbs_fields.next() catch return error.InvalidCrl;
    if (next != null and next.?.tag == 0x30) {
        revoked_entries = next.?.value;
        try validateRevokedEntries(revoked_entries);
        next = tbs_fields.next() catch return error.InvalidCrl;
    }
    if (next) |extensions| {
        if (!version_two or extensions.tag != 0xa0) return error.InvalidCrl;
        var explicit = Reader{ .bytes = extensions.value };
        const sequence = explicit.require(0x30) catch return error.InvalidCrl;
        if (!explicit.done()) return error.InvalidCrl;
        try validateExtensions(sequence.value);
        if ((tbs_fields.next() catch return error.InvalidCrl) != null) {
            return error.InvalidCrl;
        }
    }

    if (signature_value.value.len < 2 or signature_value.value[0] != 0) {
        return error.InvalidCrl;
    }
    try verifySignature(
        signature_algorithm,
        issuer_certificate,
        certificate_list.value[tbs.start..tbs.end],
        signature_value.value[1..],
    );

    return .{
        .der = crl_der,
        .issuer_certificate_der = issuer_certificate_der,
        .issuer_name = issuer.value,
        .revoked_entries = revoked_entries,
        .this_update = this_update,
        .next_update = next_update,
    };
}

const SignatureAlgorithm = x509_signature.Algorithm;

fn parseSignatureAlgorithm(algorithm: Element) Error!SignatureAlgorithm {
    return x509_signature.parseAlgorithmIdentifier(algorithm.value) catch |err| switch (err) {
        error.UnsupportedSignatureAlgorithm => error.UnsupportedSignatureAlgorithm,
        else => error.InvalidCrl,
    };
}

fn verifySignature(
    algorithm: SignatureAlgorithm,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    x509_signature.verify(algorithm, issuer, message, signature_bytes) catch |err| switch (err) {
        error.InvalidIssuer => return error.InvalidIssuer,
        error.UnsupportedSignatureAlgorithm => return error.UnsupportedSignatureAlgorithm,
        else => return error.InvalidCrlSignature,
    };
}

const RevokedEntry = struct {
    serial: []const u8,
};

fn parseRevokedEntry(entry: Element) Error!RevokedEntry {
    if (entry.tag != 0x30) return error.InvalidCrl;
    var fields = Reader{ .bytes = entry.value };
    const serial = fields.require(0x02) catch return error.InvalidCrl;
    validateSerial(serial.value) catch return error.InvalidCrl;
    const revocation_date = (fields.next() catch return error.InvalidCrl) orelse
        return error.InvalidCrl;
    _ = parseTime(entry.value, revocation_date) catch return error.InvalidCrl;
    if (fields.next() catch return error.InvalidCrl) |extensions| {
        if (extensions.tag != 0x30) return error.InvalidCrl;
        try validateExtensions(extensions.value);
        if (!fields.done()) return error.InvalidCrl;
    }
    return .{ .serial = serial.value };
}

fn validateRevokedEntries(entries_bytes: []const u8) Error!void {
    var entries = Reader{ .bytes = entries_bytes };
    while (entries.next() catch return error.InvalidCrl) |entry| {
        _ = try parseRevokedEntry(entry);
    }
}

fn validateExtensions(bytes: []const u8) Error!void {
    var extensions = Reader{ .bytes = bytes };
    var checked_end: usize = 0;
    while (extensions.next() catch return error.InvalidCrl) |extension| {
        if (extension.tag != 0x30) return error.InvalidCrl;
        var fields = Reader{ .bytes = extension.value };
        const oid = fields.require(0x06) catch return error.InvalidCrl;
        try validateOid(oid.value);
        if (std.mem.eql(u8, oid.value, &oid_delta_crl_indicator) or
            std.mem.eql(u8, oid.value, &oid_issuing_distribution_point) or
            std.mem.eql(u8, oid.value, &oid_certificate_issuer))
        {
            return error.UnsupportedCriticalExtension;
        }
        var prior = Reader{ .bytes = bytes[0..checked_end] };
        while (prior.next() catch return error.InvalidCrl) |prior_extension| {
            if (prior_extension.tag != 0x30) return error.InvalidCrl;
            var prior_fields = Reader{ .bytes = prior_extension.value };
            const prior_oid = prior_fields.require(0x06) catch
                return error.InvalidCrl;
            if (std.mem.eql(u8, prior_oid.value, oid.value)) {
                return error.InvalidCrl;
            }
        }
        var value = (fields.next() catch return error.InvalidCrl) orelse
            return error.InvalidCrl;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidCrl;
            }
            critical = true;
            value = (fields.next() catch return error.InvalidCrl) orelse
                return error.InvalidCrl;
        }
        if (value.tag != 0x04 or !fields.done()) return error.InvalidCrl;
        if (critical) return error.UnsupportedCriticalExtension;
        checked_end = extension.end;
    }
}

fn validateOid(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidCrl;
    var at_subidentifier_start = true;
    for (value) |byte| {
        if (at_subidentifier_start and byte == 0x80) return error.InvalidCrl;
        at_subidentifier_start = (byte & 0x80) == 0;
    }
    if (!at_subidentifier_start) return error.InvalidCrl;
}

fn certificateSerial(certificate_der: []const u8) ![]const u8 {
    _ = try parseCertificate(certificate_der);
    var top = Reader{ .bytes = certificate_der };
    const certificate = try top.require(0x30);
    var fields = Reader{ .bytes = certificate.value };
    const tbs = try fields.require(0x30);
    var tbs_fields = Reader{ .bytes = tbs.value };
    var serial = (try tbs_fields.next()) orelse return error.InvalidDer;
    if (serial.tag == 0xa0) {
        serial = (try tbs_fields.next()) orelse return error.InvalidDer;
    }
    if (serial.tag != 0x02) return error.InvalidDer;
    try validateSerial(serial.value);
    return serial.value;
}

fn validateSerial(serial: []const u8) Error!void {
    if (serial.len == 0 or serial.len > 20 or (serial[0] & 0x80) != 0 or
        (serial.len > 1 and serial[0] == 0 and (serial[1] & 0x80) == 0))
    {
        return error.CertificateSerialInvalid;
    }
    var nonzero = false;
    for (serial) |byte| nonzero = nonzero or byte != 0;
    if (!nonzero) return error.CertificateSerialInvalid;
}

fn parseCertificate(der: []const u8) !Certificate.Parsed {
    var top = Reader{ .bytes = der };
    _ = try top.require(0x30);
    if (!top.done()) return error.InvalidDer;
    return Certificate.parse(.{ .buffer = der, .index = 0 });
}

fn parseTime(bytes: []const u8, time: Element) !u64 {
    if ((time.tag == 0x17 and
        (time.value.len != 13 or time.value[12] != 'Z')) or
        (time.tag == 0x18 and
            (time.value.len != 15 or time.value[14] != 'Z')) or
        (time.tag != 0x17 and time.tag != 0x18) or
        time.value_start > std.math.maxInt(u32) or
        time.end > std.math.maxInt(u32))
    {
        return error.InvalidDer;
    }
    const identifier: Certificate.der.Identifier = @bitCast(time.tag);
    return Certificate.parseTime(.{ .buffer = bytes, .index = 0 }, .{
        .identifier = identifier,
        .slice = .{
            .start = @intCast(time.value_start),
            .end = @intCast(time.end),
        },
    });
}

const Element = struct {
    tag: u8,
    start: usize,
    value_start: usize,
    end: usize,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn require(self: *Reader, tag: u8) !Element {
        const value = (try self.next()) orelse return error.InvalidDer;
        if (value.tag != tag) return error.InvalidDer;
        return value;
    }

    fn next(self: *Reader) !?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidDer;
        const start = self.offset;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidDer;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidDer;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidDer;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidDer;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidDer;
        }
        if (length > self.bytes.len - self.offset) return error.InvalidDer;
        const value_start = self.offset;
        const value = self.bytes[value_start .. value_start + length];
        self.offset += length;
        return .{
            .tag = tag,
            .start = start,
            .value_start = value_start,
            .end = self.offset,
            .value = value,
        };
    }

    fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

const ca_base64 =
    "MIIBhDCCASmgAwIBAgICEAAwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBgxFjAUBgNV" ++
    "BAMMDUNSTCBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQantue" ++
    "ZFhV35+7BoVoG9/+jPWbhpRoMPiTYHDqJfZk7qZab4SMQITgtsFnZ5n5up9IOZnP" ++
    "bgML6KLa9BKOmrxYo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB" ++
    "BjAdBgNVHQ4EFgQU4Y88Ik092FGXnPjSSa7GXltOPjQwHwYDVR0jBBgwFoAU4Y88" ++
    "Ik092FGXnPjSSa7GXltOPjQwCgYIKoZIzj0EAwIDSQAwRgIhAPUbM4y3hpf9d8SU" ++
    "VmCYJBEtqK4aEvFU6CF+czPw9xkTAiEAnz2ASewLVc2Uc42VgyUKR19yy8SlGYvX" ++
    "h7Mb4/RIYtM=";
const good_base64 =
    "MIIBlDCCATmgAwIBAgICEAEwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBYxFDASBgNV" ++
    "BAMMC2dvb2QtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWQ6bctG2" ++
    "c8QseTp/gBMXYeuqnNYn7TiCJr9E9+os+4kuiZ+AdSqPsorbp/VAONrhbjkyYwTy" ++
    "4iqeZEYmjy4h7KN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYD" ++
    "VR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFPbNjkXzEROtcFB/jpriCQRx5Xd+" ++
    "MB8GA1UdIwQYMBaAFOGPPCJNPdhRl5z40kmuxl5bTj40MAoGCCqGSM49BAMCA0kA" ++
    "MEYCIQDS2PsKUe7bgIU6ktMWa9J7z/dRt8ZskJT+QzggaiZ0hQIhAIuXlBXP0iGg" ++
    "W3MfGt8dY47up1C9sqSmlxMxpWG0tkKG";
const revoked_base64 =
    "MIIBlzCCATygAwIBAgICEAIwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBkxFzAVBgNV" ++
    "BAMMDnJldm9rZWQtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfOEs" ++
    "A83kNW0KeINCBpHrxhJW07yht+u4R+h/mriq0ohvAqq4xo+CYuPNYfVM8uDEpvFa" ++
    "W0mHf5ffORS3zcXFWKN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4Aw" ++
    "EwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHjbxgNaDfc+edyrH/FcgLXx" ++
    "lJnWMB8GA1UdIwQYMBaAFOGPPCJNPdhRl5z40kmuxl5bTj40MAoGCCqGSM49BAMC" ++
    "A0kAMEYCIQDmRnZBG6KpALNt5yfzutiD3wy4zU88qgI87M3csPE2pQIhAIk+S4vd" ++
    "vM8Mlu1nZe4M0YkCWi7omb60P32wFmllWa63";
const crl_base64 =
    "MIHUMH0CAQEwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRlc3QgUm9vdBcN" ++
    "MjYwOTAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjAjMCECAhACFw0yNjA5MjIxOTAy" ++
    "MzFaMAwwCgYDVR0VBAMKAQGgDzANMAsGA1UdFAQEAgIQADAKBggqhkjOPQQDAgNH" ++
    "ADBEAiAcMtii8815JG7qfPRtjkJKxxWmrCnIW01AFwAjEEgkqgIgJNMKp1VLVy22" ++
    "tfQaelszInC3rbiKsCifZE4eYEmms/8=";

fn decodeFixture(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, len);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, encoded);
    return decoded;
}

test "CRL verifies signature and distinguishes revoked serials" {
    const allocator = std.testing.allocator;
    const ca = try decodeFixture(allocator, ca_base64);
    defer allocator.free(ca);
    const good = try decodeFixture(allocator, good_base64);
    defer allocator.free(good);
    const revoked = try decodeFixture(allocator, revoked_base64);
    defer allocator.free(revoked);
    const crl_bytes = try decodeFixture(allocator, crl_base64);
    defer allocator.free(crl_bytes);

    const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));
}

test "CRL rejects tampering and invalid update windows" {
    const allocator = std.testing.allocator;
    const ca = try decodeFixture(allocator, ca_base64);
    defer allocator.free(ca);
    const crl_bytes = try decodeFixture(allocator, crl_base64);
    defer allocator.free(crl_bytes);

    const tampered = try allocator.dupe(u8, crl_bytes);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_800_000_000),
    );
    try std.testing.expectError(
        error.CrlNotYetValid,
        parseAndVerify(crl_bytes, ca, 1_770_000_000),
    );
    try std.testing.expectError(
        error.CrlExpired,
        parseAndVerify(crl_bytes, ca, 2_000_000_000),
    );

    const wrong_issuer = @embedFile("testdata/ca.der");
    try std.testing.expectError(
        error.IssuerMismatch,
        parseAndVerify(crl_bytes, wrong_issuer, 1_800_000_000),
    );
    const wrong_leaf = @embedFile("testdata/server.der");
    const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
    try std.testing.expectError(
        error.IssuerMismatch,
        list.isRevoked(wrong_leaf),
    );
}

test "CRL verifies Mosquitto RSA SHA256 fixtures" {
    const allocator = std.testing.allocator;
    const ca = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-signing-ca.pem"),
        "CERTIFICATE",
    );
    defer allocator.free(ca);
    const good = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-client.pem"),
        "CERTIFICATE",
    );
    defer allocator.free(good);
    const revoked = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-client-revoked.pem"),
        "CERTIFICATE",
    );
    defer allocator.free(revoked);
    const crl_bytes = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-crl.pem"),
        "X509 CRL",
    );
    defer allocator.free(crl_bytes);

    const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));

    const tampered = try allocator.dupe(u8, crl_bytes);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_800_000_000),
    );
}

test "CRL verifies Ed25519 fixtures and rejects signature tampering" {
    const ca = @embedFile("testdata/ed25519-crl-ca.der");
    const good = @embedFile("testdata/ed25519-crl-good.der");
    const revoked = @embedFile("testdata/ed25519-crl-revoked.der");
    const crl_bytes = @embedFile("testdata/ed25519.crl.der");

    const list = try parseAndVerify(crl_bytes, ca, 1_790_419_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));

    const tampered = try std.testing.allocator.dupe(u8, crl_bytes);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_790_419_000),
    );
}

test "CRL verifies P384 SHA384 fixtures and rejects signature tampering" {
    const ca = @embedFile("testdata/p384-crl-ca.der");
    const good = @embedFile("testdata/p384-crl-good.der");
    const revoked = @embedFile("testdata/p384-crl-revoked.der");
    const crl_bytes = @embedFile("testdata/p384.crl.der");

    const list = try parseAndVerify(crl_bytes, ca, 1_790_420_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));

    const tampered = try std.testing.allocator.dupe(u8, crl_bytes);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_790_420_000),
    );
}

test "CRL verifies OpenSSL RSA PKCS1 SHA-384 and SHA-512 fixtures" {
    const ca = @embedFile("testdata/rsa-pss-crl-ca.der");
    const crls = [_][]const u8{
        @embedFile("testdata/rsa-pkcs1-sha384.crl.der"),
        @embedFile("testdata/rsa-pkcs1-sha512.crl.der"),
    };
    for (crls) |crl_bytes| {
        const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
        try std.testing.expectEqual(@as(usize, 0), list.revoked_entries.len);
    }
}

test "CRL verifies OpenSSL RSA-PSS SHA-256 SHA-384 and SHA-512 fixtures" {
    const ca = @embedFile("testdata/rsa-pss-crl-ca.der");
    const crls = [_][]const u8{
        @embedFile("testdata/rsa-pss-sha256.crl.der"),
        @embedFile("testdata/rsa-pss-sha384.crl.der"),
        @embedFile("testdata/rsa-pss-sha512.crl.der"),
    };
    for (crls) |crl_bytes| {
        const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
        try std.testing.expectEqual(@as(usize, 0), list.revoked_entries.len);
        try std.testing.expectEqual(@as(u64, 1_767_225_600), list.this_update);
        try std.testing.expectEqual(@as(u64, 2_082_758_400), list.next_update);
    }

    const tampered = try std.testing.allocator.dupe(u8, crls[2]);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_800_000_000),
    );

    const wrong_salt = try std.testing.allocator.dupe(u8, crls[0]);
    defer std.testing.allocator.free(wrong_salt);
    const encoded_salt_length = [_]u8{ 0xa2, 0x03, 0x02, 0x01, 0x20 };
    var search_from: usize = 0;
    var replacements: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        wrong_salt,
        search_from,
        &encoded_salt_length,
    )) |offset| {
        wrong_salt[offset + encoded_salt_length.len - 1] = 31;
        search_from = offset + encoded_salt_length.len;
        replacements += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), replacements);
    try std.testing.expectError(
        error.UnsupportedSignatureAlgorithm,
        parseAndVerify(wrong_salt, ca, 1_800_000_000),
    );
}

test "CRL rejects Ed25519 AlgorithmIdentifier parameters" {
    try std.testing.expectError(
        error.InvalidCrl,
        parseSignatureAlgorithm(.{
            .tag = 0x30,
            .start = 0,
            .value_start = 0,
            .end = 7,
            .value = &.{ 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00 },
        }),
    );
}

fn decodePemFixture(
    allocator: std.mem.Allocator,
    pem: []const u8,
    label: []const u8,
) ![]u8 {
    const begin = try std.fmt.allocPrint(
        allocator,
        "-----BEGIN {s}-----",
        .{label},
    );
    defer allocator.free(begin);
    const end = try std.fmt.allocPrint(
        allocator,
        "-----END {s}-----",
        .{label},
    );
    defer allocator.free(end);
    const begin_at = std.mem.indexOf(u8, pem, begin) orelse
        return error.InvalidCrl;
    const body_start = begin_at + begin.len;
    const end_at = std.mem.indexOfPos(u8, pem, body_start, end) orelse
        return error.InvalidCrl;
    var compact: std.ArrayList(u8) = .empty;
    defer compact.deinit(allocator);
    for (pem[body_start..end_at]) |byte| switch (byte) {
        ' ', '\t', '\r', '\n' => {},
        else => try compact.append(allocator, byte),
    };
    const len = try std.base64.standard.Decoder.calcSizeForSlice(compact.items);
    const decoded = try allocator.alloc(u8, len);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, compact.items);
    return decoded;
}
