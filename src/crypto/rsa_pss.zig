//! RSA-PSS parameters and AlgorithmIdentifier parsing.
//!
//! This module is shared by RSA key parsing, X.509 certificate verification,
//! and TLS signature-scheme validation. It deliberately constrains PSS to
//! interoperable profiles: traditional PSS uses MGF1 with the same hash,
//! RFC 8692 PSS uses SHAKE natively as its MGF, salts are one digest long,
//! and trailerField is 1.

const std = @import("std");
const der = @import("../der.zig");
const signature_algorithm = @import("signature_algorithm.zig");

pub const Algorithm = signature_algorithm.Algorithm;

pub const Error = error{
    InvalidAlgorithmIdentifier,
    UnsupportedSignatureAlgorithm,
};

pub const PssHash = enum {
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    shake128,
    shake256,

    pub fn digestLength(self: PssHash) usize {
        return switch (self) {
            .sha1 => std.crypto.hash.Sha1.digest_length,
            .sha224 => std.crypto.hash.sha2.Sha224.digest_length,
            .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
            .sha384 => std.crypto.hash.sha2.Sha384.digest_length,
            .sha512 => std.crypto.hash.sha2.Sha512.digest_length,
            .sha512_224 => std.crypto.hash.sha2.Sha512_224.digest_length,
            .sha512_256 => std.crypto.hash.sha2.Sha512_256.digest_length,
            .sha3_224 => std.crypto.hash.sha3.Sha3_224.digest_length,
            .sha3_256 => std.crypto.hash.sha3.Sha3_256.digest_length,
            .sha3_384 => std.crypto.hash.sha3.Sha3_384.digest_length,
            .sha3_512 => std.crypto.hash.sha3.Sha3_512.digest_length,
            .shake128 => std.crypto.hash.sha3.Shake128.digest_length,
            .shake256 => std.crypto.hash.sha3.Shake256.digest_length,
        };
    }

    pub fn signatureAlgorithm(self: PssHash) Error!Algorithm {
        return switch (self) {
            .sha1 => error.UnsupportedSignatureAlgorithm,
            .sha224 => .rsa_pss_sha224,
            .sha256 => .rsa_pss_sha256,
            .sha384 => .rsa_pss_sha384,
            .sha512 => .rsa_pss_sha512,
            .sha512_224 => .rsa_pss_sha512_224,
            .sha512_256 => .rsa_pss_sha512_256,
            .sha3_224 => .rsa_pss_sha3_224,
            .sha3_256 => .rsa_pss_sha3_256,
            .sha3_384 => .rsa_pss_sha3_384,
            .sha3_512 => .rsa_pss_sha3_512,
            .shake128 => .rsa_pss_shake128,
            .shake256 => .rsa_pss_shake256,
        };
    }
};

pub const PssProfile = struct {
    hash: PssHash,
    mgf_hash: PssHash,
    salt_length: usize,
    trailer_field: usize,
};

pub const PssKeyConstraints = union(enum) {
    unrestricted,
    restricted: PssProfile,

    pub fn permits(
        self: PssKeyConstraints,
        signature_algorithm_value: Algorithm,
    ) bool {
        const signature_profile = pssProfileForAlgorithm(
            signature_algorithm_value,
        ) orelse return false;
        return switch (self) {
            .unrestricted => true,
            .restricted => |key_profile| key_profile.hash ==
                signature_profile.hash and
                key_profile.mgf_hash == signature_profile.mgf_hash and
                key_profile.trailer_field == signature_profile.trailer_field and
                signature_profile.salt_length >= key_profile.salt_length,
        };
    }
};

pub fn pssProfileForAlgorithm(algorithm: Algorithm) ?PssProfile {
    const hash: PssHash = switch (algorithm) {
        .rsa_pss_sha224 => .sha224,
        .rsa_pss_sha256 => .sha256,
        .rsa_pss_sha384 => .sha384,
        .rsa_pss_sha512 => .sha512,
        .rsa_pss_sha512_224 => .sha512_224,
        .rsa_pss_sha512_256 => .sha512_256,
        .rsa_pss_sha3_224 => .sha3_224,
        .rsa_pss_sha3_256 => .sha3_256,
        .rsa_pss_sha3_384 => .sha3_384,
        .rsa_pss_sha3_512 => .sha3_512,
        .rsa_pss_shake128 => .shake128,
        .rsa_pss_shake256 => .shake256,
        else => return null,
    };
    return .{
        .hash = hash,
        .mgf_hash = hash,
        .salt_length = hash.digestLength(),
        .trailer_field = 1,
    };
}

pub fn parsePssPublicKeyAlgorithmIdentifier(
    encoded: []const u8,
) Error!PssKeyConstraints {
    var fields = der.Reader{ .bytes = encoded };
    const oid = fields.require(0x06) catch
        return error.InvalidAlgorithmIdentifier;
    if (std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake128)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .{ .restricted = pssProfileForAlgorithm(
            .rsa_pss_shake128,
        ).? };
    }
    if (std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake256)) {
        if (!fields.done()) return error.InvalidAlgorithmIdentifier;
        return .{ .restricted = pssProfileForAlgorithm(
            .rsa_pss_shake256,
        ).? };
    }
    if (!std.mem.eql(u8, oid.value, &oid_rsassa_pss)) {
        return error.UnsupportedSignatureAlgorithm;
    }
    const parameters = (fields.next() catch
        return error.InvalidAlgorithmIdentifier) orelse
        return .unrestricted;
    if (parameters.tag != 0x30 or !fields.done()) {
        return error.InvalidAlgorithmIdentifier;
    }
    const profile = try parsePssProfile(parameters.value);
    if (profile.trailer_field != 1) {
        return error.UnsupportedSignatureAlgorithm;
    }
    return .{ .restricted = profile };
}

pub fn parsePssProfile(encoded: []const u8) Error!PssProfile {
    var fields = der.Reader{ .bytes = encoded };
    var hash: PssHash = .sha1;
    var mask_hash: PssHash = .sha1;
    var salt_length: usize = 20;
    var trailer_field: usize = 1;
    var previous_tag: u8 = 0x9f;
    while (fields.next() catch
        return error.InvalidAlgorithmIdentifier) |field|
    {
        if (field.tag < 0xa0 or field.tag > 0xa3 or
            (previous_tag != 0x9f and field.tag <= previous_tag))
        {
            return error.InvalidAlgorithmIdentifier;
        }
        previous_tag = field.tag;
        switch (field.tag) {
            0xa0 => hash = try parseExplicitHashAlgorithm(field),
            0xa1 => mask_hash = try parseExplicitMaskAlgorithm(field),
            0xa2 => salt_length = try parseExplicitSmallInteger(field),
            0xa3 => trailer_field = try parseExplicitSmallInteger(field),
            else => unreachable,
        }
    }
    return .{
        .hash = hash,
        .mgf_hash = mask_hash,
        .salt_length = salt_length,
        .trailer_field = trailer_field,
    };
}

fn parseExplicitHashAlgorithm(field: der.Element) Error!PssHash {
    var explicit = der.Reader{ .bytes = field.value };
    const algorithm = explicit.require(0x30) catch
        return error.InvalidAlgorithmIdentifier;
    if (!explicit.done()) return error.InvalidAlgorithmIdentifier;
    return parseHashAlgorithm(algorithm.value);
}

fn parseExplicitMaskAlgorithm(field: der.Element) Error!PssHash {
    var explicit = der.Reader{ .bytes = field.value };
    const algorithm = explicit.require(0x30) catch
        return error.InvalidAlgorithmIdentifier;
    if (!explicit.done()) return error.InvalidAlgorithmIdentifier;
    var fields = der.Reader{ .bytes = algorithm.value };
    const oid = fields.require(0x06) catch
        return error.InvalidAlgorithmIdentifier;
    if (!std.mem.eql(u8, oid.value, &oid_mgf1)) {
        return error.UnsupportedSignatureAlgorithm;
    }
    const parameters = fields.require(0x30) catch
        return error.InvalidAlgorithmIdentifier;
    if (!fields.done()) return error.InvalidAlgorithmIdentifier;
    return parseHashAlgorithm(parameters.value);
}

fn parseHashAlgorithm(encoded: []const u8) Error!PssHash {
    var fields = der.Reader{ .bytes = encoded };
    const oid = fields.require(0x06) catch
        return error.InvalidAlgorithmIdentifier;
    const hash: PssHash = if (std.mem.eql(u8, oid.value, &oid_sha1))
        .sha1
    else if (std.mem.eql(u8, oid.value, &oid_sha224))
        .sha224
    else if (std.mem.eql(u8, oid.value, &oid_sha256))
        .sha256
    else if (std.mem.eql(u8, oid.value, &oid_sha384))
        .sha384
    else if (std.mem.eql(u8, oid.value, &oid_sha512))
        .sha512
    else if (std.mem.eql(u8, oid.value, &oid_sha512_224))
        .sha512_224
    else if (std.mem.eql(u8, oid.value, &oid_sha512_256))
        .sha512_256
    else if (std.mem.eql(u8, oid.value, &oid_sha3_224))
        .sha3_224
    else if (std.mem.eql(u8, oid.value, &oid_sha3_256))
        .sha3_256
    else if (std.mem.eql(u8, oid.value, &oid_sha3_384))
        .sha3_384
    else if (std.mem.eql(u8, oid.value, &oid_sha3_512))
        .sha3_512
    else
        return error.UnsupportedSignatureAlgorithm;
    if (fields.next() catch return error.InvalidAlgorithmIdentifier) |parameters| {
        if (parameters.tag != 0x05 or parameters.value.len != 0 or
            !fields.done())
        {
            return error.InvalidAlgorithmIdentifier;
        }
    }
    return hash;
}

fn parseExplicitSmallInteger(field: der.Element) Error!usize {
    var explicit = der.Reader{ .bytes = field.value };
    const integer = explicit.require(0x02) catch
        return error.InvalidAlgorithmIdentifier;
    if (!explicit.done() or integer.value.len == 0 or
        (integer.value[0] & 0x80) != 0 or
        (integer.value.len > 1 and integer.value[0] == 0 and
            (integer.value[1] & 0x80) == 0) or
        integer.value.len > @sizeOf(usize))
    {
        return error.InvalidAlgorithmIdentifier;
    }
    var result: usize = 0;
    for (integer.value) |byte| {
        result = std.math.mul(usize, result, 256) catch
            return error.InvalidAlgorithmIdentifier;
        result = std.math.add(usize, result, byte) catch
            return error.InvalidAlgorithmIdentifier;
    }
    return result;
}

const oid_rsassa_pss = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
};
const oid_rsassa_pss_shake128 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e,
};
const oid_rsassa_pss_shake256 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f,
};
const oid_mgf1 = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
};
const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
const oid_sha224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
};
const oid_sha256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
};
const oid_sha384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
};
const oid_sha512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
};
const oid_sha512_224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
};
const oid_sha512_256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
};
const oid_sha3_224 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
};
const oid_sha3_256 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
};
const oid_sha3_384 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
};
const oid_sha3_512 = [_]u8{
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
};
