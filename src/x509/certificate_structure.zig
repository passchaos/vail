//! Structural validation for X.509 certificate DER.
//!
//! Zig std's index-based certificate parser trusts element lengths and can
//! read past the end of a malformed buffer. Every production path that hands
//! untrusted DER to `std.crypto.Certificate.parse` must first run this bounded
//! structure check.

const std = @import("std");
const der_reader = @import("../der.zig");

const Certificate = std.crypto.Certificate;

pub const Error = error{InvalidCertificate};

/// Reject malformed or truncated DER before handing the buffer to Zig std's
/// index-based certificate parser.
pub fn validate(bytes: []const u8) !void {
    try der_reader.validateDocument(bytes);

    var outer = der_reader.Reader{ .bytes = bytes };
    const certificate = (try outer.next()) orelse
        return error.InvalidCertificate;
    if (certificate.tag != 0x30 or !outer.done()) {
        return error.InvalidCertificate;
    }

    var certificate_reader = der_reader.Reader{ .bytes = certificate.value };
    const tbs = (try certificate_reader.next()) orelse
        return error.InvalidCertificate;
    const signature_algorithm = (try certificate_reader.next()) orelse
        return error.InvalidCertificate;
    const signature_value = (try certificate_reader.next()) orelse
        return error.InvalidCertificate;
    if (!certificate_reader.done() or tbs.tag != 0x30 or
        signature_algorithm.tag != 0x30 or signature_value.tag != 0x03)
    {
        return error.InvalidCertificate;
    }

    var tbs_reader = der_reader.Reader{ .bytes = tbs.value };
    var serial = (try tbs_reader.next()) orelse
        return error.InvalidCertificate;
    if (serial.tag == 0xa0) {
        serial = (try tbs_reader.next()) orelse
            return error.InvalidCertificate;
    }
    if (serial.tag != 0x02) return error.InvalidCertificate;

    const tbs_signature = (try tbs_reader.next()) orelse
        return error.InvalidCertificate;
    const issuer = (try tbs_reader.next()) orelse
        return error.InvalidCertificate;
    const validity = (try tbs_reader.next()) orelse
        return error.InvalidCertificate;
    const subject = (try tbs_reader.next()) orelse
        return error.InvalidCertificate;
    const subject_public_key_info = (try tbs_reader.next()) orelse
        return error.InvalidCertificate;
    if (tbs_signature.tag != 0x30 or issuer.tag != 0x30 or
        validity.tag != 0x30 or subject.tag != 0x30 or
        subject_public_key_info.tag != 0x30)
    {
        return error.InvalidCertificate;
    }

    var validity_reader = der_reader.Reader{ .bytes = validity.value };
    const not_before = (try validity_reader.next()) orelse
        return error.InvalidCertificate;
    const not_after = (try validity_reader.next()) orelse
        return error.InvalidCertificate;
    if (!validity_reader.done() or
        (not_before.tag != 0x17 and not_before.tag != 0x18) or
        (not_after.tag != 0x17 and not_after.tag != 0x18))
    {
        return error.InvalidCertificate;
    }

    var spki_reader = der_reader.Reader{
        .bytes = subject_public_key_info.value,
    };
    const public_key_algorithm = (try spki_reader.next()) orelse
        return error.InvalidCertificate;
    const public_key = (try spki_reader.next()) orelse
        return error.InvalidCertificate;
    if (!spki_reader.done() or public_key_algorithm.tag != 0x30 or
        public_key.tag != 0x03)
    {
        return error.InvalidCertificate;
    }
}

/// Validate the certificate structure and then run Zig std's parser.
pub fn parseStandard(der: []const u8) !Certificate.Parsed {
    try validate(der);
    return Certificate.parse(.{ .buffer = der, .index = 0 });
}
