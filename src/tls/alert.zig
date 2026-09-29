//! TLS alert protocol values and strict two-byte codec.

const std = @import("std");

pub const Level = enum(u8) {
    warning = 1,
    fatal = 2,
};

pub const Description = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,
};

pub fn closeNotify() Alert {
    return .{ .level = .warning, .description = .close_notify };
}

/// Map internal protocol failures to the least-surprising TLS 1.3 fatal alert.
/// Callers may override policy-specific certificate failures before sending.
pub fn fatalForError(err: anyerror) Alert {
    const description: Description = switch (err) {
        error.AuthenticationFailed => .bad_record_mac,
        error.RecordTooLarge => .record_overflow,
        error.NoTls13,
        error.InvalidLegacyVersion,
        => .protocol_version,
        error.NoSharedCipherSuite,
        error.NoSupportedKeyShare,
        error.UnsupportedSignatureScheme,
        error.MissingExtendedMasterSecret,
        => .handshake_failure,
        error.UnsupportedContentType,
        error.InterleavedHandshake,
        error.UnexpectedPlaintextRecord,
        error.InvalidChangeCipherSpec,
        => .unexpected_message,
        error.BadClientFinished => .decrypt_error,
        error.CertificateExpired => .certificate_expired,
        error.CertificateUntrusted,
        error.CertificateIssuerNotFound,
        => .unknown_ca,
        error.InvalidCertificate,
        error.BadCertificateVerify,
        error.InvalidCompressedCertificate,
        error.CertificateTooLarge,
        => .bad_certificate,
        error.SelectedUnofferedCompressionAlgorithm => .illegal_parameter,
        error.NoApplicationProtocol => .no_application_protocol,
        error.UnrecognizedName => .unrecognized_name,
        error.MissingExtension => .missing_extension,
        error.UnsupportedExtension => .unsupported_extension,
        error.InvalidClientHello,
        error.InvalidServerHello,
        error.InvalidRecord,
        error.InvalidAlert,
        error.InvalidAlertLevel,
        error.InvalidKeyUpdate,
        error.InvalidClientKeyExchange,
        error.InvalidFinished,
        error.HandshakeMessageTooLarge,
        => .decode_error,
        else => .internal_error,
    };
    return .{ .level = .fatal, .description = description };
}

pub const Error = error{
    InvalidAlert,
    InvalidAlertLevel,
};

pub const Alert = struct {
    level: Level,
    description: Description,

    pub fn toBytes(self: Alert) [2]u8 {
        return .{ @intFromEnum(self.level), @intFromEnum(self.description) };
    }

    pub fn isCloseNotify(self: Alert) bool {
        return self.description == .close_notify;
    }

    /// TLS 1.3 treats every alert other than `user_canceled` as terminating;
    /// the legacy level byte cannot downgrade an error alert to a warning.
    pub fn terminatesConnection(self: Alert) bool {
        return self.description != .user_canceled;
    }
};

pub fn parse(bytes: []const u8) Error!Alert {
    if (bytes.len != 2) return error.InvalidAlert;
    const level: Level = switch (bytes[0]) {
        1 => .warning,
        2 => .fatal,
        else => return error.InvalidAlertLevel,
    };
    return .{
        .level = level,
        .description = @enumFromInt(bytes[1]),
    };
}

test "TLS alerts round-trip known and unknown descriptions" {
    inline for ([_]Alert{
        .{ .level = .warning, .description = .close_notify },
        .{ .level = .fatal, .description = .decode_error },
        .{ .level = .fatal, .description = @enumFromInt(200) },
    }) |expected| {
        const encoded = expected.toBytes();
        try std.testing.expectEqual(expected, try parse(&encoded));
    }
    try std.testing.expectError(error.InvalidAlert, parse(&.{2}));
    try std.testing.expectError(error.InvalidAlertLevel, parse(&.{ 3, 0 }));
    try std.testing.expect(closeNotify().isCloseNotify());
    try std.testing.expect((Alert{
        .level = .warning,
        .description = .decode_error,
    }).terminatesConnection());
    try std.testing.expect(!(Alert{
        .level = .warning,
        .description = .user_canceled,
    }).terminatesConnection());
    try std.testing.expectEqual(
        Description.bad_record_mac,
        fatalForError(error.AuthenticationFailed).description,
    );
    try std.testing.expectEqual(
        Description.internal_error,
        fatalForError(error.OutOfMemory).description,
    );
}
