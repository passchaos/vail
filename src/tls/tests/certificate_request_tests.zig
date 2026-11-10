const std = @import("std");
const auth = @import("../handshake/auth.zig");
const certificate_compression = @import("../handshake/certificate_compression.zig");
const cipher_suite = @import("../crypto/cipher_suite.zig");
const client_auth = @import("../handshake/client_auth.zig");
const key_schedule = @import("../crypto/key_schedule.zig");
const key_exchange = @import("../key_exchange.zig");
const secret = @import("../crypto/secret.zig");
const ticket_keyring = @import("../crypto/ticket_keyring.zig");
const transcript = @import("../crypto/transcript.zig");
const p521 = @import("../../crypto/ec/p521.zig");
const sm2 = @import("../../crypto/sign/sm2.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const common = @import("common.zig");
const decodeHex = common.decodeHex;
const writeTestFinished = common.writeTestFinished;
const expectHex = common.expectHex;
const checkCertificateAllocationFailure = common.checkCertificateAllocationFailure;

test "CertificateRequest advertises built-in signature schemes" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try client_auth.writeRequestWithOptions(
        &encoded,
        allocator,
        .{
            .request_context = "request",
            .certificate_authorities = &.{"ca-subject"},
            .compression_algorithms = &.{.zlib},
            .request_ocsp = true,
            .certificate_signature_schemes = &.{
                auth.signature_scheme_ed25519,
            },
        },
    );
    const parsed = try client_auth.parseRequest(encoded.items);
    try std.testing.expectEqualStrings("request", parsed.request_context);
    try std.testing.expectEqualStrings(
        "\x00\x0aca-subject",
        parsed.certificate_authorities,
    );
    try std.testing.expect(parsed.supports_ed25519);
    try std.testing.expect(parsed.supports_ecdsa_p256_sha256);
    try std.testing.expect(parsed.supports_ecdsa_p384_sha384);
    try std.testing.expect(parsed.supports_rsa_pss_rsae_sha256);
    try std.testing.expect(parsed.supports_rsa_pss_rsae_sha384);
    try std.testing.expect(parsed.supports_rsa_pss_rsae_sha512);
    try std.testing.expect(parsed.supports_rsa_pss_pss_sha256);
    try std.testing.expect(parsed.supports_rsa_pss_pss_sha384);
    try std.testing.expect(parsed.supports_rsa_pss_pss_sha512);
    try std.testing.expect(parsed.supports_sm2sig_sm3);
    try std.testing.expect(parsed.supports_ml_dsa_44);
    try std.testing.expect(parsed.supports_ml_dsa_65);
    try std.testing.expect(parsed.supports_ml_dsa_87);
    try std.testing.expect(parsed.supportsCertificateSignatureScheme(
        auth.signature_scheme_ed25519,
    ));
    try std.testing.expect(!parsed.supportsCertificateSignatureScheme(
        auth.signature_scheme_rsa_pss_rsae_sha256,
    ));
    try std.testing.expect(!try parsed.supportsCertificateChain(&.{
        @embedFile("../../x509/testdata/server.der"),
        @embedFile("../../x509/testdata/ca.der"),
    }));
    try std.testing.expect(parsed.supportsCertificateCompression(.zlib));
    try std.testing.expect(!parsed.supportsCertificateCompression(.brotli));
    try std.testing.expect(parsed.requests_ocsp);

    const empty_certificate_algorithms = [_]u8{
        0x0d, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x0e, 0x00,
        0x0d, 0x00, 0x04, 0x00,
        0x02, 0x08, 0x07, 0x00,
        0x32, 0x00, 0x02, 0x00,
        0x00,
    };
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(&empty_certificate_algorithms),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.writeRequestWithOptions(
            &encoded,
            allocator,
            .{
                .request_context = "request",
                .certificate_signature_schemes = &.{},
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.writeRequestWithOptions(
            &encoded,
            allocator,
            .{
                .request_context = "request",
                .certificate_signature_schemes = &.{
                    auth.signature_scheme_ed25519,
                    auth.signature_scheme_ed25519,
                },
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    const duplicate_certificate_authorities = [_]u8{
        0x0d, 0x00, 0x00, 0x1d,
        0x00, 0x00, 0x1a, 0x00,
        0x0d, 0x00, 0x04, 0x00,
        0x02, 0x08, 0x07, 0x00,
        0x2f, 0x00, 0x05, 0x00,
        0x03, 0x00, 0x01, 'a',
        0x00, 0x2f, 0x00, 0x05,
        0x00, 0x03, 0x00, 0x01,
        'b',
    };
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(&duplicate_certificate_authorities),
    );

    const unknown_extension = [_]u8{
        0x0d, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x0e, 0x00,
        0x0d, 0x00, 0x04, 0x00,
        0x02, 0x08, 0x07, 0xfa,
        0xfa, 0x00, 0x02, 0x12,
        0x34,
    };
    const parsed_unknown = try client_auth.parseRequest(&unknown_extension);
    try std.testing.expect(parsed_unknown.supports_ed25519);
    try std.testing.expectEqual(@as(usize, 0), parsed_unknown.certificate_authorities.len);

    const non_empty_status_request = [_]u8{
        0x0d, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x0e, 0x00,
        0x0d, 0x00, 0x04, 0x00,
        0x02, 0x08, 0x07, 0x00,
        0x05, 0x00, 0x02, 0x12,
        0x34,
    };
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(&non_empty_status_request),
    );

    const misplaced_alpn = [_]u8{
        0x0d, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x0e, 0x00,
        0x0d, 0x00, 0x04, 0x00,
        0x02, 0x08, 0x07, 0x00,
        0x10, 0x00, 0x02, 0x12,
        0x34,
    };
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(&misplaced_alpn),
    );

    const duplicate_unknown_extensions = [_]u8{
        0x0d, 0x00, 0x00, 0x13,
        0x00, 0x00, 0x10, 0x00,
        0x0d, 0x00, 0x04, 0x00,
        0x02, 0x08, 0x07, 0xfa,
        0xfa, 0x00, 0x00, 0xfa,
        0xfa, 0x00, 0x00,
    };
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(&duplicate_unknown_extensions),
    );
}

test "CertificateRequest accepts more than 64 unique extensions" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    // Handshake header, empty request context, and extension-vector length.
    try encoded.appendSlice(allocator, &.{
        0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    });
    try encoded.appendSlice(allocator, &.{
        0x00, 0x0d, 0x00, 0x04,
        0x00, 0x02, 0x08, 0x07,
    });
    for (0..65) |index| {
        var extension = [_]u8{ 0, 0, 0, 0 };
        std.mem.writeInt(
            u16,
            extension[0..2],
            @intCast(0x8000 + index),
            .big,
        );
        try encoded.appendSlice(allocator, &extension);
    }

    var extensions_len = encoded.items.len - 7;
    std.mem.writeInt(
        u16,
        encoded.items[5..7],
        @intCast(extensions_len),
        .big,
    );
    var body_len = encoded.items.len - 4;
    encoded.items[1] = @truncate(body_len >> 16);
    encoded.items[2] = @truncate(body_len >> 8);
    encoded.items[3] = @truncate(body_len);

    const parsed = try client_auth.parseRequest(encoded.items);
    try std.testing.expect(parsed.supports_ed25519);

    // The complete extension type namespace is tracked, so a duplicate after
    // the former 64-entry boundary remains fatal.
    try encoded.appendSlice(allocator, &.{ 0x80, 0x00, 0x00, 0x00 });
    extensions_len = encoded.items.len - 7;
    std.mem.writeInt(
        u16,
        encoded.items[5..7],
        @intCast(extensions_len),
        .big,
    );
    body_len = encoded.items.len - 4;
    encoded.items[1] = @truncate(body_len >> 16);
    encoded.items[2] = @truncate(body_len >> 8);
    encoded.items[3] = @truncate(body_len);
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(encoded.items),
    );
}

test "CertificateRequest preserves repeated signature scheme values" {
    const encoded = [_]u8{
        0x0d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x1d, 0x00,
        0x0d, 0x00, 0x06, 0x00,
        0x04, 0x08, 0x07, 0x08,
        0x07, 0x00, 0x32, 0x00,
        0x06, 0x00, 0x04, 0x08,
        0x07, 0x08, 0x07, 0x00,
        0x1b, 0x00, 0x05, 0x04,
        0x00, 0x01, 0x00, 0x02,
    };
    const parsed = try client_auth.parseRequest(&encoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x07, 0x08, 0x07 },
        parsed.signature_algorithms,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x07, 0x08, 0x07 },
        parsed.certificate_signature_algorithms.?,
    );
    try std.testing.expect(parsed.supports_ed25519);
    try std.testing.expect(parsed.supportsCertificateSignatureScheme(
        auth.signature_scheme_ed25519,
    ));
    try std.testing.expect(parsed.supportsCertificateCompression(.zlib));
    try std.testing.expect(parsed.supportsCertificateCompression(.brotli));
}

test "CertificateRequest OID filters select matching X509 leaf" {
    const allocator = std.testing.allocator;
    const certificate = @embedFile("../../x509/testdata/ed25519-crl-good.der");
    const key_usage_oid = [_]u8{ 0x55, 0x1d, 0x0f };
    const extended_key_usage_oid = [_]u8{ 0x55, 0x1d, 0x25 };
    const unknown_oid = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x7f };
    const digital_signature = [_]u8{ 0x03, 0x02, 0x07, 0x80 };
    const client_auth_usage = [_]u8{
        0x30, 0x0a, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x02,
    };
    const server_auth_usage = [_]u8{
        0x30, 0x0a, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x01,
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try client_auth.writeRequestWithOptions(&encoded, allocator, .{
        .request_context = "request",
        .oid_filters = &.{
            .{ .oid = &key_usage_oid, .values = &digital_signature },
            .{ .oid = &extended_key_usage_oid, .values = &client_auth_usage },
            .{ .oid = &unknown_oid, .values = "opaque-value" },
        },
    });
    const matching = try client_auth.parseRequest(encoded.items);
    try std.testing.expect(matching.oid_filters.len != 0);
    try std.testing.expect(try matching.supportsCertificateChain(&.{certificate}));

    encoded.clearRetainingCapacity();
    try client_auth.writeRequestWithOptions(&encoded, allocator, .{
        .request_context = "request",
        .oid_filters = &.{.{
            .oid = &extended_key_usage_oid,
            .values = &server_auth_usage,
        }},
    });
    const mismatching = try client_auth.parseRequest(encoded.items);
    try std.testing.expect(!try mismatching.supportsCertificateChain(
        &.{certificate},
    ));
}

test "CertificateRequest OID filters reject invalid and duplicate entries" {
    const allocator = std.testing.allocator;
    const extended_key_usage_oid = [_]u8{ 0x55, 0x1d, 0x25 };
    const any_extended_key_usage = [_]u8{
        0x30, 0x06, 0x06, 0x04,
        0x55, 0x1d, 0x25, 0x00,
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.writeRequestWithOptions(&encoded, allocator, .{
            .request_context = "request",
            .oid_filters = &.{.{ .oid = &.{0x80}, .values = &.{} }},
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.writeRequestWithOptions(&encoded, allocator, .{
            .request_context = "request",
            .oid_filters = &.{.{
                .oid = &extended_key_usage_oid,
                .values = &any_extended_key_usage,
            }},
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.writeRequestWithOptions(&encoded, allocator, .{
            .request_context = "request",
            .oid_filters = &.{
                .{ .oid = &.{ 0x2b, 0x01 }, .values = &.{} },
                .{ .oid = &.{ 0x2b, 0x01 }, .values = &.{} },
            },
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    try client_auth.writeRequestWithOptions(&encoded, allocator, .{
        .request_context = "request",
        .oid_filters = &.{
            .{ .oid = &.{ 0x55, 0x1d, 0x0f }, .values = &.{} },
            .{ .oid = &.{ 0x55, 0x1d, 0x10 }, .values = &.{} },
        },
    });
    const second_oid = std.mem.lastIndexOf(
        u8,
        encoded.items,
        &.{ 0x03, 0x55, 0x1d, 0x10, 0x00, 0x00 },
    ).?;
    encoded.items[second_oid + 3] = 0x0f;
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(encoded.items),
    );
}

test "CertificateRequest writer preflights nested vector lengths" {
    const allocator = std.testing.allocator;
    const authority = try allocator.alloc(u8, std.math.maxInt(u16) - 3);
    defer allocator.free(authority);
    @memset(authority, 0x2a);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, "prefix");
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.writeRequestWithOptions(&encoded, allocator, .{
            .request_context = &.{},
            .certificate_authorities = &.{authority},
        }),
    );
    try std.testing.expectEqualStrings("prefix", encoded.items);
}

test "CertificateRequest rejects an empty certificate authorities vector" {
    const encoded = [_]u8{
        0x0d, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x0e, 0x00,
        0x0d, 0x00, 0x04, 0x00,
        0x02, 0x08, 0x07, 0x00,
        0x2f, 0x00, 0x02, 0x00,
        0x00,
    };
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.parseRequest(&encoded),
    );
}

test "TLS 1.3 initial CertificateRequest requires an empty context" {
    try client_auth.validateInitialRequestContext(&.{});
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        client_auth.validateInitialRequestContext("post-handshake"),
    );
}

test "optional client Certificate supports an empty chain" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try auth.writeClientCertificateWithContext(
        &encoded,
        allocator,
        &.{},
        "optional",
    );
    var parsed = try auth.parseClientCertificateWithContext(
        allocator,
        encoded.items,
        "optional",
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), parsed.entries.len);
    try std.testing.expectError(
        error.EmptyCertificateChain,
        auth.parseCertificateWithContext(
            allocator,
            encoded.items,
            "optional",
        ),
    );
}

test "client identity validates OCSP configuration" {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x63} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    const base = client_auth.ClientIdentity{
        .certificate_chain = &.{&public_key},
        .signer = .{ .ed25519 = .{ .key_pair = key_pair } },
    };

    var invalid = base;
    invalid.ocsp_response = "leaf";
    invalid.ocsp_responses = &.{"entry"};
    try std.testing.expectError(error.InvalidCertificate, invalid.validate());

    invalid = base;
    invalid.ocsp_responses = &.{ null, null };
    try std.testing.expectError(error.InvalidCertificate, invalid.validate());

    invalid = base;
    invalid.ocsp_response = &.{};
    try std.testing.expectError(error.InvalidCertificate, invalid.validate());
}

test "client CertificateVerify uses the distinct TLS context" {
    const allocator = std.testing.allocator;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x61} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    const transcript_hash = [_]u8{0x62} ** 32;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try auth.writeCertificateVerifyForRole(
        &encoded,
        allocator,
        .{ .ed25519 = .{ .key_pair = key_pair } },
        &transcript_hash,
        .client,
    );
    const parsed = try auth.parseCertificateVerify(encoded.items);
    try auth.verifyCertificateVerifyForRole(
        &public_key,
        parsed,
        &transcript_hash,
        .client,
    );
    try std.testing.expectError(
        error.BadCertificateVerify,
        auth.verifyCertificateVerifyForRole(
            &public_key,
            parsed,
            &transcript_hash,
            .server,
        ),
    );
}
