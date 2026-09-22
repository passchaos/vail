const std = @import("std");
const trust = @import("trust.zig");

test "bundle verifier validates hostname and time" {
    const server_der = @embedFile("testdata/server.der");
    const ca_der = @embedFile("testdata/ca.der");
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, ca_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{server_der},
    });
    try std.testing.expectError(
        error.CertificateHostMismatch,
        verifier.verify(.{
            .server_name = "other.example",
            .chain = &.{server_der},
        }),
    );
}

test "client certificate bundle verifier validates trust without hostname" {
    const client_der = @embedFile("testdata/server.der");
    const ca_der = @embedFile("testdata/ca.der");
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, ca_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.ClientCertificateBundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };
    try verifier.verify(.{
        .server_name = null,
        .chain = &.{client_der},
    });
    try verifier.verify(.{
        .server_name = "not-the-client-name.example",
        .chain = &.{client_der},
    });
    try verifier.clientVerifier().verifyTrust(null, &.{client_der});

    var corrupted_client = client_der.*;
    corrupted_client[corrupted_client.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.clientVerifier().verifyTrust(null, &.{&corrupted_client}),
    );
}

test "bundle verifier treats the same certificate key as a trust anchor" {
    const server_der = @embedFile("testdata/server.der");
    var configured_anchor = server_der.*;
    configured_anchor[configured_anchor.len - 1] ^= 1;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &configured_anchor);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };

    // An explicitly configured anchor does not need a valid issuer signature.
    // TLS still verifies CertificateVerify possession separately.
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&configured_anchor},
    });

    var same_subject_and_key = configured_anchor;
    same_subject_and_key[same_subject_and_key.len - 1] ^= 2;
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&same_subject_and_key},
    });
}

test "bundle verifier checks exact trust anchor validity" {
    const server_der = @embedFile("testdata/server.der");
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, server_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);

    try std.testing.expectError(
        error.CertificateNotYetValid,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 1,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{server_der},
        }),
    );
    try std.testing.expectError(
        error.CertificateExpired,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 3_000_000_000,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{server_der},
        }),
    );
}

test "bundle verifier still verifies non-anchor certificate signatures" {
    const ca_der = @embedFile("testdata/ca.der");
    const server_der = @embedFile("testdata/server.der");
    var corrupted_server = server_der.*;
    corrupted_server[corrupted_server.len - 1] ^= 1;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, ca_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };

    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&corrupted_server},
        }),
    );
}

test "bundle verifier accepts an equivalent cross-signed trust anchor" {
    const server_der = @embedFile("testdata/server.der");
    var cross_signed_der = server_der.*;
    const parsed = try std.crypto.Certificate.parse(.{
        .buffer = &cross_signed_der,
        .index = 0,
    });
    const issuer_offset = @intFromPtr(parsed.issuer().ptr) -
        @intFromPtr(&cross_signed_der);
    cross_signed_der[issuer_offset + parsed.issuer().len - 1] ^= 1;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, server_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };

    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&cross_signed_der},
    });
    try std.testing.expectError(
        error.CertificateNotYetValid,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 1,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&cross_signed_der},
        }),
    );
    try std.testing.expectError(
        error.CertificateExpired,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 3_000_000_000,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&cross_signed_der},
        }),
    );
}

test "bundle verifier rejects an equivalent subject with another key" {
    const server_der = @embedFile("testdata/server.der");
    var impostor_der = server_der.*;
    const parsed = try std.crypto.Certificate.parse(.{
        .buffer = &impostor_der,
        .index = 0,
    });
    const issuer_offset = @intFromPtr(parsed.issuer().ptr) -
        @intFromPtr(&impostor_der);
    const public_key_offset = @intFromPtr(parsed.pubKey().ptr) -
        @intFromPtr(&impostor_der);
    impostor_der[issuer_offset + parsed.issuer().len - 1] ^= 1;
    impostor_der[public_key_offset + parsed.pubKey().len - 1] ^= 1;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, server_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };
    try std.testing.expectError(
        error.CertificateIssuerNotFound,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&impostor_der},
        }),
    );
}

test "bundle verifier enforces leaf and issuer certificate usage" {
    const ca_der = @embedFile("testdata/ca.der");
    const server_der = @embedFile("testdata/server.der");
    const ca = try trust.testing.certificateUsage(ca_der);
    try std.testing.expect(ca.basic_constraints_present);
    try std.testing.expect(ca.is_ca);
    try std.testing.expect(ca.key_usage_present);
    try std.testing.expect(ca.key_cert_sign);
    try trust.testing.validateIssuerUsage(ca, 0);

    const leaf = try trust.testing.certificateUsage(server_der);
    try std.testing.expect(leaf.basic_constraints_present);
    try std.testing.expect(!leaf.is_ca);
    try std.testing.expect(leaf.key_usage_present);
    try std.testing.expect(leaf.digital_signature);
    try trust.testing.validateLeafUsage(leaf);

    var invalid_leaf = server_der.*;
    const leaf_key_usage = std.mem.indexOf(
        u8,
        &invalid_leaf,
        &.{ 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80 },
    ) orelse return error.TestUnexpectedResult;
    invalid_leaf[leaf_key_usage + 7] = 0x02;
    invalid_leaf[leaf_key_usage + 8] = 0x04;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, ca_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&invalid_leaf},
        }),
    );

    var invalid_ca = ca_der.*;
    const ca_key_usage = std.mem.indexOf(
        u8,
        &invalid_ca,
        &.{ 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06 },
    ) orelse return error.TestUnexpectedResult;
    invalid_ca[ca_key_usage + 11] = 0x02;
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ server_der, &invalid_ca },
        }),
    );

    var unknown_critical_ca = ca_der.*;
    const basic_constraints_oid = std.mem.indexOf(
        u8,
        &unknown_critical_ca,
        &.{ 0x55, 0x1d, 0x13 },
    ) orelse return error.TestUnexpectedResult;
    unknown_critical_ca[basic_constraints_oid + 2] = 0x14;
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ server_der, &unknown_critical_ca },
        }),
    );

    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateLeafUsage(.{
            .key_usage_present = true,
        }),
    );
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateLeafUsage(.{
            .extended_key_usage_present = true,
        }),
    );
    try trust.testing.validateLeafUsage(.{
        .extended_key_usage_present = true,
        .server_auth = true,
    });
    try trust.testing.validateLeafUsage(.{
        .extended_key_usage_present = true,
        .any_extended_key_usage = true,
    });

    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateIssuerUsage(.{}, 0),
    );
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateIssuerUsage(.{
            .basic_constraints_present = true,
            .is_ca = true,
            .key_usage_present = true,
        }, 0),
    );
    try std.testing.expectError(
        error.CertificatePathLengthExceeded,
        trust.testing.validateIssuerUsage(.{
            .basic_constraints_present = true,
            .is_ca = true,
            .path_len = 0,
        }, 1),
    );
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateIssuerUsage(.{
            .basic_constraints_present = true,
            .is_ca = true,
            .unsupported_critical_extension = true,
        }, 0),
    );
}

test "bundle verifier parses serverAuth and anyExtendedKeyUsage" {
    const server_auth = try trust.testing.parseExtendedKeyUsage(
        &.{ 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 },
    );
    try std.testing.expect(server_auth.server_auth);
    try std.testing.expect(!server_auth.client_auth);
    try std.testing.expect(!server_auth.any);

    const client_auth = try trust.testing.parseExtendedKeyUsage(
        &.{ 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 },
    );
    try std.testing.expect(!client_auth.server_auth);
    try std.testing.expect(client_auth.client_auth);
    try std.testing.expect(!client_auth.any);
    try trust.testing.validateClientLeafUsage(.{
        .extended_key_usage_present = true,
        .client_auth = true,
    });
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateClientLeafUsage(.{
            .extended_key_usage_present = true,
            .server_auth = true,
        }),
    );
    try trust.testing.validateClientIssuerUsage(.{
        .basic_constraints_present = true,
        .is_ca = true,
        .extended_key_usage_present = true,
        .client_auth = true,
    }, 0);
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateClientIssuerUsage(.{
            .basic_constraints_present = true,
            .is_ca = true,
            .extended_key_usage_present = true,
            .server_auth = true,
        }, 0),
    );

    const any = try trust.testing.parseExtendedKeyUsage(
        &.{ 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x25, 0x00 },
    );
    try std.testing.expect(!any.server_auth);
    try std.testing.expect(any.any);

    const code_signing = try trust.testing.parseExtendedKeyUsage(
        &.{ 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 },
    );
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateLeafUsage(.{
            .extended_key_usage_present = true,
            .server_auth = code_signing.server_auth,
            .any_extended_key_usage = code_signing.any,
        }),
    );
}

test "bundle verifier parses basic constraints and key usage strictly" {
    const ca = try trust.testing.parseBasicConstraints(
        &.{ 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00 },
    );
    try std.testing.expect(ca.is_ca);
    try std.testing.expectEqual(@as(?usize, 0), ca.path_len);
    const leaf = try trust.testing.parseBasicConstraints(&.{ 0x30, 0x00 });
    try std.testing.expect(!leaf.is_ca);
    try std.testing.expect(leaf.path_len == null);
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.parseBasicConstraints(
            &.{ 0x30, 0x03, 0x01, 0x01, 0x00 },
        ),
    );

    const digital_signature = try trust.testing.parseKeyUsage(
        &.{ 0x03, 0x02, 0x07, 0x80 },
    );
    try std.testing.expect(digital_signature.digital_signature);
    try std.testing.expect(!digital_signature.key_cert_sign);
    const key_cert_sign = try trust.testing.parseKeyUsage(
        &.{ 0x03, 0x02, 0x02, 0x04 },
    );
    try std.testing.expect(!key_cert_sign.digital_signature);
    try std.testing.expect(key_cert_sign.key_cert_sign);
}

test "bundle verifier path length skips self-issued intermediates" {
    const ca_der = @embedFile("testdata/ca.der");
    const server_der = @embedFile("testdata/server.der");

    try std.testing.expectEqual(
        @as(usize, 3),
        try trust.testing.countCaBelow(3, ca_der),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        try trust.testing.countCaBelow(3, server_der),
    );
    try std.testing.expectError(
        error.CertificatePathLengthExceeded,
        trust.testing.countCaBelow(std.math.maxInt(usize), server_der),
    );
}
