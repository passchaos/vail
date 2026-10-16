const std = @import("std");
const auth = @import("../tls/auth.zig");
const ed25519 = @import("../crypto/ed25519.zig");
const p256 = @import("../crypto/p256.zig");
const p521 = @import("../crypto/p521.zig");
const certificate_compat = @import("certificate.zig");
const trust = @import("trust.zig");
const crl = @import("crl.zig");
const ocsp = @import("ocsp.zig");
const path_vectors = @import("testdata/path_vectors.zig");

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

test "server certificate identity verification covers DNS and IP authorities" {
    const dns_leaf = decodeHex(path_vectors.leaf_hex);
    try trust.verifyServerCertificateIdentity(&dns_leaf, "localhost");
    try std.testing.expectError(
        error.CertificateHostMismatch,
        trust.verifyServerCertificateIdentity(&dns_leaf, "other.example"),
    );

    const ip4_leaf = decodeHex(path_vectors.ip_constraints_allowed_leaf_hex);
    try trust.verifyServerCertificateIdentity(&ip4_leaf, "10.1.2.3");
    try std.testing.expectError(
        error.CertificateHostMismatch,
        trust.verifyServerCertificateIdentity(&ip4_leaf, "10.1.2.4"),
    );

    const ip6_leaf = decodeHex(path_vectors.ip_constraints_ipv6_leaf_hex);
    try trust.verifyServerCertificateIdentity(&ip6_leaf, "2001:db8:1::42");
    try std.testing.expectError(
        error.CertificateHostMismatch,
        trust.verifyServerCertificateIdentity(&ip6_leaf, "2001:db8:1::43"),
    );
}

test "TLS leaf OCSP staple is enforced by bundle trust policy" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.root_hex);
    const intermediate = decodeHex(path_vectors.intermediate_hex);
    const leaf = decodeHex(path_vectors.leaf_hex);
    const good = decodeHex(path_vectors.ocsp_good_hex);
    const revoked = decodeHex(path_vectors.ocsp_revoked_hex);
    const now = 1_790_663_000;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);

    var certificate_message: std.ArrayList(u8) = .empty;
    defer certificate_message.deinit(allocator);
    try auth.writeCertificateWithOcsp(
        &certificate_message,
        allocator,
        &.{ &leaf, &intermediate },
        &good,
    );
    var parsed = try auth.parseCertificate(
        allocator,
        certificate_message.items,
    );
    defer parsed.deinit(allocator);

    const required = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .require,
    };
    try required.verify(.{
        .server_name = "localhost",
        .chain = parsed.entries,
        .ocsp_response = parsed.ocsp_response,
    });
    try required.clientVerifier().verifyTrustWithOcsp(
        "localhost",
        parsed.entries,
        parsed.ocsp_response,
    );
    try std.testing.expectError(
        error.CertificateOcspResponseRequired,
        required.verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
        }),
    );
    try std.testing.expectError(
        error.CertificateRevoked,
        required.verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_response = &revoked,
        }),
    );
    try (trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .if_present,
    }).verify(.{
        .server_name = "localhost",
        .chain = &.{ &leaf, &intermediate },
    });

    const leaf_only_responses = [_]?[]const u8{ &good, null };
    try (trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .if_present,
    }).verify(.{
        .server_name = "localhost",
        .chain = &.{ &leaf, &intermediate },
        .ocsp_responses = &leaf_only_responses,
    });

    const misplaced_responses = [_]?[]const u8{ &good, &good };
    try std.testing.expectError(
        error.CertificateStatusNotFound,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = now,
            .stapled_ocsp = .if_present,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_responses = &misplaced_responses,
        }),
    );
    try std.testing.expectError(
        error.InvalidCertificateOcspResponses,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = now,
            .stapled_ocsp = .if_present,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_responses = &.{&good},
        }),
    );

    const inconsistent_legacy = [_]?[]const u8{ &revoked, null };
    try std.testing.expectError(
        error.InvalidCertificateOcspResponses,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = now,
            .stapled_ocsp = .if_present,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_response = &good,
            .ocsp_responses = &inconsistent_legacy,
        }),
    );
}

test "RFC 7633 status_request automatically requires a valid OCSP staple" {
    const allocator = std.testing.allocator;
    const ca = decodeHex(path_vectors.must_staple_ca_hex);
    const leaf = decodeHex(path_vectors.must_staple_leaf_hex);
    const good = decodeHex(path_vectors.must_staple_ocsp_good_hex);
    const now = 1_790_809_920;

    const usage = try trust.testing.certificateUsage(&leaf);
    try std.testing.expect(usage.must_staple);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &ca);
    try bundle.parseCert(allocator, 0, now);

    // The caller's default `.ignore` policy cannot disable a certificate's
    // signed status_request requirement.
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try std.testing.expectError(
        error.CertificateOcspResponseRequired,
        verifier.verify(.{
            .server_name = "must-staple.localhost",
            .chain = &.{&leaf},
        }),
    );
    try verifier.verify(.{
        .server_name = "must-staple.localhost",
        .chain = &.{&leaf},
        .ocsp_response = &good,
    });

    var tampered = good;
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOcspSignature,
        verifier.verify(.{
            .server_name = "must-staple.localhost",
            .chain = &.{&leaf},
            .ocsp_response = &tampered,
        }),
    );
}

test "TLS 1.3 multi-stapling validates leaf and selected intermediate" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.multi_staple_root_hex);
    const intermediate = decodeHex(path_vectors.multi_staple_intermediate_hex);
    const leaf = decodeHex(path_vectors.multi_staple_leaf_hex);
    const leaf_ocsp = decodeHex(path_vectors.multi_staple_leaf_ocsp_hex);
    const intermediate_ocsp = decodeHex(
        path_vectors.multi_staple_intermediate_ocsp_hex,
    );
    const now = 1_790_821_380;

    const parsed_root = try @import("certificate.zig").parse(&root);
    const parsed_intermediate = try @import("certificate.zig").parse(
        &intermediate,
    );
    const parsed_leaf = try @import("certificate.zig").parse(&leaf);
    try parsed_intermediate.verify(parsed_root, now);
    try parsed_leaf.verify(parsed_intermediate, now);

    try std.testing.expectEqual(
        @import("ocsp.zig").Status.good,
        try @import("ocsp.zig").verify(
            &leaf_ocsp,
            &leaf,
            &intermediate,
            now,
            .{},
        ),
    );
    try std.testing.expectEqual(
        @import("ocsp.zig").Status.good,
        try @import("ocsp.zig").verify(
            &intermediate_ocsp,
            &intermediate,
            &root,
            now,
            .{},
        ),
    );

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .if_present,
    };

    const all_responses = [_]?[]const u8{ &leaf_ocsp, &intermediate_ocsp };
    try verifier.verify(.{
        .server_name = "multi-staple.localhost",
        .chain = &.{ &leaf, &intermediate },
        .ocsp_response = &leaf_ocsp,
        .ocsp_responses = &all_responses,
    });

    const leaf_only = [_]?[]const u8{ &leaf_ocsp, null };
    try verifier.verify(.{
        .server_name = "multi-staple.localhost",
        .chain = &.{ &leaf, &intermediate },
        .ocsp_responses = &leaf_only,
    });

    const missing_leaf = [_]?[]const u8{ null, &intermediate_ocsp };
    try std.testing.expectError(
        error.CertificateOcspResponseRequired,
        verifier.verify(.{
            .server_name = "multi-staple.localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_responses = &missing_leaf,
        }),
    );

    const swapped = [_]?[]const u8{ &intermediate_ocsp, &leaf_ocsp };
    try std.testing.expectError(
        error.CertificateStatusNotFound,
        verifier.verify(.{
            .server_name = "multi-staple.localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_responses = &swapped,
        }),
    );

    var tampered_intermediate = intermediate_ocsp;
    tampered_intermediate[tampered_intermediate.len - 1] ^= 1;
    const tampered = [_]?[]const u8{ &leaf_ocsp, &tampered_intermediate };
    try std.testing.expectError(
        error.InvalidOcspSignature,
        verifier.verify(.{
            .server_name = "multi-staple.localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_responses = &tampered,
        }),
    );
}

test "TLS 1.3 multi-stapling validates RSA leaf and intermediate staples" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.rsa_multi_staple_root_hex);
    const intermediate = decodeHex(
        path_vectors.rsa_multi_staple_intermediate_hex,
    );
    const leaf = decodeHex(path_vectors.rsa_multi_staple_leaf_hex);
    const leaf_ocsp = decodeHex(path_vectors.rsa_multi_staple_leaf_ocsp_hex);
    const intermediate_ocsp = decodeHex(
        path_vectors.rsa_multi_staple_intermediate_ocsp_hex,
    );
    const now = 1_790_821_380;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .if_present,
    };

    const responses = [_]?[]const u8{ &leaf_ocsp, &intermediate_ocsp };
    try verifier.verify(.{
        .server_name = "multi-staple.localhost",
        .chain = &.{ &leaf, &intermediate },
        .ocsp_responses = &responses,
    });

    var tampered_intermediate = intermediate_ocsp;
    tampered_intermediate[tampered_intermediate.len - 1] ^= 1;
    const tampered = [_]?[]const u8{ &leaf_ocsp, &tampered_intermediate };
    try std.testing.expectError(
        error.InvalidOcspSignature,
        verifier.verify(.{
            .server_name = "multi-staple.localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_responses = &tampered,
        }),
    );
}

test "bundle trust accepts an authorized delegated OCSP responder" {
    const allocator = std.testing.allocator;
    const issuer = decodeHex(path_vectors.delegated_ocsp_ca_hex);
    const leaf = decodeHex(path_vectors.delegated_ocsp_leaf_hex);
    const unknown_leaf = decodeHex(
        path_vectors.delegated_ocsp_unknown_leaf_hex,
    );
    const good = decodeHex(path_vectors.delegated_ocsp_good_hex);
    const unknown = decodeHex(path_vectors.delegated_ocsp_unknown_hex);
    const now = 1_790_664_300;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &issuer);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .require,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
        .ocsp_response = &good,
    });
    try std.testing.expectError(
        error.CertificateOcspStatusUnknown,
        verifier.verify(.{
            .server_name = "unknown.localhost",
            .chain = &.{&unknown_leaf},
            .ocsp_response = &unknown,
        }),
    );
}

test "bundle verifier builds an unordered path and backtracks decoys" {
    const root = decodeHex(path_vectors.root_hex);
    const intermediate = decodeHex(path_vectors.intermediate_hex);
    const decoy = decodeHex(path_vectors.decoy_hex);
    const leaf = decodeHex(path_vectors.leaf_hex);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &root);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };

    // The decoy has the same Subject as the valid intermediate but another
    // key. Root and intermediates are deliberately unordered.
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ &leaf, &decoy, &root, &intermediate },
    });
    const leaf_usage = try trust.testing.certificateUsage(&leaf);
    const intermediate_usage = try trust.testing.certificateUsage(
        &intermediate,
    );
    const decoy_usage = try trust.testing.certificateUsage(&decoy);
    try std.testing.expectEqualSlices(
        u8,
        leaf_usage.authority_key_identifier.?,
        intermediate_usage.subject_key_identifier.?,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        leaf_usage.authority_key_identifier.?,
        decoy_usage.subject_key_identifier.?,
    ));
    // One check selects the AKI/SKI-matched intermediate and the second reaches
    // the root. Trying the same-subject decoy first would exceed this budget.
    try (trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
        .path_limits = .{ .max_candidate_checks = 2 },
    }).verify(.{
        .server_name = "localhost",
        .chain = &.{ &leaf, &decoy, &intermediate },
    });
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &decoy },
        }),
    );

    try std.testing.expectError(
        error.CertificatePathSearchLimitExceeded,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 1_900_000_000,
            .path_limits = .{ .max_candidate_checks = 1 },
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &decoy, &intermediate },
        }),
    );
    try std.testing.expectError(
        error.CertificatePathTooDeep,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 1_900_000_000,
            .path_limits = .{ .max_depth = 1 },
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
        }),
    );
    try std.testing.expectError(
        error.InvalidCertificatePathLimits,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 1_900_000_000,
            .path_limits = .{ .max_depth = 0 },
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
        }),
    );
    var oversized_chain: [17][]const u8 = @splat(&decoy);
    oversized_chain[0] = &leaf;
    try std.testing.expectError(
        error.CertificatePathTooManyCertificates,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &oversized_chain,
        }),
    );
}

test "bundle verifier routes AKI issuer and serial before a same-name decoy" {
    const root = decodeHex(path_vectors.serial_root_hex);
    const intermediate = decodeHex(path_vectors.serial_intermediate_hex);
    const decoy = decodeHex(path_vectors.serial_decoy_hex);
    const leaf = decodeHex(path_vectors.serial_leaf_hex);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &root);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);

    const leaf_usage = try trust.testing.certificateUsage(&leaf);
    try std.testing.expect(leaf_usage.authority_key_identifier == null);
    const leaf_authority = (try trust.testing.certificateAuthorityKeyIdentifier(
        &leaf,
    )).?;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x10, 0x01 },
        leaf_authority.authority_cert_serial_number.?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x10, 0x01 },
        try trust.testing.certificateSerialNumber(&intermediate),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x10, 0x02 },
        try trust.testing.certificateSerialNumber(&decoy),
    );

    // The matching intermediate plus the root consume the whole budget. A
    // linear scan that tries the decoy first would require a third check.
    try (trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
        .path_limits = .{ .max_candidate_checks = 2 },
    }).verify(.{
        .server_name = "serial.localhost",
        .chain = &.{ &leaf, &decoy, &intermediate },
    });
}

test "bundle verifier backtracks across cross-signed intermediates" {
    const leaf = decodeHex(path_vectors.leaf_hex);
    const original_intermediate = decodeHex(path_vectors.intermediate_hex);
    const cross_intermediate = decodeHex(path_vectors.cross_intermediate_hex);
    const alternate_root = decodeHex(path_vectors.alternate_root_hex);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &alternate_root);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);

    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ &leaf, &original_intermediate, &cross_intermediate },
    });
    try std.testing.expectError(
        error.CertificatePathSearchLimitExceeded,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 1_900_000_000,
            .path_limits = .{ .max_candidate_checks = 2 },
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &original_intermediate, &cross_intermediate },
        }),
    );
}

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

test "bundle verifier accepts RSA-PSS signed leaves and intermediates" {
    const root = @embedFile("testdata/rsa-pss-crl-ca.der");
    const pss_leaf = @embedFile("testdata/rsa-pss-leaf.der");
    const pss_intermediate = @embedFile("testdata/rsa-pss-intermediate.der");
    const intermediate_leaf = @embedFile(
        "testdata/rsa-pss-intermediate-leaf.der",
    );
    const now = 1_800_000_000;

    try std.testing.expectError(
        error.CertificateHasUnrecognizedObjectId,
        std.crypto.Certificate.parse(.{ .buffer = pss_leaf, .index = 0 }),
    );
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, root);
    try bundle.parseCert(std.testing.allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{pss_leaf},
    });
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ intermediate_leaf, pss_intermediate },
    });
    try std.testing.expectError(
        error.CertificateHostMismatch,
        verifier.verify(.{
            .server_name = "not-localhost.example",
            .chain = &.{pss_leaf},
        }),
    );

    const tampered = try std.testing.allocator.dupe(u8, pss_leaf);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{tampered},
        }),
    );

    const wrong_salt = try std.testing.allocator.dupe(u8, pss_leaf);
    defer std.testing.allocator.free(wrong_salt);
    const encoded_salt_length = [_]u8{ 0xa2, 0x03, 0x02, 0x01, 0x30 };
    var search_from: usize = 0;
    var replacements: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        wrong_salt,
        search_from,
        &encoded_salt_length,
    )) |offset| {
        wrong_salt[offset + encoded_salt_length.len - 1] = 47;
        search_from = offset + encoded_salt_length.len;
        replacements += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), replacements);
    try std.testing.expectError(
        error.UnsupportedSignatureAlgorithm,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{wrong_salt},
        }),
    );
}

test "bundle verifier enforces constrained RSA-PSS issuer parameters" {
    const root = @embedFile("testdata/rsa-pss-crl-ca.der");
    const constrained_leaf = @embedFile(
        "testdata/rsa-pss-constrained-leaf.der",
    );
    const constrained_intermediate = @embedFile(
        "testdata/rsa-pss-constrained-intermediate.der",
    );
    const child = @embedFile("testdata/rsa-pss-constrained-child.der");
    const now = 1_800_000_000;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, root);
    try bundle.parseCert(std.testing.allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{constrained_leaf},
    });
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ child, constrained_intermediate },
    });

    const excessive_salt = try std.testing.allocator.dupe(
        u8,
        constrained_intermediate,
    );
    defer std.testing.allocator.free(excessive_salt);
    const encoded_salt = [_]u8{ 0xa2, 0x03, 0x02, 0x01, 0x20 };
    const salt_at = std.mem.indexOf(u8, excessive_salt, &encoded_salt) orelse
        return error.TestUnexpectedResult;
    excessive_salt[salt_at + encoded_salt.len - 1] = 64;
    try std.testing.expectError(
        error.CertificateSignatureAlgorithmUnsupported,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ child, excessive_salt },
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

test "client trust verifier enforces authenticated CRL status" {
    const ca = @embedFile("testdata/ed25519-crl-ca.der");
    const good = @embedFile("testdata/ed25519-crl-good.der");
    const revoked = @embedFile("testdata/ed25519-crl-revoked.der");
    const encoded_crl = @embedFile("testdata/ed25519.crl.der");
    const now = 1_790_419_000;
    const list = try crl.parseAndVerify(encoded_crl, ca, now);
    const set = crl.VerifiedSet{ .lists = &.{list} };

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, ca);
    try bundle.parseCert(std.testing.allocator, 0, now);
    const verifier = trust.ClientCertificateBundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .revocation = set.policy(true),
    };
    try verifier.verify(.{ .server_name = null, .chain = &.{good} });
    try std.testing.expectError(
        error.CertificateRevoked,
        verifier.verify(.{ .server_name = null, .chain = &.{revoked} }),
    );

    const empty = crl.VerifiedSet{ .lists = &.{} };
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (trust.ClientCertificateBundleVerifier{
            .bundle = &bundle,
            .now_seconds = now,
            .revocation = empty.policy(true),
        }).verify(.{ .server_name = null, .chain = &.{good} }),
    );
    try (trust.ClientCertificateBundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .revocation = empty.policy(false),
    }).verify(.{ .server_name = null, .chain = &.{good} });
}

test "prepared Ed25519 verifier authenticates a certificate" {
    const ca = @embedFile("testdata/ed25519-crl-ca.der");
    const good = @embedFile("testdata/ed25519-crl-good.der");
    const now = 1_790_419_000;
    const parsed_ca = try std.crypto.Certificate.parse(.{
        .buffer = ca,
        .index = 0,
    });
    const parsed_good = try std.crypto.Certificate.parse(.{
        .buffer = good,
        .index = 0,
    });
    const public_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(
        parsed_ca.pubKey()[0..std.crypto.sign.Ed25519.PublicKey.encoded_length].*,
    );
    const verifier = try ed25519.PreparedVerifier.init(public_key);
    try certificate_compat.verifySignatureAndValidityWithEd25519(
        parsed_good,
        null,
        parsed_ca,
        now,
        &verifier,
    );
}

test "prepared P-256 verifier authenticates a certificate" {
    const root = decodeHex(path_vectors.root_hex);
    const intermediate = decodeHex(path_vectors.intermediate_hex);
    const now = 1_790_663_000;
    const parsed_root = try std.crypto.Certificate.parse(.{
        .buffer = &root,
        .index = 0,
    });
    const parsed_intermediate = try std.crypto.Certificate.parse(.{
        .buffer = &intermediate,
        .index = 0,
    });
    const public_key = try std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey
        .fromSec1(parsed_root.pubKey());
    const verifier = try p256.PreparedVerifier.init(public_key.p);
    try certificate_compat.verifySignatureAndValidityWithP256(
        parsed_intermediate,
        null,
        parsed_root,
        now,
        &verifier,
    );
}

test "CRL issuer matching uses RFC 5280 distinguished-name equality" {
    const utf8_issuer = decodeHex(path_vectors.crl_dn_issuer_utf8_hex);
    const printable_issuer = decodeHex(
        path_vectors.crl_dn_issuer_printable_hex,
    );
    const wrong_issuer = decodeHex(path_vectors.crl_dn_wrong_hex);
    const leaf = decodeHex(path_vectors.crl_dn_leaf_hex);
    const encoded_crl = decodeHex(path_vectors.crl_dn_crl_hex);
    const now = 1_790_842_300;

    const utf8_list = try crl.parseAndVerify(
        &encoded_crl,
        &utf8_issuer,
        now,
    );
    try std.testing.expect(!(try utf8_list.isRevoked(&leaf)));
    const set = crl.VerifiedSet{ .lists = &.{utf8_list} };
    try set.policy(true).verify(&leaf, &printable_issuer);

    const printable_list = try crl.parseAndVerify(
        &encoded_crl,
        &printable_issuer,
        now,
    );
    try std.testing.expect(!(try printable_list.isRevoked(&leaf)));
    try std.testing.expectError(
        error.InvalidCrlSignature,
        crl.parseAndVerify(&encoded_crl, &wrong_issuer, now),
    );
}

test "RFC 5280 delta CRL overrides a complete base CRL" {
    const ca = decodeHex(path_vectors.delta_crl_ca_hex);
    const held = decodeHex(path_vectors.delta_crl_held_hex);
    const added = decodeHex(path_vectors.delta_crl_added_hex);
    const clean = decodeHex(path_vectors.delta_crl_clean_hex);
    const base_der = decodeHex(path_vectors.delta_crl_base_hex);
    const delta_der = decodeHex(path_vectors.delta_crl_delta_hex);
    const indirect_der = decodeHex(path_vectors.delta_crl_indirect_hex);
    const indirect_target = decodeHex(
        path_vectors.delta_crl_indirect_target_hex,
    );
    const indirect_authorized_der = decodeHex(
        path_vectors.delta_crl_indirect_authorized_hex,
    );
    const delegated_signer = decodeHex(path_vectors.indirect_crl_delegate_hex);
    const delegated_target = decodeHex(
        path_vectors.indirect_crl_delegated_target_hex,
    );
    const delegated_crl_der = decodeHex(
        path_vectors.indirect_crl_delegate_crl_hex,
    );
    const now = 1_790_844_200;

    const base = try crl.parseAndVerify(&base_der, &ca, now);
    const delta = try crl.parseAndVerify(&delta_der, &ca, now);
    const indirect = try crl.parseAndVerify(&indirect_der, &ca, now);
    try std.testing.expect(!base.isDelta());
    try std.testing.expect(delta.isDelta());
    try std.testing.expect(indirect.isIndirect());
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x00 }, base.crl_number.?);
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x00 }, delta.delta_base_number.?);
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x01 }, delta.crl_number.?);
    try std.testing.expect(try indirect.isRevoked(&held));
    try std.testing.expect(try base.isRevoked(&held));
    try std.testing.expect(!(try base.isRevoked(&added)));
    try std.testing.expectError(
        error.InvalidDeltaCrl,
        delta.isRevoked(&added),
    );

    const combined = try crl.CombinedList.init(base, delta);
    try std.testing.expect(!(try combined.isRevoked(&held)));
    try std.testing.expect(try combined.isRevoked(&added));
    try std.testing.expect(!(try combined.isRevoked(&clean)));

    const set = crl.VerifiedSet{
        .lists = &.{base},
        .combined_lists = &.{combined},
    };
    try set.policy(true).verify(&held, &ca);
    try std.testing.expectError(
        error.CertificateRevoked,
        set.policy(true).verify(&added, &ca),
    );
    try set.policy(true).verify(&clean, &ca);

    var wrong_base = base;
    wrong_base.crl_number = &.{ 0x0f, 0xff };
    try std.testing.expectError(
        error.InvalidDeltaCrl,
        crl.CombinedList.init(wrong_base, delta),
    );
    var mismatched_scope = delta;
    mismatched_scope.issuing_distribution_point = indirect.issuing_distribution_point;
    try std.testing.expectError(
        error.CrlScopeMismatch,
        crl.CombinedList.init(base, mismatched_scope),
    );
    var wrong_signer = delta;
    wrong_signer.issuer_certificate_der = &held;
    try std.testing.expectError(
        error.CrlScopeMismatch,
        crl.CombinedList.init(base, wrong_signer),
    );
    var delta_without_indicator = delta;
    delta_without_indicator.delta_base_number = null;
    try std.testing.expectError(
        error.InvalidCrl,
        delta_without_indicator.isRevoked(&held),
    );

    const indirect_set = crl.VerifiedSet{ .lists = &.{indirect} };
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        indirect_set.policy(true).verify(&held, &ca),
    );

    const indirect_authorized = try crl.parseAndVerify(
        &indirect_authorized_der,
        &ca,
        now,
    );
    const authorization = try crl.AuthorizedIndirectList.init(
        indirect_authorized,
        &ca,
        now,
    );
    const authorized_set = crl.VerifiedSet{
        .lists = &.{},
        .indirect_lists = &.{authorization},
    };
    try std.testing.expectError(
        error.CertificateRevoked,
        authorized_set.policy(true).verify(&indirect_target, &ca),
    );
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        authorized_set.policy(true).verify(&clean, &ca),
    );

    const delegated_crl = try crl.parseAndVerify(
        &delegated_crl_der,
        &delegated_signer,
        now,
    );
    const delegated_authorization = try crl.AuthorizedIndirectList.init(
        delegated_crl,
        &ca,
        now,
    );
    const delegated_set = crl.VerifiedSet{
        .lists = &.{},
        .indirect_lists = &.{delegated_authorization},
    };
    try delegated_set.policy(true).verify(&delegated_target, &ca);
    var partial_delegated_crl = delegated_crl;
    var partial_point = partial_delegated_crl.issuing_distribution_point.?;
    partial_point.only_some_reasons = &.{ 0x07, 0x80 };
    partial_delegated_crl.issuing_distribution_point = partial_point;
    const partial_authorization = try crl.AuthorizedIndirectList.init(
        partial_delegated_crl,
        &ca,
        now,
    );
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (crl.VerifiedSet{
            .lists = &.{},
            .indirect_lists = &.{partial_authorization},
        }).policy(true).verify(&delegated_target, &ca),
    );
    var delegated_with_issuer_entry = delegated_crl;
    delegated_with_issuer_entry.revoked_entries =
        "\x30\x4f\x02\x02\x02\x58\x17\x0d261001084142Z" ++
        "\x30\x3a" ++
        "\x30\x0a\x06\x03\x55\x1d\x15\x04\x03\x0a\x01\x05" ++
        "\x30\x2c\x06\x03\x55\x1d\x1d\x01\x01\xff\x04\x22" ++
        "\x30\x20\xa4\x1e\x30\x1c\x31\x1a\x30\x18" ++
        "\x06\x03\x55\x04\x03\x0c\x11Vail Delta CRL CA";
    const revoked_authorization = try crl.AuthorizedIndirectList.init(
        delegated_with_issuer_entry,
        &ca,
        now,
    );
    try std.testing.expectError(
        error.CertificateRevoked,
        (crl.VerifiedSet{
            .lists = &.{},
            .indirect_lists = &.{revoked_authorization},
        }).policy(true).verify(&delegated_target, &ca),
    );
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (crl.VerifiedSet{ .lists = &.{delegated_crl} })
            .policy(true).verify(&delegated_target, &ca),
    );
    try std.testing.expectError(
        error.InvalidIssuer,
        crl.AuthorizedIndirectList.init(delegated_crl, &held, now),
    );
}

test "RFC 5280 complementary CRL reason partitions aggregate" {
    const ca = decodeHex(path_vectors.reason_crl_ca_hex);
    const clean = decodeHex(path_vectors.reason_crl_clean_hex);
    const one_der = decodeHex(path_vectors.reason_crl_one_hex);
    const two_der = decodeHex(path_vectors.reason_crl_two_hex);
    const now = 1_790_845_500;
    const one = try crl.parseAndVerify(&one_der, &ca, now);
    const two = try crl.parseAndVerify(&two_der, &ca, now);

    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (crl.VerifiedSet{ .lists = &.{one} })
            .policy(true).verify(&clean, &ca),
    );
    try (crl.VerifiedSet{ .lists = &.{ one, two } })
        .policy(true).verify(&clean, &ca);
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (crl.VerifiedSet{ .lists = &.{ one, one } })
            .policy(true).verify(&clean, &ca),
    );
}

test "RFC 5280 indirect base and delta CRLs combine after authorization" {
    const root = decodeHex(path_vectors.indirect_delta_root_hex);
    const delegate = decodeHex(path_vectors.indirect_delta_delegate_hex);
    const target = decodeHex(path_vectors.indirect_delta_target_hex);
    const base_der = decodeHex(path_vectors.indirect_delta_base_hex);
    const delta_der = decodeHex(path_vectors.indirect_delta_delta_hex);
    const now = 1_790_846_900;

    const base = try crl.parseAndVerify(&base_der, &delegate, now);
    const delta = try crl.parseAndVerify(&delta_der, &delegate, now);
    const combined = try crl.CombinedList.init(base, delta);
    const authorized = try crl.AuthorizedIndirectCombinedList.init(
        combined,
        &root,
        now,
    );
    try (crl.VerifiedSet{
        .lists = &.{},
        .indirect_combined_lists = &.{authorized},
    }).policy(true).verify(&target, &root);

    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (crl.VerifiedSet{
            .lists = &.{},
            .combined_lists = &.{combined},
        }).policy(true).verify(&target, &root),
    );
    var wrong_scope = delta;
    wrong_scope.issuing_distribution_point = null;
    try std.testing.expectError(
        error.CrlScopeMismatch,
        crl.CombinedList.init(base, wrong_scope),
    );
}

test "indirect delta CRL signer chain terminates at certificate issuer" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.multihop_crl_root_hex);
    const intermediate = decodeHex(path_vectors.multihop_crl_intermediate_hex);
    const signer = decodeHex(path_vectors.multihop_crl_signer_hex);
    const target = decodeHex(path_vectors.multihop_crl_target_hex);
    const target_ca = decodeHex(path_vectors.multihop_crl_target_ca_hex);
    const sibling_target = decodeHex(
        path_vectors.multihop_crl_sibling_target_hex,
    );
    const base_der = decodeHex(path_vectors.multihop_crl_base_hex);
    const delta_der = decodeHex(path_vectors.multihop_crl_delta_hex);
    const now = 1_790_848_300;

    const base = try crl.parseAndVerify(&base_der, &signer, now);
    const delta = try crl.parseAndVerify(&delta_der, &signer, now);
    const combined = try crl.CombinedList.init(base, delta);
    try std.testing.expectError(
        error.InvalidIssuer,
        crl.AuthorizedIndirectCombinedList.init(combined, &root, now),
    );
    const authorized = try crl.AuthorizedIndirectCombinedList.initWithSignerChain(
        allocator,
        combined,
        &root,
        &.{ &signer, &intermediate },
        now,
        .{},
        .{},
    );
    try (crl.VerifiedSet{
        .lists = &.{},
        .indirect_combined_lists = &.{authorized},
    }).policy(true).verify(&target, &root);
    try std.testing.expectError(
        error.InvalidIssuer,
        crl.AuthorizedIndirectCombinedList.initWithSignerChain(
            allocator,
            combined,
            &root,
            &.{&signer},
            now,
            .{},
            .{},
        ),
    );

    var sibling_anchor_bundle: std.crypto.Certificate.Bundle = .empty;
    defer sibling_anchor_bundle.deinit(allocator);
    try sibling_anchor_bundle.bytes.appendSlice(allocator, &root);
    try sibling_anchor_bundle.parseCert(allocator, 0, now);
    try (trust.CertificateAuthorityBundleVerifier{
        .bundle = &sibling_anchor_bundle,
        .now_seconds = now,
    }).verify(&.{&target_ca});
    const empty_status = crl.VerifiedSet{ .lists = &.{} };
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (trust.CrlSignerBundleVerifier{
            .bundle = &sibling_anchor_bundle,
            .now_seconds = now,
            .revocation = empty_status.policy(true),
        }).verify(&.{ &signer, &intermediate }),
    );

    const sibling_authorized =
        try crl.AuthorizedIndirectCombinedList.initWithTrustAnchor(
            allocator,
            combined,
            &target_ca,
            &.{&target_ca},
            &.{ &signer, &intermediate },
            &root,
            now,
            .{},
            .{},
        );
    try (crl.VerifiedSet{
        .lists = &.{},
        .indirect_combined_lists = &.{sibling_authorized},
    }).policy(true).verify(&sibling_target, &target_ca);
    try std.testing.expectError(
        error.InvalidIssuer,
        crl.AuthorizedIndirectCombinedList.initWithTrustAnchor(
            allocator,
            combined,
            &target_ca,
            &.{&intermediate},
            &.{ &signer, &intermediate },
            &root,
            now,
            .{},
            .{},
        ),
    );
    try std.testing.expectError(
        error.InvalidIssuer,
        crl.AuthorizedIndirectCombinedList.initWithTrustAnchorOptions(
            allocator,
            combined,
            &target_ca,
            &.{&target_ca},
            &.{ &signer, &intermediate },
            &root,
            now,
            .{ .signer_revocation = empty_status.policy(true) },
        ),
    );
}

test "freshestCRL automatically selects the newest compatible delta" {
    const ca = decodeHex(path_vectors.freshest_crl_ca_hex);
    const held = decodeHex(path_vectors.freshest_crl_held_hex);
    const clean = decodeHex(path_vectors.freshest_crl_clean_hex);
    const base_der = decodeHex(path_vectors.freshest_crl_base_hex);
    const old_der = decodeHex(path_vectors.freshest_crl_delta_old_hex);
    const new_der = decodeHex(path_vectors.freshest_crl_delta_new_hex);
    const now = 1_790_848_980;
    const base = try crl.parseAndVerify(&base_der, &ca, now);
    const old = try crl.parseAndVerify(&old_der, &ca, now);
    const newest = try crl.parseAndVerify(&new_der, &ca, now);
    try std.testing.expect(base.freshest_crl != null);
    var freshest_urls = try crl.listFreshestCrlUrls(base);
    try std.testing.expectEqualStrings(
        "http://crl.example.test/latest.delta.crl",
        (try freshest_urls.next()).?,
    );
    try std.testing.expect(try freshest_urls.next() == null);

    try (crl.VerifiedSet{ .lists = &.{ base, old } })
        .policy(true).verify(&held, &ca);
    inline for (.{
        [_]crl.List{ base, old, newest },
        [_]crl.List{ base, newest, old },
    }) |lists| {
        try std.testing.expectError(
            error.CertificateRevoked,
            (crl.VerifiedSet{ .lists = &lists })
                .policy(true).verify(&held, &ca),
        );
        try (crl.VerifiedSet{ .lists = &lists })
            .policy(true).verify(&clean, &ca);
    }

    var base_without_freshest = base;
    base_without_freshest.freshest_crl = null;
    try std.testing.expectError(
        error.CertificateRevoked,
        (crl.VerifiedSet{ .lists = &.{ base_without_freshest, old } })
            .policy(true).verify(&held, &ca),
    );
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (crl.VerifiedSet{ .lists = &.{old} })
            .policy(true).verify(&clean, &ca),
    );

    const FetchContext = struct {
        old: []const u8,
        newest: []const u8,
        calls: usize = 0,

        fn fetch(
            context_ptr: ?*anyopaque,
            uri: []const u8,
            output: []u8,
        ) anyerror!?usize {
            const self: *@This() = @ptrCast(@alignCast(context_ptr.?));
            self.calls += 1;
            const source = if (std.mem.eql(
                u8,
                uri,
                "https://old.test/delta.crl",
            )) self.old else if (std.mem.eql(
                u8,
                uri,
                "https://new.test/delta.crl",
            )) self.newest else return null;
            if (source.len > output.len) return error.BufferTooSmall;
            @memcpy(output[0..source.len], source);
            return source.len;
        }
    };
    var fetched_base = base;
    fetched_base.freshest_crl =
        "\x30\x60\x30\x3c\xa0\x3a\xa0\x38" ++
        "\x86\x1ahttps://old.test/delta.crl" ++
        "\x86\x1ahttps://old.test/delta.crl" ++
        "\x30\x20\xa0\x1e\xa0\x1c" ++
        "\x86\x1ahttps://new.test/delta.crl";
    var context = FetchContext{ .old = &old_der, .newest = &new_der };
    var best_buffer: [1024]u8 = undefined;
    var scratch_buffer: [1024]u8 = undefined;
    const fetched = (try crl.fetchLatestDelta(
        &best_buffer,
        &scratch_buffer,
        fetched_base,
        &ca,
        now,
        try crl.listFreshestCrlUrls(fetched_base),
        .{ .context = &context, .fetch = FetchContext.fetch },
        .{},
    )).?;
    try std.testing.expectEqual(@as(usize, 2), context.calls);
    try std.testing.expect(try (try crl.CombinedList.init(
        fetched_base,
        fetched.list,
    )).isRevoked(&held));

    const ConditionalContext = struct {
        der: []const u8,
        mode: enum { fetched, not_modified, failing } = .fetched,
        calls: usize = 0,
        saw_validators: bool = false,

        fn fetch(
            context_ptr: ?*anyopaque,
            request: crl.ConditionalRequest,
            output: []u8,
        ) anyerror!crl.ConditionalFetchResult {
            const self: *@This() = @ptrCast(@alignCast(context_ptr.?));
            self.calls += 1;
            self.saw_validators = request.if_none_match != null and
                request.if_modified_since != null;
            return switch (self.mode) {
                .failing => error.NetworkUnavailable,
                .not_modified => .not_modified,
                .fetched => blk: {
                    if (self.der.len > output.len) return error.BufferTooSmall;
                    @memcpy(output[0..self.der.len], self.der);
                    break :blk .{ .fetched = .{
                        .len = self.der.len,
                        .etag = "\"delta-v2\"",
                        .last_modified = "Thu, 01 Oct 2026 10:02:00 GMT",
                    } };
                },
            };
        }
    };
    var cache_body: [1024]u8 = undefined;
    var cache_uri: [128]u8 = undefined;
    var cache_etag: [64]u8 = undefined;
    var cache_modified: [64]u8 = undefined;
    var refresh_scratch: [1024]u8 = undefined;
    var cache = crl.DeltaCache.init(
        &cache_body,
        &cache_uri,
        &cache_etag,
        &cache_modified,
    );
    var conditional = ConditionalContext{ .der = &new_der };
    const delta_uri = "https://new.test/delta.crl";
    switch (try crl.refreshDeltaCache(
        &cache,
        &refresh_scratch,
        base,
        &ca,
        now,
        delta_uri,
        .{ .context = &conditional, .fetch = ConditionalContext.fetch },
        .{},
    )) {
        .updated => |updated| try std.testing.expect(try (try crl.CombinedList.init(
            base,
            updated.list,
        )).isRevoked(&held)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings(delta_uri, cache.sourceUri().?);
    try std.testing.expectEqualStrings("\"delta-v2\"", cache.etag().?);
    conditional.mode = .not_modified;
    switch (try crl.refreshDeltaCache(
        &cache,
        &refresh_scratch,
        base,
        &ca,
        now + 1,
        delta_uri,
        .{ .context = &conditional, .fetch = ConditionalContext.fetch },
        .{},
    )) {
        .not_modified => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(conditional.saw_validators);
    conditional.mode = .failing;
    try std.testing.expectError(
        error.NetworkUnavailable,
        crl.refreshDeltaCache(
            &cache,
            &refresh_scratch,
            base,
            &ca,
            now + 2,
            delta_uri,
            .{ .context = &conditional, .fetch = ConditionalContext.fetch },
            .{},
        ),
    );
    const calls_after_failure = conditional.calls;
    switch (try crl.refreshDeltaCache(
        &cache,
        &refresh_scratch,
        base,
        &ca,
        now + 2,
        delta_uri,
        .{ .context = &conditional, .fetch = ConditionalContext.fetch },
        .{},
    )) {
        .deferred => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(calls_after_failure, conditional.calls);
    try std.testing.expectEqualSlices(u8, &new_der, cache.encoded().?);
    conditional.mode = .fetched;
    conditional.der = "not a CRL";
    try std.testing.expectError(
        error.InvalidCrl,
        crl.refreshDeltaCache(
            &cache,
            &refresh_scratch,
            base,
            &ca,
            now + 3,
            delta_uri,
            .{ .context = &conditional, .fetch = ConditionalContext.fetch },
            .{},
        ),
    );
    try std.testing.expectEqualSlices(u8, &new_der, cache.encoded().?);
}

test "CRL distribution points support nameRelativeToCRLIssuer" {
    const ca = decodeHex(path_vectors.relative_crl_ca_hex);
    const leaf = decodeHex(path_vectors.relative_crl_leaf_hex);
    const encoded_crl = decodeHex(path_vectors.relative_crl_crl_hex);
    const now = 1_790_849_600;
    const list = try crl.parseAndVerify(&encoded_crl, &ca, now);
    try std.testing.expect(list.issuing_distribution_point.?.distribution_point != null);
    try (crl.VerifiedSet{ .lists = &.{list} })
        .policy(true).verify(&leaf, &ca);

    var wrong_scope = list;
    var wrong_point = wrong_scope.issuing_distribution_point.?;
    wrong_point.distribution_point =
        "\xa1\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03bad";
    wrong_scope.issuing_distribution_point = wrong_point;
    try std.testing.expectError(
        error.CertificateRevocationStatusUnavailable,
        (crl.VerifiedSet{ .lists = &.{wrong_scope} })
            .policy(true).verify(&leaf, &ca),
    );
}

test "CRLDP and Freshest CRL expose ordered absolute URI iterators" {
    const certificate = decodeHex(path_vectors.crl_uri_certificate_hex);
    var distribution_urls = try crl.distributionPointUrls(&certificate);
    try std.testing.expectEqualStrings(
        "http://crl.example.test/base.crl",
        (try distribution_urls.next()).?,
    );
    try std.testing.expectEqualStrings(
        "ldap://directory.example.test/base",
        (try distribution_urls.next()).?,
    );
    try std.testing.expect(try distribution_urls.next() == null);

    var freshest_urls = try crl.certificateFreshestCrlUrls(&certificate);
    try std.testing.expectEqualStrings(
        "https://crl.example.test/latest.delta.crl",
        (try freshest_urls.next()).?,
    );
    try std.testing.expect(try freshest_urls.next() == null);
}

test "client certificate trust anchors validate before listener setup" {
    const ca_der = @embedFile("testdata/ca.der");
    const leaf_der = @embedFile("testdata/server.der");
    try trust.validateClientCertificateAuthority(ca_der, 1_900_000_000);
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.validateClientCertificateAuthority(
            leaf_der,
            1_900_000_000,
        ),
    );
    try std.testing.expectError(
        error.CertificateNotYetValid,
        trust.validateClientCertificateAuthority(ca_der, 1),
    );
    try std.testing.expectError(
        error.CertificateExpired,
        trust.validateClientCertificateAuthority(ca_der, 3_000_000_000),
    );
}

test "client certificate paths enforce DNS and IP name constraints" {
    const root = decodeHex(path_vectors.client_constraints_root_hex);
    const intermediate = decodeHex(
        path_vectors.client_constraints_intermediate_hex,
    );
    const good = decodeHex(path_vectors.client_constraints_good_hex);
    const bad = decodeHex(path_vectors.client_constraints_bad_hex);
    const outside_intermediate = decodeHex(
        path_vectors.client_constraints_outside_intermediate_hex,
    );
    const outside_leaf = decodeHex(
        path_vectors.client_constraints_outside_leaf_hex,
    );
    const rollover = decodeHex(path_vectors.client_constraints_rollover_hex);
    const rollover_leaf = decodeHex(
        path_vectors.client_constraints_rollover_leaf_hex,
    );
    const now = 1_900_000_000;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &root);
    try bundle.parseCert(std.testing.allocator, 0, now);
    const verifier = trust.ClientCertificateBundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };

    try trust.validateClientCertificateAuthority(&root, now);
    // Name Constraints apply only to the chosen path: the deliberately
    // out-of-subtree certificate is presented here but is not selected.
    try (trust.ClientCertificateBundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .path_limits = .{ .max_candidate_checks = 2 },
    }).verify(.{
        .server_name = null,
        .chain = &.{ &good, &outside_intermediate, &intermediate },
    });
    try std.testing.expectError(
        error.CertificatePathSearchLimitExceeded,
        (trust.ClientCertificateBundleVerifier{
            .bundle = &bundle,
            .now_seconds = now,
            .path_limits = .{ .max_candidate_checks = 1 },
        }).verify(.{
            .server_name = null,
            .chain = &.{ &good, &outside_intermediate, &intermediate },
        }),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = null,
            .chain = &.{ &bad, &intermediate },
        }),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = null,
            .chain = &.{ &outside_leaf, &outside_intermediate },
        }),
    );
    try (trust.ClientCertificateBundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .path_limits = .{ .max_candidate_checks = 3 },
    }).verify(.{
        .server_name = null,
        .chain = &.{ &rollover_leaf, &rollover },
    });
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
    try std.testing.expectError(
        error.CertificateOcspIssuerUnavailable,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = 1_900_000_000,
            .stapled_ocsp = .if_present,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&same_subject_and_key},
            .ocsp_response = "unverifiable-without-an-issuer",
        }),
    );
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
    try std.testing.expect(ca.crl_sign);
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
    // A malformed presented candidate must not poison the shorter valid path
    // from the leaf directly to the configured trust anchor.
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ server_der, &invalid_ca },
    });
    var invalid_anchor_bundle: std.crypto.Certificate.Bundle = .empty;
    defer invalid_anchor_bundle.deinit(std.testing.allocator);
    try invalid_anchor_bundle.bytes.appendSlice(
        std.testing.allocator,
        &invalid_ca,
    );
    try invalid_anchor_bundle.parseCert(
        std.testing.allocator,
        0,
        1_900_000_000,
    );
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        (trust.BundleVerifier{
            .bundle = &invalid_anchor_bundle,
            .now_seconds = 1_900_000_000,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{server_der},
        }),
    );

    var unknown_critical_ca = ca_der.*;
    const basic_constraints_oid = std.mem.indexOf(
        u8,
        &unknown_critical_ca,
        &.{ 0x55, 0x1d, 0x13 },
    ) orelse return error.TestUnexpectedResult;
    unknown_critical_ca[basic_constraints_oid + 2] = 0x14;
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ server_der, &unknown_critical_ca },
    });

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

test "TLS Feature DER parsing is strict and preserves critical semantics" {
    const must_staple = try trust.testing.parseTlsFeatures(
        &.{ 0x30, 0x03, 0x02, 0x01, 0x05 },
    );
    try std.testing.expect(must_staple.status_request);
    try std.testing.expect(!must_staple.unsupported);

    const mixed = try trust.testing.parseTlsFeatures(
        &.{
            0x30, 0x09,
            0x02, 0x01,
            0x05, 0x02,
            0x01, 0x11,
            0x02, 0x01,
            0x00,
        },
    );
    try std.testing.expect(mixed.status_request);
    try std.testing.expect(mixed.unsupported);

    const large_unknown = try trust.testing.parseTlsFeatures(
        &.{ 0x30, 0x04, 0x02, 0x02, 0x00, 0x80 },
    );
    try std.testing.expect(!large_unknown.status_request);
    try std.testing.expect(large_unknown.unsupported);

    const invalid = [_][]const u8{
        &.{ 0x30, 0x00 },
        &.{ 0x30, 0x03, 0x02, 0x01, 0xff },
        &.{ 0x30, 0x04, 0x02, 0x02, 0x00, 0x05 },
        &.{ 0x30, 0x02, 0x02, 0x00 },
        &.{ 0x30, 0x03, 0x04, 0x01, 0x05 },
        &.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05 },
        &.{ 0x30, 0x81, 0x03, 0x02, 0x01, 0x05 },
        &.{ 0x30, 0x03, 0x02, 0x01, 0x05, 0x00 },
    };
    for (invalid) |encoded| {
        try std.testing.expectError(
            error.InvalidCertificateExtension,
            trust.testing.parseTlsFeatures(encoded),
        );
    }

    const leaf = decodeHex(path_vectors.must_staple_leaf_hex);
    var unknown_noncritical = leaf;
    const tls_feature_oid = &.{
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18,
    };
    const feature_offset = std.mem.indexOf(
        u8,
        &unknown_noncritical,
        tls_feature_oid,
    ) orelse return error.TestUnexpectedResult;
    unknown_noncritical[feature_offset + tls_feature_oid.len + 6] = 0x11;
    const noncritical_usage = try trust.testing.certificateUsage(
        &unknown_noncritical,
    );
    try std.testing.expect(!noncritical_usage.must_staple);
    try std.testing.expect(!noncritical_usage.unsupported_critical_extension);

    var unknown_critical = leaf;
    const original_feature_offset = std.mem.indexOf(
        u8,
        &unknown_critical,
        tls_feature_oid,
    ) orelse return error.TestUnexpectedResult;
    unknown_critical[original_feature_offset + tls_feature_oid.len - 1] = 0x19;
    const authority_key_identifier = &.{
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
        0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    };
    const authority_offset = std.mem.indexOf(
        u8,
        &unknown_critical,
        authority_key_identifier,
    ) orelse return error.TestUnexpectedResult;
    const critical_unknown_extension = [_]u8{
        0x30, 0x1f,
        0x06, 0x08,
        0x2b, 0x06,
        0x01, 0x05,
        0x05, 0x07,
        0x01, 0x18,
        0x01, 0x01,
        0xff, 0x04,
        0x10, 0x30,
        0x0e, 0x02,
        0x01, 0x11,
        0x02, 0x09,
        0x00, 0x80,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00,
    };
    @memcpy(
        unknown_critical[authority_offset..][0..critical_unknown_extension.len],
        &critical_unknown_extension,
    );
    const critical_usage = try trust.testing.certificateUsage(
        &unknown_critical,
    );
    try std.testing.expect(critical_usage.unsupported_critical_extension);
    try std.testing.expectError(
        error.InvalidCertificateUsage,
        trust.testing.validateLeafUsage(critical_usage),
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
    try std.testing.expect(!digital_signature.crl_sign);
    const key_cert_sign = try trust.testing.parseKeyUsage(
        &.{ 0x03, 0x02, 0x02, 0x04 },
    );
    try std.testing.expect(!key_cert_sign.digital_signature);
    try std.testing.expect(key_cert_sign.key_cert_sign);
    try std.testing.expect(!key_cert_sign.crl_sign);
}

test "RFC 8446 OID filters match key usage and extended key usage" {
    const client_certificate = @embedFile("testdata/ed25519-crl-good.der");
    const key_usage_oid = [_]u8{ 0x55, 0x1d, 0x0f };
    const extended_key_usage_oid = [_]u8{ 0x55, 0x1d, 0x25 };
    const unknown_oid = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x7f };

    try std.testing.expectEqual(
        trust.OidFilterMatch.match,
        try trust.matchOidFilter(
            client_certificate,
            &key_usage_oid,
            &.{ 0x03, 0x02, 0x07, 0x80 },
        ),
    );
    try std.testing.expectEqual(
        trust.OidFilterMatch.mismatch,
        try trust.matchOidFilter(
            client_certificate,
            &key_usage_oid,
            &.{ 0x03, 0x02, 0x02, 0x04 },
        ),
    );
    try std.testing.expectEqual(
        trust.OidFilterMatch.match,
        try trust.matchOidFilter(
            client_certificate,
            &extended_key_usage_oid,
            &.{
                0x30, 0x0a, 0x06, 0x08,
                0x2b, 0x06, 0x01, 0x05,
                0x05, 0x07, 0x03, 0x02,
            },
        ),
    );
    try std.testing.expectEqual(
        trust.OidFilterMatch.mismatch,
        try trust.matchOidFilter(
            client_certificate,
            &extended_key_usage_oid,
            &.{
                0x30, 0x0a, 0x06, 0x08,
                0x2b, 0x06, 0x01, 0x05,
                0x05, 0x07, 0x03, 0x01,
            },
        ),
    );
    try std.testing.expectEqual(
        trust.OidFilterMatch.match,
        try trust.matchOidFilter(client_certificate, &key_usage_oid, &.{}),
    );
    try std.testing.expectEqual(
        trust.OidFilterMatch.unrecognized,
        try trust.matchOidFilter(
            client_certificate,
            &unknown_oid,
            "opaque-value",
        ),
    );
    try std.testing.expectError(
        error.InvalidOidFilter,
        trust.validateOidFilter(&.{0x80}, &.{}),
    );
    try std.testing.expectError(
        error.InvalidOidFilter,
        trust.validateOidFilter(
            &extended_key_usage_oid,
            &.{ 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x25, 0x00 },
        ),
    );
}

test "AKI and SKI codecs are strict while routing remains compatible" {
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 2, 3 },
        try trust.testing.parseSubjectKeyIdentifier(
            &.{ 0x04, 0x03, 1, 2, 3 },
        ),
    );
    const key_identifier = try trust.testing.parseAuthorityKeyIdentifier(
        &.{ 0x30, 0x05, 0x80, 0x03, 1, 2, 3 },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 2, 3 },
        key_identifier.key_identifier.?,
    );
    const issuer_and_serial = try trust.testing.parseAuthorityKeyIdentifier(
        &.{
            0x30, 0x08,
            0xa1, 0x03,
            0x82, 0x01,
            'x',  0x82,
            0x01, 0x01,
        },
    );
    try std.testing.expect(issuer_and_serial.key_identifier == null);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x82, 0x01, 'x' },
        issuer_and_serial.authority_cert_issuer.?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{1},
        issuer_and_serial.authority_cert_serial_number.?,
    );
    const directory_issuer = try trust.testing.parseAuthorityKeyIdentifier(
        &.{
            0x30, 0x17,
            0xa1, 0x12,
            0xa4, 0x10,
            0x30, 0x0e,
            0x31, 0x0c,
            0x30, 0x0a,
            0x06, 0x03,
            0x55, 0x04,
            0x03, 0x0c,
            0x03, 'o',
            'n',  'e',
            0x82, 0x01,
            0x01,
        },
    );
    try std.testing.expectEqual(
        @as(?bool, true),
        try trust.testing.authorityIssuerMatches(
            directory_issuer.authority_cert_issuer.?,
            "\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03ONE",
        ),
    );
    try std.testing.expectEqual(
        @as(?bool, false),
        try trust.testing.authorityIssuerMatches(
            directory_issuer.authority_cert_issuer.?,
            "\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03two",
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.parseAuthorityKeyIdentifier(
            &.{ 0x30, 0x03, 0xa1, 0x01, 0x00 },
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.parseAuthorityKeyIdentifier(
            &.{
                0x30, 0x08,
                0xa1, 0x03,
                0xa4, 0x01,
                0x00, 0x82,
                0x01, 0x01,
            },
        ),
    );
    // dNSName is primitive; accepting its constructed form would make the
    // GeneralName CHOICE structurally ambiguous.
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.parseAuthorityKeyIdentifier(
            &.{
                0x30, 0x08,
                0xa1, 0x03,
                0xa2, 0x01,
                'x',  0x82,
                0x01, 0x01,
            },
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.parseAuthorityKeyIdentifier(
            &.{
                0x30, 0x0a,
                0x80, 0x03,
                1,    2,
                3,    0x80,
                0x03, 4,
                5,    6,
            },
        ),
    );
    try std.testing.expectEqual(
        @as(u2, 0),
        try trust.testing.issuerIdentityPriority(
            key_identifier,
            &.{ 1, 2, 3 },
            &.{},
            &.{},
        ),
    );
    try std.testing.expectEqual(
        @as(u2, 1),
        try trust.testing.issuerIdentityPriority(
            key_identifier,
            null,
            &.{},
            &.{},
        ),
    );
    try std.testing.expectEqual(
        @as(u2, 2),
        try trust.testing.issuerIdentityPriority(
            key_identifier,
            "other",
            &.{},
            &.{},
        ),
    );
    try std.testing.expectEqual(
        @as(u2, 0),
        try trust.testing.issuerIdentityPriority(
            directory_issuer,
            null,
            "\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03ONE",
            &.{1},
        ),
    );
    try std.testing.expectEqual(
        @as(u2, 2),
        try trust.testing.issuerIdentityPriority(
            directory_issuer,
            null,
            "\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03ONE",
            &.{2},
        ),
    );
    try std.testing.expectEqual(
        @as(u2, 2),
        try trust.testing.issuerIdentityPriority(
            directory_issuer,
            null,
            "\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03two",
            &.{1},
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{5},
        try trust.testing.certificateSerialNumber(
            &.{ 0x30, 0x08, 0x30, 0x06, 0xa0, 0x01, 0x00, 0x02, 0x01, 0x05 },
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.certificateSerialNumber(
            &.{ 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x80 },
        ),
    );
}

test "bundle verifier enforces permitted and excluded DNS constraints" {
    const constraints =
        "\x30\x26" ++
        "\xa0\x0f\x30\x0d\x82\x0bexample.com" ++
        "\xa1\x13\x30\x11\x82\x0fbad.example.com";
    try trust.testing.validateDnsNameConstraints(
        constraints,
        "api.example.com",
    );
    try trust.testing.validateDnsNameConstraints(
        constraints,
        "example.com",
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateDnsNameConstraints(
            constraints,
            "bad.example.com",
        ),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateDnsNameConstraints(
            constraints,
            "other.test",
        ),
    );

    const subdomains_only =
        "\x30\x12\xa0\x10\x30\x0e\x82\x0c.example.com";
    try trust.testing.validateDnsNameConstraints(
        subdomains_only,
        "api.example.com",
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateDnsNameConstraints(
            subdomains_only,
            "example.com",
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.validateDnsNameConstraints(
            "\x30\x0a\xa0\x08\x30\x06\x87\x04\x7f\x00\x00\x01",
            "example.com",
        ),
    );
    inline for (.{
        "bad..example.com",
        "-bad.example.com",
        "bad-.example.com",
    }) |invalid_name| {
        try std.testing.expectError(
            error.InvalidCertificateExtension,
            trust.testing.validateDnsNameConstraints(
                "\x30\x18\xa0\x16\x30\x14\x82\x10" ++ invalid_name,
                "example.com",
            ),
        );
    }
}

test "RFC 5280 rfc822Name constraints distinguish mailbox host and domain" {
    const domain_constraints =
        "\x30\x2b" ++
        "\xa0\x10\x30\x0e\x81\x0c.example.com" ++
        "\xa1\x17\x30\x15\x81\x13blocked.example.com";
    try trust.testing.validateRfc822NameConstraints(
        domain_constraints,
        "alice@mail.example.com",
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateRfc822NameConstraints(
            domain_constraints,
            "alice@example.com",
        ),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateRfc822NameConstraints(
            domain_constraints,
            "alice@blocked.example.com",
        ),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateRfc822NameConstraints(
            domain_constraints,
            "alice@other.test",
        ),
    );

    const host_constraint =
        "\x30\x11\xa0\x0f\x30\x0d\x81\x0bexample.com";
    try trust.testing.validateRfc822NameConstraints(
        host_constraint,
        "alice@EXAMPLE.COM",
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateRfc822NameConstraints(
            host_constraint,
            "alice@mail.example.com",
        ),
    );

    const mailbox_constraint =
        "\x30\x17\xa0\x15\x30\x13\x81\x11Admin@example.com";
    try trust.testing.validateRfc822NameConstraints(
        mailbox_constraint,
        "Admin@EXAMPLE.COM",
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateRfc822NameConstraints(
            mailbox_constraint,
            "admin@example.com",
        ),
    );
    try trust.testing.validateRfc822NameConstraints(
        host_constraint,
        "\"quoted@local\"@example.com",
    );

    const invalid_mailboxes = [_][]const u8{
        "@example.com",
        "alice@",
        "alice..smith@example.com",
        "alice @example.com",
        "alice@.example.com",
        "alice@bad..example.com",
        "\"unterminated@example.com",
    };
    for (invalid_mailboxes) |mailbox| {
        try std.testing.expectError(
            error.InvalidCertificateExtension,
            trust.testing.validateRfc822NameConstraints(
                host_constraint,
                mailbox,
            ),
        );
    }
}

test "bundle verifier enforces rfc822Name constraints from a real CA" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.email_constraints_root_hex);
    const good = decodeHex(path_vectors.email_constraints_good_hex);
    const excluded = decodeHex(path_vectors.email_constraints_excluded_hex);
    const outside = decodeHex(path_vectors.email_constraints_outside_hex);
    const subject_good = decodeHex(
        path_vectors.email_constraints_subject_good_hex,
    );
    const subject_outside = decodeHex(
        path_vectors.email_constraints_subject_outside_hex,
    );
    const now = 1_790_835_000;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&good},
    });
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&excluded},
        }),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&outside},
        }),
    );
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&subject_good},
    });
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&subject_outside},
        }),
    );
}

test "RFC 5280 URI constraints match only a DNS authority host" {
    const domain_constraints =
        "\x30\x2b" ++
        "\xa0\x10\x30\x0e\x86\x0c.example.com" ++
        "\xa1\x17\x30\x15\x86\x13blocked.example.com";
    try trust.testing.validateUriNameConstraints(
        domain_constraints,
        "https://api.example.com/path?q=1#fragment",
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateUriNameConstraints(
            domain_constraints,
            "https://example.com/",
        ),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateUriNameConstraints(
            domain_constraints,
            "https://blocked.example.com/",
        ),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateUriNameConstraints(
            domain_constraints,
            "https://other.test/",
        ),
    );

    const host_constraint =
        "\x30\x11\xa0\x0f\x30\x0d\x86\x0bexample.com";
    try trust.testing.validateUriNameConstraints(
        host_constraint,
        "HTTPS://user@EXAMPLE.COM:443/a",
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateUriNameConstraints(
            host_constraint,
            "https://api.example.com/",
        ),
    );

    const invalid_uris = [_][]const u8{
        "mailto:alice@example.com",
        "https:///path",
        "https://127.0.0.1/",
        "https://[2001:db8::1]/",
        "https://bad host.example.com/",
        "https://bad..example.com/",
        "relative/path",
    };
    for (invalid_uris) |uri| {
        try std.testing.expectError(
            error.InvalidCertificateExtension,
            trust.testing.validateUriNameConstraints(host_constraint, uri),
        );
    }
}

test "RFC 5280 directoryName constraints compare DN subtrees" {
    const constraints =
        "\x30\x6e\xa0\x2c\x30\x2a\xa4\x28\x30\x26" ++
        "\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02US" ++
        "\x31\x17\x30\x15\x06\x03\x55\x04\x0a\x0c\x0e" ++
        " Example  Org " ++
        "\xa1\x3e\x30\x3c\xa4\x3a\x30\x38" ++
        "\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02US" ++
        "\x31\x17\x30\x15\x06\x03\x55\x04\x0a\x0c\x0e" ++
        " Example  Org " ++
        "\x31\x10\x30\x0e\x06\x03\x55\x04\x0b\x0c\x07Blocked";
    const good_name =
        "\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02us" ++
        "\x31\x14\x30\x12\x06\x03\x55\x04\x0a\x13\x0b" ++
        "example org" ++
        "\x31\x11\x30\x0f\x06\x03\x55\x04\x0b\x0c\x08Services" ++
        "\x31\x0e\x30\x0c\x06\x03\x55\x04\x03\x0c\x05Caf\xc3\xa9";
    const excluded_name =
        "\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02US" ++
        "\x31\x17\x30\x15\x06\x03\x55\x04\x0a\x0c\x0e" ++
        " Example  Org " ++
        "\x31\x10\x30\x0e\x06\x03\x55\x04\x0b\x13\x07BLOCKED" ++
        "\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host";
    const outside_name =
        "\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02US" ++
        "\x31\x12\x30\x10\x06\x03\x55\x04\x0a\x0c\x09Other Org";

    try trust.testing.validateDirectoryNameConstraints(
        constraints,
        good_name,
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateDirectoryNameConstraints(
            constraints,
            excluded_name,
        ),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        trust.testing.validateDirectoryNameConstraints(
            constraints,
            outside_name,
        ),
    );
}

test "RFC 5280 directoryName constraints use RFC 4518 and DC matching" {
    const unicode_constraints =
        "\x30\x1a\xa0\x18\x30\x16\xa4\x14\x30\x12" ++
        "\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x0c\x07Stra\xc3\x9fe";
    const unicode_name =
        "\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x0c\x07STRASSE" ++
        "\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host";
    try trust.testing.validateDirectoryNameConstraints(
        unicode_constraints,
        unicode_name,
    );

    const canonical_constraints =
        "\x30\x18\xa0\x16\x30\x14\xa4\x12\x30\x10" ++
        "\x31\x0e\x30\x0c\x06\x03\x55\x04\x0a\x0c\x05Caf\xc3\xa9";
    const canonical_name =
        "\x31\x0f\x30\x0d\x06\x03\x55\x04\x0a\x0c\x06Cafe\xcc\x81" ++
        "\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host";
    try trust.testing.validateDirectoryNameConstraints(
        canonical_constraints,
        canonical_name,
    );

    const dc_constraints =
        "\x30\x36\xa0\x34\x30\x32\xa4\x30\x30\x2e" ++
        "\x31\x13\x30\x11\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19" ++
        "\x16\x03COM" ++
        "\x31\x17\x30\x15\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19" ++
        "\x16\x07Example";
    const dc_name =
        "\x31\x13\x30\x11\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19" ++
        "\x16\x03com" ++
        "\x31\x17\x30\x15\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19" ++
        "\x16\x07example" ++
        "\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host";
    try trust.testing.validateDirectoryNameConstraints(dc_constraints, dc_name);
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.validateDirectoryNameConstraints(
            dc_constraints,
            "\x31\x13\x30\x11\x06\x0a\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19" ++
                "\x0c\x03com",
        ),
    );

    // Both RDNs are valid DER SETs, but their attribute order differs because
    // one equivalent value changes from PrintableString to UTF8String.
    const multivalued_constraints =
        "\x30\x25\xa0\x23\x30\x21\xa4\x1f\x30\x1d\x31\x1b" ++
        "\x30\x0b\x06\x03\x55\x04\x0b\x13\x04Beta" ++
        "\x30\x0c\x06\x03\x55\x04\x0b\x13\x05Alpha";
    const multivalued_name =
        "\x31\x1b\x30\x0b\x06\x03\x55\x04\x0b\x0c\x04BETA" ++
        "\x30\x0c\x06\x03\x55\x04\x0b\x13\x05alpha" ++
        "\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04host";
    try trust.testing.validateDirectoryNameConstraints(
        multivalued_constraints,
        multivalued_name,
    );

    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.validateDirectoryNameConstraints(
            unicode_constraints,
            "\x30\x00",
        ),
    );
    try std.testing.expectError(
        error.UnsupportedCertificateNameConstraint,
        trust.testing.validateDirectoryNameConstraints(
            unicode_constraints,
            "\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x14\x07legacy!",
        ),
    );
}

test "bundle verifier enforces directoryName constraints from a real CA" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.directory_constraints_root_hex);
    const good = decodeHex(path_vectors.directory_constraints_good_hex);
    const excluded = decodeHex(
        path_vectors.directory_constraints_excluded_hex,
    );
    const outside = decodeHex(path_vectors.directory_constraints_outside_hex);
    const san_excluded = decodeHex(
        path_vectors.directory_constraints_san_excluded_hex,
    );
    const now = 1_790_837_100;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&good},
    });
    inline for (.{ excluded, outside, san_excluded }) |certificate| {
        try std.testing.expectError(
            error.CertificateNameConstraintViolation,
            verifier.verify(.{
                .server_name = "localhost",
                .chain = &.{&certificate},
            }),
        );
    }
}

test "bundle verifier processes RFC 5280 and RFC 9618 policy paths" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.policy_root_hex);
    const intermediate = decodeHex(path_vectors.policy_intermediate_hex);
    const bad_intermediate = decodeHex(
        path_vectors.policy_bad_intermediate_hex,
    );
    const good = decodeHex(path_vectors.policy_good_hex);
    const outside = decodeHex(path_vectors.policy_outside_hex);
    const missing = decodeHex(path_vectors.policy_missing_hex);
    const policy_a = [_]u8{ 0x2a, 0x03, 0x04 };
    const accepted = [_][]const u8{&policy_a};
    const now = 1_790_838_900;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .certificate_policy = .{
            .initial_policy_set = &accepted,
            .require_explicit_policy = true,
        },
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ &good, &intermediate },
    });
    try std.testing.expectError(
        error.CertificatePolicyViolation,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &good, &bad_intermediate },
        }),
    );
    // Both intermediates have the same subject and key, so signature and AKI
    // routing accept either. Policy failure on the first candidate must still
    // backtrack into the second candidate.
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{ &good, &bad_intermediate, &intermediate },
    });
    inline for (.{ outside, missing }) |certificate| {
        try std.testing.expectError(
            error.CertificatePolicyViolation,
            verifier.verify(.{
                .server_name = "localhost",
                .chain = &.{ &certificate, &intermediate },
            }),
        );
    }

    const inhibited = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .certificate_policy = .{
            .initial_policy_set = &accepted,
            .require_explicit_policy = true,
            .inhibit_policy_mapping = true,
        },
    };
    try std.testing.expectError(
        error.CertificatePolicyViolation,
        inhibited.verify(.{
            .server_name = "localhost",
            .chain = &.{ &good, &intermediate },
        }),
    );

    // The intermediate's requireExplicitPolicy=0 is independently effective
    // with the default any-policy caller input.
    const constrained_by_ca = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try constrained_by_ca.verify(.{
        .server_name = "localhost",
        .chain = &.{ &good, &intermediate },
    });
    inline for (.{ outside, missing }) |certificate| {
        try std.testing.expectError(
            error.CertificatePolicyViolation,
            constrained_by_ca.verify(.{
                .server_name = "localhost",
                .chain = &.{ &certificate, &intermediate },
            }),
        );
    }

    const policy_b = [_]u8{ 0x2a, 0x03, 0x05 };
    const wrong_initial = [_][]const u8{&policy_b};
    const wrong_policy_domain = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .certificate_policy = .{
            .initial_policy_set = &wrong_initial,
            .require_explicit_policy = true,
        },
    };
    try std.testing.expectError(
        error.CertificatePolicyViolation,
        wrong_policy_domain.verify(.{
            .server_name = "localhost",
            .chain = &.{ &good, &intermediate },
        }),
    );
}

test "bundle verifier links RFC 5280 equivalent issuer names" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.dn_equivalent_root_hex);
    const utf8_issuer = decodeHex(path_vectors.dn_equivalent_issuer_utf8_hex);
    const printable_issuer = decodeHex(
        path_vectors.dn_equivalent_issuer_printable_hex,
    );
    const wrong_issuer = decodeHex(
        path_vectors.dn_equivalent_wrong_issuer_hex,
    );
    const leaf = decodeHex(path_vectors.dn_equivalent_leaf_hex);
    const now = 1_790_840_400;

    const parsed_utf8 = try std.crypto.Certificate.parse(.{
        .buffer = &utf8_issuer,
        .index = 0,
    });
    const parsed_printable = try std.crypto.Certificate.parse(.{
        .buffer = &printable_issuer,
        .index = 0,
    });
    try std.testing.expect(!std.mem.eql(
        u8,
        parsed_utf8.subject(),
        parsed_printable.subject(),
    ));
    try std.testing.expect(try trust.testing.directoryNamesEqual(
        parsed_utf8.subject(),
        parsed_printable.subject(),
    ));

    var root_bundle: std.crypto.Certificate.Bundle = .empty;
    defer root_bundle.deinit(allocator);
    try root_bundle.bytes.appendSlice(allocator, &root);
    try root_bundle.parseCert(allocator, 0, now);
    try (trust.BundleVerifier{
        .bundle = &root_bundle,
        .now_seconds = now,
    }).verify(.{
        .server_name = "localhost",
        .chain = &.{ &leaf, &printable_issuer },
    });

    var direct_bundle: std.crypto.Certificate.Bundle = .empty;
    defer direct_bundle.deinit(allocator);
    try direct_bundle.bytes.appendSlice(allocator, &printable_issuer);
    try direct_bundle.parseCert(allocator, 0, now);
    try (trust.BundleVerifier{
        .bundle = &direct_bundle,
        .now_seconds = now,
    }).verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
    });

    var fallback_bundle: std.crypto.Certificate.Bundle = .empty;
    defer fallback_bundle.deinit(allocator);
    try fallback_bundle.bytes.appendSlice(allocator, &wrong_issuer);
    try fallback_bundle.parseCert(allocator, 0, now);
    const printable_offset = fallback_bundle.bytes.items.len;
    try fallback_bundle.bytes.appendSlice(allocator, &printable_issuer);
    try fallback_bundle.parseCert(
        allocator,
        @intCast(printable_offset),
        now,
    );
    try (trust.BundleVerifier{
        .bundle = &fallback_bundle,
        .now_seconds = now,
    }).verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
    });

    var wrong_bundle: std.crypto.Certificate.Bundle = .empty;
    defer wrong_bundle.deinit(allocator);
    try wrong_bundle.bytes.appendSlice(allocator, &wrong_issuer);
    try wrong_bundle.parseCert(allocator, 0, now);
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        (trust.BundleVerifier{
            .bundle = &wrong_bundle,
            .now_seconds = now,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&leaf},
        }),
    );
}

test "bundle verifier enforces URI constraints from a real CA" {
    const allocator = std.testing.allocator;
    const root = decodeHex(path_vectors.uri_constraints_root_hex);
    const good = decodeHex(path_vectors.uri_constraints_good_hex);
    const excluded = decodeHex(path_vectors.uri_constraints_excluded_hex);
    const outside = decodeHex(path_vectors.uri_constraints_outside_hex);
    const now = 1_790_835_500;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&good},
    });
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&excluded},
        }),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&outside},
        }),
    );
}

test "bundle verifier applies DNS constraints from a real intermediate" {
    const root = decodeHex(path_vectors.root_hex);
    const constrained = decodeHex(path_vectors.constrained_intermediate_hex);
    const example_leaf = decodeHex(path_vectors.example_leaf_hex);
    const localhost_leaf = decodeHex(path_vectors.leaf_hex);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &root);
    try bundle.parseCert(std.testing.allocator, 0, 1_900_000_000);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };
    try verifier.verify(.{
        .server_name = "api.example.com",
        .chain = &.{ &example_leaf, &constrained },
    });
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &localhost_leaf, &constrained },
        }),
    );
}

test "bundle verifier matches IP SANs and enforces IPv4 and IPv6 constraints" {
    const root = decodeHex(path_vectors.ip_constraints_root_hex);
    const allowed = decodeHex(path_vectors.ip_constraints_allowed_leaf_hex);
    const excluded = decodeHex(path_vectors.ip_constraints_excluded_leaf_hex);
    const outside = decodeHex(path_vectors.ip_constraints_outside_leaf_hex);
    const ipv6 = decodeHex(path_vectors.ip_constraints_ipv6_leaf_hex);
    const now = 1_900_000_000;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &root);
    try bundle.parseCert(std.testing.allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };

    try verifier.verify(.{
        .server_name = "10.1.2.3",
        .chain = &.{&allowed},
    });
    try verifier.verify(.{
        .server_name = "2001:db8:1::42",
        .chain = &.{&ipv6},
    });
    try std.testing.expectError(
        error.CertificateHostMismatch,
        verifier.verify(.{
            .server_name = "10.1.2.4",
            .chain = &.{&allowed},
        }),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "10.2.3.4",
            .chain = &.{&excluded},
        }),
    );
    try std.testing.expectError(
        error.CertificateNameConstraintViolation,
        verifier.verify(.{
            .server_name = "192.168.1.1",
            .chain = &.{&outside},
        }),
    );

    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.validateIpNameConstraints(
            "\x30\x0e\xa0\x0c\x30\x0a\x87\x08" ++
                "\x0a\x00\x00\x00\xff\x00\xff\x00",
            "10.1.2.3",
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificateExtension,
        trust.testing.validateIpNameConstraints(
            "\x30\x0e\xa0\x0c\x30\x0a\x87\x08" ++
                "\x0a\x01\x00\x00\xff\x00\x00\x00",
            "10.1.2.3",
        ),
    );
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

test "bundle verifier recursively fetches caIssuers into caller buffers" {
    const root = decodeHex(path_vectors.aia_path_root_hex);
    const intermediate = decodeHex(path_vectors.aia_path_intermediate_hex);
    const leaf = decodeHex(path_vectors.aia_path_leaf_hex);
    const intermediate_cms = decodeHex(
        path_vectors.aia_path_intermediate_certs_only_hex,
    );
    const now = 1_800_000_000;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &root);
    try bundle.parseCert(std.testing.allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
    };
    try std.testing.expectError(
        error.CertificateIssuerNotFound,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&leaf},
        }),
    );

    var fetch_context = AiaPathFetchContext{
        .intermediate_cms = &intermediate_cms,
        .root = &root,
    };
    var issuer_storage: [2048]u8 = undefined;
    var fetch_scratch: [1024]u8 = undefined;
    var fetched_output: [4][]const u8 = undefined;
    const presented_responses = [_]?[]const u8{null};
    const fetched = try verifier.verifyWithFetchedIssuers(
        .{
            .server_name = "localhost",
            .chain = &.{&leaf},
            .ocsp_responses = &presented_responses,
        },
        &issuer_storage,
        &fetch_scratch,
        &fetched_output,
        .{ .context = &fetch_context, .fetch = AiaPathFetchContext.fetch },
        .{ .max_certificates = fetched_output.len },
    );
    try std.testing.expectEqual(@as(usize, 2), fetch_context.calls);
    try std.testing.expectEqual(@as(usize, 2), fetched.fetches);
    try std.testing.expectEqual(@as(usize, 2), fetched.certificates.len);
    try std.testing.expectEqual(
        intermediate.len + root.len,
        fetched.storage_used,
    );
    try std.testing.expectEqualSlices(
        u8,
        &intermediate,
        fetched.certificates[0],
    );
    try std.testing.expectEqualSlices(u8, &root, fetched.certificates[1]);
}

const AiaPathFetchContext = struct {
    intermediate_cms: []const u8,
    root: []const u8,
    calls: usize = 0,

    fn fetch(
        opaque_context: ?*anyopaque,
        uri: []const u8,
        output: []u8,
    ) anyerror!?usize {
        const self: *@This() = @ptrCast(@alignCast(
            opaque_context orelse return error.MissingTestContext,
        ));
        const response = if (std.mem.eql(
            u8,
            uri,
            "http://aia.example.test/intermediate.p7c",
        ))
            self.intermediate_cms
        else if (std.mem.eql(
            u8,
            uri,
            "http://aia.example.test/root.der",
        ))
            self.root
        else
            return error.UnexpectedIssuerUrl;
        self.calls += 1;
        if (response.len > output.len) return error.BufferTooSmall;
        @memcpy(output[0..response.len], response);
        return response.len;
    }
};

test "P-521 issuer verifies certificate CRL and OCSP" {
    const root = decodeHex(path_vectors.p521_root_hex);
    const leaf = decodeHex(path_vectors.p521_leaf_hex);
    const encoded_crl = decodeHex(path_vectors.p521_crl_hex);
    const encoded_ocsp = decodeHex(path_vectors.p521_ocsp_hex);
    const now = 1_800_000_000;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, &root);
    try bundle.parseCert(std.testing.allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .require,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
        .ocsp_response = &encoded_ocsp,
    });

    const list = try crl.parseAndVerify(&encoded_crl, &root, now);
    try std.testing.expect(!try list.isRevoked(&leaf));
    try std.testing.expectEqual(
        ocsp.Status.good,
        try ocsp.verify(&encoded_ocsp, &leaf, &root, now, .{}),
    );
    const parsed_root = try std.crypto.Certificate.parse(.{
        .buffer = &root,
        .index = 0,
    });
    var prepared = try p521.CompactPreparedVerifier.init(
        parsed_root.pubKey(),
    );
    try std.testing.expectEqual(
        ocsp.Status.good,
        try ocsp.verifyWithP521(
            &encoded_ocsp,
            &leaf,
            &root,
            now,
            .{},
            &prepared,
        ),
    );

    var altered_leaf = leaf;
    altered_leaf[altered_leaf.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .now_seconds = now,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&altered_leaf},
        }),
    );
    var altered_crl = encoded_crl;
    altered_crl[altered_crl.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        crl.parseAndVerify(&altered_crl, &root, now),
    );
    var altered_ocsp = encoded_ocsp;
    altered_ocsp[altered_ocsp.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOcspSignature,
        ocsp.verify(&altered_ocsp, &leaf, &root, now, .{}),
    );
    try std.testing.expectError(
        error.InvalidOcspSignature,
        ocsp.verifyWithP521(
            &altered_ocsp,
            &leaf,
            &root,
            now,
            .{},
            &prepared,
        ),
    );
}

test "P-521 ECDSA SHA3 verifies certificate CRL and OCSP" {
    const self_signed_root = decodeHex(path_vectors.p521_sha3_root_hex);
    const leaf = decodeHex(path_vectors.p521_sha3_leaf_hex);
    const encoded_crl = decodeHex(path_vectors.p521_sha3_crl_hex);
    const encoded_ocsp = decodeHex(path_vectors.p521_sha3_ocsp_hex);
    const now = 1_800_000_000;

    const parsed_root = try certificate_compat.parse(&self_signed_root);
    try std.testing.expectEqual(
        @import("signature.zig").Algorithm.ecdsa_sha3_512,
        parsed_root.signature_algorithm.?,
    );
    try parsed_root.verify(parsed_root, now);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .compatible_trust_anchors = &.{&self_signed_root},
        .now_seconds = now,
        .stapled_ocsp = .require,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
        .ocsp_response = &encoded_ocsp,
    });

    const list = try crl.parseAndVerify(&encoded_crl, &self_signed_root, now);
    try std.testing.expect(!try list.isRevoked(&leaf));
    try std.testing.expectEqual(
        ocsp.Status.good,
        try ocsp.verify(
            &encoded_ocsp,
            &leaf,
            &self_signed_root,
            now,
            .{},
        ),
    );

    var altered_leaf = leaf;
    altered_leaf[altered_leaf.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .compatible_trust_anchors = &.{&self_signed_root},
            .now_seconds = now,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&altered_leaf},
        }),
    );
    var altered_crl = encoded_crl;
    altered_crl[altered_crl.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        crl.parseAndVerify(&altered_crl, &self_signed_root, now),
    );
    var altered_ocsp = encoded_ocsp;
    altered_ocsp[altered_ocsp.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOcspSignature,
        ocsp.verify(&altered_ocsp, &leaf, &self_signed_root, now, .{}),
    );

    try std.testing.expectError(
        error.CertificatePathTooManyTrustAnchors,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .compatible_trust_anchors = &.{
                &self_signed_root,
                &self_signed_root,
            },
            .now_seconds = now,
            .path_limits = .{ .max_compatible_trust_anchors = 1 },
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&leaf},
        }),
    );
    try std.testing.expectError(
        error.DuplicateTrustAnchor,
        (trust.BundleVerifier{
            .bundle = &bundle,
            .compatible_trust_anchors = &.{
                &self_signed_root,
                &self_signed_root,
            },
            .now_seconds = now,
        }).verify(.{
            .server_name = "localhost",
            .chain = &.{&leaf},
        }),
    );
}

test "SystemStore owns compatible DER and transactional PEM anchors" {
    const allocator = std.testing.allocator;
    const sha3_root = decodeHex(path_vectors.p521_sha3_root_hex);
    const sha3_leaf = decodeHex(path_vectors.p521_sha3_leaf_hex);
    const ordinary_root = decodeHex(path_vectors.p521_root_hex);
    const pss_anchor = @embedFile("testdata/rsa-pss-intermediate.der");
    const pss_leaf = @embedFile("testdata/rsa-pss-intermediate-leaf.der");
    const now = 1_800_000_000;

    var store = trust.SystemStore.initEmpty(allocator);
    defer store.deinit();
    try std.testing.expect(try store.addCompatibleCertificate(&sha3_root, now));
    try std.testing.expect(!(try store.addCompatibleCertificate(
        &sha3_root,
        now,
    )));
    try std.testing.expect(try store.addCompatibleCertificate(pss_anchor, now));
    try std.testing.expectEqual(@as(usize, 2), store.compatibleAnchorCount());
    try store.verifier(now).verify(.{
        .server_name = "localhost",
        .chain = &.{&sha3_leaf},
    });
    try store.verifier(now).verify(.{
        .server_name = "localhost",
        .chain = &.{pss_leaf},
    });

    const sha3_pem = try pemCertificate(allocator, &sha3_root);
    defer allocator.free(sha3_pem);
    const ordinary_pem = try pemCertificate(allocator, &ordinary_root);
    defer allocator.free(ordinary_pem);
    var pem_bundle: std.ArrayList(u8) = .empty;
    defer pem_bundle.deinit(allocator);
    try pem_bundle.appendSlice(allocator, "ignored preamble\n");
    try pem_bundle.appendSlice(allocator, sha3_pem);
    try pem_bundle.appendSlice(allocator, ordinary_pem);

    var pem_store = trust.SystemStore.initEmpty(allocator);
    defer pem_store.deinit();
    try std.testing.expectEqual(
        @as(usize, 2),
        try pem_store.addCompatiblePem(pem_bundle.items, now),
    );
    try std.testing.expectEqual(@as(usize, 2), pem_store.compatibleAnchorCount());
    try std.testing.expectEqual(
        @as(usize, 0),
        try pem_store.addCompatiblePem(pem_bundle.items, now),
    );

    var filtered_store = trust.SystemStore.initEmpty(allocator);
    defer filtered_store.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        try filtered_store.addUnsupportedPem(pem_bundle.items, now),
    );
    try filtered_store.verifier(now).verify(.{
        .server_name = "localhost",
        .chain = &.{&sha3_leaf},
    });

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "anchors.pem",
        .data = pem_bundle.items,
    });
    var file_store = trust.SystemStore.initEmpty(allocator);
    defer file_store.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        try file_store.addCompatiblePemFile(
            std.testing.io,
            temporary.dir,
            "anchors.pem",
            now,
            .{ .only_std_unsupported = true },
        ),
    );
    try file_store.verifier(now).verify(.{
        .server_name = "localhost",
        .chain = &.{&sha3_leaf},
    });
    try std.testing.expectError(
        error.StreamTooLong,
        file_store.addCompatiblePemFile(
            std.testing.io,
            temporary.dir,
            "anchors.pem",
            now,
            .{ .max_bytes = 1 },
        ),
    );
    const absolute_path = try temporary.dir.realPathFileAlloc(
        std.testing.io,
        "anchors.pem",
        allocator,
    );
    defer allocator.free(absolute_path);
    var absolute_store = trust.SystemStore.initEmpty(allocator);
    defer absolute_store.deinit();
    try std.testing.expectEqual(
        @as(usize, 2),
        try absolute_store.addCompatiblePemFileAbsolute(
            std.testing.io,
            absolute_path,
            now,
            .{},
        ),
    );

    var invalid_bundle: std.ArrayList(u8) = .empty;
    defer invalid_bundle.deinit(allocator);
    try invalid_bundle.appendSlice(allocator, sha3_pem);
    try invalid_bundle.appendSlice(
        allocator,
        "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n",
    );
    var atomic_store = trust.SystemStore.initEmpty(allocator);
    defer atomic_store.deinit();
    try std.testing.expectError(
        error.InvalidCharacter,
        atomic_store.addCompatiblePem(invalid_bundle.items, now),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        atomic_store.compatibleAnchorCount(),
    );
}

test "RSA-PSS SHA3 verifies certificate CRL and OCSP" {
    const root = decodeHex(path_vectors.rsa_pss_sha3_root_hex);
    const leaf = decodeHex(path_vectors.rsa_pss_sha3_leaf_hex);
    const encoded_crl = decodeHex(path_vectors.rsa_pss_sha3_crl_hex);
    const encoded_ocsp = decodeHex(path_vectors.rsa_pss_sha3_ocsp_hex);
    const now = 1_800_000_000;

    const parsed_leaf = try certificate_compat.parse(&leaf);
    try std.testing.expectEqual(
        @import("signature.zig").Algorithm.rsa_pss_sha3_256,
        parsed_leaf.signature_algorithm.?,
    );
    const parsed_root = try certificate_compat.parse(&root);
    try parsed_root.verify(parsed_root, now);

    var store = trust.SystemStore.initEmpty(std.testing.allocator);
    defer store.deinit();
    try std.testing.expect(try store.addCompatibleCertificate(&root, now));
    const verifier = store.verifier(now);
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
        .ocsp_response = &encoded_ocsp,
    });

    const list = try crl.parseAndVerify(&encoded_crl, &root, now);
    try std.testing.expect(!try list.isRevoked(&leaf));
    try std.testing.expectEqual(
        ocsp.Status.good,
        try ocsp.verify(&encoded_ocsp, &leaf, &root, now, .{}),
    );

    var altered_leaf = leaf;
    altered_leaf[altered_leaf.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&altered_leaf},
        }),
    );
    var altered_crl = encoded_crl;
    altered_crl[altered_crl.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        crl.parseAndVerify(&altered_crl, &root, now),
    );
    var altered_ocsp = encoded_ocsp;
    altered_ocsp[altered_ocsp.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOcspSignature,
        ocsp.verify(&altered_ocsp, &leaf, &root, now, .{}),
    );
}

test "RSA PKCS1 SHA3 verifies certificate CRL and OCSP" {
    const root = decodeHex(path_vectors.rsa_pkcs1_sha3_root_hex);
    const leaf = decodeHex(path_vectors.rsa_pkcs1_sha3_leaf_hex);
    const encoded_crl = decodeHex(path_vectors.rsa_pkcs1_sha3_crl_hex);
    const encoded_ocsp = decodeHex(path_vectors.rsa_pkcs1_sha3_ocsp_hex);
    const now = 1_800_000_000;

    const parsed_leaf = try certificate_compat.parse(&leaf);
    try std.testing.expectEqual(
        @import("signature.zig").Algorithm.rsa_pkcs1_sha3_256,
        parsed_leaf.signature_algorithm.?,
    );
    const parsed_root = try certificate_compat.parse(&root);
    try parsed_root.verify(parsed_root, now);

    var store = trust.SystemStore.initEmpty(std.testing.allocator);
    defer store.deinit();
    try std.testing.expect(try store.addCompatibleCertificate(&root, now));
    const verifier = store.verifier(now);
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
        .ocsp_response = &encoded_ocsp,
    });
    const list = try crl.parseAndVerify(&encoded_crl, &root, now);
    try std.testing.expect(!try list.isRevoked(&leaf));
    try std.testing.expectEqual(
        ocsp.Status.good,
        try ocsp.verify(&encoded_ocsp, &leaf, &root, now, .{}),
    );

    var altered_leaf = leaf;
    altered_leaf[altered_leaf.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateSignatureInvalid,
        verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&altered_leaf},
        }),
    );
}

fn pemCertificate(
    allocator: std.mem.Allocator,
    certificate_der: []const u8,
) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    const encoded_start = result.items.len;
    try result.resize(allocator, encoded_start + encoded_len);
    _ = std.base64.standard.Encoder.encode(
        result.items[encoded_start..],
        certificate_der,
    );
    try result.appendSlice(allocator, "\n-----END CERTIFICATE-----\n");
    return result.toOwnedSlice(allocator);
}
