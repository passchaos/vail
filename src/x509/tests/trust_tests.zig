const std = @import("std");
const auth = @import("../../tls/handshake/auth.zig");
const ed25519 = @import("../../crypto/sign/ed25519.zig");
const p256 = @import("../../crypto/ec/p256.zig");
const p521 = @import("../../crypto/ec/p521.zig");
const certificate_compat = @import("../certificate.zig");
const trust = @import("../trust.zig");
const crl = @import("../crl.zig");
const ocsp = @import("../ocsp.zig");
const path_vectors = @import("../testdata/path_vectors.zig");

const common = @import("common.zig");
const decodeHex = common.decodeHex;

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
    try auth.ClientVerifier.fromTrustVerifier(required.clientVerifier()).verifyTrustWithOcsp(
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

    const parsed_root = try @import("../certificate.zig").parse(&root);
    const parsed_intermediate = try @import("../certificate.zig").parse(
        &intermediate,
    );
    const parsed_leaf = try @import("../certificate.zig").parse(&leaf);
    try parsed_intermediate.verify(parsed_root, now);
    try parsed_leaf.verify(parsed_intermediate, now);

    try std.testing.expectEqual(
        @import("../ocsp.zig").Status.good,
        try @import("../ocsp.zig").verify(
            &leaf_ocsp,
            &leaf,
            &intermediate,
            now,
            .{},
        ),
    );
    try std.testing.expectEqual(
        @import("../ocsp.zig").Status.good,
        try @import("../ocsp.zig").verify(
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
    const server_der = @embedFile("../testdata/server.der");
    const ca_der = @embedFile("../testdata/ca.der");
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

    try verifier.verifyServerChain(.{
        .server_name = "other.example",
        .chain = &.{server_der},
    });
    try auth.ClientVerifier.fromTrustVerifier(verifier.serverChainVerifier()).verifyTrust(
        "other.example",
        &.{server_der},
    );

    var corrupted = server_der.*;
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateUntrusted,
        auth.ClientVerifier.fromTrustVerifier(verifier.serverChainVerifier()).verifyTrust(
            "other.example",
            &.{&corrupted},
        ),
    );
}

test "bundle verifier accepts RSA-PSS signed leaves and intermediates" {
    const root = @embedFile("../testdata/rsa-pss-crl-ca.der");
    const pss_leaf = @embedFile("../testdata/rsa-pss-leaf.der");
    const pss_intermediate = @embedFile("../testdata/rsa-pss-intermediate.der");
    const intermediate_leaf = @embedFile(
        "../testdata/rsa-pss-intermediate-leaf.der",
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
    const root = @embedFile("../testdata/rsa-pss-crl-ca.der");
    const constrained_leaf = @embedFile(
        "../testdata/rsa-pss-constrained-leaf.der",
    );
    const constrained_intermediate = @embedFile(
        "../testdata/rsa-pss-constrained-intermediate.der",
    );
    const child = @embedFile("../testdata/rsa-pss-constrained-child.der");
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
    const client_der = @embedFile("../testdata/server.der");
    const ca_der = @embedFile("../testdata/ca.der");
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
    try auth.ClientVerifier.fromTrustVerifier(verifier.clientVerifier()).verifyTrust(null, &.{client_der});

    var corrupted_client = client_der.*;
    corrupted_client[corrupted_client.len - 1] ^= 1;
    try std.testing.expectError(
        error.CertificateUntrusted,
        auth.ClientVerifier.fromTrustVerifier(verifier.clientVerifier()).verifyTrust(null, &.{&corrupted_client}),
    );
}

test "client trust verifier enforces authenticated CRL status" {
    const ca = @embedFile("../testdata/ed25519-crl-ca.der");
    const good = @embedFile("../testdata/ed25519-crl-good.der");
    const revoked = @embedFile("../testdata/ed25519-crl-revoked.der");
    const encoded_crl = @embedFile("../testdata/ed25519.crl.der");
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
    const ca = @embedFile("../testdata/ed25519-crl-ca.der");
    const good = @embedFile("../testdata/ed25519-crl-good.der");
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
