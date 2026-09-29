const std = @import("std");
const auth = @import("../tls/auth.zig");
const trust = @import("trust.zig");
const crl = @import("crl.zig");
const path_vectors = @import("testdata/path_vectors.zig");

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
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
