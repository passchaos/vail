const std = @import("std");
const vail = @import("vail");
const vectors = vail.x509.testing.path_vectors;

const iterations: usize = 5_000;
const batch_iterations: usize = 1_000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const root = decodeHex(vectors.root_hex);
    const alternate_root = decodeHex(vectors.alternate_root_hex);
    const intermediate = decodeHex(vectors.intermediate_hex);
    const cross_intermediate = decodeHex(vectors.cross_intermediate_hex);
    const decoy = decodeHex(vectors.decoy_hex);
    const leaf = decodeHex(vectors.leaf_hex);
    const ocsp_good = decodeHex(vectors.ocsp_good_hex);
    const delegated_ca = decodeHex(vectors.delegated_ocsp_ca_hex);
    const delegated_leaf = decodeHex(vectors.delegated_ocsp_leaf_hex);
    const delegated_ocsp = decodeHex(vectors.delegated_ocsp_good_hex);
    const ip_root = decodeHex(vectors.ip_constraints_root_hex);
    const ip_leaf = decodeHex(vectors.ip_constraints_allowed_leaf_hex);
    const directory_root = decodeHex(vectors.directory_constraints_root_hex);
    const directory_leaf = decodeHex(vectors.directory_constraints_good_hex);
    const policy_root = decodeHex(vectors.policy_root_hex);
    const policy_intermediate = decodeHex(vectors.policy_intermediate_hex);
    const policy_leaf = decodeHex(vectors.policy_good_hex);
    const dn_root = decodeHex(vectors.dn_equivalent_root_hex);
    const dn_issuer = decodeHex(vectors.dn_equivalent_issuer_printable_hex);
    const dn_leaf = decodeHex(vectors.dn_equivalent_leaf_hex);
    const equivalent_ocsp_issuer = decodeHex(vectors.crl_dn_issuer_utf8_hex);
    const equivalent_ocsp_target = decodeHex(vectors.ocsp_dn_ocsp_target_hex);
    const equivalent_ocsp_response = decodeHex(vectors.ocsp_dn_response_hex);
    const delta_crl_ca = decodeHex(vectors.delta_crl_ca_hex);
    const delta_crl_held = decodeHex(vectors.delta_crl_held_hex);
    const delta_crl_added = decodeHex(vectors.delta_crl_added_hex);
    const base_crl_der = decodeHex(vectors.delta_crl_base_hex);
    const delta_crl_der = decodeHex(vectors.delta_crl_delta_hex);
    const reason_crl_ca = decodeHex(vectors.reason_crl_ca_hex);
    const reason_crl_clean = decodeHex(vectors.reason_crl_clean_hex);
    const reason_crl_one_der = decodeHex(vectors.reason_crl_one_hex);
    const reason_crl_two_der = decodeHex(vectors.reason_crl_two_hex);
    const indirect_delta_root = decodeHex(vectors.multihop_crl_root_hex);
    const indirect_delta_intermediate = decodeHex(
        vectors.multihop_crl_intermediate_hex,
    );
    const indirect_delta_signer = decodeHex(vectors.multihop_crl_signer_hex);
    const indirect_delta_target = decodeHex(vectors.multihop_crl_target_hex);
    const indirect_delta_base_der = decodeHex(vectors.multihop_crl_base_hex);
    const indirect_delta_delta_der = decodeHex(vectors.multihop_crl_delta_hex);
    const freshest_crl_ca = decodeHex(vectors.freshest_crl_ca_hex);
    const freshest_crl_clean = decodeHex(vectors.freshest_crl_clean_hex);
    const freshest_crl_base_der = decodeHex(vectors.freshest_crl_base_hex);
    const freshest_crl_old_der = decodeHex(vectors.freshest_crl_delta_old_hex);
    const freshest_crl_new_der = decodeHex(vectors.freshest_crl_delta_new_hex);
    const serial_root = decodeHex(vectors.serial_root_hex);
    const serial_intermediate = decodeHex(vectors.serial_intermediate_hex);
    const serial_decoy = decodeHex(vectors.serial_decoy_hex);
    const serial_leaf = decodeHex(vectors.serial_leaf_hex);
    const batch_issuer = decodeHex(vectors.ocsp_batch_issuer_hex);
    const batch_leaf1 = decodeHex(vectors.ocsp_batch_leaf1_hex);
    const batch_leaf2 = decodeHex(vectors.ocsp_batch_leaf2_hex);
    const batch_response = decodeHex(vectors.ocsp_batch_response_hex);
    const aia_root = decodeHex(vectors.aia_path_root_hex);
    const aia_leaf = decodeHex(vectors.aia_path_leaf_hex);
    const aia_intermediate = decodeHex(vectors.aia_path_intermediate_hex);
    const aia_intermediate_cms = decodeHex(
        vectors.aia_path_intermediate_certs_only_hex,
    );
    const aia_intermediate_ber = try berCertificateSet(
        allocator,
        &aia_intermediate,
    );
    defer allocator.free(aia_intermediate_ber);
    const p521_root = decodeHex(vectors.p521_root_hex);
    const p521_leaf = decodeHex(vectors.p521_leaf_hex);
    const p521_ocsp = decodeHex(vectors.p521_ocsp_hex);
    const p521_signature = decodeHex(vectors.p521_sha512_signature_hex);
    const p521_sha3_root = decodeHex(vectors.p521_sha3_root_hex);
    const p521_sha3_leaf = decodeHex(vectors.p521_sha3_leaf_hex);
    const p521_sha3_ocsp = decodeHex(vectors.p521_sha3_ocsp_hex);
    const rsa_pss_sha3_root = decodeHex(vectors.rsa_pss_sha3_root_hex);
    const rsa_pss_sha3_leaf = decodeHex(vectors.rsa_pss_sha3_leaf_hex);
    const rsa_pss_sha3_ocsp = decodeHex(vectors.rsa_pss_sha3_ocsp_hex);
    const rsa_pkcs1_sha3_root = decodeHex(vectors.rsa_pkcs1_sha3_root_hex);
    const rsa_pkcs1_sha3_leaf = decodeHex(vectors.rsa_pkcs1_sha3_leaf_hex);
    const rsa_pkcs1_sha3_ocsp = decodeHex(vectors.rsa_pkcs1_sha3_ocsp_hex);

    var root_bundle: std.crypto.Certificate.Bundle = .empty;
    defer root_bundle.deinit(allocator);
    try root_bundle.bytes.appendSlice(allocator, &root);
    try root_bundle.parseCert(allocator, 0, 1_900_000_000);
    const root_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &root_bundle,
        .now_seconds = 1_900_000_000,
    };

    var alternate_bundle: std.crypto.Certificate.Bundle = .empty;
    defer alternate_bundle.deinit(allocator);
    try alternate_bundle.bytes.appendSlice(allocator, &alternate_root);
    try alternate_bundle.parseCert(allocator, 0, 1_900_000_000);
    const alternate_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &alternate_bundle,
        .now_seconds = 1_900_000_000,
    };

    const unordered_start = nowNs(init.io);
    for (0..iterations) |_| {
        try root_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &decoy, &root, &intermediate },
        });
    }
    const unordered_ns = nowNs(init.io) -| unordered_start;

    const cross_start = nowNs(init.io);
    for (0..iterations) |_| {
        try alternate_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate, &cross_intermediate },
        });
    }
    const cross_ns = nowNs(init.io) -| cross_start;

    const ocsp_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &root_bundle,
        .now_seconds = 1_790_663_000,
        .stapled_ocsp = .require,
    };
    const ocsp_start = nowNs(init.io);
    for (0..iterations) |_| {
        try ocsp_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &leaf, &intermediate },
            .ocsp_response = &ocsp_good,
        });
    }
    const ocsp_ns = nowNs(init.io) -| ocsp_start;

    var delegated_bundle: std.crypto.Certificate.Bundle = .empty;
    defer delegated_bundle.deinit(allocator);
    try delegated_bundle.bytes.appendSlice(allocator, &delegated_ca);
    try delegated_bundle.parseCert(allocator, 0, 1_790_664_300);
    const delegated_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &delegated_bundle,
        .now_seconds = 1_790_664_300,
        .stapled_ocsp = .require,
    };
    const delegated_start = nowNs(init.io);
    for (0..iterations) |_| {
        try delegated_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&delegated_leaf},
            .ocsp_response = &delegated_ocsp,
        });
    }
    const delegated_ns = nowNs(init.io) -| delegated_start;

    var ip_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ip_bundle.deinit(allocator);
    try ip_bundle.bytes.appendSlice(allocator, &ip_root);
    try ip_bundle.parseCert(allocator, 0, 1_900_000_000);
    const ip_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &ip_bundle,
        .now_seconds = 1_900_000_000,
    };
    const ip_start = nowNs(init.io);
    for (0..iterations) |_| {
        try ip_verifier.verify(.{
            .server_name = "10.1.2.3",
            .chain = &.{&ip_leaf},
        });
    }
    const ip_ns = nowNs(init.io) -| ip_start;

    var directory_bundle: std.crypto.Certificate.Bundle = .empty;
    defer directory_bundle.deinit(allocator);
    try directory_bundle.bytes.appendSlice(allocator, &directory_root);
    try directory_bundle.parseCert(allocator, 0, 1_790_837_100);
    const directory_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &directory_bundle,
        .now_seconds = 1_790_837_100,
    };
    const directory_start = nowNs(init.io);
    for (0..iterations) |_| {
        try directory_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&directory_leaf},
        });
    }
    const directory_ns = nowNs(init.io) -| directory_start;

    var policy_bundle: std.crypto.Certificate.Bundle = .empty;
    defer policy_bundle.deinit(allocator);
    try policy_bundle.bytes.appendSlice(allocator, &policy_root);
    try policy_bundle.parseCert(allocator, 0, 1_790_838_900);
    const policy_a = [_]u8{ 0x2a, 0x03, 0x04 };
    const accepted_policies = [_][]const u8{&policy_a};
    const policy_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &policy_bundle,
        .now_seconds = 1_790_838_900,
        .certificate_policy = .{
            .initial_policy_set = &accepted_policies,
            .require_explicit_policy = true,
        },
    };
    const policy_start = nowNs(init.io);
    for (0..iterations) |_| {
        try policy_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &policy_leaf, &policy_intermediate },
        });
    }
    const policy_ns = nowNs(init.io) -| policy_start;

    var dn_bundle: std.crypto.Certificate.Bundle = .empty;
    defer dn_bundle.deinit(allocator);
    try dn_bundle.bytes.appendSlice(allocator, &dn_root);
    try dn_bundle.parseCert(allocator, 0, 1_790_840_400);
    const dn_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &dn_bundle,
        .now_seconds = 1_790_840_400,
    };
    const dn_start = nowNs(init.io);
    for (0..iterations) |_| {
        try dn_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{ &dn_leaf, &dn_issuer },
        });
    }
    const dn_ns = nowNs(init.io) -| dn_start;

    var serial_bundle: std.crypto.Certificate.Bundle = .empty;
    defer serial_bundle.deinit(allocator);
    try serial_bundle.bytes.appendSlice(allocator, &serial_root);
    try serial_bundle.parseCert(allocator, 0, 1_900_000_000);
    const serial_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &serial_bundle,
        .now_seconds = 1_900_000_000,
        .path_limits = .{ .max_candidate_checks = 2 },
    };
    const serial_start = nowNs(init.io);
    for (0..iterations) |_| {
        try serial_verifier.verify(.{
            .server_name = "serial.localhost",
            .chain = &.{ &serial_leaf, &serial_decoy, &serial_intermediate },
        });
    }
    const serial_ns = nowNs(init.io) -| serial_start;

    var aia_bundle: std.crypto.Certificate.Bundle = .empty;
    defer aia_bundle.deinit(allocator);
    try aia_bundle.bytes.appendSlice(allocator, &aia_root);
    try aia_bundle.parseCert(allocator, 0, 1_800_000_000);
    const aia_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &aia_bundle,
        .now_seconds = 1_800_000_000,
    };
    var aia_context = AiaFetchContext{
        .intermediate_cms = &aia_intermediate_cms,
        .root = &aia_root,
    };
    var aia_storage: [2048]u8 = undefined;
    var aia_scratch: [1024]u8 = undefined;
    var aia_output: [4][]const u8 = undefined;
    var aia_checksum: usize = 0;
    const aia_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        const fetched = try aia_verifier.verifyWithFetchedIssuers(
            .{ .server_name = "localhost", .chain = &.{&aia_leaf} },
            &aia_storage,
            &aia_scratch,
            &aia_output,
            .{ .context = &aia_context, .fetch = AiaFetchContext.fetch },
            .{ .max_certificates = aia_output.len },
        );
        aia_checksum +%= fetched.storage_used;
    }
    const aia_ns = nowNs(init.io) -| aia_start;

    var aia_ber_context = AiaFetchContext{
        .intermediate_cms = aia_intermediate_ber,
        .root = &aia_root,
    };
    var aia_ber_storage: [2048]u8 = undefined;
    var aia_ber_scratch: [1024]u8 = undefined;
    var aia_ber_output: [4][]const u8 = undefined;
    var aia_ber_checksum: usize = 0;
    const aia_ber_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        const fetched = try aia_verifier.verifyWithFetchedIssuers(
            .{ .server_name = "localhost", .chain = &.{&aia_leaf} },
            &aia_ber_storage,
            &aia_ber_scratch,
            &aia_ber_output,
            .{
                .context = &aia_ber_context,
                .fetch = AiaFetchContext.fetch,
            },
            .{
                .max_certificates = aia_ber_output.len,
                .allow_ber_certs_only = true,
            },
        );
        aia_ber_checksum +%= fetched.storage_used;
    }
    const aia_ber_ns = nowNs(init.io) -| aia_ber_start;

    var p521_bundle: std.crypto.Certificate.Bundle = .empty;
    defer p521_bundle.deinit(allocator);
    try p521_bundle.bytes.appendSlice(allocator, &p521_root);
    try p521_bundle.parseCert(allocator, 0, 1_800_000_000);
    const p521_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &p521_bundle,
        .now_seconds = 1_800_000_000,
        .stapled_ocsp = .require,
    };
    const p521_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        try p521_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&p521_leaf},
            .ocsp_response = &p521_ocsp,
        });
    }
    const p521_ns = nowNs(init.io) -| p521_start;

    const parsed_p521_root = try std.crypto.Certificate.parse(.{
        .buffer = &p521_root,
        .index = 0,
    });
    const p521_verify_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        std.mem.doNotOptimizeAway(p521_signature[0]);
        try vail.crypto.p521.verify(
            std.crypto.hash.sha2.Sha512,
            "Vail pure Zig P-521 oracle",
            &p521_signature,
            parsed_p521_root.pubKey(),
        );
    }
    const p521_verify_ns = nowNs(init.io) -| p521_verify_start;

    var p521_sha3_bundle: std.crypto.Certificate.Bundle = .empty;
    defer p521_sha3_bundle.deinit(allocator);
    const p521_sha3_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &p521_sha3_bundle,
        .compatible_trust_anchors = &.{&p521_sha3_root},
        .now_seconds = 1_800_000_000,
        .stapled_ocsp = .require,
    };
    const p521_sha3_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        try p521_sha3_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&p521_sha3_leaf},
            .ocsp_response = &p521_sha3_ocsp,
        });
    }
    const p521_sha3_ns = nowNs(init.io) -| p521_sha3_start;

    var rsa_sha3_bundle: std.crypto.Certificate.Bundle = .empty;
    defer rsa_sha3_bundle.deinit(allocator);
    const rsa_pss_sha3_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &rsa_sha3_bundle,
        .compatible_trust_anchors = &.{&rsa_pss_sha3_root},
        .now_seconds = 1_800_000_000,
        .stapled_ocsp = .require,
    };
    const rsa_pss_sha3_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        try rsa_pss_sha3_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&rsa_pss_sha3_leaf},
            .ocsp_response = &rsa_pss_sha3_ocsp,
        });
    }
    const rsa_pss_sha3_ns = nowNs(init.io) -| rsa_pss_sha3_start;

    const rsa_pkcs1_sha3_verifier = vail.x509.trust.BundleVerifier{
        .bundle = &rsa_sha3_bundle,
        .compatible_trust_anchors = &.{&rsa_pkcs1_sha3_root},
        .now_seconds = 1_800_000_000,
        .stapled_ocsp = .require,
    };
    const rsa_pkcs1_sha3_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        try rsa_pkcs1_sha3_verifier.verify(.{
            .server_name = "localhost",
            .chain = &.{&rsa_pkcs1_sha3_leaf},
            .ocsp_response = &rsa_pkcs1_sha3_ocsp,
        });
    }
    const rsa_pkcs1_sha3_ns = nowNs(init.io) -| rsa_pkcs1_sha3_start;

    var status_checksum: usize = 0;
    const repeated_ocsp_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        status_checksum +%= @intFromEnum(try vail.x509.ocsp.verify(
            &batch_response,
            &batch_leaf1,
            &batch_issuer,
            1_790_818_560,
            .{},
        ));
        status_checksum +%= @intFromEnum(try vail.x509.ocsp.verify(
            &batch_response,
            &batch_leaf2,
            &batch_issuer,
            1_790_818_560,
            .{},
        ));
    }
    const repeated_ocsp_ns = nowNs(init.io) -| repeated_ocsp_start;

    const batch_certificates = [_][]const u8{ &batch_leaf1, &batch_leaf2 };
    var statuses: [batch_certificates.len]vail.x509.ocsp.Status = undefined;
    const batch_ocsp_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        try vail.x509.ocsp.verifyMany(
            &statuses,
            &batch_response,
            &batch_certificates,
            &batch_issuer,
            1_790_818_560,
            .{},
        );
        status_checksum +%= @intFromEnum(statuses[0]);
        status_checksum +%= @intFromEnum(statuses[1]);
    }
    const batch_ocsp_ns = nowNs(init.io) -| batch_ocsp_start;

    const equivalent_ocsp_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        status_checksum +%= @intFromEnum(try vail.x509.ocsp.verify(
            &equivalent_ocsp_response,
            &equivalent_ocsp_target,
            &equivalent_ocsp_issuer,
            1_790_842_500,
            .{},
        ));
    }
    const equivalent_ocsp_ns = nowNs(init.io) -| equivalent_ocsp_start;

    const base_crl = try vail.x509.crl.parseAndVerify(
        &base_crl_der,
        &delta_crl_ca,
        1_790_844_200,
    );
    const delta_crl = try vail.x509.crl.parseAndVerify(
        &delta_crl_der,
        &delta_crl_ca,
        1_790_844_200,
    );
    const combined_crl = try vail.x509.crl.CombinedList.init(
        base_crl,
        delta_crl,
    );
    const delta_crl_start = nowNs(init.io);
    for (0..iterations) |_| {
        status_checksum +%= @intFromBool(try combined_crl.isRevoked(
            &delta_crl_held,
        ));
        status_checksum +%= @intFromBool(try combined_crl.isRevoked(
            &delta_crl_added,
        ));
    }
    const delta_crl_ns = nowNs(init.io) -| delta_crl_start;

    const reason_crl_one = try vail.x509.crl.parseAndVerify(
        &reason_crl_one_der,
        &reason_crl_ca,
        1_790_845_500,
    );
    const reason_crl_two = try vail.x509.crl.parseAndVerify(
        &reason_crl_two_der,
        &reason_crl_ca,
        1_790_845_500,
    );
    const reason_crl_set = vail.x509.crl.VerifiedSet{
        .lists = &.{ reason_crl_one, reason_crl_two },
    };
    const reason_crl_policy = reason_crl_set.policy(true);
    const reason_crl_start = nowNs(init.io);
    for (0..iterations) |_| {
        try reason_crl_policy.verify(&reason_crl_clean, &reason_crl_ca);
    }
    const reason_crl_ns = nowNs(init.io) -| reason_crl_start;

    const indirect_delta_base = try vail.x509.crl.parseAndVerify(
        &indirect_delta_base_der,
        &indirect_delta_signer,
        1_790_848_300,
    );
    const indirect_delta_delta = try vail.x509.crl.parseAndVerify(
        &indirect_delta_delta_der,
        &indirect_delta_signer,
        1_790_848_300,
    );
    const indirect_delta_combined = try vail.x509.crl.CombinedList.init(
        indirect_delta_base,
        indirect_delta_delta,
    );
    const indirect_delta_authorized =
        try vail.x509.crl.AuthorizedIndirectCombinedList.initWithSignerChain(
            allocator,
            indirect_delta_combined,
            &indirect_delta_root,
            &.{ &indirect_delta_signer, &indirect_delta_intermediate },
            1_790_848_300,
            .{},
            .{},
        );
    const indirect_delta_set = vail.x509.crl.VerifiedSet{
        .lists = &.{},
        .indirect_combined_lists = &.{indirect_delta_authorized},
    };
    const indirect_delta_policy = indirect_delta_set.policy(true);
    const indirect_delta_start = nowNs(init.io);
    for (0..iterations) |_| {
        try indirect_delta_policy.verify(
            &indirect_delta_target,
            &indirect_delta_root,
        );
    }
    const indirect_delta_ns = nowNs(init.io) -| indirect_delta_start;

    const freshest_base = try vail.x509.crl.parseAndVerify(
        &freshest_crl_base_der,
        &freshest_crl_ca,
        1_790_848_980,
    );
    const freshest_old = try vail.x509.crl.parseAndVerify(
        &freshest_crl_old_der,
        &freshest_crl_ca,
        1_790_848_980,
    );
    const freshest_new = try vail.x509.crl.parseAndVerify(
        &freshest_crl_new_der,
        &freshest_crl_ca,
        1_790_848_980,
    );
    const freshest_set = vail.x509.crl.VerifiedSet{
        .lists = &.{ freshest_base, freshest_old, freshest_new },
    };
    const freshest_policy = freshest_set.policy(true);
    const freshest_start = nowNs(init.io);
    for (0..iterations) |_| {
        try freshest_policy.verify(&freshest_crl_clean, &freshest_crl_ca);
    }
    const freshest_ns = nowNs(init.io) -| freshest_start;

    var fetch_context = DeltaFetchContext{ .der = &freshest_crl_new_der };
    var fetched_delta: [1024]u8 = undefined;
    var fetched_scratch: [1024]u8 = undefined;
    const fetch_delta_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        const fetched = (try vail.x509.crl.fetchLatestDelta(
            &fetched_delta,
            &fetched_scratch,
            freshest_base,
            &freshest_crl_ca,
            1_790_848_980,
            try vail.x509.crl.listFreshestCrlUrls(freshest_base),
            .{ .context = &fetch_context, .fetch = DeltaFetchContext.fetch },
            .{},
        )).?;
        status_checksum +%= fetched.encoded.len;
    }
    const fetch_delta_ns = nowNs(init.io) -| fetch_delta_start;

    var conditional_context = ConditionalDeltaFetchContext{
        .der = &freshest_crl_new_der,
    };
    var cache_body: [1024]u8 = undefined;
    var cache_uri: [128]u8 = undefined;
    var cache_etag: [64]u8 = undefined;
    var cache_modified: [64]u8 = undefined;
    var conditional_scratch: [1024]u8 = undefined;
    var delta_cache = vail.x509.crl.DeltaCache.init(
        &cache_body,
        &cache_uri,
        &cache_etag,
        &cache_modified,
    );
    const delta_uri = "http://crl.example.test/latest.delta.crl";
    _ = try vail.x509.crl.refreshDeltaCache(
        &delta_cache,
        &conditional_scratch,
        freshest_base,
        &freshest_crl_ca,
        1_790_848_980,
        delta_uri,
        .{
            .context = &conditional_context,
            .fetch = ConditionalDeltaFetchContext.fetch,
        },
        .{},
    );
    conditional_context.not_modified = true;
    const conditional_start = nowNs(init.io);
    for (0..batch_iterations) |_| {
        _ = try vail.x509.crl.refreshDeltaCache(
            &delta_cache,
            &conditional_scratch,
            freshest_base,
            &freshest_crl_ca,
            1_790_848_981,
            delta_uri,
            .{
                .context = &conditional_context,
                .fetch = ConditionalDeltaFetchContext.fetch,
            },
            .{},
        );
    }
    const conditional_ns = nowNs(init.io) -| conditional_start;

    std.debug.print(
        "unordered-decoy={d} ns/op cross-sign-backtrack={d} ns/op " ++
            "ocsp-stapled={d} ns/op delegated-ocsp={d} ns/op " ++
            "ip-name-constraints={d} ns/op " ++
            "directory-name-constraints={d} ns/op issuer-serial={d} ns/op " ++
            "certificate-policy={d} ns/op equivalent-dn={d} ns/op " ++
            "aia-fetch-path={d} ns/op aia-ber-fetch-path={d} ns/op " ++
            "p521-cert-ocsp={d} ns/op " ++
            "p521-verify={d} ns/op " ++
            "p521-sha3-cert-ocsp={d} ns/op " ++
            "rsa-pss-sha3-cert-ocsp={d} ns/op " ++
            "rsa-pkcs1-sha3-cert-ocsp={d} ns/op " ++
            "ocsp-repeated-2={d} ns/op ocsp-batch-2={d} ns/op " ++
            "equivalent-dn-ocsp={d} ns/op " ++
            "delta-crl-2={d} ns/op partitioned-crl={d} ns/op " ++
            "indirect-delta-crl={d} ns/op freshest-crl={d} ns/op " ++
            "fetch-delta={d} ns/op conditional-304={d} ns/op " ++
            "checksum={d}\n",
        .{
            unordered_ns / iterations,
            cross_ns / iterations,
            ocsp_ns / iterations,
            delegated_ns / iterations,
            ip_ns / iterations,
            directory_ns / iterations,
            serial_ns / iterations,
            policy_ns / iterations,
            dn_ns / iterations,
            aia_ns / batch_iterations,
            aia_ber_ns / batch_iterations,
            p521_ns / batch_iterations,
            p521_verify_ns / batch_iterations,
            p521_sha3_ns / batch_iterations,
            rsa_pss_sha3_ns / batch_iterations,
            rsa_pkcs1_sha3_ns / batch_iterations,
            repeated_ocsp_ns / batch_iterations,
            batch_ocsp_ns / batch_iterations,
            equivalent_ocsp_ns / batch_iterations,
            delta_crl_ns / iterations,
            reason_crl_ns / iterations,
            indirect_delta_ns / iterations,
            freshest_ns / iterations,
            fetch_delta_ns / batch_iterations,
            conditional_ns / batch_iterations,
            status_checksum +% aia_checksum +% aia_ber_checksum,
        },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn berCertificateSet(
    allocator: std.mem.Allocator,
    certificate: []const u8,
) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(
        allocator,
        "\x30\x80" ++
            "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" ++
            "\xa0\x80\x30\x80\x02\x01\x01" ++
            "\x31\x80\x00\x00" ++
            "\x30\x80\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01" ++
            "\x00\x00\xa0\x80",
    );
    try result.appendSlice(allocator, certificate);
    try result.appendSlice(
        allocator,
        "\x00\x00\x31\x80\x00\x00" ++
            "\x00\x00\x00\x00\x00\x00",
    );
    return result.toOwnedSlice(allocator);
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

const DeltaFetchContext = struct {
    der: []const u8,

    fn fetch(
        opaque_context: ?*anyopaque,
        uri: []const u8,
        output: []u8,
    ) anyerror!?usize {
        if (uri.len == 0) return null;
        const self: *@This() = @ptrCast(@alignCast(opaque_context.?));
        if (self.der.len > output.len) return error.BufferTooSmall;
        @memcpy(output[0..self.der.len], self.der);
        return self.der.len;
    }
};

const AiaFetchContext = struct {
    intermediate_cms: []const u8,
    root: []const u8,

    fn fetch(
        opaque_context: ?*anyopaque,
        uri: []const u8,
        output: []u8,
    ) anyerror!?usize {
        const self: *@This() = @ptrCast(@alignCast(opaque_context.?));
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
        if (response.len > output.len) return error.BufferTooSmall;
        @memcpy(output[0..response.len], response);
        return response.len;
    }
};

const ConditionalDeltaFetchContext = struct {
    der: []const u8,
    not_modified: bool = false,

    fn fetch(
        opaque_context: ?*anyopaque,
        request: vail.x509.crl.ConditionalRequest,
        output: []u8,
    ) anyerror!vail.x509.crl.ConditionalFetchResult {
        const self: *@This() = @ptrCast(@alignCast(opaque_context.?));
        if (self.not_modified) {
            if (request.if_none_match == null or
                request.if_modified_since == null)
            {
                return error.MissingValidator;
            }
            return .not_modified;
        }
        if (self.der.len > output.len) return error.BufferTooSmall;
        @memcpy(output[0..self.der.len], self.der);
        return .{ .fetched = .{
            .len = self.der.len,
            .etag = "\"bench-delta\"",
            .last_modified = "Thu, 01 Oct 2026 10:02:00 GMT",
        } };
    }
};
