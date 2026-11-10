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
