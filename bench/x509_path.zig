const std = @import("std");
const vail = @import("vail");
const vectors = vail.x509.testing.path_vectors;

const iterations: usize = 5_000;

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
    const serial_root = decodeHex(vectors.serial_root_hex);
    const serial_intermediate = decodeHex(vectors.serial_intermediate_hex);
    const serial_decoy = decodeHex(vectors.serial_decoy_hex);
    const serial_leaf = decodeHex(vectors.serial_leaf_hex);

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

    std.debug.print(
        "unordered-decoy={d} ns/op cross-sign-backtrack={d} ns/op " ++
            "ocsp-stapled={d} ns/op delegated-ocsp={d} ns/op " ++
            "ip-name-constraints={d} ns/op issuer-serial={d} ns/op\n",
        .{
            unordered_ns / iterations,
            cross_ns / iterations,
            ocsp_ns / iterations,
            delegated_ns / iterations,
            ip_ns / iterations,
            serial_ns / iterations,
        },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
