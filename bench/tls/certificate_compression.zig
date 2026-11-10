const std = @import("std");
const vail = @import("vail");

const prepare_iterations: usize = 250;
const decompress_iterations: usize = 5_000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const vectors = vail.testdata.x509.path_vectors;
    const leaf = decodeHex(vectors.leaf_hex);
    const intermediate = decodeHex(vectors.intermediate_hex);
    const root = decodeHex(vectors.root_hex);
    const ocsp_response = decodeHex(vectors.ocsp_good_hex);

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try vail.tls.auth.writeCertificateWithOcsp(
        &certificate,
        allocator,
        &.{ &leaf, &intermediate, &root },
        &ocsp_response,
    );

    try benchmarkAlgorithm(init.io, allocator, certificate.items, .zlib);
    try benchmarkAlgorithm(init.io, allocator, certificate.items, .brotli);
    try benchmarkAlgorithm(init.io, allocator, certificate.items, .zstd);
}

fn benchmarkAlgorithm(
    io: std.Io,
    allocator: std.mem.Allocator,
    certificate: []const u8,
    algorithm: vail.tls.certificate_compression.Algorithm,
) !void {
    var checksum: u64 = 0;
    const prepare_start = nowNs(io);
    for (0..prepare_iterations) |_| {
        var prepared = try prepare(allocator, certificate, algorithm);
        checksum +%= prepared.compressed[prepared.compressed.len - 1];
        prepared.deinit();
    }
    const prepare_ns = nowNs(io) -| prepare_start;

    var prepared = try prepare(allocator, certificate, algorithm);
    defer prepared.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try prepared.view().write(&encoded, allocator);

    const decompress_start = nowNs(io);
    for (0..decompress_iterations) |_| {
        const restored = try vail.tls.certificate_compression
            .decompressCertificate(
            allocator,
            encoded.items,
            &.{algorithm},
            certificate.len,
        );
        checksum +%= restored[restored.len - 1];
        allocator.free(restored);
    }
    const decompress_ns = nowNs(io) -| decompress_start;

    std.debug.print(
        "{s}: certificate={d} bytes compressed={d} bytes ratio={d:.2}% " ++
            "prepare={d} ns/op decompress={d} ns/op checksum={d}\n",
        .{
            @tagName(algorithm),
            certificate.len,
            encoded.items.len,
            100.0 * @as(f64, @floatFromInt(encoded.items.len)) /
                @as(f64, @floatFromInt(certificate.len)),
            prepare_ns / prepare_iterations,
            decompress_ns / decompress_iterations,
            checksum,
        },
    );
}

fn prepare(
    allocator: std.mem.Allocator,
    certificate: []const u8,
    algorithm: vail.tls.certificate_compression.Algorithm,
) !vail.tls.certificate_compression.Prepared {
    return switch (algorithm) {
        .zlib => vail.tls.certificate_compression.Prepared.initZlib(
            allocator,
            certificate,
            .amortized,
        ),
        .brotli => vail.tls.certificate_compression.Prepared.initBrotli(
            allocator,
            certificate,
            .amortized,
        ),
        .zstd => vail.tls.certificate_compression.Prepared.initZstd(
            allocator,
            certificate,
            .amortized,
        ),
        else => error.UnsupportedCompressionAlgorithm,
    };
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
