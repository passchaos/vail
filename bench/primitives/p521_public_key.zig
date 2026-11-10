const std = @import("std");
const vail = @import("vail");

const iterations: usize = 20_000;
const warmup_iterations: usize = 32;

pub fn main(init: std.process.Init) !void {
    const vectors = vail.testdata.x509.path_vectors;
    const root = decodeHex(vectors.p521_root_hex);
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &root,
        .index = 0,
    });
    const public_key = try vail.crypto.p521.PublicKey.fromSec1(
        certificate.pubKey(),
    );
    var checksum: u64 = 0;

    for (0..warmup_iterations) |_| {
        const uncompressed = public_key.toUncompressedSec1();
        const compressed = public_key.toCompressedSec1();
        checksum +%= uncompressed[1] +% compressed[0];
    }

    var start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const encoded = public_key.toUncompressedSec1();
        checksum +%= encoded[iteration % encoded.len];
    }
    const uncompressed_elapsed = nowNs(init.io) -| start;

    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const encoded = public_key.toCompressedSec1();
        checksum +%= encoded[iteration % encoded.len];
    }
    const compressed_elapsed = nowNs(init.io) -| start;

    std.debug.print(
        "pure-zig-p521-public-uncompressed={d} ns/op " ++
            "compressed={d} ns/op checksum={d}\n",
        .{
            uncompressed_elapsed / iterations,
            compressed_elapsed / iterations,
            checksum,
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
