const std = @import("std");
const vail = @import("vail");

const iterations: usize = 5_000;
const warmup_iterations: usize = 32;
const message = "Vail pure Zig P-521 oracle";

pub fn main(init: std.process.Init) !void {
    const vectors = vail.x509.testing.path_vectors;
    const root = decodeHex(vectors.p521_root_hex);
    const signature = decodeHex(vectors.p521_sha512_signature_hex);
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &root,
        .index = 0,
    });
    const public_key = certificate.pubKey();

    for (0..warmup_iterations) |_| {
        try vail.crypto.p521.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
            public_key,
        );
    }
    const start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(signature[0]);
        try vail.crypto.p521.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
            public_key,
        );
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "pure-zig-p521-one-shot-sha512={d} ns/verify\n",
        .{elapsed / iterations},
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
