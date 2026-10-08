const std = @import("std");
const vail = @import("vail");

const iterations: usize = 5_000;
const init_iterations: usize = 100;
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
    const parsed = try vail.crypto.p521.PublicKey.fromSec1(public_key);
    const prepared = try vail.crypto.p521.PreparedVerifier.init(public_key);
    const throughput = try vail.crypto.p521.ThroughputPreparedVerifier.init(
        public_key,
    );
    const compact = try vail.crypto.p521.CompactPreparedVerifier.init(
        public_key,
    );

    for (0..warmup_iterations) |_| {
        try vail.crypto.p521.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
            public_key,
        );
        try parsed.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
        );
        try prepared.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
        );
        try throughput.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
        );
        try compact.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
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
    const parsed_start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(signature[0]);
        try parsed.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
        );
    }
    const parsed_elapsed = nowNs(init.io) -| parsed_start;
    const prepared_start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(signature[0]);
        try prepared.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
        );
    }
    const prepared_elapsed = nowNs(init.io) -| prepared_start;
    const throughput_start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(signature[0]);
        try throughput.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
        );
    }
    const throughput_elapsed = nowNs(init.io) -| throughput_start;
    const compact_start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(signature[0]);
        try compact.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &signature,
        );
    }
    const compact_elapsed = nowNs(init.io) -| compact_start;
    const prepared_init_start = nowNs(init.io);
    for (0..init_iterations) |_| {
        var initialized = try vail.crypto.p521.PreparedVerifier.init(
            public_key,
        );
        std.mem.doNotOptimizeAway(&initialized);
    }
    const prepared_init_elapsed = nowNs(init.io) -| prepared_init_start;
    const compact_init_start = nowNs(init.io);
    for (0..init_iterations) |_| {
        var initialized = try vail.crypto.p521.CompactPreparedVerifier.init(
            public_key,
        );
        std.mem.doNotOptimizeAway(&initialized);
    }
    const compact_init_elapsed = nowNs(init.io) -| compact_init_start;
    const throughput_init_start = nowNs(init.io);
    for (0..init_iterations) |_| {
        var initialized = try vail.crypto.p521.ThroughputPreparedVerifier.init(
            public_key,
        );
        std.mem.doNotOptimizeAway(&initialized);
    }
    const throughput_init_elapsed = nowNs(init.io) -| throughput_init_start;
    std.debug.print(
        "pure-zig-p521-sha512={d} ns/verify " ++
            "pure-zig-p521-parsed-sha512={d} ns/verify " ++
            "pure-zig-p521-prepared-sha512={d} ns/verify " ++
            "pure-zig-p521-throughput-sha512={d} ns/verify " ++
            "pure-zig-p521-compact-sha512={d} ns/verify " ++
            "pure-zig-p521-prepared-init={d} ns/init " ++
            "pure-zig-p521-compact-init={d} ns/init " ++
            "pure-zig-p521-throughput-init={d} ns/init\n",
        .{
            elapsed / iterations,
            parsed_elapsed / iterations,
            prepared_elapsed / iterations,
            throughput_elapsed / iterations,
            compact_elapsed / iterations,
            prepared_init_elapsed / init_iterations,
            compact_init_elapsed / init_iterations,
            throughput_init_elapsed / init_iterations,
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
