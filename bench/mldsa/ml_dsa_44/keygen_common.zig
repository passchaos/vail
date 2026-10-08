const std = @import("std");
const vail = @import("vail");

const MlDsa = std.crypto.sign.mldsa.MLDSA44;
const iterations: usize = 5_000;
const warmup_iterations: usize = 32;

pub const Mode = enum {
    zig_std,
    accelerated,
};

pub fn run(init: std.process.Init, comptime mode: Mode) !void {
    if (comptime mode == .zig_std) {
        return benchmarkStd(init.io);
    }
    return benchmarkAccelerated(init.io);
}

fn benchmarkStd(io: std.Io) !void {
    var seed = [_]u8{0x5a} ** MlDsa.seed_length;
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var key_pair = try MlDsa.KeyPair.generateDeterministic(seed);
        const public_key = key_pair.public_key.toBytes();
        checksum +%= public_key[iteration % public_key.len];
        vail.crypto.mldsa.wipeKeyPair44(&key_pair);
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&seed);
        var key_pair = try MlDsa.KeyPair.generateDeterministic(seed);
        const public_key = key_pair.public_key.toBytes();
        checksum +%= public_key[iteration % public_key.len];
        vail.crypto.mldsa.wipeKeyPair44(&key_pair);
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "mldsa44-keygen-zig_std={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn benchmarkAccelerated(io: std.Io) !void {
    var seed = [_]u8{0x5a} ** MlDsa.seed_length;
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var key_pair = try vail.crypto.mldsa.generateKeyPair44(seed);
        checksum +%= key_pair.public_key_bytes[iteration % key_pair.public_key_bytes.len];
        key_pair.deinit();
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&seed);
        var key_pair = try vail.crypto.mldsa.generateKeyPair44(seed);
        checksum +%= key_pair.public_key_bytes[iteration % key_pair.public_key_bytes.len];
        key_pair.deinit();
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "mldsa44-keygen-accelerated={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
