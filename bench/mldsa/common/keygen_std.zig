const std = @import("std");

const iterations: usize = 5_000;
const warmup_iterations: usize = 32;

pub fn run(
    init: std.process.Init,
    comptime MlDsa: type,
    comptime name: []const u8,
) !void {
    var seed = [_]u8{0x5a} ** MlDsa.seed_length;
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var key_pair = try MlDsa.KeyPair.generateDeterministic(seed);
        const public_key = key_pair.public_key.toBytes();
        checksum +%= public_key[iteration % public_key.len];
        std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&seed);
        var key_pair = try MlDsa.KeyPair.generateDeterministic(seed);
        const public_key = key_pair.public_key.toBytes();
        checksum +%= public_key[iteration % public_key.len];
        std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-keygen-zig-std={d} ns/op checksum={d}\n",
        .{ name, elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
