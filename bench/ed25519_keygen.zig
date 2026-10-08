const std = @import("std");
const vail = @import("vail");

const VailEd25519 = vail.crypto.ed25519;
const iterations: usize = 100_000;
const warmup_iterations: usize = 128;

pub fn main(init: std.process.Init) !void {
    var seed = [_]u8{0x42} ** 32;
    var key_pair = try VailEd25519.generateKeyPairDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key));
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        key_pair = try VailEd25519.generateKeyPairDeterministic(seed);
        std.mem.doNotOptimizeAway(&key_pair);
        checksum +%= key_pair.public_key.toBytes()[iteration % 32];
    }

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        key_pair = try VailEd25519.generateKeyPairDeterministic(seed);
        std.mem.doNotOptimizeAway(&key_pair);
        checksum +%= key_pair.public_key.toBytes()[iteration % 32];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-ed25519-keygen={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
