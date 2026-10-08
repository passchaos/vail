const std = @import("std");
const vail = @import("vail");

const MlDsa = std.crypto.sign.mldsa.MLDSA65;
const iterations: usize = 5_000;
const warmup_iterations: usize = 32;

pub fn main(init: std.process.Init) !void {
    var seed = [_]u8{0x5a} ** MlDsa.seed_length;
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var key_pair = try vail.crypto.mldsa.generateKeyPair65(seed);
        checksum +%= key_pair.public_key_bytes[iteration % key_pair.public_key_bytes.len];
        key_pair.deinit();
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&seed);
        var key_pair = try vail.crypto.mldsa.generateKeyPair65(seed);
        checksum +%= key_pair.public_key_bytes[iteration % key_pair.public_key_bytes.len];
        key_pair.deinit();
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-mldsa65-keygen-accelerated={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
