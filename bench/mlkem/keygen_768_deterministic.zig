const std = @import("std");
const vail = @import("vail");

const MLKem = vail.crypto.mlkem.nist.MLKem768;
const iterations: usize = 100_000;
const warmup_iterations: usize = 128;

pub fn main(init: std.process.Init) !void {
    var seed = [_]u8{0x42} ** MLKem.seed_length;
    defer std.crypto.secureZero(u8, &seed);
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var generated = try MLKem.SecretKey.generateDeterministic(seed);
        std.mem.doNotOptimizeAway(&generated);
        checksum +%= seed[0];
        generated.wipe();
    }

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var generated = try MLKem.SecretKey.generateDeterministic(seed);
        std.mem.doNotOptimizeAway(&generated);
        checksum +%= seed[0];
        generated.wipe();
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "pure-zig-mlkem768-keygen={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
