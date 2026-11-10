const std = @import("std");
const vail = @import("vail");

const Ed25519 = std.crypto.sign.Ed25519;
const iterations: usize = 50_000;
const warmup_iterations: usize = 64;
const message = "Vail Ed25519 benchmark input";

pub fn main(init: std.process.Init) !void {
    const key_pair = try vail.crypto.ed25519.generateKeyPairDeterministic(
        [_]u8{0x42} ** Ed25519.KeyPair.seed_length,
    );
    const signature = try vail.crypto.ed25519.sign(
        key_pair,
        message,
        null,
    );
    try vail.crypto.ed25519.verify(signature, message, key_pair.public_key);

    for (0..warmup_iterations) |_| {
        try vail.crypto.ed25519.verify(
            signature,
            message,
            key_pair.public_key,
        );
    }
    const start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try vail.crypto.ed25519.verify(
            signature,
            message,
            key_pair.public_key,
        );
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print("vail-ed25519={d} ns/verify\n", .{
        elapsed / iterations,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
