const std = @import("std");
const vail = @import("vail");

const X25519 = vail.crypto.x25519.X25519;
const iterations: usize = 100_000;
const warmup_iterations: usize = 64;

pub fn main(init: std.process.Init) !void {
    var secret = [_]u8{0x42} ** X25519.secret_length;
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const public_key = try X25519.recoverPublicKey(secret);
        checksum +%= public_key[iteration % public_key.len];
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const public_key = try X25519.recoverPublicKey(secret);
        checksum +%= public_key[iteration % public_key.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-x25519-public={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
