const std = @import("std");
const vail = @import("vail");

const kex = vail.tls.key_exchange.p384;
const iterations: usize = 1_000;
const warmup_iterations: usize = 32;

pub fn main(init: std.process.Init) !void {
    var local_secret = [_]u8{0} ** kex.secret_len;
    local_secret[local_secret.len - 1] = 7;
    var peer_secret = [_]u8{0} ** kex.secret_len;
    peer_secret[peer_secret.len - 1] = 11;
    const peer_public = try kex.publicKey(peer_secret);
    var checksum: u64 = 0;

    for (0..warmup_iterations) |_| {
        std.mem.doNotOptimizeAway(&local_secret);
        const public = try kex.publicKey(local_secret);
        checksum +%= public[public.len - 1];
    }
    const public_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&local_secret);
        const public = try kex.publicKey(local_secret);
        checksum +%= public[iteration % public.len];
    }
    const public_ns = (nowNs(init.io) -| public_start) / iterations;

    for (0..warmup_iterations) |_| {
        std.mem.doNotOptimizeAway(&local_secret);
        std.mem.doNotOptimizeAway(&peer_public);
        const shared = try kex.sharedSecret(local_secret, &peer_public);
        checksum +%= shared[shared.len - 1];
    }
    const shared_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&local_secret);
        std.mem.doNotOptimizeAway(&peer_public);
        const shared = try kex.sharedSecret(local_secret, &peer_public);
        checksum +%= shared[iteration % shared.len];
    }
    const shared_ns = (nowNs(init.io) -| shared_start) / iterations;
    std.debug.print(
        "pure-zig-p384-public={d} ns/op shared={d} ns/op checksum={d}\n",
        .{ public_ns, shared_ns, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
