const std = @import("std");
const vail = @import("vail");

const StdX25519 = std.crypto.dh.X25519;
const X25519 = vail.crypto.x25519.X25519;
const iterations: usize = 100_000;
const warmup_iterations: usize = 64;

pub fn main(init: std.process.Init) !void {
    var secret = [_]u8{0x42} ** X25519.secret_length;
    const peer_secret = [_]u8{0x69} ** X25519.secret_length;
    const peer_public = try X25519.recoverPublicKey(peer_secret);
    const expected_public = try StdX25519.recoverPublicKey(secret);
    const actual_public = try X25519.recoverPublicKey(secret);
    if (!std.mem.eql(u8, &expected_public, &actual_public)) {
        return error.InvalidPublicKey;
    }
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const public = try StdX25519.recoverPublicKey(secret);
        checksum +%= public[iteration % public.len];
    }
    var start = nowNs(init.io);
    for (0..iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const public = try StdX25519.recoverPublicKey(secret);
        checksum +%= public[iteration % public.len];
    }
    const std_public_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const public = try X25519.recoverPublicKey(secret);
        checksum +%= public[iteration % public.len];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const public = try X25519.recoverPublicKey(secret);
        checksum +%= public[iteration % public.len];
    }
    const vail_public_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const shared = try X25519.scalarmult(secret, peer_public);
        checksum +%= shared[iteration % shared.len];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const shared = try X25519.scalarmult(secret, peer_public);
        checksum +%= shared[iteration % shared.len];
    }
    const shared_ns = nowNs(init.io) -| start;

    std.debug.print(
        "zig-std-x25519-public={d} ns/op vail-public={d} ns/op " ++
            "vail-shared={d} ns/op checksum={d}\n",
        .{
            std_public_ns / iterations,
            vail_public_ns / iterations,
            shared_ns / iterations,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
