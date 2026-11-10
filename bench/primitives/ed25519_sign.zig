const std = @import("std");
const vail = @import("vail");

const Ed25519 = std.crypto.sign.Ed25519;
const Curve = Ed25519.Curve;
const VailEd25519 = vail.crypto.ed25519;
const VailX25519 = vail.crypto.x25519.X25519;
const iterations: usize = 100_000;
const warmup_iterations: usize = 64;
const message = "Vail Ed25519 benchmark input";

pub fn main(init: std.process.Init) !void {
    const seed = [_]u8{0x42} ** Ed25519.KeyPair.seed_length;
    const key_pair = try VailEd25519.generateKeyPairDeterministic(seed);
    var prepared = try VailEd25519.PreparedSigner.init(key_pair);
    defer prepared.deinit();
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        const signature = try VailEd25519.sign(key_pair, message, null);
        checksum +%= signature.toBytes()[iteration % 64];
    }
    var start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const signature = try VailEd25519.sign(key_pair, message, null);
        checksum +%= signature.toBytes()[iteration % 64];
    }
    const one_shot_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        const signature = try prepared.signDeterministic(message);
        checksum +%= signature.toBytes()[iteration % 64];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const signature = try prepared.signDeterministic(message);
        checksum +%= signature.toBytes()[iteration % 64];
    }
    const prepared_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const expanded = VailEd25519.testing.hashSeed(seed);
        std.mem.doNotOptimizeAway(&expanded);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const expanded = VailEd25519.testing.hashSeed(seed);
        checksum +%= expanded[iteration % expanded.len];
    }
    const expand_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        var candidate = try VailEd25519.PreparedSigner.init(key_pair);
        std.mem.doNotOptimizeAway(&candidate);
        candidate.deinit();
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        var candidate = try VailEd25519.PreparedSigner.init(key_pair);
        checksum +%= candidate.scalar[iteration % candidate.scalar.len];
        candidate.deinit();
    }
    const prepare_ns = nowNs(init.io) -| start;

    var wide = [_]u8{0x69} ** 64;
    for (0..warmup_iterations) |iteration| {
        wide[0] = @truncate(iteration);
        const reduced = VailEd25519.testing.reduce64(wide);
        std.mem.doNotOptimizeAway(&reduced);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        wide[0] = @truncate(iteration);
        const reduced = VailEd25519.testing.reduce64(wide);
        checksum +%= reduced[iteration % reduced.len];
    }
    const reduce_ns = nowNs(init.io) -| start;

    const nonce = Curve.scalar.reduce64([_]u8{0x37} ** 64);
    const challenge = Curve.scalar.reduce64([_]u8{0x59} ** 64);
    for (0..warmup_iterations) |_| {
        const response = VailEd25519.testing.mulAdd(
            challenge,
            prepared.scalar,
            nonce,
        );
        std.mem.doNotOptimizeAway(&response);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const response = VailEd25519.testing.mulAdd(
            challenge,
            prepared.scalar,
            nonce,
        );
        checksum +%= response[iteration % response.len];
    }
    const mul_add_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const encoded = try VailX25519.mulEdwardsBaseEncoded(nonce);
        std.mem.doNotOptimizeAway(&encoded);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const encoded = try VailX25519.mulEdwardsBaseEncoded(nonce);
        checksum +%= encoded[iteration % encoded.len];
    }
    const base_ns = nowNs(init.io) -| start;

    std.debug.print(
        "vail-ed25519-sign={d} ns/op prepared={d} ns/op " ++
            "seed-sha512={d} ns/op prepare={d} ns/op " ++
            "reduce64={d} ns/op mul-add={d} ns/op base={d} ns/op " ++
            "checksum={d}\n",
        .{
            one_shot_ns / iterations,
            prepared_ns / iterations,
            expand_ns / iterations,
            prepare_ns / iterations,
            reduce_ns / iterations,
            mul_add_ns / iterations,
            base_ns / iterations,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
