const std = @import("std");
const vail = @import("vail");

const MLKem = vail.crypto.mlkem.nist.MLKem768;
const Hybrid = vail.tls.key_exchange.x25519_mlkem768;
const iterations: usize = 5_000;
const warmup_iterations: usize = 32;

pub fn main(init: std.process.Init) !void {
    var seed = [_]u8{0x42} ** MLKem.seed_length;
    var encaps_seed = [_]u8{0x69} ** MLKem.encaps_seed_length;
    var key_pair = try MLKem.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    var encapsulated = key_pair.public_key.encapsDeterministic(&encaps_seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&encapsulated));
    const x25519_secret = [_]u8{0x37} ** Hybrid.x25519_secret_len;
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var generated = try MLKem.SecretKey.generateDeterministic(seed);
        std.mem.doNotOptimizeAway(&generated);
        generated.wipe();
    }
    var start = nowNs(init.io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var generated = try MLKem.SecretKey.generateDeterministic(seed);
        std.mem.doNotOptimizeAway(&generated);
        checksum +%= seed[0];
        generated.wipe();
    }
    const keygen_ns = (nowNs(init.io) -| start) / iterations;

    for (0..warmup_iterations) |iteration| {
        encaps_seed[0] = @truncate(iteration);
        const generated = key_pair.public_key.encapsDeterministic(&encaps_seed);
        checksum +%= generated.ciphertext[iteration % MLKem.ciphertext_length];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        encaps_seed[0] = @truncate(iteration);
        const generated = key_pair.public_key.encapsDeterministic(&encaps_seed);
        checksum +%= generated.ciphertext[iteration % MLKem.ciphertext_length];
        std.mem.doNotOptimizeAway(&generated);
    }
    const encaps_ns = (nowNs(init.io) -| start) / iterations;

    for (0..warmup_iterations) |iteration| {
        const shared = try key_pair.secret_key.decaps(&encapsulated.ciphertext);
        checksum +%= shared[iteration % shared.len];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const shared = try key_pair.secret_key.decaps(&encapsulated.ciphertext);
        checksum +%= shared[iteration % shared.len];
        std.mem.doNotOptimizeAway(&shared);
    }
    const decaps_ns = (nowNs(init.io) -| start) / iterations;

    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var started = try Hybrid.clientStart(x25519_secret, seed);
        checksum +%= started.share[iteration % started.share.len];
        started.secret.wipe();
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var started = try Hybrid.clientStart(x25519_secret, seed);
        checksum +%= started.share[iteration % started.share.len];
        started.secret.wipe();
    }
    const hybrid_client_ns = (nowNs(init.io) -| start) / iterations;

    std.debug.print(
        "pure-zig-mlkem768-keygen={d} ns/op encaps={d} ns/op " ++
            "decaps={d} ns/op hybrid-client={d} ns/op checksum={d}\n",
        .{ keygen_ns, encaps_ns, decaps_ns, hybrid_client_ns, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
