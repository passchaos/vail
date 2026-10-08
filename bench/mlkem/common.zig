const std = @import("std");

const iterations: usize = 5_000;
const warmup_iterations: usize = 32;

pub fn run(
    init: std.process.Init,
    comptime MLKem: type,
    comptime name: []const u8,
) !void {
    var setup_seed = [_]u8{0x42} ** MLKem.seed_length;
    defer std.crypto.secureZero(u8, &setup_seed);
    var encaps_seed = [_]u8{0x69} ** MLKem.encaps_seed_length;
    defer std.crypto.secureZero(u8, &encaps_seed);
    var key_pair = try MLKem.KeyPair.generateDeterministic(setup_seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    var encapsulated = key_pair.public_key.encapsDeterministic(&encaps_seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&encapsulated));
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        var seed: [MLKem.seed_length]u8 = undefined;
        init.io.randomSecure(&seed) catch return error.RandomUnavailable;
        var generated = try MLKem.SecretKey.generateDeterministic(seed);
        std.mem.doNotOptimizeAway(&generated);
        checksum +%= seed[iteration % seed.len];
        generated.wipe();
        std.crypto.secureZero(u8, &seed);
    }
    var start = nowNs(init.io);
    for (0..iterations) |iteration| {
        var seed: [MLKem.seed_length]u8 = undefined;
        init.io.randomSecure(&seed) catch return error.RandomUnavailable;
        var generated = try MLKem.SecretKey.generateDeterministic(seed);
        std.mem.doNotOptimizeAway(&generated);
        checksum +%= seed[iteration % seed.len];
        generated.wipe();
        std.crypto.secureZero(u8, &seed);
    }
    var elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-random-keygen={d} ns/op checksum={d}\n",
        .{ name, elapsed / iterations, checksum },
    );

    checksum = 0;
    for (0..warmup_iterations) |iteration| {
        var generated = key_pair.public_key.encaps(init.io);
        checksum +%= generated.ciphertext[iteration % generated.ciphertext.len];
        std.crypto.secureZero(u8, std.mem.asBytes(&generated));
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        var generated = key_pair.public_key.encaps(init.io);
        checksum +%= generated.ciphertext[iteration % generated.ciphertext.len];
        std.mem.doNotOptimizeAway(&generated);
        std.crypto.secureZero(u8, std.mem.asBytes(&generated));
    }
    elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-random-encaps={d} ns/op checksum={d}\n",
        .{ name, elapsed / iterations, checksum },
    );

    checksum = 0;
    for (0..warmup_iterations) |iteration| {
        var shared = try key_pair.secret_key.decaps(&encapsulated.ciphertext);
        checksum +%= shared[iteration % shared.len];
        std.crypto.secureZero(u8, &shared);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        var shared = try key_pair.secret_key.decaps(&encapsulated.ciphertext);
        checksum +%= shared[iteration % shared.len];
        std.mem.doNotOptimizeAway(&shared);
        std.crypto.secureZero(u8, &shared);
    }
    elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-decaps={d} ns/op checksum={d}\n",
        .{ name, elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
