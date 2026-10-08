const std = @import("std");

const iterations: usize = 5_000;
const warmup_iterations: usize = 32;

pub fn run(
    init: std.process.Init,
    comptime MlDsa: type,
    comptime name: []const u8,
) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(.{0x5a} ** 32);
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        init.io.randomSecure(&noise) catch return error.RandomUnavailable;
        var signer = try key_pair.signer(noise);
        signer.update(&message);
        const encoded = signer.finalize().toBytes();
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, std.mem.asBytes(&signer.h));
        std.crypto.secureZero(u8, &signer.rnd);
        std.crypto.secureZero(u8, &noise);
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        init.io.randomSecure(&noise) catch return error.RandomUnavailable;
        var signer = try key_pair.signer(noise);
        signer.update(&message);
        const encoded = signer.finalize().toBytes();
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, std.mem.asBytes(&signer.h));
        std.crypto.secureZero(u8, &signer.rnd);
        std.crypto.secureZero(u8, &noise);
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-random-sign-zig-std={d} ns/op checksum={d}\n",
        .{ name, elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
