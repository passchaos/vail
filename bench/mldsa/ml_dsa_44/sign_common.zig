const std = @import("std");
const vail = @import("vail");

const MlDsa = std.crypto.sign.mldsa.MLDSA44;
const iterations: usize = 5_000;
const warmup_iterations: usize = 32;

pub const Mode = enum {
    zig_std,
    prepared,
};

pub fn run(init: std.process.Init, comptime mode: Mode) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(.{0x5a} ** 32);
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);

    if (comptime mode == .zig_std) {
        try benchmarkStd(init.io, &key_pair, &message);
    } else {
        var prepared = vail.crypto.mldsa.PreparedSigner44.init(
            &key_pair.secret_key,
        );
        defer prepared.deinit();
        try benchmarkPrepared(init.io, &prepared, &message);
    }
}

fn benchmarkStd(
    io: std.Io,
    key_pair: *const MlDsa.KeyPair,
    message: *const [128]u8,
) !void {
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        io.randomSecure(&noise) catch return error.RandomUnavailable;
        var signer = try key_pair.signer(noise);
        signer.update(message);
        const encoded = signer.finalize().toBytes();
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, std.mem.asBytes(&signer.h));
        std.crypto.secureZero(u8, &signer.rnd);
        std.crypto.secureZero(u8, &noise);
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        io.randomSecure(&noise) catch return error.RandomUnavailable;
        var signer = try key_pair.signer(noise);
        signer.update(message);
        const encoded = signer.finalize().toBytes();
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, std.mem.asBytes(&signer.h));
        std.crypto.secureZero(u8, &signer.rnd);
        std.crypto.secureZero(u8, &noise);
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "mldsa44-sign-std={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn benchmarkPrepared(
    io: std.Io,
    prepared: *const vail.crypto.mldsa.PreparedSigner44,
    message: *const [128]u8,
) !void {
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        io.randomSecure(&noise) catch return error.RandomUnavailable;
        const encoded = prepared.sign(message, noise);
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, &noise);
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        io.randomSecure(&noise) catch return error.RandomUnavailable;
        const encoded = prepared.sign(message, noise);
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, &noise);
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "mldsa44-sign-prepared={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
