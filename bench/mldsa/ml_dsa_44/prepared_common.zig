const std = @import("std");
const vail = @import("vail");

const MlDsa = std.crypto.sign.mldsa.MLDSA44;
const iterations: usize = 20_000;
const warmup_iterations: usize = 64;

pub const Mode = enum {
    zig_std,
    cached_t1_ntt,
};

pub fn run(init: std.process.Init, comptime mode: Mode) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(.{0x5a} ** 32);
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);

    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    const signature_bytes = (try key_pair.sign(&message, null)).toBytes();

    if (comptime mode == .zig_std) {
        try benchmarkStd(
            init.io,
            &key_pair.public_key,
            &message,
            &signature_bytes,
        );
    } else {
        const prepared = vail.crypto.mldsa.PreparedVerifier44.init(
            &key_pair.public_key,
        );
        try benchmarkCached(
            init.io,
            &prepared,
            &message,
            &signature_bytes,
        );
    }
}

fn benchmarkStd(
    io: std.Io,
    public_key: *const MlDsa.PublicKey,
    message: *const [128]u8,
    signature_bytes: *const [MlDsa.Signature.encoded_length]u8,
) !void {
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        const signature = try MlDsa.Signature.fromBytes(signature_bytes.*);
        try signature.verify(message, public_key.*);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(signature_bytes);
        const signature = try MlDsa.Signature.fromBytes(signature_bytes.*);
        try signature.verify(message, public_key.*);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "mldsa44-prepared-std={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn benchmarkCached(
    io: std.Io,
    prepared: *const vail.crypto.mldsa.PreparedVerifier44,
    message: *const [128]u8,
    signature_bytes: *const [MlDsa.Signature.encoded_length]u8,
) !void {
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            signature_bytes,
        );
        try prepared.verifyPrepared(&signature, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(signature_bytes);
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            signature_bytes,
        );
        try prepared.verifyPrepared(&signature, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "mldsa44-prepared-cached-t1-ntt={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
