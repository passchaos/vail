const std = @import("std");
const vail = @import("vail");

const MlDsa = std.crypto.sign.mldsa.MLDSA44;
const iterations: usize = 10_000;
const warmup_iterations: usize = 32;

pub fn main(init: std.process.Init) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(.{0x5a} ** 32);
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    const public_bytes = key_pair.public_key.toBytes();

    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    const signature_bytes = (try key_pair.sign(&message, null)).toBytes();

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        const prepared = try vail.crypto.mldsa.PreparedVerifier44.fromBytes(public_bytes);
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            &signature_bytes,
        );
        try prepared.verifyPrepared(&signature, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&public_bytes);
        std.mem.doNotOptimizeAway(&signature_bytes);
        const prepared = try vail.crypto.mldsa.PreparedVerifier44.fromBytes(public_bytes);
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            &signature_bytes,
        );
        try prepared.verifyPrepared(&signature, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-mldsa44-raw-verify={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
