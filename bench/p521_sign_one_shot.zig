const std = @import("std");
const vail = @import("vail");

const iterations: usize = 10_000;
const warmup_iterations: usize = 32;
const message = "Vail pure Zig P-521 signing benchmark";

pub fn main(init: std.process.Init) !void {
    var secret_key = try vail.crypto.p521.SecretKey.fromBytes(decodeHex(
        "00123456789abcdef00112233445566778899aabbccddeeff1021324354657687" ++
            "98a9bacbdcedfe0f112233445566778899aabbccddeeff00123456789abcdef1234",
    ));
    defer secret_key.deinit();
    var key_pair = try vail.crypto.p521.KeyPair.fromSecretKey(secret_key);
    defer key_pair.deinit();
    var encoded: [vail.crypto.p521.Signature.der_encoded_length_max]u8 =
        undefined;
    var checksum: u64 = 0;

    for (0..warmup_iterations) |_| {
        var prepared = try key_pair.prepareRandomNonce(init.io);
        defer prepared.deinit();
        const signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            &prepared,
        );
        std.mem.doNotOptimizeAway(signature.toDer(&encoded));
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        var prepared = try key_pair.prepareRandomNonce(init.io);
        defer prepared.deinit();
        const signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            &prepared,
        );
        const der = signature.toDer(&encoded);
        checksum +%= der[iteration % der.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "pure-zig-p521-sha512-random-end-to-end={d} ns/sign checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
