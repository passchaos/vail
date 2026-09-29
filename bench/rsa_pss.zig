const std = @import("std");
const vail = @import("vail");

const iterations: usize = 500;

pub fn main(init: std.process.Init) !void {
    const vectors = vail.crypto.testing.rsa_signing;
    const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const message = [_]u8{0x42} ** 130;
    var salt = [_]u8{0x51} ** 32;
    var signature: [512]u8 = undefined;
    var checksum: u64 = 0;

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        salt[0] = @truncate(iteration);
        const len = try prepared_key.signPssSha256(
            &message,
            &salt,
            &signature,
        );
        checksum +%= signature[iteration % len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "rsa-2048-pss-sha256={d} ns/sign checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );

    checksum = 0;
    const pkcs1_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const len = try prepared_key.signPkcs1v15Sha256(
            &message,
            &signature,
        );
        checksum +%= signature[iteration % len];
    }
    const pkcs1_elapsed = nowNs(init.io) -| pkcs1_start;
    std.debug.print(
        "rsa-2048-pkcs1-sha256={d} ns/sign checksum={d}\n",
        .{ pkcs1_elapsed / iterations, checksum },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
