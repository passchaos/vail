const std = @import("std");
const vail = @import("vail");

const Sha256 = vail.crypto.sha256;
const iterations: usize = 500_000;
const warmup_iterations: usize = 64;

const Material = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

pub fn main(init: std.process.Init) !void {
    var secret = [_]u8{0x42} ** Sha256.digest_len;
    var checksum: u64 = 0;
    const expected = Material{
        .key = decodeHex("da4f3a4cddb4f22a0a3480aa02d23e16"),
        .iv = decodeHex("55c937e2671304101facd192"),
        .hp = decodeHex("1fa5fdcb2578e7f3bc03e9965473aa42"),
    };
    const actual = derive(&secret);
    if (!std.mem.eql(u8, &expected.key, &actual.key) or
        !std.mem.eql(u8, &expected.iv, &actual.iv) or
        !std.mem.eql(u8, &expected.hp, &actual.hp))
    {
        return error.InvalidBenchmarkVector;
    }

    for (0..warmup_iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const material = derive(&secret);
        checksum +%= material.key[0] +% material.iv[0] +% material.hp[0];
    }

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const material = derive(&secret);
        checksum +%= material.key[iteration % material.key.len];
        checksum +%= material.iv[iteration % material.iv.len];
        checksum +%= material.hp[iteration % material.hp.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-hkdf-sha256-three-labels={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn derive(secret: *const Sha256.Digest) Material {
    // The primitive benchmark excludes erasure on both sides; production
    // callers include PreparedHmac.deinit() in their measured boundaries.
    var expander: Sha256.PreparedHmac = undefined;
    expander.initInto(secret);
    return .{
        .key = expander.expandLabel("quic key", "", 16),
        .iv = expander.expandLabel("quic iv", "", 12),
        .hp = expander.expandLabel("quic hp", "", 16),
    };
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
