const std = @import("std");
const vail = @import("vail");

const Sha384 = vail.crypto.sha512.Sha384;
const PreparedHmac = vail.crypto.sha512.PreparedHmac(Sha384);
const iterations: usize = 250_000;
const warmup_iterations: usize = 64;

const Material = struct {
    key: [32]u8,
    iv: [12]u8,
    hp: [32]u8,
};

pub fn main(init: std.process.Init) !void {
    var secret = [_]u8{0x42} ** Sha384.digest_length;
    var checksum: u64 = 0;
    const expected = Material{
        .key = decodeHex(
            "fb68811e875a2d8f746b0b7d0894d9c7" ++
                "f5d7488084755a4c2f3e05afbcb6a6e8",
        ),
        .iv = decodeHex("fc7000d22122c05870b4ff40"),
        .hp = decodeHex(
            "8e2f232374c71ffe78a724bcb0550510" ++
                "1d86613c51b9181768e9ec75f2062593",
        ),
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
        "vail-hkdf-sha384-three-labels={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn derive(secret: *const [Sha384.digest_length]u8) Material {
    // The primitive benchmark excludes erasure on both sides; production
    // callers include PreparedHmac.deinit() in their measured boundaries.
    const expander = PreparedHmac.init(secret);
    return .{
        .key = expander.expandLabel("quic key", "", 32),
        .iv = expander.expandLabel("quic iv", "", 12),
        .hp = expander.expandLabel("quic hp", "", 32),
    };
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
