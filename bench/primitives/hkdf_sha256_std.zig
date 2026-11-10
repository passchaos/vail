const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.Hkdf(HmacSha256);
const digest_len = HkdfSha256.prk_length;
const iterations: usize = 500_000;
const warmup_iterations: usize = 64;

const Material = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

pub fn main(init: std.process.Init) !void {
    var secret = [_]u8{0x42} ** digest_len;
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const material = derive(secret);
        checksum +%= material.key[0] +% material.iv[0] +% material.hp[0];
    }

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        secret[0] = @truncate(iteration);
        const material = derive(secret);
        checksum +%= material.key[iteration % material.key.len];
        checksum +%= material.iv[iteration % material.iv.len];
        checksum +%= material.hp[iteration % material.hp.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "zig-std-hkdf-sha256-three-labels={d} ns/op checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn derive(secret: [digest_len]u8) Material {
    return .{
        .key = std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            secret,
            "quic key",
            "",
            16,
        ),
        .iv = std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            secret,
            "quic iv",
            "",
            12,
        ),
        .hp = std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            secret,
            "quic hp",
            "",
            16,
        ),
    };
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
