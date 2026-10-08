const std = @import("std");
const vail = @import("vail");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const verify_iterations: usize = 100_000;
const prepare_iterations: usize = 5_000;
const warmup_iterations: usize = 32;
const message = "Vail P-256 verification benchmark input";
const public_key_bytes = decodeHex(
    "042ca00e33928e5b66cc63a70e91c78f5d9e0db34711f9108778151912d389c5" ++
        "89c6c886572fd6dad9d01e0b98c5fec3276e9a2e4b89705140f564f7eb65016b95",
);
const signature_bytes = decodeHex(
    "304502207dceeb937f45830524392b71592522427449295e473662fc05ddaf24a190" ++
        "d0a0022100f2484127a1165596d1a8dfe11a3d1e2a4b0d6983dde8af7fcd065d664" ++
        "cbc576c",
);

pub fn main(init: std.process.Init) !void {
    const public_key = try Ecdsa.PublicKey.fromSec1(&public_key_bytes);
    const signature = try Ecdsa.Signature.fromDer(&signature_bytes);
    var verifier = try vail.crypto.p256.PreparedVerifier.init(public_key.p);
    std.mem.doNotOptimizeAway(&verifier);

    for (0..warmup_iterations) |_| {
        try verifier.verify(
            std.crypto.hash.sha2.Sha256,
            message,
            signature,
        );
    }
    var start = nowNs(init.io);
    for (0..verify_iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try verifier.verify(
            std.crypto.hash.sha2.Sha256,
            message,
            signature,
        );
    }
    const verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const prepared = try vail.crypto.p256.PreparedVerifier.init(
            public_key.p,
        );
        std.mem.doNotOptimizeAway(&prepared);
    }
    start = nowNs(init.io);
    for (0..prepare_iterations) |_| {
        const prepared = try vail.crypto.p256.PreparedVerifier.init(
            public_key.p,
        );
        std.mem.doNotOptimizeAway(&prepared);
    }
    const prepare_ns = nowNs(init.io) -| start;

    std.debug.print(
        "vail-p256-prepared={d} ns/verify prepare={d} ns/op\n",
        .{
            verify_ns / verify_iterations,
            prepare_ns / prepare_iterations,
        },
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
