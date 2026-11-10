const std = @import("std");
const vail = @import("vail");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const iterations: usize = 10_000;
const warmup_iterations: usize = 32;
const message = "Vail P-384 verification benchmark input";

pub fn main(init: std.process.Init) !void {
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Ecdsa.KeyPair.seed_length,
    );
    const signature = try key_pair.sign(message, null);
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key = try Ecdsa.PublicKey.fromSec1(&encoded_public_key);

    for (0..warmup_iterations) |_| {
        try vail.crypto.p384.verify(
            std.crypto.hash.sha2.Sha384,
            message,
            signature,
            public_key,
        );
    }
    const start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try vail.crypto.p384.verify(
            std.crypto.hash.sha2.Sha384,
            message,
            signature,
            public_key,
        );
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-p384-sha384={d} ns/verify\n",
        .{elapsed / iterations},
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
