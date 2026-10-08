const std = @import("std");
const vail = @import("vail");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const iterations: usize = 2_000;
const warmup_iterations: usize = 64;
const message = "Vail P-384 signing benchmark input";

pub fn main(init: std.process.Init) !void {
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Ecdsa.KeyPair.seed_length,
    );
    var nonce_noise: [vail.crypto.p384.secret_key_encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce_noise);
    var encoded: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    var checksum: u64 = 0;

    for (0..warmup_iterations) |_| {
        try init.io.randomSecure(&nonce_noise);
        const signature = try vail.crypto.p384.sign(
            std.crypto.hash.sha2.Sha384,
            key_pair,
            message,
            nonce_noise,
        );
        std.mem.doNotOptimizeAway(signature.toDer(&encoded));
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        try init.io.randomSecure(&nonce_noise);
        const signature = try vail.crypto.p384.sign(
            std.crypto.hash.sha2.Sha384,
            key_pair,
            message,
            nonce_noise,
        );
        const der = signature.toDer(&encoded);
        checksum +%= der[iteration % der.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "pure-zig-p384-sha384={d} ns/sign checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
