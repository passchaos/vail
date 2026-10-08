const std = @import("std");
const vail = @import("vail");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Scalar = std.crypto.ecc.P384.scalar.Scalar;
const Fe = std.crypto.ecc.P384.Fe;
const iterations: usize = 10_000;
const sign_iterations: usize = 1_000;
const warmup_iterations: usize = 32;
const message = "Vail P-384 verification benchmark input";

pub fn main(init: std.process.Init) !void {
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Ecdsa.KeyPair.seed_length,
    );
    const signature = try key_pair.sign(message, null);
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key = try Ecdsa.PublicKey.fromSec1(&encoded_public_key);
    const scalar = try Scalar.fromBytes(signature.s, .big);
    const field = try Fe.fromBytes(signature.r, .big);
    var checksum: u64 = 0;

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

    for (0..warmup_iterations) |_| {
        const inverse = scalar.invert();
        std.mem.doNotOptimizeAway(&inverse);
    }
    var inverse_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const inverse = scalar.invert();
        checksum +%= inverse.toBytes(.little)[iteration % 48];
    }
    const std_inverse_ns = nowNs(init.io) -| inverse_start;

    for (0..warmup_iterations) |_| {
        const inverse = vail.crypto.p384.testing.invertSecret(scalar);
        std.mem.doNotOptimizeAway(&inverse);
    }
    inverse_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const inverse = vail.crypto.p384.testing.invertSecret(scalar);
        checksum +%= inverse.toBytes(.little)[iteration % 48];
    }
    const secret_inverse_ns = nowNs(init.io) -| inverse_start;

    var multiply_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const product = scalar.mul(scalar);
        checksum +%= product.toBytes(.little)[iteration % 48];
    }
    const std_multiply_ns = nowNs(init.io) -| multiply_start;
    multiply_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const product = vail.crypto.p384.testing.mulSecretScalars(
            scalar,
            scalar,
        );
        checksum +%= product.toBytes(.little)[iteration % 48];
    }
    const secret_multiply_ns = nowNs(init.io) -| multiply_start;

    for (0..warmup_iterations) |_| {
        const inverse = vail.crypto.p384.testing.invertPublic(scalar);
        std.mem.doNotOptimizeAway(&inverse);
    }
    inverse_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const inverse = vail.crypto.p384.testing.invertPublic(scalar);
        checksum +%= inverse.toBytes(.little)[iteration % 48];
    }
    const vail_inverse_ns = nowNs(init.io) -| inverse_start;

    for (0..warmup_iterations) |_| {
        const inverse = vail.crypto.p384.testing.invertFieldStd(field);
        std.mem.doNotOptimizeAway(&inverse);
    }
    inverse_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const inverse = vail.crypto.p384.testing.invertFieldStd(field);
        checksum +%= inverse.toBytes(.little)[iteration % 48];
    }
    const std_field_inverse_ns = nowNs(init.io) -| inverse_start;

    for (0..warmup_iterations) |_| {
        const inverse = vail.crypto.p384.testing.invertField(field);
        std.mem.doNotOptimizeAway(&inverse);
    }
    inverse_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const inverse = vail.crypto.p384.testing.invertField(field);
        checksum +%= inverse.toBytes(.little)[iteration % 48];
    }
    const field_inverse_ns = nowNs(init.io) -| inverse_start;

    for (0..warmup_iterations) |_| {
        const point = vail.crypto.p384.testing.mulBase(scalar);
        std.mem.doNotOptimizeAway(&point);
    }
    const base_start = nowNs(init.io);
    for (0..sign_iterations) |iteration| {
        const point = vail.crypto.p384.testing.mulBase(scalar);
        checksum +%= point.x.toBytes(.little)[iteration % 48];
    }
    const base_ns = nowNs(init.io) -| base_start;

    for (0..warmup_iterations) |_| {
        const generated = try key_pair.sign(message, null);
        std.mem.doNotOptimizeAway(&generated);
    }
    const sign_start = nowNs(init.io);
    for (0..sign_iterations) |iteration| {
        const generated = try key_pair.sign(message, null);
        checksum +%= generated.r[iteration % generated.r.len];
    }
    const sign_ns = nowNs(init.io) -| sign_start;

    for (0..warmup_iterations) |_| {
        const generated = try vail.crypto.p384.sign(
            std.crypto.hash.sha2.Sha384,
            key_pair,
            message,
            null,
        );
        std.mem.doNotOptimizeAway(&generated);
    }
    const vail_sign_start = nowNs(init.io);
    for (0..sign_iterations) |iteration| {
        const generated = try vail.crypto.p384.sign(
            std.crypto.hash.sha2.Sha384,
            key_pair,
            message,
            null,
        );
        checksum +%= generated.r[iteration % generated.r.len];
    }
    const vail_sign_ns = nowNs(init.io) -| vail_sign_start;
    std.debug.print(
        "vail-p384-sha384={d} ns/verify std-inverse={d} ns/op " ++
            "secret-inverse={d} ns/op std-mul={d} ns/op " ++
            "secret-mul={d} ns/op vail-inverse={d} ns/op " ++
            "std-field-inverse={d} ns/op field-inverse={d} ns/op " ++
            "base-mul={d} ns/op std-sign={d} ns/op " ++
            "vail-sign={d} ns/op checksum={d}\n",
        .{
            elapsed / iterations,
            std_inverse_ns / iterations,
            secret_inverse_ns / iterations,
            std_multiply_ns / iterations,
            secret_multiply_ns / iterations,
            vail_inverse_ns / iterations,
            std_field_inverse_ns / iterations,
            field_inverse_ns / iterations,
            base_ns / sign_iterations,
            sign_ns / sign_iterations,
            vail_sign_ns / sign_iterations,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
