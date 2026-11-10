const std = @import("std");
const vail = @import("vail");

const Ed25519 = std.crypto.sign.Ed25519;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const VailX25519 = @import("vail").crypto.x25519.X25519;
const VailEd25519 = vail.crypto.ed25519;
const iterations: usize = 50_000;
const preparation_iterations: usize = 2_000;
const warmup_iterations: usize = 64;
const message = "Vail Ed25519 benchmark input";

pub fn main(init: std.process.Init) !void {
    const seed = [_]u8{0x42} ** Ed25519.KeyPair.seed_length;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
    const signature = try key_pair.sign(message, null);
    const vail_key_pair = try VailEd25519.generateKeyPairDeterministic(seed);
    const vail_signature = try VailEd25519.sign(vail_key_pair, message, null);
    var prepared_signer = try VailEd25519.PreparedSigner.init(vail_key_pair);
    defer prepared_signer.deinit();
    const prepared_signature = try prepared_signer.signDeterministic(message);
    const prepared_verifier = try VailEd25519.PreparedVerifier.init(
        key_pair.public_key,
    );
    if (!std.mem.eql(
        u8,
        &signature.toBytes(),
        &vail_signature.toBytes(),
    )) return error.InvalidSignature;
    if (!std.mem.eql(
        u8,
        &signature.toBytes(),
        &prepared_signature.toBytes(),
    )) return error.InvalidSignature;
    try signature.verify(message, key_pair.public_key);
    try VailEd25519.verify(signature, message, key_pair.public_key);
    try prepared_verifier.verify(signature, message);
    const scalar = Edwards25519.scalar.reduce64([_]u8{0x69} ** 64);
    const expected_point = try Edwards25519.basePoint.mul(scalar);
    const vail_point = try VailX25519.mulEdwardsBase(scalar);
    if (!std.mem.eql(u8, &expected_point.toBytes(), &vail_point.toBytes())) {
        return error.InvalidBaseMultiplication;
    }
    var checksum: u64 = 0;

    var mutable_seed = seed;
    for (0..warmup_iterations) |iteration| {
        mutable_seed[0] = @truncate(iteration);
        const generated = try Ed25519.KeyPair.generateDeterministic(
            mutable_seed,
        );
        checksum +%= generated.public_key.toBytes()[iteration % 32];
    }
    var start = nowNs(init.io);
    for (0..iterations) |iteration| {
        mutable_seed[0] = @truncate(iteration);
        const generated = try Ed25519.KeyPair.generateDeterministic(
            mutable_seed,
        );
        checksum +%= generated.public_key.toBytes()[iteration % 32];
    }
    const key_pair_ns = nowNs(init.io) -| start;

    mutable_seed = seed;
    for (0..warmup_iterations) |iteration| {
        mutable_seed[0] = @truncate(iteration);
        const generated = try VailEd25519.generateKeyPairDeterministic(
            mutable_seed,
        );
        std.mem.doNotOptimizeAway(&generated);
        checksum +%= generated.public_key.toBytes()[iteration % 32];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        mutable_seed[0] = @truncate(iteration);
        const generated = try VailEd25519.generateKeyPairDeterministic(
            mutable_seed,
        );
        std.mem.doNotOptimizeAway(&generated);
        checksum +%= generated.public_key.toBytes()[iteration % 32];
    }
    const vail_key_pair_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        const point = try Edwards25519.basePoint.mul(scalar);
        checksum +%= point.toBytes()[iteration % 32];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&scalar);
        const point = try Edwards25519.basePoint.mul(scalar);
        checksum +%= point.toBytes()[iteration % 32];
    }
    const base_mul_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        const point = try VailX25519.mulEdwardsBase(scalar);
        checksum +%= point.toBytes()[iteration % 32];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&scalar);
        const point = try VailX25519.mulEdwardsBase(scalar);
        checksum +%= point.toBytes()[iteration % 32];
    }
    const vail_base_mul_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        const generated_signature = try key_pair.sign(message, null);
        checksum +%= generated_signature.toBytes()[iteration % 64];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const generated_signature = try key_pair.sign(message, null);
        checksum +%= generated_signature.toBytes()[iteration % 64];
    }
    const sign_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        const generated_signature = try VailEd25519.sign(
            vail_key_pair,
            message,
            null,
        );
        checksum +%= generated_signature.toBytes()[iteration % 64];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const generated_signature = try VailEd25519.sign(
            vail_key_pair,
            message,
            null,
        );
        checksum +%= generated_signature.toBytes()[iteration % 64];
    }
    const vail_sign_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |iteration| {
        const generated_signature = try prepared_signer.signDeterministic(message);
        checksum +%= generated_signature.toBytes()[iteration % 64];
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const generated_signature = try prepared_signer.signDeterministic(message);
        checksum +%= generated_signature.toBytes()[iteration % 64];
    }
    const prepared_sign_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        try signature.verify(message, key_pair.public_key);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try signature.verify(message, key_pair.public_key);
    }
    const verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        try VailEd25519.verify(signature, message, key_pair.public_key);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try VailEd25519.verify(signature, message, key_pair.public_key);
    }
    const vail_verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const prepared = try VailEd25519.PreparedVerifier.init(
            key_pair.public_key,
        );
        checksum +%= prepared.public_key_bytes[0];
    }
    start = nowNs(init.io);
    for (0..preparation_iterations) |_| {
        std.mem.doNotOptimizeAway(&key_pair.public_key);
        const prepared = try VailEd25519.PreparedVerifier.init(
            key_pair.public_key,
        );
        checksum +%= prepared.public_key_bytes[0];
    }
    const preparation_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        try prepared_verifier.verify(signature, message);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try prepared_verifier.verify(signature, message);
    }
    const prepared_verify_ns = nowNs(init.io) -| start;

    std.debug.print(
        "zig-ed25519-keypair={d} ns/op base-mul={d} ns/op " ++
            "vail-keypair={d} ns/op vail-base-mul={d} ns/op " ++
            "sign={d} ns/op vail-sign={d} ns/op " ++
            "vail-prepared-sign={d} ns/op " ++
            "verify={d} ns/op vail-verify={d} ns/op vail-prepare={d} ns/op " ++
            "vail-prepared-verify={d} ns/op checksum={d}\n",
        .{
            key_pair_ns / iterations,
            base_mul_ns / iterations,
            vail_key_pair_ns / iterations,
            vail_base_mul_ns / iterations,
            sign_ns / iterations,
            vail_sign_ns / iterations,
            prepared_sign_ns / iterations,
            verify_ns / iterations,
            vail_verify_ns / iterations,
            preparation_ns / preparation_iterations,
            prepared_verify_ns / iterations,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
