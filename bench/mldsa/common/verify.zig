const std = @import("std");
const vail = @import("vail");

const prepared_iterations: usize = 10_000;
const raw_iterations: usize = 2_000;
const warmup_iterations: usize = 32;

pub fn run(
    init: std.process.Init,
    comptime MlDsa: type,
    comptime PreparedVerifier: type,
    comptime PreparedSignature: type,
    comptime name: []const u8,
    comptime seed_byte: u8,
    comptime signature_scheme: u16,
) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(
        .{seed_byte} ** MlDsa.seed_length,
    );
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    const public_bytes = key_pair.public_key.toBytes();
    const signature_bytes = (try key_pair.sign(&message, null)).toBytes();
    const prepared = PreparedVerifier.init(&key_pair.public_key);

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        const signature = try PreparedSignature.fromBytes(&signature_bytes);
        try prepared.verifyPrepared(&signature, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    var start = nowNs(init.io);
    for (0..prepared_iterations) |iteration| {
        std.mem.doNotOptimizeAway(&signature_bytes);
        const signature = try PreparedSignature.fromBytes(&signature_bytes);
        try prepared.verifyPrepared(&signature, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    var elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-prepared-key-verify={d} ns/op checksum={d}\n",
        .{ name, elapsed / prepared_iterations, checksum },
    );

    checksum = 0;
    for (0..warmup_iterations) |iteration| {
        const raw_key = try PreparedVerifier.fromBytes(public_bytes);
        const signature = try PreparedSignature.fromBytes(&signature_bytes);
        try raw_key.verifyPrepared(&signature, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    start = nowNs(init.io);
    for (0..raw_iterations) |iteration| {
        std.mem.doNotOptimizeAway(&public_bytes);
        std.mem.doNotOptimizeAway(&signature_bytes);
        const raw_key = try PreparedVerifier.fromBytes(public_bytes);
        const signature = try PreparedSignature.fromBytes(&signature_bytes);
        try raw_key.verifyPrepared(&signature, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-raw-verify={d} ns/op checksum={d}\n",
        .{ name, elapsed / raw_iterations, checksum },
    );

    const parsed = vail.tls.auth.ParsedCertificateVerify{
        .scheme = signature_scheme,
        .signature = &signature_bytes,
    };
    checksum = 0;
    for (0..warmup_iterations) |iteration| {
        try vail.tls.auth.verifySignedContent(&public_bytes, parsed, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    start = nowNs(init.io);
    for (0..raw_iterations) |iteration| {
        std.mem.doNotOptimizeAway(&public_bytes);
        std.mem.doNotOptimizeAway(&signature_bytes);
        try vail.tls.auth.verifySignedContent(&public_bytes, parsed, &message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "vail-{s}-tls-raw-verify={d} ns/op checksum={d}\n",
        .{ name, elapsed / raw_iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
