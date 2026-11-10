const std = @import("std");
const vail = @import("vail");

const MlDsa = std.crypto.sign.mldsa.MLDSA44;
const keygen_iterations: usize = 2_000;
const prepare_iterations: usize = 2_000;
const sign_iterations: usize = 5_000;
const verify_iterations: usize = 10_000;
const raw_verify_iterations: usize = 2_000;
const warmup_iterations: usize = 16;

pub fn main(init: std.process.Init) !void {
    const kat_seed = decodeHex(
        "f696484048ec21f96cf50a56d0759c44" ++
            "8f3779752f0383d37449690694cf7a68",
    );
    const expected_prefix = decodeHex(
        "bd4e96f9a038ab5e36214fe69c0b1cb8" ++
            "35ef9d7c8417e76aecd152f5cddebec8",
    );
    var kat = try MlDsa.KeyPair.generateDeterministic(kat_seed);
    defer std.crypto.secureZero(MlDsa.KeyPair, (&kat)[0..1]);
    const kat_public = kat.public_key.toBytes();
    if (!std.mem.eql(u8, &expected_prefix, kat_public[0..expected_prefix.len])) {
        return error.InvalidBenchmarkVector;
    }

    const message = benchmarkInput(128);
    var key_pair = try MlDsa.KeyPair.generateDeterministic([_]u8{0x5a} ** 32);
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    const public_bytes = key_pair.public_key.toBytes();
    const generated_signature = try key_pair.sign(&message, null);
    const generated_signature_bytes = generated_signature.toBytes();
    const signature_bytes = fixedSignature();
    if (!std.mem.eql(u8, &generated_signature_bytes, &signature_bytes)) {
        return error.InvalidBenchmarkVector;
    }
    const signature = try MlDsa.Signature.fromBytes(signature_bytes);
    try signature.verify(&message, key_pair.public_key);

    try benchmarkKeygen(init.io);
    try benchmarkPublicKeyPreparation(init.io, &public_bytes);
    try benchmarkRandomizedSigning(init.io, &key_pair, &message);
    try benchmarkPreparedKeyVerification(
        init.io,
        &key_pair.public_key,
        &message,
        &signature_bytes,
    );
    try benchmarkRawVerification(
        init.io,
        &public_bytes,
        &message,
        &signature_bytes,
    );
    try benchmarkTlsRawVerification(
        init.io,
        &public_bytes,
        &message,
        &signature_bytes,
    );
}

fn benchmarkKeygen(io: std.Io) !void {
    var seed = [_]u8{0x5a} ** MlDsa.seed_length;
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        var key_pair = try vail.crypto.mldsa.generateKeyPair44(seed);
        const public_key = key_pair.public_key_bytes;
        checksum +%= public_key[iteration % public_key.len];
        key_pair.deinit();
    }
    const start = nowNs(io);
    for (0..keygen_iterations) |iteration| {
        seed[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&seed);
        var key_pair = try vail.crypto.mldsa.generateKeyPair44(seed);
        const public_key = key_pair.public_key_bytes;
        checksum +%= public_key[iteration % public_key.len];
        key_pair.deinit();
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-mldsa44-keygen-from-seed={d} ns/op checksum={d}\n",
        .{ elapsed / keygen_iterations, checksum },
    );
}

fn benchmarkPublicKeyPreparation(
    io: std.Io,
    public_bytes: *const [MlDsa.PublicKey.encoded_length]u8,
) !void {
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        const public_key = try vail.crypto.mldsa.publicKey44FromBytes(
            public_bytes.*,
        );
        const encoded = public_key.toBytes();
        checksum +%= encoded[iteration % encoded.len];
    }
    const start = nowNs(io);
    for (0..prepare_iterations) |iteration| {
        std.mem.doNotOptimizeAway(public_bytes);
        const public_key = try vail.crypto.mldsa.publicKey44FromBytes(
            public_bytes.*,
        );
        const encoded = public_key.toBytes();
        checksum +%= encoded[iteration % encoded.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-mldsa44-public-key-prepare={d} ns/op checksum={d}\n",
        .{ elapsed / prepare_iterations, checksum },
    );
}

fn benchmarkRandomizedSigning(
    io: std.Io,
    key_pair: *const MlDsa.KeyPair,
    message: *const [128]u8,
) !void {
    var prepared = vail.crypto.mldsa.PreparedSigner44.init(
        &key_pair.secret_key,
    );
    defer prepared.deinit();
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        io.randomSecure(&noise) catch return error.RandomUnavailable;
        const encoded = prepared.sign(message, noise);
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, &noise);
    }
    const start = nowNs(io);
    for (0..sign_iterations) |iteration| {
        var noise: [MlDsa.noise_length]u8 = undefined;
        io.randomSecure(&noise) catch return error.RandomUnavailable;
        const encoded = prepared.sign(message, noise);
        checksum +%= encoded[iteration % encoded.len];
        std.crypto.secureZero(u8, &noise);
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-mldsa44-prepared-random-sign={d} ns/op checksum={d}\n",
        .{ elapsed / sign_iterations, checksum },
    );
}

fn benchmarkPreparedKeyVerification(
    io: std.Io,
    public_key: *const MlDsa.PublicKey,
    message: *const [128]u8,
    signature_bytes: *const [MlDsa.Signature.encoded_length]u8,
) !void {
    const prepared = vail.crypto.mldsa.PreparedVerifier44.init(public_key);
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            signature_bytes,
        );
        try prepared.verifyPrepared(&signature, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const start = nowNs(io);
    for (0..verify_iterations) |iteration| {
        std.mem.doNotOptimizeAway(signature_bytes);
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            signature_bytes,
        );
        try prepared.verifyPrepared(&signature, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-mldsa44-prepared-key-verify={d} ns/op checksum={d}\n",
        .{ elapsed / verify_iterations, checksum },
    );
}

fn benchmarkRawVerification(
    io: std.Io,
    public_bytes: *const [MlDsa.PublicKey.encoded_length]u8,
    message: *const [128]u8,
    signature_bytes: *const [MlDsa.Signature.encoded_length]u8,
) !void {
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        const prepared = try vail.crypto.mldsa.PreparedVerifier44.fromBytes(
            public_bytes.*,
        );
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            signature_bytes,
        );
        try prepared.verifyPrepared(&signature, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const start = nowNs(io);
    for (0..raw_verify_iterations) |iteration| {
        std.mem.doNotOptimizeAway(public_bytes);
        std.mem.doNotOptimizeAway(signature_bytes);
        const prepared = try vail.crypto.mldsa.PreparedVerifier44.fromBytes(
            public_bytes.*,
        );
        const signature = try vail.crypto.mldsa.PreparedSignature44.fromBytes(
            signature_bytes,
        );
        try prepared.verifyPrepared(&signature, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-mldsa44-raw-verify={d} ns/op checksum={d}\n",
        .{ elapsed / raw_verify_iterations, checksum },
    );
}

fn benchmarkTlsRawVerification(
    io: std.Io,
    public_bytes: *const [MlDsa.PublicKey.encoded_length]u8,
    message: *const [128]u8,
    signature_bytes: *const [MlDsa.Signature.encoded_length]u8,
) !void {
    const parsed = vail.tls.auth.ParsedCertificateVerify{
        .scheme = vail.tls.auth.signature_scheme_ml_dsa_44,
        .signature = signature_bytes,
    };
    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        try vail.tls.auth.verifySignedContent(public_bytes, parsed, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const start = nowNs(io);
    for (0..raw_verify_iterations) |iteration| {
        std.mem.doNotOptimizeAway(public_bytes);
        std.mem.doNotOptimizeAway(signature_bytes);
        try vail.tls.auth.verifySignedContent(public_bytes, parsed, message);
        checksum +%= signature_bytes[iteration % signature_bytes.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-mldsa44-tls-raw-verify={d} ns/op checksum={d}\n",
        .{ elapsed / raw_verify_iterations, checksum },
    );
}

fn benchmarkInput(comptime len: usize) [len]u8 {
    var input: [len]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    return input;
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn fixedSignature() [MlDsa.Signature.encoded_length]u8 {
    const encoded = @embedFile("../testdata/mldsa44_signature.hex");
    var result: [MlDsa.Signature.encoded_length]u8 = undefined;
    var high: ?u8 = null;
    var output_index: usize = 0;
    for (encoded) |byte| {
        if (std.ascii.isWhitespace(byte)) continue;
        const nibble = std.fmt.charToDigit(byte, 16) catch unreachable;
        if (high) |value| {
            result[output_index] = value << 4 | nibble;
            output_index += 1;
            high = null;
        } else {
            high = nibble;
        }
    }
    std.debug.assert(high == null);
    std.debug.assert(output_index == result.len);
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
