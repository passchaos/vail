const std = @import("std");
const implementation = @import("mldsa.zig");
const mldsa_avx2 = @import("mldsa_avx2.zig");

const MlDsa44 = implementation.MlDsa44;
const MlDsa65 = implementation.MlDsa65;
const MlDsa87 = implementation.MlDsa87;
const PreparedVerifier44 = implementation.PreparedVerifier44;
const PreparedVerifier65 = implementation.PreparedVerifier65;
const PreparedVerifier87 = implementation.PreparedVerifier87;
const PreparedSignature44 = implementation.PreparedSignature44;
const PreparedSignature65 = implementation.PreparedSignature65;
const PreparedSignature87 = implementation.PreparedSignature87;
const PreparedSigner44 = implementation.PreparedSigner44;
const PreparedSigner65 = implementation.PreparedSigner65;
const PreparedSigner87 = implementation.PreparedSigner87;
const publicKey44FromBytes = implementation.publicKey44FromBytes;
const keyPair44FromSeed = implementation.keyPair44FromSeed;
const generateKeyPair44 = implementation.generateKeyPair44;
const generateKeyPair65 = implementation.generateKeyPair65;
const generateKeyPair87 = implementation.generateKeyPair87;

const coefficient_count = 256;
const modulus: u32 = 8_380_417;

fn signMask(value: u32) u32 {
    return @bitCast(@as(i32, @bitCast(value)) >> 31);
}

fn reduceLe2Q(value: u32) u32 {
    const high = value >> 23;
    const low = value & 0x7fffff;
    return low +% (high << 13) -% high;
}

fn normalizeSignedNtt(value: i32) u32 {
    const positive: u32 = @intCast(@as(i64, value) + 6 * @as(i64, modulus));
    const at_most_2q = reduceLe2Q(positive);
    const reduced = at_most_2q -% modulus;
    return reduced +% (signMask(reduced) & modulus);
}

test "prepared ML-DSA-44 verifier matches Zig std for every fixed-signature byte" {
    var key_pair = try MlDsa44.KeyPair.generateDeterministic(.{0x5a} ** 32);
    defer std.crypto.secureZero(MlDsa44.KeyPair, (&key_pair)[0..1]);

    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    const fixed_signature = (try key_pair.sign(&message, null)).toBytes();
    const prepared = PreparedVerifier44.init(&key_pair.public_key);

    if (comptime mldsa_avx2.enabled) {
        const standard_signature = try MlDsa44.Signature.fromBytes(fixed_signature);
        const accelerated_signature = try PreparedSignature44.fromBytes(
            &fixed_signature,
        );
        try std.testing.expectEqual(
            standard_signature.c_tilde,
            accelerated_signature.c_tilde,
        );
        try std.testing.expectEqual(
            standard_signature.hint,
            accelerated_signature.hint,
        );
        for (0..4) |poly_index| {
            for (0..coefficient_count) |index| {
                try std.testing.expectEqual(
                    standard_signature.z.ps[poly_index].cs[index],
                    normalizeSignedNtt(
                        @bitCast(accelerated_signature.z.ps[poly_index].cs[index]),
                    ),
                );
            }
        }
    }

    try std.testing.expect(standardAccepts(
        fixed_signature,
        &message,
        key_pair.public_key,
    ));
    try std.testing.expect(preparedAccepts(
        fixed_signature,
        &message,
        &prepared,
    ));

    for (0..fixed_signature.len) |index| {
        var mutated = fixed_signature;
        mutated[index] ^= 1;
        try std.testing.expectEqual(
            standardAccepts(mutated, &message, key_pair.public_key),
            preparedAccepts(mutated, &message, &prepared),
        );
    }

    const context = "prepared-verifier-oracle";
    const contextual_signature = try key_pair.signWithContext(
        &message,
        null,
        context,
    );
    try contextual_signature.verifyWithContext(
        &message,
        key_pair.public_key,
        context,
    );
    try prepared.verifyWithContext(contextual_signature, &message, context);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        prepared.verifyWithContext(contextual_signature, &message, "wrong"),
    );
}

test "prepared ML-DSA-44 signer matches Zig std and verifies across noise inputs" {
    var key_pair = try MlDsa44.KeyPair.generateDeterministic(.{0x5a} ** 32);
    defer std.crypto.secureZero(MlDsa44.KeyPair, (&key_pair)[0..1]);
    var prepared = PreparedSigner44.init(&key_pair.secret_key);
    defer prepared.deinit();

    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);

    const expected = (try key_pair.sign(&message, null)).toBytes();
    const actual = prepared.sign(&message, .{0} ** MlDsa44.noise_length);
    try std.testing.expectEqual(expected, actual);

    inline for ([_]u8{ 1, 0x5a, 0xff }) |noise_byte| {
        const signature_bytes = prepared.sign(
            &message,
            .{noise_byte} ** MlDsa44.noise_length,
        );
        const signature = try MlDsa44.Signature.fromBytes(signature_bytes);
        try signature.verify(&message, key_pair.public_key);
    }

    const context = "prepared-signer-oracle";
    const context_noise = [_]u8{0xa5} ** MlDsa44.noise_length;
    const expected_context = (try key_pair.signWithContext(
        &message,
        context_noise,
        context,
    )).toBytes();
    const actual_context = try prepared.signWithContext(
        &message,
        context_noise,
        context,
    );
    try std.testing.expectEqual(expected_context, actual_context);
    try std.testing.expectError(
        error.ContextTooLong,
        prepared.signWithContext(&message, context_noise, &([_]u8{0} ** 256)),
    );

    var wiped = PreparedSigner44.init(&key_pair.secret_key);
    wiped.deinit();
    for (std.mem.asBytes(&wiped)) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "prepared ML-DSA-65 signer matches Zig std and verifies across noise inputs" {
    try testPreparedSignerWide(MlDsa65, PreparedSigner65, 0x65);
}

test "prepared ML-DSA-87 signer matches Zig std and verifies across noise inputs" {
    try testPreparedSignerWide(MlDsa87, PreparedSigner87, 0x87);
}

fn testPreparedSignerWide(
    comptime MlDsa: type,
    comptime PreparedSigner: type,
    comptime seed_byte: u8,
) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(
        .{seed_byte} ** MlDsa.seed_length,
    );
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    var prepared = PreparedSigner.init(&key_pair.secret_key);
    defer prepared.deinit();

    var message: [128]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    const deterministic_noise = [_]u8{0} ** MlDsa.noise_length;
    const expected = (try key_pair.sign(&message, deterministic_noise)).toBytes();
    const actual = prepared.sign(&message, deterministic_noise);
    try std.testing.expectEqual(expected, actual);

    inline for ([_]u8{ 1, 0x5a, 0xff }) |noise_byte| {
        const signature_bytes = prepared.sign(
            &message,
            .{noise_byte} ** MlDsa.noise_length,
        );
        const signature = try MlDsa.Signature.fromBytes(signature_bytes);
        try signature.verify(&message, key_pair.public_key);
    }

    const context = "prepared-wide-signer-oracle";
    const context_noise = [_]u8{0xa5} ** MlDsa.noise_length;
    const expected_context = (try key_pair.signWithContext(
        &message,
        context_noise,
        context,
    )).toBytes();
    const actual_context = try prepared.signWithContext(
        &message,
        context_noise,
        context,
    );
    try std.testing.expectEqual(expected_context, actual_context);

    const secret_bytes = key_pair.secret_key.toBytes();
    var decoded = try PreparedSigner.fromBytes(&secret_bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(
        actual,
        decoded.sign(&message, deterministic_noise),
    );

    var wiped = PreparedSigner.init(&key_pair.secret_key);
    wiped.deinit();
    for (std.mem.asBytes(&wiped)) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "accelerated ML-DSA-44 key generation matches Zig std byte for byte" {
    inline for ([_]u8{ 0, 0x5a, 0xff }) |seed_byte| {
        const seed = [_]u8{seed_byte} ** MlDsa44.seed_length;
        var expected = try MlDsa44.KeyPair.generateDeterministic(seed);
        defer std.crypto.secureZero(MlDsa44.KeyPair, (&expected)[0..1]);
        var actual = try keyPair44FromSeed(seed);
        defer std.crypto.secureZero(MlDsa44.KeyPair, (&actual)[0..1]);
        try std.testing.expectEqual(
            expected.public_key.toBytes(),
            actual.public_key.toBytes(),
        );
        try std.testing.expectEqual(
            expected.secret_key.toBytes(),
            actual.secret_key.toBytes(),
        );

        var compact = try generateKeyPair44(seed);
        defer compact.deinit();
        try std.testing.expectEqual(
            expected.public_key.toBytes(),
            compact.public_key_bytes,
        );
        try std.testing.expectEqual(
            expected.secret_key.toBytes(),
            compact.secret_key_bytes,
        );

        const message = "accelerated ML-DSA-44 key generation oracle";
        const signature = try actual.sign(message, null);
        try signature.verify(message, expected.public_key);
        var compact_signer = try compact.preparedSigner();
        defer compact_signer.deinit();
        const compact_signature = compact_signer.sign(
            message,
            .{0} ** MlDsa44.noise_length,
        );
        const decoded_signature = try MlDsa44.Signature.fromBytes(
            compact_signature,
        );
        try decoded_signature.verify(message, expected.public_key);
        try std.testing.expectEqual(
            (try expected.sign(message, null)).toBytes(),
            compact_signature,
        );
    }
}

test "accelerated ML-DSA-87 compact key generation matches Zig std byte for byte" {
    inline for ([_]u8{ 0, 0x5a, 0xff }) |seed_byte| {
        const seed = [_]u8{seed_byte} ** MlDsa87.seed_length;
        var expected = try MlDsa87.KeyPair.generateDeterministic(seed);
        defer std.crypto.secureZero(MlDsa87.KeyPair, (&expected)[0..1]);
        var actual = try generateKeyPair87(seed);
        defer actual.deinit();
        try std.testing.expectEqual(
            expected.public_key.toBytes(),
            actual.public_key_bytes,
        );
        try std.testing.expectEqual(
            expected.secret_key.toBytes(),
            actual.secret_key_bytes,
        );

        const message = "accelerated ML-DSA-87 compact key generation oracle";
        var signer = try actual.preparedSigner();
        defer signer.deinit();
        const signature_bytes = signer.sign(
            message,
            .{0} ** MlDsa87.noise_length,
        );
        const signature = try MlDsa87.Signature.fromBytes(signature_bytes);
        try signature.verify(message, expected.public_key);
        try std.testing.expectEqual(
            (try expected.sign(message, null)).toBytes(),
            signature_bytes,
        );
    }
}

test "accelerated ML-DSA-65 compact key generation matches Zig std byte for byte" {
    inline for ([_]u8{ 0, 0x5a, 0xff }) |seed_byte| {
        const seed = [_]u8{seed_byte} ** MlDsa65.seed_length;
        var expected = try MlDsa65.KeyPair.generateDeterministic(seed);
        defer std.crypto.secureZero(MlDsa65.KeyPair, (&expected)[0..1]);
        var actual = try generateKeyPair65(seed);
        defer actual.deinit();
        try std.testing.expectEqual(
            expected.public_key.toBytes(),
            actual.public_key_bytes,
        );
        try std.testing.expectEqual(
            expected.secret_key.toBytes(),
            actual.secret_key_bytes,
        );

        const message = "accelerated ML-DSA-65 compact key generation oracle";
        var signer = try actual.preparedSigner();
        defer signer.deinit();
        const signature_bytes = signer.sign(
            message,
            .{0} ** MlDsa65.noise_length,
        );
        const signature = try MlDsa65.Signature.fromBytes(signature_bytes);
        try signature.verify(message, expected.public_key);
        try std.testing.expectEqual(
            (try expected.sign(message, null)).toBytes(),
            signature_bytes,
        );
    }
}

test "prepared ML-DSA-65 verifier matches Zig std" {
    try testPreparedWide(
        MlDsa65,
        PreparedVerifier65,
        PreparedSignature65,
        0x65,
    );
}

test "prepared ML-DSA-87 verifier matches Zig std" {
    try testPreparedWide(
        MlDsa87,
        PreparedVerifier87,
        PreparedSignature87,
        0x87,
    );
}

fn testPreparedWide(
    comptime MlDsa: type,
    comptime PreparedVerifier: type,
    comptime PreparedSignature: type,
    comptime seed_byte: u8,
) !void {
    var key_pair = try MlDsa.KeyPair.generateDeterministic(
        .{seed_byte} ** MlDsa.seed_length,
    );
    defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
    var message: [173]u8 = undefined;
    for (&message, 0..) |*byte, index| byte.* = @truncate(index *% 149 +% 37);
    const signature_bytes = (try key_pair.sign(&message, null)).toBytes();
    const signature = try PreparedSignature.fromBytes(&signature_bytes);
    const prepared = try PreparedVerifier.fromBytes(
        key_pair.public_key.toBytes(),
    );
    try prepared.verifyPrepared(&signature, &message);

    var wrong_message = message;
    wrong_message[91] ^= 1;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        prepared.verifyPrepared(&signature, &wrong_message),
    );

    for (0..signature_bytes.len) |index| {
        var mutated = signature_bytes;
        mutated[index] ^= 1;
        const expected = standardAcceptsWide(
            MlDsa,
            mutated,
            &message,
            key_pair.public_key,
        );
        const actual = preparedAcceptsWide(
            PreparedSignature,
            mutated,
            &message,
            &prepared,
        );
        try std.testing.expectEqual(expected, actual);
    }
}

fn standardAcceptsWide(
    comptime MlDsa: type,
    signature_bytes: [MlDsa.Signature.encoded_length]u8,
    message: []const u8,
    public_key: MlDsa.PublicKey,
) bool {
    const signature = MlDsa.Signature.fromBytes(signature_bytes) catch return false;
    signature.verify(message, public_key) catch return false;
    return true;
}

fn preparedAcceptsWide(
    comptime PreparedSignature: type,
    signature_bytes: anytype,
    message: []const u8,
    prepared: anytype,
) bool {
    const signature = PreparedSignature.fromBytes(&signature_bytes) catch return false;
    prepared.verifyPrepared(&signature, message) catch return false;
    return true;
}

fn standardAccepts(
    signature_bytes: [MlDsa44.Signature.encoded_length]u8,
    message: []const u8,
    public_key: MlDsa44.PublicKey,
) bool {
    const signature = MlDsa44.Signature.fromBytes(signature_bytes) catch return false;
    signature.verify(message, public_key) catch return false;
    return true;
}

fn preparedAccepts(
    signature_bytes: [MlDsa44.Signature.encoded_length]u8,
    message: []const u8,
    prepared: *const PreparedVerifier44,
) bool {
    const signature = PreparedSignature44.fromBytes(&signature_bytes) catch return false;
    prepared.verifyPrepared(&signature, message) catch return false;
    return true;
}
