//! P-256 ECDSA signing, verification, and ECDH helpers.
//!
//! Verification uses a variable-time Jacobian/wNAF double-scalar multiplication
//! specialized for public ECDSA inputs. The final x-coordinate comparison stays
//! projective, avoiding a field inversion.
//! ECDH uses constant-schedule fixed-base and arbitrary-point multiplication on
//! supported x86_64 targets, with Zig std as the portable fallback.

const std = @import("std");
const builtin = @import("builtin");
const point_adx = @import("p256_point_ops_adx.zig");
const base_mul_x86 = @import("p256_base_mul_x86.zig");
const field_arm64 = @import("p256_field_arm64.zig");
const field_inv_x86 = @import("p256_field_inv_x86.zig");
const scalar_inv_x86 = @import("p256_scalar_inv_x86.zig");
const scalar_mul_x86 = @import("p256_scalar_mul_x86.zig");
const sha256 = @import("sha256.zig");
const FastSha512 = @import("sha512.zig").Sha512;

const P256 = std.crypto.ecc.P256;
const Scalar = P256.scalar.Scalar;
const Fe = P256.Fe;
const table_values = @import("p256_tables.zig");
const base_wnaf_width = 10;
const base_wnaf_entries = 1 << (base_wnaf_width - 2);
const public_wnaf_width = 6;
const public_wnaf_entries = 1 << (public_wnaf_width - 2);
const wnaf_digits = 257;
const comb_groups = 4;
const comb_width = 8;
const comb_entries = 1 << comb_width;
const comb_windows = 8;
const scalar_limb_count = 4;
const ScalarLimbs = [scalar_limb_count]u64;

const WnafEntry = struct {
    position: u16,
    digit: i16,
};

fn Wnaf(comptime width: usize) type {
    return struct {
        entries: [(wnaf_digits + width - 1) / width]WnafEntry,
        len: usize,
    };
}

const scalar_modulus = ScalarLimbs{
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
};
const field_modulus = [4]u64{
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
};
const scalar_negative_inverse = blk: {
    var inverse: u64 = 1;
    for (0..6) |_| {
        inverse *%= 2 -% scalar_modulus[0] *% inverse;
    }
    break :blk 0 -% inverse;
};
const scalar_montgomery_r2 = ScalarLimbs{
    0x8324_4c95_be79_eea2,
    0x4699_799c_49bd_6fa6,
    0x2845_b239_2b6b_ec59,
    0x66e1_2d94_f3d9_5620,
};
const deterministic_candidate_count = 4;
const secret_inversion_window_width = 5;
const secret_inversion_table_entries = 1 << (secret_inversion_window_width - 1);
const InversionStep = struct { squares: u9, table_index: u4 };
const InversionSchedule = struct {
    steps: [128]InversionStep,
    len: usize,
};
const inversion_schedule = buildInversionSchedule();
const use_x86_64_adx_field = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

inline fn opaqueWord(value: u64) u64 {
    if (@inComptime()) return value;
    return asm volatile (""
        : [result] "=r" (-> u64),
        : [input] "0" (value),
    );
}

inline fn wipeCallerSavedRegisters() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        if (comptime builtin.mode != .Debug and std.Target.x86.featureSetHas(
            builtin.cpu.features,
            .avx,
        )) {
            asm volatile ("vzeroall" ::: .{
                    .xmm0 = true,
                    .xmm1 = true,
                    .xmm2 = true,
                    .xmm3 = true,
                    .xmm4 = true,
                    .xmm5 = true,
                    .xmm6 = true,
                    .xmm7 = true,
                    .xmm8 = true,
                    .xmm9 = true,
                    .xmm10 = true,
                    .xmm11 = true,
                    .xmm12 = true,
                    .xmm13 = true,
                    .xmm14 = true,
                    .xmm15 = true,
                    .memory = true,
                });
        } else {
            asm volatile (
                \\pxor %%xmm0, %%xmm0
                \\pxor %%xmm1, %%xmm1
                \\pxor %%xmm2, %%xmm2
                \\pxor %%xmm3, %%xmm3
                \\pxor %%xmm4, %%xmm4
                \\pxor %%xmm5, %%xmm5
                \\pxor %%xmm6, %%xmm6
                \\pxor %%xmm7, %%xmm7
                \\pxor %%xmm8, %%xmm8
                \\pxor %%xmm9, %%xmm9
                \\pxor %%xmm10, %%xmm10
                \\pxor %%xmm11, %%xmm11
                \\pxor %%xmm12, %%xmm12
                \\pxor %%xmm13, %%xmm13
                \\pxor %%xmm14, %%xmm14
                \\pxor %%xmm15, %%xmm15
                ::: .{
                    .xmm0 = true,
                    .xmm1 = true,
                    .xmm2 = true,
                    .xmm3 = true,
                    .xmm4 = true,
                    .xmm5 = true,
                    .xmm6 = true,
                    .xmm7 = true,
                    .xmm8 = true,
                    .xmm9 = true,
                    .xmm10 = true,
                    .xmm11 = true,
                    .xmm12 = true,
                    .xmm13 = true,
                    .xmm14 = true,
                    .xmm15 = true,
                    .memory = true,
                });
        }
        asm volatile (
            \\xorq %%rax, %%rax
            \\xorq %%rcx, %%rcx
            \\xorq %%rdx, %%rdx
            \\xorq %%rsi, %%rsi
            \\xorq %%rdi, %%rdi
            \\xorq %%r8, %%r8
            \\xorq %%r9, %%r9
            \\xorq %%r10, %%r10
            \\xorq %%r11, %%r11
            ::: .{
                .rax = true,
                .rcx = true,
                .rdx = true,
                .rsi = true,
                .rdi = true,
                .r8 = true,
                .r9 = true,
                .r10 = true,
                .r11 = true,
                .memory = true,
            });
    } else {
        asm volatile ("" ::: .{ .memory = true });
    }
}

pub const KeyAgreementError = error{
    InvalidSecretKey,
    InvalidPublicKey,
    KeyAgreementFailed,
};

pub const secret_key_encoded_length = P256.scalar.encoded_length;
pub const uncompressed_sec1_encoded_length = 1 + 2 * P256.Fe.encoded_length;

/// Recover an uncompressed SEC1 public key from a canonical non-zero scalar.
pub fn ecdhPublicKey(
    secret_key_bytes: [secret_key_encoded_length]u8,
) KeyAgreementError![uncompressed_sec1_encoded_length]u8 {
    defer wipeCallerSavedRegisters();
    var owned_secret = secret_key_bytes;
    defer std.crypto.secureZero(u8, &owned_secret);
    var scalar_limbs: ScalarLimbs = undefined;
    if (!decodeCanonicalNonzeroScalar(&scalar_limbs, &owned_secret)) {
        std.crypto.secureZero(u8, std.mem.asBytes(&scalar_limbs));
        return error.InvalidSecretKey;
    }
    defer std.crypto.secureZero(u8, std.mem.asBytes(&scalar_limbs));

    if (comptime base_mul_x86.enabled) {
        var output: [8]u64 = undefined;
        base_mul_x86.scalarMult(
            &output,
            &scalar_limbs,
            &table_values.base_ecdh_block6,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&output));
        var x = encodeScalar(output[0..4].*);
        var y = encodeScalar(output[4..8].*);
        std.mem.reverse(u8, &x);
        std.mem.reverse(u8, &y);
        return .{0x04} ++ x ++ y;
    }

    const public = P256.basePoint.mul(owned_secret, .big) catch
        return error.KeyAgreementFailed;
    return public.toUncompressedSec1();
}

/// Compute a P-256 ECDH shared x-coordinate from a validated SEC1 point.
pub fn ecdhSharedSecret(
    secret_key_bytes: [secret_key_encoded_length]u8,
    peer_public_key_sec1: []const u8,
) KeyAgreementError![P256.Fe.encoded_length]u8 {
    defer wipeCallerSavedRegisters();
    var owned_secret = secret_key_bytes;
    defer std.crypto.secureZero(u8, &owned_secret);
    var scalar = Scalar.fromBytes(owned_secret, .big) catch
        return error.InvalidSecretKey;
    defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
    if (scalar.isZero()) return error.InvalidSecretKey;
    const peer = P256.fromSec1(peer_public_key_sec1) catch
        return error.InvalidPublicKey;
    peer.rejectIdentity() catch return error.InvalidPublicKey;

    if (comptime scalar_mul_x86.enabled) {
        var scalar_bytes = scalar.toBytes(.little);
        defer std.crypto.secureZero(u8, &scalar_bytes);
        var scalar_limbs = decodeScalar(scalar_bytes);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&scalar_limbs));
        const input = encodeJacobian(JacobianPoint.fromAffine(
            affineFromP256(peer),
        ));
        var output_limbs: [12]u64 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&output_limbs));
        scalar_mul_x86.scalarMult(&output_limbs, &scalar_limbs, &input);
        const output = decodeJacobian(output_limbs);
        if (output.isIdentity()) return error.KeyAgreementFailed;
        var inverse = invertSecretField(output.z);
        defer std.crypto.secureZero(Fe, (&inverse)[0..1]);
        var inverse_squared = fieldSquare(inverse);
        defer std.crypto.secureZero(Fe, (&inverse_squared)[0..1]);
        var shared_x = fieldMul(output.x, inverse_squared);
        defer std.crypto.secureZero(Fe, (&shared_x)[0..1]);
        return shared_x.toBytes(.big);
    }

    const shared = peer.mul(owned_secret, .big) catch
        return error.KeyAgreementFailed;
    return shared.affineCoordinates().x.toBytes(.big);
}

/// Sign a message with deterministic RFC 6979 nonce derivation and optional
/// additional noise. Private arithmetic follows a fixed instruction schedule.
pub fn sign(
    comptime Hash: type,
    key_pair: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).KeyPair,
    message: []const u8,
    noise: ?[P256.scalar.encoded_length]u8,
) (std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError)!std.crypto.sign.ecdsa.Ecdsa(
    P256,
    Hash,
).Signature {
    var digest: [Hash.digest_length]u8 = undefined;
    hashMessage(Hash, message, &digest);
    return signPrehashed(Hash, key_pair, digest, noise);
}

/// Sign a precomputed digest. The first four nonce candidates exactly follow
/// Zig std's RFC 6979 sequence; a fixed-work 512-bit reduction handles the
/// less-than-2^-128 case where all four candidates are non-canonical.
pub fn signPrehashed(
    comptime Hash: type,
    key_pair: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).KeyPair,
    digest: [Hash.digest_length]u8,
    noise: ?[P256.scalar.encoded_length]u8,
) (std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError)!std.crypto.sign.ecdsa.Ecdsa(
    P256,
    Hash,
).Signature {
    defer wipeCallerSavedRegisters();
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P256, Hash);
    const z = scalarFromDigest(Hash, digest);
    var nonce: Scalar = undefined;
    deterministicScalarAssign(
        Hash,
        &nonce,
        &digest,
        &key_pair.secret_key.bytes,
        noise,
    );
    defer std.crypto.secureZero(Scalar, (&nonce)[0..1]);
    var nonce_bytes = nonce.toBytes(.little);
    defer std.crypto.secureZero(u8, &nonce_bytes);
    var nonce_limbs = decodeScalar(nonce_bytes);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&nonce_limbs));
    var x_limbs: [4]u64 = undefined;
    secretBaseMulXCanonicalAssign(&x_limbs, &nonce_limbs);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&x_limbs));
    const r = reduceFieldXToScalar(&x_limbs);
    if (r.isZero()) return error.IdentityElement;

    var nonce_inverse: Scalar = undefined;
    invertSecretScalarAssign(&nonce_inverse, &nonce);
    defer std.crypto.secureZero(Scalar, (&nonce_inverse)[0..1]);
    var private_limbs: ScalarLimbs = undefined;
    inline for (0..scalar_limb_count) |index| {
        private_limbs[scalar_limb_count - 1 - index] = std.mem.readInt(
            u64,
            key_pair.secret_key.bytes[index * 8 ..][0..8],
            .big,
        );
    }
    defer std.crypto.secureZero(u8, std.mem.asBytes(&private_limbs));
    var private_scalar: Scalar = undefined;
    scalarLimbsToMontgomeryAssign(&private_scalar, &private_limbs);
    defer std.crypto.secureZero(Scalar, (&private_scalar)[0..1]);
    var product: Scalar = undefined;
    scalarMontgomeryMulAssign(&product, &r, &private_scalar);
    defer std.crypto.secureZero(Scalar, (&product)[0..1]);
    var sum = z.add(product);
    defer std.crypto.secureZero(Scalar, (&sum)[0..1]);
    var s: Scalar = undefined;
    scalarMontgomeryMulAssign(&s, &nonce_inverse, &sum);
    defer std.crypto.secureZero(Scalar, (&s)[0..1]);
    if (s.isZero()) return error.IdentityElement;
    return Scheme.Signature{
        .r = r.toBytes(.big),
        .s = s.toBytes(.big),
    };
}

/// Encode a P-256 signature as the short-form DER sequence used by TLS.
pub fn signatureToDer(
    comptime Hash: type,
    signature: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature,
    output: *[
        std.crypto.sign.ecdsa.Ecdsa(
            P256,
            Hash,
        ).Signature.der_encoded_length_max
    ]u8,
) []u8 {
    const r = std.mem.trimStart(u8, &signature.r, &.{0});
    const s = std.mem.trimStart(u8, &signature.s, &.{0});
    const r_pad: usize = r[0] >> 7;
    const s_pad: usize = s[0] >> 7;
    const r_len = r.len + r_pad;
    const s_len = s.len + s_pad;
    const sequence_len = 2 + r_len + 2 + s_len;
    output[0] = 0x30;
    output[1] = @intCast(sequence_len);
    output[2] = 0x02;
    output[3] = @intCast(r_len);
    var offset: usize = 4;
    if (r_pad != 0) {
        output[offset] = 0;
        offset += 1;
    }
    @memcpy(output[offset..][0..r.len], r);
    offset += r.len;
    output[offset] = 0x02;
    output[offset + 1] = @intCast(s_len);
    offset += 2;
    if (s_pad != 0) {
        output[offset] = 0;
        offset += 1;
    }
    @memcpy(output[offset..][0..s.len], s);
    offset += s.len;
    return output[0..offset];
}

noinline fn reduceFieldXToScalar(value: *const ScalarLimbs) Scalar {
    const subtraction = scalarSubRaw(value.*, scalar_modulus);
    var canonical: ScalarLimbs = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&canonical));
    const use_subtraction = subtraction.borrow ^ 1;
    const mask = opaqueWord(0 -% @as(u64, use_subtraction));
    inline for (0..scalar_limb_count) |index| {
        canonical[index] = (subtraction.value[index] & mask) |
            (value[index] & ~mask);
    }
    var normal = Scalar{ .fe = .{ .limbs = canonical } };
    defer std.crypto.secureZero(Scalar, (&normal)[0..1]);
    const r2 = Scalar{ .fe = .{ .limbs = scalar_montgomery_r2 } };
    var result: Scalar = undefined;
    scalarMontgomeryMulAssign(&result, &normal, &r2);
    return result;
}

noinline fn deterministicScalarAssign(
    comptime Hash: type,
    output: *Scalar,
    digest: *const [Hash.digest_length]u8,
    secret_key: *const [P256.scalar.encoded_length]u8,
    noise: ?[P256.scalar.encoded_length]u8,
) void {
    if (comptime Hash == std.crypto.hash.sha2.Sha256) {
        deterministicScalarSha256Assign(
            output,
            digest,
            secret_key,
            noise,
        );
        return;
    }
    const Prf = switch (Hash) {
        std.crypto.hash.sha3.Shake128 => std.crypto.hash.sha3.KMac128,
        std.crypto.hash.sha3.Shake256 => std.crypto.hash.sha3.KMac256,
        else => std.crypto.auth.hmac.Hmac(Hash),
    };
    var key = [_]u8{0x00} ** Hash.digest_length;
    defer std.crypto.secureZero(u8, &key);
    var material = [_]u8{0x00} **
        (Hash.digest_length + 1 + P256.scalar.encoded_length * 2 +
            Hash.digest_length);
    defer std.crypto.secureZero(u8, &material);
    var candidates: [deterministic_candidate_count][P256.scalar.encoded_length]u8 =
        undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&candidates));
    const value = material[0..Hash.digest_length];
    const separator = &material[value.len];
    const random = material[value.len + 1 ..][0..P256.scalar.encoded_length];
    const secret = material[value.len + 1 + P256.scalar.encoded_length ..][0..P256.scalar.encoded_length];
    const message_hash = material[material.len - Hash.digest_length ..];

    @memset(value, 0x01);
    separator.* = 0x00;
    if (noise) |bytes| @memcpy(random, &bytes);
    @memcpy(secret, secret_key);
    @memcpy(message_hash, digest);
    Prf.create(&key, &material, &key);
    Prf.create(value, value, &key);
    separator.* = 0x01;
    Prf.create(&key, &material, &key);
    Prf.create(value, value, &key);
    fillDeterministicCandidate(Prf, &candidates[0], value, &key);
    inline for (1..deterministic_candidate_count) |index| {
        separator.* = 0x00;
        Prf.create(&key, material[0 .. value.len + 1], &key);
        Prf.create(value, value, &key);
        fillDeterministicCandidate(Prf, &candidates[index], value, &key);
    }

    selectNonceCandidates(output, &candidates);
}

/// RFC 6979's K/V chain performs several HMACs under each newly derived key.
/// Retain the SHA-256 ipad/opad states for that key until the next K update.
noinline fn deterministicScalarSha256Assign(
    output: *Scalar,
    digest: *const [std.crypto.hash.sha2.Sha256.digest_length]u8,
    secret_key: *const [P256.scalar.encoded_length]u8,
    noise: ?[P256.scalar.encoded_length]u8,
) void {
    const digest_length = std.crypto.hash.sha2.Sha256.digest_length;
    var key = [_]u8{0x00} ** digest_length;
    defer std.crypto.secureZero(u8, &key);
    var material = [_]u8{0x00} **
        (digest_length + 1 + P256.scalar.encoded_length * 2 + digest_length);
    defer std.crypto.secureZero(u8, &material);
    var candidates: [deterministic_candidate_count][P256.scalar.encoded_length]u8 =
        undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&candidates));
    const value = material[0..digest_length];
    const separator = &material[value.len];
    const random = material[value.len + 1 ..][0..P256.scalar.encoded_length];
    const secret = material[value.len + 1 + P256.scalar.encoded_length ..][0..P256.scalar.encoded_length];
    const message_hash = material[material.len - digest_length ..];

    @memset(value, 0x01);
    separator.* = 0x00;
    if (noise) |bytes| @memcpy(random, &bytes);
    @memcpy(secret, secret_key);
    @memcpy(message_hash, digest);

    var prepared = sha256.PreparedHmac.init(&key);
    defer prepared.deinit();
    prepared.create(&key, &material);
    prepared.deinit();
    prepared.initInto(&key);
    prepared.createShort(value, value);
    separator.* = 0x01;
    prepared.create(&key, &material);
    prepared.deinit();
    prepared.initInto(&key);
    prepared.createShort(value, value);
    prepared.createShort(value, value);
    candidates[0] = value.*;

    inline for (1..deterministic_candidate_count) |index| {
        separator.* = 0x00;
        prepared.createShort(&key, material[0 .. value.len + 1]);
        prepared.deinit();
        prepared.initInto(&key);
        prepared.createShort(value, value);
        prepared.createShort(value, value);
        candidates[index] = value.*;
    }

    selectNonceCandidates(output, &candidates);
}

noinline fn selectNonceCandidates(
    output: *Scalar,
    candidates: *const [deterministic_candidate_count][P256.scalar.encoded_length]u8,
) void {
    var result = Scalar.one;
    defer std.crypto.secureZero(Scalar, (&result)[0..1]);
    var fallback: Scalar = undefined;
    reduceWideScalarAssign(
        &fallback,
        &candidates[deterministic_candidate_count - 2],
        &candidates[deterministic_candidate_count - 1],
    );
    defer std.crypto.secureZero(Scalar, (&fallback)[0..1]);
    scalarConditionalMove(
        &fallback,
        Scalar.one,
        @intFromBool(fallback.isZero()),
    );
    result = fallback;
    var selected: u1 = 0;
    inline for (candidates) |*candidate| {
        var reduced: ReducedNonceCandidate = undefined;
        reduceNonceCandidateAssign(&reduced, candidate);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&reduced));
        const take = reduced.valid & (selected ^ 1);
        scalarConditionalMove(&result, reduced.scalar, take);
        selected |= reduced.valid;
    }
    output.* = result;
}

fn fillDeterministicCandidate(
    comptime Prf: type,
    candidate: *[P256.scalar.encoded_length]u8,
    value: *[Prf.mac_length]u8,
    key: []const u8,
) void {
    var offset: usize = 0;
    while (offset < candidate.len) : (offset += value.len) {
        const end = @min(offset + value.len, candidate.len);
        Prf.create(value, value, key);
        @memcpy(candidate[offset..end], value[0 .. end - offset]);
    }
}

const ReducedNonceCandidate = struct {
    scalar: Scalar,
    valid: u1,
};

noinline fn reduceNonceCandidateAssign(
    output: *ReducedNonceCandidate,
    candidate: *const [P256.scalar.encoded_length]u8,
) void {
    var limbs: ScalarLimbs = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&limbs));
    inline for (0..scalar_limb_count) |index| {
        limbs[scalar_limb_count - 1 - index] = std.mem.readInt(
            u64,
            candidate[index * 8 ..][0..8],
            .big,
        );
    }
    var combined: u64 = 0;
    inline for (limbs) |limb| combined |= limb;
    const zero: u1 = @truncate((@as(u65, combined) -% 1) >> 64);
    const canonical = scalarSubRaw(limbs, scalar_modulus).borrow;
    // Every 256-bit candidate is below 2n because the P-256 order has its
    // high bit set. One final subtraction in the Montgomery kernel therefore
    // canonicalizes even the rejected candidates without a generic decoder.
    scalarLimbsToMontgomeryAssign(&output.scalar, &limbs);
    output.valid = canonical & (zero ^ 1);
}

fn scalarConditionalMove(destination: *Scalar, source: Scalar, choice: u1) void {
    const mask = opaqueWord(0 -% @as(u64, choice));
    inline for (0..scalar_limb_count) |index| {
        destination.fe.limbs[index] = (source.fe.limbs[index] & mask) |
            (destination.fe.limbs[index] & ~mask);
    }
}

pub fn verify(
    comptime Hash: type,
    message: []const u8,
    signature: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature,
    public_key: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).PublicKey,
) std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature.VerifyError!void {
    var digest: [Hash.digest_length]u8 = undefined;
    hashMessage(Hash, message, &digest);
    return verifyPrehashed(Hash, signature, digest, public_key);
}

pub fn verifyPrehashed(
    comptime Hash: type,
    signature: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature,
    digest: [Hash.digest_length]u8,
    public_key: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).PublicKey,
) std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature.VerifyError!void {
    const r = try Scalar.fromBytes(signature.r, .big);
    const s = try Scalar.fromBytes(signature.s, .big);
    if (r.isZero() or s.isZero()) return error.IdentityElement;
    try public_key.p.rejectIdentity();
    const public_affine = affineFromP256(public_key.p);
    const public_table = precomputeCachedProjective(
        public_wnaf_entries,
        public_affine,
    );
    return verifyWithTable(Hash, r, s, digest, &public_table);
}

/// Reusable public-key table for repeated P-256 signature verification.
/// Preparation depends only on public input and is intentionally variable-time.
pub const PreparedVerifier = struct {
    public_table: [comb_groups][comb_entries]AffinePoint,

    pub noinline fn init(
        public_key: P256,
    ) std.crypto.errors.IdentityElementError!PreparedVerifier {
        try public_key.rejectIdentity();
        return .{ .public_table = precomputeComb(affineFromP256(public_key)) };
    }

    pub fn matchesPublicKey(
        self: *const PreparedVerifier,
        public_key: P256,
    ) bool {
        const candidate = affineFromP256(public_key);
        const prepared = self.public_table[0][1];
        return candidate.x.equivalent(prepared.x) and
            candidate.y.equivalent(prepared.y);
    }

    pub fn verify(
        self: *const PreparedVerifier,
        comptime Hash: type,
        message: []const u8,
        signature: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature,
    ) std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature.VerifyError!void {
        var digest: [Hash.digest_length]u8 = undefined;
        hashMessage(Hash, message, &digest);
        return self.verifyPrehashed(Hash, signature, digest);
    }

    pub noinline fn verifyPrehashed(
        self: *const PreparedVerifier,
        comptime Hash: type,
        signature: std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature,
        digest: [Hash.digest_length]u8,
    ) std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature.VerifyError!void {
        @setEvalBranchQuota(10_000_000);
        const r = try Scalar.fromBytes(signature.r, .big);
        const s = try Scalar.fromBytes(signature.s, .big);
        if (r.isZero() or s.isZero()) return error.IdentityElement;
        const z = scalarFromDigest(Hash, digest);
        if (z.isZero()) return error.SignatureVerificationFailed;
        const s_inverse = invertPublicScalar(s);
        const v1 = z.mul(s_inverse).toBytes(.little);
        const v2 = r.mul(s_inverse).toBytes(.little);
        const point = doubleScalarMulComb(v1, v2, &self.public_table);
        if (point.isIdentity() or !jacobianXMatchesR(point, r)) {
            return error.SignatureVerificationFailed;
        }
    }
};

/// Narrow component hooks used by the checked-in microbenchmark.
pub const testing = struct {
    pub noinline fn invertPublic(value: Scalar) Scalar {
        return invertPublicScalar(value);
    }

    pub noinline fn invertSecret(value: Scalar) Scalar {
        return invertSecretScalar(value);
    }

    pub noinline fn mulSecretScalars(a: Scalar, b: Scalar) Scalar {
        return scalarMontgomeryMul(a, b);
    }
};

inline fn hashMessage(
    comptime Hash: type,
    message: []const u8,
    digest: *[Hash.digest_length]u8,
) void {
    if (comptime Hash == std.crypto.hash.sha2.Sha512) {
        FastSha512.hash(message, digest, .{});
    } else {
        Hash.hash(message, digest, .{});
    }
}

fn verifyWithTable(
    comptime Hash: type,
    r: Scalar,
    s: Scalar,
    digest: [Hash.digest_length]u8,
    public_table: *const [public_wnaf_entries]CachedJacobianPoint,
) std.crypto.sign.ecdsa.Ecdsa(P256, Hash).Signature.VerifyError!void {
    const z = scalarFromDigest(Hash, digest);
    if (z.isZero()) return error.SignatureVerificationFailed;
    const s_inverse = invertPublicScalar(s);
    const v1 = z.mul(s_inverse).toBytes(.little);
    const v2 = r.mul(s_inverse).toBytes(.little);
    const point = doubleScalarMulProjectiveTable(v1, v2, public_table);
    if (point.isIdentity() or !jacobianXMatchesR(point, r)) {
        return error.SignatureVerificationFailed;
    }
}

/// Variable-time inversion for public P-256 signature scalars.
fn invertPublicScalar(value: Scalar) Scalar {
    std.debug.assert(!value.isZero());
    var first = decodeScalar(value.toBytes(.little));
    var second = scalar_modulus;
    var first_coefficient = scalarOne();
    var second_coefficient = [_]u64{0} ** scalar_limb_count;
    while (!scalarEqual(first, scalarOne()) and
        !scalarEqual(second, scalarOne()))
    {
        if ((first[0] & 1) == 0) {
            const shift = scalarTrailingZeroBits(first);
            first = scalarShiftRightBits(first, shift);
            first_coefficient = scalarDividePowerOfTwo(
                first_coefficient,
                shift,
            );
        }
        if ((second[0] & 1) == 0) {
            const shift = scalarTrailingZeroBits(second);
            second = scalarShiftRightBits(second, shift);
            second_coefficient = scalarDividePowerOfTwo(
                second_coefficient,
                shift,
            );
        }
        if (!scalarLessThan(first, second)) {
            first = scalarSubRaw(first, second).value;
            first_coefficient = scalarSubModulo(
                first_coefficient,
                second_coefficient,
            );
        } else {
            second = scalarSubRaw(second, first).value;
            second_coefficient = scalarSubModulo(
                second_coefficient,
                first_coefficient,
            );
        }
    }
    const inverse = if (scalarEqual(first, scalarOne()))
        first_coefficient
    else
        second_coefficient;
    return Scalar.fromBytes(encodeScalar(inverse), .little) catch unreachable;
}

const ScalarAddResult = struct { value: ScalarLimbs, carry: u1 };
const ScalarSubResult = struct { value: ScalarLimbs, borrow: u1 };

inline fn scalarAddRaw(a: ScalarLimbs, b: ScalarLimbs) ScalarAddResult {
    var result: ScalarLimbs = undefined;
    var carry: u1 = 0;
    inline for (0..scalar_limb_count) |index| {
        const first = @addWithOverflow(a[index], b[index]);
        const second = @addWithOverflow(first[0], carry);
        result[index] = second[0];
        carry = first[1] | second[1];
    }
    return .{ .value = result, .carry = carry };
}

inline fn scalarSubRaw(a: ScalarLimbs, b: ScalarLimbs) ScalarSubResult {
    var result: ScalarLimbs = undefined;
    var borrow: u1 = 0;
    inline for (0..scalar_limb_count) |index| {
        const first = @subWithOverflow(a[index], b[index]);
        const second = @subWithOverflow(first[0], borrow);
        result[index] = second[0];
        borrow = first[1] | second[1];
    }
    return .{ .value = result, .borrow = borrow };
}

fn scalarShiftRightBits(value: ScalarLimbs, shift: u7) ScalarLimbs {
    var result: ScalarLimbs = undefined;
    if (shift == 64) {
        for (0..scalar_limb_count - 1) |index| {
            result[index] = value[index + 1];
        }
        result[scalar_limb_count - 1] = 0;
        return result;
    }
    const low_shift: u6 = @intCast(shift);
    const high_shift: u6 = @intCast(64 - shift);
    for (0..scalar_limb_count - 1) |index| {
        result[index] = (value[index] >> low_shift) |
            (value[index + 1] << high_shift);
    }
    result[scalar_limb_count - 1] =
        value[scalar_limb_count - 1] >> low_shift;
    return result;
}

fn scalarDividePowerOfTwo(value: ScalarLimbs, shift: u7) ScalarLimbs {
    const mask = if (shift == 64)
        std.math.maxInt(u64)
    else
        (@as(u64, 1) << @as(u6, @intCast(shift))) - 1;
    const multiplier = value[0] *% scalar_negative_inverse & mask;
    var sum: [scalar_limb_count + 1]u64 = undefined;
    var carry: u128 = 0;
    inline for (0..scalar_limb_count) |index| {
        const accumulated = @as(u128, scalar_modulus[index]) * multiplier +
            value[index] + carry;
        sum[index] = @truncate(accumulated);
        carry = accumulated >> 64;
    }
    sum[scalar_limb_count] = @truncate(carry);

    var result: ScalarLimbs = undefined;
    if (shift == 64) {
        @memcpy(&result, sum[1..]);
    } else {
        const low_shift: u6 = @intCast(shift);
        const high_shift: u6 = @intCast(64 - shift);
        inline for (0..scalar_limb_count) |index| {
            result[index] = (sum[index] >> low_shift) |
                (sum[index + 1] << high_shift);
        }
    }
    return result;
}

inline fn scalarSubModulo(a: ScalarLimbs, b: ScalarLimbs) ScalarLimbs {
    const difference = scalarSubRaw(a, b);
    if (difference.borrow == 0) return difference.value;
    return scalarAddRaw(difference.value, scalar_modulus).value;
}

fn scalarTrailingZeroBits(value: ScalarLimbs) u7 {
    return if (value[0] == 0) 64 else @ctz(value[0]);
}

fn scalarLessThan(a: ScalarLimbs, b: ScalarLimbs) bool {
    var index: usize = scalar_limb_count;
    while (index != 0) {
        index -= 1;
        if (a[index] != b[index]) return a[index] < b[index];
    }
    return false;
}

fn scalarEqual(a: ScalarLimbs, b: ScalarLimbs) bool {
    var difference: u64 = 0;
    for (a, b) |a_limb, b_limb| difference |= a_limb ^ b_limb;
    return difference == 0;
}

fn scalarOne() ScalarLimbs {
    return .{ 1, 0, 0, 0 };
}

fn decodeScalar(encoded: [32]u8) ScalarLimbs {
    var result: ScalarLimbs = undefined;
    inline for (0..scalar_limb_count) |index| {
        result[index] = std.mem.readInt(
            u64,
            encoded[index * 8 ..][0..8],
            .little,
        );
    }
    return result;
}

fn decodeCanonicalNonzeroScalar(
    output: *ScalarLimbs,
    encoded: *const [secret_key_encoded_length]u8,
) bool {
    inline for (0..scalar_limb_count) |index| {
        output[scalar_limb_count - 1 - index] = std.mem.readInt(
            u64,
            encoded[index * 8 ..][0..8],
            .big,
        );
    }
    var combined: u64 = 0;
    inline for (output.*) |limb| combined |= limb;
    const nonzero = @as(u1, @truncate((@as(u65, combined) -% 1) >> 64)) ^ 1;
    const canonical = scalarSubRaw(output.*, scalar_modulus).borrow;
    return (nonzero & canonical) != 0;
}

fn encodeScalar(value: ScalarLimbs) [32]u8 {
    var result: [32]u8 = undefined;
    inline for (0..scalar_limb_count) |index| {
        std.mem.writeInt(
            u64,
            result[index * 8 ..][0..8],
            value[index],
            .little,
        );
    }
    return result;
}

fn fieldMul(a: Fe, b: Fe) Fe {
    if (comptime use_x86_64_adx_field) {
        var result: [4]u64 = undefined;
        vailP256MontgomeryMul(
            &result,
            &a.limbs,
            &b.limbs,
            &field_modulus,
        );
        return .{ .limbs = result };
    }
    if (comptime field_arm64.enabled) {
        var result: [4]u64 = undefined;
        field_arm64.mul(&result, &a.limbs, &b.limbs);
        return .{ .limbs = result };
    }
    return fieldMulPortable(a, b);
}

fn fieldMulPortable(a: Fe, b: Fe) Fe {
    var product = [_]u64{0} ** 9;
    inline for (0..4) |left| {
        var carry: u128 = 0;
        inline for (0..4) |right| {
            const accumulated = @as(u128, a.limbs[left]) * b.limbs[right] +
                product[left + right] + carry;
            product[left + right] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        product[left + 4] = @truncate(carry);
    }
    return fieldMontgomeryReduce(product);
}

fn fieldMontgomeryReduce(product_input: [9]u64) Fe {
    var product = product_input;
    // Montgomery reduction uses -p^-1 = 1 mod 2^64 because p[0] = -1.
    inline for (0..4) |round| {
        const factor = product[round];
        var carry: u128 = 0;
        inline for (0..4) |index| {
            const accumulated = @as(u128, factor) * field_modulus[index] +
                product[round + index] + carry;
            product[round + index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        var sum = @addWithOverflow(
            product[round + 4],
            @as(u64, @truncate(carry)),
        );
        product[round + 4] = sum[0];
        var propagation = sum[1];
        inline for (round + 5..9) |index| {
            sum = @addWithOverflow(product[index], @as(u64, propagation));
            product[index] = sum[0];
            propagation = sum[1];
        }
        std.debug.assert(propagation == 0);
    }

    const unreduced = [4]u64{
        product[4],
        product[5],
        product[6],
        product[7],
    };
    var reduced: [4]u64 = undefined;
    var borrow: u1 = 0;
    inline for (0..4) |index| {
        const first = @subWithOverflow(unreduced[index], field_modulus[index]);
        const second = @subWithOverflow(first[0], borrow);
        reduced[index] = second[0];
        borrow = first[1] | second[1];
    }
    const high = @subWithOverflow(product[8], @as(u64, borrow));
    const keep_unreduced = 0 -% @as(u64, high[1]);
    inline for (0..4) |index| {
        reduced[index] = (unreduced[index] & keep_unreduced) |
            (reduced[index] & ~keep_unreduced);
    }
    return .{ .limbs = reduced };
}

extern fn vailP256MontgomeryMul(
    output: *[4]u64,
    a: *const [4]u64,
    b: *const [4]u64,
    modulus: *const [4]u64,
) callconv(.c) void;

extern fn vailP256MontgomerySquare(
    output: *[4]u64,
    value: *const [4]u64,
    modulus: *const [4]u64,
) callconv(.c) void;

comptime {
    if (use_x86_64_adx_field) {
        asm (
            \\.text
            \\.macro vail_p256_product_row multiplicand, product, shift
            \\movq 0+\shift(\product), %r8
            \\xorl %eax, %eax
            \\mulxq 0(\multiplicand), %r9, %r10
            \\adcxq %r8, %r9
            \\movq %r9, 0+\shift(\product)
            \\movq 8+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\mulxq 8(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 8+\shift(\product)
            \\movq 16+\shift(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq 16(\multiplicand), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, 16+\shift(\product)
            \\movq 24+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\mulxq 24(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 24+\shift(\product)
            \\adoxq %rax, %r11
            \\adcxq %rax, %r11
            \\addq %r11, 32+\shift(\product)
            \\adcq $0, 40+\shift(\product)
            \\.endm
            \\
            \\.macro vail_p256_reduce_row product, shift, modulus
            \\movq 0+\shift(\product), %rdx
            \\movq %rdx, %r10
            \\shlq $32, %r10
            \\movq %rdx, %r11
            \\shrq $32, %r11
            \\addq 8+\shift(\product), %r10
            \\adcq $0, %r11
            \\movq %r10, 8+\shift(\product)
            \\movq 16+\shift(\product), %r10
            \\addq %r11, %r10
            \\movq $0, %r8
            \\adcq $0, %r8
            \\movq %r10, 16+\shift(\product)
            \\mulxq 24(\modulus), %r10, %r11
            \\addq 24+\shift(\product), %r10
            \\adcq $0, %r11
            \\addq %r8, %r10
            \\adcq $0, %r11
            \\movq %r10, 24+\shift(\product)
            \\addq %r11, 32+\shift(\product)
            \\adcq %rdi, 40+\shift(\product)
            \\setc %dil
            \\.endm
            \\
            \\.macro vail_p256_square_term left, right, twice
            \\movq \left(%r13), %rdx
            \\mulxq \right(%r13), %r8, %r9
            \\addq %r8, %r10
            \\adcq %r9, %r11
            \\adcq $0, %r12
            \\.if \twice
            \\addq %r8, %r10
            \\adcq %r9, %r11
            \\adcq $0, %r12
            \\.endif
            \\.endm
            \\
            \\.macro vail_p256_square_limb offset
            \\movq %r10, \offset(%rsp)
            \\movq %r11, %r10
            \\movq %r12, %r11
            \\xorl %r12d, %r12d
            \\.endm
            \\
            \\.p2align 5
            \\.globl vailP256MontgomeryMul
            \\.hidden vailP256MontgomeryMul
            \\.type vailP256MontgomeryMul,@function
            \\vailP256MontgomeryMul:
            \\pushq %rbx
            \\pushq %rbp
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\subq $80, %rsp
            \\movq %rdi, %r12
            \\movq %rsi, %r13
            \\movq %rdx, %rbx
            \\movq %rcx, %r14
            \\vpxor %ymm0, %ymm0, %ymm0
            \\vmovdqu %ymm0, 0(%rsp)
            \\vmovdqu %ymm0, 32(%rsp)
            \\movq $0, 64(%rsp)
            \\.irp outer, 0, 1, 2, 3
            \\movq 8*\outer(%rbx), %rdx
            \\vail_p256_product_row %r13, %rsp, 8*\outer
            \\.endr
            \\
            \\xorl %edi, %edi
            \\.irp outer, 0, 1, 2, 3
            \\vail_p256_reduce_row %rsp, 8*\outer, %r14
            \\.endr
            \\
            \\clc
            \\.irp offset, 0, 8, 16, 24
            \\movq 32+\offset(%rsp), %r8
            \\sbbq \offset(%r14), %r8
            \\movq %r8, \offset(%r12)
            \\.endr
            \\sbbq %r8, %r8
            \\movq 64(%rsp), %r9
            \\negq %r9
            \\sbbq %r9, %r9
            \\notq %r9
            \\andq %r9, %r8
            \\testq %r8, %r8
            \\.irp offset, 0, 8, 16, 24
            \\movq \offset(%r12), %r9
            \\cmovneq 32+\offset(%rsp), %r9
            \\movq %r9, \offset(%r12)
            \\.endr
            \\
            \\vzeroupper
            \\addq $80, %rsp
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbp
            \\popq %rbx
            \\retq
            \\.size vailP256MontgomeryMul, .-vailP256MontgomeryMul
            \\
            \\.p2align 5
            \\.globl vailP256MontgomerySquare
            \\.hidden vailP256MontgomerySquare
            \\.type vailP256MontgomerySquare,@function
            \\vailP256MontgomerySquare:
            \\pushq %rbx
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\subq $80, %rsp
            \\movq %rdi, %rbx
            \\movq %rsi, %r13
            \\movq %rdx, %r14
            \\xorl %r10d, %r10d
            \\xorl %r11d, %r11d
            \\xorl %r12d, %r12d
            \\vail_p256_square_term 0, 0, 0
            \\vail_p256_square_limb 0
            \\vail_p256_square_term 0, 8, 1
            \\vail_p256_square_limb 8
            \\vail_p256_square_term 0, 16, 1
            \\vail_p256_square_term 8, 8, 0
            \\vail_p256_square_limb 16
            \\vail_p256_square_term 0, 24, 1
            \\vail_p256_square_term 8, 16, 1
            \\vail_p256_square_limb 24
            \\vail_p256_square_term 8, 24, 1
            \\vail_p256_square_term 16, 16, 0
            \\vail_p256_square_limb 32
            \\vail_p256_square_term 16, 24, 1
            \\vail_p256_square_limb 40
            \\vail_p256_square_term 24, 24, 0
            \\movq %r10, 48(%rsp)
            \\movq %r11, 56(%rsp)
            \\movq %r12, 64(%rsp)
            \\
            \\xorl %edi, %edi
            \\.irp outer, 0, 1, 2, 3
            \\vail_p256_reduce_row %rsp, 8*\outer, %r14
            \\.endr
            \\
            \\clc
            \\.irp offset, 0, 8, 16, 24
            \\movq 32+\offset(%rsp), %r8
            \\sbbq \offset(%r14), %r8
            \\movq %r8, \offset(%rbx)
            \\.endr
            \\sbbq %r8, %r8
            \\movq 64(%rsp), %r9
            \\negq %r9
            \\sbbq %r9, %r9
            \\notq %r9
            \\andq %r9, %r8
            \\testq %r8, %r8
            \\.irp offset, 0, 8, 16, 24
            \\movq \offset(%rbx), %r9
            \\cmovneq 32+\offset(%rsp), %r9
            \\movq %r9, \offset(%rbx)
            \\.endr
            \\
            \\addq $80, %rsp
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbx
            \\retq
            \\.size vailP256MontgomerySquare, .-vailP256MontgomerySquare
            \\.purgem vail_p256_product_row
            \\.purgem vail_p256_reduce_row
            \\.purgem vail_p256_square_term
            \\.purgem vail_p256_square_limb
        );
    }
}

inline fn fieldAdd(a: Fe, b: Fe) Fe {
    var sum: [4]u64 = undefined;
    var carry: u1 = 0;
    inline for (0..4) |index| {
        const first = @addWithOverflow(a.limbs[index], b.limbs[index]);
        const second = @addWithOverflow(first[0], carry);
        sum[index] = second[0];
        carry = first[1] | second[1];
    }

    var reduced: [4]u64 = undefined;
    var borrow: u1 = 0;
    inline for (0..4) |index| {
        const first = @subWithOverflow(sum[index], field_modulus[index]);
        const second = @subWithOverflow(first[0], borrow);
        reduced[index] = second[0];
        borrow = first[1] | second[1];
    }
    const high = @subWithOverflow(@as(u64, carry), @as(u64, borrow));
    const keep_sum = 0 -% @as(u64, high[1]);
    inline for (0..4) |index| {
        reduced[index] = (sum[index] & keep_sum) |
            (reduced[index] & ~keep_sum);
    }
    return .{ .limbs = reduced };
}

inline fn fieldDouble(value: Fe) Fe {
    return fieldAdd(value, value);
}

inline fn fieldSquare(value: Fe) Fe {
    if (comptime use_x86_64_adx_field) {
        var result: [4]u64 = undefined;
        vailP256MontgomerySquare(
            &result,
            &value.limbs,
            &field_modulus,
        );
        return .{ .limbs = result };
    }
    if (comptime field_arm64.enabled) {
        var result: [4]u64 = undefined;
        field_arm64.square(&result, &value.limbs);
        return .{ .limbs = result };
    }
    return fieldMul(value, value);
}

fn invertSecretField(value: Fe) Fe {
    if (comptime field_inv_x86.enabled) {
        return .{ .limbs = field_inv_x86.invert(&value.limbs) };
    }
    return value.invert();
}

noinline fn secretBaseMulXCanonicalAssign(
    output: *[4]u64,
    scalar: *const ScalarLimbs,
) void {
    if (comptime base_mul_x86.enabled) {
        base_mul_x86.scalarMultX(
            output,
            scalar,
            &table_values.base_ecdh_block6,
        );
        return;
    }
    var scalar_bytes = encodeScalar(scalar.*);
    defer std.crypto.secureZero(u8, &scalar_bytes);
    var point = P256.basePoint.mul(scalar_bytes, .little) catch unreachable;
    defer std.crypto.secureZero(P256, (&point)[0..1]);
    var affine = point.affineCoordinates();
    defer std.crypto.secureZero(@TypeOf(affine), (&affine)[0..1]);
    output.* = decodeScalar(affine.x.toBytes(.little));
}

noinline fn scalarMontgomeryMulAssign(
    output: *Scalar,
    a: *const Scalar,
    b: *const Scalar,
) void {
    var product = [_]u64{0} ** (2 * scalar_limb_count + 1);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
    inline for (0..scalar_limb_count) |row| {
        var carry: u128 = 0;
        inline for (0..scalar_limb_count) |column| {
            const index = row + column;
            const accumulated = @as(u128, a.fe.limbs[row]) *
                b.fe.limbs[column] + product[index] + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        inline for (row + scalar_limb_count..product.len) |index| {
            const accumulated = @as(u128, product[index]) + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
    }

    inline for (0..scalar_limb_count) |row| {
        const multiplier = product[row] *% scalar_negative_inverse;
        var carry: u128 = 0;
        inline for (0..scalar_limb_count) |column| {
            const index = row + column;
            const accumulated = @as(u128, multiplier) *
                scalar_modulus[column] + product[index] + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        inline for (row + scalar_limb_count..product.len) |index| {
            const accumulated = @as(u128, product[index]) + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
    }

    var reduced: ScalarLimbs = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&reduced));
    var borrow: u1 = 0;
    inline for (0..scalar_limb_count) |index| {
        const first = @subWithOverflow(
            product[scalar_limb_count + index],
            scalar_modulus[index],
        );
        const second = @subWithOverflow(first[0], borrow);
        reduced[index] = second[0];
        borrow = first[1] | second[1];
    }
    const high = @subWithOverflow(product[2 * scalar_limb_count], borrow);
    const use_reduced: u1 = high[1] ^ 1;
    const mask = opaqueWord(0 -% @as(u64, use_reduced));
    inline for (0..scalar_limb_count) |index| {
        output.fe.limbs[index] = (reduced[index] & mask) |
            (product[scalar_limb_count + index] & ~mask);
    }
}

fn scalarMontgomeryMul(a: Scalar, b: Scalar) Scalar {
    defer wipeCallerSavedRegisters();
    var result: Scalar = undefined;
    scalarMontgomeryMulAssign(&result, &a, &b);
    return result;
}

noinline fn scalarLimbsToMontgomeryAssign(
    output: *Scalar,
    limbs: *const ScalarLimbs,
) void {
    var normal = Scalar{ .fe = .{ .limbs = limbs.* } };
    defer std.crypto.secureZero(Scalar, (&normal)[0..1]);
    const r2 = Scalar{ .fe = .{ .limbs = scalar_montgomery_r2 } };
    scalarMontgomeryMulAssign(output, &normal, &r2);
}

noinline fn reduceWideScalarAssign(
    output: *Scalar,
    high_bytes: *const [P256.scalar.encoded_length]u8,
    low_bytes: *const [P256.scalar.encoded_length]u8,
) void {
    var high_limbs: ScalarLimbs = undefined;
    var low_limbs: ScalarLimbs = undefined;
    inline for (0..scalar_limb_count) |index| {
        high_limbs[scalar_limb_count - 1 - index] = std.mem.readInt(
            u64,
            high_bytes[index * 8 ..][0..8],
            .big,
        );
        low_limbs[scalar_limb_count - 1 - index] = std.mem.readInt(
            u64,
            low_bytes[index * 8 ..][0..8],
            .big,
        );
    }
    defer std.crypto.secureZero(u8, std.mem.asBytes(&high_limbs));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&low_limbs));

    var high: Scalar = undefined;
    scalarLimbsToMontgomeryAssign(&high, &high_limbs);
    defer std.crypto.secureZero(Scalar, (&high)[0..1]);
    var high_shifted: Scalar = undefined;
    const r2 = Scalar{ .fe = .{ .limbs = scalar_montgomery_r2 } };
    scalarMontgomeryMulAssign(&high_shifted, &high, &r2);
    defer std.crypto.secureZero(Scalar, (&high_shifted)[0..1]);

    var low: Scalar = undefined;
    scalarLimbsToMontgomeryAssign(&low, &low_limbs);
    defer std.crypto.secureZero(Scalar, (&low)[0..1]);
    output.* = high_shifted.add(low);
}

noinline fn invertSecretScalarAssign(
    output: *Scalar,
    value: *const Scalar,
) void {
    if (comptime scalar_inv_x86.enabled) {
        var encoded = value.toBytes(.little);
        defer std.crypto.secureZero(u8, &encoded);
        var limbs = decodeScalar(encoded);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&limbs));
        var inverse = scalar_inv_x86.invert(&limbs, &scalar_modulus);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&inverse));
        var normal = Scalar{ .fe = .{ .limbs = inverse } };
        defer std.crypto.secureZero(Scalar, (&normal)[0..1]);
        const r2 = Scalar{ .fe = .{ .limbs = scalar_montgomery_r2 } };
        scalarMontgomeryMulAssign(output, &normal, &r2);
        return;
    }

    var powers: [secret_inversion_table_entries]Scalar = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&powers));
    powers[0] = value.*;
    var squared: Scalar = undefined;
    scalarMontgomeryMulAssign(&squared, value, value);
    defer std.crypto.secureZero(Scalar, (&squared)[0..1]);
    for (1..secret_inversion_table_entries) |index| {
        scalarMontgomeryMulAssign(
            &powers[index],
            &powers[index - 1],
            &squared,
        );
    }

    var result = Scalar.one;
    defer std.crypto.secureZero(Scalar, (&result)[0..1]);
    inline for (inversion_schedule.steps[0..inversion_schedule.len]) |step| {
        inline for (0..step.squares) |_| {
            scalarMontgomeryMulAssign(&result, &result, &result);
        }
        scalarMontgomeryMulAssign(
            &result,
            &result,
            &powers[step.table_index],
        );
    }
    output.* = result;
}

fn invertSecretScalar(value: Scalar) Scalar {
    defer wipeCallerSavedRegisters();
    var result: Scalar = undefined;
    invertSecretScalarAssign(&result, &value);
    return result;
}

fn scalarBit(value: ScalarLimbs, index: usize) bool {
    return ((value[index / 64] >> @intCast(index % 64)) & 1) != 0;
}

fn buildInversionSchedule() InversionSchedule {
    @setEvalBranchQuota(100_000);
    const exponent = scalarSubRaw(
        scalar_modulus,
        .{ 2, 0, 0, 0 },
    ).value;
    var schedule = InversionSchedule{ .steps = undefined, .len = 0 };
    var pending_squares: usize = 0;
    var bit_end: usize = 256;
    while (bit_end != 0) {
        if (!scalarBit(exponent, bit_end - 1)) {
            pending_squares += 1;
            bit_end -= 1;
            continue;
        }
        var bit_start = bit_end - @min(bit_end, secret_inversion_window_width);
        while (!scalarBit(exponent, bit_start)) bit_start += 1;
        var window_value: u5 = 0;
        var bit_index = bit_end;
        while (bit_index != bit_start) {
            bit_index -= 1;
            window_value = (window_value << 1) |
                @intFromBool(scalarBit(exponent, bit_index));
        }
        pending_squares += bit_end - bit_start;
        schedule.steps[schedule.len] = .{
            .squares = @intCast(pending_squares),
            .table_index = @intCast(window_value >> 1),
        };
        schedule.len += 1;
        pending_squares = 0;
        bit_end = bit_start;
    }
    return schedule;
}

fn scalarFromDigest(
    comptime Hash: type,
    digest: [Hash.digest_length]u8,
) Scalar {
    const scalar_len = P256.scalar.encoded_length;
    const padded_len = @max(Hash.digest_length, scalar_len);
    const padded = [_]u8{0} ** (padded_len - Hash.digest_length) ++ digest;
    var limbs: ScalarLimbs = undefined;
    inline for (0..scalar_limb_count) |index| {
        limbs[scalar_limb_count - 1 - index] = std.mem.readInt(
            u64,
            padded[index * 8 ..][0..8],
            .big,
        );
    }
    var result: Scalar = undefined;
    scalarLimbsToMontgomeryAssign(&result, &limbs);
    return result;
}

const AffinePoint = struct {
    x: Fe,
    y: Fe,

    fn neg(point: AffinePoint) AffinePoint {
        return .{ .x = point.x, .y = point.y.neg() };
    }
};

const JacobianPoint = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity = JacobianPoint{
        .x = Fe.zero,
        .y = Fe.one,
        .z = Fe.zero,
    };

    fn fromAffine(point: AffinePoint) JacobianPoint {
        return .{ .x = point.x, .y = point.y, .z = Fe.one };
    }

    fn isIdentity(point: JacobianPoint) bool {
        return point.z.isZero();
    }

    fn neg(point: JacobianPoint) JacobianPoint {
        return .{ .x = point.x, .y = point.y.neg(), .z = point.z };
    }

    inline fn dbl(point: JacobianPoint) JacobianPoint {
        if (comptime point_adx.enabled) {
            const input = encodeJacobian(point);
            return decodeJacobian(point_adx.pointDouble(&input));
        }
        const delta = fieldSquare(point.z);
        const gamma = fieldSquare(point.y);
        const beta = fieldMul(point.x, gamma);
        const alpha_base = fieldMul(
            point.x.sub(delta),
            point.x.add(delta),
        );
        const alpha = fieldDouble(alpha_base).add(alpha_base);
        const beta4 = fieldDouble(fieldDouble(beta));
        const beta8 = fieldDouble(beta4);
        const x = fieldSquare(alpha).sub(beta8);
        const gamma8 = fieldDouble(fieldDouble(fieldDouble(
            fieldSquare(gamma),
        )));
        const y = fieldMul(alpha, beta4.sub(x)).sub(gamma8);
        const z = fieldSquare(point.y.add(point.z))
            .sub(gamma).sub(delta);
        return .{ .x = x, .y = y, .z = z };
    }

    inline fn addMixed(point: JacobianPoint, other: AffinePoint) JacobianPoint {
        if (point.isIdentity()) return fromAffine(other);
        const z_squared = fieldSquare(point.z);
        const other_x = fieldMul(other.x, z_squared);
        const other_y = fieldMul(
            fieldMul(other.y, point.z),
            z_squared,
        );
        const h = other_x.sub(point.x);
        const r_base = other_y.sub(point.y);
        if (h.isZero()) {
            if (r_base.isZero()) return point.dbl();
            return identity;
        }
        const hh = fieldSquare(h);
        const i = fieldDouble(fieldDouble(hh));
        const j = fieldMul(h, i);
        const r = fieldDouble(r_base);
        const v = fieldMul(point.x, i);
        const x = fieldSquare(r).sub(j).sub(fieldDouble(v));
        const y = fieldMul(r, v.sub(x)).sub(
            fieldDouble(fieldMul(point.y, j)),
        );
        const z = fieldSquare(point.z.add(h))
            .sub(z_squared).sub(hh);
        return .{ .x = x, .y = y, .z = z };
    }

    fn add(point: JacobianPoint, other: JacobianPoint) JacobianPoint {
        if (comptime point_adx.enabled) {
            const left = encodeJacobian(point);
            const right = encodeJacobian(other);
            const sum = decodeJacobian(point_adx.pointAdd(&left, &right));
            // The verified assembly schedule deliberately excludes equal
            // non-identity inputs. Its output is the identity in that case,
            // so pay for the projective equality check only on that exceptional
            // result and dispatch to the dedicated doubling schedule.
            if (sum.isIdentity() and point.equivalent(other)) {
                return point.dbl();
            }
            return sum;
        }
        if (point.isIdentity()) return other;
        if (other.isIdentity()) return point;
        const z1_squared = fieldSquare(point.z);
        const z2_squared = fieldSquare(other.z);
        const point_x = fieldMul(point.x, z2_squared);
        const other_x = fieldMul(other.x, z1_squared);
        const point_y = fieldMul(
            fieldMul(point.y, other.z),
            z2_squared,
        );
        const other_y = fieldMul(
            fieldMul(other.y, point.z),
            z1_squared,
        );
        const h = other_x.sub(point_x);
        const r_base = other_y.sub(point_y);
        if (h.isZero()) {
            if (r_base.isZero()) return point.dbl();
            return identity;
        }
        const i = fieldSquare(fieldDouble(h));
        const j = fieldMul(h, i);
        const r = fieldDouble(r_base);
        const v = fieldMul(point_x, i);
        const x = fieldSquare(r).sub(j).sub(fieldDouble(v));
        const y = fieldMul(r, v.sub(x)).sub(
            fieldDouble(fieldMul(point_y, j)),
        );
        const z_sum = fieldSquare(point.z.add(other.z))
            .sub(z1_squared).sub(z2_squared);
        const z = fieldMul(z_sum, h);
        return .{ .x = x, .y = y, .z = z };
    }

    fn equivalent(point: JacobianPoint, other: JacobianPoint) bool {
        if (point.isIdentity()) return other.isIdentity();
        if (other.isIdentity()) return false;
        const z1_squared = fieldSquare(point.z);
        const z2_squared = fieldSquare(other.z);
        if (!fieldMul(point.x, z2_squared)
            .equivalent(fieldMul(other.x, z1_squared))) return false;
        const point_y = fieldMul(fieldMul(point.y, other.z), z2_squared);
        const other_y = fieldMul(fieldMul(other.y, point.z), z1_squared);
        return point_y.equivalent(other_y);
    }
};

inline fn encodeJacobian(point: JacobianPoint) [12]u64 {
    return point.x.limbs ++ point.y.limbs ++ point.z.limbs;
}

inline fn decodeJacobian(encoded: [12]u64) JacobianPoint {
    return .{
        .x = .{ .limbs = encoded[0..4].* },
        .y = .{ .limbs = encoded[4..8].* },
        .z = .{ .limbs = encoded[8..12].* },
    };
}

const CachedJacobianPoint = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    z_squared: Fe,
    z_cubed: Fe,

    fn neg(point: CachedJacobianPoint) CachedJacobianPoint {
        return .{
            .x = point.x,
            .y = point.y.neg(),
            .z = point.z,
            .z_squared = point.z_squared,
            .z_cubed = point.z_cubed,
        };
    }
};

const base_affine_table = loadBaseAffineTable();
const base_comb_table = loadBaseCombTable();

fn affineFromP256(point: P256) AffinePoint {
    if (point.z.equivalent(Fe.one)) {
        return .{ .x = point.x, .y = point.y };
    }
    const affine = point.affineCoordinates();
    return .{ .x = affine.x, .y = affine.y };
}

fn loadBaseAffineTable() [base_wnaf_entries]AffinePoint {
    var result: [base_wnaf_entries]AffinePoint = undefined;
    for (&result, 0..) |*point, index| {
        point.* = .{
            .x = .{ .limbs = table_values.base_wnaf_10[0][index] },
            .y = .{ .limbs = table_values.base_wnaf_10[1][index] },
        };
    }
    return result;
}

fn loadBaseCombTable() [comb_groups][comb_entries]AffinePoint {
    @setEvalBranchQuota(10_000);
    var result: [comb_groups][comb_entries]AffinePoint = undefined;
    for (&result, 0..) |*group, group_index| {
        for (group, 0..) |*point, index| {
            point.* = .{
                .x = .{ .limbs = table_values.base_comb_4x8[group_index][0][index] },
                .y = .{ .limbs = table_values.base_comb_4x8[group_index][1][index] },
            };
        }
    }
    return result;
}

fn precomputeProjective(
    comptime entries: usize,
    point: AffinePoint,
) [entries]JacobianPoint {
    var projective: [entries]JacobianPoint = undefined;
    projective[0] = JacobianPoint.fromAffine(point);
    const twice = projective[0].dbl();
    for (1..entries) |index| {
        projective[index] = projective[index - 1].add(twice);
    }
    return projective;
}

fn precomputeCachedProjective(
    comptime entries: usize,
    point: AffinePoint,
) [entries]CachedJacobianPoint {
    const projective = precomputeProjective(entries, point);
    var cached: [entries]CachedJacobianPoint = undefined;
    for (projective, 0..) |entry, index| {
        const z_squared = fieldSquare(entry.z);
        cached[index] = .{
            .x = entry.x,
            .y = entry.y,
            .z = entry.z,
            .z_squared = z_squared,
            .z_cubed = fieldMul(z_squared, entry.z),
        };
    }
    return cached;
}

fn precomputeComb(point: AffinePoint) [comb_groups][comb_entries]AffinePoint {
    @setEvalBranchQuota(10_000_000);
    const column_count = comb_groups * comb_width;
    var columns: [column_count]JacobianPoint = undefined;
    columns[0] = JacobianPoint.fromAffine(point);
    for (1..column_count) |column| {
        var shifted = columns[column - 1];
        for (0..comb_windows) |_| shifted = shifted.dbl();
        columns[column] = shifted;
    }

    var projective: [comb_groups][comb_entries]JacobianPoint = undefined;
    for (0..comb_groups) |group| {
        projective[group][0] = JacobianPoint.identity;
        projective[group][1] = columns[group * comb_width];
        for (2..comb_entries) |index| {
            const column: std.math.Log2Int(usize) = @intCast(@ctz(index));
            projective[group][index] = projective[group][
                index ^
                    (@as(usize, 1) << column)
            ].add(
                columns[group * comb_width + column],
            );
        }
    }

    var prefixes: [comb_groups][comb_entries]Fe = undefined;
    var product = Fe.one;
    for (0..comb_groups) |group| {
        for (1..comb_entries) |index| {
            prefixes[group][index] = product;
            product = fieldMul(product, projective[group][index].z);
        }
    }
    var inverse_product = product.invert();
    var result: [comb_groups][comb_entries]AffinePoint = undefined;
    var flat_index: usize = comb_groups * comb_entries;
    while (flat_index != 0) {
        flat_index -= 1;
        const group = flat_index / comb_entries;
        const index = flat_index % comb_entries;
        if (index == 0) {
            result[group][index] = .{ .x = Fe.zero, .y = Fe.one };
            continue;
        }
        const inverse = fieldMul(inverse_product, prefixes[group][index]);
        inverse_product = fieldMul(
            inverse_product,
            projective[group][index].z,
        );
        const inverse_squared = fieldSquare(inverse);
        result[group][index] = .{
            .x = fieldMul(projective[group][index].x, inverse_squared),
            .y = fieldMul(
                fieldMul(projective[group][index].y, inverse_squared),
                inverse,
            ),
        };
    }
    return result;
}

fn wnafDigits(
    comptime width: usize,
    scalar: [32]u8,
) [wnaf_digits]i16 {
    var digits = [_]i16{0} ** wnaf_digits;
    var remaining = std.mem.readInt(u256, &scalar, .little);
    var index: usize = 0;
    while (remaining != 0) : (index += 1) {
        if ((remaining & 1) != 0) {
            const residue: u16 = @truncate(
                remaining & ((1 << width) - 1),
            );
            var digit: i16 = @intCast(residue);
            if (residue >= 1 << (width - 1)) {
                digit -= 1 << width;
            }
            digits[index] = digit;
            if (digit > 0) {
                remaining -= @intCast(digit);
            } else {
                remaining += @intCast(-digit);
            }
        }
        remaining >>= 1;
    }
    return digits;
}

fn doubleScalarMulProjectiveTable(
    base_scalar: [32]u8,
    public_scalar: [32]u8,
    public_table: *const [public_wnaf_entries]CachedJacobianPoint,
) JacobianPoint {
    const base_wnaf = wnafSparse(base_wnaf_width, base_scalar);
    const public_wnaf = wnafSparse(public_wnaf_width, public_scalar);
    var result = JacobianPoint.identity;
    var base_index = base_wnaf.len;
    var public_index = public_wnaf.len;
    if (base_index == 0 and public_index == 0) return result;
    var position: usize = if (base_index == 0)
        public_wnaf.entries[public_index - 1].position
    else if (public_index == 0)
        base_wnaf.entries[base_index - 1].position
    else
        @max(
            base_wnaf.entries[base_index - 1].position,
            public_wnaf.entries[public_index - 1].position,
        );
    if (base_index != 0 and
        base_wnaf.entries[base_index - 1].position == position)
    {
        base_index -= 1;
        const base_digit = base_wnaf.entries[base_index].digit;
        result = JacobianPoint.fromAffine(signedWnafPoint(
            base_wnaf_entries,
            &base_affine_table,
            base_digit,
        ));
    }
    if (public_index != 0 and
        public_wnaf.entries[public_index - 1].position == position)
    {
        public_index -= 1;
        const public_digit = public_wnaf.entries[public_index].digit;
        const public_point = signedWnafProjectivePoint(
            public_table,
            public_digit,
        );
        result = if (result.isIdentity())
            .{ .x = public_point.x, .y = public_point.y, .z = public_point.z }
        else
            addCachedJacobian(result, public_point);
    }
    while (position != 0) {
        position -= 1;
        result = result.dbl();
        if (base_index != 0 and
            base_wnaf.entries[base_index - 1].position == position)
        {
            base_index -= 1;
            const base_digit = base_wnaf.entries[base_index].digit;
            const base_point = signedWnafPoint(
                base_wnaf_entries,
                &base_affine_table,
                base_digit,
            );
            result = if (comptime point_adx.enabled)
                result.add(JacobianPoint.fromAffine(base_point))
            else
                result.addMixed(base_point);
        }
        if (public_index != 0 and
            public_wnaf.entries[public_index - 1].position == position)
        {
            public_index -= 1;
            const public_digit = public_wnaf.entries[public_index].digit;
            const public_point = signedWnafProjectivePoint(
                public_table,
                public_digit,
            );
            result = if (comptime point_adx.enabled)
                result.add(.{
                    .x = public_point.x,
                    .y = public_point.y,
                    .z = public_point.z,
                })
            else
                addCachedJacobian(result, public_point);
        }
    }
    return result;
}

fn wnafSparse(comptime width: usize, scalar: [32]u8) Wnaf(width) {
    var result: Wnaf(width) = undefined;
    result.len = 0;
    var limbs: ScalarLimbs = undefined;
    inline for (0..scalar_limb_count) |index| {
        limbs[index] = std.mem.readInt(
            u64,
            scalar[index * 8 ..][0..8],
            .little,
        );
    }
    var carry: u16 = 0;
    var position: usize = 0;
    while (position < 256) {
        const limb_index = position / 64;
        const bit_offset: u6 = @intCast(position % 64);
        const low_bit: u16 = @truncate(limbs[limb_index] >> bit_offset);
        if ((low_bit & 1) == carry) {
            position += 1;
            continue;
        }
        var window = limbs[limb_index] >> bit_offset;
        if (bit_offset > 64 - width and limb_index + 1 < limbs.len) {
            const upper_shift: u6 = @intCast(64 - @as(u7, bit_offset));
            window |= limbs[limb_index + 1] << upper_shift;
        }
        const residue: u16 = @intCast(window & ((1 << width) - 1));
        const with_carry = residue + carry;
        carry = (with_carry >> (width - 1)) & 1;
        const digit = @as(i16, @intCast(with_carry)) -
            (@as(i16, @intCast(carry)) << width);
        std.debug.assert(result.len < result.entries.len);
        result.entries[result.len] = .{
            .position = @intCast(position),
            .digit = digit,
        };
        result.len += 1;
        position += width;
    }
    if (carry != 0) {
        std.debug.assert(position == 256);
        std.debug.assert(result.len < result.entries.len);
        result.entries[result.len] = .{ .position = 256, .digit = 1 };
        result.len += 1;
    }
    return result;
}

fn signedWnafPoint(
    comptime entries: usize,
    table: *const [entries]AffinePoint,
    digit: i16,
) AffinePoint {
    const magnitude: usize = @intCast(if (digit < 0) -digit else digit);
    var point = table[(magnitude - 1) / 2];
    if (digit < 0) point = point.neg();
    return point;
}

fn signedWnafProjectivePoint(
    table: *const [public_wnaf_entries]CachedJacobianPoint,
    digit: i16,
) CachedJacobianPoint {
    const magnitude: usize = @intCast(if (digit < 0) -digit else digit);
    var point = table[(magnitude - 1) / 2];
    if (digit < 0) point = point.neg();
    return point;
}

fn doubleScalarMulComb(
    base_scalar: [32]u8,
    public_scalar: [32]u8,
    public_table: *const [comb_groups][comb_entries]AffinePoint,
) JacobianPoint {
    @setEvalBranchQuota(10_000_000);
    const scalars = [2][33]u8{
        base_scalar ++ [_]u8{0},
        public_scalar ++ [_]u8{0},
    };
    var result = JacobianPoint.identity;
    var started = false;
    var window: usize = comb_windows;
    while (window != 0) {
        window -= 1;
        if (started) result = result.dbl();
        inline for (0..comb_groups) |group| {
            const base_digit = combDigit(&scalars[0], window, group);
            if (base_digit != 0) {
                result = result.addMixed(base_comb_table[group][base_digit]);
                started = true;
            }
            const public_digit = combDigit(&scalars[1], window, group);
            if (public_digit != 0) {
                result = result.addMixed(public_table[group][public_digit]);
                started = true;
            }
        }
    }
    return result;
}

inline fn combDigit(
    scalar: *const [33]u8,
    window: usize,
    comptime group: usize,
) u8 {
    var digit: u8 = 0;
    inline for (0..comb_width) |column| {
        const bit_index = window +
            (group * comb_width + column) * comb_windows;
        const bit: u1 = @truncate(
            scalar[bit_index / 8] >> @intCast(bit_index % 8),
        );
        digit |= @as(u8, bit) << column;
    }
    return digit;
}

inline fn addCachedJacobian(
    point: JacobianPoint,
    other: CachedJacobianPoint,
) JacobianPoint {
    if (point.isIdentity()) {
        return .{ .x = other.x, .y = other.y, .z = other.z };
    }
    const z1_squared = fieldSquare(point.z);
    const point_x = fieldMul(point.x, other.z_squared);
    const other_x = fieldMul(other.x, z1_squared);
    const point_y = fieldMul(point.y, other.z_cubed);
    const other_y = fieldMul(
        fieldMul(other.y, point.z),
        z1_squared,
    );
    const h = other_x.sub(point_x);
    const r_base = other_y.sub(point_y);
    if (h.isZero()) {
        if (r_base.isZero()) return point.dbl();
        return JacobianPoint.identity;
    }
    const i = fieldSquare(fieldDouble(h));
    const j = fieldMul(h, i);
    const r = fieldDouble(r_base);
    const v = fieldMul(point_x, i);
    const x = fieldSquare(r).sub(j).sub(fieldDouble(v));
    const y = fieldMul(r, v.sub(x)).sub(
        fieldDouble(fieldMul(point_y, j)),
    );
    const z_sum = fieldSquare(point.z.add(other.z))
        .sub(z1_squared).sub(other.z_squared);
    const z = fieldMul(z_sum, h);
    return .{ .x = x, .y = y, .z = z };
}

fn jacobianXMatchesR(point: JacobianPoint, r: Scalar) bool {
    const z_squared = fieldSquare(point.z);
    const r_bytes = r.toBytes(.big);
    const r_field = Fe.fromBytes(r_bytes, .big) catch unreachable;
    if (point.x.equivalent(fieldMul(r_field, z_squared))) return true;

    const r_int = std.mem.readInt(u256, &r_bytes, .big);
    const p_minus_n: u256 = Fe.field_order - P256.scalar.field_order;
    if (r_int >= p_minus_n) return false;
    var r_plus_n_bytes: [32]u8 = undefined;
    std.mem.writeInt(
        u256,
        &r_plus_n_bytes,
        r_int + P256.scalar.field_order,
        .big,
    );
    const r_plus_n = Fe.fromBytes(r_plus_n_bytes, .big) catch unreachable;
    return point.x.equivalent(fieldMul(r_plus_n, z_squared));
}

test "P-256 projective verifier matches Zig std across hash functions" {
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha224);
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha256);
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha384);
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha512);
    try expectValidAndInvalid(std.crypto.hash.sha3.Sha3_224);
    try expectValidAndInvalid(std.crypto.hash.sha3.Sha3_256);
    try expectValidAndInvalid(std.crypto.hash.sha3.Sha3_384);
    try expectValidAndInvalid(std.crypto.hash.sha3.Sha3_512);
    try expectValidAndInvalid(std.crypto.hash.sha3.Shake128);
    try expectValidAndInvalid(std.crypto.hash.sha3.Shake256);
}

fn expectValidAndInvalid(comptime Hash: type) !void {
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P256, Hash);
    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Scheme.KeyPair.seed_length,
    );
    const message = "Vail projective P-256 verification";
    const signature = try key_pair.sign(message, null);
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key = try Scheme.PublicKey.fromSec1(&encoded_public_key);
    const prepared = try PreparedVerifier.init(public_key.p);
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(message, &digest, .{});
    const signature_s = try Scalar.fromBytes(signature.s, .big);
    try std.testing.expect(
        invertPublicScalar(signature_s).equivalent(signature_s.invert()),
    );
    try signature.verify(message, public_key);
    try verify(Hash, message, signature, public_key);
    try prepared.verify(Hash, message, signature);
    try verifyPrehashed(
        Hash,
        signature,
        digest,
        public_key,
    );
    try prepared.verifyPrehashed(Hash, signature, digest);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verify(Hash, "tampered", signature, public_key),
    );
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        prepared.verify(Hash, "tampered", signature),
    );
    Hash.hash("tampered", &digest, .{});
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verifyPrehashed(
            Hash,
            signature,
            digest,
            public_key,
        ),
    );
}

test "P-256 verifier rejects zero and non-canonical signature scalars" {
    const Hash = std.crypto.hash.sha2.Sha256;
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P256, Hash);
    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0x73} ** Scheme.KeyPair.seed_length,
    );
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key = try Scheme.PublicKey.fromSec1(&encoded_public_key);
    const message = "P-256 scalar boundaries";
    const signature = try key_pair.sign(message, null);

    var zero_r = signature;
    zero_r.r = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.IdentityElement,
        verify(Hash, message, zero_r, public_key),
    );
    var zero_s = signature;
    zero_s.s = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.IdentityElement,
        verify(Hash, message, zero_s, public_key),
    );
    var non_canonical = signature;
    const modulus_little = encodeScalar(scalar_modulus);
    for (modulus_little, 0..) |byte, index| {
        non_canonical.r[31 - index] = byte;
    }
    try std.testing.expectError(
        error.NonCanonical,
        verify(Hash, message, non_canonical, public_key),
    );
}

test "P-256 Jacobian x check accepts r and r+n representatives" {
    const r = try Scalar.fromBytes(
        [_]u8{0} ** 31 ++ [_]u8{1},
        .big,
    );
    const z = try P256.Fe.fromInt(7);
    const r_field = try P256.Fe.fromInt(1);
    const r_plus_n = try P256.Fe.fromInt(P256.scalar.field_order + 1);
    const one = try P256.Fe.fromInt(1);
    const two = try P256.Fe.fromInt(2);

    try std.testing.expect(jacobianXMatchesR(.{
        .x = r_field.mul(z.sq()),
        .y = one,
        .z = z,
    }, r));
    try std.testing.expect(jacobianXMatchesR(.{
        .x = r_plus_n.mul(z.sq()),
        .y = one,
        .z = z,
    }, r));
    try std.testing.expect(!jacobianXMatchesR(.{
        .x = two.mul(z.sq()),
        .y = one,
        .z = z,
    }, r));
}

test "P-256 public scalar inversion matches the fixed-time inverse" {
    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..256) |_| {
        var wide: [48]u8 = undefined;
        fillDeterministic(&wide, &state);
        const value = Scalar.fromBytes48(wide, .little);
        if (value.isZero()) continue;
        try std.testing.expect(
            invertPublicScalar(value).equivalent(value.invert()),
        );
    }
}

test "P-256 signer exactly matches Zig std with SHA-256" {
    const Hash = std.crypto.hash.sha2.Sha256;
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P256, Hash);
    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0x91} ** Scheme.KeyPair.seed_length,
    );
    const message = "Vail constant-time P-256 signer";
    const deterministic_expected = try key_pair.sign(message, null);
    const deterministic_actual = try sign(Hash, key_pair, message, null);
    try std.testing.expectEqualSlices(
        u8,
        &deterministic_expected.toBytes(),
        &deterministic_actual.toBytes(),
    );
    var expected_der_storage: [Scheme.Signature.der_encoded_length_max]u8 =
        undefined;
    var actual_der_storage: [Scheme.Signature.der_encoded_length_max]u8 =
        undefined;
    try std.testing.expectEqualSlices(
        u8,
        deterministic_expected.toDer(&expected_der_storage),
        signatureToDer(Hash, deterministic_actual, &actual_der_storage),
    );
    try verify(
        Hash,
        message,
        deterministic_actual,
        key_pair.public_key,
    );

    const noise = [_]u8{0xa5} ** P256.scalar.encoded_length;
    const noisy_expected = try key_pair.sign(message, noise);
    const noisy_actual = try sign(Hash, key_pair, message, noise);
    try std.testing.expectEqualSlices(
        u8,
        &noisy_expected.toBytes(),
        &noisy_actual.toBytes(),
    );
    try noisy_actual.verify(message, key_pair.public_key);
}

test "P-256 signer matches Zig std across deterministic inputs" {
    const Hash = std.crypto.hash.sha2.Sha256;
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P256, Hash);
    var state: u64 = 0x3bd3_9e10_cb0e_f593;
    for (0..64) |iteration| {
        var secret_bytes: [Scheme.SecretKey.encoded_length]u8 = undefined;
        var digest: [Hash.digest_length]u8 = undefined;
        var noise: [Scheme.noise_length]u8 = undefined;
        fillDeterministic(&secret_bytes, &state);
        fillDeterministic(&digest, &state);
        fillDeterministic(&noise, &state);
        secret_bytes[0] &= 0x7f;
        secret_bytes[secret_bytes.len - 1] |= 1;
        const secret_key = try Scheme.SecretKey.fromBytes(secret_bytes);
        const key_pair = try Scheme.KeyPair.fromSecretKey(secret_key);
        const optional_noise: ?[Scheme.noise_length]u8 =
            if ((iteration & 1) == 0) null else noise;
        const expected = try key_pair.signPrehashed(digest, optional_noise);
        const actual = try signPrehashed(
            Hash,
            key_pair,
            digest,
            optional_noise,
        );
        try std.testing.expectEqualSlices(
            u8,
            &expected.toBytes(),
            &actual.toBytes(),
        );
        var expected_der: [Scheme.Signature.der_encoded_length_max]u8 =
            undefined;
        var actual_der: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
        try std.testing.expectEqualSlices(
            u8,
            expected.toDer(&expected_der),
            signatureToDer(Hash, actual, &actual_der),
        );
        try actual.verifyPrehashed(digest, key_pair.public_key);
    }
}

test "P-256 constant-time scalar arithmetic matches Zig std" {
    var state: u64 = 0x082e_fa98_ec4e_6c89;
    for (0..256) |_| {
        var a_wide: [48]u8 = undefined;
        var b_wide: [48]u8 = undefined;
        fillDeterministic(&a_wide, &state);
        fillDeterministic(&b_wide, &state);
        const a = Scalar.fromBytes48(a_wide, .little);
        const b = Scalar.fromBytes48(b_wide, .little);
        try std.testing.expect(
            scalarMontgomeryMul(a, b).equivalent(a.mul(b)),
        );
        if (!a.isZero()) {
            const inverse = invertSecretScalar(a);
            try std.testing.expect(inverse.equivalent(a.invert()));
            try std.testing.expect(
                scalarMontgomeryMul(inverse, a).equivalent(Scalar.one),
            );
        }
    }
}

test "P-256 field x reduction handles the n and p boundaries" {
    var n_minus_one = scalar_modulus;
    n_minus_one[0] -= 1;
    var p_minus_one = field_modulus;
    p_minus_one[0] -= 1;
    for ([_]ScalarLimbs{
        .{ 0, 0, 0, 0 },
        n_minus_one,
        scalar_modulus,
        p_minus_one,
    }) |value| {
        var encoded = encodeScalar(value);
        std.mem.reverse(u8, &encoded);
        const expected = Scalar.fromBytes48(
            [_]u8{0} ** 16 ++ encoded,
            .big,
        );
        try std.testing.expect(
            reduceFieldXToScalar(&value).equivalent(expected),
        );
    }
}

test "P-256 deterministic nonce candidate validity boundaries" {
    var reduced: ReducedNonceCandidate = undefined;
    const zero = [_]u8{0} ** P256.scalar.encoded_length;
    reduceNonceCandidateAssign(&reduced, &zero);
    try std.testing.expectEqual(@as(u1, 0), reduced.valid);

    var modulus = encodeScalar(scalar_modulus);
    std.mem.reverse(u8, &modulus);
    reduceNonceCandidateAssign(&reduced, &modulus);
    try std.testing.expectEqual(@as(u1, 0), reduced.valid);

    var largest_limbs = scalar_modulus;
    largest_limbs[0] -= 1;
    var largest = encodeScalar(largest_limbs);
    std.mem.reverse(u8, &largest);
    reduceNonceCandidateAssign(&reduced, &largest);
    try std.testing.expectEqual(@as(u1, 1), reduced.valid);
    try std.testing.expectEqualSlices(
        u8,
        &largest,
        &reduced.scalar.toBytes(.big),
    );

    const all_ones = [_]u8{0xff} ** P256.scalar.encoded_length;
    reduceNonceCandidateAssign(&reduced, &all_ones);
    const expected_all_ones = Scalar.fromBytes48(
        [_]u8{0} ** 16 ++ all_ones,
        .big,
    );
    try std.testing.expect(!reduced.scalar.isZero());
    try std.testing.expect(reduced.scalar.equivalent(expected_all_ones));

    var candidates = [_][P256.scalar.encoded_length]u8{zero} **
        deterministic_candidate_count;
    candidates[0] = modulus;
    candidates[2] = largest;
    candidates[3][candidates[3].len - 1] = 1;
    var selected: Scalar = undefined;
    selectNonceCandidates(&selected, &candidates);
    try std.testing.expectEqualSlices(
        u8,
        &largest,
        &selected.toBytes(.big),
    );
    candidates[0][candidates[0].len - 1] = 1;
    selectNonceCandidates(&selected, &candidates);
    try std.testing.expectEqualSlices(
        u8,
        &candidates[0],
        &selected.toBytes(.big),
    );
}

test "P-256 fixed-width 512-bit reduction matches Zig std" {
    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..64) |_| {
        var high: [P256.scalar.encoded_length]u8 = undefined;
        var low: [P256.scalar.encoded_length]u8 = undefined;
        fillDeterministic(&high, &state);
        fillDeterministic(&low, &state);
        const expected = Scalar.fromBytes64(high ++ low, .big);
        var actual: Scalar = undefined;
        reduceWideScalarAssign(&actual, &high, &low);
        try std.testing.expect(actual.equivalent(expected));
    }

    const all_ones = [_]u8{0xff} ** P256.scalar.encoded_length;
    const expected = Scalar.fromBytes64(all_ones ++ all_ones, .big);
    var actual: Scalar = undefined;
    reduceWideScalarAssign(&actual, &all_ones, &all_ones);
    try std.testing.expect(actual.equivalent(expected));
}

test "P-256 ECDH public key matches Zig std" {
    var one = [_]u8{0} ** secret_key_encoded_length;
    one[one.len - 1] = 1;
    try std.testing.expectEqualSlices(
        u8,
        &P256.basePoint.toUncompressedSec1(),
        &try ecdhPublicKey(one),
    );
    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..64) |_| {
        var secret: [secret_key_encoded_length]u8 = undefined;
        fillDeterministic(&secret, &state);
        secret[secret.len - 1] |= 1;
        const expected = (try P256.basePoint.mul(
            secret,
            .big,
        )).toUncompressedSec1();
        const actual = try ecdhPublicKey(secret);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "P-256 ECDH public key rejects invalid scalars" {
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhPublicKey([_]u8{0} ** secret_key_encoded_length),
    );
    var modulus_big = encodeScalar(scalar_modulus);
    std.mem.reverse(u8, &modulus_big);
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhPublicKey(modulus_big),
    );
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhPublicKey([_]u8{0xff} ** secret_key_encoded_length),
    );
}

test "P-256 ECDH shared secret matches Zig std and agrees both ways" {
    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..64) |_| {
        var first_secret: [secret_key_encoded_length]u8 = undefined;
        var second_secret: [secret_key_encoded_length]u8 = undefined;
        fillDeterministic(&first_secret, &state);
        fillDeterministic(&second_secret, &state);
        first_secret[first_secret.len - 1] |= 1;
        second_secret[second_secret.len - 1] |= 1;

        const first_public = try ecdhPublicKey(first_secret);
        const second_public = try ecdhPublicKey(second_secret);
        const first_point = try P256.fromSec1(&first_public);
        const second_point = try P256.fromSec1(&second_public);
        const expected_first = (try second_point.mul(
            first_secret,
            .big,
        )).affineCoordinates().x.toBytes(.big);
        const expected_second = (try first_point.mul(
            second_secret,
            .big,
        )).affineCoordinates().x.toBytes(.big);
        const first_shared = try ecdhSharedSecret(
            first_secret,
            &second_public,
        );
        const second_shared = try ecdhSharedSecret(
            second_secret,
            &first_public,
        );
        try std.testing.expectEqualSlices(u8, &expected_first, &first_shared);
        try std.testing.expectEqualSlices(u8, &expected_second, &second_shared);
        try std.testing.expectEqualSlices(u8, &first_shared, &second_shared);

        const compressed = second_point.toCompressedSec1();
        try std.testing.expectEqualSlices(
            u8,
            &first_shared,
            &try ecdhSharedSecret(first_secret, &compressed),
        );
    }
}

test "P-256 ECDH shared secret rejects invalid inputs" {
    var valid_secret = [_]u8{0} ** secret_key_encoded_length;
    valid_secret[valid_secret.len - 1] = 7;
    const valid_public = try ecdhPublicKey(valid_secret);
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhSharedSecret([_]u8{0} ** secret_key_encoded_length, &valid_public),
    );
    var modulus_big = encodeScalar(scalar_modulus);
    std.mem.reverse(u8, &modulus_big);
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhSharedSecret(modulus_big, &valid_public),
    );
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhSharedSecret(
            [_]u8{0xff} ** secret_key_encoded_length,
            &valid_public,
        ),
    );
    try std.testing.expectError(
        error.InvalidPublicKey,
        ecdhSharedSecret(valid_secret, &[_]u8{0x04}),
    );
    var invalid_point = [_]u8{0} ** uncompressed_sec1_encoded_length;
    invalid_point[0] = 0x04;
    try std.testing.expectError(
        error.InvalidPublicKey,
        ecdhSharedSecret(valid_secret, &invalid_point),
    );
}

test "P-256 ECDH accepts the largest canonical scalar" {
    var largest_limbs = scalar_modulus;
    largest_limbs[0] -= 1;
    var largest = encodeScalar(largest_limbs);
    std.mem.reverse(u8, &largest);
    const expected_public = (try P256.basePoint.mul(
        largest,
        .big,
    )).toUncompressedSec1();
    const actual_public = try ecdhPublicKey(largest);
    try std.testing.expectEqualSlices(u8, &expected_public, &actual_public);

    var peer_secret = [_]u8{0} ** secret_key_encoded_length;
    peer_secret[peer_secret.len - 1] = 7;
    const peer_public = try ecdhPublicKey(peer_secret);
    const peer = try P256.fromSec1(&peer_public);
    const expected_shared = (try peer.mul(
        largest,
        .big,
    )).affineCoordinates().x.toBytes(.big);
    try std.testing.expectEqualSlices(
        u8,
        &expected_shared,
        &try ecdhSharedSecret(largest, &peer_public),
    );
}

test "P-256 constant-time field inversion matches Zig std" {
    var state: u64 = 0xa409_3822_299f_31d0;
    for (0..256) |_| {
        var encoded: [32]u8 = undefined;
        fillDeterministic(&encoded, &state);
        const value = Fe.fromBytes(encoded, .little) catch continue;
        if (value.isZero()) continue;
        try std.testing.expect(
            invertSecretField(value).equivalent(value.invert()),
        );
    }
}

test "P-256 specialized field arithmetic matches Fiat" {
    const boundary = [_]Fe{
        Fe.zero,
        Fe.one,
        try Fe.fromInt(Fe.field_order - 1),
    };
    for (boundary) |a| {
        for (boundary) |b| {
            try std.testing.expectEqual(
                a.mul(b).limbs,
                fieldMul(a, b).limbs,
            );
            try std.testing.expectEqual(
                a.sq().limbs,
                fieldSquare(a).limbs,
            );
            try std.testing.expectEqual(
                a.add(b).limbs,
                fieldAdd(a, b).limbs,
            );
        }
    }

    var state: u64 = 0x4528_21e6_38d0_1377;
    for (0..4096) |_| {
        var a_bytes: [32]u8 = undefined;
        var b_bytes: [32]u8 = undefined;
        fillDeterministic(&a_bytes, &state);
        fillDeterministic(&b_bytes, &state);
        const a = Fe.fromBytes(a_bytes, .little) catch continue;
        const b = Fe.fromBytes(b_bytes, .little) catch continue;
        try std.testing.expectEqual(
            a.mul(b).limbs,
            fieldMul(a, b).limbs,
        );
        try std.testing.expectEqual(
            a.sq().limbs,
            fieldSquare(a).limbs,
        );
        try std.testing.expect(fieldAdd(a, b).equivalent(a.add(b)));
        try std.testing.expect(fieldDouble(a).equivalent(a.dbl()));
    }
}

test "P-256 prepared verifier has bounded storage and rejects identity" {
    try std.testing.expectEqual(
        @as(usize, comb_groups * comb_entries * 2 * @sizeOf(Fe)),
        @sizeOf(PreparedVerifier),
    );
    try std.testing.expectError(
        error.IdentityElement,
        PreparedVerifier.init(P256.identityElement),
    );
}

fn expectSparseWnafMatches(comptime width: usize, scalar: [32]u8) !void {
    const dense = wnafDigits(width, scalar);
    const sparse = wnafSparse(width, scalar);
    var expanded = [_]i16{0} ** wnaf_digits;
    for (sparse.entries[0..sparse.len]) |entry| {
        try std.testing.expectEqual(
            @as(i16, 0),
            expanded[entry.position],
        );
        expanded[entry.position] = entry.digit;
    }
    try std.testing.expectEqual(dense, expanded);
}

test "P-256 sparse wNAF matches dense recoding" {
    const zero = [_]u8{0} ** 32;
    try expectSparseWnafMatches(base_wnaf_width, zero);
    try expectSparseWnafMatches(public_wnaf_width, zero);

    var maximum_limbs = scalar_modulus;
    maximum_limbs[0] -= 1;
    const maximum_scalar = encodeScalar(maximum_limbs);
    try expectSparseWnafMatches(base_wnaf_width, maximum_scalar);
    try expectSparseWnafMatches(public_wnaf_width, maximum_scalar);

    var state: u64 = 0x1319_8a2e_0370_7344;
    var checked: usize = 0;
    while (checked < 512) {
        var scalar: [32]u8 = undefined;
        fillDeterministic(&scalar, &state);
        if (!scalarLessThan(decodeScalar(scalar), scalar_modulus)) continue;
        try expectSparseWnafMatches(base_wnaf_width, scalar);
        try expectSparseWnafMatches(public_wnaf_width, scalar);
        checked += 1;
    }
}

test "P-256 Jacobian double-scalar multiplication matches Zig std" {
    var state: u64 = 0xa409_3822_299f_31d0;
    for (0..64) |_| {
        var public_scalar: [32]u8 = undefined;
        var base_scalar: [32]u8 = undefined;
        var point_scalar: [32]u8 = undefined;
        fillDeterministic(&public_scalar, &state);
        fillDeterministic(&base_scalar, &state);
        fillDeterministic(&point_scalar, &state);
        point_scalar[0] |= 1;

        const public_point = P256.basePoint.mulPublic(
            point_scalar,
            .little,
        ) catch continue;
        const public_table = precomputeCachedProjective(
            public_wnaf_entries,
            affineFromP256(public_point),
        );
        const actual = doubleScalarMulProjectiveTable(
            base_scalar,
            public_scalar,
            &public_table,
        );
        const comb_table = precomputeComb(affineFromP256(public_point));
        const comb_actual = doubleScalarMulComb(
            base_scalar,
            public_scalar,
            &comb_table,
        );
        const expected = P256.mulDoubleBasePublic(
            P256.basePoint,
            base_scalar,
            public_point,
            public_scalar,
            .little,
        ) catch {
            try std.testing.expect(actual.isIdentity());
            try std.testing.expect(comb_actual.isIdentity());
            continue;
        };
        try std.testing.expect(!actual.isIdentity());
        try std.testing.expect(!comb_actual.isIdentity());
        const inverse = actual.z.invert();
        const inverse_squared = inverse.sq();
        const comb_inverse = comb_actual.z.invert();
        const comb_inverse_squared = comb_inverse.sq();
        const expected_affine = expected.affineCoordinates();
        try std.testing.expect(actual.x.mul(inverse_squared)
            .equivalent(expected_affine.x));
        try std.testing.expect(actual.y.mul(inverse_squared).mul(inverse)
            .equivalent(expected_affine.y));
        try std.testing.expect(comb_actual.x.mul(comb_inverse_squared)
            .equivalent(expected_affine.x));
        try std.testing.expect(comb_actual.y.mul(comb_inverse_squared)
            .mul(comb_inverse).equivalent(expected_affine.y));
    }
}

test "P-256 Jacobian doubling preserves identity" {
    try std.testing.expect(JacobianPoint.identity.dbl().isIdentity());
}

test "P-256 Jacobian addition handles identity inputs" {
    const generator = JacobianPoint.fromAffine(affineFromP256(P256.basePoint));

    try expectJacobianMatchesP256(
        JacobianPoint.identity.add(generator),
        P256.basePoint,
    );
    try expectJacobianMatchesP256(
        generator.add(JacobianPoint.identity),
        P256.basePoint,
    );
}

test "P-256 Jacobian addition handles equal inputs" {
    const generator = JacobianPoint.fromAffine(affineFromP256(P256.basePoint));

    try expectJacobianMatchesP256(generator.dbl(), P256.basePoint.dbl());
    try expectJacobianMatchesP256(generator.add(generator), P256.basePoint.dbl());
}

test "P-256 Jacobian addition handles inverse inputs" {
    const generator = JacobianPoint.fromAffine(affineFromP256(P256.basePoint));

    try std.testing.expect(generator.add(generator.neg()).isIdentity());
}

fn expectJacobianMatchesP256(actual: JacobianPoint, expected: P256) !void {
    try std.testing.expect(!actual.isIdentity());
    const inverse = actual.z.invert();
    const inverse_squared = inverse.sq();
    const expected_affine = expected.affineCoordinates();
    try std.testing.expect(actual.x.mul(inverse_squared)
        .equivalent(expected_affine.x));
    try std.testing.expect(actual.y.mul(inverse_squared).mul(inverse)
        .equivalent(expected_affine.y));
}

fn fillDeterministic(output: []u8, state: *u64) void {
    std.debug.assert(output.len % 8 == 0);
    var offset: usize = 0;
    while (offset != output.len) : (offset += 8) {
        state.* +%= 0x9e37_79b9_7f4a_7c15;
        var value = state.*;
        value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
        value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
        value ^= value >> 31;
        std.mem.writeInt(u64, output[offset..][0..8], value, .little);
    }
}
