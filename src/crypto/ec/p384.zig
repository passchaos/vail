//! P-384 ECDSA signing and verification.
//!
//! Verification uses variable-time wNAF double-scalar multiplication and a
//! projective final x-coordinate check. Linux x86_64 BMI2/ADX builds use
//! in-tree Montgomery-Jacobian point operations; other targets retain the
//! pure-Zig formulas below. Signing uses a constant-schedule 4x6-bit fixed-base
//! comb with full-table selection and explicit secret cleanup.

const std = @import("std");
const builtin = @import("builtin");
const P384 = std.crypto.ecc.P384;
const Scalar = P384.scalar.Scalar;
const Fe = P384.Fe;
const point_adx = @import("p384_point_ops_adx.zig");
const field_inv_x86 = @import("p384_field_inv_x86.zig");
const scalar_inv_x86 = @import("p384_scalar_inv_x86.zig");
const scalar_mul_x86 = @import("p384_scalar_mul_x86.zig");
const table_data = @import("p384_tables.zig");
const fast_sha2 = @import("../hash/sha512.zig");
const FastSha384 = fast_sha2.Sha384;
const FastSha512 = fast_sha2.Sha512;

const scalar_limb_count = 6;
const ScalarLimbs = [scalar_limb_count]u64;
const scalar_modulus = ScalarLimbs{
    0xecec_196a_ccc5_2973,
    0x581a_0db2_48b0_a77a,
    0xc763_4d81_f437_2ddf,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
};
const scalar_negative_inverse = blk: {
    var inverse: u64 = 1;
    for (0..6) |_| inverse *%= 2 -% scalar_modulus[0] *% inverse;
    break :blk 0 -% inverse;
};
const scalar_montgomery_r2 = ScalarLimbs{
    0x2d31_9b24_19b4_09a9,
    0xff3d_81e5_df1a_a419,
    0xbc3e_483a_fcb8_2947,
    0xd40d_4917_4aab_1cc5,
    0x3fb0_5b7a_2826_6895,
    0x0c84_ee01_2b39_bf21,
};

const base_wnaf_width = 10;
const base_wnaf_entries = 1 << (base_wnaf_width - 2);
const public_wnaf_width = 6;
const public_wnaf_entries = 1 << (public_wnaf_width - 2);
const wnaf_digits = 385;
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

const secret_window_width = 6;
const secret_comb_tables = 4;
const secret_window_entries = 1 << secret_window_width;
const secret_window_count = 16;
const secret_selection_lanes = 8;
const SecretSelectionVector = @Vector(secret_selection_lanes, u64);
const secret_inversion_window_width = 5;
const secret_inversion_table_entries = 1 << (secret_inversion_window_width - 1);
const InversionStep = struct { squares: u9, table_index: u4 };
const InversionSchedule = struct {
    steps: [128]InversionStep,
    len: usize,
};
const inversion_schedule = buildInversionSchedule();

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

const AffinePoint = struct {
    x: Fe,
    y: Fe,

    fn neg(point: AffinePoint) AffinePoint {
        return .{ .x = point.x, .y = point.y.neg() };
    }

    comptime {
        std.debug.assert(@sizeOf(AffinePoint) == 12 * @sizeOf(u64));
        std.debug.assert(@offsetOf(AffinePoint, "x") == 0);
        std.debug.assert(@offsetOf(AffinePoint, "y") == 6 * @sizeOf(u64));
    }
};

const SecretAffinePoint = struct {
    point: AffinePoint,
    identity: u1,
};

const SecretBaseTable = struct {
    x: [scalar_limb_count][secret_window_entries]u64,
    y: [scalar_limb_count][secret_window_entries]u64,
};

pub const KeyAgreementError = error{
    InvalidSecretKey,
    InvalidPublicKey,
    KeyAgreementFailed,
};

pub const secret_key_encoded_length = P384.scalar.encoded_length;
pub const uncompressed_sec1_encoded_length = 1 + 2 * P384.Fe.encoded_length;

/// Recover an uncompressed SEC1 public key from a canonical non-zero scalar.
pub fn ecdhPublicKey(
    secret_key_bytes: [secret_key_encoded_length]u8,
) KeyAgreementError![uncompressed_sec1_encoded_length]u8 {
    var owned_secret = secret_key_bytes;
    defer std.crypto.secureZero(u8, &owned_secret);
    var scalar = Scalar.fromBytes(owned_secret, .big) catch
        return error.InvalidSecretKey;
    defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
    if (scalar.isZero()) return error.InvalidSecretKey;
    var scalar_bytes = scalar.toBytes(.little);
    defer std.crypto.secureZero(u8, &scalar_bytes);
    var scalar_limbs = decodeScalar(scalar_bytes);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&scalar_limbs));
    var affine: AffinePoint = undefined;
    secretBaseMulAffineAssign(&affine, &scalar_limbs);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&affine));
    return .{0x04} ++ affine.x.toBytes(.big) ++ affine.y.toBytes(.big);
}

/// Compute a P-384 ECDH shared x-coordinate from a validated SEC1 point.
pub fn ecdhSharedSecret(
    secret_key_bytes: [secret_key_encoded_length]u8,
    peer_public_key_sec1: []const u8,
) KeyAgreementError![P384.Fe.encoded_length]u8 {
    var owned_secret = secret_key_bytes;
    defer std.crypto.secureZero(u8, &owned_secret);
    var scalar = Scalar.fromBytes(owned_secret, .big) catch
        return error.InvalidSecretKey;
    defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
    if (scalar.isZero()) return error.InvalidSecretKey;
    const peer = P384.fromSec1(peer_public_key_sec1) catch
        return error.InvalidPublicKey;
    peer.rejectIdentity() catch return error.InvalidPublicKey;

    if (comptime scalar_mul_x86.enabled) {
        var scalar_bytes = scalar.toBytes(.little);
        defer std.crypto.secureZero(u8, &scalar_bytes);
        var scalar_limbs = decodeScalar(scalar_bytes);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&scalar_limbs));
        const input = JacobianPoint.fromP384Affine(peer);
        var output: JacobianPoint = undefined;
        defer std.crypto.secureZero(JacobianPoint, (&output)[0..1]);
        scalar_mul_x86.scalarMult(
            @ptrCast(&output),
            &scalar_limbs,
            @ptrCast(&input),
        );
        if (output.isIdentity()) return error.KeyAgreementFailed;
        var inverse = invertSecretField(output.z);
        defer std.crypto.secureZero(Fe, (&inverse)[0..1]);
        var inverse_squared = inverse.sq();
        defer std.crypto.secureZero(Fe, (&inverse_squared)[0..1]);
        var shared_x = output.x.mul(inverse_squared);
        defer std.crypto.secureZero(Fe, (&shared_x)[0..1]);
        return shared_x.toBytes(.big);
    }

    const shared = peer.mul(owned_secret, .big) catch
        return error.KeyAgreementFailed;
    return shared.affineCoordinates().x.toBytes(.big);
}

/// Sign a message while preserving Zig std's deterministic nonce and optional
/// noise semantics. All private arithmetic stays in this pure-Zig module.
pub fn sign(
    comptime Hash: type,
    key_pair: std.crypto.sign.ecdsa.Ecdsa(P384, Hash).KeyPair,
    message: []const u8,
    noise: ?[P384.scalar.encoded_length]u8,
) (std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError)!std.crypto.sign.ecdsa.Ecdsa(
    P384,
    Hash,
).Signature {
    var digest: [Hash.digest_length]u8 = undefined;
    hashMessage(Hash, message, &digest);
    return signPrehashed(Hash, key_pair, digest, noise);
}

/// Sign a digest while preserving Zig std's deterministic nonce and optional
/// noise semantics.
pub fn signPrehashed(
    comptime Hash: type,
    key_pair: std.crypto.sign.ecdsa.Ecdsa(P384, Hash).KeyPair,
    digest: [Hash.digest_length]u8,
    noise: ?[P384.scalar.encoded_length]u8,
) (std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError)!std.crypto.sign.ecdsa.Ecdsa(
    P384,
    Hash,
).Signature {
    defer wipeCallerSavedRegisters();
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P384, Hash);
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
    var affine: AffinePoint = undefined;
    secretBaseMulAffineAssign(&affine, &nonce_limbs);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&affine));
    const r = reduceToScalar(P384.Fe.encoded_length, affine.x.toBytes(.big));
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
    var sum = z.add(r.mul(private_scalar));
    defer std.crypto.secureZero(Scalar, (&sum)[0..1]);
    const s = nonce_inverse.mul(sum);
    if (s.isZero()) return error.IdentityElement;
    return Scheme.Signature{
        .r = r.toBytes(.big),
        .s = s.toBytes(.big),
    };
}

fn reduceToScalar(comptime unreduced_len: usize, bytes: [unreduced_len]u8) Scalar {
    if (unreduced_len == P384.scalar.encoded_length) {
        var limbs: ScalarLimbs = undefined;
        inline for (0..scalar_limb_count) |index| {
            limbs[scalar_limb_count - 1 - index] = std.mem.readInt(
                u64,
                bytes[index * 8 ..][0..8],
                .big,
            );
        }
        var result: Scalar = undefined;
        scalarLimbsToMontgomeryAssign(&result, &limbs);
        return result;
    } else if (unreduced_len > P384.scalar.encoded_length) {
        var wide = [_]u8{0} ** 64;
        @memcpy(wide[wide.len - bytes.len ..], &bytes);
        return Scalar.fromBytes64(wide, .big);
    }
    var padded = [_]u8{0} ** 48;
    @memcpy(padded[padded.len - bytes.len ..], &bytes);
    return Scalar.fromBytes(padded, .big) catch unreachable;
}

noinline fn deterministicScalarAssign(
    comptime Hash: type,
    output: *Scalar,
    digest: *const [Hash.digest_length]u8,
    secret_key: *const [P384.scalar.encoded_length]u8,
    noise: ?[P384.scalar.encoded_length]u8,
) void {
    defer wipeCallerSavedRegisters();
    if (comptime Hash == std.crypto.hash.sha2.Sha384) {
        deterministicScalarSha384Assign(
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
        (Hash.digest_length + 1 + P384.scalar.encoded_length * 2 +
            Hash.digest_length);
    defer std.crypto.secureZero(u8, &material);
    var first_candidate = [_]u8{0x00} ** P384.scalar.encoded_length;
    defer std.crypto.secureZero(u8, &first_candidate);
    var second_candidate = [_]u8{0x00} ** P384.scalar.encoded_length;
    defer std.crypto.secureZero(u8, &second_candidate);
    const value = material[0..Hash.digest_length];
    const separator = &material[value.len];
    const random = material[value.len + 1 ..][0..P384.scalar.encoded_length];
    const secret = material[value.len + 1 + P384.scalar.encoded_length ..][0..P384.scalar.encoded_length];
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
    fillDeterministicCandidate(Prf, &first_candidate, value, &key);

    // Compute the RFC 6979 retry unconditionally so candidate acceptance does
    // not create a secret-dependent branch. A second non-canonical candidate
    // is reduced instead of adding an unbounded timing-dependent retry; its
    // probability is below 2^-388 for the P-384 subgroup order.
    separator.* = 0x00;
    Prf.create(&key, material[0 .. value.len + 1], &key);
    Prf.create(value, value, &key);
    fillDeterministicCandidate(Prf, &second_candidate, value, &key);

    var first: ReducedNonceCandidate = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&first));
    reduceNonceCandidateAssign(&first, &first_candidate);
    var second: ReducedNonceCandidate = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&second));
    reduceNonceCandidateAssign(&second, &second_candidate);
    var result = second.scalar;
    defer std.crypto.secureZero(Scalar, (&result)[0..1]);
    scalarConditionalMove(&result, first.scalar, first.valid);
    const result_zero = scalarZeroChoice(result);
    scalarConditionalMove(&result, Scalar.one, result_zero);
    output.* = result;
}

/// Retain SHA-384's ipad/opad states across adjacent RFC 6979 operations
/// performed under the same derived key.
noinline fn deterministicScalarSha384Assign(
    output: *Scalar,
    digest: *const [std.crypto.hash.sha2.Sha384.digest_length]u8,
    secret_key: *const [P384.scalar.encoded_length]u8,
    noise: ?[P384.scalar.encoded_length]u8,
) void {
    const digest_length = std.crypto.hash.sha2.Sha384.digest_length;
    const PreparedHmac = fast_sha2.PreparedHmac(FastSha384);
    var key = [_]u8{0x00} ** digest_length;
    defer std.crypto.secureZero(u8, &key);
    var material = [_]u8{0x00} **
        (digest_length + 1 + P384.scalar.encoded_length * 2 + digest_length);
    defer std.crypto.secureZero(u8, &material);
    var candidates: [2][P384.scalar.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&candidates));
    const value = material[0..digest_length];
    const separator = &material[value.len];
    const random = material[value.len + 1 ..][0..P384.scalar.encoded_length];
    const secret = material[value.len + 1 + P384.scalar.encoded_length ..][0..P384.scalar.encoded_length];
    const message_hash = material[material.len - digest_length ..];

    @memset(value, 0x01);
    separator.* = 0x00;
    if (noise) |bytes| @memcpy(random, &bytes);
    @memcpy(secret, secret_key);
    @memcpy(message_hash, digest);

    var prepared = PreparedHmac.init(&key);
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

    separator.* = 0x00;
    prepared.createShort(&key, material[0 .. value.len + 1]);
    prepared.deinit();
    prepared.initInto(&key);
    prepared.createShort(value, value);
    prepared.createShort(value, value);
    candidates[1] = value.*;

    var first: ReducedNonceCandidate = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&first));
    reduceNonceCandidateAssign(&first, &candidates[0]);
    var second: ReducedNonceCandidate = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&second));
    reduceNonceCandidateAssign(&second, &candidates[1]);
    var result = second.scalar;
    defer std.crypto.secureZero(Scalar, (&result)[0..1]);
    scalarConditionalMove(&result, first.scalar, first.valid);
    const result_zero = scalarZeroChoice(result);
    scalarConditionalMove(&result, Scalar.one, result_zero);
    output.* = result;
}

fn fillDeterministicCandidate(
    comptime Prf: type,
    candidate: *[P384.scalar.encoded_length]u8,
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
    candidate: *const [48]u8,
) void {
    defer wipeCallerSavedRegisters();
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
    scalarLimbsToMontgomeryAssign(&output.scalar, &limbs);
    output.valid = canonical & (zero ^ 1);
}

fn scalarZeroChoice(value: Scalar) u1 {
    var combined: u64 = 0;
    inline for (value.fe.limbs) |limb| combined |= limb;
    return @truncate((@as(u65, combined) -% 1) >> 64);
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
    signature: std.crypto.sign.ecdsa.Ecdsa(P384, Hash).Signature,
    public_key: std.crypto.sign.ecdsa.Ecdsa(P384, Hash).PublicKey,
) std.crypto.sign.ecdsa.Ecdsa(P384, Hash).Signature.VerifyError!void {
    var digest: [Hash.digest_length]u8 = undefined;
    hashMessage(Hash, message, &digest);
    return verifyPrehashed(Hash, signature, digest, public_key);
}

pub fn verifyPrehashed(
    comptime Hash: type,
    signature: std.crypto.sign.ecdsa.Ecdsa(P384, Hash).Signature,
    digest: [Hash.digest_length]u8,
    public_key: std.crypto.sign.ecdsa.Ecdsa(P384, Hash).PublicKey,
) std.crypto.sign.ecdsa.Ecdsa(P384, Hash).Signature.VerifyError!void {
    const r = try Scalar.fromBytes(signature.r, .big);
    const s = try Scalar.fromBytes(signature.s, .big);
    if (r.isZero() or s.isZero()) return error.IdentityElement;
    try public_key.p.rejectIdentity();

    const z = scalarFromDigest(Hash, digest);
    const inverse = invertPublicScalar(s);
    const scalar_for_base = z.mul(inverse).toBytes(.little);
    const scalar_for_key = r.mul(inverse).toBytes(.little);
    const public_table = precomputeOdd(
        public_wnaf_entries,
        JacobianPoint.fromP384Affine(public_key.p),
    );
    const result = doubleScalarMul(
        scalar_for_base,
        scalar_for_key,
        public_key.p,
        &public_table,
    );
    if (result.isIdentity() or !jacobianXMatchesR(result, r)) {
        return error.SignatureVerificationFailed;
    }
}

pub const testing = struct {
    pub noinline fn invertPublic(value: Scalar) Scalar {
        return invertPublicScalar(value);
    }

    pub noinline fn invertField(value: Fe) Fe {
        return invertSecretField(value);
    }

    pub noinline fn invertFieldStd(value: Fe) Fe {
        return value.invert();
    }

    pub noinline fn mulSecretScalars(a: Scalar, b: Scalar) Scalar {
        return scalarMontgomeryMul(a, b);
    }

    pub noinline fn invertSecret(value: Scalar) Scalar {
        return invertSecretScalar(value);
    }

    pub noinline fn mulBase(value: Scalar) AffinePoint {
        var bytes = value.toBytes(.little);
        defer std.crypto.secureZero(u8, &bytes);
        return secretBaseMulAffine(decodeScalar(bytes));
    }
};

fn invertSecretField(value: Fe) Fe {
    if (comptime field_inv_x86.enabled) {
        return .{ .limbs = field_inv_x86.invert(&value.limbs) };
    }
    return value.invert();
}

noinline fn scalarMontgomeryMulAssign(
    output: *Scalar,
    a: *const Scalar,
    b: *const Scalar,
) void {
    defer wipeCallerSavedRegisters();
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
    var result: Scalar = undefined;
    scalarMontgomeryMulAssign(&result, &a, &b);
    return result;
}

noinline fn scalarLimbsToMontgomeryAssign(
    output: *Scalar,
    limbs: *const ScalarLimbs,
) void {
    // The P-384 order has its high bit set, so every six-limb input is below
    // 2n and the Montgomery kernel's single final subtraction is sufficient.
    var normal = Scalar{ .fe = .{ .limbs = limbs.* } };
    defer std.crypto.secureZero(Scalar, (&normal)[0..1]);
    const r2 = Scalar{ .fe = .{ .limbs = scalar_montgomery_r2 } };
    scalarMontgomeryMulAssign(output, &normal, &r2);
}

noinline fn invertSecretScalarAssign(
    output: *Scalar,
    value: *const Scalar,
) void {
    defer wipeCallerSavedRegisters();
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
        .{ 2, 0, 0, 0, 0, 0 },
    ).value;
    var schedule = InversionSchedule{ .steps = undefined, .len = 0 };
    var pending_squares: usize = 0;
    var bit_end: usize = 384;
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
                @as(u1, @intFromBool(scalarBit(exponent, bit_index)));
        }
        pending_squares += bit_end - bit_start;
        schedule.steps[schedule.len] = .{
            .squares = @intCast(pending_squares),
            .table_index = @truncate(window_value >> 1),
        };
        schedule.len += 1;
        pending_squares = 0;
        bit_end = bit_start;
    }
    std.debug.assert(pending_squares == 0);
    return schedule;
}

inline fn hashMessage(
    comptime Hash: type,
    message: []const u8,
    digest: *[Hash.digest_length]u8,
) void {
    if (comptime Hash == std.crypto.hash.sha2.Sha384) {
        FastSha384.hash(message, digest, .{});
    } else if (comptime Hash == std.crypto.hash.sha2.Sha512) {
        FastSha512.hash(message, digest, .{});
    } else {
        Hash.hash(message, digest, .{});
    }
}

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
        for (0..scalar_limb_count - 1) |index| result[index] = value[index + 1];
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
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

fn scalarOne() ScalarLimbs {
    return .{ 1, 0, 0, 0, 0, 0 };
}

fn decodeScalar(encoded: [48]u8) ScalarLimbs {
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

fn encodeScalar(value: ScalarLimbs) [48]u8 {
    var result: [48]u8 = undefined;
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

fn scalarFromDigest(
    comptime Hash: type,
    digest: [Hash.digest_length]u8,
) Scalar {
    const scalar_len = P384.scalar.encoded_length;
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

const JacobianPoint = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity = JacobianPoint{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    fn fromAffine(point: AffinePoint) JacobianPoint {
        return .{ .x = point.x, .y = point.y, .z = Fe.one };
    }

    fn fromP384Affine(point: P384) JacobianPoint {
        if (point.z.equivalent(Fe.one)) {
            return .{ .x = point.x, .y = point.y, .z = Fe.one };
        }
        const affine = point.affineCoordinates();
        return .{ .x = affine.x, .y = affine.y, .z = Fe.one };
    }

    fn isIdentity(point: JacobianPoint) bool {
        return point.z.isZero();
    }

    fn neg(point: JacobianPoint) JacobianPoint {
        return .{ .x = point.x, .y = point.y.neg(), .z = point.z };
    }

    fn dbl(point: JacobianPoint) JacobianPoint {
        var result = point;
        result.dblAssign();
        return result;
    }

    fn dblAssign(point: *JacobianPoint) void {
        if (!@inComptime() and comptime point_adx.enabled) {
            point_adx.pointDouble(
                @ptrCast(point),
                @ptrCast(point),
            );
            return;
        }
        const delta = point.z.sq();
        const gamma = point.y.sq();
        const beta = point.x.mul(gamma);
        const alpha_base = point.x.sub(delta).mul(point.x.add(delta));
        const alpha = alpha_base.dbl().add(alpha_base);
        const beta4 = beta.dbl().dbl();
        const beta8 = beta4.dbl();
        const x = alpha.sq().sub(beta8);
        const gamma8 = gamma.sq().dbl().dbl().dbl();
        const y = alpha.mul(beta4.sub(x)).sub(gamma8);
        const z = point.y.add(point.z).sq().sub(gamma).sub(delta);
        point.* = .{ .x = x, .y = y, .z = z };
    }

    fn dblSecretAssign(point: *JacobianPoint) void {
        if (comptime point_adx.enabled) {
            point_adx.pointDouble(
                @ptrCast(point),
                @ptrCast(point),
            );
            return;
        }
        const delta = point.z.sq();
        const gamma = point.y.sq();
        const beta = point.x.mul(gamma);
        const alpha_base = point.x.sub(delta).mul(point.x.add(delta));
        const alpha = alpha_base.dbl().add(alpha_base);
        const beta4 = beta.dbl().dbl();
        const beta8 = beta4.dbl();
        const x = alpha.sq().sub(beta8);
        const gamma8 = gamma.sq().dbl().dbl().dbl();
        const y = alpha.mul(beta4.sub(x)).sub(gamma8);
        const z = point.y.add(point.z).sq().sub(gamma).sub(delta);
        point.* = .{ .x = x, .y = y, .z = z };
    }

    fn add(point: JacobianPoint, other: JacobianPoint) JacobianPoint {
        if (point.isIdentity()) return other;
        if (other.isIdentity()) return point;
        if (!@inComptime() and comptime point_adx.enabled) {
            var sum: JacobianPoint = undefined;
            point_adx.pointAdd(
                @ptrCast(&sum),
                @ptrCast(&point),
                @ptrCast(&other),
            );
            if (sum.isIdentity() and point.equivalent(other)) {
                return point.dbl();
            }
            return sum;
        }
        const z1_squared = point.z.sq();
        const z2_squared = other.z.sq();
        const point_x = point.x.mul(z2_squared);
        const other_x = other.x.mul(z1_squared);
        const point_y = point.y.mul(other.z).mul(z2_squared);
        const other_y = other.y.mul(point.z).mul(z1_squared);
        const h = other_x.sub(point_x);
        const r_base = other_y.sub(point_y);
        if (h.isZero()) {
            if (r_base.isZero()) return point.dbl();
            return identity;
        }
        const i = h.dbl().sq();
        const j = h.mul(i);
        const r = r_base.dbl();
        const v = point_x.mul(i);
        const x = r.sq().sub(j).sub(v.dbl());
        const y = r.mul(v.sub(x)).sub(point_y.mul(j).dbl());
        const z = point.z.add(other.z).sq()
            .sub(z1_squared).sub(z2_squared).mul(h);
        return .{ .x = x, .y = y, .z = z };
    }

    fn addMixed(point: JacobianPoint, other: AffinePoint) JacobianPoint {
        if (point.isIdentity()) {
            return .{ .x = other.x, .y = other.y, .z = Fe.one };
        }
        if (!@inComptime() and comptime point_adx.enabled) {
            var sum: JacobianPoint = undefined;
            point_adx.pointMixedAdd(
                @ptrCast(&sum),
                @ptrCast(&point),
                @ptrCast(&other),
            );
            if (sum.isIdentity() and point.equivalent(.{
                .x = other.x,
                .y = other.y,
                .z = Fe.one,
            })) return point.dbl();
            return sum;
        }
        const z_squared = point.z.sq();
        const other_x = other.x.mul(z_squared);
        const other_y = other.y.mul(point.z).mul(z_squared);
        const h = other_x.sub(point.x);
        const r_base = other_y.sub(point.y);
        if (h.isZero()) {
            if (r_base.isZero()) return point.dbl();
            return identity;
        }
        const hh = h.sq();
        const i = hh.dbl().dbl();
        const j = h.mul(i);
        const r = r_base.dbl();
        const v = point.x.mul(i);
        const x = r.sq().sub(j).sub(v.dbl());
        const y = r.mul(v.sub(x)).sub(point.y.mul(j).dbl());
        const z = point.z.add(h).sq().sub(z_squared).sub(hh);
        return .{ .x = x, .y = y, .z = z };
    }

    fn addAssignIncomplete(
        point: *JacobianPoint,
        other: *const JacobianPoint,
    ) bool {
        std.debug.assert(point_adx.enabled);
        point_adx.pointAdd(
            @ptrCast(point),
            @ptrCast(point),
            @ptrCast(other),
        );
        return point.isIdentity();
    }

    fn addMixedAssignIncomplete(
        point: *JacobianPoint,
        other: *const AffinePoint,
    ) bool {
        std.debug.assert(point_adx.enabled);
        point_adx.pointMixedAdd(
            @ptrCast(point),
            @ptrCast(point),
            @ptrCast(other),
        );
        return point.isIdentity();
    }

    noinline fn addMixedSecret(
        point: *JacobianPoint,
        other: *const SecretAffinePoint,
        point_identity: u1,
    ) void {
        defer wipeCallerSavedRegisters();
        var original = point.*;
        defer std.crypto.secureZero(JacobianPoint, (&original)[0..1]);
        if (comptime point_adx.enabled) {
            point_adx.pointMixedAdd(
                @ptrCast(point),
                @ptrCast(point),
                @ptrCast(&other.point),
            );
        } else {
            const z_squared = original.z.sq();
            const other_x = other.point.x.mul(z_squared);
            const other_y = other.point.y.mul(original.z).mul(z_squared);
            const h = other_x.sub(original.x);
            const hh = h.sq();
            const i = hh.dbl().dbl();
            const j = h.mul(i);
            const r = other_y.sub(original.y).dbl();
            const v = original.x.mul(i);
            const x = r.sq().sub(j).sub(v.dbl());
            const y = r.mul(v.sub(x)).sub(original.y.mul(j).dbl());
            const z = original.z.add(h).sq().sub(z_squared).sub(hh);
            point.* = .{ .x = x, .y = y, .z = z };
        }
        const select_other = point_identity & (other.identity ^ 1);
        point.x.cMov(other.point.x, select_other);
        point.y.cMov(other.point.y, select_other);
        point.z.cMov(Fe.one, select_other);
        point.conditionalMove(original, other.identity);
    }

    fn conditionalMove(
        point: *JacobianPoint,
        other: JacobianPoint,
        choice: u1,
    ) void {
        const mask = opaqueWord(0 -% @as(u64, choice));
        const destination: *[3 * scalar_limb_count]u64 = @ptrCast(point);
        const source: *const [3 * scalar_limb_count]u64 = @ptrCast(&other);
        inline for (0..3 * scalar_limb_count) |index| {
            destination[index] = (source[index] & mask) |
                (destination[index] & ~mask);
        }
    }

    fn equivalent(point: JacobianPoint, other: JacobianPoint) bool {
        if (point.isIdentity()) return other.isIdentity();
        if (other.isIdentity()) return false;
        const z1_squared = point.z.sq();
        const z2_squared = other.z.sq();
        if (!point.x.mul(z2_squared).equivalent(other.x.mul(z1_squared))) {
            return false;
        }
        const point_y = point.y.mul(other.z).mul(z2_squared);
        const other_y = other.y.mul(point.z).mul(z1_squared);
        return point_y.equivalent(other_y);
    }

    comptime {
        std.debug.assert(@sizeOf(JacobianPoint) == 18 * @sizeOf(u64));
        std.debug.assert(@offsetOf(JacobianPoint, "x") == 0);
        std.debug.assert(@offsetOf(JacobianPoint, "y") == 6 * @sizeOf(u64));
        std.debug.assert(@offsetOf(JacobianPoint, "z") == 12 * @sizeOf(u64));
    }
};

noinline fn selectSecretBaseAssign(
    output: *SecretAffinePoint,
    table: *const SecretBaseTable,
    index: u6,
) void {
    defer wipeCallerSavedRegisters();
    const offsets = @Vector(secret_selection_lanes, u64){
        0, 1, 2, 3, 4, 5, 6, 7,
    };
    const zero: SecretSelectionVector = @splat(0);
    const ones: SecretSelectionVector = @splat(std.math.maxInt(u64));
    output.identity = @truncate(
        (@as(u7, index) -% 1) >> secret_window_width,
    );
    for (0..scalar_limb_count) |limb| {
        var selected_x = zero;
        var selected_y = zero;
        inline for (0..secret_window_entries / secret_selection_lanes) |chunk| {
            const candidate_indices = offsets +
                @as(SecretSelectionVector, @splat(
                    chunk * secret_selection_lanes,
                ));
            const matches = candidate_indices ==
                @as(SecretSelectionVector, @splat(index));
            const mask = @select(u64, matches, ones, zero);
            const start = chunk * secret_selection_lanes;
            const x: SecretSelectionVector =
                table.x[limb][start..][0..secret_selection_lanes].*;
            const y: SecretSelectionVector =
                table.y[limb][start..][0..secret_selection_lanes].*;
            selected_x |= x & mask;
            selected_y |= y & mask;
        }
        output.point.x.limbs[limb] = @reduce(.Or, selected_x);
        output.point.y.limbs[limb] = @reduce(.Or, selected_y);
    }
}

fn selectSecretBase(
    table: *const SecretBaseTable,
    index: u6,
) SecretAffinePoint {
    var result: SecretAffinePoint = undefined;
    selectSecretBaseAssign(&result, table, index);
    return result;
}

noinline fn secretBaseMulAffineAssign(
    output: *AffinePoint,
    scalar: *const ScalarLimbs,
) void {
    defer wipeCallerSavedRegisters();
    var result = JacobianPoint.identity;
    defer std.crypto.secureZero(JacobianPoint, (&result)[0..1]);
    var result_identity: u1 = 1;
    var window: usize = secret_window_count;
    while (window != 0) {
        window -= 1;
        result.dblSecretAssign();
        for (0..secret_comb_tables) |group| {
            var digit: u6 = 0;
            inline for (0..secret_window_width) |column| {
                const bit_index = window +
                    (group * secret_window_width + column) *
                        secret_window_count;
                const scalar_bit: u1 = @truncate(
                    scalar[bit_index / 64] >> @intCast(bit_index % 64),
                );
                digit |= @as(u6, scalar_bit) << column;
            }
            var selected: SecretAffinePoint = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&selected));
            selectSecretBaseAssign(
                &selected,
                &secret_base_tables[group],
                digit,
            );
            result.addMixedSecret(&selected, result_identity);
            result_identity &= selected.identity;
        }
    }
    var inverse = invertSecretField(result.z);
    defer std.crypto.secureZero(Fe, (&inverse)[0..1]);
    var inverse_squared = inverse.sq();
    defer std.crypto.secureZero(Fe, (&inverse_squared)[0..1]);
    output.* = .{
        .x = result.x.mul(inverse_squared),
        .y = result.y.mul(inverse_squared).mul(inverse),
    };
}

fn secretBaseMulAffine(scalar: ScalarLimbs) AffinePoint {
    var result: AffinePoint = undefined;
    secretBaseMulAffineAssign(&result, &scalar);
    return result;
}

fn precomputeOdd(
    comptime entries: usize,
    point: JacobianPoint,
) [entries]JacobianPoint {
    var multiples: [entries]JacobianPoint = undefined;
    multiples[0] = point;
    const twice = point.dbl();
    for (1..entries) |index| {
        if (!@inComptime() and comptime point_adx.enabled) {
            multiples[index] = multiples[index - 1];
            _ = multiples[index].addAssignIncomplete(&twice);
        } else {
            multiples[index] = multiples[index - 1].add(twice);
        }
    }
    return multiples;
}

fn wnafDigits(
    comptime width: usize,
    scalar: [48]u8,
) [wnaf_digits]i16 {
    var digits = [_]i16{0} ** wnaf_digits;
    var remaining = std.mem.readInt(u384, &scalar, .little);
    var index: usize = 0;
    while (remaining != 0) : (index += 1) {
        if ((remaining & 1) != 0) {
            const residue: u16 = @truncate(remaining & ((1 << width) - 1));
            var digit: i16 = @intCast(residue);
            if (residue >= 1 << (width - 1)) digit -= 1 << width;
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

fn wnafSparse(comptime width: usize, scalar: [48]u8) Wnaf(width) {
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
    while (position < 384) {
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
        std.debug.assert(position == 384);
        std.debug.assert(result.len < result.entries.len);
        result.entries[result.len] = .{ .position = 384, .digit = 1 };
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

fn addSignedWnafAffineIncomplete(
    point: *JacobianPoint,
    comptime entries: usize,
    table: *const [entries]AffinePoint,
    digit: i16,
) bool {
    const magnitude: usize = @intCast(if (digit < 0) -digit else digit);
    const selected = &table[(magnitude - 1) / 2];
    if (digit > 0) return point.addMixedAssignIncomplete(selected);
    var negated = selected.neg();
    return point.addMixedAssignIncomplete(&negated);
}

fn doubleScalarMul(
    base_scalar: [48]u8,
    public_scalar: [48]u8,
    public_key_point: P384,
    public_table: *const [public_wnaf_entries]JacobianPoint,
) JacobianPoint {
    const base_wnaf = wnafSparse(base_wnaf_width, base_scalar);
    const public_wnaf = wnafSparse(public_wnaf_width, public_scalar);
    var result = JacobianPoint.identity;
    var exceptional = false;
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
        result = JacobianPoint.fromAffine(signedWnafPoint(
            base_wnaf_entries,
            &base_wnaf_table,
            base_wnaf.entries[base_index].digit,
        ));
    }
    if (public_index != 0 and
        public_wnaf.entries[public_index - 1].position == position)
    {
        public_index -= 1;
        const public_digit = public_wnaf.entries[public_index].digit;
        if (result.isIdentity()) {
            result = signedWnafJacobianPoint(
                public_wnaf_entries,
                public_table,
                public_digit,
            );
        } else if (comptime point_adx.enabled) {
            exceptional = addSignedWnafJacobianIncomplete(
                &result,
                public_wnaf_entries,
                public_table,
                public_digit,
            );
        } else {
            result = result.add(signedWnafJacobianPoint(
                public_wnaf_entries,
                public_table,
                public_digit,
            ));
        }
    }

    while (position != 0) {
        position -= 1;
        result.dblAssign();
        if (base_index != 0 and
            base_wnaf.entries[base_index - 1].position == position)
        {
            base_index -= 1;
            if (comptime point_adx.enabled) {
                exceptional = addSignedWnafAffineIncomplete(
                    &result,
                    base_wnaf_entries,
                    &base_wnaf_table,
                    base_wnaf.entries[base_index].digit,
                ) or exceptional;
            } else {
                result = result.addMixed(signedWnafPoint(
                    base_wnaf_entries,
                    &base_wnaf_table,
                    base_wnaf.entries[base_index].digit,
                ));
            }
        }
        if (public_index != 0 and
            public_wnaf.entries[public_index - 1].position == position)
        {
            public_index -= 1;
            if (comptime point_adx.enabled) {
                exceptional = addSignedWnafJacobianIncomplete(
                    &result,
                    public_wnaf_entries,
                    public_table,
                    public_wnaf.entries[public_index].digit,
                ) or exceptional;
            } else {
                result = result.add(signedWnafJacobianPoint(
                    public_wnaf_entries,
                    public_table,
                    public_wnaf.entries[public_index].digit,
                ));
            }
        }
    }
    if (exceptional) {
        const exact = P384.mulDoubleBasePublic(
            P384.basePoint,
            base_scalar,
            public_key_point,
            public_scalar,
            .little,
        ) catch return JacobianPoint.identity;
        return JacobianPoint.fromP384Affine(exact);
    }
    return result;
}

fn signedWnafJacobianPoint(
    comptime entries: usize,
    table: *const [entries]JacobianPoint,
    digit: i16,
) JacobianPoint {
    const magnitude: usize = @intCast(if (digit < 0) -digit else digit);
    var point = table[(magnitude - 1) / 2];
    if (digit < 0) point = point.neg();
    return point;
}

fn addSignedWnafJacobianIncomplete(
    point: *JacobianPoint,
    comptime entries: usize,
    table: *const [entries]JacobianPoint,
    digit: i16,
) bool {
    const magnitude: usize = @intCast(if (digit < 0) -digit else digit);
    const selected = &table[(magnitude - 1) / 2];
    if (digit > 0) return point.addAssignIncomplete(selected);
    var negated = selected.neg();
    return point.addAssignIncomplete(&negated);
}

fn jacobianXMatchesR(point: JacobianPoint, r: Scalar) bool {
    const z_squared = point.z.sq();
    const r_bytes = r.toBytes(.big);
    const r_field = Fe.fromBytes(r_bytes, .big) catch unreachable;
    if (point.x.equivalent(r_field.mul(z_squared))) return true;

    const r_int = std.mem.readInt(u384, &r_bytes, .big);
    const p_minus_n: u384 = Fe.field_order - P384.scalar.field_order;
    if (r_int >= p_minus_n) return false;
    var lifted_bytes: [48]u8 = undefined;
    std.mem.writeInt(u384, &lifted_bytes, r_int + P384.scalar.field_order, .big);
    const lifted = Fe.fromBytes(lifted_bytes, .big) catch unreachable;
    return point.x.equivalent(lifted.mul(z_squared));
}

const base_wnaf_table = blk: {
    var points: [base_wnaf_entries]AffinePoint = undefined;
    for (0..base_wnaf_entries) |index| {
        points[index] = .{
            .x = .{ .limbs = table_data.base_wnaf_10[0][index] },
            .y = .{ .limbs = table_data.base_wnaf_10[1][index] },
        };
    }
    break :blk points;
};

const secret_base_tables = blk: {
    var tables: [secret_comb_tables]SecretBaseTable = undefined;
    for (0..secret_comb_tables) |group| {
        tables[group] = .{
            .x = table_data.base_comb_4x6[group][0],
            .y = table_data.base_comb_4x6[group][1],
        };
    }
    break :blk tables;
};

test "P-384 constant-time base multiplication matches Zig std" {
    const fixed = [_]ScalarLimbs{
        .{ 1, 0, 0, 0, 0, 0 },
        .{ 2, 0, 0, 0, 0, 0 },
        .{ 63, 0, 0, 0, 0, 0 },
        scalarSubRaw(scalar_modulus, .{ 1, 0, 0, 0, 0, 0 }).value,
    };
    for (fixed) |scalar| try expectSecretBaseMatchesStd(scalar);

    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..64) |_| {
        var wide: [64]u8 = undefined;
        fillDeterministic(&wide, &state);
        const reduced = Scalar.fromBytes64(wide, .little);
        if (reduced.isZero()) continue;
        try expectSecretBaseMatchesStd(decodeScalar(reduced.toBytes(.little)));
    }
}

fn expectSecretBaseMatchesStd(scalar: ScalarLimbs) !void {
    const bytes = encodeScalar(scalar);
    const expected = try P384.basePoint.mul(bytes, .little);
    const expected_affine = expected.affineCoordinates();
    const actual = secretBaseMulAffine(scalar);
    if (!actual.x.equivalent(expected_affine.x) or
        !actual.y.equivalent(expected_affine.y))
    {
        std.debug.print(
            "P-384 comb mismatch scalar={any} x={} y={}\n",
            .{
                scalar,
                actual.x.equivalent(expected_affine.x),
                actual.y.equivalent(expected_affine.y),
            },
        );
    }
    try std.testing.expect(actual.x.equivalent(expected_affine.x));
    try std.testing.expect(actual.y.equivalent(expected_affine.y));
}

test "P-384 constant-time base-table selection scans every entry" {
    try std.testing.expectEqual(
        @as(
            usize,
            2 * scalar_limb_count * secret_window_entries * @sizeOf(u64),
        ),
        @sizeOf(SecretBaseTable),
    );
    inline for (0..secret_comb_tables) |group| {
        for (0..secret_window_entries) |index| {
            const selected = selectSecretBase(
                &secret_base_tables[group],
                @intCast(index),
            );
            inline for (0..scalar_limb_count) |limb| {
                try std.testing.expectEqual(
                    secret_base_tables[group].x[limb][index],
                    selected.point.x.limbs[limb],
                );
                try std.testing.expectEqual(
                    secret_base_tables[group].y[limb][index],
                    selected.point.y.limbs[limb],
                );
            }
            try std.testing.expectEqual(
                @as(u1, @intFromBool(index == 0)),
                selected.identity,
            );
        }
    }
}

test "P-384 constant-time base tables have the expected comb weights" {
    inline for (0..secret_comb_tables) |group| {
        inline for ([_]u6{ 1, 2, 3, 31, 63 }) |index| {
            var scalar: u384 = 0;
            inline for (0..secret_window_width) |column| {
                if ((index >> column) & 1 != 0) {
                    scalar |= @as(u384, 1) << @intCast(
                        (group * secret_window_width + column) *
                            secret_window_count,
                    );
                }
            }
            var bytes: [48]u8 = undefined;
            std.mem.writeInt(u384, &bytes, scalar, .little);
            const expected = try P384.basePoint.mul(bytes, .little);
            const expected_affine = expected.affineCoordinates();
            const selected = selectSecretBase(
                &secret_base_tables[group],
                index,
            );
            if (!selected.point.x.equivalent(expected_affine.x) or
                !selected.point.y.equivalent(expected_affine.y))
            {
                std.debug.print("comb table mismatch group={} index={}\n", .{
                    group,
                    index,
                });
            }
            try std.testing.expect(
                selected.point.x.equivalent(expected_affine.x),
            );
            try std.testing.expect(
                selected.point.y.equivalent(expected_affine.y),
            );
        }
    }
}

test "P-384 signer exactly matches Zig std with SHA-384" {
    try expectSignerMatchesStd(std.crypto.hash.sha2.Sha384);
}

test "P-384 ECDH matches Zig std and agrees in both directions" {
    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..64) |_| {
        var first_secret: [secret_key_encoded_length]u8 = undefined;
        var second_secret: [secret_key_encoded_length]u8 = undefined;
        fillDeterministic(&first_secret, &state);
        fillDeterministic(&second_secret, &state);
        first_secret[0] &= 0x7f;
        second_secret[0] &= 0x7f;
        first_secret[first_secret.len - 1] |= 1;
        second_secret[second_secret.len - 1] |= 1;

        const first_public = try ecdhPublicKey(first_secret);
        const second_public = try ecdhPublicKey(second_secret);
        const second_point = try P384.fromSec1(&second_public);
        const first_point = try P384.fromSec1(&first_public);
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

        const compressed = (try P384.fromSec1(&second_public)).toCompressedSec1();
        try std.testing.expectEqualSlices(
            u8,
            &first_shared,
            &try ecdhSharedSecret(first_secret, &compressed),
        );
    }
}

test "P-384 ECDH rejects invalid secret and peer encodings" {
    var valid_secret = [_]u8{0} ** secret_key_encoded_length;
    valid_secret[valid_secret.len - 1] = 7;
    const valid_public = try ecdhPublicKey(valid_secret);
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhPublicKey([_]u8{0} ** secret_key_encoded_length),
    );
    var modulus_big = encodeScalar(scalar_modulus);
    std.mem.reverse(u8, &modulus_big);
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhSharedSecret(modulus_big, &valid_public),
    );
    try std.testing.expectError(
        error.InvalidPublicKey,
        ecdhSharedSecret(valid_secret, &[_]u8{0x04}),
    );
}

fn expectSignerMatchesStd(comptime Hash: type) !void {
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P384, Hash);
    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0x91} ** Scheme.KeyPair.seed_length,
    );
    const message = "Vail constant-time P-384 signer";
    const deterministic_expected = try key_pair.sign(message, null);
    const deterministic_actual = try sign(Hash, key_pair, message, null);
    try std.testing.expectEqualSlices(
        u8,
        &deterministic_expected.toBytes(),
        &deterministic_actual.toBytes(),
    );
    try verify(
        Hash,
        message,
        deterministic_actual,
        key_pair.public_key,
    );

    const noise = [_]u8{0x69} ** Scheme.noise_length;
    const noisy_expected = try key_pair.sign(message, noise);
    const noisy_actual = try sign(Hash, key_pair, message, noise);
    try std.testing.expectEqualSlices(
        u8,
        &noisy_expected.toBytes(),
        &noisy_actual.toBytes(),
    );
    try verify(Hash, message, noisy_actual, key_pair.public_key);
}

test "P-384 verifier matches Zig std across hash functions" {
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha224);
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha256);
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha384);
    try expectValidAndInvalid(std.crypto.hash.sha2.Sha512);
    try expectValidAndInvalid(std.crypto.hash.sha3.Sha3_256);
    try expectValidAndInvalid(std.crypto.hash.sha3.Sha3_384);
    try expectValidAndInvalid(std.crypto.hash.sha3.Sha3_512);
    try expectValidAndInvalid(std.crypto.hash.sha3.Shake128);
    try expectValidAndInvalid(std.crypto.hash.sha3.Shake256);
}

fn expectValidAndInvalid(comptime Hash: type) !void {
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P384, Hash);
    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Scheme.KeyPair.seed_length,
    );
    const message = "Vail projective P-384 verification";
    const signature = try key_pair.sign(message, null);
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key = try Scheme.PublicKey.fromSec1(&encoded_public_key);
    try signature.verify(message, public_key);
    try verify(Hash, message, signature, public_key);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verify(Hash, "tampered", signature, public_key),
    );
}

test "P-384 verifier rejects zero and non-canonical signature scalars" {
    const Hash = std.crypto.hash.sha2.Sha384;
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(P384, Hash);
    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0x73} ** Scheme.KeyPair.seed_length,
    );
    const encoded_public_key = key_pair.public_key.toUncompressedSec1();
    const public_key = try Scheme.PublicKey.fromSec1(&encoded_public_key);
    const message = "P-384 scalar boundaries";
    const signature = try key_pair.sign(message, null);

    var zero_r = signature;
    zero_r.r = [_]u8{0} ** P384.scalar.encoded_length;
    try std.testing.expectError(
        error.IdentityElement,
        verify(Hash, message, zero_r, public_key),
    );
    var zero_s = signature;
    zero_s.s = [_]u8{0} ** P384.scalar.encoded_length;
    try std.testing.expectError(
        error.IdentityElement,
        verify(Hash, message, zero_s, public_key),
    );
    var non_canonical = signature;
    const modulus_little = encodeScalar(scalar_modulus);
    for (modulus_little, 0..) |byte, index| {
        non_canonical.r[P384.scalar.encoded_length - 1 - index] = byte;
    }
    try std.testing.expectError(
        error.NonCanonical,
        verify(Hash, message, non_canonical, public_key),
    );
}

test "P-384 Jacobian x check accepts r and r+n representatives" {
    const r = try Scalar.fromBytes(
        [_]u8{0} ** (P384.scalar.encoded_length - 1) ++ [_]u8{1},
        .big,
    );
    const z = try Fe.fromInt(7);
    const one = try Fe.fromInt(1);
    const two = try Fe.fromInt(2);
    const lifted = try Fe.fromInt(P384.scalar.field_order + 1);

    try std.testing.expect(jacobianXMatchesR(.{
        .x = one.mul(z.sq()),
        .y = one,
        .z = z,
    }, r));
    try std.testing.expect(jacobianXMatchesR(.{
        .x = lifted.mul(z.sq()),
        .y = one,
        .z = z,
    }, r));
    try std.testing.expect(!jacobianXMatchesR(.{
        .x = two.mul(z.sq()),
        .y = one,
        .z = z,
    }, r));
}

test "P-384 public scalar inversion matches the fixed-time inverse" {
    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..128) |_| {
        var wide: [64]u8 = undefined;
        fillDeterministic(&wide, &state);
        const value = Scalar.fromBytes64(wide, .little);
        if (value.isZero()) continue;
        try std.testing.expect(
            invertPublicScalar(value).equivalent(value.invert()),
        );
    }
}

test "P-384 secret field inversion matches Zig std" {
    var state: u64 = 0xa409_3822_299f_31d0;
    for (0..128) |_| {
        var encoded: [48]u8 = undefined;
        fillDeterministic(&encoded, &state);
        const value = Fe.fromBytes(encoded, .little) catch continue;
        const actual = invertSecretField(value);
        try std.testing.expect(actual.equivalent(value.invert()));
        if (!value.isZero()) {
            try std.testing.expect(actual.mul(value).equivalent(Fe.one));
        }
    }
}

test "P-384 secret scalar Montgomery multiplication matches Zig std" {
    var state: u64 = 0x4528_21e6_38d0_1377;
    for (0..256) |_| {
        var wide_a: [64]u8 = undefined;
        var wide_b: [64]u8 = undefined;
        fillDeterministic(&wide_a, &state);
        fillDeterministic(&wide_b, &state);
        const a = Scalar.fromBytes64(wide_a, .little);
        const b = Scalar.fromBytes64(wide_b, .little);
        try std.testing.expect(
            scalarMontgomeryMul(a, b).equivalent(a.mul(b)),
        );
    }
}

test "P-384 optimized secret scalar inversion matches Zig std" {
    const fixed = [_]Scalar{
        Scalar.one,
        Scalar.fromBytes(
            encodeScalar(scalarSubRaw(
                scalar_modulus,
                .{ 1, 0, 0, 0, 0, 0 },
            ).value),
            .little,
        ) catch unreachable,
    };
    for (fixed) |value| {
        const actual = invertSecretScalar(value);
        try std.testing.expect(actual.equivalent(value.invert()));
        try std.testing.expect(
            scalarMontgomeryMul(actual, value).equivalent(Scalar.one),
        );
    }

    var state: u64 = 0xbe54_66cf_34e9_0c6c;
    for (0..128) |_| {
        var wide: [64]u8 = undefined;
        fillDeterministic(&wide, &state);
        const value = Scalar.fromBytes64(wide, .little);
        if (value.isZero()) continue;
        const actual = invertSecretScalar(value);
        try std.testing.expect(actual.equivalent(value.invert()));
        try std.testing.expect(
            scalarMontgomeryMul(actual, value).equivalent(Scalar.one),
        );
    }
}

test "P-384 nonce candidates use branchless canonical selection" {
    const zero_bytes = [_]u8{0} ** 48;
    var zero: ReducedNonceCandidate = undefined;
    reduceNonceCandidateAssign(&zero, &zero_bytes);
    try std.testing.expectEqual(@as(u1, 0), zero.valid);
    try std.testing.expect(zero.scalar.isZero());

    const modulus = encodeScalar(scalar_modulus);
    var modulus_big = modulus;
    std.mem.reverse(u8, &modulus_big);
    var non_canonical: ReducedNonceCandidate = undefined;
    reduceNonceCandidateAssign(&non_canonical, &modulus_big);
    try std.testing.expectEqual(@as(u1, 0), non_canonical.valid);
    try std.testing.expect(non_canonical.scalar.isZero());

    const below = scalarSubRaw(
        scalar_modulus,
        .{ 1, 0, 0, 0, 0, 0 },
    ).value;
    var below_big = encodeScalar(below);
    std.mem.reverse(u8, &below_big);
    var canonical: ReducedNonceCandidate = undefined;
    reduceNonceCandidateAssign(&canonical, &below_big);
    try std.testing.expectEqual(@as(u1, 1), canonical.valid);
    try std.testing.expectEqualSlices(
        u8,
        &below_big,
        &canonical.scalar.toBytes(.big),
    );

    const all_ones = [_]u8{0xff} ** P384.scalar.encoded_length;
    var maximum: ReducedNonceCandidate = undefined;
    reduceNonceCandidateAssign(&maximum, &all_ones);
    const expected_maximum = Scalar.fromBytes64(
        [_]u8{0} ** 16 ++ all_ones,
        .big,
    );
    try std.testing.expectEqual(@as(u1, 0), maximum.valid);
    try std.testing.expect(maximum.scalar.equivalent(expected_maximum));
}

fn expectSparseWnafMatches(comptime width: usize, scalar: [48]u8) !void {
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

test "P-384 sparse wNAF matches dense recoding" {
    const zero = [_]u8{0} ** 48;
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
        var scalar: [48]u8 = undefined;
        fillDeterministic(&scalar, &state);
        if (!scalarLessThan(decodeScalar(scalar), scalar_modulus)) continue;
        try expectSparseWnafMatches(base_wnaf_width, scalar);
        try expectSparseWnafMatches(public_wnaf_width, scalar);
        checked += 1;
    }
}

test "P-384 Jacobian double-scalar multiplication matches Zig std" {
    var state: u64 = 0xa409_3822_299f_31d0;
    for (0..32) |_| {
        var public_scalar: [48]u8 = undefined;
        var base_scalar: [48]u8 = undefined;
        var point_scalar: [48]u8 = undefined;
        fillDeterministic(&public_scalar, &state);
        fillDeterministic(&base_scalar, &state);
        fillDeterministic(&point_scalar, &state);
        point_scalar[0] |= 1;

        const public_point = P384.basePoint.mulPublic(
            point_scalar,
            .little,
        ) catch continue;
        const public_table = precomputeOdd(
            public_wnaf_entries,
            JacobianPoint.fromP384Affine(public_point),
        );
        const actual = doubleScalarMul(
            base_scalar,
            public_scalar,
            public_point,
            &public_table,
        );
        const expected = P384.mulDoubleBasePublic(
            P384.basePoint,
            base_scalar,
            public_point,
            public_scalar,
            .little,
        ) catch {
            try std.testing.expect(actual.isIdentity());
            continue;
        };
        try expectJacobianMatchesP384(actual, expected);
    }
}

test "P-384 Jacobian operations handle exceptional inputs" {
    const affine_generator = AffinePoint{
        .x = P384.basePoint.x,
        .y = P384.basePoint.y,
    };
    const generator = JacobianPoint.fromAffine(affine_generator);
    try std.testing.expect(JacobianPoint.identity.dbl().isIdentity());
    try expectJacobianMatchesP384(
        JacobianPoint.identity.add(generator),
        P384.basePoint,
    );
    try expectJacobianMatchesP384(
        generator.add(JacobianPoint.identity),
        P384.basePoint,
    );
    try expectJacobianMatchesP384(generator.dbl(), P384.basePoint.dbl());
    try expectJacobianMatchesP384(generator.add(generator), P384.basePoint.dbl());
    try std.testing.expect(generator.add(generator.neg()).isIdentity());
    try expectJacobianMatchesP384(
        generator.addMixed(affine_generator),
        P384.basePoint.dbl(),
    );
    try std.testing.expect(generator.addMixed(affine_generator.neg()).isIdentity());
}

fn expectJacobianMatchesP384(actual: JacobianPoint, expected: P384) !void {
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
    for (output) |*byte| {
        state.* ^= state.* << 13;
        state.* ^= state.* >> 7;
        state.* ^= state.* << 17;
        byte.* = @truncate(state.*);
    }
}
