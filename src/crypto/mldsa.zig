//! Pure-Zig ML-DSA helpers layered over Zig std's FIPS 204 implementation.

const std = @import("std");
const keccak4 = @import("keccak4.zig");
const keccak_avx2 = @import("keccak_avx2.zig");
const mldsa_avx2 = @import("mldsa_avx2.zig");

pub const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;
pub const MlDsa65 = std.crypto.sign.mldsa.MLDSA65;
pub const MlDsa87 = std.crypto.sign.mldsa.MLDSA87;
pub const mldsa_accelerated = mldsa_avx2.enabled;
pub const mldsa44_accelerated = mldsa_accelerated;

const coefficient_count = 256;
const modulus: u32 = 8_380_417;
const t1_bytes_per_poly = 320;
const q_inverse: u32 = 4_236_238_847;
const r_over_256: u32 = 41_978;
const primitive_root: u32 = 1_753;
const decomposition_gamma2: u32 = 95_232;

const PolyVec4 = @TypeOf(@as(MlDsa44.PublicKey, undefined).t1);
const Poly = @TypeOf(@as(PolyVec4, undefined).ps[0]);
const Matrix44 = @TypeOf(@as(MlDsa44.PublicKey, undefined).A);
const AcceleratedMatrix44 = if (mldsa_avx2.enabled) Matrix44 else void;
const AcceleratedPolyVec4 = if (mldsa_avx2.enabled) PolyVec4 else void;
const FallbackSecretKey44 = if (mldsa_avx2.enabled) void else MlDsa44.SecretKey;
const Vector4u32 = @Vector(4, u32);
const Vector4u64 = @Vector(4, u64);

const Shake256 = if (keccak_avx2.enabled)
    FastShake256
else
    std.crypto.hash.sha3.Shake256;

const FastShake256 = keccak_avx2.Shake256;

fn initShake256() Shake256 {
    if (comptime keccak_avx2.enabled) return FastShake256.init(.{});
    return std.crypto.hash.sha3.Shake256.init(.{});
}

/// An ML-DSA-44 public key prepared for repeated verification.
///
/// This owns the public-key hash and matrix representation needed by verify,
/// plus `NTT(2^D * t1)`, a public-key-only term otherwise recomputed for every
/// signature.
pub const PreparedVerifier44 = struct {
    tr: [64]u8,
    matrix_hat: Matrix44 align(32),
    t1_2d_hat: PolyVec4 align(32),

    pub fn init(public_key: *const MlDsa44.PublicKey) PreparedVerifier44 {
        var t1_2d_hat: PolyVec4 align(32) = public_key.t1;
        for (&t1_2d_hat.ps) |*poly| {
            for (&poly.cs) |*coefficient| coefficient.* <<= 13;
            if (comptime mldsa_avx2.enabled) {
                nttCustomSignedAlignedInPlace(@alignCast(poly));
            } else {
                nttScalarInPlace(poly);
            }
        }
        return .{
            .matrix_hat = if (comptime mldsa_avx2.enabled)
                matrixToCustomOrder(&public_key.A)
            else
                public_key.A,
            .tr = public_key.tr,
            .t1_2d_hat = t1_2d_hat,
        };
    }

    /// Decode and prepare a public key without materializing an intermediate
    /// Zig std `PublicKey` on accelerated targets.
    pub fn fromBytes(
        bytes: [MlDsa44.PublicKey.encoded_length]u8,
    ) !PreparedVerifier44 {
        if (comptime !keccak4.enabled) {
            const public_key = try MlDsa44.PublicKey.fromBytes(bytes);
            return init(&public_key);
        }

        var prepared: PreparedVerifier44 = undefined;
        var rho: [32]u8 = bytes[0..32].*;
        deriveMatrix44(&prepared.matrix_hat, &rho);
        matrixToCustomOrderInPlace(@alignCast(&prepared.matrix_hat));
        inline for (0..4) |index| {
            unpackT1(
                &prepared.t1_2d_hat.ps[index].cs,
                bytes[32 + index * t1_bytes_per_poly ..][0..t1_bytes_per_poly],
            );
            for (&prepared.t1_2d_hat.ps[index].cs) |*coefficient| {
                coefficient.* <<= 13;
            }
            nttCustomSignedAlignedInPlace(
                @alignCast(&prepared.t1_2d_hat.ps[index]),
            );
        }

        var hash = initShake256();
        hash.update(&bytes);
        hash.squeeze(&prepared.tr);
        return prepared;
    }

    pub fn verify(
        self: *const PreparedVerifier44,
        signature: MlDsa44.Signature,
        message: []const u8,
    ) std.crypto.errors.SignatureVerificationError!void {
        return self.verifyWithContext(signature, message, "");
    }

    pub fn verifyWithContext(
        self: *const PreparedVerifier44,
        signature: MlDsa44.Signature,
        message: []const u8,
        context: []const u8,
    ) std.crypto.errors.SignatureVerificationError!void {
        if (context.len > 255) return error.SignatureVerificationFailed;
        var hash = initShake256();
        hash.update(&self.tr);
        hash.update(&[_]u8{ 0, @intCast(context.len) });
        hash.update(context);
        hash.update(message);
        var mu: [64]u8 = undefined;
        hash.squeeze(&mu);
        return self.verifyMu(&signature, &mu);
    }

    pub fn verifyPrepared(
        self: *const PreparedVerifier44,
        signature: *const PreparedSignature44,
        message: []const u8,
    ) std.crypto.errors.SignatureVerificationError!void {
        var hash = initMessageHash(&self.tr, "");
        hash.update(message);
        var mu: [64]u8 = undefined;
        hash.squeeze(&mu);
        return self.verifyMu(signature, &mu);
    }

    /// Create an incremental verifier while retaining this prepared public key.
    pub fn verifier(
        self: *const PreparedVerifier44,
        signature: MlDsa44.Signature,
        context: []const u8,
    ) std.crypto.errors.ContextTooLongError!Verifier44 {
        return Verifier44.init(self, signature, context);
    }

    fn verifyMu(
        self: *const PreparedVerifier44,
        signature: anytype,
        mu: *const [64]u8,
    ) std.crypto.errors.SignatureVerificationError!void {
        var z_hat: PolyVec4 align(32) = signature.z;
        var w_prime: PolyVec4 align(32) = undefined;
        if (comptime mldsa_avx2.enabled) {
            nttCustomSignedVectorAlignedInPlace(&z_hat);
            matrixMulVectorHatCustom(
                &w_prime,
                @alignCast(&self.matrix_hat),
                &z_hat,
            );

            var challenge_hat: Poly align(32) = sampleInBall44(&signature.c_tilde);
            nttCustomSignedAlignedInPlace(&challenge_hat);
            for (0..4) |row| {
                var product: Poly align(32) = self.t1_2d_hat.ps[row];
                mldsa_avx2.pointwise(
                    @ptrCast(@alignCast(&product.cs)),
                    @ptrCast(@alignCast(&challenge_hat.cs)),
                );
                subtractSignedForInv(&w_prime.ps[row], &product);
                mldsa_avx2.invNtt(
                    @ptrCast(@alignCast(&w_prime.ps[row].cs)),
                );
                normalizeSignedPolyInPlace(&w_prime.ps[row]);
            }
        } else {
            nttScalarVectorInPlace(&z_hat);
            w_prime = matrixMulVectorHat(&self.matrix_hat, &z_hat);
            var challenge_hat = sampleInBall44(&signature.c_tilde);
            nttScalarInPlace(&challenge_hat);
            for (0..4) |row| {
                const product = mulHat(
                    self.t1_2d_hat.ps[row],
                    challenge_hat,
                );
                w_prime.ps[row] = sub(w_prime.ps[row], product);
                reduceLe2QInPlace(&w_prime.ps[row]);
                invNttInPlace(&w_prime.ps[row]);
                normalizeLe2QInPlace(&w_prime.ps[row]);
            }
        }

        var w1_packed: [4 * 192]u8 = undefined;
        if (comptime mldsa_avx2.enabled) {
            var hint: PolyVec4 align(32) = signature.hint;
            for (0..4) |row| {
                mldsa_avx2.useHint88(
                    @ptrCast(@alignCast(&w_prime.ps[row].cs)),
                    @ptrCast(@alignCast(&hint.ps[row].cs)),
                );
                packW1High(
                    &w_prime.ps[row],
                    w1_packed[row * 192 ..][0..192],
                );
            }
        } else {
            for (0..4) |row| {
                packW1(
                    &w_prime.ps[row],
                    &signature.hint.ps[row],
                    w1_packed[row * 192 ..][0..192],
                );
            }
        }

        var challenge_hash = initShake256();
        challenge_hash.update(mu);
        challenge_hash.update(&w1_packed);
        var expected_challenge: [32]u8 = undefined;
        challenge_hash.squeeze(&expected_challenge);
        if (!std.mem.eql(u8, &expected_challenge, &signature.c_tilde)) {
            return error.SignatureVerificationFailed;
        }
    }
};

/// ML-DSA-44 signature decoded into the representation consumed by the
/// accelerated verifier. On portable targets this remains Zig std's canonical
/// non-negative representation.
pub const PreparedSignature44 = struct {
    c_tilde: [32]u8,
    z: PolyVec4 align(32),
    hint: PolyVec4 align(32),

    pub fn fromBytes(
        bytes: *const [MlDsa44.Signature.encoded_length]u8,
    ) std.crypto.errors.EncodingError!PreparedSignature44 {
        if (comptime !mldsa_avx2.enabled) {
            const signature = try MlDsa44.Signature.fromBytes(bytes.*);
            return .{
                .c_tilde = signature.c_tilde,
                .z = signature.z,
                .hint = signature.hint,
            };
        }

        var signature: PreparedSignature44 = undefined;
        signature.c_tilde = bytes[0..32].*;
        inline for (0..4) |index| {
            mldsa_avx2.unpackZ17(
                @ptrCast(@alignCast(&signature.z.ps[index].cs)),
                bytes[32 + index * 576 ..][0..576],
            );
            if (mldsa_avx2.exceeds(
                @ptrCast(@alignCast(&signature.z.ps[index].cs)),
                130_994,
            )) return error.InvalidEncoding;
        }
        signature.hint = try unpackHint44(bytes[2_336..]);
        return signature;
    }
};

pub const PreparedSignature65 = PreparedSignatureWideImpl(
    MlDsa65,
    6,
    5,
    55,
    48,
    524_092,
);
pub const PreparedSignature87 = PreparedSignatureWideImpl(
    MlDsa87,
    8,
    7,
    75,
    64,
    524_168,
);

pub const PreparedVerifier65 = PreparedVerifierWideImpl(
    MlDsa65,
    PreparedSignature65,
    6,
    5,
    49,
    48,
);
pub const PreparedVerifier87 = PreparedVerifierWideImpl(
    MlDsa87,
    PreparedSignature87,
    8,
    7,
    60,
    64,
);

fn PreparedSignatureWideImpl(
    comptime MlDsa: type,
    comptime k: usize,
    comptime l: usize,
    comptime omega: usize,
    comptime challenge_bytes: usize,
    comptime norm_bound: i32,
) type {
    const VectorL = @TypeOf(@as(MlDsa.Signature, undefined).z);
    const VectorK = @TypeOf(@as(MlDsa.Signature, undefined).hint);
    return struct {
        c_tilde: [challenge_bytes]u8,
        z: VectorL align(32),
        hint: VectorK align(32),

        const Self = @This();

        pub fn fromBytes(
            bytes: *const [MlDsa.Signature.encoded_length]u8,
        ) std.crypto.errors.EncodingError!Self {
            if (comptime !mldsa_avx2.enabled) {
                const signature = try MlDsa.Signature.fromBytes(bytes.*);
                return .{
                    .c_tilde = signature.c_tilde,
                    .z = signature.z,
                    .hint = signature.hint,
                };
            }

            var signature: Self = undefined;
            signature.c_tilde = bytes[0..challenge_bytes].*;
            inline for (0..l) |index| {
                const offset = challenge_bytes + index * 640;
                mldsa_avx2.unpackZ19(
                    @ptrCast(@alignCast(&signature.z.ps[index].cs)),
                    bytes[offset..][0..640],
                );
                if (mldsa_avx2.exceeds(
                    @ptrCast(@alignCast(&signature.z.ps[index].cs)),
                    norm_bound,
                )) return error.InvalidEncoding;
            }
            signature.hint = try unpackHint(
                VectorK,
                k,
                omega,
                bytes[challenge_bytes + l * 640 ..],
            );
            return signature;
        }
    };
}

fn PreparedVerifierWideImpl(
    comptime MlDsa: type,
    comptime PreparedSignature: type,
    comptime k: usize,
    comptime l: usize,
    comptime tau: u16,
    comptime challenge_bytes: usize,
) type {
    const PublicKey = MlDsa.PublicKey;
    const Matrix = @TypeOf(@as(PublicKey, undefined).A);
    const VectorK = @TypeOf(@as(PublicKey, undefined).t1);
    const VectorL = @TypeOf(@as(MlDsa.Signature, undefined).z);
    const FallbackPublicKey = if (mldsa_avx2.enabled) void else PublicKey;
    return struct {
        tr: [64]u8,
        matrix_hat: if (mldsa_avx2.enabled) Matrix else void align(if (mldsa_avx2.enabled) 32 else 1),
        t1_2d_hat: if (mldsa_avx2.enabled) VectorK else void align(if (mldsa_avx2.enabled) 32 else 1),
        fallback_public_key: FallbackPublicKey,

        const Self = @This();

        pub fn init(public_key: *const PublicKey) Self {
            if (comptime !mldsa_avx2.enabled) {
                return .{
                    .tr = public_key.tr,
                    .matrix_hat = {},
                    .t1_2d_hat = {},
                    .fallback_public_key = public_key.*,
                };
            }
            var matrix_hat: Matrix align(32) = public_key.A;
            matrixToCustomOrderGeneric(&matrix_hat, k, l);
            var t1_2d_hat: VectorK align(32) = public_key.t1;
            for (&t1_2d_hat.ps) |*poly| {
                for (&poly.cs) |*coefficient| coefficient.* <<= 13;
                nttCustomSignedAlignedInPlace(@alignCast(poly));
            }
            return .{
                .tr = public_key.tr,
                .matrix_hat = matrix_hat,
                .t1_2d_hat = t1_2d_hat,
                .fallback_public_key = {},
            };
        }

        pub fn fromBytes(bytes: [PublicKey.encoded_length]u8) !Self {
            if (comptime !mldsa_avx2.enabled) {
                const public_key = try PublicKey.fromBytes(bytes);
                return init(&public_key);
            }
            var prepared: Self = undefined;
            const rho = bytes[0..32].*;
            deriveMatrixGeneric(&prepared.matrix_hat, &rho, k, l);
            matrixToCustomOrderGeneric(&prepared.matrix_hat, k, l);
            inline for (0..k) |index| {
                unpackT1(
                    &prepared.t1_2d_hat.ps[index].cs,
                    bytes[32 + index * t1_bytes_per_poly ..][0..t1_bytes_per_poly],
                );
                for (&prepared.t1_2d_hat.ps[index].cs) |*coefficient| {
                    coefficient.* <<= 13;
                }
                nttCustomSignedAlignedInPlace(
                    @alignCast(&prepared.t1_2d_hat.ps[index]),
                );
            }
            var hash = initShake256();
            hash.update(&bytes);
            hash.squeeze(&prepared.tr);
            prepared.fallback_public_key = {};
            return prepared;
        }

        pub fn verifyPrepared(
            self: *const Self,
            signature: *const PreparedSignature,
            message: []const u8,
        ) std.crypto.errors.SignatureVerificationError!void {
            if (comptime !mldsa_avx2.enabled) {
                const standard: MlDsa.Signature = .{
                    .c_tilde = signature.c_tilde,
                    .z = signature.z,
                    .hint = signature.hint,
                };
                standard.verify(message, self.fallback_public_key) catch
                    return error.SignatureVerificationFailed;
                return;
            }

            var hash = initMessageHash(&self.tr, "");
            hash.update(message);
            var mu: [64]u8 = undefined;
            hash.squeeze(&mu);

            var z_hat: VectorL align(32) = signature.z;
            nttCustomSignedVector(&z_hat);
            var w_prime: VectorK align(32) = undefined;
            matrixMulVectorHatCustomGeneric(
                &w_prime,
                &self.matrix_hat,
                &z_hat,
                k,
                l,
            );
            var challenge_hat: Poly align(32) = sampleInBall(tau, &signature.c_tilde);
            nttCustomSignedAlignedInPlace(&challenge_hat);
            for (0..k) |row| {
                var product: Poly align(32) = self.t1_2d_hat.ps[row];
                pointwiseInPlace(&product, &challenge_hat);
                subtractSignedForInv(&w_prime.ps[row], &product);
                mldsa_avx2.invNtt(
                    @ptrCast(@alignCast(&w_prime.ps[row].cs)),
                );
                normalizeSignedPolyInPlace(&w_prime.ps[row]);
            }

            var hint: VectorK align(32) = signature.hint;
            var w1_packed: [k * 128]u8 = undefined;
            for (0..k) |row| {
                mldsa_avx2.useHint32(
                    @ptrCast(@alignCast(&w_prime.ps[row].cs)),
                    @ptrCast(@alignCast(&hint.ps[row].cs)),
                );
                packW1High19(
                    &w_prime.ps[row],
                    w1_packed[row * 128 ..][0..128],
                );
            }

            var challenge_hash = initShake256();
            challenge_hash.update(&mu);
            challenge_hash.update(&w1_packed);
            var expected: [challenge_bytes]u8 = undefined;
            challenge_hash.squeeze(&expected);
            if (!std.mem.eql(u8, &expected, &signature.c_tilde)) {
                return error.SignatureVerificationFailed;
            }
        }
    };
}

/// ML-DSA-44 secret key prepared for repeated signing. Call `deinit` when the
/// signer is no longer needed so all cached secret material is erased.
pub const PreparedSigner44 = struct {
    key: [32]u8,
    tr: [64]u8,
    matrix_hat: AcceleratedMatrix44 align(if (mldsa_avx2.enabled) 32 else 1),
    s1_hat: AcceleratedPolyVec4 align(if (mldsa_avx2.enabled) 32 else 1),
    s2_hat: AcceleratedPolyVec4 align(if (mldsa_avx2.enabled) 32 else 1),
    t0_hat: AcceleratedPolyVec4 align(if (mldsa_avx2.enabled) 32 else 1),
    fallback_secret_key: FallbackSecretKey44,

    pub fn init(secret_key: *const MlDsa44.SecretKey) PreparedSigner44 {
        if (comptime !mldsa_avx2.enabled) {
            return .{
                .key = secret_key.key,
                .tr = secret_key.tr,
                .matrix_hat = {},
                .s1_hat = {},
                .s2_hat = {},
                .t0_hat = {},
                .fallback_secret_key = secret_key.*,
            };
        }

        return .{
            .key = secret_key.key,
            .tr = secret_key.tr,
            .matrix_hat = matrixToCustomOrder(&secret_key.A),
            .s1_hat = prepareSecretVector(&secret_key.s1),
            .s2_hat = prepareSecretVector(&secret_key.s2),
            .t0_hat = prepareSecretVector(&secret_key.t0),
            .fallback_secret_key = {},
        };
    }

    pub fn fromBytes(
        bytes: *const [MlDsa44.SecretKey.encoded_length]u8,
    ) !PreparedSigner44 {
        if (comptime !mldsa_avx2.enabled) {
            var secret_key = try MlDsa44.SecretKey.fromBytes(bytes.*);
            defer std.crypto.secureZero(
                MlDsa44.SecretKey,
                (&secret_key)[0..1],
            );
            return init(&secret_key);
        }

        var signer: PreparedSigner44 = undefined;
        const rho = bytes[0..32].*;
        signer.key = bytes[32..64].*;
        signer.tr = bytes[64..128].*;
        signer.fallback_secret_key = {};
        deriveMatrix44(&signer.matrix_hat, &rho);
        matrixToCustomOrderInPlace(@alignCast(&signer.matrix_hat));

        var secret: PolyVec4 align(32) = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
        unpackEta2Vector(&secret, bytes[128..512]);
        signer.s1_hat = prepareSecretVector(&secret);
        unpackEta2Vector(&secret, bytes[512..896]);
        signer.s2_hat = prepareSecretVector(&secret);
        unpackT0Vector(&secret, bytes[896..]);
        signer.t0_hat = prepareSecretVector(&secret);
        return signer;
    }

    pub fn deinit(self: *PreparedSigner44) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn sign(
        self: *const PreparedSigner44,
        message: []const u8,
        noise: [MlDsa44.noise_length]u8,
    ) [MlDsa44.Signature.encoded_length]u8 {
        return self.signWithContext(message, noise, "") catch unreachable;
    }

    pub fn signWithContext(
        self: *const PreparedSigner44,
        message: []const u8,
        noise: [MlDsa44.noise_length]u8,
        context: []const u8,
    ) std.crypto.errors.ContextTooLongError![MlDsa44.Signature.encoded_length]u8 {
        if (context.len > 255) return error.ContextTooLong;
        var randomizer = noise;
        defer std.crypto.secureZero(u8, &randomizer);
        if (comptime !mldsa_avx2.enabled) {
            var signer = try self.fallback_secret_key.signerWithContext(
                randomizer,
                context,
            );
            defer {
                std.crypto.secureZero(u8, std.mem.asBytes(&signer.h));
                std.crypto.secureZero(u8, &signer.rnd);
            }
            signer.update(message);
            return signer.finalize().toBytes();
        }

        var message_hash = initMessageHash(&self.tr, context);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&message_hash));
        message_hash.update(message);
        var mu: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &mu);
        message_hash.squeeze(&mu);

        var rho_hash = initShake256();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&rho_hash));
        rho_hash.update(&self.key);
        rho_hash.update(&randomizer);
        rho_hash.update(&mu);
        var rho_prime: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &rho_prime);
        rho_hash.squeeze(&rho_prime);

        var y: PolyVec4 align(32) = undefined;
        var y_hat: PolyVec4 align(32) = undefined;
        var w0: PolyVec4 align(32) = undefined;
        var w1: PolyVec4 align(32) = undefined;
        var hint: PolyVec4 align(32) = undefined;
        var challenge_hat: Poly align(32) = undefined;
        var scratch: Poly align(32) = undefined;
        defer {
            std.crypto.secureZero(u8, std.mem.asBytes(&y));
            std.crypto.secureZero(u8, std.mem.asBytes(&y_hat));
            std.crypto.secureZero(u8, std.mem.asBytes(&w0));
            std.crypto.secureZero(u8, std.mem.asBytes(&w1));
            std.crypto.secureZero(u8, std.mem.asBytes(&hint));
            std.crypto.secureZero(u8, std.mem.asBytes(&challenge_hat));
            std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
        }

        var signature: [MlDsa44.Signature.encoded_length]u8 = undefined;
        var nonce: u16 = 0;
        attempts: for (0..576) |_| {
            deriveMask4(&y, &rho_prime, nonce);
            nonce += 4;
            y_hat = y;
            nttCustomSignedVectorAlignedInPlace(&y_hat);
            matrixMulVectorHatCustom(
                &w0,
                @alignCast(&self.matrix_hat),
                &y_hat,
            );
            for (0..4) |row| {
                mldsa_avx2.invNtt(
                    @ptrCast(@alignCast(&w0.ps[row].cs)),
                );
                normalizeSignedPolyInPlace(&w0.ps[row]);
                mldsa_avx2.decompose88(
                    @ptrCast(@alignCast(&w1.ps[row].cs)),
                    @ptrCast(@alignCast(&w0.ps[row].cs)),
                );
                packW1High(
                    &w1.ps[row],
                    signature[32 + row * 192 ..][0..192],
                );
            }

            var challenge_hash = initShake256();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&challenge_hash));
            challenge_hash.update(&mu);
            challenge_hash.update(signature[32..800]);
            challenge_hash.squeeze(signature[0..32]);
            challenge_hat = sampleInBall44(signature[0..32]);
            nttCustomSignedAlignedInPlace(&challenge_hat);

            var rejected: u32 = 0;
            for (0..4) |row| {
                scratch = self.s2_hat.ps[row];
                pointwiseInPlace(&scratch, &challenge_hat);
                inverseAndCenter(&scratch);
                subSignedInPlace(&w0.ps[row], &scratch);
                rejected |= @intFromBool(exceedsSigned(
                    @alignCast(&w0.ps[row]),
                    95_154,
                ));
            }
            if (rejected != 0) continue :attempts;

            rejected = 0;
            for (0..4) |row| {
                scratch = self.s1_hat.ps[row];
                pointwiseInPlace(&scratch, &challenge_hat);
                inverseAndCenter(&scratch);
                addSignedInPlace(&scratch, &y.ps[row]);
                rejected |= @intFromBool(exceedsSigned(&scratch, 130_994));
                packZ17Signed(
                    &scratch,
                    signature[32 + row * 576 ..][0..576],
                );
            }
            if (rejected != 0) continue :attempts;

            rejected = 0;
            for (0..4) |row| {
                scratch = self.t0_hat.ps[row];
                pointwiseInPlace(&scratch, &challenge_hat);
                inverseAndCenter(&scratch);
                rejected |= @intFromBool(exceedsSigned(
                    &scratch,
                    decomposition_gamma2,
                ));
                addSignedInPlace(&w0.ps[row], &scratch);
            }
            if (rejected != 0) continue :attempts;
            const hint_count = makeHint44(&hint, &w0, &w1);
            if (hint_count > 80) continue :attempts;
            // All rejection checks have passed. The resulting hint is part of
            // the public signature, so sparse encoding may use its positions.
            packHint44(signature[2_336..], &hint, hint_count);
            return signature;
        }
        unreachable;
    }
};

pub const PreparedSigner65 = PreparedSignerWideImpl(
    MlDsa65,
    6,
    5,
    4,
    55,
    49,
    48,
);
pub const PreparedSigner87 = PreparedSignerWideImpl(
    MlDsa87,
    8,
    7,
    2,
    75,
    60,
    64,
);

fn PreparedSignerWideImpl(
    comptime MlDsa: type,
    comptime k: usize,
    comptime l: usize,
    comptime eta: usize,
    comptime omega: usize,
    comptime tau: u16,
    comptime challenge_bytes: usize,
) type {
    const SecretKey = MlDsa.SecretKey;
    const Matrix = @TypeOf(@as(SecretKey, undefined).A);
    const VectorL = @TypeOf(@as(SecretKey, undefined).s1);
    const VectorK = @TypeOf(@as(SecretKey, undefined).s2);
    const FallbackSecretKey = if (mldsa_avx2.enabled) void else SecretKey;
    const eta_bytes_per_poly = if (eta == 2) 96 else 128;
    const s1_offset = 128;
    const s2_offset = s1_offset + l * eta_bytes_per_poly;
    const t0_offset = s2_offset + k * eta_bytes_per_poly;
    const z_bytes_per_poly = 640;
    const hint_offset = challenge_bytes + l * z_bytes_per_poly;
    const beta: i32 = tau * eta;

    return struct {
        key: [32]u8,
        tr: [64]u8,
        matrix_hat: if (mldsa_avx2.enabled) Matrix else void align(if (mldsa_avx2.enabled) 32 else 1),
        s1_hat: if (mldsa_avx2.enabled) VectorL else void align(if (mldsa_avx2.enabled) 32 else 1),
        s2_hat: if (mldsa_avx2.enabled) VectorK else void align(if (mldsa_avx2.enabled) 32 else 1),
        t0_hat: if (mldsa_avx2.enabled) VectorK else void align(if (mldsa_avx2.enabled) 32 else 1),
        fallback_secret_key: FallbackSecretKey,

        const Self = @This();

        pub fn init(secret_key: *const SecretKey) Self {
            if (comptime !mldsa_avx2.enabled) {
                return .{
                    .key = secret_key.key,
                    .tr = secret_key.tr,
                    .matrix_hat = {},
                    .s1_hat = {},
                    .s2_hat = {},
                    .t0_hat = {},
                    .fallback_secret_key = secret_key.*,
                };
            }

            var matrix_hat: Matrix align(32) = secret_key.A;
            matrixToCustomOrderGeneric(&matrix_hat, k, l);
            return .{
                .key = secret_key.key,
                .tr = secret_key.tr,
                .matrix_hat = matrix_hat,
                .s1_hat = prepareSecretVectorGeneric(VectorL, &secret_key.s1),
                .s2_hat = prepareSecretVectorGeneric(VectorK, &secret_key.s2),
                .t0_hat = prepareSecretVectorGeneric(VectorK, &secret_key.t0),
                .fallback_secret_key = {},
            };
        }

        pub fn fromBytes(
            bytes: *const [SecretKey.encoded_length]u8,
        ) !Self {
            if (comptime !mldsa_avx2.enabled) {
                var secret_key = try SecretKey.fromBytes(bytes.*);
                defer std.crypto.secureZero(SecretKey, (&secret_key)[0..1]);
                return init(&secret_key);
            }

            var signer: Self = undefined;
            const rho = bytes[0..32].*;
            signer.key = bytes[32..64].*;
            signer.tr = bytes[64..128].*;
            signer.fallback_secret_key = {};
            deriveMatrixGeneric(&signer.matrix_hat, &rho, k, l);
            matrixToCustomOrderGeneric(&signer.matrix_hat, k, l);

            var s1: VectorL align(32) = undefined;
            var s2: VectorK align(32) = undefined;
            var t0: VectorK align(32) = undefined;
            defer {
                std.crypto.secureZero(u8, std.mem.asBytes(&s1));
                std.crypto.secureZero(u8, std.mem.asBytes(&s2));
                std.crypto.secureZero(u8, std.mem.asBytes(&t0));
            }
            unpackEtaVectorGeneric(
                &s1,
                bytes[s1_offset..s2_offset],
                l,
                eta,
            );
            unpackEtaVectorGeneric(
                &s2,
                bytes[s2_offset..t0_offset],
                k,
                eta,
            );
            unpackT0VectorGeneric(&t0, bytes[t0_offset..], k);
            signer.s1_hat = prepareSecretVectorGeneric(VectorL, &s1);
            signer.s2_hat = prepareSecretVectorGeneric(VectorK, &s2);
            signer.t0_hat = prepareSecretVectorGeneric(VectorK, &t0);
            return signer;
        }

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }

        pub fn sign(
            self: *const Self,
            message: []const u8,
            noise: [MlDsa.noise_length]u8,
        ) [MlDsa.Signature.encoded_length]u8 {
            return self.signWithContext(message, noise, "") catch unreachable;
        }

        pub fn signWithContext(
            self: *const Self,
            message: []const u8,
            noise: [MlDsa.noise_length]u8,
            context: []const u8,
        ) std.crypto.errors.ContextTooLongError![MlDsa.Signature.encoded_length]u8 {
            if (context.len > 255) return error.ContextTooLong;
            var randomizer = noise;
            defer std.crypto.secureZero(u8, &randomizer);
            if (comptime !mldsa_avx2.enabled) {
                var signer = try self.fallback_secret_key.signerWithContext(
                    randomizer,
                    context,
                );
                defer {
                    std.crypto.secureZero(u8, std.mem.asBytes(&signer.h));
                    std.crypto.secureZero(u8, &signer.rnd);
                }
                signer.update(message);
                return signer.finalize().toBytes();
            }

            var message_hash = initMessageHash(&self.tr, context);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&message_hash));
            message_hash.update(message);
            var mu: [64]u8 = undefined;
            defer std.crypto.secureZero(u8, &mu);
            message_hash.squeeze(&mu);

            var rho_hash = initShake256();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&rho_hash));
            rho_hash.update(&self.key);
            rho_hash.update(&randomizer);
            rho_hash.update(&mu);
            var rho_prime: [64]u8 = undefined;
            defer std.crypto.secureZero(u8, &rho_prime);
            rho_hash.squeeze(&rho_prime);

            var y: VectorL align(32) = undefined;
            var y_hat: VectorL align(32) = undefined;
            var w0: VectorK align(32) = undefined;
            var w1: VectorK align(32) = undefined;
            var hint: VectorK align(32) = undefined;
            var challenge_hat: Poly align(32) = undefined;
            var scratch: Poly align(32) = undefined;
            defer {
                std.crypto.secureZero(u8, std.mem.asBytes(&y));
                std.crypto.secureZero(u8, std.mem.asBytes(&y_hat));
                std.crypto.secureZero(u8, std.mem.asBytes(&w0));
                std.crypto.secureZero(u8, std.mem.asBytes(&w1));
                std.crypto.secureZero(u8, std.mem.asBytes(&hint));
                std.crypto.secureZero(u8, std.mem.asBytes(&challenge_hat));
                std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            }

            var signature: [MlDsa.Signature.encoded_length]u8 = undefined;
            var nonce: u16 = 0;
            attempts: for (0..576) |_| {
                deriveMask19Generic(&y, &rho_prime, nonce, l);
                nonce += l;
                y_hat = y;
                nttCustomSignedVector(&y_hat);
                matrixMulVectorHatCustomGeneric(
                    &w0,
                    &self.matrix_hat,
                    &y_hat,
                    k,
                    l,
                );
                for (0..k) |row| {
                    mldsa_avx2.invNtt(
                        @ptrCast(@alignCast(&w0.ps[row].cs)),
                    );
                    normalizeSignedPolyInPlace(&w0.ps[row]);
                    decompose32Poly(&w1.ps[row], &w0.ps[row]);
                    packW1High19(
                        &w1.ps[row],
                        signature[challenge_bytes + row * 128 ..][0..128],
                    );
                }

                var challenge_hash = initShake256();
                defer std.crypto.secureZero(u8, std.mem.asBytes(&challenge_hash));
                challenge_hash.update(&mu);
                challenge_hash.update(
                    signature[challenge_bytes .. challenge_bytes + k * 128],
                );
                challenge_hash.squeeze(signature[0..challenge_bytes]);
                challenge_hat = sampleInBall(
                    tau,
                    signature[0..challenge_bytes],
                );
                nttCustomSignedAlignedInPlace(&challenge_hat);

                var rejected: u32 = 0;
                for (0..k) |row| {
                    scratch = self.s2_hat.ps[row];
                    pointwiseInPlace(&scratch, &challenge_hat);
                    inverseAndCenter(&scratch);
                    subSignedInPlace(&w0.ps[row], &scratch);
                    rejected |= @intFromBool(exceedsSigned(
                        @alignCast(&w0.ps[row]),
                        261_888 - beta,
                    ));
                }
                if (rejected != 0) continue :attempts;

                rejected = 0;
                for (0..l) |row| {
                    scratch = self.s1_hat.ps[row];
                    pointwiseInPlace(&scratch, &challenge_hat);
                    inverseAndCenter(&scratch);
                    addSignedInPlace(&scratch, &y.ps[row]);
                    rejected |= @intFromBool(exceedsSigned(
                        &scratch,
                        524_288 - beta,
                    ));
                    packZ19Signed(
                        &scratch,
                        signature[challenge_bytes + row * z_bytes_per_poly ..][0..z_bytes_per_poly],
                    );
                }
                if (rejected != 0) continue :attempts;

                rejected = 0;
                for (0..k) |row| {
                    scratch = self.t0_hat.ps[row];
                    pointwiseInPlace(&scratch, &challenge_hat);
                    inverseAndCenter(&scratch);
                    rejected |= @intFromBool(exceedsSigned(&scratch, 261_888));
                    addSignedInPlace(&w0.ps[row], &scratch);
                }
                if (rejected != 0) continue :attempts;
                const hint_count = makeHintGeneric(&hint, &w0, &w1, k, 261_888);
                if (hint_count > omega) continue :attempts;
                packHintGeneric(
                    signature[hint_offset..],
                    &hint,
                    hint_count,
                    k,
                    omega,
                );
                return signature;
            }
            unreachable;
        }
    };
}

/// Compact ML-DSA-44 key material in the standard FIPS 204 wire representation.
pub const KeyPair44 = struct {
    public_key_bytes: [MlDsa44.PublicKey.encoded_length]u8,
    secret_key_bytes: [MlDsa44.SecretKey.encoded_length]u8,

    pub fn deinit(self: *KeyPair44) void {
        std.crypto.secureZero(u8, &self.secret_key_bytes);
    }

    pub fn preparedSigner(self: *const KeyPair44) !PreparedSigner44 {
        return PreparedSigner44.fromBytes(&self.secret_key_bytes);
    }
};

pub const KeyPair65 = CompactKeyPairWide(MlDsa65, PreparedSigner65);
pub const KeyPair87 = CompactKeyPairWide(MlDsa87, PreparedSigner87);

fn CompactKeyPairWide(comptime MlDsa: type, comptime PreparedSigner: type) type {
    return struct {
        public_key_bytes: [MlDsa.PublicKey.encoded_length]u8,
        secret_key_bytes: [MlDsa.SecretKey.encoded_length]u8,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, &self.secret_key_bytes);
        }

        pub fn preparedSigner(self: *const Self) !PreparedSigner {
            return PreparedSigner.fromBytes(&self.secret_key_bytes);
        }
    };
}

/// Generate a standard encoded ML-DSA-44 key pair.
pub fn generateKeyPair44(seed: [MlDsa44.seed_length]u8) !KeyPair44 {
    if (comptime !mldsa_avx2.enabled) {
        var key_pair = try MlDsa44.KeyPair.generateDeterministic(seed);
        defer wipeKeyPair44(&key_pair);
        return .{
            .public_key_bytes = key_pair.public_key.toBytes(),
            .secret_key_bytes = key_pair.secret_key.toBytes(),
        };
    }

    var expanded_seed: [128]u8 = undefined;
    defer std.crypto.secureZero(u8, &expanded_seed);
    var seed_hash = initShake256();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&seed_hash));
    seed_hash.update(&seed);
    seed_hash.update(&[_]u8{ 4, 4 });
    seed_hash.squeeze(&expanded_seed);

    var result: KeyPair44 = undefined;
    const rho = expanded_seed[0..32].*;
    var key = expanded_seed[96..128].*;
    defer std.crypto.secureZero(u8, &key);
    var matrix_hat: Matrix44 align(32) = undefined;
    deriveMatrix44(&matrix_hat, &rho);
    matrixToCustomOrderInPlace(&matrix_hat);

    var secret_seed = expanded_seed[32..96].*;
    defer std.crypto.secureZero(u8, &secret_seed);
    var s1: PolyVec4 align(32) = undefined;
    var s2: PolyVec4 align(32) = undefined;
    var t: Poly align(32) = undefined;
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(&s1));
        std.crypto.secureZero(u8, std.mem.asBytes(&s2));
        std.crypto.secureZero(u8, std.mem.asBytes(&t));
    }
    deriveEta2Vector(&s1, &secret_seed, 0);
    deriveEta2Vector(&s2, &secret_seed, 4);
    packEta2Vector(&s1, result.secret_key_bytes[128..512]);
    packEta2Vector(&s2, result.secret_key_bytes[512..896]);
    prepareSecretVectorInPlace(&s1);

    for (0..4) |row| {
        mldsa_avx2.dotHatL4(
            @ptrCast(@alignCast(&t.cs)),
            @ptrCast(@alignCast(&matrix_hat.rows[row].ps)),
            @ptrCast(@alignCast(&s1.ps)),
        );
        mldsa_avx2.invNtt(@ptrCast(@alignCast(&t.cs)));
        normalizeSignedPolyInPlace(&t);
        addCenteredToCanonical(&t, &s2.ps[row]);
        var t1: Poly = undefined;
        power2RoundInPlace(&t1, &t);
        packT1Poly(
            &t1,
            result.public_key_bytes[32 + row * t1_bytes_per_poly ..][0..t1_bytes_per_poly],
        );
        packT0Poly(
            &t,
            result.secret_key_bytes[896 + row * 416 ..][0..416],
        );
    }
    result.public_key_bytes[0..32].* = rho;
    var tr_hash = initShake256();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&tr_hash));
    tr_hash.update(&result.public_key_bytes);
    var tr: [64]u8 = undefined;
    tr_hash.squeeze(&tr);

    result.secret_key_bytes[0..32].* = rho;
    result.secret_key_bytes[32..64].* = key;
    result.secret_key_bytes[64..128].* = tr;
    return result;
}

/// Generate a standard encoded ML-DSA-65 key pair using four-way SHAKE and
/// the in-tree AVX2 polynomial arithmetic when available.
pub fn generateKeyPair65(seed: [MlDsa65.seed_length]u8) !KeyPair65 {
    return generateKeyPairWide(MlDsa65, KeyPair65, 6, 5, 4, seed);
}

/// Generate a standard encoded ML-DSA-87 key pair. The accelerated path keeps
/// secret vectors in the assembly kernel's NTT order until their encoded
/// representation has been produced.
pub fn generateKeyPair87(seed: [MlDsa87.seed_length]u8) !KeyPair87 {
    return generateKeyPairWide(MlDsa87, KeyPair87, 8, 7, 2, seed);
}

fn generateKeyPairWide(
    comptime MlDsa: type,
    comptime EncodedKeyPair: type,
    comptime k: usize,
    comptime l: usize,
    comptime eta: usize,
    seed: [MlDsa.seed_length]u8,
) !EncodedKeyPair {
    if (comptime !mldsa_avx2.enabled) {
        var key_pair = try MlDsa.KeyPair.generateDeterministic(seed);
        defer std.crypto.secureZero(MlDsa.KeyPair, (&key_pair)[0..1]);
        return .{
            .public_key_bytes = key_pair.public_key.toBytes(),
            .secret_key_bytes = key_pair.secret_key.toBytes(),
        };
    }

    const Matrix = @TypeOf(@as(MlDsa.PublicKey, undefined).A);
    const VectorL = @TypeOf(@as(MlDsa.SecretKey, undefined).s1);
    const VectorK = @TypeOf(@as(MlDsa.SecretKey, undefined).s2);
    const SecretVector = struct { ps: [k + l]Poly };
    const eta_bytes_per_poly = if (eta == 2) 96 else 128;
    const t0_bytes_per_poly = 416;
    const s1_offset = 128;
    const s2_offset = s1_offset + l * eta_bytes_per_poly;
    const t0_offset = s2_offset + k * eta_bytes_per_poly;

    var expanded_seed: [128]u8 = undefined;
    defer std.crypto.secureZero(u8, &expanded_seed);
    var seed_hash = initShake256();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&seed_hash));
    seed_hash.update(&seed);
    seed_hash.update(&[_]u8{ k, l });
    seed_hash.squeeze(&expanded_seed);

    var result: EncodedKeyPair = undefined;
    const rho = expanded_seed[0..32].*;
    var key = expanded_seed[96..128].*;
    defer std.crypto.secureZero(u8, &key);
    var matrix_hat: Matrix align(32) = undefined;
    deriveMatrixGeneric(&matrix_hat, &rho, k, l);
    matrixToCustomOrderGeneric(&matrix_hat, k, l);

    var secret_seed = expanded_seed[32..96].*;
    defer std.crypto.secureZero(u8, &secret_seed);
    var secret: SecretVector align(32) = undefined;
    var t: VectorK align(32) = undefined;
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(&secret));
        std.crypto.secureZero(u8, std.mem.asBytes(&t));
    }
    if (comptime eta == 2) {
        deriveEta2VectorGeneric(&secret, &secret_seed, 0, k + l, false);
    } else if (comptime eta == 4) {
        deriveEta4VectorSignedGeneric(&secret, &secret_seed, 0, k + l);
    } else {
        @compileError("unsupported ML-DSA eta");
    }
    const s1: *align(32) VectorL = @ptrCast(@alignCast(&secret.ps[0]));
    const s2: *align(32) VectorK = @ptrCast(@alignCast(&secret.ps[l]));
    if (comptime eta == 2) {
        packEta2VectorSignedGeneric(
            s1,
            result.secret_key_bytes[s1_offset..s2_offset],
            l,
        );
        packEta2VectorSignedGeneric(
            s2,
            result.secret_key_bytes[s2_offset..t0_offset],
            k,
        );
    } else {
        packEta4VectorGeneric(
            s1,
            result.secret_key_bytes[s1_offset..s2_offset],
            l,
        );
        packEta4VectorGeneric(
            s2,
            result.secret_key_bytes[s2_offset..t0_offset],
            k,
        );
    }
    nttCustomSignedVector(s1);
    matrixMulVectorHatCustomGeneric(&t, &matrix_hat, s1, k, l);

    for (0..k) |row| {
        mldsa_avx2.invNtt(@ptrCast(@alignCast(&t.ps[row].cs)));
        normalizeSignedPolyInPlace(&t.ps[row]);
        addSignedToCanonical(&t.ps[row], &s2.ps[row]);
        var t1: Poly = undefined;
        power2RoundInPlace(&t1, &t.ps[row]);
        packT1Poly(
            &t1,
            result.public_key_bytes[32 + row * t1_bytes_per_poly ..][0..t1_bytes_per_poly],
        );
        packT0Poly(
            &t.ps[row],
            result.secret_key_bytes[t0_offset + row * t0_bytes_per_poly ..][0..t0_bytes_per_poly],
        );
    }
    result.public_key_bytes[0..32].* = rho;
    var tr_hash = initShake256();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&tr_hash));
    tr_hash.update(&result.public_key_bytes);
    var tr: [64]u8 = undefined;
    tr_hash.squeeze(&tr);

    result.secret_key_bytes[0..32].* = rho;
    result.secret_key_bytes[32..64].* = key;
    result.secret_key_bytes[64..128].* = tr;
    return result;
}

/// Incremental ML-DSA-44 verifier backed by a caller-owned prepared key.
pub const Verifier44 = struct {
    hash: Shake256,
    signature: MlDsa44.Signature,
    prepared: *const PreparedVerifier44,

    fn init(
        prepared: *const PreparedVerifier44,
        signature: MlDsa44.Signature,
        context: []const u8,
    ) std.crypto.errors.ContextTooLongError!Verifier44 {
        if (context.len > 255) return error.ContextTooLong;

        var hash = initShake256();
        hash.update(&prepared.tr);
        hash.update(&[_]u8{ 0, @intCast(context.len) });
        hash.update(context);
        return .{
            .hash = hash,
            .signature = signature,
            .prepared = prepared,
        };
    }

    pub fn update(self: *Verifier44, data: []const u8) void {
        self.hash.update(data);
    }

    pub fn verify(self: *Verifier44) std.crypto.errors.SignatureVerificationError!void {
        var mu: [64]u8 = undefined;
        self.hash.squeeze(&mu);
        return self.prepared.verifyMu(&self.signature, &mu);
    }
};

/// Decode an ML-DSA-44 public key while expanding its 4x4 public matrix with
/// four-way SHAKE128 on supported x86_64 targets. The returned type and wire
/// semantics are exactly Zig std's ML-DSA-44 `PublicKey`.
pub fn publicKey44FromBytes(
    bytes: [MlDsa44.PublicKey.encoded_length]u8,
) !MlDsa44.PublicKey {
    if (comptime !keccak4.enabled) return MlDsa44.PublicKey.fromBytes(bytes);

    var public_key: MlDsa44.PublicKey = undefined;
    public_key.rho = bytes[0..32].*;
    public_key.t1_packed = bytes[32..].*;
    inline for (0..4) |index| {
        unpackT1(
            &public_key.t1.ps[index].cs,
            public_key.t1_packed[index * t1_bytes_per_poly ..][0..t1_bytes_per_poly],
        );
    }
    deriveMatrix44(&public_key.A, &public_key.rho);

    var hash = initShake256();
    hash.update(&bytes);
    hash.squeeze(&public_key.tr);
    return public_key;
}

/// Deterministically generate an ML-DSA-44 key pair using the accelerated
/// public and secret arithmetic paths when available.
pub fn keyPair44FromSeed(seed: [MlDsa44.seed_length]u8) !MlDsa44.KeyPair {
    if (comptime !mldsa_avx2.enabled) {
        return MlDsa44.KeyPair.generateDeterministic(seed);
    }

    var expanded_seed: [128]u8 = undefined;
    defer std.crypto.secureZero(u8, &expanded_seed);
    var seed_hash = initShake256();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&seed_hash));
    seed_hash.update(&seed);
    seed_hash.update(&[_]u8{ 4, 4 });
    seed_hash.squeeze(&expanded_seed);

    var public_key: MlDsa44.PublicKey = undefined;
    var secret_key: MlDsa44.SecretKey = undefined;
    public_key.rho = expanded_seed[0..32].*;
    secret_key.rho = public_key.rho;
    secret_key.key = expanded_seed[96..128].*;
    deriveMatrix44(&public_key.A, &public_key.rho);
    secret_key.A = public_key.A;

    var secret_seed = expanded_seed[32..96].*;
    defer std.crypto.secureZero(u8, &secret_seed);
    deriveEta2Vector(&secret_key.s1, &secret_seed, 0);
    deriveEta2Vector(&secret_key.s2, &secret_seed, 4);

    var matrix_hat: Matrix44 align(32) = matrixToCustomOrder(&public_key.A);
    var s1_hat: PolyVec4 align(32) = prepareSecretVector(&secret_key.s1);
    var t: PolyVec4 align(32) = undefined;
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(&s1_hat));
        std.crypto.secureZero(u8, std.mem.asBytes(&t));
    }
    matrixMulVectorHatCustom(&t, &matrix_hat, &s1_hat);
    for (0..4) |row| {
        mldsa_avx2.invNtt(@ptrCast(@alignCast(&t.ps[row].cs)));
        normalizeSignedPolyInPlace(&t.ps[row]);
        addCenteredToCanonical(&t.ps[row], &secret_key.s2.ps[row]);
        power2RoundPoly(
            &public_key.t1.ps[row],
            &secret_key.t0.ps[row],
            &t.ps[row],
        );
    }
    packT1Vector(&public_key.t1, &public_key.t1_packed);

    secret_key.s1_hat = customSignedToStandard(s1_hat);
    var s2_hat: PolyVec4 align(32) = prepareSecretVector(&secret_key.s2);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&s2_hat));
    secret_key.s2_hat = customSignedToStandard(s2_hat);
    var t0_hat: PolyVec4 align(32) = prepareSecretVector(&secret_key.t0);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&t0_hat));
    secret_key.t0_hat = customSignedToStandard(t0_hat);

    const public_bytes = public_key.toBytes();
    var tr_hash = initShake256();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&tr_hash));
    tr_hash.update(&public_bytes);
    tr_hash.squeeze(&public_key.tr);
    secret_key.tr = public_key.tr;
    return .{
        .public_key = public_key,
        .secret_key = secret_key,
    };
}

/// Erase every secret-bearing component of an ML-DSA-44 key pair while
/// leaving its public matrix and public hashes alone.
pub fn wipeKeyPair44(key_pair: *MlDsa44.KeyPair) void {
    std.crypto.secureZero(u8, &key_pair.secret_key.key);
    std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key.s1));
    std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key.s2));
    std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key.t0));
    std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key.s1_hat));
    std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key.s2_hat));
    std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key.t0_hat));
}

fn deriveMatrix44(matrix: anytype, rho: *const [32]u8) void {
    deriveMatrixGeneric(matrix, rho, 4, 4);
}

fn deriveMatrixGeneric(
    matrix: anytype,
    rho: *const [32]u8,
    comptime k: usize,
    comptime l: usize,
) void {
    var offset: usize = 0;
    while (offset < k * l) : (offset += 4) {
        var inputs: [4][keccak4.matrix_input_length]u8 = undefined;
        for (&inputs, 0..) |*input, lane| {
            const flat_index = @min(offset + lane, k * l - 1);
            const row: u8 = @intCast(flat_index / l);
            const column: u8 = @intCast(flat_index % l);
            input.* = rho.* ++ .{ column, row };
        }
        const expanded = keccak4.shake128MldsaMatrix(&inputs);
        for (&expanded, 0..) |*stream, lane| {
            const flat_index = offset + lane;
            if (flat_index >= k * l) break;
            const row = flat_index / l;
            const column = flat_index % l;
            var coefficient_index: usize = 0;
            appendUniform(
                &matrix.rows[row].ps[column].cs,
                &coefficient_index,
                stream,
            );
            if (coefficient_index != coefficient_count) {
                var scalar = std.crypto.hash.sha3.Shake128.init(.{});
                scalar.update(&inputs[lane]);
                var skipped: [keccak4.mldsa_matrix_output_length]u8 = undefined;
                scalar.squeeze(&skipped);
                var block: [std.crypto.hash.sha3.Shake128.block_length]u8 =
                    undefined;
                while (coefficient_index != coefficient_count) {
                    scalar.squeeze(&block);
                    appendUniform(
                        &matrix.rows[row].ps[column].cs,
                        &coefficient_index,
                        &block,
                    );
                }
            }
        }
    }
}

fn appendUniform(
    output: *[coefficient_count]u32,
    coefficient_index: *usize,
    bytes: []const u8,
) void {
    if (comptime mldsa_avx2.enabled) {
        if (bytes.len == 840 and coefficient_index.* == 0) {
            coefficient_index.* = mldsa_avx2.rejectUniform(
                output,
                bytes[0..840],
            );
            return;
        }
    }
    var offset: usize = 0;
    while (offset + 3 <= bytes.len and
        coefficient_index.* < coefficient_count) : (offset += 3)
    {
        const value = (@as(u32, bytes[offset]) |
            (@as(u32, bytes[offset + 1]) << 8) |
            (@as(u32, bytes[offset + 2]) << 16)) & 0x7fffff;
        if (value < modulus) {
            output[coefficient_index.*] = value;
            coefficient_index.* += 1;
        }
    }
}

fn unpackT1(output: *[coefficient_count]u32, bytes: []const u8) void {
    std.debug.assert(bytes.len == t1_bytes_per_poly);
    var coefficient_index: usize = 0;
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += 5) {
        output[coefficient_index] =
            (@as(u32, bytes[offset]) |
                (@as(u32, bytes[offset + 1]) << 8)) & 0x3ff;
        output[coefficient_index + 1] =
            ((@as(u32, bytes[offset + 1]) >> 2) |
                (@as(u32, bytes[offset + 2]) << 6)) & 0x3ff;
        output[coefficient_index + 2] =
            ((@as(u32, bytes[offset + 2]) >> 4) |
                (@as(u32, bytes[offset + 3]) << 4)) & 0x3ff;
        output[coefficient_index + 3] =
            ((@as(u32, bytes[offset + 3]) >> 6) |
                (@as(u32, bytes[offset + 4]) << 2)) & 0x3ff;
        coefficient_index += 4;
    }
}

fn unpackEta2Vector(output: *PolyVec4, bytes: *const [384]u8) void {
    for (0..4) |poly_index| {
        var coefficient_index: usize = 0;
        var offset: usize = poly_index * 96;
        const end = offset + 96;
        while (offset < end) : (offset += 3) {
            const b0: u32 = bytes[offset];
            const b1: u32 = bytes[offset + 1];
            const b2: u32 = bytes[offset + 2];
            const values = [8]u32{
                b0 & 7,
                (b0 >> 3) & 7,
                (b0 >> 6) | ((b1 << 2) & 7),
                (b1 >> 1) & 7,
                (b1 >> 4) & 7,
                (b1 >> 7) | ((b2 << 1) & 7),
                (b2 >> 2) & 7,
                b2 >> 5,
            };
            inline for (values) |value| {
                output.ps[poly_index].cs[coefficient_index] =
                    modulus + 2 - value;
                coefficient_index += 1;
            }
        }
    }
}

fn unpackT0Vector(output: *PolyVec4, bytes: *const [1_664]u8) void {
    for (0..4) |poly_index| {
        var coefficient_index: usize = 0;
        var offset: usize = poly_index * 416;
        const end = offset + 416;
        while (offset < end) : (offset += 13) {
            const b0: u32 = bytes[offset];
            const b1: u32 = bytes[offset + 1];
            const b2: u32 = bytes[offset + 2];
            const b3: u32 = bytes[offset + 3];
            const b4: u32 = bytes[offset + 4];
            const b5: u32 = bytes[offset + 5];
            const b6: u32 = bytes[offset + 6];
            const b7: u32 = bytes[offset + 7];
            const b8: u32 = bytes[offset + 8];
            const b9: u32 = bytes[offset + 9];
            const b10: u32 = bytes[offset + 10];
            const b11: u32 = bytes[offset + 11];
            const b12: u32 = bytes[offset + 12];
            const values = [8]u32{
                (b0 | (b1 << 8)) & 0x1fff,
                ((b1 >> 5) | (b2 << 3) | (b3 << 11)) & 0x1fff,
                ((b3 >> 2) | (b4 << 6)) & 0x1fff,
                ((b4 >> 7) | (b5 << 1) | (b6 << 9)) & 0x1fff,
                ((b6 >> 4) | (b7 << 4) | (b8 << 12)) & 0x1fff,
                ((b8 >> 1) | (b9 << 7)) & 0x1fff,
                ((b9 >> 6) | (b10 << 2) | (b11 << 10)) & 0x1fff,
                (b11 >> 3) | (b12 << 5),
            };
            inline for (values) |value| {
                output.ps[poly_index].cs[coefficient_index] =
                    modulus + (1 << 12) - value;
                coefficient_index += 1;
            }
        }
    }
}

fn unpackEtaVectorGeneric(
    output: anytype,
    bytes: []const u8,
    comptime count: usize,
    comptime eta: usize,
) void {
    const bytes_per_poly = if (eta == 2) 96 else 128;
    std.debug.assert(output.ps.len == count);
    std.debug.assert(bytes.len == count * bytes_per_poly);
    for (0..count) |poly_index| {
        var coefficient_index: usize = 0;
        if (comptime eta == 2) {
            var offset = poly_index * bytes_per_poly;
            const end = offset + bytes_per_poly;
            while (offset < end) : (offset += 3) {
                const b0: u32 = bytes[offset];
                const b1: u32 = bytes[offset + 1];
                const b2: u32 = bytes[offset + 2];
                const values = [8]u32{
                    b0 & 7,
                    (b0 >> 3) & 7,
                    (b0 >> 6) | ((b1 << 2) & 7),
                    (b1 >> 1) & 7,
                    (b1 >> 4) & 7,
                    (b1 >> 7) | ((b2 << 1) & 7),
                    (b2 >> 2) & 7,
                    b2 >> 5,
                };
                inline for (values) |value| {
                    output.ps[poly_index].cs[coefficient_index] =
                        modulus + @as(u32, eta) - value;
                    coefficient_index += 1;
                }
            }
        } else if (comptime eta == 4) {
            for (bytes[poly_index * bytes_per_poly ..][0..bytes_per_poly]) |byte| {
                output.ps[poly_index].cs[coefficient_index] =
                    modulus + @as(u32, eta) - (byte & 15);
                output.ps[poly_index].cs[coefficient_index + 1] =
                    modulus + @as(u32, eta) - (byte >> 4);
                coefficient_index += 2;
            }
        } else {
            @compileError("unsupported ML-DSA eta");
        }
    }
}

fn unpackT0VectorGeneric(
    output: anytype,
    bytes: []const u8,
    comptime count: usize,
) void {
    std.debug.assert(output.ps.len == count);
    std.debug.assert(bytes.len == count * 416);
    for (0..count) |poly_index| {
        var coefficient_index: usize = 0;
        var offset = poly_index * 416;
        const end = offset + 416;
        while (offset < end) : (offset += 13) {
            const b0: u32 = bytes[offset];
            const b1: u32 = bytes[offset + 1];
            const b2: u32 = bytes[offset + 2];
            const b3: u32 = bytes[offset + 3];
            const b4: u32 = bytes[offset + 4];
            const b5: u32 = bytes[offset + 5];
            const b6: u32 = bytes[offset + 6];
            const b7: u32 = bytes[offset + 7];
            const b8: u32 = bytes[offset + 8];
            const b9: u32 = bytes[offset + 9];
            const b10: u32 = bytes[offset + 10];
            const b11: u32 = bytes[offset + 11];
            const b12: u32 = bytes[offset + 12];
            const values = [8]u32{
                (b0 | (b1 << 8)) & 0x1fff,
                ((b1 >> 5) | (b2 << 3) | (b3 << 11)) & 0x1fff,
                ((b3 >> 2) | (b4 << 6)) & 0x1fff,
                ((b4 >> 7) | (b5 << 1) | (b6 << 9)) & 0x1fff,
                ((b6 >> 4) | (b7 << 4) | (b8 << 12)) & 0x1fff,
                ((b8 >> 1) | (b9 << 7)) & 0x1fff,
                ((b9 >> 6) | (b10 << 2) | (b11 << 10)) & 0x1fff,
                (b11 >> 3) | (b12 << 5),
            };
            inline for (values) |value| {
                output.ps[poly_index].cs[coefficient_index] =
                    modulus + (1 << 12) - value;
                coefficient_index += 1;
            }
        }
    }
}

fn unpackHint44(bytes: []const u8) std.crypto.errors.EncodingError!PolyVec4 {
    return unpackHint(PolyVec4, 4, 80, bytes);
}

fn unpackHint(
    comptime Vector: type,
    comptime k: usize,
    comptime omega: usize,
    bytes: []const u8,
) std.crypto.errors.EncodingError!Vector {
    std.debug.assert(bytes.len == omega + k);
    var result: Vector = undefined;
    @memset(std.mem.asBytes(&result), 0);
    var previous: u8 = 0;
    for (0..k) |poly_index| {
        const boundary = bytes[omega + poly_index];
        if (boundary < previous or boundary > omega) {
            return error.InvalidEncoding;
        }
        var index = previous;
        while (index < boundary) : (index += 1) {
            if (index > previous and bytes[index] <= bytes[index - 1]) {
                return error.InvalidEncoding;
            }
            result.ps[poly_index].cs[bytes[index]] = 1;
        }
        previous = boundary;
    }
    for (bytes[previous..omega]) |byte| {
        if (byte != 0) return error.InvalidEncoding;
    }
    return result;
}

fn initMessageHash(public_key_hash: *const [64]u8, context: []const u8) Shake256 {
    var hash = initShake256();
    hash.update(public_key_hash);
    hash.update(&[_]u8{ 0, @intCast(context.len) });
    hash.update(context);
    return hash;
}

fn matrixMulVectorHat(matrix: *const Matrix44, vector: *const PolyVec4) PolyVec4 {
    var result: PolyVec4 = undefined;
    for (0..4) |row| {
        var sum: Poly = .{ .cs = .{0} ** coefficient_count };
        for (0..4) |column| {
            sum = add(sum, mulHat(matrix.rows[row].ps[column], vector.ps[column]));
        }
        result.ps[row] = sum;
    }
    return result;
}

fn add(a: Poly, b: Poly) Poly {
    var result: Poly = undefined;
    for (0..coefficient_count) |index| {
        result.cs[index] = a.cs[index] +% b.cs[index];
    }
    return result;
}

fn sub(a: Poly, b: Poly) Poly {
    var result: Poly = undefined;
    for (0..coefficient_count) |index| {
        result.cs[index] = a.cs[index] +% (2 * modulus -% b.cs[index]);
    }
    return result;
}

fn mulHat(a: Poly, b: Poly) Poly {
    var result: Poly = undefined;
    for (0..coefficient_count) |index| {
        result.cs[index] = montgomeryReduceLe2Q(
            @as(u64, a.cs[index]) * @as(u64, b.cs[index]),
        );
    }
    return result;
}

fn nttScalarVectorInPlace(vector: *PolyVec4) void {
    for (&vector.ps) |*poly| nttScalarInPlace(poly);
}

fn nttInPlace(poly: *Poly) void {
    if (comptime mldsa_avx2.enabled) {
        var coefficients: [coefficient_count]i32 align(32) = undefined;
        for (&coefficients, poly.cs) |*output, input| {
            output.* = @intCast(input);
        }
        mldsa_avx2.ntt(&coefficients);
        for (0..4) |block| {
            for (0..8) |row| {
                for (0..8) |column| {
                    const standard_index = block * 64 + row * 8 + column;
                    const custom_index = block * 64 + column * 8 + row;
                    poly.cs[standard_index] = normalizeSignedNtt(
                        coefficients[custom_index],
                    );
                }
            }
        }
        return;
    }
    nttScalarInPlace(poly);
}

fn nttCustomSignedVectorAlignedInPlace(vector: *align(32) PolyVec4) void {
    nttCustomSignedVector(vector);
}

fn nttCustomSignedVector(vector: anytype) void {
    for (&vector.ps) |*poly| {
        nttCustomSignedAlignedInPlace(@alignCast(poly));
    }
}

fn nttCustomSignedAlignedInPlace(poly: *align(32) Poly) void {
    mldsa_avx2.ntt(@ptrCast(@alignCast(&poly.cs)));
}

fn matrixMulVectorHatCustom(
    output: *align(32) PolyVec4,
    matrix: *align(32) const Matrix44,
    vector: *align(32) const PolyVec4,
) void {
    matrixMulVectorHatCustomGeneric(output, matrix, vector, 4, 4);
}

fn matrixMulVectorHatCustomGeneric(
    output: anytype,
    matrix: anytype,
    vector: anytype,
    comptime k: usize,
    comptime l: usize,
) void {
    for (0..k) |row| {
        const output_poly: *align(32) [256]i32 =
            @ptrCast(@alignCast(&output.ps[row].cs));
        if (comptime l == 4) {
            mldsa_avx2.dotHatL4(
                output_poly,
                @ptrCast(@alignCast(&matrix.rows[row].ps)),
                @ptrCast(@alignCast(&vector.ps)),
            );
        } else if (comptime l == 5) {
            mldsa_avx2.dotHatL5(
                output_poly,
                @ptrCast(@alignCast(&matrix.rows[row].ps)),
                @ptrCast(@alignCast(&vector.ps)),
            );
        } else if (comptime l == 7) {
            mldsa_avx2.dotHatL7(
                output_poly,
                @ptrCast(@alignCast(&matrix.rows[row].ps)),
                @ptrCast(@alignCast(&vector.ps)),
            );
        } else {
            @compileError("unsupported ML-DSA matrix width");
        }
    }
}

fn subtractSignedForInv(left_and_output: *Poly, right: *const Poly) void {
    for (&left_and_output.cs, right.cs) |*left_bits, right_bits| {
        var difference = @as(i32, @bitCast(left_bits.*)) -
            @as(i32, @bitCast(right_bits));
        if (difference >= @as(i32, modulus)) difference -= modulus;
        if (difference <= -@as(i32, modulus)) difference += modulus;
        left_bits.* = @bitCast(difference);
    }
}

fn normalizeSignedPolyInPlace(poly: *Poly) void {
    for (&poly.cs) |*coefficient| {
        coefficient.* = normalizeSignedNtt(@bitCast(coefficient.*));
    }
}

fn matrixToCustomOrder(matrix: *const Matrix44) Matrix44 {
    var result: Matrix44 align(32) = matrix.*;
    matrixToCustomOrderGeneric(&result, 4, 4);
    return result;
}

fn matrixToCustomOrderInPlace(matrix: *align(32) Matrix44) void {
    matrixToCustomOrderGeneric(matrix, 4, 4);
}

fn matrixToCustomOrderGeneric(
    matrix: anytype,
    comptime k: usize,
    comptime l: usize,
) void {
    for (0..k) |row| {
        for (0..l) |column| {
            mldsa_avx2.toCustomOrder(
                @alignCast(&matrix.rows[row].ps[column].cs),
            );
        }
    }
}

fn prepareSecretVector(input: *const PolyVec4) PolyVec4 {
    return prepareSecretVectorGeneric(PolyVec4, input);
}

fn prepareSecretVectorGeneric(comptime Vector: type, input: *const Vector) Vector {
    var result: Vector align(32) = undefined;
    for (0..result.ps.len) |poly_index| {
        for (0..coefficient_count) |index| {
            const centered = @as(i32, @intCast(input.ps[poly_index].cs[index])) -
                @as(i32, modulus);
            result.ps[poly_index].cs[index] = @bitCast(centered);
        }
        nttCustomSignedAlignedInPlace(
            @alignCast(&result.ps[poly_index]),
        );
    }
    return result;
}

fn prepareSecretVectorInPlace(vector: *align(32) PolyVec4) void {
    prepareSecretVectorInPlaceGeneric(vector, 4);
}

fn prepareSecretVectorInPlaceGeneric(
    vector: anytype,
    comptime count: usize,
) void {
    std.debug.assert(vector.ps.len == count);
    for (&vector.ps) |*poly| {
        for (&poly.cs) |*coefficient| {
            const centered = @as(i32, @intCast(coefficient.*)) -
                @as(i32, modulus);
            coefficient.* = @bitCast(centered);
        }
        nttCustomSignedAlignedInPlace(@alignCast(poly));
    }
}

fn deriveMask4(
    output: *align(32) PolyVec4,
    seed: *const [64]u8,
    nonce: u16,
) void {
    var inputs: [4][keccak4.mldsa_mask_input_length]u8 = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&inputs));
    for (&inputs, 0..) |*input, lane| {
        const lane_nonce = nonce + @as(u16, @intCast(lane));
        input.* = seed.* ++ .{
            @as(u8, @truncate(lane_nonce)),
            @as(u8, @truncate(lane_nonce >> 8)),
        };
    }
    var expanded = keccak4.shake256MldsaMask(&inputs);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&expanded));
    for (&output.ps, &expanded) |*poly, *bytes| {
        mldsa_avx2.unpackZ17(
            @ptrCast(@alignCast(&poly.cs)),
            bytes[0..576],
        );
    }
}

fn deriveMask19Generic(
    output: anytype,
    seed: *const [64]u8,
    nonce: u16,
    comptime count: usize,
) void {
    std.debug.assert(output.ps.len == count);
    var offset: usize = 0;
    while (offset < count) : (offset += 4) {
        var inputs: [4][keccak4.mldsa_mask_input_length]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&inputs));
        for (&inputs, 0..) |*input, lane| {
            const index = @min(offset + lane, count - 1);
            const lane_nonce = nonce + @as(u16, @intCast(index));
            input.* = seed.* ++ .{
                @as(u8, @truncate(lane_nonce)),
                @as(u8, @truncate(lane_nonce >> 8)),
            };
        }
        var expanded = keccak4.shake256MldsaMask(&inputs);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&expanded));
        for (&expanded, 0..) |*bytes, lane| {
            const index = offset + lane;
            if (index >= count) break;
            mldsa_avx2.unpackZ19(
                @ptrCast(@alignCast(&output.ps[index].cs)),
                bytes[0..640],
            );
        }
    }
}

fn deriveEta2Vector(
    output: *PolyVec4,
    seed: *const [64]u8,
    nonce: u16,
) void {
    deriveEta2VectorGeneric(output, seed, nonce, 4, true);
}

fn deriveEta2VectorGeneric(
    output: anytype,
    seed: *const [64]u8,
    nonce: u16,
    comptime count: usize,
    comptime canonicalize: bool,
) void {
    std.debug.assert(output.ps.len == count);
    var offset: usize = 0;
    while (offset < count) : (offset += 4) {
        var inputs: [4][keccak4.mldsa_eta_input_length]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&inputs));
        for (&inputs, 0..) |*input, lane| {
            const index = @min(offset + lane, count - 1);
            const lane_nonce = nonce + @as(u16, @intCast(index));
            input.* = seed.* ++ .{
                @as(u8, @truncate(lane_nonce)),
                @as(u8, @truncate(lane_nonce >> 8)),
            };
        }
        var expanded = keccak4.shake256MldsaEta(&inputs);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&expanded));
        for (&expanded, &inputs, 0..) |*bytes, *input, lane| {
            const index = offset + lane;
            if (index >= count) break;
            const poly = &output.ps[index];
            var coefficient_index = mldsa_avx2.rejectEta2(
                &poly.cs,
                bytes[0..FastShake256.rate],
            );
            appendEta2Signed(
                &poly.cs,
                &coefficient_index,
                bytes[FastShake256.rate..],
            );
            if (coefficient_index != coefficient_count) {
                var hash = initShake256();
                defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
                hash.update(input);
                var skipped: [keccak4.mldsa_eta_output_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &skipped);
                hash.squeeze(&skipped);
                var block: [FastShake256.rate]u8 = undefined;
                defer std.crypto.secureZero(u8, &block);
                while (coefficient_index != coefficient_count) {
                    hash.squeeze(&block);
                    appendEta2Signed(&poly.cs, &coefficient_index, &block);
                }
            }
            if (comptime canonicalize) {
                for (&poly.cs) |*coefficient| {
                    coefficient.* = @intCast(
                        @as(i64, modulus) + @as(i32, @bitCast(coefficient.*)),
                    );
                }
            }
        }
    }
}

fn appendEta2Signed(
    output: *[coefficient_count]u32,
    coefficient_index: *usize,
    bytes: []const u8,
) void {
    for (bytes) |byte| {
        const candidates = [2]u32{ byte & 15, byte >> 4 };
        inline for (candidates) |candidate| {
            if (candidate <= 14 and coefficient_index.* < coefficient_count) {
                const reduced = candidate - ((205 * candidate) >> 10) * 5;
                const signed: i32 = 2 - @as(i32, @intCast(reduced));
                output[coefficient_index.*] = @bitCast(signed);
                coefficient_index.* += 1;
            }
        }
        if (coefficient_index.* == coefficient_count) return;
    }
}

fn deriveEta4VectorSignedGeneric(
    output: anytype,
    seed: *const [64]u8,
    nonce: u16,
    comptime count: usize,
) void {
    std.debug.assert(output.ps.len == count);
    var offset: usize = 0;
    while (offset < count) : (offset += 4) {
        var inputs: [4][keccak4.mldsa_eta_input_length]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&inputs));
        for (&inputs, 0..) |*input, lane| {
            const index = @min(offset + lane, count - 1);
            const lane_nonce = nonce + @as(u16, @intCast(index));
            input.* = seed.* ++ .{
                @as(u8, @truncate(lane_nonce)),
                @as(u8, @truncate(lane_nonce >> 8)),
            };
        }
        var expanded = keccak4.shake256MldsaEta(&inputs);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&expanded));
        for (&expanded, &inputs, 0..) |*bytes, *input, lane| {
            const index = offset + lane;
            if (index >= count) break;
            deriveEta4PolyFromExpanded(&output.ps[index], input, bytes);
        }
    }
}

fn deriveEta4PolyFromExpanded(
    poly: *Poly,
    input: *const [keccak4.mldsa_eta_input_length]u8,
    expanded: *const [keccak4.mldsa_eta_output_length]u8,
) void {
    var coefficient_index = mldsa_avx2.rejectEta4(
        &poly.cs,
        expanded,
        coefficient_count,
    );
    if (coefficient_index != coefficient_count) {
        var hash = initShake256();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
        hash.update(input);
        var skipped: [keccak4.mldsa_eta_output_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &skipped);
        hash.squeeze(&skipped);
        var block: [FastShake256.rate]u8 = undefined;
        defer std.crypto.secureZero(u8, &block);
        while (coefficient_index != coefficient_count) {
            hash.squeeze(&block);
            appendEta4Signed(&poly.cs, &coefficient_index, &block);
        }
    }
}

fn appendEta4Signed(
    output: *[coefficient_count]u32,
    coefficient_index: *usize,
    bytes: []const u8,
) void {
    for (bytes) |byte| {
        const candidates = [2]u32{ byte & 15, byte >> 4 };
        inline for (candidates) |candidate| {
            if (candidate <= 8 and coefficient_index.* < coefficient_count) {
                const signed: i32 = 4 - @as(i32, @intCast(candidate));
                output[coefficient_index.*] = @bitCast(signed);
                coefficient_index.* += 1;
            }
        }
        if (coefficient_index.* == coefficient_count) return;
    }
}

fn customSignedToStandard(input: PolyVec4) PolyVec4 {
    var result: PolyVec4 align(32) = input;
    for (&result.ps) |*poly| {
        mldsa_avx2.toCustomOrder(@alignCast(&poly.cs));
        for (&poly.cs) |*coefficient| {
            coefficient.* = normalizeSignedNtt(@bitCast(coefficient.*));
        }
    }
    return result;
}

fn addCenteredToCanonical(output: *Poly, centered: *const Poly) void {
    for (&output.cs, centered.cs) |*coefficient, centered_bits| {
        var sum = @as(i32, @intCast(coefficient.*)) +
            (@as(i32, @intCast(centered_bits)) - @as(i32, modulus));
        if (sum < 0) sum += modulus;
        if (sum >= @as(i32, modulus)) sum -= modulus;
        coefficient.* = @intCast(sum);
    }
}

fn addSignedToCanonical(output: *Poly, signed: *const Poly) void {
    for (&output.cs, signed.cs) |*coefficient, signed_bits| {
        var sum = @as(i32, @intCast(coefficient.*)) +
            @as(i32, @bitCast(signed_bits));
        if (sum < 0) sum += modulus;
        if (sum >= @as(i32, modulus)) sum -= modulus;
        coefficient.* = @intCast(sum);
    }
}

fn power2RoundPoly(high: *Poly, low: *Poly, input: *const Poly) void {
    for (input.cs, 0..) |coefficient, index| {
        var low_bits = coefficient & ((1 << 13) - 1);
        low_bits -%= (1 << 12) + 1;
        low_bits +%= signMask(low_bits) & (1 << 13);
        low_bits -%= (1 << 12) - 1;
        low.cs[index] = modulus +% low_bits;
        high.cs[index] = (coefficient -% low_bits) >> 13;
    }
}

fn power2RoundInPlace(high: *Poly, low_and_input: *Poly) void {
    for (&low_and_input.cs, &high.cs) |*coefficient, *high_coefficient| {
        const input = coefficient.*;
        var low_bits = input & ((1 << 13) - 1);
        low_bits -%= (1 << 12) + 1;
        low_bits +%= signMask(low_bits) & (1 << 13);
        low_bits -%= (1 << 12) - 1;
        coefficient.* = modulus +% low_bits;
        high_coefficient.* = (input -% low_bits) >> 13;
    }
}

fn packT1Vector(vector: *const PolyVec4, output: *[4 * t1_bytes_per_poly]u8) void {
    for (0..4) |poly_index| {
        packT1Poly(
            &vector.ps[poly_index],
            output[poly_index * t1_bytes_per_poly ..][0..t1_bytes_per_poly],
        );
    }
}

fn packT1Poly(poly: *const Poly, output: *[t1_bytes_per_poly]u8) void {
    var coefficient_index: usize = 0;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 5) {
        const c0 = poly.cs[coefficient_index];
        const c1 = poly.cs[coefficient_index + 1];
        const c2 = poly.cs[coefficient_index + 2];
        const c3 = poly.cs[coefficient_index + 3];
        output[offset] = @truncate(c0);
        output[offset + 1] = @truncate((c0 >> 8) | (c1 << 2));
        output[offset + 2] = @truncate((c1 >> 6) | (c2 << 4));
        output[offset + 3] = @truncate((c2 >> 4) | (c3 << 6));
        output[offset + 4] = @truncate(c3 >> 2);
        coefficient_index += 4;
    }
}

fn packEta2Vector(vector: *const PolyVec4, output: *[384]u8) void {
    packEta2VectorGeneric(vector, output, 4);
}

fn packEta2VectorGeneric(
    vector: anytype,
    output: []u8,
    comptime count: usize,
) void {
    std.debug.assert(vector.ps.len == count);
    std.debug.assert(output.len == count * 96);
    for (0..count) |poly_index| {
        var coefficient_index: usize = 0;
        var offset: usize = poly_index * 96;
        const end = offset + 96;
        while (offset < end) : (offset += 3) {
            var encoded: [8]u32 = undefined;
            inline for (0..8) |lane| {
                encoded[lane] = modulus + 2 -
                    vector.ps[poly_index].cs[coefficient_index + lane];
            }
            output[offset] = @truncate(
                encoded[0] | (encoded[1] << 3) | (encoded[2] << 6),
            );
            output[offset + 1] = @truncate(
                (encoded[2] >> 2) | (encoded[3] << 1) |
                    (encoded[4] << 4) | (encoded[5] << 7),
            );
            output[offset + 2] = @truncate(
                (encoded[5] >> 1) | (encoded[6] << 2) |
                    (encoded[7] << 5),
            );
            coefficient_index += 8;
        }
    }
}

fn packEta2VectorSignedGeneric(
    vector: anytype,
    output: []u8,
    comptime count: usize,
) void {
    std.debug.assert(vector.ps.len == count);
    std.debug.assert(output.len == count * 96);
    for (0..count) |poly_index| {
        var coefficient_index: usize = 0;
        var offset: usize = poly_index * 96;
        const end = offset + 96;
        while (offset < end) : (offset += 3) {
            var encoded: [8]u32 = undefined;
            inline for (0..8) |lane| {
                encoded[lane] = @intCast(
                    2 - @as(i32, @bitCast(
                        vector.ps[poly_index].cs[coefficient_index + lane],
                    )),
                );
            }
            output[offset] = @truncate(
                encoded[0] | (encoded[1] << 3) | (encoded[2] << 6),
            );
            output[offset + 1] = @truncate(
                (encoded[2] >> 2) | (encoded[3] << 1) |
                    (encoded[4] << 4) | (encoded[5] << 7),
            );
            output[offset + 2] = @truncate(
                (encoded[5] >> 1) | (encoded[6] << 2) |
                    (encoded[7] << 5),
            );
            coefficient_index += 8;
        }
    }
}

fn packEta4VectorGeneric(
    vector: anytype,
    output: []u8,
    comptime count: usize,
) void {
    std.debug.assert(vector.ps.len == count);
    std.debug.assert(output.len == count * 128);
    for (0..count) |poly_index| {
        for (0..128) |offset| {
            const first: u32 = @intCast(
                4 - @as(i32, @bitCast(vector.ps[poly_index].cs[offset * 2])),
            );
            const second: u32 = @intCast(
                4 - @as(i32, @bitCast(vector.ps[poly_index].cs[offset * 2 + 1])),
            );
            output[poly_index * 128 + offset] = @truncate(first | (second << 4));
        }
    }
}

fn packT0Vector(vector: *const PolyVec4, output: *[1_664]u8) void {
    for (0..4) |poly_index| {
        packT0Poly(
            &vector.ps[poly_index],
            output[poly_index * 416 ..][0..416],
        );
    }
}

fn packT0Poly(poly: *const Poly, output: *[416]u8) void {
    var coefficient_index: usize = 0;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 13) {
        var encoded: [8]u32 = undefined;
        inline for (0..8) |lane| {
            encoded[lane] = modulus + (1 << 12) - poly.cs[coefficient_index + lane];
        }
        output[offset] = @truncate(encoded[0]);
        output[offset + 1] = @truncate((encoded[0] >> 8) | (encoded[1] << 5));
        output[offset + 2] = @truncate(encoded[1] >> 3);
        output[offset + 3] = @truncate((encoded[1] >> 11) | (encoded[2] << 2));
        output[offset + 4] = @truncate((encoded[2] >> 6) | (encoded[3] << 7));
        output[offset + 5] = @truncate(encoded[3] >> 1);
        output[offset + 6] = @truncate((encoded[3] >> 9) | (encoded[4] << 4));
        output[offset + 7] = @truncate(encoded[4] >> 4);
        output[offset + 8] = @truncate((encoded[4] >> 12) | (encoded[5] << 1));
        output[offset + 9] = @truncate((encoded[5] >> 7) | (encoded[6] << 6));
        output[offset + 10] = @truncate(encoded[6] >> 2);
        output[offset + 11] = @truncate((encoded[6] >> 10) | (encoded[7] << 3));
        output[offset + 12] = @truncate(encoded[7] >> 5);
        coefficient_index += 8;
    }
}

fn pointwiseInPlace(left_and_output: *align(32) Poly, right: *align(32) const Poly) void {
    mldsa_avx2.pointwise(
        @ptrCast(@alignCast(&left_and_output.cs)),
        @ptrCast(@alignCast(&right.cs)),
    );
}

fn inverseAndCenter(poly: *align(32) Poly) void {
    mldsa_avx2.invNtt(@ptrCast(@alignCast(&poly.cs)));
    centerSignedPolyInPlace(poly);
}

fn centerSignedPolyInPlace(poly: *Poly) void {
    const half_modulus: i32 = (modulus - 1) / 2;
    for (&poly.cs) |*bits| {
        var coefficient: i32 = @bitCast(bits.*);
        if (coefficient > half_modulus) coefficient -= modulus;
        if (coefficient < -half_modulus) coefficient += modulus;
        bits.* = @bitCast(coefficient);
    }
}

fn addSignedInPlace(left_and_output: *Poly, right: *const Poly) void {
    for (&left_and_output.cs, right.cs) |*left_bits, right_bits| {
        const sum = @as(i32, @bitCast(left_bits.*)) +
            @as(i32, @bitCast(right_bits));
        left_bits.* = @bitCast(sum);
    }
}

fn subSignedInPlace(left_and_output: *Poly, right: *const Poly) void {
    for (&left_and_output.cs, right.cs) |*left_bits, right_bits| {
        const difference = @as(i32, @bitCast(left_bits.*)) -
            @as(i32, @bitCast(right_bits));
        left_bits.* = @bitCast(difference);
    }
}

fn exceedsSigned(poly: *align(32) const Poly, bound: i32) bool {
    return mldsa_avx2.exceeds(
        @ptrCast(@alignCast(&poly.cs)),
        bound,
    );
}

fn packZ17Signed(poly: *const Poly, output: *[576]u8) void {
    var coefficient_index: usize = 0;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 9) {
        const p0: u32 = @intCast(131_072 - @as(i32, @bitCast(poly.cs[coefficient_index])));
        const p1: u32 = @intCast(131_072 - @as(i32, @bitCast(poly.cs[coefficient_index + 1])));
        const p2: u32 = @intCast(131_072 - @as(i32, @bitCast(poly.cs[coefficient_index + 2])));
        const p3: u32 = @intCast(131_072 - @as(i32, @bitCast(poly.cs[coefficient_index + 3])));
        output[offset] = @truncate(p0);
        output[offset + 1] = @truncate(p0 >> 8);
        output[offset + 2] = @truncate((p0 >> 16) | (p1 << 2));
        output[offset + 3] = @truncate(p1 >> 6);
        output[offset + 4] = @truncate((p1 >> 14) | (p2 << 4));
        output[offset + 5] = @truncate(p2 >> 4);
        output[offset + 6] = @truncate((p2 >> 12) | (p3 << 6));
        output[offset + 7] = @truncate(p3 >> 2);
        output[offset + 8] = @truncate(p3 >> 10);
        coefficient_index += 4;
    }
}

fn packZ19Signed(poly: *const Poly, output: *[640]u8) void {
    var coefficient_index: usize = 0;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 5) {
        const p0: u32 = @intCast(
            524_288 - @as(i32, @bitCast(poly.cs[coefficient_index])),
        );
        const p1: u32 = @intCast(
            524_288 - @as(i32, @bitCast(poly.cs[coefficient_index + 1])),
        );
        output[offset] = @truncate(p0);
        output[offset + 1] = @truncate(p0 >> 8);
        output[offset + 2] = @truncate((p0 >> 16) | (p1 << 4));
        output[offset + 3] = @truncate(p1 >> 4);
        output[offset + 4] = @truncate(p1 >> 12);
        coefficient_index += 2;
    }
}

fn makeHint44(
    output: *PolyVec4,
    low: *const PolyVec4,
    high: *const PolyVec4,
) usize {
    var count: usize = 0;
    for (0..4) |poly_index| {
        for (0..coefficient_count) |index| {
            const low_signed: i32 = @bitCast(low.ps[poly_index].cs[index]);
            const sign_extension = low_signed >> 31;
            const low_canonical: u32 = @bitCast(
                low_signed + (sign_extension & @as(i32, modulus)),
            );
            const high_coefficient = high.ps[poly_index].cs[index];
            const no_hint = low_canonical <= decomposition_gamma2 or
                low_canonical > modulus - decomposition_gamma2 or
                (low_canonical == modulus - decomposition_gamma2 and
                    high_coefficient == 0);
            const hint: u32 = @intFromBool(!no_hint);
            output.ps[poly_index].cs[index] = hint;
            count += hint;
        }
    }
    return count;
}

fn makeHintGeneric(
    output: anytype,
    low: anytype,
    high: anytype,
    comptime count: usize,
    comptime gamma2: u32,
) usize {
    var hint_count: usize = 0;
    for (0..count) |poly_index| {
        for (0..coefficient_count) |index| {
            const low_signed: i32 = @bitCast(low.ps[poly_index].cs[index]);
            const sign_extension = low_signed >> 31;
            const low_canonical: u32 = @bitCast(
                low_signed + (sign_extension & @as(i32, modulus)),
            );
            const high_coefficient = high.ps[poly_index].cs[index];
            const no_hint = low_canonical <= gamma2 or
                low_canonical > modulus - gamma2 or
                (low_canonical == modulus - gamma2 and high_coefficient == 0);
            const hint: u32 = @intFromBool(!no_hint);
            output.ps[poly_index].cs[index] = hint;
            hint_count += hint;
        }
    }
    return hint_count;
}

fn packHint44(output: *[84]u8, hint: *const PolyVec4, hint_count: usize) void {
    std.debug.assert(hint_count <= 80);
    var count: usize = 0;
    for (0..4) |poly_index| {
        for (0..coefficient_count) |index| {
            if (hint.ps[poly_index].cs[index] != 0) {
                output[count] = @intCast(index);
                count += 1;
            }
        }
        output[80 + poly_index] = @intCast(count);
    }
    @memset(output[count..80], 0);
}

fn packHintGeneric(
    output: []u8,
    hint: anytype,
    hint_count: usize,
    comptime count: usize,
    comptime omega: usize,
) void {
    std.debug.assert(output.len == omega + count);
    std.debug.assert(hint_count <= omega);
    var written: usize = 0;
    for (0..count) |poly_index| {
        for (0..coefficient_count) |index| {
            if (hint.ps[poly_index].cs[index] != 0) {
                output[written] = @intCast(index);
                written += 1;
            }
        }
        output[omega + poly_index] = @intCast(written);
    }
    @memset(output[written..omega], 0);
}

fn decompose32Poly(high: *Poly, low_and_input: *Poly) void {
    for (&low_and_input.cs, &high.cs) |*low, *high_coefficient| {
        const input = low.*;
        var high_bits = (input + 127) >> 7;
        high_bits = ((high_bits * 1_025) + (1 << 21)) >> 22;
        const corner_mask: i32 = @bitCast(signMask(15 -% high_bits));
        const signed_low = @as(i32, @intCast(input)) -
            @as(i32, @intCast(high_bits * 523_776)) + corner_mask;
        high_coefficient.* = high_bits & 15;
        low.* = @bitCast(signed_low);
    }
}

fn nttScalarInPlace(poly: *Poly) void {
    var zeta_index: usize = 0;
    var length: usize = coefficient_count / 2;
    while (length > 0) : (length >>= 1) {
        var offset: usize = 0;
        while (offset < coefficient_count - length) : (offset += 2 * length) {
            zeta_index += 1;
            const zeta = ntt_zetas[zeta_index];
            var index = offset;
            if (comptime keccak4.enabled) {
                while (index + 4 <= offset + length) : (index += 4) {
                    const lower = loadVector4(&poly.cs[index]);
                    const product = montgomeryMulVector4(
                        loadVector4(&poly.cs[index + length]),
                        zeta,
                    );
                    storeVector4(
                        &poly.cs[index + length],
                        lower +% @as(Vector4u32, @splat(2 * modulus)) -% product,
                    );
                    storeVector4(&poly.cs[index], lower +% product);
                }
            }
            while (index < offset + length) : (index += 1) {
                const t = montgomeryReduceLe2Q(
                    @as(u64, zeta) * @as(u64, poly.cs[index + length]),
                );
                poly.cs[index + length] =
                    poly.cs[index] +% (2 * modulus -% t);
                poly.cs[index] +%= t;
            }
        }
    }
}

fn normalizeSignedNtt(value: i32) u32 {
    const positive: u32 = @intCast(@as(i64, value) + 6 * @as(i64, modulus));
    const at_most_2q = reduceLe2Q(positive);
    const reduced = at_most_2q -% modulus;
    return reduced +% (signMask(reduced) & modulus);
}

fn invNttInPlace(poly: *Poly) void {
    var zeta_index: usize = 0;
    var length: usize = 1;
    while (length < coefficient_count) : (length <<= 1) {
        var offset: usize = 0;
        while (offset < coefficient_count - length) : (offset += 2 * length) {
            const zeta: u64 = inverse_ntt_zetas[zeta_index];
            zeta_index += 1;
            for (offset..offset + length) |index| {
                const t = poly.cs[index];
                poly.cs[index] = t +% poly.cs[index + length];
                poly.cs[index + length] = montgomeryReduceLe2Q(
                    zeta * @as(
                        u64,
                        t +% 256 * modulus -% poly.cs[index + length],
                    ),
                );
            }
        }
    }
    for (&poly.cs) |*coefficient| {
        coefficient.* = montgomeryReduceLe2Q(
            @as(u64, r_over_256) * @as(u64, coefficient.*),
        );
    }
}

fn reduceLe2QInPlace(poly: *Poly) void {
    for (&poly.cs) |*coefficient| coefficient.* = reduceLe2Q(coefficient.*);
}

fn normalizeLe2QInPlace(poly: *Poly) void {
    for (&poly.cs) |*coefficient| {
        const reduced = coefficient.* -% modulus;
        coefficient.* = reduced +% (signMask(reduced) & modulus);
    }
}

fn reduceLe2Q(value: u32) u32 {
    const high = value >> 23;
    const low = value & 0x7fffff;
    return low +% (high << 13) -% high;
}

fn montgomeryReduceLe2Q(value: u64) u32 {
    const multiplier = (value *% q_inverse) & 0xffffffff;
    return @truncate((value +% multiplier * @as(u64, modulus)) >> 32);
}

inline fn montgomeryMulVector4(
    values: Vector4u32,
    multiplier: u32,
) Vector4u32 {
    const product = @as(Vector4u64, @intCast(values)) *%
        @as(Vector4u64, @splat(multiplier));
    const low: Vector4u32 = @truncate(product);
    const factors = low *% @as(Vector4u32, @splat(q_inverse));
    const correction = @as(Vector4u64, @intCast(factors)) *%
        @as(Vector4u64, @splat(modulus));
    return @truncate((product +% correction) >> @splat(32));
}

inline fn loadVector4(pointer: *const u32) Vector4u32 {
    return @as(*align(1) const Vector4u32, @ptrCast(pointer)).*;
}

inline fn storeVector4(pointer: *u32, value: Vector4u32) void {
    @as(*align(1) Vector4u32, @ptrCast(pointer)).* = value;
}

fn sampleInBall44(seed: *const [32]u8) Poly {
    return sampleInBall(39, seed);
}

fn sampleInBall(comptime tau: u16, seed: []const u8) Poly {
    var result: Poly = .{ .cs = .{0} ** coefficient_count };
    var stream: [std.crypto.hash.sha3.Shake256.block_length]u8 = undefined;
    var hash = initShake256();
    hash.update(seed);
    hash.squeeze(&stream);

    var signs: u64 = 0;
    for (0..8) |index| {
        signs |= @as(u64, stream[index]) << @intCast(index * 8);
    }
    var stream_offset: usize = 8;
    var index: u16 = coefficient_count - tau;
    while (index < coefficient_count) : (index += 1) {
        var selected: u16 = undefined;
        while (true) {
            if (stream_offset == stream.len) {
                hash.squeeze(&stream);
                stream_offset = 0;
            }
            selected = stream[stream_offset];
            stream_offset += 1;
            if (selected <= index) break;
        }
        result.cs[index] = result.cs[selected];
        result.cs[selected] = 1;
        const sign_bit: u1 = @truncate(signs);
        const negative_mask = -%@as(u32, sign_bit);
        result.cs[selected] ^= negative_mask & modulus;
        signs >>= 1;
    }
    return result;
}

fn packW1(poly: *const Poly, hint: *const Poly, output: *[192]u8) void {
    var coefficient_index: usize = 0;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 3) {
        const c0 = useHint44(poly.cs[coefficient_index], hint.cs[coefficient_index]);
        const c1 = useHint44(poly.cs[coefficient_index + 1], hint.cs[coefficient_index + 1]);
        const c2 = useHint44(poly.cs[coefficient_index + 2], hint.cs[coefficient_index + 2]);
        const c3 = useHint44(poly.cs[coefficient_index + 3], hint.cs[coefficient_index + 3]);
        output[offset] = @truncate(c0 | (c1 << 6));
        output[offset + 1] = @truncate((c1 >> 2) | (c2 << 4));
        output[offset + 2] = @truncate((c2 >> 4) | (c3 << 2));
        coefficient_index += 4;
    }
}

fn packW1High(poly: *const Poly, output: *[192]u8) void {
    var coefficient_index: usize = 0;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 3) {
        const c0 = poly.cs[coefficient_index];
        const c1 = poly.cs[coefficient_index + 1];
        const c2 = poly.cs[coefficient_index + 2];
        const c3 = poly.cs[coefficient_index + 3];
        output[offset] = @truncate(c0 | (c1 << 6));
        output[offset + 1] = @truncate((c1 >> 2) | (c2 << 4));
        output[offset + 2] = @truncate((c2 >> 4) | (c3 << 2));
        coefficient_index += 4;
    }
}

fn packW1High19(poly: *const Poly, output: *[128]u8) void {
    var coefficient_index: usize = 0;
    for (output) |*byte| {
        byte.* = @truncate(
            poly.cs[coefficient_index] |
                (poly.cs[coefficient_index + 1] << 4),
        );
        coefficient_index += 2;
    }
}

fn useHint44(value: u32, hint: u32) u32 {
    const decomposition = decompose44(value);
    var high = decomposition.high;
    if (hint == 0) return high;
    if (decomposition.low_plus_q > modulus) {
        high = if (high == 43) 0 else high + 1;
    } else {
        high = if (high == 0) 43 else high - 1;
    }
    return high;
}

fn decompose44(value: u32) struct { low_plus_q: u32, high: u32 } {
    var high = (value + 127) >> 7;
    high = ((high * 11_275) + (1 << 23)) >> 24;
    high ^= signMask(43 -% high) & high;

    var low_plus_q = value -% high * (2 * decomposition_gamma2);
    low_plus_q +%= signMask(low_plus_q -% (modulus - 1) / 2) & modulus;
    return .{ .low_plus_q = low_plus_q, .high = high };
}

fn signMask(value: u32) u32 {
    return @bitCast(@as(i32, @bitCast(value)) >> 31);
}

const ntt_zetas = computeNttZetas();
const inverse_ntt_zetas = computeInverseNttZetas();

fn computeNttZetas() [coefficient_count]u32 {
    @setEvalBranchQuota(100_000);
    var result: [coefficient_count]u32 = undefined;
    for (0..coefficient_count) |index| {
        const exponent = @bitReverse(@as(u8, @intCast(index)));
        result[index] = toMontgomery(modularPow(primitive_root, exponent));
    }
    return result;
}

fn computeInverseNttZetas() [coefficient_count]u32 {
    @setEvalBranchQuota(100_000);
    var result: [coefficient_count]u32 = undefined;
    const inverse_root = modularInverse(primitive_root);
    for (0..coefficient_count) |index| {
        const reversed_index: u8 = @intCast(255 - index);
        const exponent: u32 = 256 - @as(u32, @bitReverse(reversed_index));
        result[index] = toMontgomery(modularPow(inverse_root, exponent));
    }
    return result;
}

fn toMontgomery(value: u32) u32 {
    const r_mod_q: u32 = @intCast((@as(u64, 1) << 32) % modulus);
    const r_squared_mod_q: u32 = @intCast(
        (@as(u64, r_mod_q) * r_mod_q) % modulus,
    );
    return montgomeryReduceLe2Q(@as(u64, value) * r_squared_mod_q);
}

fn modularInverse(value: u32) u32 {
    var old_remainder: i64 = modulus;
    var remainder: i64 = value;
    var old_coefficient: i64 = 0;
    var coefficient: i64 = 1;
    while (remainder != 0) {
        const quotient = @divTrunc(old_remainder, remainder);
        const next_remainder = old_remainder - quotient * remainder;
        old_remainder = remainder;
        remainder = next_remainder;
        const next_coefficient = old_coefficient - quotient * coefficient;
        old_coefficient = coefficient;
        coefficient = next_coefficient;
    }
    std.debug.assert(old_remainder == 1);
    if (old_coefficient < 0) old_coefficient += modulus;
    return @intCast(old_coefficient);
}

fn modularPow(base_value: u32, exponent_value: u32) u32 {
    var result: u32 = 1;
    var base = base_value;
    var exponent = exponent_value;
    while (exponent != 0) : (exponent >>= 1) {
        if (exponent & 1 != 0) {
            result = @intCast((@as(u64, result) * base) % modulus);
        }
        base = @intCast((@as(u64, base) * base) % modulus);
    }
    return result;
}

test "four-way ML-DSA-44 public key preparation matches Zig std" {
    if (comptime !keccak4.enabled) return error.SkipZigTest;
    inline for ([_]u8{ 0, 1, 0x5a, 0xff }) |seed_byte| {
        const generated = MlDsa44.newKeyFromSeed(
            &([_]u8{seed_byte} ** MlDsa44.seed_length),
        );
        const bytes = generated.pk.toBytes();
        const expected = try MlDsa44.PublicKey.fromBytes(bytes);
        const actual = try publicKey44FromBytes(bytes);
        try std.testing.expectEqual(expected.rho, actual.rho);
        try std.testing.expectEqual(expected.t1_packed, actual.t1_packed);
        try std.testing.expectEqual(expected.tr, actual.tr);
        inline for (0..4) |row| {
            inline for (0..4) |column| {
                try std.testing.expectEqual(
                    expected.A.rows[row].ps[column].cs,
                    actual.A.rows[row].ps[column].cs,
                );
            }
        }
    }
}

test "ML-DSA-44 verifier NTT constants and roundtrip match the specification" {
    const expected_prefix = [16]u32{
        4_193_792, 25_847,    5_771_523, 7_861_508,
        237_124,   7_602_457, 7_504_169, 466_468,
        1_826_347, 2_353_451, 8_021_166, 6_288_512,
        3_119_733, 5_495_562, 3_111_497, 2_680_103,
    };
    try std.testing.expectEqual(expected_prefix, ntt_zetas[0..expected_prefix.len].*);

    var poly: Poly = .{ .cs = .{0} ** coefficient_count };
    for (&poly.cs, 0..) |*coefficient, index| coefficient.* = @intCast(index);
    nttInPlace(&poly);
    reduceLe2QInPlace(&poly);
    invNttInPlace(&poly);
    reduceLe2QInPlace(&poly);
    normalizeLe2QInPlace(&poly);
    for (poly.cs, 0..) |coefficient, index| {
        const expected = reduceLe2Q(toMontgomery(@intCast(index)));
        const normalized = blk: {
            const reduced = expected -% modulus;
            break :blk reduced +% (signMask(reduced) & modulus);
        };
        try std.testing.expectEqual(normalized, coefficient);
    }
}

test "AVX2 ML-DSA NTT matches the scalar transform coefficient by coefficient" {
    if (comptime !mldsa_avx2.enabled) return error.SkipZigTest;
    inline for ([_]u32{ 1, 17, 65_537, modulus - 1 }) |factor| {
        var input: Poly = undefined;
        for (&input.cs, 0..) |*coefficient, index| {
            coefficient.* = @intCast(
                (@as(u64, index) * factor + factor *% 31) % modulus,
            );
        }

        var expected = input;
        nttScalarInPlace(&expected);
        reduceLe2QInPlace(&expected);
        normalizeLe2QInPlace(&expected);

        var actual: [coefficient_count]i32 align(32) = undefined;
        for (&actual, input.cs) |*output, coefficient| {
            output.* = @intCast(coefficient);
        }
        mldsa_avx2.ntt(&actual);
        for (0..4) |block| {
            for (0..8) |row| {
                for (0..8) |column| {
                    const standard_index = block * 64 + row * 8 + column;
                    const custom_index = block * 64 + column * 8 + row;
                    try std.testing.expectEqual(
                        expected.cs[standard_index],
                        normalizeSignedNtt(actual[custom_index]),
                    );
                }
            }
        }
        mldsa_avx2.invNtt(&actual);
        for (actual, input.cs) |coefficient, input_coefficient| {
            const montgomery = reduceLe2Q(toMontgomery(input_coefficient));
            const reduced = montgomery -% modulus;
            const expected_coefficient =
                reduced +% (signMask(reduced) & modulus);
            try std.testing.expectEqual(
                expected_coefficient,
                normalizeSignedNtt(coefficient),
            );
        }
    }
}

test "AVX2 ML-DSA pointwise kernels match scalar Montgomery arithmetic" {
    if (comptime !mldsa_avx2.enabled) return error.SkipZigTest;

    var left: Poly align(32) = undefined;
    var right: Poly align(32) = undefined;
    for (&left.cs, &right.cs, 0..) |*a, *b, index| {
        a.* = @intCast((@as(u64, index) * 65_537 + 17) % modulus);
        b.* = @intCast((@as(u64, index) * 131_071 + 29) % modulus);
    }
    const expected_product = mulHat(left, right);
    mldsa_avx2.pointwise(
        @ptrCast(@alignCast(&left.cs)),
        @ptrCast(@alignCast(&right.cs)),
    );
    for (left.cs, expected_product.cs) |actual, expected| {
        try std.testing.expectEqual(
            normalizeCoefficient(expected),
            normalizeSignedNtt(@bitCast(actual)),
        );
    }

    var left_vector: PolyVec4 align(32) = undefined;
    var right_vector: PolyVec4 align(32) = undefined;
    for (0..4) |poly_index| {
        for (0..coefficient_count) |index| {
            left_vector.ps[poly_index].cs[index] = @intCast(
                (@as(u64, index) * (257 + poly_index * 2) + poly_index + 1) % modulus,
            );
            right_vector.ps[poly_index].cs[index] = @intCast(
                (@as(u64, index) * (521 + poly_index * 4) + poly_index + 3) % modulus,
            );
        }
    }
    var expected_dot: Poly = .{ .cs = .{0} ** coefficient_count };
    for (0..4) |poly_index| {
        expected_dot = add(
            expected_dot,
            mulHat(left_vector.ps[poly_index], right_vector.ps[poly_index]),
        );
    }
    var actual_dot: Poly align(32) = undefined;
    mldsa_avx2.dotHatL4(
        @ptrCast(@alignCast(&actual_dot.cs)),
        @ptrCast(@alignCast(&left_vector.ps)),
        @ptrCast(@alignCast(&right_vector.ps)),
    );
    for (actual_dot.cs, expected_dot.cs) |actual, expected| {
        try std.testing.expectEqual(
            normalizeCoefficient(expected),
            normalizeSignedNtt(@bitCast(actual)),
        );
    }
}

test "AVX2 ML-DSA-44 use-hint matches scalar packed output" {
    if (comptime !mldsa_avx2.enabled) return error.SkipZigTest;
    var polynomial: Poly align(32) = undefined;
    var hint: Poly align(32) = .{ .cs = .{0} ** coefficient_count };
    for (&polynomial.cs, 0..) |*coefficient, index| {
        coefficient.* = @intCast(
            (@as(u64, index) * 196_613 + 97_531) % modulus,
        );
        hint.cs[index] = @intFromBool(index % 7 == 0 or index % 29 == 0);
    }

    var expected: [192]u8 = undefined;
    packW1(&polynomial, &hint, &expected);
    mldsa_avx2.useHint88(
        @ptrCast(@alignCast(&polynomial.cs)),
        @ptrCast(@alignCast(&hint.cs)),
    );
    var actual: [192]u8 = undefined;
    packW1High(&polynomial, &actual);
    try std.testing.expectEqual(expected, actual);
}

test "AVX2 ML-DSA-44 decomposition matches scalar coefficients" {
    if (comptime !mldsa_avx2.enabled) return error.SkipZigTest;
    var low: Poly align(32) = undefined;
    var high: Poly align(32) = undefined;
    var original: [coefficient_count]u32 = undefined;
    for (&low.cs, &original, 0..) |*coefficient, *copy, index| {
        coefficient.* = @intCast(
            (@as(u64, index) * 524_287 + 131_101) % modulus,
        );
        copy.* = coefficient.*;
    }
    mldsa_avx2.decompose88(
        @ptrCast(@alignCast(&high.cs)),
        @ptrCast(@alignCast(&low.cs)),
    );
    for (original, 0..) |coefficient, index| {
        const expected = decompose44(coefficient);
        try std.testing.expectEqual(expected.high, high.cs[index]);
        try std.testing.expectEqual(
            @as(i32, @intCast(expected.low_plus_q)) - @as(i32, modulus),
            @as(i32, @bitCast(low.cs[index])),
        );
    }
}

test "AVX2 ML-DSA eta=4 rejection matches scalar sampling" {
    if (!mldsa_avx2.enabled) return error.SkipZigTest;

    var inputs: [4][keccak4.mldsa_eta_output_length]u8 = undefined;
    @memset(&inputs[0], 0x88);
    @memset(&inputs[1], 0xff);
    for (&inputs[2], 0..) |*byte, index| byte.* = @truncate(index *% 73 +% 19);
    for (&inputs[3], 0..) |*byte, index| byte.* = @truncate(index);

    for (&inputs) |*input| {
        var expected: [coefficient_count]u32 = undefined;
        var expected_count: usize = 0;
        appendEta4Signed(&expected, &expected_count, input);
        var actual: [coefficient_count]u32 align(32) = undefined;
        const actual_count = mldsa_avx2.rejectEta4(&actual, input, actual.len);
        try std.testing.expectEqual(expected_count, actual_count);
        try std.testing.expectEqualSlices(
            u32,
            expected[0..expected_count],
            actual[0..actual_count],
        );

        inline for ([_]usize{ 1, 7, 8, 9, 31, 255 }) |capacity| {
            const sentinel: u32 = 0xdeadbeef;
            var guarded: [coefficient_count + 2]u32 align(32) =
                .{sentinel} ** (coefficient_count + 2);
            const bounded_count = mldsa_avx2.rejectEta4(
                @ptrCast(&guarded[1]),
                input,
                capacity,
            );
            const expected_bounded = @min(expected_count, capacity);
            try std.testing.expectEqual(expected_bounded, bounded_count);
            try std.testing.expectEqualSlices(
                u32,
                expected[0..expected_bounded],
                guarded[1..][0..bounded_count],
            );
            try std.testing.expectEqual(sentinel, guarded[0]);
            try std.testing.expectEqual(sentinel, guarded[1 + capacity]);
        }
    }
}

test "AVX2 SHAKE256 sponge matches Zig std across rate boundaries" {
    if (comptime !keccak_avx2.enabled) return error.SkipZigTest;
    var input: [1_312]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 193 +% 71);

    inline for ([_]usize{ 0, 1, 32, 135, 136, 137, 271, 1_312 }) |length| {
        var expected: [272]u8 = undefined;
        std.crypto.hash.sha3.Shake256.hash(input[0..length], &expected, .{});

        var actual: [272]u8 = undefined;
        var hash = FastShake256.init(.{});
        const split = @min(length, 73);
        hash.update(input[0..split]);
        hash.update(input[split..length]);
        hash.squeeze(actual[0..17]);
        hash.squeeze(actual[17..]);
        try std.testing.expectEqual(expected, actual);
    }
}

fn normalizeCoefficient(value: u32) u32 {
    const at_most_2q = reduceLe2Q(value);
    const reduced = at_most_2q -% modulus;
    return reduced +% (signMask(reduced) & modulus);
}
