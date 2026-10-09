//! Optimized Ed25519 key derivation, signing, and verification.

const std = @import("std");
const decode_adx = @import("ed25519_decode_adx.zig");
const point_adx = @import("ed25519_point_ops_adx.zig");
const scalar_adx = @import("ed25519_scalar_adx.zig");
const x25519 = @import("x25519.zig");
const table_values = @import("x25519_tables.zig");
const verify_table = @import("ed25519_verify_table.zig");

const StdEd25519 = std.crypto.sign.Ed25519;
const Curve = StdEd25519.Curve;
const Fe = Curve.Fe;
const sha512 = @import("sha512.zig");
const Sha512 = sha512.Sha512;
const IdentityElementError = std.crypto.errors.IdentityElementError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const KeyMismatchError = std.crypto.errors.KeyMismatchError;
const WeakPublicKeyError = std.crypto.errors.WeakPublicKeyError;
const EncodingError = std.crypto.errors.EncodingError;
const SignatureVerificationError =
    std.crypto.errors.SignatureVerificationError;

const verify_comb_groups = 4;
const verify_comb_width = 5;
const verify_comb_entries = 1 << verify_comb_width;
const verify_comb_windows = 13;
const one_shot_base_width = 12;
const one_shot_base_entries = 1 << (one_shot_base_width - 2);
const one_shot_public_width = 6;
const one_shot_public_entries = 1 << (one_shot_public_width - 2);
const one_shot_wnaf_digits = 257;

const AdxPoint = [16]u64;
const AdxCachedPoint = [12]u64;

const AdxWnafEntry = struct {
    position: u16,
    digit: i16,
};

fn AdxWnaf(comptime width: usize) type {
    return struct {
        entries: [(one_shot_wnaf_digits + width - 1) / width]AdxWnafEntry,
        len: usize,
    };
}

const CachedPoint = struct {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
};

pub const SignError = IdentityElementError || NonCanonicalError ||
    KeyMismatchError || WeakPublicKeyError;
pub const VerifyError = IdentityElementError || NonCanonicalError ||
    EncodingError || WeakPublicKeyError || SignatureVerificationError;

/// Expanded Ed25519 signing state for repeated signatures with one key.
pub const PreparedSigner = struct {
    scalar: [32]u8,
    prefix: [32]u8,
    nonce_prefix_state: Sha512,
    public_key_bytes: [StdEd25519.PublicKey.encoded_length]u8,

    pub fn init(key_pair: StdEd25519.KeyPair) KeyMismatchError!PreparedSigner {
        const embedded_public = key_pair.secret_key.publicKeyBytes();
        const public_key_bytes = key_pair.public_key.toBytes();
        if (!std.mem.eql(u8, &embedded_public, &public_key_bytes)) {
            return error.KeyMismatch;
        }

        var expanded: [Sha512.digest_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &expanded);
        sha512.hash32(&key_pair.secret_key.seed(), &expanded);
        Curve.scalar.clamp(expanded[0..32]);
        var nonce_prefix_state = sha512.initWithPrefix32(expanded[32..64]);
        defer std.crypto.secureZero(
            u8,
            std.mem.asBytes(&nonce_prefix_state),
        );
        return .{
            .scalar = expanded[0..32].*,
            .prefix = expanded[32..].*,
            .nonce_prefix_state = nonce_prefix_state,
            .public_key_bytes = public_key_bytes,
        };
    }

    pub fn deinit(self: *PreparedSigner) void {
        std.crypto.secureZero(u8, &self.scalar);
        std.crypto.secureZero(u8, &self.prefix);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.nonce_prefix_state));
        self.* = undefined;
    }

    pub fn matchesPublicKey(
        self: *const PreparedSigner,
        public_key: StdEd25519.PublicKey,
    ) bool {
        return std.mem.eql(
            u8,
            &self.public_key_bytes,
            &public_key.toBytes(),
        );
    }

    pub fn sign(
        self: *const PreparedSigner,
        message: []const u8,
        noise: ?[StdEd25519.noise_length]u8,
    ) SignError!StdEd25519.Signature {
        if (noise) |random| {
            var nonce_hasher = sha512.initWithPrefix64(
                &random,
                &self.prefix,
            );
            defer std.crypto.secureZero(u8, std.mem.asBytes(&nonce_hasher));
            return signWithNonceHasher(
                &self.scalar,
                self.public_key_bytes,
                message,
                &nonce_hasher,
            );
        }
        return self.signDeterministic(message);
    }

    pub fn signDeterministic(
        self: *const PreparedSigner,
        message: []const u8,
    ) SignError!StdEd25519.Signature {
        var nonce_hasher = self.nonce_prefix_state;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&nonce_hasher));
        return signWithNonceHasher(
            &self.scalar,
            self.public_key_bytes,
            message,
            &nonce_hasher,
        );
    }
};

/// Reusable public-key state for low-latency Ed25519 verification.
pub const PreparedVerifier = struct {
    public_key_bytes: [StdEd25519.PublicKey.encoded_length]u8,
    public_table: [verify_comb_groups][verify_comb_entries]CachedPoint,

    pub const InitError = IdentityElementError || EncodingError ||
        WeakPublicKeyError;

    pub fn init(public_key: StdEd25519.PublicKey) InitError!PreparedVerifier {
        const public_key_bytes = public_key.toBytes();
        const public_point = try Curve.fromBytes(public_key_bytes);
        if (curveIdentity(public_point)) return error.IdentityElement;
        const verification_point = public_point.clearCofactor().neg();
        if (curveIdentity(verification_point)) return error.WeakPublicKey;
        return .{
            .public_key_bytes = public_key_bytes,
            .public_table = buildPublicComb(verification_point),
        };
    }

    pub fn matchesPublicKey(
        self: *const PreparedVerifier,
        public_key: StdEd25519.PublicKey,
    ) bool {
        return std.mem.eql(
            u8,
            &self.public_key_bytes,
            &public_key.toBytes(),
        );
    }

    /// Verify using Zig std's cofactored equation. Signature and message are
    /// public, so table indexing and zero-digit skipping are variable-time.
    pub fn verify(
        self: *const PreparedVerifier,
        signature: StdEd25519.Signature,
        message: []const u8,
    ) VerifyError!void {
        const signature_bytes = signature.toBytes();
        const encoded_nonce = signature_bytes[0..Curve.encoded_length].*;
        const response = signature_bytes[Curve.encoded_length..].*;
        try Curve.scalar.rejectNonCanonical(response);
        try Curve.rejectNonCanonical(encoded_nonce);
        const expected_nonce = try Curve.fromBytes(encoded_nonce);
        try expected_nonce.rejectIdentity();

        var challenge_hasher = sha512.initWithPrefix64(
            &encoded_nonce,
            &self.public_key_bytes,
        );
        challenge_hasher.update(message);
        var challenge_wide: [Sha512.digest_length]u8 = undefined;
        challenge_hasher.final(&challenge_wide);
        const challenge = scalar_adx.reduce64(&challenge_wide);

        const combined = doubleScalarMulComb(
            Curve.scalar.mul8(response),
            challenge,
            &self.public_table,
        );
        const check = combined.sub(expected_nonce.clearCofactor());
        if (!check.x.isZero() or !check.y.equivalent(check.z)) {
            return error.SignatureVerificationFailed;
        }
    }
};

/// Verify an Ed25519 signature. Linux x86_64 BMI2/ADX builds use a
/// public-input variable-time wNAF path; other targets retain Zig std's
/// cofactored verifier.
pub fn verify(
    signature: StdEd25519.Signature,
    message: []const u8,
    public_key: StdEd25519.PublicKey,
) VerifyError!void {
    if (comptime point_adx.enabled and decode_adx.enabled) {
        return verifyAdx(signature, message, public_key);
    }
    return signature.verify(message, public_key) catch |err| switch (err) {
        error.IdentityElement => {
            // Zig std currently treats every x=0 point as the identity. The
            // y=-1 point has order two instead, so preserve Vail's portable
            // distinction between the identity and other low-order keys.
            const public_point = Curve.fromBytes(public_key.toBytes()) catch
                return err;
            if (!curveIdentity(public_point) and
                curveIdentity(public_point.clearCofactor()))
            {
                return error.WeakPublicKey;
            }
            return err;
        },
        else => return err,
    };
}

fn verifyAdx(
    signature: StdEd25519.Signature,
    message: []const u8,
    public_key: StdEd25519.PublicKey,
) VerifyError!void {
    const signature_bytes = signature.toBytes();
    const encoded_nonce = signature_bytes[0..Curve.encoded_length].*;
    const response = signature_bytes[Curve.encoded_length..].*;
    try Curve.scalar.rejectNonCanonical(response);
    try Curve.rejectNonCanonical(encoded_nonce);

    const public_key_bytes = public_key.toBytes();
    var public_affine: [8]u64 = undefined;
    if (!decode_adx.decode(&public_affine, &public_key_bytes)) {
        return error.InvalidEncoding;
    }
    if (adxAffineIdentity(public_affine)) return error.IdentityElement;
    var public_projective = adxProjectiveFromAffine(public_affine);
    public_projective[0..4].* = adxNegateField(public_projective[0..4].*);
    var public_point: AdxPoint = undefined;
    point_adx.pointDoubleProjective(&public_point, &public_projective);
    point_adx.pointDoubleProjective(&public_point, @ptrCast(&public_point));
    point_adx.pointDouble(&public_point, @ptrCast(&public_point));
    if (adxProjectiveIdentity(public_point)) return error.WeakPublicKey;
    var twice_public: AdxPoint = undefined;
    point_adx.pointDouble(&twice_public, @ptrCast(&public_point));

    var nonce_affine: [8]u64 = undefined;
    if (!decode_adx.decode(&nonce_affine, &encoded_nonce)) {
        return error.InvalidEncoding;
    }
    if (adxAffineIdentity(nonce_affine)) return error.IdentityElement;
    const nonce_projective = adxProjectiveFromAffine(nonce_affine);
    var expected_nonce: AdxPoint = undefined;
    point_adx.pointDoubleProjective(&expected_nonce, &nonce_projective);
    point_adx.pointDoubleProjective(&expected_nonce, @ptrCast(&expected_nonce));
    point_adx.pointDoubleProjective(&expected_nonce, @ptrCast(&expected_nonce));

    var challenge_hasher = sha512.initWithPrefix64(
        &encoded_nonce,
        &public_key_bytes,
    );
    challenge_hasher.update(message);
    var challenge_wide: [Sha512.digest_length]u8 = undefined;
    challenge_hasher.final(&challenge_wide);
    const base_scalar = Curve.scalar.mul8(response);
    const public_scalar = scalar_adx.reduce64(&challenge_wide);

    var public_table: [one_shot_public_entries]AdxPoint = undefined;
    public_table[0] = public_point;
    for (1..one_shot_public_entries) |index| {
        point_adx.pointAdd(
            &public_table[index],
            &public_table[index - 1],
            &twice_public,
        );
    }
    const combined = adxDoubleScalarMul(
        base_scalar,
        public_scalar,
        &public_table,
    );
    if (!adxPointsEquivalent(combined, expected_nonce)) {
        return error.SignatureVerificationFailed;
    }
}

/// Derive an Ed25519 public key from its 32-byte seed.
pub fn recoverPublicKey(
    seed: [StdEd25519.KeyPair.seed_length]u8,
) IdentityElementError![StdEd25519.PublicKey.encoded_length]u8 {
    return recoverPublicKeyPtr(&seed);
}

fn recoverPublicKeyPtr(
    seed: *const [StdEd25519.KeyPair.seed_length]u8,
) [StdEd25519.PublicKey.encoded_length]u8 {
    var expanded: [Sha512.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &expanded);
    sha512.hash32(seed, &expanded);
    Curve.scalar.clamp(expanded[0..32]);
    return x25519.mulEdwardsBaseEncodedNonZeroPtr(expanded[0..32]);
}

/// Deterministically derive a standard-library-compatible Ed25519 key pair.
pub fn generateKeyPairDeterministic(
    seed: [StdEd25519.KeyPair.seed_length]u8,
) IdentityElementError!StdEd25519.KeyPair {
    const public_key_bytes = recoverPublicKeyPtr(&seed);
    const secret_key_bytes = seed ++ public_key_bytes;
    return .{
        .public_key = .{ .bytes = public_key_bytes },
        .secret_key = .{ .bytes = secret_key_bytes },
    };
}

/// Sign with a standard-library Ed25519 key pair while using Vail's fixed-base
/// comb for the secret nonce multiplication.
pub fn sign(
    key_pair: StdEd25519.KeyPair,
    message: []const u8,
    noise: ?[StdEd25519.noise_length]u8,
) SignError!StdEd25519.Signature {
    const embedded_public = key_pair.secret_key.publicKeyBytes();
    const public_key_bytes = key_pair.public_key.toBytes();
    if (!std.mem.eql(u8, &embedded_public, &public_key_bytes)) {
        return error.KeyMismatch;
    }

    var expanded: [Sha512.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &expanded);
    sha512.hash32(&key_pair.secret_key.seed(), &expanded);
    Curve.scalar.clamp(expanded[0..32]);

    var nonce_hasher = if (noise) |random|
        sha512.initWithPrefix64(&random, expanded[32..64])
    else
        sha512.initWithPrefix32(expanded[32..64]);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&nonce_hasher));
    return signWithNonceHasher(
        expanded[0..32],
        public_key_bytes,
        message,
        &nonce_hasher,
    );
}

fn signWithNonceHasher(
    scalar: *const [32]u8,
    public_key_bytes: [StdEd25519.PublicKey.encoded_length]u8,
    message: []const u8,
    nonce_hasher: *Sha512,
) SignError!StdEd25519.Signature {
    nonce_hasher.update(message);
    var nonce_wide: [Sha512.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce_wide);
    nonce_hasher.final(&nonce_wide);
    var nonce = scalar_adx.reduce64(&nonce_wide);
    defer std.crypto.secureZero(u8, &nonce);

    const encoded_nonce = try x25519.mulEdwardsBaseEncodedPtr(&nonce);

    var challenge_hasher = sha512.initWithPrefix64(
        &encoded_nonce,
        &public_key_bytes,
    );
    challenge_hasher.update(message);
    var challenge_wide: [Sha512.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &challenge_wide);
    challenge_hasher.final(&challenge_wide);
    const challenge = scalar_adx.reduce64(&challenge_wide);

    const response = scalar_adx.mulAdd(&challenge, scalar, &nonce);
    return StdEd25519.Signature.fromBytes(encoded_nonce ++ response);
}

pub const testing = struct {
    pub fn hashSeed(seed: [32]u8) [64]u8 {
        var digest: [64]u8 = undefined;
        sha512.hash32(&seed, &digest);
        return digest;
    }

    pub fn reduce64(wide: [64]u8) [32]u8 {
        return scalar_adx.reduce64(&wide);
    }

    pub fn mulAdd(x: [32]u8, y: [32]u8, addend: [32]u8) [32]u8 {
        return scalar_adx.mulAdd(&x, &y, &addend);
    }
};

fn buildPublicComb(
    point: Curve,
) [verify_comb_groups][verify_comb_entries]CachedPoint {
    const column_count = verify_comb_groups * verify_comb_width;
    const point_count = verify_comb_groups * verify_comb_entries;
    var columns: [column_count]Curve = undefined;
    columns[0] = point;
    for (1..column_count) |column| {
        var next = columns[column - 1];
        for (0..verify_comb_windows) |_| next = next.dbl();
        columns[column] = next;
    }

    var points: [verify_comb_groups][verify_comb_entries]Curve = undefined;
    for (0..verify_comb_groups) |group| {
        points[group][0] = Curve.identityElement;
        points[group][1] = columns[group * verify_comb_width];
        for (2..verify_comb_entries) |index| {
            const column: std.math.Log2Int(usize) = @intCast(@ctz(index));
            points[group][index] = points[group][
                index ^ (@as(usize, 1) << column)
            ].add(columns[group * verify_comb_width + column]);
        }
    }

    var prefixes: [point_count]Fe = undefined;
    var product = Fe.one;
    for (0..point_count) |flat_index| {
        prefixes[flat_index] = product;
        const group = flat_index / verify_comb_entries;
        const index = flat_index % verify_comb_entries;
        product = product.mul(points[group][index].z);
    }

    var table: [verify_comb_groups][verify_comb_entries]CachedPoint = undefined;
    var inverse_product = product.invert();
    var flat_index: usize = point_count;
    while (flat_index != 0) {
        flat_index -= 1;
        const group = flat_index / verify_comb_entries;
        const index = flat_index % verify_comb_entries;
        const projective = points[group][index];
        const inverse = inverse_product.mul(prefixes[flat_index]);
        inverse_product = inverse_product.mul(projective.z);
        const x = projective.x.mul(inverse);
        const y = projective.y.mul(inverse);
        const t = projective.t.mul(inverse);
        table[group][index] = .{
            .y_plus_x = y.add(x),
            .y_minus_x = y.sub(x),
            .xy2d = t.mul(Fe.edwards25519d2),
        };
    }
    return table;
}

fn doubleScalarMulComb(
    base_scalar: [32]u8,
    public_scalar: [32]u8,
    public_table: *const [verify_comb_groups][verify_comb_entries]CachedPoint,
) Curve {
    const scalars = [2][33]u8{
        base_scalar ++ [_]u8{0},
        public_scalar ++ [_]u8{0},
    };
    var result = Curve.identityElement;
    var window: usize = verify_comb_windows;
    while (window != 0) {
        window -= 1;
        if (window != verify_comb_windows - 1) result = result.dbl();
        inline for (0..verify_comb_groups) |group| {
            const base_digit = verificationCombDigit(
                &scalars[0],
                window,
                group,
            );
            if (base_digit != 0) {
                result = addCached(
                    result,
                    loadBaseCached(group, base_digit),
                );
            }
            const public_digit = verificationCombDigit(
                &scalars[1],
                window,
                group,
            );
            if (public_digit != 0) {
                result = addCached(result, public_table[group][public_digit]);
            }
        }
    }
    return result;
}

inline fn verificationCombDigit(
    scalar: *const [33]u8,
    window: usize,
    comptime group: usize,
) usize {
    var digit: usize = 0;
    inline for (0..verify_comb_width) |column| {
        const bit_index = window +
            (group * verify_comb_width + column) * verify_comb_windows;
        const bit: u1 = @truncate(
            scalar[bit_index / 8] >> @intCast(bit_index % 8),
        );
        digit |= @as(usize, bit) << column;
    }
    return digit;
}

inline fn loadBaseCached(group: usize, index: usize) CachedPoint {
    var point: CachedPoint = undefined;
    inline for (0..5) |limb| {
        point.y_plus_x.limbs[limb] =
            table_values.cached[group][0][limb][index];
        point.y_minus_x.limbs[limb] =
            table_values.cached[group][1][limb][index];
        point.xy2d.limbs[limb] =
            table_values.cached[group][2][limb][index];
    }
    return point;
}

inline fn addCached(point: Curve, cached: CachedPoint) Curve {
    const a = point.y.sub(point.x).mul(cached.y_minus_x);
    const b = point.x.add(point.y).mul(cached.y_plus_x);
    const c = point.t.mul(cached.xy2d);
    const d = point.z.add(point.z);
    const x = b.sub(a);
    const y = b.add(a);
    const z = d.add(c);
    const t = d.sub(c);
    return .{
        .x = x.mul(t),
        .y = y.mul(z),
        .z = z.mul(t),
        .t = x.mul(y),
    };
}

fn adxDoubleScalarMul(
    base_scalar: [32]u8,
    public_scalar: [32]u8,
    public_table: *const [one_shot_public_entries]AdxPoint,
) AdxPoint {
    const base_wnaf = adxWnafSparse(one_shot_base_width, base_scalar);
    const public_wnaf = adxWnafSparse(one_shot_public_width, public_scalar);
    var result = adxIdentityPoint();
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

    // Both scalars and their wNAF digits are public during verification.
    while (true) {
        if (base_index != 0 and
            base_wnaf.entries[base_index - 1].position == position)
        {
            base_index -= 1;
            const base_digit = base_wnaf.entries[base_index].digit;
            var selected = verify_table.base_wnaf_12[
                (@abs(base_digit) - 1) / 2
            ];
            if (base_digit < 0) adxNegateCached(&selected);
            point_adx.pointPrecomputedAdd(&result, &result, &selected);
        }
        if (public_index != 0 and
            public_wnaf.entries[public_index - 1].position == position)
        {
            public_index -= 1;
            const public_digit = public_wnaf.entries[public_index].digit;
            var selected = public_table[(@abs(public_digit) - 1) / 2];
            if (public_digit < 0) adxNegatePoint(&selected);
            point_adx.pointAdd(&result, &result, &selected);
        }
        if (position == 0) break;
        position -= 1;
        const needs_extended =
            (base_index != 0 and
                base_wnaf.entries[base_index - 1].position == position) or
            (public_index != 0 and
                public_wnaf.entries[public_index - 1].position == position);
        if (needs_extended) {
            point_adx.pointDouble(&result, @ptrCast(&result));
        } else {
            point_adx.pointDoubleProjective(&result, @ptrCast(&result));
        }
    }
    return result;
}

fn adxWnafSparse(
    comptime width: usize,
    scalar: [32]u8,
) AdxWnaf(width) {
    var result: AdxWnaf(width) = undefined;
    result.len = 0;
    var limbs: [4]u64 = undefined;
    inline for (0..4) |index| {
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
        const bit: u16 = @truncate(limbs[limb_index] >> bit_offset);
        if ((bit & 1) == carry) {
            position += 1;
            continue;
        }
        var window = limbs[limb_index] >> bit_offset;
        if (bit_offset > 64 - width and limb_index + 1 < limbs.len) {
            const upper_shift: u6 = @intCast(64 - @as(u7, bit_offset));
            window |= limbs[limb_index + 1] << upper_shift;
        }
        const residue: u16 = @truncate(window & ((1 << width) - 1));
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

fn adxWnafDigits(
    comptime width: usize,
    scalar: [32]u8,
) [one_shot_wnaf_digits]i16 {
    var digits = [_]i16{0} ** one_shot_wnaf_digits;
    var remaining = std.mem.readInt(u256, &scalar, .little);
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

fn adxProjectiveFromAffine(affine: [8]u64) [12]u64 {
    return affine ++ [4]u64{ 1, 0, 0, 0 };
}

fn adxIdentityPoint() AdxPoint {
    return .{ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };
}

fn curveIdentity(point: Curve) bool {
    return point.x.isZero() and point.y.equivalent(point.z);
}

fn adxAffineIdentity(point: [8]u64) bool {
    return adxFieldZero(point[0..4].*) and
        point[4] == 1 and point[5] == 0 and
        point[6] == 0 and point[7] == 0;
}

fn adxProjectiveIdentity(point: AdxPoint) bool {
    return adxFieldZero(point[0..4].*) and
        adxFieldEqual(point[4..8].*, point[8..12].*);
}

fn adxPointsEquivalent(first: AdxPoint, second: AdxPoint) bool {
    var first_cross: [4]u64 = undefined;
    var second_cross: [4]u64 = undefined;
    decode_adx.fieldMul(
        &first_cross,
        &first[0..4].*,
        &second[8..12].*,
    );
    decode_adx.fieldMul(
        &second_cross,
        &second[0..4].*,
        &first[8..12].*,
    );
    if (!adxFieldEqual(first_cross, second_cross)) return false;
    decode_adx.fieldMul(
        &first_cross,
        &first[4..8].*,
        &second[8..12].*,
    );
    decode_adx.fieldMul(
        &second_cross,
        &second[4..8].*,
        &first[8..12].*,
    );
    return adxFieldEqual(first_cross, second_cross);
}

fn adxNegateCached(point: *AdxCachedPoint) void {
    const y_minus_x = point[0..4].*;
    point[0..4].* = point[4..8].*;
    point[4..8].* = y_minus_x;
    point[8..12].* = adxNegateField(point[8..12].*);
}

fn adxNegatePoint(point: *AdxPoint) void {
    point[0..4].* = adxNegateField(point[0..4].*);
    point[12..16].* = adxNegateField(point[12..16].*);
}

fn adxNegateField(value: [4]u64) [4]u64 {
    const modulus = [4]u64{
        0xffff_ffff_ffff_ffed,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    };
    var result: [4]u64 = undefined;
    var borrow: u1 = 0;
    inline for (0..4) |index| {
        const first = @subWithOverflow(modulus[index], value[index]);
        const second = @subWithOverflow(first[0], borrow);
        result[index] = second[0];
        borrow = first[1] | second[1];
    }
    var combined: u64 = 0;
    inline for (value) |limb| combined |= limb;
    const mask = 0 -% ((combined | (0 -% combined)) >> 63);
    inline for (&result) |*limb| limb.* &= mask;
    return result;
}

fn adxFieldZero(value: [4]u64) bool {
    return (value[0] | value[1] | value[2] | value[3]) == 0;
}

fn adxFieldEqual(left: [4]u64, right: [4]u64) bool {
    return ((left[0] ^ right[0]) |
        (left[1] ^ right[1]) |
        (left[2] ^ right[2]) |
        (left[3] ^ right[3])) == 0;
}

fn adxDecodeField(bytes: [32]u8) [4]u64 {
    var limbs: [4]u64 = undefined;
    inline for (0..4) |index| {
        limbs[index] = std.mem.readInt(
            u64,
            bytes[index * 8 ..][0..8],
            .little,
        );
    }
    return limbs;
}

fn adxEncodeField(limbs: [4]u64) [32]u8 {
    var bytes: [32]u8 = undefined;
    inline for (0..4) |index| {
        std.mem.writeInt(
            u64,
            bytes[index * 8 ..][0..8],
            limbs[index],
            .little,
        );
    }
    return bytes;
}

fn expectSparseWnafMatches(comptime width: usize, scalar: [32]u8) !void {
    const dense = adxWnafDigits(width, scalar);
    const sparse = adxWnafSparse(width, scalar);
    var expanded = [_]i16{0} ** one_shot_wnaf_digits;
    for (sparse.entries[0..sparse.len]) |entry| {
        try std.testing.expectEqual(
            @as(i16, 0),
            expanded[entry.position],
        );
        expanded[entry.position] = entry.digit;
    }
    try std.testing.expectEqual(dense, expanded);
}

test "Ed25519 sparse wNAF matches dense recoding" {
    try expectSparseWnafMatches(one_shot_base_width, [_]u8{0} ** 32);
    var maximum_scalar: [32]u8 = undefined;
    std.mem.writeInt(
        u256,
        &maximum_scalar,
        Curve.scalar.field_order - 1,
        .little,
    );
    try expectSparseWnafMatches(one_shot_public_width, maximum_scalar);

    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..512) |_| {
        var scalar: [32]u8 = undefined;
        fillDeterministic(&scalar, &state);
        scalar = Curve.scalar.reduce(scalar);
        try expectSparseWnafMatches(one_shot_base_width, scalar);
        try expectSparseWnafMatches(one_shot_public_width, scalar);
    }
}

test "Ed25519 RFC 8032 empty-message vector" {
    var seed: [StdEd25519.KeyPair.seed_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &seed,
        "9d61b19deffd5a60ba844af492ec2cc4" ++
            "4449c5697b326919703bac031cae7f60",
    );
    const key_pair = try generateKeyPairDeterministic(seed);

    var expected_public: [StdEd25519.PublicKey.encoded_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_public,
        "d75a980182b10ab7d54bfed3c964073a" ++
            "0ee172f3daa62325af021a68f707511a",
    );
    try std.testing.expectEqual(
        expected_public,
        key_pair.public_key.toBytes(),
    );

    var expected_signature: [StdEd25519.Signature.encoded_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_signature,
        "e5564300c360ac729086e2cc806e828a" ++
            "84877f1eb8e5d974d873e06522490155" ++
            "5fb8821590a33bacc61e39701cf9b46b" ++
            "d25bf5f0595bbe24655141438e7a100b",
    );
    const signature = try sign(key_pair, "", null);
    try std.testing.expectEqual(expected_signature, signature.toBytes());
}

test "Ed25519 public-key recovery and signing match Zig std" {
    const messages = [_][]const u8{
        "",
        "a",
        "Vail fixed-base Ed25519",
        "a message spanning more than one SHA-512 compression block" ** 3,
    };
    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..64) |_| {
        var seed: [StdEd25519.KeyPair.seed_length]u8 = undefined;
        fillDeterministic(&seed, &state);
        const expected_key_pair = try StdEd25519.KeyPair
            .generateDeterministic(seed);
        const actual_key_pair = try generateKeyPairDeterministic(seed);
        var prepared_signer = try PreparedSigner.init(actual_key_pair);
        defer prepared_signer.deinit();
        try std.testing.expectEqual(
            expected_key_pair.public_key.toBytes(),
            actual_key_pair.public_key.toBytes(),
        );
        try std.testing.expectEqual(
            expected_key_pair.secret_key.toBytes(),
            actual_key_pair.secret_key.toBytes(),
        );
        const prepared = try PreparedVerifier.init(actual_key_pair.public_key);
        for (messages) |message| {
            const expected = try expected_key_pair.sign(message, null);
            const actual = try sign(actual_key_pair, message, null);
            const prepared_signature = try prepared_signer.sign(message, null);
            try std.testing.expectEqual(expected.toBytes(), actual.toBytes());
            try std.testing.expectEqual(
                expected.toBytes(),
                prepared_signature.toBytes(),
            );
            try actual.verify(message, actual_key_pair.public_key);
            try verify(actual, message, actual_key_pair.public_key);
            try prepared.verify(actual, message);
        }
    }
}

test "Ed25519 signing preserves noise and key mismatch behavior" {
    const seed = [_]u8{0x42} ** StdEd25519.KeyPair.seed_length;
    const key_pair = try generateKeyPairDeterministic(seed);
    const noise = [_]u8{0x69} ** StdEd25519.noise_length;
    const expected = try key_pair.sign("message", noise);
    const actual = try sign(key_pair, "message", noise);
    try std.testing.expectEqual(expected.toBytes(), actual.toBytes());
    var prepared_signer = try PreparedSigner.init(key_pair);
    defer prepared_signer.deinit();
    const prepared_signature = try prepared_signer.sign("message", noise);
    try std.testing.expectEqual(expected.toBytes(), prepared_signature.toBytes());

    var mismatched = key_pair;
    mismatched.public_key = (try StdEd25519.KeyPair.generateDeterministic(
        [_]u8{0x24} ** StdEd25519.KeyPair.seed_length,
    )).public_key;
    try std.testing.expectError(
        error.KeyMismatch,
        sign(mismatched, "message", null),
    );
    try std.testing.expectError(
        error.KeyMismatch,
        PreparedSigner.init(mismatched),
    );

    const prepared = try PreparedVerifier.init(key_pair.public_key);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verify(actual, "altered message", key_pair.public_key),
    );
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        prepared.verify(actual, "altered message"),
    );

    var non_canonical = actual.toBytes();
    @memset(non_canonical[32..], 0xff);
    try std.testing.expectError(
        error.NonCanonical,
        prepared.verify(StdEd25519.Signature.fromBytes(non_canonical), "message"),
    );

    var identity_bytes = [_]u8{0} ** StdEd25519.PublicKey.encoded_length;
    identity_bytes[0] = 1;
    try std.testing.expectError(
        error.IdentityElement,
        PreparedVerifier.init(try StdEd25519.PublicKey.fromBytes(identity_bytes)),
    );
}

test "Ed25519 prepared verifier has a bounded caller-owned footprint" {
    try std.testing.expectEqual(@as(usize, 320), @sizeOf(PreparedSigner));
    try std.testing.expectEqual(
        @as(usize, 15_392),
        @sizeOf(PreparedVerifier),
    );
}

test "Ed25519 prepared verifier classifies non-identity low-order keys" {
    var order_two = [_]u8{0xff} ** StdEd25519.PublicKey.encoded_length;
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    try std.testing.expectError(
        error.WeakPublicKey,
        PreparedVerifier.init(try StdEd25519.PublicKey.fromBytes(order_two)),
    );
}

test "Ed25519 ADX projective-only doubling matches full doubling" {
    if (comptime !point_adx.enabled) return error.SkipZigTest;
    var state: u64 = 0xa409_3822_299f_31d0;
    for (0..64) |_| {
        var seed: [StdEd25519.KeyPair.seed_length]u8 = undefined;
        fillDeterministic(&seed, &state);
        const key_pair = try generateKeyPairDeterministic(seed);
        var affine: [8]u64 = undefined;
        const public_key_bytes = key_pair.public_key.toBytes();
        try std.testing.expect(decode_adx.decode(&affine, &public_key_bytes));
        const projective_input = adxProjectiveFromAffine(affine);

        var full: AdxPoint = undefined;
        point_adx.pointDouble(&full, &projective_input);
        var projective = [_]u64{0xa5a5_a5a5_a5a5_a5a5} ** 16;
        point_adx.pointDoubleProjective(&projective, &projective_input);
        try std.testing.expectEqual(full[0..12].*, projective[0..12].*);
        try std.testing.expectEqual(
            [_]u64{0xa5a5_a5a5_a5a5_a5a5} ** 4,
            projective[12..16].*,
        );

        inline for (0..2) |_| {
            var full_next: AdxPoint = undefined;
            point_adx.pointDouble(&full_next, @ptrCast(&full));
            var projective_next =
                [_]u64{0xa5a5_a5a5_a5a5_a5a5} ** 16;
            point_adx.pointDoubleProjective(
                &projective_next,
                @ptrCast(&projective),
            );
            try std.testing.expectEqual(
                full_next[0..12].*,
                projective_next[0..12].*,
            );
            try std.testing.expectEqual(
                [_]u64{0xa5a5_a5a5_a5a5_a5a5} ** 4,
                projective_next[12..16].*,
            );
            full = full_next;
            projective = projective_next;
        }

        var full_after_projective: AdxPoint = undefined;
        point_adx.pointDouble(&full_after_projective, @ptrCast(&projective));
        point_adx.pointDouble(&full, @ptrCast(&full));
        try std.testing.expectEqual(full, full_after_projective);
    }
}

test "Ed25519 ADX fixed-base verification table matches Zig std" {
    if (comptime !point_adx.enabled) return error.SkipZigTest;
    const indices = [_]usize{ 0, 1, 2, 31, 255, 1023 };
    for (indices) |index| {
        var scalar = [_]u8{0} ** 32;
        std.mem.writeInt(u16, scalar[0..2], @intCast(2 * index + 1), .little);
        const point = try Curve.basePoint.mulPublic(scalar);
        const inverse = point.z.invert();
        const x = point.x.mul(inverse);
        const y = point.y.mul(inverse);
        const expected = [3]Fe{
            y.sub(x),
            y.add(x),
            x.mul(y).mul(Fe.edwards25519d2),
        };
        inline for (0..expected.len) |coordinate| {
            try std.testing.expect(expected[coordinate].equivalent(
                Fe.fromBytes(adxEncodeField(
                    verify_table.base_wnaf_12[index][coordinate * 4 ..][0..4].*,
                )),
            ));
        }
    }
}

test "Ed25519 one-shot verifier preserves scalar and point rejection" {
    const key_pair = try generateKeyPairDeterministic(
        [_]u8{0x53} ** StdEd25519.KeyPair.seed_length,
    );
    const message = "Ed25519 one-shot rejection behavior";
    const signature = try sign(key_pair, message, null);

    var non_canonical_s = signature.toBytes();
    @memset(non_canonical_s[32..], 0xff);
    try std.testing.expectError(
        error.NonCanonical,
        verify(
            StdEd25519.Signature.fromBytes(non_canonical_s),
            message,
            key_pair.public_key,
        ),
    );

    var non_canonical_r = signature.toBytes();
    @memset(non_canonical_r[0..32], 0xff);
    try std.testing.expectError(
        error.NonCanonical,
        verify(
            StdEd25519.Signature.fromBytes(non_canonical_r),
            message,
            key_pair.public_key,
        ),
    );

    var identity_bytes = [_]u8{0} ** StdEd25519.PublicKey.encoded_length;
    identity_bytes[0] = 1;
    const identity_key = try StdEd25519.PublicKey.fromBytes(identity_bytes);
    try std.testing.expectError(
        error.IdentityElement,
        verify(signature, message, identity_key),
    );

    const order_four_positive = [_]u8{0} ** StdEd25519.PublicKey.encoded_length;
    var order_four_negative = order_four_positive;
    order_four_negative[31] = 0x80;
    var order_two = [_]u8{0xff} ** StdEd25519.PublicKey.encoded_length;
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    var order_eight_first: [StdEd25519.PublicKey.encoded_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &order_eight_first,
        "26e8958fc2b227b045c3f489f2ef98f0" ++
            "d5dfac05d3c63339b13802886d53fc05",
    );
    var order_eight_first_negative = order_eight_first;
    order_eight_first_negative[31] ^= 0x80;
    var order_eight_second: [StdEd25519.PublicKey.encoded_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &order_eight_second,
        "c7176a703d4dd84fba3c0b760d10670f" ++
            "2a2053fa2c39ccc64ec7fd7792ac037a",
    );
    var order_eight_second_negative = order_eight_second;
    order_eight_second_negative[31] ^= 0x80;
    const weak_keys = [_][StdEd25519.PublicKey.encoded_length]u8{
        order_four_positive,
        order_four_negative,
        order_two,
        order_eight_first,
        order_eight_first_negative,
        order_eight_second,
        order_eight_second_negative,
    };
    for (weak_keys) |weak_key_bytes| {
        const weak_key = try StdEd25519.PublicKey.fromBytes(weak_key_bytes);
        try std.testing.expectError(
            error.WeakPublicKey,
            verify(signature, message, weak_key),
        );
    }
}

test "Ed25519 one-shot verifier preserves cofactored mixed-torsion semantics" {
    const key_pair = try generateKeyPairDeterministic(
        [_]u8{0xa7} ** StdEd25519.KeyPair.seed_length,
    );
    var order_two_encoding = [_]u8{0xff} ** Curve.encoded_length;
    order_two_encoding[0] = 0xec;
    order_two_encoding[31] = 0x7f;
    const order_two = try Curve.fromBytes(order_two_encoding);
    const original = try Curve.fromBytes(key_pair.public_key.toBytes());
    const mixed_bytes = original.add(order_two).toBytes();
    const mixed_public_key = try StdEd25519.PublicKey.fromBytes(mixed_bytes);

    var prepared = try PreparedSigner.init(key_pair);
    defer prepared.deinit();
    const messages = [_][]const u8{ "a", "b", "c", "d" };
    var observed_strict_rejection = false;
    for (messages) |message| {
        var nonce_hasher = sha512.initWithPrefix32(&prepared.prefix);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&nonce_hasher));
        const signature = try signWithNonceHasher(
            &prepared.scalar,
            mixed_bytes,
            message,
            &nonce_hasher,
        );
        try signature.verify(message, mixed_public_key);
        try verify(signature, message, mixed_public_key);
        signature.verifyStrict(message, mixed_public_key) catch |err| switch (err) {
            error.SignatureVerificationFailed => {
                observed_strict_rejection = true;
                break;
            },
            else => return err,
        };
    }
    try std.testing.expect(observed_strict_rejection);
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
