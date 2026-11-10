//! Allocation-free ECDSA signing and verification over NIST P-521.
//!
//! Verification uses variable-time joint scalar multiplication because all of
//! its inputs are public. Private-key operations use a separate fixed-base
//! comb with branchless Jacobian formulas, full-table selection, fixed-pass
//! field reduction, and constant-time scalar Montgomery arithmetic.

const std = @import("std");
const builtin = @import("builtin");
const FastSha512 = @import("../hash/sha512.zig").Sha512;
const field_inv_x86 = @import("p521_field_inv_x86.zig");
const field_mul_x86 = @import("p521_field_mul_x86.zig");
const scalar_inv_x86 = @import("p384_scalar_inv_x86.zig");
const scalar_mul_x86 = @import("p521_scalar_mul_x86.zig");

const field = @import("p521_field.zig");
const limb_count = field.limb_count;
const encoded_length = field.encoded_length;
const Limbs = field.Limbs;
const FieldLimbs = field.FieldLimbs;
const field_radix_bits = field.field_radix_bits;
const field_mask = field.field_mask;
const field_top_mask = field.field_top_mask;
const field_modulus_hex = field.field_modulus_hex;
const field_modulus = field.field_modulus;
const field_modulus_binary = field.field_modulus_binary;
const inversion_window_width = field.inversion_window_width;
const inversion_leading_ones = field.inversion_leading_ones;
const inversion_tail_bits = field.inversion_tail_bits;
const InversionStep = field.InversionStep;
const InversionSchedule = field.InversionSchedule;
const inversion_schedule = field.inversion_schedule;
const Fe = field.Fe;
const powTwoMinusOne = field.powTwoMinusOne;
const SecretFe = field.SecretFe;
const FieldSubResult = field.FieldSubResult;
const fieldSubWithBorrow = field.fieldSubWithBorrow;
const fieldMul = field.fieldMul;
const FieldSquareTerm = field.FieldSquareTerm;
const field_square_schedule = field.field_square_schedule;
const fieldReduceFolded = field.fieldReduceFolded;
const fieldReduce = field.fieldReduce;
const fieldAddSecret = field.fieldAddSecret;
const fieldSubSecret = field.fieldSubSecret;
const fieldMulSmallSecret = field.fieldMulSmallSecret;
const fieldMulSecret = field.fieldMulSecret;
const fieldReduceFoldedSecret = field.fieldReduceFoldedSecret;
const fieldReduceSecret = field.fieldReduceSecret;
const fieldFoldSecret = field.fieldFoldSecret;
const selectFieldLimbs = field.selectFieldLimbs;
const fieldLessThan = field.fieldLessThan;
const fieldEqual = field.fieldEqual;
const decodeField = field.decodeField;
const fieldLimbsFromLimbs = field.fieldLimbsFromLimbs;
const limbsFromFieldLimbs = field.limbsFromFieldLimbs;
const invertFieldX86 = field.invertFieldX86;
const encodeField = field.encodeField;
const encodeScalar = field.encodeScalar;
const AddResult = field.AddResult;
const SubResult = field.SubResult;
const addRaw = field.addRaw;
const subRaw = field.subRaw;
const subSmall = field.subSmall;
const shiftRightOne = field.shiftRightOne;
const trailingZeroBits = field.trailingZeroBits;
const shiftRightBits = field.shiftRightBits;
const dividePowerOfTwoModulo = field.dividePowerOfTwoModulo;
const halfModulo = field.halfModulo;
const subModulo = field.subModulo;
const lessThan = field.lessThan;
const equal = field.equal;
const limbsZero = field.limbsZero;
const bit = field.bit;
const buildInversionSchedule = field.buildInversionSchedule;
const one = field.one;
const decode = field.decode;
const limbsFromHex = field.limbsFromHex;
const scalar_modulus = field.scalar_modulus;
const fieldAdd = field.fieldAdd;
const fieldMulSmall = field.fieldMulSmall;
const fieldSub = field.fieldSub;
const fieldSubRaw = field.fieldSubRaw;
const fieldLimbsFromHex = field.fieldLimbsFromHex;
const opaqueWord = field.opaqueWord;
const fieldSquare = field.fieldSquare;
const fieldSquareSecret = field.fieldSquareSecret;

comptime {
    @setEvalBranchQuota(10_000_000);
}

const base_wnaf_width = 12;
const base_wnaf_table_entries = 1 << (base_wnaf_width - 2);
const prepared_wnaf_width = 10;
const prepared_wnaf_table_entries = 1 << (prepared_wnaf_width - 2);
const throughput_wnaf_width = 14;
const throughput_wnaf_table_entries = 1 << (throughput_wnaf_width - 2);
const one_shot_wnaf_width = 6;
const one_shot_wnaf_table_entries = 1 << (one_shot_wnaf_width - 2);
const wnaf_digit_count = 522;
const secret_window_width = 6;
const secret_comb_tables = 4;
const secret_window_entries = 1 << secret_window_width;
const secret_window_count = 22;
const secret_selection_lanes = 8;
const SecretSelectionVector = @Vector(secret_selection_lanes, u64);
const ecdh_window_width = 3;
const ecdh_comb_tables = 4;

const WnafEntry = struct {
    position: u16,
    digit: i16,
};

fn Wnaf(comptime width: usize) type {
    return struct {
        entries: [(wnaf_digit_count + width - 1) / width]WnafEntry,
        len: usize,
    };
}
const ecdh_window_entries = 1 << ecdh_window_width;
const ecdh_window_count = 44;
const ecdh_selection_lanes = 4;
const EcdhSelectionVector = @Vector(ecdh_selection_lanes, u64);
const use_x86_64_adx_scalar = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

pub const Error = error{
    InvalidPublicKey,
    InvalidSignature,
};

pub const SigningError = error{
    InvalidSecretKey,
    InvalidNonce,
    NonceAlreadyUsed,
};
pub const GenerateError = SigningError || std.Io.RandomSecureError;
pub const KeyAgreementError = error{
    InvalidSecretKey,
    InvalidPublicKey,
    KeyAgreementFailed,
};

pub const compressed_sec1_encoded_length = 1 + encoded_length;
pub const uncompressed_sec1_encoded_length = 1 + 2 * encoded_length;
pub const secret_key_encoded_length = encoded_length;
pub const max_prepared_nonce_batch = 64;

/// Validate a compressed or uncompressed SEC1 P-521 public key.
pub fn validatePublicKey(public_key_sec1: []const u8) Error!void {
    _ = try PublicKey.fromSec1(public_key_sec1);
}

/// Recover the uncompressed SEC1 public key for a canonical non-zero scalar.
pub fn ecdhPublicKey(
    secret_key_bytes: [secret_key_encoded_length]u8,
) KeyAgreementError![uncompressed_sec1_encoded_length]u8 {
    var owned_secret = secret_key_bytes;
    defer std.crypto.secureZero(u8, &owned_secret);
    var scalar = Scalar.fromBytes(&owned_secret) catch
        return error.InvalidSecretKey;
    defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
    var secret_point = SecretPoint.mulBasePrepared(
        scalar.value,
        &secret_base_tables,
    );
    defer std.crypto.secureZero(SecretPoint, (&secret_point)[0..1]);
    const public_point = secret_point.toJacobian();
    return .{0x04} ++ encodeField(public_point.x.value) ++
        encodeField(public_point.y.value);
}

/// Canonical P-521 ECDH scalar retained for repeated agreements. The caller
/// owns this value and must wipe it with `deinit` when it is no longer needed.
pub const PreparedEcdhSecret = struct {
    scalar: Limbs,

    pub fn init(
        secret_key_bytes: [secret_key_encoded_length]u8,
    ) KeyAgreementError!PreparedEcdhSecret {
        var owned_secret = secret_key_bytes;
        defer std.crypto.secureZero(u8, &owned_secret);
        var scalar = Scalar.fromBytes(&owned_secret) catch
            return error.InvalidSecretKey;
        defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
        return .{ .scalar = scalar.value };
    }

    pub fn sharedSecret(
        self: *const PreparedEcdhSecret,
        peer_public_key_sec1: []const u8,
    ) KeyAgreementError![encoded_length]u8 {
        return ecdhSharedSecretWithScalar(&self.scalar, peer_public_key_sec1);
    }

    pub fn deinit(self: *PreparedEcdhSecret) void {
        std.crypto.secureZero(PreparedEcdhSecret, self[0..1]);
    }
};

/// Compute the SEC1 ECDH shared x-coordinate with a validated P-521 point.
/// Point-table construction depends only on the public peer key; multiplication
/// by the private scalar uses a one-shot-optimized full-table constant-time
/// comb.
pub fn ecdhSharedSecret(
    secret_key_bytes: [secret_key_encoded_length]u8,
    peer_public_key_sec1: []const u8,
) KeyAgreementError![encoded_length]u8 {
    var prepared = try PreparedEcdhSecret.init(secret_key_bytes);
    defer prepared.deinit();
    return prepared.sharedSecret(peer_public_key_sec1);
}

fn ecdhSharedSecretWithScalar(
    scalar: *const Limbs,
    peer_public_key_sec1: []const u8,
) KeyAgreementError![encoded_length]u8 {
    const peer = Point.fromSec1(peer_public_key_sec1) catch
        return error.InvalidPublicKey;
    if (comptime scalar_mul_x86.enabled) {
        var input = [_]u64{0} ** (3 * limb_count);
        input[0..limb_count].* = limbsFromFieldLimbs(peer.x.value);
        input[limb_count .. 2 * limb_count].* =
            limbsFromFieldLimbs(peer.y.value);
        input[2 * limb_count] = 1;
        var output: [3 * limb_count]u64 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&output));
        scalar_mul_x86.scalarMultCanonicalPoint(
            &output,
            scalar,
            &input,
        );
        var combined: u64 = 0;
        inline for (output[2 * limb_count ..]) |limb| combined |= limb;
        if (combined == 0) return error.KeyAgreementFailed;
        var z_inverse = field_inv_x86.invert(
            @ptrCast(output[2 * limb_count ..].ptr),
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&z_inverse));
        var z_inverse_squared: Limbs = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&z_inverse_squared));
        field_mul_x86.mul(
            &z_inverse_squared,
            &z_inverse,
            &z_inverse,
        );
        var shared_x: Limbs = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&shared_x));
        field_mul_x86.mul(
            &shared_x,
            @ptrCast(output[0..limb_count].ptr),
            &z_inverse_squared,
        );
        return encodeBinaryLimbs(&shared_x);
    }
    const tables = SecretPoint.prepareEcdhTables(peer);
    var shared_point = SecretPoint.mulEcdhPrepared(scalar.*, &tables);
    defer std.crypto.secureZero(SecretPoint, (&shared_point)[0..1]);
    if (shared_point.z.isZeroChoice() != 0) {
        return error.KeyAgreementFailed;
    }
    var shared_x = shared_point.toAffineX();
    defer std.crypto.secureZero(Fe, (&shared_x)[0..1]);
    return encodeField(shared_x.value);
}

fn encodeBinaryLimbs(value: *const Limbs) [encoded_length]u8 {
    var little = [_]u8{0} ** (limb_count * @sizeOf(u64));
    defer std.crypto.secureZero(u8, &little);
    inline for (0..limb_count) |index| {
        std.mem.writeInt(
            u64,
            little[index * 8 ..][0..8],
            value[index],
            .little,
        );
    }
    var encoded: [encoded_length]u8 = undefined;
    for (&encoded, 0..) |*byte, index| {
        byte.* = little[encoded_length - 1 - index];
    }
    return encoded;
}

const curve_b = fieldLimbsFromHex(
    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1" ++
        "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
);
const generator_x = fieldLimbsFromHex(
    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d" ++
        "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
);
const generator_y = fieldLimbsFromHex(
    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e" ++
        "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
);
const oid_id_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01";
const oid_secp521r1 = "\x2b\x81\x04\x00\x23";

/// Verify an ASN.1 DER ECDSA signature using an uncompressed or compressed
/// SEC1 P-521 public key and a supported Zig hash implementation.
pub fn verify(
    comptime Hash: type,
    message: []const u8,
    signature_der: []const u8,
    public_key_sec1: []const u8,
) Error!void {
    const public_key = try PublicKey.fromSec1(public_key_sec1);
    return public_key.verify(Hash, message, signature_der);
}

/// Validated P-521 public point without a precomputed multiplication table.
/// This small caller-owned form avoids repeated SEC1 decoding and curve
/// validation while retaining one-shot table construction per signature.
pub const PublicKey = struct {
    point: Point,

    pub fn fromSec1(public_key_sec1: []const u8) Error!PublicKey {
        return .{
            .point = Point.fromSec1(public_key_sec1) catch
                return error.InvalidPublicKey,
        };
    }

    pub fn verify(
        self: *const PublicKey,
        comptime Hash: type,
        message: []const u8,
        signature_der: []const u8,
    ) Error!void {
        const input = try verificationInput(Hash, message, signature_der);
        return verifyResult(
            input.expected_r,
            Point.mulAddBase(
                input.scalar_for_base,
                input.scalar_for_key,
                self.point,
            ),
        );
    }

    pub fn toUncompressedSec1(self: PublicKey) [uncompressed_sec1_encoded_length]u8 {
        std.debug.assert(self.point.z.equivalent(Fe.one_fe));
        return .{0x04} ++ encodeField(self.point.x.value) ++
            encodeField(self.point.y.value);
    }

    pub fn toCompressedSec1(self: PublicKey) [compressed_sec1_encoded_length]u8 {
        std.debug.assert(self.point.z.equivalent(Fe.one_fe));
        return .{@as(u8, if (self.point.y.isOdd()) 0x03 else 0x02)} ++
            encodeField(self.point.x.value);
    }
};

/// Canonical non-zero P-521 private scalar.
pub const SecretKey = struct {
    bytes: [secret_key_encoded_length]u8,

    pub fn fromBytes(
        bytes: [secret_key_encoded_length]u8,
    ) SigningError!SecretKey {
        _ = Scalar.fromBytes(&bytes) catch return error.InvalidSecretKey;
        return .{ .bytes = bytes };
    }

    pub fn toBytes(self: SecretKey) [secret_key_encoded_length]u8 {
        return self.bytes;
    }

    pub fn deinit(self: *SecretKey) void {
        std.crypto.secureZero(SecretKey, self[0..1]);
    }
};

/// One ECDSA nonce with its message-independent scalar inverse and `r`
/// component precomputed. This value is single-use: `signPrepared` consumes
/// and wipes it before processing the message.
pub const PreparedNonce = struct {
    inverse: SecretScalarMontgomery,
    r: Scalar,
    state: enum(u8) { consumed = 0, ready = 1 } = .ready,

    pub fn isReady(self: *const PreparedNonce) bool {
        return self.state == .ready;
    }

    pub fn deinit(self: *PreparedNonce) void {
        std.crypto.secureZero(PreparedNonce, self[0..1]);
    }
};

/// P-521 key pair backed entirely by fixed-width Zig arithmetic.
pub const KeyPair = struct {
    secret_key: SecretKey,
    private_scalar: SecretScalarMontgomery,
    public_key: PublicKey,
    base_tables: [secret_comb_tables]SecretBaseTable,

    pub fn generate(io: std.Io) GenerateError!KeyPair {
        var bytes: [secret_key_encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &bytes);
        while (true) {
            try io.randomSecure(&bytes);
            bytes[0] &= 1;
            var secret_key = SecretKey.fromBytes(bytes) catch continue;
            defer secret_key.deinit();
            return fromSecretKey(secret_key);
        }
    }

    pub fn fromSecretKey(secret_key: SecretKey) SigningError!KeyPair {
        var scalar = Scalar.fromBytes(&secret_key.bytes) catch
            return error.InvalidSecretKey;
        defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
        const base_tables = SecretPoint.prepareBaseTables();
        var secret_point = SecretPoint.mulBasePrepared(
            scalar.value,
            &base_tables,
        );
        defer std.crypto.secureZero(SecretPoint, (&secret_point)[0..1]);
        return .{
            .secret_key = secret_key,
            .private_scalar = SecretScalarMontgomery.fromScalar(scalar),
            .public_key = .{ .point = secret_point.toJacobian() },
            .base_tables = base_tables,
        };
    }

    pub fn fromDer(encoded: []const u8) SigningError!KeyPair {
        var parsed = try parsePrivateKeyDer(encoded);
        defer std.crypto.secureZero(u8, &parsed.secret_key);
        var secret_key = try SecretKey.fromBytes(parsed.secret_key);
        defer secret_key.deinit();
        var key_pair = try fromSecretKey(secret_key);
        errdefer key_pair.deinit();
        if (parsed.public_key) |encoded_public_key| {
            const parsed_public_key = PublicKey.fromSec1(encoded_public_key) catch
                return error.InvalidSecretKey;
            const expected = parsed_public_key.toUncompressedSec1();
            const actual = key_pair.public_key.toUncompressedSec1();
            if (!std.mem.eql(u8, &expected, &actual)) {
                return error.InvalidSecretKey;
            }
        }
        return key_pair;
    }

    /// Sign with a caller-supplied canonical, non-zero nonce. The nonce must be
    /// freshly generated for every distinct signature under this key.
    pub fn sign(
        self: *const KeyPair,
        comptime Hash: type,
        message: []const u8,
        nonce_bytes: *const [encoded_length]u8,
    ) SigningError!Signature {
        var prepared = try self.prepareNonce(nonce_bytes);
        defer prepared.deinit();
        return self.signPrepared(Hash, message, &prepared);
    }

    /// Perform the message-independent point multiplication and scalar
    /// inversion for a fresh nonce. The returned value must be consumed at
    /// most once, and must be wiped with `deinit` if it is not consumed.
    pub fn prepareNonce(
        self: *const KeyPair,
        nonce_bytes: *const [encoded_length]u8,
    ) SigningError!PreparedNonce {
        var nonce = Scalar.fromBytes(nonce_bytes) catch
            return error.InvalidNonce;
        defer std.crypto.secureZero(Scalar, (&nonce)[0..1]);
        const r = try self.nonceScalar(nonce);
        return .{
            .inverse = SecretScalarMontgomery.fromScalar(nonce).invert(),
            .r = r,
        };
    }

    /// Prepare several independent nonces with one field inversion and one
    /// scalar inversion. Output is committed only after every input is
    /// canonical and every `r` is nonzero. Existing ready values in `output`
    /// must be consumed or deinitialized by the caller before invoking this
    /// function.
    pub fn prepareNonceBatch(
        self: *const KeyPair,
        comptime count: usize,
        nonce_bytes: *const [count][encoded_length]u8,
        output: *[count]PreparedNonce,
    ) SigningError!void {
        comptime {
            if (count == 0 or count > max_prepared_nonce_batch) {
                @compileError("P-521 nonce batch size must be in 1...64");
            }
        }
        var nonces: [count]Scalar = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&nonces));
        var nonces_montgomery: [count]SecretScalarMontgomery = undefined;
        defer std.crypto.secureZero(
            u8,
            std.mem.asBytes(&nonces_montgomery),
        );
        var prefixes_montgomery: [count]SecretScalarMontgomery = undefined;
        defer std.crypto.secureZero(
            u8,
            std.mem.asBytes(&prefixes_montgomery),
        );
        var nonce_points: [count]SecretPoint = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&nonce_points));
        var r_values: [count]Scalar = undefined;
        for (nonce_bytes, 0..) |*encoded, index| {
            nonces[index] = Scalar.fromBytes(encoded) catch
                return error.InvalidNonce;
            for (nonces[0..index]) |previous| {
                if (equal(previous.value, nonces[index].value)) {
                    return error.InvalidNonce;
                }
            }
            nonce_points[index] = SecretPoint.mulBasePrepared(
                nonces[index].value,
                &self.base_tables,
            );
            nonces_montgomery[index] =
                SecretScalarMontgomery.fromScalar(nonces[index]);
            prefixes_montgomery[index] = if (index == 0)
                nonces_montgomery[index]
            else
                prefixes_montgomery[index - 1].mul(
                    nonces_montgomery[index],
                );
        }
        var affine_x = SecretPoint.batchToAffineX(count, &nonce_points);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&affine_x));
        for (affine_x, 0..) |x, index| {
            r_values[index] = try nonceScalarFromAffineX(x);
        }

        var inverse = prefixes_montgomery[count - 1].invert();
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&inverse)[0..1],
        );
        var prepared: [count]PreparedNonce = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&prepared));
        var index = count;
        while (index != 0) {
            index -= 1;
            const prefix = if (index == 0)
                SecretScalarMontgomery{ .value = scalar_montgomery_one }
            else
                prefixes_montgomery[index - 1];
            prepared[index] = .{
                .inverse = inverse.mul(prefix),
                .r = r_values[index],
            };
            inverse = inverse.mul(nonces_montgomery[index]);
        }
        output.* = prepared;
    }

    pub fn prepareRandomNonceBatch(
        self: *const KeyPair,
        comptime count: usize,
        io: std.Io,
        output: *[count]PreparedNonce,
    ) GenerateError!void {
        comptime {
            if (count == 0 or count > max_prepared_nonce_batch) {
                @compileError("P-521 nonce batch size must be in 1...64");
            }
        }
        var nonces: [count][secret_key_encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&nonces));
        while (true) {
            for (&nonces) |*nonce| {
                try io.randomSecure(nonce);
                nonce[0] &= 1;
            }
            self.prepareNonceBatch(count, &nonces, output) catch |err| switch (err) {
                error.InvalidNonce => continue,
                error.InvalidSecretKey,
                error.NonceAlreadyUsed,
                => return err,
            };
            return;
        }
    }

    fn nonceScalar(self: *const KeyPair, nonce: Scalar) SigningError!Scalar {
        var nonce_point = SecretPoint.mulBasePrepared(
            nonce.value,
            &self.base_tables,
        );
        defer std.crypto.secureZero(SecretPoint, (&nonce_point)[0..1]);
        var affine_x = nonce_point.toAffineX();
        defer std.crypto.secureZero(Fe, (&affine_x)[0..1]);
        return nonceScalarFromAffineX(affine_x);
    }

    pub fn prepareRandomNonce(
        self: *const KeyPair,
        io: std.Io,
    ) GenerateError!PreparedNonce {
        var nonce: [secret_key_encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &nonce);
        while (true) {
            try io.randomSecure(&nonce);
            nonce[0] &= 1;
            return self.prepareNonce(&nonce) catch |err| switch (err) {
                error.InvalidNonce => continue,
                error.InvalidSecretKey,
                error.NonceAlreadyUsed,
                => return err,
            };
        }
    }

    /// Sign using and irreversibly consume one prepared nonce.
    pub fn signPrepared(
        self: *const KeyPair,
        comptime Hash: type,
        message: []const u8,
        prepared: *PreparedNonce,
    ) SigningError!Signature {
        comptime {
            if (Hash.digest_length > encoded_length) {
                @compileError("P-521 ECDSA hash output exceeds the subgroup size");
            }
        }
        if (!prepared.isReady()) return error.NonceAlreadyUsed;
        var inverse = prepared.inverse;
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&inverse)[0..1],
        );
        const r = prepared.r;
        prepared.deinit();

        var digest: [Hash.digest_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        hashMessage(Hash, message, &digest);
        var digest_bytes = [_]u8{0} ** encoded_length;
        defer std.crypto.secureZero(u8, &digest_bytes);
        @memcpy(digest_bytes[encoded_length - digest.len ..], &digest);
        const z = scalarReduce(decode(&digest_bytes));
        const r_montgomery = SecretScalarMontgomery.fromScalar(r);
        var sum_montgomery = SecretScalarMontgomery.fromScalar(z).add(
            r_montgomery.mul(self.private_scalar),
        );
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&sum_montgomery)[0..1],
        );
        var s_montgomery = inverse.mul(sum_montgomery);
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&s_montgomery)[0..1],
        );
        const s = s_montgomery.toScalar();
        if (limbsZero(s.value)) return error.InvalidNonce;
        return .{ .r = r, .s = s };
    }

    pub fn deinit(self: *KeyPair) void {
        std.crypto.secureZero(
            SecretScalarMontgomery,
            (&self.private_scalar)[0..1],
        );
        self.secret_key.deinit();
    }
};

/// Parsed P-521 public key with its width-10 odd multiples retained for
/// workloads that verify multiple signatures under the same key. Width-12
/// generator multiples are compiled in. The value is caller-owned and contains
/// no secret material or heap allocation.
pub const PreparedVerifier = struct {
    key_multiples: [prepared_wnaf_table_entries]AffinePoint,

    pub fn init(public_key_sec1: []const u8) Error!PreparedVerifier {
        const public_key = Point.fromSec1(public_key_sec1) catch
            return error.InvalidPublicKey;
        return .{
            .key_multiples = Point.prepareWnafKeyAffine(
                prepared_wnaf_table_entries,
                public_key,
            ),
        };
    }

    pub fn verify(
        self: *const PreparedVerifier,
        comptime Hash: type,
        message: []const u8,
        signature_der: []const u8,
    ) Error!void {
        const input = try verificationInput(Hash, message, signature_der);
        return verifyResult(
            input.expected_r,
            Point.mulAddPreparedWnaf(
                base_wnaf_width,
                base_wnaf_table_entries,
                prepared_wnaf_width,
                prepared_wnaf_table_entries,
                input.scalar_for_base,
                input.scalar_for_key,
                &self.key_multiples,
                &base_prepared_wnaf_multiples,
            ),
        );
    }
};

/// Large-table verifier for long-lived keys and maximum verification
/// throughput. Its width-14 public-key table is caller-owned; the matching
/// generator table is compiled in. It contains no secret material or heap
/// allocation.
pub const ThroughputPreparedVerifier = struct {
    key_multiples: [throughput_wnaf_table_entries]AffinePoint,

    pub fn init(public_key_sec1: []const u8) Error!ThroughputPreparedVerifier {
        const public_key = Point.fromSec1(public_key_sec1) catch
            return error.InvalidPublicKey;
        return .{
            .key_multiples = Point.prepareWnafKeyAffine(
                throughput_wnaf_table_entries,
                public_key,
            ),
        };
    }

    pub fn verify(
        self: *const ThroughputPreparedVerifier,
        comptime Hash: type,
        message: []const u8,
        signature_der: []const u8,
    ) Error!void {
        const input = try verificationInput(Hash, message, signature_der);
        return verifyResult(
            input.expected_r,
            Point.mulAddPreparedWnaf(
                throughput_wnaf_width,
                throughput_wnaf_table_entries,
                throughput_wnaf_width,
                throughput_wnaf_table_entries,
                input.scalar_for_base,
                input.scalar_for_key,
                &self.key_multiples,
                &base_throughput_wnaf_multiples,
            ),
        );
    }
};

/// Compact width-6 cached-Jacobian verifier for short batches such as one
/// certificate plus its stapled OCSP response.
pub const CompactPreparedVerifier = struct {
    key_multiples: [one_shot_wnaf_table_entries]CachedPoint,

    pub fn init(public_key_sec1: []const u8) Error!CompactPreparedVerifier {
        const public_key = Point.fromSec1(public_key_sec1) catch
            return error.InvalidPublicKey;
        return .{
            .key_multiples = Point.precomputeOddCached(
                one_shot_wnaf_table_entries,
                public_key,
            ),
        };
    }

    pub fn verify(
        self: *const CompactPreparedVerifier,
        comptime Hash: type,
        message: []const u8,
        signature_der: []const u8,
    ) Error!void {
        const input = try verificationInput(Hash, message, signature_der);
        return verifyResult(
            input.expected_r,
            Point.mulAddPreparedCachedWnaf(
                input.scalar_for_base,
                input.scalar_for_key,
                &self.key_multiples,
            ),
        );
    }
};

const VerificationInput = struct {
    expected_r: Scalar,
    scalar_for_base: Limbs,
    scalar_for_key: Limbs,
};

inline fn verificationInput(
    comptime Hash: type,
    message: []const u8,
    signature_der: []const u8,
) Error!VerificationInput {
    comptime {
        if (Hash.digest_length > encoded_length) {
            @compileError("P-521 ECDSA hash output exceeds the subgroup size");
        }
    }
    const signature = try Signature.fromDer(signature_der);
    var digest: [Hash.digest_length]u8 = undefined;
    hashMessage(Hash, message, &digest);
    var digest_bytes = [_]u8{0} ** encoded_length;
    @memcpy(digest_bytes[encoded_length - digest.len ..], &digest);
    const z = Scalar{ .value = decode(&digest_bytes) };
    const inverse = signature.s.invert();
    return .{
        .expected_r = signature.r,
        .scalar_for_base = z.mul(inverse).value,
        .scalar_for_key = signature.r.mul(inverse).value,
    };
}

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

inline fn verifyResult(expected_r: Scalar, result: Point) Error!void {
    if (result.isIdentity()) return error.InvalidSignature;

    // ECDSA accepts x mod n == r. Since the P-521 field prime p is smaller
    // than 2n, the canonical affine x is either r or r + n. Compare both
    // candidates directly in Jacobian coordinates (X == x * Z^2), avoiding
    // a field inversion at the end of every verification.
    const z_squared = result.z.sq();
    const expected = Fe.fromCanonicalLimbs(expected_r.value);
    if (result.x.equivalent(expected.mul(z_squared))) return;

    const expected_plus_order = addRaw(expected_r.value, scalar_modulus);
    if (expected_plus_order.carry == 0 and
        lessThan(expected_plus_order.value, field_modulus_binary))
    {
        const lifted_candidate = Fe.fromCanonicalLimbs(
            expected_plus_order.value,
        );
        if (result.x.equivalent(lifted_candidate.mul(z_squared))) return;
    }
    return error.InvalidSignature;
}

pub const Signature = struct {
    r: Scalar,
    s: Scalar,

    pub const encoded_length = 2 * secret_key_encoded_length;
    pub const der_encoded_length_max =
        2 * secret_key_encoded_length + 2 * 4 + 1;

    pub fn toBytes(self: Signature) [Signature.encoded_length]u8 {
        return encodeScalar(self.r.value) ++ encodeScalar(self.s.value);
    }

    pub fn fromBytes(bytes: [Signature.encoded_length]u8) Error!Signature {
        return .{
            .r = Scalar.fromBytes(bytes[0..secret_key_encoded_length]) catch
                return error.InvalidSignature,
            .s = Scalar.fromBytes(bytes[secret_key_encoded_length..]) catch
                return error.InvalidSignature,
        };
    }

    pub fn toDer(
        self: Signature,
        output: *[der_encoded_length_max]u8,
    ) []u8 {
        const r_bytes = encodeScalar(self.r.value);
        const s_bytes = encodeScalar(self.s.value);
        const r_start = scalarDerStart(&r_bytes);
        const s_start = scalarDerStart(&s_bytes);
        const r_prefix: usize = @intFromBool((r_bytes[r_start] & 0x80) != 0);
        const s_prefix: usize = @intFromBool((s_bytes[s_start] & 0x80) != 0);
        const r_len = r_bytes.len - r_start + r_prefix;
        const s_len = s_bytes.len - s_start + s_prefix;
        const content_len = 2 + r_len + 2 + s_len;
        var offset: usize = 0;
        output[offset] = 0x30;
        offset += 1;
        if (content_len < 128) {
            output[offset] = @intCast(content_len);
            offset += 1;
        } else {
            output[offset] = 0x81;
            output[offset + 1] = @intCast(content_len);
            offset += 2;
        }
        offset = writeDerScalar(output, offset, r_bytes[r_start..], r_prefix);
        offset = writeDerScalar(output, offset, s_bytes[s_start..], s_prefix);
        return output[0..offset];
    }

    pub fn fromDer(encoded: []const u8) Error!Signature {
        var outer = DerReader{ .bytes = encoded };
        const sequence = outer.require(0x30) catch
            return error.InvalidSignature;
        if (!outer.done()) return error.InvalidSignature;
        var fields = DerReader{ .bytes = sequence };
        const r = try parseScalarInteger(&fields);
        const s = try parseScalarInteger(&fields);
        if (!fields.done()) return error.InvalidSignature;
        return .{ .r = r, .s = s };
    }

    fn scalarDerStart(bytes: *const [secret_key_encoded_length]u8) usize {
        var start: usize = 0;
        while (start + 1 < bytes.len and bytes[start] == 0) : (start += 1) {}
        return start;
    }

    fn writeDerScalar(
        output: *[der_encoded_length_max]u8,
        start: usize,
        bytes: []const u8,
        prefix: usize,
    ) usize {
        var offset = start;
        output[offset] = 0x02;
        output[offset + 1] = @intCast(bytes.len + prefix);
        offset += 2;
        if (prefix != 0) {
            output[offset] = 0;
            offset += 1;
        }
        @memcpy(output[offset..][0..bytes.len], bytes);
        return offset + bytes.len;
    }
};

fn parseScalarInteger(reader: *DerReader) Error!Scalar {
    var encoded = reader.require(0x02) catch
        return error.InvalidSignature;
    if (encoded.len == 0 or (encoded[0] & 0x80) != 0) {
        return error.InvalidSignature;
    }
    if (encoded[0] == 0) {
        if (encoded.len == 1 or (encoded[1] & 0x80) == 0) {
            return error.InvalidSignature;
        }
        encoded = encoded[1..];
    }
    return Scalar.fromBytes(encoded) catch error.InvalidSignature;
}

const Scalar = struct {
    value: Limbs,

    fn fromBytes(encoded: []const u8) !Scalar {
        if (encoded.len == 0 or encoded.len > encoded_length) {
            return error.NonCanonical;
        }
        const value = decode(encoded);
        if (limbsZero(value) or !lessThan(value, scalar_modulus)) {
            return error.NonCanonical;
        }
        return .{ .value = value };
    }

    fn mul(a: Scalar, b: Scalar) Scalar {
        const a_montgomery = scalar_montgomery.toMontgomery(a.value);
        const b_montgomery = scalar_montgomery.toMontgomery(b.value);
        return .{ .value = scalar_montgomery.fromMontgomery(
            scalar_montgomery.mul(a_montgomery, b_montgomery),
        ) };
    }

    fn mulSecret(a: Scalar, b: Scalar) Scalar {
        const a_montgomery = scalar_montgomery.toMontgomerySecret(a.value);
        const b_montgomery = scalar_montgomery.toMontgomerySecret(b.value);
        return .{ .value = scalar_montgomery.fromMontgomerySecret(
            scalar_montgomery.mulSecret(a_montgomery, b_montgomery),
        ) };
    }

    fn addSecret(a: Scalar, b: Scalar) Scalar {
        return .{ .value = scalarAddSecret(a.value, b.value) };
    }

    fn invertSecret(self: Scalar) Scalar {
        return SecretScalarMontgomery.fromScalar(self).invert().toScalar();
    }

    fn invert(self: Scalar) Scalar {
        // Binary extended GCD is variable-time, which is safe here because an
        // ECDSA signature's s value is public. It is substantially cheaper
        // than exponentiating to n-2 with generic Montgomery products.
        var first = self.value;
        var second = scalar_modulus;
        var first_coefficient = one();
        var second_coefficient = [_]u64{0} ** limb_count;
        while (!equal(first, one()) and !equal(second, one())) {
            if ((first[0] & 1) == 0) {
                const first_shift = trailingZeroBits(first);
                first = shiftRightBits(first, first_shift);
                first_coefficient = dividePowerOfTwoModulo(
                    first_coefficient,
                    first_shift,
                    scalar_modulus,
                    scalar_montgomery.negative_inverse,
                );
            }
            if ((second[0] & 1) == 0) {
                const second_shift = trailingZeroBits(second);
                second = shiftRightBits(second, second_shift);
                second_coefficient = dividePowerOfTwoModulo(
                    second_coefficient,
                    second_shift,
                    scalar_modulus,
                    scalar_montgomery.negative_inverse,
                );
            }
            if (!lessThan(first, second)) {
                first = subRaw(first, second).value;
                first_coefficient = subModulo(
                    first_coefficient,
                    second_coefficient,
                    scalar_modulus,
                );
            } else {
                second = subRaw(second, first).value;
                second_coefficient = subModulo(
                    second_coefficient,
                    first_coefficient,
                    scalar_modulus,
                );
            }
        }
        return .{ .value = if (equal(first, one()))
            first_coefficient
        else
            second_coefficient };
    }
};

const SecretScalarMontgomery = struct {
    value: Limbs,

    fn fromScalar(scalar: Scalar) SecretScalarMontgomery {
        return .{
            .value = scalar_montgomery.toMontgomerySecret(scalar.value),
        };
    }

    fn toScalar(self: SecretScalarMontgomery) Scalar {
        return .{
            .value = scalar_montgomery.fromMontgomerySecret(self.value),
        };
    }

    fn add(
        first: SecretScalarMontgomery,
        second: SecretScalarMontgomery,
    ) SecretScalarMontgomery {
        return .{ .value = scalarAddSecret(first.value, second.value) };
    }

    fn mul(
        first: SecretScalarMontgomery,
        second: SecretScalarMontgomery,
    ) SecretScalarMontgomery {
        return .{
            .value = scalar_montgomery.mulSecret(first.value, second.value),
        };
    }

    fn invert(self: SecretScalarMontgomery) SecretScalarMontgomery {
        if (comptime scalar_inv_x86.enabled) {
            var normal = scalar_montgomery.fromMontgomerySecret(self.value);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&normal));
            var inverse = scalar_inv_x86.invertLimbs(
                limb_count,
                &normal,
                &scalar_modulus,
            );
            defer std.crypto.secureZero(u8, std.mem.asBytes(&inverse));
            return .{ .value = scalar_montgomery.toMontgomerySecret(inverse) };
        }
        return self.invertPortable();
    }

    fn invertPortable(self: SecretScalarMontgomery) SecretScalarMontgomery {
        const base = self.value;
        var table: [16]Limbs = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&table));
        table[0] = base;
        const base_squared = scalar_montgomery.mulSecretPointers(&base, &base);
        for (1..table.len) |index| {
            table[index] = scalar_montgomery.mulSecretPointers(
                &table[index - 1],
                &base_squared,
            );
        }
        // n - 2 starts with 262 one-bits. Build that Mersenne exponent with
        // ten multiplies, then apply the sliding-window schedule only to the
        // remaining 259 bits instead of windowing the full exponent.
        var result = scalarPowTwoMinusOne(base, inversion_leading_ones);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
        for (inversion_schedule.steps[0..inversion_schedule.len]) |step| {
            for (0..step.squares) |_| {
                result = scalar_montgomery.mulSecretPointers(
                    &result,
                    &result,
                );
            }
            result = scalar_montgomery.mulSecretPointers(
                &result,
                &table[step.table_index],
            );
        }
        return .{ .value = result };
    }
};

fn scalarReduce(value: Limbs) Scalar {
    const reduced = subRaw(value, scalar_modulus);
    return .{ .value = selectLimbs(
        value,
        reduced.value,
        reduced.borrow ^ 1,
    ) };
}

const Point = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity = Point{ .x = Fe.zero, .y = Fe.one_fe, .z = Fe.zero };
    const base = Point{
        .x = .{ .value = generator_x },
        .y = .{ .value = generator_y },
        .z = Fe.one_fe,
    };

    fn fromSec1(encoded: []const u8) !Point {
        if (encoded.len == 1 + 2 * encoded_length and encoded[0] == 4) {
            const x = try Fe.fromBytes(encoded[1 .. 1 + encoded_length]);
            const y = try Fe.fromBytes(encoded[1 + encoded_length ..]);
            return fromAffine(x, y);
        }
        if (encoded.len == 1 + encoded_length and
            (encoded[0] == 2 or encoded[0] == 3))
        {
            const x = try Fe.fromBytes(encoded[1..]);
            const rhs = curveRhs(x);
            var y = try rhs.sqrt();
            const expected_odd = encoded[0] == 3;
            if (y.isOdd() != expected_odd) y = y.neg();
            return fromAffine(x, y);
        }
        return error.InvalidEncoding;
    }

    fn fromAffine(x: Fe, y: Fe) !Point {
        if (!y.sq().equivalent(curveRhs(x))) {
            return error.InvalidEncoding;
        }
        return .{ .x = x, .y = y, .z = Fe.one_fe };
    }

    fn isIdentity(self: Point) bool {
        return self.z.isZero();
    }

    fn dbl(self: Point) Point {
        var result = self;
        result.dblAssign();
        return result;
    }

    fn dblAssign(self: *Point) void {
        if (self.isIdentity()) {
            self.* = identity;
            return;
        }
        // The cofactor-one P-521 group has odd prime order, so a valid
        // non-identity point cannot have y = 0 (which would have order two).
        const delta = self.z.sq();
        const gamma = self.y.sq();
        const beta = self.x.mul(gamma);
        const alpha = self.x.sub(delta).mul(self.x.add(delta)).mulSmall(3);
        const x3 = alpha.sq().sub(beta.mulSmall(8));
        const z3 = self.y.add(self.z).sq().sub(gamma).sub(delta);
        const y3 = alpha.mul(beta.mulSmall(4).sub(x3)).sub(
            gamma.sq().mulSmall(8),
        );
        self.* = .{ .x = x3, .y = y3, .z = z3 };
    }

    fn add(self: Point, other: Point) Point {
        if (self.isIdentity()) return other;
        if (other.isIdentity()) return self;
        const z1z1 = self.z.sq();
        const z2z2 = other.z.sq();
        const first_x = self.x.mul(z2z2);
        const second_x = other.x.mul(z1z1);
        const s1 = self.y.mul(other.z).mul(z2z2);
        const s2 = other.y.mul(self.z).mul(z1z1);
        if (first_x.equivalent(second_x)) {
            if (!s1.equivalent(s2)) return identity;
            return self.dbl();
        }
        const h = second_x.sub(first_x);
        const i = h.dbl().sq();
        const j = h.mul(i);
        const r = s2.sub(s1).dbl();
        const v = first_x.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
        const z3 = self.z.add(other.z).sq().sub(z1z1).sub(z2z2).mul(h);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    fn addCached(
        self: Point,
        other: *const CachedPoint,
        negate_y: bool,
    ) Point {
        std.debug.assert(!other.identity);
        const other_y = if (negate_y) other.y.neg() else other.y;
        if (self.isIdentity()) {
            return .{ .x = other.x, .y = other_y, .z = other.z };
        }
        const z1z1 = self.z.sq();
        const first_x = self.x.mul(other.z_squared);
        const second_x = other.x.mul(z1z1);
        const s1 = self.y.mul(other.z_cubed);
        const s2 = other_y.mul(self.z).mul(z1z1);
        if (first_x.equivalent(second_x)) {
            if (!s1.equivalent(s2)) return identity;
            return self.dbl();
        }
        const h = second_x.sub(first_x);
        const i = h.dbl().sq();
        const j = h.mul(i);
        const r = s2.sub(s1).dbl();
        const v = first_x.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
        const z3 = self.z.add(other.z).sq().sub(z1z1).sub(
            other.z_squared,
        ).mul(h);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    fn addMixed(
        self: Point,
        other: *const AffinePoint,
        negate_y: bool,
    ) Point {
        std.debug.assert(!other.identity);
        const other_y = if (negate_y) other.y.neg() else other.y;
        if (self.isIdentity()) {
            return .{ .x = other.x, .y = other_y, .z = Fe.one_fe };
        }
        const z1z1 = self.z.sq();
        const second_x = other.x.mul(z1z1);
        const second_y = other_y.mul(self.z).mul(z1z1);
        if (self.x.equivalent(second_x)) {
            if (!self.y.equivalent(second_y)) return identity;
            return self.dbl();
        }
        const h = second_x.sub(self.x);
        const hh = h.sq();
        const i = hh.mulSmall(4);
        const j = h.mul(i);
        const r = second_y.sub(self.y).dbl();
        const v = self.x.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(self.y.mul(j).dbl());
        const z3 = self.z.add(h).sq().sub(z1z1).sub(hh);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    fn prepareWnafKeyAffine(
        comptime table_entries: usize,
        public_key: Point,
    ) [table_entries]AffinePoint {
        return batchToAffine(
            table_entries,
            precomputeOdd(table_entries, public_key),
        );
    }

    fn mulAddPreparedWnaf(
        comptime base_width: usize,
        comptime base_table_entries: usize,
        comptime key_width: usize,
        comptime key_table_entries: usize,
        scalar_for_base: Limbs,
        scalar_for_key: Limbs,
        key_multiples: *const [key_table_entries]AffinePoint,
        base_multiples: *const [base_table_entries]AffinePoint,
    ) Point {
        const base_wnaf = wnafSparse(base_width, scalar_for_base);
        const key_wnaf = wnafSparse(key_width, scalar_for_key);
        var result = identity;
        var base_index = base_wnaf.len;
        var key_index = key_wnaf.len;
        if (base_index == 0 and key_index == 0) return result;
        var position: usize = if (base_index == 0)
            key_wnaf.entries[key_index - 1].position
        else if (key_index == 0)
            base_wnaf.entries[base_index - 1].position
        else
            @max(
                base_wnaf.entries[base_index - 1].position,
                key_wnaf.entries[key_index - 1].position,
            );
        while (true) {
            if (base_index != 0 and
                base_wnaf.entries[base_index - 1].position == position)
            {
                base_index -= 1;
                const base_digit = base_wnaf.entries[base_index].digit;
                const magnitude: usize = @intCast(
                    if (base_digit < 0) -base_digit else base_digit,
                );
                std.debug.assert(magnitude <= 2 * base_multiples.len - 1);
                result = result.addMixed(
                    &base_multiples[(magnitude - 1) / 2],
                    base_digit < 0,
                );
            }
            if (key_index != 0 and
                key_wnaf.entries[key_index - 1].position == position)
            {
                key_index -= 1;
                const key_digit = key_wnaf.entries[key_index].digit;
                const magnitude: usize = @intCast(
                    if (key_digit < 0) -key_digit else key_digit,
                );
                std.debug.assert(magnitude <= 2 * key_multiples.len - 1);
                result = result.addMixed(
                    &key_multiples[(magnitude - 1) / 2],
                    key_digit < 0,
                );
            }
            if (position == 0) break;
            position -= 1;
            result.dblAssign();
        }
        return result;
    }

    fn mulAddPreparedCachedWnaf(
        scalar_for_base: Limbs,
        scalar_for_key: Limbs,
        key_multiples: *const [one_shot_wnaf_table_entries]CachedPoint,
    ) Point {
        const base_wnaf = wnafSparse(
            base_wnaf_width,
            scalar_for_base,
        );
        const key_wnaf = wnafSparse(
            one_shot_wnaf_width,
            scalar_for_key,
        );
        var result = identity;
        var base_index = base_wnaf.len;
        var key_index = key_wnaf.len;
        if (base_index == 0 and key_index == 0) return result;
        var position: usize = if (base_index == 0)
            key_wnaf.entries[key_index - 1].position
        else if (key_index == 0)
            base_wnaf.entries[base_index - 1].position
        else
            @max(
                base_wnaf.entries[base_index - 1].position,
                key_wnaf.entries[key_index - 1].position,
            );
        while (true) {
            if (base_index != 0 and
                base_wnaf.entries[base_index - 1].position == position)
            {
                base_index -= 1;
                const base_digit = base_wnaf.entries[base_index].digit;
                const magnitude: usize = @intCast(
                    if (base_digit < 0) -base_digit else base_digit,
                );
                std.debug.assert(
                    magnitude <= 2 * base_prepared_wnaf_multiples.len - 1,
                );
                result = result.addMixed(
                    &base_prepared_wnaf_multiples[(magnitude - 1) / 2],
                    base_digit < 0,
                );
            }
            if (key_index != 0 and
                key_wnaf.entries[key_index - 1].position == position)
            {
                key_index -= 1;
                const key_digit = key_wnaf.entries[key_index].digit;
                const magnitude: usize = @intCast(
                    if (key_digit < 0) -key_digit else key_digit,
                );
                std.debug.assert(magnitude <= 2 * key_multiples.len - 1);
                result = result.addCached(
                    &key_multiples[(magnitude - 1) / 2],
                    key_digit < 0,
                );
            }
            if (position == 0) break;
            position -= 1;
            result.dblAssign();
        }
        return result;
    }

    fn mulAddBase(
        scalar_for_base: Limbs,
        scalar_for_key: Limbs,
        public_key: Point,
    ) Point {
        const key_multiples = precomputeOddCached(
            one_shot_wnaf_table_entries,
            public_key,
        );
        return mulAddPreparedCachedWnaf(
            scalar_for_base,
            scalar_for_key,
            &key_multiples,
        );
    }

    fn precomputeOdd(
        comptime table_entries: usize,
        point: Point,
    ) [table_entries]Point {
        var multiples: [table_entries]Point = undefined;
        multiples[0] = point;
        const twice = point.dbl();
        for (1..multiples.len) |index| {
            multiples[index] = multiples[index - 1].add(twice);
        }
        return multiples;
    }

    fn precomputeOddCached(
        comptime table_entries: usize,
        point: Point,
    ) [table_entries]CachedPoint {
        var cached: [table_entries]CachedPoint = undefined;
        // SEC1 decoding and the built-in base point both produce affine
        // coordinates. Avoid recomputing the known Z, Z^2, and Z^3 values for
        // the first table entry.
        std.debug.assert(point.z.equivalent(Fe.one_fe));
        cached[0] = .{
            .x = point.x,
            .y = point.y,
            .z = Fe.one_fe,
            .z_squared = Fe.one_fe,
            .z_cubed = Fe.one_fe,
            .identity = false,
        };
        const twice = CachedPoint.init(point.dbl());
        for (1..table_entries) |index| {
            // The operands are (2 * index - 1)P and 2P. For the valid
            // non-identity P-521 points used here, the prime group order is
            // larger than every table coefficient, so they cannot be equal,
            // inverses, or identities.
            cached[index] = CachedPoint.init(
                CachedPoint.addDistinct(cached[index - 1], twice),
            );
        }
        return cached;
    }
};

const SecretAffinePoint = struct {
    x: SecretFe = SecretFe.zero,
    y: SecretFe = SecretFe.one_fe,
    identity: u1 = 1,
};

const SecretBaseTable = struct {
    x: [limb_count][secret_window_entries]u64,
    y: [limb_count][secret_window_entries]u64,
};

const SecretEcdhTable = struct {
    x: [limb_count][ecdh_window_entries]u64,
    y: [limb_count][ecdh_window_entries]u64,
};

/// Constant-schedule Jacobian formulas used only with secret scalars. Comb
/// digits select a public affine point by a full-table mask scan. The comb
/// construction keeps non-identity operands distinct, so the fast mixed-add
/// formula needs only branchless identity correction.
const SecretPoint = struct {
    x: SecretFe,
    y: SecretFe,
    z: SecretFe,

    const identity = SecretPoint{
        .x = SecretFe.zero,
        .y = SecretFe.one_fe,
        .z = SecretFe.zero,
    };
    const base = SecretPoint{
        .x = .{ .value = generator_x },
        .y = .{ .value = generator_y },
        .z = SecretFe.one_fe,
    };

    noinline fn dbl(point: SecretPoint) SecretPoint {
        const delta = point.z.sq();
        const gamma = point.y.sq();
        const beta = point.x.mul(gamma);
        const alpha = point.x.sub(delta).mul(
            point.x.add(delta),
        ).mulSmall(3);
        const x3 = alpha.sq().sub(beta.mulSmall(8));
        const z3 = point.y.mul(point.z).dbl();
        const y3 = alpha.mul(beta.mulSmall(4).sub(x3)).sub(
            gamma.sq().mulSmall(8),
        );
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    fn addMixed(first: SecretPoint, second: SecretAffinePoint) SecretPoint {
        const first_identity = first.z.isZeroChoice();
        const z_squared = first.z.sq();
        const second_x = second.x.mul(z_squared);
        const second_y = second.y.mul(first.z).mul(z_squared);
        const h = second_x.sub(first.x);
        const hh = h.sq();
        const i = hh.mulSmall(4);
        const j = h.mul(i);
        const r = second_y.sub(first.y).dbl();
        const v = first.x.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(first.y.mul(j).dbl());
        const z3 = first.z.mul(h).dbl();
        var result = SecretPoint{ .x = x3, .y = y3, .z = z3 };
        const second_projective = SecretPoint{
            .x = second.x,
            .y = second.y,
            .z = SecretFe.one_fe,
        };
        result.conditionalMove(
            second_projective,
            first_identity & (second.identity ^ 1),
        );
        result.conditionalMove(first, second.identity);
        return result;
    }

    fn conditionalMove(self: *SecretPoint, other: SecretPoint, choice: u1) void {
        const mask = opaqueWord(0 -% @as(u64, choice));
        inline for (0..limb_count) |limb| {
            self.x.value[limb] = (other.x.value[limb] & mask) |
                (self.x.value[limb] & ~mask);
            self.y.value[limb] = (other.y.value[limb] & mask) |
                (self.y.value[limb] & ~mask);
            self.z.value[limb] = (other.z.value[limb] & mask) |
                (self.z.value[limb] & ~mask);
        }
    }

    fn selectBase(
        table: *const SecretBaseTable,
        index: u6,
    ) SecretAffinePoint {
        const offsets = @Vector(secret_selection_lanes, u64){
            0, 1, 2, 3, 4, 5, 6, 7,
        };
        const zero: SecretSelectionVector = @splat(0);
        const ones: SecretSelectionVector = @splat(std.math.maxInt(u64));
        var selected_x = [_]SecretSelectionVector{zero} ** limb_count;
        var selected_y = [_]SecretSelectionVector{zero} ** limb_count;
        inline for (0..secret_window_entries / secret_selection_lanes) |chunk| {
            const candidate_indices = offsets +
                @as(SecretSelectionVector, @splat(
                    chunk * secret_selection_lanes,
                ));
            const matches = candidate_indices ==
                @as(SecretSelectionVector, @splat(index));
            const mask = @select(u64, matches, ones, zero);
            inline for (0..limb_count) |limb| {
                const start = chunk * secret_selection_lanes;
                const x: SecretSelectionVector =
                    table.x[limb][start..][0..secret_selection_lanes].*;
                const y: SecretSelectionVector =
                    table.y[limb][start..][0..secret_selection_lanes].*;
                selected_x[limb] |= x & mask;
                selected_y[limb] |= y & mask;
            }
        }
        var selected = SecretAffinePoint{
            .identity = @truncate(
                (@as(u7, index) -% 1) >> secret_window_width,
            ),
        };
        inline for (0..limb_count) |limb| {
            selected.x.value[limb] = @reduce(.Or, selected_x[limb]);
            selected.y.value[limb] = @reduce(.Or, selected_y[limb]);
        }
        return selected;
    }

    fn selectEcdhBase(
        table: *const SecretEcdhTable,
        index: u4,
    ) SecretAffinePoint {
        const offsets = @Vector(ecdh_selection_lanes, u64){ 0, 1, 2, 3 };
        const zero: EcdhSelectionVector = @splat(0);
        const ones: EcdhSelectionVector = @splat(std.math.maxInt(u64));
        var selected_x = [_]EcdhSelectionVector{zero} ** limb_count;
        var selected_y = [_]EcdhSelectionVector{zero} ** limb_count;
        inline for (0..ecdh_window_entries / ecdh_selection_lanes) |chunk| {
            const candidate_indices = offsets +
                @as(EcdhSelectionVector, @splat(
                    chunk * ecdh_selection_lanes,
                ));
            const matches = candidate_indices ==
                @as(EcdhSelectionVector, @splat(index));
            const mask = @select(u64, matches, ones, zero);
            inline for (0..limb_count) |limb| {
                const start = chunk * ecdh_selection_lanes;
                const x: EcdhSelectionVector =
                    table.x[limb][start..][0..ecdh_selection_lanes].*;
                const y: EcdhSelectionVector =
                    table.y[limb][start..][0..ecdh_selection_lanes].*;
                selected_x[limb] |= x & mask;
                selected_y[limb] |= y & mask;
            }
        }
        var selected = SecretAffinePoint{
            .identity = @truncate(
                (@as(u5, index) -% 1) >> ecdh_window_width,
            ),
        };
        inline for (0..limb_count) |limb| {
            selected.x.value[limb] = @reduce(.Or, selected_x[limb]);
            selected.y.value[limb] = @reduce(.Or, selected_y[limb]);
        }
        return selected;
    }

    fn prepareBaseTables() [secret_comb_tables]SecretBaseTable {
        return prepareTables(Point.base);
    }

    fn prepareTables(source_point: Point) [secret_comb_tables]SecretBaseTable {
        @setEvalBranchQuota(10_000_000);
        const column_count = secret_comb_tables * secret_window_width;
        const point_count = secret_comb_tables * secret_window_entries;
        var columns: [column_count]Point = undefined;
        columns[0] = source_point;
        inline for (1..column_count) |column| {
            var point = columns[column - 1];
            inline for (0..secret_window_count) |_| point = point.dbl();
            columns[column] = point;
        }
        var projective: [point_count]Point = undefined;
        inline for (0..secret_comb_tables) |group| {
            const offset = group * secret_window_entries;
            projective[offset] = Point.identity;
            projective[offset + 1] = columns[group * secret_window_width];
            for (2..secret_window_entries) |index| {
                const column: u3 = @intCast(@ctz(index));
                projective[offset + index] = projective[
                    offset + (index ^ (@as(usize, 1) << column))
                ].add(columns[group * secret_window_width + column]);
            }
        }
        const affine = batchToAffine(point_count, projective);
        var tables: [secret_comb_tables]SecretBaseTable = undefined;
        inline for (0..secret_comb_tables) |group| {
            inline for (0..secret_window_entries) |index| {
                const source = affine[group * secret_window_entries + index];
                inline for (0..limb_count) |limb| {
                    tables[group].x[limb][index] = source.x.value[limb];
                    tables[group].y[limb][index] = source.y.value[limb];
                }
            }
        }
        return tables;
    }

    fn prepareEcdhTables(source_point: Point) [ecdh_comb_tables]SecretEcdhTable {
        @setEvalBranchQuota(10_000_000);
        const column_count = ecdh_comb_tables * ecdh_window_width;
        const point_count = ecdh_comb_tables * ecdh_window_entries;
        var columns: [column_count]Point = undefined;
        columns[0] = source_point;
        inline for (1..column_count) |column| {
            var point = columns[column - 1];
            inline for (0..ecdh_window_count) |_| point = point.dbl();
            columns[column] = point;
        }
        var projective: [point_count]Point = undefined;
        inline for (0..ecdh_comb_tables) |group| {
            const offset = group * ecdh_window_entries;
            projective[offset] = Point.identity;
            projective[offset + 1] = columns[group * ecdh_window_width];
            for (2..ecdh_window_entries) |index| {
                const column: u2 = @intCast(@ctz(index));
                projective[offset + index] = projective[
                    offset + (index ^ (@as(usize, 1) << column))
                ].add(columns[group * ecdh_window_width + column]);
            }
        }
        const affine = batchToAffine(point_count, projective);
        var tables: [ecdh_comb_tables]SecretEcdhTable = undefined;
        inline for (0..ecdh_comb_tables) |group| {
            inline for (0..ecdh_window_entries) |index| {
                const source = affine[group * ecdh_window_entries + index];
                inline for (0..limb_count) |limb| {
                    tables[group].x[limb][index] = source.x.value[limb];
                    tables[group].y[limb][index] = source.y.value[limb];
                }
            }
        }
        return tables;
    }

    fn mulBasePrepared(
        scalar: Limbs,
        tables: *const [secret_comb_tables]SecretBaseTable,
    ) SecretPoint {
        var result = identity;
        var window: usize = secret_window_count;
        while (window != 0) {
            window -= 1;
            result = result.dbl();
            inline for (0..secret_comb_tables) |group| {
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
                result = result.addMixed(selectBase(&tables[group], digit));
            }
        }
        return result;
    }

    fn mulEcdhPrepared(
        scalar: Limbs,
        tables: *const [ecdh_comb_tables]SecretEcdhTable,
    ) SecretPoint {
        var result = identity;
        var window: usize = ecdh_window_count;
        while (window != 0) {
            window -= 1;
            result = result.dbl();
            inline for (0..ecdh_comb_tables) |group| {
                var digit: u4 = 0;
                inline for (0..ecdh_window_width) |column| {
                    const bit_index = window +
                        (group * ecdh_window_width + column) *
                            ecdh_window_count;
                    const scalar_bit: u1 = @truncate(
                        scalar[bit_index / 64] >> @intCast(bit_index % 64),
                    );
                    digit |= @as(u4, scalar_bit) << column;
                }
                result = result.addMixed(
                    selectEcdhBase(&tables[group], digit),
                );
            }
        }
        return result;
    }

    fn toJacobian(self: SecretPoint) Point {
        const z_inverse = self.z.invert();
        const z_squared = z_inverse.sq();
        return .{
            .x = self.x.mul(z_squared).canonical(),
            .y = self.y.mul(z_squared).mul(z_inverse).canonical(),
            .z = Fe.one_fe,
        };
    }

    fn toAffineX(self: SecretPoint) Fe {
        const z_inverse = self.z.invert();
        return self.x.mul(z_inverse.sq()).canonical();
    }

    fn batchToAffineX(
        comptime count: usize,
        points: *const [count]SecretPoint,
    ) [count]Fe {
        comptime std.debug.assert(count != 0);
        var prefixes: [count]SecretFe = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&prefixes));
        for (points, 0..) |point, index| {
            prefixes[index] = if (index == 0)
                point.z
            else
                prefixes[index - 1].mul(point.z);
        }

        var inverse = prefixes[count - 1].invert();
        defer std.crypto.secureZero(SecretFe, (&inverse)[0..1]);
        var result: [count]Fe = undefined;
        var index = count;
        while (index != 0) {
            index -= 1;
            const prefix = if (index == 0)
                SecretFe.one_fe
            else
                prefixes[index - 1];
            var point_inverse = inverse.mul(prefix);
            defer std.crypto.secureZero(SecretFe, (&point_inverse)[0..1]);
            result[index] = points[index].x.mul(point_inverse.sq()).canonical();
            inverse = inverse.mul(points[index].z);
        }
        return result;
    }
};

const secret_base_tables = SecretPoint.prepareBaseTables();

fn nonceScalarFromAffineX(affine_x: Fe) SigningError!Scalar {
    const x_bytes = encodeField(affine_x.value);
    const r = scalarReduce(decode(&x_bytes));
    if (limbsZero(r.value)) return error.InvalidNonce;
    return r;
}

const AffinePoint = struct {
    x: Fe = Fe.zero,
    y: Fe = Fe.one_fe,
    identity: bool = true,
};

/// Jacobian table entry with the public Z powers reused by every addition.
const CachedPoint = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    z_squared: Fe,
    z_cubed: Fe,
    identity: bool,

    fn init(point: Point) CachedPoint {
        if (point.isIdentity()) {
            return .{
                .x = point.x,
                .y = point.y,
                .z = point.z,
                .z_squared = Fe.zero,
                .z_cubed = Fe.zero,
                .identity = true,
            };
        }
        const z_squared = point.z.sq();
        return .{
            .x = point.x,
            .y = point.y,
            .z = point.z,
            .z_squared = z_squared,
            .z_cubed = point.z.mul(z_squared),
            .identity = false,
        };
    }

    fn addDistinct(self: CachedPoint, other: CachedPoint) Point {
        std.debug.assert(!self.identity);
        std.debug.assert(!other.identity);
        const first_x = self.x.mul(other.z_squared);
        const second_x = other.x.mul(self.z_squared);
        const s1 = self.y.mul(other.z_cubed);
        const s2 = other.y.mul(self.z_cubed);
        std.debug.assert(!first_x.equivalent(second_x));
        const h = second_x.sub(first_x);
        const i = h.dbl().sq();
        const j = h.mul(i);
        const r = s2.sub(s1).dbl();
        const v = first_x.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
        const z3 = self.z.add(other.z).sq().sub(
            self.z_squared,
        ).sub(other.z_squared).mul(h);
        return .{ .x = x3, .y = y3, .z = z3 };
    }
};

fn wnafDigits(
    comptime width: usize,
    value: Limbs,
) [wnaf_digit_count]i16 {
    var digits = [_]i16{0} ** wnaf_digit_count;
    var remaining = value;
    var index: usize = 0;
    while (!limbsZero(remaining)) : (index += 1) {
        std.debug.assert(index < digits.len);
        if ((remaining[0] & 1) != 0) {
            const residue: u16 = @intCast(
                remaining[0] & ((1 << width) - 1),
            );
            var digit: i16 = @intCast(residue);
            if (residue >= 1 << (width - 1)) {
                digit -= 1 << width;
            }
            digits[index] = digit;
            if (digit > 0) {
                remaining = subSmall(remaining, @intCast(digit));
            } else {
                var addend = [_]u64{0} ** limb_count;
                addend[0] = @intCast(-digit);
                const sum = addRaw(remaining, addend);
                std.debug.assert(sum.carry == 0);
                remaining = sum.value;
            }
        }
        remaining = shiftRightOne(remaining);
    }
    return digits;
}

fn wnafSparse(comptime width: usize, value: Limbs) Wnaf(width) {
    var result: Wnaf(width) = undefined;
    result.len = 0;
    var carry: u16 = 0;
    var position: usize = 0;
    while (position < 521) {
        const limb_index = position / 64;
        const bit_offset: u6 = @intCast(position % 64);
        const low_bit: u16 = @truncate(value[limb_index] >> bit_offset);
        if ((low_bit & 1) == carry) {
            position += 1;
            continue;
        }
        var window = value[limb_index] >> bit_offset;
        if (bit_offset > 64 - width and limb_index + 1 < value.len) {
            const upper_shift: u6 = @intCast(64 - @as(u7, bit_offset));
            window |= value[limb_index + 1] << upper_shift;
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
        std.debug.assert(position == 521);
        std.debug.assert(result.len < result.entries.len);
        result.entries[result.len] = .{ .position = 521, .digit = 1 };
        result.len += 1;
    }
    return result;
}

fn batchToAffine(comptime count: usize, points: [count]Point) [count]AffinePoint {
    var prefixes: [count]Fe = undefined;
    var product = Fe.one_fe;
    for (points, 0..) |point, index| {
        prefixes[index] = product;
        if (!point.isIdentity()) product = product.mul(point.z);
    }

    var inverse = product.invert();
    var result: [count]AffinePoint = undefined;
    var index = points.len;
    while (index != 0) {
        index -= 1;
        const point = points[index];
        if (point.isIdentity()) {
            result[index] = .{};
            continue;
        }
        const z_inverse = inverse.mul(prefixes[index]);
        inverse = inverse.mul(point.z);
        const z_squared = z_inverse.sq();
        result[index] = .{
            .x = point.x.mul(z_squared),
            .y = point.y.mul(z_squared).mul(z_inverse),
            .identity = false,
        };
    }
    return result;
}

const base_prepared_wnaf_multiples = blk: {
    @setEvalBranchQuota(100_000_000);
    break :blk batchToAffine(
        base_wnaf_table_entries,
        Point.precomputeOdd(base_wnaf_table_entries, Point.base),
    );
};

const base_throughput_wnaf_multiples = blk: {
    @setEvalBranchQuota(100_000_000);
    break :blk batchToAffine(
        throughput_wnaf_table_entries,
        Point.precomputeOdd(throughput_wnaf_table_entries, Point.base),
    );
};

inline fn curveRhs(x: Fe) Fe {
    return x.sq().mul(x).sub(x.mulSmall(3)).add(.{ .value = curve_b });
}

pub fn scalarPowTwoMinusOne(base: Limbs, count: usize) Limbs {
    std.debug.assert(count != 0);
    if (count == 1) return base;
    const half_count = count / 2;
    const half = scalarPowTwoMinusOne(base, half_count);
    var result = half;
    for (0..half_count) |_| {
        result = scalar_montgomery.mulSecretPointers(&result, &result);
    }
    result = scalar_montgomery.mulSecretPointers(&result, &half);
    if (count % 2 != 0) {
        result = scalar_montgomery.mulSecretPointers(&result, &result);
        result = scalar_montgomery.mulSecretPointers(&result, &base);
    }
    return result;
}

const Montgomery = struct {
    modulus: Limbs,
    negative_inverse: u64,
    r_squared: Limbs,

    fn init(comptime modulus: Limbs) Montgomery {
        @setEvalBranchQuota(100_000);
        var inverse: u64 = 1;
        inline for (0..6) |_| inverse *%= 2 -% modulus[0] *% inverse;
        var r_squared = one();
        for (0..2 * limb_count * @bitSizeOf(u64)) |_| {
            r_squared = doubleMod(r_squared, modulus);
        }
        return .{
            .modulus = modulus,
            .negative_inverse = 0 -% inverse,
            .r_squared = r_squared,
        };
    }

    fn toMontgomery(self: Montgomery, value: Limbs) Limbs {
        return self.mul(value, self.r_squared);
    }

    fn fromMontgomery(self: Montgomery, value: Limbs) Limbs {
        return self.mul(value, one());
    }

    fn toMontgomerySecret(self: Montgomery, value: Limbs) Limbs {
        return self.mulSecret(value, self.r_squared);
    }

    fn fromMontgomerySecret(self: Montgomery, value: Limbs) Limbs {
        return self.mulSecret(value, one());
    }

    fn mul(self: Montgomery, a: Limbs, b: Limbs) Limbs {
        var intermediate = [_]u64{0} ** (limb_count + 2);
        for (0..limb_count) |i| {
            var carry: u128 = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, a[j]) * b[i] +
                    intermediate[j] + carry;
                intermediate[j] = @truncate(wide);
                carry = wide >> 64;
            }
            const upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count] = upper[0];
            intermediate[limb_count + 1] = upper[1];

            const factor = intermediate[0] *% self.negative_inverse;
            carry = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, factor) * self.modulus[j] +
                    intermediate[j] + carry;
                if (j != 0) intermediate[j - 1] = @truncate(wide);
                carry = wide >> 64;
            }
            const reduced_upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count - 1] = reduced_upper[0];
            intermediate[limb_count] = intermediate[limb_count + 1] +%
                reduced_upper[1];
            intermediate[limb_count + 1] = 0;
        }
        return self.reduce(
            intermediate[0..limb_count].*,
            intermediate[limb_count],
        );
    }

    fn mulSecret(self: Montgomery, a: Limbs, b: Limbs) Limbs {
        return self.mulSecretPointers(&a, &b);
    }

    fn mulSecretPointers(
        self: Montgomery,
        a: *const Limbs,
        b: *const Limbs,
    ) Limbs {
        if (comptime use_x86_64_adx_scalar) {
            var result: Limbs = undefined;
            vailP521ScalarMontgomeryMul(
                &result,
                a,
                b,
                &scalar_modulus,
                scalar_montgomery.negative_inverse,
            );
            return result;
        }
        return self.mulSecretInternal(a.*, b.*);
    }

    fn mulSecretInternal(self: Montgomery, a: Limbs, b: Limbs) Limbs {
        var intermediate = [_]u64{0} ** (limb_count + 2);
        for (0..limb_count) |i| {
            var carry: u128 = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, a[j]) * b[i] +
                    intermediate[j] + carry;
                intermediate[j] = @truncate(wide);
                carry = wide >> 64;
            }
            const upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count] = upper[0];
            intermediate[limb_count + 1] = upper[1];

            const factor = intermediate[0] *% self.negative_inverse;
            carry = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, factor) * self.modulus[j] +
                    intermediate[j] + carry;
                if (j != 0) intermediate[j - 1] = @truncate(wide);
                carry = wide >> 64;
            }
            const reduced_upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count - 1] = reduced_upper[0];
            intermediate[limb_count] = intermediate[limb_count + 1] +%
                reduced_upper[1];
            intermediate[limb_count + 1] = 0;
        }
        return self.reduceSecret(
            intermediate[0..limb_count].*,
            intermediate[limb_count],
        );
    }

    fn reduce(self: Montgomery, value: Limbs, extra: u64) Limbs {
        const reduced = subRaw(value, self.modulus);
        if (extra != 0 or reduced.borrow == 0) return reduced.value;
        return value;
    }

    fn reduceSecret(self: Montgomery, value: Limbs, extra: u64) Limbs {
        const reduced = subRaw(value, self.modulus);
        const use_reduced = @as(u1, @intFromBool(extra != 0)) |
            (reduced.borrow ^ 1);
        return selectLimbs(value, reduced.value, use_reduced);
    }

    fn doubleMod(value: Limbs, modulus: Limbs) Limbs {
        const doubled = addRaw(value, value);
        const reduced = subRaw(doubled.value, modulus);
        if (doubled.carry != 0 or reduced.borrow == 0) return reduced.value;
        return doubled.value;
    }
};

extern fn vailP521ScalarMontgomeryMul(
    output: *Limbs,
    a: *const Limbs,
    b: *const Limbs,
    modulus: *const Limbs,
    negative_inverse: u64,
) callconv(.c) void;

comptime {
    if (use_x86_64_adx_scalar) {
        asm (
            \\.text
            \\.macro vail_p521_product_row multiplicand, product, shift
            \\movq 0+\shift(\product), %r8
            \\xorl %eax, %eax
            \\mulxq 0(\multiplicand), %r9, %r10
            \\adcxq %r8, %r9
            \\movq %r9, 0+\shift(\product)
            \\movq 8+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\.irp offset, 8, 24, 40
            \\mulxq \offset(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, \offset+\shift(\product)
            \\movq \offset+8+\shift(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq \offset+8(\multiplicand), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, \offset+8+\shift(\product)
            \\movq \offset+16+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\.endr
            \\mulxq 56(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 56+\shift(\product)
            \\movq 64+\shift(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq 64(\multiplicand), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, 64+\shift(\product)
            \\adoxq %rax, %r10
            \\adcxq %rax, %r10
            \\addq %r10, 72+\shift(\product)
            \\adcq $0, 80+\shift(\product)
            \\.endm
            \\
            \\.macro vail_p521_reduce_row product, shift, modulus, inverse
            \\movq 0+\shift(\product), %r8
            \\movq %r8, %rdx
            \\imulq \inverse, %rdx
            \\xorl %eax, %eax
            \\mulxq 0(\modulus), %r9, %r10
            \\adcxq %r8, %r9
            \\movq 8+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\.irp offset, 8, 24, 40
            \\mulxq \offset(\modulus), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, \offset+\shift(\product)
            \\movq \offset+8+\shift(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq \offset+8(\modulus), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, \offset+8+\shift(\product)
            \\movq \offset+16+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\.endr
            \\mulxq 56(\modulus), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 56+\shift(\product)
            \\movq 64+\shift(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq 64(\modulus), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, 64+\shift(\product)
            \\adoxq %rax, %r10
            \\adcxq %rax, %r10
            \\addq %r10, 72+\shift(\product)
            \\adcq %rdi, 80+\shift(\product)
            \\setc %dil
            \\.endm
            \\
            \\.p2align 5
            \\.globl vailP521ScalarMontgomeryMul
            \\.hidden vailP521ScalarMontgomeryMul
            \\.type vailP521ScalarMontgomeryMul,@function
            \\vailP521ScalarMontgomeryMul:
            \\pushq %rbx
            \\pushq %rbp
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\subq $160, %rsp
            \\movq %rdi, %r12
            \\movq %rsi, %r13
            \\movq %rdx, %rbx
            \\movq %rcx, %r14
            \\movq %r8, %rbp
            \\vpxor %ymm0, %ymm0, %ymm0
            \\.irp offset, 0, 32, 64, 96, 128
            \\vmovdqu %ymm0, \offset(%rsp)
            \\.endr
            \\.irp outer, 0, 1, 2, 3, 4, 5, 6, 7, 8
            \\movq 8*\outer(%rbx), %rdx
            \\vail_p521_product_row %r13, %rsp, 8*\outer
            \\.endr
            \\
            \\xorl %edi, %edi
            \\.irp outer, 0, 1, 2, 3, 4, 5, 6, 7, 8
            \\vail_p521_reduce_row %rsp, 8*\outer, %r14, %rbp
            \\.endr
            \\
            \\clc
            \\.irp offset, 0, 8, 16, 24, 32, 40, 48, 56, 64
            \\movq 72+\offset(%rsp), %r8
            \\sbbq \offset(%r14), %r8
            \\movq %r8, \offset(%r12)
            \\.endr
            \\sbbq %r8, %r8
            \\movq 144(%rsp), %r9
            \\negq %r9
            \\sbbq %r9, %r9
            \\notq %r9
            \\andq %r9, %r8
            \\testq %r8, %r8
            \\.irp offset, 0, 8, 16, 24, 32, 40, 48, 56, 64
            \\movq \offset(%r12), %r9
            \\cmovneq 72+\offset(%rsp), %r9
            \\movq %r9, \offset(%r12)
            \\.endr
            \\
            \\vpxor %ymm0, %ymm0, %ymm0
            \\.irp offset, 0, 32, 64, 96, 128
            \\vmovdqu %ymm0, \offset(%rsp)
            \\.endr
            \\vzeroupper
            \\addq $160, %rsp
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbp
            \\popq %rbx
            \\retq
            \\.size vailP521ScalarMontgomeryMul, .-vailP521ScalarMontgomeryMul
            \\.purgem vail_p521_product_row
            \\.purgem vail_p521_reduce_row
        );
    }
}

inline fn selectLimbs(a: Limbs, b: Limbs, select_b: u1) Limbs {
    const mask = opaqueWord(0 -% @as(u64, select_b));
    var result: Limbs = undefined;
    inline for (0..limb_count) |index| {
        result[index] = (b[index] & mask) | (a[index] & ~mask);
    }
    return result;
}

inline fn scalarAddSecret(a: Limbs, b: Limbs) Limbs {
    const sum = addRaw(a, b);
    const reduced = subRaw(sum.value, scalar_modulus);
    const use_reduced = sum.carry | (reduced.borrow ^ 1);
    return selectLimbs(sum.value, reduced.value, use_reduced);
}

const scalar_montgomery = Montgomery.init(scalar_modulus);
const scalar_montgomery_one = scalar_montgomery.toMontgomery(one());

comptime {
    const twice_order = addRaw(scalar_modulus, scalar_modulus);
    if (!lessThan(scalar_modulus, field_modulus_binary) or
        twice_order.carry != 0 or
        !lessThan(field_modulus_binary, twice_order.value))
    {
        @compileError("P-521 projective x check requires n < p < 2n");
    }
}

const DerReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn done(self: DerReader) bool {
        return self.offset == self.bytes.len;
    }

    fn require(self: *DerReader, tag: u8) ![]const u8 {
        if (self.offset + 2 > self.bytes.len or self.bytes[self.offset] != tag) {
            return error.InvalidDer;
        }
        self.offset += 1;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidDer;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidDer;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidDer;
            }
            self.offset += count;
            if (length < 128) return error.InvalidDer;
        }
        const end = std.math.add(usize, self.offset, length) catch
            return error.InvalidDer;
        if (end > self.bytes.len) return error.InvalidDer;
        const value = self.bytes[self.offset..end];
        self.offset = end;
        return value;
    }
};

const ParsedPrivateKey = struct {
    secret_key: [secret_key_encoded_length]u8,
    public_key: ?[]const u8,
};

fn parsePrivateKeyDer(encoded: []const u8) SigningError!ParsedPrivateKey {
    var outer = DerReader{ .bytes = encoded };
    const sequence = outer.require(0x30) catch
        return error.InvalidSecretKey;
    if (!outer.done()) return error.InvalidSecretKey;
    var fields = DerReader{ .bytes = sequence };
    const version = fields.require(0x02) catch
        return error.InvalidSecretKey;
    if (fields.done()) return error.InvalidSecretKey;
    return switch (fields.bytes[fields.offset]) {
        0x04 => blk: {
            if (!std.mem.eql(u8, version, "\x01")) {
                return error.InvalidSecretKey;
            }
            break :blk parseEcPrivateKeyFields(&fields);
        },
        0x30 => blk: {
            if (!std.mem.eql(u8, version, "\x00")) {
                return error.InvalidSecretKey;
            }
            const algorithm = fields.require(0x30) catch
                return error.InvalidSecretKey;
            var algorithm_fields = DerReader{ .bytes = algorithm };
            const algorithm_oid = algorithm_fields.require(0x06) catch
                return error.InvalidSecretKey;
            const curve_oid = algorithm_fields.require(0x06) catch
                return error.InvalidSecretKey;
            if (!algorithm_fields.done() or
                !std.mem.eql(u8, algorithm_oid, oid_id_ec_public_key) or
                !std.mem.eql(u8, curve_oid, oid_secp521r1))
            {
                return error.InvalidSecretKey;
            }
            const private_key = fields.require(0x04) catch
                return error.InvalidSecretKey;
            if (!fields.done()) return error.InvalidSecretKey;
            var private_outer = DerReader{ .bytes = private_key };
            const private_sequence = private_outer.require(0x30) catch
                return error.InvalidSecretKey;
            if (!private_outer.done()) return error.InvalidSecretKey;
            var private_fields = DerReader{ .bytes = private_sequence };
            const private_version = private_fields.require(0x02) catch
                return error.InvalidSecretKey;
            if (!std.mem.eql(u8, private_version, "\x01")) {
                return error.InvalidSecretKey;
            }
            break :blk parseEcPrivateKeyFields(&private_fields);
        },
        else => error.InvalidSecretKey,
    };
}

fn parseEcPrivateKeyFields(
    fields: *DerReader,
) SigningError!ParsedPrivateKey {
    const scalar = fields.require(0x04) catch
        return error.InvalidSecretKey;
    if (scalar.len != secret_key_encoded_length) {
        return error.InvalidSecretKey;
    }
    var parsed = ParsedPrivateKey{
        .secret_key = scalar[0..secret_key_encoded_length].*,
        .public_key = null,
    };
    var saw_parameters = false;
    var saw_public_key = false;
    while (!fields.done()) {
        switch (fields.bytes[fields.offset]) {
            0xa0 => {
                if (saw_parameters or saw_public_key) {
                    return error.InvalidSecretKey;
                }
                saw_parameters = true;
                const parameters = fields.require(0xa0) catch
                    return error.InvalidSecretKey;
                var parameter_fields = DerReader{ .bytes = parameters };
                const curve_oid = parameter_fields.require(0x06) catch
                    return error.InvalidSecretKey;
                if (!parameter_fields.done() or
                    !std.mem.eql(u8, curve_oid, oid_secp521r1))
                {
                    return error.InvalidSecretKey;
                }
            },
            0xa1 => {
                if (saw_public_key) return error.InvalidSecretKey;
                saw_public_key = true;
                const public_wrapper = fields.require(0xa1) catch
                    return error.InvalidSecretKey;
                var public_fields = DerReader{ .bytes = public_wrapper };
                const bit_string = public_fields.require(0x03) catch
                    return error.InvalidSecretKey;
                if (!public_fields.done() or bit_string.len < 2 or
                    bit_string[0] != 0)
                {
                    return error.InvalidSecretKey;
                }
                const public_key = bit_string[1..];
                if (public_key.len != compressed_sec1_encoded_length and
                    public_key.len != uncompressed_sec1_encoded_length)
                {
                    return error.InvalidSecretKey;
                }
                parsed.public_key = public_key;
            },
            else => return error.InvalidSecretKey,
        }
    }
    return parsed;
}

const FieldWide = u1152;
const ScalarWide = u576;

fn fieldWide(value: FieldLimbs) FieldWide {
    var result: FieldWide = 0;
    inline for (value, 0..) |limb, index| {
        result |= @as(FieldWide, limb) << (index * field_radix_bits);
    }
    return result;
}

fn scalarWide(value: Limbs) ScalarWide {
    var result: ScalarWide = 0;
    inline for (value, 0..) |limb, index| {
        result |= @as(ScalarWide, limb) << (index * 64);
    }
    return result;
}

fn expectSparseWnafMatches(comptime width: usize, value: Limbs) !void {
    const dense = wnafDigits(width, value);
    const sparse = wnafSparse(width, value);
    var expanded = [_]i16{0} ** wnaf_digit_count;
    for (sparse.entries[0..sparse.len]) |entry| {
        try std.testing.expectEqual(
            @as(i16, 0),
            expanded[entry.position],
        );
        expanded[entry.position] = entry.digit;
    }
    try std.testing.expectEqual(dense, expanded);

    var reconstructed: i1024 = 0;
    var weight: i1024 = 1;
    var previous_nonzero: ?usize = null;
    for (dense, 0..) |digit, index| {
        if (digit != 0) {
            const magnitude: u16 = @intCast(
                if (digit < 0) -digit else digit,
            );
            try std.testing.expect((magnitude & 1) != 0);
            try std.testing.expect(magnitude < 1 << (width - 1));
            if (previous_nonzero) |previous| {
                try std.testing.expect(index - previous >= width);
            }
            previous_nonzero = index;
            reconstructed += @as(i1024, digit) * weight;
        }
        weight *= 2;
    }
    try std.testing.expectEqual(
        @as(i1024, @intCast(scalarWide(value))),
        reconstructed,
    );
}

test "P-521 configured wNAF reconstructs bounded scalars" {
    const values = [_]Limbs{
        [_]u64{0} ** limb_count,
        one(),
        subSmall(scalar_modulus, 1),
        .{
            0xfedc_ba98_7654_3211,
            0x0123_4567_89ab_cdef,
            0xa5a5_5a5a_a5a5_5a5a,
            0x1357_9bdf_2468_ace1,
            0x1122_3344_5566_7788,
            0x8877_6655_4433_2211,
            0xcafe_babe_dead_beef,
            0x0102_0304_0506_0708,
            0x0000_0000_0000_00ff,
        },
    };
    inline for ([_]usize{
        one_shot_wnaf_width,
        prepared_wnaf_width,
        base_wnaf_width,
        throughput_wnaf_width,
    }) |width| {
        for (values) |value| {
            try expectSparseWnafMatches(width, value);
        }
    }

    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..256) |_| {
        var value: Limbs = undefined;
        for (&value) |*limb| {
            state +%= 0x9e37_79b9_7f4a_7c15;
            var random = state;
            random = (random ^ (random >> 30)) *% 0xbf58_476d_1ce4_e5b9;
            random = (random ^ (random >> 27)) *% 0x94d0_49bb_1331_11eb;
            random ^= random >> 31;
            limb.* = random;
        }
        value[limb_count - 1] &= 0xff;
        inline for ([_]usize{
            one_shot_wnaf_width,
            prepared_wnaf_width,
            base_wnaf_width,
            throughput_wnaf_width,
        }) |width| {
            try expectSparseWnafMatches(width, value);
        }
    }
}

test "P-521 batched modular halving matches repeated halving" {
    const shifts = [_]u7{ 1, 2, 3, 7, 16, 31, 63, 64 };
    var state: u64 = 0x9e37_79b9_7f4a_7c15;
    for (0..128) |_| {
        var value: Limbs = undefined;
        inline for (0..limb_count) |index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            value[index] = state;
        }
        value[limb_count - 1] &= 0x01ff;
        if (!lessThan(value, scalar_modulus)) {
            value = subRaw(value, scalar_modulus).value;
        }
        if (limbsZero(value)) value = one();
        for (shifts) |shift| {
            var expected = value;
            for (0..shift) |_| {
                expected = halfModulo(expected, scalar_modulus);
            }
            try std.testing.expectEqual(
                expected,
                dividePowerOfTwoModulo(
                    value,
                    shift,
                    scalar_modulus,
                    scalar_montgomery.negative_inverse,
                ),
            );
        }
        const scalar = Scalar{ .value = value };
        try std.testing.expectEqual(
            one(),
            scalar.mul(scalar.invert()).value,
        );
        try std.testing.expectEqualSlices(
            u64,
            &scalar.invert().value,
            &scalar.invertSecret().value,
        );
    }
}

test "P-521 constant-time scalar arithmetic matches public oracle" {
    var two = one();
    two[0] = 2;
    const values = [_]Limbs{
        one(),
        two,
        subSmall(scalar_modulus, 1),
        .{
            0xfedc_ba98_7654_3211,
            0x0123_4567_89ab_cdef,
            0xa5a5_5a5a_a5a5_5a5a,
            0x1357_9bdf_2468_ace1,
            0x1122_3344_5566_7788,
            0x8877_6655_4433_2211,
            0xcafe_babe_dead_beef,
            0x0102_0304_0506_0708,
            0x0000_0000_0000_00ff,
        },
    };
    const modulus = scalarWide(scalar_modulus);
    for (values, 0..) |value, index| {
        const scalar = Scalar{ .value = value };
        try std.testing.expectEqualSlices(
            u64,
            &scalar.invert().value,
            &scalar.invertSecret().value,
        );
        const other = values[(index + 1) % values.len];
        try std.testing.expectEqual(
            (scalarWide(value) + scalarWide(other)) % modulus,
            scalarWide(scalar.addSecret(.{ .value = other }).value),
        );
        var scalar_montgomery_value =
            SecretScalarMontgomery.fromScalar(scalar);
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&scalar_montgomery_value)[0..1],
        );
        var optimized_inverse = scalar_montgomery_value.invert();
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&optimized_inverse)[0..1],
        );
        var portable_inverse = scalar_montgomery_value.invertPortable();
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&portable_inverse)[0..1],
        );
        try std.testing.expectEqualSlices(
            u64,
            &portable_inverse.value,
            &optimized_inverse.value,
        );
        var other_montgomery_value = SecretScalarMontgomery.fromScalar(.{
            .value = other,
        });
        defer std.crypto.secureZero(
            SecretScalarMontgomery,
            (&other_montgomery_value)[0..1],
        );
        try std.testing.expectEqualSlices(
            u64,
            &scalar.mulSecret(.{ .value = other }).value,
            &scalar_montgomery_value.mul(other_montgomery_value).toScalar().value,
        );
        try std.testing.expectEqualSlices(
            u64,
            &scalar.addSecret(.{ .value = other }).value,
            &scalar_montgomery_value.add(other_montgomery_value).toScalar().value,
        );
    }
}

test "P-521 cached odd-multiple table matches full Jacobian recurrence" {
    const vectors = @import("../../x509/testdata/path_vectors.zig");
    const root = decodeHex(vectors.p521_root_hex);
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &root,
        .index = 0,
    });
    const public_key = try Point.fromSec1(certificate.pubKey());
    for ([_]Point{ Point.base, public_key }) |source| {
        const expected = Point.precomputeOdd(
            one_shot_wnaf_table_entries,
            source,
        );
        const actual = Point.precomputeOddCached(
            one_shot_wnaf_table_entries,
            source,
        );
        for (expected, actual) |point, cached| {
            try std.testing.expect(point.x.equivalent(cached.x));
            try std.testing.expect(point.y.equivalent(cached.y));
            try std.testing.expect(point.z.equivalent(cached.z));
            try std.testing.expect(
                point.z.sq().equivalent(cached.z_squared),
            );
            try std.testing.expect(
                point.z.mul(cached.z_squared).equivalent(cached.z_cubed),
            );
            try std.testing.expectEqual(point.isIdentity(), cached.identity);
        }
    }
}

test "P-521 field arithmetic matches a wide integer oracle" {
    const modulus = (@as(FieldWide, 1) << 521) - 1;
    const fixed = [_]FieldLimbs{
        Fe.zero.value,
        Fe.one_fe.value,
        fieldSubRaw(field_modulus, Fe.one_fe.value),
        generator_x,
        generator_y,
        curve_b,
    };
    for (fixed) |a| {
        for (fixed) |b| {
            try std.testing.expectEqual(
                (fieldWide(a) + fieldWide(b)) % modulus,
                fieldWide(fieldAdd(a, b)),
            );
            try std.testing.expectEqual(
                (fieldWide(a) + modulus - fieldWide(b)) % modulus,
                fieldWide(fieldSub(a, b)),
            );
            try std.testing.expectEqual(
                (fieldWide(a) + modulus - fieldWide(b)) % modulus,
                fieldWide(fieldSubSecret(a, b)),
            );
            try std.testing.expectEqual(
                fieldWide(a) * fieldWide(b) % modulus,
                fieldWide(fieldMul(a, b)),
            );
        }
        try std.testing.expectEqual(
            fieldWide(a) * fieldWide(a) % modulus,
            fieldWide(fieldSquare(a)),
        );
    }

    var state: u64 = 0xd1b5_4a32_d192_ed03;
    for (0..64) |_| {
        var a: FieldLimbs = undefined;
        var b: FieldLimbs = undefined;
        inline for (0..limb_count) |index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            a[index] = state & field_mask;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b[index] = state & field_mask;
        }
        a[limb_count - 1] &= field_top_mask;
        b[limb_count - 1] &= field_top_mask;
        const wide_a = fieldWide(a);
        const wide_b = fieldWide(b);
        try std.testing.expectEqual(
            (wide_a + wide_b) % modulus,
            fieldWide(fieldAdd(a, b)),
        );
        try std.testing.expectEqual(
            (wide_a + modulus - wide_b) % modulus,
            fieldWide(fieldSub(a, b)),
        );
        try std.testing.expectEqual(
            (wide_a + modulus - wide_b) % modulus,
            fieldWide(fieldSubSecret(a, b)),
        );
        try std.testing.expectEqual(
            wide_a * wide_b % modulus,
            fieldWide(fieldMul(a, b)),
        );
        try std.testing.expectEqual(
            wide_a * wide_a % modulus,
            fieldWide(fieldSquare(a)),
        );
    }
}

test "P-521 secret field inversion matches the portable chain" {
    const fixed = [_]FieldLimbs{
        Fe.one_fe.value,
        fieldSubRaw(field_modulus, Fe.one_fe.value),
        generator_x,
        generator_y,
        curve_b,
    };
    for (fixed) |value| {
        const secret = SecretFe{ .value = value };
        try std.testing.expect(fieldEqual(
            secret.invert().value,
            secret.invertPortable().value,
        ));
    }

    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..64) |_| {
        var value: FieldLimbs = undefined;
        inline for (0..limb_count) |index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            value[index] = state & field_mask;
        }
        value[limb_count - 1] &= field_top_mask;
        if (!fieldLessThan(value, field_modulus)) {
            value = fieldSubRaw(value, field_modulus);
        }
        if (fieldEqual(value, Fe.zero.value)) value = Fe.one_fe.value;
        const secret = SecretFe{ .value = value };
        try std.testing.expect(fieldEqual(
            secret.invert().value,
            secret.invertPortable().value,
        ));
    }
}

test "P-521 small field multipliers match repeated modular addition" {
    const cases = [_]FieldLimbs{
        Fe.zero.value,
        Fe.one_fe.value,
        fieldSubRaw(field_modulus, Fe.one_fe.value),
        generator_x,
        generator_y,
        curve_b,
    };
    inline for ([_]u4{ 0, 1, 2, 3, 4, 8, 15 }) |multiplier| {
        for (cases) |value| {
            var expected = Fe.zero;
            for (0..multiplier) |_| {
                expected = expected.add(.{ .value = value });
            }
            try std.testing.expect(fieldEqual(
                fieldMulSmall(value, multiplier),
                expected.value,
            ));
        }
    }
}

test "P-521 compares the final x coordinate without inversion" {
    const expected = Scalar{ .value = one() };
    var seven = one();
    seven[0] = 7;
    const z = Fe.fromCanonicalLimbs(seven);
    const z_squared = z.sq();

    try verifyResult(expected, .{
        .x = Fe.fromCanonicalLimbs(expected.value).mul(z_squared),
        .y = Fe.one_fe,
        .z = z,
    });

    const expected_plus_order = addRaw(expected.value, scalar_modulus);
    try std.testing.expectEqual(@as(u1, 0), expected_plus_order.carry);
    try std.testing.expect(lessThan(
        expected_plus_order.value,
        field_modulus_binary,
    ));
    try verifyResult(expected, .{
        .x = Fe.fromCanonicalLimbs(expected_plus_order.value).mul(z_squared),
        .y = Fe.one_fe,
        .z = z,
    });

    var two = one();
    two[0] = 2;
    try std.testing.expectError(error.InvalidSignature, verifyResult(
        expected,
        .{
            .x = Fe.fromCanonicalLimbs(two).mul(z_squared),
            .y = Fe.one_fe,
            .z = z,
        },
    ));
    try std.testing.expectError(
        error.InvalidSignature,
        verifyResult(expected, Point.identity),
    );
}

test "P-521 field and group constants are valid" {
    try std.testing.expectEqual(
        @as(usize, 5888),
        @sizeOf(CompactPreparedVerifier),
    );
    try std.testing.expectEqual(@as(usize, 38_912), @sizeOf(PreparedVerifier));
    try std.testing.expectEqual(
        @as(usize, 622_592),
        @sizeOf(ThroughputPreparedVerifier),
    );
    try std.testing.expectEqual(@as(usize, 216), @sizeOf(PublicKey));
    var base = Point.base;
    std.mem.doNotOptimizeAway(&base);
    try std.testing.expect(base.y.sq().equivalent(curveRhs(base.x)));
    try std.testing.expect(Point.identity.dbl().isIdentity());
    try std.testing.expect((Point{
        .x = base.x,
        .y = Fe.zero,
        .z = Fe.one_fe,
    }).dbl().isIdentity());
    var order = scalar_modulus;
    std.mem.doNotOptimizeAway(&order);
    const order_times_base = Point.mulAddBase(
        order,
        [_]u64{0} ** limb_count,
        Point.base,
    );
    try std.testing.expect(order_times_base.isIdentity());
}

test "P-521 constant-time base multiplication matches public wNAF" {
    var two = one();
    two[0] = 2;
    var fifteen = one();
    fifteen[0] = 15;
    const cases = [_]Limbs{
        one(),
        two,
        fifteen,
        subSmall(scalar_modulus, 1),
        .{
            0xfedc_ba98_7654_3211,
            0x0123_4567_89ab_cdef,
            0xa5a5_5a5a_a5a5_5a5a,
            0x1357_9bdf_2468_ace1,
            0x1122_3344_5566_7788,
            0x8877_6655_4433_2211,
            0xcafe_babe_dead_beef,
            0x0102_0304_0506_0708,
            0x0000_0000_0000_00ff,
        },
    };
    const zero = [_]u64{0} ** limb_count;
    const base_tables = SecretPoint.prepareBaseTables();
    for (cases) |scalar| {
        const expected = Point.mulAddBase(scalar, zero, Point.base);
        const actual = SecretPoint.mulBasePrepared(
            scalar,
            &base_tables,
        ).toJacobian();
        const affine = batchToAffine(2, .{ expected, actual });
        try std.testing.expect(!affine[0].identity);
        try std.testing.expect(!affine[1].identity);
        try std.testing.expect(affine[0].x.equivalent(affine[1].x));
        try std.testing.expect(affine[0].y.equivalent(affine[1].y));
    }

    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..64) |_| {
        var scalar: Limbs = undefined;
        inline for (0..limb_count) |index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            scalar[index] = state;
        }
        scalar[limb_count - 1] &= 0x01ff;
        if (!lessThan(scalar, scalar_modulus)) {
            scalar = subRaw(scalar, scalar_modulus).value;
        }
        if (limbsZero(scalar)) scalar = one();
        const expected = Point.mulAddBase(scalar, zero, Point.base);
        const actual = SecretPoint.mulBasePrepared(
            scalar,
            &base_tables,
        ).toJacobian();
        const affine = batchToAffine(2, .{ expected, actual });
        try std.testing.expect(!affine[0].identity);
        try std.testing.expect(!affine[1].identity);
        try std.testing.expect(affine[0].x.equivalent(affine[1].x));
        try std.testing.expect(affine[0].y.equivalent(affine[1].y));
    }
}

test "P-521 constant-time base-table selection scans every entry" {
    const tables = SecretPoint.prepareBaseTables();
    try std.testing.expectEqual(
        @as(usize, 2 * limb_count * secret_window_entries * @sizeOf(u64)),
        @sizeOf(SecretBaseTable),
    );
    inline for (0..secret_comb_tables) |group| {
        for (0..secret_window_entries) |index| {
            const selected = SecretPoint.selectBase(
                &tables[group],
                @intCast(index),
            );
            inline for (0..limb_count) |limb| {
                try std.testing.expectEqual(
                    tables[group].x[limb][index],
                    selected.x.value[limb],
                );
                try std.testing.expectEqual(
                    tables[group].y[limb][index],
                    selected.y.value[limb],
                );
            }
            try std.testing.expectEqual(
                @as(u1, @intFromBool(index == 0)),
                selected.identity,
            );
        }
    }
}

test "P-521 ECDH comb selection scans every entry" {
    const tables = SecretPoint.prepareEcdhTables(Point.base);
    try std.testing.expectEqual(
        @as(usize, 2 * limb_count * ecdh_window_entries * @sizeOf(u64)),
        @sizeOf(SecretEcdhTable),
    );
    inline for (0..ecdh_comb_tables) |group| {
        for (0..ecdh_window_entries) |index| {
            const selected = SecretPoint.selectEcdhBase(
                &tables[group],
                @intCast(index),
            );
            inline for (0..limb_count) |limb| {
                try std.testing.expectEqual(
                    tables[group].x[limb][index],
                    selected.x.value[limb],
                );
                try std.testing.expectEqual(
                    tables[group].y[limb][index],
                    selected.y.value[limb],
                );
            }
            try std.testing.expectEqual(
                @as(u1, @intFromBool(index == 0)),
                selected.identity,
            );
        }
    }
}

test "P-521 ECDH agrees in both directions and rejects invalid inputs" {
    var first_secret = [_]u8{0} ** secret_key_encoded_length;
    first_secret[first_secret.len - 1] = 7;
    var second_secret = [_]u8{0} ** secret_key_encoded_length;
    second_secret[second_secret.len - 1] = 11;
    const first_public = try ecdhPublicKey(first_secret);
    const second_public = try ecdhPublicKey(second_secret);
    const first_shared = try ecdhSharedSecret(first_secret, &second_public);
    const second_shared = try ecdhSharedSecret(second_secret, &first_public);
    try std.testing.expectEqualSlices(u8, &first_shared, &second_shared);

    var prepared_first = try PreparedEcdhSecret.init(first_secret);
    defer prepared_first.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &first_shared,
        &try prepared_first.sharedSecret(&second_public),
    );

    const parsed_second = try PublicKey.fromSec1(&second_public);
    const compressed_second = parsed_second.toCompressedSec1();
    try std.testing.expectEqualSlices(
        u8,
        &first_shared,
        &try ecdhSharedSecret(first_secret, &compressed_second),
    );

    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhPublicKey([_]u8{0} ** secret_key_encoded_length),
    );
    try std.testing.expectError(
        error.InvalidSecretKey,
        PreparedEcdhSecret.init([_]u8{0} ** secret_key_encoded_length),
    );
    try std.testing.expectError(
        error.InvalidSecretKey,
        ecdhSharedSecret(
            encodeScalar(scalar_modulus),
            &second_public,
        ),
    );
    var invalid_public = second_public;
    invalid_public[invalid_public.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidPublicKey,
        ecdhSharedSecret(first_secret, &invalid_public),
    );
}

test "P-521 accelerated ECDH matches the portable comb" {
    if (comptime !scalar_mul_x86.enabled) return error.SkipZigTest;
    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..32) |_| {
        var secret = [_]u8{0} ** secret_key_encoded_length;
        var peer_secret = [_]u8{0} ** secret_key_encoded_length;
        for (secret[2..]) |*byte| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            byte.* = @truncate(state);
        }
        for (peer_secret[2..]) |*byte| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            byte.* = @truncate(state);
        }
        secret[secret.len - 1] |= 1;
        peer_secret[peer_secret.len - 1] |= 1;
        const peer_public = try ecdhPublicKey(peer_secret);
        const expected = try legacyEcdhSharedSecret(secret, &peer_public);
        const actual = try ecdhSharedSecret(secret, &peer_public);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }

    const high_secret = encodeScalar(subSmall(scalar_modulus, 1));
    var peer_secret = [_]u8{0} ** secret_key_encoded_length;
    peer_secret[peer_secret.len - 1] = 19;
    const peer_public = try ecdhPublicKey(peer_secret);
    const expected = try legacyEcdhSharedSecret(high_secret, &peer_public);
    const actual = try ecdhSharedSecret(high_secret, &peer_public);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

fn legacyEcdhSharedSecret(
    secret_key_bytes: [secret_key_encoded_length]u8,
    peer_public_key_sec1: []const u8,
) KeyAgreementError![encoded_length]u8 {
    var owned_secret = secret_key_bytes;
    defer std.crypto.secureZero(u8, &owned_secret);
    var scalar = Scalar.fromBytes(&owned_secret) catch
        return error.InvalidSecretKey;
    defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
    const peer = Point.fromSec1(peer_public_key_sec1) catch
        return error.InvalidPublicKey;
    const tables = SecretPoint.prepareEcdhTables(peer);
    var shared_point = SecretPoint.mulEcdhPrepared(scalar.value, &tables);
    defer std.crypto.secureZero(SecretPoint, (&shared_point)[0..1]);
    if (shared_point.z.isZeroChoice() != 0) {
        return error.KeyAgreementFailed;
    }
    var shared_x = shared_point.toAffineX();
    defer std.crypto.secureZero(Fe, (&shared_x)[0..1]);
    return encodeField(shared_x.value);
}

test "P-521 signs an independent fixed-nonce SHA-512 vector" {
    const secret_bytes = decodeHex(
        "00123456789abcdef00112233445566778899aabbccddeeff1021324354657687" ++
            "98a9bacbdcedfe0f112233445566778899aabbccddeeff00123456789abcdef1234",
    );
    const nonce = decodeHex(
        "000deadbeefcafebabefeedface0123456789abcdef102030405060708090a0b0" ++
            "c0d0e0f00112233445566778899aabbccddeeff13579bdf2468ace00123456789ab",
    );
    const expected_public_key = decodeHex(
        "040105107ef0224c55644f85f04a2ba93a356752ceafe7524d9a054ff9d2a3d4" ++
            "5f351af52eec561f61780dbd8984573e5b88705c86af5b384048c4b754e6c431" ++
            "00b1700194b4626848b166a7b0bbc38b903582c1cd4648637800c308b03327a1d" ++
            "6302c4f2f960f1a8eeca948bbe0b750a7f1c201422e535fdf4e74ec8693be07883ea8c008",
    );
    const expected_signature = decodeHex(
        "308187024146c838e1aa6d211483b62ec2507f49e13736e4423d1e7e181c463c" ++
            "4339d8afb943b31b0cd0e42255c39706c6a5649751d983074a578f7c251928a8" ++
            "414ce95f082b024201e8ae0c75f7efcbb9cdb600be86722ff29191c150e635b7" ++
            "ff2c5badcf23bfdee3b67022f1e57da4077386f7e2d5518b44d5433aee789964" ++
            "d5deeb8dc85529d3e0b5",
    );
    const message = "pure Zig P-521 signing oracle";

    var secret_key = try SecretKey.fromBytes(secret_bytes);
    defer secret_key.deinit();
    var key_pair = try KeyPair.fromSecretKey(secret_key);
    defer key_pair.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &expected_public_key,
        &key_pair.public_key.toUncompressedSec1(),
    );
    const expected_compressed = [_]u8{0x02} ++
        expected_public_key[1 .. 1 + encoded_length].*;
    try std.testing.expectEqualSlices(
        u8,
        &expected_compressed,
        &key_pair.public_key.toCompressedSec1(),
    );

    const signature = try key_pair.sign(
        std.crypto.hash.sha2.Sha512,
        message,
        &nonce,
    );
    var encoded: [Signature.der_encoded_length_max]u8 = undefined;
    const der = signature.toDer(&encoded);
    try std.testing.expectEqualSlices(u8, &expected_signature, der);
    var prepared_nonce = try key_pair.prepareNonce(&nonce);
    defer prepared_nonce.deinit();
    try std.testing.expect(prepared_nonce.isReady());
    const prepared_signature = try key_pair.signPrepared(
        std.crypto.hash.sha2.Sha512,
        message,
        &prepared_nonce,
    );
    try std.testing.expect(!prepared_nonce.isReady());
    try std.testing.expect(limbsZero(prepared_nonce.inverse.value));
    try std.testing.expect(limbsZero(prepared_nonce.r.value));
    var prepared_der: [Signature.der_encoded_length_max]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        der,
        prepared_signature.toDer(&prepared_der),
    );
    try std.testing.expectError(
        error.NonceAlreadyUsed,
        key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            &prepared_nonce,
        ),
    );

    var singleton_batch: [1]PreparedNonce = undefined;
    try key_pair.prepareNonceBatch(1, &.{nonce}, &singleton_batch);
    defer singleton_batch[0].deinit();
    var singleton_individual = try key_pair.prepareNonce(&nonce);
    defer singleton_individual.deinit();
    try std.testing.expectEqualSlices(
        u64,
        &singleton_individual.inverse.value,
        &singleton_batch[0].inverse.value,
    );
    try std.testing.expectEqualSlices(
        u64,
        &singleton_individual.r.value,
        &singleton_batch[0].r.value,
    );

    var batch_nonces = [_][encoded_length]u8{nonce} ** 4;
    for (&batch_nonces, 0..) |*batch_nonce, index| {
        batch_nonce[batch_nonce.len - 1] +%= @intCast(index + 1);
    }
    var batch: [batch_nonces.len]PreparedNonce = undefined;
    try key_pair.prepareNonceBatch(
        batch_nonces.len,
        &batch_nonces,
        &batch,
    );
    defer for (&batch) |*item| item.deinit();
    for (&batch, &batch_nonces) |*batch_item, *batch_nonce| {
        var individual = try key_pair.prepareNonce(batch_nonce);
        defer individual.deinit();
        try std.testing.expectEqualSlices(
            u64,
            &individual.inverse.value,
            &batch_item.inverse.value,
        );
        try std.testing.expectEqualSlices(
            u64,
            &individual.r.value,
            &batch_item.r.value,
        );
        const batch_signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            batch_item,
        );
        const individual_signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            &individual,
        );
        try std.testing.expectEqualSlices(
            u8,
            &individual_signature.toBytes(),
            &batch_signature.toBytes(),
        );
    }
    var invalid_batch_nonces = batch_nonces;
    invalid_batch_nonces[2] = [_]u8{0} ** encoded_length;
    try std.testing.expectError(
        error.InvalidNonce,
        key_pair.prepareNonceBatch(
            invalid_batch_nonces.len,
            &invalid_batch_nonces,
            &batch,
        ),
    );
    for (&batch) |*item| {
        try std.testing.expect(!item.isReady());
        try std.testing.expect(limbsZero(item.inverse.value));
        try std.testing.expect(limbsZero(item.r.value));
    }
    var duplicate_batch_nonces = batch_nonces;
    duplicate_batch_nonces[2] = duplicate_batch_nonces[0];
    try std.testing.expectError(
        error.InvalidNonce,
        key_pair.prepareNonceBatch(
            duplicate_batch_nonces.len,
            &duplicate_batch_nonces,
            &batch,
        ),
    );
    for (&batch) |*item| {
        try std.testing.expect(!item.isReady());
        try std.testing.expect(limbsZero(item.inverse.value));
        try std.testing.expect(limbsZero(item.r.value));
    }
    var random_batch: [4]PreparedNonce = undefined;
    try key_pair.prepareRandomNonceBatch(
        random_batch.len,
        std.testing.io,
        &random_batch,
    );
    defer for (&random_batch) |*item| item.deinit();
    for (&random_batch) |*item| {
        try std.testing.expect(item.isReady());
        const random_signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            item,
        );
        var random_encoded: [Signature.der_encoded_length_max]u8 = undefined;
        const random_der = random_signature.toDer(&random_encoded);
        try verify(
            std.crypto.hash.sha2.Sha512,
            message,
            random_der,
            &expected_public_key,
        );
    }
    const raw_signature = signature.toBytes();
    const decoded_signature = try Signature.fromBytes(raw_signature);
    var reencoded: [Signature.der_encoded_length_max]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        der,
        decoded_signature.toDer(&reencoded),
    );
    try verify(
        std.crypto.hash.sha2.Sha512,
        message,
        der,
        &expected_public_key,
    );

    inline for (.{
        std.crypto.hash.sha3.Shake128,
        std.crypto.hash.sha3.Shake256,
    }, 0..) |Hash, index| {
        var shake_nonce = nonce;
        shake_nonce[shake_nonce.len - 1] +%= @intCast(index + 1);
        const shake_signature = try key_pair.sign(
            Hash,
            message,
            &shake_nonce,
        );
        const shake_der = shake_signature.toDer(&encoded);
        try verify(Hash, message, shake_der, &expected_public_key);
    }

    try std.testing.expectError(
        error.InvalidSecretKey,
        SecretKey.fromBytes([_]u8{0} ** secret_key_encoded_length),
    );
    try std.testing.expectError(
        error.InvalidSecretKey,
        SecretKey.fromBytes(encodeScalar(scalar_modulus)),
    );
    try std.testing.expectError(
        error.InvalidNonce,
        key_pair.sign(
            std.crypto.hash.sha2.Sha512,
            message,
            &([_]u8{0} ** encoded_length),
        ),
    );

    var generated = try KeyPair.generate(std.testing.io);
    defer generated.deinit();
    const generated_signature = try generated.sign(
        std.crypto.hash.sha2.Sha512,
        message,
        &nonce,
    );
    const generated_public = generated.public_key.toUncompressedSec1();
    const generated_der = generated_signature.toDer(&encoded);
    try verify(
        std.crypto.hash.sha2.Sha512,
        message,
        generated_der,
        &generated_public,
    );

    const sec1_der = decodeHex(
        "3081dc020101044200123456789abcdef00112233445566778899aabbccddeeff10" ++
            "2132435465768798a9bacbdcedfe0f112233445566778899aabbccddeeff001234" ++
            "56789abcdef1234a00706052b81040023a1818903818600040105107ef0224c556" ++
            "44f85f04a2ba93a356752ceafe7524d9a054ff9d2a3d45f351af52eec561f617" ++
            "80dbd8984573e5b88705c86af5b384048c4b754e6c43100b1700194b4626848b" ++
            "166a7b0bbc38b903582c1cd4648637800c308b03327a1d6302c4f2f960f1a8ee" ++
            "ca948bbe0b750a7f1c201422e535fdf4e74ec8693be07883ea8c008",
    );
    const pkcs8_der = decodeHex(
        "3081f7020100301006072a8648ce3d020106052b810400230481df3081dc020101" ++
            "044200123456789abcdef00112233445566778899aabbccddeeff10213243546576" ++
            "8798a9bacbdcedfe0f112233445566778899aabbccddeeff00123456789abcdef1" ++
            "234a00706052b81040023a1818903818600040105107ef0224c55644f85f04a2b" ++
            "a93a356752ceafe7524d9a054ff9d2a3d45f351af52eec561f61780dbd898457" ++
            "3e5b88705c86af5b384048c4b754e6c43100b1700194b4626848b166a7b0bbc" ++
            "38b903582c1cd4648637800c308b03327a1d6302c4f2f960f1a8eeca948bbe0b" ++
            "750a7f1c201422e535fdf4e74ec8693be07883ea8c008",
    );
    var sec1_key = try KeyPair.fromDer(&sec1_der);
    defer sec1_key.deinit();
    var pkcs8_key = try KeyPair.fromDer(&pkcs8_der);
    defer pkcs8_key.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &expected_public_key,
        &sec1_key.public_key.toUncompressedSec1(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_public_key,
        &pkcs8_key.public_key.toUncompressedSec1(),
    );
    const bare_sec1 = [_]u8{ 0x30, 0x47, 0x02, 0x01, 0x01, 0x04, 0x42 } ++
        secret_bytes;
    var bare_key = try KeyPair.fromDer(&bare_sec1);
    defer bare_key.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &expected_public_key,
        &bare_key.public_key.toUncompressedSec1(),
    );
    var wrong_curve = pkcs8_der;
    wrong_curve[22] ^= 1;
    try std.testing.expectError(
        error.InvalidSecretKey,
        KeyPair.fromDer(&wrong_curve),
    );
    var wrong_public = sec1_der;
    wrong_public[wrong_public.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSecretKey,
        KeyPair.fromDer(&wrong_public),
    );
    var short_scalar = sec1_der;
    short_scalar[7] -= 1;
    try std.testing.expectError(
        error.InvalidSecretKey,
        KeyPair.fromDer(&short_scalar),
    );
    var trailing: [sec1_der.len + 1]u8 = undefined;
    @memcpy(trailing[0..sec1_der.len], &sec1_der);
    trailing[trailing.len - 1] = 0;
    try std.testing.expectError(
        error.InvalidSecretKey,
        KeyPair.fromDer(&trailing),
    );
    bare_key.deinit();
    try std.testing.expect(limbsZero(bare_key.private_scalar.value));
    try std.testing.expect(std.mem.allEqual(u8, &bare_key.secret_key.bytes, 0));
}

test "P-521 rejects malformed SEC1 and DER encodings" {
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const base_sec1 = [_]u8{0x04} ++
        encodeField(generator_x) ++ encodeField(generator_y);
    try std.testing.expectError(
        error.InvalidPublicKey,
        verify(Sha512, "message", "\x30\x06\x02\x01\x01\x02\x01\x01", "\x04"),
    );
    var public_key = [_]u8{0} ** (1 + 2 * encoded_length);
    public_key[0] = 4;
    try std.testing.expectError(
        error.InvalidPublicKey,
        verify(
            Sha512,
            "message",
            "\x30\x06\x02\x01\x01\x02\x01\x01",
            &public_key,
        ),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        verify(
            Sha512,
            "message",
            "\x30\x06\x02\x01\x00\x02\x01\x01",
            &base_sec1,
        ),
    );
}

test "P-521 verifies independent OpenSSL SHA-2 signatures" {
    const public_key = decodeHex(
        "040046a8b6b07a8b3f6297aef1a827ac7bada74f5b9d8743409e1bb84e437657" ++
            "e4c34c14b21c2ce9fe54de5dd7ef65dd9e9abf30e4ec9f12003110f49254aa1f" ++
            "69d1f8013c078f6bb12f820abbbba183230803bea0d050b75a07540f68fb75e68" ++
            "c4551131e18a4d61723459c31ab4ec75dfae9646b4741237e5c39493cae6cab7d" ++
            "b546efbb",
    );
    const compressed_key = decodeHex(
        "030046a8b6b07a8b3f6297aef1a827ac7bada74f5b9d8743409e1bb84e437657" ++
            "e4c34c14b21c2ce9fe54de5dd7ef65dd9e9abf30e4ec9f12003110f49254aa1f" ++
            "69d1f8",
    );
    const sha224_signature = decodeHex(
        "308187024201e7c09ad5ae1219b0276bb1fa5e61db7fd82fc2e9c29de7e6d689" ++
            "b9a9fe177d8cf059c773346a41312fc890af0f92145a70897e84be8ff07fc0c63" ++
            "de151ebecab4502414055cdd9b3fc8c43bb45be3b712378fb3c3c9711be9df211" ++
            "323a4d2f24847774e4649f5a74d5676df3c188ed3cb284bf8d0a4c3170bafea77" ++
            "1dfc9bf273b99e799",
    );
    const sha256_signature = decodeHex(
        "308187024201b20705be58e8cc15d03115fbd9e0ae125a5675ef67dba9e583a917" ++
            "67ab89387a4d6d460fcc119d6f68b9708cac79b18d1872ff6bd564589689080e1a" ++
            "d9749c16040241580f487c7fbd93a59741f5091626518a947d4f44de0e1f8140db" ++
            "2c59abe57c9379b6c90f257c64884d04531e7d5032049dba3779ffcb3da509b0c6" ++
            "a3c40c38bcb7",
    );
    const sha384_signature = decodeHex(
        "3081880242013ce2eca17b3c74e42b4bf0cc49617fb995785b2c37ecfe55ab57d1" ++
            "1a3c444e352a1413a6dcb9da63a8a2a3d1a546e0ba5cbe2890ef03ddbffaf14fd" ++
            "cd78d9d36f202420151568acc23becbdfa766ddab38725dfc9c5362516f63a5197" ++
            "d31d7f90bc999c44ca1ceaa73b699fe08696568cbfa1764990f5a8d9e838b43da" ++
            "c0969c4701b303bc",
    );
    const sha512_signature = decodeHex(
        "3081870242019338c3cd65f87461f34e8c12ca0e5ed10e4b3a38e0874f18125a0" ++
            "83c918d29a372a34c8ef968151b43a8fff9ecf0528507d22c600a40c4f743b68b" ++
            "2875715164ae02411f45257d2da561e4a3492f8dfc1908b82d09d0eab0151d3076" ++
            "fefce5cbf37cbb58757fb5baa6d9c8e634361a764a44554f89b36893ffba5357f5" ++
            "75878664fca001",
    );
    const message = "Vail pure Zig P-521 oracle";
    const parsed_public_key = try PublicKey.fromSec1(&public_key);
    const parsed_compressed_key = try PublicKey.fromSec1(&compressed_key);
    try std.testing.expectEqualSlices(
        u8,
        &public_key,
        &parsed_public_key.toUncompressedSec1(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &public_key,
        &parsed_compressed_key.toUncompressedSec1(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &compressed_key,
        &parsed_public_key.toCompressedSec1(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &compressed_key,
        &parsed_compressed_key.toCompressedSec1(),
    );
    try verify(std.crypto.hash.sha2.Sha224, message, &sha224_signature, &public_key);
    try verify(std.crypto.hash.sha2.Sha256, message, &sha256_signature, &public_key);
    try verify(std.crypto.hash.sha2.Sha384, message, &sha384_signature, &public_key);
    try verify(std.crypto.hash.sha2.Sha512, message, &sha512_signature, &public_key);
    try parsed_public_key.verify(
        std.crypto.hash.sha2.Sha512,
        message,
        &sha512_signature,
    );
    try parsed_compressed_key.verify(
        std.crypto.hash.sha2.Sha512,
        message,
        &sha512_signature,
    );
    const prepared = try PreparedVerifier.init(&public_key);
    const throughput = try ThroughputPreparedVerifier.init(&public_key);
    const compact = try CompactPreparedVerifier.init(&public_key);
    try prepared.verify(
        std.crypto.hash.sha2.Sha512,
        message,
        &sha512_signature,
    );
    try compact.verify(
        std.crypto.hash.sha2.Sha512,
        message,
        &sha512_signature,
    );
    try throughput.verify(
        std.crypto.hash.sha2.Sha512,
        message,
        &sha512_signature,
    );
    try prepared.verify(
        std.crypto.hash.sha2.Sha256,
        message,
        &sha256_signature,
    );
    try verify(
        std.crypto.hash.sha2.Sha512,
        message,
        &sha512_signature,
        &compressed_key,
    );

    try std.testing.expectError(
        error.InvalidSignature,
        verify(
            std.crypto.hash.sha2.Sha512,
            "Vail pure Zig P-521 oraclf",
            &sha512_signature,
            &public_key,
        ),
    );
    var altered_signature = sha512_signature;
    altered_signature[altered_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &altered_signature,
            &public_key,
        ),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        prepared.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &altered_signature,
        ),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        parsed_public_key.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &altered_signature,
        ),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        compact.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &altered_signature,
        ),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        throughput.verify(
            std.crypto.hash.sha2.Sha512,
            message,
            &altered_signature,
        ),
    );
}

test "P-521 verifies independent OpenSSL RFC 8692 SHAKE signatures" {
    const vectors = @import("../../x509/testdata/path_vectors.zig");
    const public_key = decodeHex(vectors.p521_shake_public_key_hex);
    const shake128_signature = decodeHex(
        vectors.p521_shake128_signature_hex,
    );
    var shake256_signature = decodeHex(
        vectors.p521_shake256_signature_hex,
    );
    const message = "Vail RFC 8692 ECDSA SHAKE oracle";
    try verify(
        std.crypto.hash.sha3.Shake128,
        message,
        &shake128_signature,
        &public_key,
    );
    try verify(
        std.crypto.hash.sha3.Shake256,
        message,
        &shake256_signature,
        &public_key,
    );

    shake256_signature[shake256_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verify(
            std.crypto.hash.sha3.Shake256,
            message,
            &shake256_signature,
            &public_key,
        ),
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
