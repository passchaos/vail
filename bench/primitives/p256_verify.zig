const std = @import("std");
const vail = @import("vail");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P256 = std.crypto.ecc.P256;
const Scalar = P256.scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;
const iterations: usize = 20_000;
const warmup_iterations: usize = 32;

pub fn main(init: std.process.Init) !void {
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Ecdsa.KeyPair.seed_length,
    );
    var encoded_public_key = key_pair.public_key.toUncompressedSec1();
    std.mem.doNotOptimizeAway(&encoded_public_key);
    var public_key = try Ecdsa.PublicKey.fromSec1(&encoded_public_key);
    std.mem.doNotOptimizeAway(&public_key);
    const message = "Vail P-256 verification benchmark input";
    var signature = try key_pair.sign(message, null);
    var runtime_zero: u8 = 0;
    const volatile_zero: *volatile u8 = &runtime_zero;
    signature.r[0] ^= volatile_zero.*;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(message, &digest, .{});
    std.mem.doNotOptimizeAway(&digest);

    try signature.verifyPrehashed(digest, public_key);
    try verifyDoubleBase(signature, digest, public_key);
    try verifyProjective(signature, digest, public_key);
    try vail.crypto.p256.verifyPrehashed(
        Sha256,
        signature,
        digest,
        public_key,
    );
    var prepared = try vail.crypto.p256.PreparedVerifier.init(public_key.p);
    std.mem.doNotOptimizeAway(&prepared);
    try prepared.verify(Sha256, message, signature);

    const r = try Scalar.fromBytes(signature.r, .big);
    const s = try Scalar.fromBytes(signature.s, .big);
    const z = scalarFromDigest(digest);
    const s_inverse = s.invert();
    const v1 = z.mul(s_inverse).toBytes(.little);
    const v2 = r.mul(s_inverse).toBytes(.little);
    const projective = try P256.mulDoubleBasePublic(
        P256.basePoint,
        v1,
        public_key.p,
        v2,
        .little,
    );

    var checksum: u64 = 0;
    for (0..warmup_iterations) |_| {
        try signature.verifyPrehashed(digest, public_key);
    }
    var start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try signature.verifyPrehashed(digest, public_key);
    }
    const std_verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        try verifyDoubleBase(signature, digest, public_key);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try verifyDoubleBase(signature, digest, public_key);
    }
    const double_verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        try verifyProjective(signature, digest, public_key);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try verifyProjective(signature, digest, public_key);
    }
    const projective_verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        try vail.crypto.p256.verifyPrehashed(
            Sha256,
            signature,
            digest,
            public_key,
        );
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try vail.crypto.p256.verifyPrehashed(
            Sha256,
            signature,
            digest,
            public_key,
        );
    }
    const vail_verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const verifier = try vail.crypto.p256.PreparedVerifier.init(
            public_key.p,
        );
        std.mem.doNotOptimizeAway(&verifier);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        const verifier = try vail.crypto.p256.PreparedVerifier.init(
            public_key.p,
        );
        std.mem.doNotOptimizeAway(&verifier);
    }
    const prepare_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        try prepared.verify(Sha256, message, signature);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&signature);
        try prepared.verify(Sha256, message, signature);
    }
    const prepared_verify_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const inverse = s.invert();
        std.mem.doNotOptimizeAway(&inverse);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const inverse = s.invert();
        checksum +%= inverse.toBytes(.little)[iteration % 32];
    }
    const scalar_inverse_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const inverse = vail.crypto.p256.testing.invertPublic(s);
        std.mem.doNotOptimizeAway(&inverse);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const inverse = vail.crypto.p256.testing.invertPublic(s);
        checksum +%= inverse.toBytes(.little)[iteration % 32];
    }
    const vail_scalar_inverse_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const point = try P256.mulDoubleBasePublic(
            P256.basePoint,
            v1,
            public_key.p,
            v2,
            .little,
        );
        std.mem.doNotOptimizeAway(&point);
    }
    start = nowNs(init.io);
    for (0..iterations) |_| {
        const point = try P256.mulDoubleBasePublic(
            P256.basePoint,
            v1,
            public_key.p,
            v2,
            .little,
        );
        std.mem.doNotOptimizeAway(&point);
    }
    const double_mul_ns = nowNs(init.io) -| start;

    for (0..warmup_iterations) |_| {
        const affine = projective.affineCoordinates();
        std.mem.doNotOptimizeAway(&affine);
    }
    start = nowNs(init.io);
    for (0..iterations) |iteration| {
        const affine = projective.affineCoordinates();
        checksum +%= affine.x.toBytes(.big)[iteration % 32];
    }
    const affine_ns = nowNs(init.io) -| start;

    std.debug.print(
        "p256-std-verify={d} ns/op double-verify={d} ns/op " ++
            "projective-verify={d} ns/op " ++
            "vail-verify={d} ns/op " ++
            "prepare={d} ns/op prepared-verify={d} ns/op " ++
            "scalar-inverse={d} ns/op double-mul={d} ns/op " ++
            "vail-scalar-inverse={d} ns/op " ++
            "affine={d} ns/op checksum={d}\n",
        .{
            std_verify_ns / iterations,
            double_verify_ns / iterations,
            projective_verify_ns / iterations,
            vail_verify_ns / iterations,
            prepare_ns / iterations,
            prepared_verify_ns / iterations,
            scalar_inverse_ns / iterations,
            double_mul_ns / iterations,
            vail_scalar_inverse_ns / iterations,
            affine_ns / iterations,
            checksum,
        },
    );
}

fn verifyDoubleBase(
    signature: Ecdsa.Signature,
    digest: [Sha256.digest_length]u8,
    public_key: Ecdsa.PublicKey,
) !void {
    const r = try Scalar.fromBytes(signature.r, .big);
    const s = try Scalar.fromBytes(signature.s, .big);
    if (r.isZero() or s.isZero()) return error.IdentityElement;
    const z = scalarFromDigest(digest);
    if (z.isZero()) return error.SignatureVerificationFailed;
    const s_inverse = s.invert();
    const v1 = z.mul(s_inverse).toBytes(.little);
    const v2 = r.mul(s_inverse).toBytes(.little);
    const point = try P256.mulDoubleBasePublic(
        P256.basePoint,
        v1,
        public_key.p,
        v2,
        .little,
    );
    const x = point.affineCoordinates().x.toBytes(.big);
    if (!r.equivalent(scalarFromDigest(x))) {
        return error.SignatureVerificationFailed;
    }
}

fn verifyProjective(
    signature: Ecdsa.Signature,
    digest: [Sha256.digest_length]u8,
    public_key: Ecdsa.PublicKey,
) !void {
    const r = try Scalar.fromBytes(signature.r, .big);
    const s = try Scalar.fromBytes(signature.s, .big);
    if (r.isZero() or s.isZero()) return error.IdentityElement;
    const z = scalarFromDigest(digest);
    if (z.isZero()) return error.SignatureVerificationFailed;
    const s_inverse = s.invert();
    const v1 = z.mul(s_inverse).toBytes(.little);
    const v2 = r.mul(s_inverse).toBytes(.little);
    const point = try P256.mulDoubleBasePublic(
        P256.basePoint,
        v1,
        public_key.p,
        v2,
        .little,
    );

    const r_field = try P256.Fe.fromBytes(signature.r, .big);
    if (point.x.equivalent(r_field.mul(point.z))) return;
    const r_int = std.mem.readInt(u256, &signature.r, .big);
    const p_minus_n = P256.Fe.field_order - P256.scalar.field_order;
    if (r_int < p_minus_n) {
        var r_plus_n_bytes: [32]u8 = undefined;
        std.mem.writeInt(
            u256,
            &r_plus_n_bytes,
            r_int + P256.scalar.field_order,
            .big,
        );
        const r_plus_n = try P256.Fe.fromBytes(r_plus_n_bytes, .big);
        if (point.x.equivalent(r_plus_n.mul(point.z))) return;
    }
    return error.SignatureVerificationFailed;
}

fn scalarFromDigest(bytes: [32]u8) Scalar {
    return Scalar.fromBytes48([_]u8{0} ** 16 ++ bytes, .big);
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
