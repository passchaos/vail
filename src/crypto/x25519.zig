//! X25519 with a constant-time fixed-base public-key path.
//!
//! Linux x86_64 AVX2/BMI2/ADX builds use an in-tree constant-time ladder for
//! arbitrary-point multiplication; other targets use Zig's standard-library
//! ladder. Public-key recovery uses a fixed-base Edwards25519 comb so TLS and
//! HPKE key generation do not pay for a general ladder.

const std = @import("std");
const ed25519_base_adx = @import("ed25519_base_adx.zig");
const x25519_adx = @import("x25519_adx.zig");
const x25519_base_adx = @import("x25519_base_adx.zig");

const StdX25519 = std.crypto.dh.X25519;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Fe = Edwards25519.Fe;
const IdentityElementError = std.crypto.errors.IdentityElementError;
const table_values = @import("x25519_public_tables.zig");

const comb_groups = 5;
const comb_width = 4;
const comb_entries = 1 << comb_width;
const comb_windows = 13;
const selection_lanes = 16;
const SelectionVector = @Vector(selection_lanes, u64);

const CachedPoint = struct {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
};

/// X25519 primitive used by Vail's TLS and HPKE code.
pub const X25519 = struct {
    pub const Curve = StdX25519.Curve;
    pub const secret_length = StdX25519.secret_length;
    pub const public_length = StdX25519.public_length;
    pub const shared_length = StdX25519.shared_length;
    pub const seed_length = StdX25519.seed_length;

    /// Recovers the public key with a constant-time fixed-base comb.
    pub fn recoverPublicKey(
        secret_key: [secret_length]u8,
    ) IdentityElementError![public_length]u8 {
        var secret = secret_key;
        defer std.crypto.secureZero(u8, &secret);
        if (comptime x25519_base_adx.enabled) {
            return x25519_base_adx.scalarMultBase(&secret);
        }
        var scalar = [_]u8{0} ** 33;
        defer std.crypto.secureZero(u8, &scalar);
        scalar[0..secret_length].* = secret;
        Curve.scalar.clamp(scalar[0..secret_length]);

        var result = mulEdwardsBaseExtended(&scalar);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));

        // For an Edwards point (X:Y:Z:T), the corresponding Montgomery
        // coordinate is u = (Z + Y) / (Z - Y).
        const numerator = result.z.add(result.y);
        const denominator = result.z.sub(result.y);
        return numerator.mul(denominator.invert()).toBytes();
    }

    /// Multiply the Edwards25519 base point by an arbitrary little-endian
    /// scalar with a constant-time full-table scan.
    pub fn mulEdwardsBase(
        scalar_bytes: [secret_length]u8,
    ) IdentityElementError!Edwards25519 {
        var scalar = scalar_bytes ++ [_]u8{0};
        defer std.crypto.secureZero(u8, &scalar);
        const result = mulEdwardsBaseExtended(&scalar);
        try result.rejectIdentity();
        return result;
    }

    /// Multiply the Edwards25519 base point and return its canonical encoding.
    pub fn mulEdwardsBaseEncoded(
        scalar_bytes: [secret_length]u8,
    ) IdentityElementError![Edwards25519.encoded_length]u8 {
        return X25519.mulEdwardsBaseEncodedPtr(&scalar_bytes);
    }

    /// Pointer form avoids copying an already caller-owned scalar.
    pub fn mulEdwardsBaseEncodedPtr(
        scalar_bytes: *const [secret_length]u8,
    ) IdentityElementError![Edwards25519.encoded_length]u8 {
        if (comptime ed25519_base_adx.enabled) {
            const result = ed25519_base_adx.scalarMultBase(scalar_bytes);
            if (!result.non_identity) return error.IdentityElement;
            return result.encoded;
        }
        const point = try X25519.mulEdwardsBase(scalar_bytes.*);
        return point.toBytes();
    }

    /// Fixed-base Edwards multiplication when the caller has already proved
    /// that the scalar is non-zero modulo the group order.
    pub fn mulEdwardsBaseEncodedNonZeroPtr(
        scalar_bytes: *const [secret_length]u8,
    ) [Edwards25519.encoded_length]u8 {
        if (comptime ed25519_base_adx.enabled) {
            return ed25519_base_adx.scalarMultBaseNonZero(scalar_bytes);
        }
        return (X25519.mulEdwardsBase(scalar_bytes.*) catch unreachable)
            .toBytes();
    }

    /// Multiplies an arbitrary peer point with a constant-time ladder.
    pub fn scalarmult(
        secret_key: [secret_length]u8,
        public_key: [public_length]u8,
    ) IdentityElementError![shared_length]u8 {
        var scalar = secret_key;
        defer std.crypto.secureZero(u8, &scalar);
        var shared_secret: [shared_length]u8 = undefined;
        try scalarmultInto(&shared_secret, &scalar, &public_key);
        return shared_secret;
    }

    /// Pointer form for callers that already own and erase the private scalar.
    pub fn scalarmultInto(
        shared_secret: *[shared_length]u8,
        secret_key: *const [secret_length]u8,
        public_key: *const [public_length]u8,
    ) IdentityElementError!void {
        if (comptime x25519_adx.enabled) {
            if (!x25519_adx.scalarMultInto(
                shared_secret,
                secret_key,
                public_key,
            )) return error.IdentityElement;
            return;
        }
        shared_secret.* = try StdX25519.scalarmult(secret_key.*, public_key.*);
    }
};

pub const mulEdwardsBase = X25519.mulEdwardsBase;
pub const mulEdwardsBaseEncoded = X25519.mulEdwardsBaseEncoded;
pub const mulEdwardsBaseEncodedPtr = X25519.mulEdwardsBaseEncodedPtr;
pub const mulEdwardsBaseEncodedNonZeroPtr =
    X25519.mulEdwardsBaseEncodedNonZeroPtr;

fn mulEdwardsBaseExtended(scalar: *const [33]u8) Edwards25519 {
    var window: usize = comb_windows - 1;
    var initial_digit: usize = 0;
    inline for (0..comb_width) |column| {
        const bit_index = window + column * comb_windows;
        const bit: u1 = @truncate(
            scalar[bit_index / 8] >> @intCast(bit_index % 8),
        );
        initial_digit |= @as(usize, bit) << column;
    }

    var result = selectInitial(&table_values.initial, initial_digit);
    inline for (1..comb_groups) |group| {
        const digit = combDigit(scalar, window, group);
        result = addCached(
            result,
            selectCached(&table_values.cached[group], digit),
        );
    }

    while (window != 0) {
        window -= 1;
        result = result.dbl();
        inline for (0..comb_groups) |group| {
            const digit = combDigit(scalar, window, group);
            result = addCached(
                result,
                selectCached(&table_values.cached[group], digit),
            );
        }
    }

    return result;
}

inline fn combDigit(
    scalar: *const [33]u8,
    window: usize,
    comptime group: usize,
) usize {
    var digit: usize = 0;
    inline for (0..comb_width) |column| {
        const bit_index = window +
            (group * comb_width + column) * comb_windows;
        const bit: u1 = @truncate(
            scalar[bit_index / 8] >> @intCast(bit_index % 8),
        );
        digit |= @as(usize, bit) << column;
    }
    return digit;
}

fn addCached(point: Edwards25519, cached: CachedPoint) Edwards25519 {
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

noinline fn selectCached(
    table: *const [3][5][comb_entries]u64,
    index: usize,
) CachedPoint {
    const offsets = SelectionVector{
        0, 1, 2,  3,  4,  5,  6,  7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    const zero: SelectionVector = @splat(0);
    const ones: SelectionVector = @splat(std.math.maxInt(u64));
    var masks: [comb_entries / selection_lanes]SelectionVector = undefined;
    inline for (0..comb_entries / selection_lanes) |chunk| {
        const candidates = offsets + @as(
            SelectionVector,
            @splat(chunk * selection_lanes),
        );
        masks[chunk] = @select(
            u64,
            candidates == @as(
                SelectionVector,
                @splat(@as(u64, @intCast(index))),
            ),
            ones,
            zero,
        );
    }

    var result: CachedPoint = undefined;
    inline for (0..5) |limb| {
        result.y_plus_x.limbs[limb] = 0;
        result.y_minus_x.limbs[limb] = 0;
        result.xy2d.limbs[limb] = 0;
        inline for (0..comb_entries / selection_lanes) |chunk| {
            const start = chunk * selection_lanes;
            result.y_plus_x.limbs[limb] |= @reduce(
                .Or,
                table[0][limb][start..][0..selection_lanes].* & masks[chunk],
            );
            result.y_minus_x.limbs[limb] |= @reduce(
                .Or,
                table[1][limb][start..][0..selection_lanes].* & masks[chunk],
            );
            result.xy2d.limbs[limb] |= @reduce(
                .Or,
                table[2][limb][start..][0..selection_lanes].* & masks[chunk],
            );
        }
    }
    return result;
}

noinline fn selectInitial(
    table: *const [3][5][comb_entries]u64,
    index: usize,
) Edwards25519 {
    const offsets = SelectionVector{
        0, 1, 2,  3,  4,  5,  6,  7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    const zero: SelectionVector = @splat(0);
    const ones: SelectionVector = @splat(std.math.maxInt(u64));
    var masks: [comb_entries / selection_lanes]SelectionVector = undefined;
    inline for (0..comb_entries / selection_lanes) |chunk| {
        const candidates = offsets + @as(
            SelectionVector,
            @splat(chunk * selection_lanes),
        );
        masks[chunk] = @select(
            u64,
            candidates == @as(
                SelectionVector,
                @splat(@as(u64, @intCast(index))),
            ),
            ones,
            zero,
        );
    }

    var result = Edwards25519.identityElement;
    inline for (0..5) |limb| {
        result.x.limbs[limb] = 0;
        result.y.limbs[limb] = 0;
        result.t.limbs[limb] = 0;
        inline for (0..comb_entries / selection_lanes) |chunk| {
            const start = chunk * selection_lanes;
            result.x.limbs[limb] |= @reduce(
                .Or,
                table[0][limb][start..][0..selection_lanes].* & masks[chunk],
            );
            result.y.limbs[limb] |= @reduce(
                .Or,
                table[1][limb][start..][0..selection_lanes].* & masks[chunk],
            );
            result.t.limbs[limb] |= @reduce(
                .Or,
                table[2][limb][start..][0..selection_lanes].* & masks[chunk],
            );
        }
    }
    return result;
}

test "fixed-base recovery matches RFC 7748 key pairs" {
    const alice_secret = try decode32(
        "77076d0a7318a57d3c16c17251b26645" ++
            "df4c2f87ebc0992ab177fba51db92c2a",
    );
    const alice_public = try decode32(
        "8520f0098930a754748b7ddcb43ef75a" ++
            "0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
    const bob_secret = try decode32(
        "5dab087e624a8a4b79e17f8b83800ee6" ++
            "6f3bb1292618b6fd1c2f8b27ff88e0eb",
    );
    const bob_public = try decode32(
        "de9edb7d7b7dc1b4d35b61c2ece43537" ++
            "3f8343c85b78674dadfc7e146f882b4f",
    );

    try std.testing.expectEqual(
        alice_public,
        try X25519.recoverPublicKey(alice_secret),
    );
    try std.testing.expectEqual(
        bob_public,
        try X25519.recoverPublicKey(bob_secret),
    );
    const shared_secret = try decode32(
        "4a5d9d5ba4ce2de1728e3bf480350f25" ++
            "e07e21c947d19e3376f09b3c1e161742",
    );
    try std.testing.expectEqual(
        shared_secret,
        try X25519.scalarmult(alice_secret, bob_public),
    );
    try std.testing.expectEqual(
        shared_secret,
        try X25519.scalarmult(bob_secret, alice_public),
    );
}

test "fixed-base recovery matches the Montgomery ladder" {
    const boundary_keys = [_][X25519.secret_length]u8{
        [_]u8{0x00} ** X25519.secret_length,
        [_]u8{0xff} ** X25519.secret_length,
        [_]u8{0x55} ** X25519.secret_length,
        [_]u8{0xaa} ** X25519.secret_length,
        [_]u8{0x88} ** X25519.secret_length,
        [_]u8{0x78} ** X25519.secret_length,
        [_]u8{0x08} ++ [_]u8{0} ** (X25519.secret_length - 1),
    };
    for (boundary_keys) |secret_key| {
        try expectMatchesLadder(secret_key);
    }

    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..256) |_| {
        var secret_key: [X25519.secret_length]u8 = undefined;
        for (0..4) |word| {
            std.mem.writeInt(
                u64,
                secret_key[word * 8 ..][0..8],
                splitMix64(&state),
                .little,
            );
        }
        try expectMatchesLadder(secret_key);
    }
}

test "fixed-base Edwards multiplication matches Zig std" {
    const boundary_scalars = [_][32]u8{
        [_]u8{0x00} ** 32,
        [_]u8{0xff} ** 32,
        [_]u8{0x55} ** 32,
        [_]u8{0xaa} ** 32,
    };
    for (boundary_scalars) |scalar| {
        try expectEdwardsBaseMatches(scalar);
    }

    var state: u64 = 0x1319_8a2e_0370_7344;
    for (0..256) |_| {
        var scalar: [32]u8 = undefined;
        for (0..4) |word| {
            state +%= 0x9e37_79b9_7f4a_7c15;
            var value = state;
            value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
            value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
            value ^= value >> 31;
            std.mem.writeInt(
                u64,
                scalar[word * 8 ..][0..8],
                value,
                .little,
            );
        }
        try expectEdwardsBaseMatches(scalar);
    }
}

test "arbitrary-point X25519 matches Zig std" {
    const boundary_scalars = [_][32]u8{
        [_]u8{0x00} ** 32,
        [_]u8{0xff} ** 32,
        [_]u8{0x55} ** 32,
        [_]u8{0xaa} ** 32,
    };
    const boundary_points = [_][32]u8{
        [_]u8{0x00} ** 32,
        [_]u8{0xff} ** 32,
        [_]u8{0x55} ** 32,
        [_]u8{0xaa} ** 32,
        [_]u8{9} ++ [_]u8{0} ** 31,
    };
    for (boundary_scalars) |scalar| {
        for (boundary_points) |point| {
            try expectScalarMultMatches(scalar, point);
        }
    }

    var state: u64 = 0x082e_fa98_ec4e_6c89;
    for (0..512) |_| {
        var scalar: [32]u8 = undefined;
        var point: [32]u8 = undefined;
        for (0..4) |word| {
            std.mem.writeInt(
                u64,
                scalar[word * 8 ..][0..8],
                splitMix64(&state),
                .little,
            );
            std.mem.writeInt(
                u64,
                point[word * 8 ..][0..8],
                splitMix64(&state),
                .little,
            );
        }
        try expectScalarMultMatches(scalar, point);
    }
}

test "RFC 7748 X25519 iterated vector" {
    const initial = [_]u8{9} ++ [_]u8{0} ** 31;
    const expected = try decode32(
        "684cf59ba83309552800ef566f2f4d3c" ++
            "1c3887c49360e3875f2eb94d99532c51",
    );
    var scalar = initial;
    var point = initial;
    for (0..1_000) |_| {
        const output = try X25519.scalarmult(scalar, point);
        point = scalar;
        scalar = output;
    }
    try std.testing.expectEqual(expected, scalar);
}

fn expectEdwardsBaseMatches(scalar: [32]u8) !void {
    const expected = Edwards25519.basePoint.mul(scalar) catch |err| {
        try std.testing.expectError(err, mulEdwardsBase(scalar));
        try std.testing.expectError(err, mulEdwardsBaseEncoded(scalar));
        return;
    };
    const actual = try mulEdwardsBase(scalar);
    try std.testing.expectEqual(expected.toBytes(), actual.toBytes());
    try std.testing.expectEqual(
        expected.toBytes(),
        try mulEdwardsBaseEncoded(scalar),
    );
}

fn expectMatchesLadder(secret_key: [X25519.secret_length]u8) !void {
    const expected = try StdX25519.recoverPublicKey(secret_key);
    const actual = try X25519.recoverPublicKey(secret_key);
    try std.testing.expectEqual(expected, actual);
}

fn expectScalarMultMatches(
    secret_key: [X25519.secret_length]u8,
    public_key: [X25519.public_length]u8,
) !void {
    const expected = StdX25519.scalarmult(secret_key, public_key) catch |err| {
        try std.testing.expectError(
            err,
            X25519.scalarmult(secret_key, public_key),
        );
        var actual_into: [X25519.shared_length]u8 = undefined;
        try std.testing.expectError(
            err,
            X25519.scalarmultInto(&actual_into, &secret_key, &public_key),
        );
        return;
    };
    const actual = try X25519.scalarmult(secret_key, public_key);
    try std.testing.expectEqual(expected, actual);
    var actual_into: [X25519.shared_length]u8 = undefined;
    try X25519.scalarmultInto(&actual_into, &secret_key, &public_key);
    try std.testing.expectEqual(expected, actual_into);
}

fn splitMix64(state: *u64) u64 {
    state.* +%= 0x9e37_79b9_7f4a_7c15;
    var value = state.*;
    value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
    return value ^ (value >> 31);
}

fn decode32(encoded: *const [64:0]u8) ![32]u8 {
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
}
