//! SM2 public-key signature verification (GB/T 32918.2-2016).
//!
//! The local AWS-LC checkout currently defines `OPENSSL_NO_SM2`, so Vail keeps
//! a portable verifier here as the first SM2 building block.  The code covers
//! the SM2-specific ZA binding (`user_id || curve || public key`) and the SM2
//! verification equation; secret-key signing is intentionally left for a later
//! constant-time/provider-backed slice.

const std = @import("std");
const sm3 = @import("sm3.zig");

pub const scalar_len = 32;
pub const public_key_len = 65;
pub const default_user_id = "1234567812345678";

pub const Error = error{
    InvalidPublicKey,
    InvalidSignature,
    InvalidUserId,
    SignatureVerificationFailed,
};

pub const SecretKey = struct {
    bytes: [scalar_len]u8,

    pub fn fromBytes(bytes: [scalar_len]u8) Error!SecretKey {
        const value = std.mem.readInt(u256, &bytes, .big);
        // SM2 signatures require (1 + d)^-1 modulo n, so d = n - 1 is
        // unusable even though ordinary scalar multiplication could encode it.
        if (value == 0 or value >= order_n - 1) {
            return error.InvalidSignature;
        }
        return .{ .bytes = bytes };
    }

    fn scalar(self: SecretKey) u256 {
        return std.mem.readInt(u256, &self.bytes, .big);
    }
};

pub const PublicKey = struct {
    point: Point,

    pub fn fromUncompressedSec1(bytes: []const u8) Error!PublicKey {
        if (bytes.len != public_key_len or bytes[0] != 0x04) {
            return error.InvalidPublicKey;
        }
        const x = std.mem.readInt(u256, bytes[1..33], .big);
        const y = std.mem.readInt(u256, bytes[33..65], .big);
        if (x >= field_p or y >= field_p) return error.InvalidPublicKey;
        const point = Point{ .x = x, .y = y };
        if (!point.isOnCurve()) return error.InvalidPublicKey;
        return .{ .point = point };
    }

    pub fn toUncompressedSec1(self: PublicKey) [public_key_len]u8 {
        var out: [public_key_len]u8 = undefined;
        out[0] = 0x04;
        std.mem.writeInt(u256, out[1..33], self.point.x, .big);
        std.mem.writeInt(u256, out[33..65], self.point.y, .big);
        return out;
    }
};

pub const KeyPair = struct {
    secret_key: SecretKey,
    public_key: PublicKey,

    pub fn fromSecretKey(secret_key: SecretKey) Error!KeyPair {
        const public_point = scalarMult(secret_key.scalar(), base_point);
        if (public_point.infinity or !public_point.isOnCurve()) {
            return error.InvalidPublicKey;
        }
        return .{
            .secret_key = secret_key,
            .public_key = .{ .point = public_point },
        };
    }

    pub fn sign(
        self: KeyPair,
        user_id: []const u8,
        message: []const u8,
        nonce: [scalar_len]u8,
    ) Error!Signature {
        return signDigest(
            self.secret_key,
            try digest(user_id, self.public_key, message),
            nonce,
        );
    }
};

pub const Signature = struct {
    pub const der_encoded_length_max = 72;

    r: u256,
    s: u256,

    pub fn fromRaw(bytes: [64]u8) Error!Signature {
        return init(
            std.mem.readInt(u256, bytes[0..32], .big),
            std.mem.readInt(u256, bytes[32..64], .big),
        );
    }

    pub fn fromDer(der: []const u8) Error!Signature {
        var pos: usize = 0;
        if (readByte(der, &pos) != 0x30) return error.InvalidSignature;
        const sequence_len = try readDerLen(der, &pos);
        if (sequence_len != der.len - pos) return error.InvalidSignature;
        const r = try readDerInt(der, &pos);
        const s = try readDerInt(der, &pos);
        if (pos != der.len) return error.InvalidSignature;
        return init(r, s);
    }

    pub fn toRaw(self: Signature) [64]u8 {
        var out: [64]u8 = undefined;
        std.mem.writeInt(u256, out[0..32], self.r, .big);
        std.mem.writeInt(u256, out[32..64], self.s, .big);
        return out;
    }

    pub fn toDer(self: Signature, buffer: *[der_encoded_length_max]u8) []const u8 {
        var offset: usize = 2;
        offset = writeDerInt(buffer, offset, self.r);
        offset = writeDerInt(buffer, offset, self.s);
        buffer[0] = 0x30;
        buffer[1] = @intCast(offset - 2);
        return buffer[0..offset];
    }

    fn init(r: u256, s: u256) Error!Signature {
        if (r == 0 or r >= order_n or s == 0 or s >= order_n) {
            return error.InvalidSignature;
        }
        return .{ .r = r, .s = s };
    }
};

pub fn signDigest(
    secret_key: SecretKey,
    message_digest: sm3.Digest,
    nonce: [scalar_len]u8,
) Error!Signature {
    const d = secret_key.scalar();
    const k = std.mem.readInt(u256, &nonce, .big);
    if (k == 0 or k >= order_n) return error.InvalidSignature;

    const point = scalarMult(k, base_point);
    if (point.infinity) return error.InvalidSignature;
    const e = std.mem.readInt(u256, &message_digest, .big) % order_n;
    const r = addMod(e, point.x % order_n, order_n);
    if (r == 0 or addMod(r, k, order_n) == 0) {
        return error.InvalidSignature;
    }

    const rd = mulMod(r, d, order_n);
    const numerator = subMod(k, rd, order_n);
    const denominator = addMod(1, d, order_n);
    const s = mulMod(invMod(denominator, order_n), numerator, order_n);
    return Signature.init(r, s);
}

pub fn za(user_id: []const u8, public_key: PublicKey) Error!sm3.Digest {
    if (user_id.len > std.math.maxInt(u16) / 8) return error.InvalidUserId;
    var h = sm3.Hash.init(.{});
    var entl: [2]u8 = undefined;
    std.mem.writeInt(u16, &entl, @intCast(user_id.len * 8), .big);
    h.update(&entl);
    h.update(user_id);
    updateInt(&h, curve_a);
    updateInt(&h, curve_b);
    updateInt(&h, base_point.x);
    updateInt(&h, base_point.y);
    updateInt(&h, public_key.point.x);
    updateInt(&h, public_key.point.y);
    var out: sm3.Digest = undefined;
    h.final(&out);
    return out;
}

pub fn digest(
    user_id: []const u8,
    public_key: PublicKey,
    message: []const u8,
) Error!sm3.Digest {
    const z = try za(user_id, public_key);
    var h = sm3.Hash.init(.{});
    h.update(&z);
    h.update(message);
    var out: sm3.Digest = undefined;
    h.final(&out);
    return out;
}

pub fn verify(
    user_id: []const u8,
    public_key: PublicKey,
    message: []const u8,
    signature: Signature,
) Error!void {
    return verifyDigest(
        public_key,
        try digest(user_id, public_key, message),
        signature,
    );
}

pub fn verifyDigest(
    public_key: PublicKey,
    message_digest: sm3.Digest,
    signature: Signature,
) Error!void {
    const e = std.mem.readInt(u256, &message_digest, .big) % order_n;
    const t = addMod(signature.r, signature.s, order_n);
    if (t == 0) return error.SignatureVerificationFailed;

    const s_g = scalarMult(signature.s, base_point);
    const t_p = scalarMult(t, public_key.point);
    const sum = pointAdd(s_g, t_p);
    if (sum.infinity) return error.SignatureVerificationFailed;

    const r = addMod(e, sum.x % order_n, order_n);
    if (r != signature.r) return error.SignatureVerificationFailed;
}

const Point = struct {
    x: u256 = 0,
    y: u256 = 0,
    infinity: bool = false,

    fn isOnCurve(self: Point) bool {
        if (self.infinity) return false;
        const y2 = mulMod(self.y, self.y, field_p);
        const x2 = mulMod(self.x, self.x, field_p);
        const x3 = mulMod(x2, self.x, field_p);
        const ax = mulMod(curve_a, self.x, field_p);
        const rhs = addMod(addMod(x3, ax, field_p), curve_b, field_p);
        return y2 == rhs;
    }
};

fn pointAdd(p: Point, q: Point) Point {
    if (p.infinity) return q;
    if (q.infinity) return p;
    if (p.x == q.x) {
        if (addMod(p.y, q.y, field_p) == 0) return .{ .infinity = true };
        return pointDouble(p);
    }
    const numerator = subMod(q.y, p.y, field_p);
    const denominator = subMod(q.x, p.x, field_p);
    const lambda = mulMod(numerator, invMod(denominator, field_p), field_p);
    const x3 = subMod(subMod(mulMod(lambda, lambda, field_p), p.x, field_p), q.x, field_p);
    const y3 = subMod(mulMod(lambda, subMod(p.x, x3, field_p), field_p), p.y, field_p);
    return .{ .x = x3, .y = y3 };
}

fn pointDouble(p: Point) Point {
    if (p.infinity or p.y == 0) return .{ .infinity = true };
    const x2 = mulMod(p.x, p.x, field_p);
    const numerator = addMod(mulMod(3, x2, field_p), curve_a, field_p);
    const denominator = mulMod(2, p.y, field_p);
    const lambda = mulMod(numerator, invMod(denominator, field_p), field_p);
    const x3 = subMod(mulMod(lambda, lambda, field_p), mulMod(2, p.x, field_p), field_p);
    const y3 = subMod(mulMod(lambda, subMod(p.x, x3, field_p), field_p), p.y, field_p);
    return .{ .x = x3, .y = y3 };
}

fn scalarMult(scalar: u256, point: Point) Point {
    var out = Point{ .infinity = true };
    var bit_index: u9 = 256;
    while (bit_index > 0) {
        bit_index -= 1;
        out = pointDouble(out);
        if (((scalar >> @intCast(bit_index)) & 1) != 0) {
            out = pointAdd(out, point);
        }
    }
    return out;
}

fn updateInt(h: *sm3.Hash, value: u256) void {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    h.update(&bytes);
}

fn addMod(a: u256, b: u256, modulus: u256) u256 {
    return @intCast((@as(u512, a) + @as(u512, b)) % @as(u512, modulus));
}

fn subMod(a: u256, b: u256, modulus: u256) u256 {
    if (a >= b) return a - b;
    return @intCast((@as(u512, modulus) + @as(u512, a) - @as(u512, b)) % @as(u512, modulus));
}

fn mulMod(a: u256, b: u256, modulus: u256) u256 {
    return @intCast((@as(u512, a) * @as(u512, b)) % @as(u512, modulus));
}

fn invMod(value: u256, modulus: u256) u256 {
    std.debug.assert(value != 0);
    return powMod(value, modulus - 2, modulus);
}

fn powMod(base: u256, exponent: u256, modulus: u256) u256 {
    var result: u256 = 1;
    var b = base % modulus;
    var e = exponent;
    while (e != 0) : (e >>= 1) {
        if ((e & 1) != 0) result = mulMod(result, b, modulus);
        b = mulMod(b, b, modulus);
    }
    return result;
}

fn readByte(bytes: []const u8, pos: *usize) u8 {
    if (pos.* >= bytes.len) return 0xff;
    defer pos.* += 1;
    return bytes[pos.*];
}

fn readDerLen(bytes: []const u8, pos: *usize) Error!usize {
    const first = readByte(bytes, pos);
    if (first < 0x80) return first;
    const len_len = first & 0x7f;
    if (len_len == 0 or len_len > 2 or pos.* + len_len > bytes.len) {
        return error.InvalidSignature;
    }
    var len: usize = 0;
    for (0..len_len) |_| {
        len = (len << 8) | readByte(bytes, pos);
    }
    if (len < 0x80) return error.InvalidSignature;
    return len;
}

fn readDerInt(bytes: []const u8, pos: *usize) Error!u256 {
    if (readByte(bytes, pos) != 0x02) return error.InvalidSignature;
    const len = try readDerLen(bytes, pos);
    if (len == 0 or len > 33 or pos.* + len > bytes.len) {
        return error.InvalidSignature;
    }
    const int_bytes = bytes[pos.* .. pos.* + len];
    pos.* += len;
    if (int_bytes.len == 33) {
        if (int_bytes[0] != 0 or int_bytes[1] < 0x80) {
            return error.InvalidSignature;
        }
        return std.mem.readInt(u256, int_bytes[1..33], .big);
    }
    if (int_bytes[0] >= 0x80) return error.InvalidSignature;
    if (int_bytes.len > 1 and int_bytes[0] == 0 and int_bytes[1] < 0x80) {
        return error.InvalidSignature;
    }
    var padded: [32]u8 = [_]u8{0} ** 32;
    @memcpy(padded[32 - int_bytes.len ..], int_bytes);
    return std.mem.readInt(u256, &padded, .big);
}

fn writeDerInt(buffer: *[Signature.der_encoded_length_max]u8, offset: usize, value: u256) usize {
    var raw: [32]u8 = undefined;
    std.mem.writeInt(u256, &raw, value, .big);
    const trimmed = std.mem.trimStart(u8, &raw, &.{0});
    const integer_bytes = if (trimmed.len == 0) raw[31..32] else trimmed;
    var pos = offset;
    buffer[pos] = 0x02;
    pos += 1;
    const needs_sign_pad = (integer_bytes[0] & 0x80) != 0;
    buffer[pos] = @intCast(integer_bytes.len + @intFromBool(needs_sign_pad));
    pos += 1;
    if (needs_sign_pad) {
        buffer[pos] = 0;
        pos += 1;
    }
    @memcpy(buffer[pos..][0..integer_bytes.len], integer_bytes);
    return pos + integer_bytes.len;
}

const field_p: u256 = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff;
const curve_a: u256 = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc;
const curve_b: u256 = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93;
const order_n: u256 = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123;
const base_point = Point{
    .x = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7,
    .y = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0,
};

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var output: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, hex) catch unreachable;
    return output;
}

test "SM2 ZA matches the official example vector" {
    const public = try PublicKey.fromUncompressedSec1(&decodeHex(
        "04" ++
            "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020" ++
            "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
    ));
    const expected = decodeHex(
        "b2e14c5c79c6df5b85f4fe7ed8db7a262b9da7e07ccb0ea9f4747b8ccda8a4f3",
    );
    const actual = try za(default_user_id, public);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "SM2 verifies the official raw signature example" {
    const public = try PublicKey.fromUncompressedSec1(&decodeHex(
        "04" ++
            "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020" ++
            "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
    ));
    const signature = try Signature.fromRaw(decodeHex(
        "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3" ++
            "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa",
    ));
    try verify(default_user_id, public, "message digest", signature);
}

test "SM2 signs the official raw signature example with a fixed nonce" {
    const secret = try SecretKey.fromBytes(decodeHex(
        "3945208f7b2133b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
    ));
    const key_pair = try KeyPair.fromSecretKey(secret);
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(
            "04" ++
                "7b61ca523b80c6ac4ba89becb46a68a991aebe115aa108c68bb0214f187309e0" ++
                "20cd660da7edcbb94f160966c5a9dd041787d2d75df00a2a3686816059cf2849",
        ),
        &key_pair.public_key.toUncompressedSec1(),
    );
    const signature = try key_pair.sign(
        default_user_id,
        "message digest",
        decodeHex(
            "59276e27d506861a16680f3ad9c02dccccef3cc1fa3cdbe4ce6d54b80deac1bc",
        ),
    );
    try verify(default_user_id, key_pair.public_key, "message digest", signature);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verify(default_user_id, key_pair.public_key, "tampered", signature),
    );
    var der: [Signature.der_encoded_length_max]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &decodeHex(
            "3046022100ea5abdb2ccd97b89605c4d8b906b4cea264f400928b8df331fc9258fae5ad83d" ++
                "022100942a37ee941c502dc5a69665b0d430702a67dbc2566307772b92b86bfc909638",
        ),
        signature.toDer(&der),
    );
}

test "SM2 verifies an OpenSSL-generated DER signature" {
    const public = try PublicKey.fromUncompressedSec1(&decodeHex(
        "04" ++
            "483438408e88ac41575c7d2fc8d751fc21c081d43e83daa5cca7b1ad0e35b4" ++
            "cb3b333dac7fd549beb897d7b77af2130d36eff2e5cd64f0fbf9d6e165eaf232f5",
    ));
    const signature = try Signature.fromDer(&decodeHex(
        "30440220623193ce4f69eff7c81083ea1df02d33d1848d34b908d66c4ea67f393d6eced8" ++
            "0220332a10d44a38ce301e5c7e2a91243c9ea04b6e43c0d7f71f60f6311955efb1da",
    ));
    try verify(default_user_id, public, "Vail SM2 test message", signature);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verify("other-id", public, "Vail SM2 test message", signature),
    );
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verify(default_user_id, public, "tampered", signature),
    );
}
