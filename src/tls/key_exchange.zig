//! TLS 1.3 X25519 and secp256r1 key exchange primitives.

const std = @import("std");

pub const secret_len = std.crypto.dh.X25519.secret_length;
pub const public_len = std.crypto.dh.X25519.public_length;
pub const shared_len = std.crypto.dh.X25519.shared_length;

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
    KeyExchangeFailed,
};

pub fn publicKey(secret_key: [secret_len]u8) Error![public_len]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(secret_key) catch
        return error.KeyExchangeFailed;
}

pub const p256 = struct {
    const Curve = std.crypto.ecc.P256;

    pub const secret_len = Curve.scalar.encoded_length;
    pub const public_len = 1 + 2 * Curve.Fe.encoded_length;
    pub const shared_len = Curve.Fe.encoded_length;

    pub fn publicKey(
        secret_key: [p256.secret_len]u8,
    ) Error![p256.public_len]u8 {
        try validateSecret(secret_key);
        const public = Curve.basePoint.mul(
            secret_key,
            .big,
        ) catch return error.KeyExchangeFailed;
        return public.toUncompressedSec1();
    }

    pub fn sharedSecret(
        secret_key: [p256.secret_len]u8,
        peer_public_key: []const u8,
    ) Error![p256.shared_len]u8 {
        try validateSecret(secret_key);
        if (peer_public_key.len != p256.public_len or
            peer_public_key[0] != 0x04)
        {
            return error.InvalidPublicKey;
        }
        const peer = Curve.fromSec1(peer_public_key) catch
            return error.InvalidPublicKey;
        // `mul` uses the constant-time table path; `mulPublic` is for public
        // signature scalars and must not be used with an ECDH private key.
        const shared = peer.mul(secret_key, .big) catch
            return error.KeyExchangeFailed;
        return shared.affineCoordinates().x.toBytes(.big);
    }

    fn validateSecret(
        secret_key: [p256.secret_len]u8,
    ) Error!void {
        const scalar = Curve.scalar.Scalar.fromBytes(
            secret_key,
            .big,
        ) catch return error.InvalidSecretKey;
        if (scalar.isZero()) return error.InvalidSecretKey;
    }
};

pub fn sharedSecret(
    secret_key: [secret_len]u8,
    peer_public_key: []const u8,
) Error![shared_len]u8 {
    if (peer_public_key.len != public_len) {
        return error.InvalidPublicKey;
    }
    return std.crypto.dh.X25519.scalarmult(
        secret_key,
        peer_public_key[0..public_len].*,
    ) catch return error.KeyExchangeFailed;
}
