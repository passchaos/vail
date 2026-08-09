//! TLS 1.3 X25519 key exchange primitives.

const std = @import("std");

pub const secret_len = std.crypto.dh.X25519.secret_length;
pub const public_len = std.crypto.dh.X25519.public_length;
pub const shared_len = std.crypto.dh.X25519.shared_length;

pub const Error = error{
    InvalidPublicKey,
    KeyExchangeFailed,
};

pub fn publicKey(secret_key: [secret_len]u8) Error![public_len]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(secret_key) catch
        return error.KeyExchangeFailed;
}

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
