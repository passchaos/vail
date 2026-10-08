//! TLS X25519MLKEM768 hybrid key exchange.
//!
//! This implements the TLS named group registered as `0x11ec`. Its wire
//! format and secret combiner deliberately differ from `std.crypto`'s generic
//! C2PRI hybrid KEM:
//!
//! - client share: ML-KEM-768 encapsulation key || X25519 public key
//! - server share: ML-KEM-768 ciphertext || X25519 public key
//! - TLS input keying material: ML-KEM shared secret || X25519 shared secret
//!
//! Keeping this construction in Vail prevents transport integrations from
//! accidentally using the similarly named but wire-incompatible generic KEM.

const std = @import("std");

const MLKem768 = @import("../../crypto/mlkem.zig").nist.MLKem768;
const X25519 = @import("../../crypto/x25519.zig").X25519;

pub const named_group: u16 = 0x11ec;

pub const x25519_secret_len = X25519.secret_length;
pub const x25519_public_len = X25519.public_length;
pub const mlkem_seed_len = MLKem768.seed_length;
pub const mlkem_public_len = MLKem768.PublicKey.encoded_length;
pub const mlkem_ciphertext_len = MLKem768.ciphertext_length;
pub const mlkem_shared_len = MLKem768.shared_length;
pub const encaps_seed_len = MLKem768.encaps_seed_length;

pub const client_share_len = mlkem_public_len + x25519_public_len;
pub const server_share_len = mlkem_ciphertext_len + x25519_public_len;
pub const shared_len = mlkem_shared_len + X25519.shared_length;

pub const Error = error{
    InvalidSecretKey,
    InvalidClientShare,
    InvalidServerShare,
    KeyExchangeFailed,
};

/// Compact client-side state retained between ClientHello and ServerHello.
///
/// ML-KEM key generation is deterministic from its 64-byte seed, so retaining
/// the seed avoids keeping both the expanded 2400-byte private key and its
/// public key alive for the entire network round trip.
pub const ClientSecret = struct {
    x25519_secret: [x25519_secret_len]u8,
    mlkem_seed: [mlkem_seed_len]u8,

    pub fn wipe(self: *ClientSecret) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const ClientStart = struct {
    secret: ClientSecret,
    share: [client_share_len]u8,
};

pub const ServerResponse = struct {
    share: [server_share_len]u8,
    shared_secret: [shared_len]u8,

    pub fn wipeSharedSecret(self: *ServerResponse) void {
        std.crypto.secureZero(u8, &self.shared_secret);
    }
};

/// Builds a deterministic client share from caller-supplied secure entropy.
pub fn clientStart(
    x25519_secret: [x25519_secret_len]u8,
    mlkem_seed: [mlkem_seed_len]u8,
) Error!ClientStart {
    const x25519_public = X25519.recoverPublicKey(x25519_secret) catch
        return error.InvalidSecretKey;
    const public_key = MLKem768.PublicKey.generateDeterministic(mlkem_seed) catch
        return error.InvalidSecretKey;
    const mlkem_public = public_key.toBytes();

    var share: [client_share_len]u8 = undefined;
    @memcpy(share[0..mlkem_public_len], &mlkem_public);
    @memcpy(share[mlkem_public_len..], &x25519_public);
    return .{
        .secret = .{
            .x25519_secret = x25519_secret,
            .mlkem_seed = mlkem_seed,
        },
        .share = share,
    };
}

/// Encapsulates to a client share and returns the server's wire share and IKM.
pub fn serverRespond(
    client_share: []const u8,
    x25519_secret: [x25519_secret_len]u8,
    encaps_seed: [encaps_seed_len]u8,
) Error!ServerResponse {
    if (client_share.len != client_share_len) {
        return error.InvalidClientShare;
    }

    const mlkem_public = MLKem768.PublicKey.fromBytes(
        client_share[0..mlkem_public_len],
    ) catch return error.InvalidClientShare;
    var encapsulated = mlkem_public.encapsDeterministic(&encaps_seed);
    defer std.crypto.secureZero(
        u8,
        &encapsulated.shared_secret,
    );

    const client_x25519 = client_share[mlkem_public_len..][0..x25519_public_len].*;
    var x25519_shared: [X25519.shared_length]u8 = undefined;
    X25519.scalarmultInto(
        &x25519_shared,
        &x25519_secret,
        &client_x25519,
    ) catch return error.InvalidClientShare;
    defer std.crypto.secureZero(u8, &x25519_shared);
    const x25519_public = X25519.recoverPublicKey(x25519_secret) catch
        return error.InvalidSecretKey;

    var share: [server_share_len]u8 = undefined;
    @memcpy(share[0..mlkem_ciphertext_len], &encapsulated.ciphertext);
    @memcpy(share[mlkem_ciphertext_len..], &x25519_public);
    return .{
        .share = share,
        .shared_secret = combine(
            encapsulated.shared_secret,
            x25519_shared,
        ),
    };
}

/// Completes X25519MLKEM768 from the exact ServerHello key-share payload.
pub fn clientSharedSecret(
    secret: *const ClientSecret,
    server_share: []const u8,
) Error![shared_len]u8 {
    if (server_share.len != server_share_len) {
        return error.InvalidServerShare;
    }

    var secret_key = MLKem768.SecretKey.generateDeterministic(
        secret.mlkem_seed,
    ) catch return error.InvalidSecretKey;
    defer secret_key.wipe();
    var mlkem_shared = secret_key.decaps(
        server_share[0..mlkem_ciphertext_len],
    ) catch return error.KeyExchangeFailed;
    defer std.crypto.secureZero(u8, &mlkem_shared);

    const server_x25519 =
        server_share[mlkem_ciphertext_len..][0..x25519_public_len].*;
    var x25519_shared: [X25519.shared_length]u8 = undefined;
    X25519.scalarmultInto(
        &x25519_shared,
        &secret.x25519_secret,
        &server_x25519,
    ) catch return error.InvalidServerShare;
    defer std.crypto.secureZero(u8, &x25519_shared);
    return combine(mlkem_shared, x25519_shared);
}

fn combine(
    mlkem_shared: [mlkem_shared_len]u8,
    x25519_shared: [X25519.shared_length]u8,
) [shared_len]u8 {
    // The TLS draft feeds this concatenation directly to HKDF-Extract. Adding
    // another KDF here would produce a non-interoperable named group.
    return mlkem_shared ++ x25519_shared;
}
