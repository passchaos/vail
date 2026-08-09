//! TLS ECDHE + ML-KEM hybrid named-group construction.
//!
//! This is intentionally distinct from `std.crypto.kem.hybrid`: TLS uses a
//! fixed concatenation of the two raw shared secrets and a TLS-specific wire
//! layout, whereas the generic hybrid KEM applies the C2PRI combiner.

const std = @import("std");

pub const Error = error{
    InvalidSecretKey,
    InvalidClientShare,
    InvalidServerShare,
    KeyExchangeFailed,
};

pub const Params = struct {
    named_group: u16,
    Curve: type,
    MLKem: type,
};

pub fn Group(comptime params: Params) type {
    return struct {
        const Self = @This();
        const Curve = params.Curve;
        const MLKem = params.MLKem;

        pub const named_group = params.named_group;
        pub const curve_secret_len = Curve.scalar.encoded_length;
        pub const curve_public_len = 1 + 2 * Curve.Fe.encoded_length;
        pub const curve_shared_len = Curve.Fe.encoded_length;
        pub const mlkem_seed_len = MLKem.seed_length;
        pub const mlkem_public_len = MLKem.PublicKey.encoded_length;
        pub const mlkem_ciphertext_len = MLKem.ciphertext_length;
        pub const mlkem_shared_len = MLKem.shared_length;
        pub const encaps_seed_len = MLKem.encaps_seed_length;

        // Registered ECDHE-MLKEM groups place the NIST curve first in both
        // wire shares and the TLS input keying material.
        pub const client_share_len = curve_public_len + mlkem_public_len;
        pub const server_share_len = curve_public_len + mlkem_ciphertext_len;
        pub const shared_len = curve_shared_len + mlkem_shared_len;

        pub const ClientSecret = struct {
            curve_secret: [curve_secret_len]u8,
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

        pub fn clientStart(
            curve_secret: [curve_secret_len]u8,
            mlkem_seed: [mlkem_seed_len]u8,
        ) Error!ClientStart {
            const curve_public = try publicKey(curve_secret);
            var key_pair = MLKem.KeyPair.generateDeterministic(
                mlkem_seed,
            ) catch return error.InvalidSecretKey;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
            const mlkem_public = key_pair.public_key.toBytes();

            var share: [client_share_len]u8 = undefined;
            @memcpy(share[0..curve_public_len], &curve_public);
            @memcpy(share[curve_public_len..], &mlkem_public);
            return .{
                .secret = .{
                    .curve_secret = curve_secret,
                    .mlkem_seed = mlkem_seed,
                },
                .share = share,
            };
        }

        pub fn serverRespond(
            client_share: []const u8,
            curve_secret: [curve_secret_len]u8,
            encaps_seed: [encaps_seed_len]u8,
        ) Error!ServerResponse {
            if (client_share.len != client_share_len) {
                return error.InvalidClientShare;
            }
            const peer_curve = Curve.fromSec1(
                client_share[0..curve_public_len],
            ) catch return error.InvalidClientShare;
            var curve_shared = (peer_curve.mul(
                curve_secret,
                .big,
            ) catch return error.InvalidClientShare)
                .affineCoordinates().x.toBytes(.big);
            defer std.crypto.secureZero(u8, &curve_shared);

            const mlkem_public = MLKem.PublicKey.fromBytes(
                client_share[curve_public_len..][0..mlkem_public_len],
            ) catch return error.InvalidClientShare;
            var encapsulated = mlkem_public.encapsDeterministic(
                &encaps_seed,
            );
            defer std.crypto.secureZero(
                u8,
                &encapsulated.shared_secret,
            );
            const curve_public = try publicKey(curve_secret);

            var share: [server_share_len]u8 = undefined;
            @memcpy(share[0..curve_public_len], &curve_public);
            @memcpy(
                share[curve_public_len..],
                &encapsulated.ciphertext,
            );
            return .{
                .share = share,
                .shared_secret = combine(
                    curve_shared,
                    encapsulated.shared_secret,
                ),
            };
        }

        pub fn clientSharedSecret(
            secret: *const ClientSecret,
            server_share: []const u8,
        ) Error![shared_len]u8 {
            if (server_share.len != server_share_len) {
                return error.InvalidServerShare;
            }
            const peer_curve = Curve.fromSec1(
                server_share[0..curve_public_len],
            ) catch return error.InvalidServerShare;
            var curve_shared = (peer_curve.mul(
                secret.curve_secret,
                .big,
            ) catch return error.InvalidServerShare)
                .affineCoordinates().x.toBytes(.big);
            defer std.crypto.secureZero(u8, &curve_shared);

            var key_pair = MLKem.KeyPair.generateDeterministic(
                secret.mlkem_seed,
            ) catch return error.InvalidSecretKey;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
            var mlkem_shared = key_pair.secret_key.decaps(
                server_share[curve_public_len..][0..mlkem_ciphertext_len],
            ) catch return error.KeyExchangeFailed;
            defer std.crypto.secureZero(u8, &mlkem_shared);
            return combine(curve_shared, mlkem_shared);
        }

        fn publicKey(
            secret: [curve_secret_len]u8,
        ) Error![curve_public_len]u8 {
            const scalar = Curve.scalar.Scalar.fromBytes(
                secret,
                .big,
            ) catch return error.InvalidSecretKey;
            if (scalar.isZero()) return error.InvalidSecretKey;
            const public = Curve.basePoint.mul(
                secret,
                .big,
            ) catch return error.InvalidSecretKey;
            return public.toUncompressedSec1();
        }

        fn combine(
            curve_shared: [curve_shared_len]u8,
            mlkem_shared: [mlkem_shared_len]u8,
        ) [shared_len]u8 {
            _ = Self;
            return curve_shared ++ mlkem_shared;
        }
    };
}
