//! Generic pure ML-KEM TLS named-group construction.

const std = @import("std");

pub const Error = error{
    InvalidSecretKey,
    InvalidClientShare,
    InvalidServerShare,
    KeyExchangeFailed,
};

pub const Params = struct {
    named_group: u16,
    MLKem: type,
};

pub fn Group(comptime params: Params) type {
    return struct {
        const MLKem = params.MLKem;

        pub const named_group = params.named_group;
        pub const seed_len = MLKem.seed_length;
        pub const client_share_len = MLKem.PublicKey.encoded_length;
        pub const server_share_len = MLKem.ciphertext_length;
        pub const shared_len = MLKem.shared_length;
        pub const encaps_seed_len = MLKem.encaps_seed_length;

        pub const ClientSecret = struct {
            seed: [seed_len]u8,

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

        pub fn clientStart(seed: [seed_len]u8) Error!ClientStart {
            var key_pair = MLKem.KeyPair.generateDeterministic(seed) catch
                return error.InvalidSecretKey;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
            return .{
                .secret = .{ .seed = seed },
                .share = key_pair.public_key.toBytes(),
            };
        }

        pub fn serverRespond(
            client_share: []const u8,
            encaps_seed: [encaps_seed_len]u8,
        ) Error!ServerResponse {
            if (client_share.len != client_share_len) {
                return error.InvalidClientShare;
            }
            const public_key = MLKem.PublicKey.fromBytes(
                client_share[0..client_share_len],
            ) catch return error.InvalidClientShare;
            var encapsulated = public_key.encapsDeterministic(&encaps_seed);
            defer std.crypto.secureZero(u8, &encapsulated.shared_secret);
            return .{
                .share = encapsulated.ciphertext,
                .shared_secret = encapsulated.shared_secret,
            };
        }

        pub fn clientSharedSecret(
            secret: *const ClientSecret,
            server_share: []const u8,
        ) Error![shared_len]u8 {
            if (server_share.len != server_share_len) {
                return error.InvalidServerShare;
            }
            var key_pair = MLKem.KeyPair.generateDeterministic(
                secret.seed,
            ) catch return error.InvalidSecretKey;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
            return key_pair.secret_key.decaps(
                server_share[0..server_share_len],
            ) catch return error.KeyExchangeFailed;
        }
    };
}
