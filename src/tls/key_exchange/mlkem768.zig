//! TLS ML-KEM-768 key exchange for registered named group `0x0201`.
//!
//! The ClientHello share is the encoded ML-KEM encapsulation key, the
//! ServerHello share is the ciphertext, and the KEM's 32-byte shared secret is
//! passed directly to the TLS 1.3 key schedule. Client state retains only the
//! deterministic key-generation seed instead of the expanded secret key.

const std = @import("std");

const MLKem768 = std.crypto.kem.ml_kem.MLKem768;

pub const named_group: u16 = 0x0201;
pub const seed_len = MLKem768.seed_length;
pub const client_share_len = MLKem768.PublicKey.encoded_length;
pub const server_share_len = MLKem768.ciphertext_length;
pub const shared_len = MLKem768.shared_length;
pub const encaps_seed_len = MLKem768.encaps_seed_length;

pub const Error = error{
    InvalidSecretKey,
    InvalidClientShare,
    InvalidServerShare,
    KeyExchangeFailed,
};

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
    var key_pair = MLKem768.KeyPair.generateDeterministic(seed) catch
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
    const public_key = MLKem768.PublicKey.fromBytes(
        client_share[0..client_share_len],
    ) catch
        return error.InvalidClientShare;
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
    var key_pair = MLKem768.KeyPair.generateDeterministic(secret.seed) catch
        return error.InvalidSecretKey;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    return key_pair.secret_key.decaps(server_share[0..server_share_len]) catch
        return error.KeyExchangeFailed;
}

test "ML-KEM-768 TLS shares agree and use the registered layout" {
    const client_seed = [_]u8{0x11} ** seed_len;
    const encaps_seed = [_]u8{0x22} ** encaps_seed_len;
    var client = try clientStart(client_seed);
    defer client.secret.wipe();
    var response = try serverRespond(&client.share, encaps_seed);
    defer response.wipeSharedSecret();
    var client_shared = try clientSharedSecret(
        &client.secret,
        &response.share,
    );
    defer std.crypto.secureZero(u8, &client_shared);

    try std.testing.expectEqual(@as(u16, 0x0201), named_group);
    try std.testing.expectEqual(@as(usize, 1184), client.share.len);
    try std.testing.expectEqual(@as(usize, 1088), response.share.len);
    try std.testing.expectEqual(@as(usize, 32), client_shared.len);
    try std.testing.expectEqualSlices(
        u8,
        &response.shared_secret,
        &client_shared,
    );
}

test "ML-KEM-768 rejects malformed shares and implicitly rejects tampering" {
    var client = try clientStart([_]u8{0x31} ** seed_len);
    defer client.secret.wipe();
    try std.testing.expectError(
        error.InvalidClientShare,
        serverRespond(
            client.share[0 .. client.share.len - 1],
            [_]u8{0x32} ** encaps_seed_len,
        ),
    );

    var response = try serverRespond(
        &client.share,
        [_]u8{0x32} ** encaps_seed_len,
    );
    defer response.wipeSharedSecret();
    try std.testing.expectError(
        error.InvalidServerShare,
        clientSharedSecret(
            &client.secret,
            response.share[0 .. response.share.len - 1],
        ),
    );

    var tampered = response.share;
    tampered[0] ^= 1;
    var rejected = try clientSharedSecret(&client.secret, &tampered);
    defer std.crypto.secureZero(u8, &rejected);
    try std.testing.expect(!std.mem.eql(
        u8,
        &response.shared_secret,
        &rejected,
    ));
}
