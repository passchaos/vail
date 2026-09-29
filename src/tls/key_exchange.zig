//! TLS 1.3 classical and post-quantum hybrid key-exchange primitives.

const std = @import("std");

pub const x25519_mlkem768 =
    @import("key_exchange/x25519_mlkem768.zig");
pub const secp256r1_mlkem768 =
    @import("key_exchange/secp256r1_mlkem768.zig").implementation;
pub const secp384r1_mlkem1024 =
    @import("key_exchange/secp384r1_mlkem1024.zig").implementation;

pub const secret_len = std.crypto.dh.X25519.secret_length;
pub const public_len = std.crypto.dh.X25519.public_length;
pub const shared_len = std.crypto.dh.X25519.shared_length;

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
    KeyExchangeFailed,
};

pub const named_group_x25519: u16 = 0x001d;
pub const named_group_secp256r1: u16 = 0x0017;
pub const named_group_secp384r1: u16 = 0x0018;

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

pub const p384 = struct {
    const Curve = std.crypto.ecc.P384;

    pub const secret_len = Curve.scalar.encoded_length;
    pub const public_len = 1 + 2 * Curve.Fe.encoded_length;
    pub const shared_len = Curve.Fe.encoded_length;

    pub fn publicKey(
        secret_key: [p384.secret_len]u8,
    ) Error![p384.public_len]u8 {
        try validateSecret(secret_key);
        const public = Curve.basePoint.mul(
            secret_key,
            .big,
        ) catch return error.KeyExchangeFailed;
        return public.toUncompressedSec1();
    }

    pub fn sharedSecret(
        secret_key: [p384.secret_len]u8,
        peer_public_key: []const u8,
    ) Error![p384.shared_len]u8 {
        try validateSecret(secret_key);
        if (peer_public_key.len != p384.public_len or
            peer_public_key[0] != 0x04)
        {
            return error.InvalidPublicKey;
        }
        const peer = Curve.fromSec1(peer_public_key) catch
            return error.InvalidPublicKey;
        // `mul` takes the constant-time path required for private ECDH
        // scalars; the public-scalar multiplication API is not appropriate.
        const shared = peer.mul(secret_key, .big) catch
            return error.KeyExchangeFailed;
        return shared.affineCoordinates().x.toBytes(.big);
    }

    fn validateSecret(
        secret_key: [p384.secret_len]u8,
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

pub const max_server_share_len = secp384r1_mlkem1024.server_share_len;
pub const max_client_share_len = secp384r1_mlkem1024.client_share_len;
pub const max_shared_len = secp384r1_mlkem1024.shared_len;

/// Single-use client entropy retained between ClientHello and ServerHello.
pub const ClientKeyMaterial = union(enum) {
    x25519: [secret_len]u8,
    secp256r1: [p256.secret_len]u8,
    secp384r1: [p384.secret_len]u8,
    x25519_mlkem768: struct {
        x25519_secret: [x25519_mlkem768.x25519_secret_len]u8,
        mlkem_seed: [x25519_mlkem768.mlkem_seed_len]u8,
    },
    secp256r1_mlkem768: struct {
        curve_secret: [secp256r1_mlkem768.curve_secret_len]u8,
        mlkem_seed: [secp256r1_mlkem768.mlkem_seed_len]u8,
    },
    secp384r1_mlkem1024: struct {
        curve_secret: [secp384r1_mlkem1024.curve_secret_len]u8,
        mlkem_seed: [secp384r1_mlkem1024.mlkem_seed_len]u8,
    },

    pub fn namedGroup(self: ClientKeyMaterial) u16 {
        return switch (self) {
            .x25519 => named_group_x25519,
            .secp256r1 => named_group_secp256r1,
            .secp384r1 => named_group_secp384r1,
            .x25519_mlkem768 => x25519_mlkem768.named_group,
            .secp256r1_mlkem768 => secp256r1_mlkem768.named_group,
            .secp384r1_mlkem1024 => secp384r1_mlkem1024.named_group,
        };
    }

    /// Consume and wipe caller-owned material, returning the public ClientHello
    /// share plus the minimum private state needed for ServerHello.
    pub fn start(self: *ClientKeyMaterial) Error!ClientExchange {
        var owned = self.*;
        self.wipe();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&owned));
        var result = ClientExchange{
            .material = owned,
            .share_storage = undefined,
            .share_len = 0,
        };
        switch (owned) {
            .x25519 => |private| result.setShare(&(try publicKey(private))),
            .secp256r1 => |private| result.setShare(
                &(try p256.publicKey(private)),
            ),
            .secp384r1 => |private| result.setShare(
                &(try p384.publicKey(private)),
            ),
            .x25519_mlkem768 => |material| {
                var started = x25519_mlkem768.clientStart(
                    material.x25519_secret,
                    material.mlkem_seed,
                ) catch |err| return mapHybridError(err);
                defer started.secret.wipe();
                result.setShare(&started.share);
            },
            .secp256r1_mlkem768 => |material| {
                var started = secp256r1_mlkem768.clientStart(
                    material.curve_secret,
                    material.mlkem_seed,
                ) catch |err| return mapHybridError(err);
                defer started.secret.wipe();
                result.setShare(&started.share);
            },
            .secp384r1_mlkem1024 => |material| {
                var started = secp384r1_mlkem1024.clientStart(
                    material.curve_secret,
                    material.mlkem_seed,
                ) catch |err| return mapHybridError(err);
                defer started.secret.wipe();
                result.setShare(&started.share);
            },
        }
        return result;
    }

    pub fn wipe(self: *ClientKeyMaterial) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }
};

pub const ClientExchange = struct {
    material: ClientKeyMaterial,
    share_storage: [max_client_share_len]u8,
    share_len: usize,

    pub fn namedGroup(self: *const ClientExchange) u16 {
        return self.material.namedGroup();
    }

    pub fn clientShare(self: *const ClientExchange) []const u8 {
        return self.share_storage[0..self.share_len];
    }

    /// Complete the exchange and consume all retained private material.
    pub fn complete(
        self: *ClientExchange,
        server_share: []const u8,
    ) Error!SharedSecret {
        defer self.deinit();
        return switch (self.material) {
            .x25519 => |private| blk: {
                var shared = try sharedSecret(private, server_share);
                defer std.crypto.secureZero(u8, &shared);
                break :blk SharedSecret.init(&shared);
            },
            .secp256r1 => |private| blk: {
                var shared = try p256.sharedSecret(private, server_share);
                defer std.crypto.secureZero(u8, &shared);
                break :blk SharedSecret.init(&shared);
            },
            .secp384r1 => |private| blk: {
                var shared = try p384.sharedSecret(private, server_share);
                defer std.crypto.secureZero(u8, &shared);
                break :blk SharedSecret.init(&shared);
            },
            .x25519_mlkem768 => |material| blk: {
                const client_secret = x25519_mlkem768.ClientSecret{
                    .x25519_secret = material.x25519_secret,
                    .mlkem_seed = material.mlkem_seed,
                };
                var shared = x25519_mlkem768.clientSharedSecret(
                    &client_secret,
                    server_share,
                ) catch |err| return mapHybridError(err);
                defer std.crypto.secureZero(u8, &shared);
                break :blk SharedSecret.init(&shared);
            },
            .secp256r1_mlkem768 => |material| blk: {
                const client_secret = secp256r1_mlkem768.ClientSecret{
                    .curve_secret = material.curve_secret,
                    .mlkem_seed = material.mlkem_seed,
                };
                var shared = secp256r1_mlkem768.clientSharedSecret(
                    &client_secret,
                    server_share,
                ) catch |err| return mapHybridError(err);
                defer std.crypto.secureZero(u8, &shared);
                break :blk SharedSecret.init(&shared);
            },
            .secp384r1_mlkem1024 => |material| blk: {
                const client_secret = secp384r1_mlkem1024.ClientSecret{
                    .curve_secret = material.curve_secret,
                    .mlkem_seed = material.mlkem_seed,
                };
                var shared = secp384r1_mlkem1024.clientSharedSecret(
                    &client_secret,
                    server_share,
                ) catch |err| return mapHybridError(err);
                defer std.crypto.secureZero(u8, &shared);
                break :blk SharedSecret.init(&shared);
            },
        };
    }

    pub fn deinit(self: *ClientExchange) void {
        self.material.wipe();
        std.crypto.secureZero(u8, &self.share_storage);
        self.* = undefined;
    }

    fn setShare(self: *ClientExchange, share: []const u8) void {
        std.debug.assert(share.len <= max_client_share_len);
        @memcpy(self.share_storage[0..share.len], share);
        self.share_len = share.len;
    }
};

pub const SharedSecret = struct {
    storage: [max_shared_len]u8,
    len: usize,

    fn init(shared: []const u8) SharedSecret {
        std.debug.assert(shared.len <= max_shared_len);
        var result = SharedSecret{
            .storage = undefined,
            .len = shared.len,
        };
        @memcpy(result.storage[0..shared.len], shared);
        return result;
    }

    pub fn bytes(self: *const SharedSecret) []const u8 {
        return self.storage[0..self.len];
    }

    pub fn deinit(self: *SharedSecret) void {
        std.crypto.secureZero(u8, &self.storage);
        self.* = undefined;
    }
};

/// Single-use server entropy for one negotiated TLS named group.
///
/// Hybrid variants contain both the classical private scalar and the ML-KEM
/// encapsulation seed. `server_handshake` consumes and wipes this value after
/// producing its ServerHello so ephemeral secrets cannot be accidentally
/// reused across connections.
pub const ServerKeyMaterial = union(enum) {
    x25519: [secret_len]u8,
    secp256r1: [p256.secret_len]u8,
    secp384r1: [p384.secret_len]u8,
    x25519_mlkem768: struct {
        x25519_secret: [x25519_mlkem768.x25519_secret_len]u8,
        encaps_seed: [x25519_mlkem768.encaps_seed_len]u8,
    },
    secp256r1_mlkem768: struct {
        curve_secret: [secp256r1_mlkem768.curve_secret_len]u8,
        encaps_seed: [secp256r1_mlkem768.encaps_seed_len]u8,
    },
    secp384r1_mlkem1024: struct {
        curve_secret: [secp384r1_mlkem1024.curve_secret_len]u8,
        encaps_seed: [secp384r1_mlkem1024.encaps_seed_len]u8,
    },

    pub fn namedGroup(self: ServerKeyMaterial) u16 {
        return switch (self) {
            .x25519 => named_group_x25519,
            .secp256r1 => named_group_secp256r1,
            .secp384r1 => named_group_secp384r1,
            .x25519_mlkem768 => x25519_mlkem768.named_group,
            .secp256r1_mlkem768 => secp256r1_mlkem768.named_group,
            .secp384r1_mlkem1024 => secp384r1_mlkem1024.named_group,
        };
    }

    pub fn respond(
        self: ServerKeyMaterial,
        client_share: []const u8,
    ) Error!ServerExchange {
        return switch (self) {
            .x25519 => |private| blk: {
                const public = try publicKey(private);
                var shared = try sharedSecret(private, client_share);
                defer std.crypto.secureZero(u8, &shared);
                break :blk ServerExchange.init(&public, &shared);
            },
            .secp256r1 => |private| blk: {
                const public = try p256.publicKey(private);
                var shared = try p256.sharedSecret(private, client_share);
                defer std.crypto.secureZero(u8, &shared);
                break :blk ServerExchange.init(&public, &shared);
            },
            .secp384r1 => |private| blk: {
                const public = try p384.publicKey(private);
                var shared = try p384.sharedSecret(private, client_share);
                defer std.crypto.secureZero(u8, &shared);
                break :blk ServerExchange.init(&public, &shared);
            },
            .x25519_mlkem768 => |material| blk: {
                var response = x25519_mlkem768.serverRespond(
                    client_share,
                    material.x25519_secret,
                    material.encaps_seed,
                ) catch |err| return mapHybridError(err);
                defer response.wipeSharedSecret();
                break :blk ServerExchange.init(
                    &response.share,
                    &response.shared_secret,
                );
            },
            .secp256r1_mlkem768 => |material| blk: {
                var response = secp256r1_mlkem768.serverRespond(
                    client_share,
                    material.curve_secret,
                    material.encaps_seed,
                ) catch |err| return mapHybridError(err);
                defer response.wipeSharedSecret();
                break :blk ServerExchange.init(
                    &response.share,
                    &response.shared_secret,
                );
            },
            .secp384r1_mlkem1024 => |material| blk: {
                var response = secp384r1_mlkem1024.serverRespond(
                    client_share,
                    material.curve_secret,
                    material.encaps_seed,
                ) catch |err| return mapHybridError(err);
                defer response.wipeSharedSecret();
                break :blk ServerExchange.init(
                    &response.share,
                    &response.shared_secret,
                );
            },
        };
    }

    pub fn wipe(self: *ServerKeyMaterial) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }
};

pub const ServerExchange = struct {
    server_share_storage: [max_server_share_len]u8,
    server_share_len: usize,
    shared_storage: [max_shared_len]u8,
    shared_len: usize,

    fn init(server_share: []const u8, shared: []const u8) ServerExchange {
        std.debug.assert(server_share.len <= max_server_share_len);
        std.debug.assert(shared.len <= max_shared_len);
        var result = ServerExchange{
            .server_share_storage = undefined,
            .server_share_len = server_share.len,
            .shared_storage = undefined,
            .shared_len = shared.len,
        };
        @memcpy(result.server_share_storage[0..server_share.len], server_share);
        @memcpy(result.shared_storage[0..shared.len], shared);
        return result;
    }

    pub fn serverShare(self: *const ServerExchange) []const u8 {
        return self.server_share_storage[0..self.server_share_len];
    }

    pub fn sharedSecretBytes(self: *const ServerExchange) []const u8 {
        return self.shared_storage[0..self.shared_len];
    }

    pub fn deinit(self: *ServerExchange) void {
        std.crypto.secureZero(u8, &self.server_share_storage);
        std.crypto.secureZero(u8, &self.shared_storage);
        self.* = undefined;
    }
};

fn mapHybridError(err: anyerror) Error {
    return switch (err) {
        error.InvalidSecretKey => error.InvalidSecretKey,
        error.InvalidClientShare,
        error.InvalidServerShare,
        => error.InvalidPublicKey,
        else => error.KeyExchangeFailed,
    };
}

test "server key material owns classical and hybrid response construction" {
    const client_private = [_]u8{0x11} ** secret_len;
    const client_public = try publicKey(client_private);
    var material = ServerKeyMaterial{
        .x25519 = [_]u8{0x22} ** secret_len,
    };
    var response = try material.respond(&client_public);
    defer response.deinit();
    const client_shared = try sharedSecret(
        client_private,
        response.serverShare(),
    );
    try std.testing.expectEqual(named_group_x25519, material.namedGroup());
    try std.testing.expectEqualSlices(
        u8,
        &client_shared,
        response.sharedSecretBytes(),
    );

    var hybrid_client = try x25519_mlkem768.clientStart(
        [_]u8{0x31} ** x25519_mlkem768.x25519_secret_len,
        [_]u8{0x32} ** x25519_mlkem768.mlkem_seed_len,
    );
    defer hybrid_client.secret.wipe();
    const hybrid_material = ServerKeyMaterial{
        .x25519_mlkem768 = .{
            .x25519_secret = [_]u8{0x33} **
                x25519_mlkem768.x25519_secret_len,
            .encaps_seed = [_]u8{0x34} **
                x25519_mlkem768.encaps_seed_len,
        },
    };
    var hybrid_response = try hybrid_material.respond(&hybrid_client.share);
    defer hybrid_response.deinit();
    const hybrid_shared = try x25519_mlkem768.clientSharedSecret(
        &hybrid_client.secret,
        hybrid_response.serverShare(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &hybrid_shared,
        hybrid_response.sharedSecretBytes(),
    );
}

test "client key material is single-use across classical and hybrid groups" {
    var client_material = ClientKeyMaterial{
        .x25519 = [_]u8{0x41} ** secret_len,
    };
    var client = try client_material.start();
    var server_material = ServerKeyMaterial{
        .x25519 = [_]u8{0x42} ** secret_len,
    };
    var response = try server_material.respond(client.clientShare());
    defer response.deinit();
    var client_shared = try client.complete(response.serverShare());
    defer client_shared.deinit();
    try std.testing.expectEqualSlices(
        u8,
        response.sharedSecretBytes(),
        client_shared.bytes(),
    );

    var hybrid_material = ClientKeyMaterial{
        .secp256r1_mlkem768 = .{
            .curve_secret = [_]u8{0} **
                (secp256r1_mlkem768.curve_secret_len - 1) ++ .{1},
            .mlkem_seed = [_]u8{0x43} **
                secp256r1_mlkem768.mlkem_seed_len,
        },
    };
    var hybrid_client = try hybrid_material.start();
    var hybrid_server_material = ServerKeyMaterial{
        .secp256r1_mlkem768 = .{
            .curve_secret = [_]u8{0} **
                (secp256r1_mlkem768.curve_secret_len - 1) ++ .{2},
            .encaps_seed = [_]u8{0x44} **
                secp256r1_mlkem768.encaps_seed_len,
        },
    };
    var hybrid_response = try hybrid_server_material.respond(
        hybrid_client.clientShare(),
    );
    defer hybrid_response.deinit();
    var hybrid_shared = try hybrid_client.complete(
        hybrid_response.serverShare(),
    );
    defer hybrid_shared.deinit();
    try std.testing.expectEqualSlices(
        u8,
        hybrid_response.sharedSecretBytes(),
        hybrid_shared.bytes(),
    );
}

test {
    _ = @import("key_exchange/tests.zig");
}
