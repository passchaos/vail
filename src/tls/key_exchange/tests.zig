const std = @import("std");
const target = @import("x25519_mlkem768.zig");

test {
    _ = @import("mlkem768.zig");
    _ = @import("mlkem1024.zig");
}

test "X25519MLKEM768 agrees and preserves the registered TLS layout" {
    const client_x25519 = [_]u8{0x11} ** target.x25519_secret_len;
    const client_mlkem = [_]u8{0x22} ** target.mlkem_seed_len;
    const server_x25519 = [_]u8{0x33} ** target.x25519_secret_len;
    const encaps_seed = [_]u8{0x44} ** target.encaps_seed_len;

    var client = try target.clientStart(
        client_x25519,
        client_mlkem,
    );
    defer client.secret.wipe();
    var response = try target.serverRespond(
        &client.share,
        server_x25519,
        encaps_seed,
    );
    defer response.wipeSharedSecret();
    const client_shared = try target.clientSharedSecret(
        &client.secret,
        &response.share,
    );

    try std.testing.expectEqual(@as(u16, 0x11ec), target.named_group);
    try std.testing.expectEqual(@as(usize, 1216), client.share.len);
    try std.testing.expectEqual(@as(usize, 1120), response.share.len);
    try std.testing.expectEqual(@as(usize, 64), client_shared.len);
    try std.testing.expectEqualSlices(
        u8,
        &response.shared_secret,
        &client_shared,
    );

    // X25519MLKEM768 is the registered hybrid with ML-KEM first. Verify the
    // exact wire layout rather than merely proving that both local roles agree.
    var key_pair = try std.crypto.kem.ml_kem.MLKem768.KeyPair
        .generateDeterministic(client_mlkem);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    const mlkem_public = key_pair.public_key.toBytes();
    const client_x25519_public =
        try std.crypto.dh.X25519.recoverPublicKey(client_x25519);
    try std.testing.expectEqualSlices(
        u8,
        &mlkem_public,
        client.share[0..target.mlkem_public_len],
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_x25519_public,
        client.share[target.mlkem_public_len..],
    );

    const encapsulated = key_pair.public_key.encapsDeterministic(
        &encaps_seed,
    );
    const server_x25519_public =
        try std.crypto.dh.X25519.recoverPublicKey(server_x25519);
    try std.testing.expectEqualSlices(
        u8,
        &encapsulated.ciphertext,
        response.share[0..target.mlkem_ciphertext_len],
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_x25519_public,
        response.share[target.mlkem_ciphertext_len..],
    );
}

test "X25519MLKEM768 rejects malformed shares and binds both components" {
    var client = try target.clientStart(
        [_]u8{0x51} ** target.x25519_secret_len,
        [_]u8{0x52} ** target.mlkem_seed_len,
    );
    defer client.secret.wipe();
    try std.testing.expectError(
        error.InvalidClientShare,
        target.serverRespond(
            client.share[0 .. client.share.len - 1],
            [_]u8{0x53} ** target.x25519_secret_len,
            [_]u8{0x54} ** target.encaps_seed_len,
        ),
    );

    var response = try target.serverRespond(
        &client.share,
        [_]u8{0x53} ** target.x25519_secret_len,
        [_]u8{0x54} ** target.encaps_seed_len,
    );
    defer response.wipeSharedSecret();
    try std.testing.expectError(
        error.InvalidServerShare,
        target.clientSharedSecret(
            &client.secret,
            response.share[0 .. response.share.len - 1],
        ),
    );

    var tampered_mlkem = response.share;
    tampered_mlkem[0] ^= 1;
    const tampered_mlkem_shared = try target.clientSharedSecret(
        &client.secret,
        &tampered_mlkem,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &response.shared_secret,
        &tampered_mlkem_shared,
    ));

    var tampered_x25519 = response.share;
    tampered_x25519[tampered_x25519.len - 1] ^= 1;
    const tampered_x25519_shared = try target.clientSharedSecret(
        &client.secret,
        &tampered_x25519,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &response.shared_secret,
        &tampered_x25519_shared,
    ));
}

test "secp256r1MLKEM768 agrees and uses classical-first TLS layout" {
    try testEcdhMlKemGroup(
        @import("secp256r1_mlkem768.zig").implementation,
        std.crypto.ecc.P256,
        std.crypto.kem.ml_kem.MLKem768,
        0x11eb,
        1249,
        1153,
    );
}

test "secp384r1MLKEM1024 agrees and uses classical-first TLS layout" {
    try testEcdhMlKemGroup(
        @import("secp384r1_mlkem1024.zig").implementation,
        std.crypto.ecc.P384,
        std.crypto.kem.ml_kem.MLKem1024,
        0x11ed,
        1665,
        1665,
    );
}

fn testEcdhMlKemGroup(
    comptime Group: type,
    comptime Curve: type,
    comptime MLKem: type,
    expected_group: u16,
    expected_client_len: usize,
    expected_server_len: usize,
) !void {
    const client_curve =
        [_]u8{0} ** (Group.curve_secret_len - 1) ++ [_]u8{1};
    const server_curve =
        [_]u8{0} ** (Group.curve_secret_len - 1) ++ [_]u8{2};
    const mlkem_seed = [_]u8{0x72} ** Group.mlkem_seed_len;
    const encaps_seed = [_]u8{0x73} ** Group.encaps_seed_len;
    var client = try Group.clientStart(client_curve, mlkem_seed);
    defer client.secret.wipe();
    var response = try Group.serverRespond(
        &client.share,
        server_curve,
        encaps_seed,
    );
    defer response.wipeSharedSecret();
    const client_shared = try Group.clientSharedSecret(
        &client.secret,
        &response.share,
    );
    try std.testing.expectEqual(expected_group, Group.named_group);
    try std.testing.expectEqual(expected_client_len, client.share.len);
    try std.testing.expectEqual(expected_server_len, response.share.len);
    try std.testing.expectEqualSlices(
        u8,
        &response.shared_secret,
        &client_shared,
    );

    const client_public = try Curve.basePoint.mul(
        client_curve,
        .big,
    );
    const client_sec1 = client_public.toUncompressedSec1();
    try std.testing.expectEqualSlices(
        u8,
        &client_sec1,
        client.share[0..Group.curve_public_len],
    );
    var kem = try MLKem.KeyPair.generateDeterministic(mlkem_seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kem));
    const kem_public = kem.public_key.toBytes();
    try std.testing.expectEqualSlices(
        u8,
        &kem_public,
        client.share[Group.curve_public_len..],
    );

    var malformed = client.share;
    malformed[0] = 0x02;
    try std.testing.expectError(
        error.InvalidClientShare,
        Group.serverRespond(
            &malformed,
            server_curve,
            encaps_seed,
        ),
    );
}
