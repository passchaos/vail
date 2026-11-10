//! TLS ML-KEM-768 registered named group (`0x0201`).

const std = @import("std");
const mlkem = @import("mlkem.zig");
const crypto_mlkem = @import("../../crypto/pq/mlkem.zig");

pub const implementation = mlkem.Group(.{
    .named_group = 0x0201,
    .MLKem = crypto_mlkem.nist.MLKem768,
});

test "ML-KEM-768 TLS shares agree and use the registered layout" {
    const target = implementation;
    const client_seed = [_]u8{0x11} ** target.seed_len;
    const encaps_seed = [_]u8{0x22} ** target.encaps_seed_len;
    var client = try target.clientStart(client_seed);
    defer client.secret.wipe();
    var response = try target.serverRespond(&client.share, encaps_seed);
    defer response.wipeSharedSecret();
    var client_shared = try target.clientSharedSecret(
        &client.secret,
        &response.share,
    );
    defer std.crypto.secureZero(u8, &client_shared);

    try std.testing.expectEqual(@as(u16, 0x0201), target.named_group);
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
    const target = implementation;
    var client = try target.clientStart([_]u8{0x31} ** target.seed_len);
    defer client.secret.wipe();
    try std.testing.expectError(
        error.InvalidClientShare,
        target.serverRespond(
            client.share[0 .. client.share.len - 1],
            [_]u8{0x32} ** target.encaps_seed_len,
        ),
    );

    var response = try target.serverRespond(
        &client.share,
        [_]u8{0x32} ** target.encaps_seed_len,
    );
    defer response.wipeSharedSecret();
    try std.testing.expectError(
        error.InvalidServerShare,
        target.clientSharedSecret(
            &client.secret,
            response.share[0 .. response.share.len - 1],
        ),
    );

    var tampered = response.share;
    tampered[0] ^= 1;
    var rejected = try target.clientSharedSecret(&client.secret, &tampered);
    defer std.crypto.secureZero(u8, &rejected);
    try std.testing.expect(!std.mem.eql(
        u8,
        &response.shared_secret,
        &rejected,
    ));
}
