//! TLS ML-KEM-1024 registered named group (`0x0202`).

const std = @import("std");
const mlkem = @import("mlkem.zig");

pub const implementation = mlkem.Group(.{
    .named_group = 0x0202,
    .MLKem = std.crypto.kem.ml_kem.MLKem1024,
});

test "ML-KEM-1024 TLS shares agree and reject malformed inputs" {
    const target = implementation;
    var client = try target.clientStart([_]u8{0x41} ** target.seed_len);
    defer client.secret.wipe();
    var response = try target.serverRespond(
        &client.share,
        [_]u8{0x42} ** target.encaps_seed_len,
    );
    defer response.wipeSharedSecret();
    var client_shared = try target.clientSharedSecret(
        &client.secret,
        &response.share,
    );
    defer std.crypto.secureZero(u8, &client_shared);

    try std.testing.expectEqual(@as(u16, 0x0202), target.named_group);
    try std.testing.expectEqual(@as(usize, 1568), client.share.len);
    try std.testing.expectEqual(@as(usize, 1568), response.share.len);
    try std.testing.expectEqual(@as(usize, 32), client_shared.len);
    try std.testing.expectEqualSlices(
        u8,
        &response.shared_secret,
        &client_shared,
    );
    try std.testing.expectError(
        error.InvalidClientShare,
        target.serverRespond(
            client.share[0 .. client.share.len - 1],
            [_]u8{0x42} ** target.encaps_seed_len,
        ),
    );
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
