const std = @import("std");
const traffic = @import("traffic_crypto.zig");

test "AES and ChaCha traffic suites round-trip without allocation" {
    const secret = [_]u8{0x42} ** traffic.secret_len;
    inline for (.{ traffic.Suite.aes_128_gcm_sha256, .chacha20_poly1305_sha256 }) |suite| {
        const keys = traffic.Keys.derive(suite, secret, .{});
        const plaintext = "Vail QUIC traffic";
        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [traffic.tag_len]u8 = undefined;
        try keys.protect(7, "header", plaintext, &ciphertext, &tag);
        var opened: [plaintext.len]u8 = undefined;
        try keys.open(7, "header", &ciphertext, tag, &opened);
        try std.testing.expectEqualStrings(plaintext, &opened);
        var bad_tag = tag;
        bad_tag[0] ^= 1;
        try std.testing.expectError(
            error.AuthenticationFailed,
            keys.open(7, "header", &ciphertext, bad_tag, &opened),
        );
    }
}

test "ChaCha header protection follows RFC 9001 sample layout" {
    const keys = traffic.Keys{
        .suite = .chacha20_poly1305_sha256,
        .secret = [_]u8{0} ** traffic.secret_len,
        .key = [_]u8{0} ** traffic.max_key_len,
        .iv = [_]u8{0} ** traffic.iv_len,
        .hp = [_]u8{0} ** traffic.max_key_len,
    };
    const sample = [traffic.sample_len]u8{
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    };
    const mask = keys.headerProtectionMask(sample);
    // RFC 8439 §2.3.2 first ChaCha20 block under all-zero key/nonce.
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x76, 0xb8, 0xe0, 0xad, 0xa0 },
        &mask,
    );
}
