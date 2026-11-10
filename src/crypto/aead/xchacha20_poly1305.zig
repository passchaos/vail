//! XChaCha20-Poly1305 (24-byte nonce) for WireGuard cookie replies.

const std = @import("std");

const Impl = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_length = Impl.key_length;
pub const nonce_length = Impl.nonce_length;
pub const tag_length = Impl.tag_length;
pub const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const Context = struct {
    key: [key_length]u8,

    pub fn init(key: [key_length]u8) Context {
        return .{ .key = key };
    }

    pub fn deinit(self: *Context) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    /// `ciphertext` and `plaintext` must have the same length and not overlap
    /// unless they start at the same address.
    pub fn encrypt(
        self: *const Context,
        ciphertext: []u8,
        tag: *[tag_length]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) void {
        std.debug.assert(ciphertext.len == plaintext.len);
        Impl.encrypt(
            ciphertext,
            tag,
            plaintext,
            associated_data,
            nonce,
            self.key,
        );
    }

    pub fn decrypt(
        self: *const Context,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [tag_length]u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) AuthenticationError!void {
        std.debug.assert(plaintext.len == ciphertext.len);
        try Impl.decrypt(
            plaintext,
            ciphertext,
            tag,
            associated_data,
            nonce,
            self.key,
        );
    }
};

test "XChaCha20-Poly1305 round trip" {
    const key = [_]u8{0x42} ** key_length;
    const nonce = [_]u8{0x13} ** nonce_length;
    const message = "wireguard cookie";
    const ad = "mac1";

    var ciphertext: [message.len]u8 = undefined;
    var tag: [tag_length]u8 = undefined;
    var ctx = Context.init(key);
    defer ctx.deinit();
    ctx.encrypt(&ciphertext, &tag, message, ad, nonce);

    var plaintext: [message.len]u8 = undefined;
    try ctx.decrypt(&plaintext, &ciphertext, tag, ad, nonce);
    try std.testing.expectEqualStrings(message, &plaintext);

    var bad_tag = tag;
    bad_tag[0] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        ctx.decrypt(&plaintext, &ciphertext, bad_tag, ad, nonce),
    );
}
