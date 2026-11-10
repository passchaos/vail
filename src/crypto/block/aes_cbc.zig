//! AES-CBC with PKCS#7 padding for legacy protocol compatibility.
//!
//! CBC is unauthenticated by itself. Callers must pair it with a MAC (for
//! example OpenVPN's HMAC data channel). The context stores prepared AES
//! encryption and decryption schedules.

const std = @import("std");

const Aes256 = std.crypto.core.aes.Aes256;
const EncryptCtx = std.crypto.core.aes.AesEncryptCtx(Aes256);
const DecryptCtx = std.crypto.core.aes.AesDecryptCtx(Aes256);

pub const key_length = 32;
pub const block_length = 16;

pub const Error = error{
    InvalidLength,
    BufferTooSmall,
    PaddingError,
};

pub const Context = struct {
    encrypt_ctx: EncryptCtx,
    decrypt_ctx: DecryptCtx,

    pub fn init(key: [key_length]u8) Context {
        return .{
            .encrypt_ctx = Aes256.initEnc(key),
            .decrypt_ctx = Aes256.initDec(key),
        };
    }

    pub fn deinit(self: *Context) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    /// Encrypts with PKCS#7 padding. `out` must have room for one extra block.
    /// Returns the ciphertext length.
    pub fn encryptPkcs7(
        self: *const Context,
        out: []u8,
        iv: [block_length]u8,
        plaintext: []const u8,
    ) Error!usize {
        const padded_len = plaintext.len + (block_length - plaintext.len % block_length);
        if (out.len < padded_len) return error.BufferTooSmall;

        const pad: u8 = @intCast(block_length - plaintext.len % block_length);
        if (plaintext.ptr != out.ptr) {
            @memcpy(out[0..plaintext.len], plaintext);
        }
        @memset(out[plaintext.len..padded_len], pad);

        var previous = iv;
        var offset: usize = 0;
        while (offset < padded_len) : (offset += block_length) {
            var block: [block_length]u8 = undefined;
            for (0..block_length) |index| {
                block[index] = out[offset + index] ^ previous[index];
            }
            self.encrypt_ctx.encrypt(
                out[offset..][0..block_length],
                &block,
            );
            previous = out[offset..][0..block_length].*;
        }
        return padded_len;
    }

    /// Decrypts and validates PKCS#7 padding. Returns the plaintext length.
    pub fn decryptPkcs7(
        self: *const Context,
        out: []u8,
        iv: [block_length]u8,
        ciphertext: []const u8,
    ) Error!usize {
        if (ciphertext.len == 0 or
            ciphertext.len % block_length != 0)
        {
            return error.InvalidLength;
        }
        if (out.len < ciphertext.len) return error.BufferTooSmall;

        var previous = iv;
        var offset: usize = 0;
        while (offset < ciphertext.len) : (offset += block_length) {
            var decrypted: [block_length]u8 = undefined;
            self.decrypt_ctx.decrypt(
                &decrypted,
                ciphertext[offset..][0..block_length],
            );
            for (0..block_length) |index| {
                out[offset + index] = decrypted[index] ^ previous[index];
            }
            previous = ciphertext[offset..][0..block_length].*;
        }

        const pad = out[ciphertext.len - 1];
        if (pad == 0 or pad > block_length) return error.PaddingError;
        var index = ciphertext.len - pad;
        while (index < ciphertext.len) : (index += 1) {
            if (out[index] != pad) return error.PaddingError;
        }
        return ciphertext.len - pad;
    }
};

test "AES-256-CBC PKCS#7 round trip" {
    const key = [_]u8{0x42} ** key_length;
    const iv = [_]u8{0x13} ** block_length;
    var ctx = Context.init(key);
    defer ctx.deinit();

    var ciphertext: [64]u8 = undefined;
    const written = try ctx.encryptPkcs7(
        &ciphertext,
        iv,
        "openvpn cbc payload",
    );
    var plaintext: [64]u8 = undefined;
    const plaintext_len = try ctx.decryptPkcs7(
        &plaintext,
        iv,
        ciphertext[0..written],
    );
    try std.testing.expectEqualStrings(
        "openvpn cbc payload",
        plaintext[0..plaintext_len],
    );
}

test "invalid padding is rejected" {
    const key = [_]u8{1} ** key_length;
    const iv = [_]u8{2} ** block_length;
    var ctx = Context.init(key);
    defer ctx.deinit();
    var ciphertext: [32]u8 = [_]u8{0} ** 32;
    var plaintext: [32]u8 = undefined;
    try std.testing.expectError(
        error.PaddingError,
        ctx.decryptPkcs7(&plaintext, iv, &ciphertext),
    );
}
