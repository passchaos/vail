//! Stitched ARM64 ChaCha20-Poly1305 kernels from AWS-LC (BoringSSL).
//!
//! A single call produces the ChaCha20 keystream, the ciphertext, and the
//! Poly1305 tag over the associated data and ciphertext. The caller compares
//! the tag in constant time and clears tentative plaintext on failure.

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.object_format == .macho and
    builtin.cpu.arch == .aarch64 and
    builtin.cpu.has(.aarch64, .neon) and
    builtin.mode != .Debug and
    builtin.mode != .ReleaseSmall;

/// Input block shared with the kernels. The computed tag is written to the
/// first 16 bytes, which overlap `key` as in the C union.
pub const Data = extern struct {
    key: [32]u8,
    counter: u32,
    nonce: [12]u8,
    extra_ciphertext: ?[*]const u8,
    extra_ciphertext_len: usize,
};

/// Encrypt `plaintext` into `ciphertext` and write the tag to `tag`.
pub fn seal(
    ciphertext: []u8,
    tag: *[16]u8,
    plaintext: []const u8,
    associated_data: []const u8,
    nonce: [12]u8,
    key: [32]u8,
) void {
    std.debug.assert(ciphertext.len == plaintext.len);
    var data: Data align(16) = .{
        .key = key,
        .counter = 0,
        .nonce = nonce,
        .extra_ciphertext = null,
        .extra_ciphertext_len = 0,
    };
    vailChacha20Poly1305SealArm64(
        ciphertext.ptr,
        plaintext.ptr,
        plaintext.len,
        associated_data.ptr,
        associated_data.len,
        &data,
    );
    tag.* = data.key[0..16].*;
    std.crypto.secureZero(u8, std.mem.asBytes(&data));
}

/// Decrypt `ciphertext` into `plaintext` and verify the tag. The output
/// buffer holds tentative plaintext when authentication fails.
pub fn open(
    plaintext: []u8,
    ciphertext: []const u8,
    tag: [16]u8,
    associated_data: []const u8,
    nonce: [12]u8,
    key: [32]u8,
) !void {
    std.debug.assert(plaintext.len == ciphertext.len);
    var data: Data align(16) = .{
        .key = key,
        .counter = 0,
        .nonce = nonce,
        .extra_ciphertext = null,
        .extra_ciphertext_len = 0,
    };
    vailChacha20Poly1305OpenArm64(
        plaintext.ptr,
        ciphertext.ptr,
        ciphertext.len,
        associated_data.ptr,
        associated_data.len,
        &data,
    );
    const computed: [16]u8 = data.key[0..16].*;
    std.crypto.secureZero(u8, std.mem.asBytes(&data));
    if (!std.crypto.timing_safe.eql([16]u8, computed, tag)) {
        return error.AuthenticationFailed;
    }
}

extern fn vailChacha20Poly1305SealArm64(
    ciphertext: [*]u8,
    plaintext: [*]const u8,
    plaintext_len: usize,
    associated_data: [*]const u8,
    associated_data_len: usize,
    data: *Data,
) callconv(.c) void;

extern fn vailChacha20Poly1305OpenArm64(
    plaintext: [*]u8,
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    associated_data: [*]const u8,
    associated_data_len: usize,
    data: *Data,
) callconv(.c) void;
