//! Stitched ARM64 AES-GCM kernels from AWS-LC (BoringSSL).
//!
//! The kernels interleave AES rounds with the PMULL GHASH over whole
//! ciphertext blocks: they update the GHASH accumulator and the counter block
//! in place. The caller absorbs the associated data, the final partial block,
//! and the length block, and derives the tag mask itself.

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.object_format == .macho and
    builtin.cpu.arch == .aarch64 and
    builtin.cpu.has(.aarch64, .aes) and
    builtin.mode != .Debug and
    builtin.mode != .ReleaseSmall;

/// OpenSSL-compatible AES key schedule layout expected by the kernels: the
/// round key bytes first, then the round count at byte offset 240.
pub const AesKey = extern struct {
    rd_key: [60]u32,
    rounds: u32,
};

/// Key-dependent state the stitched kernels need per prepared context.
pub const Stitched = if (enabled) struct {
    key: AesKey,
    htable: [16]u128,
} else struct {};

/// Pack the standard AES round key bytes into the OpenSSL schedule layout.
pub fn initKeySchedule(round_key_bytes: []const u8) AesKey {
    std.debug.assert(round_key_bytes.len % 16 == 0);
    std.debug.assert(round_key_bytes.len <= 15 * 16);
    var key: AesKey = undefined;
    @memset(std.mem.asBytes(&key), 0);
    @memcpy(std.mem.asBytes(&key.rd_key)[0..round_key_bytes.len], round_key_bytes);
    key.rounds = @intCast(round_key_bytes.len / 16 - 1);
    return key;
}

/// Derive the GHASH multiplication table. `hash_key` holds the 16-byte hash
/// key as two u64 halves read big-endian, matching the OpenSSL convention the
/// kernel expects.
pub fn initHtable(hash_key: *const [2]u64) [16]u128 {
    var table: [16]u128 = undefined;
    vailGcmInitArm64(&table, hash_key);
    return table;
}

/// Encrypt whole blocks, updating `xi` and `ivec` in place.
pub fn encrypt(
    key: *const AesKey,
    htable: *const [16]u128,
    xi: *[16]u8,
    ivec: *[16]u8,
    output: []u8,
    input: []const u8,
) void {
    const blocks = input.len / 16;
    if (blocks == 0) return;
    const bits: u64 = @intCast(blocks * 16 * 8);
    if (blocks >= 16) {
        switch (key.rounds) {
            10 => vailAesGcm8xEnc128Arm64(
                input.ptr,
                bits,
                output.ptr,
                xi,
                ivec,
                key,
                htable,
            ),
            12 => vailAesGcm8xEnc192Arm64(
                input.ptr,
                bits,
                output.ptr,
                xi,
                ivec,
                key,
                htable,
            ),
            14 => vailAesGcm8xEnc256Arm64(
                input.ptr,
                bits,
                output.ptr,
                xi,
                ivec,
                key,
                htable,
            ),
            else => unreachable,
        }
    } else {
        vailAesGcmEncKernelArm64(
            input.ptr,
            bits,
            output.ptr,
            xi,
            ivec,
            key,
            htable,
        );
    }
}

/// Decrypt whole blocks, updating `xi` and `ivec` in place.
pub fn decrypt(
    key: *const AesKey,
    htable: *const [16]u128,
    xi: *[16]u8,
    ivec: *[16]u8,
    output: []u8,
    input: []const u8,
) void {
    const blocks = input.len / 16;
    if (blocks == 0) return;
    const bits: u64 = @intCast(blocks * 16 * 8);
    if (blocks >= 16) {
        switch (key.rounds) {
            10 => vailAesGcm8xDec128Arm64(
                input.ptr,
                bits,
                output.ptr,
                xi,
                ivec,
                key,
                htable,
            ),
            12 => vailAesGcm8xDec192Arm64(
                input.ptr,
                bits,
                output.ptr,
                xi,
                ivec,
                key,
                htable,
            ),
            14 => vailAesGcm8xDec256Arm64(
                input.ptr,
                bits,
                output.ptr,
                xi,
                ivec,
                key,
                htable,
            ),
            else => unreachable,
        }
    } else {
        vailAesGcmDecKernelArm64(
            input.ptr,
            bits,
            output.ptr,
            xi,
            ivec,
            key,
            htable,
        );
    }
}

extern fn vailGcmInitArm64(
    htable: *[16]u128,
    h: *const [2]u64,
) callconv(.c) void;

extern fn vailAesGcmEncKernelArm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;

extern fn vailAesGcmDecKernelArm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;

extern fn vailAesGcm8xEnc128Arm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;

extern fn vailAesGcm8xDec128Arm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;

extern fn vailAesGcm8xEnc192Arm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;

extern fn vailAesGcm8xDec192Arm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;

extern fn vailAesGcm8xEnc256Arm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;

extern fn vailAesGcm8xDec256Arm64(
    in: [*]const u8,
    in_bits: u64,
    out: [*]u8,
    xi: *[16]u8,
    ivec: *[16]u8,
    key: *const AesKey,
    htable: *const [16]u128,
) callconv(.c) void;
