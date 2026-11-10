//! BLAKE2s primitives used by WireGuard and other lightweight protocols.
//!
//! WireGuard uses BLAKE2s-256 for its Noise transcript hash, HMAC-BLAKE2s-256
//! inside HKDF, and keyed BLAKE2s-128 for MAC1/MAC2 and cookies. Keeping these
//! wrappers here gives protocol libraries a single audited implementation.

const std = @import("std");

const Blake2s256Impl = std.crypto.hash.blake2.Blake2s256;
const Blake2s128Impl = std.crypto.hash.blake2.Blake2s128;

pub const digest_length = 32;
pub const short_digest_length = 16;
pub const block_length = Blake2s256Impl.block_length;
pub const key_length_max = Blake2s256Impl.key_length_max;

pub const Digest = [digest_length]u8;
pub const ShortDigest = [short_digest_length]u8;

/// HMAC keyed with BLAKE2s-256, as required by WireGuard's HKDF construction.
pub const Hmac = std.crypto.auth.hmac.Hmac(Blake2s256Impl);

pub fn hash(input: []const u8) Digest {
    var out: Digest = undefined;
    Blake2s256Impl.hash(input, &out, .{});
    return out;
}

/// Hashes several byte ranges as one logical input without allocating.
pub fn hashParts(parts: []const []const u8) Digest {
    var state = Blake2s256Impl.init(.{});
    for (parts) |part| state.update(part);
    var out: Digest = undefined;
    state.final(&out);
    return out;
}

pub fn hash128(input: []const u8) ShortDigest {
    var out: ShortDigest = undefined;
    Blake2s128Impl.hash(input, &out, .{});
    return out;
}

/// Keyed BLAKE2s-256. `key` must be at most 32 bytes; longer keys are rejected
/// by the standard library in safe builds.
pub fn keyedHash(key: []const u8, input: []const u8) Digest {
    var out: Digest = undefined;
    Blake2s256Impl.hash(input, &out, .{ .key = key });
    return out;
}

/// Keyed BLAKE2s-128 used for WireGuard MAC1, MAC2, and cookies.
pub fn keyedHash128(key: []const u8, input: []const u8) ShortDigest {
    var out: ShortDigest = undefined;
    Blake2s128Impl.hash(input, &out, .{ .key = key });
    return out;
}

/// Incremental keyed BLAKE2s-128 for bounded, streaming MAC computation.
pub const KeyedHash128 = struct {
    state: Blake2s128Impl,
    out: ShortDigest = undefined,

    pub fn init(key: []const u8) KeyedHash128 {
        return .{ .state = Blake2s128Impl.init(.{ .key = key }) };
    }

    pub fn update(self: *KeyedHash128, input: []const u8) void {
        self.state.update(input);
    }

    pub fn final(self: *KeyedHash128) ShortDigest {
        self.state.final(&self.out);
        return self.out;
    }
};

test "BLAKE2s-256 empty vector" {
    try std.testing.expectEqual(
        Digest{
            0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
            0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
            0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
            0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
        },
        hash(""),
    );
}

test "BLAKE2s-128 keyed matches std" {
    const key = "wireguard-cookie";
    const message = "source-ip-and-port";
    var expected: ShortDigest = undefined;
    std.crypto.hash.blake2.Blake2s128.hash(
        message,
        &expected,
        .{ .key = key },
    );
    try std.testing.expectEqual(expected, keyedHash128(key, message));
}

test "HMAC-BLAKE2s-256 known vector" {
    // HMAC-BLAKE2s-256 with key "key" and message "The quick brown fox jumps
    // over the lazy dog", matching the Go/Rust WireGuard implementations.
    const expected: Digest = .{
        0xf9, 0x32, 0x15, 0xbb, 0x90, 0xd4, 0xaf, 0x4c,
        0x30, 0x61, 0xcd, 0x93, 0x2f, 0xb1, 0x69, 0xfb,
        0x8b, 0xb8, 0xa9, 0x1d, 0x0b, 0x40, 0x22, 0xba,
        0xea, 0x12, 0x71, 0xe1, 0x32, 0x3c, 0xd9, 0xa0,
    };
    var actual: Digest = undefined;
    Hmac.create(&actual, "The quick brown fox jumps over the lazy dog", "key");
    try std.testing.expectEqual(expected, actual);
}
