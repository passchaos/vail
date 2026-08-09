//! Incremental TLS 1.3 transcript hashing.

const std = @import("std");
const secret = @import("secret.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384Hash = std.crypto.hash.sha2.Sha384;
pub const digest_len = Sha256.digest_length;

pub fn Hasher(comptime Hash: type) type {
    return struct {
        state: Hash = .init(.{}),

        pub const digest_len = Hash.digest_length;

        pub fn update(self: *@This(), bytes: []const u8) void {
            self.state.update(bytes);
        }

        pub fn digest(self: @This()) [Hash.digest_length]u8 {
            var state = self.state;
            var output: [Hash.digest_length]u8 = undefined;
            state.final(&output);
            return output;
        }

        pub fn hash(
            parts: []const []const u8,
        ) [Hash.digest_length]u8 {
            var transcript = @This(){};
            for (parts) |part| transcript.update(part);
            return transcript.digest();
        }
    };
}

pub const Sha256Transcript = Hasher(Sha256);
pub const Sha384 = Hasher(Sha384Hash);
pub const Transcript = Sha256Transcript;

/// Source-compatible SHA-256 one-shot transcript hashing.
pub const hash = Sha256Transcript.hash;

pub const Digest = struct {
    hash: secret.Hash,
    storage: [secret.max_len]u8,

    pub fn bytes(self: *const Digest) []const u8 {
        return self.storage[0..self.hash.len()];
    }

    pub fn sha256(self: Digest) error{HashMismatch}![32]u8 {
        if (self.hash != .sha256) return error.HashMismatch;
        return self.storage[0..32].*;
    }

    pub fn sha384(self: Digest) error{HashMismatch}![48]u8 {
        if (self.hash != .sha384) return error.HashMismatch;
        return self.storage;
    }
};

pub fn hashFor(
    algorithm: secret.Hash,
    parts: []const []const u8,
) Digest {
    var result = Digest{
        .hash = algorithm,
        .storage = [_]u8{0} ** secret.max_len,
    };
    switch (algorithm) {
        .sha256 => result.storage[0..32].* =
            Sha256Transcript.hash(parts),
        .sha384 => result.storage =
            Sha384.hash(parts),
    }
    return result;
}
