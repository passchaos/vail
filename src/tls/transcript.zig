//! Incremental TLS 1.3 transcript hashing.

const std = @import("std");

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
