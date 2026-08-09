//! Runtime-owned TLS 1.3 secret values.
//!
//! Negotiation chooses the transcript hash at runtime, while each concrete
//! key schedule still benefits from fixed-size compile-time arrays. `Secret`
//! is the narrow bridge between those layers: it stores at most SHA-384's
//! 48 bytes, carries the hash identity, rejects length mismatches, and wipes
//! unused capacity so stale key material cannot leak through copies.

const std = @import("std");

pub const max_len: usize = std.crypto.hash.sha2.Sha384.digest_length;

pub const Hash = enum(u8) {
    sha256,
    sha384,

    pub fn len(self: Hash) usize {
        return switch (self) {
            .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
            .sha384 => std.crypto.hash.sha2.Sha384.digest_length,
        };
    }
};

pub const Error = error{
    InvalidSecretLength,
    HashMismatch,
};

pub const Secret = struct {
    hash: Hash,
    storage: [max_len]u8,

    pub fn fromSha256(value: [32]u8) Secret {
        return initUnchecked(.sha256, &value);
    }

    pub fn fromSha384(value: [48]u8) Secret {
        return initUnchecked(.sha384, &value);
    }

    pub fn init(hash: Hash, value: []const u8) Error!Secret {
        if (value.len != hash.len()) return error.InvalidSecretLength;
        return initUnchecked(hash, value);
    }

    pub fn bytes(self: *const Secret) []const u8 {
        return self.storage[0..self.hash.len()];
    }

    pub fn mutableBytes(self: *Secret) []u8 {
        return self.storage[0..self.hash.len()];
    }

    pub fn sha256(self: Secret) Error![32]u8 {
        if (self.hash != .sha256) return error.HashMismatch;
        return self.storage[0..32].*;
    }

    pub fn sha384(self: Secret) Error![48]u8 {
        if (self.hash != .sha384) return error.HashMismatch;
        return self.storage;
    }

    pub fn eql(self: *const Secret, other: *const Secret) bool {
        if (self.hash != other.hash) return false;
        // The length is public suite metadata, while all secret bytes are
        // compared in constant time by the standard crypto primitive.
        return switch (self.hash) {
            .sha256 => std.crypto.timing_safe.eql(
                [32]u8,
                self.storage[0..32].*,
                other.storage[0..32].*,
            ),
            .sha384 => std.crypto.timing_safe.eql(
                [48]u8,
                self.storage,
                other.storage,
            ),
        };
    }

    pub fn deinit(self: *Secret) void {
        std.crypto.secureZero(u8, &self.storage);
        self.* = undefined;
    }

    fn initUnchecked(hash: Hash, value: []const u8) Secret {
        var result = Secret{
            .hash = hash,
            .storage = [_]u8{0} ** max_len,
        };
        @memcpy(result.storage[0..value.len], value);
        return result;
    }
};

test "runtime TLS secrets enforce hash-bound lengths" {
    const sha256 = Secret.fromSha256([_]u8{0x21} ** 32);
    const sha384 = Secret.fromSha384([_]u8{0x38} ** 48);
    try std.testing.expectEqual(Hash.sha256, sha256.hash);
    try std.testing.expectEqual(@as(usize, 32), sha256.bytes().len);
    try std.testing.expectEqual(@as(usize, 48), sha384.bytes().len);
    try std.testing.expectError(
        error.HashMismatch,
        sha256.sha384(),
    );
    try std.testing.expectError(
        error.InvalidSecretLength,
        Secret.init(.sha384, &([_]u8{0} ** 32)),
    );
    try std.testing.expect(!sha256.eql(&sha384));
}
