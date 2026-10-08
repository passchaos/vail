//! Incremental TLS 1.3 transcript hashing.

const std = @import("std");
const sha256 = @import("../crypto/sha256.zig");
const fast_sha2 = @import("../crypto/sha512.zig");
const sm3 = @import("../crypto/sm3.zig");
const secret = @import("secret.zig");

const Sha256 = sha256.Hash;
const Sha384Hash = fast_sha2.Sha384;
const Sm3Hash = sm3.Hash;
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
pub const Sm3 = Hasher(Sm3Hash);
pub const Transcript = Sha256Transcript;

/// Source-compatible SHA-256 one-shot transcript hashing.
pub const hash = Sha256Transcript.hash;

/// Runtime-selected incremental transcript state.
///
/// TLS 1.3 chooses its transcript hash with the cipher suite. Keeping the
/// concrete hash state, rather than only its digest, allows a server to extend
/// the transcript with a client's Certificate/CertificateVerify/Finished
/// flight after its own Finished has already been emitted.
pub const State = union(secret.Hash) {
    sha256: Sha256Transcript,
    sha384: Sha384,
    sm3: Sm3,

    pub fn init(algorithm: secret.Hash) State {
        return switch (algorithm) {
            .sha256 => .{ .sha256 = .{} },
            .sha384 => .{ .sha384 = .{} },
            .sm3 => .{ .sm3 = .{} },
        };
    }

    pub fn update(self: *State, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*state| state.update(bytes),
        }
    }

    pub fn digest(self: State) Digest {
        var result = Digest{
            .hash = std.meta.activeTag(self),
            .storage = [_]u8{0} ** secret.max_len,
        };
        switch (self) {
            .sha256 => |state| {
                result.storage[0..32].* = state.digest();
            },
            .sha384 => |state| {
                result.storage = state.digest();
            },
            .sm3 => |state| {
                result.storage[0..32].* = state.digest();
            },
        }
        return result;
    }
};

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

    pub fn sm3(self: Digest) error{HashMismatch}![32]u8 {
        if (self.hash != .sm3) return error.HashMismatch;
        return self.storage[0..32].*;
    }
};

pub fn hashFor(
    algorithm: secret.Hash,
    parts: []const []const u8,
) Digest {
    var state = State.init(algorithm);
    for (parts) |part| state.update(part);
    return state.digest();
}

/// Construct the transcript after a TLS 1.3 HelloRetryRequest.
///
/// RFC 8446 section 4.4.1 replaces ClientHello1 with a synthetic
/// `message_hash` handshake message containing Hash(ClientHello1), then hashes
/// the exact HelloRetryRequest bytes.
pub fn afterHelloRetryRequest(
    algorithm: secret.Hash,
    first_client_hello: []const u8,
    hello_retry_request: []const u8,
) State {
    const first_hash = hashFor(algorithm, &.{first_client_hello});
    var message_hash_header = [4]u8{
        254,
        0,
        0,
        @intCast(first_hash.bytes().len),
    };
    var state = State.init(algorithm);
    state.update(&message_hash_header);
    state.update(first_hash.bytes());
    state.update(hello_retry_request);
    return state;
}

test "runtime transcript state extends a negotiated hash" {
    inline for ([_]secret.Hash{ .sha256, .sha384, .sm3 }) |algorithm| {
        var state = State.init(algorithm);
        state.update("client");
        const before = state.digest();
        state.update("server");
        const after = state.digest();
        try std.testing.expectEqualSlices(
            u8,
            hashFor(algorithm, &.{"client"}).bytes(),
            before.bytes(),
        );
        try std.testing.expectEqualSlices(
            u8,
            hashFor(algorithm, &.{ "client", "server" }).bytes(),
            after.bytes(),
        );
    }
}

test "HelloRetryRequest transcript uses synthetic message_hash" {
    inline for ([_]secret.Hash{ .sha256, .sha384, .sm3 }) |algorithm| {
        const first = "first ClientHello";
        const retry = "HelloRetryRequest";
        const first_hash = hashFor(algorithm, &.{first});
        const header = [_]u8{
            254,
            0,
            0,
            @intCast(first_hash.bytes().len),
        };
        const expected = hashFor(
            algorithm,
            &.{ &header, first_hash.bytes(), retry },
        );
        const actual = afterHelloRetryRequest(algorithm, first, retry).digest();
        try std.testing.expectEqualSlices(
            u8,
            expected.bytes(),
            actual.bytes(),
        );
    }
}
