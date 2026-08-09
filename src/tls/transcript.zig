//! Incremental TLS 1.3 SHA-256 transcript hashing.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const digest_len = Sha256.digest_length;

pub const Transcript = struct {
    state: Sha256 = .init(.{}),

    pub fn update(self: *Transcript, bytes: []const u8) void {
        self.state.update(bytes);
    }

    pub fn digest(self: Transcript) [digest_len]u8 {
        var state = self.state;
        var output: [digest_len]u8 = undefined;
        state.final(&output);
        return output;
    }
};

pub fn hash(parts: []const []const u8) [digest_len]u8 {
    var transcript = Transcript{};
    for (parts) |part| transcript.update(part);
    return transcript.digest();
}
