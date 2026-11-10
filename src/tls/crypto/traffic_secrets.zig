//! Owned record-layer secrets for transferring an established TLS connection
//! to kTLS or another external record implementation.

const std = @import("std");

pub const Version = enum {
    tls12,
    tls13,
};

pub const Algorithm = enum {
    aes_128_gcm,
    aes_128_ccm,
    aes_128_ccm_8,
    aes_256_gcm,
    chacha20_poly1305,
    sm4_gcm,
    sm4_ccm,

    pub fn keyLen(self: Algorithm) usize {
        return switch (self) {
            .aes_128_gcm, .aes_128_ccm, .aes_128_ccm_8, .sm4_gcm, .sm4_ccm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }
};

pub const Error = error{
    InvalidKeyLength,
    InvalidIvLength,
    SequenceExhausted,
};

/// One direction's current record key. `iv` is always the complete 12-byte
/// nonce base. For TLS 1.2 AES-GCM it is the four-byte fixed salt followed by
/// the eight-byte explicit-IV starting point; Vail starts that suffix at zero.
pub const Direction = struct {
    sequence_number: u64,
    generation: u64,
    algorithm: Algorithm,
    key_storage: [32]u8,
    key_len: u8,
    iv: [12]u8,

    pub fn init(
        sequence_number: u64,
        generation: u64,
        algorithm: Algorithm,
        key_bytes: []const u8,
        iv: []const u8,
    ) Error!Direction {
        if (key_bytes.len != algorithm.keyLen()) return error.InvalidKeyLength;
        if (iv.len != 12) return error.InvalidIvLength;
        var result = Direction{
            .sequence_number = sequence_number,
            .generation = generation,
            .algorithm = algorithm,
            .key_storage = [_]u8{0} ** 32,
            .key_len = @intCast(key_bytes.len),
            .iv = iv[0..12].*,
        };
        @memcpy(result.key_storage[0..key_bytes.len], key_bytes);
        return result;
    }

    pub fn key(self: *const Direction) []const u8 {
        return self.key_storage[0..self.key_len];
    }

    /// Big-endian record sequence encoding used by TLS AAD and Linux kTLS.
    pub fn sequenceBytes(self: *const Direction) [8]u8 {
        var encoded: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded, self.sequence_number, .big);
        return encoded;
    }

    pub fn deinit(self: *Direction) void {
        std.crypto.secureZero(u8, &self.key_storage);
        std.crypto.secureZero(u8, &self.iv);
        self.* = undefined;
    }
};

pub const Extracted = struct {
    version: Version,
    tx: Direction,
    rx: Direction,

    pub fn deinit(self: *Extracted) void {
        self.tx.deinit();
        self.rx.deinit();
        self.* = undefined;
    }
};

test "traffic-secret ownership validates sizes and wipes explicitly" {
    var direction = try Direction.init(
        7,
        2,
        .aes_128_gcm,
        &([_]u8{0x41} ** 16),
        &([_]u8{0x51} ** 12),
    );
    try std.testing.expectEqual(@as(u64, 7), direction.sequence_number);
    try std.testing.expectEqual(@as(u64, 2), direction.generation);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0x41} ** 16),
        direction.key(),
    );
    try std.testing.expectEqual(
        [_]u8{0} ** 7 ++ .{7},
        direction.sequenceBytes(),
    );
    try std.testing.expectError(
        error.InvalidKeyLength,
        Direction.init(0, 0, .aes_128_gcm, &([_]u8{0} ** 15), &([_]u8{0} ** 12)),
    );
    try std.testing.expectError(
        error.InvalidIvLength,
        Direction.init(0, 0, .aes_128_gcm, &([_]u8{0} ** 16), &([_]u8{0} ** 11)),
    );
    direction.deinit();
}
