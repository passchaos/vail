//! Stateful TLS 1.3 record protection.
//!
//! `record.Keys` exposes the raw sequence-number API used by low-level tests.
//! `State` is the connection-facing wrapper: it owns one directional traffic
//! secret, prevents nonce reuse, advances the sequence only after successful
//! protection, and performs atomic traffic-secret updates.

const std = @import("std");
const cipher_suite = @import("cipher_suite.zig");
const key_schedule = @import("key_schedule.zig");
const record = @import("../record.zig");
const record_fragment = @import("../record_fragment.zig");
const secret = @import("secret.zig");
const traffic_secrets = @import("traffic_secrets.zig");

pub const Error = record.Error || key_schedule.Error || error{
    SequenceExhausted,
    KeyUpdateRequired,
    ConfidentialityLimitReached,
    KeyGenerationExhausted,
};

pub const State = struct {
    suite: cipher_suite.Suite,
    traffic_secret: secret.Secret,
    keys: record.Keys,
    next_sequence_number: u64 = 0,
    generation: u64 = 0,

    /// Initialize one read or write direction. The state owns its copy of
    /// `traffic_secret` and wipes it in `deinit`.
    pub fn init(
        suite: cipher_suite.Suite,
        traffic_secret: secret.Secret,
    ) Error!State {
        return .{
            .suite = suite,
            .traffic_secret = traffic_secret,
            .keys = try record.Keys.derive(suite, traffic_secret),
        };
    }

    pub fn deinit(self: *State) void {
        self.keys.deinit();
        self.traffic_secret.deinit();
        self.* = undefined;
    }

    pub fn sequenceNumber(self: *const State) ?u64 {
        return if (self.next_sequence_number == std.math.maxInt(u64))
            null
        else
            self.next_sequence_number;
    }

    pub fn extractedDirection(
        self: *const State,
    ) Error!traffic_secrets.Direction {
        const sequence = self.sequenceNumber() orelse
            return error.SequenceExhausted;
        const algorithm: traffic_secrets.Algorithm = switch (self.suite) {
            .aes_128_gcm_sha256 => .aes_128_gcm,
            .aes_128_ccm_sha256 => .aes_128_ccm,
            .aes_128_ccm_8_sha256 => .aes_128_ccm_8,
            .aes_256_gcm_sha384 => .aes_256_gcm,
            .chacha20_poly1305_sha256 => .chacha20_poly1305,
            .sm4_gcm_sm3 => .sm4_gcm,
            .sm4_ccm_sm3 => .sm4_ccm,
        };
        return traffic_secrets.Direction.init(
            sequence,
            self.generation,
            algorithm,
            self.keys.key[0..self.suite.keyLen()],
            &self.keys.iv,
        ) catch unreachable;
    }

    pub inline fn seal(
        self: *State,
        inner_type: u8,
        plaintext: []const u8,
        output: []u8,
    ) Error!usize {
        return self.sealPadded(inner_type, plaintext, 0, output);
    }

    /// Seal exactly one non-empty record containing at most
    /// `max_fragment_plaintext` bytes and report explicit caller progress.
    pub fn sealFragment(
        self: *State,
        inner_type: u8,
        plaintext: []const u8,
        max_fragment_plaintext: usize,
        output: []u8,
    ) Error!record_fragment.SealResult {
        const fragment = try record_fragment.selectPlaintext(
            plaintext,
            max_fragment_plaintext,
            record.max_plaintext_len,
        );
        const written = try self.seal(inner_type, fragment, output);
        return .{
            .plaintext_consumed = fragment.len,
            .output_written = written,
        };
    }

    pub inline fn sealPadded(
        self: *State,
        inner_type: u8,
        plaintext: []const u8,
        padding_len: usize,
        output: []u8,
    ) Error!usize {
        const sequence = try self.currentWriteSequence();
        const len = try self.keys.sealPadded(
            sequence,
            inner_type,
            plaintext,
            padding_len,
            output,
        );
        self.advanceSequence();
        return len;
    }

    /// Seal the KeyUpdate record reserved at the end of a traffic generation.
    /// Ordinary records are rejected one record earlier so the connection can
    /// always transmit this transition without exceeding the AEAD bound.
    pub inline fn sealForKeyUpdate(
        self: *State,
        plaintext: []const u8,
        output: []u8,
    ) Error!usize {
        const sequence = try self.currentReservedWriteSequence();
        const len = try self.keys.seal(
            sequence,
            record.content_type_handshake,
            plaintext,
            output,
        );
        self.advanceSequence();
        return len;
    }

    pub inline fn open(
        self: *State,
        ciphertext: []const u8,
        plaintext: []u8,
    ) Error!record.Opened {
        const sequence = try self.currentReadSequence();
        const opened = try self.keys.open(sequence, ciphertext, plaintext);
        self.advanceSequence();
        return opened;
    }

    pub fn canUpdate(self: *const State) bool {
        return self.generation != std.math.maxInt(u64);
    }

    pub fn needsUpdate(self: *const State) bool {
        const limit = self.suite.tlsConfidentialityLimit();
        return limit != std.math.maxInt(u64) and
            self.next_sequence_number >= limit - 1;
    }

    /// Advance to RFC 8446's next `traffic upd` generation and reset the
    /// sequence number. New key material is fully derived before old material
    /// is destroyed, leaving the state unchanged if derivation fails.
    pub fn update(self: *State) Error!void {
        if (!self.canUpdate()) return error.KeyGenerationExhausted;

        var next_secret = try key_schedule.nextTrafficSecretFor(
            self.traffic_secret,
        );
        errdefer next_secret.deinit();
        var next_keys = try record.Keys.derive(self.suite, next_secret);
        errdefer next_keys.deinit();

        self.keys.deinit();
        self.traffic_secret.deinit();
        self.keys = next_keys;
        self.traffic_secret = next_secret;
        self.next_sequence_number = 0;
        self.generation += 1;
    }

    fn currentWriteSequence(self: *const State) Error!u64 {
        const sequence = try self.currentReadSequence();
        if (self.needsUpdate()) {
            @branchHint(.unlikely);
            return error.KeyUpdateRequired;
        }
        return sequence;
    }

    fn currentReservedWriteSequence(self: *const State) Error!u64 {
        const sequence = try self.currentReadSequence();
        if (sequence >= self.suite.tlsConfidentialityLimit()) {
            return error.ConfidentialityLimitReached;
        }
        return sequence;
    }

    fn currentReadSequence(self: *const State) Error!u64 {
        // Reserve maxInt(u64) as an exhausted sentinel. TLS AEAD usage limits
        // are much lower, so sacrificing this unreachable final nonce avoids
        // carrying and branching on a separate flag in every hot-path record.
        if (self.next_sequence_number == std.math.maxInt(u64)) {
            @branchHint(.unlikely);
            return error.SequenceExhausted;
        }
        return self.next_sequence_number;
    }

    fn advanceSequence(self: *State) void {
        self.next_sequence_number += 1;
    }
};

test "traffic state advances sequence only after successful records" {
    const initial = secret.Secret.fromSha256([_]u8{0x41} ** 32);
    var sender = try State.init(.aes_128_gcm_sha256, initial);
    defer sender.deinit();
    var receiver = try State.init(.aes_128_gcm_sha256, initial);
    defer receiver.deinit();

    var first: [128]u8 = undefined;
    const first_len = try sender.seal(
        record.content_type_application_data,
        "first",
        &first,
    );
    var second: [128]u8 = undefined;
    const second_len = try sender.seal(
        record.content_type_application_data,
        "second",
        &second,
    );
    try std.testing.expectEqual(@as(?u64, 2), sender.sequenceNumber());

    var plaintext: [128]u8 = undefined;
    const opened_first = try receiver.open(first[0..first_len], &plaintext);
    try std.testing.expectEqualStrings("first", plaintext[0..opened_first.len]);
    try std.testing.expectEqual(@as(?u64, 1), receiver.sequenceNumber());

    try std.testing.expectError(
        error.AuthenticationFailed,
        receiver.open(first[0..first_len], &plaintext),
    );
    try std.testing.expectEqual(@as(?u64, 1), receiver.sequenceNumber());

    const opened_second = try receiver.open(second[0..second_len], &plaintext);
    try std.testing.expectEqualStrings("second", plaintext[0..opened_second.len]);
    try std.testing.expectEqual(@as(?u64, 2), receiver.sequenceNumber());
}

test "CCM-8 traffic-secret extraction preserves the short-tag algorithm" {
    const initial = secret.Secret.fromSha256([_]u8{0x45} ** 32);
    var state = try State.init(.aes_128_ccm_8_sha256, initial);
    defer state.deinit();
    var direction = try state.extractedDirection();
    defer direction.deinit();
    try std.testing.expectEqual(
        traffic_secrets.Algorithm.aes_128_ccm_8,
        direction.algorithm,
    );
    try std.testing.expectEqual(@as(usize, 16), direction.key().len);
}

test "SM4-CCM traffic-secret extraction preserves the algorithm" {
    const initial = secret.Secret.fromSm3([_]u8{0x46} ** 32);
    var state = try State.init(.sm4_ccm_sm3, initial);
    defer state.deinit();
    var direction = try state.extractedDirection();
    defer direction.deinit();
    try std.testing.expectEqual(
        traffic_secrets.Algorithm.sm4_ccm,
        direction.algorithm,
    );
    try std.testing.expectEqual(@as(usize, 16), direction.key().len);
}

test "traffic update resets sequence and invalidates old keys" {
    inline for ([_]cipher_suite.Suite{
        .aes_128_gcm_sha256,
        .aes_128_ccm_sha256,
        .aes_128_ccm_8_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
        .sm4_gcm_sm3,
        .sm4_ccm_sm3,
    }) |suite| {
        const initial = switch (suite.hash()) {
            .sha256 => secret.Secret.fromSha256([_]u8{0x71} ** 32),
            .sha384 => secret.Secret.fromSha384([_]u8{0x72} ** 48),
            .sm3 => secret.Secret.fromSm3([_]u8{0x73} ** 32),
        };
        var sender = try State.init(suite, initial);
        defer sender.deinit();
        var receiver = try State.init(suite, initial);
        defer receiver.deinit();
        var stale_receiver = try State.init(suite, initial);
        defer stale_receiver.deinit();

        try sender.update();
        try receiver.update();
        try std.testing.expectEqual(@as(u64, 1), sender.generation);
        try std.testing.expectEqual(@as(?u64, 0), sender.sequenceNumber());

        var ciphertext: [128]u8 = undefined;
        const ciphertext_len = try sender.seal(
            record.content_type_application_data,
            "new generation",
            &ciphertext,
        );
        var plaintext: [128]u8 = undefined;
        try std.testing.expectError(
            error.AuthenticationFailed,
            stale_receiver.open(ciphertext[0..ciphertext_len], &plaintext),
        );
        const opened = try receiver.open(
            ciphertext[0..ciphertext_len],
            &plaintext,
        );
        try std.testing.expectEqualStrings(
            "new generation",
            plaintext[0..opened.len],
        );
    }
}

test "traffic state fails closed when the sequence is exhausted" {
    const initial = secret.Secret.fromSha256([_]u8{0x51} ** 32);
    var state = try State.init(.chacha20_poly1305_sha256, initial);
    defer state.deinit();
    state.next_sequence_number = std.math.maxInt(u64) - 1;

    var ciphertext: [64]u8 = undefined;
    _ = try state.seal(
        record.content_type_application_data,
        "last",
        &ciphertext,
    );
    try std.testing.expectEqual(@as(?u64, null), state.sequenceNumber());
    try std.testing.expectError(
        error.SequenceExhausted,
        state.seal(
            record.content_type_application_data,
            "never reuse nonce",
            &ciphertext,
        ),
    );
}

test "traffic state requires updates at AEAD confidentiality limits" {
    inline for ([_]cipher_suite.Suite{
        .aes_128_gcm_sha256,
        .aes_128_ccm_sha256,
        .aes_128_ccm_8_sha256,
        .aes_256_gcm_sha384,
        .sm4_gcm_sm3,
        .sm4_ccm_sm3,
    }) |suite| {
        const initial = switch (suite.hash()) {
            .sha256 => secret.Secret.fromSha256([_]u8{0x61} ** 32),
            .sha384 => secret.Secret.fromSha384([_]u8{0x62} ** 48),
            .sm3 => secret.Secret.fromSm3([_]u8{0x63} ** 32),
        };
        var state = try State.init(suite, initial);
        defer state.deinit();
        state.next_sequence_number = suite.tlsConfidentialityLimit() - 1;
        try std.testing.expect(state.needsUpdate());

        var ciphertext: [64]u8 = undefined;
        try std.testing.expectError(
            error.KeyUpdateRequired,
            state.seal(
                record.content_type_application_data,
                "rotate first",
                &ciphertext,
            ),
        );
        const key_update_message = [_]u8{ 24, 0, 0, 1, 0 };
        _ = try state.sealForKeyUpdate(
            &key_update_message,
            &ciphertext,
        );
        try std.testing.expectError(
            error.ConfidentialityLimitReached,
            state.sealForKeyUpdate(&key_update_message, &ciphertext),
        );
        try state.update();
        try std.testing.expect(!state.needsUpdate());
        try std.testing.expectEqual(@as(?u64, 0), state.sequenceNumber());
    }
}
