//! SHA-256 digest, prepared HMAC/HKDF expansion, and constant-time comparison.

const std = @import("std");
const builtin = @import("builtin");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const digest_len = Sha256.digest_length;
pub const Digest = [digest_len]u8;

const accelerated = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    builtin.zig_backend != .stage2_c and
    std.Target.x86.featureSetHas(builtin.cpu.features, .sha) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

pub const Hash = if (accelerated) AcceleratedSha256 else Sha256;

pub fn hash(bytes: []const u8) Digest {
    var output: Digest = undefined;
    Hash.hash(bytes, &output, .{});
    return output;
}

pub fn eql(expected: Digest, received: Digest) bool {
    return std.crypto.timing_safe.eql(Digest, expected, received);
}

/// Reusable HMAC-SHA-256 state for several short messages under the same
/// 32-byte key. TLS 1.3 and QUIC derive multiple labelled values from one
/// HKDF PRK; retaining the states after the ipad and opad blocks avoids two
/// redundant SHA-256 compressions for every additional label.
pub const PreparedHmac = struct {
    inner: Sha256,
    outer: Sha256,

    pub fn init(key: *const Digest) PreparedHmac {
        var result: PreparedHmac = undefined;
        result.initInto(key);
        return result;
    }

    pub fn initInto(self: *PreparedHmac, key: *const Digest) void {
        var pad = [_]u8{0x36} ** Sha256.block_length;
        defer std.crypto.secureZero(u8, &pad);
        for (key, 0..) |byte, index| pad[index] ^= byte;

        self.inner = Sha256.init(.{});
        self.inner.update(&pad);

        for (&pad) |*byte| byte.* ^= 0x36 ^ 0x5c;
        self.outer = Sha256.init(.{});
        self.outer.update(&pad);
    }

    pub fn create(
        self: *const PreparedHmac,
        output: *Digest,
        message: []const u8,
    ) void {
        if (comptime accelerated) {
            if (message.len >= Sha256.block_length) {
                self.createAccelerated(output, message);
                return;
            }
        }
        var inner = self.inner;
        defer std.crypto.secureZero(Sha256, (&inner)[0..1]);
        inner.update(message);

        var inner_digest: Digest = undefined;
        defer std.crypto.secureZero(u8, &inner_digest);
        inner.final(&inner_digest);

        var outer = self.outer;
        defer std.crypto.secureZero(Sha256, (&outer)[0..1]);
        outer.update(&inner_digest);
        outer.final(output);
    }

    fn createAccelerated(
        self: *const PreparedHmac,
        output: *Digest,
        message: []const u8,
    ) void {
        var inner_state = self.inner.s;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&inner_state));
        var block = [_]u8{0} ** Sha256.block_length;
        defer std.crypto.secureZero(u8, &block);

        const full_blocks = message.len / Sha256.block_length;
        const remainder = message[full_blocks * Sha256.block_length ..];
        @memcpy(block[0..remainder.len], remainder);
        block[remainder.len] = 0x80;
        const message_blocks: *const [Sha256.block_length]u8 =
            @ptrCast(message.ptr);
        if (remainder.len <= Sha256.block_length - 9) {
            std.mem.writeInt(
                u64,
                block[56..64],
                (Sha256.block_length +
                    @as(u64, @intCast(message.len))) * 8,
                .big,
            );
            sha256Blocks(
                &inner_state,
                message_blocks,
                full_blocks,
                &block,
                true,
            );
        } else {
            sha256Blocks(
                &inner_state,
                message_blocks,
                full_blocks,
                &block,
                true,
            );
            @memset(&block, 0);
            std.mem.writeInt(
                u64,
                block[56..64],
                (Sha256.block_length +
                    @as(u64, @intCast(message.len))) * 8,
                .big,
            );
            sha256Blocks(&inner_state, &block, 1, &block, false);
        }

        @memset(&block, 0);
        writeDigest(&inner_state, block[0..digest_len]);
        block[digest_len] = 0x80;
        std.mem.writeInt(
            u64,
            block[56..64],
            (Sha256.block_length + digest_len) * 8,
            .big,
        );

        var outer = self.outer;
        defer std.crypto.secureZero(Sha256, (&outer)[0..1]);
        outer.update(&block);
        writeDigest(&outer.s, output);
    }

    pub fn createShort(
        self: *const PreparedHmac,
        output: *Digest,
        message: []const u8,
    ) void {
        std.debug.assert(message.len <= 55);
        var block = [_]u8{0} ** Sha256.block_length;
        defer std.crypto.secureZero(u8, &block);
        @memcpy(block[0..message.len], message);
        block[message.len] = 0x80;
        std.mem.writeInt(
            u64,
            block[56..64],
            (Sha256.block_length + @as(u64, @intCast(message.len))) * 8,
            .big,
        );

        var inner = self.inner;
        defer std.crypto.secureZero(Sha256, (&inner)[0..1]);
        inner.update(&block);

        @memset(&block, 0);
        for (inner.s, 0..) |word, index| {
            std.mem.writeInt(u32, block[index * 4 ..][0..4], word, .big);
        }
        block[digest_len] = 0x80;
        std.mem.writeInt(
            u64,
            block[56..64],
            (Sha256.block_length + digest_len) * 8,
            .big,
        );

        var outer = self.outer;
        defer std.crypto.secureZero(Sha256, (&outer)[0..1]);
        outer.update(&block);
        for (outer.s, 0..) |word, index| {
            std.mem.writeInt(u32, output[index * 4 ..][0..4], word, .big);
        }
    }

    /// Expand one HKDF-SHA-256 output block with an RFC 8446 label.
    pub fn expandLabel(
        self: *const PreparedHmac,
        label: []const u8,
        context: []const u8,
        comptime output_len: usize,
    ) [output_len]u8 {
        comptime std.debug.assert(output_len <= digest_len);
        std.debug.assert(label.len <= 249);
        std.debug.assert(context.len <= 255);

        const tls13 = "tls13 ";
        var encoded: [2 + 1 + tls13.len + 249 + 1 + 255 + 1]u8 = undefined;
        std.mem.writeInt(u16, encoded[0..2], output_len, .big);
        encoded[2] = @intCast(tls13.len + label.len);
        @memcpy(encoded[3..][0..tls13.len], tls13);
        var offset: usize = 3 + tls13.len;
        @memcpy(encoded[offset..][0..label.len], label);
        offset += label.len;
        encoded[offset] = @intCast(context.len);
        offset += 1;
        @memcpy(encoded[offset..][0..context.len], context);
        offset += context.len;
        encoded[offset] = 1;
        offset += 1;

        var full: Digest = undefined;
        if (offset <= 55) {
            self.createShort(&full, encoded[0..offset]);
        } else {
            self.create(&full, encoded[0..offset]);
        }
        if (comptime output_len == digest_len) return full;
        defer std.crypto.secureZero(u8, &full);
        return full[0..output_len].*;
    }

    pub fn deinit(self: *PreparedHmac) void {
        std.crypto.secureZero(PreparedHmac, self[0..1]);
        self.* = undefined;
    }
};

fn hashAccelerated(input: []const u8, output: *Digest) void {
    std.debug.assert(input.len >= Sha256.block_length);
    var state = Sha256.init(.{}).s;
    const full_blocks = input.len / Sha256.block_length;
    const remainder = input[full_blocks * Sha256.block_length ..];
    var block = [_]u8{0} ** Sha256.block_length;
    @memcpy(block[0..remainder.len], remainder);
    block[remainder.len] = 0x80;
    const blocks: *const [Sha256.block_length]u8 = @ptrCast(input.ptr);
    if (remainder.len <= Sha256.block_length - 9) {
        std.mem.writeInt(
            u64,
            block[56..64],
            @as(u64, @intCast(input.len)) * 8,
            .big,
        );
        sha256Blocks(&state, blocks, full_blocks, &block, true);
    } else {
        sha256Blocks(&state, blocks, full_blocks, &block, true);
        @memset(&block, 0);
        std.mem.writeInt(
            u64,
            block[56..64],
            @as(u64, @intCast(input.len)) * 8,
            .big,
        );
        sha256Blocks(&state, &block, 1, &block, false);
    }
    writeDigest(&state, output);
}

fn writeDigest(state: *const [8]u32, output: []u8) void {
    for (state[0 .. output.len / 4], 0..) |word, index| {
        std.mem.writeInt(u32, output[index * 4 ..][0..4], word, .big);
    }
}

const AcceleratedSha256 = struct {
    const Self = @This();

    pub const block_length = Sha256.block_length;
    pub const digest_length = Sha256.digest_length;
    pub const Options = struct {};

    s: [8]u32 align(16),
    buf: [block_length]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init(options: Options) Self {
        _ = options;
        return .{ .s = Sha256.init(.{}).s };
    }

    pub fn hash(input: []const u8, output: *Digest, options: Options) void {
        _ = options;
        if (input.len <= block_length - 9) {
            hashShort(input, output);
            return;
        }
        if (input.len >= block_length) {
            hashAccelerated(input, output);
            return;
        }
        Sha256.hash(input, output, .{});
    }

    pub fn update(state: *Self, input: []const u8) void {
        var offset: usize = 0;
        if (state.buf_len != 0 and state.buf_len + input.len >= block_length) {
            const needed = block_length - state.buf_len;
            @memcpy(state.buf[state.buf_len..][0..needed], input[0..needed]);
            state.compress(&state.buf, 1);
            state.buf_len = 0;
            offset = needed;
        }

        const full_blocks = (input.len - offset) / block_length;
        if (full_blocks != 0) {
            const blocks: *const [block_length]u8 = @ptrCast(input[offset..].ptr);
            state.compress(blocks, full_blocks);
            offset += full_blocks * block_length;
        }

        const remainder = input[offset..];
        @memcpy(state.buf[state.buf_len..][0..remainder.len], remainder);
        state.buf_len += @intCast(remainder.len);
        state.total_len += input.len;
    }

    pub fn peek(state: Self) Digest {
        var copy = state;
        return copy.finalResult();
    }

    pub fn final(state: *Self, output: *Digest) void {
        @memset(state.buf[state.buf_len..], 0);
        state.buf[state.buf_len] = 0x80;
        state.buf_len += 1;
        if (block_length - state.buf_len < 8) {
            state.compress(&state.buf, 1);
            @memset(&state.buf, 0);
        }

        std.mem.writeInt(u64, state.buf[56..64], state.total_len *% 8, .big);
        state.compress(&state.buf, 1);
        writeDigest(&state.s, output);
    }

    pub fn finalResult(state: *Self) Digest {
        var output: Digest = undefined;
        state.final(&output);
        return output;
    }

    fn compress(
        state: *Self,
        blocks: *const [block_length]u8,
        block_count: usize,
    ) void {
        if (block_count == 1) {
            var standard = Sha256.init(.{});
            standard.s = state.s;
            standard.update(blocks);
            state.s = standard.s;
            return;
        }
        sha256Blocks(&state.s, blocks, block_count, blocks, false);
    }
};

fn hashShort(input: []const u8, output: *Digest) void {
    std.debug.assert(input.len <= Sha256.block_length - 9);
    var block = [_]u8{0} ** Sha256.block_length;
    @memcpy(block[0..input.len], input);
    block[input.len] = 0x80;
    std.mem.writeInt(
        u64,
        block[56..64],
        @as(u64, @intCast(input.len)) * 8,
        .big,
    );
    var state = Sha256.init(.{});
    state.update(&block);
    writeDigest(&state.s, output);
}

const round_constants = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/// SHA-256 SHA-NI compression derived from Zig std's MIT-licensed single-block
/// implementation, with state conversion and writeback hoisted around the
/// complete-block loop.
fn sha256Blocks(
    state: *[8]u32,
    blocks: *const [Sha256.block_length]u8,
    block_count: usize,
    tail: *const [Sha256.block_length]u8,
    comptime include_tail: bool,
) void {
    std.debug.assert(block_count != 0 or include_tail);
    const V4u32 = @Vector(4, u32);
    var x: V4u32 = .{ state[5], state[4], state[1], state[0] };
    var y: V4u32 = .{ state[7], state[6], state[3], state[2] };
    const bytes: [*]const u8 = @ptrCast(blocks);

    var block_index: usize = 0;
    const total_blocks = block_count + @intFromBool(include_tail);
    while (block_index < total_blocks) : (block_index += 1) {
        const block: *align(1) const [Sha256.block_length]u8 = if (comptime include_tail)
            if (block_index == block_count)
                tail
            else
                @ptrCast(bytes + block_index * Sha256.block_length)
        else
            @ptrCast(bytes + block_index * Sha256.block_length);
        var schedule_words: [64]u32 align(16) = undefined;
        for (@as(*align(1) const [16]u32, @ptrCast(block)), 0..) |*word, index| {
            schedule_words[index] = std.mem.readInt(
                u32,
                std.mem.asBytes(word),
                .big,
            );
        }
        const schedule = @as(*[16]V4u32, @ptrCast(&schedule_words));
        const previous_x = x;
        const previous_y = y;

        comptime var round: u8 = 0;
        inline while (round < 16) : (round += 1) {
            if (round < 12) {
                var tmp = schedule[round];
                schedule[round + 4] = asm (
                    \\ sha256msg1 %[w4_7], %[tmp]
                    \\ vpalignr $0x4, %[w8_11], %[w12_15], %[result]
                    \\ paddd %[tmp], %[result]
                    \\ sha256msg2 %[w12_15], %[result]
                    : [tmp] "=&x" (tmp),
                      [result] "=&x" (-> V4u32),
                    : [_] "0" (tmp),
                      [w4_7] "x" (schedule[round + 1]),
                      [w8_11] "x" (schedule[round + 2]),
                      [w12_15] "x" (schedule[round + 3]),
                );
            }

            const words = schedule[round] +%
                @as(V4u32, round_constants[4 * round ..][0..4].*);
            y = asm ("sha256rnds2 %[x], %[y]"
                : [y] "=x" (-> V4u32),
                : [_] "0" (y),
                  [x] "x" (x),
                  [_] "{xmm0}" (words),
            );
            x = asm ("sha256rnds2 %[y], %[x]"
                : [x] "=x" (-> V4u32),
                : [_] "0" (x),
                  [y] "x" (y),
                  [_] "{xmm0}" (@as(
                    V4u32,
                    @bitCast(@as(u128, @bitCast(words)) >> 64),
                  )),
            );
        }

        x +%= previous_x;
        y +%= previous_y;
    }

    state[0] = x[3];
    state[1] = x[2];
    state[4] = x[1];
    state[5] = x[0];
    state[2] = y[3];
    state[3] = y[2];
    state[6] = y[1];
    state[7] = y[0];
}

test "SHA-256 helper produces a stable digest" {
    var expected: Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "0c1e785d63a51283ffecd0d4b165c41ca1ab9da1d620854f58c79d8058400197",
    );
    try std.testing.expectEqualSlices(u8, &expected, &hash("vail"));
}

test "accelerated SHA-256 matches Zig std across block boundaries" {
    const lengths = [_]usize{
        0, 1, 31, 32, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024,
    };
    var input: [1024]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);

    for (lengths) |length| {
        var expected: Digest = undefined;
        Sha256.hash(input[0..length], &expected, .{});
        try std.testing.expectEqualSlices(u8, &expected, &hash(input[0..length]));
    }
}

test "prepared HMAC-SHA-256 matches Zig std" {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const key = [_]u8{0x42} ** digest_len;
    const message_55 = [_]u8{0xa5} ** 55;
    const message_56 = [_]u8{0x5a} ** 56;
    const message_128 = [_]u8{0xc3} ** 128;
    const message_1024 = [_]u8{0x96} ** 1024;
    const messages = [_][]const u8{
        "",
        "short",
        &message_55,
        &message_56,
        &message_128,
        &message_1024,
    };

    var prepared = PreparedHmac.init(&key);
    defer prepared.deinit();
    for (messages) |message| {
        var expected: Digest = undefined;
        HmacSha256.create(&expected, message, &key);
        var actual: Digest = undefined;
        prepared.create(&actual, message);
        try std.testing.expectEqual(expected, actual);
    }
}

test "prepared HKDF-SHA-256 labels match Zig std" {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const HkdfSha256 = std.crypto.kdf.hkdf.Hkdf(HmacSha256);
    const key = [_]u8{0x67} ** digest_len;
    const context = [_]u8{0x91} ** digest_len;

    var prepared = PreparedHmac.init(&key);
    defer prepared.deinit();
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            key,
            "c hs traffic",
            &context,
            32,
        ),
        prepared.expandLabel("c hs traffic", &context, 32),
    );
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(HkdfSha256, key, "quic key", "", 16),
        prepared.expandLabel("quic key", "", 16),
    );
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(HkdfSha256, key, "quic iv", "", 12),
        prepared.expandLabel("quic iv", "", 12),
    );
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            key,
            "1234567890123",
            &context,
            32,
        ),
        prepared.expandLabel("1234567890123", &context, 32),
    );
}
