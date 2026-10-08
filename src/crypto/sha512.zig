//! SHA-384 and SHA-512 with an in-tree x86_64 AVX compression backend.
//!
//! The compression schedule is derived from OpenSSL's Apache-2.0-licensed
//! `sha512-x86_64.pl`. Other targets use Zig's standard-library SHA-2.
// Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const builtin = @import("builtin");

const StdSha384 = std.crypto.hash.sha2.Sha384;
const StdSha512 = std.crypto.hash.sha2.Sha512;

pub const accelerated = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    builtin.zig_backend != .stage2_c and
    std.Target.x86.featureSetHas(builtin.cpu.features, .ssse3) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx);

const sha384_iv = [8]u64{
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
};
const sha512_iv = [8]u64{
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
};

const AcceleratedSha384 = AcceleratedSha2x64(sha384_iv, 48);
const AcceleratedSha512 = AcceleratedSha2x64(sha512_iv, 64);

pub const Sha384 = if (accelerated) AcceleratedSha384 else StdSha384;
pub const Sha512 = if (accelerated) AcceleratedSha512 else StdSha512;

pub fn initWithPrefix32(prefix: *const [32]u8) Sha512 {
    var state = Sha512.init(.{});
    if (comptime accelerated) {
        state.buf[0..32].* = prefix.*;
        state.buf_len = 32;
        state.total_len = 32;
    } else {
        state.update(prefix);
    }
    return state;
}

pub fn initWithPrefix64(
    first: *const [32]u8,
    second: *const [32]u8,
) Sha512 {
    var state = Sha512.init(.{});
    if (comptime accelerated) {
        state.buf[0..32].* = first.*;
        state.buf[32..64].* = second.*;
        state.buf_len = 64;
        state.total_len = 64;
    } else {
        state.update(first);
        state.update(second);
    }
    return state;
}

/// Hash a 32-byte input using the single-block SHA-512 layout used by Ed25519
/// seed expansion. The dedicated path avoids streaming bookkeeping while
/// retaining the portable standard-library fallback.
pub fn hash32(input: *const [32]u8, output: *[64]u8) void {
    if (comptime !accelerated) {
        StdSha512.hash(input, output, .{});
        return;
    }
    var state = AcceleratedSha512.iv;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&state));
    var block = [_]u8{0} ** AcceleratedSha512.block_length;
    defer std.crypto.secureZero(u8, &block);
    block[0..input.len].* = input.*;
    block[input.len] = 0x80;
    std.mem.writeInt(u128, block[112..128], input.len * 8, .big);
    vailSha512BlockAvx(&state, &block, 1);
    for (state, 0..) |word, word_index| {
        std.mem.writeInt(u64, output[word_index * 8 ..][0..8], word, .big);
    }
}

/// Reusable HMAC state for SHA-384/SHA-512 messages under a digest-sized key.
pub fn PreparedHmac(comptime Hash: type) type {
    comptime std.debug.assert(Hash.block_length == 128);
    comptime std.debug.assert(
        Hash.digest_length == Sha384.digest_length or
            Hash.digest_length == Sha512.digest_length,
    );
    return struct {
        const Self = @This();
        const Digest = [Hash.digest_length]u8;

        inner: Hash,
        outer: Hash,

        pub fn init(key: *const Digest) Self {
            var result: Self = undefined;
            result.initInto(key);
            return result;
        }

        pub fn initInto(self: *Self, key: *const Digest) void {
            var pad = [_]u8{0x36} ** Hash.block_length;
            defer std.crypto.secureZero(u8, &pad);
            for (key, 0..) |byte, index| pad[index] ^= byte;

            self.inner = Hash.init(.{});
            self.inner.update(&pad);
            for (&pad) |*byte| byte.* ^= 0x36 ^ 0x5c;
            self.outer = Hash.init(.{});
            self.outer.update(&pad);
        }

        pub fn create(
            self: *const Self,
            output: *Digest,
            message: []const u8,
        ) void {
            var inner = self.inner;
            defer std.crypto.secureZero(Hash, (&inner)[0..1]);
            var inner_digest: Digest = undefined;
            defer std.crypto.secureZero(u8, &inner_digest);
            if (comptime accelerated) {
                if (message.len != 0 and
                    message.len % Hash.block_length == 0 and
                    inner.buf_len == 0)
                {
                    inner.finalExactInput(message, &inner_digest);
                } else {
                    inner.update(message);
                    inner.final(&inner_digest);
                }
            } else {
                inner.update(message);
                inner.final(&inner_digest);
            }

            var outer = self.outer;
            defer std.crypto.secureZero(Hash, (&outer)[0..1]);
            outer.update(&inner_digest);
            outer.final(output);
        }

        pub fn createShort(
            self: *const Self,
            output: *Digest,
            message: []const u8,
        ) void {
            std.debug.assert(message.len <= 111);
            var block = [_]u8{0} ** Hash.block_length;
            defer std.crypto.secureZero(u8, &block);
            @memcpy(block[0..message.len], message);
            block[message.len] = 0x80;
            std.mem.writeInt(
                u128,
                block[112..128],
                (Hash.block_length + @as(u128, @intCast(message.len))) * 8,
                .big,
            );

            var inner = self.inner;
            defer std.crypto.secureZero(Hash, (&inner)[0..1]);
            inner.update(&block);

            @memset(&block, 0);
            for (inner.s[0 .. Hash.digest_length / 8], 0..) |word, index| {
                std.mem.writeInt(u64, block[index * 8 ..][0..8], word, .big);
            }
            block[Hash.digest_length] = 0x80;
            std.mem.writeInt(
                u128,
                block[112..128],
                (Hash.block_length + Hash.digest_length) * 8,
                .big,
            );

            var outer = self.outer;
            defer std.crypto.secureZero(Hash, (&outer)[0..1]);
            outer.update(&block);
            for (outer.s[0 .. Hash.digest_length / 8], 0..) |word, index| {
                std.mem.writeInt(u64, output[index * 8 ..][0..8], word, .big);
            }
        }

        pub fn expandLabel(
            self: *const Self,
            label: []const u8,
            context: []const u8,
            comptime output_len: usize,
        ) [output_len]u8 {
            comptime std.debug.assert(output_len <= Hash.digest_length);
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
            if (offset <= 111) {
                self.createShort(&full, encoded[0..offset]);
            } else {
                self.create(&full, encoded[0..offset]);
            }
            if (comptime output_len == Hash.digest_length) return full;
            defer std.crypto.secureZero(u8, &full);
            return full[0..output_len].*;
        }

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(Self, self[0..1]);
            self.* = undefined;
        }
    };
}

fn AcceleratedSha2x64(
    comptime initial_state: [8]u64,
    comptime output_length: usize,
) type {
    return struct {
        const Self = @This();

        pub const block_length = 128;
        pub const digest_length = output_length;
        pub const Options = struct {};

        s: [8]u64,
        buf: [block_length]u8 = undefined,
        buf_len: u8 = 0,
        total_len: u128 = 0,

        const iv = initial_state;

        pub fn init(options: Options) Self {
            _ = options;
            return .{ .s = iv };
        }

        pub fn hash(input: []const u8, output: *[digest_length]u8, options: Options) void {
            _ = options;
            // The one-shot boundary can feed complete input blocks directly
            // to the compressor and needs only one reusable padding block.
            var state = iv;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&state));

            const full_blocks = input.len / block_length;
            const remainder = input[full_blocks * block_length ..];
            if (full_blocks != 0 and remainder.len == 0) {
                // Keep the chaining words in the compression routine across
                // the non-contiguous public padding block.
                var padding = [_]u8{0} ** block_length;
                padding[0] = 0x80;
                std.mem.writeInt(
                    u128,
                    padding[block_length - 16 .. block_length],
                    @as(u128, input.len) * 8,
                    .big,
                );
                const blocks: *const [block_length]u8 = @ptrCast(input.ptr);
                vailSha512BlocksAndFinalAvx(
                    &state,
                    blocks,
                    full_blocks,
                    &padding,
                );
            } else if (full_blocks != 0) {
                const blocks: *const [block_length]u8 = @ptrCast(input.ptr);
                vailSha512BlockAvx(&state, blocks, full_blocks);
            }

            if (remainder.len != 0 or full_blocks == 0) {
                var block = [_]u8{0} ** block_length;
                defer if (remainder.len != 0) std.crypto.secureZero(u8, &block);
                @memcpy(block[0..remainder.len], remainder);
                block[remainder.len] = 0x80;
                if (remainder.len > block_length - 17) {
                    vailSha512BlockAvx(&state, &block, 1);
                    @memset(&block, 0);
                }
                std.mem.writeInt(
                    u128,
                    block[block_length - 16 .. block_length],
                    @as(u128, input.len) * 8,
                    .big,
                );
                vailSha512BlockAvx(&state, &block, 1);
            }

            writeDigest(&state, output);
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

        pub fn peek(state: Self) [digest_length]u8 {
            var copy = state;
            return copy.finalResult();
        }

        pub fn final(state: *Self, output: *[digest_length]u8) void {
            if (state.buf_len == 0) {
                var padding = [_]u8{0} ** block_length;
                padding[0] = 0x80;
                std.mem.writeInt(
                    u128,
                    padding[block_length - 16 .. block_length],
                    state.total_len * 8,
                    .big,
                );
                state.compress(&padding, 1);
                writeDigest(&state.s, output);
                return;
            }
            @memset(state.buf[state.buf_len..], 0);
            state.buf[state.buf_len] = 0x80;
            state.buf_len += 1;
            if (block_length - state.buf_len < 16) {
                state.compress(&state.buf, 1);
                @memset(&state.buf, 0);
            }

            var index: usize = 1;
            var bit_length = state.total_len >> 5;
            state.buf[block_length - 1] = @as(u8, @intCast(state.total_len & 0x1f)) << 3;
            while (index < 16) : (index += 1) {
                state.buf[block_length - 1 - index] = @intCast(bit_length & 0xff);
                bit_length >>= 8;
            }
            state.compress(&state.buf, 1);

            writeDigest(&state.s, output);
        }

        pub fn finalResult(state: *Self) [digest_length]u8 {
            var output: [digest_length]u8 = undefined;
            state.final(&output);
            return output;
        }

        /// Consume a non-empty whole-block suffix and its public padding in
        /// one compression call. The caller must own this state exclusively.
        fn finalExactInput(
            state: *Self,
            input: []const u8,
            output: *[digest_length]u8,
        ) void {
            std.debug.assert(state.buf_len == 0);
            std.debug.assert(input.len != 0);
            std.debug.assert(input.len % block_length == 0);

            const total_len = state.total_len + input.len;
            var padding = [_]u8{0} ** block_length;
            padding[0] = 0x80;
            std.mem.writeInt(
                u128,
                padding[block_length - 16 .. block_length],
                total_len * 8,
                .big,
            );
            const blocks: *const [block_length]u8 = @ptrCast(input.ptr);
            vailSha512BlocksAndFinalAvx(
                &state.s,
                blocks,
                input.len / block_length,
                &padding,
            );
            state.total_len = total_len;
            writeDigest(&state.s, output);
        }

        inline fn writeDigest(
            words: *const [8]u64,
            output: *[digest_length]u8,
        ) void {
            for (words[0 .. digest_length / 8], 0..) |word, word_index| {
                std.mem.writeInt(
                    u64,
                    output[word_index * 8 ..][0..8],
                    word,
                    .big,
                );
            }
        }

        fn compress(
            state: *Self,
            blocks: *const [block_length]u8,
            block_count: usize,
        ) void {
            vailSha512BlockAvx(&state.s, blocks, block_count);
        }
    };
}

extern fn vailSha512BlockAvx(
    state: *[8]u64,
    blocks: *const [AcceleratedSha512.block_length]u8,
    block_count: usize,
) callconv(.c) void;

extern fn vailSha512BlocksAndFinalAvx(
    state: *[8]u64,
    blocks: *const [AcceleratedSha512.block_length]u8,
    block_count: usize,
    final_block: *const [AcceleratedSha512.block_length]u8,
) callconv(.c) void;

test "accelerated SHA-512 matches Zig std across block boundaries" {
    const lengths = [_]usize{
        0, 1, 31, 32, 47, 63, 111, 112, 127, 128, 129, 255, 256, 257, 1024,
    };
    var input: [1024]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);

    for (lengths) |length| {
        var expected: [Sha512.digest_length]u8 = undefined;
        var actual: [Sha512.digest_length]u8 = undefined;
        StdSha512.hash(input[0..length], &expected, .{});
        Sha512.hash(input[0..length], &actual, .{});
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        if (length == 32) {
            hash32(input[0..32], &actual);
            try std.testing.expectEqualSlices(u8, &expected, &actual);
        }

        var expected_stream = StdSha512.init(.{});
        var actual_stream = Sha512.init(.{});
        var offset: usize = 0;
        while (offset < length) {
            const take = @min(length - offset, 1 + offset % 37);
            expected_stream.update(input[offset..][0..take]);
            actual_stream.update(input[offset..][0..take]);
            offset += take;
        }
        expected_stream.final(&expected);
        actual_stream.final(&actual);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "accelerated SHA-384 matches Zig std across block boundaries" {
    const lengths = [_]usize{
        0, 1, 31, 47, 48, 63, 111, 112, 127, 128, 129, 255, 256, 257, 1024,
    };
    var input: [1024]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 137 +% 23);

    for (lengths) |length| {
        var expected: [Sha384.digest_length]u8 = undefined;
        var actual: [Sha384.digest_length]u8 = undefined;
        StdSha384.hash(input[0..length], &expected, .{});
        Sha384.hash(input[0..length], &actual, .{});
        try std.testing.expectEqualSlices(u8, &expected, &actual);

        var expected_stream = StdSha384.init(.{});
        var actual_stream = Sha384.init(.{});
        var offset: usize = 0;
        while (offset < length) {
            const take = @min(length - offset, 1 + offset % 41);
            expected_stream.update(input[offset..][0..take]);
            actual_stream.update(input[offset..][0..take]);
            offset += take;
        }
        expected_stream.final(&expected);
        actual_stream.final(&actual);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "accelerated HMAC-SHA-384 matches Zig std" {
    const FastHmac = std.crypto.auth.hmac.Hmac(Sha384);
    const StdHmac = std.crypto.auth.hmac.Hmac(StdSha384);
    const key = [_]u8{0x42} ** 48;
    const input = [_]u8{0xa5} ** 1024;
    var prepared = PreparedHmac(Sha384).init(&key);
    defer prepared.deinit();
    for ([_]usize{ 0, 1, 47, 48, 111, 112, 127, 128, 129, 256, 257, 1024 }) |length| {
        var expected: [StdHmac.mac_length]u8 = undefined;
        var actual: [FastHmac.mac_length]u8 = undefined;
        StdHmac.create(&expected, input[0..length], &key);
        FastHmac.create(&actual, input[0..length], &key);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        prepared.create(&actual, input[0..length]);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        if (length <= 111) {
            prepared.createShort(&actual, input[0..length]);
            try std.testing.expectEqualSlices(u8, &expected, &actual);
        }
    }
}

test "accelerated HMAC-SHA-512 matches Zig std" {
    const FastHmac = std.crypto.auth.hmac.Hmac(Sha512);
    const StdHmac = std.crypto.auth.hmac.Hmac(StdSha512);
    const key = [_]u8{0x42} ** 64;
    const input = [_]u8{0xa5} ** 1024;
    var prepared = PreparedHmac(Sha512).init(&key);
    defer prepared.deinit();
    for ([_]usize{ 0, 1, 63, 64, 111, 112, 127, 128, 129, 256, 257, 1024 }) |length| {
        var expected: [StdHmac.mac_length]u8 = undefined;
        var actual: [FastHmac.mac_length]u8 = undefined;
        StdHmac.create(&expected, input[0..length], &key);
        FastHmac.create(&actual, input[0..length], &key);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        prepared.create(&actual, input[0..length]);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        if (length <= 111) {
            prepared.createShort(&actual, input[0..length]);
            try std.testing.expectEqualSlices(u8, &expected, &actual);
        }
    }
}

comptime {
    if (accelerated) asm (@embedFile("sha512/avx.S"));
}
