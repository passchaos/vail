//! Prepared pure-Zig ChaCha20-Poly1305 with a wide vector path.
//!
//! The wide path combines counter zero (the Poly1305 one-time key) with the
//! first three payload blocks. AVX2 targets then evaluate eight word-transposed
//! blocks per core call and XOR while transposing them back to byte order,
//! avoiding a separate 512-byte keystream pass. Exact 512-byte and common
//! 496-byte tail paths also avoid generic slice-tail machinery. NEON targets
//! retain four-block batches, and portable targets retain Zig std's audited
//! implementation. Disjoint-buffer opening shares the encryption traversal
//! and securely clears all tentative plaintext before returning an
//! authentication failure; exact in-place opening authenticates first.

const std = @import("std");
const builtin = @import("builtin");

const StdChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Poly1305 = std.crypto.onetimeauth.Poly1305;

pub const key_length = StdChaCha20Poly1305.key_length;
pub const nonce_length = StdChaCha20Poly1305.nonce_length;
pub const tag_length = StdChaCha20Poly1305.tag_length;
pub const AuthenticationError = std.crypto.errors.AuthenticationError;

const wide_enabled = switch (builtin.cpu.arch) {
    .x86_64 => builtin.zig_backend != .stage2_x86_64 and
        builtin.cpu.has(.x86, .avx2),
    .aarch64 => builtin.zig_backend != .stage2_aarch64 and
        builtin.cpu.has(.aarch64, .neon),
    else => false,
};
const max_bulk_degree = if (builtin.cpu.arch == .x86_64) 8 else 4;
const StoredKey = if (wide_enabled) [8]u32 else [key_length]u8;

pub const Context = struct {
    key: StoredKey,

    pub fn init(key: [key_length]u8) Context {
        if (comptime wide_enabled) {
            var words: [8]u32 = undefined;
            for (0..words.len) |index| {
                words[index] = std.mem.readInt(
                    u32,
                    key[index * 4 ..][0..4],
                    .little,
                );
            }
            return .{ .key = words };
        }
        return .{ .key = key };
    }

    pub fn deinit(self: *Context) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    pub inline fn encrypt(
        self: *const Context,
        ciphertext: []u8,
        tag: *[tag_length]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) void {
        @setEvalBranchQuota(10_000);
        std.debug.assert(ciphertext.len == plaintext.len);
        std.debug.assert(
            plaintext.len <= 64 * (@as(u39, 1) << 32) - 64,
        );
        if (comptime !wide_enabled) {
            return StdChaCha20Poly1305.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
                self.key,
            );
        }
        if (comptime builtin.cpu.arch == .x86_64) {
            if (plaintext.len == 1200 and
                associated_data.len > 16 and
                associated_data.len <= 32)
            {
                // Keep the common QUIC-sized path behind a compact call
                // boundary without imposing call overhead on short records.
                return self.encrypt1200(
                    ciphertext,
                    tag,
                    plaintext,
                    associated_data,
                    nonce,
                );
            }
        }
        var poly_key = self.encryptWideAndPolyKey(
            ciphertext,
            plaintext,
            nonce,
        );
        defer std.crypto.secureZero(u8, &poly_key);
        authenticate(tag, associated_data, ciphertext, &poly_key);
    }

    noinline fn encrypt1200(
        self: *const Context,
        ciphertext: []u8,
        tag: *[tag_length]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) void {
        std.debug.assert(ciphertext.len == 1200);
        std.debug.assert(plaintext.len == 1200);
        std.debug.assert(associated_data.len > 16 and associated_data.len <= 32);
        var poly_key = self.encryptWideAndPolyKey(
            ciphertext,
            plaintext,
            nonce,
        );
        defer std.crypto.secureZero(u8, &poly_key);
        authenticate(tag, associated_data, ciphertext, &poly_key);
    }

    /// `plaintext` and `ciphertext` must be disjoint or have the same start.
    /// Disjoint output is securely cleared before an authentication failure
    /// is returned; exact in-place opening authenticates before overwriting.
    pub noinline fn decrypt(
        self: *const Context,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [tag_length]u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) AuthenticationError!void {
        std.debug.assert(plaintext.len == ciphertext.len);
        const in_place = plaintext.ptr == ciphertext.ptr;
        std.debug.assert(in_place or !slicesOverlap(plaintext, ciphertext));
        std.debug.assert(
            ciphertext.len <= 64 * (@as(u39, 1) << 32) - 64,
        );
        if (comptime !wide_enabled) {
            return StdChaCha20Poly1305.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
                self.key,
            );
        }

        if (!in_place) {
            var poly_key = self.encryptWideAndPolyKey(
                plaintext,
                ciphertext,
                nonce,
            );
            defer std.crypto.secureZero(u8, &poly_key);
            if (!authenticateTag(
                tag,
                associated_data,
                ciphertext,
                &poly_key,
            )) {
                std.crypto.secureZero(u8, plaintext);
                return error.AuthenticationFailed;
            }
            return;
        }

        if (ciphertext.len <= 64) {
            var blocks: [128]u8 = undefined;
            defer std.crypto.secureZero(u8, &blocks);
            ChaChaVec(2).blocks(&blocks, &self.key, nonce, 0);
            if (!authenticateTag(
                tag,
                associated_data,
                ciphertext,
                blocks[0..32],
            )) {
                @memset(plaintext, undefined);
                return error.AuthenticationFailed;
            }
            xorBytes(plaintext, ciphertext, blocks[64..][0..ciphertext.len]);
            return;
        }

        var blocks: [256]u8 = undefined;
        defer std.crypto.secureZero(u8, &blocks);
        ChaChaVec(4).blocks(&blocks, &self.key, nonce, 0);
        if (!authenticateTag(
            tag,
            associated_data,
            ciphertext,
            blocks[0..32],
        )) {
            @memset(plaintext, undefined);
            return error.AuthenticationFailed;
        }
        const first_len = @min(@as(usize, 3 * 64), ciphertext.len);
        xorBytes(
            plaintext[0..first_len],
            ciphertext[0..first_len],
            blocks[64..][0..first_len],
        );
        self.xorPayloadFrom(
            plaintext[first_len..],
            ciphertext[first_len..],
            nonce,
            4,
        );
    }

    inline fn encryptWideAndPolyKey(
        self: *const Context,
        output: []u8,
        input: []const u8,
        nonce: [nonce_length]u8,
    ) [32]u8 {
        if (input.len <= 64) {
            var blocks: [128]u8 = undefined;
            ChaChaVec(2).blocks(&blocks, &self.key, nonce, 0);
            xorBytes(output, input, blocks[64..][0..input.len]);
            return blocks[0..32].*;
        }

        const first_len: usize = @min(input.len, 3 * 64);
        const poly_key = ChaChaVec(4).encryptFirst3AndPolyKey(
            output[0..first_len],
            input[0..first_len],
            &self.key,
            nonce,
        );
        var blocks: [256]u8 = undefined;
        var offset = first_len;
        var counter: u32 = 4;
        while (offset < input.len) {
            const remaining = input.len - offset;
            if (comptime max_bulk_degree == 8) {
                if (remaining > 256) {
                    const len = @min(@as(usize, 512), remaining);
                    ChaChaVec(8).xorBlocks(
                        output[offset..][0..len],
                        input[offset..][0..len],
                        &self.key,
                        nonce,
                        counter,
                    );
                    offset += len;
                    counter +%= 8;
                    continue;
                }
            }
            ChaChaVec(4).blocks(&blocks, &self.key, nonce, counter);
            const len = @min(@as(usize, 256), remaining);
            xorBytes(
                output[offset..][0..len],
                input[offset..][0..len],
                blocks[0..len],
            );
            offset += len;
            counter +%= 4;
        }
        return poly_key;
    }

    fn xorPayloadFrom(
        self: *const Context,
        output: []u8,
        input: []const u8,
        nonce: [nonce_length]u8,
        initial_counter: u32,
    ) void {
        var blocks: [256]u8 = undefined;
        var offset: usize = 0;
        var counter = initial_counter;
        while (offset < input.len) {
            const remaining = input.len - offset;
            if (comptime max_bulk_degree == 8) {
                if (remaining > 256) {
                    const len = @min(@as(usize, 512), remaining);
                    ChaChaVec(8).xorBlocks(
                        output[offset..][0..len],
                        input[offset..][0..len],
                        &self.key,
                        nonce,
                        counter,
                    );
                    offset += len;
                    counter +%= 8;
                    continue;
                }
            }
            ChaChaVec(4).blocks(&blocks, &self.key, nonce, counter);
            const len = @min(@as(usize, 256), remaining);
            xorBytes(
                output[offset..][0..len],
                input[offset..][0..len],
                blocks[0..len],
            );
            offset += len;
            counter +%= 4;
        }
    }
};

inline fn slicesOverlap(a: []const u8, b: []const u8) bool {
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    const a_end = std.math.add(usize, a_start, a.len) catch return true;
    const b_end = std.math.add(usize, b_start, b.len) catch return true;
    return a_start < b_end and b_start < a_end;
}

inline fn authenticateTag(
    expected: [tag_length]u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    poly_key: *const [Poly1305.key_length]u8,
) bool {
    var computed: [tag_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &computed);
    authenticate(&computed, associated_data, ciphertext, poly_key);
    return std.crypto.timing_safe.eql([tag_length]u8, computed, expected);
}

pub inline fn encrypt(
    ciphertext: []u8,
    tag: *[tag_length]u8,
    plaintext: []const u8,
    associated_data: []const u8,
    nonce: [nonce_length]u8,
    key: [key_length]u8,
) void {
    var context = Context.init(key);
    defer context.deinit();
    context.encrypt(ciphertext, tag, plaintext, associated_data, nonce);
}

pub inline fn decrypt(
    plaintext: []u8,
    ciphertext: []const u8,
    tag: [tag_length]u8,
    associated_data: []const u8,
    nonce: [nonce_length]u8,
    key: [key_length]u8,
) AuthenticationError!void {
    var context = Context.init(key);
    defer context.deinit();
    return context.decrypt(
        plaintext,
        ciphertext,
        tag,
        associated_data,
        nonce,
    );
}

inline fn authenticate(
    tag: *[tag_length]u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    poly_key: *const [Poly1305.key_length]u8,
) void {
    if (comptime wide_enabled) {
        if (ciphertext.len == 0) {
            @branchHint(.unlikely);
            return authenticatePortable(
                tag,
                associated_data,
                ciphertext,
                poly_key,
            );
        }
        return authenticateWide(tag, associated_data, ciphertext, poly_key);
    }
    authenticatePortable(tag, associated_data, ciphertext, poly_key);
}

noinline fn authenticateWide(
    tag: *[tag_length]u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    poly_key: *const [Poly1305.key_length]u8,
) void {
    std.debug.assert(ciphertext.len != 0);
    var mac = WidePoly1305.init(poly_key);
    defer mac.deinit();
    if (ciphertext.len == 1200 and
        associated_data.len > 16 and
        associated_data.len <= 32)
    {
        // The padded AAD, ciphertext, and length block contain 78 Poly1305
        // blocks. Pack them as 6 + 9*8 so only ten reductions are needed.
        const upper_powers = WidePoly1305.multiplyFour(mac.r);
        const batch8_powers = WidePoly1305.combineBatch8Powers(
            mac.r,
            upper_powers,
        );
        var prefix = [_]u8{0} ** 64;
        copySmall(
            prefix[32 .. 32 + associated_data.len],
            associated_data,
        );
        mac.processBatch8HalvesPrepared(
            &prefix,
            ciphertext[0..64],
            &batch8_powers,
            2,
        );

        var offset: usize = 64;
        while (offset != 1088) : (offset += 128) {
            mac.processBatch8Prepared(
                ciphertext[offset..][0..128],
                &batch8_powers,
                0,
            );
        }
        var suffix: [64]u8 = undefined;
        suffix[0..48].* = ciphertext[1152..1200].*;
        std.mem.writeInt(u64, suffix[48..56], associated_data.len, .little);
        std.mem.writeInt(u64, suffix[56..64], ciphertext.len, .little);
        mac.processBatch8HalvesPrepared(
            ciphertext[1088..1152],
            &suffix,
            &batch8_powers,
            0,
        );
        mac.final(tag);
        return;
    }
    if (associated_data.len < 64) {
        const aad_padded_len = std.mem.alignForward(
            usize,
            associated_data.len,
            Poly1305.block_length,
        );
        const aad_block_count = aad_padded_len /
            Poly1305.block_length;
        const ciphertext_block_count = ciphertext.len /
            Poly1305.block_length +
            @intFromBool(
                ciphertext.len % Poly1305.block_length != 0,
            );
        if (aad_padded_len < 64 and
            ciphertext.len >= 64 - aad_padded_len and
            aad_block_count + ciphertext_block_count % 4 >= 4)
        {
            // Hash one full vector batch across the mandatory AAD padding
            // boundary instead of serially multiplying the short header
            // blocks.
            var prefix = [_]u8{0} ** 64;
            copySmall(prefix[0..associated_data.len], associated_data);
            const ciphertext_prefix_len = 64 - aad_padded_len;
            copySmall(
                prefix[aad_padded_len..],
                ciphertext[0..ciphertext_prefix_len],
            );
            mac.updateBlocks(&prefix);
            mac.updatePaddedAndLength(
                ciphertext[ciphertext_prefix_len..],
                associated_data.len,
                ciphertext.len,
            );
        } else {
            mac.updatePadded(associated_data);
            mac.updatePaddedAndLength(
                ciphertext,
                associated_data.len,
                ciphertext.len,
            );
        }
    } else {
        mac.updatePadded(associated_data);
        mac.updatePaddedAndLength(
            ciphertext,
            associated_data.len,
            ciphertext.len,
        );
    }
    mac.final(tag);
}

noinline fn authenticatePortable(
    tag: *[tag_length]u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    poly_key: *const [Poly1305.key_length]u8,
) void {
    var mac = Poly1305.init(poly_key);
    mac.update(associated_data);
    mac.pad();
    mac.update(ciphertext);
    mac.pad();
    var lengths: [16]u8 = undefined;
    std.mem.writeInt(u64, lengths[0..8], associated_data.len, .little);
    std.mem.writeInt(u64, lengths[8..16], ciphertext.len, .little);
    mac.update(&lengths);
    mac.final(tag);
}

inline fn copySmall(output: []u8, input: []const u8) void {
    std.debug.assert(output.len >= input.len);
    std.debug.assert(input.len <= 64);
    var offset: usize = 0;
    while (offset + 32 <= input.len) : (offset += 32) {
        output[offset..][0..32].* = input[offset..][0..32].*;
    }
    while (offset + 16 <= input.len) : (offset += 16) {
        output[offset..][0..16].* = input[offset..][0..16].*;
    }
    while (offset < input.len) : (offset += 1) {
        output[offset] = input[offset];
    }
}

/// Four consecutive blocks are evaluated as
/// `(h+m0)r^4 + m1r^3 + m2r^2 + m3r`. Long AVX2 inputs use the equivalent
/// eight-block polynomial and compute `r^5` through `r^8` together only when
/// that setup cost is amortized. Keeping limbs below 26 bits lets LLVM lower
/// widened u32 lane products to portable vector instructions while every
/// horizontal sum remains comfortably below u64 overflow.
const WidePoly1305 = struct {
    const limb_bits = 26;
    const limb_mask: u64 = (1 << limb_bits) - 1;
    const hibit: u64 = 1 << 24;
    const Limbs = [5]u64;
    const BatchLane = @Vector(4, u32);
    const Batch8Lane = @Vector(8, u32);
    // Match AVX2's lane-local unpack order so block parsing needs no vpermq.
    const batch8_block_order = [8]usize{ 0, 2, 1, 3, 4, 6, 5, 7 };

    r: [5]BatchLane,
    h: Limbs = @splat(0),
    pad: [2]u64,

    fn init(key: *const [32]u8) WidePoly1305 {
        const t0 = std.mem.readInt(u64, key[0..8], .little);
        const t1 = std.mem.readInt(u64, key[8..16], .little);
        const r1 = Limbs{
            t0 & limb_mask,
            (t0 >> 26) & 0x3ffff03,
            ((t0 >> 52) | (t1 << 12)) & 0x3ffc0ff,
            (t1 >> 14) & 0x3f03fff,
            (t1 >> 40) & 0x00fffff,
        };
        var wide_powers: [4]Limbs = undefined;
        wide_powers[0] = r1;
        wide_powers[1] = multiply(r1, r1);
        const upper_powers = multiplyPair(
            wide_powers[1],
            r1,
            wide_powers[1],
            wide_powers[1],
        );
        wide_powers[2] = upper_powers[0];
        wide_powers[3] = upper_powers[1];
        var powers: [5]BatchLane = undefined;
        inline for (0..5) |limb| {
            powers[limb] = .{
                @intCast(wide_powers[3][limb]),
                @intCast(wide_powers[2][limb]),
                @intCast(wide_powers[1][limb]),
                @intCast(wide_powers[0][limb]),
            };
        }
        return .{
            .r = powers,
            .pad = .{
                std.mem.readInt(u64, key[16..24], .little),
                std.mem.readInt(u64, key[24..32], .little),
            },
        };
    }

    fn deinit(self: *WidePoly1305) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    inline fn updatePadded(self: *WidePoly1305, input: []const u8) void {
        const full_len = input.len & ~@as(usize, 15);
        self.updateBlocks(input[0..full_len]);
        if (full_len != input.len) {
            var block = [_]u8{0} ** 16;
            copySmall(block[0 .. input.len - full_len], input[full_len..]);
            self.updateBlocks(&block);
        }
    }

    inline fn updateBlocks(self: *WidePoly1305, input: []const u8) void {
        std.debug.assert(input.len % 16 == 0);
        var offset: usize = 0;
        if (comptime max_bulk_degree == 8) {
            if (input.len >= 512) {
                const upper_powers = multiplyFour(self.r);
                while (offset + 128 <= input.len) : (offset += 128) {
                    self.processBatch8(
                        input[offset..][0..128],
                        &upper_powers,
                        0,
                    );
                }
            }
        }
        while (offset + 64 <= input.len) : (offset += 64) {
            self.processBatch(input[offset..][0..64]);
        }
        while (offset < input.len) : (offset += 16) {
            const message = parseBlock(input[offset..][0..16]);
            var sum = self.h;
            inline for (0..5) |index| sum[index] += message[index];
            var r1: Limbs = undefined;
            inline for (0..5) |limb| r1[limb] = self.r[limb][3];
            self.h = multiply(sum, r1);
        }
    }

    inline fn updatePaddedAndLength(
        self: *WidePoly1305,
        input: []const u8,
        associated_data_len: usize,
        ciphertext_len: usize,
    ) void {
        var lengths: [16]u8 = undefined;
        std.mem.writeInt(u64, lengths[0..8], associated_data_len, .little);
        std.mem.writeInt(u64, lengths[8..16], ciphertext_len, .little);
        const block_count = input.len / 16;
        if (input.len >= 16 and
            input.len % 16 == 0 and
            block_count % 4 == 1)
        {
            const leading_len = input.len - 16;
            self.updateBlocks(input[0..leading_len]);
            self.processPair(input[leading_len..][0..16], &lengths);
            return;
        }
        self.updatePadded(input);
        self.updateBlocks(&lengths);
    }

    inline fn processBatch(
        self: *WidePoly1305,
        input: *const [64]u8,
    ) void {
        const words: @Vector(8, u64) = @bitCast(input.*);
        const t0: @Vector(4, u64) = @shuffle(
            u64,
            words,
            undefined,
            [_]i32{ 0, 2, 4, 6 },
        );
        const t1: @Vector(4, u64) = @shuffle(
            u64,
            words,
            undefined,
            [_]i32{ 1, 3, 5, 7 },
        );
        const mask: @Vector(4, u64) = @splat(limb_mask);
        var a = [5]BatchLane{
            @intCast(t0 & mask),
            @intCast((t0 >> @splat(26)) & mask),
            @intCast(((t0 >> @splat(52)) | (t1 << @splat(12))) & mask),
            @intCast((t1 >> @splat(14)) & mask),
            @intCast((t1 >> @splat(40)) | @as(@Vector(4, u64), @splat(hibit))),
        };
        inline for (0..5) |limb| {
            var accumulator: BatchLane = @splat(0);
            accumulator[0] = @intCast(self.h[limb]);
            a[limb] +%= accumulator;
        }

        self.accumulate(4, a, self.r);
    }

    inline fn processPair(
        self: *WidePoly1305,
        first: *const [16]u8,
        second: *const [16]u8,
    ) void {
        const PairLane = @Vector(2, u32);
        const first_limbs = parseBlock(first);
        const second_limbs = parseBlock(second);
        var a: [5]PairLane = undefined;
        var r: [5]PairLane = undefined;
        inline for (0..5) |limb| {
            a[limb] = .{
                @intCast(first_limbs[limb] + self.h[limb]),
                @intCast(second_limbs[limb]),
            };
            r[limb] = .{
                self.r[limb][2],
                self.r[limb][3],
            };
        }
        self.accumulate(2, a, r);
    }

    inline fn processBatch8(
        self: *WidePoly1305,
        input: *const [128]u8,
        upper_powers: *const [5]BatchLane,
        comptime leading_zero_blocks: usize,
    ) void {
        const powers = combineBatch8Powers(self.r, upper_powers.*);
        self.processBatch8Prepared(input, &powers, leading_zero_blocks);
    }

    inline fn processBatch8Prepared(
        self: *WidePoly1305,
        input: *const [128]u8,
        powers: *const [5]Batch8Lane,
        comptime leading_zero_blocks: usize,
    ) void {
        self.processBatch8HalvesPrepared(
            input[0..64],
            input[64..128],
            powers,
            leading_zero_blocks,
        );
    }

    inline fn processBatch8HalvesPrepared(
        self: *WidePoly1305,
        first: *const [64]u8,
        second: *const [64]u8,
        powers: *const [5]Batch8Lane,
        comptime leading_zero_blocks: usize,
    ) void {
        comptime std.debug.assert(leading_zero_blocks < 8);
        const WideLane64 = @Vector(8, u64);
        const first_words: WideLane64 = @bitCast(first.*);
        const second_words: WideLane64 = @bitCast(second.*);
        const words: @Vector(16, u64) = @shuffle(
            u64,
            first_words,
            second_words,
            [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7, -1, -2, -3, -4, -5, -6, -7, -8 },
        );
        const even_indices = comptime blk: {
            var indices: [8]i32 = undefined;
            for (batch8_block_order, 0..) |block, lane| {
                indices[lane] = @intCast(2 * block);
            }
            break :blk indices;
        };
        const odd_indices = comptime blk: {
            var indices: [8]i32 = undefined;
            for (batch8_block_order, 0..) |block, lane| {
                indices[lane] = @intCast(2 * block + 1);
            }
            break :blk indices;
        };
        const t0: WideLane64 = @shuffle(u64, words, undefined, even_indices);
        const t1: WideLane64 = @shuffle(u64, words, undefined, odd_indices);
        const mask: WideLane64 = @splat(limb_mask);
        var a = [5]Batch8Lane{
            @intCast(t0 & mask),
            @intCast((t0 >> @splat(26)) & mask),
            @intCast(((t0 >> @splat(52)) | (t1 << @splat(12))) & mask),
            @intCast((t1 >> @splat(14)) & mask),
            @intCast((t1 >> @splat(40)) | @as(WideLane64, @splat(hibit))),
        };
        if (comptime leading_zero_blocks != 0) {
            inline for (0..5) |limb| {
                inline for (0..leading_zero_blocks) |block| {
                    a[limb][batch8_block_order[block]] = 0;
                }
            }
        }
        inline for (0..5) |limb| {
            var accumulator: Batch8Lane = @splat(0);
            accumulator[batch8_block_order[leading_zero_blocks]] =
                @intCast(self.h[limb]);
            a[limb] +%= accumulator;
        }

        self.accumulate(8, a, powers.*);
    }

    inline fn combineBatch8Powers(
        lower_powers: [5]BatchLane,
        upper_powers: [5]BatchLane,
    ) [5]Batch8Lane {
        var powers: [5]Batch8Lane = undefined;
        inline for (0..5) |limb| {
            powers[limb] = @shuffle(
                u32,
                upper_powers[limb],
                lower_powers[limb],
                [_]i32{ 0, 2, 1, 3, -1, -3, -2, -4 },
            );
        }
        return powers;
    }

    inline fn accumulate(
        self: *WidePoly1305,
        comptime lanes: usize,
        a: [5]@Vector(lanes, u32),
        r: [5]@Vector(lanes, u32),
    ) void {
        @setEvalBranchQuota(10_000);
        const Vector = @Vector(lanes, u32);
        const s1 = r[1] *% @as(Vector, @splat(5));
        const s2 = r[2] *% @as(Vector, @splat(5));
        const s3 = r[3] *% @as(Vector, @splat(5));
        const s4 = r[4] *% @as(Vector, @splat(5));

        var d0 = @reduce(.Add, mulWide(lanes, a[0], r[0]) +% mulWide(lanes, a[1], s4) +% mulWide(lanes, a[2], s3) +% mulWide(lanes, a[3], s2) +% mulWide(lanes, a[4], s1));
        var d1 = @reduce(.Add, mulWide(lanes, a[0], r[1]) +% mulWide(lanes, a[1], r[0]) +% mulWide(lanes, a[2], s4) +% mulWide(lanes, a[3], s3) +% mulWide(lanes, a[4], s2));
        var d2 = @reduce(.Add, mulWide(lanes, a[0], r[2]) +% mulWide(lanes, a[1], r[1]) +% mulWide(lanes, a[2], r[0]) +% mulWide(lanes, a[3], s4) +% mulWide(lanes, a[4], s3));
        var d3 = @reduce(.Add, mulWide(lanes, a[0], r[3]) +% mulWide(lanes, a[1], r[2]) +% mulWide(lanes, a[2], r[1]) +% mulWide(lanes, a[3], r[0]) +% mulWide(lanes, a[4], s4));
        var d4 = @reduce(.Add, mulWide(lanes, a[0], r[4]) +% mulWide(lanes, a[1], r[3]) +% mulWide(lanes, a[2], r[2]) +% mulWide(lanes, a[3], r[1]) +% mulWide(lanes, a[4], r[0]));
        self.h = reduce(&d0, &d1, &d2, &d3, &d4);
    }

    inline fn mulWide(
        comptime lanes: usize,
        a: @Vector(lanes, u32),
        b: @Vector(lanes, u32),
    ) @Vector(lanes, u64) {
        return @as(@Vector(lanes, u64), @intCast(a)) *%
            @as(@Vector(lanes, u64), @intCast(b));
    }

    fn final(self: *WidePoly1305, output: *[16]u8) void {
        var h0 = self.h[0];
        var h1 = self.h[1];
        var h2 = self.h[2];
        var h3 = self.h[3];
        var h4 = self.h[4];

        var carry = h1 >> limb_bits;
        h1 &= limb_mask;
        h2 += carry;
        carry = h2 >> limb_bits;
        h2 &= limb_mask;
        h3 += carry;
        carry = h3 >> limb_bits;
        h3 &= limb_mask;
        h4 += carry;
        carry = h4 >> limb_bits;
        h4 &= limb_mask;
        h0 += carry * 5;
        carry = h0 >> limb_bits;
        h0 &= limb_mask;
        h1 += carry;

        var g0 = h0 + 5;
        carry = g0 >> limb_bits;
        g0 &= limb_mask;
        var g1 = h1 + carry;
        carry = g1 >> limb_bits;
        g1 &= limb_mask;
        var g2 = h2 + carry;
        carry = g2 >> limb_bits;
        g2 &= limb_mask;
        var g3 = h3 + carry;
        carry = g3 >> limb_bits;
        g3 &= limb_mask;
        const g4 = h4 + carry -% (1 << limb_bits);
        const use_g = (g4 >> 63) -% 1;
        const use_h = ~use_g;
        h0 = (h0 & use_h) | (g0 & use_g);
        h1 = (h1 & use_h) | (g1 & use_g);
        h2 = (h2 & use_h) | (g2 & use_g);
        h3 = (h3 & use_h) | (g3 & use_g);
        h4 = (h4 & use_h) | (g4 & use_g);

        const low = h0 | (h1 << 26) | (h2 << 52);
        const high = (h2 >> 12) | (h3 << 14) | (h4 << 40);
        const tagged_low = @addWithOverflow(low, self.pad[0]);
        const tagged_high = high +% self.pad[1] +% tagged_low[1];
        std.mem.writeInt(u64, output[0..8], tagged_low[0], .little);
        std.mem.writeInt(u64, output[8..16], tagged_high, .little);
    }

    fn parseBlock(block: *const [16]u8) Limbs {
        const t0 = std.mem.readInt(u64, block[0..8], .little);
        const t1 = std.mem.readInt(u64, block[8..16], .little);
        return .{
            t0 & limb_mask,
            (t0 >> 26) & limb_mask,
            ((t0 >> 52) | (t1 << 12)) & limb_mask,
            (t1 >> 14) & limb_mask,
            (t1 >> 40) | hibit,
        };
    }

    fn multiply(h: Limbs, r: Limbs) Limbs {
        const s1 = r[1] * 5;
        const s2 = r[2] * 5;
        const s3 = r[3] * 5;
        const s4 = r[4] * 5;
        var d0 = h[0] * r[0] + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1;
        var d1 = h[0] * r[1] + h[1] * r[0] + h[2] * s4 + h[3] * s3 + h[4] * s2;
        var d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s4 + h[4] * s3;
        var d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s4;
        var d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];
        return reduce(&d0, &d1, &d2, &d3, &d4);
    }

    fn multiplyPair(
        h0: Limbs,
        r0: Limbs,
        h1: Limbs,
        r1: Limbs,
    ) [2]Limbs {
        const Pair32 = @Vector(2, u32);
        const Pair64 = @Vector(2, u64);
        var h: [5]Pair32 = undefined;
        var r: [5]Pair32 = undefined;
        inline for (0..5) |limb| {
            h[limb] = .{ @intCast(h0[limb]), @intCast(h1[limb]) };
            r[limb] = .{ @intCast(r0[limb]), @intCast(r1[limb]) };
        }
        const five: Pair32 = @splat(5);
        const s1 = r[1] *% five;
        const s2 = r[2] *% five;
        const s3 = r[3] *% five;
        const s4 = r[4] *% five;
        const d0 = mulWide(2, h[0], r[0]) +% mulWide(2, h[1], s4) +% mulWide(2, h[2], s3) +% mulWide(2, h[3], s2) +% mulWide(2, h[4], s1);
        var d1 = mulWide(2, h[0], r[1]) +% mulWide(2, h[1], r[0]) +% mulWide(2, h[2], s4) +% mulWide(2, h[3], s3) +% mulWide(2, h[4], s2);
        var d2 = mulWide(2, h[0], r[2]) +% mulWide(2, h[1], r[1]) +% mulWide(2, h[2], r[0]) +% mulWide(2, h[3], s4) +% mulWide(2, h[4], s3);
        var d3 = mulWide(2, h[0], r[3]) +% mulWide(2, h[1], r[2]) +% mulWide(2, h[2], r[1]) +% mulWide(2, h[3], r[0]) +% mulWide(2, h[4], s4);
        var d4 = mulWide(2, h[0], r[4]) +% mulWide(2, h[1], r[3]) +% mulWide(2, h[2], r[2]) +% mulWide(2, h[3], r[1]) +% mulWide(2, h[4], r[0]);
        const shift: Pair64 = @splat(limb_bits);
        const mask: Pair64 = @splat(limb_mask);
        var carry = d0 >> shift;
        var result0 = d0 & mask;
        d1 +%= carry;
        carry = d1 >> shift;
        var result1 = d1 & mask;
        d2 +%= carry;
        carry = d2 >> shift;
        const result2 = d2 & mask;
        d3 +%= carry;
        carry = d3 >> shift;
        const result3 = d3 & mask;
        d4 +%= carry;
        carry = d4 >> shift;
        const result4 = d4 & mask;
        result0 +%= carry *% @as(Pair64, @splat(5));
        carry = result0 >> shift;
        result0 &= mask;
        result1 +%= carry;
        return .{
            .{ result0[0], result1[0], result2[0], result3[0], result4[0] },
            .{ result0[1], result1[1], result2[1], result3[1], result4[1] },
        };
    }

    fn multiplyFour(lower_powers: [5]BatchLane) [5]BatchLane {
        const Lane32 = @Vector(4, u32);
        const Lane64 = @Vector(4, u64);
        var h: [5]Lane32 = undefined;
        var r: [5]Lane32 = undefined;
        inline for (0..5) |limb| {
            h[limb] = @splat(lower_powers[limb][0]);
            r[limb] = .{
                lower_powers[limb][3],
                lower_powers[limb][2],
                lower_powers[limb][1],
                lower_powers[limb][0],
            };
        }
        const five: Lane32 = @splat(5);
        const s1 = r[1] *% five;
        const s2 = r[2] *% five;
        const s3 = r[3] *% five;
        const s4 = r[4] *% five;
        const d0 = mulWide(4, h[0], r[0]) +% mulWide(4, h[1], s4) +% mulWide(4, h[2], s3) +% mulWide(4, h[3], s2) +% mulWide(4, h[4], s1);
        var d1 = mulWide(4, h[0], r[1]) +% mulWide(4, h[1], r[0]) +% mulWide(4, h[2], s4) +% mulWide(4, h[3], s3) +% mulWide(4, h[4], s2);
        var d2 = mulWide(4, h[0], r[2]) +% mulWide(4, h[1], r[1]) +% mulWide(4, h[2], r[0]) +% mulWide(4, h[3], s4) +% mulWide(4, h[4], s3);
        var d3 = mulWide(4, h[0], r[3]) +% mulWide(4, h[1], r[2]) +% mulWide(4, h[2], r[1]) +% mulWide(4, h[3], r[0]) +% mulWide(4, h[4], s4);
        var d4 = mulWide(4, h[0], r[4]) +% mulWide(4, h[1], r[3]) +% mulWide(4, h[2], r[2]) +% mulWide(4, h[3], r[1]) +% mulWide(4, h[4], r[0]);
        const shift: Lane64 = @splat(limb_bits);
        const mask: Lane64 = @splat(limb_mask);
        var carry = d0 >> shift;
        var result0 = d0 & mask;
        d1 +%= carry;
        carry = d1 >> shift;
        var result1 = d1 & mask;
        d2 +%= carry;
        carry = d2 >> shift;
        const result2 = d2 & mask;
        d3 +%= carry;
        carry = d3 >> shift;
        const result3 = d3 & mask;
        d4 +%= carry;
        carry = d4 >> shift;
        const result4 = d4 & mask;
        result0 +%= carry *% @as(Lane64, @splat(5));
        carry = result0 >> shift;
        result0 &= mask;
        result1 +%= carry;

        const result_limbs = [5]Lane64{
            result0,
            result1,
            result2,
            result3,
            result4,
        };
        var result: [5]BatchLane = undefined;
        inline for (0..5) |limb| {
            result[limb] = .{
                @intCast(result_limbs[limb][3]),
                @intCast(result_limbs[limb][2]),
                @intCast(result_limbs[limb][1]),
                @intCast(result_limbs[limb][0]),
            };
        }
        return result;
    }

    fn reduce(
        d0: *u64,
        d1: *u64,
        d2: *u64,
        d3: *u64,
        d4: *u64,
    ) Limbs {
        var carry = d0.* >> limb_bits;
        var h0 = d0.* & limb_mask;
        d1.* += carry;
        carry = d1.* >> limb_bits;
        const h1 = d1.* & limb_mask;
        d2.* += carry;
        carry = d2.* >> limb_bits;
        const h2 = d2.* & limb_mask;
        d3.* += carry;
        carry = d3.* >> limb_bits;
        const h3 = d3.* & limb_mask;
        d4.* += carry;
        carry = d4.* >> limb_bits;
        const h4 = d4.* & limb_mask;
        h0 += carry * 5;
        carry = h0 >> limb_bits;
        h0 &= limb_mask;
        return .{ h0, h1 + carry, h2, h3, h4 };
    }
};

inline fn xorBytes(output: []u8, input: []const u8, stream: []const u8) void {
    const Bytes32 = @Vector(32, u8);
    const Bytes16 = @Vector(16, u8);
    var offset: usize = 0;
    while (offset + @sizeOf(Bytes32) <= input.len) : (offset += @sizeOf(Bytes32)) {
        const input_vec: Bytes32 = @bitCast(input[offset..][0..@sizeOf(Bytes32)].*);
        const stream_vec: Bytes32 = @bitCast(stream[offset..][0..@sizeOf(Bytes32)].*);
        output[offset..][0..@sizeOf(Bytes32)].* = @bitCast(input_vec ^ stream_vec);
    }
    if (offset + @sizeOf(Bytes16) <= input.len) {
        const input_vec: Bytes16 = @bitCast(input[offset..][0..@sizeOf(Bytes16)].*);
        const stream_vec: Bytes16 = @bitCast(stream[offset..][0..@sizeOf(Bytes16)].*);
        output[offset..][0..@sizeOf(Bytes16)].* = @bitCast(input_vec ^ stream_vec);
        offset += @sizeOf(Bytes16);
    }
    while (offset < input.len) : (offset += 1) {
        output[offset] = input[offset] ^ stream[offset];
    }
}

fn ChaChaVec(comptime degree: comptime_int) type {
    // Eight AVX2 lanes benefit from a state-word layout and vectorized output
    // transpose. Smaller batches avoid that transpose and retain the compact
    // block-interleaved implementation used by the NEON and short-input paths.
    return if (degree == 8)
        ChaChaTransposedVec(degree)
    else
        ChaChaInterleavedVec(degree);
}

fn ChaChaTransposedVec(comptime degree: comptime_int) type {
    return struct {
        const Lane = @Vector(degree, u32);
        const State = [16]Lane;

        fn xorBlocks(
            output: []u8,
            input: []const u8,
            key: *const [8]u32,
            nonce: [nonce_length]u8,
            counter: u32,
        ) void {
            std.debug.assert(output.len == input.len);
            std.debug.assert(output.len <= 64 * degree);
            const state = generate(key, nonce, counter);
            if (input.len == 512) {
                return xorKnownLength(512, output[0..512], input[0..512], state);
            }
            if (input.len == 496) {
                return xorKnownLength(496, output[0..496], input[0..496], state);
            }
            inline for (0..2) |half| {
                const base = 8 * half;
                const t0 = interleave32Low(
                    state[base],
                    state[base + 1],
                );
                const t1 = interleave32High(
                    state[base],
                    state[base + 1],
                );
                const t2 = interleave32Low(
                    state[base + 2],
                    state[base + 3],
                );
                const t3 = interleave32High(
                    state[base + 2],
                    state[base + 3],
                );
                const t4 = interleave32Low(
                    state[base + 4],
                    state[base + 5],
                );
                const t5 = interleave32High(
                    state[base + 4],
                    state[base + 5],
                );
                const t6 = interleave32Low(
                    state[base + 6],
                    state[base + 7],
                );
                const t7 = interleave32High(
                    state[base + 6],
                    state[base + 7],
                );
                const s0 = interleave64Low(t0, t2);
                const s1 = interleave64High(t0, t2);
                const s2 = interleave64Low(t1, t3);
                const s3 = interleave64High(t1, t3);
                const s4 = interleave64Low(t4, t6);
                const s5 = interleave64High(t4, t6);
                const s6 = interleave64Low(t5, t7);
                const s7 = interleave64High(t5, t7);
                xorHalf(output, input, 0, half, combine128Low(s0, s4));
                xorHalf(output, input, 1, half, combine128Low(s1, s5));
                xorHalf(output, input, 2, half, combine128Low(s2, s6));
                xorHalf(output, input, 3, half, combine128Low(s3, s7));
                xorHalf(output, input, 4, half, combine128High(s0, s4));
                xorHalf(output, input, 5, half, combine128High(s1, s5));
                xorHalf(output, input, 6, half, combine128High(s2, s6));
                xorHalf(output, input, 7, half, combine128High(s3, s7));
            }
        }

        inline fn xorKnownLength(
            comptime len: usize,
            output: *[len]u8,
            input: *const [len]u8,
            state: State,
        ) void {
            inline for (0..2) |half| {
                const base = 8 * half;
                const t0 = interleave32Low(
                    state[base],
                    state[base + 1],
                );
                const t1 = interleave32High(
                    state[base],
                    state[base + 1],
                );
                const t2 = interleave32Low(
                    state[base + 2],
                    state[base + 3],
                );
                const t3 = interleave32High(
                    state[base + 2],
                    state[base + 3],
                );
                const t4 = interleave32Low(
                    state[base + 4],
                    state[base + 5],
                );
                const t5 = interleave32High(
                    state[base + 4],
                    state[base + 5],
                );
                const t6 = interleave32Low(
                    state[base + 6],
                    state[base + 7],
                );
                const t7 = interleave32High(
                    state[base + 6],
                    state[base + 7],
                );
                const s0 = interleave64Low(t0, t2);
                const s1 = interleave64High(t0, t2);
                const s2 = interleave64Low(t1, t3);
                const s3 = interleave64High(t1, t3);
                const s4 = interleave64Low(t4, t6);
                const s5 = interleave64High(t4, t6);
                const s6 = interleave64Low(t5, t7);
                const s7 = interleave64High(t5, t7);
                inline for (0..8) |block| {
                    const words = switch (block) {
                        0 => combine128Low(s0, s4),
                        1 => combine128Low(s1, s5),
                        2 => combine128Low(s2, s6),
                        3 => combine128Low(s3, s7),
                        4 => combine128High(s0, s4),
                        5 => combine128High(s1, s5),
                        6 => combine128High(s2, s6),
                        7 => combine128High(s3, s7),
                        else => unreachable,
                    };
                    const start = 64 * block + 32 * half;
                    if (start + 32 <= len) {
                        const Bytes = @Vector(32, u8);
                        const stream: Bytes = @bitCast(words);
                        const plain: Bytes = @bitCast(input[start..][0..32].*);
                        output[start..][0..32].* = @bitCast(plain ^ stream);
                    } else if (start + 16 <= len) {
                        const Bytes = @Vector(16, u8);
                        const stream: [32]u8 = @bitCast(words);
                        const stream_vec: Bytes = @bitCast(stream[0..16].*);
                        const plain: Bytes = @bitCast(input[start..][0..16].*);
                        output[start..][0..16].* = @bitCast(plain ^ stream_vec);
                    }
                }
            }
        }

        inline fn generate(
            key: *const [8]u32,
            nonce: [nonce_length]u8,
            counter: u32,
        ) State {
            const constants = comptime [_]u32{
                std.mem.readInt(u32, "expa", .little),
                std.mem.readInt(u32, "nd 3", .little),
                std.mem.readInt(u32, "2-by", .little),
                std.mem.readInt(u32, "te k", .little),
            };
            const counter_offsets: Lane = comptime blk: {
                var offsets: [degree]u32 = undefined;
                for (0..degree) |block| offsets[block] = block;
                break :blk offsets;
            };
            var state: State = .{
                @splat(constants[0]),
                @splat(constants[1]),
                @splat(constants[2]),
                @splat(constants[3]),
                @splat(key[0]),
                @splat(key[1]),
                @splat(key[2]),
                @splat(key[3]),
                @splat(key[4]),
                @splat(key[5]),
                @splat(key[6]),
                @splat(key[7]),
                @as(Lane, @splat(counter)) +% counter_offsets,
                @splat(std.mem.readInt(u32, nonce[0..4], .little)),
                @splat(std.mem.readInt(u32, nonce[4..8], .little)),
                @splat(std.mem.readInt(u32, nonce[8..12], .little)),
            };

            core(&state);
            state[0] +%= @splat(constants[0]);
            state[1] +%= @splat(constants[1]);
            state[2] +%= @splat(constants[2]);
            state[3] +%= @splat(constants[3]);
            inline for (0..8) |word| state[4 + word] +%= @splat(key[word]);
            state[12] +%= @as(Lane, @splat(counter)) +% counter_offsets;
            state[13] +%= @splat(std.mem.readInt(u32, nonce[0..4], .little));
            state[14] +%= @splat(std.mem.readInt(u32, nonce[4..8], .little));
            state[15] +%= @splat(std.mem.readInt(u32, nonce[8..12], .little));
            return state;
        }

        inline fn interleave32Low(a: Lane, b: Lane) Lane {
            return @shuffle(
                u32,
                a,
                b,
                [_]i32{ 0, -1, 1, -2, 4, -5, 5, -6 },
            );
        }

        inline fn interleave32High(a: Lane, b: Lane) Lane {
            return @shuffle(
                u32,
                a,
                b,
                [_]i32{ 2, -3, 3, -4, 6, -7, 7, -8 },
            );
        }

        inline fn interleave64Low(a: Lane, b: Lane) Lane {
            return @shuffle(
                u32,
                a,
                b,
                [_]i32{ 0, 1, -1, -2, 4, 5, -5, -6 },
            );
        }

        inline fn interleave64High(a: Lane, b: Lane) Lane {
            return @shuffle(
                u32,
                a,
                b,
                [_]i32{ 2, 3, -3, -4, 6, 7, -7, -8 },
            );
        }

        inline fn combine128Low(a: Lane, b: Lane) Lane {
            return @shuffle(
                u32,
                a,
                b,
                [_]i32{ 0, 1, 2, 3, -1, -2, -3, -4 },
            );
        }

        inline fn combine128High(a: Lane, b: Lane) Lane {
            return @shuffle(
                u32,
                a,
                b,
                [_]i32{ 4, 5, 6, 7, -5, -6, -7, -8 },
            );
        }

        inline fn xorHalf(
            output: []u8,
            input: []const u8,
            comptime block: usize,
            comptime half: usize,
            words: Lane,
        ) void {
            const start = 64 * block + 32 * half;
            if (start >= input.len) return;
            const len = @min(@as(usize, 32), input.len - start);
            const stream: [32]u8 = @bitCast(words);
            xorBytes(
                output[start..][0..len],
                input[start..][0..len],
                stream[0..len],
            );
        }

        fn core(state: *State) void {
            @setEvalBranchQuota(10_000);
            var round: usize = 0;
            // Two double rounds per loop cut fixed loop-control overhead while
            // keeping the AVX2 hot body comfortably inside the instruction cache.
            while (round < 20) : (round += 4) {
                inline for (0..2) |_| {
                    quarterRound(&state[0], &state[4], &state[8], &state[12]);
                    quarterRound(&state[1], &state[5], &state[9], &state[13]);
                    quarterRound(&state[2], &state[6], &state[10], &state[14]);
                    quarterRound(&state[3], &state[7], &state[11], &state[15]);
                    quarterRound(&state[0], &state[5], &state[10], &state[15]);
                    quarterRound(&state[1], &state[6], &state[11], &state[12]);
                    quarterRound(&state[2], &state[7], &state[8], &state[13]);
                    quarterRound(&state[3], &state[4], &state[9], &state[14]);
                }
            }
        }

        inline fn quarterRound(
            a: *Lane,
            b: *Lane,
            c: *Lane,
            d: *Lane,
        ) void {
            a.* +%= b.*;
            d.* ^= a.*;
            d.* = rotateBytes(d.*, 16);
            c.* +%= d.*;
            b.* ^= c.*;
            b.* = std.math.rotl(Lane, b.*, 12);
            a.* +%= b.*;
            d.* ^= a.*;
            d.* = rotateBytes(d.*, 8);
            c.* +%= d.*;
            b.* ^= c.*;
            b.* = std.math.rotl(Lane, b.*, 7);
        }

        inline fn rotateBytes(value: Lane, comptime bits: u5) Lane {
            const ByteLane = @Vector(4 * degree, u8);
            const bytes: ByteLane = @bitCast(value);
            const mask = comptime blk: {
                var indices: [4 * degree]i32 = undefined;
                const byte_offset = switch (bits) {
                    8 => 3,
                    16 => 2,
                    else => @compileError("unsupported byte rotation"),
                };
                for (0..degree) |word| {
                    for (0..4) |byte| {
                        indices[word * 4 + byte] = @intCast(
                            word * 4 + ((byte + byte_offset) & 3),
                        );
                    }
                }
                break :blk indices;
            };
            return @bitCast(@shuffle(u8, bytes, undefined, mask));
        }
    };
}

fn ChaChaInterleavedVec(comptime degree: comptime_int) type {
    return struct {
        const Lane = @Vector(4 * degree, u32);
        const HalfBlock = @Vector(8, u32);
        const State = [4]Lane;

        fn encryptFirst3AndPolyKey(
            output: []u8,
            input: []const u8,
            key: *const [8]u32,
            nonce: [nonce_length]u8,
        ) [32]u8 {
            comptime std.debug.assert(degree == 4);
            std.debug.assert(output.len == input.len);
            std.debug.assert(input.len > 64 and input.len <= 3 * 64);
            const state = generate(key, nonce, 0);
            const poly_key: [32]u8 = @bitCast(blockHalf(state, 0, 0));
            inline for (1..4) |block| {
                inline for (0..2) |half| {
                    const start = 64 * (block - 1) + 32 * half;
                    if (start >= input.len) return poly_key;
                    const len = @min(@as(usize, 32), input.len - start);
                    const stream: [32]u8 = @bitCast(blockHalf(
                        state,
                        block,
                        half,
                    ));
                    xorBytes(
                        output[start..][0..len],
                        input[start..][0..len],
                        stream[0..len],
                    );
                }
            }
            return poly_key;
        }

        inline fn blockHalf(
            state: State,
            comptime block: usize,
            comptime half: usize,
        ) HalfBlock {
            const base: i32 = 4 * block;
            return @shuffle(
                u32,
                state[2 * half],
                state[2 * half + 1],
                [_]i32{
                    base,
                    base + 1,
                    base + 2,
                    base + 3,
                    -base - 1,
                    -base - 2,
                    -base - 3,
                    -base - 4,
                },
            );
        }

        fn blocks(
            output: *[64 * degree]u8,
            key: *const [8]u32,
            nonce: [nonce_length]u8,
            counter: u32,
        ) void {
            const state = generate(key, nonce, counter);
            inline for (0..degree) |block| {
                inline for (0..4) |row| {
                    inline for (0..4) |column| {
                        std.mem.writeInt(
                            u32,
                            output[64 * block + 16 * row + 4 * column ..][0..4],
                            state[row][4 * block + column],
                            .little,
                        );
                    }
                }
            }
        }

        inline fn generate(
            key: *const [8]u32,
            nonce: [nonce_length]u8,
            counter: u32,
        ) State {
            const constants = comptime [_]u32{
                std.mem.readInt(u32, "expa", .little),
                std.mem.readInt(u32, "nd 3", .little),
                std.mem.readInt(u32, "2-by", .little),
                std.mem.readInt(u32, "te k", .little),
            };
            var initial: State = undefined;
            inline for (0..degree) |block| {
                inline for (0..4) |index| {
                    initial[0][4 * block + index] = constants[index];
                    initial[1][4 * block + index] = key[index];
                    initial[2][4 * block + index] = key[4 + index];
                }
                initial[3][4 * block] = counter +% @as(u32, block);
                initial[3][4 * block + 1] = std.mem.readInt(
                    u32,
                    nonce[0..4],
                    .little,
                );
                initial[3][4 * block + 2] = std.mem.readInt(
                    u32,
                    nonce[4..8],
                    .little,
                );
                initial[3][4 * block + 3] = std.mem.readInt(
                    u32,
                    nonce[8..12],
                    .little,
                );
            }

            var state = initial;
            core(&state);
            state[0] +%= initial[0];
            state[1] +%= initial[1];
            state[2] +%= initial[2];
            state[3] +%= initial[3];
            return state;
        }

        fn core(state: *State) void {
            const m0 = comptime blk: {
                var mask: [4 * degree]i32 = undefined;
                for (0..degree) |block| {
                    const base: i32 = @intCast(4 * block);
                    mask[4 * block ..][0..4].* = .{
                        base + 3, base, base + 1, base + 2,
                    };
                }
                break :blk mask;
            };
            const m1 = comptime blk: {
                var mask: [4 * degree]i32 = undefined;
                for (0..degree) |block| {
                    const base: i32 = @intCast(4 * block);
                    mask[4 * block ..][0..4].* = .{
                        base + 2, base + 3, base, base + 1,
                    };
                }
                break :blk mask;
            };
            const m2 = comptime blk: {
                var mask: [4 * degree]i32 = undefined;
                for (0..degree) |block| {
                    const base: i32 = @intCast(4 * block);
                    mask[4 * block ..][0..4].* = .{
                        base + 1, base + 2, base + 3, base,
                    };
                }
                break :blk mask;
            };

            @setEvalBranchQuota(10_000);
            var round: usize = 0;
            // Match the bounded unroll used by the eight-block AVX2 core.
            while (round < 20) : (round += 4) {
                inline for (0..2) |_| {
                    state[0] +%= state[1];
                    state[3] ^= state[0];
                    state[3] = rotateBytes(state[3], 16);
                    state[2] +%= state[3];
                    state[1] ^= state[2];
                    state[1] = std.math.rotl(Lane, state[1], 12);
                    state[0] +%= state[1];
                    state[3] ^= state[0];
                    state[0] = @shuffle(u32, state[0], undefined, m0);
                    state[3] = rotateBytes(state[3], 8);
                    state[2] +%= state[3];
                    state[3] = @shuffle(u32, state[3], undefined, m1);
                    state[1] ^= state[2];
                    state[2] = @shuffle(u32, state[2], undefined, m2);
                    state[1] = std.math.rotl(Lane, state[1], 7);

                    state[0] +%= state[1];
                    state[3] ^= state[0];
                    state[3] = rotateBytes(state[3], 16);
                    state[2] +%= state[3];
                    state[1] ^= state[2];
                    state[1] = std.math.rotl(Lane, state[1], 12);
                    state[0] +%= state[1];
                    state[3] ^= state[0];
                    state[0] = @shuffle(u32, state[0], undefined, m2);
                    state[3] = rotateBytes(state[3], 8);
                    state[2] +%= state[3];
                    state[3] = @shuffle(u32, state[3], undefined, m1);
                    state[1] ^= state[2];
                    state[2] = @shuffle(u32, state[2], undefined, m0);
                    state[1] = std.math.rotl(Lane, state[1], 7);
                }
            }
        }

        inline fn rotateBytes(value: Lane, comptime bits: u5) Lane {
            const ByteLane = @Vector(16 * degree, u8);
            const bytes: ByteLane = @bitCast(value);
            const mask = comptime blk: {
                var indices: [16 * degree]i32 = undefined;
                const byte_offset = switch (bits) {
                    8 => 3,
                    16 => 2,
                    else => @compileError("unsupported byte rotation"),
                };
                for (0..4 * degree) |word| {
                    for (0..4) |byte| {
                        indices[word * 4 + byte] = @intCast(
                            word * 4 + ((byte + byte_offset) & 3),
                        );
                    }
                }
                break :blk indices;
            };
            return @bitCast(@shuffle(u8, bytes, undefined, mask));
        }
    };
}

test "prepared ChaCha20-Poly1305 matches Zig std across boundaries" {
    const key = [_]u8{0x42} ** key_length;
    const nonce = [_]u8{0x24} ** nonce_length;
    var context = Context.init(key);
    defer context.deinit();
    var input: [16 * 1024 + 1]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    var expected: [input.len]u8 = undefined;
    var actual: [input.len]u8 = undefined;
    var opened: [input.len]u8 = undefined;

    inline for ([_]usize{
        0,    1,         15,            16,  17,  63,  64,   65,   127,  128,
        191,  192,       193,           255, 256, 257, 1199, 1200, 1201, 4097,
        8192, 16 * 1024, 16 * 1024 + 1,
    }) |len| {
        inline for (.{
            "",
            "a",
            "associated data",
            "sixteen-byte-aad",
            "0123456789abcdefg",
            "0123456789abcdef0123456789abcdef",
        }) |aad| {
            var expected_tag: [tag_length]u8 = undefined;
            var actual_tag: [tag_length]u8 = undefined;
            StdChaCha20Poly1305.encrypt(
                expected[0..len],
                &expected_tag,
                input[0..len],
                aad,
                nonce,
                key,
            );
            context.encrypt(
                actual[0..len],
                &actual_tag,
                input[0..len],
                aad,
                nonce,
            );
            try std.testing.expectEqualSlices(u8, expected[0..len], actual[0..len]);
            try std.testing.expectEqual(expected_tag, actual_tag);
            try context.decrypt(
                opened[0..len],
                actual[0..len],
                actual_tag,
                aad,
                nonce,
            );
            try std.testing.expectEqualSlices(u8, input[0..len], opened[0..len]);
            if (len != 0) {
                actual_tag[0] ^= 1;
                try std.testing.expectError(
                    error.AuthenticationFailed,
                    context.decrypt(
                        opened[0..len],
                        actual[0..len],
                        actual_tag,
                        aad,
                        nonce,
                    ),
                );
                if (comptime wide_enabled) {
                    try std.testing.expectEqualSlices(
                        u8,
                        &([_]u8{0} ** len),
                        opened[0..len],
                    );
                }
            }
        }
    }

    var in_place = input[0..1200].*;
    var in_place_tag: [tag_length]u8 = undefined;
    context.encrypt(
        &in_place,
        &in_place_tag,
        &in_place,
        "0123456789abcdefg",
        nonce,
    );
    try context.decrypt(
        &in_place,
        &in_place,
        in_place_tag,
        "0123456789abcdefg",
        nonce,
    );
    try std.testing.expectEqualSlices(u8, input[0..1200], &in_place);
}

test "wide Poly1305 pair matches the serial oracle" {
    const key = [_]u8{0x42} ** Poly1305.key_length;
    const prefix = [_]u8{0x91} ** 64;
    var pair: [32]u8 = undefined;
    for (&pair, 0..) |*byte, index| byte.* = @truncate(index *% 29 +% 7);

    var expected_state = Poly1305.init(&key);
    expected_state.update(&prefix);
    expected_state.update(&pair);
    var expected: [tag_length]u8 = undefined;
    expected_state.final(&expected);

    var actual_state = WidePoly1305.init(&key);
    defer actual_state.deinit();
    actual_state.processBatch(&prefix);
    actual_state.processPair(pair[0..16], pair[16..32]);
    var actual: [tag_length]u8 = undefined;
    actual_state.final(&actual);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "wide Poly1305 eight-block batch matches the serial oracle" {
    for (0..32) |case_index| {
        var key: [Poly1305.key_length]u8 = undefined;
        var prefix: [64]u8 = undefined;
        var input: [128]u8 = undefined;
        for (&key, 0..) |*byte, index| {
            byte.* = @truncate(index *% 37 +% case_index *% 19 +% 3);
        }
        for (&prefix, 0..) |*byte, index| {
            byte.* = @truncate(index *% 31 +% case_index *% 23 +% 5);
        }
        for (&input, 0..) |*byte, index| {
            byte.* = @truncate(index *% 43 +% case_index *% 29 +% 11);
        }

        var expected_state = Poly1305.init(&key);
        expected_state.update(&prefix);
        expected_state.update(&input);
        var expected: [tag_length]u8 = undefined;
        expected_state.final(&expected);

        var actual_state = WidePoly1305.init(&key);
        actual_state.processBatch(&prefix);
        if (comptime max_bulk_degree == 8) {
            const upper_powers = WidePoly1305.multiplyFour(
                actual_state.r,
            );
            actual_state.processBatch8(&input, &upper_powers, 0);
        } else {
            actual_state.processBatch(input[0..64]);
            actual_state.processBatch(input[64..128]);
        }
        var actual: [tag_length]u8 = undefined;
        actual_state.final(&actual);
        actual_state.deinit();
        try std.testing.expectEqualSlices(u8, &expected, &actual);

        var expected_skipped_state = Poly1305.init(&key);
        expected_skipped_state.update(&prefix);
        expected_skipped_state.update(input[32..]);
        var expected_skipped: [tag_length]u8 = undefined;
        expected_skipped_state.final(&expected_skipped);

        var actual_skipped_state = WidePoly1305.init(&key);
        actual_skipped_state.processBatch(&prefix);
        if (comptime max_bulk_degree == 8) {
            const upper_powers = WidePoly1305.multiplyFour(
                actual_skipped_state.r,
            );
            actual_skipped_state.processBatch8(
                &input,
                &upper_powers,
                2,
            );
        } else {
            actual_skipped_state.updateBlocks(input[32..]);
        }
        var actual_skipped: [tag_length]u8 = undefined;
        actual_skipped_state.final(&actual_skipped);
        actual_skipped_state.deinit();
        try std.testing.expectEqualSlices(
            u8,
            &expected_skipped,
            &actual_skipped,
        );
    }
}

test "prepared ChaCha20-Poly1305 batches across padded AAD boundaries" {
    const key = [_]u8{0x91} ** key_length;
    const nonce = [_]u8{0x37} ** nonce_length;
    var context = Context.init(key);
    defer context.deinit();
    var aad: [65]u8 = undefined;
    var input: [257]u8 = undefined;
    for (&aad, 0..) |*byte, index| byte.* = @truncate(index *% 29 +% 3);
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% 11);
    var expected: [input.len]u8 = undefined;
    var actual: [input.len]u8 = undefined;
    var opened: [input.len]u8 = undefined;

    for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 47, 48, 49, 63, 64, 65 }) |aad_len| {
        for ([_]usize{ 47, 48, 49, 63, 64, 65, 127, 128, 129, 256, 257 }) |len| {
            var expected_tag: [tag_length]u8 = undefined;
            var actual_tag: [tag_length]u8 = undefined;
            StdChaCha20Poly1305.encrypt(
                expected[0..len],
                &expected_tag,
                input[0..len],
                aad[0..aad_len],
                nonce,
                key,
            );
            context.encrypt(
                actual[0..len],
                &actual_tag,
                input[0..len],
                aad[0..aad_len],
                nonce,
            );
            try std.testing.expectEqualSlices(u8, expected[0..len], actual[0..len]);
            try std.testing.expectEqual(expected_tag, actual_tag);
            try context.decrypt(
                opened[0..len],
                actual[0..len],
                actual_tag,
                aad[0..aad_len],
                nonce,
            );
            try std.testing.expectEqualSlices(u8, input[0..len], opened[0..len]);
        }
    }
}

test "RFC 8439 ChaCha20-Poly1305 AEAD vector" {
    const key = try hexBytes(
        "808182838485868788898a8b8c8d8e8f" ++
            "909192939495969798999a9b9c9d9e9f",
    );
    const nonce = try hexBytes("070000004041424344454647");
    const aad = try hexBytes("50515253c0c1c2c3c4c5c6c7");
    const plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you " ++
        "only one tip for the future, sunscreen would be it.";
    const expected = try hexBytes(
        "d31a8d34648e60db7b86afbc53ef7ec2" ++
            "a4aded51296e08fea9e2b5a736ee62d6" ++
            "3dbea45e8ca9671282fafb69da92728b" ++
            "1a71de0a9e060b2905d6a5b67ecd3b36" ++
            "92ddbd7f2d778b8c9803aee328091b58" ++
            "fab324e4fad675945585808b4831d7bc" ++
            "3ff4def08e4b7a9de576d26586cec64b" ++
            "6116",
    );
    const expected_tag = try hexBytes("1ae10b594f09e26a7e902ecbd0600691");
    var context = Context.init(key);
    defer context.deinit();
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_length]u8 = undefined;
    context.encrypt(&ciphertext, &tag, plaintext, &aad, nonce);
    try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
    try std.testing.expectEqual(expected_tag, tag);
}

fn hexBytes(comptime encoded: []const u8) ![encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
}
