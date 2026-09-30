//! Prepared pure-Zig ChaCha20-Poly1305 with a four-block vector path.
//!
//! The wide path combines counter zero (the Poly1305 one-time key) with the
//! first three payload blocks, then emits four payload blocks per core call.
//! Portable targets retain Zig std's audited implementation.

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

    pub noinline fn encrypt(
        self: *const Context,
        ciphertext: []u8,
        tag: *[tag_length]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) void {
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
        var poly_key = self.encryptWideAndPolyKey(
            ciphertext,
            plaintext,
            nonce,
        );
        defer std.crypto.secureZero(u8, &poly_key);
        authenticate(tag, associated_data, ciphertext, &poly_key);
    }

    pub noinline fn decrypt(
        self: *const Context,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [tag_length]u8,
        associated_data: []const u8,
        nonce: [nonce_length]u8,
    ) AuthenticationError!void {
        std.debug.assert(plaintext.len == ciphertext.len);
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

        var poly_key = self.polyKey(nonce);
        defer std.crypto.secureZero(u8, &poly_key);
        var computed_tag: [tag_length]u8 = undefined;
        authenticate(
            &computed_tag,
            associated_data,
            ciphertext,
            &poly_key,
        );
        defer std.crypto.secureZero(u8, &computed_tag);
        if (!std.crypto.timing_safe.eql(
            [tag_length]u8,
            computed_tag,
            tag,
        )) {
            @memset(plaintext, undefined);
            return error.AuthenticationFailed;
        }
        self.xorPayload(plaintext, ciphertext, nonce);
    }

    fn polyKey(self: *const Context, nonce: [nonce_length]u8) [32]u8 {
        var blocks: [128]u8 = undefined;
        ChaChaVec(2).blocks(&blocks, self.key, nonce, 0);
        return blocks[0..32].*;
    }

    fn encryptWideAndPolyKey(
        self: *const Context,
        output: []u8,
        input: []const u8,
        nonce: [nonce_length]u8,
    ) [32]u8 {
        if (input.len <= 64) {
            var blocks: [128]u8 = undefined;
            ChaChaVec(2).blocks(&blocks, self.key, nonce, 0);
            xorBytes(output, input, blocks[64..][0..input.len]);
            return blocks[0..32].*;
        }

        var blocks: [256]u8 = undefined;
        ChaChaVec(4).blocks(&blocks, self.key, nonce, 0);
        const poly_key = blocks[0..32].*;
        const first_len: usize = @min(input.len, 3 * 64);
        xorBytes(output[0..first_len], input[0..first_len], blocks[64..][0..first_len]);
        var offset = first_len;
        var counter: u32 = 4;
        while (offset < input.len) {
            ChaChaVec(4).blocks(&blocks, self.key, nonce, counter);
            const len = @min(blocks.len, input.len - offset);
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

    fn xorPayload(
        self: *const Context,
        output: []u8,
        input: []const u8,
        nonce: [nonce_length]u8,
    ) void {
        if (input.len <= 64) {
            var blocks: [128]u8 = undefined;
            ChaChaVec(2).blocks(&blocks, self.key, nonce, 0);
            xorBytes(output, input, blocks[64..][0..input.len]);
            return;
        }
        var blocks: [256]u8 = undefined;
        var offset: usize = 0;
        var counter: u32 = 1;
        while (offset < input.len) {
            ChaChaVec(4).blocks(&blocks, self.key, nonce, counter);
            const len = @min(blocks.len, input.len - offset);
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

fn authenticate(
    tag: *[tag_length]u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    poly_key: *const [Poly1305.key_length]u8,
) void {
    if (comptime wide_enabled) {
        if (ciphertext.len != 0) {
            var mac = WidePoly1305.init(poly_key);
            defer mac.deinit();
            mac.updatePadded(associated_data);
            mac.updatePadded(ciphertext);
            var lengths: [16]u8 = undefined;
            std.mem.writeInt(u64, lengths[0..8], associated_data.len, .little);
            std.mem.writeInt(u64, lengths[8..16], ciphertext.len, .little);
            mac.updateBlocks(&lengths);
            mac.final(tag);
            return;
        }
    }
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

/// Four consecutive blocks are evaluated as
/// `(h+m0)r^4 + m1r^3 + m2r^2 + m3r`. Keeping limbs below 26 bits lets LLVM
/// lower the widened u32 lane products to portable vector instructions while
/// every horizontal sum remains comfortably below u64 overflow.
const WidePoly1305 = struct {
    const limb_bits = 26;
    const limb_mask: u64 = (1 << limb_bits) - 1;
    const hibit: u64 = 1 << 24;
    const Limbs = [5]u64;

    r: [4]Limbs,
    h: Limbs = @splat(0),
    pad: [4]u32,

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
        var powers: [4]Limbs = undefined;
        powers[0] = r1;
        for (1..powers.len) |index| {
            powers[index] = multiply(powers[index - 1], r1);
        }
        return .{
            .r = powers,
            .pad = .{
                std.mem.readInt(u32, key[16..20], .little),
                std.mem.readInt(u32, key[20..24], .little),
                std.mem.readInt(u32, key[24..28], .little),
                std.mem.readInt(u32, key[28..32], .little),
            },
        };
    }

    fn deinit(self: *WidePoly1305) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    fn updatePadded(self: *WidePoly1305, input: []const u8) void {
        const full_len = input.len & ~@as(usize, 15);
        self.updateBlocks(input[0..full_len]);
        if (full_len != input.len) {
            var block = [_]u8{0} ** 16;
            @memcpy(block[0 .. input.len - full_len], input[full_len..]);
            self.updateBlocks(&block);
        }
    }

    fn updateBlocks(self: *WidePoly1305, input: []const u8) void {
        std.debug.assert(input.len % 16 == 0);
        var offset: usize = 0;
        while (offset + 64 <= input.len) : (offset += 64) {
            self.processBatch(4, input[offset..][0..64]);
        }
        while (offset < input.len) : (offset += 16) {
            const message = parseBlock(input[offset..][0..16]);
            var sum = self.h;
            inline for (0..5) |index| sum[index] += message[index];
            self.h = multiply(sum, self.r[0]);
        }
    }

    fn processBatch(
        self: *WidePoly1305,
        comptime count: comptime_int,
        input: *const [16 * count]u8,
    ) void {
        const U32xN = @Vector(count, u32);
        var a: [5]U32xN = undefined;
        var r: [5]U32xN = undefined;
        inline for (0..count) |lane| {
            var message = parseBlock(input[lane * 16 ..][0..16]);
            if (lane == 0) {
                inline for (0..5) |limb| message[limb] += self.h[limb];
            }
            const power = self.r[count - 1 - lane];
            inline for (0..5) |limb| {
                a[limb][lane] = @intCast(message[limb]);
                r[limb][lane] = @intCast(power[limb]);
            }
        }
        const five: U32xN = @splat(5);
        const s1 = r[1] *% five;
        const s2 = r[2] *% five;
        const s3 = r[3] *% five;
        const s4 = r[4] *% five;

        var d0 = @reduce(.Add, mulWide(count, a[0], r[0]) +% mulWide(count, a[1], s4) +% mulWide(count, a[2], s3) +% mulWide(count, a[3], s2) +% mulWide(count, a[4], s1));
        var d1 = @reduce(.Add, mulWide(count, a[0], r[1]) +% mulWide(count, a[1], r[0]) +% mulWide(count, a[2], s4) +% mulWide(count, a[3], s3) +% mulWide(count, a[4], s2));
        var d2 = @reduce(.Add, mulWide(count, a[0], r[2]) +% mulWide(count, a[1], r[1]) +% mulWide(count, a[2], r[0]) +% mulWide(count, a[3], s4) +% mulWide(count, a[4], s3));
        var d3 = @reduce(.Add, mulWide(count, a[0], r[3]) +% mulWide(count, a[1], r[2]) +% mulWide(count, a[2], r[1]) +% mulWide(count, a[3], r[0]) +% mulWide(count, a[4], s4));
        var d4 = @reduce(.Add, mulWide(count, a[0], r[4]) +% mulWide(count, a[1], r[3]) +% mulWide(count, a[2], r[2]) +% mulWide(count, a[3], r[1]) +% mulWide(count, a[4], r[0]));
        self.h = reduce(&d0, &d1, &d2, &d3, &d4);
    }

    inline fn mulWide(
        comptime count: comptime_int,
        a: @Vector(count, u32),
        b: @Vector(count, u32),
    ) @Vector(count, u64) {
        return @as(@Vector(count, u64), @intCast(a)) *%
            @as(@Vector(count, u64), @intCast(b));
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

        const words = [_]u64{
            (h0 | (h1 << 26)) & 0xffff_ffff,
            ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff,
            ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff,
            ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff,
        };
        var value = words[0] + self.pad[0];
        std.mem.writeInt(u32, output[0..4], @truncate(value), .little);
        value = words[1] + self.pad[1] + (value >> 32);
        std.mem.writeInt(u32, output[4..8], @truncate(value), .little);
        value = words[2] + self.pad[2] + (value >> 32);
        std.mem.writeInt(u32, output[8..12], @truncate(value), .little);
        value = words[3] + self.pad[3] + (value >> 32);
        std.mem.writeInt(u32, output[12..16], @truncate(value), .little);
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
    const Bytes = @Vector(32, u8);
    var offset: usize = 0;
    while (offset + @sizeOf(Bytes) <= input.len) : (offset += @sizeOf(Bytes)) {
        const input_vec: Bytes = @bitCast(input[offset..][0..@sizeOf(Bytes)].*);
        const stream_vec: Bytes = @bitCast(stream[offset..][0..@sizeOf(Bytes)].*);
        output[offset..][0..@sizeOf(Bytes)].* = @bitCast(input_vec ^ stream_vec);
    }
    while (offset < input.len) : (offset += 1) {
        output[offset] = input[offset] ^ stream[offset];
    }
}

fn ChaChaVec(comptime degree: comptime_int) type {
    return struct {
        const Lane = @Vector(4 * degree, u32);
        const State = [4]Lane;

        fn blocks(
            output: *[64 * degree]u8,
            key: [8]u32,
            nonce: [nonce_length]u8,
            counter: u32,
        ) void {
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

        fn core(state: *State) void {
            const m0 = switch (degree) {
                2 => [_]i32{ 3, 0, 1, 2 } ++ [_]i32{ 7, 4, 5, 6 },
                4 => [_]i32{ 3, 0, 1, 2 } ++ [_]i32{ 7, 4, 5, 6 } ++
                    [_]i32{ 11, 8, 9, 10 } ++ [_]i32{ 15, 12, 13, 14 },
                else => @compileError("invalid ChaCha vector degree"),
            };
            const m1 = switch (degree) {
                2 => [_]i32{ 2, 3, 0, 1 } ++ [_]i32{ 6, 7, 4, 5 },
                4 => [_]i32{ 2, 3, 0, 1 } ++ [_]i32{ 6, 7, 4, 5 } ++
                    [_]i32{ 10, 11, 8, 9 } ++ [_]i32{ 14, 15, 12, 13 },
                else => @compileError("invalid ChaCha vector degree"),
            };
            const m2 = switch (degree) {
                2 => [_]i32{ 1, 2, 3, 0 } ++ [_]i32{ 5, 6, 7, 4 },
                4 => [_]i32{ 1, 2, 3, 0 } ++ [_]i32{ 5, 6, 7, 4 } ++
                    [_]i32{ 9, 10, 11, 8 } ++ [_]i32{ 13, 14, 15, 12 },
                else => @compileError("invalid ChaCha vector degree"),
            };

            var round: usize = 0;
            while (round < 20) : (round += 2) {
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
        inline for (.{ "", "a", "associated data", "sixteen-byte-aad" }) |aad| {
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
            }
        }
    }

    var in_place = input[0..1200].*;
    var in_place_tag: [tag_length]u8 = undefined;
    context.encrypt(
        &in_place,
        &in_place_tag,
        &in_place,
        "in-place aad",
        nonce,
    );
    try context.decrypt(
        &in_place,
        &in_place,
        in_place_tag,
        "in-place aad",
        nonce,
    );
    try std.testing.expectEqualSlices(u8, input[0..1200], &in_place);
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
