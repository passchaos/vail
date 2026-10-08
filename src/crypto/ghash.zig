//! Cached GHASH acceleration for reusable AES-GCM keys.
//!
//! Zig's standard GHASH implementation limits the common 1 KiB message shape
//! to four blocks per reduction. This module uses the cached powers from a
//! prepared key to consume up to sixteen blocks per reduction: two parallel
//! products per VPCLMULQDQ instruction on x86_64, or independent PMULL
//! products on AArch64. Only the accumulator remains per-message state.

const std = @import("std");
const builtin = @import("builtin");

const Ghash = std.crypto.onetimeauth.Ghash;

pub const has_vpclmul = builtin.mode != .ReleaseSmall and
    builtin.cpu.arch == .x86_64 and
    builtin.zig_backend != .stage2_c and
    builtin.cpu.has(.x86, .avx2) and
    builtin.cpu.has(.x86, .vpclmulqdq);
pub const has_pmull = builtin.mode != .ReleaseSmall and
    builtin.cpu.arch == .aarch64 and
    builtin.zig_backend != .stage2_c and
    builtin.cpu.has(.aarch64, .aes);

/// Authenticate the two padded GCM domains plus their bit-length block.
pub fn create(
    precomputed: *const Ghash,
    tag: *[Ghash.mac_length]u8,
    associated_data: []const u8,
    ciphertext: []const u8,
) void {
    if (comptime has_vpclmul or has_pmull) {
        var lengths: [Ghash.block_length]u8 = undefined;
        std.mem.writeInt(
            u64,
            lengths[0..8],
            @as(u64, @intCast(associated_data.len)) * 8,
            .big,
        );
        std.mem.writeInt(
            u64,
            lengths[8..16],
            @as(u64, @intCast(ciphertext.len)) * 8,
            .big,
        );
        var accumulator = absorb(0, &precomputed.hx, associated_data);
        accumulator = absorbWithSuffix(
            accumulator,
            &precomputed.hx,
            ciphertext,
            &lengths,
        );
        std.mem.writeInt(u128, tag, accumulator, .big);
    } else {
        var mac = precomputed.*;
        mac.update(associated_data);
        mac.pad();
        mac.update(ciphertext);
        mac.pad();
        var lengths: [Ghash.block_length]u8 = undefined;
        std.mem.writeInt(
            u64,
            lengths[0..8],
            @as(u64, @intCast(associated_data.len)) * 8,
            .big,
        );
        std.mem.writeInt(
            u64,
            lengths[8..16],
            @as(u64, @intCast(ciphertext.len)) * 8,
            .big,
        );
        mac.update(&lengths);
        mac.final(tag);
    }
}

fn absorb(
    initial_accumulator: u128,
    powers: *const [16]u128,
    input: []const u8,
) u128 {
    var accumulator = initial_accumulator;
    var offset: usize = 0;
    while (input.len - offset > 16 * Ghash.block_length) {
        accumulator = hashBlocks(
            16,
            accumulator,
            input[offset..][0 .. 16 * Ghash.block_length],
            powers,
        );
        offset += 16 * Ghash.block_length;
    }
    const remaining = input[offset..];
    if (remaining.len == 0) return accumulator;

    var tail = [_]u8{0} ** (16 * Ghash.block_length);
    @memcpy(tail[0..remaining.len], remaining);
    const block_count = std.math.divCeil(
        usize,
        remaining.len,
        Ghash.block_length,
    ) catch unreachable;
    return hashTail(accumulator, &tail, powers, block_count);
}

fn absorbWithSuffix(
    initial_accumulator: u128,
    powers: *const [16]u128,
    input: []const u8,
    suffix: *const [Ghash.block_length]u8,
) u128 {
    var accumulator = initial_accumulator;
    var offset: usize = 0;
    while (input.len - offset > 16 * Ghash.block_length) {
        accumulator = hashBlocks(
            16,
            accumulator,
            input[offset..][0 .. 16 * Ghash.block_length],
            powers,
        );
        offset += 16 * Ghash.block_length;
    }

    const remaining = input[offset..];
    if (remaining.len % Ghash.block_length == 0) {
        return hashAlignedWithSuffix(
            accumulator,
            remaining,
            suffix,
            powers,
        );
    }

    var tail = [_]u8{0} ** (17 * Ghash.block_length);
    @memcpy(tail[0..remaining.len], remaining);
    const padded_len = std.mem.alignForward(
        usize,
        remaining.len,
        Ghash.block_length,
    );
    tail[padded_len..][0..Ghash.block_length].* = suffix.*;
    const tail_block_count = padded_len / Ghash.block_length + 1;
    return hashTail(
        accumulator,
        &tail,
        powers,
        tail_block_count,
    );
}

fn hashAlignedWithSuffix(
    initial_accumulator: u128,
    input: []const u8,
    suffix: *const [Ghash.block_length]u8,
    powers: *const [16]u128,
) u128 {
    var accumulator = initial_accumulator;
    var remaining = input;
    var input_block_count = input.len / Ghash.block_length;
    std.debug.assert(input_block_count <= 16);
    if (input_block_count % 2 == 0 and input_block_count != 0) {
        accumulator = hashOne(
            accumulator,
            remaining[0..Ghash.block_length],
            powers[0],
        );
        remaining = remaining[Ghash.block_length..];
        input_block_count -= 1;
    }
    return switch (input_block_count) {
        0 => hashOne(accumulator, suffix, powers[0]),
        1 => hashWithSuffix(1, accumulator, remaining[0..16], suffix, powers),
        3 => hashWithSuffix(3, accumulator, remaining[0..48], suffix, powers),
        5 => hashWithSuffix(5, accumulator, remaining[0..80], suffix, powers),
        7 => hashWithSuffix(7, accumulator, remaining[0..112], suffix, powers),
        9 => hashWithSuffix(9, accumulator, remaining[0..144], suffix, powers),
        11 => hashWithSuffix(11, accumulator, remaining[0..176], suffix, powers),
        13 => hashWithSuffix(13, accumulator, remaining[0..208], suffix, powers),
        15 => hashWithSuffix(15, accumulator, remaining[0..240], suffix, powers),
        else => unreachable,
    };
}

fn hashWithSuffix(
    comptime input_block_count: usize,
    accumulator: u128,
    input: *const [input_block_count * Ghash.block_length]u8,
    suffix: *const [Ghash.block_length]u8,
    powers: *const [16]u128,
) u128 {
    comptime std.debug.assert(
        input_block_count >= 1 and input_block_count <= 15 and
            input_block_count % 2 == 1,
    );
    if (comptime has_pmull) {
        return hashWithSuffixPmull(
            input_block_count,
            accumulator,
            input,
            suffix,
            powers,
        );
    }
    const total_block_count = input_block_count + 1;
    var product = if (input_block_count == 1)
        clmul2(
            loadSeparateBlocks(input[0..Ghash.block_length], suffix, accumulator),
            loadPowers2(powers, 1),
        )
    else
        clmul2(
            loadBlocks2(input_block_count, input, 0, accumulator),
            loadPowers2(powers, total_block_count - 1),
        );

    if (input_block_count > 1) {
        inline for (1..input_block_count / 2) |pair_index| {
            const block_index = pair_index * 2;
            const next = clmul2(
                loadBlocks2(input_block_count, input, pair_index, 0),
                loadPowers2(
                    powers,
                    total_block_count - 1 - block_index,
                ),
            );
            product.hi ^= next.hi;
            product.lo ^= next.lo;
            product.mid ^= next.mid;
        }
        const suffix_product = clmul2(
            loadSeparateBlocks(
                input[(input_block_count - 1) * Ghash.block_length ..],
                suffix,
                0,
            ),
            loadPowers2(powers, 1),
        );
        product.hi ^= suffix_product.hi;
        product.lo ^= suffix_product.lo;
        product.mid ^= suffix_product.mid;
    }
    return reduce(.{
        .hi = xorLanes(product.hi),
        .lo = xorLanes(product.lo),
        .mid = xorLanes(product.mid),
    });
}

fn hashTail(
    initial_accumulator: u128,
    tail: []const u8,
    powers: *const [16]u128,
    block_count: usize,
) u128 {
    std.debug.assert(block_count >= 1 and block_count <= 17);
    var accumulator = initial_accumulator;
    var offset: usize = 0;
    var even_block_count = block_count;
    if (block_count % 2 != 0) {
        accumulator = hashOne(
            accumulator,
            tail[0..Ghash.block_length],
            powers[0],
        );
        offset = Ghash.block_length;
        even_block_count -= 1;
    }
    accumulator = switch (even_block_count) {
        0 => accumulator,
        2 => hashBlocks(2, accumulator, tail[offset..][0 .. 2 * Ghash.block_length], powers),
        4 => hashBlocks(4, accumulator, tail[offset..][0 .. 4 * Ghash.block_length], powers),
        6 => hashBlocks(6, accumulator, tail[offset..][0 .. 6 * Ghash.block_length], powers),
        8 => hashBlocks(8, accumulator, tail[offset..][0 .. 8 * Ghash.block_length], powers),
        10 => hashBlocks(10, accumulator, tail[offset..][0 .. 10 * Ghash.block_length], powers),
        12 => hashBlocks(12, accumulator, tail[offset..][0 .. 12 * Ghash.block_length], powers),
        14 => hashBlocks(14, accumulator, tail[offset..][0 .. 14 * Ghash.block_length], powers),
        16 => hashBlocks(16, accumulator, tail[offset..][0 .. 16 * Ghash.block_length], powers),
        else => unreachable,
    };
    return accumulator;
}

const Vec = @Vector(4, u64);
const U128x2 = @Vector(2, u128);
const Repr = @Vector(2, u64);

const ProductVec = struct {
    hi: Vec,
    lo: Vec,
    mid: Vec,
};

const Product = struct {
    hi: u128,
    lo: u128,
    mid: u128,
};

inline fn multiply(x: u128, y: u128) Product {
    return .{
        .hi = clmul(x, y, 0x11),
        .lo = clmul(x, y, 0x00),
        .mid = clmul(x, y, 0x10) ^ clmul(y, x, 0x10),
    };
}

inline fn xorProduct(product: *Product, other: Product) void {
    product.hi ^= other.hi;
    product.lo ^= other.lo;
    product.mid ^= other.mid;
}

fn hashBlocks(
    comptime block_count: usize,
    accumulator: u128,
    blocks: *const [block_count * Ghash.block_length]u8,
    powers: *const [16]u128,
) u128 {
    comptime std.debug.assert(
        block_count >= 2 and block_count <= 16 and block_count % 2 == 0,
    );
    if (comptime has_pmull) {
        return hashBlocksPmull(
            block_count,
            accumulator,
            blocks,
            powers,
        );
    }
    var product = clmul2(
        loadBlocks2(block_count, blocks, 0, accumulator),
        loadPowers2(powers, block_count - 1),
    );
    inline for (1..block_count / 2) |pair_index| {
        const block_index = pair_index * 2;
        const next = clmul2(
            loadBlocks2(block_count, blocks, pair_index, 0),
            loadPowers2(powers, block_count - 1 - block_index),
        );
        product.hi ^= next.hi;
        product.lo ^= next.lo;
        product.mid ^= next.mid;
    }
    return reduce(.{
        .hi = xorLanes(product.hi),
        .lo = xorLanes(product.lo),
        .mid = xorLanes(product.mid),
    });
}

noinline fn hashBlocksPmull(
    block_count: usize,
    accumulator: u128,
    blocks: []const u8,
    powers: *const [16]u128,
) u128 {
    std.debug.assert(block_count >= 2 and block_count <= 16);
    std.debug.assert(blocks.len == block_count * Ghash.block_length);
    var product = multiply(
        accumulator ^ std.mem.readInt(u128, blocks[0..16], .big),
        powers[block_count - 1],
    );
    var index: usize = 1;
    while (index + 3 < block_count) : (index += 4) {
        const first = multiply(
            loadBlock(blocks, index),
            powers[block_count - 1 - index],
        );
        const second = multiply(
            loadBlock(blocks, index + 1),
            powers[block_count - 2 - index],
        );
        const third = multiply(
            loadBlock(blocks, index + 2),
            powers[block_count - 3 - index],
        );
        const fourth = multiply(
            loadBlock(blocks, index + 3),
            powers[block_count - 4 - index],
        );
        product.hi ^= first.hi ^ second.hi ^ third.hi ^ fourth.hi;
        product.lo ^= first.lo ^ second.lo ^ third.lo ^ fourth.lo;
        product.mid ^= first.mid ^ second.mid ^ third.mid ^ fourth.mid;
    }
    while (index < block_count) : (index += 1) {
        xorProduct(
            &product,
            multiply(
                loadBlock(blocks, index),
                powers[block_count - 1 - index],
            ),
        );
    }
    return reduce(product);
}

noinline fn hashWithSuffixPmull(
    input_block_count: usize,
    accumulator: u128,
    input: []const u8,
    suffix: *const [Ghash.block_length]u8,
    powers: *const [16]u128,
) u128 {
    std.debug.assert(input_block_count >= 1 and input_block_count <= 15);
    std.debug.assert(input.len == input_block_count * Ghash.block_length);
    const total_block_count = input_block_count + 1;
    var product = multiply(
        accumulator ^ std.mem.readInt(u128, input[0..16], .big),
        powers[total_block_count - 1],
    );
    var index: usize = 1;
    while (index + 3 < input_block_count) : (index += 4) {
        const first = multiply(
            loadBlock(input, index),
            powers[total_block_count - 1 - index],
        );
        const second = multiply(
            loadBlock(input, index + 1),
            powers[total_block_count - 2 - index],
        );
        const third = multiply(
            loadBlock(input, index + 2),
            powers[total_block_count - 3 - index],
        );
        const fourth = multiply(
            loadBlock(input, index + 3),
            powers[total_block_count - 4 - index],
        );
        product.hi ^= first.hi ^ second.hi ^ third.hi ^ fourth.hi;
        product.lo ^= first.lo ^ second.lo ^ third.lo ^ fourth.lo;
        product.mid ^= first.mid ^ second.mid ^ third.mid ^ fourth.mid;
    }
    while (index < input_block_count) : (index += 1) {
        xorProduct(
            &product,
            multiply(
                loadBlock(input, index),
                powers[total_block_count - 1 - index],
            ),
        );
    }
    xorProduct(
        &product,
        multiply(std.mem.readInt(u128, suffix, .big), powers[0]),
    );
    return reduce(product);
}

inline fn loadBlock(input: []const u8, index: usize) u128 {
    return std.mem.readInt(
        u128,
        input[index * Ghash.block_length ..][0..Ghash.block_length],
        .big,
    );
}

fn hashOne(
    accumulator: u128,
    block: *const [Ghash.block_length]u8,
    power: u128,
) u128 {
    const value = accumulator ^ std.mem.readInt(u128, block, .big);
    const lo = clmul(value, power, 0x00);
    const hi = clmul(value, power, 0x11);
    return reduce(.{
        .hi = hi,
        .lo = lo,
        .mid = clmul(value, power, 0x10) ^ clmul(power, value, 0x10),
    });
}

inline fn loadBlocks2(
    comptime block_count: usize,
    blocks: *const [block_count * Ghash.block_length]u8,
    comptime pair_index: usize,
    accumulator: u128,
) Vec {
    const offset = pair_index * 2 * Ghash.block_length;
    const raw: @Vector(32, u8) =
        blocks[offset..][0 .. 2 * Ghash.block_length].*;
    const byte_swap = @Vector(32, i32){
        15, 14, 13, 12, 11, 10, 9,  8,
        7,  6,  5,  4,  3,  2,  1,  0,
        31, 30, 29, 28, 27, 26, 25, 24,
        23, 22, 21, 20, 19, 18, 17, 16,
    };
    var values: U128x2 = @bitCast(@shuffle(u8, raw, undefined, byte_swap));
    values[0] ^= accumulator;
    return @bitCast(values);
}

inline fn loadPowers2(
    powers: *const [16]u128,
    comptime high_index: usize,
) Vec {
    const ascending: U128x2 = powers[high_index - 1 ..][0..2].*;
    const descending = @shuffle(
        u128,
        ascending,
        undefined,
        @Vector(2, i32){ 1, 0 },
    );
    return @bitCast(descending);
}

inline fn loadSeparateBlocks(
    first: *const [Ghash.block_length]u8,
    second: *const [Ghash.block_length]u8,
    accumulator: u128,
) Vec {
    return @bitCast(U128x2{
        std.mem.readInt(u128, first, .big) ^ accumulator,
        std.mem.readInt(u128, second, .big),
    });
}

inline fn xorLanes(value: Vec) u128 {
    const lanes: U128x2 = @bitCast(value);
    return lanes[0] ^ lanes[1];
}

fn clmul2(x: Vec, y: Vec) ProductVec {
    const lo = clmulVec(x, y, 0x00);
    const hi = clmulVec(x, y, 0x11);
    return .{
        .hi = hi,
        .lo = lo,
        .mid = clmulVec(x, y, 0x10) ^ clmulVec(y, x, 0x10),
    };
}

inline fn clmulVec(x: Vec, y: Vec, comptime selector: u8) Vec {
    return asm ("vpclmulqdq %[selector], %[x], %[y], %[out]"
        : [out] "=x" (-> Vec),
        : [x] "x" (x),
          [y] "x" (y),
          [selector] "n" (selector),
    );
}

fn clmulVpclmul(x: u128, y: u128, comptime selector: u8) u128 {
    const result = asm ("vpclmulqdq %[selector], %[x], %[y], %[out]"
        : [out] "=x" (-> Repr),
        : [x] "x" (@as(Repr, @bitCast(x))),
          [y] "x" (@as(Repr, @bitCast(y))),
          [selector] "n" (selector),
    );
    return @bitCast(result);
}

fn clmulPmull(x: u128, y: u128, comptime selector: u8) u128 {
    const result = switch (selector) {
        0x11 => asm ("pmull2 %[out].1q, %[x].2d, %[y].2d"
            : [out] "=w" (-> @Vector(2, u64)),
            : [x] "w" (@as(@Vector(2, u64), @bitCast(x))),
              [y] "w" (@as(@Vector(2, u64), @bitCast(y))),
        ),
        0x00 => asm ("pmull %[out].1q, %[x].1d, %[y].1d"
            : [out] "=w" (-> @Vector(2, u64)),
            : [x] "w" (@as(@Vector(2, u64), @bitCast(x))),
              [y] "w" (@as(@Vector(2, u64), @bitCast(y))),
        ),
        0x10 => asm ("pmull %[out].1q, %[x].1d, %[y].1d"
            : [out] "=w" (-> @Vector(2, u64)),
            : [x] "w" (@as(@Vector(2, u64), @bitCast(x >> 64))),
              [y] "w" (@as(@Vector(2, u64), @bitCast(y))),
        ),
        else => unreachable,
    };
    return @bitCast(result);
}

inline fn clmul(x: u128, y: u128, comptime selector: u8) u128 {
    if (comptime has_vpclmul) return clmulVpclmul(x, y, selector);
    if (comptime has_pmull) return clmulPmull(x, y, selector);
    unreachable;
}

fn reduce(product: Product) u128 {
    const hi = product.hi ^ (product.mid >> 64);
    const lo = product.lo ^ (product.mid << 64);
    const reduction_constant = (((1 << 121) | (1 << 126) | (1 << 127)) >> 64);
    const first = clmul(lo, reduction_constant, 0x00);
    const folded = ((lo << 64) | (lo >> 64)) ^ first;
    const second = clmul(folded, reduction_constant, 0x00);
    return ((folded << 64) | (folded >> 64)) ^ second ^ hi;
}
