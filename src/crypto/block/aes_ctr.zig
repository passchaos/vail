//! Wide AES-CTR for prepared AES-GCM contexts.
//!
//! The standard AES context exposes a portable eight-block API, but its x86
//! implementation currently issues one 128-bit VAES instruction per block.
//! On AVX2+VAES targets this helper drives the standard library's `BlockVec(2)`
//! abstraction to encrypt two counter blocks per 256-bit instruction while
//! retaining the standard context as the portable fallback.

const std = @import("std");
const builtin = @import("builtin");

pub const has_wide_vaes = builtin.mode != .ReleaseSmall and
    builtin.cpu.arch == .x86_64 and
    builtin.zig_backend != .stage2_c and
    builtin.cpu.has(.x86, .avx2) and
    builtin.cpu.has(.x86, .vaes);

const BlockPair = std.crypto.core.aes.BlockVec(2);

pub fn xor(
    comptime Aes: type,
    aes: std.crypto.core.aes.AesEncryptCtx(Aes),
    destination: []u8,
    source: []const u8,
    initial_counter: [Aes.block.block_length]u8,
) void {
    std.debug.assert(destination.len == source.len);
    if (comptime has_wide_vaes) {
        xorHardware(Aes, aes, destination, source, initial_counter);
    } else {
        std.crypto.core.modes.ctr(
            std.crypto.core.aes.AesEncryptCtx(Aes),
            aes,
            destination,
            source,
            initial_counter,
            .big,
        );
    }
}

pub fn xorWithTagMask(
    comptime Aes: type,
    aes: std.crypto.core.aes.AesEncryptCtx(Aes),
    tag_mask: *[Aes.block.block_length]u8,
    destination: []u8,
    source: []const u8,
    initial_counter: [Aes.block.block_length]u8,
) void {
    std.debug.assert(destination.len == source.len);
    if (comptime has_wide_vaes) {
        var round_keys = expandRoundKeys(Aes, aes);
        var counters: [2 * Aes.block.block_length]u8 = undefined;
        counters[0..Aes.block.block_length].* = initial_counter;
        counters[Aes.block.block_length..].* = initial_counter;
        std.mem.writeInt(u32, counters[12..16], 1, .big);
        std.mem.writeInt(
            u32,
            counters[Aes.block.block_length + 12 ..][0..4],
            2,
            .big,
        );

        var first_input = [_]u8{0} ** (2 * Aes.block.block_length);
        const first_len = @min(source.len, Aes.block.block_length);
        @memcpy(
            first_input[Aes.block.block_length..][0..first_len],
            source[0..first_len],
        );
        var first_output: [2 * Aes.block.block_length]u8 = undefined;
        xor2(
            Aes,
            &round_keys,
            &first_output,
            &first_input,
            &counters,
        );
        tag_mask.* = first_output[0..Aes.block.block_length].*;
        @memcpy(
            destination[0..first_len],
            first_output[Aes.block.block_length..][0..first_len],
        );
        if (first_len == source.len) return;

        var next_counter = initial_counter;
        std.mem.writeInt(u32, next_counter[12..16], 3, .big);
        xorHardwarePrepared(
            Aes,
            aes,
            &round_keys,
            destination[first_len..],
            source[first_len..],
            next_counter,
        );
    } else {
        aes.encrypt(tag_mask, &initial_counter);
        var data_counter = initial_counter;
        std.mem.writeInt(u32, data_counter[12..16], 2, .big);
        std.crypto.core.modes.ctr(
            std.crypto.core.aes.AesEncryptCtx(Aes),
            aes,
            destination,
            source,
            data_counter,
            .big,
        );
    }
}

fn xorHardware(
    comptime Aes: type,
    aes: std.crypto.core.aes.AesEncryptCtx(Aes),
    destination: []u8,
    source: []const u8,
    initial_counter: [Aes.block.block_length]u8,
) void {
    var round_keys = expandRoundKeys(Aes, aes);
    xorHardwarePrepared(
        Aes,
        aes,
        &round_keys,
        destination,
        source,
        initial_counter,
    );
}

inline fn expandRoundKeys(
    comptime Aes: type,
    aes: std.crypto.core.aes.AesEncryptCtx(Aes),
) [Aes.rounds + 1]BlockPair {
    var round_keys: [Aes.rounds + 1]BlockPair = undefined;
    inline for (aes.key_schedule.round_keys, 0..) |round_key, index| {
        const key_bytes = round_key.toBytes();
        var repeated: [BlockPair.block_length]u8 = undefined;
        repeated[0..Aes.block.block_length].* = key_bytes;
        repeated[Aes.block.block_length..].* = key_bytes;
        round_keys[index] = BlockPair.fromBytes(&repeated);
    }
    return round_keys;
}

inline fn xorHardwarePrepared(
    comptime Aes: type,
    aes: std.crypto.core.aes.AesEncryptCtx(Aes),
    round_keys: *const [Aes.rounds + 1]BlockPair,
    destination: []u8,
    source: []const u8,
    initial_counter: [Aes.block.block_length]u8,
) void {
    const block_length = Aes.block.block_length;
    const blocks_per_batch = 8;
    const batch_length = blocks_per_batch * block_length;

    var counters: [batch_length]u8 = undefined;
    inline for (0..blocks_per_batch) |index| {
        counters[index * block_length ..][0..block_length].* = initial_counter;
    }
    var counter = std.mem.readInt(u32, initial_counter[12..16], .big);
    var offset: usize = 0;
    while (offset + batch_length <= source.len) : (offset += batch_length) {
        inline for (0..blocks_per_batch) |index| {
            std.mem.writeInt(
                u32,
                counters[index * block_length + 12 ..][0..4],
                counter +% @as(u32, @intCast(index)),
                .big,
            );
        }
        xor8(
            Aes,
            round_keys,
            destination[offset..][0..batch_length],
            source[offset..][0..batch_length],
            &counters,
        );
        counter +%= blocks_per_batch;
    }

    while (offset + 2 * block_length <= source.len) : (offset += 2 * block_length) {
        inline for (0..2) |index| {
            std.mem.writeInt(
                u32,
                counters[index * block_length + 12 ..][0..4],
                counter +% @as(u32, @intCast(index)),
                .big,
            );
        }
        xor2(
            Aes,
            round_keys,
            destination[offset..][0 .. 2 * block_length],
            source[offset..][0 .. 2 * block_length],
            counters[0 .. 2 * block_length],
        );
        counter +%= 2;
    }

    if (offset + block_length <= source.len) {
        var counter_block = initial_counter;
        std.mem.writeInt(u32, counter_block[12..16], counter, .big);
        aes.xor(
            destination[offset..][0..block_length],
            source[offset..][0..block_length],
            counter_block,
        );
        counter +%= 1;
        offset += block_length;
    }

    if (offset < source.len) {
        var counter_block = initial_counter;
        std.mem.writeInt(u32, counter_block[12..16], counter, .big);
        var padded = [_]u8{0} ** block_length;
        const tail = source[offset..];
        @memcpy(padded[0..tail.len], tail);
        aes.xor(&padded, &padded, counter_block);
        @memcpy(destination[offset..], padded[0..tail.len]);
    }
}

inline fn xor8(
    comptime Aes: type,
    round_keys: *const [Aes.rounds + 1]BlockPair,
    destination: *[8 * Aes.block.block_length]u8,
    source: *const [8 * Aes.block.block_length]u8,
    counters: *const [8 * Aes.block.block_length]u8,
) void {
    var states: [4]BlockPair = undefined;
    inline for (0..states.len) |index| {
        states[index] = loadPair(counters, index).xorBlocks(round_keys[0]);
    }
    inline for (1..Aes.rounds) |round| {
        inline for (0..states.len) |index| {
            states[index] = states[index].encrypt(round_keys[round]);
        }
    }
    inline for (0..states.len) |index| {
        states[index] = states[index].encryptLast(round_keys[Aes.rounds]);
        storePair(
            destination,
            index,
            states[index].xorBlocks(loadPair(source, index)),
        );
    }
}

inline fn xor2(
    comptime Aes: type,
    round_keys: *const [Aes.rounds + 1]BlockPair,
    destination: *[2 * Aes.block.block_length]u8,
    source: *const [2 * Aes.block.block_length]u8,
    counters: *const [2 * Aes.block.block_length]u8,
) void {
    var state = loadPair(counters, 0).xorBlocks(round_keys[0]);
    inline for (1..Aes.rounds) |round| {
        state = state.encrypt(round_keys[round]);
    }
    state = state.encryptLast(round_keys[Aes.rounds]);
    storePair(destination, 0, state.xorBlocks(loadPair(source, 0)));
}

inline fn loadPair(bytes: anytype, comptime index: usize) BlockPair {
    const offset = index * BlockPair.block_length;
    return BlockPair.fromBytes(
        bytes[offset..][0..BlockPair.block_length],
    );
}

inline fn storePair(bytes: anytype, comptime index: usize, value: BlockPair) void {
    const offset = index * BlockPair.block_length;
    bytes[offset..][0..BlockPair.block_length].* = value.toBytes();
}
