//! Portable AES-192 encryption context.
//!
//! Zig's standard AES core exposes AES-128 and AES-256 key schedules. WinZip
//! AES also standardizes 192-bit keys, so this small context supplies the
//! missing FIPS-197 expansion while reusing Zig's selected constant-time AES
//! round primitive for block encryption.

const std = @import("std");

const Aes = std.crypto.core.aes;
const Block = Aes.Block;

pub const key_len: usize = 24;
pub const block_len: usize = 16;
const rounds: usize = 12;
const word_count: usize = 4 * (rounds + 1);

pub const EncryptContext = struct {
    round_keys: [rounds + 1]Block,

    const Self = @This();

    pub fn init(key: [key_len]u8) Self {
        var words: [word_count]u32 = undefined;
        for (0..6) |index|
            words[index] = std.mem.readInt(u32, key[index * 4 ..][0..4], .big);

        var rcon: u8 = 1;
        for (6..word_count) |index| {
            var temporary = words[index - 1];
            if (index % 6 == 0) {
                temporary = subWord(std.math.rotl(u32, temporary, 8)) ^
                    (@as(u32, rcon) << 24);
                rcon = multiply(rcon, 2);
            }
            words[index] = words[index - 6] ^ temporary;
        }

        var round_keys: [rounds + 1]Block = undefined;
        for (&round_keys, 0..) |*round_key, round| {
            var bytes: [block_len]u8 = undefined;
            for (0..4) |column|
                std.mem.writeInt(u32, bytes[column * 4 ..][0..4], words[round * 4 + column], .big);
            round_key.* = Block.fromBytes(&bytes);
        }
        std.crypto.secureZero(u32, &words);
        return .{ .round_keys = round_keys };
    }

    pub fn encrypt(self: *const Self, output: *[block_len]u8, input: *const [block_len]u8) void {
        var block = Block.fromBytes(input).xorBlocks(self.round_keys[0]);
        for (1..rounds) |round|
            block = block.encrypt(self.round_keys[round]);
        output.* = block.encryptLast(self.round_keys[rounds]).toBytes();
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(Self, (&self.*)[0..1]);
    }
};

fn subWord(word: u32) u32 {
    var output: u32 = 0;
    inline for (0..4) |index| {
        const shift: u5 = @intCast(24 - index * 8);
        output |= @as(u32, subByte(@truncate(word >> shift))) << shift;
    }
    return output;
}

fn subByte(byte: u8) u8 {
    const inverse = power(byte, 254);
    return inverse ^
        std.math.rotl(u8, inverse, 1) ^
        std.math.rotl(u8, inverse, 2) ^
        std.math.rotl(u8, inverse, 3) ^
        std.math.rotl(u8, inverse, 4) ^
        0x63;
}

fn power(value: u8, exponent_value: u8) u8 {
    var result: u8 = 1;
    var base = value;
    var exponent = exponent_value;
    for (0..8) |_| {
        if (exponent & 1 != 0) result = multiply(result, base);
        base = multiply(base, base);
        exponent >>= 1;
    }
    return result;
}

fn multiply(left_value: u8, right_value: u8) u8 {
    var left = left_value;
    var right = right_value;
    var result: u8 = 0;
    for (0..8) |_| {
        const selected: u8 = 0 -% (right & 1);
        result ^= left & selected;
        const high = left >> 7;
        left = (left << 1) ^ (0x1b & (0 -% high));
        right >>= 1;
    }
    return result;
}

test "AES-192 matches the FIPS-197 block vector" {
    const key = [key_len]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const input = [block_len]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const expected = [block_len]u8{
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };
    var context = EncryptContext.init(key);
    defer context.deinit();
    var output: [block_len]u8 = undefined;
    context.encrypt(&output, &input);
    try std.testing.expectEqualSlices(u8, &expected, &output);
}
