//! RAR 1.5 and RAR 2.0/2.6 password ciphers.
//!
//! These historical ciphers operate on the password bytes used by the old
//! RAR tools. They do not provide salts, authentication, or a password check;
//! the archive layer must validate decrypted data with the member CRC. Both
//! contexts are stateful and must be initialized separately for every member.

const std = @import("std");

pub const block_len: usize = 16;
pub const max_password_len: usize = 127;

pub const Error = error{
    InvalidBlockLength,
};

const crc_table = blk: {
    @setEvalBranchQuota(4096);
    break :blk makeCrcTable();
};

/// Symmetric byte-stream cipher used by RAR 1.5 members (`UNP_VER = 15`).
pub const Rar15 = struct {
    keys: [4]u16,

    pub fn init(raw_password: []const u8) Rar15 {
        const password = normalizedPassword(raw_password);
        var crc: u32 = 0xffff_ffff;
        for (password) |byte|
            crc = crc_table[@as(u8, @truncate(crc)) ^ byte] ^ (crc >> 8);

        var keys: [4]u16 = .{
            @truncate(crc),
            @truncate(crc >> 16),
            0,
            0,
        };
        for (password) |byte| {
            keys[2] = @truncate(@as(u32, keys[2]) ^ byte ^ crc_table[byte]);
            keys[3] +%= @truncate(@as(u32, byte) + (crc_table[byte] >> 16));
        }
        return .{ .keys = keys };
    }

    /// Encrypts or decrypts bytes in place. RAR15 uses the same operation in
    /// both directions and advances the context by `bytes.len` bytes.
    pub fn crypt(self: *Rar15, bytes: []u8) void {
        for (bytes) |*byte| {
            self.keys[0] +%= 0x1234;
            const table_index: u8 = @truncate((self.keys[0] & 0x01fe) >> 1);
            self.keys[1] ^= @truncate(crc_table[table_index]);
            self.keys[2] -%= @truncate(crc_table[table_index] >> 16);
            self.keys[0] ^= self.keys[2];
            self.keys[3] = std.math.rotr(u16, self.keys[3], 1) ^ self.keys[1];
            self.keys[3] = std.math.rotr(u16, self.keys[3], 1);
            self.keys[0] ^= self.keys[3];
            byte.* ^= @truncate(self.keys[0] >> 8);
        }
    }

    pub fn deinit(self: *Rar15) void {
        std.crypto.secureZero(Rar15, self[0..1]);
        self.* = undefined;
    }
};

/// Stateful 128-bit cipher used by RAR 2.0 and RAR 2.6 members.
pub const Rar20 = struct {
    substitution: [256]u8,
    keys: [4]u32,

    pub fn init(raw_password: []const u8) Rar20 {
        const password = normalizedPassword(raw_password);
        var self = Rar20{
            .substitution = initial_substitution,
            .keys = .{ 0xd3a3_b879, 0x3f6d_12f7, 0x7515_a235, 0xa4e7_f123 },
        };
        var padded: [128]u8 = @splat(0);
        defer std.crypto.secureZero(u8, &padded);
        @memcpy(padded[0..password.len], password);

        for (0..256) |round| {
            var index: usize = 0;
            while (index < password.len) : (index += 2) {
                var first: u8 = @truncate(crc_table[padded[index] -% @as(u8, @truncate(round))]);
                const second: u8 = @truncate(crc_table[padded[index + 1] +% @as(u8, @truncate(round))]);
                var distance: usize = 1;
                while (first != second) : ({
                    first +%= 1;
                    distance += 1;
                }) {
                    const other = (@as(usize, first) + index + distance) & 0xff;
                    std.mem.swap(u8, &self.substitution[first], &self.substitution[other]);
                }
            }
        }

        var offset: usize = 0;
        while (offset < password.len) : (offset += block_len)
            self.encryptBlock(padded[offset..][0..block_len]);
        return self;
    }

    pub fn encryptBlocks(self: *Rar20, bytes: []u8) Error!void {
        if (bytes.len % block_len != 0) return error.InvalidBlockLength;
        var offset: usize = 0;
        while (offset < bytes.len) : (offset += block_len)
            self.encryptBlock(bytes[offset..][0..block_len]);
    }

    pub fn decryptBlocks(self: *Rar20, bytes: []u8) Error!void {
        if (bytes.len % block_len != 0) return error.InvalidBlockLength;
        var offset: usize = 0;
        while (offset < bytes.len) : (offset += block_len)
            self.decryptBlock(bytes[offset..][0..block_len]);
    }

    pub fn deinit(self: *Rar20) void {
        std.crypto.secureZero(Rar20, self[0..1]);
        self.* = undefined;
    }

    fn encryptBlock(self: *Rar20, block: *[block_len]u8) void {
        var a = std.mem.readInt(u32, block[0..4], .little) ^ self.keys[0];
        var b = std.mem.readInt(u32, block[4..8], .little) ^ self.keys[1];
        var c = std.mem.readInt(u32, block[8..12], .little) ^ self.keys[2];
        var d = std.mem.readInt(u32, block[12..16], .little) ^ self.keys[3];
        for (0..32) |round| {
            const key = self.keys[round & 3];
            const next_c = a ^ self.substitute((c +% std.math.rotl(u32, d, 11)) ^ key);
            const next_d = b ^ self.substitute((d ^ std.math.rotl(u32, c, 17)) +% key);
            a = c;
            b = d;
            c = next_c;
            d = next_d;
        }
        std.mem.writeInt(u32, block[0..4], c ^ self.keys[0], .little);
        std.mem.writeInt(u32, block[4..8], d ^ self.keys[1], .little);
        std.mem.writeInt(u32, block[8..12], a ^ self.keys[2], .little);
        std.mem.writeInt(u32, block[12..16], b ^ self.keys[3], .little);
        self.updateKeys(block);
    }

    fn decryptBlock(self: *Rar20, block: *[block_len]u8) void {
        const ciphertext = block.*;
        var a = std.mem.readInt(u32, block[0..4], .little) ^ self.keys[0];
        var b = std.mem.readInt(u32, block[4..8], .little) ^ self.keys[1];
        var c = std.mem.readInt(u32, block[8..12], .little) ^ self.keys[2];
        var d = std.mem.readInt(u32, block[12..16], .little) ^ self.keys[3];
        var round: usize = 32;
        while (round != 0) {
            round -= 1;
            const key = self.keys[round & 3];
            const next_c = a ^ self.substitute((c +% std.math.rotl(u32, d, 11)) ^ key);
            const next_d = b ^ self.substitute((d ^ std.math.rotl(u32, c, 17)) +% key);
            a = c;
            b = d;
            c = next_c;
            d = next_d;
        }
        std.mem.writeInt(u32, block[0..4], c ^ self.keys[0], .little);
        std.mem.writeInt(u32, block[4..8], d ^ self.keys[1], .little);
        std.mem.writeInt(u32, block[8..12], a ^ self.keys[2], .little);
        std.mem.writeInt(u32, block[12..16], b ^ self.keys[3], .little);
        self.updateKeys(&ciphertext);
    }

    fn substitute(self: *const Rar20, value: u32) u32 {
        return @as(u32, self.substitution[@as(u8, @truncate(value))]) |
            (@as(u32, self.substitution[@as(u8, @truncate(value >> 8))]) << 8) |
            (@as(u32, self.substitution[@as(u8, @truncate(value >> 16))]) << 16) |
            (@as(u32, self.substitution[@as(u8, @truncate(value >> 24))]) << 24);
    }

    fn updateKeys(self: *Rar20, block: *const [block_len]u8) void {
        for (0..4) |index|
            self.keys[index] ^= crc_table[block[index]] ^
                crc_table[block[index + 4]] ^
                crc_table[block[index + 8]] ^
                crc_table[block[index + 12]];
    }
};

fn normalizedPassword(password: []const u8) []const u8 {
    const nul = std.mem.indexOfScalar(u8, password, 0) orelse password.len;
    return password[0..@min(nul, max_password_len)];
}

fn makeCrcTable() [256]u32 {
    var table: [256]u32 = undefined;
    for (&table, 0..) |*entry, index| {
        var value: u32 = @intCast(index);
        for (0..8) |_| value = if (value & 1 != 0)
            (value >> 1) ^ 0xedb8_8320
        else
            value >> 1;
        entry.* = value;
    }
    return table;
}

const initial_substitution = [256]u8{
    215, 19,  149, 35,  73,  197, 192, 205, 249, 28,  16,  119, 48,  221, 2,   42,
    232, 1,   177, 233, 14,  88,  219, 25,  223, 195, 244, 90,  87,  239, 153, 137,
    255, 199, 147, 70,  92,  66,  246, 13,  216, 40,  62,  29,  217, 230, 86,  6,
    71,  24,  171, 196, 101, 113, 218, 123, 93,  91,  163, 178, 202, 67,  44,  235,
    107, 250, 75,  234, 49,  167, 125, 211, 83,  114, 157, 144, 32,  193, 143, 36,
    158, 124, 247, 187, 89,  214, 141, 47,  121, 228, 61,  130, 213, 194, 174, 251,
    97,  110, 54,  229, 115, 57,  152, 94,  105, 243, 212, 55,  209, 245, 63,  11,
    164, 200, 31,  156, 81,  176, 227, 21,  76,  99,  139, 188, 127, 17,  248, 51,
    207, 120, 189, 210, 8,   226, 41,  72,  183, 203, 135, 165, 166, 60,  98,  7,
    122, 38,  155, 170, 69,  172, 252, 238, 39,  134, 59,  128, 236, 27,  240, 80,
    131, 3,   85,  206, 145, 79,  154, 142, 159, 220, 201, 133, 74,  64,  20,  129,
    224, 185, 138, 103, 173, 182, 43,  34,  254, 82,  198, 151, 231, 180, 58,  10,
    118, 26,  102, 12,  50,  132, 22,  191, 136, 111, 162, 179, 45,  4,   148, 108,
    161, 56,  78,  126, 242, 222, 15,  175, 146, 23,  33,  241, 181, 190, 77,  225,
    0,   46,  169, 186, 68,  95,  237, 65,  53,  208, 253, 168, 9,   18,  100, 52,
    116, 184, 160, 96,  109, 37,  30,  106, 140, 104, 150, 5,   204, 117, 112, 84,
};

test "RAR15 cipher matches a fixed legacy vector and is symmetric" {
    var data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const clear = data;
    var encryptor = Rar15.init("password");
    defer encryptor.deinit();
    encryptor.crypt(&data);
    try std.testing.expectEqualSlices(u8, &.{
        0x43, 0xdd, 0x9d, 0xf3, 0x2a, 0x83, 0xdb, 0x8f,
        0x60, 0x1f, 0x15, 0xab, 0xe1, 0xad, 0x5d, 0x11,
    }, &data);
    var decryptor = Rar15.init("password");
    defer decryptor.deinit();
    decryptor.crypt(&data);
    try std.testing.expectEqualSlices(u8, &clear, &data);
}

test "RAR20 cipher matches a fixed legacy vector and round trips blocks" {
    var data = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    };
    const clear = data;
    var encryptor = Rar20.init("password");
    defer encryptor.deinit();
    try encryptor.encryptBlocks(&data);
    try std.testing.expectEqualSlices(u8, &.{
        0x84, 0x0c, 0x88, 0x90, 0x05, 0x93, 0x3a, 0x4e,
        0x0d, 0xa7, 0xf0, 0x86, 0x87, 0x5a, 0xd8, 0x28,
        0x89, 0x3c, 0x90, 0x98, 0x32, 0x1b, 0xc2, 0xda,
        0x8e, 0x0c, 0x6d, 0x08, 0x38, 0x57, 0xfa, 0x14,
    }, &data);
    var decryptor = Rar20.init("password");
    defer decryptor.deinit();
    try decryptor.decryptBlocks(&data);
    try std.testing.expectEqualSlices(u8, &clear, &data);
}

test "legacy RAR ciphers truncate old C-string passwords and reject partial blocks" {
    var first = Rar15.init("password\x00ignored");
    defer first.deinit();
    var second = Rar15.init("password");
    defer second.deinit();
    var a = [_]u8{0} ** 8;
    var b = a;
    first.crypt(&a);
    second.crypt(&b);
    try std.testing.expectEqualSlices(u8, &a, &b);

    const long_password = [_]u8{'x'} ** 130;
    const truncated_password = [_]u8{'x'} ** max_password_len;
    var long_rar15 = Rar15.init(&long_password);
    defer long_rar15.deinit();
    var truncated_rar15 = Rar15.init(&truncated_password);
    defer truncated_rar15.deinit();
    a = @splat(0);
    b = @splat(0);
    long_rar15.crypt(&a);
    truncated_rar15.crypt(&b);
    try std.testing.expectEqualSlices(u8, &a, &b);

    var long_rar20 = Rar20.init(&long_password);
    defer long_rar20.deinit();
    var truncated_rar20 = Rar20.init(&truncated_password);
    defer truncated_rar20.deinit();
    var long_block = [_]u8{0} ** block_len;
    var truncated_block = long_block;
    try long_rar20.encryptBlocks(&long_block);
    try truncated_rar20.encryptBlocks(&truncated_block);
    try std.testing.expectEqualSlices(u8, &long_block, &truncated_block);

    var rar20 = Rar20.init("password");
    defer rar20.deinit();
    var partial: [15]u8 = undefined;
    try std.testing.expectError(error.InvalidBlockLength, rar20.decryptBlocks(&partial));
}
