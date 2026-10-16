//! RAR 3.x/4.x AES-128-CBC cryptographic primitives.
//!
//! RAR converts UTF-8 application passwords to UTF-16LE, runs its historical
//! SHA-1 derivation for 0x40000 rounds, and derives both the AES key and IV.
//! Long passwords require reproducing RAR29's in-place SHA-1 message-block
//! transform; this module implements that compatibility behavior explicitly.
//! Archive flags, salt placement, padding, CRC policy, and volume composition
//! remain the archive layer's responsibility.

const std = @import("std");

const Aes = std.crypto.core.aes;
const Aes128EncryptContext = Aes.AesEncryptCtx(Aes.Aes128);
const Aes128DecryptContext = Aes.AesDecryptCtx(Aes.Aes128);

pub const block_len: usize = 16;
pub const salt_len: usize = 8;
pub const key_len: usize = 16;
pub const rounds: u32 = 0x40000;

pub const Error = std.mem.Allocator.Error || error{
    InvalidBlockLength,
    InvalidRar4Password,
    IntegerOverflow,
};

pub const Keys = struct {
    encryption: [key_len]u8,
    iv: [block_len]u8,

    pub fn deinit(self: *Keys) void {
        std.crypto.secureZero(Keys, self[0..1]);
        self.* = undefined;
    }
};

pub fn deriveKeys(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: ?[salt_len]u8,
) Error!Keys {
    const utf16 = std.unicode.utf8ToUtf16LeAlloc(allocator, password) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUtf8 => return error.InvalidRar4Password,
    };
    defer {
        std.crypto.secureZero(u16, utf16);
        allocator.free(utf16);
    }
    const password_bytes = std.mem.sliceAsBytes(utf16);
    const raw_len = std.math.add(
        usize,
        password_bytes.len,
        if (salt == null) 0 else salt_len,
    ) catch return error.IntegerOverflow;
    const raw = try allocator.alloc(u8, raw_len);
    defer {
        std.crypto.secureZero(u8, raw);
        allocator.free(raw);
    }
    @memcpy(raw[0..password_bytes.len], password_bytes);
    if (salt) |value| @memcpy(raw[password_bytes.len..], &value);

    var hash = RarSha1.init();
    defer hash.deinit();
    var iv: [block_len]u8 = undefined;
    var counter: [3]u8 = undefined;
    var iteration: u32 = 0;
    while (iteration < rounds) : (iteration += 1) {
        hash.updateRar29(raw);
        counter = .{
            @truncate(iteration),
            @truncate(iteration >> 8),
            @truncate(iteration >> 16),
        };
        hash.update(&counter);
        if (iteration % (rounds / block_len) == 0) {
            const digest = hash.digest();
            iv[iteration / (rounds / block_len)] = digest[19];
        }
    }
    const digest = hash.digest();
    var key: [key_len]u8 = undefined;
    for (0..4) |word| {
        for (0..4) |byte| {
            key[word * 4 + byte] = digest[word * 4 + 3 - byte];
        }
    }
    return .{ .encryption = key, .iv = iv };
}

pub const Encryptor = struct {
    cipher: Aes128EncryptContext,
    previous: [block_len]u8,

    pub fn init(key: [key_len]u8, iv: [block_len]u8) Encryptor {
        return .{ .cipher = Aes.Aes128.initEnc(key), .previous = iv };
    }

    pub fn encryptBlocks(self: *Encryptor, input: []const u8, output: []u8) Error!void {
        if (input.len != output.len or input.len % block_len != 0)
            return error.InvalidBlockLength;
        var offset: usize = 0;
        while (offset < input.len) : (offset += block_len) {
            var block = input[offset..][0..block_len].*;
            defer std.crypto.secureZero(u8, &block);
            for (&block, self.previous) |*byte, previous| byte.* ^= previous;
            self.cipher.encrypt(output[offset..][0..block_len], &block);
            self.previous = output[offset..][0..block_len].*;
        }
    }

    pub fn deinit(self: *Encryptor) void {
        std.crypto.secureZero(Aes128EncryptContext, (&self.cipher)[0..1]);
        std.crypto.secureZero(u8, &self.previous);
        self.* = undefined;
    }
};

pub const Decryptor = struct {
    cipher: Aes128DecryptContext,
    previous: [block_len]u8,

    pub fn init(key: [key_len]u8, iv: [block_len]u8) Decryptor {
        return .{ .cipher = Aes.Aes128.initDec(key), .previous = iv };
    }

    pub fn decryptBlocks(self: *Decryptor, input: []const u8, output: []u8) Error!void {
        if (input.len != output.len or input.len % block_len != 0)
            return error.InvalidBlockLength;
        var offset: usize = 0;
        while (offset < input.len) : (offset += block_len) {
            const ciphertext = input[offset..][0..block_len].*;
            var block: [block_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &block);
            self.cipher.decrypt(&block, &ciphertext);
            for (&block, self.previous) |*byte, previous| byte.* ^= previous;
            output[offset..][0..block_len].* = block;
            self.previous = ciphertext;
        }
    }

    pub fn deinit(self: *Decryptor) void {
        std.crypto.secureZero(Aes128DecryptContext, (&self.cipher)[0..1]);
        std.crypto.secureZero(u8, &self.previous);
        self.* = undefined;
    }
};

const RarSha1 = struct {
    state: [5]u32,
    buffer: [64]u8 = undefined,
    buffer_len: usize = 0,
    total_len: u64 = 0,

    fn init() RarSha1 {
        return .{ .state = .{
            0x6745_2301,
            0xefcd_ab89,
            0x98ba_dcfe,
            0x1032_5476,
            0xc3d2_e1f0,
        } };
    }

    fn update(self: *RarSha1, input: []const u8) void {
        self.updateInternal(input, null);
    }

    fn updateRar29(self: *RarSha1, input: []u8) void {
        self.updateInternal(input, input);
    }

    fn updateInternal(
        self: *RarSha1,
        input: []const u8,
        mutable: ?[]u8,
    ) void {
        var offset: usize = 0;
        if (self.buffer_len != 0 and self.buffer_len + input.len >= 64) {
            const take = 64 - self.buffer_len;
            @memcpy(self.buffer[self.buffer_len..][0..take], input[0..take]);
            self.transform(&self.buffer, null);
            self.buffer_len = 0;
            offset = take;
        }
        while (offset + 64 <= input.len) : (offset += 64) {
            const mutable_block = if (mutable) |bytes| bytes[offset..][0..64] else null;
            self.transform(input[offset..][0..64], mutable_block);
        }
        @memcpy(self.buffer[self.buffer_len..][0 .. input.len - offset], input[offset..]);
        self.buffer_len += input.len - offset;
        self.total_len +%= input.len;
    }

    fn digest(self: RarSha1) [20]u8 {
        var copy = self;
        defer copy.deinit();
        const bit_len = copy.total_len *% 8;
        const padding_len: usize = if (copy.buffer_len < 56)
            56 - copy.buffer_len
        else
            64 + 56 - copy.buffer_len;
        var padding: [128]u8 = @splat(0);
        padding[0] = 0x80;
        std.mem.writeInt(u64, padding[padding_len..][0..8], bit_len, .big);
        copy.update(padding[0 .. padding_len + 8]);
        var result: [20]u8 = undefined;
        for (copy.state, 0..) |word, index|
            std.mem.writeInt(u32, result[index * 4 ..][0..4], word, .big);
        return result;
    }

    fn transform(
        self: *RarSha1,
        input: *const [64]u8,
        mutated: ?*[64]u8,
    ) void {
        var schedule: [16]u32 = undefined;
        for (0..16) |index|
            schedule[index] = std.mem.readInt(u32, input[index * 4 ..][0..4], .big);
        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        for (0..80) |index| {
            const word = if (index < 16)
                schedule[index]
            else blk: {
                const value = std.math.rotl(
                    u32,
                    schedule[(index - 3) & 15] ^ schedule[(index - 8) & 15] ^
                        schedule[(index - 14) & 15] ^ schedule[index & 15],
                    1,
                );
                schedule[index & 15] = value;
                break :blk value;
            };
            const f: u32, const constant: u32 = switch (index) {
                0...19 => .{ (b & c) | (~b & d), 0x5a82_7999 },
                20...39 => .{ b ^ c ^ d, 0x6ed9_eba1 },
                40...59 => .{ (b & c) | (b & d) | (c & d), 0x8f1b_bcdc },
                else => .{ b ^ c ^ d, 0xca62_c1d6 },
            };
            const temporary = std.math.rotl(u32, a, 5) +% f +% e +% constant +% word;
            e = d;
            d = c;
            c = std.math.rotl(u32, b, 30);
            b = a;
            a = temporary;
        }
        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
        if (mutated) |block|
            for (schedule, 0..) |word, index|
                std.mem.writeInt(u32, block[index * 4 ..][0..4], word, .little);
    }

    fn deinit(self: *RarSha1) void {
        std.crypto.secureZero(RarSha1, self[0..1]);
        self.* = undefined;
    }
};

test "RAR4 KDF matches independent SHA-1 vectors" {
    var keys = try deriveKeys(
        std.testing.allocator,
        "RAR4 密码",
        .{ 0, 1, 2, 3, 4, 5, 6, 7 },
    );
    defer keys.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x71, 0x2a, 0x6b, 0xc8, 0x3b, 0x40, 0x6a, 0xd2, 0x7f, 0xbe, 0x54, 0x83, 0xfb, 0x34, 0xa5, 0x5e },
        &keys.encryption,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x7e, 0xc9, 0xc0, 0xca, 0x42, 0xd4, 0x9a, 0x8b, 0xf3, 0x93, 0x77, 0xdf, 0x63, 0x84, 0x8a, 0xf2 },
        &keys.iv,
    );
}

test "RAR4 AES-128-CBC matches OpenSSL and decrypts in place" {
    const key = [_]u8{ 0x71, 0x2a, 0x6b, 0xc8, 0x3b, 0x40, 0x6a, 0xd2, 0x7f, 0xbe, 0x54, 0x83, 0xfb, 0x34, 0xa5, 0x5e };
    const iv = [_]u8{ 0x7e, 0xc9, 0xc0, 0xca, 0x42, 0xd4, 0x9a, 0x8b, 0xf3, 0x93, 0x77, 0xdf, 0x63, 0x84, 0x8a, 0xf2 };
    const plaintext = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    };
    const expected = [_]u8{ 0xbc, 0xb8, 0x44, 0xee, 0xfd, 0x99, 0xb7, 0x6d, 0x76, 0x91, 0xe6, 0xaa, 0xd4, 0x6d, 0xa0, 0xc9, 0x29, 0xd8, 0x22, 0xde, 0x36, 0x40, 0x94, 0x9c, 0x40, 0x13, 0x8f, 0x4a, 0x3e, 0x33, 0xfb, 0x22 };
    var encrypted: [plaintext.len]u8 = undefined;
    var encryptor = Encryptor.init(key, iv);
    defer encryptor.deinit();
    try encryptor.encryptBlocks(&plaintext, &encrypted);
    try std.testing.expectEqualSlices(u8, &expected, &encrypted);
    var decryptor = Decryptor.init(key, iv);
    defer decryptor.deinit();
    try decryptor.decryptBlocks(&encrypted, &encrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &encrypted);
}

test "RAR4 rejects invalid UTF-8 and partial AES blocks" {
    try std.testing.expectError(
        error.InvalidRar4Password,
        deriveKeys(std.testing.allocator, &.{0xff}, null),
    );
    var encryptor = Encryptor.init([_]u8{0} ** key_len, [_]u8{0} ** block_len);
    defer encryptor.deinit();
    var output: [1]u8 = undefined;
    try std.testing.expectError(error.InvalidBlockLength, encryptor.encryptBlocks(&.{0}, &output));
}
