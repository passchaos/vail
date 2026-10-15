//! Traditional PKZIP encryption primitives.
//!
//! This legacy cipher provides compatibility only. It is unauthenticated and
//! must not be presented as modern confidentiality or integrity protection.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    TruncatedZipEncryptionHeader,
    InvalidZipPassword,
    IntegerOverflow,
};

pub const header_random_len: usize = 11;
pub const header_len: usize = 12;

/// Traditional PKZIP encryption inputs. The caller supplies header entropy
/// from its own CSPRNG; deterministic bytes are useful only for reproducible
/// fixtures and must not be reused for security-sensitive archives.
pub const Options = struct {
    password: []const u8,
    header_random: [header_random_len]u8,
};

/// Resumable Traditional PKZIP cipher state. Keys are updated with plaintext
/// for both encryption and decryption.
pub const Cipher = struct {
    key0: u32 = 0x1234_5678,
    key1: u32 = 0x2345_6789,
    key2: u32 = 0x3456_7890,

    const Self = @This();

    pub fn init(password: []const u8) Self {
        var cipher = Self{};
        for (password) |byte| cipher.update(byte);
        return cipher;
    }

    pub fn encryptByte(self: *Self, plain: u8) u8 {
        const encrypted = plain ^ self.streamByte();
        self.update(plain);
        return encrypted;
    }

    pub fn decryptByte(self: *Self, encrypted: u8) u8 {
        const plain = encrypted ^ self.streamByte();
        self.update(plain);
        return plain;
    }

    pub fn encrypt(self: *Self, input: []const u8, output: []u8) void {
        std.debug.assert(output.len >= input.len);
        for (input, output[0..input.len]) |byte, *encrypted|
            encrypted.* = self.encryptByte(byte);
    }

    pub fn decrypt(self: *Self, input: []const u8, output: []u8) void {
        std.debug.assert(output.len >= input.len);
        for (input, output[0..input.len]) |byte, *plain|
            plain.* = self.decryptByte(byte);
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(Self, (&self.*)[0..1]);
    }

    fn streamByte(self: *const Self) u8 {
        const temporary = self.key2 | 2;
        return @truncate((temporary *% (temporary ^ 1)) >> 8);
    }

    fn update(self: *Self, plain: u8) void {
        self.key0 = crc32Byte(self.key0, plain);
        self.key1 = (self.key1 +% (self.key0 & 0xff)) *% 134_775_813 +% 1;
        self.key2 = crc32Byte(self.key2, @truncate(self.key1 >> 24));
    }
};

pub fn encryptAlloc(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    options: Options,
    check_byte: u8,
) Error![]u8 {
    const output_len = std.math.add(usize, header_len, compressed.len) catch
        return error.IntegerOverflow;
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);
    var cipher = Cipher.init(options.password);
    defer cipher.deinit();
    cipher.encrypt(&options.header_random, output[0..header_random_len]);
    output[header_random_len] = cipher.encryptByte(check_byte);
    cipher.encrypt(compressed, output[header_len..]);
    return output;
}

pub fn decryptAlloc(
    allocator: std.mem.Allocator,
    encrypted: []const u8,
    password: []const u8,
    check_byte: u8,
) Error![]u8 {
    if (encrypted.len < header_len) return error.TruncatedZipEncryptionHeader;
    var cipher = Cipher.init(password);
    defer cipher.deinit();
    var header: [header_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &header);
    cipher.decrypt(encrypted[0..header_len], &header);
    if (header[header_random_len] != check_byte) return error.InvalidZipPassword;
    const output = try allocator.alloc(u8, encrypted.len - header_len);
    errdefer allocator.free(output);
    cipher.decrypt(encrypted[header_len..], output);
    return output;
}

fn crc32Byte(initial: u32, byte: u8) u32 {
    var crc = initial ^ byte;
    for (0..8) |_| {
        const mask: u32 = 0 -% (crc & 1);
        crc = (crc >> 1) ^ (0xedb8_8320 & mask);
    }
    return crc;
}

test "Traditional ZipCrypto round trips and rejects wrong passwords" {
    const allocator = std.testing.allocator;
    const options = Options{
        .password = "correct horse 密码",
        .header_random = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
    };
    const payload = "traditional PKZIP encrypted payload";
    const encrypted = try encryptAlloc(allocator, payload, options, 0xa5);
    defer allocator.free(encrypted);
    try std.testing.expectEqual(payload.len + header_len, encrypted.len);
    const decoded = try decryptAlloc(allocator, encrypted, options.password, 0xa5);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, payload, decoded);
    try std.testing.expectError(
        error.InvalidZipPassword,
        decryptAlloc(allocator, encrypted, "wrong", 0xa5),
    );
    try std.testing.expectError(
        error.TruncatedZipEncryptionHeader,
        decryptAlloc(allocator, encrypted[0 .. header_len - 1], options.password, 0xa5),
    );
}

test "Traditional ZipCrypto releases every allocation failure" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const options = Options{
                .password = "allocation-safe password",
                .header_random = .{ 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
            };
            const encrypted = try encryptAlloc(allocator, "allocation-safe payload", options, 0x42);
            defer allocator.free(encrypted);
            const decrypted = try decryptAlloc(allocator, encrypted, options.password, 0x42);
            defer allocator.free(decrypted);
            try std.testing.expectEqualSlices(u8, "allocation-safe payload", decrypted);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}
