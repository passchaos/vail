//! SM3 hash function (GB/T 32905-2016).
//!
//! Vail keeps this small implementation in Zig so TLS/GMSSL-facing code can
//! depend on a stable Hash-compatible type without an external provider.

const std = @import("std");

pub const Hash = struct {
    const Self = @This();

    pub const block_length = 64;
    pub const digest_length = 32;
    pub const Options = struct {};

    s: [8]u32,
    buf: [block_length]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init(options: Options) Self {
        _ = options;
        return .{ .s = iv };
    }

    pub fn hash(bytes: []const u8, out: *[digest_length]u8, options: Options) void {
        var state = Self.init(options);
        state.update(bytes);
        state.final(out);
    }

    pub fn update(self: *Self, bytes: []const u8) void {
        var offset: usize = 0;

        if (self.buf_len != 0) {
            const buffered: usize = self.buf_len;
            const needed = block_length - buffered;
            const take = @min(needed, bytes.len);
            @memcpy(self.buf[buffered..][0..take], bytes[0..take]);
            self.buf_len = @intCast(buffered + take);
            offset += take;
            if (self.buf_len != block_length) {
                self.total_len +%= bytes.len;
                return;
            }
            if (self.buf_len == block_length) {
                self.round(&self.buf);
                self.buf_len = 0;
            }
        }

        while (offset + block_length <= bytes.len) : (offset += block_length) {
            self.round(bytes[offset..][0..block_length]);
        }

        const rest = bytes[offset..];
        @memcpy(self.buf[0..rest.len], rest);
        self.buf_len = @intCast(rest.len);
        self.total_len +%= bytes.len;
    }

    pub fn peek(self: Self) [digest_length]u8 {
        var copy = self;
        return copy.finalResult();
    }

    pub fn final(self: *Self, out: *[digest_length]u8) void {
        const buffered: usize = self.buf_len;
        @memset(self.buf[buffered..], 0);
        self.buf[buffered] = 0x80;
        self.buf_len += 1;

        if (block_length - @as(usize, self.buf_len) < 8) {
            self.round(&self.buf);
            @memset(&self.buf, 0);
        }

        std.mem.writeInt(u64, self.buf[56..64], self.total_len *% 8, .big);
        self.round(&self.buf);

        for (self.s, 0..) |word, index| {
            std.mem.writeInt(u32, out[index * 4 ..][0..4], word, .big);
        }
    }

    pub fn finalResult(self: *Self) [digest_length]u8 {
        var output: [digest_length]u8 = undefined;
        self.final(&output);
        return output;
    }

    fn round(self: *Self, block: *const [block_length]u8) void {
        var w: [68]u32 = undefined;
        var w1: [64]u32 = undefined;

        for (0..16) |index| {
            w[index] = std.mem.readInt(
                u32,
                block[index * 4 ..][0..4],
                .big,
            );
        }
        for (16..68) |index| {
            w[index] = p1(
                w[index - 16] ^ w[index - 9] ^
                    rotl(w[index - 3], 15),
            ) ^ rotl(w[index - 13], 7) ^ w[index - 6];
        }
        for (0..64) |index| {
            w1[index] = w[index] ^ w[index + 4];
        }

        var a = self.s[0];
        var b = self.s[1];
        var c = self.s[2];
        var d = self.s[3];
        var e = self.s[4];
        var f = self.s[5];
        var g = self.s[6];
        var h = self.s[7];

        for (0..64) |index| {
            // The standard defines T_j rotated by j, where j is taken modulo
            // the 32-bit word size.  Keeping that rotation explicit avoids a
            // separate table and mirrors the compression-function equation.
            const tj = if (index <= 15) @as(u32, 0x79cc4519) else 0x7a879d8a;
            const ss1 = rotl(rotl(a, 12) +% e +% rotl(tj, index), 7);
            const ss2 = ss1 ^ rotl(a, 12);
            const tt1 = ff(index, a, b, c) +% d +% ss2 +% w1[index];
            const tt2 = gg(index, e, f, g) +% h +% ss1 +% w[index];
            d = c;
            c = rotl(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rotl(f, 19);
            f = e;
            e = p0(tt2);
        }

        self.s[0] ^= a;
        self.s[1] ^= b;
        self.s[2] ^= c;
        self.s[3] ^= d;
        self.s[4] ^= e;
        self.s[5] ^= f;
        self.s[6] ^= g;
        self.s[7] ^= h;
    }
};

pub const digest_len = Hash.digest_length;
pub const Digest = [digest_len]u8;
pub const Hmac = std.crypto.auth.hmac.Hmac(Hash);

pub fn hash(bytes: []const u8) Digest {
    var output: Digest = undefined;
    Hash.hash(bytes, &output, .{});
    return output;
}

pub fn eql(expected: Digest, received: Digest) bool {
    return std.crypto.timing_safe.eql(Digest, expected, received);
}

const iv = [8]u32{
    0x7380166f,
    0x4914b2b9,
    0x172442d7,
    0xda8a0600,
    0xa96f30bc,
    0x163138aa,
    0xe38dee4d,
    0xb0fb0e4e,
};

fn rotl(value: u32, amount: anytype) u32 {
    return std.math.rotl(u32, value, amount);
}

fn p0(x: u32) u32 {
    return x ^ rotl(x, 9) ^ rotl(x, 17);
}

fn p1(x: u32) u32 {
    return x ^ rotl(x, 15) ^ rotl(x, 23);
}

fn ff(index: usize, x: u32, y: u32, z: u32) u32 {
    return if (index <= 15)
        x ^ y ^ z
    else
        (x & y) | (x & z) | (y & z);
}

fn gg(index: usize, x: u32, y: u32, z: u32) u32 {
    return if (index <= 15)
        x ^ y ^ z
    else
        (x & y) | (~x & z);
}

fn expectDigest(comptime message: []const u8, comptime expected_hex: []const u8) !void {
    const actual = hash(message);
    var expected: Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "SM3 one-shot vectors" {
    try expectDigest(
        "",
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
    );
    try expectDigest(
        "abc",
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    );
    try expectDigest(
        "abcd" ** 16,
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    );
}

test "SM3 streaming and constant-time equality helpers" {
    var streaming = Hash.init(.{});
    streaming.update("a");
    streaming.update("bc");
    const digest = streaming.finalResult();
    const one_shot = hash("abc");
    try std.testing.expect(eql(one_shot, digest));
    var wrong = digest;
    wrong[0] ^= 1;
    try std.testing.expect(!eql(one_shot, wrong));
}

test "HMAC-SM3 is available through Zig's generic HMAC API" {
    var tag: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&tag, "abc", "key");
    var expected: [Hmac.mac_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "28e63256e7c5a087b1f073265dc53092163f7b82729735d06f28f10af9d52393",
    );
    try std.testing.expectEqualSlices(u8, &expected, &tag);
}
