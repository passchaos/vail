//! AES block ciphers for 128-, 192-, and 256-bit keys.
//!
//! Zig's standard library exposes optimized 128- and 256-bit contexts but no
//! 192-bit context. This module re-exports the standard contexts for 128/256
//! and supplies a FIPS-197 192-bit key schedule on top of the standard,
//! side-channel-hardened `Block` round primitive.

const std = @import("std");

pub const block_length = 16;

/// AES with a `key_bits`-bit key. 128 and 256 delegate to the standard
/// library; 192 uses the in-tree FIPS-197 schedule.
pub fn Aes(comptime key_bits: usize) type {
    return switch (key_bits) {
        128 => std.crypto.core.aes.Aes128,
        192 => Aes192,
        256 => std.crypto.core.aes.Aes256,
        else => @compileError("AES key size must be 128, 192, or 256 bits"),
    };
}

pub const Aes128 = Aes(128);
pub const Aes256 = Aes(256);

pub const Aes192 = struct {
    pub const key_bits = 192;
    pub const rounds = 12;

    const Block = std.crypto.core.aes.Block;
    const RoundKeys = [rounds + 1]Block;

    pub const EncryptContext = struct {
        round_keys: RoundKeys,

        pub fn encrypt(
            self: EncryptContext,
            destination: *[block_length]u8,
            source: *const [block_length]u8,
        ) void {
            var block = Block.fromBytes(source).xorBlocks(self.round_keys[0]);
            for (self.round_keys[1..rounds]) |round_key| {
                block = block.encrypt(round_key);
            }
            destination.* = block.encryptLast(self.round_keys[rounds]).toBytes();
        }
    };

    pub const DecryptContext = struct {
        round_keys: RoundKeys,

        pub fn decrypt(
            self: DecryptContext,
            destination: *[block_length]u8,
            source: *const [block_length]u8,
        ) void {
            var block = Block.fromBytes(source).xorBlocks(self.round_keys[0]);
            for (self.round_keys[1..rounds]) |round_key| {
                block = block.decrypt(round_key);
            }
            destination.* = block.decryptLast(self.round_keys[rounds]).toBytes();
        }
    };

    pub fn initEnc(key: [key_bits / 8]u8) EncryptContext {
        return .{ .round_keys = expandKey(key) };
    }

    pub fn initDec(key: [key_bits / 8]u8) DecryptContext {
        const encryption_keys = expandKey(key);
        var decryption_keys: RoundKeys = undefined;
        decryption_keys[0] = encryption_keys[rounds];
        for (1..rounds) |index| {
            decryption_keys[index] = encryption_keys[rounds - index].invMixColumns();
        }
        decryption_keys[rounds] = encryption_keys[0];
        return .{ .round_keys = decryption_keys };
    }

    fn expandKey(key: [key_bits / 8]u8) RoundKeys {
        const word_count = (rounds + 1) * 4;
        var words: [word_count]u32 = undefined;
        for (0..6) |index| {
            words[index] = std.mem.readInt(u32, key[index * 4 ..][0..4], .big);
        }
        for (6..word_count) |index| {
            var temporary = words[index - 1];
            if (index % 6 == 0) {
                temporary = subWord(std.math.rotl(u32, temporary, 8)) ^
                    (@as(u32, roundConstant(index / 6)) << 24);
            }
            words[index] = words[index - 6] ^ temporary;
        }

        var round_keys: RoundKeys = undefined;
        for (&round_keys, 0..) |*round_key, round| {
            var bytes: [block_length]u8 = undefined;
            for (0..4) |column| {
                std.mem.writeInt(
                    u32,
                    bytes[column * 4 ..][0..4],
                    words[round * 4 + column],
                    .big,
                );
            }
            round_key.* = Block.fromBytes(&bytes);
        }
        std.crypto.secureZero(u32, &words);
        return round_keys;
    }

    fn subWord(word: u32) u32 {
        return (@as(u32, subByte(@truncate(word >> 24))) << 24) |
            (@as(u32, subByte(@truncate(word >> 16))) << 16) |
            (@as(u32, subByte(@truncate(word >> 8))) << 8) |
            subByte(@truncate(word));
    }

    fn subByte(byte: u8) u8 {
        // FIPS-197 multiplicative inverse followed by the affine transform.
        // The exponent and loop count are fixed, avoiding a secret-indexed
        // S-box.
        var inverse: u8 = 1;
        var base = byte;
        var exponent: u8 = 254;
        for (0..8) |_| {
            const product = gfMultiply(inverse, base);
            const mask: u8 = 0 -% (exponent & 1);
            inverse = (inverse & ~mask) | (product & mask);
            base = gfMultiply(base, base);
            exponent >>= 1;
        }
        return inverse ^ std.math.rotl(u8, inverse, 1) ^
            std.math.rotl(u8, inverse, 2) ^ std.math.rotl(u8, inverse, 3) ^
            std.math.rotl(u8, inverse, 4) ^ 0x63;
    }

    fn gfMultiply(left: u8, right: u8) u8 {
        var a = left;
        var b = right;
        var result: u8 = 0;
        for (0..8) |_| {
            result ^= a & (0 -% (b & 1));
            const high_mask: u8 = 0 -% (a >> 7);
            a = (a << 1) ^ (0x1b & high_mask);
            b >>= 1;
        }
        return result;
    }

    fn roundConstant(index: usize) u8 {
        var value: u8 = 1;
        for (1..index) |_| value = gfMultiply(value, 2);
        return value;
    }
};

test "AES-192 matches FIPS-197 appendix C.2" {
    // FIPS-197 C.2: key 000102...17, plaintext 00112233...ff.
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const plaintext = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const expected = [_]u8{
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };
    var ciphertext: [block_length]u8 = undefined;
    Aes192.initEnc(key).encrypt(&ciphertext, &plaintext);
    try std.testing.expectEqual(expected, ciphertext);
    var roundtrip: [block_length]u8 = undefined;
    Aes192.initDec(key).decrypt(&roundtrip, &ciphertext);
    try std.testing.expectEqual(plaintext, roundtrip);
}

test "AES-192 round trips every single-byte input" {
    const key = [_]u8{0x5a} ** 24;
    const encrypt_context = Aes192.initEnc(key);
    const decrypt_context = Aes192.initDec(key);
    for (0..256) |value| {
        const plaintext = [_]u8{@intCast(value)} ** block_length;
        var ciphertext: [block_length]u8 = undefined;
        encrypt_context.encrypt(&ciphertext, &plaintext);
        var roundtrip: [block_length]u8 = undefined;
        decrypt_context.decrypt(&roundtrip, &ciphertext);
        try std.testing.expectEqual(plaintext, roundtrip);
    }
}
