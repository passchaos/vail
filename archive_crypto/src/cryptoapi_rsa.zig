//! Microsoft CryptoAPI PRIVATEKEYBLOB RSA-OAEP-SHA1 unwrapping.

const std = @import("std");

const max_modulus_bits = 4096;
const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;
const Sha1 = std.crypto.hash.Sha1;

pub const Error = error{
    InvalidPrivateKeyBlob,
    UnsupportedRsaSize,
    InvalidRsaCiphertext,
    InvalidOaepPadding,
    WrappedKeySizeMismatch,
    OutputTooSmall,
};

const private_blob_type: u8 = 0x07;
const current_blob_version: u8 = 0x02;
const calg_rsa_keyx: u32 = 0x0000_a400;
const rsa2_magic: u32 = 0x3241_5352;
const header_len: usize = 20;

const PrivateKey = struct {
    modulus: []const u8,
    private_exponent: []const u8,
};

pub fn unwrapOaepSha1(
    private_key_blob: []const u8,
    ciphertext: []const u8,
    output: []u8,
) Error!usize {
    const key = try parsePrivateKeyBlob(private_key_blob);
    if (ciphertext.len != key.modulus.len) return error.InvalidRsaCiphertext;
    var encoded_message: [max_modulus_bits / 8]u8 = undefined;
    const em = encoded_message[0..key.modulus.len];
    defer std.crypto.secureZero(u8, &encoded_message);
    var modulus = Modulus.fromBytes(key.modulus, .little) catch
        return error.InvalidPrivateKeyBlob;
    defer std.crypto.secureZero(Modulus, (&modulus)[0..1]);
    var encrypted = Fe.fromBytes(modulus, ciphertext, .big) catch
        return error.InvalidRsaCiphertext;
    defer std.crypto.secureZero(Fe, (&encrypted)[0..1]);
    var decrypted = modulus.powWithEncodedExponent(
        encrypted,
        key.private_exponent,
        .little,
    ) catch return error.InvalidPrivateKeyBlob;
    defer std.crypto.secureZero(Fe, (&decrypted)[0..1]);
    decrypted.toBytes(em, .big) catch return error.InvalidPrivateKeyBlob;
    return decodeOaepSha1(em, output);
}

pub fn unwrapEsdAes256Key(
    private_key_blob: []const u8,
    ciphertext: []const u8,
) Error![32]u8 {
    var key: [32]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &key);
    const written = try unwrapOaepSha1(private_key_blob, ciphertext, &key);
    if (written != key.len) return error.WrappedKeySizeMismatch;
    return key;
}

fn parsePrivateKeyBlob(bytes: []const u8) Error!PrivateKey {
    if (bytes.len < header_len or
        bytes[0] != private_blob_type or bytes[1] != current_blob_version or
        std.mem.readInt(u16, bytes[2..4], .little) != 0 or
        std.mem.readInt(u32, bytes[4..8], .little) != calg_rsa_keyx or
        std.mem.readInt(u32, bytes[8..12], .little) != rsa2_magic)
        return error.InvalidPrivateKeyBlob;
    const bit_len: usize = std.mem.readInt(u32, bytes[12..16], .little);
    const public_exponent = std.mem.readInt(u32, bytes[16..20], .little);
    if ((bit_len != 2048 and bit_len != 4096) or
        public_exponent < 3 or public_exponent & 1 == 0)
        return error.UnsupportedRsaSize;
    const modulus_len = bit_len / 8;
    const half_len = modulus_len / 2;
    const expected_len = std.math.add(
        usize,
        header_len + 2 * modulus_len,
        5 * half_len,
    ) catch return error.InvalidPrivateKeyBlob;
    if (bytes.len != expected_len) return error.InvalidPrivateKeyBlob;
    const modulus = bytes[header_len..][0..modulus_len];
    const private_offset = header_len + modulus_len + 5 * half_len;
    const private_exponent = bytes[private_offset..][0..modulus_len];
    var exponent_nonzero: u8 = 0;
    for (private_exponent) |byte| exponent_nonzero |= byte;
    if (exponent_nonzero == 0 or modulus[modulus.len - 1] == 0 or modulus[0] & 1 == 0)
        return error.InvalidPrivateKeyBlob;
    return .{ .modulus = modulus, .private_exponent = private_exponent };
}

fn decodeOaepSha1(encoded: []u8, output: []u8) Error!usize {
    const digest_len = Sha1.digest_length;
    if (encoded.len < 2 * digest_len + 2) return error.InvalidOaepPadding;
    const masked_seed = encoded[1..][0..digest_len];
    const database = encoded[1 + digest_len ..];
    xorMgf1Sha1(masked_seed, database);
    xorMgf1Sha1(database, masked_seed);

    var expected_label_hash: [digest_len]u8 = undefined;
    Sha1.hash("", &expected_label_hash, .{});
    defer std.crypto.secureZero(u8, &expected_label_hash);
    var invalid: u8 = encoded[0];
    for (database[0..digest_len], expected_label_hash) |actual, expected|
        invalid |= actual ^ expected;

    var looking: u8 = 1;
    var message_start: usize = database.len;
    for (database[digest_len..], digest_len..) |byte, index| {
        const is_zero: u8 = @intFromBool(byte == 0);
        const is_one: u8 = @intFromBool(byte == 1);
        invalid |= looking & (1 ^ is_zero) & (1 ^ is_one);
        const take = looking & is_one;
        const mask = 0 -% @as(usize, take);
        message_start = (message_start & ~mask) | ((index + 1) & mask);
        looking &= 1 ^ is_one;
    }
    invalid |= looking;
    if (invalid != 0) return error.InvalidOaepPadding;
    const message = database[message_start..];
    if (output.len < message.len) return error.OutputTooSmall;
    @memcpy(output[0..message.len], message);
    return message.len;
}

fn xorMgf1Sha1(output: []u8, seed: []const u8) void {
    var counter: u32 = 0;
    var offset: usize = 0;
    var digest: [Sha1.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    while (offset < output.len) : (counter += 1) {
        var counter_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &counter_bytes, counter, .big);
        var hasher = Sha1.init(.{});
        hasher.update(seed);
        hasher.update(&counter_bytes);
        hasher.final(&digest);
        const take = @min(digest.len, output.len - offset);
        for (output[offset..][0..take], digest[0..take]) |*byte, mask|
            byte.* ^= mask;
        offset += take;
    }
}

test "CryptoAPI RSA private blob unwraps Python OAEP-SHA1 vector" {
    const blob_base64 =
        \\BwIAAACkAABSU0EyAAgAAAEAAQAN70jAUKO0tE3vfEmPLuCwWsl/uxUZ2qdWybpIt6vEpgju8bkyyfNVAsFcCvbjHbb8TwjMHvUnzwAYjZ4Ij3+urbBj/i3r6z124jJ+pZiFeUnPYzZb6X1pm3Cw3cVAnR3lE6gFXcUtjyG3XuVdavMHG83H6WzsT3kYw2f8LkbYOtV6aI1cXjnHZnqdYCpjmj1MULuA2IqaUeZU6rUEhbUrwyiF3p2KI1nwuQ1GKhN9GeE5rcXOVkyYXrbqRMY4yGjuzxAYnQoAQLXAHyFJaiwSEfry280ipudlI4VJbwVhrRY3gQJ3wJ4bMcfo831EB1yMZMEaCJuy9DK5rs/M5jXEpX5iAKdFJYc+0N0sqfS4PVKgSVwTIlW5tBLUCp3oqnlw7n6tttoLGfCgwSY+BmSf67cOEoCx5DiEvIindC96xomHYnv06h1l8VjuEaz/GfKp8mpOOiWNvLrk5cEAR9DzUnUYNgN519eAnJGJZvHYdVabHVMzaIc00GsunFTSBsxJ6rBvK7ozikE+ex9Kn3Pgx/NsPj6ijJFMA3ODq7Z2D1TTwMJjYDbtrp0cgAjV2TlH3oGAYG6EbqBtpPvFtZNWtia0CVVQ3M2aUC8k5Wje3mOd+BIMmxNfZ5RGp1fXu9kayMzorCd4VIbgyjLskTHp5ojYZf0isLUVvr/9lF4x9sEUpgxlpduK5v4NaxHlTxQeS1EoJte+dERqtsa5AMzJPlyGx8HDG4rtmWDEg6v7sESTxaIR8D3bqcUCIVE3DENLQ3NzXzKeM8Y3P4/EDentnnjvWwQVRefM8/O/c4QslZKnXCct9kg1S2RZNl0ID6XQ0mADlUzJvb/QmU3p3Xt6sTKnmrfcLcCCB1dMdd+a1jftN7E0cE33E+b8C1S1XdHMlo4R9aT4Kkv1I7D02+bg5fPjSJEKhXbUknCQp5Aq71aiqXnLuaDb8x1/BF7A7nDZ6ATTHNF9nTeMbiGElqI27ci4juiG6tTeB/Taf9anvuEcvSxbjTwN0ZLShRciOroJJHhTbb8c1yrF7RuxcJuLiIEW5+T45pFz7LsQ3k5T+/49gvtaRg0HW13OPdFobqLuBf+eh7XPOWVmaNsdTngtD+Go7H86eZbApYKSHbH/rUSRKHBUt5/nWaPoUmMPahm3aHlFzyly6FKIVYsBquDwQWdJfWnt5ubIqooaI0R8fSHKcGedfBSYS+DqreBPLz4vr5OMStT9UC4jWY1RKQ9+9qnYUlimFQtvoCIJW0R5tbRRDC9CHKriD9tRCrpgf82IfqiQDxlVvwgw7WyS/eItPX+1/EWWuqNsh6fsMnzGtVz8NRJRkVR54ubBoCpgIN/rI5MVhghBFOoyhMsyicOFsHA2Ny8SiOKBIi6L2d/l86q8Qli6O2EwPPJBIj+Hs/U8pGKbTYdw2Upo0B9M+Ov+4RXHV3921oQDVjA46MgcnxRC1K4N3hxjQEfrdiE8OPf3IrTK4zVV0iPj5CZ+uJs9R1dnHTa2TTYM1r4QK4pCHuYxB2jxdgmdS9V7DKIajxU=
    ;
    const cipher_base64 =
        \\JWyPfte+i30Pzj2SW2I5IIglcnFedgEEgiSs4KNcbiYdw8lsV634gwQsLERIb179n6tEYrcG59U4ee6HmOcWwcU5WsYGSY4kGXWrH50goCYh2VFLs1DeVZv21ACuCB2R7COEtI6h7BDuXmw+hynQBht5OembEP5QNJVATWiTTcZy2X+Gybli5ncfl3hqFeSfy52I0Im6hffY+3O0M2tv9rbvBLKqBrmVgYV/3cnk6ToKtMuUZVrJJZ4VHPwY3horE3EhXpgdCe4tP4XMp2hpsLROGFhlHqHPXjJku5KgBW5eSUknktKpK0BcsTyKwxicFkwTNUER2l3PZKKFpEYkVA==
    ;
    var blob: [1172]u8 = undefined;
    var ciphertext: [256]u8 = undefined;
    _ = try std.base64.standard.Decoder.decode(&blob, blob_base64);
    _ = try std.base64.standard.Decoder.decode(&ciphertext, cipher_base64);
    const key = try unwrapEsdAes256Key(&blob, &ciphertext);
    const expected: [32]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    try std.testing.expectEqualSlices(u8, &expected, &key);
    ciphertext[ciphertext.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOaepPadding,
        unwrapEsdAes256Key(&blob, &ciphertext),
    );
    blob[8] ^= 1;
    try std.testing.expectError(
        error.InvalidPrivateKeyBlob,
        unwrapEsdAes256Key(&blob, cipher_base64[0..0]),
    );
}
