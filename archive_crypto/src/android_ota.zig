//! Android update-engine payload signature primitives.
//!
//! AOSP accepts SHA-256 digests signed with RSA-2048/4096 PKCS#1 v1.5 or
//! P-256 ECDSA. This module owns strict SubjectPublicKeyInfo PEM/DER parsing
//! and cryptographic verification; the payload container owns protobuf and
//! signed-range policy.

const std = @import("std");

const max_modulus_bits = 4096;
const max_modulus_len = max_modulus_bits / 8;
const max_der_len = 1024;
const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    InvalidPublicKeyPem,
    InvalidPublicKeyDer,
    UnsupportedPublicKey,
    InvalidSignature,
    SignatureMismatch,
};

const rsa_encryption_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const ec_public_key_oid = "\x2a\x86\x48\xce\x3d\x02\x01";
const prime256v1_oid = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const sha256_digest_info_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};

pub const PublicKey = union(enum) {
    rsa: Rsa,
    ecdsa_p256: [Ecdsa.PublicKey.uncompressed_sec1_encoded_length]u8,

    pub fn parsePem(pem: []const u8) Error!PublicKey {
        const begin = "-----BEGIN PUBLIC KEY-----";
        const end = "-----END PUBLIC KEY-----";
        const begin_at = std.mem.indexOf(u8, pem, begin) orelse
            return error.InvalidPublicKeyPem;
        const data_start = begin_at + begin.len;
        const end_at = std.mem.indexOfPos(u8, pem, data_start, end) orelse
            return error.InvalidPublicKeyPem;
        if (!onlyWhitespace(pem[0..begin_at]) or
            !onlyWhitespace(pem[end_at + end.len ..]))
        {
            return error.InvalidPublicKeyPem;
        }
        const encoded = pem[data_start..end_at];
        const decoder = std.base64.standard.decoderWithIgnore(" \r\n\t");
        const upper = decoder.calcSizeUpperBound(encoded.len);
        if (upper > max_der_len) return error.InvalidPublicKeyPem;
        var der: [max_der_len]u8 = undefined;
        const len = decoder.decode(&der, encoded) catch
            return error.InvalidPublicKeyPem;
        return parseDer(der[0..len]);
    }

    pub fn parseDer(der: []const u8) Error!PublicKey {
        var outer = DerReader.init(der);
        var spki = DerReader.init(try outer.read(0x30));
        if (!outer.done()) return error.InvalidPublicKeyDer;
        var algorithm = DerReader.init(try spki.read(0x30));
        const oid = try algorithm.read(0x06);
        const bit_string = try spki.read(0x03);
        if (!spki.done() or bit_string.len < 2 or bit_string[0] != 0)
            return error.InvalidPublicKeyDer;
        if (std.mem.eql(u8, oid, rsa_encryption_oid)) {
            const null_value = try algorithm.read(0x05);
            if (null_value.len != 0 or !algorithm.done())
                return error.InvalidPublicKeyDer;
            return .{ .rsa = try Rsa.parsePkcs1(bit_string[1..]) };
        }
        if (std.mem.eql(u8, oid, ec_public_key_oid)) {
            const curve = try algorithm.read(0x06);
            if (!algorithm.done() or !std.mem.eql(u8, curve, prime256v1_oid) or
                bit_string.len - 1 != Ecdsa.PublicKey.uncompressed_sec1_encoded_length)
            {
                return error.UnsupportedPublicKey;
            }
            const sec1 = bit_string[1..][0..Ecdsa.PublicKey.uncompressed_sec1_encoded_length].*;
            _ = Ecdsa.PublicKey.fromSec1(&sec1) catch
                return error.InvalidPublicKeyDer;
            return .{ .ecdsa_p256 = sec1 };
        }
        return error.UnsupportedPublicKey;
    }

    pub fn verifySha256(
        self: PublicKey,
        digest: *const [32]u8,
        signature: []const u8,
    ) Error!void {
        return switch (self) {
            .rsa => |rsa| rsa.verifySha256(digest, signature),
            .ecdsa_p256 => |sec1| {
                const public_key = Ecdsa.PublicKey.fromSec1(&sec1) catch
                    return error.InvalidPublicKeyDer;
                const parsed = Ecdsa.Signature.fromDer(signature) catch
                    return error.InvalidSignature;
                parsed.verifyPrehashed(digest.*, public_key) catch
                    return error.SignatureMismatch;
            },
        };
    }
};

const Rsa = struct {
    modulus: [max_modulus_len]u8 = @splat(0),
    modulus_len: u16,
    exponent: u32,

    fn parsePkcs1(der: []const u8) Error!Rsa {
        var outer = DerReader.init(der);
        var sequence = DerReader.init(try outer.read(0x30));
        if (!outer.done()) return error.InvalidPublicKeyDer;
        const modulus_bytes = try positiveInteger(try sequence.read(0x02));
        const exponent_bytes = try positiveInteger(try sequence.read(0x02));
        if (!sequence.done() or
            (modulus_bytes.len != 256 and modulus_bytes.len != 512) or
            exponent_bytes.len > 4 or modulus_bytes[modulus_bytes.len - 1] & 1 == 0)
        {
            return error.UnsupportedPublicKey;
        }
        var exponent: u32 = 0;
        for (exponent_bytes) |byte| exponent = (exponent << 8) | byte;
        if (exponent < 3 or exponent & 1 == 0)
            return error.UnsupportedPublicKey;
        var result = Rsa{
            .modulus_len = @intCast(modulus_bytes.len),
            .exponent = exponent,
        };
        @memcpy(result.modulus[0..modulus_bytes.len], modulus_bytes);
        return result;
    }

    fn verifySha256(
        self: Rsa,
        digest: *const [32]u8,
        signature: []const u8,
    ) Error!void {
        const modulus_len: usize = self.modulus_len;
        if (signature.len != modulus_len) return error.InvalidSignature;
        var modulus = Modulus.fromBytes(self.modulus[0..modulus_len], .big) catch
            return error.InvalidPublicKeyDer;
        const signature_value = Fe.fromBytes(modulus, signature, .big) catch
            return error.InvalidSignature;
        var exponent_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &exponent_bytes, self.exponent, .big);
        const first = std.mem.indexOfNone(u8, &exponent_bytes, &.{0}) orelse
            return error.InvalidPublicKeyDer;
        var encoded = modulus.powWithEncodedExponent(
            signature_value,
            exponent_bytes[first..],
            .big,
        ) catch return error.InvalidSignature;
        var message: [max_modulus_len]u8 = undefined;
        encoded.toBytes(message[0..modulus_len], .big) catch
            return error.InvalidSignature;
        const padding_len = modulus_len - digest.len - sha256_digest_info_prefix.len - 3;
        var invalid: u8 = message[0] | (message[1] ^ 1);
        for (message[2 .. 2 + padding_len]) |byte| invalid |= byte ^ 0xff;
        invalid |= message[2 + padding_len];
        const prefix_start = 3 + padding_len;
        for (message[prefix_start..][0..sha256_digest_info_prefix.len], sha256_digest_info_prefix) |actual, expected|
            invalid |= actual ^ expected;
        const digest_start = prefix_start + sha256_digest_info_prefix.len;
        for (message[digest_start..][0..digest.len], digest.*) |actual, expected|
            invalid |= actual ^ expected;
        if (invalid != 0) return error.SignatureMismatch;
    }
};

const DerReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn init(bytes: []const u8) DerReader {
        return .{ .bytes = bytes };
    }

    fn done(self: DerReader) bool {
        return self.offset == self.bytes.len;
    }

    fn read(self: *DerReader, expected_tag: u8) Error![]const u8 {
        if (self.offset >= self.bytes.len or self.bytes[self.offset] != expected_tag)
            return error.InvalidPublicKeyDer;
        self.offset += 1;
        if (self.offset >= self.bytes.len) return error.InvalidPublicKeyDer;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var len: usize = 0;
        if (first & 0x80 == 0) {
            len = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or self.bytes[self.offset] == 0)
            {
                return error.InvalidPublicKeyDer;
            }
            for (self.bytes[self.offset..][0..count]) |byte|
                len = std.math.add(
                    usize,
                    std.math.mul(usize, len, 256) catch
                        return error.InvalidPublicKeyDer,
                    byte,
                ) catch return error.InvalidPublicKeyDer;
            if (len < 128) return error.InvalidPublicKeyDer;
            self.offset += count;
        }
        if (len > self.bytes.len - self.offset) return error.InvalidPublicKeyDer;
        const value = self.bytes[self.offset..][0..len];
        self.offset += len;
        return value;
    }
};

fn positiveInteger(encoded: []const u8) Error![]const u8 {
    if (encoded.len == 0 or encoded[0] & 0x80 != 0)
        return error.InvalidPublicKeyDer;
    if (encoded[0] != 0) return encoded;
    if (encoded.len == 1 or encoded[1] & 0x80 == 0)
        return error.InvalidPublicKeyDer;
    return encoded[1..];
}

fn onlyWhitespace(bytes: []const u8) bool {
    for (bytes) |byte| switch (byte) {
        ' ', '\t', '\r', '\n' => {},
        else => return false,
    };
    return true;
}

test "Android OTA RSA-2048 and P-256 signatures match OpenSSL AOSP keys" {
    const message = "Vail Android OTA signature vector\n";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});
    const rsa_pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtGHtqO21Uhy2wGz9flu
        \\IpIUR8G7dZoCZhZukGkm4mlfgL71xPSArjx02/w/FhYxOusV6/XQeKgL3i8cni3H
        \\CkCOurZLpi2L5Ver6qrxKFh6WBVZ0Dj7N6P/Mf5jZdhfvVyweLlsNK8Ypeb+Razf
        \\rsXhd4cy3dBMxouGwH7R7QQXTFCoCc8kgJBTxILl3jfvY8OrNKgYiCETa7tQdFkP
        \\0bfPwH9cAXuMjHXiZatim0tF+ivpkM2v/6LTxtD6Rq1wks/N6CHi8efrRaviFp7c
        \\0mNmBNFaV54cHEUW2SlNIiRun7L01nAz/D8kuoHfx4E3Mtj0DbvngZJMX/X+rJQ5
        \\cQIDAQAB
        \\-----END PUBLIC KEY-----
    ;
    const rsa_signature_base64 =
        "papzcNHVUNrLsXTXYtA3Wx1/y++oJY5YS3JTyw5ARP4c5vKZ6CxGjQIpwDm3yYLc" ++
        "M7kJD5TxPCenDmpHo51cnk2HYn684uX4TzVdu9ZhbawmDAOh0VUDKbDUzddvpks83" ++
        "knhyj2D16ILDGOu7YGtyksoyFofYjI3XLzoi9/O91+E9jMJbvVAEwdS+YBLbTNsl4" ++
        "IXaNG9KSqoh/mrRRlIv6p3rUBR1Eu9Ap5yV+7wwBq8g29BL2ISPv0BFeXpPoI6U8" ++
        "wjAcaf8wfpEfstcEyw1Zc5xNr/SuV860hUJRFmk5ZeuA7oM0oR/e7dgOss/njl8q" ++
        "NRguFZb0IxNLm5+lhG4Q==";
    var rsa_signature: [256]u8 = undefined;
    _ = try std.base64.standard.Decoder.decode(
        &rsa_signature,
        rsa_signature_base64,
    );
    const rsa = try PublicKey.parsePem(rsa_pem);
    try rsa.verifySha256(&digest, &rsa_signature);

    const ec_pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQZ7qLcCjrLr4x+osEw4TgIu0OaS1
        \\s8Q5GY4NqXH234vRRU7y2BE2rOwdlun8fT1Hs1Jh0xUw1diWbjGGBXWTsA==
        \\-----END PUBLIC KEY-----
    ;
    const ec_signature_base64 =
        "MEUCIQCIeXvQUhxDVRX/NKZa7OqGfnri0AT4si0YVWO7L8KXeAIgAy29DSv8KR93" ++
        "zAsRn6bpVBGsnIk0jOX0trGJGCtxPMY=";
    var ec_signature: [71]u8 = undefined;
    _ = try std.base64.standard.Decoder.decode(&ec_signature, ec_signature_base64);
    const ec = try PublicKey.parsePem(ec_pem);
    try ec.verifySha256(&digest, &ec_signature);

    digest[0] ^= 1;
    try std.testing.expectError(
        error.SignatureMismatch,
        rsa.verifySha256(&digest, &rsa_signature),
    );
    try std.testing.expectError(
        error.SignatureMismatch,
        ec.verifySha256(&digest, &ec_signature),
    );
}

test "Android OTA RSA-4096 signature and strict public-key parsing" {
    const message = "Vail Android OTA signature vector\n";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});
    const pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu8vBB+DvDPWgO1IWli5V
        \\uXHkMWYtD+wzToKIP/NkiGYdf1b9EvCgrvS3J4CutKCHoz1N5Pc29DKZduDhLbqW
        \\zqvUldJ8kSKd967PRCdM5vJHmdoxH8E7m3YROBrppcJG32B5TD5qbn6jqrsSnwjl
        \\GZN2RAuURQwalSxq3/ZttiEzEMDRo/7v5rQINlF0Rsud+HlNXrxzhR/LQyMV3d+/
        \\JvoEWPmz4unzpKyYAMOjdNTcMLB0ccULFYKfJtRCqTyfgEUbT+mGLTbDQSkzl6mc
        \\NfDg+3hu8lTjQH+6EjjDUSu6oOmVOmDf8tZPmGRdw/9R1PUx6A1yKQR6FkdkqRDO
        \\t1GvIpUpsfT36Gg59u1a6YyHKudB6igFzr3JcTgslQ9KUZK68j6Xr2AlbsffyJ5l
        \\tyuHT4gMtCppkuGUi1CZ6+i55LfAt1cVx6meE+zJYK46zu9GKgsXg72BNCi/3v1H
        \\ievZwDcm5A04YQZMZDgtb74pN1VzuCEzxCgpyx3b3Y/K8JI6n9xMeQNIPF2h9Jei
        \\O9qasV4vJ51PbnS61BHR1E9Sh8452QVT+mqJnA8uRp22+sF0wU5Ae33UAZxnKk9A
        \\x+uz6iRP6wlILlUpl+Chsjla6+UtRkE4NRJh2xdin+j9GCaXFVOzx0RPLAYrD9/c
        \\M6BOV7CKZ/2iqVnaXH6sY00CAwEAAQ==
        \\-----END PUBLIC KEY-----
    ;
    const signature_base64 =
        "sJE4QvoqF5Pjob3UTT+ud/6o2ptlZzE+q1Hj712VO8xgYEPWJlCJNJfPwpnkhiAQZ" ++
        "4bH92/5KRDNEIwvkEMTu4iV022s+Zv3AeRAiOStfgj5rlTgCkigxiQW+9hXUTCMH" ++
        "l/n3m8kIjETEQfe6ZgodM0uh1T40NxVLrvAWj1CRB+j4FAMlRmAEGsNsAZ9srSV2" ++
        "BqZ8Pe4VbCdNteyXDkdYqJcqKEARUlvS1nKREHnbdFCfK5NmSxulBSWvgk7HeFc" ++
        "EnKUJqSmz/htWKC9itFZMiq+auNfzSLqk4XOFrcIgBqvCPgHbD6jF3M0xG14Gbx" ++
        "Ko4F6OuOJzQTjJhI6eCsB90ersjqKALDWogkksVc7DZwW4Lda3nqE9Xe4Nub4dv" ++
        "7S59Ix02PgNotZpGNuLxNHh9LMbck7TBWPpmdP42af3NkJTxReBtIElyoIirnT7D" ++
        "ukzlhFOtCgEap1GtKjM1IjVNwQ5C422AeEo+Zgkuhpx7LSk/aO7VzLXyFDL8wWA" ++
        "/wAQwuIYguT/YB0+sFxyGSwvqtUVKN3eJTVwVEi8zE+xyM6QiGT8VlIs8NSUPEe" ++
        "SgqZa/oFPa/e/7wVX2Lw/DLuuUeJrHHGfG+zGvUUyQz5oJt1Zz8xLmDs2iwuCEC" ++
        "U3vUGFI25BmFaKtJmS1O0WqkZ9HE+igvZH+oWYDSJl4OsQ9k=";
    var signature: [512]u8 = undefined;
    _ = try std.base64.standard.Decoder.decode(&signature, signature_base64);
    const key = try PublicKey.parsePem(pem);
    try key.verifySha256(&digest, &signature);
    try std.testing.expectError(
        error.InvalidSignature,
        key.verifySha256(&digest, signature[0 .. signature.len - 1]),
    );
    try std.testing.expectError(
        error.InvalidPublicKeyPem,
        PublicKey.parsePem("-----BEGIN PUBLIC KEY-----\n!\n-----END PUBLIC KEY-----"),
    );
    try std.testing.expectError(
        error.InvalidPublicKeyDer,
        PublicKey.parseDer("\x30\x00"),
    );
}
