//! Allocation-free RSA private-key operations for TLS signatures.
//!
//! PKCS#1 and unencrypted PKCS#8 DER keys are parsed as borrowed slices,
//! including RFC 4055 and RFC 8692 constrained RSASSA-PSS keys. RSA
//! exponentiation uses PKCS#1 CRT parameters and a fixed-width constant-time
//! RSA-2048 path, with `std.crypto.ff` retained for larger keys. Prepared keys
//! cache Montgomery moduli so handshake signing performs no heap allocation.

const std = @import("std");
const builtin = @import("builtin");
const rsa_pss = @import("../rsa_pss.zig");

const rsa_montgomery = @import("rsa_montgomery.zig");
const Montgomery1024 = rsa_montgomery.Montgomery1024;
const Montgomery2048 = rsa_montgomery.Montgomery2048;

const Sha224 = std.crypto.hash.sha2.Sha224;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha512_224 = std.crypto.hash.sha2.Sha512_224;
const Sha512_256 = std.crypto.hash.sha2.Sha512_256;
const Sha3_224 = std.crypto.hash.sha3.Sha3_224;
const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const Sha3_384 = std.crypto.hash.sha3.Sha3_384;
const Sha3_512 = std.crypto.hash.sha3.Sha3_512;
const Shake128 = std.crypto.hash.sha3.Shake128;
const Shake256 = std.crypto.hash.sha3.Shake256;
const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFieldElement = RsaModulus.Fe;
const PrimeModulus = std.crypto.ff.Modulus(2048);
const PrimeFieldElement = PrimeModulus.Fe;

const oid_rsa_encryption = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
};
const oid_rsassa_pss = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
};
const oid_rsassa_pss_shake128 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e,
};
const oid_rsassa_pss_shake256 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f,
};

pub const Error = error{
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    UnsupportedModulusBits,
    UnsupportedPublicExponent,
    InvalidSaltLength,
    SignatureBufferTooSmall,
    MessageTooLong,
    KeyAlgorithmMismatch,
};

/// Reusable RSA-2048 public-key state for the common exponent 65537.
/// The Montgomery context is public data and does not require wiping.
pub const PreparedPublicKey = struct {
    context: Montgomery2048,
    modulus_bits: usize,

    pub fn init(
        exponent: []const u8,
        modulus: []const u8,
    ) Error!PreparedPublicKey {
        if (!std.mem.eql(u8, exponent, "\x01\x00\x01")) {
            return error.UnsupportedPublicExponent;
        }
        if (modulus.len != Montgomery2048.encoded_length or modulus[0] == 0) {
            return error.UnsupportedModulusBits;
        }
        return .{
            .context = Montgomery2048.init(modulus) catch
                return error.InvalidPublicKey,
            .modulus_bits = modulus.len * 8 - @clz(modulus[0]),
        };
    }

    pub fn verifyPssSha224(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha224, message_parts, signature);
    }

    pub fn verifyPssSha256(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha256, message_parts, signature);
    }

    pub fn verifyPssSha384(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha384, message_parts, signature);
    }

    pub fn verifyPssSha512(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha512, message_parts, signature);
    }

    /// RSASSA-PSS verification with the salt length encoded in the signature
    /// (RFC 8017 EME-PSS-VERIFY step 9: any salt length is valid). This
    /// accepts signatures produced with OpenSSL's default maximum salt, which
    /// DDS-Security peers such as CycloneDDS emit. The strict `verifyPss*`
    /// variants above require a digest-length salt.
    pub fn verifyPssSha224AutoSalt(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPssImpl(Sha224, message_parts, signature, true);
    }

    pub fn verifyPssSha256AutoSalt(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPssImpl(Sha256, message_parts, signature, true);
    }

    pub fn verifyPssSha384AutoSalt(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPssImpl(Sha384, message_parts, signature, true);
    }

    pub fn verifyPssSha512AutoSalt(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPssImpl(Sha512, message_parts, signature, true);
    }

    pub fn verifyPkcs1v15Sha224(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha224, message_parts, signature);
    }

    pub fn verifyPkcs1v15Sha256(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha256, message_parts, signature);
    }

    pub fn verifyPkcs1v15Sha384(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha384, message_parts, signature);
    }

    pub fn verifyPkcs1v15Sha512(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha512, message_parts, signature);
    }

    fn verifyPss(
        self: *const PreparedPublicKey,
        comptime Hash: type,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPssImpl(Hash, message_parts, signature, false);
    }

    fn verifyPssImpl(
        self: *const PreparedPublicKey,
        comptime Hash: type,
        message_parts: []const []const u8,
        signature: []const u8,
        comptime auto_salt: bool,
    ) Error!void {
        if (signature.len != Montgomery2048.encoded_length) {
            return error.InvalidSignature;
        }
        const encoded_signature = signature[0..Montgomery2048.encoded_length].*;
        const signature_limbs = Montgomery2048.decode(&encoded_signature);
        if (!Montgomery2048.lessThan(
            signature_limbs,
            self.context.modulus,
        )) return error.InvalidSignature;
        const recovered_limbs = self.context.pow65537(signature_limbs);
        var encoded_message: [Montgomery2048.encoded_length]u8 = undefined;
        Montgomery2048.encode(recovered_limbs, &encoded_message);
        return verifyPssEncoding(
            Hash,
            message_parts,
            &encoded_message,
            self.modulus_bits - 1,
            auto_salt,
        );
    }

    fn verifyPkcs1v15(
        self: *const PreparedPublicKey,
        comptime Hash: type,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        if (signature.len != Montgomery2048.encoded_length) {
            return error.InvalidSignature;
        }
        const encoded_signature = signature[0..Montgomery2048.encoded_length].*;
        const signature_limbs = Montgomery2048.decode(&encoded_signature);
        if (!Montgomery2048.lessThan(
            signature_limbs,
            self.context.modulus,
        )) return error.InvalidSignature;
        const recovered_limbs = self.context.pow65537(signature_limbs);
        var encoded_message: [Montgomery2048.encoded_length]u8 = undefined;
        Montgomery2048.encode(recovered_limbs, &encoded_message);

        const digest_info_prefix: []const u8 = &switch (Hash) {
            Sha224 => .{
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                0x00, 0x04, 0x1c,
            },
            Sha256 => .{
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            },
            Sha384 => .{
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                0x00, 0x04, 0x30,
            },
            Sha512 => .{
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00, 0x04, 0x40,
            },
            else => @compileError("unsupported PKCS#1 v1.5 hash"),
        };
        const digest_info_len = digest_info_prefix.len + Hash.digest_length;
        if (encoded_message.len < digest_info_len + 11 or
            encoded_message[0] != 0 or encoded_message[1] != 1)
        {
            return error.InvalidSignature;
        }
        const separator = encoded_message.len - digest_info_len - 1;
        var invalid_padding: u8 = encoded_message[separator];
        for (encoded_message[2..separator]) |byte| {
            invalid_padding |= byte ^ 0xff;
        }
        if (invalid_padding != 0 or !std.mem.eql(
            u8,
            encoded_message[separator + 1 ..][0..digest_info_prefix.len],
            digest_info_prefix,
        )) return error.InvalidSignature;

        var digest: [Hash.digest_length]u8 = undefined;
        var hasher = Hash.init(.{});
        for (message_parts) |part| hasher.update(part);
        hasher.final(&digest);
        if (!std.crypto.timing_safe.eql(
            [Hash.digest_length]u8,
            digest,
            encoded_message[encoded_message.len - Hash.digest_length ..].*,
        )) return error.InvalidSignature;
    }
};

fn verifyPssEncoding(
    comptime Hash: type,
    message_parts: []const []const u8,
    encoded_message: []u8,
    encoded_bits: usize,
    comptime auto_salt: bool,
) Error!void {
    const encoded_len = (encoded_bits + 7) / 8;
    const min_encoded_len = if (auto_salt)
        Hash.digest_length + 2
    else
        2 * Hash.digest_length + 2;
    if (encoded_len != encoded_message.len or
        encoded_len < min_encoded_len or
        encoded_message[encoded_message.len - 1] != 0xbc)
    {
        return error.InvalidSignature;
    }
    const database_len = encoded_len - Hash.digest_length - 1;
    const digest = encoded_message[database_len..][0..Hash.digest_length];
    const unused_bits = encoded_len * 8 - encoded_bits;
    if (unused_bits != 0 and
        encoded_message[0] >> @intCast(8 - unused_bits) != 0)
    {
        return error.InvalidSignature;
    }

    var seed: [Hash.digest_length + 4]u8 = undefined;
    @memcpy(seed[0..Hash.digest_length], digest);
    var offset: usize = 0;
    var counter: u32 = 0;
    while (offset < database_len) : (counter += 1) {
        std.mem.writeInt(u32, seed[Hash.digest_length..], counter, .big);
        var mask_block: [Hash.digest_length]u8 = undefined;
        Hash.hash(&seed, &mask_block, .{});
        const count = @min(mask_block.len, database_len - offset);
        for (encoded_message[offset..][0..count], mask_block[0..count]) |*byte, mask| {
            byte.* ^= mask;
        }
        offset += count;
    }
    encoded_message[0] &= @as(u8, 0xff) >> @intCast(unused_bits);

    const delimiter_index = if (auto_salt) blk: {
        // RFC 8017: DB = PS || 0x01 || salt with PS a (possibly empty) run of
        // zero bytes, so the salt length is whatever remains after the first
        // nonzero byte, which must be the 0x01 separator.
        var index: usize = 0;
        while (index < database_len and encoded_message[index] == 0) : (index += 1) {}
        if (index == database_len or encoded_message[index] != 1) {
            return error.InvalidSignature;
        }
        break :blk index;
    } else blk: {
        const index = database_len - Hash.digest_length - 1;
        var nonzero: u8 = 0;
        for (encoded_message[0..index]) |byte| nonzero |= byte;
        if (nonzero != 0 or encoded_message[index] != 1) {
            return error.InvalidSignature;
        }
        break :blk index;
    };
    const salt = encoded_message[delimiter_index + 1 .. database_len];
    var message_hash: [Hash.digest_length]u8 = undefined;
    var message_hasher = Hash.init(.{});
    for (message_parts) |part| message_hasher.update(part);
    message_hasher.final(&message_hash);
    var expected_hasher = Hash.init(.{});
    expected_hasher.update(&[_]u8{0} ** 8);
    expected_hasher.update(&message_hash);
    expected_hasher.update(salt);
    var expected: [Hash.digest_length]u8 = undefined;
    expected_hasher.final(&expected);
    if (!std.crypto.timing_safe.eql(
        [Hash.digest_length]u8,
        digest[0..Hash.digest_length].*,
        expected,
    )) return error.InvalidSignature;
}

pub const PrivateKey = struct {
    /// Unsigned, minimally encoded big-endian values borrowed from the DER.
    modulus: []const u8,
    public_exponent: []const u8,
    private_exponent: []const u8,
    prime1: []const u8,
    prime2: []const u8,
    exponent1: []const u8,
    exponent2: []const u8,
    coefficient: []const u8,
    /// Non-null for PKCS#8 id-RSASSA-PSS keys. This also marks the key as
    /// PSS-only even when the AlgorithmIdentifier omits optional constraints.
    pss_constraints: ?rsa_pss.PssKeyConstraints = null,

    pub fn fromDer(der: []const u8) Error!PrivateKey {
        var outer = Reader{ .bytes = der };
        const sequence = outer.require(0x30) catch
            return error.InvalidPrivateKey;
        if (!outer.done()) return error.InvalidPrivateKey;
        var fields = Reader{ .bytes = sequence.value };
        const version = fields.require(0x02) catch
            return error.InvalidPrivateKey;
        if (!std.mem.eql(u8, version.value, &.{0})) {
            return error.InvalidPrivateKey;
        }
        const second = (fields.next() catch
            return error.InvalidPrivateKey) orelse
            return error.InvalidPrivateKey;
        return switch (second.tag) {
            0x02 => parsePkcs1Fields(&fields, second),
            0x30 => parsePkcs8Fields(&fields, second),
            else => error.InvalidPrivateKey,
        };
    }

    pub fn modulusBits(self: PrivateKey) usize {
        return self.modulus.len * 8 - @clz(self.modulus[0]);
    }

    pub fn signatureLength(self: PrivateKey) usize {
        return self.modulus.len;
    }

    pub fn matchesPublicKey(
        self: PrivateKey,
        modulus: []const u8,
        exponent: []const u8,
    ) bool {
        return timingSafeEql(self.modulus, stripUnsignedPadding(modulus)) and
            timingSafeEql(
                self.public_exponent,
                stripUnsignedPadding(exponent),
            );
    }

    pub fn signPssSha256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha256(message, salt, output);
    }

    pub fn signPssSha224(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha224(message, salt, output);
    }

    pub fn signPssSha384(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha384(message, salt, output);
    }

    pub fn signPssSha512(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha512(message, salt, output);
    }

    pub fn signPssSha512_224(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha512_224(message, salt, output);
    }

    pub fn signPssSha512_256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha512_256(message, salt, output);
    }

    pub fn signPssShake128(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssShake128(message, salt, output);
    }

    pub fn signPssShake256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssShake256(message, salt, output);
    }

    pub fn signPssSha3_224(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_224(message, salt, output);
    }

    pub fn signPssSha3_256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_256(message, salt, output);
    }

    pub fn signPssSha3_384(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_384(message, salt, output);
    }

    pub fn signPssSha3_512(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_512(message, salt, output);
    }

    pub fn signPkcs1v15Sha256(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha256(message, output);
    }

    pub fn signPkcs1v15Sha224(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha224(message, output);
    }

    pub fn signPkcs1v15Sha384(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha384(message, output);
    }

    pub fn signPkcs1v15Sha512(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha512(message, output);
    }

    pub fn signPkcs1v15Sha512_224(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha512_224(message, output);
    }

    pub fn signPkcs1v15Sha512_256(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha512_256(message, output);
    }

    pub fn signPkcs1v15Sha3_224(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_224(message, output);
    }

    pub fn signPkcs1v15Sha3_256(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_256(message, output);
    }

    pub fn signPkcs1v15Sha3_384(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_384(message, output);
    }

    pub fn signPkcs1v15Sha3_512(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_512(message, output);
    }

    pub fn prepare(self: PrivateKey) Error!PreparedPrivateKey {
        return PreparedPrivateKey.init(self);
    }
};

pub const PreparedPrivateKey = struct {
    key: PrivateKey,
    modulus: RsaModulus,
    prime1: PrimeModulus,
    prime2: PrimeModulus,
    q_inverse_mod_p: PrimeFieldElement,
    q_full: RsaFieldElement,
    prime1_1024: ?Montgomery1024,
    prime2_1024: ?Montgomery1024,

    pub fn init(key: PrivateKey) Error!PreparedPrivateKey {
        const modulus = RsaModulus.fromBytes(key.modulus, .big) catch
            return error.InvalidPrivateKey;
        const prime1 = PrimeModulus.fromBytes(key.prime1, .big) catch
            return error.InvalidPrivateKey;
        const prime2 = PrimeModulus.fromBytes(key.prime2, .big) catch
            return error.InvalidPrivateKey;
        _ = RsaFieldElement.fromBytes(
            modulus,
            key.private_exponent,
            .big,
        ) catch return error.InvalidPrivateKey;
        _ = PrimeFieldElement.fromBytes(
            prime1,
            key.exponent1,
            .big,
        ) catch return error.InvalidPrivateKey;
        _ = PrimeFieldElement.fromBytes(
            prime2,
            key.exponent2,
            .big,
        ) catch return error.InvalidPrivateKey;
        const q_inverse_mod_p = PrimeFieldElement.fromBytes(
            prime1,
            key.coefficient,
            .big,
        ) catch return error.InvalidPrivateKey;
        const q_full = RsaFieldElement.fromBytes(
            modulus,
            key.prime2,
            .big,
        ) catch return error.InvalidPrivateKey;
        var prepared = PreparedPrivateKey{
            .key = key,
            .modulus = modulus,
            .prime1 = prime1,
            .prime2 = prime2,
            .q_inverse_mod_p = q_inverse_mod_p,
            .q_full = q_full,
            .prime1_1024 = if (key.modulus.len == 256)
                try Montgomery1024.init(key.prime1)
            else
                null,
            .prime2_1024 = if (key.modulus.len == 256)
                try Montgomery1024.init(key.prime2)
            else
                null,
        };
        errdefer prepared.deinit();
        try validateKeyConsistency(&prepared);
        return prepared;
    }

    pub fn deinit(self: *PreparedPrivateKey) void {
        std.crypto.secureZero(PreparedPrivateKey, self[0..1]);
    }

    pub fn signatureLength(self: *const PreparedPrivateKey) usize {
        return self.key.signatureLength();
    }

    pub fn matchesPublicKey(
        self: *const PreparedPrivateKey,
        modulus: []const u8,
        exponent: []const u8,
    ) bool {
        return self.key.matchesPublicKey(modulus, exponent);
    }

    pub fn signPssSha256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha256, message, salt, output);
    }

    pub fn signPssSha224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha224, message, salt, output);
    }

    pub fn signPssSha384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha384, message, salt, output);
    }

    pub fn signPssSha512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha512, message, salt, output);
    }

    pub fn signPssSha512_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha512_224, message, salt, output);
    }

    pub fn signPssSha512_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha512_256, message, salt, output);
    }

    pub fn signPssShake128(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPssShake(self, Shake128, message, salt, output);
    }

    pub fn signPssShake256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPssShake(self, Shake256, message, salt, output);
    }

    pub fn signPssSha3_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_224, message, salt, output);
    }

    pub fn signPssSha3_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_256, message, salt, output);
    }

    pub fn signPssSha3_384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_384, message, salt, output);
    }

    pub fn signPssSha3_512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_512, message, salt, output);
    }

    pub fn signPkcs1v15Sha256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha256, message, output);
    }

    pub fn signPkcs1v15Sha224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha224, message, output);
    }

    pub fn signPkcs1v15Sha384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha384, message, output);
    }

    pub fn signPkcs1v15Sha512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha512, message, output);
    }

    pub fn signPkcs1v15Sha512_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha512_224, message, output);
    }

    pub fn signPkcs1v15Sha512_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha512_256, message, output);
    }

    pub fn signPkcs1v15Sha3_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_224, message, output);
    }

    pub fn signPkcs1v15Sha3_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_256, message, output);
    }

    pub fn signPkcs1v15Sha3_384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_384, message, output);
    }

    pub fn signPkcs1v15Sha3_512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_512, message, output);
    }
};

fn parsePkcs1Fields(fields: *Reader, modulus_element: Element) Error!PrivateKey {
    const modulus = positiveInteger(modulus_element) catch
        return error.InvalidPrivateKey;
    const public_exponent = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const private_exponent = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const prime1 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const prime2 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const exponent1 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const exponent2 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const coefficient = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    if (!fields.done()) return error.InvalidPrivateKey;
    return validateComponents(
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
    );
}

fn parsePkcs8Fields(
    fields: *Reader,
    algorithm: Element,
) Error!PrivateKey {
    var algorithm_fields = Reader{ .bytes = algorithm.value };
    const oid = algorithm_fields.require(0x06) catch
        return error.InvalidPrivateKey;
    const is_rsa_encryption = std.mem.eql(
        u8,
        oid.value,
        &oid_rsa_encryption,
    );
    const is_rsa_pss = std.mem.eql(u8, oid.value, &oid_rsassa_pss) or
        std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake128) or
        std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake256);
    if (!is_rsa_encryption and !is_rsa_pss) {
        return error.InvalidPrivateKey;
    }
    const pss_constraints: ?rsa_pss.PssKeyConstraints = if (is_rsa_pss)
        rsa_pss.parsePssPublicKeyAlgorithmIdentifier(
            algorithm.value,
        ) catch return error.InvalidPrivateKey
    else blk: {
        if (algorithm_fields.next() catch
            return error.InvalidPrivateKey) |params|
        {
            if (params.tag != 0x05 or params.value.len != 0 or
                !algorithm_fields.done())
            {
                return error.InvalidPrivateKey;
            }
        }
        break :blk null;
    };
    const private_key = fields.require(0x04) catch
        return error.InvalidPrivateKey;
    if (!fields.done()) return error.InvalidPrivateKey;
    var parsed = try PrivateKey.fromDer(private_key.value);
    parsed.pss_constraints = pss_constraints;
    return parsed;
}

fn validateComponents(
    modulus: []const u8,
    public_exponent: []const u8,
    private_exponent: []const u8,
    prime1: []const u8,
    prime2: []const u8,
    exponent1: []const u8,
    exponent2: []const u8,
    coefficient: []const u8,
) Error!PrivateKey {
    if (modulus.len != 256 and modulus.len != 384 and modulus.len != 512) {
        return error.UnsupportedModulusBits;
    }
    if ((modulus[modulus.len - 1] & 1) == 0 or
        @clz(modulus[0]) != 0 or
        private_exponent.len > modulus.len or
        prime1.len > 256 or prime2.len > 256 or
        prime1.len + 1 < modulus.len / 2 or
        prime2.len + 1 < modulus.len / 2 or
        exponent1.len > prime1.len or exponent2.len > prime2.len or
        coefficient.len > prime1.len)
    {
        return error.InvalidPrivateKey;
    }
    if (public_exponent.len == 0 or public_exponent.len > 4 or
        (public_exponent[public_exponent.len - 1] & 1) == 0)
    {
        return error.InvalidPrivateKey;
    }
    var exponent: u32 = 0;
    for (public_exponent) |byte| exponent = (exponent << 8) | byte;
    if (exponent < 3) return error.InvalidPrivateKey;
    const modulus_field = RsaModulus.fromBytes(modulus, .big) catch
        return error.InvalidPrivateKey;
    _ = RsaFieldElement.fromBytes(
        modulus_field,
        private_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    return .{
        .modulus = modulus,
        .public_exponent = public_exponent,
        .private_exponent = private_exponent,
        .prime1 = prime1,
        .prime2 = prime2,
        .exponent1 = exponent1,
        .exponent2 = exponent2,
        .coefficient = coefficient,
    };
}

fn signPss(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    message: []const u8,
    salt: []const u8,
    output: []u8,
) Error!usize {
    return signPssWithMask(
        private_key,
        Hash,
        .mgf1,
        message,
        salt,
        output,
    );
}

fn signPssShake(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    message: []const u8,
    salt: []const u8,
    output: []u8,
) Error!usize {
    return signPssWithMask(
        private_key,
        Hash,
        .shake,
        message,
        salt,
        output,
    );
}

const PssMaskGeneration = enum { mgf1, shake };

fn signPssWithMask(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    comptime mask_generation: PssMaskGeneration,
    message: []const u8,
    salt: []const u8,
    output: []u8,
) Error!usize {
    if (salt.len != Hash.digest_length) return error.InvalidSaltLength;
    if (private_key.key.pss_constraints) |constraints| {
        @branchHint(.unlikely);
        const algorithm: rsa_pss.Algorithm = if (Hash == Sha224)
            .rsa_pss_sha224
        else if (Hash == Sha256)
            .rsa_pss_sha256
        else if (Hash == Sha384)
            .rsa_pss_sha384
        else if (Hash == Sha512)
            .rsa_pss_sha512
        else if (Hash == Sha512_224)
            .rsa_pss_sha512_224
        else if (Hash == Sha512_256)
            .rsa_pss_sha512_256
        else if (Hash == Sha3_224)
            .rsa_pss_sha3_224
        else if (Hash == Sha3_256)
            .rsa_pss_sha3_256
        else if (Hash == Sha3_384)
            .rsa_pss_sha3_384
        else if (Hash == Sha3_512)
            .rsa_pss_sha3_512
        else if (Hash == Shake128)
            .rsa_pss_shake128
        else if (Hash == Shake256)
            .rsa_pss_shake256
        else
            return error.KeyAlgorithmMismatch;
        if (!constraints.permits(algorithm)) {
            return error.KeyAlgorithmMismatch;
        }
    }
    const modulus_len = private_key.key.modulus.len;
    if (output.len < modulus_len) return error.SignatureBufferTooSmall;
    const modulus = private_key.modulus;
    const modulus_bits = modulus.bits();
    if (modulus_bits != modulus_len * 8) {
        return error.UnsupportedModulusBits;
    }
    const encoded_bits = modulus_bits - 1;
    const encoded_len = (encoded_bits + 7) / 8;
    if (encoded_len < 2 * Hash.digest_length + 2) {
        return error.MessageTooLong;
    }

    var encoded_message: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded_message);
    const encoded = encoded_message[0..encoded_len];
    @memset(encoded, 0);
    var message_hash: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &message_hash);
    Hash.hash(message, &message_hash, .{});
    var final_hash: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &final_hash);
    var hash_input: [8 + 2 * Sha512.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &hash_input);
    @memset(hash_input[0..8], 0);
    @memcpy(hash_input[8..][0..Hash.digest_length], &message_hash);
    @memcpy(
        hash_input[8 + Hash.digest_length ..][0..salt.len],
        salt,
    );
    Hash.hash(
        hash_input[0 .. 8 + Hash.digest_length + salt.len],
        &final_hash,
        .{},
    );

    const data_block_len = encoded_len - Hash.digest_length - 1;
    const delimiter = data_block_len - salt.len - 1;
    encoded[delimiter] = 1;
    @memcpy(encoded[data_block_len - salt.len .. data_block_len], salt);
    switch (mask_generation) {
        .mgf1 => mgf1Xor(Hash, encoded[0..data_block_len], &final_hash),
        .shake => shakeXor(Hash, encoded[0..data_block_len], &final_hash),
    }
    const unused_bits: u3 = @intCast(encoded_len * 8 - encoded_bits);
    encoded[0] &= @as(u8, 0xff) >> unused_bits;
    @memcpy(encoded[data_block_len..][0..Hash.digest_length], &final_hash);
    encoded[encoded_len - 1] = 0xbc;

    const representative = RsaFieldElement.fromBytes(
        modulus,
        encoded,
        .big,
    ) catch return error.MessageTooLong;
    var signature = try privateOperation(
        private_key,
        representative,
    );
    defer std.crypto.secureZero(RsaFieldElement, (&signature)[0..1]);
    signature.toBytes(output[0..modulus_len], .big) catch
        return error.InvalidPrivateKey;
    return modulus_len;
}

fn signPkcs1v15(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    message: []const u8,
    output: []u8,
) Error!usize {
    if (private_key.key.pss_constraints != null) {
        @branchHint(.unlikely);
        return error.KeyAlgorithmMismatch;
    }
    const modulus_len = private_key.key.modulus.len;
    if (output.len < modulus_len) return error.SignatureBufferTooSmall;
    const digest_info_prefix: []const u8 = &switch (Hash) {
        Sha224 => .{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
            0x00, 0x04, 0x1c,
        },
        Sha256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        Sha384 => .{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        },
        Sha512 => .{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        Sha512_224 => .{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05,
            0x00, 0x04, 0x1c,
        },
        Sha512_256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05,
            0x00, 0x04, 0x20,
        },
        Sha3_224 => .{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
            0x00, 0x04, 0x1c,
        },
        Sha3_256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
            0x00, 0x04, 0x20,
        },
        Sha3_384 => .{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
            0x00, 0x04, 0x30,
        },
        Sha3_512 => .{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unsupported PKCS#1 v1.5 hash"),
    };
    const digest_info_len = digest_info_prefix.len + Hash.digest_length;
    if (modulus_len < digest_info_len + 11) return error.MessageTooLong;

    var encoded_message: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded_message);
    const encoded = encoded_message[0..modulus_len];
    encoded[0] = 0;
    encoded[1] = 1;
    const separator = modulus_len - digest_info_len - 1;
    @memset(encoded[2..separator], 0xff);
    encoded[separator] = 0;
    @memcpy(
        encoded[separator + 1 ..][0..digest_info_prefix.len],
        digest_info_prefix,
    );
    var digest: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    Hash.hash(message, &digest, .{});
    @memcpy(encoded[modulus_len - digest.len ..], &digest);

    const modulus = private_key.modulus;
    const representative = RsaFieldElement.fromBytes(
        modulus,
        encoded,
        .big,
    ) catch return error.MessageTooLong;
    var signature = try privateOperation(private_key, representative);
    defer std.crypto.secureZero(RsaFieldElement, (&signature)[0..1]);
    signature.toBytes(output[0..modulus_len], .big) catch
        return error.InvalidPrivateKey;
    return modulus_len;
}

fn validateKeyConsistency(
    private_key: *const PreparedPrivateKey,
) Error!void {
    const modulus = private_key.modulus;
    const message = RsaFieldElement.fromPrimitive(
        u8,
        modulus,
        @as(u8, 2),
    ) catch return error.InvalidPrivateKey;
    var signed = try privateOperation(private_key, message);
    defer std.crypto.secureZero(RsaFieldElement, (&signed)[0..1]);
    var full_exponent_result = modulus.powWithEncodedExponent(
        message,
        private_key.key.private_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(
        RsaFieldElement,
        (&full_exponent_result)[0..1],
    );
    if (!signed.eql(full_exponent_result)) return error.InvalidPrivateKey;
}

fn verifyPrivateResult1024Pair(
    private_key: *const PreparedPrivateKey,
    signature: RsaFieldElement,
    expected_residues: Montgomery1024.Pair,
) Error!void {
    // For canonical values below n = p*q, equality modulo both private primes
    // is equivalent to equality modulo n. Reduce the final recombined result,
    // not the pre-CRT residues, so recombination faults remain detectable.
    const first_context = if (private_key.prime1_1024) |*value|
        value
    else
        unreachable;
    const second_context = if (private_key.prime2_1024) |*value|
        value
    else
        unreachable;
    var signature_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &signature_bytes);
    signature.toBytes(&signature_bytes, .big) catch
        return error.InvalidPrivateKey;

    var signature_residues = Montgomery1024.reduceWidePair(
        first_context,
        second_context,
        &signature_bytes,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&signature_residues));
    var recovered = Montgomery1024.pow65537Pair(
        first_context,
        second_context,
        signature_residues,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&recovered));
    if (!Montgomery1024.equalLimbs(
        recovered.first,
        expected_residues.first,
    ) or !Montgomery1024.equalLimbs(
        recovered.second,
        expected_residues.second,
    )) {
        return error.InvalidPrivateKey;
    }
}

fn verifyPrivateResultGeneric(
    private_key: *const PreparedPrivateKey,
    signature: RsaFieldElement,
    expected: RsaFieldElement,
) Error!void {
    const modulus = private_key.modulus;
    var recovered = modulus.powWithEncodedPublicExponent(
        signature,
        private_key.key.public_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(RsaFieldElement, (&recovered)[0..1]);
    if (!recovered.eql(expected)) return error.InvalidPrivateKey;
}

fn privateOperation(
    private_key: *const PreparedPrivateKey,
    message: RsaFieldElement,
) Error!RsaFieldElement {
    const modulus = private_key.modulus;
    const p = private_key.prime1;
    const q = private_key.prime2;
    if (private_key.prime1_1024) |*first_context| {
        const second_context = if (private_key.prime2_1024) |*value|
            value
        else
            unreachable;
        var message_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &message_bytes);
        message.toBytes(&message_bytes, .big) catch
            return error.InvalidPrivateKey;
        var residues = Montgomery1024.reduceWidePair(
            first_context,
            second_context,
            &message_bytes,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&residues));
        var powered = try Montgomery1024.powSecretPair(
            first_context,
            second_context,
            residues,
            private_key.key.exponent1,
            private_key.key.exponent2,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&powered));
        var recombined = try first_context.crtRecombine(
            powered.first,
            powered.second,
            private_key.key.prime2,
            private_key.key.coefficient,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&recombined));
        var encoded: [2 * Montgomery1024.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &encoded);
        Montgomery1024.encodeWide(recombined, &encoded);
        const signature = RsaFieldElement.fromBytes(modulus, &encoded, .big) catch
            return error.InvalidPrivateKey;
        if (std.mem.eql(u8, private_key.key.public_exponent, "\x01\x00\x01")) {
            try verifyPrivateResult1024Pair(
                private_key,
                signature,
                residues,
            );
        } else {
            @branchHint(.unlikely);
            try verifyPrivateResultGeneric(private_key, signature, message);
        }
        return signature;
    }

    const message_mod_p = p.reduce(message.v);
    const message_mod_q = q.reduce(message.v);
    var m1 = p.powWithEncodedExponent(
        message_mod_p,
        private_key.key.exponent1,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(PrimeFieldElement, (&m1)[0..1]);
    var m2 = q.powWithEncodedExponent(
        message_mod_q,
        private_key.key.exponent2,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(PrimeFieldElement, (&m2)[0..1]);

    const m2_mod_p = p.reduce(m2.v);
    var h = p.mul(
        p.sub(m1, m2_mod_p),
        private_key.q_inverse_mod_p,
    );
    defer std.crypto.secureZero(PrimeFieldElement, (&h)[0..1]);

    var h_bytes: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &h_bytes);
    h.toBytes(h_bytes[0..private_key.key.prime1.len], .big) catch
        return error.InvalidPrivateKey;
    const h_full = RsaFieldElement.fromBytes(
        modulus,
        h_bytes[0..private_key.key.prime1.len],
        .big,
    ) catch return error.InvalidPrivateKey;
    var m2_bytes: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &m2_bytes);
    m2.toBytes(m2_bytes[0..private_key.key.prime2.len], .big) catch
        return error.InvalidPrivateKey;
    const m2_full = RsaFieldElement.fromBytes(
        modulus,
        m2_bytes[0..private_key.key.prime2.len],
        .big,
    ) catch return error.InvalidPrivateKey;
    const signature = modulus.add(
        modulus.mul(private_key.q_full, h_full),
        m2_full,
    );
    try verifyPrivateResultGeneric(private_key, signature, message);
    return signature;
}

fn mgf1Xor(
    comptime Hash: type,
    output: []u8,
    seed: *const [Hash.digest_length]u8,
) void {
    var digest: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    var counter: u32 = 0;
    var offset: usize = 0;
    while (offset < output.len) : (counter += 1) {
        var hasher = Hash.init(.{});
        hasher.update(seed);
        var encoded_counter: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded_counter, counter, .big);
        hasher.update(&encoded_counter);
        hasher.final(&digest);
        const take = @min(digest.len, output.len - offset);
        for (output[offset..][0..take], digest[0..take]) |*byte, mask| {
            byte.* ^= mask;
        }
        offset += take;
    }
}

fn shakeXor(
    comptime Hash: type,
    output: []u8,
    seed: []const u8,
) void {
    var mask: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &mask);
    var xof = Hash.init(.{});
    xof.update(seed);
    xof.final(mask[0..output.len]);
    for (output, mask[0..output.len]) |*byte, mask_byte| {
        byte.* ^= mask_byte;
    }
}

fn positiveInteger(element: Element) ![]const u8 {
    if (element.tag != 0x02 or element.value.len == 0 or
        (element.value[0] & 0x80) != 0)
    {
        return error.InvalidPrivateKey;
    }
    if (element.value.len > 1 and element.value[0] == 0) {
        if ((element.value[1] & 0x80) == 0) {
            return error.InvalidPrivateKey;
        }
        return element.value[1..];
    }
    if (element.value.len == 1 and element.value[0] == 0) {
        return error.InvalidPrivateKey;
    }
    return element.value;
}

fn stripUnsignedPadding(value: []const u8) []const u8 {
    var offset: usize = 0;
    while (offset < value.len and value[offset] == 0) : (offset += 1) {}
    return value[offset..];
}

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |a_byte, b_byte| difference |= a_byte ^ b_byte;
    return difference == 0;
}

const Element = struct {
    tag: u8,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn require(self: *Reader, tag: u8) !Element {
        const element = (try self.next()) orelse
            return error.InvalidPrivateKey;
        if (element.tag != tag) return error.InvalidPrivateKey;
        return element;
    }

    fn next(self: *Reader) !?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidPrivateKey;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidPrivateKey;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidPrivateKey;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidPrivateKey;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidPrivateKey;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidPrivateKey;
        }
        if (length > self.bytes.len - self.offset) {
            return error.InvalidPrivateKey;
        }
        const start = self.offset;
        self.offset += length;
        return .{ .tag = tag, .value = self.bytes[start..self.offset] };
    }

    fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

fn expectMontgomeryPower(
    specialized: *const Montgomery1024,
    generic: PrimeModulus,
    exponent: []const u8,
    base: *const [Montgomery1024.encoded_length]u8,
) !void {
    const generic_base = try PrimeFieldElement.fromBytes(generic, base, .big);
    var expected = try generic.powWithEncodedExponent(
        generic_base,
        exponent,
        .big,
    );
    defer std.crypto.secureZero(PrimeFieldElement, (&expected)[0..1]);
    var expected_bytes: [Montgomery1024.encoded_length]u8 = undefined;
    try expected.toBytes(&expected_bytes, .big);

    var actual = try specialized.powSecret(base, exponent);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
    var actual_bytes: [Montgomery1024.encoded_length]u8 = undefined;
    Montgomery1024.encode(actual, &actual_bytes);
    try std.testing.expectEqualSlices(u8, &expected_bytes, &actual_bytes);
}

fn testMontgomeryProducts(modulus_bytes: []const u8) !void {
    const specialized = try Montgomery1024.init(modulus_bytes);
    const generic = try PrimeModulus.fromBytes(modulus_bytes, .big);
    var state: u64 = 0x6a09e667f3bcc909;
    for (0..64) |_| {
        var a_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        var b_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        for (&a_bytes, &b_bytes) |*a_byte, *b_byte| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            a_byte.* = @truncate(state);
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b_byte.* = @truncate(state);
        }
        a_bytes[0] &= 0x7f;
        b_bytes[0] &= 0x7f;

        const generic_a = try PrimeFieldElement.fromBytes(
            generic,
            &a_bytes,
            .big,
        );
        const generic_b = try PrimeFieldElement.fromBytes(
            generic,
            &b_bytes,
            .big,
        );
        var expected = generic.mul(generic_a, generic_b);
        defer std.crypto.secureZero(
            PrimeFieldElement,
            (&expected)[0..1],
        );
        var expected_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        try expected.toBytes(&expected_bytes, .big);

        const a = specialized.toMontgomery(Montgomery1024.decode(&a_bytes));
        const b = specialized.toMontgomery(Montgomery1024.decode(&b_bytes));
        const integrated_product = specialized.mul(a, b);
        const product_then_reduce = specialized.mulProduct(a, b);
        try std.testing.expectEqualSlices(
            u64,
            &product_then_reduce,
            &integrated_product,
        );
        var actual = specialized.fromMontgomery(integrated_product);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
        var actual_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        Montgomery1024.encode(actual, &actual_bytes);
        try std.testing.expectEqualSlices(u8, &expected_bytes, &actual_bytes);
    }
}

fn testMontgomeryPrime(modulus_bytes: []const u8, exponent: []const u8) !void {
    const specialized = try Montgomery1024.init(modulus_bytes);
    const generic = try PrimeModulus.fromBytes(modulus_bytes, .big);

    var zero = [_]u8{0} ** Montgomery1024.encoded_length;
    try expectMontgomeryPower(&specialized, generic, exponent, &zero);
    zero[zero.len - 1] = 1;
    try expectMontgomeryPower(&specialized, generic, exponent, &zero);

    var patterned = [_]u8{0x5a} ** Montgomery1024.encoded_length;
    patterned[0] &= 0x7f;
    try expectMontgomeryPower(&specialized, generic, exponent, &patterned);

    var modulus_minus_one = [_]u8{0} ** Montgomery1024.encoded_length;
    @memcpy(
        modulus_minus_one[modulus_minus_one.len - modulus_bytes.len ..],
        modulus_bytes,
    );
    var index = modulus_minus_one.len;
    while (index != 0) {
        index -= 1;
        if (modulus_minus_one[index] != 0) {
            modulus_minus_one[index] -= 1;
            break;
        }
        modulus_minus_one[index] = 0xff;
    }
    try expectMontgomeryPower(
        &specialized,
        generic,
        exponent,
        &modulus_minus_one,
    );
}

fn testMontgomeryWideReduction(key: PrivateKey) !void {
    const first_context = try Montgomery1024.init(key.prime1);
    const second_context = try Montgomery1024.init(key.prime2);
    const modulus = try RsaModulus.fromBytes(key.modulus, .big);
    const first_modulus = try PrimeModulus.fromBytes(key.prime1, .big);
    const second_modulus = try PrimeModulus.fromBytes(key.prime2, .big);
    var state: u64 = 0xbb67ae8584caa73b;

    for (0..64) |_| {
        var encoded: [2 * Montgomery1024.encoded_length]u8 = undefined;
        for (&encoded) |*byte| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            byte.* = @truncate(state);
        }
        encoded[0] &= 0x7f;
        const value = try RsaFieldElement.fromBytes(modulus, &encoded, .big);
        var first_expected = first_modulus.reduce(value.v);
        defer std.crypto.secureZero(
            PrimeFieldElement,
            (&first_expected)[0..1],
        );
        var second_expected = second_modulus.reduce(value.v);
        defer std.crypto.secureZero(
            PrimeFieldElement,
            (&second_expected)[0..1],
        );
        var first_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        try first_expected.toBytes(&first_bytes, .big);
        var second_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        try second_expected.toBytes(&second_bytes, .big);

        var actual = Montgomery1024.reduceWidePair(
            &first_context,
            &second_context,
            &encoded,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
        var actual_first: [Montgomery1024.encoded_length]u8 = undefined;
        Montgomery1024.encode(actual.first, &actual_first);
        var actual_second: [Montgomery1024.encoded_length]u8 = undefined;
        Montgomery1024.encode(actual.second, &actual_second);
        try std.testing.expectEqualSlices(u8, &first_bytes, &actual_first);
        try std.testing.expectEqualSlices(u8, &second_bytes, &actual_second);
    }
}

fn testMontgomeryPublic65537(modulus_bytes: []const u8) !void {
    const specialized = try Montgomery2048.init(modulus_bytes);
    const generic = RsaModulus.fromBytes(modulus_bytes, .big) catch
        return error.InvalidPrivateKey;
    var inputs = [_][Montgomery2048.encoded_length]u8{
        [_]u8{0} ** Montgomery2048.encoded_length,
        [_]u8{0} ** Montgomery2048.encoded_length,
        [_]u8{0x5a} ** Montgomery2048.encoded_length,
        [_]u8{0x7f} ** Montgomery2048.encoded_length,
    };
    inputs[1][inputs[1].len - 1] = 1;
    for (inputs) |encoded| {
        const generic_base = RsaFieldElement.fromBytes(
            generic,
            &encoded,
            .big,
        ) catch return error.InvalidPrivateKey;
        var expected = generic.powWithEncodedPublicExponent(
            generic_base,
            "\x01\x00\x01",
            .big,
        ) catch return error.InvalidPrivateKey;
        defer std.crypto.secureZero(RsaFieldElement, (&expected)[0..1]);
        var expected_bytes: [Montgomery2048.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected_bytes);
        expected.toBytes(&expected_bytes, .big) catch
            return error.InvalidPrivateKey;

        var actual = specialized.pow65537(Montgomery2048.decode(&encoded));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
        var actual_bytes: [Montgomery2048.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &actual_bytes);
        Montgomery2048.encode(actual, &actual_bytes);
        try std.testing.expectEqualSlices(u8, &expected_bytes, &actual_bytes);
    }
}

fn testMontgomeryPairFios(
    first_context: *const Montgomery1024,
    second_context: *const Montgomery1024,
) !void {
    var first_boundary = first_context.modulus;
    first_boundary[0] -= 1;
    var second_boundary = second_context.modulus;
    second_boundary[0] -= 1;
    const boundary_cios = Montgomery1024.mulPair(
        first_context,
        second_context,
        first_boundary,
        second_boundary,
        first_boundary,
        second_boundary,
    );
    var boundary_multiply_workspace = Montgomery1024.PairWorkspace{};
    defer boundary_multiply_workspace.clear();
    var boundary_product_workspace = Montgomery1024.ProductPairWorkspace{};
    defer boundary_product_workspace.clear();
    const boundary_optimized = Montgomery1024.mulPairOptimizedWithWorkspaces(
        first_context,
        second_context,
        &boundary_multiply_workspace,
        &boundary_product_workspace,
        first_boundary,
        second_boundary,
        first_boundary,
        second_boundary,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.first,
        &boundary_optimized.first,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.second,
        &boundary_optimized.second,
    );
    const boundary_square = Montgomery1024.squarePairWithWorkspaces(
        first_context,
        second_context,
        &boundary_multiply_workspace,
        &boundary_product_workspace,
        first_boundary,
        second_boundary,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.first,
        &boundary_square.first,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.second,
        &boundary_square.second,
    );

    var state: u64 = 0x9e37_79b9_7f4a_7c15;
    for (0..64) |_| {
        var encoded: [4][Montgomery1024.encoded_length]u8 = undefined;
        for (&encoded) |*value| {
            for (value) |*byte| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                byte.* = @truncate(state);
            }
            value[0] &= 0x7f;
        }
        const first_a = Montgomery1024.decode(&encoded[0]);
        const second_a = Montgomery1024.decode(&encoded[1]);
        const first_b = Montgomery1024.decode(&encoded[2]);
        const second_b = Montgomery1024.decode(&encoded[3]);
        const cios = Montgomery1024.mulPair(
            first_context,
            second_context,
            first_a,
            second_a,
            first_b,
            second_b,
        );
        const fios = Montgomery1024.mulPairFios(
            first_context,
            second_context,
            first_a,
            second_a,
            first_b,
            second_b,
        );
        try std.testing.expectEqualSlices(u64, &cios.first, &fios.first);
        try std.testing.expectEqualSlices(u64, &cios.second, &fios.second);
        var multiply_workspace = Montgomery1024.PairWorkspace{};
        defer multiply_workspace.clear();
        var product_workspace = Montgomery1024.ProductPairWorkspace{};
        defer product_workspace.clear();
        const optimized = Montgomery1024.mulPairOptimizedWithWorkspaces(
            first_context,
            second_context,
            &multiply_workspace,
            &product_workspace,
            first_a,
            second_a,
            first_b,
            second_b,
        );
        try std.testing.expectEqualSlices(
            u64,
            &cios.first,
            &optimized.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &cios.second,
            &optimized.second,
        );
        const square = Montgomery1024.squarePairWithWorkspaces(
            first_context,
            second_context,
            &multiply_workspace,
            &product_workspace,
            first_a,
            second_a,
        );
        const square_cios = Montgomery1024.mulPair(
            first_context,
            second_context,
            first_a,
            second_a,
            first_a,
            second_a,
        );
        try std.testing.expectEqualSlices(
            u64,
            &square_cios.first,
            &square.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &square_cios.second,
            &square.second,
        );

        const first_extra: u64 = encoded[0][0] & 1;
        const second_extra: u64 = encoded[1][0] & 1;
        const reduced_pair = Montgomery1024.reduceLimbsPair(
            first_context,
            second_context,
            first_a,
            second_a,
            first_extra,
            second_extra,
        );
        const first_reduced = first_context.reduceLimbs(
            first_a,
            first_extra,
        );
        const second_reduced = second_context.reduceLimbs(
            second_a,
            second_extra,
        );
        try std.testing.expectEqualSlices(
            u64,
            &first_reduced,
            &reduced_pair.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &second_reduced,
            &reduced_pair.second,
        );
    }
}

test "RSA-2048 paired table selection covers every index" {
    var first_table: [32]Montgomery1024.Limbs = undefined;
    var second_table: [32]Montgomery1024.Limbs = undefined;
    for (0..first_table.len) |entry_index| {
        for (0..Montgomery1024.limb_count) |limb_index| {
            const value = (@as(u64, entry_index) << 32) | limb_index;
            first_table[entry_index][limb_index] = value;
            second_table[entry_index][limb_index] = ~value;
        }
    }
    for (0..first_table.len) |first_index| {
        const second_index = second_table.len - 1 - first_index;
        const selected = Montgomery1024.selectTablePair(
            first_table.len,
            &first_table,
            &second_table,
            @intCast(first_index),
            @intCast(second_index),
        );
        try std.testing.expectEqualSlices(
            u64,
            &first_table[first_index],
            &selected.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &second_table[second_index],
            &selected.second,
        );
    }
}

test "RSA-2048 Montgomery exponentiation matches the generic finite field" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    try testMontgomeryWideReduction(key);
    try testMontgomeryProducts(key.prime1);
    try testMontgomeryProducts(key.prime2);
    try testMontgomeryPrime(key.prime1, key.exponent1);
    try testMontgomeryPrime(key.prime2, key.exponent2);
    try testMontgomeryPublic65537(key.modulus);

    const first_context = try Montgomery1024.init(key.prime1);
    const second_context = try Montgomery1024.init(key.prime2);
    try testMontgomeryPairFios(&first_context, &second_context);
    var first_base = [_]u8{0x36} ** Montgomery1024.encoded_length;
    var second_base = [_]u8{0x5c} ** Montgomery1024.encoded_length;
    first_base[0] &= 0x7f;
    second_base[0] &= 0x7f;
    var base_pair = Montgomery1024.Pair{
        .first = Montgomery1024.decode(&first_base),
        .second = Montgomery1024.decode(&second_base),
    };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&base_pair));
    var paired = try Montgomery1024.powSecretPair(
        &first_context,
        &second_context,
        base_pair,
        key.exponent1,
        key.exponent2,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&paired));
    var first_independent = try first_context.powSecret(
        &first_base,
        key.exponent1,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&first_independent));
    var second_independent = try second_context.powSecret(
        &second_base,
        key.exponent2,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&second_independent));
    try std.testing.expectEqualSlices(
        u64,
        &first_independent,
        &paired.first,
    );
    try std.testing.expectEqualSlices(
        u64,
        &second_independent,
        &paired.second,
    );

    var public_pair = Montgomery1024.pow65537Pair(
        &first_context,
        &second_context,
        base_pair,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&public_pair));
    var first_public = try first_context.powSecret(
        &first_base,
        "\x01\x00\x01",
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&first_public));
    var second_public = try second_context.powSecret(
        &second_base,
        "\x01\x00\x01",
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&second_public));
    try std.testing.expectEqualSlices(u64, &first_public, &public_pair.first);
    try std.testing.expectEqualSlices(u64, &second_public, &public_pair.second);
}

test "RSA-2048 paired-prime fault check rejects a corrupted result" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const message = RsaFieldElement.fromPrimitive(
        u8,
        prepared.modulus,
        42,
    ) catch return error.InvalidPrivateKey;
    var message_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &message_bytes);
    message.toBytes(&message_bytes, .big) catch
        return error.InvalidPrivateKey;
    const first_context = if (prepared.prime1_1024) |*value|
        value
    else
        unreachable;
    const second_context = if (prepared.prime2_1024) |*value|
        value
    else
        unreachable;
    var expected_residues = Montgomery1024.reduceWidePair(
        first_context,
        second_context,
        &message_bytes,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&expected_residues));

    var signature = try privateOperation(&prepared, message);
    defer std.crypto.secureZero(RsaFieldElement, (&signature)[0..1]);
    try verifyPrivateResult1024Pair(&prepared, signature, expected_residues);
    var corrupted_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &corrupted_bytes);
    signature.toBytes(&corrupted_bytes, .big) catch
        return error.InvalidPrivateKey;
    corrupted_bytes[corrupted_bytes.len - 1] ^= 1;
    const corrupted = RsaFieldElement.fromBytes(
        prepared.modulus,
        &corrupted_bytes,
        .big,
    ) catch return error.InvalidPrivateKey;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        verifyPrivateResult1024Pair(&prepared, corrupted, expected_residues),
    );
}

test "PKCS1 and PKCS8 RSA keys produce verifiable PSS signatures" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs1 = decodeHex(vectors.private_key_pkcs1_hex);
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key1 = try PrivateKey.fromDer(&pkcs1);
    const key8 = try PrivateKey.fromDer(&pkcs8);
    try std.testing.expectEqual(@as(usize, 2048), key1.modulusBits());
    try std.testing.expectEqualSlices(u8, key1.modulus, key8.modulus);
    try std.testing.expectEqualSlices(
        u8,
        key1.private_exponent,
        key8.private_exponent,
    );

    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const public_parts = try std.crypto.Certificate.rsa.PublicKey.parseDer(
        certificate.pubKey(),
    );
    try std.testing.expect(key1.matchesPublicKey(
        public_parts.modulus,
        public_parts.exponent,
    ));
    const public_key = try std.crypto.Certificate.rsa.PublicKey.fromBytes(
        public_parts.exponent,
        public_parts.modulus,
    );
    const prepared_public = try PreparedPublicKey.init(
        public_parts.exponent,
        public_parts.modulus,
    );
    const message = "pure Zig RSA-PSS signing";

    inline for (.{
        .{ Sha224, &([_]u8{0x11} ** Sha224.digest_length) },
        .{ Sha256, &([_]u8{0x21} ** Sha256.digest_length) },
        .{ Sha384, &([_]u8{0x31} ** Sha384.digest_length) },
        .{ Sha512, &([_]u8{0x41} ** Sha512.digest_length) },
    }) |case| {
        const Hash = case[0];
        const salt = case[1];
        var signature: [512]u8 = undefined;
        const signature_len = if (Hash == Sha224)
            try key8.signPssSha224(message, salt, &signature)
        else if (Hash == Sha256)
            try key8.signPssSha256(message, salt, &signature)
        else if (Hash == Sha384)
            try key8.signPssSha384(message, salt, &signature)
        else
            try key8.signPssSha512(message, salt, &signature);
        try std.testing.expectEqual(@as(usize, 256), signature_len);
        try std.crypto.Certificate.rsa.PSSSignature.verify(
            256,
            signature[0..256].*,
            message,
            public_key,
            Hash,
        );
        const parts = [_][]const u8{message};
        if (Hash == Sha224)
            try prepared_public.verifyPssSha224(&parts, signature[0..signature_len])
        else if (Hash == Sha256)
            try prepared_public.verifyPssSha256(&parts, signature[0..signature_len])
        else if (Hash == Sha384)
            try prepared_public.verifyPssSha384(&parts, signature[0..signature_len])
        else
            try prepared_public.verifyPssSha512(&parts, signature[0..signature_len]);
        signature[signature_len - 1] ^= 1;
        if (Hash == Sha224)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha224(&parts, signature[0..signature_len]),
            )
        else if (Hash == Sha256)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha256(&parts, signature[0..signature_len]),
            )
        else if (Hash == Sha384)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha384(&parts, signature[0..signature_len]),
            )
        else
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha512(&parts, signature[0..signature_len]),
            );
    }

    inline for (.{ Sha224, Sha256, Sha384, Sha512 }) |Hash| {
        var signature: [512]u8 = undefined;
        const signature_len = if (Hash == Sha224)
            try key8.signPkcs1v15Sha224(message, &signature)
        else if (Hash == Sha256)
            try key8.signPkcs1v15Sha256(message, &signature)
        else if (Hash == Sha384)
            try key8.signPkcs1v15Sha384(message, &signature)
        else
            try key8.signPkcs1v15Sha512(message, &signature);
        try std.testing.expectEqual(@as(usize, 256), signature_len);
        try std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(
            256,
            signature[0..256].*,
            message,
            public_key,
            Hash,
        );
        const parts = [_][]const u8{message};
        if (Hash == Sha224)
            try prepared_public.verifyPkcs1v15Sha224(
                &parts,
                signature[0..signature_len],
            )
        else if (Hash == Sha256)
            try prepared_public.verifyPkcs1v15Sha256(
                &parts,
                signature[0..signature_len],
            )
        else if (Hash == Sha384)
            try prepared_public.verifyPkcs1v15Sha384(
                &parts,
                signature[0..signature_len],
            )
        else
            try prepared_public.verifyPkcs1v15Sha512(
                &parts,
                signature[0..signature_len],
            );
        signature[signature_len - 1] ^= 1;
        if (Hash == Sha224)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha224(
                    &parts,
                    signature[0..signature_len],
                ),
            )
        else if (Hash == Sha256)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha256(
                    &parts,
                    signature[0..signature_len],
                ),
            )
        else if (Hash == Sha384)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha384(
                    &parts,
                    signature[0..signature_len],
                ),
            )
        else
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha512(
                    &parts,
                    signature[0..signature_len],
                ),
            );
        try std.testing.expectError(
            error.InvalidSignature,
            std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(
                256,
                signature[0..256].*,
                message,
                public_key,
                Hash,
            ),
        );
    }

    var malformed = pkcs1;
    malformed[6] = 1;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        PrivateKey.fromDer(&malformed),
    );
    var inconsistent = pkcs1;
    inconsistent[inconsistent.len - 1] ^= 1;
    const inconsistent_key = try PrivateKey.fromDer(&inconsistent);
    try std.testing.expectError(
        error.InvalidPrivateKey,
        inconsistent_key.prepare(),
    );
    var unused_signature: [512]u8 = undefined;
    try std.testing.expectError(
        error.InvalidSaltLength,
        key1.signPssSha256(message, &.{}, &unused_signature),
    );
}

test "RSA-PSS verification accepts OpenSSL's maximum salt length" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const certificate_der = decodeHex(vectors.certificate_hex);
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const public_parts = try std.crypto.Certificate.rsa.PublicKey.parseDer(
        certificate.pubKey(),
    );
    const prepared_public = try PreparedPublicKey.init(
        public_parts.exponent,
        public_parts.modulus,
    );
    const message = "vail RSA-PSS maximum-salt vector";
    const signature = decodeHex(vectors.pss_sha256_max_salt_signature_hex);
    const parts = [_][]const u8{message};

    // OpenSSL's default PSS salt length is the maximum permissible (222
    // bytes for RSA-2048/SHA-256). The strict verifier expects a
    // digest-length salt and rejects it; auto-salt verification accepts it.
    try std.testing.expectError(
        error.InvalidSignature,
        prepared_public.verifyPssSha256(&parts, &signature),
    );
    try prepared_public.verifyPssSha256AutoSalt(&parts, &signature);

    var tampered = signature;
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        prepared_public.verifyPssSha256AutoSalt(&parts, &tampered),
    );
}

test "RSA private keys sign SHA3 PSS and PKCS1 signatures" {
    const x509_signature = @import("../../x509/signature.zig");
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const message = "pure Zig RSA SHA3 signing";

    inline for (.{
        .{ Sha3_224, rsa_pss.Algorithm.rsa_pss_sha3_224, @as(u8, 0x52) },
        .{ Sha3_256, rsa_pss.Algorithm.rsa_pss_sha3_256, @as(u8, 0x62) },
        .{ Sha3_384, rsa_pss.Algorithm.rsa_pss_sha3_384, @as(u8, 0x72) },
        .{ Sha3_512, rsa_pss.Algorithm.rsa_pss_sha3_512, @as(u8, 0x82) },
    }) |case| {
        const Hash = case[0];
        const algorithm = case[1];
        const salt = [_]u8{case[2]} ** Hash.digest_length;
        var signature: [512]u8 = undefined;
        const pss_len = if (Hash == Sha3_224)
            try prepared.signPssSha3_224(message, &salt, &signature)
        else if (Hash == Sha3_256)
            try prepared.signPssSha3_256(message, &salt, &signature)
        else if (Hash == Sha3_384)
            try prepared.signPssSha3_384(message, &salt, &signature)
        else
            try prepared.signPssSha3_512(message, &salt, &signature);
        try std.testing.expectEqual(@as(usize, 256), pss_len);
        try x509_signature.verify(
            algorithm,
            certificate,
            message,
            signature[0..pss_len],
        );

        const pkcs1_algorithm: rsa_pss.Algorithm = if (Hash == Sha3_224)
            .rsa_pkcs1_sha3_224
        else if (Hash == Sha3_256)
            .rsa_pkcs1_sha3_256
        else if (Hash == Sha3_384)
            .rsa_pkcs1_sha3_384
        else
            .rsa_pkcs1_sha3_512;
        const pkcs1_len = if (Hash == Sha3_224)
            try prepared.signPkcs1v15Sha3_224(message, &signature)
        else if (Hash == Sha3_256)
            try prepared.signPkcs1v15Sha3_256(message, &signature)
        else if (Hash == Sha3_384)
            try prepared.signPkcs1v15Sha3_384(message, &signature)
        else
            try prepared.signPkcs1v15Sha3_512(message, &signature);
        try std.testing.expectEqual(@as(usize, 256), pkcs1_len);
        try x509_signature.verify(
            pkcs1_algorithm,
            certificate,
            message,
            signature[0..pkcs1_len],
        );
    }

    var one_shot_signature: [512]u8 = undefined;
    const one_shot_len = try key.signPssSha3_256(
        message,
        &([_]u8{0x92} ** Sha3_256.digest_length),
        &one_shot_signature,
    );
    try x509_signature.verify(
        .rsa_pss_sha3_256,
        certificate,
        message,
        one_shot_signature[0..one_shot_len],
    );
    _ = try key.signPkcs1v15Sha3_256(message, &one_shot_signature);
    try x509_signature.verify(
        .rsa_pkcs1_sha3_256,
        certificate,
        message,
        one_shot_signature[0..key.signatureLength()],
    );
}

test "RSA private keys sign SHA-512 truncated PSS and PKCS1 signatures" {
    const x509_signature = @import("../../x509/signature.zig");
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const message = "pure Zig RSA SHA-512 truncated signing";

    inline for (.{
        .{
            Sha512_224,
            rsa_pss.Algorithm.rsa_pss_sha512_224,
            rsa_pss.Algorithm.rsa_pkcs1_sha512_224,
            @as(u8, 0xa2),
        },
        .{
            Sha512_256,
            rsa_pss.Algorithm.rsa_pss_sha512_256,
            rsa_pss.Algorithm.rsa_pkcs1_sha512_256,
            @as(u8, 0xb2),
        },
    }) |case| {
        const Hash = case[0];
        const salt = [_]u8{case[3]} ** Hash.digest_length;
        var signature: [512]u8 = undefined;
        const pss_len = if (Hash == Sha512_224)
            try prepared.signPssSha512_224(message, &salt, &signature)
        else
            try prepared.signPssSha512_256(message, &salt, &signature);
        try x509_signature.verify(
            case[1],
            certificate,
            message,
            signature[0..pss_len],
        );

        const pkcs1_len = if (Hash == Sha512_224)
            try prepared.signPkcs1v15Sha512_224(message, &signature)
        else
            try prepared.signPkcs1v15Sha512_256(message, &signature);
        try x509_signature.verify(
            case[2],
            certificate,
            message,
            signature[0..pkcs1_len],
        );

        const one_shot_pss_len = if (Hash == Sha512_224)
            try key.signPssSha512_224(message, &salt, &signature)
        else
            try key.signPssSha512_256(message, &salt, &signature);
        try x509_signature.verify(
            case[1],
            certificate,
            message,
            signature[0..one_shot_pss_len],
        );

        const one_shot_pkcs1_len = if (Hash == Sha512_224)
            try key.signPkcs1v15Sha512_224(message, &signature)
        else
            try key.signPkcs1v15Sha512_256(message, &signature);
        try x509_signature.verify(
            case[2],
            certificate,
            message,
            signature[0..one_shot_pkcs1_len],
        );
    }
}

test "RSA private keys sign RFC 8692 PSS-SHAKE signatures" {
    const x509_signature = @import("../../x509/signature.zig");
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const message = "pure Zig RFC 8692 RSA-PSS-SHAKE signing";

    inline for (.{
        .{ Shake128, rsa_pss.Algorithm.rsa_pss_shake128, @as(u8, 0xc2) },
        .{ Shake256, rsa_pss.Algorithm.rsa_pss_shake256, @as(u8, 0xd2) },
    }) |case| {
        const Hash = case[0];
        const salt = [_]u8{case[2]} ** Hash.digest_length;
        var signature: [512]u8 = undefined;
        const signature_len = if (Hash == Shake128)
            try prepared.signPssShake128(message, &salt, &signature)
        else
            try prepared.signPssShake256(message, &salt, &signature);
        try x509_signature.verify(
            case[1],
            certificate,
            message,
            signature[0..signature_len],
        );
        signature[signature_len - 1] ^= 1;
        try std.testing.expectError(
            error.InvalidSignature,
            x509_signature.verify(
                case[1],
                certificate,
                message,
                signature[0..signature_len],
            ),
        );
    }

    var wrong_mgf_signature: [512]u8 = undefined;
    const wrong_mgf_len = try signPss(
        &prepared,
        Shake128,
        message,
        &([_]u8{0xc2} ** Shake128.digest_length),
        &wrong_mgf_signature,
    );
    try std.testing.expectError(
        error.InvalidSignature,
        x509_signature.verify(
            .rsa_pss_shake128,
            certificate,
            message,
            wrong_mgf_signature[0..wrong_mgf_len],
        ),
    );

    var signature: [512]u8 = undefined;
    const shake128_len = try key.signPssShake128(
        message,
        &([_]u8{0xe2} ** Shake128.digest_length),
        &signature,
    );
    try x509_signature.verify(
        .rsa_pss_shake128,
        certificate,
        message,
        signature[0..shake128_len],
    );
    const shake256_len = try key.signPssShake256(
        message,
        &([_]u8{0xf2} ** Shake256.digest_length),
        &signature,
    );
    try x509_signature.verify(
        .rsa_pss_shake256,
        certificate,
        message,
        signature[0..shake256_len],
    );
}

test "RFC 8692 PSS-only PKCS8 keys enforce their SHAKE profile" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const standard = decodeHex(vectors.private_key_pkcs8_hex);
    const rsa_algorithm = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    const shake_algorithm = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x06\x1e";
    const algorithm_offset = std.mem.indexOf(
        u8,
        &standard,
        rsa_algorithm,
    ) orelse return error.TestUnexpectedResult;
    var restricted: [standard.len - 3]u8 = undefined;
    @memcpy(restricted[0..algorithm_offset], standard[0..algorithm_offset]);
    @memcpy(
        restricted[algorithm_offset..][0..shake_algorithm.len],
        shake_algorithm,
    );
    @memcpy(
        restricted[algorithm_offset + shake_algorithm.len ..],
        standard[algorithm_offset + rsa_algorithm.len ..],
    );
    std.mem.writeInt(
        u16,
        restricted[2..4],
        @intCast(restricted.len - 4),
        .big,
    );

    const key = try PrivateKey.fromDer(&restricted);
    try std.testing.expect(key.pss_constraints.?.permits(.rsa_pss_shake128));
    try std.testing.expect(!key.pss_constraints.?.permits(.rsa_pss_shake256));
    var prepared = try key.prepare();
    defer prepared.deinit();
    const message = "RFC 8692 constrained private key";
    var signature: [512]u8 = undefined;
    _ = try prepared.signPssShake128(
        message,
        &([_]u8{0x71} ** Shake128.digest_length),
        &signature,
    );
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPssShake256(
            message,
            &([_]u8{0x72} ** Shake256.digest_length),
            &signature,
        ),
    );
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPkcs1v15Sha256(message, &signature),
    );
}

test "constrained RSA-PSS PKCS8 keys preserve signing restrictions" {
    const encoded = @embedFile(
        "../testdata/rsa-pss-constrained-private.pkcs8.der",
    );
    const key = try PrivateKey.fromDer(encoded);
    try std.testing.expect(key.pss_constraints != null);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const message = "constrained RSA-PSS private key";
    var signature: [512]u8 = undefined;
    const salt = [_]u8{0x84} ** Sha384.digest_length;
    const signature_len = try prepared.signPssSha384(
        message,
        &salt,
        &signature,
    );
    const public_key = try std.crypto.Certificate.rsa.PublicKey.fromBytes(
        key.public_exponent,
        key.modulus,
    );
    try std.crypto.Certificate.rsa.PSSSignature.verify(
        256,
        signature[0..256].*,
        message,
        public_key,
        Sha384,
    );
    try std.testing.expectEqual(@as(usize, 256), signature_len);
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPssSha256(
            message,
            &([_]u8{0x25} ** Sha256.digest_length),
            &signature,
        ),
    );
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPkcs1v15Sha384(message, &signature),
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
