//! Allocation-free RSA private-key operations for TLS signatures.
//!
//! PKCS#1 and unencrypted PKCS#8 DER keys are parsed as borrowed slices. RSA
//! exponentiation uses `std.crypto.ff`'s constant-time secret-exponent path and
//! PKCS#1 CRT parameters. Prepared keys cache Montgomery moduli so handshake
//! signing performs no heap allocation.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFieldElement = RsaModulus.Fe;
const PrimeModulus = std.crypto.ff.Modulus(2048);
const PrimeFieldElement = PrimeModulus.Fe;

const oid_rsa_encryption = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
};

pub const Error = error{
    InvalidPrivateKey,
    UnsupportedModulusBits,
    InvalidSaltLength,
    SignatureBufferTooSmall,
    MessageTooLong,
};

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
        };
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
    if (!std.mem.eql(u8, oid.value, &oid_rsa_encryption)) {
        return error.InvalidPrivateKey;
    }
    if (algorithm_fields.next() catch return error.InvalidPrivateKey) |params| {
        if (params.tag != 0x05 or params.value.len != 0 or
            !algorithm_fields.done())
        {
            return error.InvalidPrivateKey;
        }
    }
    const private_key = fields.require(0x04) catch
        return error.InvalidPrivateKey;
    if (!fields.done()) return error.InvalidPrivateKey;
    return PrivateKey.fromDer(private_key.value);
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
    if (salt.len != Hash.digest_length) return error.InvalidSaltLength;
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
    mgf1Xor(Hash, encoded[0..data_block_len], &final_hash);
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
    var recovered = modulus.powWithEncodedPublicExponent(
        signature,
        private_key.key.public_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(RsaFieldElement, (&recovered)[0..1]);
    if (!recovered.eql(representative)) return error.InvalidPrivateKey;
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
    var recovered = modulus.powWithEncodedPublicExponent(
        signed,
        private_key.key.public_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(RsaFieldElement, (&recovered)[0..1]);
    if (!recovered.eql(message)) return error.InvalidPrivateKey;
}

fn privateOperation(
    private_key: *const PreparedPrivateKey,
    message: RsaFieldElement,
) Error!RsaFieldElement {
    const modulus = private_key.modulus;
    const p = private_key.prime1;
    const q = private_key.prime2;
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
    return modulus.add(
        modulus.mul(private_key.q_full, h_full),
        m2_full,
    );
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

test "PKCS1 and PKCS8 RSA keys produce verifiable PSS signatures" {
    const vectors = @import("testdata/rsa_signing.zig");
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
    const message = "pure Zig RSA-PSS signing";

    inline for (.{
        .{ Sha256, &([_]u8{0x21} ** Sha256.digest_length) },
        .{ Sha384, &([_]u8{0x31} ** Sha384.digest_length) },
        .{ Sha512, &([_]u8{0x41} ** Sha512.digest_length) },
    }) |case| {
        const Hash = case[0];
        const salt = case[1];
        var signature: [512]u8 = undefined;
        const signature_len = if (Hash == Sha256)
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

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
