//! TLS 1.2 cryptographic core for RFC 5246, RFC 5288, and RFC 7905.
//!
//! This module deliberately starts below the handshake state machine: it
//! provides the PRF, master-secret/key-block derivation, Finished values, and
//! stateful AEAD records needed by both client and server implementations.

const std = @import("std");
const prepared_aes_gcm = @import("../crypto/aes_gcm.zig");
const prepared_chacha = @import("../crypto/chacha20_poly1305.zig");
const record_fragment = @import("record_fragment.zig");
const tls_secret = @import("secret.zig");
const traffic_secrets = @import("traffic_secrets.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const record_version = [_]u8{ 0x03, 0x03 };
pub const header_len: usize = 5;
pub const tag_len: usize = 16;
pub const explicit_nonce_len: usize = 8;
pub const max_plaintext_len: usize = 1 << 14;
pub const max_key_len: usize = 32;
pub const max_iv_len: usize = 12;
pub const master_secret_len: usize = 48;
pub const finished_verify_data_len: usize = 12;
pub const max_record_len: usize =
    header_len + explicit_nonce_len + max_plaintext_len + tag_len;
pub const SealFragmentResult = record_fragment.SealResult;
pub const ExtractedSecrets = traffic_secrets.Extracted;

pub const Error = error{
    InvalidSecretLength,
    InvalidSessionHash,
    InvalidKeyLength,
    InvalidIvLength,
    InvalidRecord,
    InvalidPlaintextLength,
    InvalidCiphertextLength,
    UnsupportedContentType,
    AuthenticationFailed,
    SequenceExhausted,
    ConfidentialityLimitReached,
    InvalidExporterLabel,
    ExporterContextTooLong,
    InvalidSessionId,
    InvalidSessionLifetime,
    SessionExpired,
    SessionContextMismatch,
};

pub const max_session_id_len: usize = 32;
pub const max_session_alpn_len: usize = 255;

/// Allocation-free TLS 1.2 session state. The cached master secret is bound to
/// an application-defined server identity and the negotiated ALPN so callers
/// cannot accidentally resume it across virtual hosts or protocols.
pub const Session = struct {
    id_storage: [max_session_id_len]u8,
    id_len: u8,
    master_secret: [master_secret_len]u8,
    suite: Suite,
    identity_hash: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    alpn_storage: [max_session_alpn_len]u8,
    alpn_len: u8,
    created_at_seconds: u64,
    lifetime_seconds: u32,

    pub fn init(
        session_id: []const u8,
        suite: Suite,
        master_secret: [master_secret_len]u8,
        identity: []const u8,
        alpn_protocol: []const u8,
        created_at_seconds: u64,
        lifetime_seconds: u32,
    ) Error!Session {
        return initInternal(
            session_id,
            suite,
            master_secret,
            identity,
            alpn_protocol,
            created_at_seconds,
            lifetime_seconds,
            false,
        );
    }

    /// RFC 5077 tickets do not require the issuing ServerHello to allocate a
    /// session ID. A fresh non-empty signaling ID is generated when the ticket
    /// is offered for resumption.
    pub fn initForTicket(
        session_id: []const u8,
        suite: Suite,
        master_secret: [master_secret_len]u8,
        identity: []const u8,
        alpn_protocol: []const u8,
        created_at_seconds: u64,
        lifetime_seconds: u32,
    ) Error!Session {
        return initInternal(
            session_id,
            suite,
            master_secret,
            identity,
            alpn_protocol,
            created_at_seconds,
            lifetime_seconds,
            true,
        );
    }

    fn initInternal(
        session_id: []const u8,
        suite: Suite,
        master_secret: [master_secret_len]u8,
        identity: []const u8,
        alpn_protocol: []const u8,
        created_at_seconds: u64,
        lifetime_seconds: u32,
        allow_empty_id: bool,
    ) Error!Session {
        if ((!allow_empty_id and session_id.len == 0) or
            session_id.len > max_session_id_len)
        {
            return error.InvalidSessionId;
        }
        if (identity.len == 0) return error.SessionContextMismatch;
        if (alpn_protocol.len > max_session_alpn_len) {
            return error.SessionContextMismatch;
        }
        if (lifetime_seconds == 0) return error.InvalidSessionLifetime;
        var result = Session{
            .id_storage = [_]u8{0} ** max_session_id_len,
            .id_len = @intCast(session_id.len),
            .master_secret = master_secret,
            .suite = suite,
            .identity_hash = hashSessionIdentity(identity),
            .alpn_storage = [_]u8{0} ** max_session_alpn_len,
            .alpn_len = @intCast(alpn_protocol.len),
            .created_at_seconds = created_at_seconds,
            .lifetime_seconds = lifetime_seconds,
        };
        @memcpy(result.id_storage[0..session_id.len], session_id);
        @memcpy(result.alpn_storage[0..alpn_protocol.len], alpn_protocol);
        return result;
    }

    pub fn id(self: *const Session) []const u8 {
        return self.id_storage[0..self.id_len];
    }

    pub fn alpn(self: *const Session) []const u8 {
        return self.alpn_storage[0..self.alpn_len];
    }

    pub fn validate(
        self: *const Session,
        now_seconds: u64,
        identity: []const u8,
    ) Error!void {
        if (!std.crypto.timing_safe.eql(
            [std.crypto.hash.sha2.Sha256.digest_length]u8,
            self.identity_hash,
            hashSessionIdentity(identity),
        )) return error.SessionContextMismatch;
        if (now_seconds < self.created_at_seconds or
            now_seconds - self.created_at_seconds >= self.lifetime_seconds)
        {
            return error.SessionExpired;
        }
    }

    pub fn deinit(self: *Session) void {
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, &self.id_storage);
        std.crypto.secureZero(u8, &self.identity_hash);
        std.crypto.secureZero(u8, &self.alpn_storage);
        self.* = undefined;
    }
};

fn hashSessionIdentity(identity: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    var state = std.crypto.hash.sha2.Sha256.init(.{});
    state.update("vail tls12 session identity\x00");
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, identity.len, .big);
    state.update(&len);
    state.update(identity);
    state.final(&hash);
    return hash;
}

pub const PrfHash = enum {
    sha256,
    sha384,

    pub fn len(self: PrfHash) usize {
        return switch (self) {
            .sha256 => HmacSha256.mac_length,
            .sha384 => HmacSha384.mac_length,
        };
    }
};

pub const Suite = enum(u16) {
    ecdhe_ecdsa_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_rsa_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_chacha20_poly1305_sha256 = 0xcca8,
    ecdhe_ecdsa_chacha20_poly1305_sha256 = 0xcca9,

    pub fn fromWire(value: u16) ?Suite {
        return switch (value) {
            0xc02b => .ecdhe_ecdsa_aes_128_gcm_sha256,
            0xc02c => .ecdhe_ecdsa_aes_256_gcm_sha384,
            0xc02f => .ecdhe_rsa_aes_128_gcm_sha256,
            0xc030 => .ecdhe_rsa_aes_256_gcm_sha384,
            0xcca8 => .ecdhe_rsa_chacha20_poly1305_sha256,
            0xcca9 => .ecdhe_ecdsa_chacha20_poly1305_sha256,
            else => null,
        };
    }

    pub fn prfHash(self: Suite) PrfHash {
        return switch (self) {
            .ecdhe_ecdsa_aes_256_gcm_sha384,
            .ecdhe_rsa_aes_256_gcm_sha384,
            => .sha384,
            else => .sha256,
        };
    }

    pub fn transcriptHash(self: Suite) tls_secret.Hash {
        return switch (self.prfHash()) {
            .sha256 => .sha256,
            .sha384 => .sha384,
        };
    }

    pub fn keyLength(self: Suite) usize {
        return switch (self) {
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_128_gcm_sha256,
            => 16,
            else => 32,
        };
    }

    pub fn fixedIvLength(self: Suite) usize {
        return switch (self) {
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_ecdsa_aes_256_gcm_sha384,
            .ecdhe_rsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_256_gcm_sha384,
            => 4,
            .ecdhe_rsa_chacha20_poly1305_sha256,
            .ecdhe_ecdsa_chacha20_poly1305_sha256,
            => 12,
        };
    }

    pub fn usesExplicitNonce(self: Suite) bool {
        return self.fixedIvLength() == 4;
    }

    pub fn confidentialityLimit(self: Suite) u64 {
        return switch (self) {
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_ecdsa_aes_256_gcm_sha384,
            .ecdhe_rsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_256_gcm_sha384,
            => @as(u64, 1) << 24,
            .ecdhe_rsa_chacha20_poly1305_sha256,
            .ecdhe_ecdsa_chacha20_poly1305_sha256,
            => std.math.maxInt(u64),
        };
    }
};

pub const Endpoint = enum {
    client,
    server,
};

pub fn prf(
    hash: PrfHash,
    secret: []const u8,
    label: []const u8,
    seed: []const u8,
    output: []u8,
) void {
    prfParts(hash, secret, label, &.{seed}, output);
}

fn prfParts(
    hash: PrfHash,
    secret: []const u8,
    label: []const u8,
    seed_parts: []const []const u8,
    output: []u8,
) void {
    switch (hash) {
        .sha256 => pHashParts(
            HmacSha256,
            secret,
            label,
            seed_parts,
            output,
        ),
        .sha384 => pHashParts(
            HmacSha384,
            secret,
            label,
            seed_parts,
            output,
        ),
    }
}

/// RFC 5705 exporter for an established TLS 1.2 connection. `null` context
/// and an explicitly supplied empty context intentionally produce different
/// outputs because only the latter includes the two-byte context length.
pub fn exportKeyingMaterial(
    suite: Suite,
    master_secret: *const [master_secret_len]u8,
    client_random: [32]u8,
    server_random: [32]u8,
    label: []const u8,
    context: ?[]const u8,
    output: []u8,
) Error!void {
    if (isReservedExporterLabel(label)) return error.InvalidExporterLabel;
    var context_len: [2]u8 = undefined;
    var seed_parts: [4][]const u8 = undefined;
    seed_parts[0] = &client_random;
    seed_parts[1] = &server_random;
    const part_count: usize = if (context) |value| blk: {
        if (value.len > std.math.maxInt(u16)) {
            return error.ExporterContextTooLong;
        }
        std.mem.writeInt(u16, &context_len, @intCast(value.len), .big);
        seed_parts[2] = &context_len;
        seed_parts[3] = value;
        break :blk 4;
    } else 2;
    prfParts(
        suite.prfHash(),
        master_secret,
        label,
        seed_parts[0..part_count],
        output,
    );
}

pub fn deriveMasterSecret(
    suite: Suite,
    pre_master_secret: []const u8,
    client_random: [32]u8,
    server_random: [32]u8,
) [master_secret_len]u8 {
    var result: [master_secret_len]u8 = undefined;
    var seed: [64]u8 = undefined;
    seed[0..32].* = client_random;
    seed[32..64].* = server_random;
    prf(
        suite.prfHash(),
        pre_master_secret,
        "master secret",
        &seed,
        &result,
    );
    return result;
}

pub fn deriveExtendedMasterSecret(
    suite: Suite,
    pre_master_secret: []const u8,
    session_hash: []const u8,
) Error![master_secret_len]u8 {
    if (session_hash.len != suite.prfHash().len()) {
        return error.InvalidSessionHash;
    }
    var result: [master_secret_len]u8 = undefined;
    prf(
        suite.prfHash(),
        pre_master_secret,
        "extended master secret",
        session_hash,
        &result,
    );
    return result;
}

pub fn finishedVerifyData(
    suite: Suite,
    master_secret: *const [master_secret_len]u8,
    endpoint: Endpoint,
    handshake_hash: []const u8,
) Error![finished_verify_data_len]u8 {
    if (handshake_hash.len != suite.prfHash().len()) {
        return error.InvalidSessionHash;
    }
    var result: [finished_verify_data_len]u8 = undefined;
    prf(
        suite.prfHash(),
        master_secret,
        switch (endpoint) {
            .client => "client finished",
            .server => "server finished",
        },
        handshake_hash,
        &result,
    );
    return result;
}

pub const KeyPair = struct {
    client: Keys,
    server: Keys,

    pub fn deinit(self: *KeyPair) void {
        self.client.deinit();
        self.server.deinit();
        self.* = undefined;
    }
};

pub fn deriveKeyPair(
    suite: Suite,
    master_secret: *const [master_secret_len]u8,
    client_random: [32]u8,
    server_random: [32]u8,
) Error!KeyPair {
    const key_len = suite.keyLength();
    const iv_len = suite.fixedIvLength();
    const block_len = 2 * key_len + 2 * iv_len;
    var key_block: [2 * max_key_len + 2 * max_iv_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_block);
    var seed: [64]u8 = undefined;
    seed[0..32].* = server_random;
    seed[32..64].* = client_random;
    prf(
        suite.prfHash(),
        master_secret,
        "key expansion",
        &seed,
        key_block[0..block_len],
    );
    var offset: usize = 0;
    const client_key = key_block[offset..][0..key_len];
    offset += key_len;
    const server_key = key_block[offset..][0..key_len];
    offset += key_len;
    const client_iv = key_block[offset..][0..iv_len];
    offset += iv_len;
    const server_iv = key_block[offset..][0..iv_len];
    var client = try Keys.init(suite, client_key, client_iv);
    errdefer client.deinit();
    return .{
        .client = client,
        .server = try Keys.init(suite, server_key, server_iv),
    };
}

pub const Keys = struct {
    suite: Suite,
    key: [max_key_len]u8,
    fixed_iv: [max_iv_len]u8,
    aes_gcm: ?prepared_aes_gcm.Context = null,

    pub fn init(
        suite: Suite,
        key_bytes: []const u8,
        fixed_iv_bytes: []const u8,
    ) Error!Keys {
        if (key_bytes.len != suite.keyLength()) return error.InvalidKeyLength;
        if (fixed_iv_bytes.len != suite.fixedIvLength()) {
            return error.InvalidIvLength;
        }
        var result = Keys{
            .suite = suite,
            .key = [_]u8{0} ** max_key_len,
            .fixed_iv = [_]u8{0} ** max_iv_len,
        };
        @memcpy(result.key[0..key_bytes.len], key_bytes);
        @memcpy(result.fixed_iv[0..fixed_iv_bytes.len], fixed_iv_bytes);
        result.aes_gcm = switch (suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_128_gcm_sha256,
            => prepared_aes_gcm.Context.init128(result.key[0..16].*),
            .ecdhe_ecdsa_aes_256_gcm_sha384,
            .ecdhe_rsa_aes_256_gcm_sha384,
            => prepared_aes_gcm.Context.init256(result.key),
            .ecdhe_rsa_chacha20_poly1305_sha256,
            .ecdhe_ecdsa_chacha20_poly1305_sha256,
            => null,
        };
        return result;
    }

    pub fn deinit(self: *Keys) void {
        if (self.aes_gcm) |*context| context.deinit();
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.fixed_iv);
        self.* = undefined;
    }

    pub fn seal(
        self: *const Keys,
        sequence_number: u64,
        content_type: u8,
        plaintext: []const u8,
        output: []u8,
    ) Error!usize {
        if (!validContentType(content_type)) {
            return error.UnsupportedContentType;
        }
        if (plaintext.len > max_plaintext_len) {
            return error.InvalidPlaintextLength;
        }
        const explicit_len = if (self.suite.usesExplicitNonce())
            explicit_nonce_len
        else
            0;
        const fragment_len = explicit_len + plaintext.len + tag_len;
        const total_len = header_len + fragment_len;
        if (output.len < total_len) return error.InvalidCiphertextLength;
        output[0] = content_type;
        output[1..3].* = record_version;
        std.mem.writeInt(u16, output[3..5], @intCast(fragment_len), .big);
        const ciphertext = output[header_len + explicit_len ..][0..plaintext.len];
        const tag = output[header_len + explicit_len + plaintext.len ..][0..tag_len];
        const additional_data = recordAdditionalData(
            sequence_number,
            content_type,
            @intCast(plaintext.len),
        );
        switch (self.suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_128_gcm_sha256,
            .ecdhe_ecdsa_aes_256_gcm_sha384,
            .ecdhe_rsa_aes_256_gcm_sha384,
            => {
                var explicit: [explicit_nonce_len]u8 = undefined;
                std.mem.writeInt(u64, &explicit, sequence_number, .big);
                @memcpy(output[header_len..][0..explicit_nonce_len], &explicit);
                var nonce: [12]u8 = undefined;
                nonce[0..4].* = self.fixed_iv[0..4].*;
                nonce[4..12].* = explicit;
                self.aes_gcm.?.encrypt(
                    ciphertext,
                    tag,
                    plaintext,
                    &additional_data,
                    nonce,
                );
            },
            .ecdhe_rsa_chacha20_poly1305_sha256,
            .ecdhe_ecdsa_chacha20_poly1305_sha256,
            => prepared_chacha.encrypt(
                ciphertext,
                tag,
                plaintext,
                &additional_data,
                xorSequence(self.fixed_iv, sequence_number),
                self.key,
            ),
        }
        return total_len;
    }

    pub fn open(
        self: *const Keys,
        sequence_number: u64,
        encoded: []const u8,
        plaintext: []u8,
    ) Error!Opened {
        if (encoded.len < header_len or
            !validContentType(encoded[0]) or
            !std.mem.eql(u8, encoded[1..3], &record_version))
        {
            return error.InvalidRecord;
        }
        const fragment_len = std.mem.readInt(u16, encoded[3..5], .big);
        if (fragment_len != encoded.len - header_len) {
            return error.InvalidRecord;
        }
        const explicit_len = if (self.suite.usesExplicitNonce())
            explicit_nonce_len
        else
            0;
        if (fragment_len < explicit_len + tag_len) {
            return error.InvalidRecord;
        }
        const ciphertext_len = fragment_len - explicit_len - tag_len;
        if (ciphertext_len > max_plaintext_len) return error.InvalidRecord;
        if (plaintext.len < ciphertext_len) {
            return error.InvalidPlaintextLength;
        }
        const ciphertext = encoded[header_len + explicit_len ..][0..ciphertext_len];
        const tag = encoded[header_len + explicit_len + ciphertext_len ..][0..tag_len].*;
        const additional_data = recordAdditionalData(
            sequence_number,
            encoded[0],
            @intCast(ciphertext_len),
        );
        switch (self.suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_128_gcm_sha256,
            .ecdhe_ecdsa_aes_256_gcm_sha384,
            .ecdhe_rsa_aes_256_gcm_sha384,
            => {
                var nonce: [12]u8 = undefined;
                nonce[0..4].* = self.fixed_iv[0..4].*;
                nonce[4..12].* = encoded[header_len..][0..8].*;
                self.aes_gcm.?.decrypt(
                    plaintext[0..ciphertext_len],
                    ciphertext,
                    tag,
                    &additional_data,
                    nonce,
                ) catch return error.AuthenticationFailed;
            },
            .ecdhe_rsa_chacha20_poly1305_sha256,
            .ecdhe_ecdsa_chacha20_poly1305_sha256,
            => prepared_chacha.decrypt(
                plaintext[0..ciphertext_len],
                ciphertext,
                tag,
                &additional_data,
                xorSequence(self.fixed_iv, sequence_number),
                self.key,
            ) catch return error.AuthenticationFailed,
        }
        return .{ .content_type = encoded[0], .len = ciphertext_len };
    }
};

pub const Opened = struct {
    content_type: u8,
    len: usize,
};

pub const TrafficState = struct {
    keys: Keys,
    next_sequence_number: u64 = 0,
    exhausted: bool = false,

    pub fn init(keys: Keys) TrafficState {
        return .{ .keys = keys };
    }

    pub fn deinit(self: *TrafficState) void {
        self.keys.deinit();
        self.* = undefined;
    }

    pub fn sequenceNumber(self: *const TrafficState) ?u64 {
        return if (self.exhausted) null else self.next_sequence_number;
    }

    pub fn extractedDirection(
        self: *const TrafficState,
    ) Error!traffic_secrets.Direction {
        const sequence = self.sequenceNumber() orelse
            return error.SequenceExhausted;
        const algorithm: traffic_secrets.Algorithm = switch (self.keys.suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_128_gcm_sha256,
            => .aes_128_gcm,
            .ecdhe_ecdsa_aes_256_gcm_sha384,
            .ecdhe_rsa_aes_256_gcm_sha384,
            => .aes_256_gcm,
            .ecdhe_rsa_chacha20_poly1305_sha256,
            .ecdhe_ecdsa_chacha20_poly1305_sha256,
            => .chacha20_poly1305,
        };
        var iv = [_]u8{0} ** 12;
        const fixed_iv_len = self.keys.suite.fixedIvLength();
        @memcpy(iv[0..fixed_iv_len], self.keys.fixed_iv[0..fixed_iv_len]);
        return traffic_secrets.Direction.init(
            sequence,
            0,
            algorithm,
            self.keys.key[0..self.keys.suite.keyLength()],
            &iv,
        ) catch unreachable;
    }

    pub fn seal(
        self: *TrafficState,
        content_type: u8,
        plaintext: []const u8,
        output: []u8,
    ) Error!usize {
        const sequence = try self.currentSequence(true);
        const len = try self.keys.seal(
            sequence,
            content_type,
            plaintext,
            output,
        );
        self.advance();
        return len;
    }

    /// Seal exactly one non-empty record containing at most
    /// `max_fragment_plaintext` bytes and report explicit caller progress.
    pub fn sealFragment(
        self: *TrafficState,
        content_type: u8,
        plaintext: []const u8,
        max_fragment_plaintext: usize,
        output: []u8,
    ) Error!SealFragmentResult {
        const fragment = try record_fragment.selectPlaintext(
            plaintext,
            max_fragment_plaintext,
            max_plaintext_len,
        );
        const written = try self.seal(content_type, fragment, output);
        return .{
            .plaintext_consumed = fragment.len,
            .output_written = written,
        };
    }

    pub fn open(
        self: *TrafficState,
        encoded: []const u8,
        plaintext: []u8,
    ) Error!Opened {
        const sequence = try self.currentSequence(false);
        const result = try self.keys.open(sequence, encoded, plaintext);
        self.advance();
        return result;
    }

    fn currentSequence(self: *const TrafficState, writing: bool) Error!u64 {
        if (self.exhausted) return error.SequenceExhausted;
        if (writing and
            self.next_sequence_number >= self.keys.suite.confidentialityLimit())
        {
            return error.ConfidentialityLimitReached;
        }
        return self.next_sequence_number;
    }

    fn advance(self: *TrafficState) void {
        if (self.next_sequence_number == std.math.maxInt(u64)) {
            self.exhausted = true;
        } else {
            self.next_sequence_number += 1;
        }
    }
};

/// Transfer both directions into an owned external record-layer key set.
/// Both sequence numbers are checked before either source state is destroyed.
pub fn extractTrafficSecrets(
    read: *TrafficState,
    write: *TrafficState,
) Error!traffic_secrets.Extracted {
    var tx = try write.extractedDirection();
    errdefer tx.deinit();
    const rx = try read.extractedDirection();
    write.deinit();
    read.deinit();
    return .{
        .version = .tls12,
        .tx = tx,
        .rx = rx,
    };
}

fn pHashParts(
    comptime Hmac: type,
    secret: []const u8,
    label: []const u8,
    seed_parts: []const []const u8,
    output: []u8,
) void {
    var a: [Hmac.mac_length]u8 = undefined;
    var a_mac = Hmac.init(secret);
    a_mac.update(label);
    for (seed_parts) |seed| a_mac.update(seed);
    a_mac.final(&a);
    defer std.crypto.secureZero(u8, &a);

    var offset: usize = 0;
    while (offset < output.len) {
        var block: [Hmac.mac_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &block);
        var output_mac = Hmac.init(secret);
        output_mac.update(&a);
        output_mac.update(label);
        for (seed_parts) |seed| output_mac.update(seed);
        output_mac.final(&block);
        const take = @min(block.len, output.len - offset);
        @memcpy(output[offset..][0..take], block[0..take]);
        offset += take;

        var next_a: [Hmac.mac_length]u8 = undefined;
        var next_a_mac = Hmac.init(secret);
        next_a_mac.update(&a);
        next_a_mac.final(&next_a);
        a = next_a;
    }
}

fn isReservedExporterLabel(label: []const u8) bool {
    return std.mem.eql(u8, label, "client finished") or
        std.mem.eql(u8, label, "server finished") or
        std.mem.eql(u8, label, "master secret") or
        std.mem.eql(u8, label, "key expansion");
}

fn recordAdditionalData(
    sequence_number: u64,
    content_type: u8,
    plaintext_len: u16,
) [13]u8 {
    var additional_data: [13]u8 = undefined;
    std.mem.writeInt(u64, additional_data[0..8], sequence_number, .big);
    additional_data[8] = content_type;
    additional_data[9..11].* = record_version;
    std.mem.writeInt(u16, additional_data[11..13], plaintext_len, .big);
    return additional_data;
}

fn xorSequence(iv: [max_iv_len]u8, sequence_number: u64) [max_iv_len]u8 {
    var nonce = iv;
    var encoded_sequence: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded_sequence, sequence_number, .big);
    for (encoded_sequence, 0..) |byte, index| {
        nonce[4 + index] ^= byte;
    }
    return nonce;
}

fn validContentType(value: u8) bool {
    return value == 20 or value == 21 or value == 22 or value == 23;
}

test "TLS 1.2 PRF matches the RFC 5246 SHA-256 vector" {
    var secret: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &secret,
        "9bbe436ba940f017b17652849a71db35",
    );
    var seed: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &seed,
        "a0ba9f936cda311827a6f796ffd5198c",
    );
    var expected: [100]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66",
    );
    var actual: [100]u8 = undefined;
    prf(.sha256, &secret, "test label", &seed, &actual);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "TLS 1.2 RFC 5705 exporter matches an independent HMAC oracle" {
    const master_secret = comptime blk: {
        var value: [master_secret_len]u8 = undefined;
        for (&value, 0..) |*byte, index| byte.* = @intCast(index);
        break :blk value;
    };
    const client_random = comptime blk: {
        var value: [32]u8 = undefined;
        for (&value, 0..) |*byte, index| byte.* = @intCast(0x10 + index);
        break :blk value;
    };
    const server_random = comptime blk: {
        var value: [32]u8 = undefined;
        for (&value, 0..) |*byte, index| byte.* = @intCast(0x40 + index);
        break :blk value;
    };
    var actual: [42]u8 = undefined;
    try exportKeyingMaterial(
        .ecdhe_rsa_aes_128_gcm_sha256,
        &master_secret,
        client_random,
        server_random,
        "EXPORTER-vail",
        "ctx",
        &actual,
    );
    var expected: [actual.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "d50f0ae5e40a1e97c40c946d62468a816c60b24bf9295286b9d2f5097e896cdb991889fbece8a070b968",
    );
    try std.testing.expectEqual(expected, actual);
    try std.testing.expectError(
        error.InvalidExporterLabel,
        exportKeyingMaterial(
            .ecdhe_rsa_aes_128_gcm_sha256,
            &master_secret,
            client_random,
            server_random,
            "master secret",
            null,
            &actual,
        ),
    );
}

test "TLS 1.2 sessions bind identity ALPN and lifetime" {
    var session = try Session.init(
        &.{ 1, 2, 3, 4 },
        .ecdhe_rsa_aes_128_gcm_sha256,
        [_]u8{0x41} ** master_secret_len,
        "server-a",
        "h2",
        100,
        60,
    );
    defer session.deinit();
    try session.validate(100, "server-a");
    try session.validate(159, "server-a");
    try std.testing.expectEqualStrings("h2", session.alpn());
    try std.testing.expectError(
        error.SessionExpired,
        session.validate(160, "server-a"),
    );
    try std.testing.expectError(
        error.SessionContextMismatch,
        session.validate(120, "server-b"),
    );
}

test "TLS 1.2 key blocks and AEAD records round trip" {
    const pre_master = [_]u8{0x31} ** 32;
    const client_random = [_]u8{0x32} ** 32;
    const server_random = [_]u8{0x33} ** 32;
    inline for ([_]Suite{
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        .ecdhe_rsa_aes_256_gcm_sha384,
        .ecdhe_rsa_chacha20_poly1305_sha256,
    }) |suite| {
        var master = deriveMasterSecret(
            suite,
            &pre_master,
            client_random,
            server_random,
        );
        defer std.crypto.secureZero(u8, &master);
        var pair = try deriveKeyPair(
            suite,
            &master,
            client_random,
            server_random,
        );
        defer pair.deinit();
        var sender = TrafficState.init(pair.client);
        defer sender.deinit();
        var receiver = TrafficState.init(try Keys.init(
            suite,
            sender.keys.key[0..suite.keyLength()],
            sender.keys.fixed_iv[0..suite.fixedIvLength()],
        ));
        defer receiver.deinit();

        var encoded: [max_record_len]u8 = undefined;
        const encoded_len = try sender.seal(23, "tls12 record", &encoded);
        var plaintext: [64]u8 = undefined;
        const opened = try receiver.open(encoded[0..encoded_len], &plaintext);
        try std.testing.expectEqual(@as(u8, 23), opened.content_type);
        try std.testing.expectEqualStrings(
            "tls12 record",
            plaintext[0..opened.len],
        );
        try std.testing.expectEqual(@as(?u64, 1), sender.sequenceNumber());
        try std.testing.expectEqual(@as(?u64, 1), receiver.sequenceNumber());

        encoded[encoded_len - 1] ^= 1;
        try std.testing.expectError(
            error.AuthenticationFailed,
            receiver.open(encoded[0..encoded_len], &plaintext),
        );
        try std.testing.expectEqual(@as(?u64, 1), receiver.sequenceNumber());
    }
}

test "TLS 1.2 traffic state seals bounded fragments without losing sequence" {
    const suite = Suite.ecdhe_rsa_aes_128_gcm_sha256;
    var sender = TrafficState.init(try Keys.init(
        suite,
        &([_]u8{0xa1} ** 16),
        &([_]u8{0xa2} ** 4),
    ));
    defer sender.deinit();
    var receiver = TrafficState.init(try Keys.init(
        suite,
        &([_]u8{0xa1} ** 16),
        &([_]u8{0xa2} ** 4),
    ));
    defer receiver.deinit();

    var encoded: [max_record_len]u8 = undefined;
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        sender.sealFragment(23, "", 5, &encoded),
    );
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        sender.sealFragment(23, "payload", 0, &encoded),
    );
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        sender.sealFragment(23, "payload", max_plaintext_len + 1, &encoded),
    );
    try std.testing.expectEqual(@as(?u64, 0), sender.sequenceNumber());
    try std.testing.expectError(
        error.InvalidCiphertextLength,
        sender.sealFragment(23, "payload", 5, encoded[0..1]),
    );
    try std.testing.expectEqual(@as(?u64, 0), sender.sequenceNumber());

    const payload = "TLS 1.2 fragmented application data";
    var plaintext: [max_plaintext_len]u8 = undefined;
    var offset: usize = 0;
    var record_count: u64 = 0;
    while (offset < payload.len) {
        const fragment = try sender.sealFragment(
            23,
            payload[offset..],
            5,
            &encoded,
        );
        try std.testing.expect(fragment.plaintext_consumed > 0);
        try std.testing.expect(fragment.plaintext_consumed <= 5);
        const opened = try receiver.open(
            encoded[0..fragment.output_written],
            &plaintext,
        );
        try std.testing.expectEqual(@as(u8, 23), opened.content_type);
        try std.testing.expectEqualStrings(
            payload[offset..][0..fragment.plaintext_consumed],
            plaintext[0..opened.len],
        );
        offset += fragment.plaintext_consumed;
        record_count += 1;
    }
    try std.testing.expectEqual(payload.len, offset);
    try std.testing.expectEqual(@as(?u64, record_count), sender.sequenceNumber());
    try std.testing.expectEqual(@as(?u64, record_count), receiver.sequenceNumber());
}

test "TLS 1.2 traffic states extract directional keys and nonce bases" {
    inline for (.{
        .{
            .suite = Suite.ecdhe_rsa_aes_128_gcm_sha256,
            .algorithm = traffic_secrets.Algorithm.aes_128_gcm,
        },
        .{
            .suite = Suite.ecdhe_rsa_aes_256_gcm_sha384,
            .algorithm = traffic_secrets.Algorithm.aes_256_gcm,
        },
        .{
            .suite = Suite.ecdhe_rsa_chacha20_poly1305_sha256,
            .algorithm = traffic_secrets.Algorithm.chacha20_poly1305,
        },
    }) |case| {
        const tx_key = [_]u8{0x61} ** max_key_len;
        const rx_key = [_]u8{0x71} ** max_key_len;
        const tx_iv = [_]u8{0x62} ** max_iv_len;
        const rx_iv = [_]u8{0x72} ** max_iv_len;
        var write = TrafficState.init(try Keys.init(
            case.suite,
            tx_key[0..case.suite.keyLength()],
            tx_iv[0..case.suite.fixedIvLength()],
        ));
        var read = TrafficState.init(try Keys.init(
            case.suite,
            rx_key[0..case.suite.keyLength()],
            rx_iv[0..case.suite.fixedIvLength()],
        ));
        write.next_sequence_number = 3;
        read.next_sequence_number = 7;

        var extracted = try extractTrafficSecrets(&read, &write);
        defer extracted.deinit();
        try std.testing.expectEqual(traffic_secrets.Version.tls12, extracted.version);
        try std.testing.expectEqual(@as(u64, 3), extracted.tx.sequence_number);
        try std.testing.expectEqual(@as(u64, 7), extracted.rx.sequence_number);
        try std.testing.expectEqual(@as(u64, 0), extracted.tx.generation);
        try std.testing.expectEqual(case.algorithm, extracted.tx.algorithm);
        try std.testing.expectEqual(case.algorithm, extracted.rx.algorithm);
        try std.testing.expectEqualSlices(
            u8,
            tx_key[0..case.suite.keyLength()],
            extracted.tx.key(),
        );
        try std.testing.expectEqualSlices(
            u8,
            rx_key[0..case.suite.keyLength()],
            extracted.rx.key(),
        );
        const iv_len = case.suite.fixedIvLength();
        try std.testing.expectEqualSlices(u8, tx_iv[0..iv_len], extracted.tx.iv[0..iv_len]);
        try std.testing.expectEqualSlices(u8, rx_iv[0..iv_len], extracted.rx.iv[0..iv_len]);
        if (case.suite.usesExplicitNonce()) {
            try std.testing.expectEqualSlices(
                u8,
                &([_]u8{0} ** explicit_nonce_len),
                extracted.tx.iv[iv_len..],
            );
            try std.testing.expectEqualSlices(
                u8,
                &([_]u8{0} ** explicit_nonce_len),
                extracted.rx.iv[iv_len..],
            );
        }
    }
}

test "TLS 1.2 traffic extraction is atomic when a sequence is exhausted" {
    const suite = Suite.ecdhe_rsa_aes_128_gcm_sha256;
    var write = TrafficState.init(try Keys.init(
        suite,
        &([_]u8{0x81} ** 16),
        &([_]u8{0x82} ** 4),
    ));
    defer write.deinit();
    var read = TrafficState.init(try Keys.init(
        suite,
        &([_]u8{0x91} ** 16),
        &([_]u8{0x92} ** 4),
    ));
    defer read.deinit();
    read.exhausted = true;
    try std.testing.expectError(
        error.SequenceExhausted,
        extractTrafficSecrets(&read, &write),
    );
    try std.testing.expectEqual(@as(?u64, 0), write.sequenceNumber());
    var output: [64]u8 = undefined;
    _ = try write.seal(23, "still owned", &output);
}

test "TLS 1.2 master secret EMS Finished and key block match OpenSSL" {
    const suite = Suite.ecdhe_rsa_aes_128_gcm_sha256;
    const pre_master = [_]u8{0x31} ** 32;
    const client_random = [_]u8{0x32} ** 32;
    const server_random = [_]u8{0x33} ** 32;
    var expected_master: [master_secret_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_master,
        "64afbd00c6d50fd5b8f320735bccea6a0e9f83149d2faefe09dcc42775b466ab479994b77ca17d111be1bd0e771052da",
    );
    var master = deriveMasterSecret(
        suite,
        &pre_master,
        client_random,
        server_random,
    );
    defer std.crypto.secureZero(u8, &master);
    try std.testing.expectEqualSlices(u8, &expected_master, &master);

    var pair = try deriveKeyPair(
        suite,
        &master,
        client_random,
        server_random,
    );
    defer pair.deinit();
    var expected_key_block: [40]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_key_block,
        "7cd9fe43f16e1b60ff59ac8487c85a51f880faf951ee53c791c30c7314a82cef8f101d9fb6f1b8e6",
    );
    try std.testing.expectEqualSlices(
        u8,
        expected_key_block[0..16],
        pair.client.key[0..16],
    );
    try std.testing.expectEqualSlices(
        u8,
        expected_key_block[16..32],
        pair.server.key[0..16],
    );
    try std.testing.expectEqualSlices(
        u8,
        expected_key_block[32..36],
        pair.client.fixed_iv[0..4],
    );
    try std.testing.expectEqualSlices(
        u8,
        expected_key_block[36..40],
        pair.server.fixed_iv[0..4],
    );

    const session_hash = [_]u8{0x34} ** 32;
    var extended_master = try deriveExtendedMasterSecret(
        suite,
        &pre_master,
        &session_hash,
    );
    defer std.crypto.secureZero(u8, &extended_master);
    var expected_extended_master: [master_secret_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_extended_master,
        "a9132706dc1da06a10a2f9e16f1d1228375e8138ae4d7c359c6f6ec2aeb5d05e3be19cf22fec6dd3a195d616c8277740",
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_extended_master,
        &extended_master,
    );
    const handshake_hash = [_]u8{0x35} ** 32;
    const finished = try finishedVerifyData(
        suite,
        &extended_master,
        .client,
        &handshake_hash,
    );
    var expected_finished: [finished_verify_data_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_finished,
        "3315f5da6df7252035068ab8",
    );
    try std.testing.expectEqualSlices(u8, &expected_finished, &finished);
}

test "TLS 1.2 traffic state enforces sequence and AEAD limits" {
    var keys = try Keys.init(
        .ecdhe_rsa_aes_128_gcm_sha256,
        &([_]u8{0x81} ** 16),
        &([_]u8{0x82} ** 4),
    );
    defer keys.deinit();
    var state = TrafficState.init(try Keys.init(
        .ecdhe_rsa_aes_128_gcm_sha256,
        &([_]u8{0x81} ** 16),
        &([_]u8{0x82} ** 4),
    ));
    defer state.deinit();
    state.next_sequence_number = state.keys.suite.confidentialityLimit();
    var output: [64]u8 = undefined;
    try std.testing.expectError(
        error.ConfidentialityLimitReached,
        state.seal(23, "blocked", &output),
    );
    try std.testing.expectEqual(
        state.keys.suite.confidentialityLimit(),
        state.sequenceNumber().?,
    );
    state.next_sequence_number = std.math.maxInt(u64);
    state.exhausted = true;
    try std.testing.expectError(
        error.SequenceExhausted,
        state.open(&.{}, &output),
    );
}

test "TLS 1.2 AEAD records match independent implementations" {
    const plaintext = "tls12 record";
    inline for (.{
        .{
            .suite = Suite.ecdhe_rsa_aes_128_gcm_sha256,
            .expected_hex = "170303002400000000000000076dd9b2bde4184006e5e8c48c2aecfc9ea289a3fe350c06034e8e4546",
        },
        .{
            .suite = Suite.ecdhe_rsa_chacha20_poly1305_sha256,
            .expected_hex = "170303001ce7c24b26e221148c081e2f7c9c5d47a0e8f2b01ba9265c041324588a",
        },
    }) |case| {
        const key_bytes = [_]u8{0x81} ** max_key_len;
        const iv_bytes = [_]u8{0x82} ** max_iv_len;
        var keys = try Keys.init(
            case.suite,
            key_bytes[0..case.suite.keyLength()],
            iv_bytes[0..case.suite.fixedIvLength()],
        );
        defer keys.deinit();
        var actual: [max_record_len]u8 = undefined;
        const actual_len = try keys.seal(7, 23, plaintext, &actual);
        var expected: [case.expected_hex.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case.expected_hex);
        try std.testing.expectEqualSlices(
            u8,
            &expected,
            actual[0..actual_len],
        );
    }
}
