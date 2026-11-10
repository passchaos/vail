//! RFC 9180 HPKE base mode using the mandatory-to-implement ECH suite.
//!
//! This module implements DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
//! AES-128-GCM (`0x0020, 0x0001, 0x0001`). Contexts retain prepared AES-GCM
//! key material, use the full 96-bit sequence space, and allocate no memory.

const std = @import("std");
const aes_gcm = @import("../aead/aes_gcm.zig");
const X25519 = @import("x25519.zig").X25519;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = aes_gcm.Aes128Gcm;

pub const kem_id: u16 = 0x0020;
pub const kdf_id: u16 = 0x0001;
pub const aead_id: u16 = 0x0001;

pub const secret_key_len = X25519.secret_length;
pub const public_key_len = X25519.public_length;
pub const encapsulated_key_len = X25519.public_length;
pub const shared_secret_len = 32;
pub const key_len = Aes128Gcm.key_length;
pub const nonce_len = Aes128Gcm.nonce_length;
pub const tag_len = Aes128Gcm.tag_length;
pub const exporter_secret_len = 32;
pub const max_export_len = 255 * exporter_secret_len;

pub const SecretKey = [secret_key_len]u8;
pub const PublicKey = [public_key_len]u8;
pub const EncapsulatedKey = [encapsulated_key_len]u8;
pub const SharedSecret = [shared_secret_len]u8;

pub const Error = error{
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidBufferLength,
    MessageTooLong,
    MessageLimitReached,
    ExportLengthTooLarge,
    AuthenticationFailed,
};

const version_label = "HPKE-v1";
const kem_suite_id = [_]u8{ 'K', 'E', 'M', 0x00, 0x20 };
const hpke_suite_id = [_]u8{
    'H',  'P',  'K',  'E',
    0x00, 0x20, 0x00, 0x01,
    0x00, 0x01,
};
const max_aead_plaintext_len: u128 = 16 * ((@as(u128, 1) << 32) - 2);

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    pub fn generate(io: std.Io) KeyPair {
        while (true) {
            var secret_key: SecretKey = undefined;
            io.random(&secret_key);
            const public_key = X25519.recoverPublicKey(secret_key) catch {
                std.crypto.secureZero(u8, &secret_key);
                continue;
            };
            return .{
                .public_key = public_key,
                .secret_key = secret_key,
            };
        }
    }

    pub fn fromSecretKey(secret_key: *const SecretKey) Error!KeyPair {
        return .{
            .public_key = X25519.recoverPublicKey(secret_key.*) catch
                return error.InvalidSecretKey,
            .secret_key = secret_key.*,
        };
    }

    pub fn deinit(self: *KeyPair) void {
        std.crypto.secureZero(KeyPair, self[0..1]);
        self.* = undefined;
    }
};

pub const SenderSetup = struct {
    enc: EncapsulatedKey,
    context: SenderContext,

    pub fn deinit(self: *SenderSetup) void {
        self.context.deinit();
        self.* = undefined;
    }
};

pub const SenderContext = struct {
    state: Context,

    /// Writes `plaintext.len + tag_len` bytes to `ciphertext_and_tag`.
    pub fn seal(
        self: *SenderContext,
        ciphertext_and_tag: []u8,
        plaintext: []const u8,
        aad: []const u8,
    ) Error!void {
        return self.state.seal(ciphertext_and_tag, plaintext, aad);
    }

    pub fn exportSecret(
        self: *const SenderContext,
        output: []u8,
        exporter_context: []const u8,
    ) Error!void {
        return self.state.exportSecret(output, exporter_context);
    }

    pub fn deinit(self: *SenderContext) void {
        self.state.deinit();
        self.* = undefined;
    }
};

pub const ReceiverContext = struct {
    state: Context,

    /// Opens `ciphertext_and_tag` into a buffer exactly `tag_len` bytes shorter.
    pub fn open(
        self: *ReceiverContext,
        plaintext: []u8,
        ciphertext_and_tag: []const u8,
        aad: []const u8,
    ) Error!void {
        return self.state.open(plaintext, ciphertext_and_tag, aad);
    }

    pub fn exportSecret(
        self: *const ReceiverContext,
        output: []u8,
        exporter_context: []const u8,
    ) Error!void {
        return self.state.exportSecret(output, exporter_context);
    }

    pub fn deinit(self: *ReceiverContext) void {
        self.state.deinit();
        self.* = undefined;
    }
};

/// Creates an RFC 9180 base-mode sender context with a fresh ephemeral key.
pub fn setupBaseSender(
    io: std.Io,
    recipient_public_key: PublicKey,
    info: []const u8,
) Error!SenderSetup {
    var ephemeral = KeyPair.generate(io);
    defer ephemeral.deinit();
    return setupBaseSenderWithKeyPair(
        &ephemeral,
        recipient_public_key,
        info,
    );
}

/// Creates the matching RFC 9180 base-mode receiver context.
pub fn setupBaseReceiver(
    enc: EncapsulatedKey,
    recipient_secret_key: *const SecretKey,
    info: []const u8,
) Error!ReceiverContext {
    var recipient = try KeyPair.fromSecretKey(recipient_secret_key);
    defer recipient.deinit();
    return setupBaseReceiverWithKeyPair(enc, &recipient, info);
}

/// Creates a receiver context from a key pair prepared once by the caller.
/// This avoids repeating X25519 public-key recovery for every encapsulation.
pub fn setupBaseReceiverWithKeyPair(
    enc: EncapsulatedKey,
    recipient: *const KeyPair,
    info: []const u8,
) Error!ReceiverContext {
    var shared_secret = try decap(enc, recipient);
    defer std.crypto.secureZero(u8, &shared_secret);
    return .{ .state = keySchedule(&shared_secret, info) };
}

pub fn ciphertextLength(plaintext_len: usize) Error!usize {
    if (@as(u128, plaintext_len) > max_aead_plaintext_len) {
        return error.MessageTooLong;
    }
    return std.math.add(usize, plaintext_len, tag_len) catch
        return error.MessageTooLong;
}

fn setupBaseSenderWithKeyPair(
    ephemeral: *const KeyPair,
    recipient_public_key: PublicKey,
    info: []const u8,
) Error!SenderSetup {
    var shared_secret = try encap(ephemeral, recipient_public_key);
    defer std.crypto.secureZero(u8, &shared_secret);
    return .{
        .enc = ephemeral.public_key,
        .context = .{ .state = keySchedule(&shared_secret, info) },
    };
}

fn encap(
    ephemeral: *const KeyPair,
    recipient_public_key: PublicKey,
) Error!SharedSecret {
    var dh = try exchange(&ephemeral.secret_key, recipient_public_key);
    defer std.crypto.secureZero(u8, &dh);

    var kem_context: [encapsulated_key_len + public_key_len]u8 = undefined;
    @memcpy(kem_context[0..encapsulated_key_len], &ephemeral.public_key);
    @memcpy(kem_context[encapsulated_key_len..], &recipient_public_key);
    return extractAndExpand(&dh, &kem_context);
}

fn decap(
    enc: EncapsulatedKey,
    recipient: *const KeyPair,
) Error!SharedSecret {
    var dh = try exchange(&recipient.secret_key, enc);
    defer std.crypto.secureZero(u8, &dh);

    var kem_context: [encapsulated_key_len + public_key_len]u8 = undefined;
    @memcpy(kem_context[0..encapsulated_key_len], &enc);
    @memcpy(kem_context[encapsulated_key_len..], &recipient.public_key);
    return extractAndExpand(&dh, &kem_context);
}

fn exchange(
    secret_key: *const SecretKey,
    public_key: PublicKey,
) Error![32]u8 {
    if (isAllZero(&public_key)) return error.InvalidPublicKey;
    var secret_copy = secret_key.*;
    defer std.crypto.secureZero(u8, &secret_copy);
    var shared: [32]u8 = undefined;
    X25519.scalarmultInto(&shared, &secret_copy, &public_key) catch
        return error.InvalidPublicKey;
    if (isAllZero(&shared)) return error.InvalidPublicKey;
    return shared;
}

fn extractAndExpand(dh: *const [32]u8, kem_context: []const u8) SharedSecret {
    var eae_prk = labeledExtract(&kem_suite_id, "", "eae_prk", dh);
    defer std.crypto.secureZero(u8, &eae_prk);
    var shared_secret: SharedSecret = undefined;
    labeledExpand(
        &shared_secret,
        &eae_prk,
        &kem_suite_id,
        "shared_secret",
        kem_context,
    ) catch unreachable;
    return shared_secret;
}

const Schedule = struct {
    secret: [32]u8,
    key: [key_len]u8,
    base_nonce: [nonce_len]u8,
    exporter_secret: [exporter_secret_len]u8,

    fn deinit(self: *Schedule) void {
        std.crypto.secureZero(Schedule, self[0..1]);
        self.* = undefined;
    }
};

fn deriveSchedule(
    shared_secret: *const SharedSecret,
    info: []const u8,
) Schedule {
    var psk_id_hash = labeledExtract(
        &hpke_suite_id,
        "",
        "psk_id_hash",
        "",
    );
    defer std.crypto.secureZero(u8, &psk_id_hash);
    var info_hash = labeledExtract(
        &hpke_suite_id,
        "",
        "info_hash",
        info,
    );
    defer std.crypto.secureZero(u8, &info_hash);

    var key_schedule_context: [1 + 32 + 32]u8 = undefined;
    key_schedule_context[0] = 0x00;
    @memcpy(key_schedule_context[1..33], &psk_id_hash);
    @memcpy(key_schedule_context[33..], &info_hash);

    var schedule = Schedule{
        .secret = labeledExtract(
            &hpke_suite_id,
            shared_secret,
            "secret",
            "",
        ),
        .key = undefined,
        .base_nonce = undefined,
        .exporter_secret = undefined,
    };
    labeledExpand(
        &schedule.key,
        &schedule.secret,
        &hpke_suite_id,
        "key",
        &key_schedule_context,
    ) catch unreachable;
    labeledExpand(
        &schedule.base_nonce,
        &schedule.secret,
        &hpke_suite_id,
        "base_nonce",
        &key_schedule_context,
    ) catch unreachable;
    labeledExpand(
        &schedule.exporter_secret,
        &schedule.secret,
        &hpke_suite_id,
        "exp",
        &key_schedule_context,
    ) catch unreachable;

    return schedule;
}

fn keySchedule(
    shared_secret: *const SharedSecret,
    info: []const u8,
) Context {
    var schedule = deriveSchedule(shared_secret, info);
    defer schedule.deinit();
    return Context.init(
        schedule.key,
        schedule.base_nonce,
        schedule.exporter_secret,
    );
}

const Context = struct {
    aead: Aes128Gcm,
    base_nonce: [nonce_len]u8,
    exporter_secret: [exporter_secret_len]u8,
    sequence: [nonce_len]u8,
    exhausted: bool,

    fn init(
        key: [key_len]u8,
        base_nonce: [nonce_len]u8,
        exporter_secret: [exporter_secret_len]u8,
    ) Context {
        return .{
            .aead = Aes128Gcm.init(key),
            .base_nonce = base_nonce,
            .exporter_secret = exporter_secret,
            .sequence = [_]u8{0} ** nonce_len,
            .exhausted = false,
        };
    }

    fn seal(
        self: *Context,
        ciphertext_and_tag: []u8,
        plaintext: []const u8,
        aad: []const u8,
    ) Error!void {
        if (self.exhausted) return error.MessageLimitReached;
        if (@as(u128, plaintext.len) > max_aead_plaintext_len) {
            return error.MessageTooLong;
        }
        const required_len = try ciphertextLength(plaintext.len);
        if (ciphertext_and_tag.len != required_len) {
            return error.InvalidBufferLength;
        }

        const nonce = self.currentNonce();
        const ciphertext = ciphertext_and_tag[0..plaintext.len];
        const tag = ciphertext_and_tag[plaintext.len..][0..tag_len];
        self.aead.encrypt(ciphertext, tag, plaintext, aad, nonce);
        self.incrementSequence();
    }

    fn open(
        self: *Context,
        plaintext: []u8,
        ciphertext_and_tag: []const u8,
        aad: []const u8,
    ) Error!void {
        if (self.exhausted) return error.MessageLimitReached;
        if (ciphertext_and_tag.len < tag_len or
            plaintext.len != ciphertext_and_tag.len - tag_len)
        {
            return error.InvalidBufferLength;
        }
        if (@as(u128, plaintext.len) > max_aead_plaintext_len) {
            return error.MessageTooLong;
        }

        const nonce = self.currentNonce();
        const ciphertext = ciphertext_and_tag[0..plaintext.len];
        const tag = ciphertext_and_tag[plaintext.len..][0..tag_len].*;
        self.aead.decrypt(plaintext, ciphertext, tag, aad, nonce) catch
            return error.AuthenticationFailed;
        self.incrementSequence();
    }

    fn exportSecret(
        self: *const Context,
        output: []u8,
        exporter_context: []const u8,
    ) Error!void {
        if (output.len > max_export_len) return error.ExportLengthTooLarge;
        try labeledExpand(
            output,
            &self.exporter_secret,
            &hpke_suite_id,
            "sec",
            exporter_context,
        );
    }

    fn currentNonce(self: *const Context) [nonce_len]u8 {
        var nonce = self.base_nonce;
        for (&nonce, self.sequence) |*byte, sequence_byte| {
            byte.* ^= sequence_byte;
        }
        return nonce;
    }

    fn incrementSequence(self: *Context) void {
        var index = self.sequence.len;
        while (index > 0) {
            index -= 1;
            self.sequence[index] +%= 1;
            if (self.sequence[index] != 0) return;
        }
        self.exhausted = true;
    }

    fn deinit(self: *Context) void {
        std.crypto.secureZero(Context, self[0..1]);
        self.* = undefined;
    }
};

fn labeledExtract(
    suite_id: []const u8,
    salt: []const u8,
    label: []const u8,
    ikm: []const u8,
) [32]u8 {
    var hmac = HmacSha256.init(salt);
    defer std.crypto.secureZero(HmacSha256, (&hmac)[0..1]);
    hmac.update(version_label);
    hmac.update(suite_id);
    hmac.update(label);
    hmac.update(ikm);
    var prk: [32]u8 = undefined;
    hmac.final(&prk);
    return prk;
}

fn labeledExpand(
    output: []u8,
    prk: *const [32]u8,
    suite_id: []const u8,
    label: []const u8,
    info: []const u8,
) Error!void {
    if (output.len > max_export_len) return error.ExportLengthTooLarge;

    var encoded_length: [2]u8 = undefined;
    std.mem.writeInt(u16, &encoded_length, @intCast(output.len), .big);
    var previous: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &previous);
    var previous_len: usize = 0;
    var offset: usize = 0;
    var counter: u8 = 1;

    while (offset < output.len) {
        {
            var hmac = HmacSha256.init(prk);
            defer std.crypto.secureZero(HmacSha256, (&hmac)[0..1]);
            hmac.update(previous[0..previous_len]);
            hmac.update(&encoded_length);
            hmac.update(version_label);
            hmac.update(suite_id);
            hmac.update(label);
            hmac.update(info);
            hmac.update(&.{counter});
            hmac.final(&previous);
        }
        const take = @min(previous.len, output.len - offset);
        @memcpy(output[offset..][0..take], previous[0..take]);
        offset += take;
        previous_len = previous.len;
        counter +%= 1;
    }
}

fn isAllZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn hexBytes(comptime hex: []const u8) ![hex.len / 2]u8 {
    var result: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, hex);
    return result;
}

const vector_info = "Ode on a Grecian Urn";
const vector_sk_e = hexBytes(
    "52c4a758a802cd8b936eceea31443279" ++
        "8d5baf2d7e9235dc084ab1b9cfa2f736",
) catch unreachable;
const vector_pk_e = hexBytes(
    "37fda3567bdbd628e88668c3c8d7e97" ++
        "d1d1253b6d4ea6d44c150f741f1bf4431",
) catch unreachable;
const vector_sk_r = hexBytes(
    "4612c550263fc8ad58375df3f557aac5" ++
        "31d26850903e55a9f23f21d8534e8ac8",
) catch unreachable;
const vector_pk_r = hexBytes(
    "3948cfe0ad1ddb695d780e59077195da" ++
        "6c56506b027329794ab02bca80815c4d",
) catch unreachable;
const vector_shared_secret = hexBytes(
    "fe0e18c9f024ce43799ae393c7e8fe8f" ++
        "ce9d218875e8227b0187c04e7d2ea1fc",
) catch unreachable;

test "RFC 9180 A.1 DHKEM and base-mode key schedule" {
    var ephemeral = try KeyPair.fromSecretKey(&vector_sk_e);
    defer ephemeral.deinit();
    try std.testing.expectEqual(vector_pk_e, ephemeral.public_key);
    var recipient = try KeyPair.fromSecretKey(&vector_sk_r);
    defer recipient.deinit();
    try std.testing.expectEqual(vector_pk_r, recipient.public_key);

    var shared_secret = try encap(&ephemeral, vector_pk_r);
    defer std.crypto.secureZero(u8, &shared_secret);
    try std.testing.expectEqual(vector_shared_secret, shared_secret);
    var decapped = try decap(vector_pk_e, &recipient);
    defer std.crypto.secureZero(u8, &decapped);
    try std.testing.expectEqual(shared_secret, decapped);

    var schedule = deriveSchedule(&shared_secret, vector_info);
    defer schedule.deinit();
    try std.testing.expectEqual(
        try hexBytes(
            "12fff91991e93b48de37e7daddb52981" ++
                "084bd8aa64289c3788471d9a9712f397",
        ),
        schedule.secret,
    );
    try std.testing.expectEqual(
        try hexBytes("4531685d41d65f03dc48f6b8302c05b0"),
        schedule.key,
    );
    try std.testing.expectEqual(
        try hexBytes("56d890e5accaaf011cff4b7d"),
        schedule.base_nonce,
    );
    try std.testing.expectEqual(
        try hexBytes(
            "45ff1c2e220db587171952c0592d5f5e" ++
                "be103f1561a2614e38f2ffd47e99e3f8",
        ),
        schedule.exporter_secret,
    );
}

test "RFC 9180 A.1 base-mode seal, open, and exporters" {
    var ephemeral = try KeyPair.fromSecretKey(&vector_sk_e);
    defer ephemeral.deinit();
    var sender = try setupBaseSenderWithKeyPair(
        &ephemeral,
        vector_pk_r,
        vector_info,
    );
    defer sender.deinit();
    try std.testing.expectEqual(vector_pk_e, sender.enc);

    const plaintext = "Beauty is truth, truth beauty";
    const aad = "Count-0";
    var sealed: [plaintext.len + tag_len]u8 = undefined;
    try sender.context.seal(&sealed, plaintext, aad);
    try std.testing.expectEqualSlices(
        u8,
        &(try hexBytes(
            "f938558b5d72f1a23810b4be2ab4f843" ++
                "31acc02fc97babc53a52ae8218a355a9" ++
                "6d8770ac83d07bea87e13c512a",
        )),
        &sealed,
    );

    var receiver = try setupBaseReceiver(
        vector_pk_e,
        &vector_sk_r,
        vector_info,
    );
    defer receiver.deinit();
    var opened: [plaintext.len]u8 = undefined;
    try receiver.open(&opened, &sealed, aad);
    try std.testing.expectEqualSlices(u8, plaintext, &opened);

    const sequential_vectors = .{
        .{
            "Count-1",
            "af2d7e9ac9ae7e270f46ba1f975be53c" ++
                "09f8d875bdc8535458c2494e8a6eab25" ++
                "1c03d0c22a56b8ca42c2063b84",
        },
        .{
            "Count-2",
            "498dfcabd92e8acedc281e85af1cb4e3" ++
                "e31c7dc394a1ca20e173cb7251649158" ++
                "8d96a19ad4a683518973dcc180",
        },
    };
    inline for (sequential_vectors) |entry| {
        try sender.context.seal(&sealed, plaintext, entry[0]);
        try std.testing.expectEqualSlices(
            u8,
            &(try hexBytes(entry[1])),
            &sealed,
        );
        try receiver.open(&opened, &sealed, entry[0]);
        try std.testing.expectEqualSlices(u8, plaintext, &opened);
    }

    sender.context.state.sequence = [_]u8{0} ** nonce_len;
    receiver.state.sequence = [_]u8{0} ** nonce_len;
    sender.context.state.sequence[nonce_len - 1] = 0xff;
    receiver.state.sequence[nonce_len - 1] = 0xff;
    const carry_vectors = .{
        .{
            "Count-255",
            "7175db9717964058640a3a11fb900794" ++
                "1a5d1757fda1a6935c805c21af32505b" ++
                "f106deefec4a49ac38d71c9e0a",
        },
        .{
            "Count-256",
            "957f9800542b0b8891badb026d79cc54" ++
                "597cb2d225b54c00c5238c25d05c30e3" ++
                "fbeda97d2e0e1aba483a2df9f2",
        },
    };
    inline for (carry_vectors) |entry| {
        try sender.context.seal(&sealed, plaintext, entry[0]);
        try std.testing.expectEqualSlices(
            u8,
            &(try hexBytes(entry[1])),
            &sealed,
        );
        try receiver.open(&opened, &sealed, entry[0]);
        try std.testing.expectEqualSlices(u8, plaintext, &opened);
    }

    const contexts = .{
        .{ "", "3853fe2b4035195a573ffc53856e77058" ++
            "e15d9ea064de3e59f4961d0095250ee" },
        .{ "\x00", "2e8f0b54673c7029649d4eb9d5e33bf1" ++
            "872cf76d623ff164ac185da9e88c21a5" },
        .{ "TestContext", "e9e43065102c3836401bed8c3c3c75ae" ++
            "46be1639869391d62c61f1ec7af54931" },
    };
    inline for (contexts) |entry| {
        var sender_export: [32]u8 = undefined;
        var receiver_export: [32]u8 = undefined;
        try sender.context.exportSecret(&sender_export, entry[0]);
        try receiver.exportSecret(&receiver_export, entry[0]);
        try std.testing.expectEqual(
            try hexBytes(entry[1]),
            sender_export,
        );
        try std.testing.expectEqual(sender_export, receiver_export);
    }
}

test "base mode rejects weak keys, tampering, and buffer mismatches" {
    var ephemeral = try KeyPair.fromSecretKey(&vector_sk_e);
    defer ephemeral.deinit();
    var low_order_public = [_]u8{0} ** public_key_len;
    low_order_public[0] = 1;
    try std.testing.expectError(
        error.InvalidPublicKey,
        setupBaseSenderWithKeyPair(
            &ephemeral,
            [_]u8{0} ** public_key_len,
            vector_info,
        ),
    );
    try std.testing.expectError(
        error.InvalidPublicKey,
        setupBaseSenderWithKeyPair(
            &ephemeral,
            low_order_public,
            vector_info,
        ),
    );
    try std.testing.expectError(
        error.InvalidPublicKey,
        setupBaseReceiver(
            [_]u8{0} ** encapsulated_key_len,
            &vector_sk_r,
            vector_info,
        ),
    );

    var sender = try setupBaseSenderWithKeyPair(
        &ephemeral,
        vector_pk_r,
        vector_info,
    );
    defer sender.deinit();
    var receiver = try setupBaseReceiver(
        vector_pk_e,
        &vector_sk_r,
        vector_info,
    );
    defer receiver.deinit();
    const plaintext = "authenticated";
    var sealed: [plaintext.len + tag_len]u8 = undefined;
    try std.testing.expectError(
        error.InvalidBufferLength,
        sender.context.seal(sealed[0 .. sealed.len - 1], plaintext, "aad"),
    );
    try sender.context.seal(&sealed, plaintext, "aad");
    sealed[0] ^= 1;
    var opened: [plaintext.len]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        receiver.open(&opened, &sealed, "aad"),
    );
    sealed[0] ^= 1;
    try receiver.open(&opened, &sealed, "aad");
    try std.testing.expectEqualSlices(u8, plaintext, &opened);
    try std.testing.expectError(
        error.InvalidBufferLength,
        receiver.open(opened[0 .. opened.len - 1], &sealed, "aad"),
    );
}

test "base mode uses the final 96-bit nonce exactly once" {
    var ephemeral = try KeyPair.fromSecretKey(&vector_sk_e);
    defer ephemeral.deinit();
    var sender = try setupBaseSenderWithKeyPair(
        &ephemeral,
        vector_pk_r,
        vector_info,
    );
    defer sender.deinit();
    sender.context.state.sequence = [_]u8{0xff} ** nonce_len;

    var output: [tag_len]u8 = undefined;
    try sender.context.seal(&output, "", "");
    try std.testing.expectError(
        error.MessageLimitReached,
        sender.context.seal(&output, "", ""),
    );

    var too_long_export: [max_export_len + 1]u8 = undefined;
    try std.testing.expectError(
        error.ExportLengthTooLarge,
        sender.context.exportSecret(&too_long_export, ""),
    );
}

test "random sender setup interoperates with receiver" {
    var recipient = KeyPair.generate(std.testing.io);
    defer recipient.deinit();
    var sender = try setupBaseSender(
        std.testing.io,
        recipient.public_key,
        "application info",
    );
    defer sender.deinit();
    var receiver = try setupBaseReceiver(
        sender.enc,
        &recipient.secret_key,
        "application info",
    );
    defer receiver.deinit();

    const plaintext = "allocation-free HPKE";
    var sealed: [plaintext.len + tag_len]u8 = undefined;
    var opened: [plaintext.len]u8 = undefined;
    try sender.context.seal(&sealed, plaintext, "associated data");
    try receiver.open(&opened, &sealed, "associated data");
    try std.testing.expectEqualSlices(u8, plaintext, &opened);
}
