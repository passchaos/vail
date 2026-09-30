//! Stateless TLS 1.2 and TLS 1.3 ticket sealing with bounded key rotation.
//!
//! Wire identities carry an authenticated key identifier and nonce, so open is
//! O(1) for the current key and O(history) only across the small retained key
//! set. Origin and ALPN are AEAD associated data, preventing ticket replay
//! across application security contexts without storing every issued ticket.

const std = @import("std");
const application_settings = @import("application_settings.zig");
const codec = @import("ticket.zig");
const cipher_suite = @import("cipher_suite.zig");
const secret = @import("secret.zig");
const tls12 = @import("tls12.zig");
const tls12_ticket = @import("tls12_ticket.zig");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
pub const key_len = Aes256Gcm.key_length;
pub const nonce_len = Aes256Gcm.nonce_length;
pub const tag_len = Aes256Gcm.tag_length;
pub const max_keys = 4;
const format_version: u8 = 4;
const application_settings_format_version: u8 = 6;
const header_len = 1 + @sizeOf(u32) + nonce_len;
const early_data_size_offset =
    @sizeOf(u64) + @sizeOf(u32) + @sizeOf(u32) + @sizeOf(u16);
const secret_len_offset = early_data_size_offset + @sizeOf(u32);
const secret_offset = secret_len_offset + @sizeOf(u8);
const plaintext_len = secret_offset + secret.max_len;
pub const sealed_len = header_len + plaintext_len + tag_len;
pub const max_application_settings_len: usize = 4096;
const tls12_format_version: u8 = 5;
const tls12_master_secret_offset =
    @sizeOf(u64) + @sizeOf(u32) + @sizeOf(u16) + @sizeOf(u8);
const tls12_plaintext_len = tls12_master_secret_offset +
    tls12.master_secret_len;
pub const tls12_sealed_len = header_len + tls12_plaintext_len + tag_len;

pub const Error = std.mem.Allocator.Error || error{
    InvalidKeyId,
    DuplicateKeyId,
    InvalidContext,
    InvalidTicket,
    ExpiredTicket,
    UnknownKey,
    AuthenticationFailed,
    InvalidTicketLifetime,
};

pub const Key = struct {
    id: u32,
    secret: [key_len]u8,
};

pub const Opened = struct {
    secret: [32]u8,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    cipher_suite: cipher_suite.Suite = .aes_128_gcm_sha256,
    max_early_data_size: ?u32 = null,
};

pub const OpenedSecret = struct {
    secret: secret.Secret,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    /// TLS cipher-suite wire ID.  The ticket layer recognizes 0x1302 before
    /// negotiation publishes that suite, but validates its SHA-384 binding.
    cipher_suite_wire: u16,
    max_early_data_size: ?u32 = null,
};

pub const OpenedSecretWithApplicationSettings = struct {
    allocator: std.mem.Allocator,
    secret: secret.Secret,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    cipher_suite_wire: u16,
    max_early_data_size: ?u32,
    application_settings_codepoint: ?application_settings.Codepoint,
    local_application_settings: ?[]u8,
    peer_application_settings: ?[]u8,

    pub fn deinit(self: *OpenedSecretWithApplicationSettings) void {
        self.secret.deinit();
        if (self.local_application_settings) |settings| {
            self.allocator.free(settings);
        }
        if (self.peer_application_settings) |settings| {
            self.allocator.free(settings);
        }
        self.* = undefined;
    }
};

pub const Tls12Opened = struct {
    master_secret: [tls12.master_secret_len]u8,
    suite: tls12.Suite,
    issued_at_seconds: u64,
    lifetime_seconds: u32,
    extended_master_secret: bool,

    pub fn deinit(self: *Tls12Opened) void {
        std.crypto.secureZero(u8, &self.master_secret);
        self.* = undefined;
    }
};

pub const Tls12SealInput = struct {
    master_secret: *const [tls12.master_secret_len]u8,
    suite: tls12.Suite,
    issued_at_seconds: u64,
    lifetime_seconds: u32,
    extended_master_secret: bool,
};

pub const Keyring = struct {
    keys: [max_keys]Key = undefined,
    len: usize = 0,

    pub fn init(current: Key) Error!Keyring {
        try validateKey(current);
        var result = Keyring{};
        result.keys[0] = current;
        result.len = 1;
        return result;
    }

    pub fn deinit(self: *Keyring) void {
        for (self.keys[0..self.len]) |*key| {
            std.crypto.secureZero(u8, &key.secret);
        }
        self.* = undefined;
    }

    pub fn rotate(self: *Keyring, next: Key) Error!void {
        try validateKey(next);
        for (self.keys[0..self.len]) |key| {
            if (key.id == next.id) return error.DuplicateKeyId;
        }
        const retained: usize = @min(self.len, @as(usize, max_keys - 1));
        if (self.len == max_keys) {
            // Wipe the evicted oldest secret before its slot is overwritten.
            std.crypto.secureZero(u8, &self.keys[max_keys - 1].secret);
        }
        std.mem.copyBackwards(
            Key,
            self.keys[1 .. retained + 1],
            self.keys[0..retained],
        );
        self.keys[0] = next;
        self.len = retained + 1;
    }

    pub fn currentId(self: *const Keyring) u32 {
        return self.keys[0].id;
    }

    pub fn seal(
        self: *const Keyring,
        nonce: [nonce_len]u8,
        server_id: []const u8,
        alpn: []const u8,
        opened: Opened,
    ) Error![sealed_len]u8 {
        return self.sealSecret(
            nonce,
            server_id,
            alpn,
            .{
                .secret = .fromSha256(opened.secret),
                .age_add = opened.age_add,
                .issued_at_ms = opened.issued_at_ms,
                .lifetime_seconds = opened.lifetime_seconds,
                .cipher_suite_wire = opened.cipher_suite.wireValue(),
                .max_early_data_size = opened.max_early_data_size,
            },
        );
    }

    pub fn sealSecret(
        self: *const Keyring,
        nonce: [nonce_len]u8,
        server_id: []const u8,
        alpn: []const u8,
        opened: OpenedSecret,
    ) Error![sealed_len]u8 {
        try validateContext(server_id, alpn);
        try validateOpenedFields(
            opened.lifetime_seconds,
            opened.secret.hash,
            opened.cipher_suite_wire,
        );
        const current = &self.keys[0];

        var output: [sealed_len]u8 = undefined;
        output[0] = format_version;
        std.mem.writeInt(u32, output[1..5], current.id, .big);
        @memcpy(output[5..header_len], &nonce);

        var plaintext: [plaintext_len]u8 = undefined;
        std.mem.writeInt(u64, plaintext[0..8], opened.issued_at_ms, .big);
        std.mem.writeInt(u32, plaintext[8..12], opened.lifetime_seconds, .big);
        std.mem.writeInt(u32, plaintext[12..16], opened.age_add, .big);
        std.mem.writeInt(
            u16,
            plaintext[16..18],
            opened.cipher_suite_wire,
            .big,
        );
        std.mem.writeInt(
            u32,
            plaintext[early_data_size_offset..secret_len_offset],
            opened.max_early_data_size orelse 0,
            .big,
        );
        plaintext[secret_len_offset] =
            @intCast(opened.secret.bytes().len);
        @memset(plaintext[secret_offset..], 0);
        @memcpy(
            plaintext[secret_offset..][0..opened.secret.bytes().len],
            opened.secret.bytes(),
        );
        defer std.crypto.secureZero(u8, &plaintext);

        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        Aes256Gcm.encrypt(
            output[header_len .. header_len + plaintext_len],
            output[header_len + plaintext_len ..][0..tag_len],
            &plaintext,
            aad[0..aad_len],
            nonce,
            current.secret,
        );
        return output;
    }

    pub fn sealSecretWithApplicationSettingsAlloc(
        self: *const Keyring,
        allocator: std.mem.Allocator,
        nonce: [nonce_len]u8,
        server_id: []const u8,
        alpn: []const u8,
        opened: OpenedSecret,
        settings: application_settings.Session,
    ) Error![]u8 {
        try validateContext(server_id, alpn);
        try validateOpenedFields(
            opened.lifetime_seconds,
            opened.secret.hash,
            opened.cipher_suite_wire,
        );
        if (settings.local.len > max_application_settings_len or
            settings.peer.len > max_application_settings_len)
        {
            return error.InvalidTicket;
        }
        const settings_len = 2 + 2 + settings.local.len +
            2 + settings.peer.len;
        const dynamic_plaintext_len = plaintext_len + settings_len;
        const output_len = header_len + dynamic_plaintext_len + tag_len;
        if (output_len > std.math.maxInt(u16)) return error.InvalidTicket;

        const output = try allocator.alloc(u8, output_len);
        errdefer allocator.free(output);
        output[0] = application_settings_format_version;
        const current = &self.keys[0];
        std.mem.writeInt(u32, output[1..5], current.id, .big);
        @memcpy(output[5..header_len], &nonce);

        const plaintext = try allocator.alloc(u8, dynamic_plaintext_len);
        defer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }
        writeSecretPlaintext(plaintext[0..plaintext_len], opened);
        var offset = plaintext_len;
        std.mem.writeInt(
            u16,
            plaintext[offset..][0..2],
            @intFromEnum(settings.codepoint),
            .big,
        );
        offset += 2;
        std.mem.writeInt(
            u16,
            plaintext[offset..][0..2],
            @intCast(settings.local.len),
            .big,
        );
        offset += 2;
        @memcpy(plaintext[offset..][0..settings.local.len], settings.local);
        offset += settings.local.len;
        std.mem.writeInt(
            u16,
            plaintext[offset..][0..2],
            @intCast(settings.peer.len),
            .big,
        );
        offset += 2;
        @memcpy(plaintext[offset..][0..settings.peer.len], settings.peer);

        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        Aes256Gcm.encrypt(
            output[header_len .. header_len + dynamic_plaintext_len],
            output[header_len + dynamic_plaintext_len ..][0..tag_len],
            plaintext,
            aad[0..aad_len],
            nonce,
            current.secret,
        );
        return output;
    }

    pub fn open(
        self: *const Keyring,
        identity: []const u8,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) Error!Opened {
        const opened = try self.openSecret(
            identity,
            server_id,
            alpn,
            now_ms,
        );
        return .{
            .secret = opened.secret.sha256() catch
                return error.InvalidTicket,
            .issued_at_ms = opened.issued_at_ms,
            .lifetime_seconds = opened.lifetime_seconds,
            .age_add = opened.age_add,
            .cipher_suite = cipher_suite.Suite.fromWire(
                opened.cipher_suite_wire,
            ) orelse return error.InvalidTicket,
            .max_early_data_size = opened.max_early_data_size,
        };
    }

    pub fn openSecret(
        self: *const Keyring,
        identity: []const u8,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) Error!OpenedSecret {
        try validateContext(server_id, alpn);
        if (identity.len != sealed_len or identity[0] != format_version) {
            return error.InvalidTicket;
        }
        const key_id = std.mem.readInt(u32, identity[1..5], .big);
        const key = self.find(key_id) orelse return error.UnknownKey;
        const nonce = identity[5..header_len][0..nonce_len].*;
        const ciphertext = identity[header_len .. header_len + plaintext_len];
        const tag = identity[header_len + plaintext_len ..][0..tag_len].*;

        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        var plaintext: [plaintext_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        Aes256Gcm.decrypt(
            &plaintext,
            ciphertext,
            tag,
            aad[0..aad_len],
            nonce,
            key.secret,
        ) catch return error.AuthenticationFailed;

        const suite_wire = std.mem.readInt(
            u16,
            plaintext[16..18],
            .big,
        );
        const encoded_secret_len = plaintext[secret_len_offset];
        const encoded_early_data_size = std.mem.readInt(
            u32,
            plaintext[early_data_size_offset..secret_len_offset],
            .big,
        );
        const hash = expectedHashForSuite(suite_wire) catch
            return error.InvalidTicket;
        if (encoded_secret_len != hash.len()) return error.InvalidTicket;
        const opened = OpenedSecret{
            .issued_at_ms = std.mem.readInt(u64, plaintext[0..8], .big),
            .lifetime_seconds = std.mem.readInt(u32, plaintext[8..12], .big),
            .age_add = std.mem.readInt(u32, plaintext[12..16], .big),
            .cipher_suite_wire = suite_wire,
            .max_early_data_size = if (encoded_early_data_size == 0)
                null
            else
                encoded_early_data_size,
            .secret = secret.Secret.init(
                hash,
                plaintext[secret_offset..][0..encoded_secret_len],
            ) catch return error.InvalidTicket,
        };
        try validateOpenedFields(
            opened.lifetime_seconds,
            opened.secret.hash,
            opened.cipher_suite_wire,
        );
        if (now_ms < opened.issued_at_ms) return error.ExpiredTicket;
        const lifetime_ms = @as(u64, opened.lifetime_seconds) *
            std.time.ms_per_s;
        if (now_ms - opened.issued_at_ms > lifetime_ms) {
            return error.ExpiredTicket;
        }
        return opened;
    }

    pub fn openSecretWithApplicationSettings(
        self: *const Keyring,
        allocator: std.mem.Allocator,
        identity: []const u8,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) Error!OpenedSecretWithApplicationSettings {
        if (identity.len == sealed_len and identity[0] == format_version) {
            const opened = try self.openSecret(
                identity,
                server_id,
                alpn,
                now_ms,
            );
            return .{
                .allocator = allocator,
                .secret = opened.secret,
                .age_add = opened.age_add,
                .issued_at_ms = opened.issued_at_ms,
                .lifetime_seconds = opened.lifetime_seconds,
                .cipher_suite_wire = opened.cipher_suite_wire,
                .max_early_data_size = opened.max_early_data_size,
                .application_settings_codepoint = null,
                .local_application_settings = null,
                .peer_application_settings = null,
            };
        }
        try validateContext(server_id, alpn);
        const minimum_len = header_len + plaintext_len + 6 + tag_len;
        if (identity.len < minimum_len or
            identity[0] != application_settings_format_version)
        {
            return error.InvalidTicket;
        }
        const dynamic_plaintext_len = identity.len - header_len - tag_len;
        if (dynamic_plaintext_len > plaintext_len + 6 +
            2 * max_application_settings_len)
        {
            return error.InvalidTicket;
        }
        const key_id = std.mem.readInt(u32, identity[1..5], .big);
        const key = self.find(key_id) orelse return error.UnknownKey;
        const nonce = identity[5..header_len][0..nonce_len].*;
        const plaintext = try allocator.alloc(u8, dynamic_plaintext_len);
        defer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }
        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        Aes256Gcm.decrypt(
            plaintext,
            identity[header_len .. header_len + dynamic_plaintext_len],
            identity[header_len + dynamic_plaintext_len ..][0..tag_len].*,
            aad[0..aad_len],
            nonce,
            key.secret,
        ) catch return error.AuthenticationFailed;

        var opened = try parseSecretPlaintext(plaintext[0..plaintext_len], now_ms);
        errdefer opened.secret.deinit();
        var offset = plaintext_len;
        const raw_codepoint = std.mem.readInt(
            u16,
            plaintext[offset..][0..2],
            .big,
        );
        const codepoint: application_settings.Codepoint = switch (raw_codepoint) {
            application_settings.legacy_extension_type => .legacy,
            application_settings.current_extension_type => .current,
            else => return error.InvalidTicket,
        };
        offset += 2;
        const local_len = std.mem.readInt(u16, plaintext[offset..][0..2], .big);
        offset += 2;
        if (local_len > max_application_settings_len or
            local_len > plaintext.len - offset)
        {
            return error.InvalidTicket;
        }
        const local = try allocator.dupe(
            u8,
            plaintext[offset..][0..local_len],
        );
        errdefer allocator.free(local);
        offset += local_len;
        if (plaintext.len - offset < 2) return error.InvalidTicket;
        const peer_len = std.mem.readInt(u16, plaintext[offset..][0..2], .big);
        offset += 2;
        if (peer_len > max_application_settings_len or
            peer_len != plaintext.len - offset)
        {
            return error.InvalidTicket;
        }
        const peer = try allocator.dupe(u8, plaintext[offset..]);
        return .{
            .allocator = allocator,
            .secret = opened.secret,
            .age_add = opened.age_add,
            .issued_at_ms = opened.issued_at_ms,
            .lifetime_seconds = opened.lifetime_seconds,
            .cipher_suite_wire = opened.cipher_suite_wire,
            .max_early_data_size = opened.max_early_data_size,
            .application_settings_codepoint = codepoint,
            .local_application_settings = local,
            .peer_application_settings = peer,
        };
    }

    /// Seal TLS 1.2 resumption state into an opaque RFC 5077 ticket. The
    /// server identity and negotiated ALPN are authenticated as associated
    /// data and are never exposed in the ticket plaintext.
    pub fn sealTls12(
        self: *const Keyring,
        nonce: [nonce_len]u8,
        server_id: []const u8,
        alpn: []const u8,
        input: Tls12SealInput,
    ) Error![tls12_sealed_len]u8 {
        try validateContext(server_id, alpn);
        try validateTls12Lifetime(input.lifetime_seconds);
        const current = &self.keys[0];

        var output: [tls12_sealed_len]u8 = undefined;
        output[0] = tls12_format_version;
        std.mem.writeInt(u32, output[1..5], current.id, .big);
        @memcpy(output[5..header_len], &nonce);

        var plaintext: [tls12_plaintext_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        std.mem.writeInt(u64, plaintext[0..8], input.issued_at_seconds, .big);
        std.mem.writeInt(u32, plaintext[8..12], input.lifetime_seconds, .big);
        std.mem.writeInt(u16, plaintext[12..14], @intFromEnum(input.suite), .big);
        plaintext[14] = @intFromBool(input.extended_master_secret);
        @memcpy(
            plaintext[tls12_master_secret_offset..],
            input.master_secret,
        );

        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        var tls12_key = deriveTls12Key(&current.secret);
        defer std.crypto.secureZero(u8, &tls12_key);
        Aes256Gcm.encrypt(
            output[header_len .. header_len + tls12_plaintext_len],
            output[header_len + tls12_plaintext_len ..][0..tag_len],
            &plaintext,
            aad[0..aad_len],
            nonce,
            tls12_key,
        );
        return output;
    }

    pub fn openTls12(
        self: *const Keyring,
        ticket_bytes: []const u8,
        server_id: []const u8,
        alpn: []const u8,
        now_seconds: u64,
    ) Error!Tls12Opened {
        try validateContext(server_id, alpn);
        if (ticket_bytes.len != tls12_sealed_len or
            ticket_bytes[0] != tls12_format_version)
        {
            return error.InvalidTicket;
        }
        const key_id = std.mem.readInt(u32, ticket_bytes[1..5], .big);
        const key = self.find(key_id) orelse return error.UnknownKey;
        const nonce = ticket_bytes[5..header_len][0..nonce_len].*;
        const ciphertext = ticket_bytes[header_len .. header_len + tls12_plaintext_len];
        const tag = ticket_bytes[header_len + tls12_plaintext_len ..][0..tag_len].*;
        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        var tls12_key = deriveTls12Key(&key.secret);
        defer std.crypto.secureZero(u8, &tls12_key);
        var plaintext: [tls12_plaintext_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        Aes256Gcm.decrypt(
            &plaintext,
            ciphertext,
            tag,
            aad[0..aad_len],
            nonce,
            tls12_key,
        ) catch return error.AuthenticationFailed;

        const suite = tls12.Suite.fromWire(std.mem.readInt(
            u16,
            plaintext[12..14],
            .big,
        )) orelse return error.InvalidTicket;
        if (plaintext[14] > 1) return error.InvalidTicket;
        var opened = Tls12Opened{
            .master_secret = plaintext[tls12_master_secret_offset..][0..tls12.master_secret_len].*,
            .suite = suite,
            .issued_at_seconds = std.mem.readInt(u64, plaintext[0..8], .big),
            .lifetime_seconds = std.mem.readInt(u32, plaintext[8..12], .big),
            .extended_master_secret = plaintext[14] == 1,
        };
        errdefer opened.deinit();
        try validateTls12Lifetime(opened.lifetime_seconds);
        if (now_seconds < opened.issued_at_seconds or
            now_seconds - opened.issued_at_seconds >= opened.lifetime_seconds)
        {
            return error.ExpiredTicket;
        }
        return opened;
    }

    fn find(self: *const Keyring, id: u32) ?*const Key {
        for (self.keys[0..self.len]) |*key| {
            if (key.id == id) return key;
        }
        return null;
    }
};

fn validateKey(key: Key) Error!void {
    if (key.id == 0) return error.InvalidKeyId;
}

fn validateOpenedFields(
    lifetime_seconds: u32,
    hash: secret.Hash,
    suite_wire: u16,
) Error!void {
    if (lifetime_seconds == 0 or
        lifetime_seconds > codec.max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
    const expected_hash = try expectedHashForSuite(suite_wire);
    if (expected_hash != hash) return error.InvalidTicket;
}

fn writeSecretPlaintext(
    plaintext: []u8,
    opened: OpenedSecret,
) void {
    std.debug.assert(plaintext.len == plaintext_len);
    std.mem.writeInt(u64, plaintext[0..8], opened.issued_at_ms, .big);
    std.mem.writeInt(u32, plaintext[8..12], opened.lifetime_seconds, .big);
    std.mem.writeInt(u32, plaintext[12..16], opened.age_add, .big);
    std.mem.writeInt(u16, plaintext[16..18], opened.cipher_suite_wire, .big);
    std.mem.writeInt(
        u32,
        plaintext[early_data_size_offset..secret_len_offset],
        opened.max_early_data_size orelse 0,
        .big,
    );
    plaintext[secret_len_offset] = @intCast(opened.secret.bytes().len);
    @memset(plaintext[secret_offset..], 0);
    @memcpy(
        plaintext[secret_offset..][0..opened.secret.bytes().len],
        opened.secret.bytes(),
    );
}

fn parseSecretPlaintext(
    plaintext: []const u8,
    now_ms: u64,
) Error!OpenedSecret {
    std.debug.assert(plaintext.len == plaintext_len);
    const suite_wire = std.mem.readInt(u16, plaintext[16..18], .big);
    const encoded_secret_len = plaintext[secret_len_offset];
    const encoded_early_data_size = std.mem.readInt(
        u32,
        plaintext[early_data_size_offset..secret_len_offset],
        .big,
    );
    const hash = expectedHashForSuite(suite_wire) catch
        return error.InvalidTicket;
    if (encoded_secret_len != hash.len()) return error.InvalidTicket;
    var opened = OpenedSecret{
        .issued_at_ms = std.mem.readInt(u64, plaintext[0..8], .big),
        .lifetime_seconds = std.mem.readInt(u32, plaintext[8..12], .big),
        .age_add = std.mem.readInt(u32, plaintext[12..16], .big),
        .cipher_suite_wire = suite_wire,
        .max_early_data_size = if (encoded_early_data_size == 0)
            null
        else
            encoded_early_data_size,
        .secret = secret.Secret.init(
            hash,
            plaintext[secret_offset..][0..encoded_secret_len],
        ) catch return error.InvalidTicket,
    };
    errdefer opened.secret.deinit();
    try validateOpenedFields(
        opened.lifetime_seconds,
        opened.secret.hash,
        opened.cipher_suite_wire,
    );
    if (now_ms < opened.issued_at_ms) return error.ExpiredTicket;
    const lifetime_ms = @as(u64, opened.lifetime_seconds) * std.time.ms_per_s;
    if (now_ms - opened.issued_at_ms > lifetime_ms) {
        return error.ExpiredTicket;
    }
    return opened;
}

fn validateTls12Lifetime(lifetime_seconds: u32) Error!void {
    if (lifetime_seconds == 0 or
        lifetime_seconds > tls12_ticket.max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
}

fn deriveTls12Key(base_key: *const [key_len]u8) [key_len]u8 {
    var derived: [key_len]u8 = undefined;
    HmacSha256.create(
        &derived,
        "vail tls12 session ticket key\x00",
        base_key,
    );
    return derived;
}

fn expectedHashForSuite(suite_wire: u16) Error!secret.Hash {
    return switch (suite_wire) {
        0x1301, 0x1303 => .sha256,
        0x1302 => .sha384,
        0x00c6 => .sm3,
        else => error.InvalidTicket,
    };
}

fn validateContext(server_id: []const u8, alpn: []const u8) Error!void {
    if (server_id.len == 0 or
        server_id.len > std.math.maxInt(u16) or
        alpn.len > std.math.maxInt(u8))
    {
        return error.InvalidContext;
    }
    if (2 + server_id.len + 1 + alpn.len > 512) {
        return error.InvalidContext;
    }
}

fn writeContext(
    output: *[512]u8,
    server_id: []const u8,
    alpn: []const u8,
) Error!usize {
    try validateContext(server_id, alpn);
    std.mem.writeInt(u16, output[0..2], @intCast(server_id.len), .big);
    @memcpy(output[2 .. 2 + server_id.len], server_id);
    const alpn_len_offset = 2 + server_id.len;
    output[alpn_len_offset] = @intCast(alpn.len);
    @memcpy(output[alpn_len_offset + 1 ..][0..alpn.len], alpn);
    return alpn_len_offset + 1 + alpn.len;
}

test "stateless ticket round trip preserves bounded ALPS state" {
    const allocator = std.testing.allocator;
    var keyring = try Keyring.init(.{
        .id = 6,
        .secret = [_]u8{0x91} ** key_len,
    });
    defer keyring.deinit();
    const input = OpenedSecret{
        .secret = secret.Secret.fromSha384([_]u8{0x92} ** 48),
        .age_add = 19,
        .issued_at_ms = 10_000,
        .lifetime_seconds = 60,
        .cipher_suite_wire = 0x1302,
        .max_early_data_size = 4096,
    };
    const encoded = try keyring.sealSecretWithApplicationSettingsAlloc(
        allocator,
        [_]u8{0x93} ** nonce_len,
        "example.com",
        "h2",
        input,
        .{
            .codepoint = .current,
            .local = "server-settings",
            .peer = "client-settings",
        },
    );
    defer allocator.free(encoded);
    try std.testing.expect(encoded.len > sealed_len);
    var opened = try keyring.openSecretWithApplicationSettings(
        allocator,
        encoded,
        "example.com",
        "h2",
        10_001,
    );
    defer opened.deinit();
    try std.testing.expectEqual(secret.Hash.sha384, opened.secret.hash);
    try std.testing.expectEqual(
        application_settings.Codepoint.current,
        opened.application_settings_codepoint.?,
    );
    try std.testing.expectEqualStrings(
        "server-settings",
        opened.local_application_settings.?,
    );
    try std.testing.expectEqualStrings(
        "client-settings",
        opened.peer_application_settings.?,
    );
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.openSecretWithApplicationSettings(
            allocator,
            encoded,
            "example.com",
            "h3",
            10_001,
        ),
    );

    var legacy = try keyring.sealSecret(
        [_]u8{0x94} ** nonce_len,
        "example.com",
        "h2",
        input,
    );
    var opened_legacy = try keyring.openSecretWithApplicationSettings(
        allocator,
        &legacy,
        "example.com",
        "h2",
        10_001,
    );
    defer opened_legacy.deinit();
    try std.testing.expect(opened_legacy.application_settings_codepoint == null);
    legacy[legacy.len - 1] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.openSecretWithApplicationSettings(
            allocator,
            &legacy,
            "example.com",
            "h2",
            10_001,
        ),
    );
}

test "TLS 1.2 stateless ticket round trip binds context and lifetime" {
    var keyring = try Keyring.init(.{
        .id = 7,
        .secret = [_]u8{0xa1} ** key_len,
    });
    defer keyring.deinit();
    const original = Tls12Opened{
        .master_secret = [_]u8{0xa2} ** tls12.master_secret_len,
        .suite = .ecdhe_rsa_aes_256_gcm_sha384,
        .issued_at_seconds = 100,
        .lifetime_seconds = 60,
        .extended_master_secret = true,
    };
    var ticket_bytes = try keyring.sealTls12(
        [_]u8{0xa3} ** nonce_len,
        "example.com",
        "h2",
        .{
            .master_secret = &original.master_secret,
            .suite = original.suite,
            .issued_at_seconds = original.issued_at_seconds,
            .lifetime_seconds = original.lifetime_seconds,
            .extended_master_secret = original.extended_master_secret,
        },
    );
    var opened = try keyring.openTls12(
        &ticket_bytes,
        "example.com",
        "h2",
        159,
    );
    defer opened.deinit();
    try std.testing.expectEqual(original.suite, opened.suite);
    try std.testing.expectEqual(
        original.master_secret,
        opened.master_secret,
    );
    try std.testing.expect(opened.extended_master_secret);
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.openTls12(&ticket_bytes, "other.example", "h2", 159),
    );
    try std.testing.expectError(
        error.ExpiredTicket,
        keyring.openTls12(&ticket_bytes, "example.com", "h2", 160),
    );
    ticket_bytes[ticket_bytes.len - 1] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.openTls12(&ticket_bytes, "example.com", "h2", 159),
    );

    const no_alpn_ticket = try keyring.sealTls12(
        [_]u8{0xa4} ** nonce_len,
        "example.com",
        "",
        .{
            .master_secret = &original.master_secret,
            .suite = original.suite,
            .issued_at_seconds = original.issued_at_seconds,
            .lifetime_seconds = original.lifetime_seconds,
            .extended_master_secret = original.extended_master_secret,
        },
    );
    try keyring.rotate(.{
        .id = 8,
        .secret = [_]u8{0xa5} ** key_len,
    });
    var no_alpn = try keyring.openTls12(
        &no_alpn_ticket,
        "example.com",
        "",
        159,
    );
    defer no_alpn.deinit();
    try std.testing.expectEqual(original.master_secret, no_alpn.master_secret);
}
