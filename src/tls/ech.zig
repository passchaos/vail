//! TLS Encrypted ClientHello primitives (RFC 9849).
//!
//! ECH configuration and extension parsing is allocation-free and keeps
//! borrowed views into the caller's wire bytes. Only the mandatory ECH HPKE
//! suite currently implemented by Vail is selected: X25519/HKDF-SHA256 with
//! AES-128-GCM.

const std = @import("std");
const hpke = @import("../crypto/hpke.zig");
const client_hello = @import("client_hello.zig");
const secret = @import("secret.zig");
const sm3 = @import("../crypto/sm3.zig");
const transcript = @import("transcript.zig");

const X25519 = std.crypto.dh.X25519;

pub const version: u16 = 0xfe0d;
pub const extension_type: u16 = version;
pub const outer_extensions_type: u16 = 0xfd00;
pub const inner_type: u8 = 1;
pub const outer_type: u8 = 0;
pub const confirmation_len = 8;

pub const Error = std.mem.Allocator.Error || hpke.Error || error{
    InvalidConfig,
    InvalidConfigList,
    NoSupportedConfig,
    UnsupportedConfig,
    InvalidPublicName,
    DuplicateConfigExtension,
    UnsupportedMandatoryConfigExtension,
    InvalidClientHello,
    InvalidEchExtension,
    MissingEchExtension,
    InvalidInnerClientHello,
    EchContextAlreadyUsed,
    EchContextFailed,
    InvalidRetry,
    HashMismatch,
};

pub const CipherSuite = struct {
    kdf_id: u16,
    aead_id: u16,

    pub fn supported(self: CipherSuite) bool {
        return self.kdf_id == hpke.kdf_id and self.aead_id == hpke.aead_id;
    }
};

pub const ConfigExtension = struct {
    typ: u16,
    data: []const u8,
};

/// Borrowed view of one supported ECHConfig.
pub const Config = struct {
    /// Exact `ECHConfig`, including its version and contents length. This is
    /// bound into the HPKE `info` value and must remain byte-for-byte intact.
    encoded: []const u8,
    config_id: u8,
    public_key: hpke.PublicKey,
    cipher_suite: CipherSuite,
    maximum_name_length: u8,
    public_name: []const u8,
    /// Raw contents of the ECHConfigExtension vector, without its u16 length.
    extensions: []const u8,

    pub fn outerNameMatches(self: Config, name: []const u8) bool {
        return std.ascii.eqlIgnoreCase(self.public_name, name);
    }
};

pub const ConfigOptions = struct {
    config_id: u8,
    public_key: hpke.PublicKey,
    cipher_suites: []const CipherSuite = &.{.{
        .kdf_id = hpke.kdf_id,
        .aead_id = hpke.aead_id,
    }},
    maximum_name_length: u8 = 0,
    public_name: []const u8,
    extensions: []const ConfigExtension = &.{},
};

pub const ServerConfig = struct {
    config: Config,
    key_pair: *const hpke.KeyPair,
    /// RFC 9849 permits this check but does not require it because one key may
    /// be published under more than one public name.
    require_public_name_match: bool = false,
};

pub const Outer = struct {
    cipher_suite: CipherSuite,
    config_id: u8,
    enc: []const u8,
    payload: []const u8,
};

pub const ClientHelloExtension = union(enum) {
    inner,
    outer: Outer,
};

/// Selects the first structurally valid config supporting Vail's HPKE suite.
/// Unknown versions and otherwise well-framed unsupported configs are skipped.
pub fn selectConfig(config_list: []const u8) Error!Config {
    try validateConfigList(config_list);
    var list_pos: usize = 0;
    const list = readU16Vector(config_list, &list_pos) catch unreachable;

    var config_pos: usize = 0;
    while (config_pos < list.len) {
        const start = config_pos;
        _ = readInt(u16, list, &config_pos) catch
            return error.InvalidConfigList;
        const contents_len = readInt(u16, list, &config_pos) catch
            return error.InvalidConfigList;
        _ = readSlice(list, &config_pos, contents_len) catch
            return error.InvalidConfigList;
        const encoded = list[start..config_pos];
        const selected = parseConfig(encoded) catch |err| switch (err) {
            error.UnsupportedConfig,
            error.InvalidConfig,
            error.InvalidPublicName,
            error.DuplicateConfigExtension,
            error.UnsupportedMandatoryConfigExtension,
            error.InvalidPublicKey,
            => continue,
            else => return err,
        };
        return selected;
    }
    return error.NoSupportedConfig;
}

/// Validates only the version-independent ECHConfigList framing. Individual
/// versions remain opaque so retry lists can carry future ECH versions.
pub fn validateConfigList(config_list: []const u8) Error!void {
    var list_pos: usize = 0;
    const list = readU16Vector(config_list, &list_pos) catch
        return error.InvalidConfigList;
    if (list_pos != config_list.len or list.len < 4) {
        return error.InvalidConfigList;
    }
    var config_pos: usize = 0;
    while (config_pos < list.len) {
        _ = readInt(u16, list, &config_pos) catch
            return error.InvalidConfigList;
        const contents_len = readInt(u16, list, &config_pos) catch
            return error.InvalidConfigList;
        _ = readSlice(list, &config_pos, contents_len) catch
            return error.InvalidConfigList;
    }
}

/// Parses one exact ECHConfig and requires the mandatory Vail HPKE suite.
pub fn parseConfig(encoded: []const u8) Error!Config {
    var pos: usize = 0;
    const encoded_version = readInt(u16, encoded, &pos) catch
        return error.InvalidConfig;
    const contents = readU16Vector(encoded, &pos) catch
        return error.InvalidConfig;
    if (pos != encoded.len) return error.InvalidConfig;
    if (encoded_version != version) return error.UnsupportedConfig;

    var contents_pos: usize = 0;
    const config_id = readByte(contents, &contents_pos) catch
        return error.InvalidConfig;
    const kem_id = readInt(u16, contents, &contents_pos) catch
        return error.InvalidConfig;
    const public_key_bytes = readU16Vector(contents, &contents_pos) catch
        return error.InvalidConfig;
    const cipher_suites = readU16Vector(contents, &contents_pos) catch
        return error.InvalidConfig;
    const maximum_name_length = readByte(contents, &contents_pos) catch
        return error.InvalidConfig;
    const public_name = readU8Vector(contents, &contents_pos) catch
        return error.InvalidConfig;
    const extensions = readU16Vector(contents, &contents_pos) catch
        return error.InvalidConfig;
    if (contents_pos != contents.len or cipher_suites.len < 4 or
        cipher_suites.len % 4 != 0)
    {
        return error.InvalidConfig;
    }
    if (kem_id != hpke.kem_id or public_key_bytes.len != hpke.public_key_len) {
        return error.UnsupportedConfig;
    }
    try validatePublicName(public_name);
    try validateConfigExtensions(extensions);

    const public_key = public_key_bytes[0..hpke.public_key_len].*;
    var selected_suite: ?CipherSuite = null;
    var suite_pos: usize = 0;
    while (suite_pos < cipher_suites.len) : (suite_pos += 4) {
        const suite = CipherSuite{
            .kdf_id = std.mem.readInt(
                u16,
                cipher_suites[suite_pos..][0..2],
                .big,
            ),
            .aead_id = std.mem.readInt(
                u16,
                cipher_suites[suite_pos + 2 ..][0..2],
                .big,
            ),
        };
        if (selected_suite == null and suite.supported()) {
            selected_suite = suite;
        }
    }
    if (selected_suite == null) return error.UnsupportedConfig;
    try validatePublicKey(public_key);
    return .{
        .encoded = encoded,
        .config_id = config_id,
        .public_key = public_key,
        .cipher_suite = selected_suite.?,
        .maximum_name_length = maximum_name_length,
        .public_name = public_name,
        .extensions = extensions,
    };
}

/// Serializes one ECHConfig, without an enclosing ECHConfigList length.
pub fn writeConfig(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: ConfigOptions,
) Error!void {
    const original_len = output.items.len;
    errdefer output.shrinkRetainingCapacity(original_len);
    try validatePublicName(options.public_name);
    try validatePublicKey(options.public_key);
    if (options.cipher_suites.len == 0 or
        options.cipher_suites.len > std.math.maxInt(u16) / 4)
    {
        return error.InvalidConfig;
    }

    var contents: std.ArrayList(u8) = .empty;
    defer contents.deinit(allocator);
    try contents.append(allocator, options.config_id);
    try appendInt(&contents, allocator, u16, hpke.kem_id);
    try appendInt(&contents, allocator, u16, options.public_key.len);
    try contents.appendSlice(allocator, &options.public_key);
    try appendInt(
        &contents,
        allocator,
        u16,
        options.cipher_suites.len * 4,
    );
    for (options.cipher_suites, 0..) |suite, index| {
        for (options.cipher_suites[0..index]) |previous| {
            if (std.meta.eql(previous, suite)) return error.InvalidConfig;
        }
        try appendInt(&contents, allocator, u16, suite.kdf_id);
        try appendInt(&contents, allocator, u16, suite.aead_id);
    }
    try contents.append(allocator, options.maximum_name_length);
    try contents.append(allocator, @intCast(options.public_name.len));
    try contents.appendSlice(allocator, options.public_name);

    var extension_bytes: std.ArrayList(u8) = .empty;
    defer extension_bytes.deinit(allocator);
    for (options.extensions, 0..) |extension, index| {
        if (extension.data.len > std.math.maxInt(u16)) {
            return error.InvalidConfig;
        }
        for (options.extensions[0..index]) |previous| {
            if (previous.typ == extension.typ) {
                return error.DuplicateConfigExtension;
            }
        }
        try appendInt(&extension_bytes, allocator, u16, extension.typ);
        try appendInt(
            &extension_bytes,
            allocator,
            u16,
            extension.data.len,
        );
        try extension_bytes.appendSlice(allocator, extension.data);
    }
    if (extension_bytes.items.len > std.math.maxInt(u16)) {
        return error.InvalidConfig;
    }
    try appendInt(
        &contents,
        allocator,
        u16,
        extension_bytes.items.len,
    );
    try contents.appendSlice(allocator, extension_bytes.items);
    if (contents.items.len > std.math.maxInt(u16)) {
        return error.InvalidConfig;
    }

    try appendInt(output, allocator, u16, version);
    try appendInt(output, allocator, u16, contents.items.len);
    try output.appendSlice(allocator, contents.items);
}

/// Serializes an ECHConfigList from exact encoded ECHConfig values.
pub fn writeConfigList(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    configs: []const []const u8,
) Error!void {
    if (configs.len == 0) return error.InvalidConfigList;
    var total_len: usize = 0;
    for (configs) |encoded| {
        parseConfigFraming(encoded) catch return error.InvalidConfigList;
        total_len = std.math.add(usize, total_len, encoded.len) catch
            return error.InvalidConfigList;
    }
    if (total_len > std.math.maxInt(u16)) return error.InvalidConfigList;
    const original_len = output.items.len;
    errdefer output.shrinkRetainingCapacity(original_len);
    try appendInt(output, allocator, u16, total_len);
    for (configs) |encoded| try output.appendSlice(allocator, encoded);
}

pub fn parseClientHelloExtension(payload: []const u8) Error!ClientHelloExtension {
    var pos: usize = 0;
    const typ = readByte(payload, &pos) catch
        return error.InvalidEchExtension;
    switch (typ) {
        inner_type => {
            if (pos != payload.len) return error.InvalidEchExtension;
            return .inner;
        },
        outer_type => {
            const kdf_id = readInt(u16, payload, &pos) catch
                return error.InvalidEchExtension;
            const aead_id = readInt(u16, payload, &pos) catch
                return error.InvalidEchExtension;
            const config_id = readByte(payload, &pos) catch
                return error.InvalidEchExtension;
            const enc = readU16Vector(payload, &pos) catch
                return error.InvalidEchExtension;
            const ciphertext = readU16Vector(payload, &pos) catch
                return error.InvalidEchExtension;
            if (pos != payload.len or ciphertext.len == 0) {
                return error.InvalidEchExtension;
            }
            return .{ .outer = .{
                .cipher_suite = .{ .kdf_id = kdf_id, .aead_id = aead_id },
                .config_id = config_id,
                .enc = enc,
                .payload = ciphertext,
            } };
        },
        else => return error.InvalidEchExtension,
    }
}

pub fn writeInnerExtension(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!void {
    try output.append(allocator, inner_type);
}

pub fn writeOuterExtension(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: Outer,
) Error!void {
    if (value.enc.len > std.math.maxInt(u16) or value.payload.len == 0 or
        value.payload.len > std.math.maxInt(u16))
    {
        return error.InvalidEchExtension;
    }
    const original_len = output.items.len;
    errdefer output.shrinkRetainingCapacity(original_len);
    try output.append(allocator, outer_type);
    try appendInt(output, allocator, u16, value.cipher_suite.kdf_id);
    try appendInt(output, allocator, u16, value.cipher_suite.aead_id);
    try output.append(allocator, value.config_id);
    try appendInt(output, allocator, u16, value.enc.len);
    try output.appendSlice(allocator, value.enc);
    try appendInt(output, allocator, u16, value.payload.len);
    try output.appendSlice(allocator, value.payload);
}

/// Stateful RFC 9849 client encryption context. The HPKE context is retained
/// across HelloRetryRequest, where `enc` is omitted and sequence number 1 is
/// used for the second ClientHelloOuter.
pub const ClientContext = struct {
    config: Config,
    sender: hpke.SenderSetup,
    initial_sealed: bool = false,
    retry_sealed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        config: Config,
    ) Error!ClientContext {
        var info: std.ArrayList(u8) = .empty;
        defer info.deinit(allocator);
        try appendHpkeInfo(&info, allocator, config.encoded);
        return .{
            .config = config,
            .sender = try hpke.setupBaseSender(
                io,
                config.public_key,
                info.items,
            ),
        };
    }

    pub fn sealInitial(
        self: *ClientContext,
        inner_output: *std.ArrayList(u8),
        outer_output: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        inner_template: []const u8,
        outer_template: []const u8,
    ) Error!void {
        if (self.initial_sealed) return error.EchContextAlreadyUsed;
        try self.seal(
            inner_output,
            outer_output,
            allocator,
            inner_template,
            outer_template,
            &self.sender.enc,
        );
        self.initial_sealed = true;
    }

    pub fn sealRetry(
        self: *ClientContext,
        inner_output: *std.ArrayList(u8),
        outer_output: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        inner_template: []const u8,
        outer_template: []const u8,
    ) Error!void {
        if (!self.initial_sealed or self.retry_sealed) {
            return error.InvalidRetry;
        }
        try self.seal(
            inner_output,
            outer_output,
            allocator,
            inner_template,
            outer_template,
            "",
        );
        self.retry_sealed = true;
    }

    fn seal(
        self: *ClientContext,
        inner_output: *std.ArrayList(u8),
        outer_output: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        inner_template: []const u8,
        outer_template: []const u8,
        enc: []const u8,
    ) Error!void {
        const inner_start = inner_output.items.len;
        errdefer inner_output.shrinkRetainingCapacity(inner_start);
        const outer_start = outer_output.items.len;
        errdefer outer_output.shrinkRetainingCapacity(outer_start);

        const parsed_inner = client_hello.parse(inner_template) catch
            return error.InvalidInnerClientHello;
        const parsed_outer = client_hello.parse(outer_template) catch
            return error.InvalidClientHello;
        if (!onlyTls13(parsed_inner) or !parsed_outer.offersTls13() or
            parsed_inner.encrypted_client_hello != null or
            parsed_outer.encrypted_client_hello != null or
            parsed_inner.pre_shared_key != null or
            parsed_outer.pre_shared_key != null or
            !std.mem.eql(u8, parsed_inner.session_id, parsed_outer.session_id) or
            std.mem.eql(u8, parsed_inner.random, parsed_outer.random) or
            parsed_outer.server_name == null or
            !std.ascii.eqlIgnoreCase(
                parsed_outer.server_name.?,
                self.config.public_name,
            ))
        {
            return error.InvalidClientHello;
        }

        try appendClientHelloExtension(
            inner_output,
            allocator,
            inner_template,
            extension_type,
            &.{inner_type},
        );
        var encoded_inner: std.ArrayList(u8) = .empty;
        defer encoded_inner.deinit(allocator);
        defer std.crypto.secureZero(u8, encoded_inner.items);
        try encodeClientHelloInner(
            &encoded_inner,
            allocator,
            inner_output.items[inner_start..],
            self.config.maximum_name_length,
        );

        const payload_len = hpke.ciphertextLength(encoded_inner.items.len) catch
            return error.InvalidInnerClientHello;
        var extension_payload: std.ArrayList(u8) = .empty;
        defer extension_payload.deinit(allocator);
        const placeholder = try allocator.alloc(u8, payload_len);
        defer allocator.free(placeholder);
        @memset(placeholder, 0);
        try writeOuterExtension(&extension_payload, allocator, .{
            .cipher_suite = self.config.cipher_suite,
            .config_id = self.config.config_id,
            .enc = enc,
            .payload = placeholder,
        });

        try appendClientHelloExtension(
            outer_output,
            allocator,
            outer_template,
            extension_type,
            extension_payload.items,
        );
        const outer_hello = outer_output.items[outer_start..];
        const aad = try allocator.dupe(u8, outer_hello[4..]);
        defer allocator.free(aad);
        const ciphertext = outer_output.items[outer_output.items.len - payload_len ..];
        try self.sender.context.seal(
            ciphertext,
            encoded_inner.items,
            aad,
        );
    }

    pub fn deinit(self: *ClientContext) void {
        self.sender.deinit();
        self.* = undefined;
    }
};

/// Stateful RFC 9849 server decryption context retained for a possible second
/// ClientHello after HelloRetryRequest.
pub const ServerContext = struct {
    receiver: hpke.ReceiverContext,
    config_id: u8,
    cipher_suite: CipherSuite,
    retry_opened: bool = false,
    failed: bool = false,

    pub fn openRetry(
        self: *ServerContext,
        inner_output: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        outer_client_hello: []const u8,
    ) Error!void {
        if (self.failed) return error.EchContextFailed;
        if (self.retry_opened) return error.InvalidRetry;
        self.open(
            inner_output,
            allocator,
            outer_client_hello,
            true,
        ) catch |err| {
            self.failed = true;
            return err;
        };
        self.retry_opened = true;
    }

    fn open(
        self: *ServerContext,
        inner_output: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        outer_client_hello: []const u8,
        retry: bool,
    ) Error!void {
        const parsed_outer = client_hello.parse(outer_client_hello) catch
            return error.InvalidClientHello;
        if (!parsed_outer.offersTls13() or
            parsed_outer.encrypted_client_hello == null or
            try findClientHelloExtension(
                outer_client_hello,
                outer_extensions_type,
            ) != null)
        {
            return error.InvalidClientHello;
        }
        const extension_location = try findClientHelloExtension(
            outer_client_hello,
            extension_type,
        ) orelse return error.MissingEchExtension;
        const outer = switch (try parseClientHelloExtension(
            extension_location.payload,
        )) {
            .outer => |value| value,
            .inner => return error.InvalidEchExtension,
        };
        if (outer.config_id != self.config_id or
            !std.meta.eql(outer.cipher_suite, self.cipher_suite) or
            (retry and outer.enc.len != 0) or
            (!retry and outer.enc.len != hpke.encapsulated_key_len) or
            outer.payload.len < hpke.tag_len)
        {
            return if (retry) error.InvalidRetry else error.InvalidEchExtension;
        }

        const aad = try clientHelloOuterAad(
            allocator,
            outer_client_hello,
            extension_location,
            outer,
        );
        defer allocator.free(aad);
        const encoded_len = outer.payload.len - hpke.tag_len;
        const encoded_inner = try allocator.alloc(u8, encoded_len);
        defer allocator.free(encoded_inner);
        defer std.crypto.secureZero(u8, encoded_inner);
        try self.receiver.open(encoded_inner, outer.payload, aad);
        try decodeClientHelloInner(
            inner_output,
            allocator,
            encoded_inner,
            outer_client_hello,
        );
    }

    pub fn deinit(self: *ServerContext) void {
        self.receiver.deinit();
        self.* = undefined;
    }
};

/// Opens an initial ClientHelloOuter using one exact ECHConfig and private key.
pub fn openInitial(
    inner_output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    outer_client_hello: []const u8,
    config: Config,
    secret_key: *const hpke.SecretKey,
) Error!ServerContext {
    var key_pair = try hpke.KeyPair.fromSecretKey(secret_key);
    defer key_pair.deinit();
    return openInitialWithKeyPair(
        inner_output,
        allocator,
        outer_client_hello,
        config,
        &key_pair,
    );
}

/// Opens an initial ClientHelloOuter with a reusable, prevalidated key pair.
pub fn openInitialWithKeyPair(
    inner_output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    outer_client_hello: []const u8,
    config: Config,
    key_pair: *const hpke.KeyPair,
) Error!ServerContext {
    if (!std.crypto.timing_safe.eql(
        hpke.PublicKey,
        key_pair.public_key,
        config.public_key,
    )) return error.InvalidPublicKey;

    const extension_location = try findClientHelloExtension(
        outer_client_hello,
        extension_type,
    ) orelse return error.MissingEchExtension;
    const outer = switch (try parseClientHelloExtension(
        extension_location.payload,
    )) {
        .outer => |value| value,
        .inner => return error.InvalidEchExtension,
    };
    if (outer.config_id != config.config_id or
        !std.meta.eql(outer.cipher_suite, config.cipher_suite) or
        outer.enc.len != hpke.encapsulated_key_len or
        outer.payload.len < hpke.tag_len)
    {
        return error.InvalidEchExtension;
    }
    _ = client_hello.parse(outer_client_hello) catch
        return error.InvalidClientHello;

    var info: std.ArrayList(u8) = .empty;
    defer info.deinit(allocator);
    try appendHpkeInfo(&info, allocator, config.encoded);
    var context = ServerContext{
        .receiver = try hpke.setupBaseReceiverWithKeyPair(
            outer.enc[0..hpke.encapsulated_key_len].*,
            key_pair,
            info.items,
        ),
        .config_id = config.config_id,
        .cipher_suite = config.cipher_suite,
    };
    errdefer context.deinit();
    try context.open(
        inner_output,
        allocator,
        outer_client_hello,
        false,
    );
    return context;
}

/// Derives the ServerHello acceptance signal from the transcript computed with
/// the final eight bytes of ServerHello.random replaced by zeroes.
pub fn acceptConfirmation(
    algorithm: secret.Hash,
    inner_random: [32]u8,
    transcript_hash: transcript.Digest,
) Error![confirmation_len]u8 {
    if (algorithm != transcript_hash.hash) return error.HashMismatch;
    return switch (algorithm) {
        .sha256 => confirmationFor(
            std.crypto.hash.sha2.Sha256,
            inner_random,
            try transcript_hash.sha256(),
            "ech accept confirmation",
        ),
        .sha384 => confirmationFor(
            std.crypto.hash.sha2.Sha384,
            inner_random,
            try transcript_hash.sha384(),
            "ech accept confirmation",
        ),
        .sm3 => confirmationFor(
            sm3.Hash,
            inner_random,
            try transcript_hash.sm3(),
            "ech accept confirmation",
        ),
    };
}

/// Derives the HelloRetryRequest ECH acceptance signal.
pub fn hrrAcceptConfirmation(
    algorithm: secret.Hash,
    inner_random: [32]u8,
    transcript_hash: transcript.Digest,
) Error![confirmation_len]u8 {
    if (algorithm != transcript_hash.hash) return error.HashMismatch;
    return switch (algorithm) {
        .sha256 => confirmationFor(
            std.crypto.hash.sha2.Sha256,
            inner_random,
            try transcript_hash.sha256(),
            "hrr ech accept confirmation",
        ),
        .sha384 => confirmationFor(
            std.crypto.hash.sha2.Sha384,
            inner_random,
            try transcript_hash.sha384(),
            "hrr ech accept confirmation",
        ),
        .sm3 => confirmationFor(
            sm3.Hash,
            inner_random,
            try transcript_hash.sm3(),
            "hrr ech accept confirmation",
        ),
    };
}

/// Computes the transcript digest used to verify a ServerHello acceptance
/// signal without copying the message. The caller supplies the transcript
/// state through the accepted ClientHelloInner (and HRR/ClientHelloInner2, if
/// present).
pub fn serverHelloConfirmationTranscript(
    prefix: transcript.State,
    server_hello: []const u8,
) Error!transcript.Digest {
    const confirmation_offset = 4 + 2 + 32 - confirmation_len;
    if (server_hello.len < confirmation_offset + confirmation_len or
        server_hello[0] != 2 or
        readU24At(server_hello[1..4]) != server_hello.len - 4)
    {
        return error.InvalidClientHello;
    }
    var state = prefix;
    state.update(server_hello[0..confirmation_offset]);
    state.update(&([_]u8{0} ** confirmation_len));
    state.update(server_hello[confirmation_offset + confirmation_len ..]);
    return state.digest();
}

/// Computes the HRR confirmation transcript by replacing the borrowed
/// confirmation field with zeroes and applying TLS 1.3's message_hash rollup.
pub fn helloRetryRequestConfirmationTranscript(
    algorithm: secret.Hash,
    first_inner_client_hello: []const u8,
    hello_retry_request: []const u8,
    confirmation: []const u8,
) Error!transcript.Digest {
    if (confirmation.len != confirmation_len) {
        return error.InvalidEchExtension;
    }
    const message_start = @intFromPtr(hello_retry_request.ptr);
    const confirmation_start = @intFromPtr(confirmation.ptr);
    if (confirmation_start < message_start) return error.InvalidEchExtension;
    const offset = confirmation_start - message_start;
    if (offset > hello_retry_request.len or
        confirmation.len > hello_retry_request.len - offset)
    {
        return error.InvalidEchExtension;
    }

    const first_hash = transcript.hashFor(
        algorithm,
        &.{first_inner_client_hello},
    );
    const message_hash_header = [4]u8{
        254,
        0,
        0,
        @intCast(first_hash.bytes().len),
    };
    var state = transcript.State.init(algorithm);
    state.update(&message_hash_header);
    state.update(first_hash.bytes());
    state.update(hello_retry_request[0..offset]);
    state.update(&([_]u8{0} ** confirmation_len));
    state.update(hello_retry_request[offset + confirmation_len ..]);
    return state.digest();
}

fn confirmationFor(
    comptime Hash: type,
    inner_random: [32]u8,
    transcript_hash: [Hash.digest_length]u8,
    label: []const u8,
) [confirmation_len]u8 {
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
    const zero = [_]u8{0} ** Hash.digest_length;
    var confirmation_key = Hkdf.extract(&zero, &inner_random);
    defer std.crypto.secureZero(u8, &confirmation_key);
    return std.crypto.tls.hkdfExpandLabel(
        Hkdf,
        confirmation_key,
        label,
        &transcript_hash,
        confirmation_len,
    );
}

fn appendHpkeInfo(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    encoded_config: []const u8,
) std.mem.Allocator.Error!void {
    try output.appendSlice(allocator, "tls ech\x00");
    try output.appendSlice(allocator, encoded_config);
}

fn onlyTls13(parsed: client_hello.Parsed) bool {
    const versions = parsed.supported_versions;
    if (versions.len == 0 or versions.len % 2 != 0) {
        return false;
    }
    var version_pos: usize = 0;
    while (version_pos < versions.len) : (version_pos += 2) {
        if (std.mem.readInt(
            u16,
            versions[version_pos..][0..2],
            .big,
        ) < 0x0304) return false;
    }
    return true;
}

const ClientHelloLayout = struct {
    session_id: []const u8,
    extensions_len_offset: usize,
    extensions: []const u8,
};

fn parseClientHelloLayout(bytes: []const u8) Error!ClientHelloLayout {
    var pos: usize = 0;
    if ((readByte(bytes, &pos) catch return error.InvalidClientHello) !=
        client_hello.handshake_type_client_hello)
    {
        return error.InvalidClientHello;
    }
    const body_len = readU24(bytes, &pos) catch
        return error.InvalidClientHello;
    if (body_len != bytes.len - pos) return error.InvalidClientHello;
    _ = readSlice(bytes, &pos, 2 + 32) catch
        return error.InvalidClientHello;
    const session_id = readU8Vector(bytes, &pos) catch
        return error.InvalidClientHello;
    _ = readU16Vector(bytes, &pos) catch return error.InvalidClientHello;
    _ = readU8Vector(bytes, &pos) catch return error.InvalidClientHello;
    const extensions_len_offset = pos;
    const extensions = readU16Vector(bytes, &pos) catch
        return error.InvalidClientHello;
    if (pos != bytes.len) return error.InvalidClientHello;
    return .{
        .session_id = session_id,
        .extensions_len_offset = extensions_len_offset,
        .extensions = extensions,
    };
}

const ExtensionLocation = struct {
    full_start: usize,
    full_len: usize,
    payload_start: usize,
    payload: []const u8,
};

fn findClientHelloExtension(
    bytes: []const u8,
    target: u16,
) Error!?ExtensionLocation {
    const layout = try parseClientHelloLayout(bytes);
    const extensions_start = layout.extensions_len_offset + 2;
    var pos: usize = 0;
    while (pos < layout.extensions.len) {
        const start = pos;
        const typ = readInt(u16, layout.extensions, &pos) catch
            return error.InvalidClientHello;
        const payload = readU16Vector(layout.extensions, &pos) catch
            return error.InvalidClientHello;
        if (typ == target) return .{
            .full_start = extensions_start + start,
            .full_len = pos - start,
            .payload_start = extensions_start + pos - payload.len,
            .payload = payload,
        };
    }
    return null;
}

fn appendClientHelloExtension(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    template: []const u8,
    typ: u16,
    payload: []const u8,
) Error!void {
    if (payload.len > std.math.maxInt(u16)) return error.InvalidClientHello;
    const layout = try parseClientHelloLayout(template);
    if (try findClientHelloExtension(template, typ) != null) {
        return error.InvalidClientHello;
    }
    const added_len = 4 + payload.len;
    if (layout.extensions.len > std.math.maxInt(u16) - added_len or
        template.len - 4 > std.math.maxInt(u24) - added_len)
    {
        return error.InvalidClientHello;
    }

    const start = output.items.len;
    errdefer output.shrinkRetainingCapacity(start);
    try output.appendSlice(allocator, template);
    std.mem.writeInt(
        u24,
        output.items[start + 1 ..][0..3],
        @intCast(template.len - 4 + added_len),
        .big,
    );
    std.mem.writeInt(
        u16,
        output.items[start + layout.extensions_len_offset ..][0..2],
        @intCast(layout.extensions.len + added_len),
        .big,
    );
    try appendInt(output, allocator, u16, typ);
    try appendInt(output, allocator, u16, payload.len);
    try output.appendSlice(allocator, payload);
}

fn encodeClientHelloInner(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    inner_client_hello: []const u8,
    configured_maximum_name_length: u8,
) Error!void {
    const parsed = client_hello.parse(inner_client_hello) catch
        return error.InvalidInnerClientHello;
    const extension = parsed.encrypted_client_hello orelse
        return error.MissingEchExtension;
    if (try parseClientHelloExtension(extension) != .inner or
        !onlyTls13(parsed) or parsed.pre_shared_key != null)
    {
        return error.InvalidInnerClientHello;
    }
    const layout = try parseClientHelloLayout(inner_client_hello);
    const session_len_offset = 4 + 2 + 32;
    const after_session = session_len_offset + 1 + layout.session_id.len;
    const start = output.items.len;
    errdefer output.shrinkRetainingCapacity(start);
    try output.appendSlice(
        allocator,
        inner_client_hello[4..session_len_offset],
    );
    try output.append(allocator, 0);
    try output.appendSlice(allocator, inner_client_hello[after_session..]);

    const maximum_name_length: usize = if (configured_maximum_name_length == 0)
        255
    else
        configured_maximum_name_length;
    const name_padding = if (parsed.server_name) |server_name|
        maximum_name_length -| server_name.len
    else
        maximum_name_length + 9;
    try output.appendNTimes(allocator, 0, name_padding);
    const encoded_len = output.items.len - start;
    const block_padding = 31 - ((encoded_len - 1) % 32);
    try output.appendNTimes(allocator, 0, block_padding);
}

fn clientHelloOuterAad(
    allocator: std.mem.Allocator,
    outer_client_hello: []const u8,
    extension_location: ExtensionLocation,
    outer: Outer,
) Error![]u8 {
    var pos: usize = 0;
    _ = readByte(extension_location.payload, &pos) catch
        return error.InvalidEchExtension;
    _ = readSlice(extension_location.payload, &pos, 2 + 2 + 1) catch
        return error.InvalidEchExtension;
    _ = readU16Vector(extension_location.payload, &pos) catch
        return error.InvalidEchExtension;
    const payload_len = readInt(u16, extension_location.payload, &pos) catch
        return error.InvalidEchExtension;
    if (payload_len != outer.payload.len or
        pos + payload_len != extension_location.payload.len)
    {
        return error.InvalidEchExtension;
    }
    const absolute_payload_start = extension_location.payload_start + pos;
    var aad = try allocator.dupe(u8, outer_client_hello[4..]);
    const aad_payload_start = absolute_payload_start - 4;
    @memset(aad[aad_payload_start..][0..payload_len], 0);
    return aad;
}

fn decodeClientHelloInner(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    encoded: []const u8,
    outer_client_hello: []const u8,
) Error!void {
    const outer_layout = try parseClientHelloLayout(outer_client_hello);
    var pos: usize = 0;
    _ = readSlice(encoded, &pos, 2 + 32) catch
        return error.InvalidInnerClientHello;
    const inner_session = readU8Vector(encoded, &pos) catch
        return error.InvalidInnerClientHello;
    if (inner_session.len != 0) return error.InvalidInnerClientHello;
    _ = readU16Vector(encoded, &pos) catch
        return error.InvalidInnerClientHello;
    _ = readU8Vector(encoded, &pos) catch
        return error.InvalidInnerClientHello;
    const inner_extensions = readU16Vector(encoded, &pos) catch
        return error.InvalidInnerClientHello;
    const body_end = pos;
    for (encoded[body_end..]) |byte| {
        if (byte != 0) return error.InvalidInnerClientHello;
    }

    var expanded_extensions: std.ArrayList(u8) = .empty;
    defer expanded_extensions.deinit(allocator);
    var seen = std.StaticBitSet(65536).initEmpty();
    var saw_inner_ech = false;
    var saw_outer_extensions = false;
    var outer_search_pos: usize = 0;
    var inner_pos: usize = 0;
    while (inner_pos < inner_extensions.len) {
        const extension_start = inner_pos;
        const typ = readInt(u16, inner_extensions, &inner_pos) catch
            return error.InvalidInnerClientHello;
        const payload = readU16Vector(inner_extensions, &inner_pos) catch
            return error.InvalidInnerClientHello;
        if (typ == outer_extensions_type) {
            if (saw_outer_extensions) return error.InvalidInnerClientHello;
            saw_outer_extensions = true;
            var references_pos: usize = 0;
            const references = readU8Vector(payload, &references_pos) catch
                return error.InvalidInnerClientHello;
            if (references_pos != payload.len or references.len < 2 or
                references.len % 2 != 0)
            {
                return error.InvalidInnerClientHello;
            }
            var ref_pos: usize = 0;
            while (ref_pos < references.len) : (ref_pos += 2) {
                const referenced = std.mem.readInt(
                    u16,
                    references[ref_pos..][0..2],
                    .big,
                );
                if (referenced == extension_type or
                    referenced == outer_extensions_type or
                    seen.isSet(referenced))
                {
                    return error.InvalidInnerClientHello;
                }
                const raw = try findNextOuterExtension(
                    outer_layout.extensions,
                    &outer_search_pos,
                    referenced,
                );
                seen.set(referenced);
                try expanded_extensions.appendSlice(allocator, raw);
            }
        } else {
            if (seen.isSet(typ)) return error.InvalidInnerClientHello;
            seen.set(typ);
            if (typ == extension_type) {
                if (try parseClientHelloExtension(payload) != .inner) {
                    return error.InvalidInnerClientHello;
                }
                saw_inner_ech = true;
            }
            try expanded_extensions.appendSlice(
                allocator,
                inner_extensions[extension_start..inner_pos],
            );
        }
    }
    if (!saw_inner_ech or
        expanded_extensions.items.len > std.math.maxInt(u16))
    {
        return error.InvalidInnerClientHello;
    }

    const body_len = 2 + 32 + 1 + outer_layout.session_id.len +
        (body_end - (2 + 32 + 1)) - 2 - inner_extensions.len +
        2 + expanded_extensions.items.len;
    if (body_len > std.math.maxInt(u24)) return error.InvalidInnerClientHello;
    const output_start = output.items.len;
    errdefer output.shrinkRetainingCapacity(output_start);
    try output.append(allocator, client_hello.handshake_type_client_hello);
    try appendU24(output, allocator, @intCast(body_len));
    try output.appendSlice(allocator, encoded[0 .. 2 + 32]);
    try output.append(allocator, @intCast(outer_layout.session_id.len));
    try output.appendSlice(allocator, outer_layout.session_id);
    const after_empty_session = 2 + 32 + 1;
    const before_extensions_len = body_end - 2 - inner_extensions.len;
    try output.appendSlice(
        allocator,
        encoded[after_empty_session..before_extensions_len],
    );
    try appendInt(
        output,
        allocator,
        u16,
        expanded_extensions.items.len,
    );
    try output.appendSlice(allocator, expanded_extensions.items);

    const parsed = client_hello.parse(output.items[output_start..]) catch {
        output.shrinkRetainingCapacity(output_start);
        return error.InvalidInnerClientHello;
    };
    if (!onlyTls13(parsed)) {
        output.shrinkRetainingCapacity(output_start);
        return error.InvalidInnerClientHello;
    }
}

fn findNextOuterExtension(
    extensions: []const u8,
    search_pos: *usize,
    target: u16,
) Error![]const u8 {
    while (search_pos.* < extensions.len) {
        const start = search_pos.*;
        const typ = readInt(u16, extensions, search_pos) catch
            return error.InvalidInnerClientHello;
        _ = readU16Vector(extensions, search_pos) catch
            return error.InvalidInnerClientHello;
        if (typ == target) return extensions[start..search_pos.*];
    }
    return error.InvalidInnerClientHello;
}

fn parseConfigFraming(encoded: []const u8) Error!void {
    var pos: usize = 0;
    _ = readInt(u16, encoded, &pos) catch return error.InvalidConfig;
    _ = readU16Vector(encoded, &pos) catch return error.InvalidConfig;
    if (pos != encoded.len) return error.InvalidConfig;
}

fn validateConfigExtensions(extensions: []const u8) Error!void {
    var seen = std.StaticBitSet(65536).initEmpty();
    var pos: usize = 0;
    while (pos < extensions.len) {
        const typ = readInt(u16, extensions, &pos) catch
            return error.InvalidConfig;
        _ = readU16Vector(extensions, &pos) catch
            return error.InvalidConfig;
        if (seen.isSet(typ)) return error.DuplicateConfigExtension;
        seen.set(typ);
        // RFC 9849 currently defines no config extensions. Unknown extension
        // types with the high bit set are mandatory and make this config
        // unsuitable, while optional unknown extensions are preserved.
        if (typ & 0x8000 != 0) {
            return error.UnsupportedMandatoryConfigExtension;
        }
    }
}

fn validatePublicKey(public_key: hpke.PublicKey) Error!void {
    const probe_secret = [_]u8{0x42} ** hpke.secret_key_len;
    var shared = X25519.scalarmult(probe_secret, public_key) catch
        return error.InvalidPublicKey;
    defer std.crypto.secureZero(u8, &shared);
    var aggregate: u8 = 0;
    for (shared) |byte| aggregate |= byte;
    if (aggregate == 0) return error.InvalidPublicKey;
}

fn validatePublicName(name: []const u8) Error!void {
    if (name.len == 0 or name.len > std.math.maxInt(u8) or
        name[0] == '.' or name[name.len - 1] == '.')
    {
        return error.InvalidPublicName;
    }
    var label_start: usize = 0;
    for (name, 0..) |byte, index| {
        if (byte == '.') {
            try validateLabel(name[label_start..index], false);
            label_start = index + 1;
        } else if (!isLdh(byte)) {
            return error.InvalidPublicName;
        }
    }
    try validateLabel(name[label_start..], true);
}

fn validateLabel(label: []const u8, final: bool) Error!void {
    if (label.len == 0 or label.len > 63 or label[0] == '-' or
        label[label.len - 1] == '-')
    {
        return error.InvalidPublicName;
    }
    if (!final) return;

    var all_digits = true;
    for (label) |byte| {
        if (byte < '0' or byte > '9') {
            all_digits = false;
            break;
        }
    }
    if (all_digits) return error.InvalidPublicName;
    if (label.len >= 2 and label[0] == '0' and
        (label[1] == 'x' or label[1] == 'X'))
    {
        var all_hex = true;
        for (label[2..]) |byte| {
            if (!std.ascii.isHex(byte)) {
                all_hex = false;
                break;
            }
        }
        if (all_hex) return error.InvalidPublicName;
    }
}

fn isLdh(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-';
}

fn readByte(bytes: []const u8, pos: *usize) error{InvalidEncoding}!u8 {
    return (try readSlice(bytes, pos, 1))[0];
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) error{InvalidEncoding}!T {
    const value = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, value[0..@sizeOf(T)], .big);
}

fn readU24(bytes: []const u8, pos: *usize) error{InvalidEncoding}!usize {
    const value = try readSlice(bytes, pos, 3);
    return (@as(usize, value[0]) << 16) |
        (@as(usize, value[1]) << 8) |
        value[2];
}

fn readU24At(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn readU8Vector(
    bytes: []const u8,
    pos: *usize,
) error{InvalidEncoding}![]const u8 {
    return readSlice(bytes, pos, try readByte(bytes, pos));
}

fn readU16Vector(
    bytes: []const u8,
    pos: *usize,
) error{InvalidEncoding}![]const u8 {
    return readSlice(bytes, pos, try readInt(u16, bytes, pos));
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) error{InvalidEncoding}![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch
        return error.InvalidEncoding;
    if (end > bytes.len) return error.InvalidEncoding;
    defer pos.* = end;
    return bytes[pos.*..end];
}

fn appendInt(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: anytype,
) std.mem.Allocator.Error!void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .big);
    try output.appendSlice(allocator, &encoded);
}

fn appendU24(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u24,
) std.mem.Allocator.Error!void {
    try output.appendSlice(allocator, &.{
        @truncate(value >> 16),
        @truncate(value >> 8),
        @truncate(value),
    });
}

const aws_lc_private_key = [_]u8{
    0xbc, 0xb5, 0x51, 0x29, 0x31, 0x10, 0x30, 0xc9,
    0xed, 0x26, 0xde, 0xd4, 0xb3, 0xdf, 0x3a, 0xce,
    0x06, 0x8a, 0xee, 0x17, 0xab, 0xce, 0xd7, 0xdb,
    0xf3, 0x11, 0xe5, 0xa8, 0xf3, 0xb1, 0x8e, 0x24,
};

const aws_lc_config = [_]u8{
    0xfe, 0x0d, 0x00, 0x41, 0x01, 0x00, 0x20, 0x00,
    0x20, 0xa6, 0x9a, 0x41, 0x48, 0x5d, 0x32, 0x96,
    0xa4, 0xe0, 0xc3, 0x6a, 0xee, 0xf6, 0x63, 0x0f,
    0x59, 0x32, 0x6f, 0xdc, 0xff, 0x81, 0x29, 0x59,
    0xa5, 0x85, 0xd3, 0x9b, 0x3b, 0xde, 0x98, 0x55,
    0x5c, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x03, 0x10, 0x0e, 0x70, 0x75, 0x62,
    0x6c, 0x69, 0x63, 0x2e, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x00, 0x00,
};

test "RFC 9849 config parser matches AWS-LC's wire fixture" {
    const config = try parseConfig(&aws_lc_config);
    try std.testing.expectEqual(@as(u8, 1), config.config_id);
    try std.testing.expectEqual(@as(u8, 16), config.maximum_name_length);
    try std.testing.expectEqualStrings("public.example", config.public_name);
    try std.testing.expect(config.cipher_suite.supported());
    try std.testing.expectEqual(@as(usize, 0), config.extensions.len);

    var key_pair = try hpke.KeyPair.fromSecretKey(&aws_lc_private_key);
    defer key_pair.deinit();
    try std.testing.expectEqual(config.public_key, key_pair.public_key);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try writeConfig(&encoded, std.testing.allocator, .{
        .config_id = 1,
        .public_key = key_pair.public_key,
        .cipher_suites = &.{
            .{ .kdf_id = 1, .aead_id = 1 },
            .{ .kdf_id = 1, .aead_id = 3 },
        },
        .maximum_name_length = 16,
        .public_name = "public.example",
    });
    try std.testing.expectEqualSlices(u8, &aws_lc_config, encoded.items);
}

test "ECHConfigList skips unknown and unsupported configs" {
    var unknown = aws_lc_config;
    unknown[0..2].* = .{ 0xaa, 0xaa };
    var unsupported = aws_lc_config;
    unsupported[5..7].* = .{ 0x99, 0x99 };
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try writeConfigList(
        &list,
        std.testing.allocator,
        &.{ &unknown, &unsupported, &aws_lc_config },
    );
    const selected = try selectConfig(list.items);
    try std.testing.expectEqualSlices(u8, &aws_lc_config, selected.encoded);

    try std.testing.expectError(
        error.InvalidConfigList,
        selectConfig(list.items[0 .. list.items.len - 1]),
    );
}

test "ECH configs reject mandatory extensions and unsafe public names" {
    var key_pair = try hpke.KeyPair.fromSecretKey(&aws_lc_private_key);
    defer key_pair.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.InvalidPublicName,
        writeConfig(&encoded, std.testing.allocator, .{
            .config_id = 2,
            .public_key = key_pair.public_key,
            .public_name = "127.0.0.1",
        }),
    );
    try std.testing.expectError(
        error.InvalidPublicName,
        writeConfig(&encoded, std.testing.allocator, .{
            .config_id = 2,
            .public_key = key_pair.public_key,
            .public_name = "bad-.example",
        }),
    );

    try writeConfig(&encoded, std.testing.allocator, .{
        .config_id = 2,
        .public_key = key_pair.public_key,
        .public_name = "public.example",
        .extensions = &.{.{ .typ = 0x8001, .data = "required" }},
    });
    try std.testing.expectError(
        error.UnsupportedMandatoryConfigExtension,
        parseConfig(encoded.items),
    );
}

test "ECHClientHello inner and outer extension codecs are strict" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try writeInnerExtension(&encoded, std.testing.allocator);
    try std.testing.expectEqual(
        ClientHelloExtension.inner,
        try parseClientHelloExtension(encoded.items),
    );
    try std.testing.expectError(
        error.InvalidEchExtension,
        parseClientHelloExtension(&.{ inner_type, 0 }),
    );

    encoded.clearRetainingCapacity();
    try writeOuterExtension(&encoded, std.testing.allocator, .{
        .cipher_suite = .{ .kdf_id = 1, .aead_id = 1 },
        .config_id = 7,
        .enc = &([_]u8{0x11} ** 32),
        .payload = "ciphertext",
    });
    const parsed = (try parseClientHelloExtension(encoded.items)).outer;
    try std.testing.expect(parsed.cipher_suite.supported());
    try std.testing.expectEqual(@as(u8, 7), parsed.config_id);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x11} ** 32), parsed.enc);
    try std.testing.expectEqualStrings("ciphertext", parsed.payload);
    try std.testing.expectError(
        error.InvalidEchExtension,
        parseClientHelloExtension(encoded.items[0 .. encoded.items.len - 1]),
    );
}

test "ECH confirmation labels match an independent HKDF oracle" {
    var inner_random: [32]u8 = undefined;
    for (&inner_random, 0..) |*byte, index| byte.* = @intCast(index);
    const server_digest = transcript.hashFor(
        .sha256,
        &.{"inner client hello and server hello"},
    );
    try std.testing.expectEqual(
        try hexBytes("f5f6a8eab38c831d"),
        try acceptConfirmation(.sha256, inner_random, server_digest),
    );
    const hrr_digest = transcript.hashFor(
        .sha384,
        &.{"message hash and hello retry request"},
    );
    try std.testing.expectEqual(
        try hexBytes("84be2d7fa3e2cecb"),
        try hrrAcceptConfirmation(.sha384, inner_random, hrr_digest),
    );
    try std.testing.expectError(
        error.HashMismatch,
        acceptConfirmation(.sha256, inner_random, hrr_digest),
    );
}

test "EncodedClientHelloInner expands outer extensions in linear order" {
    const allocator = std.testing.allocator;
    const share = [_]u8{0x5a} ** 32;
    var inner_template: std.ArrayList(u8) = .empty;
    defer inner_template.deinit(allocator);
    try client_hello.writeWithKeyShare(&inner_template, allocator, .{
        .random = [_]u8{0x31} ** 32,
        .session_id = "inner-session-is-removed",
        .server_name = "private.example",
        .key_share = null,
        .supported_groups = &.{0x001d},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .supported_versions = &.{0x0304},
    });
    var inner_with_ech: std.ArrayList(u8) = .empty;
    defer inner_with_ech.deinit(allocator);
    try appendClientHelloExtension(
        &inner_with_ech,
        allocator,
        inner_template.items,
        extension_type,
        &.{inner_type},
    );
    var compressed_inner: std.ArrayList(u8) = .empty;
    defer compressed_inner.deinit(allocator);
    try appendClientHelloExtension(
        &compressed_inner,
        allocator,
        inner_with_ech.items,
        outer_extensions_type,
        &.{ 2, 0, 0x33 },
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    defer std.crypto.secureZero(u8, encoded.items);
    try encodeClientHelloInner(
        &encoded,
        allocator,
        compressed_inner.items,
        15,
    );

    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try client_hello.writeWithKeyShare(&outer, allocator, .{
        .random = [_]u8{0x32} ** 32,
        .session_id = "outer-session",
        .server_name = "public.example",
        .key_share = .{ .group = 0x001d, .key_exchange = &share },
        .supported_groups = &.{0x001d},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .supported_versions = &.{0x0304},
    });
    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);
    try decodeClientHelloInner(&decoded, allocator, encoded.items, outer.items);
    const parsed = try client_hello.parse(decoded.items);
    try std.testing.expectEqualStrings("outer-session", parsed.session_id);
    try std.testing.expectEqualStrings("private.example", parsed.server_name.?);
    try std.testing.expectEqualSlices(
        u8,
        &share,
        (try parsed.keyShareForGroup(0x001d)).?.key_exchange,
    );
}

test "RFC 9849 initial and retry ClientHello encryption round trip" {
    const allocator = std.testing.allocator;
    const config = try parseConfig(&aws_lc_config);
    const session_id = "compatibility-session";
    const share = [_]u8{0x44} ** 32;

    var inner_template: std.ArrayList(u8) = .empty;
    defer inner_template.deinit(allocator);
    try client_hello.writeWithKeyShare(&inner_template, allocator, .{
        .random = [_]u8{0x11} ** 32,
        .session_id = session_id,
        .server_name = "secret.example",
        .key_share = .{ .group = 0x001d, .key_exchange = &share },
        .supported_groups = &.{0x001d},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .supported_versions = &.{0x0304},
        .alpn_protocols = &.{ "h2", "http/1.1" },
    });
    var outer_template: std.ArrayList(u8) = .empty;
    defer outer_template.deinit(allocator);
    try client_hello.writeWithKeyShare(&outer_template, allocator, .{
        .random = [_]u8{0x22} ** 32,
        .session_id = session_id,
        .server_name = "public.example",
        .key_share = .{ .group = 0x001d, .key_exchange = &share },
        .supported_groups = &.{0x001d},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .supported_versions = &.{0x0304},
    });

    var client = try ClientContext.init(allocator, std.testing.io, config);
    defer client.deinit();
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try client.sealInitial(
        &inner,
        &outer,
        allocator,
        inner_template.items,
        outer_template.items,
    );

    const parsed_inner = try client_hello.parse(inner.items);
    try std.testing.expectEqualStrings(
        "secret.example",
        parsed_inner.server_name.?,
    );
    try std.testing.expectEqual(
        ClientHelloExtension.inner,
        try parseClientHelloExtension(
            parsed_inner.encrypted_client_hello.?,
        ),
    );
    const parsed_outer = try client_hello.parse(outer.items);
    try std.testing.expectEqualStrings(
        "public.example",
        parsed_outer.server_name.?,
    );
    const outer_ech = (try parseClientHelloExtension(
        parsed_outer.encrypted_client_hello.?,
    )).outer;
    try std.testing.expectEqual(@as(usize, hpke.encapsulated_key_len), outer_ech.enc.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        (outer_ech.payload.len - hpke.tag_len) % 32,
    );

    var tampered = try allocator.dupe(u8, outer.items);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    var rejected_inner: std.ArrayList(u8) = .empty;
    defer rejected_inner.deinit(allocator);
    try std.testing.expectError(
        error.AuthenticationFailed,
        openInitial(
            &rejected_inner,
            allocator,
            tampered,
            config,
            &aws_lc_private_key,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_inner.items.len);

    var recovered: std.ArrayList(u8) = .empty;
    defer recovered.deinit(allocator);
    var server = try openInitial(
        &recovered,
        allocator,
        outer.items,
        config,
        &aws_lc_private_key,
    );
    defer server.deinit();
    try std.testing.expectEqualSlices(u8, inner.items, recovered.items);

    inner.clearRetainingCapacity();
    outer.clearRetainingCapacity();
    recovered.clearRetainingCapacity();
    try client.sealRetry(
        &inner,
        &outer,
        allocator,
        inner_template.items,
        outer_template.items,
    );
    const retry_outer = (try parseClientHelloExtension(
        (try client_hello.parse(outer.items)).encrypted_client_hello.?,
    )).outer;
    try std.testing.expectEqual(@as(usize, 0), retry_outer.enc.len);
    try server.openRetry(&recovered, allocator, outer.items);
    try std.testing.expectEqualSlices(u8, inner.items, recovered.items);
    try std.testing.expectError(
        error.InvalidRetry,
        client.sealRetry(
            &inner,
            &outer,
            allocator,
            inner_template.items,
            outer_template.items,
        ),
    );
    try std.testing.expectError(
        error.InvalidRetry,
        server.openRetry(&recovered, allocator, outer.items),
    );
}

fn hexBytes(comptime hex: []const u8) ![hex.len / 2]u8 {
    var result: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, hex);
    return result;
}
