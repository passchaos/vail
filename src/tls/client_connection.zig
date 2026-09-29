//! Incremental TLS 1.3 client handshake state.
//!
//! The client owns its ClientHello transcript and one-shot key-exchange state,
//! validates ServerHello choices against that offer, decrypts and reassembles
//! the authenticated server flight, emits encrypted client Finished records,
//! and transfers directly into established application traffic.

const std = @import("std");
const alert = @import("alert.zig");
const auth = @import("auth.zig");
const certificate_compression = @import("certificate_compression.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_auth = @import("client_auth.zig");
const client_handshake = @import("client_handshake.zig");
const client_hello = @import("client_hello.zig");
const connection = @import("connection.zig");
const key_exchange = @import("key_exchange.zig");
const key_schedule = @import("key_schedule.zig");
const psk = @import("psk.zig");
const record = @import("record.zig");
const secret = @import("secret.zig");
const server_handshake = @import("server_handshake.zig");
const server_hello = @import("server_hello.zig");
const stream = @import("stream.zig");
const ticket = @import("ticket.zig");
const traffic = @import("traffic.zig");
const transcript = @import("transcript.zig");

pub const Error = std.mem.Allocator.Error || client_hello.Error ||
    server_hello.Error || key_exchange.Error || key_schedule.Error ||
    client_handshake.Error || psk.Error || stream.ProtectedError ||
    connection.Error ||
    error{
        ClientHelloTooLarge,
        ServerFlightTooLarge,
        UnexpectedRecord,
        UnexpectedHandshakeMessage,
        UnexpectedApplicationData,
        DuplicateChangeCipherSpec,
        DuplicateHelloRetryRequest,
        MissingRetryKeyMaterial,
        DuplicateKeyMaterial,
        InvalidPskSelection,
        InvalidPskSuite,
        ServerSelectedUnofferedSuite,
        ServerSelectedUnofferedGroup,
        ServerSelectedUnofferedAlpn,
        SessionIdMismatch,
        PeerAbortedHandshake,
        AlreadyEstablished,
        ConnectionFailed,
    };

pub const Stage = enum {
    server_hello,
    server_flight,
    established,
    failed,
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    random: [32]u8,
    session_id: []const u8 = &.{},
    server_name: ?[]const u8 = null,
    key_material: *key_exchange.ClientKeyMaterial,
    /// Optional single-use material for a different group selected by HRR.
    retry_key_material: ?*key_exchange.ClientKeyMaterial = null,
    cipher_suites: []const cipher_suite.Suite =
        &cipher_suite.default_preference,
    additional_cipher_suites: []const u16 = &.{},
    supported_versions: []const u16 = &.{0x0304},
    signature_schemes: []const u16 = &client_hello.default_signature_schemes,
    /// Legacy RFC 5077 extension carried only when a version-negotiating
    /// caller also offers TLS 1.2. Null omits it; an empty slice requests one.
    tls12_session_ticket: ?[]const u8 = null,
    offer_extended_master_secret: bool = false,
    alpn_protocols: []const []const u8 = &.{},
    request_ocsp: bool = false,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{.zlib},
    max_decompressed_certificate_len: usize = 64 * 1024,
    server_verifier: auth.ClientVerifier,
    server_certificate_type: auth.CertificateType = .x509,
    client_identity: ?client_auth.ClientIdentity = null,
    resumption: ?ClientPsk = null,
};

pub const ClientPsk = struct {
    identity: []const u8,
    secret: secret.Secret,
    obfuscated_ticket_age: u32,
    suite: cipher_suite.Suite = .aes_128_gcm_sha256,
    max_early_data_size: ?u32 = null,

    pub fn fromCached(
        cached: *const ticket.Cached,
        now_ms: u64,
    ) ticket.Error!ClientPsk {
        return .{
            .identity = cached.identity,
            .secret = cached.psk,
            .obfuscated_ticket_age = try cached.obfuscatedTicketAge(now_ms),
            .suite = cached.suite,
            .max_early_data_size = cached.max_early_data_size,
        };
    }
};

pub fn ClientConnection(
    comptime max_server_flight_len: usize,
    comptime max_post_handshake_len: usize,
) type {
    return struct {
        const Self = @This();
        const Application = connection.ApplicationConnection(
            max_post_handshake_len,
        );

        pub const Established = struct {
            allocator: std.mem.Allocator,
            application: Application,
            master_secret: secret.Secret,
            transcript_after_client_finished: transcript.Digest,
            selected_alpn: ?[]u8,
            peer_certificate_chain: [][]const u8,
            resumed: bool,
            early_data_accepted: bool,
            certificate_compression: ?certificate_compression.Algorithm,
            client_certificate_compression: ?certificate_compression.Algorithm,
            server_certificate_type: auth.CertificateType,
            client_certificate_type: auth.CertificateType,

            pub fn cacheNewSessionTicket(
                self: *const Established,
                message: []const u8,
                server_name: []const u8,
                received_at_ms: u64,
            ) (ticket.Error || key_schedule.Error)!ticket.Cached {
                return ticket.cache(
                    self.allocator,
                    message,
                    self.application.traffic.read.suite,
                    self.master_secret,
                    self.transcript_after_client_finished,
                    server_name,
                    self.selected_alpn orelse "",
                    received_at_ms,
                );
            }

            pub fn deinit(self: *Established) void {
                self.application.deinit();
                self.master_secret.deinit();
                if (self.selected_alpn) |alpn| self.allocator.free(alpn);
                for (self.peer_certificate_chain) |certificate| {
                    self.allocator.free(certificate);
                }
                self.allocator.free(self.peer_certificate_chain);
                self.* = undefined;
            }
        };

        pub const Event = union(enum) {
            hello_retry_request: void,
            server_hello: void,
            compatibility_change_cipher_spec: void,
            peer_alert: alert.Alert,
            established: Established,
        };

        pub const ReceiveResult = struct {
            consumed: usize,
            event: ?Event,
        };

        const PendingHandshake = struct {
            allocator: std.mem.Allocator,
            suite: cipher_suite.Suite,
            server_hello_bytes: []u8,
            handshake_secret: secret.Secret,
            client_handshake_secret: secret.Secret,
            server_handshake_secret: secret.Secret,
            transcript_prefix: ?transcript.State,
            resumed: bool,
            early_data_offered: bool,
            server_records: traffic.State,
            client_records: traffic.State,
            receiver: stream.ProtectedReceiver(
                max_server_flight_len,
            ) = .{},
            plaintext_flight: std.ArrayList(u8) = .empty,
            saw_change_cipher_spec: bool = false,

            fn deinit(self: *PendingHandshake) void {
                self.server_records.deinit();
                self.client_records.deinit();
                self.handshake_secret.deinit();
                self.client_handshake_secret.deinit();
                self.server_handshake_secret.deinit();
                self.allocator.free(self.server_hello_bytes);
                self.plaintext_flight.deinit(self.allocator);
                self.* = undefined;
            }
        };

        const StoredPsk = struct {
            allocator: std.mem.Allocator,
            identity: []u8,
            secret: secret.Secret,
            obfuscated_ticket_age: u32,
            suite: cipher_suite.Suite,
            max_early_data_size: ?u32,

            fn init(
                allocator: std.mem.Allocator,
                value: ClientPsk,
            ) std.mem.Allocator.Error!StoredPsk {
                return .{
                    .allocator = allocator,
                    .identity = try allocator.dupe(u8, value.identity),
                    .secret = value.secret,
                    .obfuscated_ticket_age = value.obfuscated_ticket_age,
                    .suite = value.suite,
                    .max_early_data_size = value.max_early_data_size,
                };
            }

            fn deinit(self: *StoredPsk) void {
                self.secret.deinit();
                self.allocator.free(self.identity);
                self.* = undefined;
            }
        };

        allocator: std.mem.Allocator,
        server_verifier: auth.ClientVerifier,
        server_certificate_type: auth.CertificateType,
        server_name: ?[]const u8,
        client_identity: ?client_auth.ClientIdentity,
        random: [32]u8,
        cipher_suites: []const cipher_suite.Suite,
        additional_cipher_suites: []const u16,
        supported_versions: []const u16,
        signature_schemes: []const u16,
        offer_extended_master_secret: bool,
        alpn_protocols: []const []const u8,
        request_ocsp: bool,
        certificate_compression_algorithms: []const certificate_compression.Algorithm,
        max_decompressed_certificate_len: usize,
        stage: Stage = .server_hello,
        client_hello_bytes: ?[]u8,
        exchange: ?key_exchange.ClientExchange,
        retry_material: ?key_exchange.ClientKeyMaterial,
        retry_transcript: ?transcript.State = null,
        retry_suite: ?cipher_suite.Suite = null,
        retried: bool = false,
        saw_retry_change_cipher_spec: bool = false,
        resumption: ?StoredPsk,
        early_write: ?traffic.State = null,
        early_data_sent: usize = 0,
        records: stream.RecordDeframer = .{},
        hello_messages: stream.HandshakeReassembler(4096) = .{},
        pending: ?PendingHandshake = null,

        /// Consume `config.key_material`, append a complete plaintext
        /// ClientHello record to `output`, and retain the transcript/private
        /// state required for ServerHello.
        pub fn init(
            config: Config,
            output: *std.ArrayList(u8),
        ) Error!Self {
            if (config.retry_key_material) |retry| {
                if (retry == config.key_material) {
                    return error.DuplicateKeyMaterial;
                }
            }
            var exchange = try config.key_material.start();
            errdefer exchange.deinit();
            var retry_material: ?key_exchange.ClientKeyMaterial = null;
            if (config.retry_key_material) |retry| {
                if (retry.namedGroup() == exchange.namedGroup()) {
                    retry.wipe();
                    return error.DuplicateKeyMaterial;
                }
                retry_material = retry.*;
                retry.wipe();
            }
            errdefer if (retry_material) |*retry| retry.wipe();
            const supported_groups = if (retry_material) |retry|
                [_]u16{ exchange.namedGroup(), retry.namedGroup() }
            else
                [_]u16{ exchange.namedGroup(), exchange.namedGroup() };
            var hello: std.ArrayList(u8) = .empty;
            defer hello.deinit(config.allocator);
            try client_hello.writeWithKeyShare(&hello, config.allocator, .{
                .random = config.random,
                .session_id = config.session_id,
                .server_name = config.server_name,
                .key_share = .{
                    .group = exchange.namedGroup(),
                    .key_exchange = exchange.clientShare(),
                },
                .supported_groups = supported_groups[0..if (retry_material == null) 1 else 2],
                .cipher_suites = config.cipher_suites,
                .additional_cipher_suites = config.additional_cipher_suites,
                .supported_versions = config.supported_versions,
                .signature_schemes = config.signature_schemes,
                .alpn_protocols = config.alpn_protocols,
                .request_ocsp = config.request_ocsp,
                .offer_extended_master_secret = config.offer_extended_master_secret,
                .certificate_compression_algorithms = config.certificate_compression_algorithms,
                .session_ticket = config.tls12_session_ticket,
                .server_certificate_types = if (config.server_certificate_type == .raw_public_key)
                    &.{.raw_public_key}
                else
                    &.{},
                .client_certificate_types = if (config.client_identity) |identity|
                    if (identity.certificate_type == .raw_public_key)
                        &.{.raw_public_key}
                    else
                        &.{}
                else
                    &.{},
            });
            var resumption: ?StoredPsk = if (config.resumption) |value|
                try StoredPsk.init(config.allocator, value)
            else
                null;
            errdefer if (resumption) |*value| value.deinit();
            if (resumption) |value| {
                var compatible = false;
                for (config.cipher_suites) |suite| {
                    if (suite.hash() == value.secret.hash) compatible = true;
                }
                if (!compatible) return error.InvalidPskSuite;
                try psk.appendClientOfferForSecret(
                    &hello,
                    config.allocator,
                    value.identity,
                    value.obfuscated_ticket_age,
                    value.secret,
                    value.max_early_data_size != null,
                    null,
                );
            }
            if (hello.items.len > record.max_plaintext_len) {
                return error.ClientHelloTooLarge;
            }
            const owned_hello = try config.allocator.dupe(u8, hello.items);
            errdefer config.allocator.free(owned_hello);
            const record_start = output.items.len;
            errdefer output.shrinkRetainingCapacity(record_start);
            try output.appendSlice(config.allocator, &.{
                record.content_type_handshake,
                3,
                1,
                @truncate(hello.items.len >> 8),
                @truncate(hello.items.len),
            });
            try output.appendSlice(config.allocator, hello.items);
            var early_write: ?traffic.State = null;
            if (resumption) |value| {
                if (value.max_early_data_size != null) {
                    if (value.suite.hash() != value.secret.hash) {
                        return error.InvalidPskSuite;
                    }
                    const hello_hash = transcript.hashFor(
                        value.secret.hash,
                        &.{hello.items},
                    );
                    var early_secret =
                        try key_schedule.deriveClientEarlyTrafficSecretFor(
                            value.secret,
                            hello_hash,
                        );
                    defer early_secret.deinit();
                    early_write = try traffic.State.init(
                        value.suite,
                        early_secret,
                    );
                }
            }
            errdefer if (early_write) |*state| state.deinit();
            return .{
                .allocator = config.allocator,
                .server_verifier = config.server_verifier,
                .server_certificate_type = config.server_certificate_type,
                .server_name = config.server_name,
                .client_identity = config.client_identity,
                .random = config.random,
                .cipher_suites = config.cipher_suites,
                .additional_cipher_suites = config.additional_cipher_suites,
                .supported_versions = config.supported_versions,
                .signature_schemes = config.signature_schemes,
                .offer_extended_master_secret = config.offer_extended_master_secret,
                .alpn_protocols = config.alpn_protocols,
                .request_ocsp = config.request_ocsp,
                .certificate_compression_algorithms = config.certificate_compression_algorithms,
                .max_decompressed_certificate_len = config.max_decompressed_certificate_len,
                .client_hello_bytes = owned_hello,
                .exchange = exchange,
                .retry_material = retry_material,
                .resumption = resumption,
                .early_write = early_write,
            };
        }

        pub fn deinit(self: *Self) void {
            self.cleanup();
            self.* = undefined;
        }

        pub fn receive(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            if (self.stage == .failed) return error.ConnectionFailed;
            return self.receiveInner(input, output) catch |err| {
                self.fail();
                return err;
            };
        }

        /// Encrypt 0-RTT application data before ServerHello. The cumulative
        /// plaintext is bounded by the authenticated NewSessionTicket limit.
        pub fn sealEarlyData(
            self: *Self,
            plaintext: []const u8,
            output: []u8,
        ) Error!usize {
            if (self.stage != .server_hello or self.retried) {
                return error.UnexpectedApplicationData;
            }
            const writer = &(self.early_write orelse
                return error.UnexpectedApplicationData);
            const limit = (self.resumption orelse unreachable)
                .max_early_data_size orelse
                return error.UnexpectedApplicationData;
            const limit_usize: usize = @intCast(limit);
            if (plaintext.len > limit_usize or
                self.early_data_sent > limit_usize - plaintext.len)
            {
                return error.UnexpectedApplicationData;
            }
            const len = try writer.seal(
                record.content_type_application_data,
                plaintext,
                output,
            );
            self.early_data_sent += plaintext.len;
            return len;
        }

        fn receiveInner(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            return switch (self.stage) {
                .server_hello => self.receiveServerHello(input, output),
                .server_flight => self.receiveServerFlight(input, output),
                .established => error.AlreadyEstablished,
                .failed => error.ConnectionFailed,
            };
        }

        fn receiveServerHello(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const record_result = try self.records.push(input);
            const framed = record_result.framed orelse return .{
                .consumed = record_result.consumed,
                .event = null,
            };
            if (framed.content_type == stream.content_type_change_cipher_spec) {
                if (!self.retried or self.saw_retry_change_cipher_spec or
                    !std.mem.eql(u8, framed.fragment, &.{1}))
                {
                    return error.DuplicateChangeCipherSpec;
                }
                self.saw_retry_change_cipher_spec = true;
                return .{
                    .consumed = record_result.consumed,
                    .event = .{ .compatibility_change_cipher_spec = {} },
                };
            }
            if (framed.content_type != record.content_type_handshake) {
                return error.UnexpectedRecord;
            }
            var remaining = framed.fragment;
            while (remaining.len != 0) {
                const message_result = try self.hello_messages.push(remaining);
                remaining = remaining[message_result.consumed..];
                const message = message_result.message orelse continue;
                if (remaining.len != 0 or
                    message[0] != server_hello.handshake_type_server_hello)
                {
                    return error.UnexpectedHandshakeMessage;
                }
                if (server_hello.isHelloRetryRequest(message)) {
                    try self.acceptHelloRetryRequest(message, output);
                    return .{
                        .consumed = record_result.consumed,
                        .event = .{ .hello_retry_request = {} },
                    };
                }
                try self.acceptServerHello(message);
                return .{
                    .consumed = record_result.consumed,
                    .event = .{ .server_hello = {} },
                };
            }
            return .{
                .consumed = record_result.consumed,
                .event = null,
            };
        }

        fn acceptHelloRetryRequest(
            self: *Self,
            message: []const u8,
            output: *std.ArrayList(u8),
        ) Error!void {
            if (self.retried) return error.DuplicateHelloRetryRequest;
            const retry = try server_hello.parseHelloRetryRequest(message);
            const first_hello = self.client_hello_bytes orelse unreachable;
            const parsed_client = try client_hello.parse(first_hello);
            if (!parsed_client.hasCipherSuite(retry.cipher_suite.wireValue())) {
                return error.ServerSelectedUnofferedSuite;
            }
            if (!std.mem.eql(
                u8,
                parsed_client.session_id,
                retry.session_id_echo,
            )) return error.SessionIdMismatch;
            if (!try parsed_client.supportsGroup(retry.selected_group)) {
                return error.ServerSelectedUnofferedGroup;
            }
            const initial_exchange = &(self.exchange orelse unreachable);
            if (retry.selected_group == initial_exchange.namedGroup()) {
                return error.ServerSelectedUnofferedGroup;
            }
            var retry_material = &(self.retry_material orelse
                return error.MissingRetryKeyMaterial);
            if (retry.selected_group != retry_material.namedGroup()) {
                return error.MissingRetryKeyMaterial;
            }

            var retry_exchange = try retry_material.start();
            errdefer retry_exchange.deinit();
            self.retry_material = null;
            var second_hello: std.ArrayList(u8) = .empty;
            defer second_hello.deinit(self.allocator);
            const supported_groups = [_]u16{
                initial_exchange.namedGroup(),
                retry_exchange.namedGroup(),
            };
            try client_hello.writeWithKeyShare(
                &second_hello,
                self.allocator,
                .{
                    .random = self.random,
                    .session_id = parsed_client.session_id,
                    .server_name = self.server_name,
                    .key_share = .{
                        .group = retry_exchange.namedGroup(),
                        .key_exchange = retry_exchange.clientShare(),
                    },
                    .supported_groups = &supported_groups,
                    .cookie = retry.cookie,
                    .cipher_suites = self.cipher_suites,
                    .additional_cipher_suites = self.additional_cipher_suites,
                    .supported_versions = self.supported_versions,
                    .signature_schemes = self.signature_schemes,
                    .alpn_protocols = self.alpn_protocols,
                    .request_ocsp = self.request_ocsp,
                    .offer_extended_master_secret = self.offer_extended_master_secret,
                    .certificate_compression_algorithms = self.certificate_compression_algorithms,
                    .session_ticket = parsed_client.session_ticket,
                    .server_certificate_types = if (self.server_certificate_type == .raw_public_key)
                        &.{.raw_public_key}
                    else
                        &.{},
                    .client_certificate_types = if (self.client_identity) |identity|
                        if (identity.certificate_type == .raw_public_key)
                            &.{.raw_public_key}
                        else
                            &.{}
                    else
                        &.{},
                },
            );
            const retry_prefix = transcript.afterHelloRetryRequest(
                retry.cipher_suite.hash(),
                first_hello,
                message,
            );
            if (self.resumption) |resumption| {
                try psk.appendClientOfferForSecret(
                    &second_hello,
                    self.allocator,
                    resumption.identity,
                    resumption.obfuscated_ticket_age,
                    resumption.secret,
                    false,
                    retry_prefix,
                );
            }
            if (second_hello.items.len > record.max_plaintext_len) {
                return error.ClientHelloTooLarge;
            }
            const second_owned = try self.allocator.dupe(
                u8,
                second_hello.items,
            );
            errdefer self.allocator.free(second_owned);
            const output_start = output.items.len;
            errdefer output.shrinkRetainingCapacity(output_start);
            try appendPlaintextHandshakeRecord(
                output,
                self.allocator,
                second_hello.items,
            );

            self.retry_transcript = retry_prefix;
            self.retry_transcript.?.update(second_hello.items);
            self.retry_suite = retry.cipher_suite;
            if (self.early_write) |*early| early.deinit();
            self.early_write = null;
            initial_exchange.deinit();
            self.exchange = retry_exchange;
            self.allocator.free(first_hello);
            self.client_hello_bytes = second_owned;
            self.hello_messages.reset();
            self.retried = true;
        }

        fn acceptServerHello(self: *Self, message: []const u8) Error!void {
            const parsed_server = try server_hello.parseServerHello(message);
            if (self.retry_suite) |retry_suite| {
                if (parsed_server.cipher_suite != retry_suite) {
                    return error.ServerSelectedUnofferedSuite;
                }
            }
            const hello_bytes = self.client_hello_bytes orelse unreachable;
            const parsed_client = try client_hello.parse(hello_bytes);
            if (!parsed_client.hasCipherSuite(
                parsed_server.cipher_suite.wireValue(),
            )) return error.ServerSelectedUnofferedSuite;
            if (!std.mem.eql(
                u8,
                parsed_client.session_id,
                parsed_server.session_id_echo,
            )) return error.SessionIdMismatch;
            const resumed = if (parsed_server.selected_psk_identity) |identity| blk: {
                if (identity != psk.selected_identity_first) {
                    return error.InvalidPskSelection;
                }
                const resumption = self.resumption orelse
                    return error.InvalidPskSelection;
                if (resumption.secret.hash != parsed_server.cipher_suite.hash()) {
                    return error.InvalidPskSuite;
                }
                break :blk true;
            } else false;

            var exchange = self.exchange orelse unreachable;
            self.exchange = null;
            if (parsed_server.key_share_group != exchange.namedGroup()) {
                exchange.deinit();
                return error.ServerSelectedUnofferedGroup;
            }
            var shared = try exchange.complete(parsed_server.key_share);
            defer shared.deinit();
            var handshake_transcript = self.retry_transcript orelse blk: {
                var initial = transcript.State.init(
                    parsed_server.cipher_suite.hash(),
                );
                initial.update(hello_bytes);
                break :blk initial;
            };
            const transcript_prefix = self.retry_transcript;
            const early_data_offered = resumed and self.early_write != null;
            handshake_transcript.update(message);
            const hello_hash = handshake_transcript.digest();
            var handshake = try key_schedule.deriveHandshakeFor(
                parsed_server.cipher_suite.hash(),
                shared.bytes(),
                hello_hash,
                if (resumed) self.resumption.?.secret else null,
            );
            defer handshake.early_secret.deinit();
            errdefer {
                handshake.handshake_secret.deinit();
                handshake.client_traffic_secret.deinit();
                handshake.server_traffic_secret.deinit();
            }
            var server_records = try traffic.State.init(
                parsed_server.cipher_suite,
                handshake.server_traffic_secret,
            );
            errdefer server_records.deinit();
            var client_records = try traffic.State.init(
                parsed_server.cipher_suite,
                handshake.client_traffic_secret,
            );
            errdefer client_records.deinit();
            const owned_server_hello = try self.allocator.dupe(u8, message);
            errdefer self.allocator.free(owned_server_hello);
            self.pending = .{
                .allocator = self.allocator,
                .suite = parsed_server.cipher_suite,
                .server_hello_bytes = owned_server_hello,
                .handshake_secret = handshake.handshake_secret,
                .client_handshake_secret = handshake.client_traffic_secret,
                .server_handshake_secret = handshake.server_traffic_secret,
                .transcript_prefix = transcript_prefix,
                .resumed = resumed,
                .early_data_offered = early_data_offered,
                .server_records = server_records,
                .client_records = client_records,
                .saw_change_cipher_spec = self.saw_retry_change_cipher_spec,
            };
            if (self.resumption) |*resumption| {
                resumption.deinit();
            }
            self.resumption = null;
            if (self.early_write) |*early| early.deinit();
            self.early_write = null;
            self.stage = .server_flight;
        }

        fn receiveServerFlight(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const pending = &(self.pending orelse unreachable);
            var consumed: usize = 0;
            while (true) {
                const result = try pending.receiver.push(
                    input[consumed..],
                    &pending.server_records,
                );
                consumed += result.consumed;
                const protected = result.event orelse return .{
                    .consumed = consumed,
                    .event = null,
                };
                switch (protected) {
                    .change_cipher_spec => {
                        if (pending.saw_change_cipher_spec) {
                            return error.DuplicateChangeCipherSpec;
                        }
                        pending.saw_change_cipher_spec = true;
                        return .{
                            .consumed = consumed,
                            .event = .{
                                .compatibility_change_cipher_spec = {},
                            },
                        };
                    },
                    .alert => |peer_alert| {
                        const event: Event = .{ .peer_alert = peer_alert };
                        self.fail();
                        return .{ .consumed = consumed, .event = event };
                    },
                    .application_data => return error.UnexpectedApplicationData,
                    .handshake => |message| {
                        if (pending.plaintext_flight.items.len + message.len >
                            max_server_flight_len)
                        {
                            return error.ServerFlightTooLarge;
                        }
                        try pending.plaintext_flight.appendSlice(
                            self.allocator,
                            message,
                        );
                        if (message[0] ==
                            server_handshake.handshake_type_finished)
                        {
                            if (pending.receiver.hasPendingHandshakeData()) {
                                return error.UnexpectedHandshakeMessage;
                            }
                            return .{
                                .consumed = consumed,
                                .event = .{
                                    .established = try self.establish(output),
                                },
                            };
                        }
                        if (consumed == input.len and
                            !pending.receiver.hasPendingHandshakeData())
                        {
                            return .{ .consumed = consumed, .event = null };
                        }
                    },
                }
            }
        }

        fn establish(
            self: *Self,
            output: *std.ArrayList(u8),
        ) Error!Established {
            const pending = &(self.pending orelse unreachable);
            var client_messages: std.ArrayList(u8) = .empty;
            defer client_messages.deinit(self.allocator);
            var verified = try client_handshake
                .verifyServerAndWriteClientFlight(
                &client_messages,
                self.allocator,
                .{
                    .client_hello_bytes = self.client_hello_bytes orelse unreachable,
                    .server_hello_bytes = pending.server_hello_bytes,
                    .encrypted_server_flight = pending.plaintext_flight.items,
                    .handshake_secret = pending.handshake_secret,
                    .client_handshake_traffic_secret = pending.client_handshake_secret,
                    .server_handshake_traffic_secret = pending.server_handshake_secret,
                    .transcript_prefix = pending.transcript_prefix,
                    .psk_resumed = pending.resumed,
                    .early_data_offered = pending.early_data_offered,
                    .server_verifier = self.server_verifier,
                    .server_certificate_type = self.server_certificate_type,
                    .server_name = self.server_name,
                    .certificate_compression_algorithms = self.certificate_compression_algorithms,
                    .max_decompressed_certificate_len = self.max_decompressed_certificate_len,
                    .client_identity = self.client_identity,
                },
            );
            var verified_owned = true;
            defer if (verified_owned) verified.deinit();

            if (verified.selected_alpn) |selected| {
                const offered = try client_hello.parse(
                    self.client_hello_bytes orelse unreachable,
                );
                if (!try offered.supportsAlpnProtocol(selected)) {
                    return error.ServerSelectedUnofferedAlpn;
                }
            }

            const alpn_copy = if (verified.selected_alpn) |selected|
                try self.allocator.dupe(u8, selected)
            else
                null;
            errdefer if (alpn_copy) |selected| self.allocator.free(selected);
            var application = try Application.init(
                verified.cipher_suite,
                verified.application.server_traffic_secret,
                verified.application.client_traffic_secret,
            );
            errdefer application.deinit();

            var offset: usize = 0;
            while (offset < client_messages.items.len) {
                const chunk_len = @min(
                    record.max_plaintext_len,
                    client_messages.items.len - offset,
                );
                var encrypted: [record.max_record_len]u8 = undefined;
                const encrypted_len = try pending.client_records.seal(
                    record.content_type_handshake,
                    client_messages.items[offset..][0..chunk_len],
                    &encrypted,
                );
                try output.appendSlice(
                    self.allocator,
                    encrypted[0..encrypted_len],
                );
                offset += chunk_len;
            }

            verified.application.client_traffic_secret.deinit();
            verified.application.server_traffic_secret.deinit();
            const established = Established{
                .allocator = self.allocator,
                .application = application,
                .master_secret = verified.application.master_secret,
                .transcript_after_client_finished = verified.transcript_after_client_finished,
                .selected_alpn = alpn_copy,
                .peer_certificate_chain = verified.peer_certificate_chain,
                .resumed = pending.resumed,
                .early_data_accepted = verified.early_data_accepted,
                .certificate_compression = verified.certificate_compression,
                .client_certificate_compression = verified.client_certificate_compression,
                .server_certificate_type = verified.server_certificate_type,
                .client_certificate_type = verified.client_certificate_type,
            };
            verified_owned = false;
            pending.deinit();
            self.pending = null;
            if (self.client_hello_bytes) |bytes| self.allocator.free(bytes);
            self.client_hello_bytes = null;
            self.stage = .established;
            return established;
        }

        fn fail(self: *Self) void {
            self.cleanup();
            self.stage = .failed;
        }

        fn cleanup(self: *Self) void {
            if (self.exchange) |*exchange| exchange.deinit();
            self.exchange = null;
            if (self.retry_material) |*retry| retry.wipe();
            self.retry_material = null;
            if (self.early_write) |*early| early.deinit();
            self.early_write = null;
            if (self.resumption) |*resumption| {
                resumption.deinit();
            }
            self.resumption = null;
            if (self.pending) |*pending| pending.deinit();
            self.pending = null;
            if (self.client_hello_bytes) |bytes| self.allocator.free(bytes);
            self.client_hello_bytes = null;
        }
    };
}

fn appendPlaintextHandshakeRecord(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    message: []const u8,
) std.mem.Allocator.Error!void {
    std.debug.assert(message.len <= record.max_plaintext_len);
    try output.appendSlice(allocator, &.{
        record.content_type_handshake,
        3,
        3,
        @truncate(message.len >> 8),
        @truncate(message.len),
    });
    try output.appendSlice(allocator, message);
}

fn ed25519SubjectPublicKeyInfo(public_key: [32]u8) [44]u8 {
    var spki = [_]u8{
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03,
        0x2b, 0x65,
        0x70, 0x03,
        0x21, 0x00,
    } ++ ([_]u8{0} ** 32);
    @memcpy(spki[12..], &public_key);
    return spki;
}

test "client and server states establish over one-byte transport reads" {
    const allocator = std.testing.allocator;
    const Client = ClientConnection(64 * 1024, 256);
    const Server = @import("server_connection.zig").ServerConnection(
        64 * 1024,
        256,
    );
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xc1} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    const certificate_padding = [_]u8{0xc7} ** 4096;
    const certificate_chain = [_][]const u8{
        &certificate,
        &certificate_padding,
    };
    const server_ocsp_response = "identity-specific-ocsp";
    var certificate_message: std.ArrayList(u8) = .empty;
    defer certificate_message.deinit(allocator);
    try auth.writeCertificateWithOcsp(
        &certificate_message,
        allocator,
        &certificate_chain,
        server_ocsp_response,
    );
    var prepared_certificate =
        try certificate_compression.Prepared.initZlib(
            allocator,
            certificate_message.items,
            .amortized,
        );
    defer prepared_certificate.deinit();
    const compressed_certificates =
        [_]certificate_compression.PreparedView{
            prepared_certificate.view(),
        };
    const identity_set = @import("server_connection.zig").IdentitySet{
        .entries = &.{.{
            .server_name_pattern = "example.com",
            .identity = .{
                .certificate_chain = &certificate_chain,
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
                .ocsp_response = server_ocsp_response,
                .compressed_certificates = &compressed_certificates,
            },
        }},
    };
    const client_signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xc0} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const client_certificate = client_signing_key.public_key.toBytes();
    const client_certificate_padding = [_]u8{0xc8} ** 4096;
    const client_certificate_chain = [_][]const u8{
        &client_certificate,
        &client_certificate_padding,
    };
    var client_certificate_message: std.ArrayList(u8) = .empty;
    defer client_certificate_message.deinit(allocator);
    try auth.writeClientCertificateWithContext(
        &client_certificate_message,
        allocator,
        &client_certificate_chain,
        "mtls",
    );
    var prepared_client_certificate =
        try certificate_compression.Prepared.initZlib(
            allocator,
            client_certificate_message.items,
            .amortized,
        );
    defer prepared_client_certificate.deinit();
    const compressed_client_certificates =
        [_]certificate_compression.PreparedView{
            prepared_client_certificate.view(),
        };

    var client_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xc2} ** key_exchange.secret_len,
    };
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xc3} ** 32,
        .server_name = "example.com",
        .key_material = &client_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .request_ocsp = true,
        .server_verifier = .{ .verify_trust = struct {
            fn verify(
                context: ?*anyopaque,
                trust_context: auth.TrustContext,
            ) anyerror!void {
                _ = context;
                if (trust_context.chain.len == 0 or
                    trust_context.ocsp_response == null or
                    !std.mem.eql(
                        u8,
                        trust_context.ocsp_response.?,
                        server_ocsp_response,
                    ))
                {
                    return error.UnexpectedServerIdentity;
                }
            }
        }.verify },
        .client_identity = .{
            .certificate_chain = &client_certificate_chain,
            .signer = .{
                .ed25519 = .{ .key_pair = client_signing_key },
            },
            .compressed_certificates = &compressed_client_certificates,
        },
    }, &client_wire);
    defer client.deinit();

    var server_material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xc4} ** key_exchange.secret_len,
    };
    const fallback_signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xc9} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const fallback_certificate = fallback_signing_key.public_key.toBytes();
    var server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
            .alpn_protocols = &.{"h2"},
        },
        .server_random = [_]u8{0xc5} ** 32,
        .key_material = &server_material,
        .certificate_chain = &.{&fallback_certificate},
        .signer = .{
            .ed25519 = .{ .key_pair = fallback_signing_key },
        },
        .identity_resolver = identity_set.resolver(),
        .client_auth = .{ .request_context = "mtls" },
        .client_auth_policy = .{
            .verifier = .{
                .pinned_ed25519_public_key = client_certificate,
            },
            .requirement = .required,
        },
    });
    defer server.deinit();

    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(allocator);
    var saw_server_flight = false;
    for (client_wire.items) |byte| {
        const received = try server.receive(&.{byte}, &server_flight);
        if (received.event) |event| switch (event) {
            .server_flight => saw_server_flight = true,
            else => return error.UnexpectedServerEvent,
        };
    }
    try std.testing.expect(saw_server_flight);

    const server_hello_len = 4 +
        ((@as(usize, server_flight.items[1]) << 16) |
            (@as(usize, server_flight.items[2]) << 8) |
            server_flight.items[3]);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    try server_wire.appendSlice(allocator, &.{
        record.content_type_handshake,
        3,
        3,
        @truncate(server_hello_len >> 8),
        @truncate(server_hello_len),
    });
    try server_wire.appendSlice(
        allocator,
        server_flight.items[0..server_hello_len],
    );
    try server_wire.appendSlice(
        allocator,
        server_flight.items[server_hello_len..],
    );

    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(allocator);
    var client_established: ?Client.Established = null;
    for (server_wire.items) |byte| {
        const received = try client.receive(&.{byte}, &client_finished);
        if (received.event) |event| switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => {},
            .established => |established| {
                try std.testing.expect(client_established == null);
                client_established = established;
            },
            .hello_retry_request => return error.UnexpectedHelloRetryRequest,
            .peer_alert => return error.PeerAbortedHandshake,
        };
    }
    var established_client = client_established orelse
        return error.ClientDidNotEstablish;
    defer established_client.deinit();
    try std.testing.expectEqualStrings(
        "h2",
        established_client.selected_alpn.?,
    );
    try std.testing.expectEqual(
        @as(usize, certificate_chain.len),
        established_client.peer_certificate_chain.len,
    );
    try std.testing.expectEqual(
        certificate_compression.Algorithm.zlib,
        established_client.certificate_compression.?,
    );

    const server_established_result = try server.receive(
        client_finished.items,
        &server_flight,
    );
    var established_server = server_established_result.event.?.established;
    defer established_server.deinit();
    try std.testing.expectEqual(
        @as(usize, client_certificate_chain.len),
        established_server.peer_certificate_chain.?.len,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_certificate,
        established_server.peer_certificate_chain.?[0],
    );
    try std.testing.expectEqual(
        certificate_compression.Algorithm.zlib,
        established_server.client_certificate_compression.?,
    );

    var application_record: [128]u8 = undefined;
    const application_len = try established_client.application
        .sealApplicationData("state-machine round trip", &application_record);
    const application = try established_server.application.receive(
        application_record[0..application_len],
    );
    try std.testing.expectEqualStrings(
        "state-machine round trip",
        application.event.?.application_data,
    );

    const ticket_module = @import("ticket_keyring.zig");
    var keyring = try ticket_module.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{0xc6} ** ticket_module.key_len,
    });
    defer keyring.deinit();
    var ticket_record: [512]u8 = undefined;
    const ticket_record_len = try established_server.sealNewSessionTicket(
        allocator,
        .{
            .keyring = &keyring,
            .sealing_nonce = [_]u8{0xc7} ** ticket_module.nonce_len,
            .server_id = "example.com",
            .alpn = "h2",
            .ticket_nonce = &.{ 1, 2, 3 },
            .age_add = 19,
            .issued_at_ms = 10_000,
            .lifetime_seconds = 60,
        },
        &ticket_record,
    );
    const received_ticket = try established_client.application.receive(
        ticket_record[0..ticket_record_len],
    );
    var cached = try established_client.cacheNewSessionTicket(
        received_ticket.event.?.post_handshake,
        "example.com",
        10_000,
    );
    defer cached.deinit();
    const cached_offer = try ClientPsk.fromCached(&cached, 11_000);
    try std.testing.expectEqual(@as(u32, 1_019), cached_offer.obfuscated_ticket_age);
    var opened_ticket = try keyring.openSecret(
        cached.identity,
        "example.com",
        "h2",
        11_000,
    );
    defer opened_ticket.secret.deinit();
    try std.testing.expect(cached.psk.eql(&opened_ticket.secret));
}

test "client and server establish mutual RFC 7250 raw public keys" {
    const allocator = std.testing.allocator;
    const Client = ClientConnection(64 * 1024, 256);
    const Server = @import("server_connection.zig").ServerConnection(
        64 * 1024,
        256,
    );
    const server_signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xd1} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const client_signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xd2} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const server_spki = ed25519SubjectPublicKeyInfo(
        server_signing_key.public_key.toBytes(),
    );
    const client_spki = ed25519SubjectPublicKeyInfo(
        client_signing_key.public_key.toBytes(),
    );

    var client_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xd3} ** key_exchange.secret_len,
    };
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xd4} ** 32,
        .server_name = "rpk.example",
        .key_material = &client_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .server_verifier = .{ .pinned_raw_public_key = &server_spki },
        .server_certificate_type = .raw_public_key,
        .client_identity = .{
            .certificate_chain = &.{&client_spki},
            .signer = .{
                .ed25519 = .{ .key_pair = client_signing_key },
            },
            .certificate_type = .raw_public_key,
        },
    }, &client_wire);
    defer client.deinit();
    const offered = try client_hello.parse(
        client_wire.items[record.header_len..],
    );
    try std.testing.expect(offered.supportsServerCertificateType(
        .raw_public_key,
    ));
    try std.testing.expect(offered.supportsClientCertificateType(
        .raw_public_key,
    ));

    var server_material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xd5} ** key_exchange.secret_len,
    };
    var server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
        },
        .server_random = [_]u8{0xd6} ** 32,
        .key_material = &server_material,
        .certificate_chain = &.{&server_spki},
        .signer = .{
            .ed25519 = .{ .key_pair = server_signing_key },
        },
        .server_certificate_type = .raw_public_key,
        .client_auth = .{},
        .client_auth_policy = .{
            .verifier = .{ .pinned_raw_public_key = &client_spki },
            .requirement = .required,
            .certificate_type = .raw_public_key,
        },
    });
    defer server.deinit();

    var server_flight_bytes: std.ArrayList(u8) = .empty;
    defer server_flight_bytes.deinit(allocator);
    const server_result = try server.receive(
        client_wire.items,
        &server_flight_bytes,
    );
    switch (server_result.event.?) {
        .server_flight => {},
        else => return error.ExpectedServerFlight,
    }
    const server_hello_len = 4 +
        ((@as(usize, server_flight_bytes.items[1]) << 16) |
            (@as(usize, server_flight_bytes.items[2]) << 8) |
            server_flight_bytes.items[3]);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    try appendPlaintextHandshakeRecord(
        &server_wire,
        allocator,
        server_flight_bytes.items[0..server_hello_len],
    );
    try server_wire.appendSlice(
        allocator,
        server_flight_bytes.items[server_hello_len..],
    );

    var client_flight_bytes: std.ArrayList(u8) = .empty;
    defer client_flight_bytes.deinit(allocator);
    var client_established: ?Client.Established = null;
    var offset: usize = 0;
    while (offset < server_wire.items.len) {
        const received = try client.receive(
            server_wire.items[offset..],
            &client_flight_bytes,
        );
        if (received.consumed == 0 and received.event == null) {
            return error.ClientStateStalled;
        }
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => {},
            .established => |established| client_established = established,
            .hello_retry_request => return error.UnexpectedHelloRetryRequest,
            .peer_alert => return error.PeerAbortedHandshake,
        };
    }
    var established_client = client_established orelse
        return error.ClientDidNotEstablish;
    defer established_client.deinit();
    try std.testing.expectEqual(
        auth.CertificateType.raw_public_key,
        established_client.server_certificate_type,
    );
    try std.testing.expectEqual(
        auth.CertificateType.raw_public_key,
        established_client.client_certificate_type,
    );
    try std.testing.expectEqual(@as(usize, 1), established_client
        .peer_certificate_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        &server_spki,
        established_client.peer_certificate_chain[0],
    );

    var server_established: ?Server.Established = null;
    offset = 0;
    while (offset < client_flight_bytes.items.len) {
        const received = try server.receive(
            client_flight_bytes.items[offset..],
            &server_flight_bytes,
        );
        if (received.consumed == 0 and received.event == null) {
            return error.ServerStateStalled;
        }
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .established => |established| server_established = established,
            else => {},
        };
    }
    var established_server = server_established orelse
        return error.ServerDidNotEstablish;
    defer established_server.deinit();
    try std.testing.expectEqual(
        auth.CertificateType.raw_public_key,
        established_server.server_certificate_type,
    );
    try std.testing.expectEqual(
        auth.CertificateType.raw_public_key,
        established_server.client_certificate_type,
    );
    try std.testing.expectEqual(@as(usize, 1), established_server
        .peer_certificate_chain.?.len);
    try std.testing.expectEqualSlices(
        u8,
        &client_spki,
        established_server.peer_certificate_chain.?[0],
    );
}

test "client and server complete P-256 HelloRetryRequest transcript" {
    const allocator = std.testing.allocator;
    const Client = ClientConnection(64 * 1024, 256);
    const Server = @import("server_connection.zig").ServerConnection(
        64 * 1024,
        256,
    );
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xe1} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = ed25519SubjectPublicKeyInfo(
        signing_key.public_key.toBytes(),
    );
    const ServerModule = @import("server_connection.zig");
    const ResolverContext = struct {
        calls: usize = 0,
        identity: ServerModule.ResolvedIdentity,

        fn resolve(
            opaque_context: ?*anyopaque,
            hello: client_hello.Parsed,
        ) anyerror!?ServerModule.ResolvedIdentity {
            const self: *@This() = @ptrCast(@alignCast(
                opaque_context orelse return error.MissingContext,
            ));
            self.calls += 1;
            if (hello.server_name == null) return null;
            return self.identity;
        }
    };

    var initial_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xe2} ** key_exchange.secret_len,
    };
    var retry_material = key_exchange.ClientKeyMaterial{
        .secp256r1 = [_]u8{0} ** (key_exchange.p256.secret_len - 1) ++ .{1},
    };
    const retry_psk_secret = secret.Secret.fromSha256([_]u8{0xe7} ** 32);
    var client_psk = ClientPsk{
        .identity = "hrr-resumption-ticket",
        .secret = retry_psk_secret,
        .obfuscated_ticket_age = 1_009,
        .suite = .aes_128_gcm_sha256,
        .max_early_data_size = 1024,
    };
    var client_output: std.ArrayList(u8) = .empty;
    defer client_output.deinit(allocator);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xe3} ** 32,
        .session_id = &.{ 1, 2, 3 },
        .server_name = "example.com",
        .key_material = &initial_material,
        .retry_key_material = &retry_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .server_verifier = .{ .pinned_raw_public_key = &certificate },
        .server_certificate_type = .raw_public_key,
        .resumption = client_psk,
    }, &client_output);
    client_psk.secret.deinit();
    defer client.deinit();
    var forbidden_early_record: [128]u8 = undefined;
    _ = try client.sealEarlyData(
        "offered before retry",
        &forbidden_early_record,
    );

    var server_material = key_exchange.ServerKeyMaterial{
        .secp256r1 = [_]u8{0} ** (key_exchange.p256.secret_len - 1) ++ .{2},
    };
    var server_psk = @import("server_connection.zig").ServerPsk{
        .identity = "hrr-resumption-ticket",
        .secret = retry_psk_secret,
        .age_policy = .{
            .age_add = 9,
            .issued_at_ms = 10_000,
            .lifetime_seconds = 60,
            .now_ms = 11_000,
            .tolerance_ms = 0,
        },
        .max_early_data_size = 1024,
    };
    var retry_replay_cache = @import("early_data.zig").ReplayCache(2){};
    var resolver_context = ResolverContext{
        .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .certificate_type = .raw_public_key,
        },
    };
    var server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_secp256r1},
            .alpn_protocols = &.{"h2"},
        },
        .server_random = [_]u8{0xe4} ** 32,
        .key_material = &server_material,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        .server_certificate_type = .raw_public_key,
        .identity_resolver = .{
            .context = @ptrCast(&resolver_context),
            .resolve_fn = ResolverContext.resolve,
        },
        .retry_cookie = "retry-cookie",
        .resumption = .{ .fixed = &server_psk },
        .early_data = .{
            .replay_guard = retry_replay_cache.guard(),
            .max_bytes = 1024,
        },
    });
    defer server.deinit();

    var server_output: std.ArrayList(u8) = .empty;
    defer server_output.deinit(allocator);
    const retry_result = try server.receive(
        client_output.items,
        &server_output,
    );
    switch (retry_result.event.?) {
        .hello_retry_request => {},
        else => return error.ExpectedHelloRetryRequest,
    }
    try std.testing.expectEqual(@as(usize, 1), resolver_context.calls);
    try std.testing.expectEqual(
        @import("server_connection.zig").Stage.second_client_hello,
        server.stage,
    );

    var retry_record: std.ArrayList(u8) = .empty;
    defer retry_record.deinit(allocator);
    try appendPlaintextHandshakeRecord(
        &retry_record,
        allocator,
        server_output.items,
    );
    client_output.clearRetainingCapacity();
    const client_retry = try client.receive(
        retry_record.items,
        &client_output,
    );
    switch (client_retry.event.?) {
        .hello_retry_request => {},
        else => return error.ExpectedHelloRetryRequest,
    }
    try std.testing.expectError(
        error.UnexpectedApplicationData,
        client.sealEarlyData("forbidden after retry", &forbidden_early_record),
    );
    const second_client_hello = try client_hello.parse(
        client_output.items[record.header_len..],
    );
    try std.testing.expectEqualStrings(
        "retry-cookie",
        second_client_hello.cookie.?,
    );
    try std.testing.expect(
        try second_client_hello.keyShareForGroup(
            key_exchange.named_group_secp256r1,
        ) != null,
    );
    try std.testing.expect(
        second_client_hello.supportsCertificateCompression(.zlib),
    );
    try std.testing.expect(second_client_hello.supportsServerCertificateType(
        .raw_public_key,
    ));

    server_output.clearRetainingCapacity();
    const flight_result = try server.receive(
        client_output.items,
        &server_output,
    );
    switch (flight_result.event.?) {
        .server_flight => {},
        else => return error.ExpectedServerFlight,
    }
    try std.testing.expectEqual(@as(usize, 1), resolver_context.calls);
    const server_hello_len = 4 +
        ((@as(usize, server_output.items[1]) << 16) |
            (@as(usize, server_output.items[2]) << 8) |
            server_output.items[3]);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    try appendPlaintextHandshakeRecord(
        &server_wire,
        allocator,
        server_output.items[0..server_hello_len],
    );
    try server_wire.appendSlice(
        allocator,
        server_output.items[server_hello_len..],
    );

    client_output.clearRetainingCapacity();
    var client_established: ?Client.Established = null;
    var offset: usize = 0;
    while (offset < server_wire.items.len) {
        const received = try client.receive(
            server_wire.items[offset..],
            &client_output,
        );
        if (received.consumed == 0 and received.event == null) {
            return error.ClientStateStalled;
        }
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => {},
            .established => |established| {
                client_established = established;
            },
            .hello_retry_request => return error.DuplicateHelloRetryRequest,
            .peer_alert => return error.PeerAbortedHandshake,
        };
    }
    var established_client = client_established orelse
        return error.ClientDidNotEstablish;
    defer established_client.deinit();
    try std.testing.expect(established_client.resumed);
    try std.testing.expect(!established_client.early_data_accepted);
    try std.testing.expectEqual(
        @as(usize, 0),
        established_client.peer_certificate_chain.len,
    );

    const server_established_result = try server.receive(
        client_output.items,
        &server_output,
    );
    var established_server = server_established_result.event.?.established;
    defer established_server.deinit();
    try std.testing.expect(established_server.resumed);
    try std.testing.expect(!established_server.early_data_accepted);
    try std.testing.expectEqual(
        @import("server_connection.zig").Stage.established,
        server.stage,
    );
    try std.testing.expectEqual(
        Stage.established,
        client.stage,
    );
}

test "client connection rejects unoffered ServerHello choices and HRR" {
    try expectRejectedServerHello(
        .aes_256_gcm_sha384,
        key_exchange.named_group_x25519,
        &.{},
        [_]u8{0xd1} ** 32,
        error.ServerSelectedUnofferedSuite,
    );
    try expectRejectedServerHello(
        .aes_128_gcm_sha256,
        key_exchange.named_group_secp256r1,
        &.{},
        [_]u8{0xd2} ** 32,
        error.ServerSelectedUnofferedGroup,
    );
    try expectRejectedServerHello(
        .aes_128_gcm_sha256,
        key_exchange.named_group_x25519,
        &.{1},
        [_]u8{0xd3} ** 32,
        error.SessionIdMismatch,
    );
    try expectRejectedServerHello(
        .aes_128_gcm_sha256,
        key_exchange.named_group_x25519,
        &.{},
        server_hello.hello_retry_request_random,
        error.InvalidServerHello,
    );
}

fn expectRejectedServerHello(
    suite: cipher_suite.Suite,
    group: u16,
    session_id_echo: []const u8,
    random: [32]u8,
    expected_error: anyerror,
) !void {
    const allocator = std.testing.allocator;
    var material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xd4} ** key_exchange.secret_len,
    };
    var client_output: std.ArrayList(u8) = .empty;
    defer client_output.deinit(allocator);
    var client = try ClientConnection(4096, 256).init(.{
        .allocator = allocator,
        .random = [_]u8{0xd5} ** 32,
        .key_material = &material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .server_verifier = .{},
    }, &client_output);
    defer client.deinit();

    const server_public = try key_exchange.publicKey(
        [_]u8{0xd6} ** key_exchange.secret_len,
    );
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try server_hello.writeServerHello(&hello, allocator, .{
        .random = random,
        .session_id_echo = session_id_echo,
        .cipher_suite = suite,
        .key_share_group = group,
        .key_share = &server_public,
    });
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try wire.appendSlice(allocator, &.{
        record.content_type_handshake,
        3,
        3,
        @truncate(hello.items.len >> 8),
        @truncate(hello.items.len),
    });
    try wire.appendSlice(allocator, hello.items);
    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try std.testing.expectError(
        expected_error,
        client.receive(wire.items, &response),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        client.receive("", &response),
    );
}

test "client connection rejects a second HelloRetryRequest" {
    const allocator = std.testing.allocator;
    var initial_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xf1} ** key_exchange.secret_len,
    };
    var retry_material = key_exchange.ClientKeyMaterial{
        .secp256r1 = [_]u8{0} ** (key_exchange.p256.secret_len - 1) ++ .{1},
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var client = try ClientConnection(4096, 256).init(.{
        .allocator = allocator,
        .random = [_]u8{0xf2} ** 32,
        .key_material = &initial_material,
        .retry_key_material = &retry_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .server_verifier = .{},
    }, &output);
    defer client.deinit();

    var retry: std.ArrayList(u8) = .empty;
    defer retry.deinit(allocator);
    try server_hello.writeHelloRetryRequest(&retry, allocator, .{
        .session_id_echo = &.{},
        .cipher_suite = .aes_128_gcm_sha256,
        .selected_group = key_exchange.named_group_secp256r1,
        .cookie = "cookie",
    });
    var retry_record: std.ArrayList(u8) = .empty;
    defer retry_record.deinit(allocator);
    try appendPlaintextHandshakeRecord(&retry_record, allocator, retry.items);
    output.clearRetainingCapacity();
    const first = try client.receive(retry_record.items, &output);
    switch (first.event.?) {
        .hello_retry_request => {},
        else => return error.ExpectedHelloRetryRequest,
    }
    try std.testing.expectError(
        error.DuplicateHelloRetryRequest,
        client.receive(retry_record.items, &output),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        client.receive("", &output),
    );
}

test "client and server states complete PSK-DHE resumption" {
    const allocator = std.testing.allocator;
    const Client = ClientConnection(64 * 1024, 256);
    const server_module = @import("server_connection.zig");
    const Server = server_module.ServerConnection(64 * 1024, 256);
    const psk_secret = secret.Secret.fromSha256([_]u8{0xa7} ** 32);
    const age_add: u32 = 100;
    const actual_age: u32 = 1_000;
    const ticket_module = @import("ticket_keyring.zig");
    var keyring = try ticket_module.Keyring.init(.{
        .id = 7,
        .secret = [_]u8{0xa6} ** ticket_module.key_len,
    });
    defer keyring.deinit();
    const identity = try keyring.sealSecret(
        [_]u8{0xa5} ** ticket_module.nonce_len,
        "example.com",
        "h2",
        .{
            .secret = psk_secret,
            .age_add = age_add,
            .issued_at_ms = 10_000,
            .lifetime_seconds = 60,
            .cipher_suite_wire = cipher_suite.Suite.aes_128_gcm_sha256.wireValue(),
        },
    );

    var client_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xa8} ** key_exchange.secret_len,
    };
    var client_psk = ClientPsk{
        .identity = &identity,
        .secret = psk_secret,
        .obfuscated_ticket_age = actual_age +% age_add,
    };
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xa9} ** 32,
        .key_material = &client_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .server_verifier = .{},
        .resumption = client_psk,
    }, &client_wire);
    client_psk.secret.deinit();
    defer client.deinit();

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xaa} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    var server_material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xab} ** key_exchange.secret_len,
    };
    var server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
            .alpn_protocols = &.{"h2"},
        },
        .server_random = [_]u8{0xac} ** 32,
        .key_material = &server_material,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        .resumption = .{ .tickets = .{
            .keyring = &keyring,
            .server_id = "example.com",
            .now_ms = 10_000 + actual_age,
        } },
        .client_auth = .{ .request_context = "optional-client" },
        .client_auth_policy = .{
            .verifier = .{},
            .requirement = .optional,
        },
    });
    defer server.deinit();

    var server_output: std.ArrayList(u8) = .empty;
    defer server_output.deinit(allocator);
    const server_flight_result = try server.receive(
        client_wire.items,
        &server_output,
    );
    switch (server_flight_result.event.?) {
        .server_flight => {},
        else => return error.ExpectedServerFlight,
    }
    try std.testing.expect((server.pending orelse unreachable).resumed);

    const server_hello_len = 4 +
        ((@as(usize, server_output.items[1]) << 16) |
            (@as(usize, server_output.items[2]) << 8) |
            server_output.items[3]);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    try appendPlaintextHandshakeRecord(
        &server_wire,
        allocator,
        server_output.items[0..server_hello_len],
    );
    try server_wire.appendSlice(
        allocator,
        server_output.items[server_hello_len..],
    );

    client_wire.clearRetainingCapacity();
    var client_established: ?Client.Established = null;
    var offset: usize = 0;
    while (offset < server_wire.items.len) {
        const received = try client.receive(
            server_wire.items[offset..],
            &client_wire,
        );
        if (received.consumed == 0 and received.event == null) {
            return error.ClientStateStalled;
        }
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => {},
            .established => |established| {
                client_established = established;
            },
            .hello_retry_request => return error.UnexpectedHelloRetryRequest,
            .peer_alert => return error.PeerAbortedHandshake,
        };
    }
    var established_client = client_established orelse
        return error.ClientDidNotEstablish;
    defer established_client.deinit();
    try std.testing.expect(established_client.resumed);
    try std.testing.expectEqual(
        @as(usize, 0),
        established_client.peer_certificate_chain.len,
    );

    const server_established_result = try server.receive(
        client_wire.items,
        &server_output,
    );
    var established_server = server_established_result.event.?.established;
    defer established_server.deinit();
    try std.testing.expect(established_server.resumed);
    try std.testing.expect(established_server.peer_certificate_chain == null);
}

test "server state rejects a tampered selected PSK binder and locks" {
    const allocator = std.testing.allocator;
    const server_module = @import("server_connection.zig");
    const Server = server_module.ServerConnection(4096, 256);
    const psk_secret = secret.Secret.fromSha256([_]u8{0xb7} ** 32);

    var client_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xb8} ** key_exchange.secret_len,
    };
    var offered_psk = ClientPsk{
        .identity = "selected-ticket",
        .secret = psk_secret,
        .obfuscated_ticket_age = 0,
    };
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var client = try ClientConnection(4096, 256).init(.{
        .allocator = allocator,
        .random = [_]u8{0xb9} ** 32,
        .key_material = &client_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .server_verifier = .{},
        .resumption = offered_psk,
    }, &client_wire);
    offered_psk.secret.deinit();
    defer client.deinit();
    client_wire.items[client_wire.items.len - 1] ^= 1;

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xba} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    var server_material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xbb} ** key_exchange.secret_len,
    };
    var accepted_psk = server_module.ServerPsk{
        .identity = "selected-ticket",
        .secret = psk_secret,
    };
    var server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
        },
        .server_random = [_]u8{0xbc} ** 32,
        .key_material = &server_material,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        .resumption = .{ .fixed = &accepted_psk },
    });
    defer server.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try std.testing.expectError(
        error.InvalidPskBinder,
        server.receive(client_wire.items, &output),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        server.receive("", &output),
    );
}

test "client and server accept bounded replay-guarded 0-RTT" {
    const allocator = std.testing.allocator;
    const server_module = @import("server_connection.zig");
    const early_module = @import("early_data.zig");
    const ticket_module = @import("ticket_keyring.zig");
    const Client = ClientConnection(64 * 1024, 256);
    const Server = server_module.ServerConnection(64 * 1024, 256);
    const psk_secret = secret.Secret.fromSha256([_]u8{0xc7} ** 32);
    var keyring = try ticket_module.Keyring.init(.{
        .id = 9,
        .secret = [_]u8{0xc8} ** ticket_module.key_len,
    });
    defer keyring.deinit();
    const identity = try keyring.sealSecret(
        [_]u8{0xc9} ** ticket_module.nonce_len,
        "example.com",
        "h2",
        .{
            .secret = psk_secret,
            .age_add = 23,
            .issued_at_ms = 20_000,
            .lifetime_seconds = 60,
            .cipher_suite_wire = cipher_suite.Suite.aes_128_gcm_sha256.wireValue(),
            .max_early_data_size = 1024,
        },
    );
    var replay_cache = early_module.ReplayCache(4){};

    var client_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xca} ** key_exchange.secret_len,
    };
    var offered_psk = ClientPsk{
        .identity = &identity,
        .secret = psk_secret,
        .obfuscated_ticket_age = 1_023,
        .suite = .aes_128_gcm_sha256,
        .max_early_data_size = 1024,
    };
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xcb} ** 32,
        .server_name = "example.com",
        .key_material = &client_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .server_verifier = .{},
        .resumption = offered_psk,
    }, &client_wire);
    offered_psk.secret.deinit();
    defer client.deinit();
    const client_hello_record_len = client_wire.items.len;
    var early_record: [256]u8 = undefined;
    const early_record_len = try client.sealEarlyData(
        "zero round trip",
        &early_record,
    );
    try client_wire.appendSlice(
        allocator,
        early_record[0..early_record_len],
    );

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xcc} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    var server_material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xcd} ** key_exchange.secret_len,
    };
    var server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
            .alpn_protocols = &.{"h2"},
        },
        .server_random = [_]u8{0xce} ** 32,
        .key_material = &server_material,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        .resumption = .{ .tickets = .{
            .keyring = &keyring,
            .server_id = "example.com",
            .now_ms = 21_000,
        } },
        .early_data = .{
            .replay_guard = replay_cache.guard(),
            .max_bytes = 1024,
        },
    });
    defer server.deinit();

    var server_output: std.ArrayList(u8) = .empty;
    defer server_output.deinit(allocator);
    const server_flight = try server.receive(
        client_wire.items,
        &server_output,
    );
    try std.testing.expectEqual(client_hello_record_len, server_flight.consumed);
    switch (server_flight.event.?) {
        .server_flight => {},
        else => return error.ExpectedServerFlight,
    }
    const early = try server.receive(
        client_wire.items[server_flight.consumed..],
        &server_output,
    );
    try std.testing.expectEqualStrings(
        "zero round trip",
        early.event.?.early_data,
    );

    const server_hello_len = 4 +
        ((@as(usize, server_output.items[1]) << 16) |
            (@as(usize, server_output.items[2]) << 8) |
            server_output.items[3]);
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    try appendPlaintextHandshakeRecord(
        &server_wire,
        allocator,
        server_output.items[0..server_hello_len],
    );
    try server_wire.appendSlice(
        allocator,
        server_output.items[server_hello_len..],
    );
    client_wire.clearRetainingCapacity();
    var client_established: ?Client.Established = null;
    var offset: usize = 0;
    while (offset < server_wire.items.len) {
        const received = try client.receive(
            server_wire.items[offset..],
            &client_wire,
        );
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => {},
            .established => |established| {
                client_established = established;
            },
            else => return error.UnexpectedClientEvent,
        };
    }
    var established_client = client_established orelse
        return error.ClientDidNotEstablish;
    defer established_client.deinit();
    try std.testing.expect(established_client.early_data_accepted);

    const end_of_early_data = try server.receive(
        client_wire.items,
        &server_output,
    );
    switch (end_of_early_data.event.?) {
        .end_of_early_data => {},
        else => return error.ExpectedEndOfEarlyData,
    }
    const established_result = try server.receive("", &server_output);
    var established_server = established_result.event.?.established;
    defer established_server.deinit();
    try std.testing.expect(established_server.early_data_accepted);

    // A second connection can still resume, but the same ticket identity is
    // replayed and therefore its 0-RTT records are decrypted and discarded.
    var replay_material = key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0xcf} ** key_exchange.secret_len,
    };
    var replay_psk = ClientPsk{
        .identity = &identity,
        .secret = psk_secret,
        .obfuscated_ticket_age = 1_024,
        .suite = .aes_128_gcm_sha256,
        .max_early_data_size = 1024,
    };
    var replay_wire: std.ArrayList(u8) = .empty;
    defer replay_wire.deinit(allocator);
    var replay_client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xd0} ** 32,
        .server_name = "example.com",
        .key_material = &replay_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .server_verifier = .{},
        .resumption = replay_psk,
    }, &replay_wire);
    replay_psk.secret.deinit();
    defer replay_client.deinit();
    const replay_hello_len = replay_wire.items.len;
    const replay_early_len = try replay_client.sealEarlyData(
        "must be discarded",
        &early_record,
    );
    try replay_wire.appendSlice(
        allocator,
        early_record[0..replay_early_len],
    );
    var replay_server_material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0xd1} ** key_exchange.secret_len,
    };
    var replay_server = Server.init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
            .alpn_protocols = &.{"h2"},
        },
        .server_random = [_]u8{0xd2} ** 32,
        .key_material = &replay_server_material,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        .resumption = .{ .tickets = .{
            .keyring = &keyring,
            .server_id = "example.com",
            .now_ms = 21_001,
        } },
        .early_data = .{
            .replay_guard = replay_cache.guard(),
            .max_bytes = 1024,
        },
    });
    defer replay_server.deinit();
    var replay_server_output: std.ArrayList(u8) = .empty;
    defer replay_server_output.deinit(allocator);
    _ = try replay_server.receive(replay_wire.items, &replay_server_output);
    try std.testing.expect(
        !(replay_server.pending orelse unreachable).early_data_accepted,
    );
    const discarded = try replay_server.receive(
        replay_wire.items[replay_hello_len..],
        &replay_server_output,
    );
    try std.testing.expect(discarded.event == null);
    try std.testing.expectEqual(
        replay_early_len,
        discarded.consumed,
    );
}
