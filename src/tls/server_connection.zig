//! Incremental TLS 1.3 server handshake state.
//!
//! This state owns ClientHello framing, key exchange, server-flight emission,
//! encrypted client Finished verification, and the transition to established
//! application traffic. It removes the need for callers to manually carry
//! shared secrets, transcript hashes, traffic keys, or record sequence numbers.

const std = @import("std");
const alert = @import("alert.zig");
const application_settings = @import("application_settings.zig");
const auth = @import("auth.zig");
const certificate_compression = @import("certificate_compression.zig");
const client_auth = @import("client_auth.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const connection = @import("connection.zig");
const early_data = @import("early_data.zig");
const ech = @import("ech.zig");
const key_exchange = @import("key_exchange.zig");
const key_log = @import("key_log.zig");
const key_schedule = @import("key_schedule.zig");
const psk = @import("psk.zig");
const record = @import("record.zig");
const record_size_limit = @import("record_size_limit.zig");
const secret = @import("secret.zig");
const server_flight = @import("server_flight.zig");
const server_handshake = @import("server_handshake.zig");
const server_hello = @import("server_hello.zig");
const stream = @import("stream.zig");
const ticket = @import("ticket.zig");
const ticket_keyring = @import("ticket_keyring.zig");
const traffic = @import("traffic.zig");
const transcript = @import("transcript.zig");

pub const Error = std.mem.Allocator.Error || client_hello.Error ||
    server_handshake.Error || stream.ProtectedError || key_schedule.Error ||
    secret.Error || psk.Error || connection.Error || ech.Error || error{
    UnexpectedRecord,
    UnexpectedHandshakeMessage,
    UnexpectedApplicationData,
    DuplicateChangeCipherSpec,
    BadClientFinished,
    PeerAbortedHandshake,
    InvalidSecondClientHello,
    InvalidRetryCookie,
    EarlyDataAfterRetry,
    AlreadyEstablished,
    ConnectionFailed,
    InvalidClientAuthConfiguration,
    IdentityResolutionFailed,
    UnrecognizedName,
    NoRequestedTicketsPending,
};

pub const Stage = enum {
    client_hello,
    second_client_hello,
    client_finished,
    established,
    failed,
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    policy: server_flight.Policy,
    server_random: [32]u8,
    /// Single-use material consumed and wiped after ClientHello negotiation.
    key_material: *key_exchange.ServerKeyMaterial,
    certificate_chain: []const []const u8,
    signer: auth.Signer,
    server_certificate_type: auth.CertificateType = .x509,
    identity_resolver: ?IdentityResolver = null,
    client_auth: ?server_handshake.ClientAuthOptions = null,
    client_auth_policy: ?client_auth.ServerPolicy = null,
    /// RFC 8449 limit advertised when the client offers the extension.
    record_size_limit: ?u16 = null,
    /// Maximum RFC 9149 ticket request count honored per connection.
    max_requested_tickets: u8 = 0,
    retry_cookie: ?[]const u8 = null,
    resumption: ?ServerResumption = null,
    early_data: ?EarlyDataPolicy = null,
    ech: ?ech.ServerConfig = null,
    /// Opt-in NSS-compatible traffic-secret logging for diagnostics.
    key_log: ?key_log.Logger = null,
};

pub const ResolvedIdentity = struct {
    certificate_chain: []const []const u8,
    signer: auth.Signer,
    certificate_type: auth.CertificateType = .x509,
    /// Exact DER DistinguishedNames under which this X.509 chain is valid.
    /// When populated, IdentitySet uses ClientHello CA hints to filter it.
    certificate_authorities: []const []const u8 = &.{},
    ocsp_response: ?[]const u8 = null,
    compressed_certificates: []const certificate_compression.PreparedView = &.{},

    pub fn validate(self: ResolvedIdentity) auth.Error!void {
        if (self.certificate_type == .raw_public_key and
            (self.ocsp_response != null or
                self.certificate_authorities.len != 0))
        {
            return error.InvalidCertificate;
        }
        for (self.certificate_authorities) |name| {
            if (name.len == 0) return error.InvalidCertificate;
        }
        try (auth.ServerIdentity{
            .certificate_chain = self.certificate_chain,
            .signer = self.signer,
            .certificate_type = self.certificate_type,
        }).validate();
    }
};

pub const IdentityResolver = struct {
    context: ?*anyopaque,
    resolve_fn: *const fn (
        context: ?*anyopaque,
        hello: client_hello.Parsed,
    ) anyerror!?ResolvedIdentity,

    pub fn resolve(
        self: IdentityResolver,
        hello: client_hello.Parsed,
    ) anyerror!?ResolvedIdentity {
        return self.resolve_fn(self.context, hello);
    }
};

pub const NamedIdentity = struct {
    server_name_pattern: []const u8,
    identity: ResolvedIdentity,
};

pub const IdentitySet = struct {
    entries: []const NamedIdentity,
    fallback: ?ResolvedIdentity = null,

    pub fn resolver(self: *const IdentitySet) IdentityResolver {
        return .{
            .context = @ptrCast(@constCast(self)),
            .resolve_fn = resolveIdentitySet,
        };
    }

    fn resolveIdentitySet(
        opaque_context: ?*anyopaque,
        hello: client_hello.Parsed,
    ) anyerror!?ResolvedIdentity {
        const self: *const IdentitySet = @ptrCast(@alignCast(
            opaque_context orelse return error.MissingIdentityResolver,
        ));
        if (hello.server_name) |server_name| {
            for (self.entries) |entry| {
                if (std.ascii.eqlIgnoreCase(
                    entry.server_name_pattern,
                    server_name,
                ) and try identityCompatible(hello, entry.identity)) {
                    return entry.identity;
                }
            }
            for (self.entries) |entry| {
                if (matchesWildcardServerName(
                    entry.server_name_pattern,
                    server_name,
                ) and try identityCompatible(hello, entry.identity)) {
                    return entry.identity;
                }
            }
        }
        if (self.fallback) |fallback| {
            if (try identityCompatible(hello, fallback)) {
                return fallback;
            }
        }
        return null;
    }
};

fn identityCompatible(
    hello: client_hello.Parsed,
    identity: ResolvedIdentity,
) client_hello.Error!bool {
    if (!try hello.supportsSignatureScheme(identity.signer.scheme())) {
        return false;
    }
    if (identity.certificate_type == .x509 and
        hello.certificate_authorities != null and
        identity.certificate_authorities.len != 0)
    {
        for (identity.certificate_authorities) |name| {
            if (hello.supportsCertificateAuthority(name)) break;
        } else return false;
    }
    if (hello.server_certificate_types.len == 0) {
        return identity.certificate_type == .x509;
    }
    return hello.supportsServerCertificateType(identity.certificate_type);
}

pub const ServerPsk = struct {
    identity: []const u8,
    secret: secret.Secret,
    age_policy: ?psk.TicketAgePolicy = null,
    max_early_data_size: ?u32 = null,
};

pub const EarlyDataPolicy = struct {
    replay_guard: early_data.Guard,
    max_bytes: u32,
};

pub const TicketResumption = struct {
    keyring: *const ticket_keyring.Keyring,
    server_id: []const u8,
    now_ms: u64,
};

pub const ServerResumption = union(enum) {
    fixed: *ServerPsk,
    tickets: TicketResumption,
};

/// `max_handshake_message_len` bounds both ClientHello and encrypted client
/// Certificate messages, including an RFC 7250 SubjectPublicKeyInfo.
pub fn ServerConnection(
    comptime max_handshake_message_len: usize,
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
            resumed: bool,
            early_data_accepted: bool,
            certificate_compression: ?certificate_compression.Algorithm,
            client_certificate_compression: ?certificate_compression.Algorithm,
            server_certificate_type: auth.CertificateType,
            client_certificate_type: auth.CertificateType,
            local_record_size_limit: ?u16,
            peer_record_size_limit: ?u16,
            remaining_requested_tickets: u8,
            application_settings_codepoint: ?application_settings.Codepoint,
            local_application_settings: ?[]u8,
            peer_application_settings: ?[]u8,
            peer_certificate_chain: ?[][]u8 = null,
            ech_accepted: bool,

            pub const TicketOptions = struct {
                keyring: *const ticket_keyring.Keyring,
                sealing_nonce: [ticket_keyring.nonce_len]u8,
                server_id: []const u8,
                alpn: []const u8,
                ticket_nonce: []const u8,
                age_add: u32,
                issued_at_ms: u64,
                lifetime_seconds: u32,
                allow_early_data: bool = false,
            };

            pub fn deinit(self: *Established) void {
                self.application.deinit();
                self.master_secret.deinit();
                if (self.peer_certificate_chain) |chain| {
                    for (chain) |certificate| self.allocator.free(certificate);
                    self.allocator.free(chain);
                }
                if (self.local_application_settings) |settings| {
                    self.allocator.free(settings);
                }
                if (self.peer_application_settings) |settings| {
                    self.allocator.free(settings);
                }
                self.* = undefined;
            }

            pub fn dangerousExtractSecrets(
                self: *Established,
            ) connection.Error!connection.ExtractedSecrets {
                return self.application.dangerousExtractSecrets();
            }

            pub fn sealNewSessionTicket(
                self: *Established,
                allocator: std.mem.Allocator,
                options: TicketOptions,
                output: []u8,
            ) (Error || ticket.Error || ticket_keyring.Error)!usize {
                var resumption_master =
                    try key_schedule.deriveResumptionMasterSecretFor(
                        self.master_secret,
                        self.transcript_after_client_finished,
                    );
                defer resumption_master.deinit();
                var resumption_psk = try key_schedule.deriveResumptionPskFor(
                    resumption_master,
                    options.ticket_nonce,
                );
                defer resumption_psk.deinit();
                const identity = try options.keyring.sealSecret(
                    options.sealing_nonce,
                    options.server_id,
                    options.alpn,
                    .{
                        .secret = resumption_psk,
                        .age_add = options.age_add,
                        .issued_at_ms = options.issued_at_ms,
                        .lifetime_seconds = options.lifetime_seconds,
                        .cipher_suite_wire = self.application.suite.wireValue(),
                        .max_early_data_size = if (options.allow_early_data)
                            ticket.quic_early_data_size
                        else
                            null,
                    },
                );
                var message: std.ArrayList(u8) = .empty;
                defer message.deinit(allocator);
                try ticket.write(&message, allocator, .{
                    .lifetime_seconds = options.lifetime_seconds,
                    .age_add = options.age_add,
                    .nonce = options.ticket_nonce,
                    .ticket = &identity,
                    .allow_early_data = options.allow_early_data,
                });
                return self.application.sealPostHandshake(
                    message.items,
                    output,
                );
            }

            pub fn requestedTicketsRemaining(
                self: *const Established,
            ) u8 {
                return self.remaining_requested_tickets;
            }

            pub fn sealRequestedNewSessionTicket(
                self: *Established,
                allocator: std.mem.Allocator,
                options: TicketOptions,
                output: []u8,
            ) (Error || ticket.Error || ticket_keyring.Error)!usize {
                if (self.remaining_requested_tickets == 0) {
                    return error.NoRequestedTicketsPending;
                }
                const len = try self.sealNewSessionTicket(
                    allocator,
                    options,
                    output,
                );
                self.remaining_requested_tickets -= 1;
                return len;
            }
        };

        pub const Event = union(enum) {
            hello_retry_request: void,
            server_flight: void,
            compatibility_change_cipher_spec: void,
            early_data: []const u8,
            end_of_early_data: void,
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
            client_random: [32]u8,
            handshake_secret: secret.Secret,
            client_handshake_secret: secret.Secret,
            transcript_after_server_finished: transcript.Digest,
            transcript_state: transcript.State,
            resumed: bool,
            certificate_compression: ?certificate_compression.Algorithm,
            server_certificate_type: auth.CertificateType,
            client_certificate_type: auth.CertificateType,
            client_records: traffic.State,
            early_records: ?traffic.State = null,
            early_data_accepted: bool = false,
            early_data_limit: usize = 0,
            early_data_received: usize = 0,
            expect_end_of_early_data: bool = false,
            early_deframer: stream.RecordDeframer = .{},
            early_messages: stream.HandshakeReassembler(4) = .{},
            early_plaintext: [record.max_inner_plaintext_len]u8 = undefined,
            receiver: stream.ProtectedReceiver(max_handshake_message_len) = .{},
            saw_change_cipher_spec: bool = false,
            client_flight: std.ArrayList(u8) = .empty,
            client_certificate: ?MessageRange = null,
            client_certificate_verify: ?MessageRange = null,
            authenticated_client_chain: ?[][]u8 = null,
            client_certificate_compression: ?certificate_compression.Algorithm = null,
            local_record_size_limit: ?u16,
            peer_record_size_limit: ?u16,
            requested_ticket_count: u8,
            application_settings: ?application_settings.Payload,
            peer_application_settings: ?[]u8 = null,
            expect_client_encrypted_extensions: bool,
            transcript_after_client_finished: ?transcript.Digest = null,

            fn deinit(self: *PendingHandshake) void {
                self.client_records.deinit();
                if (self.early_records) |*early| early.deinit();
                self.handshake_secret.deinit();
                self.client_handshake_secret.deinit();
                self.client_flight.deinit(self.allocator);
                if (self.authenticated_client_chain) |chain| {
                    for (chain) |certificate| {
                        self.allocator.free(certificate);
                    }
                    self.allocator.free(chain);
                }
                if (self.peer_application_settings) |settings| {
                    self.allocator.free(settings);
                }
                self.* = undefined;
            }
        };

        const MessageRange = struct {
            start: usize,
            len: usize,

            fn slice(self: MessageRange, bytes: []const u8) []const u8 {
                return bytes[self.start..][0..self.len];
            }
        };

        const SelectedResumption = struct {
            psk_secret: secret.Secret,
            max_early_data_size: ?u32,
            issued_at_ms: ?u64,
            lifetime_seconds: ?u32,

            fn deinit(self: *SelectedResumption) void {
                self.psk_secret.deinit();
                self.* = undefined;
            }
        };

        const RetryState = struct {
            allocator: std.mem.Allocator,
            first_client_hello: []u8,
            transcript_after_retry: transcript.State,
            suite: cipher_suite.Suite,
            selected_group: u16,
            identity: ResolvedIdentity,

            fn deinit(self: *RetryState) void {
                self.allocator.free(self.first_client_hello);
                self.* = undefined;
            }
        };

        config: Config,
        stage: Stage = .client_hello,
        key_material_consumed: bool = false,
        psk_consumed: bool = false,
        records: stream.RecordDeframer = .{},
        hello_messages: stream.HandshakeReassembler(
            max_handshake_message_len,
        ) = .{},
        retry: ?RetryState = null,
        ech_context: ?ech.ServerContext = null,
        ech_offered: bool = false,
        ech_accepted: bool = false,
        saw_retry_change_cipher_spec: bool = false,
        pending: ?PendingHandshake = null,

        pub fn init(config: Config) Self {
            return .{ .config = config };
        }

        pub fn deinit(self: *Self) void {
            self.cleanup();
            self.* = undefined;
        }

        fn resolveIdentity(
            self: *const Self,
            hello: client_hello.Parsed,
        ) Error!ResolvedIdentity {
            const identity = if (self.config.identity_resolver) |resolver|
                resolver.resolve(hello) catch
                    return error.IdentityResolutionFailed
            else
                ResolvedIdentity{
                    .certificate_chain = self.config.certificate_chain,
                    .signer = self.config.signer,
                    .certificate_type = self.config.server_certificate_type,
                    .ocsp_response = self.config.policy.ocsp_response,
                    .compressed_certificates = self.config.policy.compressed_certificates,
                };
            const selected = identity orelse return error.UnrecognizedName;
            try selected.validate();
            if (!try hello.supportsSignatureScheme(selected.signer.scheme())) {
                return error.UnsupportedSignatureScheme;
            }
            return selected;
        }

        /// Feed arbitrary transport bytes. When `.server_flight` is returned,
        /// the complete cleartext ServerHello plus encrypted handshake flight
        /// has been appended to `output`. `.established` transfers ownership of
        /// application traffic and the master secret to the caller.
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

        fn receiveInner(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            return switch (self.stage) {
                .client_hello,
                .second_client_hello,
                => self.receiveClientHello(input, output),
                .client_finished => self.receiveClientFinished(input),
                .established => error.AlreadyEstablished,
                .failed => error.ConnectionFailed,
            };
        }

        fn receiveClientHello(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            if ((self.config.client_auth == null) !=
                (self.config.client_auth_policy == null))
            {
                return error.InvalidClientAuthConfiguration;
            }
            const record_result = try self.records.push(input);
            const framed = record_result.framed orelse return .{
                .consumed = record_result.consumed,
                .event = null,
            };
            if (framed.content_type == stream.content_type_change_cipher_spec) {
                if (self.stage != .second_client_hello or
                    self.saw_retry_change_cipher_spec or
                    !std.mem.eql(u8, framed.fragment, &.{1}))
                {
                    return error.DuplicateChangeCipherSpec;
                }
                self.saw_retry_change_cipher_spec = true;
                return .{
                    .consumed = record_result.consumed,
                    .event = .{
                        .compatibility_change_cipher_spec = {},
                    },
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
                    message[0] != client_hello.handshake_type_client_hello)
                {
                    return error.UnexpectedHandshakeMessage;
                }
                var inner_hello: std.ArrayList(u8) = .empty;
                defer inner_hello.deinit(self.config.allocator);
                const effective_message = try self.clientHelloForNegotiation(
                    message,
                    &inner_hello,
                );
                const parsed = try client_hello.parse(effective_message);
                if (self.stage == .second_client_hello) {
                    return self.acceptSecondClientHello(
                        record_result.consumed,
                        effective_message,
                        parsed,
                        output,
                    );
                }
                const material_group = self.config.key_material.namedGroup();
                if (try parsed.keyShareForGroup(material_group) == null) {
                    return self.sendHelloRetryRequest(
                        record_result.consumed,
                        effective_message,
                        parsed,
                        output,
                    );
                }
                try self.startServerFlight(
                    effective_message,
                    parsed,
                    null,
                    null,
                    null,
                    null,
                    output,
                );
                return .{
                    .consumed = record_result.consumed,
                    .event = .{ .server_flight = {} },
                };
            }
            return .{
                .consumed = record_result.consumed,
                .event = null,
            };
        }

        fn clientHelloForNegotiation(
            self: *Self,
            outer_message: []const u8,
            inner_output: *std.ArrayList(u8),
        ) Error![]const u8 {
            const parsed_outer = try client_hello.parse(outer_message);
            if (parsed_outer.encrypted_client_hello != null) {
                self.ech_offered = true;
            }
            if (self.stage == .second_client_hello) {
                const context = &(self.ech_context orelse
                    return outer_message);
                try context.openRetry(
                    inner_output,
                    self.config.allocator,
                    outer_message,
                );
                return inner_output.items;
            }
            const server_config = self.config.ech orelse return outer_message;
            const encoded_extension = parsed_outer.encrypted_client_hello orelse
                return outer_message;
            const outer = switch (try ech.parseClientHelloExtension(
                encoded_extension,
            )) {
                .outer => |value| value,
                .inner => return error.InvalidEchExtension,
            };
            if (outer.config_id != server_config.config.config_id or
                !std.meta.eql(
                    outer.cipher_suite,
                    server_config.config.cipher_suite,
                ))
            {
                return outer_message;
            }
            if (server_config.require_public_name_match and
                (parsed_outer.server_name == null or
                    !server_config.config.outerNameMatches(
                        parsed_outer.server_name.?,
                    )))
            {
                return error.InvalidClientHello;
            }
            var context = ech.openInitialWithKeyPair(
                inner_output,
                self.config.allocator,
                outer_message,
                server_config.config,
                server_config.key_pair,
            ) catch |err| switch (err) {
                error.AuthenticationFailed => return outer_message,
                else => return err,
            };
            errdefer context.deinit();
            self.ech_context = context;
            self.ech_accepted = true;
            return inner_output.items;
        }

        fn sendHelloRetryRequest(
            self: *Self,
            consumed: usize,
            message: []const u8,
            parsed: client_hello.Parsed,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const material_group = self.config.key_material.namedGroup();
            const identity = try self.resolveIdentity(parsed);
            var policy = self.config.policy;
            policy.server_certificate_type = identity.certificate_type;
            policy.client_certificate_type = if (self.config.client_auth_policy) |client_policy|
                client_policy.certificate_type
            else
                .x509;
            const selected = try server_flight.selectHelloRetryRequest(
                parsed,
                policy,
                material_group,
            );
            const first_client_hello = try self.config.allocator.dupe(
                u8,
                message,
            );
            errdefer self.config.allocator.free(first_client_hello);
            const retry_start = output.items.len;
            try server_hello.writeHelloRetryRequest(
                output,
                self.config.allocator,
                .{
                    .session_id_echo = parsed.session_id,
                    .cipher_suite = selected.suite,
                    .selected_group = selected.selected_group,
                    .cookie = self.config.retry_cookie,
                    .ech_confirmation = if (self.ech_context != null)
                        [_]u8{0} ** ech.confirmation_len
                    else
                        null,
                },
            );
            if (self.ech_context != null) {
                const retry_bytes = output.items[retry_start..];
                const confirmation_transcript =
                    transcript.afterHelloRetryRequest(
                        selected.suite.hash(),
                        message,
                        retry_bytes,
                    ).digest();
                const confirmation = try ech.hrrAcceptConfirmation(
                    selected.suite.hash(),
                    parsed.random.*,
                    confirmation_transcript,
                );
                output.items[output.items.len - ech.confirmation_len ..][0..ech.confirmation_len].* = confirmation;
            }
            self.retry = .{
                .allocator = self.config.allocator,
                .first_client_hello = first_client_hello,
                .transcript_after_retry = transcript.afterHelloRetryRequest(
                    selected.suite.hash(),
                    message,
                    output.items[retry_start..],
                ),
                .suite = selected.suite,
                .selected_group = selected.selected_group,
                .identity = identity,
            };
            self.hello_messages.reset();
            self.stage = .second_client_hello;
            return .{
                .consumed = consumed,
                .event = .{ .hello_retry_request = {} },
            };
        }

        fn acceptSecondClientHello(
            self: *Self,
            consumed: usize,
            message: []const u8,
            parsed: client_hello.Parsed,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const retry = &(self.retry orelse unreachable);
            try client_hello.validateSecondClientHello(
                retry.first_client_hello,
                parsed,
                retry.selected_group,
                self.config.retry_cookie,
            );
            var prefix = retry.transcript_after_retry;
            const binder_prefix = retry.transcript_after_retry;
            prefix.update(message);
            try self.startServerFlight(
                message,
                parsed,
                prefix,
                retry.suite,
                binder_prefix,
                retry.identity,
                output,
            );
            retry.deinit();
            self.retry = null;
            return .{
                .consumed = consumed,
                .event = .{ .server_flight = {} },
            };
        }

        fn startServerFlight(
            self: *Self,
            message: []const u8,
            parsed: client_hello.Parsed,
            transcript_prefix: ?transcript.State,
            retry_suite: ?cipher_suite.Suite,
            binder_prefix: ?transcript.State,
            resolved_identity: ?ResolvedIdentity,
            output: *std.ArrayList(u8),
        ) Error!void {
            var policy = self.config.policy;
            const identity = resolved_identity orelse
                try self.resolveIdentity(parsed);
            policy.ocsp_response = identity.ocsp_response;
            policy.compressed_certificates =
                identity.compressed_certificates;
            policy.server_certificate_type = identity.certificate_type;
            policy.client_certificate_type = if (self.config.client_auth_policy) |client_policy|
                client_policy.certificate_type
            else
                .x509;
            const retry_suites = if (retry_suite) |suite|
                [_]cipher_suite.Suite{suite}
            else
                undefined;
            if (retry_suite != null) policy.cipher_suites = &retry_suites;
            const selection = try server_flight.select(parsed, policy);
            var selected_psk = try self.selectResumption(
                message,
                selection,
                binder_prefix,
            );
            defer if (selected_psk) |*selected| selected.deinit();
            const early_limit = if (selection.application_settings == null) if (selected_psk) |selected|
                try self.acceptedEarlyDataLimit(
                    message,
                    selected,
                    binder_prefix != null,
                )
            else
                null else null;
            var early_records: ?traffic.State = null;
            if (selected_psk != null and
                (try client_hello.parse(message)).early_data)
            {
                const hello_hash = if (binder_prefix) |prefix_state| blk: {
                    var state = prefix_state;
                    state.update(message);
                    break :blk state.digest();
                } else transcript.hashFor(
                    selection.suite.hash(),
                    &.{message},
                );
                var early_secret =
                    try key_schedule.deriveClientEarlyTrafficSecretFor(
                        selected_psk.?.psk_secret,
                        hello_hash,
                    );
                defer early_secret.deinit();
                key_log.emit(
                    self.config.key_log,
                    key_log.client_early_traffic_secret,
                    parsed.random,
                    early_secret.bytes(),
                );
                early_records = try traffic.State.init(
                    selection.suite,
                    early_secret,
                );
            }
            errdefer if (early_records) |*early| early.deinit();
            self.consumeFixedPsk();
            self.key_material_consumed = true;
            var ech_retry_configs: std.ArrayList(u8) = .empty;
            defer ech_retry_configs.deinit(self.config.allocator);
            if (self.ech_offered and !self.ech_accepted) {
                if (self.config.ech) |server_ech| {
                    try ech.writeConfigList(
                        &ech_retry_configs,
                        self.config.allocator,
                        &.{server_ech.config.encoded},
                    );
                }
            }
            var result = try server_handshake
                .writeServerHandshakeFlightManaged(
                output,
                self.config.allocator,
                .{
                    .client_hello_bytes = message,
                    .parsed_client_hello = parsed,
                    .policy = policy,
                    .server_random = self.config.server_random,
                    .key_material = self.config.key_material,
                    .certificate_chain = identity.certificate_chain,
                    .signer = identity.signer,
                    .psk = if (selected_psk) |selected|
                        selected.psk_secret
                    else
                        null,
                    .selected_psk_identity = if (selected_psk != null)
                        psk.selected_identity_first
                    else
                        null,
                    .accept_early_data = early_limit != null,
                    .ech_inner_random = if (self.ech_context != null)
                        parsed.random.*
                    else
                        null,
                    .ech_retry_configs = if (ech_retry_configs.items.len != 0)
                        ech_retry_configs.items
                    else
                        null,
                    .transcript_prefix = transcript_prefix,
                    .client_auth = self.config.client_auth,
                    .record_size_limit = self.config.record_size_limit,
                    .max_requested_tickets = self.config.max_requested_tickets,
                },
            );
            errdefer {
                result.handshake_secret.deinit();
                result.client_handshake_traffic_secret.deinit();
                result.server_handshake_traffic_secret.deinit();
            }
            var client_records = try traffic.State.init(
                result.selection.suite,
                result.client_handshake_traffic_secret,
            );
            errdefer client_records.deinit();
            key_log.emit(
                self.config.key_log,
                key_log.client_handshake_traffic_secret,
                parsed.random,
                result.client_handshake_traffic_secret.bytes(),
            );
            key_log.emit(
                self.config.key_log,
                key_log.server_handshake_traffic_secret,
                parsed.random,
                result.server_handshake_traffic_secret.bytes(),
            );
            result.server_handshake_traffic_secret.deinit();
            self.pending = .{
                .allocator = self.config.allocator,
                .suite = result.selection.suite,
                .client_random = parsed.random.*,
                .handshake_secret = result.handshake_secret,
                .client_handshake_secret = result.client_handshake_traffic_secret,
                .transcript_after_server_finished = result.transcript_after_server_finished,
                .transcript_state = result.transcript_state_after_server_finished,
                .resumed = selected_psk != null,
                .certificate_compression = result.certificate_compression,
                .server_certificate_type = result.selection.server_certificate_type,
                .client_certificate_type = result.selection.client_certificate_type,
                .local_record_size_limit = result.local_record_size_limit,
                .peer_record_size_limit = result.peer_record_size_limit,
                .requested_ticket_count = result.requested_ticket_count,
                .application_settings = result.application_settings,
                .expect_client_encrypted_extensions = result.application_settings != null,
                .client_records = client_records,
                .early_records = early_records,
                .early_data_accepted = early_limit != null,
                .early_data_limit = early_limit orelse 0,
                .expect_end_of_early_data = early_limit != null,
                .saw_change_cipher_spec = self.saw_retry_change_cipher_spec,
            };
            if (result.local_record_size_limit) |limit| {
                self.pending.?.receiver.setMaxCiphertextFragmentLen(
                    try record_size_limit.maxCiphertextFragment(limit),
                );
            }
            if (self.ech_context) |*context| context.deinit();
            self.ech_context = null;
            self.stage = .client_finished;
        }

        fn selectResumption(
            self: *Self,
            client_hello_bytes: []const u8,
            selection: server_flight.Selection,
            binder_prefix: ?transcript.State,
        ) Error!?SelectedResumption {
            const configured = self.config.resumption orelse return null;
            const parsed = try client_hello.parse(client_hello_bytes);
            if (parsed.pre_shared_key == null) return null;
            const offer = try psk.parseClientOfferForHash(
                client_hello_bytes,
                selection.suite.hash(),
            );
            return switch (configured) {
                .fixed => |fixed| blk: {
                    if (!std.mem.eql(u8, offer.identity, fixed.identity) or
                        fixed.secret.hash != selection.suite.hash())
                    {
                        break :blk null;
                    }
                    try psk.verifyClientOfferForSecret(
                        client_hello_bytes,
                        offer,
                        fixed.identity,
                        fixed.secret,
                        binder_prefix,
                    );
                    if (fixed.age_policy) |age_policy| {
                        try psk.validateTicketAge(offer, age_policy);
                    }
                    break :blk .{
                        .psk_secret = fixed.secret,
                        .max_early_data_size = fixed.max_early_data_size,
                        .issued_at_ms = if (fixed.age_policy) |age|
                            age.issued_at_ms
                        else
                            null,
                        .lifetime_seconds = if (fixed.age_policy) |age|
                            age.lifetime_seconds
                        else
                            null,
                    };
                },
                .tickets => |tickets| blk: {
                    var opened = tickets.keyring.openSecret(
                        offer.identity,
                        tickets.server_id,
                        selection.alpn_protocol orelse "",
                        tickets.now_ms,
                    ) catch break :blk null;
                    defer opened.secret.deinit();
                    if (opened.cipher_suite_wire !=
                        selection.suite.wireValue() or
                        opened.secret.hash != selection.suite.hash())
                    {
                        break :blk null;
                    }
                    try psk.verifyClientOfferForSecret(
                        client_hello_bytes,
                        offer,
                        offer.identity,
                        opened.secret,
                        binder_prefix,
                    );
                    try psk.validateTicketAge(offer, .{
                        .age_add = opened.age_add,
                        .issued_at_ms = opened.issued_at_ms,
                        .lifetime_seconds = opened.lifetime_seconds,
                        .now_ms = tickets.now_ms,
                    });
                    break :blk .{
                        .psk_secret = opened.secret,
                        .max_early_data_size = opened.max_early_data_size,
                        .issued_at_ms = opened.issued_at_ms,
                        .lifetime_seconds = opened.lifetime_seconds,
                    };
                },
            };
        }

        fn acceptedEarlyDataLimit(
            self: *Self,
            client_hello_bytes: []const u8,
            selected: SelectedResumption,
            after_retry: bool,
        ) Error!?usize {
            if (after_retry or
                !(try client_hello.parse(client_hello_bytes)).early_data)
            {
                return null;
            }
            const configured = self.config.early_data orelse return null;
            const ticket_limit = selected.max_early_data_size orelse
                return null;
            const issued_at_ms = selected.issued_at_ms orelse return null;
            const lifetime_seconds = selected.lifetime_seconds orelse
                return null;
            const expires_at_ms = std.math.add(
                u64,
                issued_at_ms,
                @as(u64, lifetime_seconds) * std.time.ms_per_s,
            ) catch return null;
            configured.replay_guard.checkAndMark(
                (try psk.parseClientOffer(client_hello_bytes)).identity,
                if (self.config.resumption) |resumption| switch (resumption) {
                    .fixed => |fixed| if (fixed.age_policy) |age|
                        age.now_ms
                    else
                        return null,
                    .tickets => |tickets| tickets.now_ms,
                } else return null,
                expires_at_ms,
            ) catch return null;
            return @min(
                @as(usize, ticket_limit),
                @as(usize, configured.max_bytes),
            );
        }

        fn consumeFixedPsk(self: *Self) void {
            if (self.psk_consumed) return;
            if (self.config.resumption) |configured| switch (configured) {
                .fixed => |fixed| fixed.secret.deinit(),
                .tickets => {},
            };
            self.psk_consumed = true;
        }

        fn receiveClientFinished(
            self: *Self,
            input: []const u8,
        ) Error!ReceiveResult {
            const pending = &(self.pending orelse unreachable);
            if (pending.early_records != null) {
                return self.receiveEarlyOrHandshake(input);
            }
            const result = try pending.receiver.push(
                input,
                &pending.client_records,
            );
            return self.handleClientProtected(
                result.consumed,
                result.event,
            );
        }

        fn receiveEarlyOrHandshake(
            self: *Self,
            input: []const u8,
        ) Error!ReceiveResult {
            const pending = &(self.pending orelse unreachable);
            const result = try pending.early_deframer.push(input);
            const framed = result.framed orelse return .{
                .consumed = result.consumed,
                .event = null,
            };
            if (framed.content_type == stream.content_type_change_cipher_spec) {
                if (pending.saw_change_cipher_spec or
                    !std.mem.eql(u8, framed.fragment, &.{1}))
                {
                    return error.DuplicateChangeCipherSpec;
                }
                pending.saw_change_cipher_spec = true;
                return .{
                    .consumed = result.consumed,
                    .event = .{
                        .compatibility_change_cipher_spec = {},
                    },
                };
            }
            if (framed.content_type != record.content_type_application_data) {
                return error.UnexpectedRecord;
            }

            const early = &(pending.early_records.?);
            const early_opened = early.open(
                framed.bytes,
                &pending.early_plaintext,
            ) catch |err| switch (err) {
                error.AuthenticationFailed => {
                    if (pending.expect_end_of_early_data) {
                        return error.UnexpectedHandshakeMessage;
                    }
                    early.deinit();
                    pending.early_records = null;
                    return self.handleClientProtected(
                        result.consumed,
                        try pending.receiver.processFramed(
                            framed,
                            &pending.client_records,
                        ),
                    );
                },
                else => return err,
            };
            if (early_opened.content_type == record.content_type_handshake) {
                if (!pending.expect_end_of_early_data) {
                    return error.UnexpectedHandshakeMessage;
                }
                const message_result = try pending.early_messages.push(
                    pending.early_plaintext[0..early_opened.len],
                );
                if (message_result.consumed != early_opened.len) {
                    return error.UnexpectedHandshakeMessage;
                }
                const message = message_result.message orelse return .{
                    .consumed = result.consumed,
                    .event = null,
                };
                if (!std.mem.eql(u8, message, &.{ 5, 0, 0, 0 })) {
                    return error.UnexpectedHandshakeMessage;
                }
                pending.expect_end_of_early_data = false;
                pending.transcript_state.update(message);
                early.deinit();
                pending.early_records = null;
                return .{
                    .consumed = result.consumed,
                    .event = .{ .end_of_early_data = {} },
                };
            }
            if (early_opened.content_type != record.content_type_application_data) {
                return error.UnexpectedApplicationData;
            }
            if (!pending.early_data_accepted) {
                return .{ .consumed = result.consumed, .event = null };
            }
            if (early_opened.len > pending.early_data_limit or
                pending.early_data_received >
                    pending.early_data_limit - early_opened.len)
            {
                return error.UnexpectedApplicationData;
            }
            pending.early_data_received += early_opened.len;
            return .{
                .consumed = result.consumed,
                .event = .{
                    .early_data = pending.early_plaintext[0..early_opened.len],
                },
            };
        }

        fn handleClientProtected(
            self: *Self,
            consumed: usize,
            protected_optional: ?stream.ProtectedEvent,
        ) Error!ReceiveResult {
            const pending = &(self.pending orelse unreachable);
            const protected = protected_optional orelse return .{
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
                    return .{
                        .consumed = consumed,
                        .event = event,
                    };
                },
                .application_data => return error.UnexpectedApplicationData,
                .handshake => |message| {
                    if (pending.expect_end_of_early_data) {
                        if (!std.mem.eql(u8, message, &.{ 5, 0, 0, 0 })) {
                            return error.UnexpectedHandshakeMessage;
                        }
                        pending.expect_end_of_early_data = false;
                        pending.transcript_state.update(message);
                        return .{
                            .consumed = consumed,
                            .event = .{ .end_of_early_data = {} },
                        };
                    }
                    if (pending.expect_client_encrypted_extensions) {
                        const received = application_settings
                            .parseClientEncryptedExtensions(message) catch
                            return error.UnexpectedHandshakeMessage;
                        const negotiated = pending.application_settings orelse
                            unreachable;
                        if (received.codepoint != negotiated.codepoint) {
                            return error.UnexpectedHandshakeMessage;
                        }
                        pending.peer_application_settings = try self.config.allocator.dupe(
                            u8,
                            received.settings,
                        );
                        pending.expect_client_encrypted_extensions = false;
                        pending.transcript_state.update(message);
                        if (pending.receiver.hasPendingHandshakeData()) {
                            const next = try pending.receiver.push(
                                "",
                                &pending.client_records,
                            );
                            return self.handleClientProtected(
                                consumed,
                                next.event,
                            );
                        }
                        return .{ .consumed = consumed, .event = null };
                    }
                    if (self.config.client_auth_policy != null) {
                        return self.handleClientAuthHandshake(
                            consumed,
                            message,
                        );
                    }
                    if (pending.receiver.hasPendingHandshakeData()) {
                        return error.UnexpectedHandshakeMessage;
                    }
                    if (message.len < 4 or
                        message[0] != server_handshake.handshake_type_finished)
                    {
                        return error.UnexpectedHandshakeMessage;
                    }
                    const body_len = (@as(usize, message[1]) << 16) |
                        (@as(usize, message[2]) << 8) | message[3];
                    if (body_len != message.len - 4 or
                        body_len != pending.suite.hash().len())
                    {
                        return error.BadClientFinished;
                    }
                    var expected = try key_schedule.computeFinishedFor(
                        pending.client_handshake_secret,
                        pending.transcript_state.digest(),
                    );
                    defer expected.deinit();
                    var actual = try secret.Secret.init(
                        expected.hash,
                        message[4..],
                    );
                    defer actual.deinit();
                    if (!expected.eql(&actual)) {
                        return error.BadClientFinished;
                    }
                    pending.transcript_state.update(message);
                    return .{
                        .consumed = consumed,
                        .event = .{
                            .established = try self.establish(),
                        },
                    };
                },
            }
        }

        fn handleClientAuthHandshake(
            self: *Self,
            consumed: usize,
            message: []const u8,
        ) Error!ReceiveResult {
            const pending = &(self.pending orelse unreachable);
            const start = pending.client_flight.items.len;
            try pending.client_flight.appendSlice(
                self.config.allocator,
                message,
            );
            const range = MessageRange{ .start = start, .len = message.len };
            if (pending.client_certificate == null) {
                if (message[0] != auth.handshake_type_certificate and
                    message[0] != certificate_compression
                        .handshake_type_compressed_certificate)
                {
                    return error.UnexpectedHandshakeMessage;
                }
                pending.client_certificate = range;
                if (pending.receiver.hasPendingHandshakeData()) {
                    const next = try pending.receiver.push(
                        "",
                        &pending.client_records,
                    );
                    return self.handleClientProtected(consumed, next.event);
                }
                return .{ .consumed = consumed, .event = null };
            }
            if (message[0] == auth.handshake_type_certificate_verify and
                pending.client_certificate_verify == null)
            {
                pending.client_certificate_verify = range;
                if (pending.receiver.hasPendingHandshakeData()) {
                    const next = try pending.receiver.push(
                        "",
                        &pending.client_records,
                    );
                    return self.handleClientProtected(consumed, next.event);
                }
                return .{ .consumed = consumed, .event = null };
            }
            if (message[0] != server_handshake.handshake_type_finished or
                pending.receiver.hasPendingHandshakeData())
            {
                return error.UnexpectedHandshakeMessage;
            }
            const request = self.config.client_auth orelse unreachable;
            const policy = self.config.client_auth_policy orelse unreachable;
            var verification = try client_auth.verifyClientFlightWithCompression(
                self.config.allocator,
                policy,
                request.request_context,
                pending.transcript_state,
                pending.client_handshake_secret,
                pending.client_certificate.?.slice(
                    pending.client_flight.items,
                ),
                if (pending.client_certificate_verify) |verify|
                    verify.slice(pending.client_flight.items)
                else
                    null,
                range.slice(pending.client_flight.items),
                request.certificate_compression_algorithms,
                request.max_decompressed_certificate_len,
            );
            defer verification.deinit(self.config.allocator);
            if (verification.authenticated()) {
                pending.authenticated_client_chain = try copyClientChain(
                    self.config.allocator,
                    verification.certificate.entries,
                );
            }
            pending.client_certificate_compression =
                verification.certificate_compression;
            pending.transcript_after_client_finished =
                verification.transcript_after_client_finished;
            return .{
                .consumed = consumed,
                .event = .{ .established = try self.establish() },
            };
        }

        fn establish(self: *Self) Error!Established {
            const pending = &(self.pending orelse unreachable);
            var application = try key_schedule.deriveApplicationFor(
                pending.handshake_secret,
                pending.transcript_after_server_finished,
            );
            errdefer {
                application.master_secret.deinit();
                application.client_traffic_secret.deinit();
                application.server_traffic_secret.deinit();
            }
            var application_connection = try Application.initWithRecordSizeLimits(
                pending.suite,
                application.client_traffic_secret,
                application.server_traffic_secret,
                pending.local_record_size_limit,
                pending.peer_record_size_limit,
            );
            errdefer application_connection.deinit();
            const local_application_settings = if (pending.application_settings) |settings|
                try self.config.allocator.dupe(u8, settings.settings)
            else
                null;
            errdefer if (local_application_settings) |settings| {
                self.config.allocator.free(settings);
            };
            if (self.config.key_log) |logger| {
                logger.log(
                    key_log.client_traffic_secret_0,
                    &pending.client_random,
                    application.client_traffic_secret.bytes(),
                );
                logger.log(
                    key_log.server_traffic_secret_0,
                    &pending.client_random,
                    application.server_traffic_secret.bytes(),
                );
                if (logger.willLog(key_log.exporter_secret)) {
                    var exporter = try key_schedule
                        .deriveExporterMasterSecretFor(
                        application.master_secret,
                        pending.transcript_after_server_finished,
                    );
                    defer exporter.deinit();
                    logger.logEnabled(
                        key_log.exporter_secret,
                        &pending.client_random,
                        exporter.bytes(),
                    );
                }
            }
            application.client_traffic_secret.deinit();
            application.server_traffic_secret.deinit();
            const established = Established{
                .allocator = self.config.allocator,
                .application = application_connection,
                .master_secret = application.master_secret,
                .transcript_after_client_finished = pending.transcript_after_client_finished orelse
                    pending.transcript_state.digest(),
                .resumed = pending.resumed,
                .early_data_accepted = pending.early_data_accepted,
                .certificate_compression = pending.certificate_compression,
                .client_certificate_compression = pending.client_certificate_compression,
                .server_certificate_type = pending.server_certificate_type,
                .client_certificate_type = pending.client_certificate_type,
                .local_record_size_limit = pending.local_record_size_limit,
                .peer_record_size_limit = pending.peer_record_size_limit,
                .remaining_requested_tickets = pending.requested_ticket_count,
                .application_settings_codepoint = if (pending.application_settings) |settings|
                    settings.codepoint
                else
                    null,
                .local_application_settings = local_application_settings,
                .peer_application_settings = pending.peer_application_settings,
                .peer_certificate_chain = pending.authenticated_client_chain,
                .ech_accepted = self.ech_accepted,
            };
            pending.authenticated_client_chain = null;
            pending.peer_application_settings = null;
            pending.deinit();
            self.pending = null;
            self.stage = .established;
            return established;
        }

        fn fail(self: *Self) void {
            self.cleanup();
            self.stage = .failed;
        }

        fn cleanup(self: *Self) void {
            if (self.pending) |*pending| pending.deinit();
            self.pending = null;
            if (self.retry) |*retry| retry.deinit();
            self.retry = null;
            if (self.ech_context) |*context| context.deinit();
            self.ech_context = null;
            if (!self.key_material_consumed) {
                self.config.key_material.wipe();
                self.key_material_consumed = true;
            }
            self.consumeFixedPsk();
        }
    };
}

fn matchesServerNamePattern(pattern: []const u8, server_name: []const u8) bool {
    if (pattern.len == 0 or server_name.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(pattern, server_name)) return true;
    return matchesWildcardServerName(pattern, server_name);
}

fn matchesWildcardServerName(pattern: []const u8, server_name: []const u8) bool {
    if (!std.mem.startsWith(u8, pattern, "*.") or pattern.len == 2 or
        std.mem.indexOfScalar(u8, pattern[1..], '*') != null)
    {
        return false;
    }
    const first_dot = std.mem.indexOfScalar(u8, server_name, '.') orelse
        return false;
    return first_dot != 0 and std.ascii.eqlIgnoreCase(
        pattern[1..],
        server_name[first_dot..],
    );
}

fn copyClientChain(
    allocator: std.mem.Allocator,
    certificates: []const []const u8,
) std.mem.Allocator.Error![][]u8 {
    const copies = try allocator.alloc([]u8, certificates.len);
    var copied: usize = 0;
    errdefer {
        for (copies[0..copied]) |certificate| allocator.free(certificate);
        allocator.free(copies);
    }
    for (certificates, 0..) |certificate, index| {
        copies[index] = try allocator.dupe(u8, certificate);
        copied += 1;
    }
    return copies;
}

test "HelloRetryRequest preserves RFC 7250 certificate type offers" {
    const allocator = std.testing.allocator;
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try client_hello.writeWithKeyShare(&first, allocator, .{
        .random = [_]u8{0x97} ** 32,
        .key_share = .{
            .group = key_exchange.named_group_x25519,
            .key_exchange = &([_]u8{0x98} ** 32),
        },
        .supported_groups = &.{
            key_exchange.named_group_x25519,
            key_exchange.named_group_secp256r1,
        },
        .server_certificate_types = &.{.raw_public_key},
        .client_certificate_types = &.{.raw_public_key},
    });
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try client_hello.writeWithKeyShare(&second, allocator, .{
        .random = [_]u8{0x97} ** 32,
        .key_share = .{
            .group = key_exchange.named_group_secp256r1,
            .key_exchange = &([_]u8{0x04} ++ ([_]u8{0x99} ** 64)),
        },
        .supported_groups = &.{
            key_exchange.named_group_x25519,
            key_exchange.named_group_secp256r1,
        },
        .server_certificate_types = &.{.raw_public_key},
    });
    try std.testing.expectError(
        error.InvalidSecondClientHello,
        client_hello.validateSecondClientHello(
            first.items,
            try client_hello.parse(second.items),
            key_exchange.named_group_secp256r1,
            null,
        ),
    );
}

test "identity set selects SNI wildcard and compatible signature scheme" {
    const allocator = std.testing.allocator;
    const client_public = try key_exchange.publicKey(
        [_]u8{0xa0} ** key_exchange.secret_len,
    );
    var encoded_hello: std.ArrayList(u8) = .empty;
    defer encoded_hello.deinit(allocator);
    try client_hello.write(&encoded_hello, allocator, .{
        .random = [_]u8{0xa1} ** 32,
        .server_name = "api.example.com",
        .x25519_public_key = client_public,
        .server_certificate_types = &.{.raw_public_key},
        .certificate_authorities = &.{"ca-b"},
    });
    var hello = try client_hello.parse(encoded_hello.items);
    const only_ed25519 = [_]u8{
        0,                                             2,
        @truncate(auth.signature_scheme_ed25519 >> 8), @truncate(auth.signature_scheme_ed25519),
    };
    hello.signature_algorithms = &only_ed25519;

    const p256_key = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair
        .generateDeterministic(
        [_]u8{0xa2} **
            std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.seed_length,
    );
    const ed25519_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xa3} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const p256_certificate = p256_key.public_key.toUncompressedSec1();
    const ed25519_public_key = ed25519_key.public_key.toBytes();
    var ed25519_certificate = [_]u8{
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03,
        0x2b, 0x65,
        0x70, 0x03,
        0x21, 0x00,
    } ++ ([_]u8{0} ** 32);
    @memcpy(ed25519_certificate[12..], &ed25519_public_key);
    const identities = IdentitySet{
        .entries = &.{
            .{
                .server_name_pattern = "api.example.com",
                .identity = .{
                    .certificate_chain = &.{&p256_certificate},
                    .signer = .{
                        .ecdsa_p256_sha256 = .{ .key_pair = p256_key },
                    },
                },
            },
            .{
                .server_name_pattern = "*.example.com",
                .identity = .{
                    .certificate_chain = &.{&ed25519_certificate},
                    .signer = .{
                        .ed25519 = .{ .key_pair = ed25519_key },
                    },
                    .certificate_type = .raw_public_key,
                },
            },
        },
    };
    const selected = (try identities.resolver().resolve(hello)) orelse
        return error.ExpectedIdentity;
    try std.testing.expectEqual(
        auth.signature_scheme_ed25519,
        selected.signer.scheme(),
    );
    try std.testing.expect(matchesServerNamePattern(
        "*.example.com",
        "API.example.com",
    ));
    try std.testing.expect(!matchesServerNamePattern(
        "*.example.com",
        "deep.api.example.com",
    ));

    var ca_hello = hello;
    ca_hello.server_certificate_types = &.{};
    const ca_identities = IdentitySet{ .entries = &.{
        .{
            .server_name_pattern = "api.example.com",
            .identity = .{
                .certificate_chain = &.{&ed25519_certificate},
                .signer = .{ .ed25519 = .{ .key_pair = ed25519_key } },
                .certificate_authorities = &.{"ca-a"},
                .ocsp_response = "first",
            },
        },
        .{
            .server_name_pattern = "api.example.com",
            .identity = .{
                .certificate_chain = &.{&ed25519_certificate},
                .signer = .{ .ed25519 = .{ .key_pair = ed25519_key } },
                .certificate_authorities = &.{"ca-b"},
                .ocsp_response = "second",
            },
        },
    } };
    const ca_selected = (try ca_identities.resolver().resolve(ca_hello)) orelse
        return error.ExpectedIdentity;
    try std.testing.expectEqualStrings("second", ca_selected.ocsp_response.?);

    var unknown = hello;
    unknown.server_name = "other.test";
    try std.testing.expectEqual(
        @as(?ResolvedIdentity, null),
        try identities.resolver().resolve(unknown),
    );
}

test "server connection incrementally establishes X25519 TLS" {
    const allocator = std.testing.allocator;
    const client_private = [_]u8{0x11} ** key_exchange.secret_len;
    const client_public = try key_exchange.publicKey(client_private);
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.write(&hello, allocator, .{
        .random = [_]u8{0x12} ** 32,
        .x25519_public_key = client_public,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    var hello_record: [record.header_len + max_client_hello_for_test]u8 =
        undefined;
    hello_record[0] = record.content_type_handshake;
    hello_record[1..3].* = .{ 3, 1 };
    std.mem.writeInt(u16, hello_record[3..5], @intCast(hello.items.len), .big);
    @memcpy(hello_record[record.header_len..][0..hello.items.len], hello.items);
    const hello_record_len = record.header_len + hello.items.len;

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x13} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    var material = key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0x14} ** key_exchange.secret_len,
    };
    var server = ServerConnection(max_client_hello_for_test, 256).init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
        },
        .server_random = [_]u8{0x15} ** 32,
        .key_material = &material,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
    });
    defer server.deinit();
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    var saw_flight = false;
    for (hello_record[0..hello_record_len]) |byte| {
        const received = try server.receive(&.{byte}, &flight);
        if (received.event) |event| switch (event) {
            .server_flight => saw_flight = true,
            else => return error.UnexpectedServerEvent,
        };
    }
    try std.testing.expect(saw_flight);
    try std.testing.expectEqual(Stage.client_finished, server.stage);

    const compatibility_ccs = [_]u8{ 20, 3, 3, 0, 1, 1 };
    const ccs_result = try server.receive(&compatibility_ccs, &flight);
    switch (ccs_result.event.?) {
        .compatibility_change_cipher_spec => {},
        else => return error.UnexpectedServerEvent,
    }

    const pending = &(server.pending orelse unreachable);
    var client_handshake_records = try traffic.State.init(
        pending.suite,
        pending.client_handshake_secret,
    );
    defer client_handshake_records.deinit();
    var verify_data = try key_schedule.computeFinishedFor(
        pending.client_handshake_secret,
        pending.transcript_state.digest(),
    );
    defer verify_data.deinit();
    var finished: [4 + secret.max_len]u8 = undefined;
    finished[0] = server_handshake.handshake_type_finished;
    finished[1] = 0;
    finished[2] = 0;
    finished[3] = @intCast(verify_data.bytes().len);
    @memcpy(finished[4..][0..verify_data.bytes().len], verify_data.bytes());
    var encrypted_finished: [128]u8 = undefined;
    const encrypted_finished_len = try client_handshake_records.seal(
        record.content_type_handshake,
        finished[0 .. 4 + verify_data.bytes().len],
        &encrypted_finished,
    );
    const established_result = try server.receive(
        encrypted_finished[0..encrypted_finished_len],
        &flight,
    );
    var established = established_result.event.?.established;
    defer established.deinit();
    try std.testing.expectEqual(Stage.established, server.stage);

    var client_application = try connection.ApplicationConnection(256).init(
        pending_suite_for_test,
        established.application.traffic.write.traffic_secret,
        established.application.traffic.read.traffic_secret,
    );
    defer client_application.deinit();
    var wire: [128]u8 = undefined;
    const wire_len = try client_application.sealApplicationData(
        "established",
        &wire,
    );
    const application = try established.application.receive(
        wire[0..wire_len],
    );
    try std.testing.expectEqualStrings(
        "established",
        application.event.?.application_data,
    );
}

const max_client_hello_for_test = 4096;
const pending_suite_for_test = cipher_suite.Suite.aes_128_gcm_sha256;

const ReadyTestServer = struct {
    server: ServerConnection(max_client_hello_for_test, 256),
    material: *key_exchange.ServerKeyMaterial,
    certificate: *[std.crypto.sign.Ed25519.PublicKey.encoded_length]u8,
    chain: [][]const u8,

    fn deinit(self: *ReadyTestServer) void {
        const allocator = std.testing.allocator;
        self.server.deinit();
        allocator.free(self.chain);
        allocator.destroy(self.certificate);
        allocator.destroy(self.material);
        self.* = undefined;
    }
};

fn readyTestServer() !ReadyTestServer {
    const allocator = std.testing.allocator;
    const material = try allocator.create(key_exchange.ServerKeyMaterial);
    errdefer allocator.destroy(material);
    material.* = .{ .x25519 = [_]u8{0xb1} ** key_exchange.secret_len };
    const key_pair = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xb2} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = try allocator.create(
        [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8,
    );
    errdefer allocator.destroy(certificate);
    certificate.* = key_pair.public_key.toBytes();
    const chain = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(chain);
    chain[0] = certificate;

    var server = ServerConnection(max_client_hello_for_test, 256).init(.{
        .allocator = allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{key_exchange.named_group_x25519},
        },
        .server_random = [_]u8{0xb3} ** 32,
        .key_material = material,
        .certificate_chain = chain,
        .signer = .{ .ed25519 = .{ .key_pair = key_pair } },
    });
    errdefer server.deinit();

    const client_public = try key_exchange.publicKey(
        [_]u8{0xb4} ** key_exchange.secret_len,
    );
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.write(&hello, allocator, .{
        .random = [_]u8{0xb5} ** 32,
        .x25519_public_key = client_public,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    var hello_record: [record.header_len + max_client_hello_for_test]u8 =
        undefined;
    hello_record[0] = record.content_type_handshake;
    hello_record[1..3].* = .{ 3, 1 };
    std.mem.writeInt(u16, hello_record[3..5], @intCast(hello.items.len), .big);
    @memcpy(hello_record[record.header_len..][0..hello.items.len], hello.items);
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    const received = try server.receive(
        hello_record[0 .. record.header_len + hello.items.len],
        &flight,
    );
    switch (received.event.?) {
        .server_flight => {},
        else => return error.UnexpectedServerEvent,
    }
    return .{
        .server = server,
        .material = material,
        .certificate = certificate,
        .chain = chain,
    };
}

test "server connection rejects duplicate compatibility CCS and locks" {
    var fixture = try readyTestServer();
    defer fixture.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.testing.allocator);
    const ccs = [_]u8{ 20, 3, 3, 0, 1, 1 };
    _ = try fixture.server.receive(&ccs, &output);
    try std.testing.expectError(
        error.DuplicateChangeCipherSpec,
        fixture.server.receive(&ccs, &output),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        fixture.server.receive("", &output),
    );
}

test "server connection rejects application data before Finished" {
    var fixture = try readyTestServer();
    defer fixture.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.testing.allocator);
    const pending = &(fixture.server.pending orelse unreachable);
    var client_records = try traffic.State.init(
        pending.suite,
        pending.client_handshake_secret,
    );
    defer client_records.deinit();
    var wire: [128]u8 = undefined;
    const wire_len = try client_records.seal(
        record.content_type_application_data,
        "too early",
        &wire,
    );
    try std.testing.expectError(
        error.UnexpectedApplicationData,
        fixture.server.receive(wire[0..wire_len], &output),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        fixture.server.receive("", &output),
    );
}

test "server connection rejects malformed Finished and locks" {
    var fixture = try readyTestServer();
    defer fixture.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.testing.allocator);
    const pending = &(fixture.server.pending orelse unreachable);
    var client_records = try traffic.State.init(
        pending.suite,
        pending.client_handshake_secret,
    );
    defer client_records.deinit();
    const malformed = [_]u8{
        server_handshake.handshake_type_finished, 0, 0, 1, 0,
    };
    var wire: [128]u8 = undefined;
    const wire_len = try client_records.seal(
        record.content_type_handshake,
        &malformed,
        &wire,
    );
    try std.testing.expectError(
        error.BadClientFinished,
        fixture.server.receive(wire[0..wire_len], &output),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        fixture.server.receive("", &output),
    );
}

test "server connection rejects messages coalesced after client Finished" {
    var fixture = try readyTestServer();
    defer fixture.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.testing.allocator);
    const pending = &(fixture.server.pending orelse unreachable);
    var client_records = try traffic.State.init(
        pending.suite,
        pending.client_handshake_secret,
    );
    defer client_records.deinit();
    var verify_data = try key_schedule.computeFinishedFor(
        pending.client_handshake_secret,
        pending.transcript_state.digest(),
    );
    defer verify_data.deinit();
    var messages: [4 + secret.max_len + 5]u8 = undefined;
    messages[0] = server_handshake.handshake_type_finished;
    messages[1] = 0;
    messages[2] = 0;
    messages[3] = @intCast(verify_data.bytes().len);
    @memcpy(messages[4..][0..verify_data.bytes().len], verify_data.bytes());
    const trailing_start = 4 + verify_data.bytes().len;
    messages[trailing_start..][0..5].* = .{ 24, 0, 0, 1, 0 };
    var wire: [128]u8 = undefined;
    const wire_len = try client_records.seal(
        record.content_type_handshake,
        messages[0 .. trailing_start + 5],
        &wire,
    );
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        fixture.server.receive(wire[0..wire_len], &output),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        fixture.server.receive("", &output),
    );
}
