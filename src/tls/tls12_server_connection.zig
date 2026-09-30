//! Incremental TLS 1.2 ECDHE server state.
//!
//! The state supports the modern ECDHE-RSA/ECDHE-ECDSA AES-GCM and ChaCha20
//! suites over P-256/P-384, optional or required client authentication, and
//! mandatory RFC 7627 Extended Master Secret by default. No legacy CBC,
//! static RSA key exchange, or renegotiation is accepted.

const std = @import("std");
const alert = @import("alert.zig");
const auth = @import("auth.zig");
const client_auth = @import("client_auth.zig");
const client_hello = @import("client_hello.zig");
const key_exchange = @import("key_exchange.zig");
const key_log = @import("key_log.zig");
const record13 = @import("record.zig");
const stream = @import("stream.zig");
const tls12 = @import("tls12.zig");
const handshake = @import("tls12_handshake.zig");
const ticket_keyring = @import("ticket_keyring.zig");
const tls12_ticket = @import("tls12_ticket.zig");
const transcript = @import("transcript.zig");

pub const Error = std.mem.Allocator.Error || stream.Error ||
    stream.HandshakeError || handshake.Error || key_exchange.Error ||
    tls12.Error || tls12_ticket.Error || ticket_keyring.Error || alert.Error ||
    auth.Error || client_auth.Error || error{
    UnexpectedRecord,
    UnexpectedHandshakeMessage,
    InvalidChangeCipherSpec,
    BadClientFinished,
    AlreadyEstablished,
    ConnectionFailed,
    PeerAbortedHandshake,
    InvalidClientAuthConfiguration,
    InvalidSessionTicketConfiguration,
};

pub const Stage = enum {
    client_hello,
    client_certificate,
    client_key_exchange,
    client_certificate_verify,
    change_cipher_spec,
    client_finished,
    established,
    failed,
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    policy: handshake.Policy = .{},
    server_random: [32]u8,
    /// Single-use P-256 scalar retained for source compatibility. It is
    /// required when the selected group is secp256r1.
    server_private_key: ?*[key_exchange.p256.secret_len]u8 = null,
    /// Single-use P-384 scalar required when secp384r1 is selected.
    server_private_key_p384: ?*[key_exchange.p384.secret_len]u8 = null,
    certificate_chain: []const []const u8,
    signer: auth.Signer,
    client_auth_policy: ?client_auth.ServerPolicy = null,
    resumption: ?Resumption = null,
    /// Stateless RFC 5077 tickets. This is currently mutually exclusive with
    /// TLS 1.2 client authentication, matching the session-ID resume policy.
    session_tickets: ?SessionTicketPolicy = null,
    /// Opt-in NSS-compatible master-secret logging for diagnostics.
    key_log: ?key_log.Logger = null,
};

pub const Resumption = struct {
    session: *const tls12.Session,
    identity: []const u8,
    now_seconds: u64,
};

pub const SessionTicketPolicy = struct {
    keyring: *const ticket_keyring.Keyring,
    /// Authentication context shared by all connections for one server
    /// identity. It is bound into the ticket AEAD associated data.
    server_id: []const u8,
    now_seconds: u64,
    lifetime_seconds: u32,
    /// Must be unique for every ticket encrypted under the current key.
    sealing_nonce: [ticket_keyring.nonce_len]u8,
};

pub const Event = union(enum) {
    server_flight: void,
    client_key_exchange: void,
    change_cipher_spec: void,
    peer_alert: alert.Alert,
    established: Established,
};

pub const ReceiveResult = struct {
    consumed: usize,
    event: ?Event,
};

pub const ApplicationReceiveResult = struct {
    consumed: usize,
    event: ?Established.ApplicationEvent,
};

const PrivateKey = union(enum) {
    none,
    secp256r1: [key_exchange.p256.secret_len]u8,
    secp384r1: [key_exchange.p384.secret_len]u8,

    fn wipe(self: *PrivateKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }
};

const Pending = struct {
    allocator: std.mem.Allocator,
    server_private_key: PrivateKey,
    client_random: [32]u8,
    selection: handshake.Selection,
    transcript_state: transcript.State,
    master_secret: ?[tls12.master_secret_len]u8 = null,
    client_traffic: ?tls12.TrafficState = null,
    server_traffic: ?tls12.TrafficState = null,
    transcript_bytes: std.ArrayList(u8) = .empty,
    peer_certificate_chain: ?[][]const u8 = null,
    resumed: bool = false,
    session_id: [tls12.max_session_id_len]u8 =
        [_]u8{0} ** tls12.max_session_id_len,
    session_id_len: u8 = 0,

    fn deinit(self: *Pending) void {
        self.server_private_key.wipe();
        if (self.master_secret) |*master| {
            std.crypto.secureZero(u8, master);
        }
        if (self.client_traffic) |*traffic| traffic.deinit();
        if (self.server_traffic) |*traffic| traffic.deinit();
        self.transcript_bytes.deinit(self.allocator);
        if (self.peer_certificate_chain) |chain| {
            freeCertificateChain(self.allocator, chain);
        }
        self.* = undefined;
    }
};

pub const Established = struct {
    allocator: std.mem.Allocator,
    read: tls12.TrafficState,
    write: tls12.TrafficState,
    master_secret: [tls12.master_secret_len]u8,
    client_random: [32]u8,
    server_random: [32]u8,
    suite: tls12.Suite,
    peer_certificate_chain: ?[][]const u8,
    resumed: bool,
    session_id: [tls12.max_session_id_len]u8,
    session_id_len: u8,
    alpn_storage: [tls12.max_session_alpn_len]u8,
    alpn_len: u8,
    records: stream.RecordDeframer = .{},
    plaintext: [tls12.max_plaintext_len]u8 = undefined,
    local_closed: bool = false,
    peer_closed: bool = false,
    failed: bool = false,
    secrets_extracted: bool = false,

    pub const ApplicationEvent = union(enum) {
        application_data: []const u8,
        alert: alert.Alert,
    };

    pub fn deinit(self: *Established) void {
        if (!self.secrets_extracted) {
            self.read.deinit();
            self.write.deinit();
        }
        std.crypto.secureZero(u8, &self.master_secret);
        if (self.peer_certificate_chain) |chain| {
            freeCertificateChain(self.allocator, chain);
        }
        self.* = undefined;
    }

    /// Consume the live record layer and return its current transmit and
    /// receive keys. The connection remains safe to `deinit`, but all record
    /// I/O is permanently disabled after this call.
    pub fn dangerousExtractSecrets(
        self: *Established,
    ) Error!tls12.ExtractedSecrets {
        if (self.failed or self.local_closed or self.peer_closed) {
            return error.ConnectionFailed;
        }
        const extracted = try tls12.extractTrafficSecrets(
            &self.read,
            &self.write,
        );
        self.secrets_extracted = true;
        self.failed = true;
        return extracted;
    }

    pub fn sealApplicationData(
        self: *Established,
        plaintext: []const u8,
        output: []u8,
    ) Error!usize {
        if (self.failed or self.local_closed or self.peer_closed) {
            return error.ConnectionFailed;
        }
        return self.write.seal(23, plaintext, output);
    }

    /// Seal one non-empty application-data record with an explicit
    /// plaintext limit and return the consumed/written progress.
    pub fn sealApplicationDataFragment(
        self: *Established,
        plaintext: []const u8,
        max_fragment_plaintext: usize,
        output: []u8,
    ) Error!tls12.SealFragmentResult {
        if (self.failed or self.local_closed or self.peer_closed) {
            return error.ConnectionFailed;
        }
        return self.write.sealFragment(
            23,
            plaintext,
            max_fragment_plaintext,
            output,
        );
    }

    pub fn sealCloseNotify(
        self: *Established,
        output: []u8,
    ) Error!usize {
        if (self.failed or self.local_closed) return error.ConnectionFailed;
        const payload = alert.closeNotify().toBytes();
        const len = try self.write.seal(21, &payload, output);
        self.local_closed = true;
        return len;
    }

    pub fn exportKeyingMaterial(
        self: *const Established,
        label: []const u8,
        context: ?[]const u8,
        output: []u8,
    ) Error!void {
        try tls12.exportKeyingMaterial(
            self.suite,
            &self.master_secret,
            self.client_random,
            self.server_random,
            label,
            context,
            output,
        );
    }

    pub fn createSession(
        self: *const Established,
        identity: []const u8,
        now_seconds: u64,
        lifetime_seconds: u32,
    ) tls12.Error!tls12.Session {
        if (self.session_id_len == 0) return error.InvalidSessionId;
        return tls12.Session.init(
            self.session_id[0..self.session_id_len],
            self.suite,
            self.master_secret,
            identity,
            self.alpn_storage[0..self.alpn_len],
            now_seconds,
            lifetime_seconds,
        );
    }

    pub fn receive(
        self: *Established,
        input: []const u8,
    ) Error!ApplicationReceiveResult {
        if (self.failed) return error.ConnectionFailed;
        return self.receiveInner(input) catch |err| {
            self.failed = true;
            return err;
        };
    }

    fn receiveInner(
        self: *Established,
        input: []const u8,
    ) Error!ApplicationReceiveResult {
        const framed = try self.records.push(input);
        const record = framed.framed orelse return .{
            .consumed = framed.consumed,
            .event = null,
        };
        const opened = try self.read.open(record.bytes, &self.plaintext);
        const payload = self.plaintext[0..opened.len];
        return switch (opened.content_type) {
            23 => .{
                .consumed = framed.consumed,
                .event = .{ .application_data = payload },
            },
            21 => blk: {
                const received = try alert.parse(payload);
                if (received.isCloseNotify()) self.peer_closed = true;
                break :blk .{
                    .consumed = framed.consumed,
                    .event = .{ .alert = received },
                };
            },
            else => error.UnexpectedRecord,
        };
    }
};

pub fn ServerConnection(
    comptime max_client_hello_len: usize,
    comptime max_handshake_message_len: usize,
) type {
    return struct {
        const Self = @This();

        config: Config,
        stage: Stage = .client_hello,
        p256_private_key_consumed: bool = false,
        p384_private_key_consumed: bool = false,
        records: stream.RecordDeframer = .{},
        messages: stream.HandshakeReassembler(
            @max(max_client_hello_len, max_handshake_message_len),
        ) = .{},
        pending: ?Pending = null,

        pub fn init(config: Config) Self {
            return .{ .config = config };
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

        fn receiveInner(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const framed_result = try self.records.push(input);
            const framed = framed_result.framed orelse return .{
                .consumed = framed_result.consumed,
                .event = null,
            };
            return switch (self.stage) {
                .client_hello => self.receiveClientHello(
                    framed_result.consumed,
                    framed,
                    output,
                ),
                .client_certificate => self.receiveClientCertificate(
                    framed_result.consumed,
                    framed,
                ),
                .client_key_exchange => self.receiveClientKeyExchange(
                    framed_result.consumed,
                    framed,
                ),
                .client_certificate_verify => self.receiveClientCertificateVerify(
                    framed_result.consumed,
                    framed,
                ),
                .change_cipher_spec => self.receiveChangeCipherSpec(
                    framed_result.consumed,
                    framed,
                ),
                .client_finished => self.receiveClientFinished(
                    framed_result.consumed,
                    framed,
                    output,
                ),
                .established => error.AlreadyEstablished,
                .failed => error.ConnectionFailed,
            };
        }

        fn receiveClientHello(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            if (framed.content_type != 22) return error.UnexpectedRecord;
            const message_result = try self.messages.push(framed.fragment);
            const message = message_result.message orelse return .{
                .consumed = consumed,
                .event = null,
            };
            if (message_result.consumed != framed.fragment.len or
                message[0] != client_hello.handshake_type_client_hello)
            {
                return error.UnexpectedHandshakeMessage;
            }
            const parsed = try client_hello.parse(message);
            if ((self.config.policy.client_certificate_authorities == null) !=
                (self.config.client_auth_policy == null))
            {
                return error.InvalidClientAuthConfiguration;
            }
            if (self.config.session_tickets != null and
                self.config.client_auth_policy != null)
            {
                return error.InvalidSessionTicketConfiguration;
            }
            if (self.config.session_tickets) |ticket_policy| {
                if (ticket_policy.server_id.len == 0 or
                    ticket_policy.server_id.len > std.math.maxInt(u16) or
                    ticket_policy.lifetime_seconds == 0 or
                    ticket_policy.lifetime_seconds >
                        tls12_ticket.max_lifetime_seconds)
                {
                    return error.InvalidSessionTicketConfiguration;
                }
            }
            var policy = self.config.policy;
            policy.issue_session_ticket = self.config.session_tickets != null;
            if (try self.tryResume(
                consumed,
                message,
                parsed,
                policy,
                output,
            )) |result| return result;
            // A non-empty ticket that cannot be resumed must fall back to a
            // full handshake without echoing the client's signaling ID;
            // otherwise the client could mistake the fallback for resumption.
            if (parsed.session_ticket) |offered_ticket| {
                if (offered_ticket.len != 0) policy.new_session_id = &.{};
            }
            const selection = try handshake.select(
                parsed,
                self.config.signer,
                policy,
            );
            var private_key: PrivateKey = undefined;
            var public_key_storage: [key_exchange.p384.public_len]u8 = undefined;
            const public_key_len: usize = switch (selection.group) {
                key_exchange.named_group_secp256r1 => blk: {
                    const configured = self.config.server_private_key orelse
                        return error.NoSupportedGroup;
                    private_key = .{ .secp256r1 = configured.* };
                    self.consumeP256PrivateKey();
                    const public = try key_exchange.p256.publicKey(
                        private_key.secp256r1,
                    );
                    public_key_storage[0..public.len].* = public;
                    break :blk public.len;
                },
                key_exchange.named_group_secp384r1 => blk: {
                    const configured = self.config.server_private_key_p384 orelse
                        return error.NoSupportedGroup;
                    private_key = .{ .secp384r1 = configured.* };
                    self.consumeP384PrivateKey();
                    const public = try key_exchange.p384.publicKey(
                        private_key.secp384r1,
                    );
                    public_key_storage = public;
                    break :blk public.len;
                },
                else => return error.NoSupportedGroup,
            };
            errdefer private_key.wipe();
            var flight: std.ArrayList(u8) = .empty;
            defer flight.deinit(self.config.allocator);
            const result = try handshake.writeServerFlight(
                &flight,
                self.config.allocator,
                message,
                parsed,
                policy,
                self.config.server_random,
                public_key_storage[0..public_key_len],
                self.config.certificate_chain,
                self.config.signer,
            );
            const output_start = output.items.len;
            errdefer output.items.len = output_start;
            try appendPlaintextRecords(
                output,
                self.config.allocator,
                22,
                flight.items,
            );
            var transcript_bytes: std.ArrayList(u8) = .empty;
            errdefer transcript_bytes.deinit(self.config.allocator);
            try transcript_bytes.appendSlice(self.config.allocator, message);
            try transcript_bytes.appendSlice(
                self.config.allocator,
                flight.items,
            );
            self.pending = .{
                .allocator = self.config.allocator,
                .server_private_key = private_key,
                .client_random = parsed.random.*,
                .selection = result.selection,
                .transcript_state = result.transcript_state,
                .transcript_bytes = transcript_bytes,
                .session_id = copySessionId(policy.new_session_id),
                .session_id_len = @intCast(
                    policy.new_session_id.len,
                ),
            };
            self.messages.reset();
            self.stage = if (self.config.client_auth_policy != null)
                .client_certificate
            else
                .client_key_exchange;
            return .{
                .consumed = consumed,
                .event = .{ .server_flight = {} },
            };
        }

        fn tryResume(
            self: *Self,
            consumed: usize,
            client_hello_bytes: []const u8,
            parsed: client_hello.Parsed,
            policy: handshake.Policy,
            output: *std.ArrayList(u8),
        ) Error!?ReceiveResult {
            if (self.config.client_auth_policy != null) return null;
            var ticket_session: ?tls12.Session = null;
            defer if (ticket_session) |*session| session.deinit();
            const configured = blk: {
                if (parsed.session_ticket) |offered_ticket| {
                    if (offered_ticket.len != 0) {
                        const ticket_policy = self.config.session_tickets orelse
                            return null;
                        const selected_alpn = try handshake.selectAlpn(
                            parsed.alpn_protocols,
                            policy.alpn_protocols,
                        );
                        var opened = ticket_policy.keyring.openTls12(
                            offered_ticket,
                            ticket_policy.server_id,
                            selected_alpn orelse "",
                            ticket_policy.now_seconds,
                        ) catch return null;
                        defer opened.deinit();
                        if (!opened.extended_master_secret or
                            parsed.session_id.len == 0)
                        {
                            return null;
                        }
                        ticket_session = tls12.Session.init(
                            parsed.session_id,
                            opened.suite,
                            opened.master_secret,
                            ticket_policy.server_id,
                            selected_alpn orelse "",
                            opened.issued_at_seconds,
                            opened.lifetime_seconds,
                        ) catch return null;
                        break :blk Resumption{
                            .session = &ticket_session.?,
                            .identity = ticket_policy.server_id,
                            .now_seconds = ticket_policy.now_seconds,
                        };
                    }
                }
                break :blk self.config.resumption orelse return null;
            };
            if (!std.mem.eql(u8, parsed.session_id, configured.session.id())) {
                return null;
            }
            configured.session.validate(
                configured.now_seconds,
                configured.identity,
            ) catch return null;
            var server_hello: std.ArrayList(u8) = .empty;
            defer server_hello.deinit(self.config.allocator);
            const selection = handshake.writeResumedServerHello(
                &server_hello,
                self.config.allocator,
                parsed,
                policy,
                self.config.server_random,
                configured.session,
            ) catch return null;
            var state = transcript.State.init(selection.suite.transcriptHash());
            state.update(client_hello_bytes);
            state.update(server_hello.items);
            var keys = try tls12.deriveKeyPair(
                selection.suite,
                &configured.session.master_secret,
                parsed.random.*,
                self.config.server_random,
            );
            errdefer keys.deinit();
            var server_traffic = tls12.TrafficState.init(keys.server);
            errdefer server_traffic.deinit();
            var client_traffic = tls12.TrafficState.init(keys.client);
            errdefer client_traffic.deinit();
            var new_session_ticket: std.ArrayList(u8) = .empty;
            defer new_session_ticket.deinit(self.config.allocator);
            if (selection.session_ticket_acknowledged) {
                try self.writeNewSessionTicket(
                    &new_session_ticket,
                    &configured.session.master_secret,
                    selection,
                );
                state.update(new_session_ticket.items);
            }
            const server_verify = try tls12.finishedVerifyData(
                selection.suite,
                &configured.session.master_secret,
                .server,
                state.digest().bytes(),
            );
            var server_finished: [4 + tls12.finished_verify_data_len]u8 =
                undefined;
            handshake.writeFinished(&server_finished, server_verify);
            var encrypted_finished: [64]u8 = undefined;
            const encrypted_len = try server_traffic.seal(
                22,
                &server_finished,
                &encrypted_finished,
            );
            state.update(&server_finished);
            var transcript_bytes: std.ArrayList(u8) = .empty;
            errdefer transcript_bytes.deinit(self.config.allocator);
            try transcript_bytes.appendSlice(
                self.config.allocator,
                client_hello_bytes,
            );
            try transcript_bytes.appendSlice(
                self.config.allocator,
                server_hello.items,
            );
            try transcript_bytes.appendSlice(
                self.config.allocator,
                new_session_ticket.items,
            );
            try transcript_bytes.appendSlice(
                self.config.allocator,
                &server_finished,
            );

            const output_start = output.items.len;
            errdefer output.items.len = output_start;
            try appendPlaintextRecord(
                output,
                self.config.allocator,
                22,
                server_hello.items,
            );
            if (new_session_ticket.items.len != 0) {
                try appendPlaintextRecord(
                    output,
                    self.config.allocator,
                    22,
                    new_session_ticket.items,
                );
            }
            try appendPlaintextRecord(
                output,
                self.config.allocator,
                stream.content_type_change_cipher_spec,
                &.{1},
            );
            try output.appendSlice(
                self.config.allocator,
                encrypted_finished[0..encrypted_len],
            );
            self.consumeP256PrivateKey();
            self.consumeP384PrivateKey();
            self.pending = .{
                .allocator = self.config.allocator,
                .server_private_key = .none,
                .client_random = parsed.random.*,
                .selection = selection,
                .transcript_state = state,
                .master_secret = configured.session.master_secret,
                .client_traffic = client_traffic,
                .server_traffic = server_traffic,
                .transcript_bytes = transcript_bytes,
                .resumed = true,
                .session_id = copySessionId(configured.session.id()),
                .session_id_len = @intCast(configured.session.id().len),
            };
            self.messages.reset();
            self.stage = .change_cipher_spec;
            return .{
                .consumed = consumed,
                .event = .{ .server_flight = {} },
            };
        }

        fn receiveClientCertificate(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
        ) Error!ReceiveResult {
            if (framed.content_type != 22) return error.UnexpectedRecord;
            const message_result = try self.messages.push(framed.fragment);
            const message = message_result.message orelse return .{
                .consumed = consumed,
                .event = null,
            };
            if (message_result.consumed != framed.fragment.len) {
                return error.UnexpectedHandshakeMessage;
            }
            var certificate = try handshake.parseClientCertificate(
                self.config.allocator,
                message,
            );
            defer certificate.deinit(self.config.allocator);
            const policy = self.config.client_auth_policy orelse unreachable;
            if (certificate.entries.len == 0) {
                if (policy.requirement == .required) {
                    return error.ClientCertificateRequired;
                }
            } else {
                try policy.verifier.verifyTrust(null, certificate.entries);
                const pending = &(self.pending orelse unreachable);
                pending.peer_certificate_chain = try copyCertificateChain(
                    self.config.allocator,
                    certificate.entries,
                );
            }
            const pending = &(self.pending orelse unreachable);
            pending.transcript_state.update(message);
            try pending.transcript_bytes.appendSlice(
                self.config.allocator,
                message,
            );
            self.messages.reset();
            self.stage = .client_key_exchange;
            return .{ .consumed = consumed, .event = null };
        }

        fn receiveClientKeyExchange(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
        ) Error!ReceiveResult {
            if (framed.content_type != 22) return error.UnexpectedRecord;
            const message_result = try self.messages.push(framed.fragment);
            const message = message_result.message orelse return .{
                .consumed = consumed,
                .event = null,
            };
            if (message_result.consumed != framed.fragment.len) {
                return error.UnexpectedHandshakeMessage;
            }
            const client_public = try handshake.parseClientKeyExchange(message);
            const pending = &(self.pending orelse unreachable);
            var shared_storage = [_]u8{0} ** key_exchange.p384.shared_len;
            const shared_secret: []u8 = switch (pending.selection.group) {
                key_exchange.named_group_secp256r1 => blk: {
                    if (pending.server_private_key != .secp256r1) {
                        return error.NoSupportedGroup;
                    }
                    const shared = try key_exchange.p256.sharedSecret(
                        pending.server_private_key.secp256r1,
                        client_public,
                    );
                    shared_storage[0..shared.len].* = shared;
                    break :blk shared_storage[0..shared.len];
                },
                key_exchange.named_group_secp384r1 => blk: {
                    if (pending.server_private_key != .secp384r1) {
                        return error.NoSupportedGroup;
                    }
                    const shared = try key_exchange.p384.sharedSecret(
                        pending.server_private_key.secp384r1,
                        client_public,
                    );
                    shared_storage = shared;
                    break :blk &shared_storage;
                },
                else => return error.NoSupportedGroup,
            };
            defer std.crypto.secureZero(u8, &shared_storage);
            pending.server_private_key.wipe();
            pending.transcript_state.update(message);
            try pending.transcript_bytes.appendSlice(
                self.config.allocator,
                message,
            );
            var master_secret = if (pending.selection.extended_master_secret)
                try tls12.deriveExtendedMasterSecret(
                    pending.selection.suite,
                    shared_secret,
                    pending.transcript_state.digest().bytes(),
                )
            else blk: {
                break :blk tls12.deriveMasterSecret(
                    pending.selection.suite,
                    shared_secret,
                    pending.client_random,
                    self.config.server_random,
                );
            };
            errdefer std.crypto.secureZero(u8, &master_secret);
            var keys = try tls12.deriveKeyPair(
                pending.selection.suite,
                &master_secret,
                pending.client_random,
                self.config.server_random,
            );
            errdefer keys.deinit();
            pending.master_secret = master_secret;
            pending.client_traffic = tls12.TrafficState.init(keys.client);
            pending.server_traffic = tls12.TrafficState.init(keys.server);
            self.messages.reset();
            self.stage = if (pending.peer_certificate_chain != null)
                .client_certificate_verify
            else
                .change_cipher_spec;
            return .{
                .consumed = consumed,
                .event = .{ .client_key_exchange = {} },
            };
        }

        fn receiveClientCertificateVerify(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
        ) Error!ReceiveResult {
            if (framed.content_type != 22) return error.UnexpectedRecord;
            const message_result = try self.messages.push(framed.fragment);
            const message = message_result.message orelse return .{
                .consumed = consumed,
                .event = null,
            };
            if (message_result.consumed != framed.fragment.len) {
                return error.UnexpectedHandshakeMessage;
            }
            const pending = &(self.pending orelse unreachable);
            const chain = pending.peer_certificate_chain orelse
                return error.UnexpectedHandshakeMessage;
            try handshake.verifyCertificateVerify(
                chain[0],
                message,
                pending.transcript_bytes.items,
            );
            pending.transcript_state.update(message);
            try pending.transcript_bytes.appendSlice(
                self.config.allocator,
                message,
            );
            self.messages.reset();
            self.stage = .change_cipher_spec;
            return .{ .consumed = consumed, .event = null };
        }

        fn receiveChangeCipherSpec(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
        ) Error!ReceiveResult {
            if (framed.content_type != stream.content_type_change_cipher_spec or
                !std.mem.eql(u8, framed.fragment, &.{1}))
            {
                return error.InvalidChangeCipherSpec;
            }
            self.stage = .client_finished;
            return .{
                .consumed = consumed,
                .event = .{ .change_cipher_spec = {} },
            };
        }

        fn receiveClientFinished(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const pending = &(self.pending orelse unreachable);
            var plaintext: [64]u8 = undefined;
            const opened = try pending.client_traffic.?.open(
                framed.bytes,
                &plaintext,
            );
            if (opened.content_type != 22) return error.UnexpectedRecord;
            const finished_message = plaintext[0..opened.len];
            const received_verify = try handshake.parseFinished(
                finished_message,
            );
            const expected_verify = try tls12.finishedVerifyData(
                pending.selection.suite,
                &(pending.master_secret orelse unreachable),
                .client,
                pending.transcript_state.digest().bytes(),
            );
            if (!std.crypto.timing_safe.eql(
                [tls12.finished_verify_data_len]u8,
                received_verify,
                expected_verify,
            )) return error.BadClientFinished;
            pending.transcript_state.update(finished_message);

            if (pending.resumed) {
                return .{
                    .consumed = consumed,
                    .event = .{ .established = self.establish() },
                };
            }

            var new_session_ticket: std.ArrayList(u8) = .empty;
            defer new_session_ticket.deinit(self.config.allocator);
            if (pending.selection.session_ticket_acknowledged) {
                try self.writeNewSessionTicket(
                    &new_session_ticket,
                    &pending.master_secret.?,
                    pending.selection,
                );
                pending.transcript_state.update(new_session_ticket.items);
            }

            const server_verify = try tls12.finishedVerifyData(
                pending.selection.suite,
                &(pending.master_secret orelse unreachable),
                .server,
                pending.transcript_state.digest().bytes(),
            );
            var server_finished: [4 + tls12.finished_verify_data_len]u8 =
                undefined;
            handshake.writeFinished(&server_finished, server_verify);
            var encrypted_finished: [64]u8 = undefined;
            const encrypted_len = try pending.server_traffic.?.seal(
                22,
                &server_finished,
                &encrypted_finished,
            );
            const output_start = output.items.len;
            errdefer output.items.len = output_start;
            if (new_session_ticket.items.len != 0) {
                try appendPlaintextRecord(
                    output,
                    self.config.allocator,
                    22,
                    new_session_ticket.items,
                );
            }
            try appendPlaintextRecord(
                output,
                self.config.allocator,
                stream.content_type_change_cipher_spec,
                &.{1},
            );
            try output.appendSlice(
                self.config.allocator,
                encrypted_finished[0..encrypted_len],
            );
            return .{
                .consumed = consumed,
                .event = .{ .established = self.establish() },
            };
        }

        fn writeNewSessionTicket(
            self: *const Self,
            output: *std.ArrayList(u8),
            master_secret: *const [tls12.master_secret_len]u8,
            selection: handshake.Selection,
        ) Error!void {
            const policy = self.config.session_tickets orelse
                return error.InvalidSessionTicketConfiguration;
            const ticket_bytes = try policy.keyring.sealTls12(
                policy.sealing_nonce,
                policy.server_id,
                selection.alpn_protocol orelse "",
                .{
                    .master_secret = master_secret,
                    .suite = selection.suite,
                    .issued_at_seconds = policy.now_seconds,
                    .lifetime_seconds = policy.lifetime_seconds,
                    .extended_master_secret = selection.extended_master_secret,
                },
            );
            try tls12_ticket.write(
                output,
                self.config.allocator,
                policy.lifetime_seconds,
                &ticket_bytes,
            );
        }

        fn establish(self: *Self) Established {
            const pending = &(self.pending orelse unreachable);
            const selected_alpn: []const u8 =
                pending.selection.alpn_protocol orelse "";
            key_log.emit(
                self.config.key_log,
                key_log.client_random,
                &pending.client_random,
                &pending.master_secret.?,
            );
            const established = Established{
                .allocator = self.config.allocator,
                .read = pending.client_traffic.?,
                .write = pending.server_traffic.?,
                .master_secret = pending.master_secret.?,
                .client_random = pending.client_random,
                .server_random = self.config.server_random,
                .suite = pending.selection.suite,
                .peer_certificate_chain = pending.peer_certificate_chain,
                .resumed = pending.resumed,
                .session_id = pending.session_id,
                .session_id_len = pending.session_id_len,
                .alpn_storage = copyAlpn(selected_alpn),
                .alpn_len = @intCast(selected_alpn.len),
            };
            pending.client_traffic = null;
            pending.server_traffic = null;
            pending.master_secret = null;
            pending.peer_certificate_chain = null;
            pending.deinit();
            self.pending = null;
            self.stage = .established;
            return established;
        }

        fn consumeP256PrivateKey(self: *Self) void {
            if (self.p256_private_key_consumed) return;
            if (self.config.server_private_key) |private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            self.p256_private_key_consumed = true;
        }

        fn consumeP384PrivateKey(self: *Self) void {
            if (self.p384_private_key_consumed) return;
            if (self.config.server_private_key_p384) |private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            self.p384_private_key_consumed = true;
        }

        fn fail(self: *Self) void {
            self.cleanup();
            self.stage = .failed;
        }

        fn cleanup(self: *Self) void {
            if (self.pending) |*pending| pending.deinit();
            self.pending = null;
            if (!self.p256_private_key_consumed) self.consumeP256PrivateKey();
            if (!self.p384_private_key_consumed) self.consumeP384PrivateKey();
        }
    };
}

fn appendPlaintextRecords(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    content_type: u8,
    payload: []const u8,
) std.mem.Allocator.Error!void {
    var offset: usize = 0;
    while (offset < payload.len) {
        const len = @min(record13.max_plaintext_len, payload.len - offset);
        try appendPlaintextRecord(
            output,
            allocator,
            content_type,
            payload[offset..][0..len],
        );
        offset += len;
    }
}

fn appendPlaintextRecord(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    content_type: u8,
    payload: []const u8,
) std.mem.Allocator.Error!void {
    try output.appendSlice(allocator, &.{
        content_type,
        3,
        3,
        @truncate(payload.len >> 8),
        @truncate(payload.len),
    });
    try output.appendSlice(allocator, payload);
}

fn copyCertificateChain(
    allocator: std.mem.Allocator,
    certificates: []const []const u8,
) std.mem.Allocator.Error![][]const u8 {
    const copies = try allocator.alloc([]const u8, certificates.len);
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

fn freeCertificateChain(
    allocator: std.mem.Allocator,
    certificates: [][]const u8,
) void {
    for (certificates) |certificate| allocator.free(certificate);
    allocator.free(certificates);
}

fn copySessionId(id: []const u8) [tls12.max_session_id_len]u8 {
    var result = [_]u8{0} ** tls12.max_session_id_len;
    @memcpy(result[0..id.len], id);
    return result;
}

fn copyAlpn(alpn: []const u8) [tls12.max_session_alpn_len]u8 {
    var result = [_]u8{0} ** tls12.max_session_alpn_len;
    @memcpy(result[0..alpn.len], alpn);
    return result;
}

test "TLS 1.2 server requires EMS and locks after rejection" {
    const allocator = std.testing.allocator;
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.writeWithKeyShare(&hello, allocator, .{
        .random = [_]u8{0x51} ** 32,
        .key_share = .{
            .group = key_exchange.named_group_x25519,
            .key_exchange = &([_]u8{0x52} ** 32),
        },
        .supported_groups = &.{
            key_exchange.named_group_x25519,
            key_exchange.named_group_secp256r1,
        },
        .additional_cipher_suites = &.{
            @intFromEnum(tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256),
        },
        .supported_versions = &.{0x0303},
    });
    var hello_record: std.ArrayList(u8) = .empty;
    defer hello_record.deinit(allocator);
    try appendPlaintextRecord(&hello_record, allocator, 22, hello.items);

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x53} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    var server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    server_private[server_private.len - 1] = 4;
    var server = ServerConnection(4096, 4096).init(.{
        .allocator = allocator,
        .server_random = [_]u8{0x54} ** 32,
        .server_private_key = &server_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
    });
    defer server.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try std.testing.expectError(
        error.MissingExtendedMasterSecret,
        server.receive(hello_record.items, &output),
    );
    try std.testing.expectEqual(Stage.failed, server.stage);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** key_exchange.p256.secret_len),
        &server_private,
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        server.receive(&.{}, &output),
    );
}

test "TLS 1.2 server rejects a bad encrypted client Finished and locks" {
    const allocator = std.testing.allocator;
    const suite = tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256;
    const master_secret = [_]u8{0x61} ** tls12.master_secret_len;
    const client_random = [_]u8{0x62} ** 32;
    const server_random = [_]u8{0x63} ** 32;
    var key_pair = try tls12.deriveKeyPair(
        suite,
        &master_secret,
        client_random,
        server_random,
    );
    defer key_pair.deinit();
    var client_sender = tls12.TrafficState.init(try tls12.Keys.init(
        suite,
        key_pair.client.key[0..suite.keyLength()],
        key_pair.client.fixed_iv[0..suite.fixedIvLength()],
    ));
    defer client_sender.deinit();
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x64} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    var unused_private = [_]u8{0} ** key_exchange.p256.secret_len;
    unused_private[unused_private.len - 1] = 1;
    var server = ServerConnection(4096, 4096).init(.{
        .allocator = allocator,
        .server_random = server_random,
        .server_private_key = &unused_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
    });
    defer server.deinit();
    var state = transcript.State.init(.sha256);
    state.update("authenticated transcript");
    server.pending = .{
        .allocator = allocator,
        .server_private_key = .{
            .secp256r1 = [_]u8{0} ** key_exchange.p256.secret_len,
        },
        .client_random = client_random,
        .selection = .{
            .suite = suite,
            .group = key_exchange.named_group_secp256r1,
            .alpn_protocol = null,
            .extended_master_secret = true,
        },
        .transcript_state = state,
        .master_secret = master_secret,
        .client_traffic = tls12.TrafficState.init(key_pair.client),
        .server_traffic = tls12.TrafficState.init(key_pair.server),
    };
    server.stage = .client_finished;

    var bad_finished: [4 + tls12.finished_verify_data_len]u8 = undefined;
    handshake.writeFinished(
        &bad_finished,
        [_]u8{0x65} ** tls12.finished_verify_data_len,
    );
    var encrypted: [128]u8 = undefined;
    const encrypted_len = try client_sender.seal(22, &bad_finished, &encrypted);
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try std.testing.expectError(
        error.BadClientFinished,
        server.receive(encrypted[0..encrypted_len], &output),
    );
    try std.testing.expectEqual(Stage.failed, server.stage);
    try std.testing.expectEqual(@as(usize, 0), output.items.len);
    try std.testing.expectError(
        error.ConnectionFailed,
        server.receive(&.{}, &output),
    );
}
