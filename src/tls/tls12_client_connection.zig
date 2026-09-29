//! Incremental TLS 1.2 ECDHE client state.
//!
//! The first integrated profile is deliberately narrow and modern:
//! The state supports the modern ECDHE-RSA/ECDHE-ECDSA AES-GCM and ChaCha20
//! suites over P-256/P-384, mandatory Extended Master Secret and secure
//! renegotiation signaling, and optional client identity responses. It owns
//! transcript ordering, authenticates the server certificate and ephemeral
//! share, and changes traffic keys only across the two CCS boundaries.

const std = @import("std");
const alert = @import("alert.zig");
const auth = @import("auth.zig");
const certificate_compression = @import("certificate_compression.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_auth = @import("client_auth.zig");
const client_hello = @import("client_hello.zig");
const key_exchange = @import("key_exchange.zig");
const record13 = @import("record.zig");
const stream = @import("stream.zig");
const tls12 = @import("tls12.zig");
const tls12_ticket = @import("tls12_ticket.zig");
const handshake = @import("tls12_handshake.zig");
const transcript = @import("transcript.zig");

pub const Error = std.mem.Allocator.Error || stream.Error ||
    stream.HandshakeError || client_hello.Error || handshake.Error ||
    key_exchange.Error || tls12.Error || auth.Error || client_auth.Error ||
    tls12_ticket.Error || alert.Error || error{
    ClientHelloTooLarge,
    ServerFlightTooLarge,
    UnsupportedProfile,
    DowngradeDetected,
    UnexpectedRecord,
    UnexpectedHandshakeMessage,
    InvalidChangeCipherSpec,
    BadServerFinished,
    AlreadyEstablished,
    ConnectionFailed,
    PeerAbortedHandshake,
};

pub const Stage = enum {
    server_flight,
    server_change_cipher_spec,
    server_finished,
    established,
    failed,
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    random: [32]u8,
    session_id: []const u8 = &.{},
    server_name: ?[]const u8 = null,
    client_private_key: ?*[key_exchange.p256.secret_len]u8 = null,
    client_private_key_p384: ?*[key_exchange.p384.secret_len]u8 = null,
    policy: handshake.Policy = .{},
    tls13_cipher_suites: []const cipher_suite.Suite = &.{},
    client_hello_key_share: ?client_hello.OfferedKeyShare = null,
    client_hello_supported_groups: []const u16 = &.{},
    supported_versions: []const u16 = &.{0x0303},
    signature_schemes: []const u16 = &client_hello.default_signature_schemes,
    request_ocsp: bool = false,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{},
    server_verifier: auth.ClientVerifier,
    client_identity: ?client_auth.ClientIdentity = null,
    resumption: ?tls12.Session = null,
    /// Request a new RFC 5077 ticket during a full or session-ID handshake.
    request_session_ticket: bool = false,
    /// Borrowed cached ticket; `init` deep-copies it before returning.
    ticket_resumption: ?*const tls12_ticket.Cached = null,
    now_seconds: u64 = 0,
};

pub const Event = union(enum) {
    client_flight: void,
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

const Pending = struct {
    allocator: std.mem.Allocator,
    client_private_key: ?[key_exchange.p256.secret_len]u8,
    client_private_key_p384: ?[key_exchange.p384.secret_len]u8,
    client_random: [32]u8,
    client_hello: []u8,
    server_flight: std.ArrayList(u8) = .empty,
    message_count: usize = 0,
    saw_certificate_status: bool = false,
    suite: ?tls12.Suite = null,
    server_random: ?[32]u8 = null,
    transcript_state: ?transcript.State = null,
    master_secret: ?[tls12.master_secret_len]u8 = null,
    client_traffic: ?tls12.TrafficState = null,
    server_traffic: ?tls12.TrafficState = null,
    peer_certificate_chain: ?[][]const u8 = null,
    selected_alpn: ?[]u8 = null,
    negotiated_session_id: [tls12.max_session_id_len]u8 =
        [_]u8{0} ** tls12.max_session_id_len,
    negotiated_session_id_len: u8 = 0,
    resumption: ?tls12.Session = null,
    ticket_resumption: ?tls12_ticket.Cached = null,
    expect_new_session_ticket: bool = false,
    received_new_session_ticket: bool = false,
    new_session_ticket: ?[]u8 = null,
    new_session_ticket_lifetime_hint_seconds: u32 = 0,
    resumed: bool = false,

    fn deinit(self: *Pending) void {
        if (self.client_private_key) |*private_key| {
            std.crypto.secureZero(u8, private_key);
        }
        if (self.client_private_key_p384) |*private_key| {
            std.crypto.secureZero(u8, private_key);
        }
        std.crypto.secureZero(u8, self.client_hello);
        self.allocator.free(self.client_hello);
        self.server_flight.deinit(self.allocator);
        if (self.master_secret) |*master| {
            std.crypto.secureZero(u8, master);
        }
        if (self.client_traffic) |*traffic| traffic.deinit();
        if (self.server_traffic) |*traffic| traffic.deinit();
        if (self.peer_certificate_chain) |chain| {
            freeCertificateChain(self.allocator, chain);
        }
        if (self.selected_alpn) |protocol| self.allocator.free(protocol);
        if (self.resumption) |*session| session.deinit();
        if (self.ticket_resumption) |*cached| cached.deinit();
        if (self.new_session_ticket) |ticket| {
            std.crypto.secureZero(u8, ticket);
            self.allocator.free(ticket);
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
    selected_alpn: ?[]u8,
    peer_certificate_chain: [][]const u8,
    resumed: bool,
    session_id: [tls12.max_session_id_len]u8,
    session_id_len: u8,
    /// Most recently authenticated RFC 5077 ticket, or the prior ticket when
    /// a resumed server elects not to renew it.
    session_ticket: ?[]u8 = null,
    session_ticket_lifetime_hint_seconds: u32 = 0,
    records: stream.RecordDeframer = .{},
    plaintext: [tls12.max_plaintext_len]u8 = undefined,
    local_closed: bool = false,
    peer_closed: bool = false,
    failed: bool = false,

    pub const ApplicationEvent = union(enum) {
        application_data: []const u8,
        alert: alert.Alert,
    };

    pub fn deinit(self: *Established) void {
        self.read.deinit();
        self.write.deinit();
        std.crypto.secureZero(u8, &self.master_secret);
        for (self.peer_certificate_chain) |certificate| {
            self.allocator.free(certificate);
        }
        self.allocator.free(self.peer_certificate_chain);
        if (self.selected_alpn) |protocol| self.allocator.free(protocol);
        if (self.session_ticket) |ticket| {
            std.crypto.secureZero(u8, ticket);
            self.allocator.free(ticket);
        }
        self.* = undefined;
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
            self.selected_alpn orelse "",
            now_seconds,
            lifetime_seconds,
        );
    }

    pub fn createTicketSession(
        self: *const Established,
        identity: []const u8,
        now_seconds: u64,
    ) tls12_ticket.Error!tls12_ticket.Cached {
        const ticket_bytes = self.session_ticket orelse
            return error.InvalidTicket;
        return tls12_ticket.Cached.init(
            self.allocator,
            ticket_bytes,
            self.session_id[0..self.session_id_len],
            self.suite,
            self.master_secret,
            identity,
            self.selected_alpn orelse "",
            now_seconds,
            self.session_ticket_lifetime_hint_seconds,
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
                if (received.terminatesConnection()) self.peer_closed = true;
                break :blk .{
                    .consumed = framed.consumed,
                    .event = .{ .alert = received },
                };
            },
            else => error.UnexpectedRecord,
        };
    }
};

pub fn ClientConnection(
    comptime max_server_flight_len: usize,
    comptime max_handshake_message_len: usize,
) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        policy: handshake.Policy,
        server_name: ?[]const u8,
        server_verifier: auth.ClientVerifier,
        client_identity: ?client_auth.ClientIdentity,
        now_seconds: u64 = 0,
        stage: Stage = .server_flight,
        records: stream.RecordDeframer = .{},
        messages: stream.HandshakeReassembler(max_handshake_message_len) = .{},
        pending: ?Pending,

        /// Consume and wipe `config.client_private_key`, append a TLS 1.2-only
        /// ClientHello record, and retain the one-shot P-256 state.
        pub fn init(
            config: Config,
            output: *std.ArrayList(u8),
        ) Error!Self {
            try validatePolicy(config.policy);
            if (config.resumption != null and config.ticket_resumption != null) {
                return error.UnsupportedProfile;
            }
            var resumption = config.resumption;
            errdefer if (resumption) |*session| session.deinit();
            if (resumption) |*session| {
                if (config.session_id.len != 0 or config.server_name == null) {
                    return error.SessionContextMismatch;
                }
                try session.validate(config.now_seconds, config.server_name.?);
                if (!containsSuite(config.policy.cipher_suites, session.suite) or
                    !containsAlpn(config.policy.alpn_protocols, session.alpn()))
                {
                    return error.SessionContextMismatch;
                }
            }
            var ticket_resumption = if (config.ticket_resumption) |cached|
                try cached.clone(config.allocator)
            else
                null;
            errdefer if (ticket_resumption) |*cached| cached.deinit();
            if (ticket_resumption) |*cached| {
                if (config.session_id.len != 0 or config.server_name == null) {
                    return error.SessionContextMismatch;
                }
                try cached.validate(config.now_seconds, config.server_name.?);
                if (!containsSuite(
                    config.policy.cipher_suites,
                    cached.session.suite,
                ) or !containsAlpn(
                    config.policy.alpn_protocols,
                    cached.alpn(),
                )) {
                    return error.SessionContextMismatch;
                }
            }
            var private_key: ?[key_exchange.p256.secret_len]u8 = if (config.client_private_key) |value|
                value.*
            else
                null;
            if (config.client_private_key) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key) |*value| std.crypto.secureZero(u8, value);
            var private_key_p384: ?[key_exchange.p384.secret_len]u8 = if (config.client_private_key_p384) |value|
                value.*
            else
                null;
            if (config.client_private_key_p384) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key_p384) |*value| {
                std.crypto.secureZero(u8, value);
            };
            for (config.policy.groups) |group| switch (group) {
                key_exchange.named_group_secp256r1 => if (private_key == null) {
                    return error.UnsupportedProfile;
                },
                key_exchange.named_group_secp384r1 => if (private_key_p384 == null) {
                    return error.UnsupportedProfile;
                },
                else => return error.UnsupportedProfile,
            };

            var suites: std.ArrayList(u16) = .empty;
            defer suites.deinit(config.allocator);
            for (config.policy.cipher_suites) |suite| {
                try suites.append(config.allocator, @intFromEnum(suite));
            }
            // RFC 5746 signaling cipher suite value. The server must answer
            // with an empty renegotiation_info extension.
            try suites.append(config.allocator, 0x00ff);

            const ticket_session_id = deriveTicketSessionId(config.random);
            var hello: std.ArrayList(u8) = .empty;
            defer hello.deinit(config.allocator);
            try client_hello.writeWithKeyShare(&hello, config.allocator, .{
                .random = config.random,
                .session_id = if (ticket_resumption != null)
                    &ticket_session_id
                else if (resumption) |*session|
                    session.id()
                else
                    config.session_id,
                .server_name = config.server_name,
                .key_share = config.client_hello_key_share,
                .supported_groups = if (config.client_hello_supported_groups.len != 0)
                    config.client_hello_supported_groups
                else
                    config.policy.groups,
                .cipher_suites = config.tls13_cipher_suites,
                .additional_cipher_suites = suites.items,
                .supported_versions = config.supported_versions,
                .signature_schemes = config.signature_schemes,
                .alpn_protocols = config.policy.alpn_protocols,
                .request_ocsp = config.request_ocsp,
                .offer_extended_master_secret = true,
                .certificate_compression_algorithms = config.certificate_compression_algorithms,
                .session_ticket = if (ticket_resumption) |*cached|
                    cached.ticket()
                else if (config.request_session_ticket)
                    &.{}
                else
                    null,
            });
            if (hello.items.len > record13.max_plaintext_len) {
                return error.ClientHelloTooLarge;
            }
            const owned_hello = try config.allocator.dupe(u8, hello.items);
            errdefer {
                std.crypto.secureZero(u8, owned_hello);
                config.allocator.free(owned_hello);
            }
            const output_start = output.items.len;
            errdefer output.shrinkRetainingCapacity(output_start);
            try appendPlaintextRecord(
                output,
                config.allocator,
                22,
                0x0301,
                hello.items,
            );
            return .{
                .allocator = config.allocator,
                .policy = config.policy,
                .server_name = config.server_name,
                .server_verifier = config.server_verifier,
                .client_identity = config.client_identity,
                .now_seconds = config.now_seconds,
                .pending = .{
                    .allocator = config.allocator,
                    .client_private_key = private_key,
                    .client_private_key_p384 = private_key_p384,
                    .client_random = config.random,
                    .client_hello = owned_hello,
                    .resumption = resumption,
                    .ticket_resumption = ticket_resumption,
                },
            };
        }

        /// Initialize from an already-emitted ClientHello. This is used by the
        /// version-negotiating client so TLS 1.2 and TLS 1.3 share one exact
        /// offer and transcript rather than racing two independently encoded
        /// hellos.
        pub fn initWithClientHello(
            config: Config,
            encoded_client_hello: []const u8,
        ) Error!Self {
            try validatePolicy(config.policy);
            if (config.resumption != null and config.ticket_resumption != null) {
                return error.UnsupportedProfile;
            }
            const parsed = try client_hello.parse(encoded_client_hello);
            if (!std.mem.eql(u8, parsed.random, &config.random) or
                !parsed.supportsVersion(0x0303) or
                !parsed.offers_extended_master_secret or
                !parsed.offers_secure_renegotiation)
            {
                return error.UnsupportedProfile;
            }
            var has_suite = false;
            for (config.policy.cipher_suites) |suite| {
                if (parsed.hasCipherSuite(@intFromEnum(suite))) {
                    has_suite = true;
                    break;
                }
            }
            if (!has_suite) return error.UnsupportedProfile;

            var resumption = config.resumption;
            errdefer if (resumption) |*session| session.deinit();
            if (resumption) |*session| {
                if (config.server_name == null or
                    !std.mem.eql(u8, parsed.session_id, session.id()))
                {
                    return error.SessionContextMismatch;
                }
                try session.validate(config.now_seconds, config.server_name.?);
                if (!containsSuite(config.policy.cipher_suites, session.suite) or
                    !containsAlpn(config.policy.alpn_protocols, session.alpn()))
                {
                    return error.SessionContextMismatch;
                }
            }
            var ticket_resumption = if (config.ticket_resumption) |cached|
                try cached.clone(config.allocator)
            else
                null;
            errdefer if (ticket_resumption) |*cached| cached.deinit();
            if (ticket_resumption) |*cached| {
                if (config.server_name == null or
                    parsed.session_id.len == 0 or
                    parsed.session_ticket == null or
                    !std.mem.eql(
                        u8,
                        parsed.session_ticket.?,
                        cached.ticket(),
                    ))
                {
                    return error.SessionContextMismatch;
                }
                try cached.validate(config.now_seconds, config.server_name.?);
                if (!containsSuite(
                    config.policy.cipher_suites,
                    cached.session.suite,
                ) or !containsAlpn(
                    config.policy.alpn_protocols,
                    cached.alpn(),
                )) {
                    return error.SessionContextMismatch;
                }
            }
            if (config.request_session_ticket and
                parsed.session_ticket == null)
            {
                return error.UnsupportedProfile;
            }

            var private_key: ?[key_exchange.p256.secret_len]u8 =
                if (config.client_private_key) |value| value.* else null;
            if (config.client_private_key) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key) |*value| {
                std.crypto.secureZero(u8, value);
            };
            var private_key_p384: ?[key_exchange.p384.secret_len]u8 =
                if (config.client_private_key_p384) |value| value.* else null;
            if (config.client_private_key_p384) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key_p384) |*value| {
                std.crypto.secureZero(u8, value);
            };
            for (config.policy.groups) |group| switch (group) {
                key_exchange.named_group_secp256r1 => {
                    if (private_key == null or !try parsed.supportsGroup(group)) {
                        return error.UnsupportedProfile;
                    }
                },
                key_exchange.named_group_secp384r1 => {
                    if (private_key_p384 == null or
                        !try parsed.supportsGroup(group))
                    {
                        return error.UnsupportedProfile;
                    }
                },
                else => return error.UnsupportedProfile,
            };
            const owned_hello = try config.allocator.dupe(
                u8,
                encoded_client_hello,
            );
            errdefer {
                std.crypto.secureZero(u8, owned_hello);
                config.allocator.free(owned_hello);
            }
            return .{
                .allocator = config.allocator,
                .policy = config.policy,
                .server_name = config.server_name,
                .server_verifier = config.server_verifier,
                .client_identity = config.client_identity,
                .now_seconds = config.now_seconds,
                .pending = .{
                    .allocator = config.allocator,
                    .client_private_key = private_key,
                    .client_private_key_p384 = private_key_p384,
                    .client_random = config.random,
                    .client_hello = owned_hello,
                    .resumption = resumption,
                    .ticket_resumption = ticket_resumption,
                },
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
                .server_flight => self.receiveServerFlight(
                    framed_result.consumed,
                    framed,
                    output,
                ),
                .server_change_cipher_spec => self.receiveChangeCipherSpec(
                    framed_result.consumed,
                    framed,
                ),
                .server_finished => self.receiveServerFinished(
                    framed_result.consumed,
                    framed,
                    output,
                ),
                .established => error.AlreadyEstablished,
                .failed => error.ConnectionFailed,
            };
        }

        fn receiveServerFlight(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            if (framed.content_type == 21) {
                return self.acceptPlaintextAlert(consumed, framed.fragment);
            }
            if (framed.content_type != 22) return error.UnexpectedRecord;
            var remaining = framed.fragment;
            while (remaining.len != 0) {
                const message_result = try self.messages.push(remaining);
                remaining = remaining[message_result.consumed..];
                const message = message_result.message orelse continue;
                try self.validateServerFlightMessage(message);
                const pending = &(self.pending orelse unreachable);
                if (pending.server_flight.items.len >
                    max_server_flight_len -| message.len)
                {
                    return error.ServerFlightTooLarge;
                }
                try pending.server_flight.appendSlice(
                    self.allocator,
                    message,
                );
                pending.message_count += 1;
                if (pending.message_count == 1 and
                    try self.acceptResumedServerHello(message))
                {
                    if (remaining.len != 0 or self.messages.pending() != 0) {
                        return error.UnexpectedHandshakeMessage;
                    }
                    return .{ .consumed = consumed, .event = null };
                }
                if (message[0] == handshake.handshake_type_server_hello_done) {
                    if (remaining.len != 0 or self.messages.pending() != 0) {
                        return error.UnexpectedHandshakeMessage;
                    }
                    try self.finishServerFlight(output);
                    return .{
                        .consumed = consumed,
                        .event = .{ .client_flight = {} },
                    };
                }
            }
            return .{ .consumed = consumed, .event = null };
        }

        fn validateServerFlightMessage(
            self: *Self,
            message: []const u8,
        ) Error!void {
            const pending = &(self.pending orelse unreachable);
            if (message.len < 4) return error.UnexpectedHandshakeMessage;
            if (pending.message_count == 2 and
                message[0] == handshake.handshake_type_certificate_status)
            {
                pending.saw_certificate_status = true;
                return;
            }
            const logical_count = pending.message_count -
                @intFromBool(pending.saw_certificate_status);
            const valid = switch (logical_count) {
                0 => message[0] == handshake.handshake_type_server_hello,
                1 => message[0] == handshake.handshake_type_certificate,
                2 => message[0] == handshake.handshake_type_server_key_exchange,
                3 => message[0] == handshake.handshake_type_certificate_request or
                    message[0] == handshake.handshake_type_server_hello_done,
                4 => message[0] == handshake.handshake_type_server_hello_done,
                else => false,
            };
            if (!valid) {
                return error.UnexpectedHandshakeMessage;
            }
        }

        fn finishServerFlight(
            self: *Self,
            output: *std.ArrayList(u8),
        ) Error!void {
            const pending = &(self.pending orelse unreachable);
            const messages = try handshake.splitServerFlight(
                pending.server_flight.items,
            );
            const server_hello = try handshake.parseServerHello(
                messages.server_hello,
                self.policy,
                self.server_name != null,
            );
            const offered_client_hello = try client_hello.parse(
                pending.client_hello,
            );
            const ocsp_response = try validateServerOcspStatus(
                offered_client_hello.requests_ocsp,
                server_hello.status_request_acknowledged,
                messages.certificate_status,
            );
            try checkDowngradeSentinel(
                pending.client_hello,
                server_hello.random,
            );
            if (pending.resumption) |*session| session.deinit();
            pending.resumption = null;
            if (pending.ticket_resumption) |*cached| cached.deinit();
            pending.ticket_resumption = null;
            pending.negotiated_session_id = copySessionId(
                server_hello.session_id,
            );
            pending.negotiated_session_id_len = @intCast(
                server_hello.session_id.len,
            );
            var certificate = try handshake.parseCertificate(
                self.allocator,
                messages.certificate,
            );
            defer certificate.deinit(self.allocator);
            try self.server_verifier.verifyTrustWithOcsp(
                self.server_name,
                certificate.entries,
                ocsp_response,
            );
            const server_key_exchange =
                try handshake.parseAndVerifyServerKeyExchange(
                    messages.server_key_exchange,
                    certificate.entries[0],
                    pending.client_random,
                    server_hello.random,
                    server_hello.suite,
                    self.policy,
                );
            try handshake.parseServerHelloDone(messages.server_hello_done);

            var client_public_storage =
                [_]u8{0} ** key_exchange.p384.public_len;
            var shared_storage = [_]u8{0} ** key_exchange.p384.shared_len;
            const client_public: []const u8 = switch (server_key_exchange.group) {
                key_exchange.named_group_secp256r1 => blk: {
                    const private_key = pending.client_private_key orelse
                        return error.UnsupportedProfile;
                    const public = try key_exchange.p256.publicKey(private_key);
                    client_public_storage[0..public.len].* = public;
                    const shared = try key_exchange.p256.sharedSecret(
                        private_key,
                        server_key_exchange.public_key,
                    );
                    shared_storage[0..shared.len].* = shared;
                    break :blk client_public_storage[0..public.len];
                },
                key_exchange.named_group_secp384r1 => blk: {
                    const private_key = pending.client_private_key_p384 orelse
                        return error.UnsupportedProfile;
                    const public = try key_exchange.p384.publicKey(private_key);
                    client_public_storage = public;
                    shared_storage = try key_exchange.p384.sharedSecret(
                        private_key,
                        server_key_exchange.public_key,
                    );
                    break :blk &client_public_storage;
                },
                else => return error.UnsupportedProfile,
            };
            const shared_secret: []const u8 = switch (server_key_exchange.group) {
                key_exchange.named_group_secp256r1 => shared_storage[0..key_exchange.p256.shared_len],
                key_exchange.named_group_secp384r1 => &shared_storage,
                else => unreachable,
            };
            defer std.crypto.secureZero(u8, &client_public_storage);
            defer std.crypto.secureZero(u8, &shared_storage);
            if (pending.client_private_key) |*value| {
                std.crypto.secureZero(u8, value);
            }
            if (pending.client_private_key_p384) |*value| {
                std.crypto.secureZero(u8, value);
            }

            var state = transcript.State.init(
                server_hello.suite.transcriptHash(),
            );
            state.update(pending.client_hello);
            state.update(messages.server_hello);
            state.update(messages.certificate);
            if (messages.certificate_status) |status| state.update(status);
            state.update(messages.server_key_exchange);
            if (messages.certificate_request) |request| state.update(request);
            state.update(messages.server_hello_done);

            var client_messages: std.ArrayList(u8) = .empty;
            defer client_messages.deinit(self.allocator);
            var client_records: std.ArrayList(u8) = .empty;
            defer client_records.deinit(self.allocator);
            const request = if (messages.certificate_request) |request_bytes|
                try handshake.parseCertificateRequest(request_bytes)
            else
                null;
            if (request != null) {
                const certificate_start = client_messages.items.len;
                if (self.client_identity) |identity| {
                    try identity.validate();
                    if (!request.?.supportsSigner(identity.signer)) {
                        return error.UnsupportedSignatureScheme;
                    }
                    try handshake.writeClientCertificate(
                        &client_messages,
                        self.allocator,
                        identity.certificate_chain,
                    );
                } else {
                    try handshake.writeClientCertificate(
                        &client_messages,
                        self.allocator,
                        &.{},
                    );
                }
                state.update(client_messages.items[certificate_start..]);
                try appendPlaintextRecords(
                    &client_records,
                    self.allocator,
                    22,
                    0x0303,
                    client_messages.items[certificate_start..],
                );
            }

            const client_key_exchange_start = client_messages.items.len;
            try handshake.writeClientKeyExchange(
                &client_messages,
                self.allocator,
                client_public,
            );
            state.update(client_messages.items[client_key_exchange_start..]);
            try appendPlaintextRecords(
                &client_records,
                self.allocator,
                22,
                0x0303,
                client_messages.items[client_key_exchange_start..],
            );
            const extended_master_session_hash = state.digest();

            if (request != null and self.client_identity != null) {
                var signed_transcript: std.ArrayList(u8) = .empty;
                defer signed_transcript.deinit(self.allocator);
                try signed_transcript.appendSlice(
                    self.allocator,
                    pending.client_hello,
                );
                try signed_transcript.appendSlice(
                    self.allocator,
                    pending.server_flight.items,
                );
                try signed_transcript.appendSlice(
                    self.allocator,
                    client_messages.items,
                );
                const verify_start = client_messages.items.len;
                try handshake.writeCertificateVerify(
                    &client_messages,
                    self.allocator,
                    self.client_identity.?.signer,
                    signed_transcript.items,
                );
                state.update(client_messages.items[verify_start..]);
                try appendPlaintextRecords(
                    &client_records,
                    self.allocator,
                    22,
                    0x0303,
                    client_messages.items[verify_start..],
                );
            }

            var master_secret = if (server_hello.extended_master_secret)
                try tls12.deriveExtendedMasterSecret(
                    server_hello.suite,
                    shared_secret,
                    extended_master_session_hash.bytes(),
                )
            else
                tls12.deriveMasterSecret(
                    server_hello.suite,
                    shared_secret,
                    pending.client_random,
                    server_hello.random,
                );
            defer std.crypto.secureZero(u8, &master_secret);
            var keys = try tls12.deriveKeyPair(
                server_hello.suite,
                &master_secret,
                pending.client_random,
                server_hello.random,
            );
            defer keys.deinit();
            var client_traffic = tls12.TrafficState.init(keys.client);
            errdefer client_traffic.deinit();
            var server_traffic = tls12.TrafficState.init(keys.server);
            errdefer server_traffic.deinit();

            const client_verify = try tls12.finishedVerifyData(
                server_hello.suite,
                &master_secret,
                .client,
                state.digest().bytes(),
            );
            var client_finished: [4 + tls12.finished_verify_data_len]u8 =
                undefined;
            handshake.writeFinished(&client_finished, client_verify);
            var encrypted_finished: [64]u8 = undefined;
            const encrypted_finished_len = try client_traffic.seal(
                22,
                &client_finished,
                &encrypted_finished,
            );
            state.update(&client_finished);

            const peer_chain = try copyCertificateChain(
                self.allocator,
                certificate.entries,
            );
            errdefer freeCertificateChain(self.allocator, peer_chain);
            const selected_alpn = if (server_hello.alpn_protocol) |protocol|
                try self.allocator.dupe(u8, protocol)
            else
                null;
            errdefer if (selected_alpn) |protocol| {
                self.allocator.free(protocol);
            };

            var client_flight: std.ArrayList(u8) = .empty;
            defer client_flight.deinit(self.allocator);
            try client_flight.appendSlice(
                self.allocator,
                client_records.items,
            );
            try appendPlaintextRecord(
                &client_flight,
                self.allocator,
                stream.content_type_change_cipher_spec,
                0x0303,
                &.{1},
            );
            try client_flight.appendSlice(
                self.allocator,
                encrypted_finished[0..encrypted_finished_len],
            );
            const output_start = output.items.len;
            errdefer output.shrinkRetainingCapacity(output_start);
            try output.appendSlice(self.allocator, client_flight.items);

            pending.suite = server_hello.suite;
            pending.server_random = server_hello.random;
            pending.transcript_state = state;
            pending.master_secret = master_secret;
            pending.client_traffic = client_traffic;
            pending.server_traffic = server_traffic;
            pending.peer_certificate_chain = peer_chain;
            pending.selected_alpn = selected_alpn;
            // Local copies are wiped while the pending state retains its own.
            client_traffic.deinit();
            server_traffic.deinit();
            self.messages.reset();
            self.stage = .server_change_cipher_spec;
        }

        fn acceptResumedServerHello(
            self: *Self,
            message: []const u8,
        ) Error!bool {
            const pending = &(self.pending orelse unreachable);
            const server_hello = try handshake.parseServerHello(
                message,
                self.policy,
                self.server_name != null,
            );
            const offered = try client_hello.parse(pending.client_hello);
            if (server_hello.session_ticket_acknowledged and
                offered.session_ticket == null)
            {
                return error.UnexpectedHandshakeMessage;
            }
            pending.expect_new_session_ticket =
                server_hello.session_ticket_acknowledged;
            const using_ticket = pending.ticket_resumption != null;
            const session = if (pending.ticket_resumption) |*cached| blk: {
                break :blk &cached.session;
            } else if (pending.resumption) |*stored|
                stored
            else
                return false;
            try checkDowngradeSentinel(
                pending.client_hello,
                server_hello.random,
            );
            const expected_session_id = if (using_ticket)
                offered.session_id
            else
                session.id();
            if (!std.mem.eql(
                u8,
                server_hello.session_id,
                expected_session_id,
            )) {
                return false;
            }
            if (server_hello.status_request_acknowledged) {
                return error.UnexpectedHandshakeMessage;
            }
            if (server_hello.suite != session.suite or
                !std.mem.eql(
                    u8,
                    server_hello.alpn_protocol orelse "",
                    session.alpn(),
                ))
            {
                return error.SessionContextMismatch;
            }
            var state = transcript.State.init(session.suite.transcriptHash());
            state.update(pending.client_hello);
            state.update(message);
            var keys = try tls12.deriveKeyPair(
                session.suite,
                &session.master_secret,
                pending.client_random,
                server_hello.random,
            );
            errdefer keys.deinit();
            const selected_alpn = if (server_hello.alpn_protocol) |protocol|
                try self.allocator.dupe(u8, protocol)
            else
                null;
            errdefer if (selected_alpn) |protocol| {
                self.allocator.free(protocol);
            };
            const empty_chain = try self.allocator.alloc([]const u8, 0);
            errdefer self.allocator.free(empty_chain);
            if (pending.client_private_key) |*private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            if (pending.client_private_key_p384) |*private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            pending.suite = session.suite;
            pending.server_random = server_hello.random;
            pending.transcript_state = state;
            pending.master_secret = session.master_secret;
            pending.client_traffic = tls12.TrafficState.init(keys.client);
            pending.server_traffic = tls12.TrafficState.init(keys.server);
            pending.peer_certificate_chain = empty_chain;
            pending.selected_alpn = selected_alpn;
            pending.negotiated_session_id = copySessionId(
                server_hello.session_id,
            );
            pending.negotiated_session_id_len = @intCast(
                server_hello.session_id.len,
            );
            pending.resumed = true;
            if (using_ticket) {
                const cached = &pending.ticket_resumption.?;
                pending.new_session_ticket = try self.allocator.dupe(
                    u8,
                    cached.ticket(),
                );
                const elapsed = self.now_seconds -
                    cached.session.created_at_seconds;
                pending.new_session_ticket_lifetime_hint_seconds =
                    cached.session.lifetime_seconds - @as(u32, @intCast(elapsed));
            }
            if (pending.resumption) |*stored| stored.deinit();
            pending.resumption = null;
            if (pending.ticket_resumption) |*cached| cached.deinit();
            pending.ticket_resumption = null;
            self.messages.reset();
            self.stage = .server_change_cipher_spec;
            return true;
        }

        fn receiveChangeCipherSpec(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
        ) Error!ReceiveResult {
            if (framed.content_type == 21) {
                return self.acceptPlaintextAlert(consumed, framed.fragment);
            }
            if (framed.content_type == 22) {
                const pending = &(self.pending orelse unreachable);
                if (!pending.expect_new_session_ticket or
                    pending.received_new_session_ticket)
                {
                    return error.UnexpectedHandshakeMessage;
                }
                const message_result = try self.messages.push(framed.fragment);
                const message = message_result.message orelse return .{
                    .consumed = consumed,
                    .event = null,
                };
                if (message_result.consumed != framed.fragment.len) {
                    return error.UnexpectedHandshakeMessage;
                }
                const received = try tls12_ticket.parse(message);
                if (received.ticket.len != 0) {
                    const ticket_copy = try self.allocator.dupe(
                        u8,
                        received.ticket,
                    );
                    if (pending.new_session_ticket) |old_ticket| {
                        std.crypto.secureZero(u8, old_ticket);
                        self.allocator.free(old_ticket);
                    }
                    pending.new_session_ticket = ticket_copy;
                    pending.new_session_ticket_lifetime_hint_seconds =
                        received.lifetime_hint_seconds;
                }
                pending.received_new_session_ticket = true;
                pending.transcript_state.?.update(message);
                self.messages.reset();
                return .{ .consumed = consumed, .event = null };
            }
            if (framed.content_type != stream.content_type_change_cipher_spec or
                !std.mem.eql(u8, framed.fragment, &.{1}))
            {
                return error.InvalidChangeCipherSpec;
            }
            const pending = &(self.pending orelse unreachable);
            if (pending.expect_new_session_ticket and
                !pending.received_new_session_ticket)
            {
                return error.UnexpectedHandshakeMessage;
            }
            self.stage = .server_finished;
            return .{
                .consumed = consumed,
                .event = .{ .change_cipher_spec = {} },
            };
        }

        fn receiveServerFinished(
            self: *Self,
            consumed: usize,
            framed: stream.FramedRecord,
            output: *std.ArrayList(u8),
        ) Error!ReceiveResult {
            const pending = &(self.pending orelse unreachable);
            var plaintext: [64]u8 = undefined;
            const opened = try pending.server_traffic.?.open(
                framed.bytes,
                &plaintext,
            );
            if (opened.content_type == 21) {
                const received = try alert.parse(plaintext[0..opened.len]);
                const event: Event = .{ .peer_alert = received };
                self.fail();
                return .{ .consumed = consumed, .event = event };
            }
            if (opened.content_type != 22) return error.UnexpectedRecord;
            const message_result = try self.messages.push(
                plaintext[0..opened.len],
            );
            const message = message_result.message orelse return .{
                .consumed = consumed,
                .event = null,
            };
            if (message_result.consumed != opened.len) {
                return error.UnexpectedHandshakeMessage;
            }
            const received_verify = try handshake.parseFinished(message);
            const expected_verify = try tls12.finishedVerifyData(
                pending.suite orelse unreachable,
                &(pending.master_secret orelse unreachable),
                .server,
                (pending.transcript_state orelse unreachable).digest().bytes(),
            );
            if (!std.crypto.timing_safe.eql(
                [tls12.finished_verify_data_len]u8,
                received_verify,
                expected_verify,
            )) return error.BadServerFinished;
            pending.transcript_state.?.update(message);
            if (pending.resumed) {
                const client_verify = try tls12.finishedVerifyData(
                    pending.suite.?,
                    &pending.master_secret.?,
                    .client,
                    pending.transcript_state.?.digest().bytes(),
                );
                var client_finished: [4 + tls12.finished_verify_data_len]u8 =
                    undefined;
                handshake.writeFinished(&client_finished, client_verify);
                var encrypted: [64]u8 = undefined;
                const encrypted_len = try pending.client_traffic.?.seal(
                    22,
                    &client_finished,
                    &encrypted,
                );
                const output_start = output.items.len;
                errdefer output.items.len = output_start;
                try appendPlaintextRecord(
                    output,
                    self.allocator,
                    stream.content_type_change_cipher_spec,
                    0x0303,
                    &.{1},
                );
                try output.appendSlice(
                    self.allocator,
                    encrypted[0..encrypted_len],
                );
                pending.transcript_state.?.update(&client_finished);
            }
            return .{
                .consumed = consumed,
                .event = .{ .established = self.establish() },
            };
        }

        fn acceptPlaintextAlert(
            self: *Self,
            consumed: usize,
            bytes: []const u8,
        ) Error!ReceiveResult {
            const received = try alert.parse(bytes);
            const event: Event = .{ .peer_alert = received };
            self.fail();
            return .{ .consumed = consumed, .event = event };
        }

        fn establish(self: *Self) Established {
            const pending = &(self.pending orelse unreachable);
            const established = Established{
                .allocator = self.allocator,
                .read = pending.server_traffic.?,
                .write = pending.client_traffic.?,
                .master_secret = pending.master_secret.?,
                .client_random = pending.client_random,
                .server_random = pending.server_random.?,
                .suite = pending.suite.?,
                .selected_alpn = pending.selected_alpn,
                .peer_certificate_chain = pending.peer_certificate_chain.?,
                .resumed = pending.resumed,
                .session_id = pending.negotiated_session_id,
                .session_id_len = pending.negotiated_session_id_len,
                .session_ticket = pending.new_session_ticket,
                .session_ticket_lifetime_hint_seconds = pending.new_session_ticket_lifetime_hint_seconds,
            };
            pending.server_traffic = null;
            pending.client_traffic = null;
            pending.master_secret = null;
            pending.selected_alpn = null;
            pending.peer_certificate_chain = null;
            pending.new_session_ticket = null;
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
        }
    };
}

fn validatePolicy(policy: handshake.Policy) Error!void {
    if (policy.cipher_suites.len == 0 or policy.groups.len == 0) {
        return error.UnsupportedProfile;
    }
    for (policy.groups) |group| {
        if (group != key_exchange.named_group_secp256r1 and
            group != key_exchange.named_group_secp384r1)
        {
            return error.UnsupportedProfile;
        }
    }
}

fn containsSuite(suites: []const tls12.Suite, target: tls12.Suite) bool {
    for (suites) |suite| if (suite == target) return true;
    return false;
}

fn containsAlpn(protocols: []const []const u8, target: []const u8) bool {
    if (target.len == 0) return protocols.len == 0;
    for (protocols) |protocol| {
        if (std.mem.eql(u8, protocol, target)) return true;
    }
    return false;
}

fn copySessionId(id: []const u8) [tls12.max_session_id_len]u8 {
    var result = [_]u8{0} ** tls12.max_session_id_len;
    @memcpy(result[0..id.len], id);
    return result;
}

pub fn deriveTicketSessionId(random: [32]u8) [tls12.max_session_id_len]u8 {
    var result: [tls12.max_session_id_len]u8 = undefined;
    var state = std.crypto.hash.sha2.Sha256.init(.{});
    state.update("vail tls12 ticket session id\x00");
    state.update(&random);
    state.final(&result);
    return result;
}

fn checkDowngradeSentinel(
    encoded_client_hello: []const u8,
    server_random: [32]u8,
) Error!void {
    const offered = try client_hello.parse(encoded_client_hello);
    if (offered.supportsVersion(0x0304) and std.mem.eql(
        u8,
        server_random[24..32],
        "DOWNGRD\x01",
    )) return error.DowngradeDetected;
}

fn validateServerOcspStatus(
    offered: bool,
    acknowledged: bool,
    certificate_status: ?[]const u8,
) Error!?[]const u8 {
    if ((acknowledged and !offered) or
        acknowledged != (certificate_status != null))
    {
        return error.UnexpectedHandshakeMessage;
    }
    return if (certificate_status) |status|
        try handshake.parseCertificateStatus(status)
    else
        null;
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

fn appendPlaintextRecord(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    content_type: u8,
    legacy_version: u16,
    payload: []const u8,
) std.mem.Allocator.Error!void {
    try output.appendSlice(allocator, &.{
        content_type,
        @truncate(legacy_version >> 8),
        @truncate(legacy_version),
        @truncate(payload.len >> 8),
        @truncate(payload.len),
    });
    try output.appendSlice(allocator, payload);
}

fn appendPlaintextRecords(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    content_type: u8,
    legacy_version: u16,
    payload: []const u8,
) std.mem.Allocator.Error!void {
    var offset: usize = 0;
    while (offset < payload.len) {
        const len = @min(record13.max_plaintext_len, payload.len - offset);
        try appendPlaintextRecord(
            output,
            allocator,
            content_type,
            legacy_version,
            payload[offset..][0..len],
        );
        offset += len;
    }
}

test "TLS 1.2 client and server authenticate and exchange application data" {
    const allocator = std.testing.allocator;
    const server_module = @import("tls12_server_connection.zig");
    const rsa = @import("../crypto/rsa.zig");
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const certificate = decodeHex(vectors.certificate_hex);
    const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try rsa.PrivateKey.fromDer(&private_key_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const ticket_keyring = @import("ticket_keyring.zig");
    var ticket_keys = try ticket_keyring.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{0x8f} ** ticket_keyring.key_len,
    });
    defer ticket_keys.deinit();

    var client_private = [_]u8{0} ** key_exchange.p256.secret_len;
    client_private[client_private.len - 1] = 3;
    const session_id = [_]u8{0xd1} ** 32;
    const policy = handshake.Policy{
        .alpn_protocols = &.{"h2"},
        .new_session_id = &session_id,
        .ocsp_response = "tls12-test-ocsp",
    };
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    const Client = ClientConnection(64 * 1024, 64 * 1024);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0x91} ** 32,
        .server_name = "localhost",
        .client_private_key = &client_private,
        .policy = policy,
        .request_ocsp = true,
        .server_verifier = .{ .verify_trust = expectTestOcsp },
        .request_session_ticket = true,
    }, &client_wire);
    defer client.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** key_exchange.p256.secret_len),
        &client_private,
    );

    var server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    server_private[server_private.len - 1] = 2;
    const Server = server_module.ServerConnection(64 * 1024, 64 * 1024);
    var server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0x92} ** 32,
        .server_private_key = &server_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
        .session_tickets = .{
            .keyring = &ticket_keys,
            .server_id = "server-identity",
            .now_seconds = 100,
            .lifetime_seconds = 60,
            .sealing_nonce = [_]u8{0x8e} ** ticket_keyring.nonce_len,
        },
    });
    defer server.deinit();

    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    var saw_server_flight = false;
    for (client_wire.items) |byte| {
        const first = try server.receive(&.{byte}, &server_wire);
        try std.testing.expectEqual(@as(usize, 1), first.consumed);
        if (first.event) |event| {
            try std.testing.expect(!saw_server_flight);
            try std.testing.expectEqual(
                std.meta.Tag(server_module.Event).server_flight,
                std.meta.activeTag(event),
            );
            saw_server_flight = true;
        }
    }
    try std.testing.expect(saw_server_flight);
    client_wire.clearRetainingCapacity();

    var saw_client_flight = false;
    for (server_wire.items) |byte| {
        const received = try client.receive(&.{byte}, &client_wire);
        try std.testing.expectEqual(@as(usize, 1), received.consumed);
        if (received.event) |event| {
            try std.testing.expect(!saw_client_flight);
            try std.testing.expectEqual(
                std.meta.Tag(Event).client_flight,
                std.meta.activeTag(event),
            );
            saw_client_flight = true;
        }
    }
    try std.testing.expect(saw_client_flight);
    server_wire.clearRetainingCapacity();

    var established_server: ?server_module.Established = null;
    for (client_wire.items) |byte| {
        const received = try server.receive(&.{byte}, &server_wire);
        try std.testing.expectEqual(@as(usize, 1), received.consumed);
        if (received.event) |event| switch (event) {
            .server_flight,
            .client_key_exchange,
            .change_cipher_spec,
            => {},
            .peer_alert => return error.UnexpectedPeerAlert,
            .established => |value| established_server = value,
        };
    }
    try std.testing.expect(established_server != null);
    defer established_server.?.deinit();
    client_wire.clearRetainingCapacity();

    var established_client: ?Established = null;
    for (server_wire.items) |byte| {
        const received = try client.receive(&.{byte}, &client_wire);
        try std.testing.expectEqual(@as(usize, 1), received.consumed);
        if (received.event) |event| switch (event) {
            .client_flight => return error.UnexpectedClientFlight,
            .change_cipher_spec => {},
            .peer_alert => return error.UnexpectedPeerAlert,
            .established => |value| established_client = value,
        };
    }
    try std.testing.expect(established_client != null);
    defer established_client.?.deinit();
    try std.testing.expectEqualStrings(
        "h2",
        established_client.?.selected_alpn.?,
    );
    try std.testing.expectEqual(@as(usize, 1), established_client.?.peer_certificate_chain.len);
    try std.testing.expect(established_client.?.session_ticket != null);

    var client_ticket = try established_client.?.createTicketSession(
        "localhost",
        100,
    );
    defer client_ticket.deinit();

    var client_exporter: [48]u8 = undefined;
    var server_exporter: [48]u8 = undefined;
    try established_client.?.exportKeyingMaterial(
        "EXPORTER-vail-test",
        "context",
        &client_exporter,
    );
    try established_server.?.exportKeyingMaterial(
        "EXPORTER-vail-test",
        "context",
        &server_exporter,
    );
    try std.testing.expectEqual(client_exporter, server_exporter);

    var application_record: [256]u8 = undefined;
    const application_len = try established_client.?.sealApplicationData(
        "client payload",
        &application_record,
    );
    const server_application = try established_server.?.receive(
        application_record[0..application_len],
    );
    try std.testing.expectEqualStrings(
        "client payload",
        server_application.event.?.application_data,
    );

    const response_len = try established_server.?.sealApplicationData(
        "server payload",
        &application_record,
    );
    const client_application = try established_client.?.receive(
        application_record[0..response_len],
    );
    try std.testing.expectEqualStrings(
        "server payload",
        client_application.event.?.application_data,
    );

    var client_session = try established_client.?.createSession(
        "localhost",
        100,
        60,
    );
    defer client_session.deinit();
    var server_session = try established_server.?.createSession(
        "server-identity",
        100,
        60,
    );
    defer server_session.deinit();
    try std.testing.expectEqualSlices(
        u8,
        client_session.id(),
        server_session.id(),
    );

    client_wire.clearRetainingCapacity();
    server_wire.clearRetainingCapacity();
    var resume_client_private = [_]u8{0} ** key_exchange.p256.secret_len;
    resume_client_private[resume_client_private.len - 1] = 11;
    var resumed_client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xd2} ** 32,
        .server_name = "localhost",
        .client_private_key = &resume_client_private,
        .policy = policy,
        .server_verifier = .{ .verify_trust = acceptTestCertificate },
        .resumption = client_session,
        .now_seconds = 101,
    }, &client_wire);
    defer resumed_client.deinit();
    var resume_server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    resume_server_private[resume_server_private.len - 1] = 12;
    var resumed_server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0xd3} ** 32,
        .server_private_key = &resume_server_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
        .resumption = .{
            .session = &server_session,
            .identity = "server-identity",
            .now_seconds = 101,
        },
    });
    defer resumed_server.deinit();
    _ = try resumed_server.receive(client_wire.items, &server_wire);
    client_wire.clearRetainingCapacity();

    var resumed_client_established: ?Established = null;
    var resume_offset: usize = 0;
    while (resume_offset < server_wire.items.len) {
        const received = try resumed_client.receive(
            server_wire.items[resume_offset..],
            &client_wire,
        );
        resume_offset += received.consumed;
        if (received.event) |event| switch (event) {
            .change_cipher_spec => {},
            .established => |value| resumed_client_established = value,
            else => return error.UnexpectedResumptionEvent,
        };
    }
    try std.testing.expect(resumed_client_established != null);
    defer resumed_client_established.?.deinit();
    try std.testing.expect(resumed_client_established.?.resumed);
    try std.testing.expectEqual(@as(usize, 0), resumed_client_established.?.peer_certificate_chain.len);

    server_wire.clearRetainingCapacity();
    var resumed_server_established: ?server_module.Established = null;
    resume_offset = 0;
    while (resume_offset < client_wire.items.len) {
        const received = try resumed_server.receive(
            client_wire.items[resume_offset..],
            &server_wire,
        );
        resume_offset += received.consumed;
        if (received.event) |event| switch (event) {
            .change_cipher_spec => {},
            .established => |value| resumed_server_established = value,
            else => return error.UnexpectedResumptionEvent,
        };
    }
    try std.testing.expect(resumed_server_established != null);
    defer resumed_server_established.?.deinit();
    try std.testing.expect(resumed_server_established.?.resumed);

    const resumed_application_len = try resumed_client_established.?
        .sealApplicationData("resumed", &application_record);
    const resumed_application = try resumed_server_established.?.receive(
        application_record[0..resumed_application_len],
    );
    try std.testing.expectEqualStrings(
        "resumed",
        resumed_application.event.?.application_data,
    );

    client_wire.clearRetainingCapacity();
    server_wire.clearRetainingCapacity();
    var ticket_client_private = [_]u8{0} ** key_exchange.p256.secret_len;
    ticket_client_private[ticket_client_private.len - 1] = 13;
    var ticket_client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xd4} ** 32,
        .server_name = "localhost",
        .client_private_key = &ticket_client_private,
        .policy = policy,
        .server_verifier = .{ .verify_trust = acceptTestCertificate },
        .ticket_resumption = &client_ticket,
        .now_seconds = 101,
    }, &client_wire);
    defer ticket_client.deinit();
    const ticket_offer = try client_hello.parse(
        client_wire.items[record13.header_len..],
    );
    try std.testing.expectEqualSlices(
        u8,
        client_ticket.ticket(),
        ticket_offer.session_ticket.?,
    );

    var ticket_server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    ticket_server_private[ticket_server_private.len - 1] = 14;
    var ticket_server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0xd5} ** 32,
        .server_private_key = &ticket_server_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
        .session_tickets = .{
            .keyring = &ticket_keys,
            .server_id = "server-identity",
            .now_seconds = 101,
            .lifetime_seconds = 60,
            .sealing_nonce = [_]u8{0x8d} ** ticket_keyring.nonce_len,
        },
    });
    defer ticket_server.deinit();
    _ = try ticket_server.receive(client_wire.items, &server_wire);
    client_wire.clearRetainingCapacity();

    var ticket_client_established: ?Established = null;
    resume_offset = 0;
    while (resume_offset < server_wire.items.len) {
        const received = try ticket_client.receive(
            server_wire.items[resume_offset..],
            &client_wire,
        );
        if (received.consumed == 0 and received.event == null) {
            return error.TicketClientStalled;
        }
        resume_offset += received.consumed;
        if (received.event) |event| switch (event) {
            .change_cipher_spec => {},
            .established => |value| ticket_client_established = value,
            else => return error.UnexpectedTicketResumptionEvent,
        };
    }
    var ticket_client_connection = ticket_client_established orelse
        return error.TicketClientDidNotEstablish;
    defer ticket_client_connection.deinit();
    try std.testing.expect(ticket_client_connection.resumed);
    try std.testing.expect(ticket_client_connection.session_ticket != null);
    try std.testing.expect(!std.mem.eql(
        u8,
        client_ticket.ticket(),
        ticket_client_connection.session_ticket.?,
    ));

    server_wire.clearRetainingCapacity();
    var ticket_server_established: ?server_module.Established = null;
    resume_offset = 0;
    while (resume_offset < client_wire.items.len) {
        const received = try ticket_server.receive(
            client_wire.items[resume_offset..],
            &server_wire,
        );
        if (received.consumed == 0 and received.event == null) {
            return error.TicketServerStalled;
        }
        resume_offset += received.consumed;
        if (received.event) |event| switch (event) {
            .change_cipher_spec => {},
            .established => |value| ticket_server_established = value,
            else => return error.UnexpectedTicketResumptionEvent,
        };
    }
    var ticket_server_connection = ticket_server_established orelse
        return error.TicketServerDidNotEstablish;
    defer ticket_server_connection.deinit();
    try std.testing.expect(ticket_server_connection.resumed);

    const ticket_application_len = try ticket_client_connection
        .sealApplicationData("ticket resumed", &application_record);
    const ticket_application = try ticket_server_connection.receive(
        application_record[0..ticket_application_len],
    );
    try std.testing.expectEqualStrings(
        "ticket resumed",
        ticket_application.event.?.application_data,
    );

    var tampered_ticket = try client_ticket.clone(allocator);
    defer tampered_ticket.deinit();
    tampered_ticket.ticket_storage[tampered_ticket.ticket_storage.len - 1] ^=
        1;
    client_wire.clearRetainingCapacity();
    server_wire.clearRetainingCapacity();
    var fallback_client_private = [_]u8{0} ** key_exchange.p256.secret_len;
    fallback_client_private[fallback_client_private.len - 1] = 15;
    var fallback_client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xd6} ** 32,
        .server_name = "localhost",
        .client_private_key = &fallback_client_private,
        .policy = policy,
        .server_verifier = .{ .verify_trust = acceptTestCertificate },
        .ticket_resumption = &tampered_ticket,
        .now_seconds = 101,
    }, &client_wire);
    defer fallback_client.deinit();
    var fallback_server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    fallback_server_private[fallback_server_private.len - 1] = 16;
    var fallback_server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0xd7} ** 32,
        .server_private_key = &fallback_server_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
        .session_tickets = .{
            .keyring = &ticket_keys,
            .server_id = "server-identity",
            .now_seconds = 101,
            .lifetime_seconds = 60,
            .sealing_nonce = [_]u8{0x8c} ** ticket_keyring.nonce_len,
        },
    });
    defer fallback_server.deinit();
    const fallback_result = try fallback_server.receive(
        client_wire.items,
        &server_wire,
    );
    try std.testing.expectEqual(
        std.meta.Tag(server_module.Event).server_flight,
        std.meta.activeTag(fallback_result.event.?),
    );
    try std.testing.expectEqual(
        server_module.Stage.client_key_exchange,
        fallback_server.stage,
    );
    const fallback_payload = server_wire.items[record13.header_len..];
    const fallback_server_hello_len = 4 +
        (@as(usize, fallback_payload[1]) << 16) +
        (@as(usize, fallback_payload[2]) << 8) +
        fallback_payload[3];
    const fallback_server_hello = try handshake.parseServerHello(
        fallback_payload[0..fallback_server_hello_len],
        policy,
        true,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        fallback_server_hello.session_id.len,
    );
    try std.testing.expect(
        fallback_server_hello.session_ticket_acknowledged,
    );
}

test "TLS 1.2 client rejects a bad encrypted server Finished and locks" {
    const allocator = std.testing.allocator;
    const suite = tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256;
    const master_secret = [_]u8{0xa1} ** tls12.master_secret_len;
    const client_random = [_]u8{0xa2} ** 32;
    const server_random = [_]u8{0xa3} ** 32;
    var state = transcript.State.init(suite.transcriptHash());
    state.update("handshake transcript");
    var keys = try tls12.deriveKeyPair(
        suite,
        &master_secret,
        client_random,
        server_random,
    );
    defer keys.deinit();
    var server_sender = tls12.TrafficState.init(try tls12.Keys.init(
        suite,
        keys.server.key[0..suite.keyLength()],
        keys.server.fixed_iv[0..suite.fixedIvLength()],
    ));
    defer server_sender.deinit();
    var client = ClientConnection(4096, 4096){
        .allocator = allocator,
        .policy = .{},
        .server_name = null,
        .server_verifier = .{},
        .client_identity = null,
        .stage = .server_finished,
        .pending = .{
            .allocator = allocator,
            .client_private_key = [_]u8{0} ** key_exchange.p256.secret_len,
            .client_private_key_p384 = null,
            .client_random = client_random,
            .client_hello = try allocator.dupe(u8, "hello"),
            .suite = suite,
            .server_random = server_random,
            .transcript_state = state,
            .master_secret = master_secret,
            .client_traffic = tls12.TrafficState.init(try tls12.Keys.init(
                suite,
                keys.client.key[0..suite.keyLength()],
                keys.client.fixed_iv[0..suite.fixedIvLength()],
            )),
            .server_traffic = tls12.TrafficState.init(try tls12.Keys.init(
                suite,
                keys.server.key[0..suite.keyLength()],
                keys.server.fixed_iv[0..suite.fixedIvLength()],
            )),
        },
    };
    defer client.deinit();
    const verify_data = try tls12.finishedVerifyData(
        suite,
        &master_secret,
        .server,
        state.digest().bytes(),
    );
    var finished: [4 + tls12.finished_verify_data_len]u8 = undefined;
    handshake.writeFinished(&finished, verify_data);
    var encrypted: [64]u8 = undefined;
    const encrypted_len = try server_sender.seal(22, &finished, &encrypted);
    encrypted[encrypted_len - 1] ^= 1;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try std.testing.expectError(
        error.AuthenticationFailed,
        client.receive(encrypted[0..encrypted_len], &output),
    );
    try std.testing.expectEqual(Stage.failed, client.stage);
    try std.testing.expectError(
        error.ConnectionFailed,
        client.receive(&.{}, &output),
    );
}

test "TLS 1.2 client rejects an authenticated downgrade sentinel" {
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(std.testing.allocator);
    try client_hello.writeWithKeyShare(&hello, std.testing.allocator, .{
        .random = [_]u8{0xa4} ** 32,
        .key_share = null,
        .supported_groups = &.{key_exchange.named_group_secp256r1},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .additional_cipher_suites = &.{
            @intFromEnum(tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256),
            0x00ff,
        },
        .supported_versions = &.{ 0x0304, 0x0303 },
        .offer_extended_master_secret = true,
    });
    var downgrade_random = [_]u8{0xa5} ** 32;
    downgrade_random[24..32].* = "DOWNGRD\x01".*;
    try std.testing.expectError(
        error.DowngradeDetected,
        checkDowngradeSentinel(hello.items, downgrade_random),
    );
    try checkDowngradeSentinel(hello.items, [_]u8{0xa6} ** 32);
}

test "TLS 1.2 client and server complete every AEAD suite on P-256" {
    const allocator = std.testing.allocator;
    const rsa = @import("../crypto/rsa.zig");
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const rsa_certificate = decodeHex(vectors.certificate_hex);
    const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try rsa.PrivateKey.fromDer(&private_key_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const ecdsa_key = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0xb1} ** Ecdsa.KeyPair.seed_length,
    );
    const ecdsa_public = ecdsa_key.public_key.toUncompressedSec1();

    inline for (std.meta.tags(tls12.Suite)) |suite| {
        const rsa_suite = switch (suite) {
            .ecdhe_rsa_aes_128_gcm_sha256,
            .ecdhe_rsa_aes_256_gcm_sha384,
            .ecdhe_rsa_chacha20_poly1305_sha256,
            => true,
            else => false,
        };
        const signer: auth.Signer = if (rsa_suite)
            .{ .rsa_pss = .{
                .prepared_key = &prepared_key,
                .io = std.testing.io,
            } }
        else
            .{ .ecdsa_p256_sha256 = .{ .key_pair = ecdsa_key } };
        const certificate: []const u8 = if (rsa_suite)
            &rsa_certificate
        else
            &ecdsa_public;
        const verifier: auth.ClientVerifier = if (rsa_suite)
            .{ .verify_trust = acceptTestCertificate }
        else
            .{ .pinned_ecdsa_p256_public_key = ecdsa_public };
        try completeSuiteHandshake(
            allocator,
            suite,
            key_exchange.named_group_secp256r1,
            certificate,
            signer,
            verifier,
            null,
            null,
        );
    }
    try completeSuiteHandshake(
        allocator,
        .ecdhe_rsa_aes_256_gcm_sha384,
        key_exchange.named_group_secp384r1,
        &rsa_certificate,
        .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
        .{ .verify_trust = acceptTestCertificate },
        null,
        null,
    );
}

test "TLS 1.2 client authentication proves possession and transfers identity" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const client_key = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0xc1} ** Ecdsa.KeyPair.seed_length,
    );
    const client_public = client_key.public_key.toUncompressedSec1();
    const server_key = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0xc2} ** Ecdsa.KeyPair.seed_length,
    );
    const server_public = server_key.public_key.toUncompressedSec1();
    try completeSuiteHandshake(
        std.testing.allocator,
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        key_exchange.named_group_secp256r1,
        &server_public,
        .{ .ecdsa_p256_sha256 = .{ .key_pair = server_key } },
        .{ .pinned_ecdsa_p256_public_key = server_public },
        .{
            .certificate_chain = &.{&client_public},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = client_key,
            } },
        },
        .{
            .verifier = .{
                .pinned_ecdsa_p256_public_key = client_public,
            },
            .requirement = .required,
        },
    );
}

test "TLS 1.2 required client authentication rejects an empty certificate" {
    const allocator = std.testing.allocator;
    const server_module = @import("tls12_server_connection.zig");
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const server_key = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0xc3} ** Ecdsa.KeyPair.seed_length,
    );
    const server_public = server_key.public_key.toUncompressedSec1();
    const suites = [_]tls12.Suite{.ecdhe_ecdsa_aes_128_gcm_sha256};
    const policy = handshake.Policy{
        .cipher_suites = &suites,
        .client_certificate_authorities = &.{},
    };
    var client_private = [_]u8{0} ** key_exchange.p256.secret_len;
    client_private[client_private.len - 1] = 9;
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    const Client = ClientConnection(64 * 1024, 64 * 1024);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xc4} ** 32,
        .server_name = "localhost",
        .client_private_key = &client_private,
        .policy = policy,
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = server_public,
        },
    }, &client_wire);
    defer client.deinit();
    var server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    server_private[server_private.len - 1] = 10;
    const Server = server_module.ServerConnection(64 * 1024, 64 * 1024);
    var server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0xc5} ** 32,
        .server_private_key = &server_private,
        .certificate_chain = &.{&server_public},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = server_key } },
        .client_auth_policy = .{
            .verifier = .{ .pinned_ecdsa_p256_public_key = server_public },
            .requirement = .required,
        },
    });
    defer server.deinit();
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    _ = try server.receive(client_wire.items, &server_wire);
    client_wire.clearRetainingCapacity();
    _ = try client.receive(server_wire.items, &client_wire);
    server_wire.clearRetainingCapacity();
    try std.testing.expectError(
        error.ClientCertificateRequired,
        server.receive(client_wire.items, &server_wire),
    );
    try std.testing.expectEqual(server_module.Stage.failed, server.stage);
}

fn completeSuiteHandshake(
    allocator: std.mem.Allocator,
    suite: tls12.Suite,
    group: u16,
    certificate: []const u8,
    signer: auth.Signer,
    verifier: auth.ClientVerifier,
    client_identity: ?client_auth.ClientIdentity,
    server_client_auth_policy: ?client_auth.ServerPolicy,
) !void {
    const server_module = @import("tls12_server_connection.zig");
    const Client = ClientConnection(64 * 1024, 64 * 1024);
    const Server = server_module.ServerConnection(64 * 1024, 64 * 1024);
    const suites = [_]tls12.Suite{suite};
    const groups = [_]u16{group};
    const policy = handshake.Policy{
        .cipher_suites = &suites,
        .groups = &groups,
        .alpn_protocols = &.{"h2"},
        .client_certificate_authorities = if (server_client_auth_policy != null)
            &.{}
        else
            null,
    };
    var client_private = [_]u8{0} ** key_exchange.p256.secret_len;
    client_private[client_private.len - 1] = 7;
    var client_private_p384 = [_]u8{0} ** key_exchange.p384.secret_len;
    client_private_p384[client_private_p384.len - 1] = 7;
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xb2} ** 32,
        .server_name = "localhost",
        .client_private_key = if (group == key_exchange.named_group_secp256r1)
            &client_private
        else
            null,
        .client_private_key_p384 = if (group ==
            key_exchange.named_group_secp384r1)
            &client_private_p384
        else
            null,
        .policy = policy,
        .server_verifier = verifier,
        .client_identity = client_identity,
    }, &client_wire);
    defer client.deinit();
    var server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    server_private[server_private.len - 1] = 8;
    var server_private_p384 = [_]u8{0} ** key_exchange.p384.secret_len;
    server_private_p384[server_private_p384.len - 1] = 8;
    var server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0xb3} ** 32,
        .server_private_key = if (group == key_exchange.named_group_secp256r1)
            &server_private
        else
            null,
        .server_private_key_p384 = if (group ==
            key_exchange.named_group_secp384r1)
            &server_private_p384
        else
            null,
        .certificate_chain = &.{certificate},
        .signer = signer,
        .client_auth_policy = server_client_auth_policy,
    });
    defer server.deinit();
    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    _ = try server.receive(client_wire.items, &server_wire);
    client_wire.clearRetainingCapacity();
    const client_flight = try client.receive(server_wire.items, &client_wire);
    try std.testing.expectEqual(
        std.meta.Tag(Event).client_flight,
        std.meta.activeTag(client_flight.event.?),
    );
    server_wire.clearRetainingCapacity();
    var established_server: ?server_module.Established = null;
    var offset: usize = 0;
    while (offset < client_wire.items.len) {
        const received = try server.receive(client_wire.items[offset..], &server_wire);
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .established => |value| established_server = value,
            .server_flight,
            .client_key_exchange,
            .change_cipher_spec,
            => {},
            .peer_alert => return error.UnexpectedPeerAlert,
        };
    }
    defer established_server.?.deinit();
    if (client_identity != null) {
        try std.testing.expectEqual(
            @as(usize, 1),
            established_server.?.peer_certificate_chain.?.len,
        );
    } else {
        try std.testing.expect(
            established_server.?.peer_certificate_chain == null,
        );
    }
    var established_client: ?Established = null;
    offset = 0;
    while (offset < server_wire.items.len) {
        const received = try client.receive(server_wire.items[offset..], &client_wire);
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .established => |value| established_client = value,
            .change_cipher_spec => {},
            .client_flight => return error.UnexpectedClientFlight,
            .peer_alert => return error.UnexpectedPeerAlert,
        };
    }
    defer established_client.?.deinit();
    try std.testing.expectEqual(suite, established_client.?.suite);
}

fn acceptTestCertificate(
    context: ?*anyopaque,
    trust: auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0) return error.EmptyCertificateChain;
}

test "TLS 1.2 OCSP negotiation rejects missing and unsolicited status" {
    var status: std.ArrayList(u8) = .empty;
    defer status.deinit(std.testing.allocator);
    try handshake.writeCertificateStatus(
        &status,
        std.testing.allocator,
        "ocsp",
    );
    try std.testing.expectEqualStrings(
        "ocsp",
        (try validateServerOcspStatus(true, true, status.items)).?,
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try validateServerOcspStatus(true, false, null),
    );
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspStatus(true, true, null),
    );
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspStatus(false, true, status.items),
    );
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspStatus(true, false, status.items),
    );
}

fn expectTestOcsp(
    context: ?*anyopaque,
    trust: auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0 or trust.ocsp_response == null or
        !std.mem.eql(
            u8,
            trust.ocsp_response.?,
            "tls12-test-ocsp",
        ))
    {
        return error.UnexpectedOcspResponse;
    }
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
