//! Incremental TLS 1.2 ECDHE client state.
//!
//! The first integrated profile is deliberately narrow and modern:
//! The state supports the modern ECDHE-RSA/ECDHE-ECDSA AES-GCM and ChaCha20
//! suites over P-256/P-384/P-521, mandatory Extended Master Secret and secure
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
const key_log = @import("key_log.zig");
const p521 = @import("../crypto/ec/p521.zig");
const record13 = @import("record.zig");
const record_size_limit = @import("record_size_limit.zig");
const stream = @import("stream.zig");
const tls12 = @import("tls12.zig");
const tls12_ticket = @import("tls12_ticket.zig");
const handshake = @import("tls12_handshake.zig");
const transcript = @import("transcript.zig");
const traffic_secrets = @import("traffic_secrets.zig");

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
    client_private_key_x25519: ?*[key_exchange.secret_len]u8 = null,
    client_private_key: ?*[key_exchange.p256.secret_len]u8 = null,
    client_private_key_p384: ?*[key_exchange.p384.secret_len]u8 = null,
    client_private_key_p521: ?*[key_exchange.p521.secret_len]u8 = null,
    policy: handshake.Policy = .{},
    tls13_cipher_suites: []const cipher_suite.Suite = &.{},
    client_hello_key_share: ?client_hello.OfferedKeyShare = null,
    client_hello_supported_groups: []const u16 = &.{},
    supported_versions: []const u16 = &.{0x0303},
    signature_schemes: []const u16 = &client_hello.default_signature_schemes,
    /// Optional RFC 8446 certificate-signature constraints carried by the
    /// shared ClientHello codec for version-negotiating callers.
    certificate_signature_schemes: ?[]const u16 = null,
    /// Request a stapled OCSP response by default so RFC 7633 Must-Staple
    /// certificates can be validated without a caller opt-in.
    request_ocsp: bool = true,
    /// Override RFC 6961 multi-stapling advertisement. Null follows
    /// `request_ocsp`, preserving one-switch opt-out while allowing v2-only.
    request_ocsp_multi: ?bool = null,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{},
    server_verifier: auth.ClientVerifier,
    client_identity: ?client_auth.ClientIdentity = null,
    resumption: ?tls12.Session = null,
    /// Request a new RFC 5077 ticket during a full or session-ID handshake.
    request_session_ticket: bool = false,
    /// Borrowed cached ticket; `init` deep-copies it before returning.
    ticket_resumption: ?*const tls12_ticket.Cached = null,
    now_seconds: u64 = 0,
    /// Opt-in NSS-compatible master-secret logging for diagnostics.
    key_log: ?key_log.Logger = null,
};

const tls12_rsa_sign_certificate_type: u8 = 1;
const tls12_ecdsa_sign_certificate_type: u8 = 64;

fn certificateRequestAcceptsIdentity(
    request: handshake.ParsedCertificateRequest,
    identity: client_auth.ClientIdentity,
) bool {
    const certificate_type = tls12ClientCertificateType(
        identity.signer.scheme(),
    ) orelse return false;
    if (std.mem.indexOfScalar(
        u8,
        request.certificate_types,
        certificate_type,
    ) == null or !request.supportsSigner(identity.signer)) return false;
    return client_auth.certificateChainMatchesAuthorities(
        identity.certificate_chain,
        request.certificate_authorities,
    );
}

fn tls12ClientCertificateType(signature_scheme: u16) ?u8 {
    return switch (signature_scheme) {
        auth.signature_scheme_rsa_pss_rsae_sha256,
        auth.signature_scheme_rsa_pss_rsae_sha384,
        auth.signature_scheme_rsa_pss_rsae_sha512,
        auth.signature_scheme_rsa_pss_pss_sha256,
        auth.signature_scheme_rsa_pss_pss_sha384,
        auth.signature_scheme_rsa_pss_pss_sha512,
        auth.signature_scheme_rsa_pkcs1_sha256,
        auth.signature_scheme_rsa_pkcs1_sha384,
        auth.signature_scheme_rsa_pkcs1_sha512,
        => tls12_rsa_sign_certificate_type,
        auth.signature_scheme_ecdsa_secp256r1_sha256,
        auth.signature_scheme_ecdsa_secp384r1_sha384,
        auth.signature_scheme_ecdsa_secp521r1_sha512,
        auth.signature_scheme_ed25519,
        auth.signature_scheme_sm2sig_sm3,
        => tls12_ecdsa_sign_certificate_type,
        else => null,
    };
}

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

pub const ReceiveIntoEvent = union(enum) {
    client_flight: void,
    change_cipher_spec: void,
    peer_alert: alert.Alert,
    established: void,
};

pub const ReceiveIntoResult = struct {
    consumed: usize,
    event: ?ReceiveIntoEvent,
};

pub const ApplicationReceiveResult = struct {
    consumed: usize,
    event: ?Established.ApplicationEvent,
};

const Pending = struct {
    allocator: std.mem.Allocator,
    client_private_key_x25519: ?[key_exchange.secret_len]u8,
    client_private_key: ?[key_exchange.p256.secret_len]u8,
    client_private_key_p384: ?[key_exchange.p384.secret_len]u8,
    client_private_key_p521: ?[key_exchange.p521.secret_len]u8,
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
    local_record_size_limit: ?u16 = null,
    peer_record_size_limit: ?u16 = null,

    fn deinit(self: *Pending) void {
        if (self.client_private_key_x25519) |*private_key| {
            std.crypto.secureZero(u8, private_key);
        }
        if (self.client_private_key) |*private_key| {
            std.crypto.secureZero(u8, private_key);
        }
        if (self.client_private_key_p384) |*private_key| {
            std.crypto.secureZero(u8, private_key);
        }
        if (self.client_private_key_p521) |*private_key| {
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
    local_record_size_limit: ?u16,
    peer_record_size_limit: ?u16,
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
        key_logger: ?key_log.Logger = null,
        now_seconds: u64 = 0,
        stage: Stage = .server_flight,
        records: stream.RecordDeframer = .{},
        messages: stream.HandshakeReassembler(max_handshake_message_len) = .{},
        pending: Pending,

        /// Consume and wipe `config.client_private_key`, append a TLS 1.2-only
        /// ClientHello record, and retain the one-shot P-256 state.
        pub fn init(
            config: Config,
            output: *std.ArrayList(u8),
        ) Error!Self {
            var result: Self = undefined;
            try result.initInto(config, output);
            return result;
        }

        /// Initialize caller-owned storage without returning the inline record
        /// and handshake buffers through an error union.
        pub fn initInto(
            self: *Self,
            config: Config,
            output: *std.ArrayList(u8),
        ) Error!void {
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
            var private_key_x25519: ?[key_exchange.secret_len]u8 =
                if (config.client_private_key_x25519) |value|
                    value.*
                else
                    null;
            if (config.client_private_key_x25519) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key_x25519) |*value| {
                std.crypto.secureZero(u8, value);
            };
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
            var private_key_p521: ?[key_exchange.p521.secret_len]u8 = if (config.client_private_key_p521) |value|
                value.*
            else
                null;
            if (config.client_private_key_p521) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key_p521) |*value| {
                std.crypto.secureZero(u8, value);
            };
            for (config.policy.groups) |group| switch (group) {
                key_exchange.named_group_x25519 => if (private_key_x25519 == null) {
                    return error.UnsupportedProfile;
                },
                key_exchange.named_group_secp256r1 => if (private_key == null) {
                    return error.UnsupportedProfile;
                },
                key_exchange.named_group_secp384r1 => if (private_key_p384 == null) {
                    return error.UnsupportedProfile;
                },
                key_exchange.named_group_secp521r1 => if (private_key_p521 == null) {
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
                .certificate_signature_schemes = config.certificate_signature_schemes,
                .alpn_protocols = config.policy.alpn_protocols,
                .request_ocsp = config.request_ocsp,
                .request_ocsp_multi = config.request_ocsp_multi orelse
                    config.request_ocsp,
                .offer_extended_master_secret = true,
                .record_size_limit = config.policy.record_size_limit,
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
            self.*.allocator = config.allocator;
            self.*.policy = config.policy;
            self.*.server_name = config.server_name;
            self.*.server_verifier = config.server_verifier;
            self.*.client_identity = config.client_identity;
            self.*.key_logger = config.key_log;
            self.*.now_seconds = config.now_seconds;
            self.*.stage = .server_flight;
            self.*.records.buffered = 0;
            self.*.messages.buffered = 0;
            self.*.pending = .{
                .allocator = config.allocator,
                .client_private_key_x25519 = private_key_x25519,
                .client_private_key = private_key,
                .client_private_key_p384 = private_key_p384,
                .client_private_key_p521 = private_key_p521,
                .client_random = config.random,
                .client_hello = owned_hello,
                .resumption = resumption,
                .ticket_resumption = ticket_resumption,
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
                !parsed.offers_secure_renegotiation or
                parsed.record_size_limit != config.policy.record_size_limit)
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

            var private_key_x25519: ?[key_exchange.secret_len]u8 =
                if (config.client_private_key_x25519) |value|
                    value.*
                else
                    null;
            if (config.client_private_key_x25519) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key_x25519) |*value| {
                std.crypto.secureZero(u8, value);
            };
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
            var private_key_p521: ?[key_exchange.p521.secret_len]u8 =
                if (config.client_private_key_p521) |value| value.* else null;
            if (config.client_private_key_p521) |value| {
                std.crypto.secureZero(u8, value);
            }
            errdefer if (private_key_p521) |*value| {
                std.crypto.secureZero(u8, value);
            };
            for (config.policy.groups) |group| switch (group) {
                key_exchange.named_group_x25519 => {
                    if (private_key_x25519 == null or
                        !try parsed.supportsGroup(group))
                    {
                        return error.UnsupportedProfile;
                    }
                },
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
                key_exchange.named_group_secp521r1 => {
                    if (private_key_p521 == null or
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
                .key_logger = config.key_log,
                .now_seconds = config.now_seconds,
                .pending = .{
                    .allocator = config.allocator,
                    .client_private_key_x25519 = private_key_x25519,
                    .client_private_key = private_key,
                    .client_private_key_p384 = private_key_p384,
                    .client_private_key_p521 = private_key_p521,
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
            var established: Established = undefined;
            const result = try self.receiveInto(
                input,
                output,
                &established,
            );
            return .{
                .consumed = result.consumed,
                .event = if (result.event) |event| switch (event) {
                    .client_flight => .{ .client_flight = {} },
                    .change_cipher_spec => .{ .change_cipher_spec = {} },
                    .peer_alert => |received| .{ .peer_alert = received },
                    .established => .{ .established = established },
                } else null,
            };
        }

        /// Feed transport bytes and write an established connection directly
        /// into caller-owned storage when the returned event is `.established`.
        pub fn receiveInto(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
            established_output: *Established,
        ) Error!ReceiveIntoResult {
            if (self.stage == .failed) return error.ConnectionFailed;
            return self.receiveInner(
                input,
                output,
                established_output,
            ) catch |err| {
                self.fail();
                return err;
            };
        }

        fn receiveInner(
            self: *Self,
            input: []const u8,
            output: *std.ArrayList(u8),
            established_output: *Established,
        ) Error!ReceiveIntoResult {
            const framed_result = try self.records.push(input);
            const framed = framed_result.framed orelse return .{
                .consumed = framed_result.consumed,
                .event = null,
            };
            if (self.stage != .server_finished) {
                if (self.policy.record_size_limit) |limit| {
                    if (framed.fragment.len > limit) {
                        return error.RecordSizeLimitExceeded;
                    }
                }
            }
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
                    established_output,
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
        ) Error!ReceiveIntoResult {
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
                const pending = &self.pending;
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
            const pending = &self.pending;
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
            const pending = &self.pending;
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
            try validateServerOcspNegotiation(
                offered_client_hello.requests_ocsp,
                offered_client_hello.requests_ocsp_multi,
                server_hello.status_request_acknowledged,
                server_hello.status_request_v2_acknowledged,
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
            var ocsp_responses: ?[]?[]const u8 = null;
            defer if (ocsp_responses) |responses| {
                self.allocator.free(responses);
            };
            const ocsp_response: ?[]const u8 = if (messages.certificate_status) |status|
                if (server_hello.status_request_v2_acknowledged) blk: {
                    const responses = try handshake.parseCertificateStatusV2(
                        self.allocator,
                        status,
                        certificate.entries.len,
                    );
                    ocsp_responses = responses;
                    break :blk responses[0];
                } else try handshake.parseCertificateStatus(status)
            else
                null;
            if (!try offered_client_hello.supportsCertificateChain(
                certificate.entries,
            )) {
                return error.UnsupportedSignatureScheme;
            }
            if (ocsp_responses) |responses| {
                try self.server_verifier.verifyTrustWithOcspResponses(
                    self.server_name,
                    certificate.entries,
                    responses,
                );
            } else {
                try self.server_verifier.verifyTrustWithOcsp(
                    self.server_name,
                    certificate.entries,
                    ocsp_response,
                );
            }
            const server_key_exchange =
                try handshake.parseAndVerifyServerKeyExchangeWithVerifier(
                    messages.server_key_exchange,
                    certificate.entries[0],
                    pending.client_random,
                    server_hello.random,
                    server_hello.suite,
                    self.policy,
                    self.server_verifier,
                );
            try handshake.parseServerHelloDone(messages.server_hello_done);

            var client_public_storage =
                [_]u8{0} ** key_exchange.p521.public_len;
            var shared_storage = [_]u8{0} ** key_exchange.p521.shared_len;
            const client_public: []const u8 = switch (server_key_exchange.group) {
                key_exchange.named_group_x25519 => blk: {
                    const private_key = pending.client_private_key_x25519 orelse
                        return error.UnsupportedProfile;
                    const public = try key_exchange.publicKey(private_key);
                    client_public_storage[0..public.len].* = public;
                    const shared = try key_exchange.sharedSecret(
                        private_key,
                        server_key_exchange.public_key,
                    );
                    shared_storage[0..shared.len].* = shared;
                    break :blk client_public_storage[0..public.len];
                },
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
                    client_public_storage[0..public.len].* = public;
                    const shared = try key_exchange.p384.sharedSecret(
                        private_key,
                        server_key_exchange.public_key,
                    );
                    shared_storage[0..shared.len].* = shared;
                    break :blk client_public_storage[0..public.len];
                },
                key_exchange.named_group_secp521r1 => blk: {
                    const private_key = pending.client_private_key_p521 orelse
                        return error.UnsupportedProfile;
                    const public = try key_exchange.p521.publicKey(private_key);
                    client_public_storage = public;
                    shared_storage = try key_exchange.p521.sharedSecret(
                        private_key,
                        server_key_exchange.public_key,
                    );
                    break :blk &client_public_storage;
                },
                else => return error.UnsupportedProfile,
            };
            const shared_secret: []const u8 = switch (server_key_exchange.group) {
                key_exchange.named_group_x25519 => shared_storage[0..key_exchange.shared_len],
                key_exchange.named_group_secp256r1 => shared_storage[0..key_exchange.p256.shared_len],
                key_exchange.named_group_secp384r1 => shared_storage[0..key_exchange.p384.shared_len],
                key_exchange.named_group_secp521r1 => &shared_storage,
                else => unreachable,
            };
            defer std.crypto.secureZero(u8, &client_public_storage);
            defer std.crypto.secureZero(u8, &shared_storage);
            if (pending.client_private_key_x25519) |*value| {
                std.crypto.secureZero(u8, value);
            }
            if (pending.client_private_key) |*value| {
                std.crypto.secureZero(u8, value);
            }
            if (pending.client_private_key_p384) |*value| {
                std.crypto.secureZero(u8, value);
            }
            if (pending.client_private_key_p521) |*value| {
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
            const selected_client_identity: ?client_auth.ClientIdentity =
                if (request) |parsed_request|
                    if (self.client_identity) |identity|
                        if (certificateRequestAcceptsIdentity(
                            parsed_request,
                            identity,
                        )) identity else null
                    else
                        null
                else
                    null;
            if (request != null) {
                const certificate_start = client_messages.items.len;
                if (selected_client_identity) |identity| {
                    try identity.validate();
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
                try appendPlaintextRecordsLimited(
                    &client_records,
                    self.allocator,
                    22,
                    0x0303,
                    client_messages.items[certificate_start..],
                    server_hello.peer_record_size_limit orelse
                        tls12.max_plaintext_len,
                );
            }

            const client_key_exchange_start = client_messages.items.len;
            try handshake.writeClientKeyExchange(
                &client_messages,
                self.allocator,
                client_public,
            );
            state.update(client_messages.items[client_key_exchange_start..]);
            try appendPlaintextRecordsLimited(
                &client_records,
                self.allocator,
                22,
                0x0303,
                client_messages.items[client_key_exchange_start..],
                server_hello.peer_record_size_limit orelse
                    tls12.max_plaintext_len,
            );
            const extended_master_session_hash = state.digest();

            if (selected_client_identity) |identity| {
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
                    identity.signer,
                    signed_transcript.items,
                );
                state.update(client_messages.items[verify_start..]);
                try appendPlaintextRecordsLimited(
                    &client_records,
                    self.allocator,
                    22,
                    0x0303,
                    client_messages.items[verify_start..],
                    server_hello.peer_record_size_limit orelse
                        tls12.max_plaintext_len,
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
            var client_traffic = try tls12.TrafficState.initWithPlaintextLimit(
                keys.client,
                server_hello.peer_record_size_limit,
            );
            errdefer client_traffic.deinit();
            var server_traffic = try tls12.TrafficState.initWithPlaintextLimit(
                keys.server,
                server_hello.local_record_size_limit,
            );
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
            pending.local_record_size_limit = server_hello.local_record_size_limit;
            pending.peer_record_size_limit = server_hello.peer_record_size_limit;
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
            const pending = &self.pending;
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
            if (pending.client_private_key_x25519) |*private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            if (pending.client_private_key) |*private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            if (pending.client_private_key_p384) |*private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            if (pending.client_private_key_p521) |*private_key| {
                std.crypto.secureZero(u8, private_key);
            }
            pending.suite = session.suite;
            pending.server_random = server_hello.random;
            pending.transcript_state = state;
            pending.master_secret = session.master_secret;
            pending.client_traffic = try tls12.TrafficState.initWithPlaintextLimit(
                keys.client,
                server_hello.peer_record_size_limit,
            );
            pending.server_traffic = try tls12.TrafficState.initWithPlaintextLimit(
                keys.server,
                server_hello.local_record_size_limit,
            );
            pending.peer_certificate_chain = empty_chain;
            pending.selected_alpn = selected_alpn;
            pending.local_record_size_limit = server_hello.local_record_size_limit;
            pending.peer_record_size_limit = server_hello.peer_record_size_limit;
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
        ) Error!ReceiveIntoResult {
            if (framed.content_type == 21) {
                return self.acceptPlaintextAlert(consumed, framed.fragment);
            }
            if (framed.content_type == 22) {
                const pending = &self.pending;
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
            const pending = &self.pending;
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
            established_output: *Established,
        ) Error!ReceiveIntoResult {
            const pending = &self.pending;
            var plaintext: [64]u8 = undefined;
            const opened = try pending.server_traffic.?.open(
                framed.bytes,
                &plaintext,
            );
            if (opened.content_type == 21) {
                const received = try alert.parse(plaintext[0..opened.len]);
                const event: ReceiveIntoEvent = .{ .peer_alert = received };
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
            self.establishInto(established_output);
            return .{
                .consumed = consumed,
                .event = .{ .established = {} },
            };
        }

        fn acceptPlaintextAlert(
            self: *Self,
            consumed: usize,
            bytes: []const u8,
        ) Error!ReceiveIntoResult {
            const received = try alert.parse(bytes);
            const event: ReceiveIntoEvent = .{ .peer_alert = received };
            self.fail();
            return .{ .consumed = consumed, .event = event };
        }

        fn establishInto(
            self: *Self,
            established_output: *Established,
        ) void {
            const pending = &self.pending;
            key_log.emit(
                self.key_logger,
                key_log.client_random,
                &pending.client_random,
                &pending.master_secret.?,
            );
            established_output.*.allocator = self.allocator;
            established_output.*.read = pending.server_traffic.?;
            established_output.*.write = pending.client_traffic.?;
            established_output.*.master_secret = pending.master_secret.?;
            established_output.*.client_random = pending.client_random;
            established_output.*.server_random = pending.server_random.?;
            established_output.*.suite = pending.suite.?;
            established_output.*.selected_alpn = pending.selected_alpn;
            established_output.*.peer_certificate_chain =
                pending.peer_certificate_chain.?;
            established_output.*.resumed = pending.resumed;
            established_output.*.session_id = pending.negotiated_session_id;
            established_output.*.session_id_len =
                pending.negotiated_session_id_len;
            established_output.*.session_ticket = pending.new_session_ticket;
            established_output.*.session_ticket_lifetime_hint_seconds =
                pending.new_session_ticket_lifetime_hint_seconds;
            established_output.*.local_record_size_limit =
                pending.local_record_size_limit;
            established_output.*.peer_record_size_limit =
                pending.peer_record_size_limit;
            established_output.*.records.buffered = 0;
            established_output.*.local_closed = false;
            established_output.*.peer_closed = false;
            established_output.*.failed = false;
            established_output.*.secrets_extracted = false;
            pending.server_traffic = null;
            pending.client_traffic = null;
            pending.master_secret = null;
            pending.selected_alpn = null;
            pending.peer_certificate_chain = null;
            pending.new_session_ticket = null;
            pending.deinit();
            self.stage = .established;
        }

        fn fail(self: *Self) void {
            self.cleanup();
            self.stage = .failed;
        }

        fn cleanup(self: *Self) void {
            switch (self.stage) {
                .server_flight,
                .server_change_cipher_spec,
                .server_finished,
                => self.pending.deinit(),
                .established, .failed => {},
            }
        }
    };
}

fn validatePolicy(policy: handshake.Policy) Error!void {
    if (policy.cipher_suites.len == 0 or policy.groups.len == 0) {
        return error.UnsupportedProfile;
    }
    for (policy.groups) |group| {
        if (group != key_exchange.named_group_x25519 and
            group != key_exchange.named_group_secp256r1 and
            group != key_exchange.named_group_secp384r1 and
            group != key_exchange.named_group_secp521r1)
        {
            return error.UnsupportedProfile;
        }
    }
    if (policy.record_size_limit) |limit| {
        _ = record_size_limit.validateTls12(limit) catch
            return error.UnsupportedProfile;
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

fn validateServerOcspNegotiation(
    offered: bool,
    offered_multi: bool,
    acknowledged: bool,
    acknowledged_multi: bool,
    certificate_status: ?[]const u8,
) Error!void {
    if ((acknowledged and !offered) or
        (acknowledged_multi and !offered_multi) or
        (acknowledged and acknowledged_multi) or
        (acknowledged or acknowledged_multi) !=
            (certificate_status != null))
    {
        return error.UnexpectedHandshakeMessage;
    }
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
    return appendPlaintextRecordsLimited(
        output,
        allocator,
        content_type,
        legacy_version,
        payload,
        record13.max_plaintext_len,
    );
}

fn appendPlaintextRecordsLimited(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    content_type: u8,
    legacy_version: u16,
    payload: []const u8,
    max_fragment_plaintext: usize,
) std.mem.Allocator.Error!void {
    std.debug.assert(max_fragment_plaintext != 0);
    var offset: usize = 0;
    while (offset < payload.len) {
        const len = @min(max_fragment_plaintext, payload.len - offset);
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

const TestMasterSecretLog = struct {
    calls: usize = 0,
    label: []const u8 = &.{},
    client_random: [32]u8 = undefined,
    secret_bytes: [tls12.master_secret_len]u8 = undefined,

    fn logger(self: *TestMasterSecretLog) key_log.Logger {
        return .{
            .context = self,
            .log_fn = TestMasterSecretLog.record,
        };
    }

    fn record(
        context: ?*anyopaque,
        label: []const u8,
        client_random_bytes: *const [32]u8,
        secret_bytes: []const u8,
    ) void {
        const self: *TestMasterSecretLog = @ptrCast(@alignCast(context.?));
        std.debug.assert(secret_bytes.len == tls12.master_secret_len);
        self.calls += 1;
        self.label = label;
        self.client_random = client_random_bytes.*;
        self.secret_bytes = secret_bytes[0..tls12.master_secret_len].*;
    }
};

test "TLS 1.2 client and server authenticate and exchange application data" {
    const allocator = std.testing.allocator;
    var client_key_log: TestMasterSecretLog = .{};
    var server_key_log: TestMasterSecretLog = .{};
    const server_module = @import("tls12_server_connection.zig");
    const rsa = @import("../crypto/sign/rsa.zig");
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
        .record_size_limit = 256,
    };
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    const Client = ClientConnection(64 * 1024, 64 * 1024);
    var client: Client = undefined;
    try client.initInto(.{
        .allocator = allocator,
        .random = [_]u8{0x91} ** 32,
        .server_name = "localhost",
        .client_private_key = &client_private,
        .policy = policy,
        .server_verifier = .{ .verify_trust = expectTestOcsp },
        .request_session_ticket = true,
        .key_log = client_key_log.logger(),
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
    var server: Server = undefined;
    server.initInto(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0x92} ** 32,
        .server_private_key = &server_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
        .key_log = server_key_log.logger(),
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

    var established_server_storage: server_module.Established = undefined;
    var established_server: ?*server_module.Established = null;
    for (client_wire.items) |byte| {
        const received = try server.receiveInto(
            &.{byte},
            &server_wire,
            &established_server_storage,
        );
        try std.testing.expectEqual(@as(usize, 1), received.consumed);
        if (received.event) |event| switch (event) {
            .server_flight,
            .client_key_exchange,
            .change_cipher_spec,
            => {},
            .peer_alert => return error.UnexpectedPeerAlert,
            .established => established_server = &established_server_storage,
        };
    }
    try std.testing.expect(established_server != null);
    defer established_server.?.deinit();
    client_wire.clearRetainingCapacity();

    var established_client_storage: Established = undefined;
    var established_client: ?*Established = null;
    for (server_wire.items) |byte| {
        const received = try client.receiveInto(
            &.{byte},
            &client_wire,
            &established_client_storage,
        );
        try std.testing.expectEqual(@as(usize, 1), received.consumed);
        if (received.event) |event| switch (event) {
            .client_flight => return error.UnexpectedClientFlight,
            .change_cipher_spec => {},
            .peer_alert => return error.UnexpectedPeerAlert,
            .established => established_client = &established_client_storage,
        };
    }
    try std.testing.expect(established_client != null);
    defer established_client.?.deinit();
    try std.testing.expectEqual(@as(usize, 1), client_key_log.calls);
    try std.testing.expectEqual(@as(usize, 1), server_key_log.calls);
    try std.testing.expectEqualStrings(key_log.client_random, client_key_log.label);
    try std.testing.expectEqualStrings(key_log.client_random, server_key_log.label);
    try std.testing.expectEqual([_]u8{0x91} ** 32, client_key_log.client_random);
    try std.testing.expectEqual(client_key_log.client_random, server_key_log.client_random);
    try std.testing.expectEqual(client_key_log.secret_bytes, server_key_log.secret_bytes);
    try std.testing.expectEqual(
        established_client.?.master_secret,
        client_key_log.secret_bytes,
    );
    try std.testing.expectEqualStrings(
        "h2",
        established_client.?.selected_alpn.?,
    );
    try std.testing.expectEqual(@as(usize, 1), established_client.?.peer_certificate_chain.len);
    try std.testing.expect(established_client.?.session_ticket != null);
    try std.testing.expectEqual(
        @as(?u16, 256),
        established_client.?.local_record_size_limit,
    );
    try std.testing.expectEqual(
        @as(?u16, 256),
        established_client.?.peer_record_size_limit,
    );
    try std.testing.expectEqual(
        @as(?u16, 256),
        established_server.?.local_record_size_limit,
    );
    try std.testing.expectEqual(
        @as(?u16, 256),
        established_server.?.peer_record_size_limit,
    );

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

    const client_fragment = try established_client.?
        .sealApplicationDataFragment("client fragmented", 6, &application_record);
    try std.testing.expectEqual(@as(usize, 6), client_fragment.plaintext_consumed);
    const server_fragment = try established_server.?.receive(
        application_record[0..client_fragment.output_written],
    );
    try std.testing.expectEqualStrings(
        "client",
        server_fragment.event.?.application_data,
    );

    const response_fragment = try established_server.?
        .sealApplicationDataFragment("server fragmented", 6, &application_record);
    try std.testing.expectEqual(@as(usize, 6), response_fragment.plaintext_consumed);
    const client_fragment_received = try established_client.?.receive(
        application_record[0..response_fragment.output_written],
    );
    try std.testing.expectEqualStrings(
        "server",
        client_fragment_received.event.?.application_data,
    );

    var oversized_record: [512]u8 = undefined;
    try std.testing.expectError(
        error.RecordSizeLimitExceeded,
        established_client.?.sealApplicationData(
            &([_]u8{0xaa} ** 257),
            &oversized_record,
        ),
    );
    const limited_fragment = try established_client.?
        .sealApplicationDataFragment(
        &([_]u8{0xbb} ** 257),
        257,
        &oversized_record,
    );
    try std.testing.expectEqual(
        @as(usize, 256),
        limited_fragment.plaintext_consumed,
    );
    const limited_received = try established_server.?.receive(
        oversized_record[0..limited_fragment.output_written],
    );
    try std.testing.expectEqual(
        @as(usize, 256),
        limited_received.event.?.application_data.len,
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

    var client_secrets = try established_client.?.dangerousExtractSecrets();
    defer client_secrets.deinit();
    var server_secrets = try established_server.?.dangerousExtractSecrets();
    defer server_secrets.deinit();
    try std.testing.expectEqual(traffic_secrets.Version.tls12, client_secrets.version);
    // Sequence zero protected each side's Finished before these two
    // application records, so the next record uses sequence three.
    try std.testing.expectEqual(@as(u64, 4), client_secrets.tx.sequence_number);
    try std.testing.expectEqual(@as(u64, 3), client_secrets.rx.sequence_number);
    try std.testing.expectEqual(@as(u64, 3), server_secrets.tx.sequence_number);
    try std.testing.expectEqual(@as(u64, 4), server_secrets.rx.sequence_number);
    try std.testing.expectEqualSlices(
        u8,
        client_secrets.tx.key(),
        server_secrets.rx.key(),
    );
    try std.testing.expectEqualSlices(
        u8,
        client_secrets.rx.key(),
        server_secrets.tx.key(),
    );
    try std.testing.expectEqual(client_secrets.tx.iv, server_secrets.rx.iv);
    try std.testing.expectEqual(client_secrets.rx.iv, server_secrets.tx.iv);
    try std.testing.expectError(
        error.ConnectionFailed,
        established_client.?.sealApplicationData("after extraction", &application_record),
    );
    try std.testing.expectError(
        error.ConnectionFailed,
        established_server.?.dangerousExtractSecrets(),
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
            .client_private_key_x25519 = null,
            .client_private_key = [_]u8{0} ** key_exchange.p256.secret_len,
            .client_private_key_p384 = null,
            .client_private_key_p521 = null,
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

test "high-level TLS 1.2 client requests OCSP by default with opt-out" {
    const allocator = std.testing.allocator;
    const Client = ClientConnection(4096, 256);

    var default_private = [_]u8{0} ** key_exchange.p256.secret_len;
    default_private[default_private.len - 1] = 1;
    var default_wire: std.ArrayList(u8) = .empty;
    defer default_wire.deinit(allocator);
    var default_client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xa7} ** 32,
        .server_name = "example.com",
        .client_private_key = &default_private,
        .server_verifier = .{},
    }, &default_wire);
    defer default_client.deinit();
    const default_hello = try client_hello.parse(
        default_wire.items[record13.header_len..],
    );
    try std.testing.expect(default_hello.requests_ocsp);
    try std.testing.expect(default_hello.requests_ocsp_multi);

    var opt_out_private = [_]u8{0} ** key_exchange.p256.secret_len;
    opt_out_private[opt_out_private.len - 1] = 2;
    var opt_out_wire: std.ArrayList(u8) = .empty;
    defer opt_out_wire.deinit(allocator);
    var opt_out_client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xa8} ** 32,
        .server_name = "example.com",
        .client_private_key = &opt_out_private,
        .request_ocsp = false,
        .server_verifier = .{},
    }, &opt_out_wire);
    defer opt_out_client.deinit();
    const opt_out_hello = try client_hello.parse(
        opt_out_wire.items[record13.header_len..],
    );
    try std.testing.expect(!opt_out_hello.requests_ocsp);
    try std.testing.expect(!opt_out_hello.requests_ocsp_multi);
}

test "TLS 1.2 client and server complete AEAD suites across groups" {
    const allocator = std.testing.allocator;
    const rsa = @import("../crypto/sign/rsa.zig");
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
            null,
            false,
        );
    }
    try completeSuiteHandshake(
        allocator,
        .ecdhe_rsa_aes_128_gcm_sha256,
        key_exchange.named_group_x25519,
        &rsa_certificate,
        .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
        .{ .verify_trust = acceptTestCertificate },
        null,
        null,
        null,
        false,
    );
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
        null,
        false,
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
        &.{},
        true,
    );
}

test "TLS 1.2 client authentication supports P-521 CertificateVerify" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const server_key = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0xc6} ** Ecdsa.KeyPair.seed_length,
    );
    const server_public = server_key.public_key.toUncompressedSec1();
    var client_secret = try p521.SecretKey.fromBytes(decodeHex(
        "00123456789abcdef00112233445566778899aabbccddeeff1021324354657687" ++
            "98a9bacbdcedfe0f112233445566778899aabbccddeeff00123456789abcdef1234",
    ));
    defer client_secret.deinit();
    var client_key = try p521.KeyPair.fromSecretKey(client_secret);
    defer client_key.deinit();
    const client_public = client_key.public_key.toUncompressedSec1();

    try completeSuiteHandshake(
        std.testing.allocator,
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        key_exchange.named_group_secp256r1,
        &server_public,
        .{ .ecdsa_p256_sha256 = .{ .key_pair = server_key } },
        .{ .pinned_ecdsa_p256_public_key = server_public },
        .{
            .certificate_chain = &.{&client_public},
            .signer = .{ .ecdsa_p521_sha512 = .{
                .key_pair = &client_key,
                .io = std.testing.io,
            } },
        },
        .{
            .verifier = .{
                .pinned_ecdsa_p521_public_key = client_public,
            },
            .requirement = .required,
        },
        &.{},
        true,
    );
}

test "TLS 1.2 client identity selection requires type and signature scheme" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0xc8} ** Ecdsa.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toUncompressedSec1();
    const identity = client_auth.ClientIdentity{
        .certificate_chain = &.{&public_key},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };
    const ecdsa_scheme = [_]u8{ 0x04, 0x03 };
    const rsa_scheme = [_]u8{ 0x08, 0x04 };
    try std.testing.expect(certificateRequestAcceptsIdentity(.{
        .certificate_types = &.{tls12_ecdsa_sign_certificate_type},
        .signature_algorithms = &ecdsa_scheme,
        .certificate_authorities = &.{},
    }, identity));
    try std.testing.expect(!certificateRequestAcceptsIdentity(.{
        .certificate_types = &.{tls12_ecdsa_sign_certificate_type},
        .signature_algorithms = &rsa_scheme,
        .certificate_authorities = &.{},
    }, identity));
    try std.testing.expect(!certificateRequestAcceptsIdentity(.{
        .certificate_types = &.{tls12_rsa_sign_certificate_type},
        .signature_algorithms = &ecdsa_scheme,
        .certificate_authorities = &.{},
    }, identity));
}

test "TLS 1.2 client authentication honors requested CA names" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const server_key = try Ecdsa.KeyPair.generateDeterministic(
        [_]u8{0xc7} ** Ecdsa.KeyPair.seed_length,
    );
    const server_public = server_key.public_key.toUncompressedSec1();
    const rsa = @import("../crypto/sign/rsa.zig");
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    const client_certificate = decodeHex(vectors.certificate_hex);
    const client_private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
    const client_private_key = try rsa.PrivateKey.fromDer(
        &client_private_key_der,
    );
    var prepared_client_key = try client_private_key.prepare();
    defer prepared_client_key.deinit();
    const parsed_client_certificate = try std.crypto.Certificate.parse(.{
        .buffer = &client_certificate,
        .index = 0,
    });
    var matching_ca_storage: [512]u8 = undefined;
    const matching_ca_name = try wrapDerSequenceForTest(
        parsed_client_certificate.issuer(),
        &matching_ca_storage,
    );
    const unrelated_ca_name = [_]u8{
        0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x0c,
    } ++ "Unrelated CA".*;

    try completeSuiteHandshake(
        std.testing.allocator,
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        key_exchange.named_group_secp256r1,
        &server_public,
        .{ .ecdsa_p256_sha256 = .{ .key_pair = server_key } },
        .{ .pinned_ecdsa_p256_public_key = server_public },
        .{
            .certificate_chain = &.{&client_certificate},
            .signer = .{ .rsa_pss = .{
                .prepared_key = &prepared_client_key,
                .io = std.testing.io,
            } },
        },
        .{
            .verifier = .{ .verify_trust = acceptTestCertificate },
            .requirement = .required,
        },
        &.{matching_ca_name},
        true,
    );
    try completeSuiteHandshake(
        std.testing.allocator,
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        key_exchange.named_group_secp256r1,
        &server_public,
        .{ .ecdsa_p256_sha256 = .{ .key_pair = server_key } },
        .{ .pinned_ecdsa_p256_public_key = server_public },
        .{
            .certificate_chain = &.{&client_certificate},
            .signer = .{ .rsa_pss = .{
                .prepared_key = &prepared_client_key,
                .io = std.testing.io,
            } },
        },
        .{
            .verifier = .{ .verify_trust = acceptTestCertificate },
            .requirement = .optional,
        },
        &.{&unrelated_ca_name},
        false,
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
    client_certificate_authorities: ?[]const []const u8,
    expect_client_certificate: bool,
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
        .client_certificate_authorities = client_certificate_authorities,
    };
    var client_private_x25519 = [_]u8{0x71} ** key_exchange.secret_len;
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
        .client_private_key_x25519 = if (group ==
            key_exchange.named_group_x25519)
            &client_private_x25519
        else
            null,
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
    var server_private_x25519 = [_]u8{0x72} ** key_exchange.secret_len;
    var server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    server_private[server_private.len - 1] = 8;
    var server_private_p384 = [_]u8{0} ** key_exchange.p384.secret_len;
    server_private_p384[server_private_p384.len - 1] = 8;
    var server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0xb3} ** 32,
        .server_private_key_x25519 = if (group ==
            key_exchange.named_group_x25519)
            &server_private_x25519
        else
            null,
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
    if (expect_client_certificate) {
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

fn wrapDerSequenceForTest(
    contents: []const u8,
    storage: []u8,
) ![]const u8 {
    const header_len: usize = if (contents.len < 128) 2 else 3;
    if (contents.len > std.math.maxInt(u8) or
        storage.len < header_len + contents.len)
    {
        return error.BufferTooShort;
    }
    storage[0] = 0x30;
    if (header_len == 2) {
        storage[1] = @intCast(contents.len);
    } else {
        storage[1] = 0x81;
        storage[2] = @intCast(contents.len);
    }
    @memcpy(storage[header_len..][0..contents.len], contents);
    return storage[0 .. header_len + contents.len];
}

test "TLS 1.2 OCSP negotiation rejects missing and unsolicited status" {
    var status: std.ArrayList(u8) = .empty;
    defer status.deinit(std.testing.allocator);
    try handshake.writeCertificateStatus(
        &status,
        std.testing.allocator,
        "ocsp",
    );
    try validateServerOcspNegotiation(true, false, true, false, status.items);
    try std.testing.expectEqualStrings(
        "ocsp",
        try handshake.parseCertificateStatus(status.items),
    );
    try validateServerOcspNegotiation(true, false, false, false, null);
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspNegotiation(true, false, true, false, null),
    );
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspNegotiation(false, false, true, false, status.items),
    );
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspNegotiation(true, false, false, false, status.items),
    );

    var multi_status: std.ArrayList(u8) = .empty;
    defer multi_status.deinit(std.testing.allocator);
    try handshake.writeCertificateStatusV2(
        &multi_status,
        std.testing.allocator,
        &.{ "leaf", "issuer" },
    );
    try validateServerOcspNegotiation(
        true,
        true,
        false,
        true,
        multi_status.items,
    );
    const responses = try handshake.parseCertificateStatusV2(
        std.testing.allocator,
        multi_status.items,
        2,
    );
    defer std.testing.allocator.free(responses);
    try std.testing.expectEqualStrings("leaf", responses[0].?);
    try std.testing.expectEqualStrings("issuer", responses[1].?);
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspNegotiation(
            true,
            true,
            true,
            true,
            multi_status.items,
        ),
    );
    try std.testing.expectError(
        error.UnexpectedHandshakeMessage,
        validateServerOcspNegotiation(
            true,
            false,
            false,
            true,
            multi_status.items,
        ),
    );
}

test "TLS 1.2 RFC 6961 validates leaf and intermediate OCSP responses" {
    const allocator = std.testing.allocator;
    const server_module = @import("tls12_server_connection.zig");
    const rsa = @import("../crypto/sign/rsa.zig");
    const rsa_vectors = @import("../crypto/testdata/rsa_signing.zig");
    const path_vectors = @import("../x509/testdata/path_vectors.zig");
    const trust = @import("../x509/trust.zig");
    const root = decodeHex(path_vectors.rsa_multi_staple_root_hex);
    const intermediate = decodeHex(
        path_vectors.rsa_multi_staple_intermediate_hex,
    );
    const leaf = decodeHex(path_vectors.rsa_multi_staple_leaf_hex);
    const leaf_ocsp = decodeHex(path_vectors.rsa_multi_staple_leaf_ocsp_hex);
    const intermediate_ocsp = decodeHex(
        path_vectors.rsa_multi_staple_intermediate_ocsp_hex,
    );
    const private_key_der = decodeHex(rsa_vectors.private_key_pkcs8_hex);
    const private_key = try rsa.PrivateKey.fromDer(&private_key_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const now = 1_790_821_380;

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &root);
    try bundle.parseCert(allocator, 0, now);
    const verifier = trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now,
        .stapled_ocsp = .if_present,
    };
    const responses = [_]?[]const u8{ &leaf_ocsp, &intermediate_ocsp };
    const policy = handshake.Policy{
        .ocsp_responses = &responses,
    };

    var client_private = [_]u8{0} ** key_exchange.p256.secret_len;
    client_private[client_private.len - 1] = 11;
    var client_wire: std.ArrayList(u8) = .empty;
    defer client_wire.deinit(allocator);
    const Client = ClientConnection(64 * 1024, 64 * 1024);
    var client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xd6} ** 32,
        .server_name = "multi-staple.localhost",
        .client_private_key = &client_private,
        .policy = policy,
        .server_verifier = auth.ClientVerifier.fromTrustVerifier(verifier.clientVerifier()),
    }, &client_wire);
    defer client.deinit();

    var server_private = [_]u8{0} ** key_exchange.p256.secret_len;
    server_private[server_private.len - 1] = 12;
    const Server = server_module.ServerConnection(64 * 1024, 64 * 1024);
    var server = Server.init(.{
        .allocator = allocator,
        .policy = policy,
        .server_random = [_]u8{0xd7} ** 32,
        .server_private_key = &server_private,
        .certificate_chain = &.{ &leaf, &intermediate },
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = std.testing.io,
        } },
    });
    defer server.deinit();

    var server_wire: std.ArrayList(u8) = .empty;
    defer server_wire.deinit(allocator);
    const server_result = try server.receive(client_wire.items, &server_wire);
    try std.testing.expectEqual(
        std.meta.Tag(server_module.Event).server_flight,
        std.meta.activeTag(server_result.event.?),
    );
    client_wire.clearRetainingCapacity();
    const client_result = try client.receive(server_wire.items, &client_wire);
    try std.testing.expectEqual(
        std.meta.Tag(Event).client_flight,
        std.meta.activeTag(client_result.event.?),
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
