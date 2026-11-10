//! QUIC TLS client handshake state and flight processing.
//! TLS 1.3 handshake adapters for QUIC CRYPTO streams.
//!
//! QUIC carries TLS handshake bytes in CRYPTO frames and protects packets with
//! QUIC packet keys. It never uses TLS record protection. This adapter keeps
//! that boundary explicit: Vail consumes and emits plaintext handshake
//! messages separated by encryption level and returns the packet-protection
//! keys that a transport implementation installs into its
//! Initial/Handshake/1-RTT packet spaces.

const std = @import("std");

const alert = @import("../../tls/alert.zig");
const application_settings = @import("../../tls/handshake/application_settings.zig");
const auth = @import("../../tls/handshake/auth.zig");
const certificate_compression = @import("../../tls/handshake/certificate_compression.zig");
const cipher_suite = @import("../../tls/crypto/cipher_suite.zig");
const client_auth = @import("../../tls/handshake/client_auth.zig");
const client_handshake = @import("../../tls/handshake/client_handshake.zig");
const client_hello = @import("../../tls/handshake/client_hello.zig");
const ech = @import("../../tls/handshake/ech.zig");
const key_schedule = @import("../../tls/crypto/key_schedule.zig");
const psk = @import("../../tls/crypto/psk.zig");
const secret = @import("../../tls/crypto/secret.zig");
const server_flight = @import("../../tls/handshake/server_flight.zig");
const server_hello = @import("../../tls/handshake/server_hello.zig");
const ticket = @import("../../tls/crypto/ticket.zig");
const ticket_keyring = @import("../../tls/crypto/ticket_keyring.zig");
const transcript = @import("../../tls/crypto/transcript.zig");
const traffic = @import("../traffic_crypto.zig");
const tls_secrets = @import("../tls_secrets.zig");

const common = @import("common.zig");
const Error = common.Error;
const EchStatus = common.EchStatus;
const RetryState = common.RetryState;
const ResumptionPsk = common.ResumptionPsk;
const validateQuicResumption = common.validateQuicResumption;
const validateRetryState = common.validateRetryState;
const clientHelloEchStatus = common.clientHelloEchStatus;
const freeCertificateChain = common.freeCertificateChain;
const takeHandshakeMessage = common.takeHandshakeMessage;
const ech_required_crypto_error = common.ech_required_crypto_error;
const handshake_type_finished = common.handshake_type_finished;

pub const ClientFlightResult = struct {
    allocator: std.mem.Allocator,
    peer_certificate_chain: [][]const u8,
    client_certificate_compression: ?certificate_compression.Algorithm,
    transcript_after_client_finished: transcript.Digest,
    application_settings_codepoint: ?application_settings.Codepoint,
    peer_application_settings: ?[]u8,

    pub fn deinit(self: *ClientFlightResult) void {
        freeCertificateChain(self.allocator, self.peer_certificate_chain);
        if (self.peer_application_settings) |settings| {
            self.allocator.free(settings);
        }
        self.* = undefined;
    }
};

pub const ClientOptions = struct {
    client_hello_bytes: []const u8,
    /// ServerHello carried in Initial CRYPTO data.
    server_hello_bytes: []const u8,
    /// EncryptedExtensions through Finished after QUIC packet protection has
    /// been removed and CRYPTO stream data has been reassembled.
    server_handshake_crypto: []const u8,
    shared_secret: []const u8,
    server_verifier: auth.ClientVerifier,
    server_name: ?[]const u8,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{},
    max_decompressed_certificate_len: usize = 64 * 1024,
    server_certificate_type: auth.CertificateType = .x509,
    client_identity: ?client_auth.ClientIdentity = null,
    application_settings: []const application_settings.Setting = &.{},
    resumption: ?ResumptionPsk = null,
    retry: ?RetryState = null,
    labels: traffic.Labels = traffic.labels_v1,
};

/// Authenticated TLS state and QUIC packet keys for a completed server flight.
/// `selected_alpn`, `peer_transport_parameters`, and the certificate chain in
/// `verified` are owned by this value.
pub const ClientResult = struct {
    allocator: std.mem.Allocator,
    verified: client_handshake.Result,
    selected_alpn: []u8,
    peer_transport_parameters: []u8,
    handshake_packet_keys: tls_secrets.DirectionalKeys,
    application_packet_keys: tls_secrets.DirectionalKeys,
    resumed: bool,
    ech_accepted: bool,

    pub fn deinit(self: *ClientResult) void {
        self.allocator.free(self.selected_alpn);
        self.allocator.free(self.peer_transport_parameters);
        self.verified.deinit();
        self.handshake_packet_keys.deinit();
        self.application_packet_keys.deinit();
        self.* = undefined;
    }
};

pub const EchRejectionOptions = struct {
    outer_client_hello_bytes: []const u8,
    server_hello_bytes: []const u8,
    server_handshake_crypto: []const u8,
    shared_secret: []const u8,
    server_verifier: auth.ClientVerifier,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{},
    max_decompressed_certificate_len: usize = 64 * 1024,
    server_certificate_type: auth.CertificateType = .x509,
    retry: ?RetryState = null,
};

/// Authenticated ECH rejection. QUIC transports close the connection with
/// `crypto_error_code` and may cache `retry_configs` only for a fresh attempt.
pub const EchRejection = struct {
    allocator: std.mem.Allocator,
    retry_configs: ?[]u8,
    crypto_error_code: u64 = ech_required_crypto_error,

    pub fn deinit(self: *EchRejection) void {
        if (self.retry_configs) |configs| self.allocator.free(configs);
        self.* = undefined;
    }
};

/// Derive the client write keys used for QUIC 0-RTT packets. The ClientHello
/// must contain an authenticated binder and an early_data offer for this PSK.
pub fn clientEarlyPacketKeys(
    client_hello_bytes: []const u8,
    resumption: ResumptionPsk,
    labels: traffic.Labels,
) Error!traffic.Keys {
    try validateQuicResumption(resumption);
    const parsed = try client_hello.parse(client_hello_bytes);
    if (!parsed.offersTls13() or
        parsed.pre_shared_key == null or
        !parsed.early_data)
    {
        return error.InvalidEarlyDataConfiguration;
    }
    if (resumption.max_early_data_size == null or
        resumption.max_early_data_size.? == 0 or
        resumption.age_policy == null or
        resumption.secret.hash != resumption.suite.hash() or
        !parsed.hasCipherSuite(resumption.suite.wireValue()))
    {
        return error.InvalidEarlyDataConfiguration;
    }
    const offer = try psk.parseClientOfferForHash(
        client_hello_bytes,
        resumption.secret.hash,
    );
    try psk.verifyClientOfferForSecret(
        client_hello_bytes,
        offer,
        resumption.identity,
        resumption.secret,
        null,
    );
    if (resumption.age_policy) |age_policy| {
        try psk.validateTicketAge(offer, age_policy);
    }
    return tls_secrets.clientEarlyKeys(
        resumption.suite,
        resumption.secret,
        transcript.hashFor(resumption.secret.hash, &.{client_hello_bytes}),
        labels,
    );
}

/// Authenticate a plaintext QUIC Handshake CRYPTO flight, emit the plaintext
/// client authentication/Finished flight, and derive Handshake plus 1-RTT
/// packet keys. A validated `RetryState` carries HRR transcript state. ECH
/// remains reserved for a stateful QUIC connection driver.
pub fn writeClientCryptoFlight(
    handshake_crypto: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: ClientOptions,
) Error!ClientResult {
    const output_start = handshake_crypto.items.len;
    errdefer handshake_crypto.shrinkRetainingCapacity(output_start);
    if (options.resumption) |resumption| {
        try validateQuicResumption(resumption);
    }

    const parsed_client = try client_hello.parse(options.client_hello_bytes);
    if (!parsed_client.offersTls13()) return error.InvalidClientHello;
    if (parsed_client.quic_transport_parameters == null) {
        return error.MissingQuicTransportParameters;
    }
    if (parsed_client.alpn_protocols.len == 0) return error.MissingAlpn;
    const ech_status = try clientHelloEchStatus(parsed_client);
    if (ech_status == .rejected) return error.UnsupportedEch;
    const ech_accepted = ech_status == .accepted;
    var offered_resumption: ?psk.Offer = null;
    if (options.resumption) |resumption| {
        if (parsed_client.pre_shared_key == null) return error.MissingPskOffer;
        const offer = try psk.findClientOfferForIdentityForHash(
            options.client_hello_bytes,
            resumption.identity,
            resumption.secret.hash,
        ) orelse return error.InvalidPskIdentity;
        try psk.verifyClientOfferForSecret(
            options.client_hello_bytes,
            offer,
            resumption.identity,
            resumption.secret,
            if (options.retry) |retry| retry.binder_prefix else null,
        );
        if (resumption.age_policy) |age_policy| {
            try psk.validateTicketAge(offer, age_policy);
        }
        offered_resumption = offer;
    } else if (parsed_client.pre_shared_key != null) {
        return error.MissingPskConfiguration;
    }
    if (parsed_client.early_data) {
        const resumption = options.resumption orelse
            return error.MissingPskConfiguration;
        if (options.retry != null or
            resumption.max_early_data_size == null or
            resumption.max_early_data_size.? == 0)
        {
            return error.InvalidEarlyDataConfiguration;
        }
    }
    for (options.certificate_compression_algorithms) |algorithm| {
        if (!parsed_client.supportsCertificateCompression(algorithm)) {
            return error.InvalidClientHello;
        }
    }

    const parsed_server = try server_hello.parseServerHello(
        options.server_hello_bytes,
    );
    if (!parsed_client.hasCipherSuite(parsed_server.cipher_suite.wireValue())) {
        return error.ServerSelectedUnofferedSuite;
    }
    if (!std.mem.eql(
        u8,
        parsed_client.session_id,
        parsed_server.session_id_echo,
    )) return error.SessionIdMismatch;
    if (!try parsed_client.supportsGroup(parsed_server.key_share_group) or
        try parsed_client.keyShareForGroup(parsed_server.key_share_group) == null)
    {
        return error.ServerSelectedUnofferedGroup;
    }
    const resumed = if (parsed_server.selected_psk_identity) |identity| blk: {
        if (options.resumption == null) return error.MissingPskConfiguration;
        if (identity != offered_resumption.?.selected_identity) {
            return error.InvalidServerHello;
        }
        break :blk true;
    } else false;
    if (options.retry) |retry| {
        try validateRetryState(
            retry,
            parsed_server.cipher_suite,
            parsed_server.key_share_group,
            options.client_hello_bytes,
            ech_status != .not_offered,
            ech_accepted,
        );
    }
    if (ech_accepted) {
        const confirmation_prefix = if (options.retry) |retry|
            retry.transcript_prefix
        else blk: {
            var state = transcript.State.init(parsed_server.cipher_suite.hash());
            state.update(options.client_hello_bytes);
            break :blk state;
        };
        const confirmation_transcript =
            try ech.serverHelloConfirmationTranscript(
                confirmation_prefix,
                options.server_hello_bytes,
            );
        const expected = try ech.acceptConfirmation(
            parsed_server.cipher_suite.hash(),
            parsed_client.random.*,
            confirmation_transcript,
        );
        if (!std.crypto.timing_safe.eql(
            [ech.confirmation_len]u8,
            parsed_server.random[parsed_server.random.len -
                ech.confirmation_len ..][0..ech.confirmation_len].*,
            expected,
        )) return error.EchRejected;
    }

    const flight = try client_handshake.splitServerFlightForMode(
        options.server_handshake_crypto,
        resumed,
    );
    const extensions = try server_hello.parseEncryptedExtensions(
        flight.encrypted_extensions,
    );
    const peer_transport_parameters = extensions.quic_transport_parameters orelse
        return error.MissingQuicTransportParameters;
    const selected_alpn = extensions.alpn_protocol orelse
        return error.MissingAlpn;
    if (!try parsed_client.supportsAlpnProtocol(selected_alpn)) {
        return error.ServerSelectedUnofferedAlpn;
    }
    if (extensions.early_data_accepted and
        (!resumed or options.resumption == null or
            options.resumption.?.suite != parsed_server.cipher_suite))
    {
        return error.InvalidEarlyDataConfiguration;
    }

    var hello_transcript = if (options.retry) |retry|
        retry.transcript_prefix
    else blk: {
        var state = transcript.State.init(parsed_server.cipher_suite.hash());
        state.update(options.client_hello_bytes);
        break :blk state;
    };
    hello_transcript.update(options.server_hello_bytes);
    var handshake = try key_schedule.deriveHandshakeFor(
        parsed_server.cipher_suite.hash(),
        options.shared_secret,
        hello_transcript.digest(),
        if (resumed) options.resumption.?.secret else null,
    );
    defer handshake.early_secret.deinit();
    defer handshake.handshake_secret.deinit();
    defer handshake.client_traffic_secret.deinit();
    defer handshake.server_traffic_secret.deinit();

    var handshake_packet_keys = try tls_secrets.handshakeKeys(
        parsed_server.cipher_suite,
        handshake,
        options.labels,
    );
    errdefer handshake_packet_keys.deinit();
    var verified = try client_handshake.verifyServerAndWriteClientFlight(
        handshake_crypto,
        allocator,
        .{
            .client_hello_bytes = options.client_hello_bytes,
            .server_hello_bytes = options.server_hello_bytes,
            .encrypted_server_flight = options.server_handshake_crypto,
            .handshake_secret = handshake.handshake_secret,
            .client_handshake_traffic_secret = handshake.client_traffic_secret,
            .server_handshake_traffic_secret = handshake.server_traffic_secret,
            .transcript_prefix = if (options.retry) |retry|
                retry.transcript_prefix
            else
                null,
            .psk_resumed = resumed,
            .early_data_offered = parsed_client.early_data,
            .send_end_of_early_data = false,
            .ech_accepted = ech_accepted,
            .ech_offered = ech_accepted,
            .server_verifier = options.server_verifier,
            .server_certificate_type = options.server_certificate_type,
            .server_name = options.server_name,
            .certificate_compression_algorithms = options.certificate_compression_algorithms,
            .max_decompressed_certificate_len = options.max_decompressed_certificate_len,
            .client_identity = options.client_identity,
            .application_settings = options.application_settings,
            .resumed_application_settings = if (resumed)
                options.resumption.?.application_settings
            else
                null,
        },
    );
    var verified_owned = true;
    defer if (verified_owned) verified.deinit();

    const owned_alpn = try allocator.dupe(u8, selected_alpn);
    errdefer allocator.free(owned_alpn);
    const owned_transport_parameters = try allocator.dupe(
        u8,
        peer_transport_parameters,
    );
    errdefer allocator.free(owned_transport_parameters);
    const application_packet_keys = try tls_secrets.applicationKeys(
        parsed_server.cipher_suite,
        verified.application,
        options.labels,
    );

    // The low-level verifier borrows ALPN from the server flight. Expose only
    // the owned copy from ClientResult so callers may release CRYPTO buffers.
    verified.selected_alpn = null;
    verified_owned = false;
    return .{
        .allocator = allocator,
        .verified = verified,
        .selected_alpn = owned_alpn,
        .peer_transport_parameters = owned_transport_parameters,
        .handshake_packet_keys = handshake_packet_keys,
        .application_packet_keys = application_packet_keys,
        .resumed = resumed,
        .ech_accepted = ech_accepted,
    };
}

/// Authenticate an ECH rejection against ClientHelloOuter and its public
/// name. No client Finished or application keys are exposed for the rejected
/// connection; QUIC must close it with `crypto_error_code`.
pub fn authenticateEchRejection(
    allocator: std.mem.Allocator,
    options: EchRejectionOptions,
) Error!EchRejection {
    const parsed_outer = try client_hello.parse(
        options.outer_client_hello_bytes,
    );
    if (try clientHelloEchStatus(parsed_outer) != .rejected) {
        return error.InvalidEchExtension;
    }
    if (!parsed_outer.offersTls13()) return error.InvalidClientHello;
    if (parsed_outer.server_name == null) return error.InvalidClientHello;
    if (parsed_outer.quic_transport_parameters == null) {
        return error.MissingQuicTransportParameters;
    }
    if (parsed_outer.alpn_protocols.len == 0) return error.MissingAlpn;
    for (options.certificate_compression_algorithms) |algorithm| {
        if (!parsed_outer.supportsCertificateCompression(algorithm)) {
            return error.InvalidClientHello;
        }
    }

    const parsed_server = try server_hello.parseServerHello(
        options.server_hello_bytes,
    );
    if (!parsed_outer.hasCipherSuite(parsed_server.cipher_suite.wireValue())) {
        return error.ServerSelectedUnofferedSuite;
    }
    if (!std.mem.eql(
        u8,
        parsed_outer.session_id,
        parsed_server.session_id_echo,
    )) return error.SessionIdMismatch;
    if (!try parsed_outer.supportsGroup(parsed_server.key_share_group) or
        try parsed_outer.keyShareForGroup(parsed_server.key_share_group) == null)
    {
        return error.ServerSelectedUnofferedGroup;
    }
    if (parsed_server.selected_psk_identity != null) {
        return error.InvalidServerHello;
    }
    if (options.retry) |retry| {
        try validateRetryState(
            retry,
            parsed_server.cipher_suite,
            parsed_server.key_share_group,
            options.outer_client_hello_bytes,
            true,
            false,
        );
    }

    const flight = try client_handshake.splitServerFlight(
        options.server_handshake_crypto,
    );
    const extensions = try server_hello.parseEncryptedExtensions(
        flight.encrypted_extensions,
    );
    _ = extensions.quic_transport_parameters orelse
        return error.MissingQuicTransportParameters;
    const selected_alpn = extensions.alpn_protocol orelse
        return error.MissingAlpn;
    if (!try parsed_outer.supportsAlpnProtocol(selected_alpn)) {
        return error.ServerSelectedUnofferedAlpn;
    }
    if (extensions.early_data_accepted) {
        return error.InvalidEarlyDataConfiguration;
    }

    var hello_transcript = if (options.retry) |retry|
        retry.transcript_prefix
    else blk: {
        var state = transcript.State.init(parsed_server.cipher_suite.hash());
        state.update(options.outer_client_hello_bytes);
        break :blk state;
    };
    hello_transcript.update(options.server_hello_bytes);
    var handshake = try key_schedule.deriveHandshakeFor(
        parsed_server.cipher_suite.hash(),
        options.shared_secret,
        hello_transcript.digest(),
        null,
    );
    defer handshake.early_secret.deinit();
    defer handshake.handshake_secret.deinit();
    defer handshake.client_traffic_secret.deinit();
    defer handshake.server_traffic_secret.deinit();

    var discarded_client_flight: std.ArrayList(u8) = .empty;
    defer discarded_client_flight.deinit(allocator);
    var verified = try client_handshake.verifyServerAndWriteClientFlight(
        &discarded_client_flight,
        allocator,
        .{
            .client_hello_bytes = options.outer_client_hello_bytes,
            .server_hello_bytes = options.server_hello_bytes,
            .encrypted_server_flight = options.server_handshake_crypto,
            .handshake_secret = handshake.handshake_secret,
            .client_handshake_traffic_secret = handshake.client_traffic_secret,
            .server_handshake_traffic_secret = handshake.server_traffic_secret,
            .transcript_prefix = if (options.retry) |retry|
                retry.transcript_prefix
            else
                null,
            .ech_offered = true,
            .server_verifier = options.server_verifier,
            .server_certificate_type = options.server_certificate_type,
            .server_name = parsed_outer.server_name,
            .certificate_compression_algorithms = options.certificate_compression_algorithms,
            .max_decompressed_certificate_len = options.max_decompressed_certificate_len,
            .send_end_of_early_data = false,
        },
    );
    defer verified.deinit();

    const retry_configs = if (verified.ech_retry_configs) |configs|
        try allocator.dupe(u8, configs)
    else
        null;
    return .{
        .allocator = allocator,
        .retry_configs = retry_configs,
    };
}
