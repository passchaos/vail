//! QUIC TLS server handshake state and flight processing.
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
const client = @import("client.zig");
const ClientFlightResult = client.ClientFlightResult;
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

pub const Result = struct {
    allocator: std.mem.Allocator,
    selection: server_flight.Selection,
    handshake_secret: secret.Secret,
    client_handshake_traffic_secret: secret.Secret,
    server_handshake_traffic_secret: secret.Secret,
    transcript_after_server_finished: transcript.Digest,
    transcript_state_after_server_finished: transcript.State,
    handshake_packet_keys: tls_secrets.DirectionalKeys,
    application_packet_keys: tls_secrets.DirectionalKeys,
    client_early_packet_keys: ?traffic.Keys,
    early_data_limit: ?u32,
    client_auth: ?ClientAuthState,
    resumed: bool,
    ech_accepted: bool,
    ech_rejected: bool,
    requested_ticket_count: u8,
    certificate_compression: ?certificate_compression.Algorithm,
    application_settings: ?application_settings.Payload,
    peer_application_settings: ?[]const u8,
    client_application_settings_required: bool,

    pub fn deinit(self: *Result) void {
        if (self.client_auth) |state| {
            self.allocator.free(state.request_context);
            self.allocator.free(state.certificate_compression_algorithms);
            if (state.certificate_signature_schemes) |schemes| {
                self.allocator.free(schemes);
            }
        }
        self.handshake_secret.deinit();
        self.client_handshake_traffic_secret.deinit();
        self.server_handshake_traffic_secret.deinit();
        self.handshake_packet_keys.deinit();
        self.application_packet_keys.deinit();
        if (self.client_early_packet_keys) |*keys| keys.deinit();
        self.* = undefined;
    }
};

pub const Options = struct {
    client_hello_bytes: []const u8,
    parsed_client_hello: client_hello.Parsed,
    policy: server_flight.Policy,
    server_random: [32]u8,
    server_key_share: []const u8,
    shared_secret: []const u8,
    certificate_chain: []const []const u8,
    signer: auth.Signer,
    client_auth: ?ClientAuthOptions = null,
    resumption: ?ResumptionPsk = null,
    /// Set only after the transport's anti-replay policy authorizes this
    /// ClientHello. The ticket limit remains an independent upper bound.
    accept_early_data: bool = false,
    /// The caller sets this only after authenticating and reconstructing a
    /// ClientHelloInner with the ECH server context.
    ech_accepted: bool = false,
    /// An authenticated replacement ECHConfigList to send only when the
    /// supplied ClientHello is an outer ECH offer that could not be decrypted.
    ech_retry_configs: ?[]const u8 = null,
    retry: ?RetryState = null,
    max_requested_tickets: u8 = 0,
    labels: traffic.Labels = traffic.labels_v1,
};

pub fn prepareRetryState(
    first_client_hello: []const u8,
    hello_retry_request: []const u8,
    second_client_hello: []const u8,
) Error!RetryState {
    const first = try client_hello.parse(first_client_hello);
    if (!first.offersTls13()) return error.InvalidClientHello;
    if (first.quic_transport_parameters == null) {
        return error.MissingQuicTransportParameters;
    }
    if (first.alpn_protocols.len == 0) return error.MissingAlpn;
    const retry = try server_hello.parseHelloRetryRequest(hello_retry_request);
    const ech_status = try clientHelloEchStatus(first);
    const ech_accepted = if (ech_status == .accepted) blk: {
        const confirmation = retry.ech_confirmation orelse
            return error.EchRejected;
        const confirmation_transcript =
            try ech.helloRetryRequestConfirmationTranscript(
                retry.cipher_suite.hash(),
                first_client_hello,
                hello_retry_request,
                confirmation,
            );
        const expected = try ech.hrrAcceptConfirmation(
            retry.cipher_suite.hash(),
            first.random.*,
            confirmation_transcript,
        );
        if (!std.crypto.timing_safe.eql(
            [ech.confirmation_len]u8,
            confirmation[0..ech.confirmation_len].*,
            expected,
        )) return error.EchRejected;
        break :blk true;
    } else blk: {
        if (retry.ech_confirmation != null) return error.InvalidServerHello;
        break :blk false;
    };
    if (!first.hasCipherSuite(retry.cipher_suite.wireValue())) {
        return error.ServerSelectedUnofferedSuite;
    }
    if (!std.mem.eql(u8, first.session_id, retry.session_id_echo)) {
        return error.SessionIdMismatch;
    }
    if (!try first.supportsGroup(retry.selected_group)) {
        return error.ServerSelectedUnofferedGroup;
    }

    const second = try client_hello.parse(second_client_hello);
    try client_hello.validateSecondClientHello(
        first_client_hello,
        second,
        retry.selected_group,
        retry.cookie,
    );
    const binder_prefix = transcript.afterHelloRetryRequest(
        retry.cipher_suite.hash(),
        first_client_hello,
        hello_retry_request,
    );
    if (first.pre_shared_key != null) {
        const first_offer = try psk.parseClientOfferForHash(
            first_client_hello,
            retry.cipher_suite.hash(),
        );
        const second_offer = try psk.parseClientOfferForHash(
            second_client_hello,
            retry.cipher_suite.hash(),
        );
        if (!std.mem.eql(u8, first_offer.identity, second_offer.identity) or
            first_offer.obfuscated_ticket_age != second_offer.obfuscated_ticket_age)
        {
            return error.InvalidSecondClientHello;
        }
    }
    var prefix = binder_prefix;
    prefix.update(second_client_hello);
    return .{
        .cipher_suite = retry.cipher_suite,
        .selected_group = retry.selected_group,
        .transcript_prefix = prefix,
        .binder_prefix = binder_prefix,
        .second_client_hello_hash = transcript.hashFor(
            retry.cipher_suite.hash(),
            &.{second_client_hello},
        ),
        .ech_offered = ech_status != .not_offered,
        .ech_accepted = ech_accepted,
    };
}

pub const ClientAuthOptions = struct {
    policy: client_auth.ServerPolicy,
    request_context: []const u8 = &.{},
    certificate_authorities: []const []const u8 = &.{},
    /// Optional constraints for signatures on the client's X.509 chain.
    certificate_signature_schemes: ?[]const u16 = null,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{ .zlib, .brotli },
    max_decompressed_certificate_len: usize = 64 * 1024,
};

pub const ClientAuthState = struct {
    policy: client_auth.ServerPolicy,
    request_context: []u8,
    certificate_compression_algorithms: []certificate_compression.Algorithm,
    certificate_signature_schemes: ?[]u16,
    max_decompressed_certificate_len: usize,
};

pub const NewSessionTicketOptions = struct {
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

pub fn writeServerCryptoFlight(
    initial_crypto: *std.ArrayList(u8),
    handshake_crypto: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: Options,
) Error!Result {
    const initial_start = initial_crypto.items.len;
    errdefer initial_crypto.shrinkRetainingCapacity(initial_start);
    const handshake_start = handshake_crypto.items.len;
    errdefer handshake_crypto.shrinkRetainingCapacity(handshake_start);
    if (options.client_auth) |value| {
        try client_auth.validateInitialRequestContext(value.request_context);
    }
    if (options.resumption) |resumption| {
        try validateQuicResumption(resumption);
    }

    if (options.parsed_client_hello.quic_transport_parameters == null or
        options.policy.quic_transport_parameters == null)
    {
        return error.MissingQuicTransportParameters;
    }
    if (options.parsed_client_hello.alpn_protocols.len == 0 or
        options.policy.alpn_protocols.len == 0)
    {
        return error.MissingAlpn;
    }
    const ech_status = try clientHelloEchStatus(options.parsed_client_hello);
    const ech_accepted = ech_status == .accepted;
    const ech_rejected = ech_status == .rejected;
    if (ech_accepted != options.ech_accepted or
        (options.ech_retry_configs != null and !ech_rejected) or
        (ech_rejected and options.parsed_client_hello.server_name == null))
    {
        return error.InvalidEchExtension;
    }
    const selection = try server_flight.select(
        options.parsed_client_hello,
        options.policy,
    );
    if (selection.alpn_protocol == null) {
        return error.NoApplicationProtocol;
    }
    if (options.retry) |retry| {
        try validateRetryState(
            retry,
            selection.suite,
            selection.key_share_group,
            options.client_hello_bytes,
            ech_status != .not_offered,
            ech_accepted,
        );
    }
    var psk_age_within_tolerance = true;
    var selected_psk_identity: ?u16 = null;
    const selected_psk: ?secret.Secret = if (ech_rejected)
        null
    else if (options.resumption) |resumption| blk: {
        if (options.parsed_client_hello.pre_shared_key == null or
            resumption.secret.hash != selection.suite.hash())
        {
            break :blk null;
        }
        const offer = try psk.findClientOfferForIdentityForHash(
            options.client_hello_bytes,
            resumption.identity,
            selection.suite.hash(),
        ) orelse break :blk null;
        try psk.verifyClientOfferForSecret(
            options.client_hello_bytes,
            offer,
            resumption.identity,
            resumption.secret,
            if (options.retry) |retry| retry.binder_prefix else null,
        );
        if (resumption.age_policy) |age_policy| {
            psk_age_within_tolerance = try psk.ticketAgeWithinTolerance(
                offer,
                age_policy,
            );
        }
        selected_psk_identity = offer.selected_identity;
        psk_age_within_tolerance = psk_age_within_tolerance and
            offer.selected_identity == psk.selected_identity_first;
        break :blk resumption.secret;
    } else null;
    if (options.accept_early_data and
        (options.retry != null or
            !options.parsed_client_hello.early_data or
            selected_psk == null or
            options.resumption.?.max_early_data_size == null or
            options.resumption.?.max_early_data_size.? == 0 or
            options.resumption.?.age_policy == null or
            options.resumption.?.suite != selection.suite))
    {
        return error.InvalidEarlyDataConfiguration;
    }
    if (options.accept_early_data and
        !application_settings.resumptionMatches(
            selection.application_settings,
            options.resumption.?.application_settings,
        ))
    {
        return error.InvalidEarlyDataConfiguration;
    }
    const early_data_accepted = options.accept_early_data and
        psk_age_within_tolerance;
    if (selected_psk == null) {
        if (!try options.parsed_client_hello.supportsSignatureScheme(
            options.signer.scheme(),
        )) return error.UnsupportedSignatureScheme;
        try (auth.ServerIdentity{
            .certificate_chain = options.certificate_chain,
            .signer = options.signer,
            .certificate_type = options.policy.server_certificate_type,
        }).validate();
    }

    var server_hello_msg: std.ArrayList(u8) = .empty;
    defer server_hello_msg.deinit(allocator);
    var server_random = options.server_random;
    if (ech_accepted) {
        @memset(server_random[server_random.len - ech.confirmation_len ..], 0);
    }
    try server_hello.writeServerHello(&server_hello_msg, allocator, .{
        .random = server_random,
        .session_id_echo = options.parsed_client_hello.session_id,
        .cipher_suite = selection.suite,
        .key_share_group = selection.key_share_group,
        .key_share = options.server_key_share,
        .selected_psk_identity = selected_psk_identity,
    });
    if (ech_accepted) {
        const confirmation_prefix = if (options.retry) |retry|
            retry.transcript_prefix
        else blk: {
            var state = transcript.State.init(selection.suite.hash());
            state.update(options.client_hello_bytes);
            break :blk state;
        };
        const confirmation_transcript =
            try ech.serverHelloConfirmationTranscript(
                confirmation_prefix,
                server_hello_msg.items,
            );
        const confirmation = try ech.acceptConfirmation(
            selection.suite.hash(),
            options.parsed_client_hello.random.*,
            confirmation_transcript,
        );
        server_hello_msg.items[4 + 2 + 32 - ech.confirmation_len ..][0..ech.confirmation_len].* = confirmation;
    }
    // The QUIC transport wraps these bytes in Initial CRYPTO frames, then
    // packet-protects those frames with Initial keys derived from the DCID.
    try initial_crypto.appendSlice(allocator, server_hello_msg.items);

    var transcript_state = if (options.retry) |retry|
        retry.transcript_prefix
    else blk: {
        var state = transcript.State.init(selection.suite.hash());
        state.update(options.client_hello_bytes);
        break :blk state;
    };
    transcript_state.update(server_hello_msg.items);
    var handshake = try key_schedule.deriveHandshakeFor(
        selection.suite.hash(),
        options.shared_secret,
        transcript_state.digest(),
        selected_psk,
    );
    defer handshake.early_secret.deinit();
    errdefer handshake.handshake_secret.deinit();
    errdefer handshake.client_traffic_secret.deinit();
    errdefer handshake.server_traffic_secret.deinit();

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(allocator);
    const can_resume = std.mem.indexOfScalar(
        u8,
        options.parsed_client_hello.psk_key_exchange_modes,
        psk.psk_dhe_ke,
    ) != null;
    const requested_ticket_count: u8 = if (can_resume) if (options.parsed_client_hello.ticket_request) |request| @min(
        if (selected_psk == null)
            request.new_session_count
        else
            request.resumption_count,
        options.max_requested_tickets,
    ) else 0 else 0;
    try server_hello.writeEncryptedExtensions(&encrypted_extensions, allocator, .{
        .alpn_protocol = selection.alpn_protocol,
        .quic_transport_parameters = options.policy.quic_transport_parameters,
        .accept_early_data = early_data_accepted,
        .ech_retry_configs = if (ech_rejected)
            options.ech_retry_configs
        else
            null,
        .server_certificate_type = if (selection.send_server_certificate_type)
            selection.server_certificate_type
        else
            null,
        .client_certificate_type = if (selection.send_client_certificate_type)
            selection.client_certificate_type
        else
            null,
        .ticket_request_hint = if (options.parsed_client_hello.ticket_request != null and
            options.max_requested_tickets != 0) requested_ticket_count else null,
        .application_settings = if (early_data_accepted)
            null
        else
            selection.application_settings,
    });
    try handshake_crypto.appendSlice(allocator, encrypted_extensions.items);
    transcript_state.update(encrypted_extensions.items);

    var certificate_request: std.ArrayList(u8) = .empty;
    defer certificate_request.deinit(allocator);
    if (options.client_auth) |client_auth_options| {
        if (client_auth_options.policy.certificate_type !=
            selection.client_certificate_type)
        {
            return error.NoSupportedCertificateType;
        }
        try client_auth.writeRequestWithOptions(
            &certificate_request,
            allocator,
            .{
                .request_context = client_auth_options.request_context,
                .certificate_authorities = client_auth_options.certificate_authorities,
                .compression_algorithms = client_auth_options.certificate_compression_algorithms,
                .certificate_signature_schemes = client_auth_options.certificate_signature_schemes,
            },
        );
        try handshake_crypto.appendSlice(allocator, certificate_request.items);
        transcript_state.update(certificate_request.items);
    }

    var selected_certificate_compression: ?certificate_compression.Algorithm = null;
    if (selected_psk == null) {
        var certificate: std.ArrayList(u8) = .empty;
        defer certificate.deinit(allocator);
        if (selection.server_certificate_type == .x509 and
            options.parsed_client_hello.requests_ocsp and
            options.policy.ocsp_response != null)
        {
            try auth.writeCertificateWithOcsp(
                &certificate,
                allocator,
                options.certificate_chain,
                options.policy.ocsp_response.?,
            );
        } else {
            try auth.writeCertificate(
                &certificate,
                allocator,
                options.certificate_chain,
            );
        }
        var compressed_certificate: std.ArrayList(u8) = .empty;
        defer compressed_certificate.deinit(allocator);
        const certificate_wire = for (options.policy.compressed_certificates) |prepared| {
            if (options.parsed_client_hello.supportsCertificateCompression(
                prepared.algorithm,
            ) and prepared.matchesCertificateMessage(certificate.items) and
                prepared.savesBytes(certificate.items.len))
            {
                try prepared.write(&compressed_certificate, allocator);
                selected_certificate_compression = prepared.algorithm;
                break compressed_certificate.items;
            }
        } else certificate.items;
        try handshake_crypto.appendSlice(allocator, certificate_wire);
        transcript_state.update(certificate_wire);

        var certificate_verify: std.ArrayList(u8) = .empty;
        defer certificate_verify.deinit(allocator);
        try auth.writeCertificateVerify(
            &certificate_verify,
            allocator,
            options.signer,
            transcript_state.digest().bytes(),
        );
        try handshake_crypto.appendSlice(allocator, certificate_verify.items);
        transcript_state.update(certificate_verify.items);
    }

    const verify_data = try key_schedule.computeFinishedFor(
        handshake.server_traffic_secret,
        transcript_state.digest(),
    );
    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try writeFinished(&finished, allocator, verify_data.bytes());
    try handshake_crypto.appendSlice(allocator, finished.items);
    transcript_state.update(finished.items);
    const transcript_after_server_finished = transcript_state.digest();
    var application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        transcript_after_server_finished,
    );
    defer application.master_secret.deinit();
    defer application.client_traffic_secret.deinit();
    defer application.server_traffic_secret.deinit();

    var client_early_packet_keys = if (early_data_accepted)
        try tls_secrets.clientEarlyKeys(
            selection.suite,
            selected_psk.?,
            transcript.hashFor(
                selection.suite.hash(),
                &.{options.client_hello_bytes},
            ),
            options.labels,
        )
    else
        null;
    errdefer if (client_early_packet_keys) |*keys| keys.deinit();

    const retained_client_auth: ?ClientAuthState = if (options.client_auth) |value| blk: {
        const request_context = try allocator.dupe(u8, value.request_context);
        errdefer allocator.free(request_context);
        const algorithms = try allocator.dupe(
            certificate_compression.Algorithm,
            value.certificate_compression_algorithms,
        );
        errdefer allocator.free(algorithms);
        const certificate_signature_schemes = if (value.certificate_signature_schemes) |schemes|
            try allocator.dupe(u16, schemes)
        else
            null;
        break :blk .{
            .policy = value.policy,
            .request_context = request_context,
            .certificate_compression_algorithms = algorithms,
            .certificate_signature_schemes = certificate_signature_schemes,
            .max_decompressed_certificate_len = value.max_decompressed_certificate_len,
        };
    } else null;
    errdefer if (retained_client_auth) |state| {
        allocator.free(state.request_context);
        allocator.free(state.certificate_compression_algorithms);
        if (state.certificate_signature_schemes) |schemes| {
            allocator.free(schemes);
        }
    };

    return .{
        .allocator = allocator,
        .selection = selection,
        .handshake_secret = handshake.handshake_secret,
        .client_handshake_traffic_secret = handshake.client_traffic_secret,
        .server_handshake_traffic_secret = handshake.server_traffic_secret,
        .transcript_after_server_finished = transcript_after_server_finished,
        .transcript_state_after_server_finished = transcript_state,
        .handshake_packet_keys = try tls_secrets.handshakeKeys(
            selection.suite,
            handshake,
            options.labels,
        ),
        .application_packet_keys = try tls_secrets.applicationKeys(
            selection.suite,
            application,
            options.labels,
        ),
        .client_early_packet_keys = client_early_packet_keys,
        .early_data_limit = if (early_data_accepted)
            options.resumption.?.max_early_data_size
        else
            null,
        .client_auth = retained_client_auth,
        .resumed = selected_psk != null,
        .ech_accepted = ech_accepted,
        .ech_rejected = ech_rejected,
        .requested_ticket_count = requested_ticket_count,
        .certificate_compression = selected_certificate_compression,
        .application_settings = selection.application_settings,
        .peer_application_settings = if (early_data_accepted)
            if (options.resumption.?.application_settings) |settings|
                settings.peer
            else
                null
        else
            null,
        .client_application_settings_required = selection.application_settings != null and
            !early_data_accepted,
    };
}

/// Verify the client's plaintext Handshake CRYPTO flight against the state
/// returned by `writeServerCryptoFlight`. When client authentication was
/// requested, the returned certificate chain is deep-owned.
pub fn verifyClientCryptoFlight(
    allocator: std.mem.Allocator,
    server: *const Result,
    client_handshake_crypto: []const u8,
) Error!ClientFlightResult {
    var offset: usize = 0;
    var transcript_state = server.transcript_state_after_server_finished;
    var peer_application_settings: ?[]u8 = null;
    errdefer if (peer_application_settings) |settings| allocator.free(settings);
    if (server.client_application_settings_required) {
        const negotiated = server.application_settings orelse unreachable;
        const client_extensions = try takeHandshakeMessage(
            client_handshake_crypto,
            &offset,
        );
        const received = application_settings.parseClientEncryptedExtensions(
            client_extensions,
        ) catch return error.InvalidClientFlight;
        if (received.codepoint != negotiated.codepoint) {
            return error.InvalidClientFlight;
        }
        peer_application_settings = try allocator.dupe(u8, received.settings);
        transcript_state.update(client_extensions);
    } else if (server.peer_application_settings) |settings| {
        peer_application_settings = try allocator.dupe(u8, settings);
    }
    if (server.client_auth) |auth_state| {
        const certificate = try takeHandshakeMessage(
            client_handshake_crypto,
            &offset,
        );
        if (certificate[0] != auth.handshake_type_certificate and
            certificate[0] !=
                certificate_compression.handshake_type_compressed_certificate)
        {
            return error.InvalidClientFlight;
        }
        var next = try takeHandshakeMessage(client_handshake_crypto, &offset);
        const certificate_verify = if (next[0] ==
            auth.handshake_type_certificate_verify)
        blk: {
            const value = next;
            next = try takeHandshakeMessage(client_handshake_crypto, &offset);
            break :blk value;
        } else null;
        if (next[0] != handshake_type_finished or
            offset != client_handshake_crypto.len)
        {
            return error.InvalidClientFlight;
        }

        var verification = try client_auth.verifyClientFlightWithOptions(
            allocator,
            auth_state.policy,
            auth_state.request_context,
            transcript_state,
            server.client_handshake_traffic_secret,
            certificate,
            certificate_verify,
            next,
            .{
                .accepted_compression_algorithms = auth_state.certificate_compression_algorithms,
                .max_decompressed_certificate_len = auth_state.max_decompressed_certificate_len,
                .certificate_signature_schemes = auth_state.certificate_signature_schemes,
            },
        );
        defer verification.deinit(allocator);
        const peer_certificate_chain = try copyCertificateChain(
            allocator,
            verification.certificate.entries,
        );
        return .{
            .allocator = allocator,
            .peer_certificate_chain = peer_certificate_chain,
            .client_certificate_compression = verification.certificate_compression,
            .transcript_after_client_finished = verification.transcript_after_client_finished,
            .application_settings_codepoint = if (server.application_settings) |settings|
                settings.codepoint
            else
                null,
            .peer_application_settings = peer_application_settings,
        };
    }

    const finished = try takeHandshakeMessage(client_handshake_crypto, &offset);
    if (offset != client_handshake_crypto.len) {
        return error.InvalidClientFlight;
    }
    try verifyClientFinished(
        &transcript_state,
        server.client_handshake_traffic_secret,
        finished,
    );
    return .{
        .allocator = allocator,
        .peer_certificate_chain = try allocator.alloc([]const u8, 0),
        .client_certificate_compression = null,
        .transcript_after_client_finished = transcript_state.digest(),
        .application_settings_codepoint = if (server.application_settings) |settings|
            settings.codepoint
        else
            null,
        .peer_application_settings = peer_application_settings,
    };
}

/// Derive a resumption PSK after authenticating the client Finished and append
/// a plaintext NewSessionTicket for delivery in QUIC 1-RTT CRYPTO data.
pub fn writeNewSessionTicket(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server: *const Result,
    verified_client: *const ClientFlightResult,
    options: NewSessionTicketOptions,
) (Error || ticket.Error || ticket_keyring.Error)!void {
    var application = try key_schedule.deriveApplicationFor(
        server.handshake_secret,
        server.transcript_after_server_finished,
    );
    defer application.master_secret.deinit();
    defer application.client_traffic_secret.deinit();
    defer application.server_traffic_secret.deinit();
    var resumption_master = try key_schedule.deriveResumptionMasterSecretFor(
        application.master_secret,
        verified_client.transcript_after_client_finished,
    );
    defer resumption_master.deinit();
    var resumption_psk = try key_schedule.deriveResumptionPskFor(
        resumption_master,
        options.ticket_nonce,
    );
    defer resumption_psk.deinit();

    const opened = ticket_keyring.OpenedSecret{
        .secret = resumption_psk,
        .age_add = options.age_add,
        .issued_at_ms = options.issued_at_ms,
        .lifetime_seconds = options.lifetime_seconds,
        .cipher_suite_wire = server.selection.suite.wireValue(),
        .max_early_data_size = if (options.allow_early_data)
            ticket.quic_early_data_size
        else
            null,
    };
    var fixed_identity: [ticket_keyring.sealed_len]u8 = undefined;
    var allocated_identity: ?[]u8 = null;
    defer if (allocated_identity) |identity| allocator.free(identity);
    const identity: []const u8 = if (options.allow_early_data and
        server.application_settings != null)
    blk: {
        const local = server.application_settings.?;
        const peer = verified_client.peer_application_settings orelse
            return error.InvalidApplicationSettings;
        allocated_identity = try options.keyring
            .sealSecretWithApplicationSettingsAlloc(
            allocator,
            options.sealing_nonce,
            options.server_id,
            options.alpn,
            opened,
            .{
                .codepoint = local.codepoint,
                .local = local.settings,
                .peer = peer,
            },
        );
        break :blk allocated_identity.?;
    } else blk: {
        fixed_identity = try options.keyring.sealSecret(
            options.sealing_nonce,
            options.server_id,
            options.alpn,
            opened,
        );
        break :blk &fixed_identity;
    };
    try ticket.write(output, allocator, .{
        .lifetime_seconds = options.lifetime_seconds,
        .age_add = options.age_add,
        .nonce = options.ticket_nonce,
        .ticket = identity,
        .allow_early_data = options.allow_early_data,
    });
}

/// Consume one RFC 9149 ticket request only after ticket construction
/// succeeds. QUIC transports encrypt the returned handshake bytes at 1-RTT.
pub fn writeRequestedNewSessionTicket(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server: *Result,
    verified_client: *const ClientFlightResult,
    options: NewSessionTicketOptions,
) (Error || ticket.Error || ticket_keyring.Error ||
    error{NoRequestedTicketsPending})!void {
    if (server.requested_ticket_count == 0) {
        return error.NoRequestedTicketsPending;
    }
    try writeNewSessionTicket(
        output,
        allocator,
        server,
        verified_client,
        options,
    );
    server.requested_ticket_count -= 1;
}

pub fn verifyClientFinished(
    state: *transcript.State,
    client_handshake_traffic_secret: secret.Secret,
    message: []const u8,
) Error!void {
    if (message.len < 4 or message[0] != handshake_type_finished) {
        return error.InvalidClientFlight;
    }
    const body_len =
        (@as(usize, message[1]) << 16) |
        (@as(usize, message[2]) << 8) |
        message[3];
    if (body_len != client_handshake_traffic_secret.hash.len() or
        body_len != message.len - 4)
    {
        return error.InvalidClientFlight;
    }
    var actual = try secret.Secret.init(
        client_handshake_traffic_secret.hash,
        message[4..],
    );
    defer actual.deinit();
    try key_schedule.verifyFinishedFor(
        client_handshake_traffic_secret,
        state.digest(),
        actual,
    );
    state.update(message);
}

pub fn copyCertificateChain(
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

pub fn writeFinished(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    verify_data: []const u8,
) Error!void {
    if (verify_data.len > std.math.maxInt(u24)) return error.InvalidFinished;
    try out.append(allocator, handshake_type_finished);
    try out.appendSlice(allocator, &.{
        @truncate(verify_data.len >> 16),
        @truncate(verify_data.len >> 8),
        @truncate(verify_data.len),
    });
    try out.appendSlice(allocator, verify_data);
}
