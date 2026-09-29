//! TLS 1.3 handshake adapters for QUIC CRYPTO streams.
//!
//! QUIC carries TLS handshake bytes in CRYPTO frames and protects packets with
//! QUIC packet keys. It never uses TLS record protection. This adapter keeps
//! that boundary explicit: Vail consumes and emits plaintext handshake
//! messages separated by encryption level and returns the packet-protection
//! keys that a transport implementation installs into its
//! Initial/Handshake/1-RTT packet spaces.

const std = @import("std");

const auth = @import("../tls/auth.zig");
const certificate_compression = @import("../tls/certificate_compression.zig");
const cipher_suite = @import("../tls/cipher_suite.zig");
const client_auth = @import("../tls/client_auth.zig");
const client_handshake = @import("../tls/client_handshake.zig");
const client_hello = @import("../tls/client_hello.zig");
const key_schedule = @import("../tls/key_schedule.zig");
const secret = @import("../tls/secret.zig");
const server_flight = @import("../tls/server_flight.zig");
const server_hello = @import("../tls/server_hello.zig");
const transcript = @import("../tls/transcript.zig");
const traffic = @import("traffic_crypto.zig");
const tls_secrets = @import("tls_secrets.zig");

pub const handshake_type_finished: u8 = 0x14;

pub const Error = std.mem.Allocator.Error || server_flight.Error ||
    server_hello.Error || client_handshake.Error || key_schedule.Error ||
    auth.Error || error{
    InvalidFinished,
    InvalidSecondClientHello,
    InvalidRetryCookie,
    EarlyDataAfterRetry,
    MissingAlpn,
    NoApplicationProtocol,
    ServerSelectedUnofferedSuite,
    ServerSelectedUnofferedGroup,
    ServerSelectedUnofferedAlpn,
    SessionIdMismatch,
    UnsupportedEch,
    UnsupportedPsk,
    InvalidRetryState,
};

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
    client_auth: ?ClientAuthState,

    pub fn deinit(self: *Result) void {
        if (self.client_auth) |state| {
            self.allocator.free(state.request_context);
            self.allocator.free(state.certificate_compression_algorithms);
        }
        self.handshake_secret.deinit();
        self.client_handshake_traffic_secret.deinit();
        self.server_handshake_traffic_secret.deinit();
        wipeDirectionalKeys(&self.handshake_packet_keys);
        wipeDirectionalKeys(&self.application_packet_keys);
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
    retry: ?RetryState = null,
    labels: traffic.Labels = traffic.labels_v1,
};

pub const RetryState = struct {
    cipher_suite: cipher_suite.Suite,
    selected_group: u16,
    transcript_prefix: transcript.State,
    second_client_hello_hash: transcript.Digest,
};

/// Validate both ClientHellos and the intervening HelloRetryRequest, then
/// return the transcript state consumed by the final client/server flight.
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
    if (first.pre_shared_key != null or first.early_data) {
        return error.UnsupportedPsk;
    }
    if (first.encrypted_client_hello != null) return error.UnsupportedEch;

    const retry = try server_hello.parseHelloRetryRequest(hello_retry_request);
    if (retry.ech_confirmation != null) return error.UnsupportedEch;
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
    var prefix = transcript.afterHelloRetryRequest(
        retry.cipher_suite.hash(),
        first_client_hello,
        hello_retry_request,
    );
    prefix.update(second_client_hello);
    return .{
        .cipher_suite = retry.cipher_suite,
        .selected_group = retry.selected_group,
        .transcript_prefix = prefix,
        .second_client_hello_hash = transcript.hashFor(
            retry.cipher_suite.hash(),
            &.{second_client_hello},
        ),
    };
}

pub const ClientAuthOptions = struct {
    policy: client_auth.ServerPolicy,
    request_context: []const u8 = &.{},
    certificate_authorities: []const []const u8 = &.{},
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{ .zlib, .brotli },
    max_decompressed_certificate_len: usize = 64 * 1024,
};

pub const ClientAuthState = struct {
    policy: client_auth.ServerPolicy,
    request_context: []u8,
    certificate_compression_algorithms: []certificate_compression.Algorithm,
    max_decompressed_certificate_len: usize,
};

pub const ClientFlightResult = struct {
    allocator: std.mem.Allocator,
    peer_certificate_chain: [][]const u8,
    client_certificate_compression: ?certificate_compression.Algorithm,
    transcript_after_client_finished: transcript.Digest,

    pub fn deinit(self: *ClientFlightResult) void {
        freeCertificateChain(self.allocator, self.peer_certificate_chain);
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

    pub fn deinit(self: *ClientResult) void {
        self.allocator.free(self.selected_alpn);
        self.allocator.free(self.peer_transport_parameters);
        self.verified.deinit();
        wipeDirectionalKeys(&self.handshake_packet_keys);
        wipeDirectionalKeys(&self.application_packet_keys);
        self.* = undefined;
    }
};

/// Authenticate a plaintext QUIC Handshake CRYPTO flight, emit the plaintext
/// client authentication/Finished flight, and derive Handshake plus 1-RTT
/// packet keys. A validated `RetryState` carries HRR transcript state. PSK,
/// 0-RTT, and ECH remain reserved for a stateful QUIC connection driver.
pub fn writeClientCryptoFlight(
    handshake_crypto: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: ClientOptions,
) Error!ClientResult {
    const output_start = handshake_crypto.items.len;
    errdefer handshake_crypto.shrinkRetainingCapacity(output_start);

    const parsed_client = try client_hello.parse(options.client_hello_bytes);
    if (!parsed_client.offersTls13()) return error.InvalidClientHello;
    if (parsed_client.quic_transport_parameters == null) {
        return error.MissingQuicTransportParameters;
    }
    if (parsed_client.alpn_protocols.len == 0) return error.MissingAlpn;
    if (parsed_client.pre_shared_key != null or parsed_client.early_data) {
        return error.UnsupportedPsk;
    }
    if (parsed_client.encrypted_client_hello != null) {
        return error.UnsupportedEch;
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
    if (parsed_server.selected_psk_identity != null) {
        return error.UnsupportedPsk;
    }
    if (options.retry) |retry| {
        try validateRetryState(
            retry,
            parsed_server.cipher_suite,
            parsed_server.key_share_group,
            options.client_hello_bytes,
        );
    }

    const flight = try client_handshake.splitServerFlight(
        options.server_handshake_crypto,
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
        null,
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
    errdefer wipeDirectionalKeys(&handshake_packet_keys);
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
            .server_verifier = options.server_verifier,
            .server_certificate_type = options.server_certificate_type,
            .server_name = options.server_name,
            .certificate_compression_algorithms = options.certificate_compression_algorithms,
            .max_decompressed_certificate_len = options.max_decompressed_certificate_len,
            .client_identity = options.client_identity,
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
    };
}

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
    if (options.parsed_client_hello.pre_shared_key != null or
        options.parsed_client_hello.early_data)
    {
        return error.UnsupportedPsk;
    }
    if (options.parsed_client_hello.encrypted_client_hello != null) {
        return error.UnsupportedEch;
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
        );
    }
    if (!try options.parsed_client_hello.supportsSignatureScheme(
        options.signer.scheme(),
    )) return error.UnsupportedSignatureScheme;
    try (auth.ServerIdentity{
        .certificate_chain = options.certificate_chain,
        .signer = options.signer,
        .certificate_type = options.policy.server_certificate_type,
    }).validate();

    var server_hello_msg: std.ArrayList(u8) = .empty;
    defer server_hello_msg.deinit(allocator);
    try server_hello.writeServerHello(&server_hello_msg, allocator, .{
        .random = options.server_random,
        .session_id_echo = options.parsed_client_hello.session_id,
        .cipher_suite = selection.suite,
        .key_share_group = selection.key_share_group,
        .key_share = options.server_key_share,
    });
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
        null,
    );
    defer handshake.early_secret.deinit();
    errdefer handshake.handshake_secret.deinit();
    errdefer handshake.client_traffic_secret.deinit();
    errdefer handshake.server_traffic_secret.deinit();

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(allocator);
    try server_hello.writeEncryptedExtensions(&encrypted_extensions, allocator, .{
        .alpn_protocol = selection.alpn_protocol,
        .quic_transport_parameters = options.policy.quic_transport_parameters,
        .server_certificate_type = if (selection.send_server_certificate_type)
            selection.server_certificate_type
        else
            null,
        .client_certificate_type = if (selection.send_client_certificate_type)
            selection.client_certificate_type
        else
            null,
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
        try client_auth.writeRequestWithCompression(
            &certificate_request,
            allocator,
            client_auth_options.request_context,
            client_auth_options.certificate_authorities,
            client_auth_options.certificate_compression_algorithms,
        );
        try handshake_crypto.appendSlice(allocator, certificate_request.items);
        transcript_state.update(certificate_request.items);
    }

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try auth.writeCertificate(
        &certificate,
        allocator,
        options.certificate_chain,
    );
    try handshake_crypto.appendSlice(allocator, certificate.items);
    transcript_state.update(certificate.items);

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

    const retained_client_auth: ?ClientAuthState = if (options.client_auth) |value| blk: {
        const request_context = try allocator.dupe(u8, value.request_context);
        errdefer allocator.free(request_context);
        const algorithms = try allocator.dupe(
            certificate_compression.Algorithm,
            value.certificate_compression_algorithms,
        );
        break :blk .{
            .policy = value.policy,
            .request_context = request_context,
            .certificate_compression_algorithms = algorithms,
            .max_decompressed_certificate_len = value.max_decompressed_certificate_len,
        };
    } else null;
    errdefer if (retained_client_auth) |state| {
        allocator.free(state.request_context);
        allocator.free(state.certificate_compression_algorithms);
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
        .client_auth = retained_client_auth,
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
    if (server.client_auth) |auth_state| {
        var offset: usize = 0;
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

        var verification = try client_auth.verifyClientFlightWithCompression(
            allocator,
            auth_state.policy,
            auth_state.request_context,
            server.transcript_state_after_server_finished,
            server.client_handshake_traffic_secret,
            certificate,
            certificate_verify,
            next,
            auth_state.certificate_compression_algorithms,
            auth_state.max_decompressed_certificate_len,
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
        };
    }

    var offset: usize = 0;
    const finished = try takeHandshakeMessage(client_handshake_crypto, &offset);
    if (offset != client_handshake_crypto.len) {
        return error.InvalidClientFlight;
    }
    var state = server.transcript_state_after_server_finished;
    try verifyClientFinished(
        &state,
        server.client_handshake_traffic_secret,
        finished,
    );
    return .{
        .allocator = allocator,
        .peer_certificate_chain = try allocator.alloc([]const u8, 0),
        .client_certificate_compression = null,
        .transcript_after_client_finished = state.digest(),
    };
}

fn validateRetryState(
    retry: RetryState,
    suite: cipher_suite.Suite,
    selected_group: u16,
    second_client_hello: []const u8,
) Error!void {
    if (retry.cipher_suite != suite or
        retry.selected_group != selected_group or
        retry.transcript_prefix.digest().hash != suite.hash())
    {
        return error.InvalidRetryState;
    }
    const actual_hash = transcript.hashFor(
        suite.hash(),
        &.{second_client_hello},
    );
    if (!std.mem.eql(
        u8,
        retry.second_client_hello_hash.bytes(),
        actual_hash.bytes(),
    )) return error.InvalidRetryState;
}

fn verifyClientFinished(
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

fn takeHandshakeMessage(
    bytes: []const u8,
    offset: *usize,
) Error![]const u8 {
    if (bytes.len -| offset.* < 4) return error.InvalidClientFlight;
    const body_len =
        (@as(usize, bytes[offset.* + 1]) << 16) |
        (@as(usize, bytes[offset.* + 2]) << 8) |
        bytes[offset.* + 3];
    const message_len = std.math.add(usize, 4, body_len) catch
        return error.InvalidClientFlight;
    if (message_len > bytes.len - offset.*) {
        return error.InvalidClientFlight;
    }
    const message = bytes[offset.*..][0..message_len];
    offset.* += message_len;
    return message;
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

fn writeFinished(
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

test "QUIC TLS server flight emits CRYPTO bytes by encryption level" {
    const allocator = std.testing.allocator;
    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x56} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const cert = ed25519SubjectPublicKeyInfo(key_pair.public_key.toBytes());
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.write(&hello, allocator, .{
        .random = [_]u8{0x11} ** 32,
        .session_id = &.{ 1, 2, 3 },
        .server_name = "example.com",
        .x25519_public_key = [_]u8{0x12} ** 32,
        .cipher_suites = &.{
            .aes_128_gcm_sha256,
            .chacha20_poly1305_sha256,
        },
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
    });
    const parsed = try client_hello.parse(hello.items);
    var initial_crypto: std.ArrayList(u8) = .empty;
    defer initial_crypto.deinit(allocator);
    var handshake_crypto: std.ArrayList(u8) = .empty;
    defer handshake_crypto.deinit(allocator);

    var result = try writeServerCryptoFlight(
        &initial_crypto,
        &handshake_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed,
            .policy = .{
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
            },
            .server_random = [_]u8{0x22} ** 32,
            .server_key_share = &.{ 9, 8, 7, 6 },
            .shared_secret = &([_]u8{0x33} ** 32),
            .certificate_chain = &.{&cert},
            .signer = .{ .ed25519 = .{ .key_pair = key_pair } },
        },
    );
    defer result.deinit();

    try std.testing.expectEqual(
        server_hello.handshake_type_server_hello,
        initial_crypto.items[0],
    );
    try std.testing.expectEqual(
        server_hello.handshake_type_encrypted_extensions,
        handshake_crypto.items[0],
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        handshake_crypto.items,
        &.{ 0x00, 0x39, 0x00, 0x03, 4, 5, 6 },
    ) != null);
    try std.testing.expectEqual(
        secret.Hash.sha256,
        result.client_handshake_traffic_secret.hash,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &result.handshake_packet_keys.client.key,
        &result.application_packet_keys.client.key,
    ));
}

test "QUIC TLS client authenticates server CRYPTO and writes Finished" {
    const allocator = std.testing.allocator;
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x71} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const public_key = signing_key.public_key.toBytes();
    const public_key_spki = ed25519SubjectPublicKeyInfo(public_key);
    const client_signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x79} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const client_public_key_spki = ed25519SubjectPublicKeyInfo(
        client_signing_key.public_key.toBytes(),
    );
    const client_identity = client_auth.ClientIdentity{
        .certificate_chain = &.{&client_public_key_spki},
        .signer = .{ .ed25519 = .{ .key_pair = client_signing_key } },
        .certificate_type = .raw_public_key,
    };
    const client_parameters = [_]u8{ 0x01, 0x04, 0x80, 0x00, 0x75, 0x30 };
    const server_parameters = [_]u8{ 0x03, 0x02, 0x44, 0xb0 };
    const shared_secret = [_]u8{0x72} ** 32;

    var client_hello_bytes: std.ArrayList(u8) = .empty;
    defer client_hello_bytes.deinit(allocator);
    try client_hello.write(&client_hello_bytes, allocator, .{
        .random = [_]u8{0x73} ** 32,
        .session_id = "quic-client",
        .server_name = "quic.example",
        .x25519_public_key = [_]u8{0x74} ** 32,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &client_parameters,
        .server_certificate_types = &.{.raw_public_key},
        .client_certificate_types = &.{.raw_public_key},
    });
    const parsed_client = try client_hello.parse(client_hello_bytes.items);

    var initial_crypto: std.ArrayList(u8) = .empty;
    defer initial_crypto.deinit(allocator);
    var server_crypto: std.ArrayList(u8) = .empty;
    defer server_crypto.deinit(allocator);
    var server_result = try writeServerCryptoFlight(
        &initial_crypto,
        &server_crypto,
        allocator,
        .{
            .client_hello_bytes = client_hello_bytes.items,
            .parsed_client_hello = parsed_client,
            .policy = .{
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &server_parameters,
                .server_certificate_type = .raw_public_key,
                .client_certificate_type = .raw_public_key,
            },
            .server_random = [_]u8{0x75} ** 32,
            .server_key_share = &.{ 0x76, 0x77, 0x78 },
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .client_auth = .{
                .policy = .{
                    .verifier = .{
                        .pinned_raw_public_key = &client_public_key_spki,
                    },
                    .certificate_type = .raw_public_key,
                },
                .request_context = "quic-mtls",
            },
        },
    );
    defer server_result.deinit();

    var client_crypto: std.ArrayList(u8) = .empty;
    defer client_crypto.deinit(allocator);
    var client_result = try writeClientCryptoFlight(
        &client_crypto,
        allocator,
        .{
            .client_hello_bytes = client_hello_bytes.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .client_identity = client_identity,
        },
    );
    defer client_result.deinit();

    try std.testing.expectEqualStrings("h3", client_result.selected_alpn);
    try std.testing.expectEqualSlices(
        u8,
        &server_parameters,
        client_result.peer_transport_parameters,
    );
    try std.testing.expectEqual(
        auth.CertificateType.raw_public_key,
        client_result.verified.server_certificate_type,
    );
    try std.testing.expectEqualSlices(
        u8,
        &public_key_spki,
        client_result.verified.peer_certificate_chain[0],
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_result.handshake_packet_keys.client.key,
        &client_result.handshake_packet_keys.client.key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_result.handshake_packet_keys.server.key,
        &client_result.handshake_packet_keys.server.key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_result.application_packet_keys.client.key,
        &client_result.application_packet_keys.client.key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_result.application_packet_keys.server.key,
        &client_result.application_packet_keys.server.key,
    );

    var client_flight = try verifyClientCryptoFlight(
        allocator,
        &server_result,
        client_crypto.items,
    );
    defer client_flight.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &client_public_key_spki,
        client_flight.peer_certificate_chain[0],
    );
    try std.testing.expectEqualSlices(
        u8,
        client_result.verified.transcript_after_client_finished.bytes(),
        client_flight.transcript_after_client_finished.bytes(),
    );

    const encrypted_extensions_len = 4 +
        ((@as(usize, server_crypto.items[1]) << 16) |
            (@as(usize, server_crypto.items[2]) << 8) |
            server_crypto.items[3]);
    var invalid_server_crypto: std.ArrayList(u8) = .empty;
    defer invalid_server_crypto.deinit(allocator);
    try server_hello.writeEncryptedExtensions(
        &invalid_server_crypto,
        allocator,
        .{
            .alpn_protocol = "h3",
            .server_certificate_type = .raw_public_key,
        },
    );
    try invalid_server_crypto.appendSlice(
        allocator,
        server_crypto.items[encrypted_extensions_len..],
    );
    var rejected_output: std.ArrayList(u8) = .empty;
    defer rejected_output.deinit(allocator);
    try std.testing.expectError(
        error.MissingQuicTransportParameters,
        writeClientCryptoFlight(&rejected_output, allocator, .{
            .client_hello_bytes = client_hello_bytes.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = invalid_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .client_identity = client_identity,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_output.items.len);

    invalid_server_crypto.clearRetainingCapacity();
    try server_hello.writeEncryptedExtensions(
        &invalid_server_crypto,
        allocator,
        .{
            .alpn_protocol = "h2",
            .quic_transport_parameters = &server_parameters,
            .server_certificate_type = .raw_public_key,
        },
    );
    try invalid_server_crypto.appendSlice(
        allocator,
        server_crypto.items[encrypted_extensions_len..],
    );
    try std.testing.expectError(
        error.ServerSelectedUnofferedAlpn,
        writeClientCryptoFlight(&rejected_output, allocator, .{
            .client_hello_bytes = client_hello_bytes.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = invalid_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .client_identity = client_identity,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_output.items.len);

    invalid_server_crypto.clearRetainingCapacity();
    try invalid_server_crypto.appendSlice(allocator, server_crypto.items);
    invalid_server_crypto.items[invalid_server_crypto.items.len - 1] ^= 1;
    try std.testing.expectError(
        error.BadServerFinished,
        writeClientCryptoFlight(&rejected_output, allocator, .{
            .client_hello_bytes = client_hello_bytes.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = invalid_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .client_identity = client_identity,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_output.items.len);

    const tampered_client_crypto = try allocator.dupe(u8, client_crypto.items);
    defer allocator.free(tampered_client_crypto);
    tampered_client_crypto[tampered_client_crypto.len - 1] ^= 1;
    try std.testing.expectError(
        error.BadClientFinished,
        verifyClientCryptoFlight(
            allocator,
            &server_result,
            tampered_client_crypto,
        ),
    );

    @memset(server_crypto.items, 0);
    try std.testing.expectEqualStrings("h3", client_result.selected_alpn);
    try std.testing.expectEqualSlices(
        u8,
        &server_parameters,
        client_result.peer_transport_parameters,
    );
    try std.testing.expectEqualSlices(
        u8,
        &public_key_spki,
        client_result.verified.peer_certificate_chain[0],
    );
}

test "QUIC TLS client and server preserve the HelloRetryRequest transcript" {
    const allocator = std.testing.allocator;
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x91} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const public_key_spki = ed25519SubjectPublicKeyInfo(
        signing_key.public_key.toBytes(),
    );
    const p256_share = [_]u8{0x04} ++ ([_]u8{0x92} ** 64);
    const shared_secret = [_]u8{0x93} ** 32;

    var first_hello: std.ArrayList(u8) = .empty;
    defer first_hello.deinit(allocator);
    try client_hello.writeWithKeyShare(&first_hello, allocator, .{
        .random = [_]u8{0x94} ** 32,
        .session_id = "quic-hrr",
        .server_name = "quic.example",
        .key_share = .{
            .group = 0x001d,
            .key_exchange = &([_]u8{0x95} ** 32),
        },
        .supported_groups = &.{ 0x001d, 0x0017 },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
    });
    var retry_bytes: std.ArrayList(u8) = .empty;
    defer retry_bytes.deinit(allocator);
    try server_hello.writeHelloRetryRequest(&retry_bytes, allocator, .{
        .session_id_echo = "quic-hrr",
        .cipher_suite = .aes_128_gcm_sha256,
        .selected_group = 0x0017,
        .cookie = "quic-cookie",
    });
    var second_hello: std.ArrayList(u8) = .empty;
    defer second_hello.deinit(allocator);
    try client_hello.writeWithKeyShare(&second_hello, allocator, .{
        .random = [_]u8{0x94} ** 32,
        .session_id = "quic-hrr",
        .server_name = "quic.example",
        .key_share = .{
            .group = 0x0017,
            .key_exchange = &p256_share,
        },
        .supported_groups = &.{ 0x001d, 0x0017 },
        .cookie = "quic-cookie",
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
    });
    const retry = try prepareRetryState(
        first_hello.items,
        retry_bytes.items,
        second_hello.items,
    );

    var initial_crypto: std.ArrayList(u8) = .empty;
    defer initial_crypto.deinit(allocator);
    var server_crypto: std.ArrayList(u8) = .empty;
    defer server_crypto.deinit(allocator);
    var server_result = try writeServerCryptoFlight(
        &initial_crypto,
        &server_crypto,
        allocator,
        .{
            .client_hello_bytes = second_hello.items,
            .parsed_client_hello = try client_hello.parse(second_hello.items),
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{0x0017},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
            },
            .server_random = [_]u8{0x96} ** 32,
            .server_key_share = &p256_share,
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .retry = retry,
        },
    );
    defer server_result.deinit();

    var client_crypto: std.ArrayList(u8) = .empty;
    defer client_crypto.deinit(allocator);
    var client_result = try writeClientCryptoFlight(
        &client_crypto,
        allocator,
        .{
            .client_hello_bytes = second_hello.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .retry = retry,
        },
    );
    defer client_result.deinit();
    var verified_client = try verifyClientCryptoFlight(
        allocator,
        &server_result,
        client_crypto.items,
    );
    defer verified_client.deinit();
    try std.testing.expectEqual(@as(usize, 0), verified_client.peer_certificate_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        &server_result.application_packet_keys.client.key,
        &client_result.application_packet_keys.client.key,
    );
    try std.testing.expectEqualSlices(
        u8,
        client_result.verified.transcript_after_client_finished.bytes(),
        verified_client.transcript_after_client_finished.bytes(),
    );

    var wrong_transcript_output: std.ArrayList(u8) = .empty;
    defer wrong_transcript_output.deinit(allocator);
    try std.testing.expectError(
        error.BadCertificateVerify,
        writeClientCryptoFlight(&wrong_transcript_output, allocator, .{
            .client_hello_bytes = second_hello.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
        }),
    );

    var altered_second_hello: std.ArrayList(u8) = .empty;
    defer altered_second_hello.deinit(allocator);
    try client_hello.writeWithKeyShare(&altered_second_hello, allocator, .{
        .random = [_]u8{0x94} ** 32,
        .session_id = "quic-hrr",
        .server_name = "quic.example",
        .key_share = .{
            .group = 0x0017,
            .key_exchange = &p256_share,
        },
        .supported_groups = &.{ 0x001d, 0x0017 },
        .cookie = "quic-cookie",
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 9, 9, 9 },
        .server_certificate_types = &.{.raw_public_key},
    });
    try std.testing.expectError(
        error.InvalidSecondClientHello,
        prepareRetryState(
            first_hello.items,
            retry_bytes.items,
            altered_second_hello.items,
        ),
    );

    var wrong_retry = retry;
    wrong_retry.selected_group = 0x001d;
    try std.testing.expectError(
        error.InvalidRetryState,
        writeClientCryptoFlight(&wrong_transcript_output, allocator, .{
            .client_hello_bytes = second_hello.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .retry = wrong_retry,
        }),
    );
}

test "QUIC TLS server requires transport parameters and a common ALPN" {
    const allocator = std.testing.allocator;
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x81} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    const shared_secret = [_]u8{0x82} ** 32;
    var client_hello_bytes: std.ArrayList(u8) = .empty;
    defer client_hello_bytes.deinit(allocator);
    var initial_crypto: std.ArrayList(u8) = .empty;
    defer initial_crypto.deinit(allocator);
    var handshake_crypto: std.ArrayList(u8) = .empty;
    defer handshake_crypto.deinit(allocator);

    try client_hello.write(&client_hello_bytes, allocator, .{
        .random = [_]u8{0x83} ** 32,
        .x25519_public_key = [_]u8{0x84} ** 32,
        .alpn_protocols = &.{"h3"},
    });
    try std.testing.expectError(
        error.MissingQuicTransportParameters,
        writeServerCryptoFlight(
            &initial_crypto,
            &handshake_crypto,
            allocator,
            .{
                .client_hello_bytes = client_hello_bytes.items,
                .parsed_client_hello = try client_hello.parse(
                    client_hello_bytes.items,
                ),
                .policy = .{
                    .alpn_protocols = &.{"h3"},
                    .quic_transport_parameters = &.{1},
                },
                .server_random = [_]u8{0x85} ** 32,
                .server_key_share = &.{1},
                .shared_secret = &shared_secret,
                .certificate_chain = &.{&certificate},
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            },
        ),
    );
    try std.testing.expectError(
        error.MissingQuicTransportParameters,
        writeClientCryptoFlight(&handshake_crypto, allocator, .{
            .client_hello_bytes = client_hello_bytes.items,
            .server_hello_bytes = &.{},
            .server_handshake_crypto = &.{},
            .shared_secret = &shared_secret,
            .server_verifier = .{},
            .server_name = "quic.example",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), handshake_crypto.items.len);

    client_hello_bytes.clearRetainingCapacity();
    try client_hello.write(&client_hello_bytes, allocator, .{
        .random = [_]u8{0x83} ** 32,
        .x25519_public_key = [_]u8{0x84} ** 32,
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{1},
    });
    try std.testing.expectError(
        error.NoApplicationProtocol,
        writeServerCryptoFlight(
            &initial_crypto,
            &handshake_crypto,
            allocator,
            .{
                .client_hello_bytes = client_hello_bytes.items,
                .parsed_client_hello = try client_hello.parse(
                    client_hello_bytes.items,
                ),
                .policy = .{
                    .alpn_protocols = &.{"h2"},
                    .quic_transport_parameters = &.{2},
                },
                .server_random = [_]u8{0x85} ** 32,
                .server_key_share = &.{1},
                .shared_secret = &shared_secret,
                .certificate_chain = &.{&certificate},
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), initial_crypto.items.len);
    try std.testing.expectEqual(@as(usize, 0), handshake_crypto.items.len);
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

fn wipeDirectionalKeys(keys: *tls_secrets.DirectionalKeys) void {
    std.crypto.secureZero(u8, std.mem.asBytes(keys));
}
