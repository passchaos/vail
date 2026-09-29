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
    MissingAlpn,
    NoApplicationProtocol,
    ServerSelectedUnofferedSuite,
    ServerSelectedUnofferedGroup,
    ServerSelectedUnofferedAlpn,
    SessionIdMismatch,
    UnsupportedEch,
    UnsupportedPsk,
};

pub const Result = struct {
    selection: server_flight.Selection,
    handshake_secret: secret.Secret,
    client_handshake_traffic_secret: secret.Secret,
    server_handshake_traffic_secret: secret.Secret,
    transcript_after_server_finished: transcript.Digest,
    handshake_packet_keys: tls_secrets.DirectionalKeys,
    application_packet_keys: tls_secrets.DirectionalKeys,

    pub fn deinit(self: *Result) void {
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
    labels: traffic.Labels = traffic.labels_v1,
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
/// packet keys. PSK/0-RTT, ECH, and HRR are intentionally rejected until a
/// stateful QUIC handshake driver can preserve their extra transcript state.
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

    const hello_hash = transcript.hashFor(
        parsed_server.cipher_suite.hash(),
        &.{ options.client_hello_bytes, options.server_hello_bytes },
    );
    var handshake = try key_schedule.deriveHandshakeFor(
        parsed_server.cipher_suite.hash(),
        options.shared_secret,
        hello_hash,
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
    const selection = try server_flight.select(
        options.parsed_client_hello,
        options.policy,
    );
    if (selection.alpn_protocol == null) {
        return error.NoApplicationProtocol;
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

    const hello_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{ options.client_hello_bytes, server_hello_msg.items },
    );
    var handshake = try key_schedule.deriveHandshakeFor(
        selection.suite.hash(),
        options.shared_secret,
        hello_hash,
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

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try auth.writeCertificate(
        &certificate,
        allocator,
        options.certificate_chain,
    );
    try handshake_crypto.appendSlice(allocator, certificate.items);

    const certificate_verify_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate.items,
        },
    );
    var certificate_verify: std.ArrayList(u8) = .empty;
    defer certificate_verify.deinit(allocator);
    try auth.writeCertificateVerify(
        &certificate_verify,
        allocator,
        options.signer,
        certificate_verify_hash.bytes(),
    );
    try handshake_crypto.appendSlice(allocator, certificate_verify.items);

    const finished_hash = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate.items,
            certificate_verify.items,
        },
    );
    const verify_data = try key_schedule.computeFinishedFor(
        handshake.server_traffic_secret,
        finished_hash,
    );
    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try writeFinished(&finished, allocator, verify_data.bytes());
    try handshake_crypto.appendSlice(allocator, finished.items);

    const transcript_after_server_finished = transcript.hashFor(
        selection.suite.hash(),
        &.{
            options.client_hello_bytes,
            server_hello_msg.items,
            encrypted_extensions.items,
            certificate.items,
            certificate_verify.items,
            finished.items,
        },
    );
    var application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        transcript_after_server_finished,
    );
    defer application.master_secret.deinit();
    defer application.client_traffic_secret.deinit();
    defer application.server_traffic_secret.deinit();

    return .{
        .selection = selection,
        .handshake_secret = handshake.handshake_secret,
        .client_handshake_traffic_secret = handshake.client_traffic_secret,
        .server_handshake_traffic_secret = handshake.server_traffic_secret,
        .transcript_after_server_finished = transcript_after_server_finished,
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
    };
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
            },
            .server_random = [_]u8{0x75} ** 32,
            .server_key_share = &.{ 0x76, 0x77, 0x78 },
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
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

    try std.testing.expectEqual(@as(usize, 36), client_crypto.items.len);
    try std.testing.expectEqual(handshake_type_finished, client_crypto.items[0]);
    var actual_finished = try secret.Secret.init(
        .sha256,
        client_crypto.items[4..],
    );
    defer actual_finished.deinit();
    try key_schedule.verifyFinishedFor(
        server_result.client_handshake_traffic_secret,
        server_result.transcript_after_server_finished,
        actual_finished,
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
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_output.items.len);

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
