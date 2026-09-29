//! TLS 1.3 authenticated server-flight processing and client-flight creation.
//!
//! Record transports decrypt/reassemble the server's encrypted handshake bytes
//! and pass them here. This module owns transcript ordering, server trust and
//! possession checks, optional client identity selection, and both Finished
//! calculations without depending on TCP or QUIC framing.

const std = @import("std");
const auth = @import("auth.zig");
const certificate_compression = @import("certificate_compression.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_auth = @import("client_auth.zig");
const key_schedule = @import("key_schedule.zig");
const secret = @import("secret.zig");
const server_handshake = @import("server_handshake.zig");
const server_hello = @import("server_hello.zig");
const transcript = @import("transcript.zig");

pub const handshake_type_end_of_early_data: u8 = 0x05;

pub const Error = std.mem.Allocator.Error || auth.Error ||
    certificate_compression.Error || client_auth.Error ||
    key_schedule.Error || secret.Error ||
    server_hello.Error || error{
    BadServerFinished,
    InvalidServerFlight,
    UnsupportedSignatureScheme,
};

pub const ServerFlight = struct {
    encrypted_extensions: []const u8,
    certificate_request: ?[]const u8 = null,
    certificate: ?[]const u8,
    certificate_verify: ?[]const u8,
    before_finished: []const u8,
    finished: []const u8,
};

pub const Options = struct {
    client_hello_bytes: []const u8,
    server_hello_bytes: []const u8,
    encrypted_server_flight: []const u8,
    handshake_secret: secret.Secret,
    client_handshake_traffic_secret: secret.Secret,
    server_handshake_traffic_secret: secret.Secret,
    /// Transcript through ClientHello2 for a HelloRetryRequest handshake.
    transcript_prefix: ?transcript.State = null,
    psk_resumed: bool = false,
    early_data_offered: bool = false,
    server_verifier: auth.ClientVerifier,
    server_name: ?[]const u8,
    certificate_compression_algorithms: []const certificate_compression.Algorithm = &.{},
    max_decompressed_certificate_len: usize = 64 * 1024,
    client_identity: ?client_auth.ClientIdentity = null,
};

pub const Result = struct {
    allocator: std.mem.Allocator,
    /// Cipher suite authenticated by the complete TLS 1.3 server flight.
    /// Keeping it with the established secrets lets transports report the
    /// negotiated AEAD and transcript hash after handshake buffers are gone.
    cipher_suite: cipher_suite.Suite,
    application: key_schedule.RuntimeApplicationSecrets,
    transcript_after_server_finished: transcript.Digest,
    transcript_after_client_finished: transcript.Digest,
    selected_alpn: ?[]const u8,
    /// Deep-owned authenticated server certificate chain. Verification runs
    /// against the parser's borrowed views first; copies are retained only
    /// after trust, CertificateVerify, and Finished all succeed.
    peer_certificate_chain: [][]const u8,
    early_data_accepted: bool,
    /// Compression used by the authenticated server Certificate message.
    certificate_compression: ?certificate_compression.Algorithm,
    /// Compression used for this client's Certificate response.
    client_certificate_compression: ?certificate_compression.Algorithm,

    pub fn deinit(self: *Result) void {
        self.application.master_secret.deinit();
        self.application.client_traffic_secret.deinit();
        self.application.server_traffic_secret.deinit();
        for (self.peer_certificate_chain) |certificate| {
            self.allocator.free(certificate);
        }
        self.allocator.free(self.peer_certificate_chain);
        self.* = undefined;
    }
};

/// Verify the authenticated server flight and append the exact client flight.
pub fn verifyServerAndWriteClientFlight(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: Options,
) Error!Result {
    const parsed_server_hello = try server_hello.parseServerHello(
        options.server_hello_bytes,
    );
    const flight = try splitServerFlightForMode(
        options.encrypted_server_flight,
        options.psk_resumed,
    );
    const encrypted_extensions =
        try server_hello.parseEncryptedExtensions(
            flight.encrypted_extensions,
        );
    if (encrypted_extensions.early_data_accepted and
        (!options.psk_resumed or !options.early_data_offered))
    {
        return error.InvalidServerFlight;
    }

    var state = options.transcript_prefix orelse blk: {
        var initial = transcript.State.init(
            parsed_server_hello.cipher_suite.hash(),
        );
        initial.update(options.client_hello_bytes);
        break :blk initial;
    };
    state.update(options.server_hello_bytes);
    state.update(flight.encrypted_extensions);
    if (flight.certificate_request) |request| state.update(request);

    var peer_certificate_chain = try allocator.alloc([]const u8, 0);
    var selected_certificate_compression: ?certificate_compression.Algorithm = null;
    if (!options.psk_resumed) {
        const certificate_wire = flight.certificate orelse
            return error.InvalidServerFlight;
        var decompressed_certificate: ?[]u8 = null;
        defer if (decompressed_certificate) |message| allocator.free(message);
        const certificate_message = if (certificate_wire[0] ==
            certificate_compression.handshake_type_compressed_certificate)
        blk: {
            selected_certificate_compression =
                (try certificate_compression.parse(certificate_wire)).algorithm;
            decompressed_certificate =
                try certificate_compression.decompressCertificate(
                    allocator,
                    certificate_wire,
                    options.certificate_compression_algorithms,
                    options.max_decompressed_certificate_len,
                );
            break :blk decompressed_certificate.?;
        } else certificate_wire;
        var certificate = try auth.parseCertificate(
            allocator,
            certificate_message,
        );
        defer certificate.deinit(allocator);
        try options.server_verifier.verifyTrustWithOcsp(
            options.server_name,
            certificate.entries,
            certificate.ocsp_response,
        );
        state.update(certificate_wire);
        const parsed_certificate_verify = try auth.parseCertificateVerify(
            flight.certificate_verify orelse
                return error.InvalidServerFlight,
        );
        const certificate_hash = state.digest();
        try auth.verifyCertificateVerify(
            certificate.entries[0],
            parsed_certificate_verify,
            certificate_hash.bytes(),
        );
        state.update(flight.certificate_verify.?);
        peer_certificate_chain = try copyCertificateChain(
            allocator,
            certificate.entries,
        );
    } else if (flight.certificate != null or
        flight.certificate_verify != null)
    {
        return error.InvalidServerFlight;
    }

    const server_verify_data = try parseFinished(
        flight.finished,
        parsed_server_hello.cipher_suite.hash(),
    );
    var expected_server_finished =
        try key_schedule.computeFinishedFor(
            options.server_handshake_traffic_secret,
            state.digest(),
        );
    defer expected_server_finished.deinit();
    var actual_server_finished = try secret.Secret.init(
        expected_server_finished.hash,
        server_verify_data,
    );
    defer actual_server_finished.deinit();
    if (!expected_server_finished.eql(&actual_server_finished)) {
        return error.BadServerFinished;
    }
    state.update(flight.finished);
    const transcript_after_server_finished = state.digest();
    errdefer freeCertificateChain(allocator, peer_certificate_chain);

    var application = try key_schedule.deriveApplicationFor(
        options.handshake_secret,
        transcript_after_server_finished,
    );
    errdefer {
        application.master_secret.deinit();
        application.client_traffic_secret.deinit();
        application.server_traffic_secret.deinit();
    }

    if (encrypted_extensions.early_data_accepted) {
        const end_of_early_data = [_]u8{
            handshake_type_end_of_early_data, 0, 0, 0,
        };
        try out.appendSlice(allocator, &end_of_early_data);
        state.update(&end_of_early_data);
    }

    var selected_client_certificate_compression: ?certificate_compression.Algorithm = null;
    if (flight.certificate_request) |request_bytes| {
        const request = try client_auth.parseRequest(request_bytes);
        const identity = options.client_identity;
        const certificate_start = out.items.len;
        if (identity) |value| {
            var ordinary_certificate: std.ArrayList(u8) = .empty;
            defer ordinary_certificate.deinit(allocator);
            try auth.writeClientCertificateWithContext(
                &ordinary_certificate,
                allocator,
                value.certificate_chain,
                request.request_context,
            );
            for (value.compressed_certificates) |prepared| {
                if (request.supportsCertificateCompression(
                    prepared.algorithm,
                ) and prepared.matchesCertificateMessage(
                    ordinary_certificate.items,
                ) and prepared.savesBytes(ordinary_certificate.items.len)) {
                    try prepared.write(out, allocator);
                    selected_client_certificate_compression =
                        prepared.algorithm;
                    break;
                }
            } else {
                try out.appendSlice(allocator, ordinary_certificate.items);
            }
        } else {
            try auth.writeClientCertificateWithContext(
                out,
                allocator,
                &.{},
                request.request_context,
            );
        }
        state.update(out.items[certificate_start..]);
        if (identity) |value| {
            try value.validate();
            if (!requestSupportsSigner(request, value.signer)) {
                return error.UnsupportedSignatureScheme;
            }
            const certificate_verify_start = out.items.len;
            const client_certificate_hash = state.digest();
            try auth.writeCertificateVerifyForRole(
                out,
                allocator,
                value.signer,
                client_certificate_hash.bytes(),
                .client,
            );
            state.update(out.items[certificate_verify_start..]);
        }
    } else if (options.client_identity != null) {
        // RFC 8446 clients send a certificate only in response to a request.
        return error.InvalidServerFlight;
    }

    var client_verify_data = try key_schedule.computeFinishedFor(
        options.client_handshake_traffic_secret,
        state.digest(),
    );
    defer client_verify_data.deinit();
    const finished_start = out.items.len;
    try writeFinished(out, allocator, client_verify_data.bytes());
    state.update(out.items[finished_start..]);

    return .{
        .allocator = allocator,
        .cipher_suite = parsed_server_hello.cipher_suite,
        .application = application,
        .transcript_after_server_finished = transcript_after_server_finished,
        .transcript_after_client_finished = state.digest(),
        .selected_alpn = encrypted_extensions.alpn_protocol,
        .peer_certificate_chain = peer_certificate_chain,
        .early_data_accepted = encrypted_extensions.early_data_accepted,
        .certificate_compression = selected_certificate_compression,
        .client_certificate_compression = selected_client_certificate_compression,
    };
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

pub fn splitServerFlight(bytes: []const u8) Error!ServerFlight {
    return splitServerFlightForMode(bytes, false);
}

pub fn splitServerFlightForMode(
    bytes: []const u8,
    psk_resumed: bool,
) Error!ServerFlight {
    const encrypted_extensions_len = try handshakeMessageLength(bytes);
    if (bytes[0] != server_hello.handshake_type_encrypted_extensions or
        encrypted_extensions_len >= bytes.len)
    {
        return error.InvalidServerFlight;
    }
    var offset = encrypted_extensions_len;
    var certificate_request: ?[]const u8 = null;
    if (bytes[offset] ==
        client_auth.handshake_type_certificate_request)
    {
        const request_len = try handshakeMessageLength(bytes[offset..]);
        certificate_request = bytes[offset..][0..request_len];
        offset += request_len;
        if (offset >= bytes.len) return error.InvalidServerFlight;
    }
    var certificate: ?[]const u8 = null;
    var certificate_verify: ?[]const u8 = null;
    if (!psk_resumed) {
        if (bytes[offset] != auth.handshake_type_certificate and
            bytes[offset] !=
                certificate_compression.handshake_type_compressed_certificate)
        {
            return error.InvalidServerFlight;
        }
        const certificate_len = try handshakeMessageLength(bytes[offset..]);
        certificate = bytes[offset..][0..certificate_len];
        offset += certificate_len;
        if (offset >= bytes.len or
            bytes[offset] != auth.handshake_type_certificate_verify)
        {
            return error.InvalidServerFlight;
        }
        const certificate_verify_len =
            try handshakeMessageLength(bytes[offset..]);
        certificate_verify = bytes[offset..][0..certificate_verify_len];
        offset += certificate_verify_len;
    }
    if (offset >= bytes.len or
        bytes[offset] != server_handshake.handshake_type_finished)
    {
        return error.InvalidServerFlight;
    }
    const finished_len = try handshakeMessageLength(bytes[offset..]);
    if (offset + finished_len != bytes.len) {
        return error.InvalidServerFlight;
    }
    return .{
        .encrypted_extensions = bytes[0..encrypted_extensions_len],
        .certificate_request = certificate_request,
        .certificate = certificate,
        .certificate_verify = certificate_verify,
        .before_finished = bytes[0..offset],
        .finished = bytes[offset..],
    };
}

fn requestSupportsSigner(
    request: client_auth.ParsedRequest,
    signer: auth.Signer,
) bool {
    return switch (signer.scheme()) {
        auth.signature_scheme_ed25519 => request.supports_ed25519,
        auth.signature_scheme_ecdsa_secp256r1_sha256 => request.supports_ecdsa_p256_sha256,
        auth.signature_scheme_ecdsa_secp384r1_sha384 => request.supports_ecdsa_p384_sha384,
        auth.signature_scheme_sm2sig_sm3 => request.supports_sm2sig_sm3,
        auth.signature_scheme_rsa_pss_rsae_sha256 => request.supports_rsa_pss_rsae_sha256,
        auth.signature_scheme_rsa_pss_rsae_sha384 => request.supports_rsa_pss_rsae_sha384,
        auth.signature_scheme_rsa_pss_rsae_sha512 => request.supports_rsa_pss_rsae_sha512,
        auth.signature_scheme_rsa_pss_pss_sha256 => request.supports_rsa_pss_pss_sha256,
        auth.signature_scheme_rsa_pss_pss_sha384 => request.supports_rsa_pss_pss_sha384,
        auth.signature_scheme_rsa_pss_pss_sha512 => request.supports_rsa_pss_pss_sha512,
        else => false,
    };
}

fn parseFinished(
    bytes: []const u8,
    hash: secret.Hash,
) Error![]const u8 {
    if (bytes.len < 4 or
        bytes[0] != server_handshake.handshake_type_finished)
    {
        return error.InvalidServerFlight;
    }
    const body_len =
        (@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) |
        bytes[3];
    if (body_len != hash.len() or body_len != bytes.len - 4) {
        return error.InvalidServerFlight;
    }
    return bytes[4..];
}

fn writeFinished(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    verify_data: []const u8,
) std.mem.Allocator.Error!void {
    try out.append(
        allocator,
        server_handshake.handshake_type_finished,
    );
    try out.appendSlice(allocator, &.{
        @truncate(verify_data.len >> 16),
        @truncate(verify_data.len >> 8),
        @truncate(verify_data.len),
    });
    try out.appendSlice(allocator, verify_data);
}

fn handshakeMessageLength(bytes: []const u8) Error!usize {
    if (bytes.len < 4) return error.InvalidServerFlight;
    const body_len =
        (@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) |
        bytes[3];
    const total = std.math.add(usize, 4, body_len) catch
        return error.InvalidServerFlight;
    if (total > bytes.len) return error.InvalidServerFlight;
    return total;
}

test "authenticated client handshake verifies server and writes identity" {
    const allocator = std.testing.allocator;
    const server_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x71} **
            std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const client_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x72} **
            std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const server_public = server_key.public_key.toBytes();
    const client_public = client_key.public_key.toBytes();
    const client_hello_bytes = "client-hello";
    const suite = @import("cipher_suite.zig").Suite
        .aes_128_gcm_sha256;
    var server_hello_bytes: std.ArrayList(u8) = .empty;
    defer server_hello_bytes.deinit(allocator);
    try server_hello.writeServerHello(
        &server_hello_bytes,
        allocator,
        .{
            .random = [_]u8{0x74} ** 32,
            .session_id_echo = &.{},
            .cipher_suite = suite,
            .key_share_group = 0x001d,
            .key_share = &([_]u8{0x75} ** 32),
        },
    );
    var state = transcript.State.init(suite.hash());
    state.update(client_hello_bytes);
    state.update(server_hello_bytes.items);
    var handshake = try key_schedule.deriveHandshakeFor(
        suite.hash(),
        &([_]u8{0x73} ** 32),
        state.digest(),
        null,
    );
    defer handshake.early_secret.deinit();
    defer handshake.handshake_secret.deinit();
    defer handshake.client_traffic_secret.deinit();
    defer handshake.server_traffic_secret.deinit();

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(allocator);
    try server_hello.writeEncryptedExtensions(
        &encrypted_extensions,
        allocator,
        .{},
    );
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try client_auth.writeRequest(
        &request,
        allocator,
        &.{},
        &.{},
    );
    var server_certificate: std.ArrayList(u8) = .empty;
    defer server_certificate.deinit(allocator);
    try auth.writeCertificate(
        &server_certificate,
        allocator,
        &.{&server_public},
    );
    var server_state = state;
    server_state.update(encrypted_extensions.items);
    server_state.update(request.items);
    server_state.update(server_certificate.items);
    var server_certificate_verify: std.ArrayList(u8) = .empty;
    defer server_certificate_verify.deinit(allocator);
    const certificate_hash = server_state.digest();
    try auth.writeCertificateVerify(
        &server_certificate_verify,
        allocator,
        .{ .ed25519 = .{ .key_pair = server_key } },
        certificate_hash.bytes(),
    );
    server_state.update(server_certificate_verify.items);
    var server_finished_data = try key_schedule.computeFinishedFor(
        handshake.server_traffic_secret,
        server_state.digest(),
    );
    defer server_finished_data.deinit();
    var server_finished: std.ArrayList(u8) = .empty;
    defer server_finished.deinit(allocator);
    try writeFinished(
        &server_finished,
        allocator,
        server_finished_data.bytes(),
    );
    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(allocator);
    try server_flight.appendSlice(
        allocator,
        encrypted_extensions.items,
    );
    try server_flight.appendSlice(allocator, request.items);
    try server_flight.appendSlice(
        allocator,
        server_certificate.items,
    );
    try server_flight.appendSlice(
        allocator,
        server_certificate_verify.items,
    );
    try server_flight.appendSlice(
        allocator,
        server_finished.items,
    );

    var client_flight: std.ArrayList(u8) = .empty;
    defer client_flight.deinit(allocator);
    var result = try verifyServerAndWriteClientFlight(
        &client_flight,
        allocator,
        .{
            .client_hello_bytes = client_hello_bytes,
            .server_hello_bytes = server_hello_bytes.items,
            .encrypted_server_flight = server_flight.items,
            .handshake_secret = handshake.handshake_secret,
            .client_handshake_traffic_secret = handshake.client_traffic_secret,
            .server_handshake_traffic_secret = handshake.server_traffic_secret,
            .server_verifier = .{
                .pinned_ed25519_public_key = server_public,
            },
            .server_name = null,
            .client_identity = .{
                .certificate_chain = &.{&client_public},
                .signer = .{ .ed25519 = .{ .key_pair = client_key } },
            },
        },
    );
    defer result.deinit();
    try std.testing.expectEqual(suite, result.cipher_suite);
    try std.testing.expectEqual(suite.hash(), result.cipher_suite.hash());
    try std.testing.expectEqual(
        @as(usize, 1),
        result.peer_certificate_chain.len,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_public,
        result.peer_certificate_chain[0],
    );
    try std.testing.expect(
        result.peer_certificate_chain[0].ptr != server_public[0..].ptr,
    );
    const certificate_len = try handshakeMessageLength(
        client_flight.items,
    );
    var parsed_client_certificate =
        try auth.parseClientCertificateWithContext(
            allocator,
            client_flight.items[0..certificate_len],
            &.{},
        );
    defer parsed_client_certificate.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &client_public,
        parsed_client_certificate.entries[0],
    );
}
