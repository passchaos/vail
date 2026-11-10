//! TLS 1.3 handshake adapters for QUIC CRYPTO streams.
//!
//! QUIC carries TLS handshake bytes in CRYPTO frames and protects packets with
//! QUIC packet keys. It never uses TLS record protection. This adapter keeps
//! that boundary explicit: Vail consumes and emits plaintext handshake
//! messages separated by encryption level and returns the packet-protection
//! keys that a transport implementation installs into its
//! Initial/Handshake/1-RTT packet spaces.

const std = @import("std");

const alert = @import("../tls/alert.zig");
const application_settings = @import("../tls/handshake/application_settings.zig");
const auth = @import("../tls/handshake/auth.zig");
const certificate_compression = @import("../tls/handshake/certificate_compression.zig");
const cipher_suite = @import("../tls/crypto/cipher_suite.zig");
const client_auth = @import("../tls/handshake/client_auth.zig");
const client_handshake = @import("../tls/handshake/client_handshake.zig");
const client_hello = @import("../tls/handshake/client_hello.zig");
const ech = @import("../tls/handshake/ech.zig");
const key_schedule = @import("../tls/crypto/key_schedule.zig");
const psk = @import("../tls/crypto/psk.zig");
const secret = @import("../tls/crypto/secret.zig");
const server_flight = @import("../tls/handshake/server_flight.zig");
const server_hello = @import("../tls/handshake/server_hello.zig");
const ticket = @import("../tls/crypto/ticket.zig");
const ticket_keyring = @import("../tls/crypto/ticket_keyring.zig");
const transcript = @import("../tls/crypto/transcript.zig");
const traffic = @import("traffic_crypto.zig");
const tls_secrets = @import("tls_secrets.zig");

pub const common = @import("handshake/common.zig");
pub const client = @import("handshake/client.zig");
pub const server = @import("handshake/server.zig");

pub const handshake_type_finished = common.handshake_type_finished;
pub const ech_required_crypto_error = common.ech_required_crypto_error;
pub const EchStatus = common.EchStatus;
pub const Error = common.Error;
pub const RetryState = common.RetryState;
pub const ResumptionPsk = common.ResumptionPsk;
pub const validateQuicResumption = common.validateQuicResumption;
pub const validateRetryState = common.validateRetryState;
pub const clientHelloEchStatus = common.clientHelloEchStatus;
pub const takeHandshakeMessage = common.takeHandshakeMessage;
pub const freeCertificateChain = common.freeCertificateChain;

pub const Result = server.Result;
pub const Options = server.Options;
pub const ClientAuthOptions = server.ClientAuthOptions;
pub const ClientAuthState = server.ClientAuthState;
pub const NewSessionTicketOptions = server.NewSessionTicketOptions;
pub const prepareRetryState = server.prepareRetryState;
pub const writeServerCryptoFlight = server.writeServerCryptoFlight;
pub const verifyClientCryptoFlight = server.verifyClientCryptoFlight;
pub const writeNewSessionTicket = server.writeNewSessionTicket;
pub const writeRequestedNewSessionTicket = server.writeRequestedNewSessionTicket;
pub const copyCertificateChain = server.copyCertificateChain;
pub const writeFinished = server.writeFinished;
pub const verifyClientFinished = server.verifyClientFinished;

pub const ClientFlightResult = client.ClientFlightResult;
pub const ClientOptions = client.ClientOptions;
pub const ClientResult = client.ClientResult;
pub const EchRejectionOptions = client.EchRejectionOptions;
pub const EchRejection = client.EchRejection;
pub const clientEarlyPacketKeys = client.clientEarlyPacketKeys;
pub const writeClientCryptoFlight = client.writeClientCryptoFlight;
pub const authenticateEchRejection = client.authenticateEchRejection;

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
        .ticket_request = .{
            .new_session_count = 3,
            .resumption_count = 1,
        },
    });
    try psk.appendPskDheMode(&hello, allocator);
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
            .max_requested_tickets = 2,
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
    try std.testing.expect(std.mem.indexOf(
        u8,
        handshake_crypto.items,
        &.{ 0x00, 0x3a, 0x00, 0x01, 2 },
    ) != null);
    try std.testing.expectEqual(@as(u8, 2), result.requested_ticket_count);
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
        .encrypted_client_hello = &.{ech.inner_type},
        .application_settings_protocols = &.{"h3"},
    });
    const parsed_client = try client_hello.parse(client_hello_bytes.items);

    var invalid_context_initial_crypto: std.ArrayList(u8) = .empty;
    defer invalid_context_initial_crypto.deinit(allocator);
    var invalid_context_server_crypto: std.ArrayList(u8) = .empty;
    defer invalid_context_server_crypto.deinit(allocator);
    try std.testing.expectError(
        error.InvalidCertificateRequest,
        writeServerCryptoFlight(
            &invalid_context_initial_crypto,
            &invalid_context_server_crypto,
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
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        invalid_context_initial_crypto.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        invalid_context_server_crypto.items.len,
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
            .client_hello_bytes = client_hello_bytes.items,
            .parsed_client_hello = parsed_client,
            .policy = .{
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &server_parameters,
                .server_certificate_type = .raw_public_key,
                .client_certificate_type = .raw_public_key,
                .application_settings = &.{.{
                    .protocol = "h3",
                    .settings = "quic-server-settings",
                }},
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
            },
            .ech_accepted = true,
        },
    );
    defer server_result.deinit();
    try std.testing.expect(server_result.ech_accepted);

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
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
        },
    );
    defer client_result.deinit();
    try std.testing.expect(client_result.ech_accepted);
    try std.testing.expectEqualStrings(
        "quic-server-settings",
        client_result.verified.peer_application_settings.?,
    );

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
    try std.testing.expectEqualStrings(
        "quic-client-settings",
        client_flight.peer_application_settings.?,
    );
    try std.testing.expectEqualSlices(
        u8,
        client_result.verified.transcript_after_client_finished.bytes(),
        client_flight.transcript_after_client_finished.bytes(),
    );
    var client_extensions_len: usize = 0;
    _ = try takeHandshakeMessage(
        client_crypto.items,
        &client_extensions_len,
    );
    try std.testing.expectError(
        error.InvalidClientFlight,
        verifyClientCryptoFlight(
            allocator,
            &server_result,
            client_crypto.items[client_extensions_len..],
        ),
    );
    const wrong_codepoint = try allocator.dupe(u8, client_crypto.items);
    defer allocator.free(wrong_codepoint);
    wrong_codepoint[6..8].* = .{ 0x44, 0xcd };
    try std.testing.expectError(
        error.InvalidClientFlight,
        verifyClientCryptoFlight(
            allocator,
            &server_result,
            wrong_codepoint,
        ),
    );

    const forged_server_hello = try allocator.dupe(u8, initial_crypto.items);
    defer allocator.free(forged_server_hello);
    forged_server_hello[4 + 2 + 31] ^= 1;
    var forged_output: std.ArrayList(u8) = .empty;
    defer forged_output.deinit(allocator);
    try std.testing.expectError(
        error.EchRejected,
        writeClientCryptoFlight(&forged_output, allocator, .{
            .client_hello_bytes = client_hello_bytes.items,
            .server_hello_bytes = forged_server_hello,
            .server_handshake_crypto = server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .client_identity = client_identity,
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), forged_output.items.len);

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
    try server_hello.writeEncryptedExtensions(
        &invalid_server_crypto,
        allocator,
        .{
            .alpn_protocol = "h3",
            .quic_transport_parameters = &server_parameters,
            .accept_early_data = true,
            .server_certificate_type = .raw_public_key,
            .client_certificate_type = .raw_public_key,
        },
    );
    try invalid_server_crypto.appendSlice(
        allocator,
        server_crypto.items[encrypted_extensions_len..],
    );
    try std.testing.expectError(
        error.InvalidEarlyDataConfiguration,
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
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
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

test "QUIC TLS server sends a Vort Brotli compressed certificate" {
    const allocator = std.testing.allocator;
    const rsa = @import("../crypto/sign/rsa.zig");
    const vectors = @import("../crypto/testdata/rsa_signing.zig");
    var certificate_der: [vectors.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate_der, vectors.certificate_hex);
    var private_key_der: [vectors.private_key_pkcs8_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &private_key_der,
        vectors.private_key_pkcs8_hex,
    );
    const private_key = try rsa.PrivateKey.fromDer(&private_key_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();

    var certificate_message: std.ArrayList(u8) = .empty;
    defer certificate_message.deinit(allocator);
    try auth.writeCertificate(
        &certificate_message,
        allocator,
        &.{&certificate_der},
    );
    var compressed_certificate = try certificate_compression.Prepared
        .initBrotli(
        allocator,
        certificate_message.items,
        .amortized,
    );
    defer compressed_certificate.deinit();
    try std.testing.expect(
        compressed_certificate.view().savesBytes(certificate_message.items.len),
    );
    const compressed_certificates = [_]certificate_compression.PreparedView{
        compressed_certificate.view(),
    };

    var client_hello_bytes: std.ArrayList(u8) = .empty;
    defer client_hello_bytes.deinit(allocator);
    try client_hello.write(&client_hello_bytes, allocator, .{
        .random = [_]u8{0x61} ** 32,
        .session_id = "quic-compression",
        .server_name = "localhost",
        .x25519_public_key = [_]u8{0x62} ** 32,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .certificate_compression_algorithms = &.{.brotli},
    });
    const shared_secret = [_]u8{0x63} ** 32;
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
            .parsed_client_hello = try client_hello.parse(
                client_hello_bytes.items,
            ),
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .compressed_certificates = &compressed_certificates,
            },
            .server_random = [_]u8{0x64} ** 32,
            .server_key_share = &([_]u8{0x65} ** 32),
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .rsa_pss = .{
                .prepared_key = &prepared_key,
                .io = std.testing.io,
            } },
        },
    );
    defer server_result.deinit();
    try std.testing.expectEqual(
        certificate_compression.Algorithm.brotli,
        server_result.certificate_compression.?,
    );
    const server_flight_messages = try client_handshake.splitServerFlight(
        server_crypto.items,
    );
    try std.testing.expectEqual(
        certificate_compression.handshake_type_compressed_certificate,
        server_flight_messages.certificate.?[0],
    );

    const Trust = struct {
        fn verify(
            _: ?*anyopaque,
            trust: auth.TrustContext,
        ) anyerror!void {
            if (trust.chain.len != 1 or trust.server_name == null or
                !std.mem.eql(u8, trust.server_name.?, "localhost"))
            {
                return error.UnexpectedCertificate;
            }
        }
    };
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
            .server_verifier = .{ .verify_trust = Trust.verify },
            .server_name = "localhost",
            .certificate_compression_algorithms = &.{.brotli},
        },
    );
    defer client_result.deinit();
    try std.testing.expectEqual(
        certificate_compression.Algorithm.brotli,
        client_result.verified.certificate_compression.?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &certificate_der,
        client_result.verified.peer_certificate_chain[0],
    );
    var verified_client = try verifyClientCryptoFlight(
        allocator,
        &server_result,
        client_crypto.items,
    );
    defer verified_client.deinit();
}

test "QUIC ECH rejection authenticates the outer public name and retry configs" {
    const allocator = std.testing.allocator;
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xb1} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const public_key_spki = ed25519SubjectPublicKeyInfo(
        signing_key.public_key.toBytes(),
    );
    const ech_secret = [_]u8{0xb2} ** 32;
    var ech_key_pair = try @import("../crypto/kex/hpke.zig").KeyPair
        .fromSecretKey(&ech_secret);
    defer ech_key_pair.deinit();
    var encoded_config: std.ArrayList(u8) = .empty;
    defer encoded_config.deinit(allocator);
    try ech.writeConfig(&encoded_config, allocator, .{
        .config_id = 29,
        .public_key = ech_key_pair.public_key,
        .public_name = "public.example",
    });
    const ech_config = try ech.parseConfig(encoded_config.items);

    const client_share = [_]u8{0xb3} ** 32;
    var inner_template: std.ArrayList(u8) = .empty;
    defer inner_template.deinit(allocator);
    try client_hello.writeWithKeyShare(&inner_template, allocator, .{
        .random = [_]u8{0xb4} ** 32,
        .session_id = "quic-ech-reject",
        .server_name = "private.example",
        .key_share = .{ .group = 0x001d, .key_exchange = &client_share },
        .supported_groups = &.{ 0x001d, 0x0017 },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
    });
    var outer_template: std.ArrayList(u8) = .empty;
    defer outer_template.deinit(allocator);
    try client_hello.writeWithKeyShare(&outer_template, allocator, .{
        .random = [_]u8{0xb5} ** 32,
        .session_id = "quic-ech-reject",
        .server_name = "public.example",
        .key_share = .{ .group = 0x001d, .key_exchange = &client_share },
        .supported_groups = &.{ 0x001d, 0x0017 },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
    });
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    var context = try ech.ClientContext.init(
        allocator,
        std.testing.io,
        ech_config,
    );
    defer context.deinit();
    try context.sealInitial(
        &inner,
        &outer,
        allocator,
        inner_template.items,
        outer_template.items,
    );

    var retry_configs: std.ArrayList(u8) = .empty;
    defer retry_configs.deinit(allocator);
    try ech.writeConfigList(
        &retry_configs,
        allocator,
        &.{ech_config.encoded},
    );
    const TrustState = struct {
        saw_public_name: bool = false,

        fn verify(
            opaque_context: ?*anyopaque,
            trust: auth.TrustContext,
        ) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(
                opaque_context orelse return error.MissingContext,
            ));
            if (trust.server_name == null or
                !std.mem.eql(u8, trust.server_name.?, "public.example"))
            {
                return error.UnexpectedServerName;
            }
            self.saw_public_name = true;
        }
    };
    var trust_state = TrustState{};
    const shared_secret = [_]u8{0xb6} ** 32;
    var initial_crypto: std.ArrayList(u8) = .empty;
    defer initial_crypto.deinit(allocator);
    var server_crypto: std.ArrayList(u8) = .empty;
    defer server_crypto.deinit(allocator);
    var server_result = try writeServerCryptoFlight(
        &initial_crypto,
        &server_crypto,
        allocator,
        .{
            .client_hello_bytes = outer.items,
            .parsed_client_hello = try client_hello.parse(outer.items),
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
            },
            .server_random = [_]u8{0xb7} ** 32,
            .server_key_share = &([_]u8{0xb8} ** 32),
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .ech_retry_configs = retry_configs.items,
        },
    );
    defer server_result.deinit();
    try std.testing.expect(server_result.ech_rejected);
    try std.testing.expect(!server_result.ech_accepted);
    try std.testing.expect(!server_result.resumed);

    var rejection = try authenticateEchRejection(allocator, .{
        .outer_client_hello_bytes = outer.items,
        .server_hello_bytes = initial_crypto.items,
        .server_handshake_crypto = server_crypto.items,
        .shared_secret = &shared_secret,
        .server_verifier = .{
            .verify_trust = TrustState.verify,
            .context = @ptrCast(&trust_state),
        },
        .server_certificate_type = .raw_public_key,
    });
    defer rejection.deinit();
    try std.testing.expect(trust_state.saw_public_name);
    try std.testing.expectEqual(
        ech_required_crypto_error,
        rejection.crypto_error_code,
    );
    try std.testing.expectEqualSlices(
        u8,
        retry_configs.items,
        rejection.retry_configs.?,
    );

    const tampered_server_crypto = try allocator.dupe(u8, server_crypto.items);
    defer allocator.free(tampered_server_crypto);
    tampered_server_crypto[tampered_server_crypto.len - 1] ^= 1;
    try std.testing.expectError(
        error.BadServerFinished,
        authenticateEchRejection(allocator, .{
            .outer_client_hello_bytes = outer.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = tampered_server_crypto,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .verify_trust = TrustState.verify,
                .context = @ptrCast(&trust_state),
            },
            .server_certificate_type = .raw_public_key,
        }),
    );
    @memset(server_crypto.items, 0);
    try std.testing.expectEqualSlices(
        u8,
        retry_configs.items,
        rejection.retry_configs.?,
    );

    var retry_bytes: std.ArrayList(u8) = .empty;
    defer retry_bytes.deinit(allocator);
    try server_hello.writeHelloRetryRequest(&retry_bytes, allocator, .{
        .session_id_echo = "quic-ech-reject",
        .cipher_suite = .aes_128_gcm_sha256,
        .selected_group = 0x0017,
        .cookie = "ech-reject-cookie",
    });
    const parsed_outer = try client_hello.parse(outer.items);
    const p256_share = [_]u8{0x04} ++ ([_]u8{0xb9} ** 64);
    var second_outer: std.ArrayList(u8) = .empty;
    defer second_outer.deinit(allocator);
    try client_hello.writeWithKeyShare(&second_outer, allocator, .{
        .random = parsed_outer.random.*,
        .session_id = parsed_outer.session_id,
        .server_name = parsed_outer.server_name,
        .key_share = .{ .group = 0x0017, .key_exchange = &p256_share },
        .supported_groups = &.{ 0x001d, 0x0017 },
        .cookie = "ech-reject-cookie",
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
        .encrypted_client_hello = parsed_outer.encrypted_client_hello,
    });
    const retry = try prepareRetryState(
        outer.items,
        retry_bytes.items,
        second_outer.items,
    );
    try std.testing.expect(retry.ech_offered);
    try std.testing.expect(!retry.ech_accepted);

    var retry_initial: std.ArrayList(u8) = .empty;
    defer retry_initial.deinit(allocator);
    var retry_server_crypto: std.ArrayList(u8) = .empty;
    defer retry_server_crypto.deinit(allocator);
    var retry_server = try writeServerCryptoFlight(
        &retry_initial,
        &retry_server_crypto,
        allocator,
        .{
            .client_hello_bytes = second_outer.items,
            .parsed_client_hello = try client_hello.parse(second_outer.items),
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{0x0017},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
            },
            .server_random = [_]u8{0xba} ** 32,
            .server_key_share = &p256_share,
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .ech_retry_configs = retry_configs.items,
            .retry = retry,
        },
    );
    defer retry_server.deinit();
    var retry_rejection = try authenticateEchRejection(allocator, .{
        .outer_client_hello_bytes = second_outer.items,
        .server_hello_bytes = retry_initial.items,
        .server_handshake_crypto = retry_server_crypto.items,
        .shared_secret = &shared_secret,
        .server_verifier = .{
            .verify_trust = TrustState.verify,
            .context = @ptrCast(&trust_state),
        },
        .server_certificate_type = .raw_public_key,
        .retry = retry,
    });
    defer retry_rejection.deinit();
    try std.testing.expectEqualSlices(
        u8,
        retry_configs.items,
        retry_rejection.retry_configs.?,
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
        .encrypted_client_hello = &.{ech.inner_type},
    });
    var retry_bytes: std.ArrayList(u8) = .empty;
    defer retry_bytes.deinit(allocator);
    try server_hello.writeHelloRetryRequest(&retry_bytes, allocator, .{
        .session_id_echo = "quic-hrr",
        .cipher_suite = .aes_128_gcm_sha256,
        .selected_group = 0x0017,
        .cookie = "quic-cookie",
        .ech_confirmation = [_]u8{0} ** ech.confirmation_len,
    });
    const hrr_confirmation = try ech.hrrAcceptConfirmation(
        .sha256,
        (try client_hello.parse(first_hello.items)).random.*,
        transcript.afterHelloRetryRequest(
            .sha256,
            first_hello.items,
            retry_bytes.items,
        ).digest(),
    );
    retry_bytes.items[retry_bytes.items.len - ech.confirmation_len ..][0..ech.confirmation_len].* = hrr_confirmation;
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
        .encrypted_client_hello = &.{ech.inner_type},
    });
    const retry = try prepareRetryState(
        first_hello.items,
        retry_bytes.items,
        second_hello.items,
    );
    const forged_retry_bytes = try allocator.dupe(u8, retry_bytes.items);
    defer allocator.free(forged_retry_bytes);
    forged_retry_bytes[forged_retry_bytes.len - 1] ^= 1;
    try std.testing.expectError(
        error.EchRejected,
        prepareRetryState(
            first_hello.items,
            forged_retry_bytes,
            second_hello.items,
        ),
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
            .ech_accepted = true,
            .retry = retry,
        },
    );
    defer server_result.deinit();
    try std.testing.expect(server_result.ech_accepted);

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
    try std.testing.expect(client_result.ech_accepted);
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
        error.EchRejected,
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
        .encrypted_client_hello = &.{ech.inner_type},
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

    var resumption_secret = secret.Secret.fromSha256([_]u8{0x97} ** 32);
    defer resumption_secret.deinit();
    const resumption = ResumptionPsk{
        .identity = "quic-hrr-ticket",
        .secret = resumption_secret,
        .suite = .aes_128_gcm_sha256,
        .max_early_data_size = ticket.quic_early_data_size,
    };
    var first_psk = try first_hello.clone(allocator);
    defer first_psk.deinit(allocator);
    try psk.appendClientOfferForSecret(
        &first_psk,
        allocator,
        resumption.identity,
        23,
        resumption.secret,
        true,
        null,
    );
    var psk_retry_bytes = try retry_bytes.clone(allocator);
    defer psk_retry_bytes.deinit(allocator);
    @memset(
        psk_retry_bytes.items[psk_retry_bytes.items.len -
            ech.confirmation_len ..],
        0,
    );
    const psk_hrr_confirmation = try ech.hrrAcceptConfirmation(
        .sha256,
        (try client_hello.parse(first_psk.items)).random.*,
        transcript.afterHelloRetryRequest(
            .sha256,
            first_psk.items,
            psk_retry_bytes.items,
        ).digest(),
    );
    psk_retry_bytes.items[psk_retry_bytes.items.len -
        ech.confirmation_len ..][0..ech.confirmation_len].* =
        psk_hrr_confirmation;
    const binder_prefix = transcript.afterHelloRetryRequest(
        .sha256,
        first_psk.items,
        psk_retry_bytes.items,
    );
    var second_psk = try second_hello.clone(allocator);
    defer second_psk.deinit(allocator);
    try psk.appendClientOfferForSecret(
        &second_psk,
        allocator,
        resumption.identity,
        23,
        resumption.secret,
        false,
        binder_prefix,
    );
    const psk_retry = try prepareRetryState(
        first_psk.items,
        psk_retry_bytes.items,
        second_psk.items,
    );
    try std.testing.expectError(
        error.InvalidEarlyDataConfiguration,
        clientEarlyPacketKeys(
            second_psk.items,
            resumption,
            traffic.labels_v1,
        ),
    );

    var invalid_early_initial: std.ArrayList(u8) = .empty;
    defer invalid_early_initial.deinit(allocator);
    var invalid_early_handshake: std.ArrayList(u8) = .empty;
    defer invalid_early_handshake.deinit(allocator);
    try std.testing.expectError(
        error.InvalidEarlyDataConfiguration,
        writeServerCryptoFlight(
            &invalid_early_initial,
            &invalid_early_handshake,
            allocator,
            .{
                .client_hello_bytes = second_psk.items,
                .parsed_client_hello = try client_hello.parse(second_psk.items),
                .policy = .{
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .groups = &.{0x0017},
                    .alpn_protocols = &.{"h3"},
                    .quic_transport_parameters = &.{ 4, 5, 6 },
                    .server_certificate_type = .raw_public_key,
                },
                .server_random = [_]u8{0x98} ** 32,
                .server_key_share = &p256_share,
                .shared_secret = &shared_secret,
                .certificate_chain = &.{&public_key_spki},
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
                .resumption = resumption,
                .ech_accepted = true,
                .accept_early_data = true,
                .retry = psk_retry,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), invalid_early_initial.items.len);
    try std.testing.expectEqual(@as(usize, 0), invalid_early_handshake.items.len);

    var resumed_initial: std.ArrayList(u8) = .empty;
    defer resumed_initial.deinit(allocator);
    var resumed_server_crypto: std.ArrayList(u8) = .empty;
    defer resumed_server_crypto.deinit(allocator);
    var resumed_server = try writeServerCryptoFlight(
        &resumed_initial,
        &resumed_server_crypto,
        allocator,
        .{
            .client_hello_bytes = second_psk.items,
            .parsed_client_hello = try client_hello.parse(second_psk.items),
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{0x0017},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
            },
            .server_random = [_]u8{0x98} ** 32,
            .server_key_share = &p256_share,
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .resumption = resumption,
            .ech_accepted = true,
            .retry = psk_retry,
        },
    );
    defer resumed_server.deinit();
    try std.testing.expect(resumed_server.resumed);

    var resumed_client_crypto: std.ArrayList(u8) = .empty;
    defer resumed_client_crypto.deinit(allocator);
    var resumed_client = try writeClientCryptoFlight(
        &resumed_client_crypto,
        allocator,
        .{
            .client_hello_bytes = second_psk.items,
            .server_hello_bytes = resumed_initial.items,
            .server_handshake_crypto = resumed_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{},
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .resumption = resumption,
            .retry = psk_retry,
        },
    );
    defer resumed_client.deinit();
    try std.testing.expect(resumed_client.resumed);
    try std.testing.expect(!resumed_client.verified.early_data_accepted);
    try std.testing.expect(resumed_server.client_early_packet_keys == null);
    var resumed_finished = try verifyClientCryptoFlight(
        allocator,
        &resumed_server,
        resumed_client_crypto.items,
    );
    defer resumed_finished.deinit();
}

test "QUIC TLS PSK resumption verifies binders and supports full-handshake fallback" {
    const allocator = std.testing.allocator;
    var resumption_secret = secret.Secret.fromSha256([_]u8{0xa1} ** 32);
    defer resumption_secret.deinit();
    const client_resumption = ResumptionPsk{
        .identity = "quic-ticket",
        .secret = resumption_secret,
        .suite = .aes_128_gcm_sha256,
        .max_early_data_size = ticket.quic_early_data_size,
        .application_settings = .{
            .codepoint = .legacy,
            .local = "quic-client-settings",
            .peer = "quic-server-settings",
        },
        .age_policy = .{
            .age_add = 7,
            .issued_at_ms = 1_000,
            .lifetime_seconds = 60,
            .now_ms = 1_010,
        },
    };
    const server_resumption = ResumptionPsk{
        .identity = client_resumption.identity,
        .secret = client_resumption.secret,
        .suite = client_resumption.suite,
        .max_early_data_size = client_resumption.max_early_data_size,
        .application_settings = .{
            .codepoint = .legacy,
            .local = "quic-server-settings",
            .peer = "quic-client-settings",
        },
        .age_policy = client_resumption.age_policy,
    };
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0xa2} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const public_key_spki = ed25519SubjectPublicKeyInfo(
        signing_key.public_key.toBytes(),
    );
    const shared_secret = [_]u8{0xa3} ** 32;

    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try client_hello.write(&hello, allocator, .{
        .random = [_]u8{0xa4} ** 32,
        .session_id = "quic-psk",
        .server_name = "quic.example",
        .x25519_public_key = [_]u8{0xa5} ** 32,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
        .application_settings_protocols = &.{"h3"},
        .ticket_request = .{
            .new_session_count = 0,
            .resumption_count = 1,
        },
    });
    try psk.appendClientOfferForSecret(
        &hello,
        allocator,
        client_resumption.identity,
        17,
        client_resumption.secret,
        true,
        null,
    );
    const parsed = try client_hello.parse(hello.items);
    var invalid_early_data_resumption = client_resumption;
    invalid_early_data_resumption.max_early_data_size = 4096;
    try std.testing.expectError(
        error.InvalidEarlyDataConfiguration,
        validateQuicResumption(invalid_early_data_resumption),
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
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
                .application_settings = &.{.{
                    .protocol = "h3",
                    .settings = "quic-server-settings",
                }},
            },
            .server_random = [_]u8{0xa6} ** 32,
            .server_key_share = &([_]u8{0xa7} ** 32),
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .resumption = server_resumption,
            .accept_early_data = true,
            .max_requested_tickets = 1,
        },
    );
    defer server_result.deinit();
    try std.testing.expect(server_result.resumed);
    try std.testing.expectEqual(
        @as(?u32, ticket.quic_early_data_size),
        server_result.early_data_limit,
    );
    var client_early_keys = try clientEarlyPacketKeys(
        hello.items,
        client_resumption,
        traffic.labels_v1,
    );
    defer client_early_keys.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &client_early_keys.key,
        &server_result.client_early_packet_keys.?.key,
    );
    const early_plaintext = "quic zero-rtt payload";
    var early_ciphertext: [early_plaintext.len]u8 = undefined;
    var early_tag: [traffic.tag_len]u8 = undefined;
    try client_early_keys.protect(
        7,
        "0-rtt-header",
        early_plaintext,
        &early_ciphertext,
        &early_tag,
    );
    var opened_early: [early_plaintext.len]u8 = undefined;
    try server_result.client_early_packet_keys.?.open(
        7,
        "0-rtt-header",
        &early_ciphertext,
        early_tag,
        &opened_early,
    );
    try std.testing.expectEqualStrings(early_plaintext, &opened_early);
    const resumed_flight = try client_handshake.splitServerFlightForMode(
        server_crypto.items,
        true,
    );
    try std.testing.expect(resumed_flight.certificate == null);
    try std.testing.expect(resumed_flight.certificate_verify == null);
    const resumed_extensions = try server_hello.parseEncryptedExtensions(
        resumed_flight.encrypted_extensions,
    );
    try std.testing.expect(resumed_extensions.early_data_accepted);
    try std.testing.expect(resumed_extensions.application_settings == null);

    var client_crypto: std.ArrayList(u8) = .empty;
    defer client_crypto.deinit(allocator);
    var client_result = try writeClientCryptoFlight(
        &client_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .server_hello_bytes = initial_crypto.items,
            .server_handshake_crypto = server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{},
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
            .resumption = client_resumption,
        },
    );
    defer client_result.deinit();
    try std.testing.expect(client_result.resumed);
    try std.testing.expect(client_result.verified.early_data_accepted);
    try std.testing.expectEqual(@as(usize, 0), client_result.verified.peer_certificate_chain.len);
    try std.testing.expectEqualStrings(
        "quic-client-settings",
        client_result.verified.local_application_settings.?,
    );
    try std.testing.expectEqualStrings(
        "quic-server-settings",
        client_result.verified.peer_application_settings.?,
    );
    try std.testing.expectEqual(@as(usize, 36), client_crypto.items.len);
    try std.testing.expectEqual(handshake_type_finished, client_crypto.items[0]);
    var verified_client = try verifyClientCryptoFlight(
        allocator,
        &server_result,
        client_crypto.items,
    );
    defer verified_client.deinit();
    try std.testing.expectEqualStrings(
        "quic-client-settings",
        verified_client.peer_application_settings.?,
    );

    var stale_server_resumption = server_resumption;
    stale_server_resumption.age_policy.?.now_ms = 21_000;
    var stale_initial: std.ArrayList(u8) = .empty;
    defer stale_initial.deinit(allocator);
    var stale_server_crypto: std.ArrayList(u8) = .empty;
    defer stale_server_crypto.deinit(allocator);
    var stale_server = try writeServerCryptoFlight(
        &stale_initial,
        &stale_server_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
                .application_settings = &.{.{
                    .protocol = "h3",
                    .settings = "quic-server-settings",
                }},
            },
            .server_random = [_]u8{0xb4} ** 32,
            .server_key_share = &([_]u8{0xb5} ** 32),
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .resumption = stale_server_resumption,
            .accept_early_data = true,
        },
    );
    defer stale_server.deinit();
    try std.testing.expect(stale_server.resumed);
    try std.testing.expect(stale_server.early_data_limit == null);
    try std.testing.expect(stale_server.client_early_packet_keys == null);
    const stale_flight = try client_handshake.splitServerFlightForMode(
        stale_server_crypto.items,
        true,
    );
    try std.testing.expect(stale_flight.certificate == null);
    const stale_extensions = try server_hello.parseEncryptedExtensions(
        stale_flight.encrypted_extensions,
    );
    try std.testing.expect(!stale_extensions.early_data_accepted);

    var stale_client_crypto: std.ArrayList(u8) = .empty;
    defer stale_client_crypto.deinit(allocator);
    var stale_client = try writeClientCryptoFlight(
        &stale_client_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .server_hello_bytes = stale_initial.items,
            .server_handshake_crypto = stale_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{},
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
            .resumption = client_resumption,
        },
    );
    defer stale_client.deinit();
    try std.testing.expect(stale_client.resumed);
    try std.testing.expect(!stale_client.verified.early_data_accepted);
    var stale_verified_client = try verifyClientCryptoFlight(
        allocator,
        &stale_server,
        stale_client_crypto.items,
    );
    defer stale_verified_client.deinit();

    var unknown_secret = secret.Secret.fromSha256([_]u8{0xb6} ** 32);
    defer unknown_secret.deinit();
    var multi_hello: std.ArrayList(u8) = .empty;
    defer multi_hello.deinit(allocator);
    try client_hello.write(&multi_hello, allocator, .{
        .random = [_]u8{0xb7} ** 32,
        .session_id = "quic-psk-multi",
        .server_name = "quic.example",
        .x25519_public_key = [_]u8{0xb8} ** 32,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h3"},
        .quic_transport_parameters = &.{ 1, 2, 3 },
        .server_certificate_types = &.{.raw_public_key},
        .application_settings_protocols = &.{"h3"},
    });
    try psk.appendClientOffersForSecrets(
        &multi_hello,
        allocator,
        &.{
            .{
                .identity = "unknown-ticket",
                .obfuscated_ticket_age = 17,
                .psk_secret = unknown_secret,
            },
            .{
                .identity = client_resumption.identity,
                .obfuscated_ticket_age = 17,
                .psk_secret = client_resumption.secret,
            },
        },
        true,
        null,
    );
    var multi_initial: std.ArrayList(u8) = .empty;
    defer multi_initial.deinit(allocator);
    var multi_server_crypto: std.ArrayList(u8) = .empty;
    defer multi_server_crypto.deinit(allocator);
    var multi_server = try writeServerCryptoFlight(
        &multi_initial,
        &multi_server_crypto,
        allocator,
        .{
            .client_hello_bytes = multi_hello.items,
            .parsed_client_hello = try client_hello.parse(multi_hello.items),
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
                .application_settings = &.{.{
                    .protocol = "h3",
                    .settings = "quic-server-settings",
                }},
            },
            .server_random = [_]u8{0xb9} ** 32,
            .server_key_share = &([_]u8{0xba} ** 32),
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .resumption = server_resumption,
            .accept_early_data = true,
        },
    );
    defer multi_server.deinit();
    try std.testing.expect(multi_server.resumed);
    try std.testing.expect(multi_server.early_data_limit == null);
    try std.testing.expect(multi_server.client_early_packet_keys == null);
    const parsed_multi_server = try server_hello.parseServerHello(
        multi_initial.items,
    );
    try std.testing.expectEqual(
        @as(?u16, 1),
        parsed_multi_server.selected_psk_identity,
    );

    var multi_client_crypto: std.ArrayList(u8) = .empty;
    defer multi_client_crypto.deinit(allocator);
    var multi_client = try writeClientCryptoFlight(
        &multi_client_crypto,
        allocator,
        .{
            .client_hello_bytes = multi_hello.items,
            .server_hello_bytes = multi_initial.items,
            .server_handshake_crypto = multi_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{},
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
            .resumption = client_resumption,
        },
    );
    defer multi_client.deinit();
    try std.testing.expect(multi_client.resumed);
    try std.testing.expect(!multi_client.verified.early_data_accepted);
    var multi_verified_client = try verifyClientCryptoFlight(
        allocator,
        &multi_server,
        multi_client_crypto.items,
    );
    defer multi_verified_client.deinit();

    var keyring = try ticket_keyring.Keyring.init(.{
        .id = 19,
        .secret = [_]u8{0xb1} ** ticket_keyring.key_len,
    });
    defer keyring.deinit();
    var replacement_ticket: std.ArrayList(u8) = .empty;
    defer replacement_ticket.deinit(allocator);
    try writeRequestedNewSessionTicket(
        &replacement_ticket,
        allocator,
        &server_result,
        &verified_client,
        .{
            .keyring = &keyring,
            .sealing_nonce = [_]u8{0xb2} ** ticket_keyring.nonce_len,
            .server_id = "quic.example",
            .alpn = "h3",
            .ticket_nonce = &.{0x01},
            .age_add = 29,
            .issued_at_ms = 2_000,
            .lifetime_seconds = 60,
            .allow_early_data = true,
        },
    );
    try std.testing.expectEqual(@as(u8, 0), server_result.requested_ticket_count);
    try std.testing.expectError(
        error.NoRequestedTicketsPending,
        writeRequestedNewSessionTicket(
            &replacement_ticket,
            allocator,
            &server_result,
            &verified_client,
            .{
                .keyring = &keyring,
                .sealing_nonce = [_]u8{0xb3} ** ticket_keyring.nonce_len,
                .server_id = "quic.example",
                .alpn = "h3",
                .ticket_nonce = &.{0x02},
                .age_add = 31,
                .issued_at_ms = 2_000,
                .lifetime_seconds = 60,
            },
        ),
    );
    var cached_replacement = try ticket.cacheWithApplicationSettings(
        allocator,
        replacement_ticket.items,
        client_result.verified.cipher_suite,
        client_result.verified.application.master_secret,
        client_result.verified.transcript_after_client_finished,
        "quic.example",
        "h3",
        2_000,
        .{
            .codepoint = .legacy,
            .local = "quic-client-settings",
            .peer = "quic-server-settings",
        },
    );
    defer cached_replacement.deinit();
    var opened_replacement = try keyring.openSecretWithApplicationSettings(
        allocator,
        cached_replacement.identity,
        "quic.example",
        "h3",
        2_000,
    );
    defer opened_replacement.deinit();
    try std.testing.expect(opened_replacement.secret.eql(
        &cached_replacement.psk,
    ));
    try std.testing.expectEqual(
        @as(?u32, ticket.quic_early_data_size),
        opened_replacement.max_early_data_size,
    );
    try std.testing.expectEqualStrings(
        "quic-server-settings",
        opened_replacement.local_application_settings.?,
    );
    try std.testing.expectEqualStrings(
        "quic-client-settings",
        opened_replacement.peer_application_settings.?,
    );

    var changed_client_crypto: std.ArrayList(u8) = .empty;
    defer changed_client_crypto.deinit(allocator);
    try std.testing.expectError(
        error.InvalidServerFlight,
        writeClientCryptoFlight(
            &changed_client_crypto,
            allocator,
            .{
                .client_hello_bytes = hello.items,
                .server_hello_bytes = initial_crypto.items,
                .server_handshake_crypto = server_crypto.items,
                .shared_secret = &shared_secret,
                .server_verifier = .{},
                .server_name = "quic.example",
                .server_certificate_type = .raw_public_key,
                .application_settings = &.{.{
                    .protocol = "h3",
                    .settings = "changed-client-settings",
                }},
                .resumption = client_resumption,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), changed_client_crypto.items.len);

    const mismatched_server_resumption = ResumptionPsk{
        .identity = server_resumption.identity,
        .secret = server_resumption.secret,
        .suite = server_resumption.suite,
        .max_early_data_size = server_resumption.max_early_data_size,
        .application_settings = .{
            .codepoint = .legacy,
            .local = "changed-server-settings",
            .peer = "quic-client-settings",
        },
        .age_policy = server_resumption.age_policy,
    };
    var mismatched_initial: std.ArrayList(u8) = .empty;
    defer mismatched_initial.deinit(allocator);
    var mismatched_server_crypto: std.ArrayList(u8) = .empty;
    defer mismatched_server_crypto.deinit(allocator);
    try std.testing.expectError(
        error.InvalidEarlyDataConfiguration,
        writeServerCryptoFlight(
            &mismatched_initial,
            &mismatched_server_crypto,
            allocator,
            .{
                .client_hello_bytes = hello.items,
                .parsed_client_hello = parsed,
                .policy = .{
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .alpn_protocols = &.{"h3"},
                    .quic_transport_parameters = &.{ 4, 5, 6 },
                    .server_certificate_type = .raw_public_key,
                    .application_settings = &.{.{
                        .protocol = "h3",
                        .settings = "quic-server-settings",
                    }},
                },
                .server_random = [_]u8{0xac} ** 32,
                .server_key_share = &([_]u8{0xad} ** 32),
                .shared_secret = &shared_secret,
                .certificate_chain = &.{&public_key_spki},
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
                .resumption = mismatched_server_resumption,
                .accept_early_data = true,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), mismatched_initial.items.len);
    try std.testing.expectEqual(@as(usize, 0), mismatched_server_crypto.items.len);

    const wrong_codepoint_resumption = ResumptionPsk{
        .identity = server_resumption.identity,
        .secret = server_resumption.secret,
        .suite = server_resumption.suite,
        .max_early_data_size = server_resumption.max_early_data_size,
        .application_settings = .{
            .codepoint = .current,
            .local = "quic-server-settings",
            .peer = "quic-client-settings",
        },
        .age_policy = server_resumption.age_policy,
    };
    try std.testing.expectError(
        error.InvalidEarlyDataConfiguration,
        writeServerCryptoFlight(
            &mismatched_initial,
            &mismatched_server_crypto,
            allocator,
            .{
                .client_hello_bytes = hello.items,
                .parsed_client_hello = parsed,
                .policy = .{
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .alpn_protocols = &.{"h3"},
                    .quic_transport_parameters = &.{ 4, 5, 6 },
                    .server_certificate_type = .raw_public_key,
                    .application_settings = &.{.{
                        .protocol = "h3",
                        .settings = "quic-server-settings",
                    }},
                },
                .server_random = [_]u8{0xae} ** 32,
                .server_key_share = &([_]u8{0xaf} ** 32),
                .shared_secret = &shared_secret,
                .certificate_chain = &.{&public_key_spki},
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
                .resumption = wrong_codepoint_resumption,
                .accept_early_data = true,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), mismatched_initial.items.len);
    try std.testing.expectEqual(@as(usize, 0), mismatched_server_crypto.items.len);

    var rejecting_initial: std.ArrayList(u8) = .empty;
    defer rejecting_initial.deinit(allocator);
    var rejecting_server_crypto: std.ArrayList(u8) = .empty;
    defer rejecting_server_crypto.deinit(allocator);
    var rejecting_server = try writeServerCryptoFlight(
        &rejecting_initial,
        &rejecting_server_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
                .application_settings = &.{.{
                    .protocol = "h3",
                    .settings = "quic-server-settings",
                }},
            },
            .server_random = [_]u8{0xaa} ** 32,
            .server_key_share = &([_]u8{0xab} ** 32),
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .resumption = server_resumption,
        },
    );
    defer rejecting_server.deinit();
    try std.testing.expect(rejecting_server.resumed);
    try std.testing.expect(rejecting_server.client_early_packet_keys == null);

    var rejecting_client_crypto: std.ArrayList(u8) = .empty;
    defer rejecting_client_crypto.deinit(allocator);
    var rejecting_client = try writeClientCryptoFlight(
        &rejecting_client_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .server_hello_bytes = rejecting_initial.items,
            .server_handshake_crypto = rejecting_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{},
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
            .resumption = client_resumption,
        },
    );
    defer rejecting_client.deinit();
    try std.testing.expect(rejecting_client.resumed);
    try std.testing.expect(!rejecting_client.verified.early_data_accepted);
    try std.testing.expectEqual(
        application_settings.handshake_type_encrypted_extensions,
        rejecting_client_crypto.items[0],
    );
    var rejecting_verified_client = try verifyClientCryptoFlight(
        allocator,
        &rejecting_server,
        rejecting_client_crypto.items,
    );
    defer rejecting_verified_client.deinit();
    try std.testing.expectEqualStrings(
        "quic-client-settings",
        rejecting_verified_client.peer_application_settings.?,
    );

    const tampered_hello = try allocator.dupe(u8, hello.items);
    defer allocator.free(tampered_hello);
    tampered_hello[tampered_hello.len - 1] ^= 1;
    var rejected_initial: std.ArrayList(u8) = .empty;
    defer rejected_initial.deinit(allocator);
    var rejected_handshake: std.ArrayList(u8) = .empty;
    defer rejected_handshake.deinit(allocator);
    try std.testing.expectError(
        error.InvalidPskBinder,
        writeServerCryptoFlight(
            &rejected_initial,
            &rejected_handshake,
            allocator,
            .{
                .client_hello_bytes = tampered_hello,
                .parsed_client_hello = try client_hello.parse(tampered_hello),
                .policy = .{
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .alpn_protocols = &.{"h3"},
                    .quic_transport_parameters = &.{ 4, 5, 6 },
                    .server_certificate_type = .raw_public_key,
                },
                .server_random = [_]u8{0xa6} ** 32,
                .server_key_share = &([_]u8{0xa7} ** 32),
                .shared_secret = &shared_secret,
                .certificate_chain = &.{&public_key_spki},
                .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
                .resumption = server_resumption,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_initial.items.len);
    try std.testing.expectEqual(@as(usize, 0), rejected_handshake.items.len);

    var fallback_initial: std.ArrayList(u8) = .empty;
    defer fallback_initial.deinit(allocator);
    var fallback_server_crypto: std.ArrayList(u8) = .empty;
    defer fallback_server_crypto.deinit(allocator);
    var fallback_server = try writeServerCryptoFlight(
        &fallback_initial,
        &fallback_server_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .parsed_client_hello = parsed,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &.{ 4, 5, 6 },
                .server_certificate_type = .raw_public_key,
            },
            .server_random = [_]u8{0xa8} ** 32,
            .server_key_share = &([_]u8{0xa9} ** 32),
            .shared_secret = &shared_secret,
            .certificate_chain = &.{&public_key_spki},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
            .resumption = .{
                .identity = "different-ticket",
                .secret = client_resumption.secret,
                .suite = .aes_128_gcm_sha256,
                .max_early_data_size = ticket.quic_early_data_size,
            },
        },
    );
    defer fallback_server.deinit();
    try std.testing.expect(!fallback_server.resumed);

    var fallback_client_crypto: std.ArrayList(u8) = .empty;
    defer fallback_client_crypto.deinit(allocator);
    var fallback_client = try writeClientCryptoFlight(
        &fallback_client_crypto,
        allocator,
        .{
            .client_hello_bytes = hello.items,
            .server_hello_bytes = fallback_initial.items,
            .server_handshake_crypto = fallback_server_crypto.items,
            .shared_secret = &shared_secret,
            .server_verifier = .{
                .pinned_raw_public_key = &public_key_spki,
            },
            .server_name = "quic.example",
            .server_certificate_type = .raw_public_key,
            .application_settings = &.{.{
                .protocol = "h3",
                .settings = "quic-client-settings",
            }},
            .resumption = client_resumption,
        },
    );
    defer fallback_client.deinit();
    try std.testing.expect(!fallback_client.resumed);
    try std.testing.expect(!fallback_client.verified.early_data_accepted);
    try std.testing.expectEqual(@as(usize, 1), fallback_client.verified.peer_certificate_chain.len);
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
