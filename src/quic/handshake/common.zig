//! Shared QUIC TLS handshake types and helpers.
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

pub const handshake_type_finished: u8 = 0x14;
pub const ech_required_crypto_error: u64 =
    0x100 + @as(u64, @intFromEnum(alert.Description.ech_required));

const EchStatus = enum {
    not_offered,
    accepted,
    rejected,
};

pub const Error = std.mem.Allocator.Error || server_flight.Error ||
    server_hello.Error || client_handshake.Error || key_schedule.Error ||
    psk.Error || ech.Error || auth.Error || error{
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
    EchRejected,
    UnsupportedEarlyData,
    InvalidEarlyDataConfiguration,
    MissingPskConfiguration,
    InvalidRetryState,
    UnsupportedCipherSuite,
};

pub const RetryState = struct {
    cipher_suite: cipher_suite.Suite,
    selected_group: u16,
    transcript_prefix: transcript.State,
    binder_prefix: transcript.State,
    second_client_hello_hash: transcript.Digest,
    ech_offered: bool,
    ech_accepted: bool,
};

pub const ResumptionPsk = struct {
    identity: []const u8,
    secret: secret.Secret,
    suite: cipher_suite.Suite,
    age_policy: ?psk.TicketAgePolicy = null,
    max_early_data_size: ?u32 = null,
    application_settings: ?application_settings.Session = null,
};

pub fn validateQuicResumption(resumption: ResumptionPsk) Error!void {
    ticket.validateQuicEarlyDataSize(
        resumption.max_early_data_size,
    ) catch return error.InvalidEarlyDataConfiguration;
}

/// Validate both ClientHellos and the intervening HelloRetryRequest, then
/// return the transcript state consumed by the final client/server flight.
pub fn validateRetryState(
    retry: RetryState,
    suite: cipher_suite.Suite,
    selected_group: u16,
    second_client_hello: []const u8,
    ech_offered: bool,
    ech_accepted: bool,
) Error!void {
    if (retry.cipher_suite != suite or
        retry.selected_group != selected_group or
        retry.ech_offered != ech_offered or
        retry.ech_accepted != ech_accepted or
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

pub fn clientHelloEchStatus(parsed: client_hello.Parsed) Error!EchStatus {
    const encoded = parsed.encrypted_client_hello orelse return .not_offered;
    return switch (try ech.parseClientHelloExtension(encoded)) {
        .inner => .accepted,
        .outer => .rejected,
    };
}

pub fn takeHandshakeMessage(
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

pub fn freeCertificateChain(
    allocator: std.mem.Allocator,
    certificates: [][]const u8,
) void {
    for (certificates) |certificate| allocator.free(certificate);
    allocator.free(certificates);
}
