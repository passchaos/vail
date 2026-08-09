//! TLS 1.3 SHA-256 HKDF key schedule (RFC 8446 §7.1).
//!
//! This module owns protocol traffic secrets. QUIC packet-protection labels
//! (`quic key`, `quic iv`, `quic hp`) remain in the transport adapter.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const secret_len = Sha256.digest_length;

pub const HandshakeSecrets = struct {
    early_secret: [secret_len]u8,
    handshake_secret: [secret_len]u8,
    client_traffic_secret: [secret_len]u8,
    server_traffic_secret: [secret_len]u8,
};

pub const ApplicationSecrets = struct {
    master_secret: [secret_len]u8,
    client_traffic_secret: [secret_len]u8,
    server_traffic_secret: [secret_len]u8,
};

pub fn earlySecret(psk: ?[secret_len]u8) [secret_len]u8 {
    const zero = [_]u8{0} ** secret_len;
    return HkdfSha256.extract(&zero, if (psk) |value| &value else &zero);
}

pub fn deriveHandshake(
    shared_secret: [secret_len]u8,
    transcript_hash: [secret_len]u8,
    psk: ?[secret_len]u8,
) HandshakeSecrets {
    const early_secret = earlySecret(psk);
    const empty_hash = std.crypto.tls.emptyHash(Sha256);
    const derived_secret = std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        early_secret,
        "derived",
        &empty_hash,
        secret_len,
    );
    const handshake_secret = HkdfSha256.extract(
        &derived_secret,
        &shared_secret,
    );
    return .{
        .early_secret = early_secret,
        .handshake_secret = handshake_secret,
        .client_traffic_secret = std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            handshake_secret,
            "c hs traffic",
            &transcript_hash,
            secret_len,
        ),
        .server_traffic_secret = std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            handshake_secret,
            "s hs traffic",
            &transcript_hash,
            secret_len,
        ),
    };
}

pub fn deriveApplication(
    handshake_secret: [secret_len]u8,
    transcript_hash: [secret_len]u8,
) ApplicationSecrets {
    const zero = [_]u8{0} ** secret_len;
    const empty_hash = std.crypto.tls.emptyHash(Sha256);
    const derived_secret = std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        handshake_secret,
        "derived",
        &empty_hash,
        secret_len,
    );
    const master_secret = HkdfSha256.extract(&derived_secret, &zero);
    return .{
        .master_secret = master_secret,
        .client_traffic_secret = std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            master_secret,
            "c ap traffic",
            &transcript_hash,
            secret_len,
        ),
        .server_traffic_secret = std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            master_secret,
            "s ap traffic",
            &transcript_hash,
            secret_len,
        ),
    };
}

pub fn deriveClientEarlyTrafficSecret(
    psk: [secret_len]u8,
    client_hello_hash: [secret_len]u8,
) [secret_len]u8 {
    return std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        earlySecret(psk),
        "c e traffic",
        &client_hello_hash,
        secret_len,
    );
}

pub fn computeBinder(
    psk: [secret_len]u8,
    truncated_client_hello_hash: [secret_len]u8,
) [secret_len]u8 {
    const empty_hash = std.crypto.tls.emptyHash(Sha256);
    const binder_key = std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        earlySecret(psk),
        "res binder",
        &empty_hash,
        secret_len,
    );
    return computeFinished(binder_key, truncated_client_hello_hash);
}

pub fn computeFinished(
    base_key: [secret_len]u8,
    transcript_hash: [secret_len]u8,
) [secret_len]u8 {
    const finished_key = std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        base_key,
        "finished",
        "",
        secret_len,
    );
    var output: [secret_len]u8 = undefined;
    HmacSha256.create(&output, &transcript_hash, &finished_key);
    return output;
}

pub fn verifyFinished(
    base_key: [secret_len]u8,
    transcript_hash: [secret_len]u8,
    verify_data: [secret_len]u8,
) error{BadFinished}!void {
    const expected = computeFinished(base_key, transcript_hash);
    if (!std.crypto.timing_safe.eql(
        [secret_len]u8,
        expected,
        verify_data,
    )) return error.BadFinished;
}

pub fn deriveResumptionMasterSecret(
    master_secret: [secret_len]u8,
    transcript_hash: [secret_len]u8,
) [secret_len]u8 {
    return std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        master_secret,
        "res master",
        &transcript_hash,
        secret_len,
    );
}

pub fn deriveResumptionPsk(
    resumption_master_secret: [secret_len]u8,
    ticket_nonce: []const u8,
) [secret_len]u8 {
    return std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        resumption_master_secret,
        "resumption",
        ticket_nonce,
        secret_len,
    );
}

pub fn nextTrafficSecret(
    traffic_secret: [secret_len]u8,
) [secret_len]u8 {
    return std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        traffic_secret,
        "traffic upd",
        "",
        secret_len,
    );
}
