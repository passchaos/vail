//! TLS 1.3 HKDF key schedules (RFC 8446 §7.1).
//!
//! `Sha256` remains the source-compatible default used by the existing netz
//! adapter. `Sha384` carries the 48-byte secrets required by
//! TLS_AES_256_GCM_SHA384, while `Sm3` provides the RFC 8998
//! TLS_SM4_GCM_SM3 schedule. All are compile-time specializations with no
//! allocation or runtime crypto dispatch.

const std = @import("std");
const sm3 = @import("../crypto/sm3.zig");
const schedule = @import("key_schedule/schedule.zig");
const secret = @import("secret.zig");
const transcript = @import("transcript.zig");

pub const Schedule = schedule.Schedule;
pub const Sha256 = Schedule(std.crypto.hash.sha2.Sha256);
pub const Sha384 = Schedule(std.crypto.hash.sha2.Sha384);
pub const Sm3 = Schedule(sm3.Hash);

pub const secret_len = Sha256.secret_len;
pub const HandshakeSecrets = Sha256.HandshakeSecrets;
pub const ApplicationSecrets = Sha256.ApplicationSecrets;

pub const earlySecret = Sha256.earlySecret;
pub const deriveApplication = Sha256.deriveApplication;
pub const deriveClientEarlyTrafficSecret =
    Sha256.deriveClientEarlyTrafficSecret;
pub const computeBinder = Sha256.computeBinder;
pub const computeFinished = Sha256.computeFinished;
pub const verifyFinished = Sha256.verifyFinished;
pub const deriveResumptionMasterSecret =
    Sha256.deriveResumptionMasterSecret;
pub const deriveResumptionPsk = Sha256.deriveResumptionPsk;
pub const nextTrafficSecret = Sha256.nextTrafficSecret;

pub fn deriveHandshake(
    shared_secret: [secret_len]u8,
    transcript_hash: [secret_len]u8,
    psk: ?[secret_len]u8,
) HandshakeSecrets {
    return Sha256.deriveHandshake(
        &shared_secret,
        transcript_hash,
        psk,
    );
}

pub const RuntimeHandshakeSecrets = struct {
    early_secret: secret.Secret,
    handshake_secret: secret.Secret,
    client_traffic_secret: secret.Secret,
    server_traffic_secret: secret.Secret,
};

pub const RuntimeApplicationSecrets = struct {
    master_secret: secret.Secret,
    client_traffic_secret: secret.Secret,
    server_traffic_secret: secret.Secret,
};

pub const Error = secret.Error || error{
    HashMismatch,
    BadFinished,
};

pub fn deriveHandshakeFor(
    algorithm: secret.Hash,
    shared_secret: []const u8,
    transcript_hash: transcript.Digest,
    psk: ?secret.Secret,
) Error!RuntimeHandshakeSecrets {
    if (transcript_hash.hash != algorithm) return error.HashMismatch;
    if (psk) |value| {
        if (value.hash != algorithm) return error.HashMismatch;
    }
    return switch (algorithm) {
        .sha256 => blk: {
            const hash = try transcript_hash.sha256();
            const derived = Sha256.deriveHandshake(
                shared_secret,
                hash,
                if (psk) |value| try value.sha256() else null,
            );
            break :blk .{
                .early_secret = .fromSha256(derived.early_secret),
                .handshake_secret = .fromSha256(derived.handshake_secret),
                .client_traffic_secret = .fromSha256(derived.client_traffic_secret),
                .server_traffic_secret = .fromSha256(derived.server_traffic_secret),
            };
        },
        .sha384 => blk: {
            const hash = try transcript_hash.sha384();
            const derived = Sha384.deriveHandshake(
                shared_secret,
                hash,
                if (psk) |value| try value.sha384() else null,
            );
            break :blk .{
                .early_secret = .fromSha384(derived.early_secret),
                .handshake_secret = .fromSha384(derived.handshake_secret),
                .client_traffic_secret = .fromSha384(derived.client_traffic_secret),
                .server_traffic_secret = .fromSha384(derived.server_traffic_secret),
            };
        },
        .sm3 => blk: {
            const hash = try transcript_hash.sm3();
            const derived = Sm3.deriveHandshake(
                shared_secret,
                hash,
                if (psk) |value| try value.sm3() else null,
            );
            break :blk .{
                .early_secret = .fromSm3(derived.early_secret),
                .handshake_secret = .fromSm3(derived.handshake_secret),
                .client_traffic_secret = .fromSm3(derived.client_traffic_secret),
                .server_traffic_secret = .fromSm3(derived.server_traffic_secret),
            };
        },
    };
}

pub fn deriveApplicationFor(
    handshake_secret: secret.Secret,
    transcript_hash: transcript.Digest,
) Error!RuntimeApplicationSecrets {
    if (handshake_secret.hash != transcript_hash.hash) {
        return error.HashMismatch;
    }
    return switch (handshake_secret.hash) {
        .sha256 => blk: {
            const derived = Sha256.deriveApplication(
                try handshake_secret.sha256(),
                try transcript_hash.sha256(),
            );
            break :blk .{
                .master_secret = .fromSha256(derived.master_secret),
                .client_traffic_secret = .fromSha256(derived.client_traffic_secret),
                .server_traffic_secret = .fromSha256(derived.server_traffic_secret),
            };
        },
        .sha384 => blk: {
            const derived = Sha384.deriveApplication(
                try handshake_secret.sha384(),
                try transcript_hash.sha384(),
            );
            break :blk .{
                .master_secret = .fromSha384(derived.master_secret),
                .client_traffic_secret = .fromSha384(derived.client_traffic_secret),
                .server_traffic_secret = .fromSha384(derived.server_traffic_secret),
            };
        },
        .sm3 => blk: {
            const derived = Sm3.deriveApplication(
                try handshake_secret.sm3(),
                try transcript_hash.sm3(),
            );
            break :blk .{
                .master_secret = .fromSm3(derived.master_secret),
                .client_traffic_secret = .fromSm3(derived.client_traffic_secret),
                .server_traffic_secret = .fromSm3(derived.server_traffic_secret),
            };
        },
    };
}

pub fn computeFinishedFor(
    base_key: secret.Secret,
    transcript_hash: transcript.Digest,
) Error!secret.Secret {
    if (base_key.hash != transcript_hash.hash) {
        return error.HashMismatch;
    }
    return switch (base_key.hash) {
        .sha256 => .fromSha256(Sha256.computeFinished(
            try base_key.sha256(),
            try transcript_hash.sha256(),
        )),
        .sha384 => .fromSha384(Sha384.computeFinished(
            try base_key.sha384(),
            try transcript_hash.sha384(),
        )),
        .sm3 => .fromSm3(Sm3.computeFinished(
            try base_key.sm3(),
            try transcript_hash.sm3(),
        )),
    };
}

pub fn verifyFinishedFor(
    base_key: secret.Secret,
    transcript_hash: transcript.Digest,
    verify_data: secret.Secret,
) Error!void {
    if (base_key.hash != verify_data.hash) return error.HashMismatch;
    const expected = try computeFinishedFor(base_key, transcript_hash);
    if (!expected.eql(&verify_data)) return error.BadFinished;
}

pub fn deriveResumptionMasterSecretFor(
    master_secret: secret.Secret,
    transcript_hash: transcript.Digest,
) Error!secret.Secret {
    if (master_secret.hash != transcript_hash.hash) {
        return error.HashMismatch;
    }
    return switch (master_secret.hash) {
        .sha256 => .fromSha256(Sha256.deriveResumptionMasterSecret(
            try master_secret.sha256(),
            try transcript_hash.sha256(),
        )),
        .sha384 => .fromSha384(Sha384.deriveResumptionMasterSecret(
            try master_secret.sha384(),
            try transcript_hash.sha384(),
        )),
        .sm3 => .fromSm3(Sm3.deriveResumptionMasterSecret(
            try master_secret.sm3(),
            try transcript_hash.sm3(),
        )),
    };
}

pub fn deriveResumptionPskFor(
    resumption_master_secret: secret.Secret,
    ticket_nonce: []const u8,
) Error!secret.Secret {
    return switch (resumption_master_secret.hash) {
        .sha256 => .fromSha256(Sha256.deriveResumptionPsk(
            try resumption_master_secret.sha256(),
            ticket_nonce,
        )),
        .sha384 => .fromSha384(Sha384.deriveResumptionPsk(
            try resumption_master_secret.sha384(),
            ticket_nonce,
        )),
        .sm3 => .fromSm3(Sm3.deriveResumptionPsk(
            try resumption_master_secret.sm3(),
            ticket_nonce,
        )),
    };
}
