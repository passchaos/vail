//! TLS 1.3 HKDF key schedules (RFC 8446 §7.1).
//!
//! `Sha256` remains the source-compatible default used by the existing netz
//! adapter. `Sha384` carries the 48-byte secrets required by
//! TLS_AES_256_GCM_SHA384. Both are compile-time specializations with no
//! allocation or runtime crypto dispatch.

const std = @import("std");
const schedule = @import("key_schedule/schedule.zig");

pub const Schedule = schedule.Schedule;
pub const Sha256 = Schedule(std.crypto.hash.sha2.Sha256);
pub const Sha384 = Schedule(std.crypto.hash.sha2.Sha384);

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
