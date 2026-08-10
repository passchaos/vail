//! QUIC Initial packet-protection key derivation.
//!
//! Initial packets are not protected by the TLS transcript. QUIC instead
//! derives deterministic AES-128-GCM packet keys from the Destination
//! Connection ID in the client's first Initial packet and a version-specific
//! salt. Keeping that logic in Vail lets transport implementations install the
//! right keys without re-implementing HKDF labels or packet protection.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const common = @import("traffic_crypto/common.zig");
const traffic = @import("traffic_crypto.zig");
const tls_secret = @import("../tls/secret.zig");

pub const version_1: u32 = 0x00000001;
pub const version_2: u32 = 0x6b3343cf;
pub const max_connection_id_len: usize = 20;

pub const salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

pub const salt_v2 = [_]u8{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
};

pub const Error = error{
    UnsupportedVersion,
    InvalidDestinationConnectionId,
};

pub const VersionConfig = struct {
    version: u32,
    salt: []const u8,
    labels: traffic.Labels,
};

pub fn versionConfig(version: u32) Error!VersionConfig {
    return switch (version) {
        version_1 => .{
            .version = version_1,
            .salt = &salt_v1,
            .labels = traffic.labels_v1,
        },
        version_2 => .{
            .version = version_2,
            .salt = &salt_v2,
            .labels = traffic.labels_v2,
        },
        else => error.UnsupportedVersion,
    };
}

pub const Direction = enum {
    client,
    server,

    fn label(self: Direction) []const u8 {
        return switch (self) {
            .client => "client in",
            .server => "server in",
        };
    }
};

pub const SecretPair = struct {
    initial_secret: [HkdfSha256.prk_length]u8,
    client: tls_secret.Secret,
    server: tls_secret.Secret,
};

pub const KeyPair = struct {
    client: traffic.Keys,
    server: traffic.Keys,
};

pub fn deriveSecretsForVersion(
    version: u32,
    destination_connection_id: []const u8,
) Error!SecretPair {
    const config = try versionConfig(version);
    return deriveSecrets(config, destination_connection_id);
}

pub fn deriveKeysForVersion(
    version: u32,
    destination_connection_id: []const u8,
) Error!KeyPair {
    const config = try versionConfig(version);
    return deriveKeys(config, destination_connection_id);
}

pub fn deriveSecrets(
    config: VersionConfig,
    destination_connection_id: []const u8,
) Error!SecretPair {
    if (destination_connection_id.len > max_connection_id_len) {
        return error.InvalidDestinationConnectionId;
    }
    const initial_secret = HkdfSha256.extract(
        config.salt,
        destination_connection_id,
    );
    return .{
        .initial_secret = initial_secret,
        .client = .fromSha256(deriveDirectionalSecret(
            initial_secret,
            .client,
        )),
        .server = .fromSha256(deriveDirectionalSecret(
            initial_secret,
            .server,
        )),
    };
}

pub fn deriveKeys(
    config: VersionConfig,
    destination_connection_id: []const u8,
) Error!KeyPair {
    const secrets = try deriveSecrets(config, destination_connection_id);
    return .{
        .client = traffic.Keys.deriveChecked(
            .aes_128_gcm_sha256,
            secrets.client,
            config.labels,
        ) catch unreachable,
        .server = traffic.Keys.deriveChecked(
            .aes_128_gcm_sha256,
            secrets.server,
            config.labels,
        ) catch unreachable,
    };
}

pub fn deriveClientKeysForVersion(
    version: u32,
    destination_connection_id: []const u8,
) Error!traffic.Keys {
    return (try deriveKeysForVersion(version, destination_connection_id)).client;
}

pub fn deriveServerKeysForVersion(
    version: u32,
    destination_connection_id: []const u8,
) Error!traffic.Keys {
    return (try deriveKeysForVersion(version, destination_connection_id)).server;
}

fn deriveDirectionalSecret(
    initial_secret: [HkdfSha256.prk_length]u8,
    direction: Direction,
) [HkdfSha256.prk_length]u8 {
    return std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        initial_secret,
        direction.label(),
        "",
        HkdfSha256.prk_length,
    );
}

comptime {
    std.debug.assert(Aes128Gcm.key_length <= common.max_key_len);
    std.debug.assert(Aes128Gcm.nonce_length == common.iv_len);
    std.debug.assert(Aes128Gcm.tag_length == common.tag_len);
}
