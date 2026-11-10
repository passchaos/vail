//! TLS-to-QUIC traffic-key adapters.
//!
//! The QUIC transport decides when encryption levels become available, when
//! old packet-number spaces are discarded, and when key phases toggle. Vail
//! keeps the cryptographic conversion narrow: TLS runtime secrets in,
//! QUIC packet-protection keys out.

const key_schedule = @import("../tls/crypto/key_schedule.zig");
const secret = @import("../tls/crypto/secret.zig");
const transcript = @import("../tls/crypto/transcript.zig");
const traffic = @import("traffic_crypto.zig");

pub const Error = key_schedule.Error || error{UnsupportedCipherSuite};

pub const DirectionalKeys = struct {
    client: traffic.Keys,
    server: traffic.Keys,

    pub fn deinit(self: *DirectionalKeys) void {
        self.client.deinit();
        self.server.deinit();
        self.* = undefined;
    }
};

pub fn keysForSecret(
    suite: traffic.Suite,
    traffic_secret: secret.Secret,
    labels: traffic.Labels,
) Error!traffic.Keys {
    return traffic.Keys.deriveChecked(
        suite,
        traffic_secret,
        labels,
    ) catch |err| switch (err) {
        error.HashMismatch => error.HashMismatch,
        error.UnsupportedCipherSuite => error.UnsupportedCipherSuite,
    };
}

pub fn handshakeKeys(
    suite: traffic.Suite,
    secrets: key_schedule.RuntimeHandshakeSecrets,
    labels: traffic.Labels,
) Error!DirectionalKeys {
    return .{
        .client = try keysForSecret(
            suite,
            secrets.client_traffic_secret,
            labels,
        ),
        .server = try keysForSecret(
            suite,
            secrets.server_traffic_secret,
            labels,
        ),
    };
}

pub fn applicationKeys(
    suite: traffic.Suite,
    secrets: key_schedule.RuntimeApplicationSecrets,
    labels: traffic.Labels,
) Error!DirectionalKeys {
    return .{
        .client = try keysForSecret(
            suite,
            secrets.client_traffic_secret,
            labels,
        ),
        .server = try keysForSecret(
            suite,
            secrets.server_traffic_secret,
            labels,
        ),
    };
}

pub fn clientEarlyKeys(
    suite: traffic.Suite,
    psk: secret.Secret,
    client_hello_hash: transcript.Digest,
    labels: traffic.Labels,
) Error!traffic.Keys {
    var early_secret = try key_schedule.deriveClientEarlyTrafficSecretFor(
        psk,
        client_hello_hash,
    );
    defer early_secret.deinit();
    return keysForSecret(suite, early_secret, labels);
}

pub fn nextKeyPhase(
    keys: traffic.Keys,
    labels: traffic.Labels,
) Error!traffic.Keys {
    return keys.nextKeyPhase(labels) catch |err| switch (err) {
        error.HashMismatch => error.HashMismatch,
    };
}
