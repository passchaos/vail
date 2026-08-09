//! Compile-time-specialized TLS 1.3 key schedule.
//!
//! RFC 8446 binds each cipher suite to one transcript hash.  Specializing the
//! schedule by hash preserves exact fixed-size secret types and lets Zig inline
//! HKDF/HMAC without a runtime algorithm switch.

const std = @import("std");

pub fn Schedule(comptime Hash: type) type {
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);

    return struct {
        const Self = @This();

        pub const secret_len = Hash.digest_length;

        comptime {
            std.debug.assert(Hmac.mac_length == secret_len);
            std.debug.assert(Hkdf.prk_length == secret_len);
        }

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
            return Hkdf.extract(
                &zero,
                if (psk) |value| &value else &zero,
            );
        }

        pub fn deriveHandshake(
            shared_secret: [secret_len]u8,
            transcript_hash: [secret_len]u8,
            psk: ?[secret_len]u8,
        ) HandshakeSecrets {
            const early_secret = earlySecret(psk);
            const empty_hash = std.crypto.tls.emptyHash(Hash);
            const derived_secret = deriveSecret(
                early_secret,
                "derived",
                &empty_hash,
            );
            const handshake_secret = Hkdf.extract(
                &derived_secret,
                &shared_secret,
            );
            return .{
                .early_secret = early_secret,
                .handshake_secret = handshake_secret,
                .client_traffic_secret = deriveSecret(
                    handshake_secret,
                    "c hs traffic",
                    &transcript_hash,
                ),
                .server_traffic_secret = deriveSecret(
                    handshake_secret,
                    "s hs traffic",
                    &transcript_hash,
                ),
            };
        }

        pub fn deriveApplication(
            handshake_secret: [secret_len]u8,
            transcript_hash: [secret_len]u8,
        ) ApplicationSecrets {
            const zero = [_]u8{0} ** secret_len;
            const empty_hash = std.crypto.tls.emptyHash(Hash);
            const derived_secret = deriveSecret(
                handshake_secret,
                "derived",
                &empty_hash,
            );
            const master_secret = Hkdf.extract(&derived_secret, &zero);
            return .{
                .master_secret = master_secret,
                .client_traffic_secret = deriveSecret(
                    master_secret,
                    "c ap traffic",
                    &transcript_hash,
                ),
                .server_traffic_secret = deriveSecret(
                    master_secret,
                    "s ap traffic",
                    &transcript_hash,
                ),
            };
        }

        pub fn deriveClientEarlyTrafficSecret(
            psk: [secret_len]u8,
            client_hello_hash: [secret_len]u8,
        ) [secret_len]u8 {
            return deriveSecret(
                earlySecret(psk),
                "c e traffic",
                &client_hello_hash,
            );
        }

        pub fn computeBinder(
            psk: [secret_len]u8,
            truncated_client_hello_hash: [secret_len]u8,
        ) [secret_len]u8 {
            const empty_hash = std.crypto.tls.emptyHash(Hash);
            const binder_key = deriveSecret(
                earlySecret(psk),
                "res binder",
                &empty_hash,
            );
            return computeFinished(
                binder_key,
                truncated_client_hello_hash,
            );
        }

        pub fn computeFinished(
            base_key: [secret_len]u8,
            transcript_hash: [secret_len]u8,
        ) [secret_len]u8 {
            const finished_key = std.crypto.tls.hkdfExpandLabel(
                Hkdf,
                base_key,
                "finished",
                "",
                secret_len,
            );
            var output: [secret_len]u8 = undefined;
            Hmac.create(&output, &transcript_hash, &finished_key);
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
            return deriveSecret(
                master_secret,
                "res master",
                &transcript_hash,
            );
        }

        pub fn deriveResumptionPsk(
            resumption_master_secret: [secret_len]u8,
            ticket_nonce: []const u8,
        ) [secret_len]u8 {
            return std.crypto.tls.hkdfExpandLabel(
                Hkdf,
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
                Hkdf,
                traffic_secret,
                "traffic upd",
                "",
                secret_len,
            );
        }

        fn deriveSecret(
            secret: [secret_len]u8,
            label: []const u8,
            transcript_hash: []const u8,
        ) [secret_len]u8 {
            return std.crypto.tls.hkdfExpandLabel(
                Hkdf,
                secret,
                label,
                transcript_hash,
                secret_len,
            );
        }

        comptime {
            _ = Self;
        }
    };
}
