//! Compile-time-specialized TLS 1.3 key schedule.
//!
//! RFC 8446 binds each cipher suite to one transcript hash.  Specializing the
//! schedule by hash preserves exact fixed-size secret types and lets Zig inline
//! HKDF/HMAC without a runtime algorithm switch.

const std = @import("std");
const sha256 = @import("../../crypto/sha256.zig");
const fast_sha2 = @import("../../crypto/sha512.zig");

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

        const TrafficSecretPair = struct {
            client: [secret_len]u8,
            server: [secret_len]u8,
        };

        const empty_transcript_hash: [secret_len]u8 = blk: {
            @setEvalBranchQuota(10_000);
            const ComptimeHash = if (Hash == fast_sha2.Sha384)
                std.crypto.hash.sha2.Sha384
            else if (Hash == sha256.Hash)
                std.crypto.hash.sha2.Sha256
            else
                Hash;
            break :blk std.crypto.tls.emptyHash(ComptimeHash);
        };

        pub fn earlySecret(psk: ?[secret_len]u8) [secret_len]u8 {
            const zero = [_]u8{0} ** secret_len;
            return Hkdf.extract(
                &zero,
                if (psk) |value| &value else &zero,
            );
        }

        pub fn deriveHandshake(
            shared_secret: []const u8,
            transcript_hash: [secret_len]u8,
            psk: ?[secret_len]u8,
        ) HandshakeSecrets {
            const early_secret = earlySecret(psk);
            const derived_secret = deriveSecret(
                early_secret,
                "derived",
                &empty_transcript_hash,
            );
            const handshake_secret = Hkdf.extract(
                &derived_secret,
                shared_secret,
            );
            const traffic = deriveSecretPair(
                handshake_secret,
                "c hs traffic",
                "s hs traffic",
                &transcript_hash,
            );
            return .{
                .early_secret = early_secret,
                .handshake_secret = handshake_secret,
                .client_traffic_secret = traffic.client,
                .server_traffic_secret = traffic.server,
            };
        }

        pub fn deriveApplication(
            handshake_secret: [secret_len]u8,
            transcript_hash: [secret_len]u8,
        ) ApplicationSecrets {
            const zero = [_]u8{0} ** secret_len;
            const derived_secret = deriveSecret(
                handshake_secret,
                "derived",
                &empty_transcript_hash,
            );
            const master_secret = Hkdf.extract(&derived_secret, &zero);
            const traffic = deriveSecretPair(
                master_secret,
                "c ap traffic",
                "s ap traffic",
                &transcript_hash,
            );
            return .{
                .master_secret = master_secret,
                .client_traffic_secret = traffic.client,
                .server_traffic_secret = traffic.server,
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
            const binder_key = deriveSecret(
                earlySecret(psk),
                "res binder",
                &empty_transcript_hash,
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

        /// Derive the TLS 1.3 exporter master secret from the transcript
        /// through the peer Finished message (RFC 8446 section 7.1).
        pub fn deriveExporterMasterSecret(
            master_secret: [secret_len]u8,
            transcript_hash: [secret_len]u8,
        ) [secret_len]u8 {
            return deriveSecret(
                master_secret,
                "exp master",
                &transcript_hash,
            );
        }

        /// Export application keying material as specified by RFC 8446
        /// section 7.5. The caller supplies the already-derived exporter
        /// master secret so no transcript or traffic-secret state is needed.
        pub fn exportKeyingMaterial(
            exporter_master_secret: [secret_len]u8,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) error{InvalidExporterInput}!void {
            // HKDF-Expand-Label prepends "tls13 " to the caller's label; its
            // one-byte vector length therefore limits the caller portion to
            // 249 bytes. The context itself is hashed before encoding.
            if (label.len > 249 or
                out.len > std.math.maxInt(u16) or
                out.len > secret_len * 255)
            {
                return error.InvalidExporterInput;
            }
            var context_hash: [secret_len]u8 = undefined;
            Hash.hash(context, &context_hash, .{});
            var derived_secret = deriveSecret(
                exporter_master_secret,
                label,
                &empty_transcript_hash,
            );
            defer std.crypto.secureZero(u8, &derived_secret);
            // The standard helper requires a comptime output length. Build its
            // RFC 8446 HkdfLabel here for caller-sized output without allocation.
            var info: [2 + 1 + 6 + 249 + 1 + 255]u8 = undefined;
            std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
            info[2] = 14;
            @memcpy(info[3..9], "tls13 ");
            @memcpy(info[9..17], "exporter");
            var offset: usize = 17;
            info[offset] = @intCast(context_hash.len);
            offset += 1;
            @memcpy(info[offset..][0..context_hash.len], &context_hash);
            offset += context_hash.len;
            Hkdf.expand(out, info[0..offset], derived_secret);
            std.crypto.secureZero(u8, &context_hash);
            std.crypto.secureZero(u8, &info);
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

        fn deriveSecretPair(
            key: [secret_len]u8,
            client_label: []const u8,
            server_label: []const u8,
            context: []const u8,
        ) TrafficSecretPair {
            if (comptime Hash == sha256.Hash) {
                var expander: sha256.PreparedHmac = undefined;
                expander.initInto(&key);
                defer expander.deinit();
                return .{
                    .client = expander.expandLabel(
                        client_label,
                        context,
                        secret_len,
                    ),
                    .server = expander.expandLabel(
                        server_label,
                        context,
                        secret_len,
                    ),
                };
            }
            if (comptime Hash == fast_sha2.Sha384) {
                var expander = fast_sha2.PreparedHmac(Hash).init(&key);
                defer expander.deinit();
                return .{
                    .client = expander.expandLabel(
                        client_label,
                        context,
                        secret_len,
                    ),
                    .server = expander.expandLabel(
                        server_label,
                        context,
                        secret_len,
                    ),
                };
            }
            return .{
                .client = deriveSecret(key, client_label, context),
                .server = deriveSecret(key, server_label, context),
            };
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

test "prepared SHA-256 traffic-secret pairs match independent HKDF" {
    const Hash = std.crypto.hash.sha2.Sha256;
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
    const Sha256Schedule = Schedule(Hash);
    const zero = [_]u8{0} ** Hash.digest_length;
    const psk = [_]u8{0x31} ** Hash.digest_length;
    const shared_secret = [_]u8{0x52} ** Hash.digest_length;
    const handshake_hash = [_]u8{0x73} ** Hash.digest_length;
    const application_hash = [_]u8{0x94} ** Hash.digest_length;
    const empty_hash = std.crypto.tls.emptyHash(Hash);

    const early_secret = Hkdf.extract(&zero, &psk);
    const early_derived = std.crypto.tls.hkdfExpandLabel(
        Hkdf,
        early_secret,
        "derived",
        &empty_hash,
        Hash.digest_length,
    );
    const handshake_secret = Hkdf.extract(&early_derived, &shared_secret);
    const handshake = Sha256Schedule.deriveHandshake(
        &shared_secret,
        handshake_hash,
        psk,
    );
    try std.testing.expectEqual(early_secret, handshake.early_secret);
    try std.testing.expectEqual(handshake_secret, handshake.handshake_secret);
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            handshake_secret,
            "c hs traffic",
            &handshake_hash,
            Hash.digest_length,
        ),
        handshake.client_traffic_secret,
    );
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            handshake_secret,
            "s hs traffic",
            &handshake_hash,
            Hash.digest_length,
        ),
        handshake.server_traffic_secret,
    );

    const handshake_derived = std.crypto.tls.hkdfExpandLabel(
        Hkdf,
        handshake_secret,
        "derived",
        &empty_hash,
        Hash.digest_length,
    );
    const master_secret = Hkdf.extract(&handshake_derived, &zero);
    const application = Sha256Schedule.deriveApplication(
        handshake_secret,
        application_hash,
    );
    try std.testing.expectEqual(master_secret, application.master_secret);
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            master_secret,
            "c ap traffic",
            &application_hash,
            Hash.digest_length,
        ),
        application.client_traffic_secret,
    );
    try std.testing.expectEqual(
        std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            master_secret,
            "s ap traffic",
            &application_hash,
            Hash.digest_length,
        ),
        application.server_traffic_secret,
    );
}
