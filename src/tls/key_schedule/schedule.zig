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
            shared_secret: []const u8,
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
                shared_secret,
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
            const empty_hash = std.crypto.tls.emptyHash(Hash);
            var derived_secret = deriveSecret(
                exporter_master_secret,
                label,
                &empty_hash,
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
