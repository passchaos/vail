const std = @import("std");
const vail = @import("vail");

const iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    const plaintext = [_]u8{0x51} ** 1200;
    inline for (.{
        vail.tls.cipher_suite.Suite.aes_128_gcm_sha256,
        vail.tls.cipher_suite.Suite.aes_128_ccm_sha256,
        vail.tls.cipher_suite.Suite.aes_256_gcm_sha384,
        vail.tls.cipher_suite.Suite.chacha20_poly1305_sha256,
        vail.tls.cipher_suite.Suite.sm4_gcm_sm3,
        vail.tls.cipher_suite.Suite.sm4_ccm_sm3,
    }) |suite| {
        const traffic_secret = switch (suite.hash()) {
            .sha256 => vail.tls.secret.Secret.fromSha256(
                [_]u8{0x42} ** 32,
            ),
            .sha384 => vail.tls.secret.Secret.fromSha384(
                [_]u8{0x43} ** 48,
            ),
            .sm3 => vail.tls.secret.Secret.fromSm3(
                [_]u8{0x44} ** 32,
            ),
        };

        var sealer = try vail.tls.traffic.State.init(
            suite,
            traffic_secret,
        );
        defer sealer.deinit();
        var roundtrip_sealer = try vail.tls.traffic.State.init(
            suite,
            traffic_secret,
        );
        defer roundtrip_sealer.deinit();
        var roundtrip_opener = try vail.tls.traffic.State.init(
            suite,
            traffic_secret,
        );
        defer roundtrip_opener.deinit();
        var ciphertext: [
            vail.tls.record.header_len + plaintext.len + 1 +
                vail.tls.record.tag_len
        ]u8 = undefined;
        var opened: [plaintext.len + 1]u8 = undefined;
        var checksum: u64 = 0;

        const seal_start = nowNs(init.io);
        for (0..iterations) |_| {
            const len = try sealer.seal(
                vail.tls.record.content_type_application_data,
                &plaintext,
                &ciphertext,
            );
            checksum +%= ciphertext[len - 1];
        }
        const seal_ns = nowNs(init.io) -| seal_start;

        const roundtrip_start = nowNs(init.io);
        for (0..iterations) |_| {
            const len = try roundtrip_sealer.seal(
                vail.tls.record.content_type_application_data,
                &plaintext,
                &ciphertext,
            );
            const result = try roundtrip_opener.open(
                ciphertext[0..len],
                &opened,
            );
            checksum +%= opened[result.len - 1];
        }
        const roundtrip_ns = nowNs(init.io) -| roundtrip_start;

        std.debug.print(
            "{s}: seal={d} ns/op open+seal={d} ns/op checksum={d}\n",
            .{
                @tagName(suite),
                seal_ns / iterations,
                roundtrip_ns / iterations,
                checksum,
            },
        );
    }
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
