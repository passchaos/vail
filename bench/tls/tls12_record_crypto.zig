const std = @import("std");
const vail = @import("vail");

const iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    const plaintext = [_]u8{0x51} ** 1200;
    inline for ([_]vail.tls.tls12.Suite{
        .ecdhe_rsa_aes_128_gcm_sha256,
        .ecdhe_rsa_aes_256_gcm_sha384,
        .ecdhe_rsa_chacha20_poly1305_sha256,
    }) |suite| {
        const key_bytes = [_]u8{0x42} ** vail.tls.tls12.max_key_len;
        const iv_bytes = [_]u8{0x43} ** vail.tls.tls12.max_iv_len;
        var sealer = vail.tls.tls12.TrafficState.init(
            try vail.tls.tls12.Keys.init(
                suite,
                key_bytes[0..suite.keyLength()],
                iv_bytes[0..suite.fixedIvLength()],
            ),
        );
        defer sealer.deinit();
        var roundtrip_sealer = vail.tls.tls12.TrafficState.init(
            try vail.tls.tls12.Keys.init(
                suite,
                key_bytes[0..suite.keyLength()],
                iv_bytes[0..suite.fixedIvLength()],
            ),
        );
        defer roundtrip_sealer.deinit();
        var opener = vail.tls.tls12.TrafficState.init(
            try vail.tls.tls12.Keys.init(
                suite,
                key_bytes[0..suite.keyLength()],
                iv_bytes[0..suite.fixedIvLength()],
            ),
        );
        defer opener.deinit();
        var ciphertext: [vail.tls.tls12.max_record_len]u8 = undefined;
        var opened: [plaintext.len]u8 = undefined;
        var checksum: u64 = 0;

        const seal_start = nowNs(init.io);
        for (0..iterations) |_| {
            const len = try sealer.seal(23, &plaintext, &ciphertext);
            checksum +%= ciphertext[len - 1];
        }
        const seal_ns = nowNs(init.io) -| seal_start;

        const roundtrip_start = nowNs(init.io);
        for (0..iterations) |_| {
            const len = try roundtrip_sealer.seal(
                23,
                &plaintext,
                &ciphertext,
            );
            const result = try opener.open(ciphertext[0..len], &opened);
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
