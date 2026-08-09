const std = @import("std");
const vail = @import("vail");

const traffic = vail.quic.traffic_crypto;
const iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    const secret = [_]u8{0x42} ** traffic.secret_len;
    const plaintext = [_]u8{0x51} ** 1200;
    const aad = "quic short header";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [traffic.tag_len]u8 = undefined;
    var opened: [plaintext.len]u8 = undefined;

    inline for (.{
        traffic.Suite.aes_128_gcm_sha256,
        traffic.Suite.chacha20_poly1305_sha256,
    }) |suite| {
        const keys = traffic.Keys.derive(suite, secret, .{});
        const seal_start = nowNs(init.io);
        var checksum: u64 = 0;
        for (0..iterations) |packet_number| {
            try keys.protect(
                packet_number,
                aad,
                &plaintext,
                &ciphertext,
                &tag,
            );
            checksum +%= ciphertext[0];
        }
        const seal_ns = nowNs(init.io) -| seal_start;

        const open_start = nowNs(init.io);
        for (0..iterations) |packet_number| {
            try keys.protect(
                packet_number,
                aad,
                &plaintext,
                &ciphertext,
                &tag,
            );
            try keys.open(
                packet_number,
                aad,
                &ciphertext,
                tag,
                &opened,
            );
            checksum +%= opened[0];
        }
        const open_ns = nowNs(init.io) -| open_start;

        std.debug.print(
            "{s}: seal={d} ns/op open+seal={d} ns/op checksum={d}\n",
            .{
                @tagName(suite),
                seal_ns / iterations,
                open_ns / iterations,
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
