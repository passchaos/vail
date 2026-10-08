const std = @import("std");
const vail = @import("vail");

const traffic = vail.quic.traffic_crypto;
const iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    std.debug.print(
        "prepared key bytes: {d}\n",
        .{@sizeOf(traffic.PreparedKeys)},
    );
    const secret = [_]u8{0x42} ** traffic.secret_len;
    const plaintext = [_]u8{0x51} ** 1200;
    const aad = "quic short header";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [traffic.tag_len]u8 = undefined;
    var opened: [plaintext.len]u8 = undefined;

    inline for (.{
        traffic.Suite.aes_128_gcm_sha256,
        traffic.Suite.aes_128_ccm_sha256,
        traffic.Suite.chacha20_poly1305_sha256,
    }) |suite| {
        const keys = try traffic.Keys.derive(suite, secret, .{});
        var prepared = traffic.PreparedKeys.init(keys);
        defer prepared.deinit();
        const seal_start = nowNs(init.io);
        var checksum: u64 = 0;
        for (0..iterations) |packet_number| {
            try prepared.protect(
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
            try prepared.protect(
                packet_number,
                aad,
                &plaintext,
                &ciphertext,
                &tag,
            );
            try prepared.open(
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

    const aes256 = traffic.aes256_sha384;
    const aes256_keys = aes256.Keys.derive(
        [_]u8{0x42} ** aes256.secret_len,
        .{},
    );
    const seal_start = nowNs(init.io);
    var checksum: u64 = 0;
    for (0..iterations) |packet_number| {
        try aes256_keys.protect(
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
        try aes256_keys.protect(
            packet_number,
            aad,
            &plaintext,
            &ciphertext,
            &tag,
        );
        try aes256_keys.open(
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
        "aes_256_gcm_sha384: seal={d} ns/op open+seal={d} ns/op checksum={d}\n",
        .{
            seal_ns / iterations,
            open_ns / iterations,
            checksum,
        },
    );

    const unified_aes256 = try traffic.Keys.deriveChecked(
        .aes_256_gcm_sha384,
        .fromSha384([_]u8{0x42} ** vail.tls.key_schedule.Sha384.secret_len),
        .{},
    );
    var prepared_unified_aes256 = traffic.PreparedKeys.init(unified_aes256);
    defer prepared_unified_aes256.deinit();
    const unified_seal_start = nowNs(init.io);
    checksum = 0;
    for (0..iterations) |packet_number| {
        try prepared_unified_aes256.protect(
            packet_number,
            aad,
            &plaintext,
            &ciphertext,
            &tag,
        );
        checksum +%= ciphertext[0];
    }
    const unified_seal_ns = nowNs(init.io) -| unified_seal_start;

    const unified_open_start = nowNs(init.io);
    for (0..iterations) |packet_number| {
        try prepared_unified_aes256.protect(
            packet_number,
            aad,
            &plaintext,
            &ciphertext,
            &tag,
        );
        try prepared_unified_aes256.open(
            packet_number,
            aad,
            &ciphertext,
            tag,
            &opened,
        );
        checksum +%= opened[0];
    }
    const unified_open_ns = nowNs(init.io) -| unified_open_start;
    std.debug.print(
        "aes_256_gcm_sha384_unified: seal={d} ns/op open+seal={d} ns/op checksum={d}\n",
        .{
            unified_seal_ns / iterations,
            unified_open_ns / iterations,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
