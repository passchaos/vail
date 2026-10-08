const std = @import("std");
const vail = @import("vail");

const ChaCha20Poly1305 = vail.crypto.chacha20_poly1305;
const iterations: usize = 200_000;
const warmup_iterations: usize = 256;

pub fn main(init: std.process.Init) void {
    var key = [_]u8{0x42} ** ChaCha20Poly1305.key_length;
    var nonce = [_]u8{0x43} ** ChaCha20Poly1305.nonce_length;
    var aad = "quic short header".*;
    var plaintext = [_]u8{0x51} ** 1200;
    std.mem.doNotOptimizeAway(&key);
    std.mem.doNotOptimizeAway(&nonce);
    std.mem.doNotOptimizeAway(&aad);
    std.mem.doNotOptimizeAway(&plaintext);
    var ciphertext: [plaintext.len]u8 = undefined;
    var opened: [plaintext.len]u8 = undefined;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    var context = ChaCha20Poly1305.Context.init(key);
    defer context.deinit();
    var checksum: u64 = 0;

    for (0..warmup_iterations) |_| {
        context.encrypt(&ciphertext, &tag, &plaintext, &aad, nonce);
        checksum +%= ciphertext[0];
        checksum +%= tag[0];
    }
    const start = nowNs(init.io);
    for (0..iterations) |_| {
        context.encrypt(&ciphertext, &tag, &plaintext, &aad, nonce);
        checksum +%= ciphertext[0];
        checksum +%= tag[0];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "pure-zig-chacha20-poly1305-seal={d} ns/op ({d} ps/op) checksum={d}\n",
        .{ elapsed / iterations, elapsed * 1000 / iterations, checksum },
    );

    for (0..warmup_iterations) |_| {
        context.decrypt(&opened, &ciphertext, tag, &aad, nonce) catch unreachable;
        checksum +%= opened[0];
    }
    const open_start = nowNs(init.io);
    for (0..iterations) |_| {
        context.decrypt(&opened, &ciphertext, tag, &aad, nonce) catch unreachable;
        checksum +%= opened[0];
    }
    const open_elapsed = nowNs(init.io) -| open_start;
    std.debug.print(
        "pure-zig-chacha20-poly1305-open={d} ns/op ({d} ps/op) checksum={d}\n",
        .{
            open_elapsed / iterations,
            open_elapsed * 1000 / iterations,
            checksum,
        },
    );

    for (0..warmup_iterations) |_| {
        context.encrypt(&ciphertext, &tag, &plaintext, &aad, nonce);
        context.decrypt(&opened, &ciphertext, tag, &aad, nonce) catch unreachable;
        checksum +%= opened[0];
    }
    const round_trip_start = nowNs(init.io);
    for (0..iterations) |_| {
        context.encrypt(&ciphertext, &tag, &plaintext, &aad, nonce);
        context.decrypt(&opened, &ciphertext, tag, &aad, nonce) catch unreachable;
        checksum +%= opened[0];
    }
    const round_trip_elapsed = nowNs(init.io) -| round_trip_start;
    std.debug.print(
        "pure-zig-chacha20-poly1305-open+seal={d} ns/op ({d} ps/op) " ++
            "checksum={d}\n",
        .{
            round_trip_elapsed / iterations,
            round_trip_elapsed * 1000 / iterations,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
