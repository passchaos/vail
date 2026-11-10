const std = @import("std");
const vail = @import("vail");

const iterations: usize = 1_000;
const warmup_iterations: usize = 32;

pub fn main(init: std.process.Init) !void {
    var local_secret = [_]u8{0} ** vail.crypto.p521.secret_key_encoded_length;
    defer std.crypto.secureZero(u8, &local_secret);
    local_secret[local_secret.len - 1] = 7;
    var peer_secret = [_]u8{0} ** vail.crypto.p521.secret_key_encoded_length;
    defer std.crypto.secureZero(u8, &peer_secret);
    peer_secret[peer_secret.len - 1] = 11;
    const peer_public = try vail.crypto.p521.ecdhPublicKey(peer_secret);
    var prepared_local = try vail.crypto.p521.PreparedEcdhSecret.init(
        local_secret,
    );
    defer prepared_local.deinit();

    var checksum: u64 = 0;
    for (0..warmup_iterations) |_| {
        try vail.crypto.p521.validatePublicKey(&peer_public);
    }
    const validate_start = nowNs(init.io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(&peer_public);
        try vail.crypto.p521.validatePublicKey(&peer_public);
    }
    const validate_elapsed = nowNs(init.io) -| validate_start;
    std.debug.print(
        "pure-zig-p521-validate={d} ns/op\n",
        .{validate_elapsed / iterations},
    );

    for (0..warmup_iterations) |_| {
        std.mem.doNotOptimizeAway(&local_secret);
        const public = try vail.crypto.p521.ecdhPublicKey(local_secret);
        checksum +%= public[public.len - 1];
    }
    const public_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&local_secret);
        const public = try vail.crypto.p521.ecdhPublicKey(local_secret);
        checksum +%= public[iteration % public.len];
    }
    const public_elapsed = nowNs(init.io) -| public_start;
    std.debug.print(
        "pure-zig-p521-ecdh-public={d} ns/op checksum={d}\n",
        .{ public_elapsed / iterations, checksum },
    );

    checksum = 0;
    for (0..warmup_iterations) |_| {
        std.mem.doNotOptimizeAway(&local_secret);
        std.mem.doNotOptimizeAway(&peer_public);
        const shared = try vail.crypto.p521.ecdhSharedSecret(
            local_secret,
            &peer_public,
        );
        checksum +%= shared[shared.len - 1];
    }
    const shared_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&local_secret);
        std.mem.doNotOptimizeAway(&peer_public);
        const shared = try vail.crypto.p521.ecdhSharedSecret(
            local_secret,
            &peer_public,
        );
        checksum +%= shared[iteration % shared.len];
    }
    const shared_elapsed = nowNs(init.io) -| shared_start;
    std.debug.print(
        "pure-zig-p521-ecdh-shared={d} ns/op checksum={d}\n",
        .{ shared_elapsed / iterations, checksum },
    );

    checksum = 0;
    for (0..warmup_iterations) |_| {
        std.mem.doNotOptimizeAway(&prepared_local);
        std.mem.doNotOptimizeAway(&peer_public);
        const shared = try prepared_local.sharedSecret(&peer_public);
        checksum +%= shared[shared.len - 1];
    }
    const prepared_shared_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.doNotOptimizeAway(&prepared_local);
        std.mem.doNotOptimizeAway(&peer_public);
        const shared = try prepared_local.sharedSecret(&peer_public);
        checksum +%= shared[iteration % shared.len];
    }
    const prepared_shared_elapsed = nowNs(init.io) -| prepared_shared_start;
    std.debug.print(
        "pure-zig-p521-ecdh-shared-prepared={d} ns/op checksum={d}\n",
        .{ prepared_shared_elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
