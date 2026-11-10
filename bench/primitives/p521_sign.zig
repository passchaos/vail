const std = @import("std");
const vail = @import("vail");

const iterations: usize = 500;
const random_iterations: usize = 1_000;
const warmup_iterations: usize = 32;
const batch_size: usize = 8;
const batch_iterations: usize = iterations / batch_size;
const message = "Vail pure Zig P-521 signing benchmark";

pub fn main(init: std.process.Init) !void {
    var secret_key = try vail.crypto.p521.SecretKey.fromBytes(decodeHex(
        "00123456789abcdef00112233445566778899aabbccddeeff1021324354657687" ++
            "98a9bacbdcedfe0f112233445566778899aabbccddeeff00123456789abcdef1234",
    ));
    defer secret_key.deinit();
    var key_pair = try vail.crypto.p521.KeyPair.fromSecretKey(secret_key);
    defer key_pair.deinit();
    var nonce = decodeHex(
        "000deadbeefcafebabefeedface0123456789abcdef102030405060708090a0b0" ++
            "c0d0e0f00112233445566778899aabbccddeeff13579bdf2468ace00123456789ab",
    );
    var encoded: [vail.crypto.p521.Signature.der_encoded_length_max]u8 =
        undefined;
    var checksum: u64 = 0;

    for (0..warmup_iterations) |iteration| {
        std.mem.writeInt(
            u16,
            nonce[nonce.len - 2 ..][0..2],
            @intCast(0x8000 + iteration),
            .big,
        );
        const signature = try key_pair.sign(
            std.crypto.hash.sha2.Sha512,
            message,
            &nonce,
        );
        _ = signature.toDer(&encoded);
    }
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.writeInt(
            u16,
            nonce[nonce.len - 2 ..][0..2],
            @intCast(iteration + 1),
            .big,
        );
        const signature = try key_pair.sign(
            std.crypto.hash.sha2.Sha512,
            message,
            &nonce,
        );
        const der = signature.toDer(&encoded);
        checksum +%= der[iteration % der.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "pure-zig-p521-sha512-end-to-end={d} ns/sign checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );

    checksum = 0;
    for (0..warmup_iterations) |_| {
        var prepared = try key_pair.prepareRandomNonce(init.io);
        defer prepared.deinit();
        const signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            &prepared,
        );
        std.mem.doNotOptimizeAway(signature.toDer(&encoded));
    }
    const random_start = nowNs(init.io);
    for (0..random_iterations) |iteration| {
        var prepared = try key_pair.prepareRandomNonce(init.io);
        defer prepared.deinit();
        const signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            &prepared,
        );
        const der = signature.toDer(&encoded);
        checksum +%= der[iteration % der.len];
    }
    const random_elapsed = nowNs(init.io) -| random_start;
    std.debug.print(
        "pure-zig-p521-sha512-random-end-to-end={d} ns/sign checksum={d}\n",
        .{ random_elapsed / random_iterations, checksum },
    );

    checksum = 0;
    const prepare_start = nowNs(init.io);
    for (0..iterations) |iteration| {
        std.mem.writeInt(
            u16,
            nonce[nonce.len - 2 ..][0..2],
            @intCast(iteration + 1),
            .big,
        );
        var prepared = try key_pair.prepareNonce(&nonce);
        checksum +%= @intFromBool(prepared.isReady());
        prepared.deinit();
    }
    const prepare_elapsed = nowNs(init.io) -| prepare_start;
    std.debug.print(
        "pure-zig-p521-nonce-prepare={d} ns/nonce checksum={d}\n",
        .{ prepare_elapsed / iterations, checksum },
    );

    var prepared_nonces: [iterations]vail.crypto.p521.PreparedNonce = undefined;
    for (&prepared_nonces, 0..) |*prepared, iteration| {
        std.mem.writeInt(
            u16,
            nonce[nonce.len - 2 ..][0..2],
            @intCast(iteration + 1),
            .big,
        );
        prepared.* = try key_pair.prepareNonce(&nonce);
    }
    defer for (&prepared_nonces) |*prepared| prepared.deinit();
    checksum = 0;
    const online_start = nowNs(init.io);
    for (&prepared_nonces, 0..) |*prepared, iteration| {
        const signature = try key_pair.signPrepared(
            std.crypto.hash.sha2.Sha512,
            message,
            prepared,
        );
        const der = signature.toDer(&encoded);
        checksum +%= der[iteration % der.len];
    }
    const online_elapsed = nowNs(init.io) -| online_start;
    std.debug.print(
        "pure-zig-p521-sha512-prepared={d} ns/sign checksum={d}\n",
        .{ online_elapsed / iterations, checksum },
    );

    var batch_nonces: [batch_size][vail.crypto.p521.secret_key_encoded_length]u8 =
        undefined;
    var batch: [batch_size]vail.crypto.p521.PreparedNonce = undefined;
    checksum = 0;
    const batch_prepare_start = nowNs(init.io);
    for (0..batch_iterations) |round| {
        for (&batch_nonces, 0..) |*batch_nonce, index| {
            batch_nonce.* = nonce;
            std.mem.writeInt(
                u16,
                batch_nonce[batch_nonce.len - 2 ..][0..2],
                @intCast(round * batch_size + index + 1),
                .big,
            );
        }
        try key_pair.prepareNonceBatch(
            batch_size,
            &batch_nonces,
            &batch,
        );
        for (&batch) |*prepared| {
            checksum +%= @intFromBool(prepared.isReady());
            prepared.deinit();
        }
    }
    const batch_prepare_elapsed = nowNs(init.io) -| batch_prepare_start;
    std.debug.print(
        "pure-zig-p521-nonce-prepare-batch8={d} ns/nonce checksum={d}\n",
        .{ batch_prepare_elapsed / (batch_iterations * batch_size), checksum },
    );

    checksum = 0;
    const batch_end_to_end_start = nowNs(init.io);
    for (0..batch_iterations) |round| {
        try key_pair.prepareRandomNonceBatch(
            batch_size,
            init.io,
            &batch,
        );
        for (&batch, 0..) |*prepared, index| {
            const signature = try key_pair.signPrepared(
                std.crypto.hash.sha2.Sha512,
                message,
                prepared,
            );
            const der = signature.toDer(&encoded);
            checksum +%= der[(round * batch_size + index) % der.len];
        }
    }
    const batch_end_to_end_elapsed = nowNs(init.io) -| batch_end_to_end_start;
    std.debug.print(
        "pure-zig-p521-sha512-random-batch8-end-to-end={d} ns/sign checksum={d}\n",
        .{
            batch_end_to_end_elapsed / (batch_iterations * batch_size),
            checksum,
        },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
