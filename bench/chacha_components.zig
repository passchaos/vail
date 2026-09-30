const std = @import("std");
const vail = @import("vail");

const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Poly1305 = std.crypto.onetimeauth.Poly1305;
const prepared = vail.crypto.chacha20_poly1305;

const iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    const key = [_]u8{0x42} ** ChaCha20Poly1305.key_length;
    const nonce = [_]u8{0x43} ** ChaCha20Poly1305.nonce_length;
    const aad = "quic short header";
    const plaintext = [_]u8{0x51} ** 1200;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    var poly_key: [Poly1305.key_length]u8 = undefined;
    var context = prepared.Context.init(key);
    defer context.deinit();
    var checksum: u64 = 0;

    var start = nowNs(init.io);
    for (0..iterations) |_| {
        ChaCha20IETF.stream(&poly_key, 0, key, nonce);
        checksum +%= poly_key[0];
    }
    const key_ns = nowNs(init.io) -| start;

    start = nowNs(init.io);
    for (0..iterations) |_| {
        ChaCha20IETF.xor(&ciphertext, &plaintext, 1, key, nonce);
        checksum +%= ciphertext[0];
    }
    const stream_ns = nowNs(init.io) -| start;

    start = nowNs(init.io);
    for (0..iterations) |_| {
        var mac = Poly1305.init(&poly_key);
        mac.update(aad);
        mac.pad();
        mac.update(&ciphertext);
        mac.pad();
        var lengths: [16]u8 = undefined;
        std.mem.writeInt(u64, lengths[0..8], aad.len, .little);
        std.mem.writeInt(u64, lengths[8..16], ciphertext.len, .little);
        mac.update(&lengths);
        mac.final(&tag);
        checksum +%= tag[0];
    }
    const poly_ns = nowNs(init.io) -| start;

    start = nowNs(init.io);
    for (0..iterations) |_| {
        ChaCha20Poly1305.encrypt(
            &ciphertext,
            &tag,
            &plaintext,
            aad,
            nonce,
            key,
        );
        checksum +%= ciphertext[0];
    }
    const aead_ns = nowNs(init.io) -| start;

    start = nowNs(init.io);
    for (0..iterations) |_| {
        context.encrypt(
            &ciphertext,
            &tag,
            &plaintext,
            aad,
            nonce,
        );
        checksum +%= ciphertext[0];
    }
    const prepared_ns = nowNs(init.io) -| start;

    var opened: [plaintext.len]u8 = undefined;
    var invalid_tag = tag;
    invalid_tag[0] ^= 1;
    start = nowNs(init.io);
    for (0..iterations) |_| {
        context.decrypt(
            &opened,
            &ciphertext,
            invalid_tag,
            aad,
            nonce,
        ) catch |err| switch (err) {
            error.AuthenticationFailed => checksum +%= 1,
        };
    }
    const prepared_authenticate_ns = nowNs(init.io) -| start;

    start = nowNs(init.io);
    for (0..iterations) |_| {
        context.encrypt(
            &ciphertext,
            &tag,
            &plaintext,
            aad,
            nonce,
        );
        try context.decrypt(
            &opened,
            &ciphertext,
            tag,
            aad,
            nonce,
        );
        checksum +%= opened[0];
    }
    const prepared_round_trip_ns = nowNs(init.io) -| start;

    std.debug.print(
        "poly-key={d} ns stream={d} ns poly1305={d} ns aead={d} ns " ++
            "prepared={d} ns prepared-auth-fail={d} ns " ++
            "prepared-open+seal={d} ns checksum={d}\n",
        .{
            key_ns / iterations,
            stream_ns / iterations,
            poly_ns / iterations,
            aead_ns / iterations,
            prepared_ns / iterations,
            prepared_authenticate_ns / iterations,
            prepared_round_trip_ns / iterations,
            checksum,
        },
    );

    inline for (.{
        .{ .len = 0, .iterations = 500_000 },
        .{ .len = 1, .iterations = 500_000 },
        .{ .len = 4, .iterations = 500_000 },
        .{ .len = 16, .iterations = 500_000 },
        .{ .len = 32, .iterations = 500_000 },
        .{ .len = 64, .iterations = 500_000 },
        .{ .len = 256, .iterations = 300_000 },
        .{ .len = 1200, .iterations = 200_000 },
        .{ .len = 16 * 1024, .iterations = 20_000 },
    }) |case| try benchmarkSize(init.io, case.len, case.iterations);
}

fn benchmarkSize(
    io: std.Io,
    comptime len: usize,
    comptime count: usize,
) !void {
    const key = [_]u8{0x62} ** ChaCha20Poly1305.key_length;
    const nonce = [_]u8{0x63} ** ChaCha20Poly1305.nonce_length;
    const aad = "quic short header";
    const plaintext = [_]u8{0x64} ** len;
    var ciphertext: [len]u8 = undefined;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    var checksum: u64 = 0;

    var start = nowNs(io);
    for (0..count) |_| {
        ChaCha20Poly1305.encrypt(
            &ciphertext,
            &tag,
            &plaintext,
            aad,
            nonce,
            key,
        );
        checksum +%= tag[0];
    }
    const standard_ns = nowNs(io) -| start;

    var context = prepared.Context.init(key);
    defer context.deinit();
    start = nowNs(io);
    for (0..count) |_| {
        context.encrypt(
            &ciphertext,
            &tag,
            &plaintext,
            aad,
            nonce,
        );
        checksum +%= tag[0];
    }
    const prepared_ns = nowNs(io) -| start;
    std.debug.print(
        "len={d}: std={d} ns prepared={d} ns checksum={d}\n",
        .{ len, standard_ns / count, prepared_ns / count, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
