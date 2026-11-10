const std = @import("std");
const vail = @import("vail");

const hpke = vail.crypto.hpke;
const setup_iterations: usize = 10_000;
const traffic_iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    var recipient = hpke.KeyPair.generate(init.io);
    defer recipient.deinit();
    var checksum: u64 = 0;

    const sender_setup_start = nowNs(init.io);
    for (0..setup_iterations) |_| {
        var sender = try hpke.setupBaseSender(
            init.io,
            recipient.public_key,
            "tls ech",
        );
        checksum +%= sender.enc[0];
        sender.deinit();
    }
    const sender_setup_ns = nowNs(init.io) -| sender_setup_start;

    var fixed_sender = try hpke.setupBaseSender(
        init.io,
        recipient.public_key,
        "tls ech",
    );
    defer fixed_sender.deinit();
    const receiver_setup_start = nowNs(init.io);
    for (0..setup_iterations) |_| {
        var receiver = try hpke.setupBaseReceiver(
            fixed_sender.enc,
            &recipient.secret_key,
            "tls ech",
        );
        var exported: [1]u8 = undefined;
        try receiver.exportSecret(&exported, "benchmark");
        checksum +%= exported[0];
        receiver.deinit();
    }
    const receiver_setup_ns = nowNs(init.io) -| receiver_setup_start;

    const plaintext = [_]u8{0x45} ** 256;
    const aad = "encrypted client hello";
    var sealed: [plaintext.len + hpke.tag_len]u8 = undefined;
    const seal_start = nowNs(init.io);
    for (0..traffic_iterations) |_| {
        try fixed_sender.context.seal(&sealed, &plaintext, aad);
        checksum +%= sealed[0];
    }
    const seal_ns = nowNs(init.io) -| seal_start;

    var sender = try hpke.setupBaseSender(
        init.io,
        recipient.public_key,
        "tls ech traffic",
    );
    defer sender.deinit();
    var receiver = try hpke.setupBaseReceiver(
        sender.enc,
        &recipient.secret_key,
        "tls ech traffic",
    );
    defer receiver.deinit();
    var opened: [plaintext.len]u8 = undefined;
    const round_trip_start = nowNs(init.io);
    for (0..traffic_iterations) |_| {
        try sender.context.seal(&sealed, &plaintext, aad);
        try receiver.open(&opened, &sealed, aad);
        checksum +%= opened[0];
    }
    const round_trip_ns = nowNs(init.io) -| round_trip_start;

    std.debug.print(
        "hpke context bytes: sender={d} receiver={d}\n" ++
            "x25519_hkdf_sha256_aes128gcm: " ++
            "sender_setup={d} ns/op receiver_setup={d} ns/op " ++
            "seal_256={d} ns/op seal_open_256={d} ns/op checksum={d}\n",
        .{
            @sizeOf(hpke.SenderContext),
            @sizeOf(hpke.ReceiverContext),
            sender_setup_ns / setup_iterations,
            receiver_setup_ns / setup_iterations,
            seal_ns / traffic_iterations,
            round_trip_ns / traffic_iterations,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
