const std = @import("std");
const vail = @import("vail");

const iterations: usize = 5_000;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const ech_secret = [_]u8{0x61} ** vail.crypto.hpke.secret_key_len;
    var ech_key_pair = try vail.crypto.hpke.KeyPair.fromSecretKey(&ech_secret);
    defer ech_key_pair.deinit();
    var encoded_config: std.ArrayList(u8) = .empty;
    defer encoded_config.deinit(allocator);
    try vail.tls.ech.writeConfig(&encoded_config, allocator, .{
        .config_id = 1,
        .public_key = ech_key_pair.public_key,
        .maximum_name_length = 32,
        .public_name = "public.example",
    });
    const config = try vail.tls.ech.parseConfig(encoded_config.items);

    const share = [_]u8{0x62} ** 32;
    var inner_template: std.ArrayList(u8) = .empty;
    defer inner_template.deinit(allocator);
    try vail.tls.client_hello.writeWithKeyShare(&inner_template, allocator, .{
        .random = [_]u8{0x63} ** 32,
        .session_id = "ech-benchmark",
        .server_name = "private.example",
        .key_share = .{ .group = 0x001d, .key_exchange = &share },
        .supported_groups = &.{0x001d},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .supported_versions = &.{0x0304},
        .alpn_protocols = &.{ "h2", "http/1.1" },
    });
    var outer_template: std.ArrayList(u8) = .empty;
    defer outer_template.deinit(allocator);
    try vail.tls.client_hello.writeWithKeyShare(&outer_template, allocator, .{
        .random = [_]u8{0x64} ** 32,
        .session_id = "ech-benchmark",
        .server_name = "public.example",
        .key_share = .{ .group = 0x001d, .key_exchange = &share },
        .supported_groups = &.{0x001d},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .supported_versions = &.{0x0304},
    });

    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    var checksum: u64 = 0;
    const client_start = nowNs(init.io);
    for (0..iterations) |_| {
        inner.clearRetainingCapacity();
        outer.clearRetainingCapacity();
        var context = try vail.tls.ech.ClientContext.init(
            allocator,
            init.io,
            config,
        );
        try context.sealInitial(
            &inner,
            &outer,
            allocator,
            inner_template.items,
            outer_template.items,
        );
        checksum +%= outer.items[outer.items.len - 1];
        context.deinit();
    }
    const client_ns = nowNs(init.io) -| client_start;

    var recovered: std.ArrayList(u8) = .empty;
    defer recovered.deinit(allocator);
    const server_start = nowNs(init.io);
    for (0..iterations) |_| {
        recovered.clearRetainingCapacity();
        var context = try vail.tls.ech.openInitialWithKeyPair(
            &recovered,
            allocator,
            outer.items,
            config,
            &ech_key_pair,
        );
        checksum +%= recovered.items[recovered.items.len - 1];
        context.deinit();
    }
    const server_ns = nowNs(init.io) -| server_start;

    const unprepared_server_start = nowNs(init.io);
    for (0..iterations) |_| {
        recovered.clearRetainingCapacity();
        var context = try vail.tls.ech.openInitial(
            &recovered,
            allocator,
            outer.items,
            config,
            &ech_secret,
        );
        checksum +%= recovered.items[0];
        context.deinit();
    }
    const unprepared_server_ns = nowNs(init.io) -| unprepared_server_start;

    std.debug.print(
        "rfc9849_x25519_aes128gcm: client={d} ns/op " ++
            "server_prepared={d} ns/op server_unprepared={d} ns/op " ++
            "inner={d} outer={d} checksum={d}\n",
        .{
            client_ns / iterations,
            server_ns / iterations,
            unprepared_server_ns / iterations,
            inner.items.len,
            outer.items.len,
            checksum,
        },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
