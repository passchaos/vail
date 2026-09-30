const std = @import("std");
const vail = @import("vail");

const iterations: usize = 5_000;
const Server = vail.tls.server_connection.ServerConnection(4096, 256);

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const client_private = [_]u8{0x31} ** vail.tls.key_exchange.secret_len;
    const client_public = try vail.tls.key_exchange.publicKey(client_private);
    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try vail.tls.client_hello.write(&client_hello, allocator, .{
        .random = [_]u8{0x32} ** 32,
        .server_name = "example.com",
        .x25519_public_key = client_public,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
    });
    var client_record: std.ArrayList(u8) = .empty;
    defer client_record.deinit(allocator);
    try appendRecord(&client_record, allocator, client_hello.items);

    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x33} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    const certificate = signing_key.public_key.toBytes();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var checksum: u64 = 0;

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        output.clearRetainingCapacity();
        var material = vail.tls.key_exchange.ServerKeyMaterial{
            .x25519 = [_]u8{@truncate(iteration + 1)} **
                vail.tls.key_exchange.secret_len,
        };
        var server = Server.init(.{
            .allocator = allocator,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{vail.tls.key_exchange.named_group_x25519},
                .alpn_protocols = &.{"h2"},
            },
            .server_random = [_]u8{0x34} ** 32,
            .key_material = &material,
            .certificate_chain = &.{&certificate},
            .signer = .{ .ed25519 = .{ .key_pair = signing_key } },
        });
        defer server.deinit();
        const result = try server.receive(client_record.items, &output);
        if (result.event == null or
            std.meta.activeTag(result.event.?) != .server_flight)
        {
            return error.HandshakeDidNotAdvance;
        }
        checksum +%= output.items[output.items.len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519_ed25519_aes128={d} ns/server-connection-flight checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn appendRecord(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    payload: []const u8,
) !void {
    try output.appendSlice(allocator, &.{
        vail.tls.record.content_type_handshake,
        3,
        1,
        @truncate(payload.len >> 8),
        @truncate(payload.len),
    });
    try output.appendSlice(allocator, payload);
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
