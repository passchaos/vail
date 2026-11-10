const std = @import("std");
const vail = @import("vail");

const iterations: usize = 5_000;

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
    const parsed = try vail.tls.client_hello.parse(client_hello.items);
    const signing_key = try std.crypto.sign.Ed25519.KeyPair
        .generateDeterministic(
        [_]u8{0x33} ** std.crypto.sign.Ed25519.KeyPair.seed_length,
    );
    var prepared_signer = try vail.crypto.ed25519.PreparedSigner.init(
        signing_key,
    );
    defer prepared_signer.deinit();
    const certificate = signing_key.public_key.toBytes();
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    var checksum: u64 = 0;

    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        flight.clearRetainingCapacity();
        var material = vail.tls.key_exchange.ServerKeyMaterial{
            .x25519 = [_]u8{@truncate(iteration + 1)} **
                vail.tls.key_exchange.secret_len,
        };
        var result = try vail.tls.server_handshake
            .writeServerHandshakeFlightManaged(
            &flight,
            allocator,
            .{
                .client_hello_bytes = client_hello.items,
                .parsed_client_hello = parsed,
                .policy = .{
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .groups = &.{
                        vail.tls.key_exchange.named_group_x25519,
                    },
                    .alpn_protocols = &.{"h2"},
                },
                .server_random = [_]u8{0x34} ** 32,
                .key_material = &material,
                .certificate_chain = &.{&certificate},
                .signer = .{ .ed25519 = .{
                    .key_pair = signing_key,
                    .prepared = &prepared_signer,
                } },
            },
        );
        defer result.handshake_secret.deinit();
        defer result.client_handshake_traffic_secret.deinit();
        defer result.server_handshake_traffic_secret.deinit();
        checksum +%= flight.items[flight.items.len - 1];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "x25519_ed25519_aes128: {d} ns/handshake checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
