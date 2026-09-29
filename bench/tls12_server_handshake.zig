const std = @import("std");
const vail = @import("vail");

const iterations: usize = 500;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const vectors = vail.crypto.testing.rsa_signing;
    const certificate = decodeHex(vectors.certificate_hex);
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(&private_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const signer = vail.tls.auth.Signer{ .rsa_pss = .{
        .prepared_key = &prepared_key,
        .io = init.io,
    } };

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try vail.tls.client_hello.writeWithKeyShare(
        &client_hello,
        allocator,
        .{
            .random = [_]u8{0x91} ** 32,
            .server_name = "example.com",
            .key_share = .{
                .group = vail.tls.key_exchange.named_group_x25519,
                .key_exchange = &([_]u8{0x92} ** 32),
            },
            .supported_groups = &.{
                vail.tls.key_exchange.named_group_x25519,
                vail.tls.key_exchange.named_group_secp256r1,
            },
            .additional_cipher_suites = &.{@intFromEnum(
                vail.tls.tls12.Suite.ecdhe_rsa_aes_128_gcm_sha256,
            )},
            .supported_versions = &.{0x0303},
            .offer_extended_master_secret = true,
        },
    );
    const parsed = try vail.tls.client_hello.parse(client_hello.items);
    var server_private = [_]u8{0} ** vail.tls.key_exchange.p256.secret_len;
    server_private[server_private.len - 1] = 5;
    const server_public = try vail.tls.key_exchange.p256.publicKey(
        server_private,
    );
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var checksum: u64 = 0;

    const start = nowNs(init.io);
    for (0..iterations) |_| {
        output.clearRetainingCapacity();
        const result = try vail.tls.tls12_handshake.writeServerFlight(
            &output,
            allocator,
            client_hello.items,
            parsed,
            .{},
            [_]u8{0x93} ** 32,
            &server_public,
            &.{&certificate},
            signer,
        );
        checksum +%= output.items[output.items.len - 1];
        checksum +%= result.transcript_state.digest().bytes()[0];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "p256-rsa2048-aes128={d} ns/server-flight checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
