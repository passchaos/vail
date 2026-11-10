const std = @import("std");
const vail = @import("vail");

const iterations: usize = 1000;
const Client = vail.tls.tls12_client_connection.ClientConnection(
    64 * 1024,
    64 * 1024,
);

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const vectors = vail.testdata.crypto.rsa_signing;
    const certificate = decodeHex(vectors.certificate_hex);
    const private_der = decodeHex(vectors.private_key_pkcs8_hex);
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(&private_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const signer = vail.tls.auth.Signer{ .rsa_pss = .{
        .prepared_key = &prepared_key,
        .io = init.io,
    } };

    var setup_private = p256Private(3);
    var setup_hello_record: std.ArrayList(u8) = .empty;
    defer setup_hello_record.deinit(allocator);
    var setup_client = try Client.init(.{
        .allocator = allocator,
        .random = [_]u8{0xa1} ** 32,
        .server_name = "localhost",
        .client_private_key = &setup_private,
        .policy = .{ .alpn_protocols = &.{"h2"} },
        .server_verifier = .{ .verify_trust = acceptCertificate },
    }, &setup_hello_record);
    defer setup_client.deinit();
    const client_hello_bytes = setup_hello_record.items[5..];
    const parsed_client = try vail.tls.client_hello.parse(client_hello_bytes);
    const server_private = p256Private(5);
    const server_public = try vail.tls.key_exchange.p256.publicKey(
        server_private,
    );
    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(allocator);
    _ = try vail.tls.tls12_handshake.writeServerFlight(
        &server_flight,
        allocator,
        client_hello_bytes,
        parsed_client,
        .{ .alpn_protocols = &.{"h2"} },
        [_]u8{0xa2} ** 32,
        &server_public,
        &.{&certificate},
        signer,
    );
    var server_record: std.ArrayList(u8) = .empty;
    defer server_record.deinit(allocator);
    try appendRecord(&server_record, allocator, server_flight.items);

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var checksum: u64 = 0;
    const start = nowNs(init.io);
    for (0..iterations) |iteration| {
        output.clearRetainingCapacity();
        var client_private = p256Private(3);
        var client = try Client.init(.{
            .allocator = allocator,
            .random = [_]u8{0xa1} ** 32,
            .server_name = "localhost",
            .client_private_key = &client_private,
            .policy = .{ .alpn_protocols = &.{"h2"} },
            .server_verifier = .{ .verify_trust = acceptCertificate },
        }, &output);
        defer client.deinit();
        output.clearRetainingCapacity();
        const result = try client.receive(server_record.items, &output);
        if (result.event == null or
            std.meta.activeTag(result.event.?) != .client_flight)
        {
            return error.HandshakeDidNotAdvance;
        }
        checksum +%= output.items[iteration % output.items.len];
    }
    const elapsed = nowNs(init.io) -| start;
    std.debug.print(
        "p256-rsa2048-verify-aes128={d} ns/client-flight checksum={d}\n",
        .{ elapsed / iterations, checksum },
    );
}

fn acceptCertificate(
    context: ?*anyopaque,
    trust: vail.tls.auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0) return error.EmptyCertificateChain;
}

fn p256Private(last: u8) [vail.tls.key_exchange.p256.secret_len]u8 {
    return [_]u8{0} ** (vail.tls.key_exchange.p256.secret_len - 1) ++ .{last};
}

fn appendRecord(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    payload: []const u8,
) !void {
    try output.appendSlice(allocator, &.{
        22,
        3,
        3,
        @truncate(payload.len >> 8),
        @truncate(payload.len),
    });
    try output.appendSlice(allocator, payload);
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
