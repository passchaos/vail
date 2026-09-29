const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const max_crypto_flight = 64 * 1024;
const client_transport_parameters = [_]u8{ 0x01, 0x02, 0x03 };
const server_transport_parameters = [_]u8{ 0x04, 0x05, 0x06 };
const certificate_der = decodeHex(vail.crypto.testing.rsa_signing.certificate_hex);
const GroupMode = enum { x25519, hybrid, mlkem768, mlkem1024 };

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode: GroupMode = if (args.next()) |value|
        if (std.mem.eql(u8, value, "hybrid"))
            .hybrid
        else if (std.mem.eql(u8, value, "mlkem"))
            .mlkem768
        else if (std.mem.eql(u8, value, "mlkem1024"))
            .mlkem1024
        else
            return error.InvalidArguments
    else
        .x25519;
    if (args.next() != null) return error.InvalidArguments;
    const allocator = std.heap.smp_allocator;
    const socket = try sysSocket();
    defer _ = linux.close(socket);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, switch (mode) {
        .x25519 => 24457,
        .hybrid => 24461,
        .mlkem768 => 24463,
        .mlkem1024 => 24465,
    });
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(socket, @ptrCast(&address), @sizeOf(linux.sockaddr.in));

    var key_material: vail.tls.key_exchange.ClientKeyMaterial = switch (mode) {
        .x25519 => .{
            .x25519 = [_]u8{0xd1} ** vail.tls.key_exchange.secret_len,
        },
        .hybrid => .{ .x25519_mlkem768 = .{
            .x25519_secret = [_]u8{0xd1} **
                vail.tls.key_exchange.x25519_mlkem768.x25519_secret_len,
            .mlkem_seed = [_]u8{0xd3} **
                vail.tls.key_exchange.x25519_mlkem768.mlkem_seed_len,
        } },
        .mlkem768 => .{
            .mlkem768 = [_]u8{0xd4} **
                vail.tls.key_exchange.mlkem768.seed_len,
        },
        .mlkem1024 => .{
            .mlkem1024 = [_]u8{0xd5} **
                vail.tls.key_exchange.mlkem1024.seed_len,
        },
    };
    var exchange = try key_material.start();
    var exchange_live = true;
    defer if (exchange_live) exchange.deinit();

    var client_initial: std.ArrayList(u8) = .empty;
    defer client_initial.deinit(allocator);
    try vail.tls.client_hello.writeWithKeyShare(
        &client_initial,
        allocator,
        .{
            .random = [_]u8{0xd2} ** 32,
            .session_id = "vail-quic",
            .server_name = "localhost",
            .key_share = .{
                .group = exchange.namedGroup(),
                .key_exchange = exchange.clientShare(),
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .alpn_protocols = &.{"h3"},
            .quic_transport_parameters = &client_transport_parameters,
        },
    );
    try writeFrame(socket, client_initial.items);

    const server_initial = try readFrame(socket, allocator);
    defer allocator.free(server_initial);
    const parsed_server = try vail.tls.server_hello.parseServerHello(
        server_initial,
    );
    if (parsed_server.key_share_group != exchange.namedGroup()) {
        return error.UnexpectedServerGroup;
    }
    var shared_secret = try exchange.complete(parsed_server.key_share);
    exchange_live = false;
    defer shared_secret.deinit();

    const server_handshake = try readFrame(socket, allocator);
    defer allocator.free(server_handshake);
    var client_handshake: std.ArrayList(u8) = .empty;
    defer client_handshake.deinit(allocator);
    var result = try vail.quic.tls_handshake.writeClientCryptoFlight(
        &client_handshake,
        allocator,
        .{
            .client_hello_bytes = client_initial.items,
            .server_hello_bytes = server_initial,
            .server_handshake_crypto = server_handshake,
            .shared_secret = shared_secret.bytes(),
            .server_verifier = .{
                .verify_trust = verifyServerCertificate,
            },
            .server_name = "localhost",
        },
    );
    defer result.deinit();
    if (!std.mem.eql(u8, result.selected_alpn, "h3") or
        !std.mem.eql(
            u8,
            result.peer_transport_parameters,
            &server_transport_parameters,
        ))
    {
        return error.UnexpectedNegotiation;
    }
    try writeFrame(socket, client_handshake.items);
    std.debug.print(
        "Vail QUIC client verified rustls/AWS-LC server group={s}\n",
        .{switch (mode) {
            .x25519 => "X25519",
            .hybrid => "X25519MLKEM768",
            .mlkem768 => "MLKEM768",
            .mlkem1024 => "MLKEM1024",
        }},
    );
}

fn verifyServerCertificate(
    _: ?*anyopaque,
    trust: vail.tls.auth.TrustContext,
) anyerror!void {
    if (trust.server_name == null or
        !std.mem.eql(u8, trust.server_name.?, "localhost") or
        trust.chain.len != 1 or
        !std.mem.eql(u8, trust.chain[0], &certificate_der))
    {
        return error.CertificateUntrusted;
    }
}

fn readFrame(fd: i32, allocator: std.mem.Allocator) ![]u8 {
    var length_bytes: [4]u8 = undefined;
    try readExact(fd, &length_bytes);
    const length: usize = @intCast(std.mem.readInt(u32, &length_bytes, .big));
    if (length == 0 or length > max_crypto_flight) {
        return error.InvalidFrameLength;
    }
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    try readExact(fd, bytes);
    return bytes;
}

fn writeFrame(fd: i32, bytes: []const u8) !void {
    if (bytes.len == 0 or bytes.len > max_crypto_flight) {
        return error.InvalidFrameLength;
    }
    var length_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &length_bytes, @intCast(bytes.len), .big);
    try writeAll(fd, &length_bytes);
    try writeAll(fd, bytes);
}

fn readExact(fd: i32, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = linux.read(fd, output[offset..].ptr, output.len - offset);
        if (linux.errno(count) != .SUCCESS) return error.ReadFailed;
        if (count == 0) return error.EndOfStream;
        offset += count;
    }
}

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(count) != .SUCCESS) return error.WriteFailed;
        offset += count;
    }
}

fn sysSocket() !i32 {
    const result = linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
    );
    if (linux.errno(result) != .SUCCESS) return error.SocketFailed;
    return @intCast(result);
}

fn sysConnect(fd: i32, address: *const linux.sockaddr, length: u32) !void {
    const result = linux.connect(fd, address, length);
    if (linux.errno(result) != .SUCCESS) return error.ConnectFailed;
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
