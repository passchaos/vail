const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Server = vail.tls.tls12_server_connection.ServerConnection(
    64 * 1024,
    64 * 1024,
);
const vectors = vail.crypto.testing.rsa_signing;
const certificate = decodeHex(vectors.certificate_hex);
const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
const session_id = [_]u8{0xf1} ** 32;

pub fn main(init: std.process.Init) !void {
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    var keyring = try vail.tls.ticket_keyring.Keyring.init(.{
        .id = 17,
        .secret = [_]u8{0xf2} ** vail.tls.ticket_keyring.key_len,
    });
    defer keyring.deinit();

    const listener = try sysSocket();
    defer _ = linux.close(listener);
    try sysReuseAddr(listener);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, 24454);
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysBind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    try sysListen(listener, 2);

    try runConnection(init, listener, &prepared_key, &keyring, false, 0xf3);
    try runConnection(init, listener, &prepared_key, &keyring, true, 0xf4);
    std.debug.print("Vail TLS 1.2 stateless ticket resumption verified\n", .{});
}

fn runConnection(
    init: std.process.Init,
    listener: i32,
    prepared_key: *const vail.crypto.rsa.PreparedPrivateKey,
    keyring: *const vail.tls.ticket_keyring.Keyring,
    expect_resumed: bool,
    random_byte: u8,
) !void {
    const client_fd = try sysAccept(listener);
    defer _ = linux.close(client_fd);
    var ecdh_private = [_]u8{0} ** vail.tls.key_exchange.p256.secret_len;
    ecdh_private[ecdh_private.len - 1] = random_byte;
    var server = Server.init(.{
        .allocator = std.heap.smp_allocator,
        .policy = .{
            .cipher_suites = &.{.ecdhe_rsa_aes_128_gcm_sha256},
            .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
            .alpn_protocols = &.{"http/1.1"},
            .new_session_id = &session_id,
        },
        .server_random = [_]u8{random_byte} ** 32,
        .server_private_key = &ecdh_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = prepared_key,
            .io = init.io,
        } },
        .session_tickets = .{
            .keyring = keyring,
            .server_id = "vail-ticket-server",
            .now_seconds = if (expect_resumed) 101 else 100,
            .lifetime_seconds = 3600,
            .sealing_nonce = [_]u8{random_byte} **
                vail.tls.ticket_keyring.nonce_len,
        },
    });
    defer server.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var input: [64 * 1024]u8 = undefined;
    var established: vail.tls.tls12_server_connection.Established =
        handshake_loop: while (true) {
            const received_len = try readSocket(client_fd, &input);
            var offset: usize = 0;
            while (offset < received_len) {
                const result = try server.receive(
                    input[offset..received_len],
                    &output,
                );
                offset += result.consumed;
                if (output.items.len != 0) {
                    try writeAll(client_fd, output.items);
                    output.clearRetainingCapacity();
                }
                if (result.event) |event| switch (event) {
                    .server_flight,
                    .client_key_exchange,
                    .change_cipher_spec,
                    => {},
                    .peer_alert => return error.PeerAbortedHandshake,
                    .established => |value| break :handshake_loop value,
                };
                if (result.consumed == 0 and result.event == null) {
                    return error.HandshakeStalled;
                }
            }
        };
    defer established.deinit();
    if (established.resumed != expect_resumed) {
        return error.UnexpectedResumptionState;
    }

    while (true) {
        const received_len = try readSocket(client_fd, &input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try established.receive(input[offset..received_len]);
            offset += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |data| if (data.len != 0) {
                    var response: [256]u8 = undefined;
                    const response_len = try established.sealApplicationData(
                        "vail ticket tls12 ok\n",
                        &response,
                    );
                    try writeAll(client_fd, response[0..response_len]);
                    return;
                },
                .alert => |received| if (!received.isCloseNotify()) {
                    return error.PeerAbortedHandshake;
                },
            };
        }
    }
}

fn readSocket(fd: i32, buffer: []u8) !usize {
    const result = linux.read(fd, buffer.ptr, buffer.len);
    if (linux.errno(result) != .SUCCESS) return error.ReadFailed;
    if (result == 0) return error.EndOfStream;
    return result;
}

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(result) != .SUCCESS) return error.WriteFailed;
        offset += result;
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

fn sysReuseAddr(fd: i32) !void {
    var yes: i32 = 1;
    const result = linux.setsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.REUSEADDR,
        @ptrCast(&yes),
        @sizeOf(i32),
    );
    if (linux.errno(result) != .SUCCESS) return error.SetSockOptFailed;
}

fn sysBind(fd: i32, address: *const linux.sockaddr, len: u32) !void {
    const result = linux.bind(fd, address, len);
    if (linux.errno(result) != .SUCCESS) return error.BindFailed;
}

fn sysListen(fd: i32, backlog: u32) !void {
    const result = linux.listen(fd, backlog);
    if (linux.errno(result) != .SUCCESS) return error.ListenFailed;
}

fn sysAccept(fd: i32) !i32 {
    const result = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(result) != .SUCCESS) return error.AcceptFailed;
    return @intCast(result);
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
