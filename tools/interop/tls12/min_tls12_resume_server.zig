const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Server = vail.tls.tls12_server_connection.ServerConnection(
    64 * 1024,
    64 * 1024,
);
const vectors = vail.testdata.crypto.rsa_signing;
const certificate = decodeHex(vectors.certificate_hex);
const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
const session_id = [_]u8{0xe1} ** 32;

pub fn main(init: std.process.Init) !void {
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();

    const listener = try sysSocket();
    defer _ = linux.close(listener);
    try sysReuseAddr(listener);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24449);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysBind(listener, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    try sysListen(listener, 2);

    var session = (try runConnection(
        init,
        listener,
        &prepared_key,
        null,
        0xe2,
    )) orelse return error.SessionNotCreated;
    defer session.deinit();
    _ = try runConnection(
        init,
        listener,
        &prepared_key,
        &session,
        0xe3,
    );
    std.debug.print("TLS 1.2 server session resumption verified\n", .{});
}

fn runConnection(
    init: std.process.Init,
    listener: i32,
    prepared_key: *const vail.crypto.rsa.PreparedPrivateKey,
    resumption: ?*const vail.tls.tls12.Session,
    random_byte: u8,
) !?vail.tls.tls12.Session {
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
        .resumption = if (resumption) |session| .{
            .session = session,
            .identity = "vail-server",
            .now_seconds = 101,
        } else null,
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
    try std.testing.expectEqual(resumption != null, established.resumed);
    const cached = if (resumption == null)
        try established.createSession("vail-server", 100, 3600)
    else
        null;

    while (true) {
        const received_len = try readSocket(client_fd, &input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try established.receive(input[offset..received_len]);
            offset += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |data| {
                    if (data.len == 0) continue;
                    var response: [256]u8 = undefined;
                    const response_len = try established.sealApplicationData(
                        "vail resumed tls12 ok\n",
                        &response,
                    );
                    try writeAll(client_fd, response[0..response_len]);
                    var close: [64]u8 = undefined;
                    const close_len = try established.sealCloseNotify(&close);
                    try writeAll(client_fd, close[0..close_len]);
                    return cached;
                },
                .alert => |received| if (!received.isCloseNotify()) {
                    return error.PeerAbortedHandshake;
                },
            };
        }
    }
}

fn readSocket(fd: i32, buffer: []u8) !usize {
    const rc = linux.read(fd, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadFailed;
    if (rc == 0) return error.EndOfStream;
    return rc;
}

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(rc) != .SUCCESS) return error.WriteFailed;
        offset += rc;
    }
}

fn sysSocket() !i32 {
    const rc = linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return @intCast(rc);
}

fn sysReuseAddr(fd: i32) !void {
    var yes: i32 = 1;
    const rc = linux.setsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.REUSEADDR,
        @ptrCast(&yes),
        @sizeOf(i32),
    );
    if (linux.errno(rc) != .SUCCESS) return error.SetSockOptFailed;
}

fn sysBind(fd: i32, addr: *const linux.sockaddr, len: u32) !void {
    const rc = linux.bind(fd, addr, len);
    if (linux.errno(rc) != .SUCCESS) return error.BindFailed;
}

fn sysListen(fd: i32, backlog: u32) !void {
    const rc = linux.listen(fd, backlog);
    if (linux.errno(rc) != .SUCCESS) return error.ListenFailed;
}

fn sysAccept(fd: i32) !i32 {
    const rc = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.AcceptFailed;
    return @intCast(rc);
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
