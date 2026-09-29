const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const AutoServer = vail.tls.versioned_server_connection.ServerConnection(
    64 * 1024,
    64 * 1024,
);
const vectors = vail.crypto.testing.rsa_signing;
const certificate = decodeHex(vectors.certificate_hex);
const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);

pub fn main(init: std.process.Init) !void {
    const listener = try sysSocket();
    defer _ = linux.close(listener);
    try sysReuseAddr(listener);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24450);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysBind(listener, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    try sysListen(listener, 1);
    const client_fd = try sysAccept(listener);
    defer _ = linux.close(client_fd);

    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const signer = vail.tls.auth.Signer{ .rsa_pss = .{
        .prepared_key = &prepared_key,
        .io = init.io,
    } };
    var tls13_key = vail.tls.key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{0x41} ** vail.tls.key_exchange.secret_len,
    };
    var tls12_key = [_]u8{0} ** vail.tls.key_exchange.p256.secret_len;
    tls12_key[tls12_key.len - 1] = 2;
    var server = AutoServer.init(.{
        .tls13 = .{
            .allocator = std.heap.smp_allocator,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &.{vail.tls.key_exchange.named_group_x25519},
                .alpn_protocols = &.{ "h2", "http/1.1" },
            },
            .server_random = [_]u8{0x42} ** 32,
            .key_material = &tls13_key,
            .certificate_chain = &.{&certificate},
            .signer = signer,
        },
        .tls12 = .{
            .allocator = std.heap.smp_allocator,
            .policy = .{
                .cipher_suites = &.{.ecdhe_rsa_aes_128_gcm_sha256},
                .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
                .alpn_protocols = &.{ "h2", "http/1.1" },
            },
            .server_random = [_]u8{0x43} ** 32,
            .server_private_key = &tls12_key,
            .certificate_chain = &.{&certificate},
            .signer = signer,
        },
    });
    defer server.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var input: [64 * 1024]u8 = undefined;
    while (true) {
        const received_len = try readSocket(client_fd, &input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try server.receive(input[offset..received_len], &output);
            offset += result.consumed;
            if (output.items.len != 0) {
                try writeAll(client_fd, output.items);
                output.clearRetainingCapacity();
            }
            if (result.event) |event| switch (event) {
                .tls13 => |tls13_event| switch (tls13_event) {
                    .established => |established| {
                        var value = established;
                        defer value.deinit();
                        std.debug.print("versioned server selected TLS 1.3\n", .{});
                        return serveTls13(client_fd, &value, &input);
                    },
                    .peer_alert => return error.PeerAbortedHandshake,
                    else => {},
                },
                .tls12 => |tls12_event| switch (tls12_event) {
                    .established => |established| {
                        var value = established;
                        defer value.deinit();
                        std.debug.print("versioned server selected TLS 1.2\n", .{});
                        return serveTls12(client_fd, &value, &input);
                    },
                    .peer_alert => return error.PeerAbortedHandshake,
                    else => {},
                },
            };
        }
    }
}

fn serveTls13(
    fd: i32,
    established: anytype,
    input: []u8,
) !void {
    while (true) {
        const received_len = try readSocket(fd, input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try established.application.receive(
                input[offset..received_len],
            );
            offset += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |data| if (data.len != 0) {
                    var response: [256]u8 = undefined;
                    const len = try established.application.sealApplicationData(
                        "vail auto tls13 ok\n",
                        &response,
                    );
                    try writeAll(fd, response[0..len]);
                    return;
                },
                .alert => |received| if (received.isCloseNotify()) return,
                else => {},
            };
        }
    }
}

fn serveTls12(
    fd: i32,
    established: anytype,
    input: []u8,
) !void {
    while (true) {
        const received_len = try readSocket(fd, input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try established.receive(input[offset..received_len]);
            offset += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |data| if (data.len != 0) {
                    var response: [256]u8 = undefined;
                    const len = try established.sealApplicationData(
                        "vail auto tls12 ok\n",
                        &response,
                    );
                    try writeAll(fd, response[0..len]);
                    return;
                },
                .alert => |received| if (received.isCloseNotify()) return,
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
