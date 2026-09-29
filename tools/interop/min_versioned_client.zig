const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const AutoClient = vail.tls.versioned_client_connection.ClientConnection(
    64 * 1024,
    64 * 1024,
);

pub fn main(init: std.process.Init) !void {
    _ = init;
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24451);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));

    var tls13_key = vail.tls.key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0x71} ** vail.tls.key_exchange.secret_len,
    };
    var tls13_retry_key = vail.tls.key_exchange.ClientKeyMaterial{
        .secp256r1 = [_]u8{0} **
            (vail.tls.key_exchange.p256.secret_len - 1) ++ .{1},
    };
    var tls12_key = [_]u8{0} ** vail.tls.key_exchange.p256.secret_len;
    tls12_key[tls12_key.len - 1] = 2;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var client = try AutoClient.init(.{
        .tls13 = .{
            .allocator = std.heap.smp_allocator,
            .random = [_]u8{0x72} ** 32,
            .server_name = "localhost",
            .key_material = &tls13_key,
            .retry_key_material = &tls13_retry_key,
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .additional_cipher_suites = &.{ 0xc02f, 0x00ff },
            .supported_versions = &.{ 0x0304, 0x0303 },
            .offer_extended_master_secret = true,
            .alpn_protocols = &.{"h2"},
            .server_verifier = .{ .verify_trust = acceptTestCertificate },
        },
        .tls12 = .{
            .allocator = std.heap.smp_allocator,
            .random = [_]u8{0x72} ** 32,
            .server_name = "localhost",
            .client_private_key = &tls12_key,
            .policy = .{
                .cipher_suites = &.{.ecdhe_rsa_aes_128_gcm_sha256},
                .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
                .alpn_protocols = &.{"h2"},
            },
            .server_verifier = .{ .verify_trust = acceptTestCertificate },
        },
    }, &output);
    defer client.deinit();
    try writeAll(fd, output.items);
    output.clearRetainingCapacity();

    var input: [64 * 1024]u8 = undefined;
    while (true) {
        const received_len = try readSocket(fd, &input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try client.receive(input[offset..received_len], &output);
            offset += result.consumed;
            if (output.items.len != 0) {
                try writeAll(fd, output.items);
                output.clearRetainingCapacity();
            }
            if (result.event) |event| switch (event) {
                .tls13 => |tls13_event| switch (tls13_event) {
                    .established => |established| {
                        var value = established;
                        defer value.deinit();
                        std.debug.print("versioned client selected TLS 1.3\n", .{});
                        return exerciseTls13(fd, &value, &input);
                    },
                    .peer_alert => return error.PeerAbortedHandshake,
                    else => {},
                },
                .tls12 => |tls12_event| switch (tls12_event) {
                    .established => |established| {
                        var value = established;
                        defer value.deinit();
                        std.debug.print("versioned client selected TLS 1.2\n", .{});
                        return exerciseTls12(fd, &value, &input);
                    },
                    .peer_alert => return error.PeerAbortedHandshake,
                    else => {},
                },
            };
        }
    }
}

fn exerciseTls13(fd: i32, established: anytype, input: []u8) !void {
    var request: [256]u8 = undefined;
    const len = try established.application.sealApplicationData(
        "GET / HTTP/1.0\r\n\r\n",
        &request,
    );
    try writeAll(fd, request[0..len]);
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
                    std.debug.print("versioned client application data verified\n", .{});
                    return;
                },
                .alert => |received| if (received.isCloseNotify()) return,
                else => {},
            };
        }
    }
}

fn exerciseTls12(fd: i32, established: anytype, input: []u8) !void {
    var request: [256]u8 = undefined;
    const len = try established.sealApplicationData(
        "GET / HTTP/1.0\r\n\r\n",
        &request,
    );
    try writeAll(fd, request[0..len]);
    while (true) {
        const received_len = try readSocket(fd, input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try established.receive(input[offset..received_len]);
            offset += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |data| if (data.len != 0) {
                    std.debug.print("versioned client application data verified\n", .{});
                    return;
                },
                .alert => |received| if (received.isCloseNotify()) return,
            };
        }
    }
}

fn acceptTestCertificate(
    context: ?*anyopaque,
    trust: vail.tls.auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0) return error.EmptyCertificateChain;
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

fn sysConnect(fd: i32, addr: *const linux.sockaddr, len: u32) !void {
    const rc = linux.connect(fd, addr, len);
    if (linux.errno(rc) != .SUCCESS) return error.ConnectFailed;
}
