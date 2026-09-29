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

pub fn main(init: std.process.Init) !void {
    const profile = try selectedProfile(init);
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    try sysReuseAddr(fd);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24446);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysBind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    try sysListen(fd, 1);
    const client_fd = try sysAccept(fd);
    defer _ = linux.close(client_fd);

    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    var ecdh_private = [_]u8{0} **
        vail.tls.key_exchange.p256.secret_len;
    ecdh_private[ecdh_private.len - 1] = 2;
    var server = Server.init(.{
        .allocator = std.heap.smp_allocator,
        .policy = .{
            .cipher_suites = &.{
                profile.suite,
            },
            .groups = &.{vail.tls.key_exchange.named_group_secp256r1},
            .alpn_protocols = &.{ "h2", "http/1.1" },
            .client_certificate_authorities = if (profile.client_auth)
                &.{}
            else
                null,
        },
        .server_random = [_]u8{0x86} ** 32,
        .server_private_key = &ecdh_private,
        .certificate_chain = &.{&certificate},
        .signer = .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = init.io,
        } },
        .client_auth_policy = if (profile.client_auth) .{
            .verifier = .{ .verify_trust = acceptTestCertificate },
            .requirement = .required,
        } else null,
    });
    defer server.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var input: [64 * 1024]u8 = undefined;
    var established: vail.tls.tls12_server_connection.Established =
        handshake: while (true) {
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
                    .server_flight,
                    .client_key_exchange,
                    .change_cipher_spec,
                    => {},
                    .peer_alert => return error.PeerAbortedHandshake,
                    .established => |value| break :handshake value,
                };
                if (result.consumed == 0 and result.event == null) {
                    return error.HandshakeStalled;
                }
            }
        };
    defer established.deinit();
    std.debug.print("TLS 1.2 client Finished verified\n", .{});
    if (established.peer_certificate_chain != null) {
        std.debug.print("TLS 1.2 client certificate verified\n", .{});
    }

    while (true) {
        const received_len = try readSocket(client_fd, &input);
        var offset: usize = 0;
        while (offset < received_len) {
            const result = try established.receive(input[offset..received_len]);
            offset += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |data| {
                    if (data.len == 0) continue;
                    var record: [256]u8 = undefined;
                    const len = try established.sealApplicationData(
                        "vail tls12 ok\n",
                        &record,
                    );
                    try writeAll(client_fd, record[0..len]);
                    var close_record: [64]u8 = undefined;
                    const close_len = try established.sealCloseNotify(
                        &close_record,
                    );
                    try writeAll(client_fd, close_record[0..close_len]);
                    std.debug.print("TLS 1.2 application data verified\n", .{});
                    return;
                },
                .alert => |received| if (!received.isCloseNotify()) {
                    return error.PeerAbortedHandshake;
                },
            };
            if (result.consumed == 0 and result.event == null) {
                return error.ApplicationStalled;
            }
        }
    }
}

const Profile = struct {
    suite: vail.tls.tls12.Suite,
    client_auth: bool = false,
};

fn selectedProfile(init: std.process.Init) !Profile {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const name = args.next() orelse return .{
        .suite = .ecdhe_rsa_aes_128_gcm_sha256,
    };
    if (args.next() != null) return error.InvalidArguments;
    if (std.mem.eql(u8, name, "aes128")) {
        return .{ .suite = .ecdhe_rsa_aes_128_gcm_sha256 };
    }
    if (std.mem.eql(u8, name, "aes256")) {
        return .{ .suite = .ecdhe_rsa_aes_256_gcm_sha384 };
    }
    if (std.mem.eql(u8, name, "chacha")) {
        return .{ .suite = .ecdhe_rsa_chacha20_poly1305_sha256 };
    }
    if (std.mem.eql(u8, name, "mtls")) {
        return .{
            .suite = .ecdhe_rsa_aes_128_gcm_sha256,
            .client_auth = true,
        };
    }
    return error.InvalidArguments;
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
