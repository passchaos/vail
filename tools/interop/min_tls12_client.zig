const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Client = vail.tls.tls12_client_connection.ClientConnection(
    64 * 1024,
    64 * 1024,
);
const Established = vail.tls.tls12_client_connection.Established;
const Event = vail.tls.tls12_client_connection.Event;
const vectors = vail.crypto.testing.rsa_signing;
const client_certificate = decodeHex(vectors.client_certificate_hex);
const client_private_key_der = decodeHex(vectors.private_key_pkcs8_hex);

pub fn main(init: std.process.Init) !void {
    const profile = try selectedProfile(init);
    const suites = [_]vail.tls.tls12.Suite{profile.suite};
    const groups = [_]u16{profile.group};
    const signing_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &client_private_key_der,
    );
    var prepared_signing_key = try signing_key.prepare();
    defer prepared_signing_key.deinit();
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24447);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));

    var private_key = [_]u8{0} ** vail.tls.key_exchange.p256.secret_len;
    private_key[private_key.len - 1] = 3;
    var private_key_p384 = [_]u8{0} ** vail.tls.key_exchange.p384.secret_len;
    private_key_p384[private_key_p384.len - 1] = 3;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var client = try Client.init(.{
        .allocator = std.heap.smp_allocator,
        .random = [_]u8{0x93} ** 32,
        .server_name = "localhost",
        .client_private_key = if (profile.group ==
            vail.tls.key_exchange.named_group_secp256r1)
            &private_key
        else
            null,
        .client_private_key_p384 = if (profile.group ==
            vail.tls.key_exchange.named_group_secp384r1)
            &private_key_p384
        else
            null,
        .policy = .{
            .cipher_suites = &suites,
            .groups = &groups,
            .alpn_protocols = &.{"http/1.1"},
        },
        .signature_schemes = if (profile.pkcs1)
            &.{vail.tls.auth.signature_scheme_rsa_pkcs1_sha256}
        else
            &vail.tls.client_hello.default_signature_schemes,
        .request_ocsp = profile.ocsp,
        .server_verifier = .{
            .verify_trust = if (profile.ocsp)
                expectTestOcsp
            else
                acceptTestCertificate,
        },
        .client_identity = if (profile.client_auth) .{
            .certificate_chain = &.{&client_certificate},
            .signer = if (profile.pkcs1)
                .{ .rsa_pkcs1 = .{
                    .prepared_key = &prepared_signing_key,
                } }
            else
                .{ .rsa_pss = .{
                    .prepared_key = &prepared_signing_key,
                    .io = init.io,
                } },
        } else null,
    }, &output);
    defer client.deinit();
    try writeAll(fd, output.items);
    output.clearRetainingCapacity();

    var driver = SocketClientDriver{ .fd = fd };
    var established: Established = while (true) {
        const event = try driver.next(&client, &output);
        switch (event) {
            .client_flight => {
                try writeAll(fd, output.items);
                output.clearRetainingCapacity();
            },
            .change_cipher_spec => {},
            .peer_alert => return error.PeerAbortedHandshake,
            .established => |value| break value,
        }
    };
    defer established.deinit();
    std.debug.print("TLS 1.2 server authenticated and Finished verified\n", .{});
    std.debug.print(
        "TLS 1.2 suite=0x{x:0>4} alpn={s}\n",
        .{
            @intFromEnum(established.suite),
            established.selected_alpn orelse "",
        },
    );

    var request: [512]u8 = undefined;
    const request_len = try established.sealApplicationData(
        "GET / HTTP/1.0\r\n\r\n",
        &request,
    );
    try writeAll(fd, request[0..request_len]);
    while (true) {
        const event = try driver.nextApplication(&established);
        switch (event) {
            .application_data => |bytes| if (bytes.len != 0) break,
            .alert => |received| {
                if (received.isCloseNotify()) return error.EarlyCloseNotify;
                return error.PeerAbortedHandshake;
            },
        }
    }
    std.debug.print("TLS 1.2 server application data verified\n", .{});

    var close: [64]u8 = undefined;
    const close_len = try established.sealCloseNotify(&close);
    try writeAll(fd, close[0..close_len]);
    _ = linux.shutdown(fd, linux.SHUT.WR);
}

const Profile = struct {
    suite: vail.tls.tls12.Suite,
    group: u16 = vail.tls.key_exchange.named_group_secp256r1,
    client_auth: bool = false,
    pkcs1: bool = false,
    ocsp: bool = false,
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
    if (std.mem.eql(u8, name, "ecdsa-aes128")) {
        return .{ .suite = .ecdhe_ecdsa_aes_128_gcm_sha256 };
    }
    if (std.mem.eql(u8, name, "ecdsa-aes256")) {
        return .{
            .suite = .ecdhe_ecdsa_aes_256_gcm_sha384,
            .group = vail.tls.key_exchange.named_group_secp384r1,
        };
    }
    if (std.mem.eql(u8, name, "ecdsa-chacha")) {
        return .{ .suite = .ecdhe_ecdsa_chacha20_poly1305_sha256 };
    }
    if (std.mem.eql(u8, name, "mtls")) {
        return .{
            .suite = .ecdhe_rsa_aes_128_gcm_sha256,
            .client_auth = true,
        };
    }
    if (std.mem.eql(u8, name, "pkcs1")) {
        return .{
            .suite = .ecdhe_rsa_aes_128_gcm_sha256,
            .pkcs1 = true,
        };
    }
    if (std.mem.eql(u8, name, "mtls-pkcs1")) {
        return .{
            .suite = .ecdhe_rsa_aes_128_gcm_sha256,
            .client_auth = true,
            .pkcs1 = true,
        };
    }
    if (std.mem.eql(u8, name, "ocsp")) {
        return .{
            .suite = .ecdhe_rsa_aes_128_gcm_sha256,
            .ocsp = true,
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

fn expectTestOcsp(
    context: ?*anyopaque,
    trust: vail.tls.auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0 or trust.ocsp_response == null or
        !std.mem.eql(u8, trust.ocsp_response.?, "rustls-tls12-ocsp"))
    {
        return error.UnexpectedOcspResponse;
    }
}

const SocketClientDriver = struct {
    fd: i32,
    buffer: [64 * 1024]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn next(
        self: *SocketClientDriver,
        client: *Client,
        output: *std.ArrayList(u8),
    ) !Event {
        while (true) {
            if (self.start < self.end) {
                const result = try client.receive(
                    self.buffer[self.start..self.end],
                    output,
                );
                self.start += result.consumed;
                if (result.event) |event| return event;
                if (result.consumed != 0) continue;
                return error.ClientDriverStalled;
            }
            const rc = linux.read(self.fd, &self.buffer, self.buffer.len);
            if (linux.errno(rc) != .SUCCESS) return error.ReadFailed;
            if (rc == 0) return error.EndOfStream;
            self.start = 0;
            self.end = rc;
        }
    }

    fn nextApplication(
        self: *SocketClientDriver,
        established: *Established,
    ) !Established.ApplicationEvent {
        while (true) {
            if (self.start < self.end) {
                const result = try established.receive(
                    self.buffer[self.start..self.end],
                );
                self.start += result.consumed;
                if (result.event) |event| return event;
                if (result.consumed != 0) continue;
                return error.ClientDriverStalled;
            }
            const rc = linux.read(self.fd, &self.buffer, self.buffer.len);
            if (linux.errno(rc) != .SUCCESS) return error.ReadFailed;
            if (rc == 0) return error.EndOfStream;
            self.start = 0;
            self.end = rc;
        }
    }
};

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

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(rc) != .SUCCESS) return error.WriteFailed;
        offset += rc;
    }
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
