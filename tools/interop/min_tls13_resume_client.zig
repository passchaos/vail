const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Client = vail.tls.client_connection.ClientConnection(64 * 1024, 2048);
const certificate_der = decodeHex(
    vail.crypto.testing.rsa_signing.certificate_hex,
);
const response = "rustls resumed tls13 ok\n";

pub fn main(init: std.process.Init) !void {
    var cached = (try runConnection(init, null, false, 0xb1)) orelse
        return error.MissingNewSessionTicket;
    defer cached.deinit();
    var resumption = try vail.tls.client_connection.ClientPsk.fromCached(
        &cached,
        11_000,
    );
    if (try runConnection(init, &resumption, true, 0xb2) != null) {
        return error.UnexpectedNewSessionTicket;
    }
    std.debug.print("Vail TLS 1.3 client ticket resumption verified\n", .{});
}

fn runConnection(
    _: std.process.Init,
    resumption: ?*vail.tls.client_connection.ClientPsk,
    expect_resumed: bool,
    random_byte: u8,
) !?vail.tls.ticket.Cached {
    defer if (resumption) |value| value.secret.deinit();
    const socket = try sysSocket();
    defer _ = linux.close(socket);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, 24459);
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(socket, @ptrCast(&address), @sizeOf(linux.sockaddr.in));

    var key_material = vail.tls.key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{random_byte} ** vail.tls.key_exchange.secret_len,
    };
    var client_hello_record: std.ArrayList(u8) = .empty;
    defer client_hello_record.deinit(std.heap.smp_allocator);
    var client = try Client.init(.{
        .allocator = std.heap.smp_allocator,
        .random = [_]u8{random_byte +% 1} ** 32,
        .server_name = "localhost",
        .key_material = &key_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .server_verifier = .{ .verify_trust = verifyServerCertificate },
        .request_resumption = true,
        .resumption = if (resumption) |value| value.* else null,
    }, &client_hello_record);
    defer client.deinit();
    try writeAll(socket, client_hello_record.items);

    var client_flight: std.ArrayList(u8) = .empty;
    defer client_flight.deinit(std.heap.smp_allocator);
    var driver = SocketClientDriver{ .fd = socket };
    var established: Client.Established = handshake: while (true) {
        const event = try driver.next(&client, &client_flight);
        switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => {},
            .established => |value| break :handshake value,
            .peer_alert => return error.PeerAbortedHandshake,
            .hello_retry_request => return error.UnexpectedHelloRetryRequest,
            .ech_rejected => |value| {
                var rejection = value;
                rejection.deinit();
                return error.EchRejected;
            },
        }
    };
    defer established.deinit();
    if (established.resumed != expect_resumed) {
        return error.UnexpectedHandshakeKind;
    }
    if (!std.mem.eql(u8, established.selected_alpn orelse "", "h2")) {
        return error.UnexpectedAlpn;
    }
    try writeAll(socket, client_flight.items);

    var request_record: [64]u8 = undefined;
    const request_len = try established.application.sealApplicationData(
        "ping",
        &request_record,
    );
    try writeAll(socket, request_record[0..request_len]);

    var cached: ?vail.tls.ticket.Cached = null;
    errdefer if (cached) |*value| value.deinit();
    var received_application = false;
    while (!received_application or (!expect_resumed and cached == null)) {
        const event = try driver.nextApplication(&established.application);
        switch (event) {
            .application_data => |bytes| {
                if (!std.mem.eql(u8, bytes, response)) {
                    return error.UnexpectedApplicationData;
                }
                received_application = true;
            },
            .post_handshake => |message| {
                if (!expect_resumed and cached == null) {
                    cached = try established.cacheNewSessionTicket(
                        message,
                        "localhost",
                        10_000,
                    );
                }
            },
            .key_update => return error.UnexpectedKeyUpdate,
            .alert => |received| {
                if (received.isCloseNotify() and received_application and
                    (expect_resumed or cached != null))
                {
                    break;
                }
                return error.PeerAlert;
            },
        }
    }
    return cached;
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

const SocketClientDriver = struct {
    fd: i32,
    buffer: [64 * 1024]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn next(
        self: *SocketClientDriver,
        client: *Client,
        output: *std.ArrayList(u8),
    ) !Client.Event {
        while (true) {
            const drained = try client.receive("", output);
            if (drained.event) |event| return event;
            if (self.start < self.end) {
                const result = try client.receive(
                    self.buffer[self.start..self.end],
                    output,
                );
                self.start += result.consumed;
                if (result.event) |event| return event;
            }
            if (self.start != self.end) return error.ClientDriverStalled;
            self.start = 0;
            self.end = try readSocket(self.fd, &self.buffer);
        }
    }

    fn nextApplication(
        self: *SocketClientDriver,
        application: anytype,
    ) !vail.tls.connection.Event {
        while (true) {
            const drained = try application.receive("");
            if (drained.event) |event| return event;
            if (self.start < self.end) {
                const result = try application.receive(
                    self.buffer[self.start..self.end],
                );
                self.start += result.consumed;
                if (result.event) |event| return event;
            }
            if (self.start != self.end) return error.ClientDriverStalled;
            self.start = 0;
            self.end = try readSocket(self.fd, &self.buffer);
        }
    }
};

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
