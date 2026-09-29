const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Client = vail.tls.client_connection.ClientConnection(64 * 1024, 256);

pub fn main(init: std.process.Init) !void {
    _ = init;
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24445);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));

    var material = vail.tls.key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0x61} ** vail.tls.key_exchange.secret_len,
    };
    var retry_material = vail.tls.key_exchange.ClientKeyMaterial{
        .secp256r1 = [_]u8{0} **
            (vail.tls.key_exchange.p256.secret_len - 1) ++ .{1},
    };
    var client_hello_record: std.ArrayList(u8) = .empty;
    defer client_hello_record.deinit(std.heap.smp_allocator);
    var client = try Client.init(.{
        .allocator = std.heap.smp_allocator,
        .random = [_]u8{0x62} ** 32,
        .server_name = "localhost",
        .key_material = &material,
        .retry_key_material = &retry_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .certificate_compression_algorithms = &.{.brotli},
        .server_verifier = .{ .verify_trust = acceptTestCertificate },
    }, &client_hello_record);
    defer client.deinit();
    try writeAll(fd, client_hello_record.items);

    var client_flight: std.ArrayList(u8) = .empty;
    defer client_flight.deinit(std.heap.smp_allocator);
    var driver = SocketClientDriver{ .fd = fd };
    var established: Client.Established = while (true) {
        const event = try driver.next(&client, &client_flight);
        switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => continue,
            .hello_retry_request => {
                try writeAll(fd, client_flight.items);
                client_flight.clearRetainingCapacity();
            },
            .peer_alert => return error.PeerAbortedHandshake,
            .ech_rejected => |value| {
                var rejection = value;
                rejection.deinit();
                return error.EchRejected;
            },
            .established => |value| break value,
        }
    };
    defer established.deinit();
    try writeAll(fd, client_flight.items);
    std.debug.print("server authenticated and finished verified\n", .{});
    if (established.certificate_compression) |algorithm| {
        std.debug.print(
            "certificate compression={s}\n",
            .{@tagName(algorithm)},
        );
    }

    var request_record: [256]u8 = undefined;
    const request_len = try established.application.sealApplicationData(
        "GET / HTTP/1.0\r\n\r\n",
        &request_record,
    );
    try writeAll(fd, request_record[0..request_len]);
    while (true) {
        const event = try driver.nextApplication(&established.application);
        switch (event) {
            .application_data => |bytes| {
                if (bytes.len != 0) break;
            },
            .post_handshake => {},
            .key_update => {
                if (established.application.keyUpdateResponseRequired()) {
                    var response: [64]u8 = undefined;
                    const response_len = try established.application
                        .sealKeyUpdateResponse(&response);
                    try writeAll(fd, response[0..response_len]);
                }
            },
            .alert => |received| {
                if (received.isCloseNotify()) return error.EarlyCloseNotify;
                return error.PeerAlert;
            },
        }
    }
    std.debug.print("server application data verified\n", .{});

    var close_record: [64]u8 = undefined;
    const close_len = try established.application.sealCloseNotify(
        &close_record,
    );
    try writeAll(fd, close_record[0..close_len]);
    _ = linux.shutdown(fd, linux.SHUT.WR);
}

fn acceptTestCertificate(
    context: ?*anyopaque,
    trust: vail.tls.auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0) return error.EmptyCertificateChain;
}

const SocketClientDriver = struct {
    fd: i32,
    buffer: [4096]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn next(
        self: *SocketClientDriver,
        client: *Client,
        client_flight: *std.ArrayList(u8),
    ) !Client.Event {
        while (true) {
            const drained = try client.receive("", client_flight);
            if (drained.event) |event| return event;
            if (self.start < self.end) {
                const result = try client.receive(
                    self.buffer[self.start..self.end],
                    client_flight,
                );
                self.start += result.consumed;
                if (result.event) |event| return event;
            }
            if (self.start != self.end) return error.ClientDriverStalled;

            const rc = linux.read(
                self.fd,
                &self.buffer,
                self.buffer.len,
            );
            if (linux.errno(rc) != .SUCCESS) return error.ReadFailed;
            if (rc == 0) return error.EndOfStream;
            self.start = 0;
            self.end = rc;
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
            const rc = linux.read(
                self.fd,
                &self.buffer,
                self.buffer.len,
            );
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
