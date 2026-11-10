const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Client = vail.tls.tls12_client_connection.ClientConnection(
    64 * 1024,
    64 * 1024,
);
const Established = vail.tls.tls12_client_connection.Established;

pub fn main(init: std.process.Init) !void {
    var session = (try runConnection(init, null)) orelse
        return error.SessionNotIssued;
    defer session.deinit();
    _ = try runConnection(init, session);
    std.debug.print("TLS 1.2 session resumption verified\n", .{});
}

fn runConnection(
    init: std.process.Init,
    resumption: ?vail.tls.tls12.Session,
) !?vail.tls.tls12.Session {
    _ = init;
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24448);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));

    var private_key = [_]u8{0} ** vail.tls.key_exchange.p256.secret_len;
    private_key[private_key.len - 1] = if (resumption == null) 3 else 4;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var client = try Client.init(.{
        .allocator = std.heap.smp_allocator,
        .random = if (resumption == null)
            [_]u8{0xd4} ** 32
        else
            [_]u8{0xd5} ** 32,
        .server_name = "localhost",
        .client_private_key = &private_key,
        .policy = .{ .alpn_protocols = &.{"http/1.1"} },
        .server_verifier = .{ .verify_trust = acceptTestCertificate },
        .resumption = resumption,
        .now_seconds = 101,
    }, &output);
    defer client.deinit();
    try writeAll(fd, output.items);
    output.clearRetainingCapacity();

    var driver = SocketDriver{ .fd = fd };
    var established: Established = while (true) {
        const result = try driver.next(&client, &output);
        switch (result) {
            .client_flight => {
                try writeAll(fd, output.items);
                output.clearRetainingCapacity();
            },
            .change_cipher_spec => {},
            .peer_alert => return error.PeerAbortedHandshake,
            .established => |value| {
                if (output.items.len != 0) {
                    try writeAll(fd, output.items);
                    output.clearRetainingCapacity();
                }
                break value;
            },
        }
    };
    defer established.deinit();
    try std.testing.expectEqual(resumption != null, established.resumed);

    const cached = if (resumption == null)
        try established.createSession("localhost", 100, 3600)
    else
        null;
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
    var close: [64]u8 = undefined;
    const close_len = try established.sealCloseNotify(&close);
    try writeAll(fd, close[0..close_len]);
    _ = linux.shutdown(fd, linux.SHUT.WR);
    return cached;
}

fn acceptTestCertificate(
    context: ?*anyopaque,
    trust: vail.tls.auth.TrustContext,
) anyerror!void {
    _ = context;
    if (trust.chain.len == 0) return error.EmptyCertificateChain;
}

const SocketDriver = struct {
    fd: i32,
    buffer: [64 * 1024]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn next(
        self: *SocketDriver,
        client: *Client,
        output: *std.ArrayList(u8),
    ) !vail.tls.tls12_client_connection.Event {
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
        self: *SocketDriver,
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
