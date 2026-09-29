const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Client = vail.tls.tls12_client_connection.ClientConnection(
    64 * 1024,
    64 * 1024,
);
const Established = vail.tls.tls12_client_connection.Established;

pub fn main(init: std.process.Init) !void {
    var ticket = (try runConnection(init, null)) orelse
        return error.SessionTicketNotIssued;
    defer ticket.deinit();
    var renewed = try runConnection(init, &ticket);
    defer if (renewed) |*value| value.deinit();
    std.debug.print("Vail TLS 1.2 ticket resumption verified\n", .{});
}

fn runConnection(
    init: std.process.Init,
    resumption: ?*const vail.tls.tls12_ticket.Cached,
) !?vail.tls.tls12_ticket.Cached {
    _ = init;
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, 24455);
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));

    var private_key = [_]u8{0} ** vail.tls.key_exchange.p256.secret_len;
    private_key[private_key.len - 1] = if (resumption == null) 21 else 22;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var client = try Client.init(.{
        .allocator = std.heap.smp_allocator,
        .random = if (resumption == null)
            [_]u8{0xa4} ** 32
        else
            [_]u8{0xa5} ** 32,
        .server_name = "localhost",
        .client_private_key = &private_key,
        .policy = .{ .alpn_protocols = &.{"http/1.1"} },
        .server_verifier = .{ .verify_trust = acceptTestCertificate },
        .request_session_ticket = true,
        .ticket_resumption = resumption,
        .now_seconds = 100,
    }, &output);
    defer client.deinit();
    try writeAll(fd, output.items);
    output.clearRetainingCapacity();

    var driver = SocketDriver{ .fd = fd };
    var established: Established = while (true) {
        const event = try driver.next(&client, &output);
        switch (event) {
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
    if (established.resumed != (resumption != null)) {
        return error.UnexpectedResumptionState;
    }
    var cached: ?vail.tls.tls12_ticket.Cached =
        if (established.session_ticket != null)
            try established.createTicketSession("localhost", 100)
        else
            null;
    errdefer if (cached) |*value| value.deinit();
    if (resumption == null and cached == null) {
        return error.SessionTicketNotIssued;
    }

    var request: [256]u8 = undefined;
    const request_len = try established.sealApplicationData(
        "GET / HTTP/1.0\r\n\r\n",
        &request,
    );
    try writeAll(fd, request[0..request_len]);
    while (true) {
        const event = try driver.nextApplication(&established);
        switch (event) {
            .application_data => |bytes| if (bytes.len != 0) {
                break;
            },
            .alert => return error.PeerAbortedHandshake,
        }
    }
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
            const count = linux.read(self.fd, &self.buffer, self.buffer.len);
            if (linux.errno(count) != .SUCCESS) return error.ReadFailed;
            if (count == 0) return error.EndOfStream;
            self.start = 0;
            self.end = count;
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
            const count = linux.read(self.fd, &self.buffer, self.buffer.len);
            if (linux.errno(count) != .SUCCESS) return error.ReadFailed;
            if (count == 0) return error.EndOfStream;
            self.start = 0;
            self.end = count;
        }
    }
};

fn sysSocket() !i32 {
    const result = linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
    );
    if (linux.errno(result) != .SUCCESS) return error.SocketFailed;
    return @intCast(result);
}

fn sysConnect(fd: i32, address: *const linux.sockaddr, len: u32) !void {
    const result = linux.connect(fd, address, len);
    if (linux.errno(result) != .SUCCESS) return error.ConnectFailed;
}

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(result) != .SUCCESS) return error.WriteFailed;
        offset += result;
    }
}
