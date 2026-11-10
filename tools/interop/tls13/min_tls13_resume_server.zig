const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Server = vail.tls.server_connection.ServerConnection(64 * 1024, 1024);
const rsa_vectors = vail.testdata.crypto.rsa_signing;
const certificate_der = decodeHex(rsa_vectors.certificate_hex);
const private_key_der = decodeHex(rsa_vectors.private_key_pkcs8_hex);
const response = "vail resumed tls13 ok\n";
const expected_early_data = "rustls zero-rtt";

pub fn main(init: std.process.Init) !void {
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    var keyring = try vail.tls.ticket_keyring.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{0xa1} ** vail.tls.ticket_keyring.key_len,
    });
    defer keyring.deinit();
    var replay_cache = vail.tls.early_data.ReplayCache(4){};

    const listener = try sysSocket();
    defer _ = linux.close(listener);
    try sysReuseAddr(listener);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, 24458);
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysBind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    try sysListen(listener, 2);

    try runConnection(
        init,
        listener,
        &prepared_key,
        &keyring,
        replay_cache.guard(),
        false,
        0xa2,
    );
    try runConnection(
        init,
        listener,
        &prepared_key,
        &keyring,
        replay_cache.guard(),
        true,
        0xa3,
    );
    std.debug.print("Vail TLS 1.3 resumption and 0-RTT verified\n", .{});
}

fn runConnection(
    init: std.process.Init,
    listener: i32,
    prepared_key: *const vail.crypto.rsa.PreparedPrivateKey,
    keyring: *const vail.tls.ticket_keyring.Keyring,
    replay_guard: vail.tls.early_data.Guard,
    expect_resumed: bool,
    random_byte: u8,
) !void {
    const client = try sysAccept(listener);
    defer _ = linux.close(client);
    var key_material = vail.tls.key_exchange.ServerKeyMaterial{
        .x25519 = [_]u8{random_byte} ** vail.tls.key_exchange.secret_len,
    };
    var server = Server.init(.{
        .allocator = std.heap.smp_allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = &.{vail.tls.key_exchange.named_group_x25519},
            .alpn_protocols = &.{"h2"},
        },
        .server_random = [_]u8{random_byte +% 1} ** 32,
        .key_material = &key_material,
        .certificate_chain = &.{&certificate_der},
        .signer = .{ .rsa_pss = .{
            .prepared_key = prepared_key,
            .io = init.io,
        } },
        .resumption = .{ .tickets = .{
            .keyring = keyring,
            .server_id = "localhost",
            .now_ms = if (expect_resumed) 11_000 else 10_000,
        } },
        .early_data = .{
            .replay_guard = replay_guard,
            .max_bytes = 1024,
        },
    });
    defer server.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var driver = SocketHandshakeDriver{ .fd = client };
    var received_early_data = false;
    var saw_end_of_early_data = false;
    var established: Server.Established = handshake: while (true) {
        const event = try driver.next(&server, &output);
        switch (event) {
            .server_flight => {
                const server_hello_len = try handshakeMessageLen(output.items);
                try writePlaintextHandshakeRecord(
                    client,
                    output.items[0..server_hello_len],
                );
                try writeAll(client, output.items[server_hello_len..]);
                output.clearRetainingCapacity();
            },
            .compatibility_change_cipher_spec => {},
            .early_data => |data| {
                if (!expect_resumed or received_early_data or
                    !std.mem.eql(u8, data, expected_early_data))
                {
                    return error.UnexpectedEarlyData;
                }
                received_early_data = true;
            },
            .end_of_early_data => {
                if (!expect_resumed or !received_early_data) {
                    return error.UnexpectedEndOfEarlyData;
                }
                saw_end_of_early_data = true;
            },
            .established => |value| break :handshake value,
            .peer_alert => return error.PeerAbortedHandshake,
            .hello_retry_request => return error.UnexpectedHelloRetryRequest,
        }
    };
    defer established.deinit();
    if (established.resumed != expect_resumed) {
        return error.UnexpectedHandshakeKind;
    }
    if (established.early_data_accepted != expect_resumed or
        received_early_data != expect_resumed or
        saw_end_of_early_data != expect_resumed)
    {
        return error.UnexpectedEarlyDataState;
    }

    if (!expect_resumed) {
        var ticket_record: [512]u8 = undefined;
        const ticket_len = try established.sealNewSessionTicket(
            std.heap.smp_allocator,
            .{
                .keyring = keyring,
                .sealing_nonce = [_]u8{0xa4} **
                    vail.tls.ticket_keyring.nonce_len,
                .server_id = "localhost",
                .alpn = "h2",
                .ticket_nonce = &.{ 1, 2, 3 },
                .age_add = 0x1020_3040,
                .issued_at_ms = 10_000,
                .lifetime_seconds = 60,
                .allow_early_data = true,
            },
            &ticket_record,
        );
        try writeAll(client, ticket_record[0..ticket_len]);
    }

    while (true) {
        const input = try driver.nextBytes();
        var offset: usize = 0;
        while (offset < input.len) {
            const result = try established.application.receive(input[offset..]);
            offset += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |data| {
                    if (!std.mem.eql(u8, data, "ping")) {
                        return error.UnexpectedApplicationData;
                    }
                    var application_record: [256]u8 = undefined;
                    const application_len = try established.application
                        .sealApplicationData(response, &application_record);
                    try writeAll(client, application_record[0..application_len]);
                    var close_record: [64]u8 = undefined;
                    const close_len = try established.application
                        .sealCloseNotify(&close_record);
                    try writeAll(client, close_record[0..close_len]);
                    _ = linux.shutdown(client, linux.SHUT.WR);
                    return;
                },
                .post_handshake,
                .key_update,
                => return error.UnexpectedPostHandshakeMessage,
                .alert => |received| if (!received.isCloseNotify()) {
                    return error.PeerAbortedHandshake;
                },
            };
            if (result.consumed == 0 and result.event == null) {
                return error.ApplicationDriverStalled;
            }
        }
    }
}

const SocketHandshakeDriver = struct {
    fd: i32,
    buffer: [64 * 1024]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn next(
        self: *SocketHandshakeDriver,
        server: *Server,
        output: *std.ArrayList(u8),
    ) !Server.Event {
        while (true) {
            const drained = try server.receive("", output);
            if (drained.event) |event| return event;
            if (self.start < self.end) {
                const result = try server.receive(
                    self.buffer[self.start..self.end],
                    output,
                );
                self.start += result.consumed;
                if (result.event) |event| return event;
            }
            if (self.start != self.end) return error.HandshakeDriverStalled;
            self.start = 0;
            self.end = try readSocket(self.fd, &self.buffer);
        }
    }

    fn nextBytes(self: *SocketHandshakeDriver) ![]const u8 {
        if (self.start < self.end) {
            const bytes = self.buffer[self.start..self.end];
            self.start = self.end;
            return bytes;
        }
        self.start = 0;
        self.end = try readSocket(self.fd, &self.buffer);
        const bytes = self.buffer[0..self.end];
        self.start = self.end;
        return bytes;
    }
};

fn handshakeMessageLen(bytes: []const u8) !usize {
    if (bytes.len < 4) return error.InvalidHandshakeMessage;
    const len = 4 + ((@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) | bytes[3]);
    if (len > bytes.len) return error.InvalidHandshakeMessage;
    return len;
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

fn writePlaintextHandshakeRecord(fd: i32, message: []const u8) !void {
    if (message.len > vail.tls.record.max_plaintext_len) {
        return error.RecordTooLarge;
    }
    var header = [5]u8{ 0x16, 0x03, 0x03, 0, 0 };
    std.mem.writeInt(u16, header[3..5], @intCast(message.len), .big);
    try writeAll(fd, &header);
    try writeAll(fd, message);
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
    var enabled: i32 = 1;
    const result = linux.setsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.REUSEADDR,
        @ptrCast(&enabled),
        @sizeOf(i32),
    );
    if (linux.errno(result) != .SUCCESS) return error.SetSockOptFailed;
}

fn sysBind(fd: i32, address: *const linux.sockaddr, length: u32) !void {
    const result = linux.bind(fd, address, length);
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
