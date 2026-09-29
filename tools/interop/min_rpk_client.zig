const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Client = vail.tls.client_connection.ClientConnection(64 * 1024, 256);
const vectors = vail.crypto.testing.rsa_signing;
const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
const public_key_spki = decodeHex(vectors.public_key_spki_hex);

pub fn main(init: std.process.Init) !void {
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, 24453);
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));

    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const signer = vail.tls.auth.Signer{ .rsa_pss = .{
        .prepared_key = &prepared_key,
        .io = init.io,
    } };
    var key_material = vail.tls.key_exchange.ClientKeyMaterial{
        .x25519 = [_]u8{0x91} ** vail.tls.key_exchange.secret_len,
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.heap.smp_allocator);
    var client = try Client.init(.{
        .allocator = std.heap.smp_allocator,
        .random = [_]u8{0x92} ** 32,
        .server_name = "localhost",
        .key_material = &key_material,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .alpn_protocols = &.{"h2"},
        .server_verifier = .{ .pinned_raw_public_key = &public_key_spki },
        .server_certificate_type = .raw_public_key,
        .client_identity = .{
            .certificate_chain = &.{&public_key_spki},
            .signer = signer,
            .certificate_type = .raw_public_key,
        },
    }, &output);
    defer client.deinit();
    try writeAll(fd, output.items);
    output.clearRetainingCapacity();

    var driver = SocketDriver{ .fd = fd };
    var established: Client.Established = while (true) {
        const event = try driver.nextHandshake(&client, &output);
        switch (event) {
            .server_hello,
            .compatibility_change_cipher_spec,
            => continue,
            .hello_retry_request => {
                try writeAll(fd, output.items);
                output.clearRetainingCapacity();
            },
            .peer_alert => return error.PeerAbortedHandshake,
            .established => |value| break value,
        }
    };
    defer established.deinit();
    try writeAll(fd, output.items);
    output.clearRetainingCapacity();
    if (established.server_certificate_type != .raw_public_key or
        established.client_certificate_type != .raw_public_key or
        established.peer_certificate_chain.len != 1 or
        !std.mem.eql(
            u8,
            established.peer_certificate_chain[0],
            &public_key_spki,
        ))
    {
        return error.UnexpectedRawPublicKey;
    }

    var request: [128]u8 = undefined;
    const request_len = try established.application.sealApplicationData(
        "ping",
        &request,
    );
    try writeAll(fd, request[0..request_len]);
    while (true) {
        const event = try driver.nextApplication(&established.application);
        switch (event) {
            .application_data => |bytes| if (bytes.len != 0) {
                if (!std.mem.eql(u8, bytes, "rustls rpk ok\n")) {
                    return error.UnexpectedApplicationData;
                }
                break;
            },
            .alert => return error.PeerAbortedHandshake,
            else => {},
        }
    }
    std.debug.print("Vail client verified mutual RFC 7250 RPK\n", .{});
}

const SocketDriver = struct {
    fd: i32,
    buffer: [4096]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn nextHandshake(
        self: *SocketDriver,
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
            if (self.start != self.end) return error.HandshakeDriverStalled;
            try self.readMore();
        }
    }

    fn nextApplication(
        self: *SocketDriver,
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
            if (self.start != self.end) return error.ApplicationDriverStalled;
            try self.readMore();
        }
    }

    fn readMore(self: *SocketDriver) !void {
        const count = linux.read(self.fd, &self.buffer, self.buffer.len);
        if (linux.errno(count) != .SUCCESS) return error.ReadFailed;
        if (count == 0) return error.EndOfStream;
        self.start = 0;
        self.end = count;
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
        const count = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(count) != .SUCCESS) return error.WriteFailed;
        offset += count;
    }
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
