const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const HandshakeServer = vail.tls.server_connection.ServerConnection(
    64 * 1024,
    256,
);

const cert_der = [_]u8{
    0x30, 0x82, 0x01, 0x30, 0x30, 0x81, 0xd6, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x12, 0x34, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x5a, 0xc0, 0xb8, 0xee, 0x09, 0xe6, 0x57, 0x67, 0xbb, 0x6c, 0x7d, 0x34, 0x40, 0xbb, 0xe1, 0x5c, 0xb9, 0x12, 0xd4, 0xaf, 0xe1, 0x0b, 0x6e, 0x1a, 0x17, 0xff, 0xa1, 0xec, 0xd1, 0xf2, 0xe5, 0x49, 0x97, 0xb4, 0x34, 0xd6, 0x58, 0x3d, 0x4a, 0x99, 0x6b, 0xae, 0x68, 0x60, 0x63, 0x0c, 0xb3, 0xd5, 0x1d, 0xd7, 0xd4, 0x1c, 0xfd, 0x16, 0x4c, 0xce, 0x7e, 0x2f, 0x66, 0xfe, 0x7e, 0x11, 0xa9, 0x14, 0xa3, 0x18, 0x30, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x91, 0x40, 0x8f, 0xe5, 0x25, 0x57, 0xf1, 0x4e, 0x19, 0xa5, 0x51, 0x9c, 0x1f, 0xfd, 0x97, 0xbc, 0x17, 0x81, 0x27, 0xad, 0xd3, 0x39, 0xf8, 0x09, 0xd8, 0x05, 0x21, 0xc9, 0x2a, 0x0b, 0x58, 0x44, 0x02, 0x21, 0x00, 0xa4, 0xf4, 0x75, 0x7c, 0x94, 0xf6, 0x33, 0xd3, 0xd5, 0x36, 0x7d, 0xdf, 0xc1, 0xd6, 0x41, 0x6e, 0x82, 0x84, 0xa1, 0x6a, 0xd4, 0x60, 0xb5, 0x72, 0xea, 0xc3, 0x2f, 0x6e, 0xb8, 0x4d, 0x8c, 0xa5,
};

const rsa_vectors = vail.crypto.testing.rsa_signing;
const rsa_cert_der = decodeHex(rsa_vectors.certificate_hex);
const rsa_private_key_der = decodeHex(rsa_vectors.private_key_pkcs8_hex);

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next();
    const use_ech = if (mode) |argument|
        std.mem.eql(u8, argument, "ech") or
            std.mem.eql(u8, argument, "ech-hrr")
    else
        false;
    const force_ech_hrr = if (mode) |argument|
        std.mem.eql(u8, argument, "ech-hrr")
    else
        false;
    if (args.next() != null) return error.InvalidArguments;
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    try sysReuseAddr(fd);
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 24444);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysBind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    try sysListen(fd, 1);
    const client = try sysAccept(fd);
    defer _ = linux.close(client);
    var key_material = if (use_ech and !force_ech_hrr)
        vail.tls.key_exchange.ServerKeyMaterial{
            .x25519 = [_]u8{0x71} ** vail.tls.key_exchange.secret_len,
        }
    else
        vail.tls.key_exchange.ServerKeyMaterial{
            .secp256r1 = [_]u8{0} **
                (vail.tls.key_exchange.p256.secret_len - 1) ++ .{1},
        };
    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &rsa_private_key_der,
    );
    var prepared_private_key = try private_key.prepare();
    defer prepared_private_key.deinit();
    const signer = vail.tls.auth.Signer{
        .rsa_pss = .{
            .prepared_key = &prepared_private_key,
            .io = init.io,
        },
    };
    var certificate_message: std.ArrayList(u8) = .empty;
    defer certificate_message.deinit(std.heap.smp_allocator);
    try vail.tls.auth.writeCertificate(
        &certificate_message,
        std.heap.smp_allocator,
        &.{&rsa_cert_der},
    );
    var prepared_certificate =
        try vail.tls.certificate_compression.Prepared.initZlib(
            std.heap.smp_allocator,
            certificate_message.items,
            .amortized,
        );
    defer prepared_certificate.deinit();
    const compressed_certificates =
        [_]vail.tls.certificate_compression.PreparedView{
            prepared_certificate.view(),
        };
    const ech_secret = [_]u8{
        0xbc, 0xb5, 0x51, 0x29, 0x31, 0x10, 0x30, 0xc9,
        0xed, 0x26, 0xde, 0xd4, 0xb3, 0xdf, 0x3a, 0xce,
        0x06, 0x8a, 0xee, 0x17, 0xab, 0xce, 0xd7, 0xdb,
        0xf3, 0x11, 0xe5, 0xa8, 0xf3, 0xb1, 0x8e, 0x24,
    };
    var ech_key_pair = try vail.crypto.hpke.KeyPair.fromSecretKey(&ech_secret);
    defer ech_key_pair.deinit();
    var ech_config_bytes: std.ArrayList(u8) = .empty;
    defer ech_config_bytes.deinit(std.heap.smp_allocator);
    if (use_ech) {
        try vail.tls.ech.writeConfig(
            &ech_config_bytes,
            std.heap.smp_allocator,
            .{
                .config_id = 1,
                .public_key = ech_key_pair.public_key,
                .maximum_name_length = 16,
                .public_name = "public.example",
            },
        );
    }
    const selected_ech = if (use_ech)
        try vail.tls.ech.parseConfig(ech_config_bytes.items)
    else
        null;
    const regular_groups = [_]u16{vail.tls.key_exchange.named_group_secp256r1};
    const ech_groups = [_]u16{vail.tls.key_exchange.named_group_x25519};
    var handshake = HandshakeServer.init(.{
        .allocator = std.heap.smp_allocator,
        .policy = .{
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .groups = if (use_ech and !force_ech_hrr)
                &ech_groups
            else
                &regular_groups,
            .alpn_protocols = &.{ "h2", "http/1.1" },
            .compressed_certificates = &compressed_certificates,
        },
        .server_random = [_]u8{0x73} ** 32,
        .key_material = &key_material,
        .certificate_chain = &.{&rsa_cert_der},
        .signer = signer,
        .ech = if (selected_ech) |config| .{
            .config = config,
            .key_pair = &ech_key_pair,
            .require_public_name_match = true,
        } else null,
    });
    defer handshake.deinit();
    var driver = SocketHandshakeDriver{ .fd = client };
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(std.heap.smp_allocator);
    while (true) {
        const event = try driver.next(&handshake, &flight);
        switch (event) {
            .hello_retry_request => {
                std.debug.print("hello retry request\n", .{});
                try writePlaintextHandshakeRecord(client, flight.items);
                flight.clearRetainingCapacity();
            },
            .compatibility_change_cipher_spec => {},
            .server_flight => break,
            else => return error.ExpectedClientHello,
        }
    }
    const server_hello_len = 4 + ((@as(usize, flight.items[1]) << 16) |
        (@as(usize, flight.items[2]) << 8) | flight.items[3]);
    try writePlaintextHandshakeRecord(
        client,
        flight.items[0..server_hello_len],
    );
    try writeAll(client, flight.items[server_hello_len..]);

    var established: HandshakeServer.Established = while (true) {
        const event = try driver.next(&handshake, &flight);
        switch (event) {
            .compatibility_change_cipher_spec,
            .early_data,
            .end_of_early_data,
            => continue,
            .established => |value| break value,
            .peer_alert => return error.PeerAbortedHandshake,
            .hello_retry_request,
            .server_flight,
            => return error.UnexpectedServerFlight,
        }
    };
    defer established.deinit();
    std.debug.print("client finished verified\n", .{});
    if (established.ech_accepted) {
        std.debug.print("ech accepted\n", .{});
    }
    if (established.certificate_compression) |algorithm| {
        std.debug.print(
            "certificate compression={s}\n",
            .{@tagName(algorithm)},
        );
    }
    var close_record: [64]u8 = undefined;
    const close_len = try established.application.sealCloseNotify(
        &close_record,
    );
    try writeAll(client, close_record[0..close_len]);
    _ = linux.shutdown(client, linux.SHUT.WR);
}

fn sysSocket() !i32 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return @intCast(rc);
}
fn sysReuseAddr(fd: i32) !void {
    var yes: i32 = 1;
    const rc = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&yes), @sizeOf(i32));
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
const SocketHandshakeDriver = struct {
    fd: i32,
    buffer: [4096]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn next(
        self: *SocketHandshakeDriver,
        handshake: *HandshakeServer,
        flight: *std.ArrayList(u8),
    ) !HandshakeServer.Event {
        while (true) {
            const drained = try handshake.receive("", flight);
            if (drained.event) |event| return event;
            if (self.start < self.end) {
                const result = try handshake.receive(
                    self.buffer[self.start..self.end],
                    flight,
                );
                self.start += result.consumed;
                if (result.event) |event| return event;
            }
            if (self.start != self.end) return error.HandshakeDriverStalled;

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

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(rc) != .SUCCESS) return error.WriteFailed;
        offset += rc;
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

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
