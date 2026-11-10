const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const max_crypto_flight = 64 * 1024;
const client_transport_parameters = [_]u8{ 0x01, 0x02, 0x03 };
const server_transport_parameters = [_]u8{ 0x04, 0x05, 0x06 };
const rsa_vectors = vail.testdata.crypto.rsa_signing;
const certificate_der = decodeHex(rsa_vectors.certificate_hex);
const private_key_der = decodeHex(rsa_vectors.private_key_pkcs8_hex);
const GroupMode = enum { x25519, hybrid, mlkem768, mlkem1024 };

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode: GroupMode = if (args.next()) |value|
        if (std.mem.eql(u8, value, "hybrid"))
            .hybrid
        else if (std.mem.eql(u8, value, "mlkem"))
            .mlkem768
        else if (std.mem.eql(u8, value, "mlkem1024"))
            .mlkem1024
        else
            return error.InvalidArguments
    else
        .x25519;
    if (args.next() != null) return error.InvalidArguments;
    const allocator = std.heap.smp_allocator;
    const listener = try sysSocket();
    defer _ = linux.close(listener);
    try sysReuseAddr(listener);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, switch (mode) {
        .x25519 => 24456,
        .hybrid => 24460,
        .mlkem768 => 24462,
        .mlkem1024 => 24464,
    });
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysBind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    try sysListen(listener, 1);
    const peer = try sysAccept(listener);
    defer _ = linux.close(peer);

    const client_initial = try readFrame(peer, allocator);
    defer allocator.free(client_initial);
    const parsed_client = try vail.tls.client_hello.parse(client_initial);
    if (parsed_client.quic_transport_parameters == null or
        !std.mem.eql(
            u8,
            &client_transport_parameters,
            parsed_client.quic_transport_parameters.?,
        ))
    {
        return error.UnexpectedTransportParameters;
    }
    if (!try parsed_client.supportsAlpnProtocol("h3")) {
        return error.MissingH3;
    }
    const selected_group = switch (mode) {
        .x25519 => vail.tls.key_exchange.named_group_x25519,
        .hybrid => vail.tls.key_exchange.x25519_mlkem768.named_group,
        .mlkem768 => vail.tls.key_exchange.mlkem768.named_group,
        .mlkem1024 => vail.tls.key_exchange.mlkem1024.named_group,
    };
    const client_share = (try parsed_client.keyShareForGroup(
        selected_group,
    )) orelse return error.MissingKeyShare;

    var key_material: vail.tls.key_exchange.ServerKeyMaterial = switch (mode) {
        .x25519 => .{
            .x25519 = [_]u8{0xc1} ** vail.tls.key_exchange.secret_len,
        },
        .hybrid => .{ .x25519_mlkem768 = .{
            .x25519_secret = [_]u8{0xc1} **
                vail.tls.key_exchange.x25519_mlkem768.x25519_secret_len,
            .encaps_seed = [_]u8{0xc3} **
                vail.tls.key_exchange.x25519_mlkem768.encaps_seed_len,
        } },
        .mlkem768 => .{
            .mlkem768 = [_]u8{0xc4} **
                vail.tls.key_exchange.mlkem768.encaps_seed_len,
        },
        .mlkem1024 => .{
            .mlkem1024 = [_]u8{0xc5} **
                vail.tls.key_exchange.mlkem1024.encaps_seed_len,
        },
    };
    defer key_material.wipe();
    var exchange = try key_material.respond(client_share.key_exchange);
    defer exchange.deinit();
    const groups = [_]u16{selected_group};

    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(&private_key_der);
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    const signer = vail.tls.auth.Signer{
        .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = init.io,
        },
    };
    var certificate_message: std.ArrayList(u8) = .empty;
    defer certificate_message.deinit(allocator);
    try vail.tls.auth.writeCertificate(
        &certificate_message,
        allocator,
        &.{&certificate_der},
    );
    var compressed_certificate = try vail.tls.certificate_compression.Prepared
        .initBrotli(
        allocator,
        certificate_message.items,
        .amortized,
    );
    defer compressed_certificate.deinit();
    const compressed_certificates =
        [_]vail.tls.certificate_compression.PreparedView{
            compressed_certificate.view(),
        };

    var server_initial: std.ArrayList(u8) = .empty;
    defer server_initial.deinit(allocator);
    var server_handshake: std.ArrayList(u8) = .empty;
    defer server_handshake.deinit(allocator);
    var result = try vail.quic.tls_handshake.writeServerCryptoFlight(
        &server_initial,
        &server_handshake,
        allocator,
        .{
            .client_hello_bytes = client_initial,
            .parsed_client_hello = parsed_client,
            .policy = .{
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .groups = &groups,
                .alpn_protocols = &.{"h3"},
                .quic_transport_parameters = &server_transport_parameters,
                .compressed_certificates = &compressed_certificates,
            },
            .server_random = [_]u8{0xc2} ** 32,
            .server_key_share = exchange.serverShare(),
            .shared_secret = exchange.sharedSecretBytes(),
            .certificate_chain = &.{&certificate_der},
            .signer = signer,
        },
    );
    defer result.deinit();
    if (result.certificate_compression != .brotli) {
        return error.CertificateCompressionNotNegotiated;
    }
    try writeFrame(peer, server_initial.items);
    try writeFrame(peer, server_handshake.items);

    const client_handshake = try readFrame(peer, allocator);
    defer allocator.free(client_handshake);
    var verified = try vail.quic.tls_handshake.verifyClientCryptoFlight(
        allocator,
        &result,
        client_handshake,
    );
    defer verified.deinit();
    if (verified.peer_certificate_chain.len != 0) {
        return error.UnexpectedClientCertificate;
    }
    std.debug.print(
        "Vail QUIC server verified rustls/AWS-LC client group={s} compression=Brotli\n",
        .{switch (mode) {
            .x25519 => "X25519",
            .hybrid => "X25519MLKEM768",
            .mlkem768 => "MLKEM768",
            .mlkem1024 => "MLKEM1024",
        }},
    );
}

fn readFrame(fd: i32, allocator: std.mem.Allocator) ![]u8 {
    var length_bytes: [4]u8 = undefined;
    try readExact(fd, &length_bytes);
    const length: usize = @intCast(std.mem.readInt(u32, &length_bytes, .big));
    if (length == 0 or length > max_crypto_flight) {
        return error.InvalidFrameLength;
    }
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    try readExact(fd, bytes);
    return bytes;
}

fn writeFrame(fd: i32, bytes: []const u8) !void {
    if (bytes.len == 0 or bytes.len > max_crypto_flight) {
        return error.InvalidFrameLength;
    }
    var length_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &length_bytes, @intCast(bytes.len), .big);
    try writeAll(fd, &length_bytes);
    try writeAll(fd, bytes);
}

fn readExact(fd: i32, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = linux.read(fd, output[offset..].ptr, output.len - offset);
        if (linux.errno(count) != .SUCCESS) return error.ReadFailed;
        if (count == 0) return error.EndOfStream;
        offset += count;
    }
}

fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(count) != .SUCCESS) return error.WriteFailed;
        offset += count;
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
