const std = @import("std");
const vail = @import("vail");

const linux = std.os.linux;
const Client = vail.tls.client_connection.ClientConnection(64 * 1024, 256);
const vectors = vail.testdata.crypto.rsa_signing;
const private_key_der = decodeHex(vectors.private_key_pkcs8_hex);
const public_key_spki = decodeHex(vectors.public_key_spki_hex);
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;
const MlDsa65 = std.crypto.sign.mldsa.MLDSA65;
const MlDsa87 = std.crypto.sign.mldsa.MLDSA87;
const ml_dsa_44_oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
const ml_dsa_65_oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
const ml_dsa_87_oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

const IdentityMode = enum { rsa, ml_dsa_44, ml_dsa_65, ml_dsa_87 };
const MlDsaKeyPair = union(IdentityMode) {
    rsa: void,
    ml_dsa_44: MlDsa44.KeyPair,
    ml_dsa_65: MlDsa65.KeyPair,
    ml_dsa_87: MlDsa87.KeyPair,
};
const MlDsaSpki = union(IdentityMode) {
    rsa: void,
    ml_dsa_44: [22 + MlDsa44.PublicKey.encoded_length]u8,
    ml_dsa_65: [22 + MlDsa65.PublicKey.encoded_length]u8,
    ml_dsa_87: [22 + MlDsa87.PublicKey.encoded_length]u8,
};

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = try parseMode(args.next());
    if (args.next() != null) return error.InvalidArguments;
    const fd = try sysSocket();
    defer _ = linux.close(fd);
    var address = std.mem.zeroes(linux.sockaddr.in);
    address.family = linux.AF.INET;
    address.port = std.mem.nativeToBig(u16, modePort(mode));
    address.addr = std.mem.nativeToBig(u32, 0x7f000001);
    try sysConnect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));

    const private_key = try vail.crypto.rsa.PrivateKey.fromDer(
        &private_key_der,
    );
    var prepared_key = try private_key.prepare();
    defer prepared_key.deinit();
    var ml_dsa_key_pair: MlDsaKeyPair = switch (mode) {
        .rsa => .{ .rsa = {} },
        .ml_dsa_44 => .{ .ml_dsa_44 = try MlDsa44.KeyPair.generateDeterministic(
            [_]u8{0x5a} ** MlDsa44.KeyPair.seed_length,
        ) },
        .ml_dsa_65 => .{ .ml_dsa_65 = try MlDsa65.KeyPair.generateDeterministic(
            [_]u8{0x5a} ** MlDsa65.KeyPair.seed_length,
        ) },
        .ml_dsa_87 => .{ .ml_dsa_87 = try MlDsa87.KeyPair.generateDeterministic(
            [_]u8{0x5a} ** MlDsa87.KeyPair.seed_length,
        ) },
    };
    defer wipeMlDsaKeyPair(&ml_dsa_key_pair);
    var ml_dsa_spki: MlDsaSpki = switch (ml_dsa_key_pair) {
        .rsa => .{ .rsa = {} },
        .ml_dsa_44 => |*key_pair| .{ .ml_dsa_44 = mlDsaSubjectPublicKeyInfo(
            MlDsa44,
            &ml_dsa_44_oid,
            key_pair.public_key.toBytes(),
        ) },
        .ml_dsa_65 => |*key_pair| .{ .ml_dsa_65 = mlDsaSubjectPublicKeyInfo(
            MlDsa65,
            &ml_dsa_65_oid,
            key_pair.public_key.toBytes(),
        ) },
        .ml_dsa_87 => |*key_pair| .{ .ml_dsa_87 = mlDsaSubjectPublicKeyInfo(
            MlDsa87,
            &ml_dsa_87_oid,
            key_pair.public_key.toBytes(),
        ) },
    };
    const signer: vail.tls.auth.Signer = switch (ml_dsa_key_pair) {
        .rsa => .{ .rsa_pss = .{
            .prepared_key = &prepared_key,
            .io = init.io,
        } },
        .ml_dsa_44 => |*key_pair| .{ .ml_dsa_44 = .{
            .key_pair = key_pair,
            .noise = [_]u8{0x5b} ** MlDsa44.noise_length,
        } },
        .ml_dsa_65 => |*key_pair| .{ .ml_dsa_65 = .{
            .key_pair = key_pair,
            .noise = [_]u8{0x5b} ** MlDsa65.noise_length,
        } },
        .ml_dsa_87 => |*key_pair| .{ .ml_dsa_87 = .{
            .key_pair = key_pair,
            .noise = [_]u8{0x5b} ** MlDsa87.noise_length,
        } },
    };
    const peer_spki: []const u8 = switch (ml_dsa_spki) {
        .rsa => &public_key_spki,
        .ml_dsa_44 => |*spki| spki,
        .ml_dsa_65 => |*spki| spki,
        .ml_dsa_87 => |*spki| spki,
    };
    const signature_schemes: []const u16 = switch (mode) {
        .rsa => &vail.tls.client_hello.default_signature_schemes,
        .ml_dsa_44 => &.{vail.tls.auth.signature_scheme_ml_dsa_44},
        .ml_dsa_65 => &.{vail.tls.auth.signature_scheme_ml_dsa_65},
        .ml_dsa_87 => &.{vail.tls.auth.signature_scheme_ml_dsa_87},
    };
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
        .signature_schemes = signature_schemes,
        .alpn_protocols = &.{"h2"},
        .server_verifier = .{ .pinned_raw_public_key = peer_spki },
        .server_certificate_type = .raw_public_key,
        .client_identity = .{
            .certificate_chain = &.{peer_spki},
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
            .ech_rejected => |value| {
                var rejection = value;
                rejection.deinit();
                return error.EchRejected;
            },
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
            peer_spki,
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
    std.debug.print(
        "Vail client verified mutual RFC 7250 RPK scheme={s}\n",
        .{modeLabel(mode)},
    );
}

fn parseMode(value: ?[]const u8) !IdentityMode {
    const name = value orelse return .rsa;
    if (std.mem.eql(u8, name, "mldsa44")) return .ml_dsa_44;
    if (std.mem.eql(u8, name, "mldsa65")) return .ml_dsa_65;
    if (std.mem.eql(u8, name, "mldsa87")) return .ml_dsa_87;
    return error.InvalidArguments;
}

fn modePort(mode: IdentityMode) u16 {
    return switch (mode) {
        .rsa => 24453,
        .ml_dsa_44 => 24469,
        .ml_dsa_65 => 24471,
        .ml_dsa_87 => 24473,
    };
}

fn modeLabel(mode: IdentityMode) []const u8 {
    return switch (mode) {
        .rsa => "RSA_PSS_SHA256",
        .ml_dsa_44 => "ML_DSA_44",
        .ml_dsa_65 => "ML_DSA_65",
        .ml_dsa_87 => "ML_DSA_87",
    };
}

fn wipeMlDsaKeyPair(key_pair: *MlDsaKeyPair) void {
    switch (key_pair.*) {
        .rsa => {},
        .ml_dsa_44 => |*value| std.crypto.secureZero(u8, std.mem.asBytes(value)),
        .ml_dsa_65 => |*value| std.crypto.secureZero(u8, std.mem.asBytes(value)),
        .ml_dsa_87 => |*value| std.crypto.secureZero(u8, std.mem.asBytes(value)),
    }
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

fn mlDsaSubjectPublicKeyInfo(
    comptime MlDsa: type,
    comptime oid: []const u8,
    public_key: [MlDsa.PublicKey.encoded_length]u8,
) [22 + MlDsa.PublicKey.encoded_length]u8 {
    var spki: [22 + MlDsa.PublicKey.encoded_length]u8 = undefined;
    spki[0] = 0x30;
    spki[1] = 0x82;
    std.mem.writeInt(u16, spki[2..4], 18 + MlDsa.PublicKey.encoded_length, .big);
    spki[4] = 0x30;
    spki[5] = 0x0b;
    spki[6] = 0x06;
    spki[7] = oid.len;
    @memcpy(spki[8..17], oid);
    spki[17] = 0x03;
    spki[18] = 0x82;
    std.mem.writeInt(u16, spki[19..21], 1 + MlDsa.PublicKey.encoded_length, .big);
    spki[21] = 0;
    @memcpy(spki[22..], &public_key);
    return spki;
}
