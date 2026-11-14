//! Deterministic mutation fuzzing for network-facing parsers.
//!
//! Run with `zig build fuzz` or `zig build fuzz -- --iterations=100000`.
//! The harness starts from valid X.509, TLS handshake, and QUIC transport
//! parameter seeds and applies random mutations before exercising every parser.
//! It is intentionally portable: Zig 0.16.0's `-ffuzz` test runner does not
//! compile (the compiler test runner passes a `builtin.StackTrace` to
//! `std.debug.writeStackTrace`), so this executable provides the same
//! crash-detection coverage without the built-in libFuzzer integration.

const std = @import("std");
const vail = @import("vail");

const max_input_len = 64 * 1024;
const default_iterations: usize = 10_000;
const default_seed: u64 = 0x9e37_79b9_7f4a_7c15;

const certificate_seed = @embedFile("x509/testdata/ca.der");
const crl_seed = @embedFile("x509/testdata/rsa-pss-sha256.crl.der");
const ocsp_seed = @embedFile("x509/testdata/rsa-pss-sha256.ocsp.der");

const Seeds = struct {
    certificate: []const u8,
    crl: []const u8,
    ocsp: []const u8,
    client_hello: []const u8,
    server_hello: []const u8,
    transport_parameters: []const u8,

    fn all(self: Seeds) [6][]const u8 {
        return .{
            self.certificate,
            self.crl,
            self.ocsp,
            self.client_hello,
            self.server_hello,
            self.transport_parameters,
        };
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var iterations = default_iterations;
    var seed = default_seed;
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            std.debug.print(
                "usage: vail-fuzz [--iterations=N] [--seed=N]\n",
                .{},
            );
            return;
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--seed=")) {
            seed = try std.fmt.parseInt(u64, arg["--seed=".len..], 10);
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }

    const allocator = init.arena.allocator();
    const seeds = try buildSeeds(allocator);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var traffic_secret = vail.tls.secret.Secret.fromSha256(
        [_]u8{0x42} ** 32,
    );
    defer traffic_secret.deinit();
    var record_keys = try vail.tls.record.Keys.derive(
        .aes_128_gcm_sha256,
        traffic_secret,
    );
    defer record_keys.deinit();

    var buffer: [max_input_len]u8 = undefined;
    const candidates = seeds.all();
    for (0..iterations) |_| {
        const seed_bytes = candidates[
            random.intRangeAtMost(
                usize,
                0,
                candidates.len - 1,
            )
        ];
        const bytes = mutate(random, seed_bytes, &buffer);
        runParsers(bytes, &record_keys);
    }

    std.debug.print(
        "fuzz: {d} iterations, seed=0x{x}\n",
        .{ iterations, seed },
    );
}

fn buildSeeds(allocator: std.mem.Allocator) !Seeds {
    var client_hello: std.ArrayList(u8) = .empty;
    try vail.tls.client_hello.write(&client_hello, allocator, .{
        .random = [_]u8{0x11} ** 32,
        .x25519_public_key = [_]u8{0x22} ** 32,
    });

    var key_share = [_]u8{0x44} ** 32;
    var server_hello: std.ArrayList(u8) = .empty;
    try vail.tls.server_hello.writeServerHello(
        &server_hello,
        allocator,
        .{
            .random = [_]u8{0x33} ** 32,
            .session_id_echo = &.{},
            .cipher_suite = .aes_128_gcm_sha256,
            .key_share_group = 0x001d,
            .key_share = &key_share,
        },
    );

    var transport_parameters: std.ArrayList(u8) = .empty;
    try vail.quic.transport_parameters.appendExtension(
        &transport_parameters,
        allocator,
        &.{ 0x01, 0x02, 0x03, 0x04 },
    );

    return .{
        .certificate = certificate_seed,
        .crl = crl_seed,
        .ocsp = ocsp_seed,
        .client_hello = client_hello.items,
        .server_hello = server_hello.items,
        .transport_parameters = transport_parameters.items,
    };
}

fn mutate(
    random: std.Random,
    seed: []const u8,
    output: []u8,
) []const u8 {
    var len = @min(seed.len, output.len);
    @memcpy(output[0..len], seed[0..len]);

    const mutation_count = random.intRangeAtMost(usize, 1, 8);
    for (0..mutation_count) |_| {
        switch (random.intRangeAtMost(u8, 0, 4)) {
            0 => if (len != 0) {
                const index = random.intRangeAtMost(usize, 0, len - 1);
                output[index] ^= @as(u8, 1) << random.int(u3);
            },
            1 => if (len != 0) {
                output[random.intRangeAtMost(usize, 0, len - 1)] =
                    random.int(u8);
            },
            2 => len = random.intRangeAtMost(usize, 0, len),
            3 => if (len != 0 and len < output.len) {
                const index = random.intRangeAtMost(usize, 0, len);
                std.mem.copyBackwards(
                    u8,
                    output[index + 1 .. len + 1],
                    output[index..len],
                );
                output[index] = random.int(u8);
                len += 1;
            },
            4 => if (len < output.len) {
                output[len] = random.int(u8);
                len += 1;
            },
            else => unreachable,
        }
    }
    return output[0..len];
}

fn runParsers(bytes: []const u8, record_keys: *const vail.tls.record.Keys) void {
    _ = vail.x509.certificate.parse(bytes) catch {};
    vail.x509.distinguished_name.validate(bytes) catch {};
    const mid = bytes.len / 2;
    _ = vail.x509.distinguished_name.eql(
        bytes[0..mid],
        bytes[mid..],
    ) catch {};
    _ = vail.x509.crl.distributionPointUrls(bytes) catch {};
    _ = vail.x509.crl.certificateFreshestCrlUrls(bytes) catch {};
    _ = vail.x509.ocsp.responderUrls(bytes) catch {};

    _ = vail.tls.client_hello.parse(bytes) catch {};
    _ = vail.tls.server_hello.parseServerHello(bytes) catch {};
    _ = vail.tls.server_hello.parseHelloRetryRequest(bytes) catch {};
    _ = vail.tls.ech.parseConfig(bytes) catch {};
    _ = vail.tls.ech.parseClientHelloExtension(bytes) catch {};
    _ = vail.quic.transport_parameters.findExtension(bytes) catch {};

    var records: vail.tls.stream.RecordDeframer = .{};
    _ = records.push(bytes) catch {};
    var messages: vail.tls.stream.HandshakeReassembler(
        max_input_len,
    ) = .{};
    _ = messages.push(bytes) catch {};

    var plaintext: [vail.tls.record.max_inner_plaintext_len]u8 = undefined;
    _ = record_keys.open(0, bytes, &plaintext) catch {};
}
