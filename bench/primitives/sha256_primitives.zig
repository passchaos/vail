const std = @import("std");
const vail = @import("vail");

const sha256 = vail.crypto.sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const short_iterations: usize = 2_000_000;
const bulk_iterations: usize = 250_000;
const one_shot_hmac_iterations: usize = 1_000_000;
const warmup_iterations: usize = 4_096;

pub fn main(init: std.process.Init) !void {
    try benchmarkDigest(
        32,
        short_iterations,
        "sha256-digest-32",
        "43599ef388fde687ef9376c222e271b7" ++
            "33efb0b6982a7810af4a0cbd5a0050e3",
        init.io,
    );
    try benchmarkDigest(
        1_024,
        bulk_iterations,
        "sha256-digest-1024",
        "575383deff0775797e1ff4c82da06914" ++
            "1937c843a81cbe50959a96bcfa88140e",
        init.io,
    );
    try benchmarkOneShotHmac(
        32,
        one_shot_hmac_iterations,
        "hmac-sha256-one-shot-32",
        "0e5c3c8cea349b9ca69197a5670ca018" ++
            "bdf024ee5c8311d5d29bb6bd06fdf099",
        init.io,
    );
    try benchmarkPreparedHmac(
        32,
        short_iterations,
        "hmac-sha256-prepared-32",
        "0e5c3c8cea349b9ca69197a5670ca018" ++
            "bdf024ee5c8311d5d29bb6bd06fdf099",
        true,
        init.io,
    );
    try benchmarkPreparedHmac(
        1_024,
        bulk_iterations,
        "hmac-sha256-prepared-1024",
        "b2c8dace2ebb0b077a7ce4e7120657ae" ++
            "f4053a93da369ee7bea48b4c2d6a79a9",
        false,
        init.io,
    );
}

fn benchmarkDigest(
    comptime input_len: usize,
    comptime iterations: usize,
    comptime label: []const u8,
    comptime expected_hex: []const u8,
    io: std.Io,
) !void {
    var input = benchmarkInput(input_len);
    var output = sha256.hash(&input);
    if (!std.mem.eql(u8, &decodeHex(expected_hex), &output)) {
        return error.InvalidBenchmarkVector;
    }

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        output = sha256.hash(&input);
        checksum +%= output[iteration % output.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        output = sha256.hash(&input);
        checksum +%= output[iteration % output.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-{s}={d} ns/op checksum={d}\n",
        .{ label, elapsed / iterations, checksum },
    );
}

fn benchmarkOneShotHmac(
    comptime input_len: usize,
    comptime iterations: usize,
    comptime label: []const u8,
    comptime expected_hex: []const u8,
    io: std.Io,
) !void {
    const key = [_]u8{0x42} ** sha256.digest_len;
    var input = benchmarkInput(input_len);
    var output: sha256.Digest = undefined;
    HmacSha256.create(&output, &input, &key);
    if (!std.mem.eql(u8, &decodeHex(expected_hex), &output)) {
        return error.InvalidBenchmarkVector;
    }

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        HmacSha256.create(&output, &input, &key);
        checksum +%= output[iteration % output.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        HmacSha256.create(&output, &input, &key);
        checksum +%= output[iteration % output.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-{s}={d} ns/op checksum={d}\n",
        .{ label, elapsed / iterations, checksum },
    );
}

fn benchmarkPreparedHmac(
    comptime input_len: usize,
    comptime iterations: usize,
    comptime label: []const u8,
    comptime expected_hex: []const u8,
    comptime use_short: bool,
    io: std.Io,
) !void {
    const key = [_]u8{0x42} ** sha256.digest_len;
    var prepared = sha256.PreparedHmac.init(&key);
    defer prepared.deinit();
    var input = benchmarkInput(input_len);
    var output: sha256.Digest = undefined;
    createPrepared(&prepared, &output, &input, use_short);
    if (!std.mem.eql(u8, &decodeHex(expected_hex), &output)) {
        return error.InvalidBenchmarkVector;
    }

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        createPrepared(&prepared, &output, &input, use_short);
        checksum +%= output[iteration % output.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        createPrepared(&prepared, &output, &input, use_short);
        checksum +%= output[iteration % output.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-{s}={d} ns/op checksum={d}\n",
        .{ label, elapsed / iterations, checksum },
    );
}

fn createPrepared(
    prepared: *const sha256.PreparedHmac,
    output: *sha256.Digest,
    input: []const u8,
    comptime use_short: bool,
) void {
    if (comptime use_short) {
        prepared.createShort(output, input);
    } else {
        prepared.create(output, input);
    }
}

fn benchmarkInput(comptime len: usize) [len]u8 {
    var input: [len]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    return input;
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
