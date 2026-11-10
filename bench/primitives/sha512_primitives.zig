const std = @import("std");
const vail = @import("vail");

const Sha384 = vail.crypto.sha512.Sha384;
const Sha512 = vail.crypto.sha512.Sha512;

const short_iterations: usize = 1_000_000;
const bulk_iterations: usize = 100_000;
const one_shot_hmac_iterations: usize = 500_000;
const warmup_iterations: usize = 4_096;

pub fn main(init: std.process.Init) !void {
    try benchmarkDigest(
        Sha384,
        64,
        short_iterations,
        "sha384-digest-64",
        "53c31096e92945814b6670bb8d694d1a" ++
            "0e7c449b005351a6393ccc28e342bfa2" ++
            "b256faeb56671aacd6ff3a5ed950c18e",
        false,
        init.io,
    );
    try benchmarkDigest(
        Sha384,
        1_024,
        bulk_iterations,
        "sha384-digest-1024",
        "2c48db2b260a7c9bafd83a138c927212" ++
            "f176ba7e615d8f36b8b35864c8da590f" ++
            "df31abd151f343b6dd281af0fd537290",
        false,
        init.io,
    );
    try benchmarkDigest(
        Sha512,
        32,
        short_iterations,
        "sha512-digest-32",
        "35bff78944368fe2796e30c990a5c34f" ++
            "41b4837de3c87f0f72b6c92b8f6d60bd" ++
            "539aea989e10413d3fc797324b7af878" ++
            "9fdaff7490c33323caa4267aa92f9537",
        true,
        init.io,
    );
    try benchmarkDigest(
        Sha512,
        1_024,
        bulk_iterations,
        "sha512-digest-1024",
        "5b303ae22dc225150714da9ea3c81738" ++
            "beacd7683c3d94766c90c6a3063ddafe" ++
            "aef0800ac7f95771a316ac04cafa39d3" ++
            "0dfd7acd986841e71ce893bdd64be426",
        false,
        init.io,
    );

    try benchmarkOneShotHmac(
        Sha384,
        64,
        one_shot_hmac_iterations,
        "hmac-sha384-one-shot-64",
        "654cb9188748e111ff1608e07e2c38d5" ++
            "aa38a641f79e4359bf393b6d10767b3a" ++
            "5cf9162f22f40793b9ce74fa663bb758",
        init.io,
    );
    try benchmarkPreparedHmac(
        Sha384,
        64,
        short_iterations,
        "hmac-sha384-prepared-64",
        "654cb9188748e111ff1608e07e2c38d5" ++
            "aa38a641f79e4359bf393b6d10767b3a" ++
            "5cf9162f22f40793b9ce74fa663bb758",
        true,
        init.io,
    );
    try benchmarkPreparedHmac(
        Sha384,
        1_024,
        bulk_iterations,
        "hmac-sha384-prepared-1024",
        "8e8a251e358fefd781232b376f5d203e" ++
            "d72b8a042faf993e9940e55e2ee9a981" ++
            "95827f209224a67127eca398c513736b",
        false,
        init.io,
    );

    try benchmarkOneShotHmac(
        Sha512,
        64,
        one_shot_hmac_iterations,
        "hmac-sha512-one-shot-64",
        "7569253a81ace72dc795f05e10009c71" ++
            "3a5f5ec32c68b2faba48329b6932a697" ++
            "fce0c9c7b94c6b5a1e8f1bfec9173b" ++
            "79e189a68159f3c59292c13e88d970c752",
        init.io,
    );
    try benchmarkPreparedHmac(
        Sha512,
        64,
        short_iterations,
        "hmac-sha512-prepared-64",
        "7569253a81ace72dc795f05e10009c71" ++
            "3a5f5ec32c68b2faba48329b6932a697" ++
            "fce0c9c7b94c6b5a1e8f1bfec9173b" ++
            "79e189a68159f3c59292c13e88d970c752",
        true,
        init.io,
    );
    try benchmarkPreparedHmac(
        Sha512,
        1_024,
        bulk_iterations,
        "hmac-sha512-prepared-1024",
        "dbfde5e172706a7d851c232d3ea5263" ++
            "c93cbcacf48e689d95e0deb34176d75d" ++
            "4f80097d923f16bb5fa0a7b323dbc5e" ++
            "361b804528ea7cd001b7dea2c90998b5b9",
        false,
        init.io,
    );
}

fn benchmarkDigest(
    comptime Hash: type,
    comptime input_len: usize,
    comptime iterations: usize,
    comptime label: []const u8,
    comptime expected_hex: []const u8,
    comptime use_hash32: bool,
    io: std.Io,
) !void {
    var input = benchmarkInput(input_len);
    var output: [Hash.digest_length]u8 = undefined;
    hash(Hash, &input, &output, use_hash32);
    if (!std.mem.eql(u8, &decodeHex(expected_hex), &output)) {
        return error.InvalidBenchmarkVector;
    }

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        hash(Hash, &input, &output, use_hash32);
        checksum +%= output[iteration % output.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        hash(Hash, &input, &output, use_hash32);
        checksum +%= output[iteration % output.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-{s}={d} ns/op ({d} ps/op) checksum={d}\n",
        .{ label, elapsed / iterations, elapsed * 1000 / iterations, checksum },
    );
}

fn benchmarkOneShotHmac(
    comptime Hash: type,
    comptime input_len: usize,
    comptime iterations: usize,
    comptime label: []const u8,
    comptime expected_hex: []const u8,
    io: std.Io,
) !void {
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    const key = [_]u8{0x42} ** Hash.digest_length;
    var input = benchmarkInput(input_len);
    var output: [Hash.digest_length]u8 = undefined;
    Hmac.create(&output, &input, &key);
    if (!std.mem.eql(u8, &decodeHex(expected_hex), &output)) {
        return error.InvalidBenchmarkVector;
    }

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        Hmac.create(&output, &input, &key);
        checksum +%= output[iteration % output.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        Hmac.create(&output, &input, &key);
        checksum +%= output[iteration % output.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-{s}={d} ns/op ({d} ps/op) checksum={d}\n",
        .{ label, elapsed / iterations, elapsed * 1000 / iterations, checksum },
    );
}

fn benchmarkPreparedHmac(
    comptime Hash: type,
    comptime input_len: usize,
    comptime iterations: usize,
    comptime label: []const u8,
    comptime expected_hex: []const u8,
    comptime use_short: bool,
    io: std.Io,
) !void {
    const Prepared = vail.crypto.sha512.PreparedHmac(Hash);
    const key = [_]u8{0x42} ** Hash.digest_length;
    var prepared = Prepared.init(&key);
    defer prepared.deinit();
    var input = benchmarkInput(input_len);
    var output: [Hash.digest_length]u8 = undefined;
    createPrepared(Hash, &prepared, &output, &input, use_short);
    if (!std.mem.eql(u8, &decodeHex(expected_hex), &output)) {
        return error.InvalidBenchmarkVector;
    }

    var checksum: u64 = 0;
    for (0..warmup_iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        createPrepared(Hash, &prepared, &output, &input, use_short);
        checksum +%= output[iteration % output.len];
    }
    const start = nowNs(io);
    for (0..iterations) |iteration| {
        input[0] = @truncate(iteration);
        std.mem.doNotOptimizeAway(&input);
        createPrepared(Hash, &prepared, &output, &input, use_short);
        checksum +%= output[iteration % output.len];
    }
    const elapsed = nowNs(io) -| start;
    std.debug.print(
        "vail-{s}={d} ns/op ({d} ps/op) checksum={d}\n",
        .{ label, elapsed / iterations, elapsed * 1000 / iterations, checksum },
    );
}

fn hash(
    comptime Hash: type,
    input: []const u8,
    output: *[Hash.digest_length]u8,
    comptime use_hash32: bool,
) void {
    if (comptime use_hash32) {
        comptime std.debug.assert(Hash == Sha512);
        std.debug.assert(input.len == 32);
        vail.crypto.sha512.hash32(input[0..32], output);
    } else {
        Hash.hash(input, output, .{});
    }
}

fn createPrepared(
    comptime Hash: type,
    prepared: *const vail.crypto.sha512.PreparedHmac(Hash),
    output: *[Hash.digest_length]u8,
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
