const std = @import("std");
const vail = @import("vail");

const message = "Vail pure Zig RSA-PSS-SHAKE signing oracle";

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const output_path = args.next() orelse return error.MissingOutputPath;
    if (args.next() != null) return error.InvalidArguments;

    const vectors = vail.crypto.testing.rsa_signing;
    const encoded_key = decodeHex(vectors.private_key_pkcs8_hex);
    const key = try vail.crypto.rsa.PrivateKey.fromDer(&encoded_key);
    var prepared = try key.prepare();
    defer prepared.deinit();
    var output_dir = try std.Io.Dir.openDirAbsolute(
        init.io,
        output_path,
        .{},
    );
    defer output_dir.close(init.io);
    var signature: [512]u8 = undefined;

    const shake128_len = try prepared.signPssShake128(
        message,
        &([_]u8{0xa2} ** 32),
        &signature,
    );
    try writeSignature(
        output_dir,
        init.io,
        "pss-shake128.sig",
        signature[0..shake128_len],
    );
    const shake256_len = try prepared.signPssShake256(
        message,
        &([_]u8{0xb2} ** 64),
        &signature,
    );
    try writeSignature(
        output_dir,
        init.io,
        "pss-shake256.sig",
        signature[0..shake256_len],
    );
}

fn writeSignature(
    dir: std.Io.Dir,
    io: std.Io,
    name: []const u8,
    signature: []const u8,
) !void {
    try dir.writeFile(io, .{ .sub_path = name, .data = signature });
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
