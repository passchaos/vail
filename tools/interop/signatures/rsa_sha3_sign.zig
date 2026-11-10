const std = @import("std");
const vail = @import("vail");

const message = "Vail pure Zig RSA SHA3 signing oracle";

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const output_path = args.next() orelse return error.MissingOutputPath;
    if (args.next() != null) return error.InvalidArguments;

    const vectors = vail.testdata.crypto.rsa_signing;
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

    const pss224 = try prepared.signPssSha3_224(
        message,
        &([_]u8{0x52} ** 28),
        &signature,
    );
    try writeSignature(output_dir, init.io, "pss-sha3-224.sig", signature[0..pss224]);
    const pss256 = try prepared.signPssSha3_256(
        message,
        &([_]u8{0x62} ** 32),
        &signature,
    );
    try writeSignature(output_dir, init.io, "pss-sha3-256.sig", signature[0..pss256]);
    const pss384 = try prepared.signPssSha3_384(
        message,
        &([_]u8{0x72} ** 48),
        &signature,
    );
    try writeSignature(output_dir, init.io, "pss-sha3-384.sig", signature[0..pss384]);
    const pss512 = try prepared.signPssSha3_512(
        message,
        &([_]u8{0x82} ** 64),
        &signature,
    );
    try writeSignature(output_dir, init.io, "pss-sha3-512.sig", signature[0..pss512]);

    const pkcs224 = try prepared.signPkcs1v15Sha3_224(message, &signature);
    try writeSignature(output_dir, init.io, "pkcs1-sha3-224.sig", signature[0..pkcs224]);
    const pkcs256 = try prepared.signPkcs1v15Sha3_256(message, &signature);
    try writeSignature(output_dir, init.io, "pkcs1-sha3-256.sig", signature[0..pkcs256]);
    const pkcs384 = try prepared.signPkcs1v15Sha3_384(message, &signature);
    try writeSignature(output_dir, init.io, "pkcs1-sha3-384.sig", signature[0..pkcs384]);
    const pkcs512 = try prepared.signPkcs1v15Sha3_512(message, &signature);
    try writeSignature(output_dir, init.io, "pkcs1-sha3-512.sig", signature[0..pkcs512]);
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
