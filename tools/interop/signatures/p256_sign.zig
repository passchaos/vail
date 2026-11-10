const std = @import("std");
const vail = @import("vail");

const Hash = std.crypto.hash.sha2.Sha256;
const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const message = "pure Zig P-256 signing oracle";

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const output_path = args.next() orelse return error.MissingOutputPath;
    if (args.next() != null) return error.InvalidArguments;

    const key_pair = try Scheme.KeyPair.generateDeterministic(
        [_]u8{0x82} ** Scheme.KeyPair.seed_length,
    );
    const noise = [_]u8{0x37} ** Scheme.noise_length;
    const signature = try vail.crypto.p256.sign(
        Hash,
        key_pair,
        message,
        noise,
    );
    var signature_der: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
    const encoded_signature = signature.toDer(&signature_der);

    const public_key = key_pair.public_key.toUncompressedSec1();
    const spki_header = [_]u8{
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07,
        0x2a, 0x86,
        0x48, 0xce,
        0x3d, 0x02,
        0x01, 0x06,
        0x08, 0x2a,
        0x86, 0x48,
        0xce, 0x3d,
        0x03, 0x01,
        0x07, 0x03,
        0x42, 0x00,
    };
    const spki = spki_header ++ public_key;

    var output_dir = try std.Io.Dir.openDirAbsolute(
        init.io,
        output_path,
        .{},
    );
    defer output_dir.close(init.io);
    try output_dir.writeFile(init.io, .{
        .sub_path = "signature.der",
        .data = encoded_signature,
    });
    try output_dir.writeFile(init.io, .{
        .sub_path = "public.der",
        .data = &spki,
    });
    try output_dir.writeFile(init.io, .{
        .sub_path = "message.bin",
        .data = message,
    });
}
