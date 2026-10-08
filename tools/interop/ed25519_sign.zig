const std = @import("std");
const vail = @import("vail");

const message = "Vail pure Zig Ed25519 signing oracle";

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const output_path = args.next() orelse return error.MissingOutputPath;
    if (args.next() != null) return error.InvalidArguments;

    const seed = [_]u8{0x42} ** std.crypto.sign.Ed25519.KeyPair.seed_length;
    const key_pair = try vail.crypto.ed25519.generateKeyPairDeterministic(seed);
    const signature = try vail.crypto.ed25519.sign(key_pair, message, null);
    const spki_header = [_]u8{
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03,
        0x2b, 0x65,
        0x70, 0x03,
        0x21, 0x00,
    };
    const spki = spki_header ++ key_pair.public_key.toBytes();
    const signature_bytes = signature.toBytes();

    var output_dir = try std.Io.Dir.openDirAbsolute(
        init.io,
        output_path,
        .{},
    );
    defer output_dir.close(init.io);
    try output_dir.writeFile(init.io, .{
        .sub_path = "public.der",
        .data = &spki,
    });
    try output_dir.writeFile(init.io, .{
        .sub_path = "signature.bin",
        .data = &signature_bytes,
    });
    try output_dir.writeFile(init.io, .{
        .sub_path = "message.bin",
        .data = message,
    });
}
