const std = @import("std");
const vail = @import("vail");

const message = "pure Zig P-521 signing oracle";

pub fn main(init: std.process.Init) !void {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const output_path = args.next() orelse return error.MissingOutputPath;
    const private_key_hex = args.next();
    if (args.next() != null) return error.InvalidArguments;

    var fixed_private_key = decodeHex(
        "3081dc020101044200123456789abcdef00112233445566778899aabbccddeeff10" ++
            "2132435465768798a9bacbdcedfe0f112233445566778899aabbccddeeff001234" ++
            "56789abcdef1234a00706052b81040023a1818903818600040105107ef0224c556" ++
            "44f85f04a2ba93a356752ceafe7524d9a054ff9d2a3d45f351af52eec561f617" ++
            "80dbd8984573e5b88705c86af5b384048c4b754e6c43100b1700194b4626848b" ++
            "166a7b0bbc38b903582c1cd4648637800c308b03327a1d6302c4f2f960f1a8ee" ++
            "ca948bbe0b750a7f1c201422e535fdf4e74ec8693be07883ea8c008",
    );
    defer std.crypto.secureZero(u8, &fixed_private_key);
    const nonce = decodeHex(
        "000deadbeefcafebabefeedface0123456789abcdef102030405060708090a0b0" ++
            "c0d0e0f00112233445566778899aabbccddeeff13579bdf2468ace00123456789ab",
    );
    var external_private_key: ?[]u8 = null;
    defer if (external_private_key) |bytes| {
        std.crypto.secureZero(u8, bytes);
        init.gpa.free(bytes);
    };
    const private_key = if (private_key_hex) |hex| blk: {
        if (hex.len == 0 or hex.len % 2 != 0) return error.InvalidArguments;
        const bytes = try init.gpa.alloc(u8, hex.len / 2);
        external_private_key = bytes;
        _ = std.fmt.hexToBytes(bytes, hex) catch
            return error.InvalidArguments;
        break :blk bytes;
    } else &fixed_private_key;
    var key_pair = try vail.crypto.p521.KeyPair.fromDer(private_key);
    defer key_pair.deinit();
    const signature = try key_pair.sign(
        std.crypto.hash.sha2.Sha512,
        message,
        &nonce,
    );
    var signature_der: [vail.crypto.p521.Signature.der_encoded_length_max]u8 =
        undefined;
    const encoded_signature = signature.toDer(&signature_der);

    const public_key = key_pair.public_key.toUncompressedSec1();
    const spki_header = [_]u8{
        0x30, 0x81, 0x9b,
        0x30, 0x10, 0x06,
        0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06,
        0x05, 0x2b, 0x81,
        0x04, 0x00, 0x23,
        0x03, 0x81, 0x86,
        0x00,
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

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
