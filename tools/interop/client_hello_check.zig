const std = @import("std");
const vail = @import("vail");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer it.deinit();
    const exe = it.next() orelse "client_hello_check";
    const hex_path = it.next() orelse {
        std.debug.print("usage: {s} <hex-file> <server-name> <cipher-hex>\n", .{exe});
        return error.InvalidArgs;
    };
    const expected_name = it.next() orelse return error.InvalidArgs;
    const expected_cipher_text = it.next() orelse return error.InvalidArgs;
    const hex = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        hex_path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(hex);
    var compact = std.ArrayList(u8).empty;
    defer compact.deinit(allocator);
    for (hex) |byte| {
        if (std.ascii.isHex(byte)) try compact.append(allocator, byte);
    }
    if (compact.items.len % 2 != 0) return error.InvalidHex;
    const hello = try allocator.alloc(u8, compact.items.len / 2);
    defer allocator.free(hello);
    _ = try std.fmt.hexToBytes(hello, compact.items);
    const parsed = try vail.tls.client_hello.parse(hello);
    if (!parsed.offersTls13()) return error.NoTls13;
    if (parsed.server_name == null or
        !std.mem.eql(u8, parsed.server_name.?, expected_name))
    {
        return error.BadServerName;
    }
    const expected_cipher = try std.fmt.parseInt(u16, expected_cipher_text, 16);
    if (!parsed.hasCipherSuite(expected_cipher)) return error.MissingCipher;
    const share = (try parsed.firstKeyShare()) orelse return error.MissingShare;
    if (share.key_exchange.len == 0) return error.EmptyShare;
    std.debug.print(
        "clienthello ok: sni={s} cipher=0x{x} first_group=0x{x} share_len={d}\n",
        .{ parsed.server_name.?, expected_cipher, share.group, share.key_exchange.len },
    );
}
