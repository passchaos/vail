const std = @import("std");
const vail = @import("vail");

pub fn main() !void {
    const digest = vail.crypto.sha256.hash("hello vail");
    std.debug.print("sha256={x}\n", .{digest});

    const key = [_]u8{0x42} ** vail.crypto.mac.key_len;
    const tag = vail.crypto.mac.authenticate(
        &key,
        "example",
        &.{ "hello", "vail" },
    );
    std.debug.print("tag={x}\n", .{tag});
    if (!vail.crypto.mac.verify(tag, tag)) return error.UnexpectedTag;
}
