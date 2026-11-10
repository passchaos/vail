const std = @import("std");
const vail = @import("vail");

pub fn main() !void {
    const key = [_]u8{0x42} ** vail.crypto.mac.key_len;
    const tag = vail.crypto.mac.authenticate(
        &key,
        "example",
        &.{ "hello", "vail" },
    );
    if (!vail.crypto.mac.verify(tag, tag)) return error.UnexpectedTag;
    std.debug.print("tag={x}\n", .{tag});
}
