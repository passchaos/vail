const std = @import("std");
const benchmark = @import("sign_common.zig");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(init, .prepared);
}
