const std = @import("std");
const benchmark = @import("keygen_common.zig");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(init, .zig_std);
}
