const std = @import("std");
const benchmark = @import("prepared_common.zig");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(init, .cached_t1_ntt);
}
