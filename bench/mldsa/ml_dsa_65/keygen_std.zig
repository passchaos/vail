const std = @import("std");
const benchmark = @import("benchmark");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(init, std.crypto.sign.mldsa.MLDSA65, "mldsa65");
}
