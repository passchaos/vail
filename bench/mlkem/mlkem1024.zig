const std = @import("std");
const vail = @import("vail");
const benchmark = @import("benchmark");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(init, vail.crypto.mlkem.nist.MLKem1024, "mlkem1024");
}
