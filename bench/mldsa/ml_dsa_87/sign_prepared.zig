const std = @import("std");
const vail = @import("vail");
const benchmark = @import("benchmark");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(
        init,
        std.crypto.sign.mldsa.MLDSA87,
        vail.crypto.mldsa.PreparedSigner87,
        "mldsa87",
    );
}
