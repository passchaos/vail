const std = @import("std");
const vail = @import("vail");
const benchmark = @import("benchmark");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(
        init,
        std.crypto.sign.mldsa.MLDSA87,
        vail.crypto.mldsa.PreparedVerifier87,
        vail.crypto.mldsa.PreparedSignature87,
        "mldsa87",
        0x87,
        vail.tls.auth.signature_scheme_ml_dsa_87,
    );
}
