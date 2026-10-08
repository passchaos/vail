const std = @import("std");
const vail = @import("vail");
const benchmark = @import("benchmark");

pub fn main(init: std.process.Init) !void {
    return benchmark.run(
        init,
        std.crypto.sign.mldsa.MLDSA65,
        vail.crypto.mldsa.PreparedVerifier65,
        vail.crypto.mldsa.PreparedSignature65,
        "mldsa65",
        0x65,
        vail.tls.auth.signature_scheme_ml_dsa_65,
    );
}
