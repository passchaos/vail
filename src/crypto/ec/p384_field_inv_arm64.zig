//! Constant-time ARM64 P-384 Montgomery field inversion.
//!
//! The instruction schedule comes from the formally verified s2n-bignum
//! implementation. Input and output use the same six-limb Montgomery
//! representation as `p384.zig`.

const builtin = @import("builtin");
const asm_compat = @import("../asm_compat.zig");

pub const enabled = asm_compat.arm64_native and
    (builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSafe);

pub fn invert(input: *const [6]u64) [6]u64 {
    if (comptime !enabled) {
        @compileError("ARM64 P-384 inversion is unavailable");
    }
    var output: [6]u64 = undefined;
    vailP384FieldInvertArm64(&output, input);
    return output;
}

extern fn vailP384FieldInvertArm64(
    output: *[6]u64,
    input: *const [6]u64,
) callconv(.c) void;

const transformed = asm_compat.arm64(@embedFile("p384_montinv_arm64.S"));

comptime {
    if (enabled) asm (transformed.bytes[0..transformed.len]);
}
