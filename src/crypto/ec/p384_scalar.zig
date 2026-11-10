//! P-384 scalar arithmetic and Montgomery helpers.
//!
//! This module contains fixed-width scalar reduction, Montgomery
//! multiplication, inversion schedules, and scalar encoding used by
//! `p384.zig`.

const std = @import("std");
const builtin = @import("builtin");
const scalar_inv_x86 = @import("p384_scalar_inv_x86.zig");
const fast_sha2 = @import("../hash/sha512.zig");
const FastSha384 = fast_sha2.Sha384;
const FastSha512 = fast_sha2.Sha512;

const P384 = std.crypto.ecc.P384;
pub const Scalar = P384.scalar.Scalar;

pub const scalar_limb_count = 6;
pub const ScalarLimbs = [scalar_limb_count]u64;
pub const scalar_modulus = ScalarLimbs{
    0xecec_196a_ccc5_2973,
    0x581a_0db2_48b0_a77a,
    0xc763_4d81_f437_2ddf,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
};
pub const scalar_negative_inverse = blk: {
    var inverse: u64 = 1;
    for (0..6) |_| inverse *%= 2 -% scalar_modulus[0] *% inverse;
    break :blk 0 -% inverse;
};
pub const scalar_montgomery_r2 = ScalarLimbs{
    0x2d31_9b24_19b4_09a9,
    0xff3d_81e5_df1a_a419,
    0xbc3e_483a_fcb8_2947,
    0xd40d_4917_4aab_1cc5,
    0x3fb0_5b7a_2826_6895,
    0x0c84_ee01_2b39_bf21,
};

pub const secret_inversion_window_width = 5;
pub const secret_inversion_table_entries = 1 << (secret_inversion_window_width - 1);
pub const InversionStep = struct { squares: u9, table_index: u4 };
pub const InversionSchedule = struct {
    steps: [128]InversionStep,
    len: usize,
};
pub const inversion_schedule = buildInversionSchedule();

pub inline fn opaqueWord(value: u64) u64 {
    if (@inComptime()) return value;
    return asm volatile (""
        : [result] "=r" (-> u64),
        : [input] "0" (value),
    );
}

pub inline fn wipeCallerSavedRegisters() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        if (comptime builtin.mode != .Debug and std.Target.x86.featureSetHas(
            builtin.cpu.features,
            .avx,
        )) {
            asm volatile ("vzeroall" ::: .{
                    .xmm0 = true,
                    .xmm1 = true,
                    .xmm2 = true,
                    .xmm3 = true,
                    .xmm4 = true,
                    .xmm5 = true,
                    .xmm6 = true,
                    .xmm7 = true,
                    .xmm8 = true,
                    .xmm9 = true,
                    .xmm10 = true,
                    .xmm11 = true,
                    .xmm12 = true,
                    .xmm13 = true,
                    .xmm14 = true,
                    .xmm15 = true,
                    .memory = true,
                });
        } else {
            asm volatile (
                \\pxor %%xmm0, %%xmm0
                \\pxor %%xmm1, %%xmm1
                \\pxor %%xmm2, %%xmm2
                \\pxor %%xmm3, %%xmm3
                \\pxor %%xmm4, %%xmm4
                \\pxor %%xmm5, %%xmm5
                \\pxor %%xmm6, %%xmm6
                \\pxor %%xmm7, %%xmm7
                \\pxor %%xmm8, %%xmm8
                \\pxor %%xmm9, %%xmm9
                \\pxor %%xmm10, %%xmm10
                \\pxor %%xmm11, %%xmm11
                \\pxor %%xmm12, %%xmm12
                \\pxor %%xmm13, %%xmm13
                \\pxor %%xmm14, %%xmm14
                \\pxor %%xmm15, %%xmm15
                ::: .{
                    .xmm0 = true,
                    .xmm1 = true,
                    .xmm2 = true,
                    .xmm3 = true,
                    .xmm4 = true,
                    .xmm5 = true,
                    .xmm6 = true,
                    .xmm7 = true,
                    .xmm8 = true,
                    .xmm9 = true,
                    .xmm10 = true,
                    .xmm11 = true,
                    .xmm12 = true,
                    .xmm13 = true,
                    .xmm14 = true,
                    .xmm15 = true,
                    .memory = true,
                });
        }
        asm volatile (
            \\xorq %%rax, %%rax
            \\xorq %%rcx, %%rcx
            \\xorq %%rdx, %%rdx
            \\xorq %%rsi, %%rsi
            \\xorq %%rdi, %%rdi
            \\xorq %%r8, %%r8
            \\xorq %%r9, %%r9
            \\xorq %%r10, %%r10
            \\xorq %%r11, %%r11
            ::: .{
                .rax = true,
                .rcx = true,
                .rdx = true,
                .rsi = true,
                .rdi = true,
                .r8 = true,
                .r9 = true,
                .r10 = true,
                .r11 = true,
                .memory = true,
            });
    } else {
        asm volatile ("" ::: .{ .memory = true });
    }
}

pub noinline fn scalarMontgomeryMulAssign(
    output: *Scalar,
    a: *const Scalar,
    b: *const Scalar,
) void {
    defer wipeCallerSavedRegisters();
    var product = [_]u64{0} ** (2 * scalar_limb_count + 1);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
    inline for (0..scalar_limb_count) |row| {
        var carry: u128 = 0;
        inline for (0..scalar_limb_count) |column| {
            const index = row + column;
            const accumulated = @as(u128, a.fe.limbs[row]) *
                b.fe.limbs[column] + product[index] + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        inline for (row + scalar_limb_count..product.len) |index| {
            const accumulated = @as(u128, product[index]) + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
    }

    inline for (0..scalar_limb_count) |row| {
        const multiplier = product[row] *% scalar_negative_inverse;
        var carry: u128 = 0;
        inline for (0..scalar_limb_count) |column| {
            const index = row + column;
            const accumulated = @as(u128, multiplier) *
                scalar_modulus[column] + product[index] + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        inline for (row + scalar_limb_count..product.len) |index| {
            const accumulated = @as(u128, product[index]) + carry;
            product[index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
    }

    var reduced: ScalarLimbs = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&reduced));
    var borrow: u1 = 0;
    inline for (0..scalar_limb_count) |index| {
        const first = @subWithOverflow(
            product[scalar_limb_count + index],
            scalar_modulus[index],
        );
        const second = @subWithOverflow(first[0], borrow);
        reduced[index] = second[0];
        borrow = first[1] | second[1];
    }
    const high = @subWithOverflow(product[2 * scalar_limb_count], borrow);
    const use_reduced: u1 = high[1] ^ 1;
    const mask = opaqueWord(0 -% @as(u64, use_reduced));
    inline for (0..scalar_limb_count) |index| {
        output.fe.limbs[index] = (reduced[index] & mask) |
            (product[scalar_limb_count + index] & ~mask);
    }
}

pub fn scalarMontgomeryMul(a: Scalar, b: Scalar) Scalar {
    var result: Scalar = undefined;
    scalarMontgomeryMulAssign(&result, &a, &b);
    return result;
}

pub noinline fn scalarLimbsToMontgomeryAssign(
    output: *Scalar,
    limbs: *const ScalarLimbs,
) void {
    // The P-384 order has its high bit set, so every six-limb input is below
    // 2n and the Montgomery kernel's single final subtraction is sufficient.
    var normal = Scalar{ .fe = .{ .limbs = limbs.* } };
    defer std.crypto.secureZero(Scalar, (&normal)[0..1]);
    const r2 = Scalar{ .fe = .{ .limbs = scalar_montgomery_r2 } };
    scalarMontgomeryMulAssign(output, &normal, &r2);
}

pub noinline fn invertSecretScalarAssign(
    output: *Scalar,
    value: *const Scalar,
) void {
    defer wipeCallerSavedRegisters();
    if (comptime scalar_inv_x86.enabled) {
        var encoded = value.toBytes(.little);
        defer std.crypto.secureZero(u8, &encoded);
        var limbs = decodeScalar(encoded);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&limbs));
        var inverse = scalar_inv_x86.invert(&limbs, &scalar_modulus);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&inverse));
        var normal = Scalar{ .fe = .{ .limbs = inverse } };
        defer std.crypto.secureZero(Scalar, (&normal)[0..1]);
        const r2 = Scalar{ .fe = .{ .limbs = scalar_montgomery_r2 } };
        scalarMontgomeryMulAssign(output, &normal, &r2);
        return;
    }
    var powers: [secret_inversion_table_entries]Scalar = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&powers));
    powers[0] = value.*;
    var squared: Scalar = undefined;
    scalarMontgomeryMulAssign(&squared, value, value);
    defer std.crypto.secureZero(Scalar, (&squared)[0..1]);
    for (1..secret_inversion_table_entries) |index| {
        scalarMontgomeryMulAssign(
            &powers[index],
            &powers[index - 1],
            &squared,
        );
    }

    var result = Scalar.one;
    defer std.crypto.secureZero(Scalar, (&result)[0..1]);
    inline for (inversion_schedule.steps[0..inversion_schedule.len]) |step| {
        inline for (0..step.squares) |_| {
            scalarMontgomeryMulAssign(&result, &result, &result);
        }
        scalarMontgomeryMulAssign(
            &result,
            &result,
            &powers[step.table_index],
        );
    }
    output.* = result;
}

pub fn invertSecretScalar(value: Scalar) Scalar {
    var result: Scalar = undefined;
    invertSecretScalarAssign(&result, &value);
    return result;
}

pub fn scalarBit(value: ScalarLimbs, index: usize) bool {
    return ((value[index / 64] >> @intCast(index % 64)) & 1) != 0;
}

pub fn buildInversionSchedule() InversionSchedule {
    @setEvalBranchQuota(100_000);
    const exponent = scalarSubRaw(
        scalar_modulus,
        .{ 2, 0, 0, 0, 0, 0 },
    ).value;
    var schedule = InversionSchedule{ .steps = undefined, .len = 0 };
    var pending_squares: usize = 0;
    var bit_end: usize = 384;
    while (bit_end != 0) {
        if (!scalarBit(exponent, bit_end - 1)) {
            pending_squares += 1;
            bit_end -= 1;
            continue;
        }
        var bit_start = bit_end - @min(bit_end, secret_inversion_window_width);
        while (!scalarBit(exponent, bit_start)) bit_start += 1;
        var window_value: u5 = 0;
        var bit_index = bit_end;
        while (bit_index != bit_start) {
            bit_index -= 1;
            window_value = (window_value << 1) |
                @as(u1, @intFromBool(scalarBit(exponent, bit_index)));
        }
        pending_squares += bit_end - bit_start;
        schedule.steps[schedule.len] = .{
            .squares = @intCast(pending_squares),
            .table_index = @truncate(window_value >> 1),
        };
        schedule.len += 1;
        pending_squares = 0;
        bit_end = bit_start;
    }
    std.debug.assert(pending_squares == 0);
    return schedule;
}

pub inline fn hashMessage(
    comptime Hash: type,
    message: []const u8,
    digest: *[Hash.digest_length]u8,
) void {
    if (comptime Hash == std.crypto.hash.sha2.Sha384) {
        FastSha384.hash(message, digest, .{});
    } else if (comptime Hash == std.crypto.hash.sha2.Sha512) {
        FastSha512.hash(message, digest, .{});
    } else {
        Hash.hash(message, digest, .{});
    }
}

pub fn invertPublicScalar(value: Scalar) Scalar {
    std.debug.assert(!value.isZero());
    var first = decodeScalar(value.toBytes(.little));
    var second = scalar_modulus;
    var first_coefficient = scalarOne();
    var second_coefficient = [_]u64{0} ** scalar_limb_count;
    while (!scalarEqual(first, scalarOne()) and
        !scalarEqual(second, scalarOne()))
    {
        if ((first[0] & 1) == 0) {
            const shift = scalarTrailingZeroBits(first);
            first = scalarShiftRightBits(first, shift);
            first_coefficient = scalarDividePowerOfTwo(
                first_coefficient,
                shift,
            );
        }
        if ((second[0] & 1) == 0) {
            const shift = scalarTrailingZeroBits(second);
            second = scalarShiftRightBits(second, shift);
            second_coefficient = scalarDividePowerOfTwo(
                second_coefficient,
                shift,
            );
        }
        if (!scalarLessThan(first, second)) {
            first = scalarSubRaw(first, second).value;
            first_coefficient = scalarSubModulo(
                first_coefficient,
                second_coefficient,
            );
        } else {
            second = scalarSubRaw(second, first).value;
            second_coefficient = scalarSubModulo(
                second_coefficient,
                first_coefficient,
            );
        }
    }
    const inverse = if (scalarEqual(first, scalarOne()))
        first_coefficient
    else
        second_coefficient;
    return Scalar.fromBytes(encodeScalar(inverse), .little) catch unreachable;
}

pub const ScalarAddResult = struct { value: ScalarLimbs, carry: u1 };
pub const ScalarSubResult = struct { value: ScalarLimbs, borrow: u1 };

pub inline fn scalarAddRaw(a: ScalarLimbs, b: ScalarLimbs) ScalarAddResult {
    var result: ScalarLimbs = undefined;
    var carry: u1 = 0;
    inline for (0..scalar_limb_count) |index| {
        const first = @addWithOverflow(a[index], b[index]);
        const second = @addWithOverflow(first[0], carry);
        result[index] = second[0];
        carry = first[1] | second[1];
    }
    return .{ .value = result, .carry = carry };
}

pub inline fn scalarSubRaw(a: ScalarLimbs, b: ScalarLimbs) ScalarSubResult {
    var result: ScalarLimbs = undefined;
    var borrow: u1 = 0;
    inline for (0..scalar_limb_count) |index| {
        const first = @subWithOverflow(a[index], b[index]);
        const second = @subWithOverflow(first[0], borrow);
        result[index] = second[0];
        borrow = first[1] | second[1];
    }
    return .{ .value = result, .borrow = borrow };
}

pub fn scalarShiftRightBits(value: ScalarLimbs, shift: u7) ScalarLimbs {
    var result: ScalarLimbs = undefined;
    if (shift == 64) {
        for (0..scalar_limb_count - 1) |index| result[index] = value[index + 1];
        result[scalar_limb_count - 1] = 0;
        return result;
    }
    const low_shift: u6 = @intCast(shift);
    const high_shift: u6 = @intCast(64 - shift);
    for (0..scalar_limb_count - 1) |index| {
        result[index] = (value[index] >> low_shift) |
            (value[index + 1] << high_shift);
    }
    result[scalar_limb_count - 1] =
        value[scalar_limb_count - 1] >> low_shift;
    return result;
}

pub fn scalarDividePowerOfTwo(value: ScalarLimbs, shift: u7) ScalarLimbs {
    const mask = if (shift == 64)
        std.math.maxInt(u64)
    else
        (@as(u64, 1) << @as(u6, @intCast(shift))) - 1;
    const multiplier = value[0] *% scalar_negative_inverse & mask;
    var sum: [scalar_limb_count + 1]u64 = undefined;
    var carry: u128 = 0;
    inline for (0..scalar_limb_count) |index| {
        const accumulated = @as(u128, scalar_modulus[index]) * multiplier +
            value[index] + carry;
        sum[index] = @truncate(accumulated);
        carry = accumulated >> 64;
    }
    sum[scalar_limb_count] = @truncate(carry);

    var result: ScalarLimbs = undefined;
    if (shift == 64) {
        @memcpy(&result, sum[1..]);
    } else {
        const low_shift: u6 = @intCast(shift);
        const high_shift: u6 = @intCast(64 - shift);
        inline for (0..scalar_limb_count) |index| {
            result[index] = (sum[index] >> low_shift) |
                (sum[index + 1] << high_shift);
        }
    }
    return result;
}

pub inline fn scalarSubModulo(a: ScalarLimbs, b: ScalarLimbs) ScalarLimbs {
    const difference = scalarSubRaw(a, b);
    if (difference.borrow == 0) return difference.value;
    return scalarAddRaw(difference.value, scalar_modulus).value;
}

pub fn scalarTrailingZeroBits(value: ScalarLimbs) u7 {
    return if (value[0] == 0) 64 else @ctz(value[0]);
}

pub fn scalarLessThan(a: ScalarLimbs, b: ScalarLimbs) bool {
    var index: usize = scalar_limb_count;
    while (index != 0) {
        index -= 1;
        if (a[index] != b[index]) return a[index] < b[index];
    }
    return false;
}

pub fn scalarEqual(a: ScalarLimbs, b: ScalarLimbs) bool {
    var difference: u64 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

pub fn scalarOne() ScalarLimbs {
    return .{ 1, 0, 0, 0, 0, 0 };
}

pub fn decodeScalar(encoded: [48]u8) ScalarLimbs {
    var result: ScalarLimbs = undefined;
    inline for (0..scalar_limb_count) |index| {
        result[index] = std.mem.readInt(
            u64,
            encoded[index * 8 ..][0..8],
            .little,
        );
    }
    return result;
}

pub fn encodeScalar(value: ScalarLimbs) [48]u8 {
    var result: [48]u8 = undefined;
    inline for (0..scalar_limb_count) |index| {
        std.mem.writeInt(
            u64,
            result[index * 8 ..][0..8],
            value[index],
            .little,
        );
    }
    return result;
}

pub fn scalarFromDigest(
    comptime Hash: type,
    digest: [Hash.digest_length]u8,
) Scalar {
    const scalar_len = P384.scalar.encoded_length;
    const padded_len = @max(Hash.digest_length, scalar_len);
    const padded = [_]u8{0} ** (padded_len - Hash.digest_length) ++ digest;
    var limbs: ScalarLimbs = undefined;
    inline for (0..scalar_limb_count) |index| {
        limbs[scalar_limb_count - 1 - index] = std.mem.readInt(
            u64,
            padded[index * 8 ..][0..8],
            .big,
        );
    }
    var result: Scalar = undefined;
    scalarLimbsToMontgomeryAssign(&result, &limbs);
    return result;
}
