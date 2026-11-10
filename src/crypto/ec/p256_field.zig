//! P-256 field arithmetic.
//!
//! This module contains the Montgomery multiplication, reduction, addition,
//! doubling, squaring, and secret inversion helpers used by `p256.zig`.

const std = @import("std");
const builtin = @import("builtin");
const field_arm64 = @import("p256_field_arm64.zig");
const field_inv_x86 = @import("p256_field_inv_x86.zig");

const P256 = std.crypto.ecc.P256;
pub const Fe = P256.Fe;

pub const field_modulus = [4]u64{
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
};

pub const use_x86_64_adx_field = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

pub inline fn opaqueWord(value: u64) u64 {
    if (@inComptime()) return value;
    return asm volatile (""
        : [result] "=r" (-> u64),
        : [input] "0" (value),
    );
}

pub fn fieldMul(a: Fe, b: Fe) Fe {
    if (comptime use_x86_64_adx_field) {
        var result: [4]u64 = undefined;
        vailP256MontgomeryMul(
            &result,
            &a.limbs,
            &b.limbs,
            &field_modulus,
        );
        return .{ .limbs = result };
    }
    if (comptime field_arm64.enabled) {
        var result: [4]u64 = undefined;
        field_arm64.mul(&result, &a.limbs, &b.limbs);
        return .{ .limbs = result };
    }
    return fieldMulPortable(a, b);
}

pub fn fieldMulPortable(a: Fe, b: Fe) Fe {
    var product = [_]u64{0} ** 9;
    inline for (0..4) |left| {
        var carry: u128 = 0;
        inline for (0..4) |right| {
            const accumulated = @as(u128, a.limbs[left]) * b.limbs[right] +
                product[left + right] + carry;
            product[left + right] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        product[left + 4] = @truncate(carry);
    }
    return fieldMontgomeryReduce(product);
}

pub fn fieldMontgomeryReduce(product_input: [9]u64) Fe {
    var product = product_input;
    // Montgomery reduction uses -p^-1 = 1 mod 2^64 because p[0] = -1.
    inline for (0..4) |round| {
        const factor = product[round];
        var carry: u128 = 0;
        inline for (0..4) |index| {
            const accumulated = @as(u128, factor) * field_modulus[index] +
                product[round + index] + carry;
            product[round + index] = @truncate(accumulated);
            carry = accumulated >> 64;
        }
        var sum = @addWithOverflow(
            product[round + 4],
            @as(u64, @truncate(carry)),
        );
        product[round + 4] = sum[0];
        var propagation = sum[1];
        inline for (round + 5..9) |index| {
            sum = @addWithOverflow(product[index], @as(u64, propagation));
            product[index] = sum[0];
            propagation = sum[1];
        }
        std.debug.assert(propagation == 0);
    }

    const unreduced = [4]u64{
        product[4],
        product[5],
        product[6],
        product[7],
    };
    var reduced: [4]u64 = undefined;
    var borrow: u1 = 0;
    inline for (0..4) |index| {
        const first = @subWithOverflow(unreduced[index], field_modulus[index]);
        const second = @subWithOverflow(first[0], borrow);
        reduced[index] = second[0];
        borrow = first[1] | second[1];
    }
    const high = @subWithOverflow(product[8], @as(u64, borrow));
    const keep_unreduced = 0 -% @as(u64, high[1]);
    inline for (0..4) |index| {
        reduced[index] = (unreduced[index] & keep_unreduced) |
            (reduced[index] & ~keep_unreduced);
    }
    return .{ .limbs = reduced };
}

extern fn vailP256MontgomeryMul(
    output: *[4]u64,
    a: *const [4]u64,
    b: *const [4]u64,
    modulus: *const [4]u64,
) callconv(.c) void;

extern fn vailP256MontgomerySquare(
    output: *[4]u64,
    value: *const [4]u64,
    modulus: *const [4]u64,
) callconv(.c) void;

comptime {
    if (use_x86_64_adx_field) {
        asm (
            \\.text
            \\.macro vail_p256_product_row multiplicand, product, shift
            \\movq 0+\shift(\product), %r8
            \\xorl %eax, %eax
            \\mulxq 0(\multiplicand), %r9, %r10
            \\adcxq %r8, %r9
            \\movq %r9, 0+\shift(\product)
            \\movq 8+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\mulxq 8(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 8+\shift(\product)
            \\movq 16+\shift(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq 16(\multiplicand), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, 16+\shift(\product)
            \\movq 24+\shift(\product), %r8
            \\adoxq %r8, %r10
            \\mulxq 24(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 24+\shift(\product)
            \\adoxq %rax, %r11
            \\adcxq %rax, %r11
            \\addq %r11, 32+\shift(\product)
            \\adcq $0, 40+\shift(\product)
            \\.endm
            \\
            \\.macro vail_p256_reduce_row product, shift, modulus
            \\movq 0+\shift(\product), %rdx
            \\movq %rdx, %r10
            \\shlq $32, %r10
            \\movq %rdx, %r11
            \\shrq $32, %r11
            \\addq 8+\shift(\product), %r10
            \\adcq $0, %r11
            \\movq %r10, 8+\shift(\product)
            \\movq 16+\shift(\product), %r10
            \\addq %r11, %r10
            \\movq $0, %r8
            \\adcq $0, %r8
            \\movq %r10, 16+\shift(\product)
            \\mulxq 24(\modulus), %r10, %r11
            \\addq 24+\shift(\product), %r10
            \\adcq $0, %r11
            \\addq %r8, %r10
            \\adcq $0, %r11
            \\movq %r10, 24+\shift(\product)
            \\addq %r11, 32+\shift(\product)
            \\adcq %rdi, 40+\shift(\product)
            \\setc %dil
            \\.endm
            \\
            \\.macro vail_p256_square_term left, right, twice
            \\movq \left(%r13), %rdx
            \\mulxq \right(%r13), %r8, %r9
            \\addq %r8, %r10
            \\adcq %r9, %r11
            \\adcq $0, %r12
            \\.if \twice
            \\addq %r8, %r10
            \\adcq %r9, %r11
            \\adcq $0, %r12
            \\.endif
            \\.endm
            \\
            \\.macro vail_p256_square_limb offset
            \\movq %r10, \offset(%rsp)
            \\movq %r11, %r10
            \\movq %r12, %r11
            \\xorl %r12d, %r12d
            \\.endm
            \\
            \\.p2align 5
            \\.globl vailP256MontgomeryMul
            \\.hidden vailP256MontgomeryMul
            \\.type vailP256MontgomeryMul,@function
            \\vailP256MontgomeryMul:
            \\pushq %rbx
            \\pushq %rbp
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\subq $80, %rsp
            \\movq %rdi, %r12
            \\movq %rsi, %r13
            \\movq %rdx, %rbx
            \\movq %rcx, %r14
            \\vpxor %ymm0, %ymm0, %ymm0
            \\vmovdqu %ymm0, 0(%rsp)
            \\vmovdqu %ymm0, 32(%rsp)
            \\movq $0, 64(%rsp)
            \\.irp outer, 0, 1, 2, 3
            \\movq 8*\outer(%rbx), %rdx
            \\vail_p256_product_row %r13, %rsp, 8*\outer
            \\.endr
            \\
            \\xorl %edi, %edi
            \\.irp outer, 0, 1, 2, 3
            \\vail_p256_reduce_row %rsp, 8*\outer, %r14
            \\.endr
            \\
            \\clc
            \\.irp offset, 0, 8, 16, 24
            \\movq 32+\offset(%rsp), %r8
            \\sbbq \offset(%r14), %r8
            \\movq %r8, \offset(%r12)
            \\.endr
            \\sbbq %r8, %r8
            \\movq 64(%rsp), %r9
            \\negq %r9
            \\sbbq %r9, %r9
            \\notq %r9
            \\andq %r9, %r8
            \\testq %r8, %r8
            \\.irp offset, 0, 8, 16, 24
            \\movq \offset(%r12), %r9
            \\cmovneq 32+\offset(%rsp), %r9
            \\movq %r9, \offset(%r12)
            \\.endr
            \\
            \\vzeroupper
            \\addq $80, %rsp
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbp
            \\popq %rbx
            \\retq
            \\.size vailP256MontgomeryMul, .-vailP256MontgomeryMul
            \\
            \\.p2align 5
            \\.globl vailP256MontgomerySquare
            \\.hidden vailP256MontgomerySquare
            \\.type vailP256MontgomerySquare,@function
            \\vailP256MontgomerySquare:
            \\pushq %rbx
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\subq $80, %rsp
            \\movq %rdi, %rbx
            \\movq %rsi, %r13
            \\movq %rdx, %r14
            \\xorl %r10d, %r10d
            \\xorl %r11d, %r11d
            \\xorl %r12d, %r12d
            \\vail_p256_square_term 0, 0, 0
            \\vail_p256_square_limb 0
            \\vail_p256_square_term 0, 8, 1
            \\vail_p256_square_limb 8
            \\vail_p256_square_term 0, 16, 1
            \\vail_p256_square_term 8, 8, 0
            \\vail_p256_square_limb 16
            \\vail_p256_square_term 0, 24, 1
            \\vail_p256_square_term 8, 16, 1
            \\vail_p256_square_limb 24
            \\vail_p256_square_term 8, 24, 1
            \\vail_p256_square_term 16, 16, 0
            \\vail_p256_square_limb 32
            \\vail_p256_square_term 16, 24, 1
            \\vail_p256_square_limb 40
            \\vail_p256_square_term 24, 24, 0
            \\movq %r10, 48(%rsp)
            \\movq %r11, 56(%rsp)
            \\movq %r12, 64(%rsp)
            \\
            \\xorl %edi, %edi
            \\.irp outer, 0, 1, 2, 3
            \\vail_p256_reduce_row %rsp, 8*\outer, %r14
            \\.endr
            \\
            \\clc
            \\.irp offset, 0, 8, 16, 24
            \\movq 32+\offset(%rsp), %r8
            \\sbbq \offset(%r14), %r8
            \\movq %r8, \offset(%rbx)
            \\.endr
            \\sbbq %r8, %r8
            \\movq 64(%rsp), %r9
            \\negq %r9
            \\sbbq %r9, %r9
            \\notq %r9
            \\andq %r9, %r8
            \\testq %r8, %r8
            \\.irp offset, 0, 8, 16, 24
            \\movq \offset(%rbx), %r9
            \\cmovneq 32+\offset(%rsp), %r9
            \\movq %r9, \offset(%rbx)
            \\.endr
            \\
            \\addq $80, %rsp
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbx
            \\retq
            \\.size vailP256MontgomerySquare, .-vailP256MontgomerySquare
            \\.purgem vail_p256_product_row
            \\.purgem vail_p256_reduce_row
            \\.purgem vail_p256_square_term
            \\.purgem vail_p256_square_limb
        );
    }
}

pub inline fn fieldAdd(a: Fe, b: Fe) Fe {
    var sum: [4]u64 = undefined;
    var carry: u1 = 0;
    inline for (0..4) |index| {
        const first = @addWithOverflow(a.limbs[index], b.limbs[index]);
        const second = @addWithOverflow(first[0], carry);
        sum[index] = second[0];
        carry = first[1] | second[1];
    }

    var reduced: [4]u64 = undefined;
    var borrow: u1 = 0;
    inline for (0..4) |index| {
        const first = @subWithOverflow(sum[index], field_modulus[index]);
        const second = @subWithOverflow(first[0], borrow);
        reduced[index] = second[0];
        borrow = first[1] | second[1];
    }
    const high = @subWithOverflow(@as(u64, carry), @as(u64, borrow));
    const keep_sum = 0 -% @as(u64, high[1]);
    inline for (0..4) |index| {
        reduced[index] = (sum[index] & keep_sum) |
            (reduced[index] & ~keep_sum);
    }
    return .{ .limbs = reduced };
}

pub inline fn fieldDouble(value: Fe) Fe {
    return fieldAdd(value, value);
}

pub inline fn fieldSquare(value: Fe) Fe {
    if (comptime use_x86_64_adx_field) {
        var result: [4]u64 = undefined;
        vailP256MontgomerySquare(
            &result,
            &value.limbs,
            &field_modulus,
        );
        return .{ .limbs = result };
    }
    if (comptime field_arm64.enabled) {
        var result: [4]u64 = undefined;
        field_arm64.square(&result, &value.limbs);
        return .{ .limbs = result };
    }
    return fieldMul(value, value);
}

pub fn invertSecretField(value: Fe) Fe {
    if (comptime field_inv_x86.enabled) {
        return .{ .limbs = field_inv_x86.invert(&value.limbs) };
    }
    return value.invert();
}
