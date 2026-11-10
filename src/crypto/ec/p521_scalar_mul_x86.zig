//! Constant-time x86_64 ADX P-521 Jacobian scalar multiplication.
//!
//! The instruction schedule comes from the formally verified s2n-bignum
//! implementation.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

const use_avx2_table_select = enabled and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

const table_select_asm = if (use_avx2_table_select)
    \\        .macro VAIL_P521_SELECT_AVX out, done
    \\        vpxor %ymm0, %ymm0, %ymm0
    \\        vpxor %ymm1, %ymm1, %ymm1
    \\        vpxor %ymm2, %ymm2, %ymm2
    \\        vpxor %ymm3, %ymm3, %ymm3
    \\        vpxor %ymm4, %ymm4, %ymm4
    \\        vpxor %ymm5, %ymm5, %ymm5
    \\        vpxor %ymm10, %ymm10, %ymm10
    \\        vpxor %ymm11, %ymm11, %ymm11
    \\        vmovq %rdi, %xmm6
    \\        vpbroadcastq %xmm6, %ymm6
    \\        movl $1, %eax
    \\        vmovq %rax, %xmm7
    \\        vpbroadcastq %xmm7, %ymm7
    \\        vmovdqa %ymm7, %ymm8
    \\        leaq (7*72)(%rsp), %rax
    \\        .rept 16
    \\        vpcmpeqq %ymm7, %ymm6, %ymm9
    \\        vpand 0(%rax), %ymm9, %ymm12
    \\        vpor %ymm12, %ymm0, %ymm0
    \\        vpand 32(%rax), %ymm9, %ymm12
    \\        vpor %ymm12, %ymm1, %ymm1
    \\        vpand 64(%rax), %ymm9, %ymm12
    \\        vpor %ymm12, %ymm2, %ymm2
    \\        vpand 96(%rax), %ymm9, %ymm12
    \\        vpor %ymm12, %ymm3, %ymm3
    \\        vpand 128(%rax), %ymm9, %ymm12
    \\        vpor %ymm12, %ymm4, %ymm4
    \\        vpand 160(%rax), %ymm9, %ymm12
    \\        vpor %ymm12, %ymm5, %ymm5
    \\        vpand 192(%rax), %xmm9, %xmm12
    \\        vpor %xmm12, %xmm10, %xmm10
    \\        vmovq 208(%rax), %xmm12
    \\        vpand %xmm9, %xmm12, %xmm12
    \\        vpor %xmm12, %xmm11, %xmm11
    \\        addq $3*72, %rax
    \\        vpaddq %ymm8, %ymm7, %ymm7
    \\        .endr
    \\        vmovdqu %ymm0, \out(%rsp)
    \\        vmovdqu %ymm1, \out+32(%rsp)
    \\        vmovdqu %ymm2, \out+64(%rsp)
    \\        vmovdqu %ymm3, \out+96(%rsp)
    \\        vmovdqu %ymm4, \out+128(%rsp)
    \\        vmovdqu %ymm5, \out+160(%rsp)
    \\        vmovdqu %xmm10, \out+192(%rsp)
    \\        vmovq %xmm11, \out+208(%rsp)
    \\        vpextrq $1, %xmm2, %rax
    \\        vextracti128 $1, %ymm2, %xmm12
    \\        vmovq %xmm12, %rbx
    \\        vpextrq $1, %xmm12, %rcx
    \\        vmovq %xmm3, %rdx
    \\        vpextrq $1, %xmm3, %r8
    \\        vextracti128 $1, %ymm3, %xmm12
    \\        vmovq %xmm12, %r9
    \\        vpextrq $1, %xmm12, %r10
    \\        vmovq %xmm4, %r11
    \\        vpextrq $1, %xmm4, %r12
    \\        jmp \done
    \\        .endm
    \\        .macro VAIL_P521_CLEAR_AVX
    \\        vzeroall
    \\        .endm
else
    \\        .macro VAIL_P521_SELECT_AVX out, done
    \\        .endm
    \\        .macro VAIL_P521_CLEAR_AVX
    \\        .endm
;

/// The three input coordinates must be canonical P-521 field elements.
pub fn scalarMultCanonicalPoint(
    output: *[27]u64,
    scalar: *const [9]u64,
    point: *const [27]u64,
) void {
    if (comptime !enabled) @compileError("ADX P-521 scalar multiplication is unavailable");
    vailP521JacobianScalarMul(output, scalar, point);
}

extern fn vailP521JacobianScalarMul(
    output: *[27]u64,
    scalar: *const [9]u64,
    point: *const [27]u64,
) callconv(.c) void;

comptime {
    if (enabled) {
        asm (table_select_asm ++ "\n" ++
                \\        .text
                \\        .balign 32
                \\vailP521JacobianScalarMul:
                \\        .cfi_startproc
                \\        endbr64
                \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
                \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
                \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
                \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
                \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
                \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
                \\        subq $56*72, %rsp ; .cfi_adjust_cfa_offset 56*72
                \\        movq %rdi, (55*72)(%rsp)
                \\        movq %rdx, %rbx
                \\        leaq (0*72)(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_bignum_mod_n521_9
                \\        leaq (7*72)(%rsp), %rdi
                \\        movq %rbx, %rsi
                \\        callq LvailP521JacobianScalarMul_bignum_mod_p521_9
                \\        leaq (7*72)+72(%rsp), %rdi
                \\        leaq 72(%rbx), %rsi
                \\        callq LvailP521JacobianScalarMul_bignum_mod_p521_9
                \\        leaq (7*72)+2*72(%rsp), %rdi
                \\        leaq 2*72(%rbx), %rsi
                \\        callq LvailP521JacobianScalarMul_bignum_mod_p521_9
                \\        xorl %eax, %eax
                \\        notq %rax
                \\        movq $0xbb6fb71e91386409, %r8
                \\        subq (0*72)(%rsp), %r8
                \\        movq $0x3bb5c9b8899c47ae, %r9
                \\        sbbq (0*72)+8(%rsp), %r9
                \\        movq $0x7fcc0148f709a5d0, %r10
                \\        sbbq (0*72)+16(%rsp), %r10
                \\        movq $0x51868783bf2f966b, %r11
                \\        sbbq (0*72)+24(%rsp), %r11
                \\        leaq -5(%rax), %r12
                \\        sbbq (0*72)+32(%rsp), %r12
                \\        movq %rax, %r13
                \\        sbbq (0*72)+40(%rsp), %r13
                \\        movq %rax, %r14
                \\        sbbq (0*72)+48(%rsp), %r14
                \\        movq %rax, %r15
                \\        sbbq (0*72)+56(%rsp), %r15
                \\        movq $0x1ff, %rax
                \\        movq (0*72)+64(%rsp), %rcx
                \\        sbbq %rcx, %rax
                \\        btq $8, %rcx
                \\        sbbq %rcx, %rcx
                \\        cmovncq (0*72)(%rsp), %r8
                \\        cmovncq (0*72)+8(%rsp), %r9
                \\        cmovncq (0*72)+16(%rsp), %r10
                \\        cmovncq (0*72)+24(%rsp), %r11
                \\        cmovncq (0*72)+32(%rsp), %r12
                \\        cmovncq (0*72)+40(%rsp), %r13
                \\        cmovncq (0*72)+48(%rsp), %r14
                \\        cmovncq (0*72)+56(%rsp), %r15
                \\        cmovncq (0*72)+64(%rsp), %rax
                \\        movq %r8, (0*72)(%rsp)
                \\        movq %r9, (0*72)+8(%rsp)
                \\        movq %r10, (0*72)+16(%rsp)
                \\        movq %r11, (0*72)+24(%rsp)
                \\        movq %r12, (0*72)+32(%rsp)
                \\        movq %r13, (0*72)+40(%rsp)
                \\        movq %r14, (0*72)+48(%rsp)
                \\        movq %r15, (0*72)+56(%rsp)
                \\        movq %rax, (0*72)+64(%rsp)
                \\        movq (7*72)+72(%rsp), %r8
                \\        movq (7*72)+72 +8(%rsp), %r9
                \\        movq (7*72)+72 +16(%rsp), %r10
                \\        movq (7*72)+72 +24(%rsp), %r11
                \\        movq (7*72)+72 +32(%rsp), %r12
                \\        movq (7*72)+72 +40(%rsp), %r13
                \\        movq (7*72)+72 +48(%rsp), %r14
                \\        movq (7*72)+72 +56(%rsp), %r15
                \\        movq (7*72)+72 +64(%rsp), %rax
                \\        movq %r8, %rbx
                \\        movq %r12, %rbp
                \\        orq %r9, %rbx
                \\        orq %r13, %rbp
                \\        orq %r10, %rbx
                \\        orq %r14, %rbp
                \\        orq %r11, %rbx
                \\        orq %r15, %rbp
                \\        orq %rbp, %rbx
                \\        orq %rax, %rbx
                \\        cmovzq %rbx, %rcx
                \\        xorq %rcx, %r8
                \\        xorq %rcx, %r9
                \\        xorq %rcx, %r10
                \\        xorq %rcx, %r11
                \\        xorq %rcx, %r12
                \\        xorq %rcx, %r13
                \\        xorq %rcx, %r14
                \\        xorq %rcx, %r15
                \\        andq $0x1FF, %rcx
                \\        xorq %rcx, %rax
                \\        movq %r8, (7*72)+72(%rsp)
                \\        movq %r9, (7*72)+72 +8(%rsp)
                \\        movq %r10, (7*72)+72 +16(%rsp)
                \\        movq %r11, (7*72)+72 +24(%rsp)
                \\        movq %r12, (7*72)+72 +32(%rsp)
                \\        movq %r13, (7*72)+72 +40(%rsp)
                \\        movq %r14, (7*72)+72 +48(%rsp)
                \\        movq %r15, (7*72)+72 +56(%rsp)
                \\        movq %rax, (7*72)+72 +64(%rsp)
                \\        leaq (7*72)+(3*72)*1(%rsp), %rdi
                \\        leaq (7*72)(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (7*72)+(3*72)*2(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*1(%rsp), %rsi
                \\        leaq (7*72)(%rsp), %rdx
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        leaq (7*72)+(3*72)*3(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*1(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (7*72)+(3*72)*4(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*3(%rsp), %rsi
                \\        leaq (7*72)(%rsp), %rdx
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        leaq (7*72)+(3*72)*5(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*2(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (7*72)+(3*72)*6(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*5(%rsp), %rsi
                \\        leaq (7*72)(%rsp), %rdx
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        leaq (7*72)+(3*72)*7(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*3(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (7*72)+(3*72)*8(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*7(%rsp), %rsi
                \\        leaq (7*72)(%rsp), %rdx
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        leaq (7*72)+(3*72)*9(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*4(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (7*72)+(3*72)*10(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*9(%rsp), %rsi
                \\        leaq (7*72)(%rsp), %rdx
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        leaq (7*72)+(3*72)*11(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*5(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (7*72)+(3*72)*12(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*11(%rsp), %rsi
                \\        leaq (7*72)(%rsp), %rdx
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        leaq (7*72)+(3*72)*13(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*6(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (7*72)+(3*72)*14(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*13(%rsp), %rsi
                \\        leaq (7*72)(%rsp), %rdx
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        leaq (7*72)+(3*72)*15(%rsp), %rdi
                \\        leaq (7*72)+(3*72)*7(%rsp), %rsi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        movq $0x1084210842108421, %rax
                \\        movq %rax, %rbx
                \\        shrq $1, %rax
                \\        movq (0*72)(%rsp), %r8
                \\        addq %rax, %r8
                \\        movq (0*72)+8(%rsp), %r9
                \\        adcq %rbx, %r9
                \\        leaq (%rbx,%rbx), %rcx
                \\        movq (0*72)+16(%rsp), %r10
                \\        adcq %rcx, %r10
                \\        leaq (%rcx,%rcx), %rcx
                \\        movq (0*72)+24(%rsp), %r11
                \\        adcq %rcx, %r11
                \\        leaq (%rcx,%rcx), %rcx
                \\        movq (0*72)+32(%rsp), %r12
                \\        adcq %rcx, %r12
                \\        movq (0*72)+40(%rsp), %r13
                \\        adcq %rax, %r13
                \\        movq (0*72)+48(%rsp), %r14
                \\        adcq %rbx, %r14
                \\        movq (0*72)+56(%rsp), %r15
                \\        leaq (%rbx,%rbx), %rcx
                \\        adcq %rcx, %r15
                \\        movq (0*72)+64(%rsp), %rax
                \\        adcq $0x84, %rax
                \\        movq %rax, %rdi
                \\        shrq $8, %rdi
                \\        shldq $56, %r15, %rax
                \\        shldq $56, %r14, %r15
                \\        shldq $56, %r13, %r14
                \\        shldq $56, %r12, %r13
                \\        shldq $56, %r11, %r12
                \\        shldq $56, %r10, %r11
                \\        shldq $56, %r9, %r10
                \\        shldq $56, %r8, %r9
                \\        shlq $56, %r8
                \\        movq %r8, (0*72)(%rsp)
                \\        movq %r9, (0*72)+8(%rsp)
                \\        movq %r10, (0*72)+16(%rsp)
                \\        movq %r11, (0*72)+24(%rsp)
                \\        movq %r12, (0*72)+32(%rsp)
                \\        movq %r13, (0*72)+40(%rsp)
                \\        movq %r14, (0*72)+48(%rsp)
                \\        movq %r15, (0*72)+56(%rsp)
                \\        movq %rax, (0*72)+64(%rsp)
                \\        xorl %ecx, %ecx
                \\        testq %rdi, %rdi
                \\        movq (7*72)(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)(%rsp)
                \\        movq (7*72)+8(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+8(%rsp)
                \\        movq (7*72)+16(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+16(%rsp)
                \\        movq (7*72)+24(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+24(%rsp)
                \\        movq (7*72)+32(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+32(%rsp)
                \\        movq (7*72)+40(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+40(%rsp)
                \\        movq (7*72)+48(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+48(%rsp)
                \\        movq (7*72)+56(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+56(%rsp)
                \\        movq (7*72)+64(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+64(%rsp)
                \\        movq (7*72)+72(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+72(%rsp)
                \\        movq (7*72)+80(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+80(%rsp)
                \\        movq (7*72)+88(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+88(%rsp)
                \\        movq (7*72)+96(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+96(%rsp)
                \\        movq (7*72)+104(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+104(%rsp)
                \\        movq (7*72)+112(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+112(%rsp)
                \\        movq (7*72)+120(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+120(%rsp)
                \\        movq (7*72)+128(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+128(%rsp)
                \\        movq (7*72)+136(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+136(%rsp)
                \\        movq (7*72)+144(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+144(%rsp)
                \\        movq (7*72)+152(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+152(%rsp)
                \\        movq (7*72)+160(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+160(%rsp)
                \\        movq (7*72)+168(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+168(%rsp)
                \\        movq (7*72)+176(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+176(%rsp)
                \\        movq (7*72)+184(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+184(%rsp)
                \\        movq (7*72)+192(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+192(%rsp)
                \\        movq (7*72)+200(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+200(%rsp)
                \\        movq (7*72)+208(%rsp), %rax
                \\        cmovzq %rcx, %rax
                \\        movq %rax, (1*72)+208(%rsp)
                \\        movl $520, %ebp
                \\LvailP521JacobianScalarMul_mainloop:
                \\        subq $5, %rbp
                \\        leaq (1*72)(%rsp), %rsi
                \\        leaq (1*72)(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (1*72)(%rsp), %rsi
                \\        leaq (1*72)(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (1*72)(%rsp), %rsi
                \\        leaq (1*72)(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (1*72)(%rsp), %rsi
                \\        leaq (1*72)(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        leaq (1*72)(%rsp), %rsi
                \\        leaq (1*72)(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_jdouble
                \\        movq (0*72)(%rsp), %r8
                \\        movq (0*72)+8(%rsp), %r9
                \\        movq (0*72)+16(%rsp), %r10
                \\        movq (0*72)+24(%rsp), %r11
                \\        movq (0*72)+32(%rsp), %r12
                \\        movq (0*72)+40(%rsp), %r13
                \\        movq (0*72)+48(%rsp), %r14
                \\        movq (0*72)+56(%rsp), %r15
                \\        movq (0*72)+64(%rsp), %rax
                \\        movq %rax, %rdi
                \\        shrq $59, %rdi
                \\        shldq $5, %r15, %rax
                \\        shldq $5, %r14, %r15
                \\        shldq $5, %r13, %r14
                \\        shldq $5, %r12, %r13
                \\        shldq $5, %r11, %r12
                \\        shldq $5, %r10, %r11
                \\        shldq $5, %r9, %r10
                \\        shldq $5, %r8, %r9
                \\        shlq $5, %r8
                \\        movq %r8, (0*72)(%rsp)
                \\        movq %r9, (0*72)+8(%rsp)
                \\        movq %r10, (0*72)+16(%rsp)
                \\        movq %r11, (0*72)+24(%rsp)
                \\        movq %r12, (0*72)+32(%rsp)
                \\        movq %r13, (0*72)+40(%rsp)
                \\        movq %r14, (0*72)+48(%rsp)
                \\        movq %r15, (0*72)+56(%rsp)
                \\        movq %rax, (0*72)+64(%rsp)
                \\        subq $16, %rdi
                \\        sbbq %rsi, %rsi
                \\        xorq %rsi, %rdi
                \\        subq %rsi, %rdi
                \\        VAIL_P521_SELECT_AVX 4*72, LvailP521JacobianScalarMul_window_selected
                \\        xorl %eax, %eax
                \\        xorl %ebx, %ebx
                \\        xorl %ecx, %ecx
                \\        xorl %edx, %edx
                \\        xorl %r8d, %r8d
                \\        xorl %r9d, %r9d
                \\        xorl %r10d, %r10d
                \\        xorl %r11d, %r11d
                \\        xorl %r12d, %r12d
                \\        cmpq $1, %rdi ; cmovzq (7*72)+(3*72)*(1 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(1 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(1 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(1 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(1 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(1 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(1 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(1 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(1 -1)+64+0*72(%rsp), %r12
                \\        cmpq $2, %rdi ; cmovzq (7*72)+(3*72)*(2 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(2 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(2 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(2 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(2 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(2 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(2 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(2 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(2 -1)+64+0*72(%rsp), %r12
                \\        cmpq $3, %rdi ; cmovzq (7*72)+(3*72)*(3 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(3 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(3 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(3 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(3 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(3 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(3 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(3 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(3 -1)+64+0*72(%rsp), %r12
                \\        cmpq $4, %rdi ; cmovzq (7*72)+(3*72)*(4 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(4 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(4 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(4 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(4 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(4 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(4 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(4 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(4 -1)+64+0*72(%rsp), %r12
                \\        cmpq $5, %rdi ; cmovzq (7*72)+(3*72)*(5 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(5 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(5 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(5 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(5 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(5 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(5 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(5 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(5 -1)+64+0*72(%rsp), %r12
                \\        cmpq $6, %rdi ; cmovzq (7*72)+(3*72)*(6 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(6 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(6 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(6 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(6 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(6 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(6 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(6 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(6 -1)+64+0*72(%rsp), %r12
                \\        cmpq $7, %rdi ; cmovzq (7*72)+(3*72)*(7 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(7 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(7 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(7 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(7 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(7 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(7 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(7 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(7 -1)+64+0*72(%rsp), %r12
                \\        cmpq $8, %rdi ; cmovzq (7*72)+(3*72)*(8 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(8 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(8 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(8 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(8 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(8 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(8 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(8 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(8 -1)+64+0*72(%rsp), %r12
                \\        cmpq $9, %rdi ; cmovzq (7*72)+(3*72)*(9 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(9 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(9 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(9 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(9 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(9 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(9 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(9 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(9 -1)+64+0*72(%rsp), %r12
                \\        cmpq $10, %rdi ; cmovzq (7*72)+(3*72)*(10 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(10 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(10 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(10 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(10 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(10 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(10 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(10 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(10 -1)+64+0*72(%rsp), %r12
                \\        cmpq $11, %rdi ; cmovzq (7*72)+(3*72)*(11 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(11 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(11 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(11 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(11 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(11 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(11 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(11 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(11 -1)+64+0*72(%rsp), %r12
                \\        cmpq $12, %rdi ; cmovzq (7*72)+(3*72)*(12 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(12 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(12 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(12 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(12 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(12 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(12 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(12 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(12 -1)+64+0*72(%rsp), %r12
                \\        cmpq $13, %rdi ; cmovzq (7*72)+(3*72)*(13 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(13 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(13 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(13 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(13 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(13 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(13 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(13 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(13 -1)+64+0*72(%rsp), %r12
                \\        cmpq $14, %rdi ; cmovzq (7*72)+(3*72)*(14 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(14 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(14 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(14 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(14 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(14 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(14 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(14 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(14 -1)+64+0*72(%rsp), %r12
                \\        cmpq $15, %rdi ; cmovzq (7*72)+(3*72)*(15 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(15 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(15 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(15 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(15 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(15 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(15 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(15 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(15 -1)+64+0*72(%rsp), %r12
                \\        cmpq $16, %rdi ; cmovzq (7*72)+(3*72)*(16 -1)+0*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(16 -1)+8+0*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(16 -1)+16+0*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(16 -1)+24+0*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(16 -1)+32+0*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(16 -1)+40+0*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(16 -1)+48+0*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(16 -1)+56+0*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(16 -1)+64+0*72(%rsp), %r12
                \\        movq %rax, (4*72)(%rsp)
                \\        movq %rbx, (4*72)+8(%rsp)
                \\        movq %rcx, (4*72)+16(%rsp)
                \\        movq %rdx, (4*72)+24(%rsp)
                \\        movq %r8, (4*72)+32(%rsp)
                \\        movq %r9, (4*72)+40(%rsp)
                \\        movq %r10, (4*72)+48(%rsp)
                \\        movq %r11, (4*72)+56(%rsp)
                \\        movq %r12, (4*72)+64(%rsp)
                \\        xorl %eax, %eax
                \\        xorl %ebx, %ebx
                \\        xorl %ecx, %ecx
                \\        xorl %edx, %edx
                \\        xorl %r8d, %r8d
                \\        xorl %r9d, %r9d
                \\        xorl %r10d, %r10d
                \\        xorl %r11d, %r11d
                \\        xorl %r12d, %r12d
                \\        cmpq $1, %rdi ; cmovzq (7*72)+(3*72)*(1 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(1 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(1 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(1 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(1 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(1 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(1 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(1 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(1 -1)+64+2*72(%rsp), %r12
                \\        cmpq $2, %rdi ; cmovzq (7*72)+(3*72)*(2 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(2 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(2 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(2 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(2 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(2 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(2 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(2 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(2 -1)+64+2*72(%rsp), %r12
                \\        cmpq $3, %rdi ; cmovzq (7*72)+(3*72)*(3 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(3 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(3 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(3 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(3 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(3 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(3 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(3 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(3 -1)+64+2*72(%rsp), %r12
                \\        cmpq $4, %rdi ; cmovzq (7*72)+(3*72)*(4 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(4 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(4 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(4 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(4 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(4 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(4 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(4 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(4 -1)+64+2*72(%rsp), %r12
                \\        cmpq $5, %rdi ; cmovzq (7*72)+(3*72)*(5 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(5 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(5 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(5 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(5 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(5 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(5 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(5 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(5 -1)+64+2*72(%rsp), %r12
                \\        cmpq $6, %rdi ; cmovzq (7*72)+(3*72)*(6 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(6 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(6 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(6 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(6 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(6 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(6 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(6 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(6 -1)+64+2*72(%rsp), %r12
                \\        cmpq $7, %rdi ; cmovzq (7*72)+(3*72)*(7 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(7 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(7 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(7 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(7 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(7 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(7 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(7 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(7 -1)+64+2*72(%rsp), %r12
                \\        cmpq $8, %rdi ; cmovzq (7*72)+(3*72)*(8 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(8 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(8 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(8 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(8 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(8 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(8 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(8 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(8 -1)+64+2*72(%rsp), %r12
                \\        cmpq $9, %rdi ; cmovzq (7*72)+(3*72)*(9 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(9 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(9 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(9 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(9 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(9 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(9 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(9 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(9 -1)+64+2*72(%rsp), %r12
                \\        cmpq $10, %rdi ; cmovzq (7*72)+(3*72)*(10 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(10 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(10 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(10 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(10 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(10 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(10 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(10 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(10 -1)+64+2*72(%rsp), %r12
                \\        cmpq $11, %rdi ; cmovzq (7*72)+(3*72)*(11 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(11 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(11 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(11 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(11 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(11 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(11 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(11 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(11 -1)+64+2*72(%rsp), %r12
                \\        cmpq $12, %rdi ; cmovzq (7*72)+(3*72)*(12 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(12 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(12 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(12 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(12 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(12 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(12 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(12 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(12 -1)+64+2*72(%rsp), %r12
                \\        cmpq $13, %rdi ; cmovzq (7*72)+(3*72)*(13 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(13 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(13 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(13 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(13 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(13 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(13 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(13 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(13 -1)+64+2*72(%rsp), %r12
                \\        cmpq $14, %rdi ; cmovzq (7*72)+(3*72)*(14 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(14 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(14 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(14 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(14 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(14 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(14 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(14 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(14 -1)+64+2*72(%rsp), %r12
                \\        cmpq $15, %rdi ; cmovzq (7*72)+(3*72)*(15 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(15 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(15 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(15 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(15 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(15 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(15 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(15 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(15 -1)+64+2*72(%rsp), %r12
                \\        cmpq $16, %rdi ; cmovzq (7*72)+(3*72)*(16 -1)+2*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(16 -1)+8+2*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(16 -1)+16+2*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(16 -1)+24+2*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(16 -1)+32+2*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(16 -1)+40+2*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(16 -1)+48+2*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(16 -1)+56+2*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(16 -1)+64+2*72(%rsp), %r12
                \\        movq %rax, (4*72)+2*72(%rsp)
                \\        movq %rbx, (4*72)+2*72 +8(%rsp)
                \\        movq %rcx, (4*72)+2*72 +16(%rsp)
                \\        movq %rdx, (4*72)+2*72 +24(%rsp)
                \\        movq %r8, (4*72)+2*72 +32(%rsp)
                \\        movq %r9, (4*72)+2*72 +40(%rsp)
                \\        movq %r10, (4*72)+2*72 +48(%rsp)
                \\        movq %r11, (4*72)+2*72 +56(%rsp)
                \\        movq %r12, (4*72)+2*72 +64(%rsp)
                \\        xorl %eax, %eax
                \\        xorl %ebx, %ebx
                \\        xorl %ecx, %ecx
                \\        xorl %edx, %edx
                \\        xorl %r8d, %r8d
                \\        xorl %r9d, %r9d
                \\        xorl %r10d, %r10d
                \\        xorl %r11d, %r11d
                \\        xorl %r12d, %r12d
                \\        cmpq $1, %rdi ; cmovzq (7*72)+(3*72)*(1 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(1 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(1 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(1 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(1 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(1 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(1 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(1 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(1 -1)+64+1*72(%rsp), %r12
                \\        cmpq $2, %rdi ; cmovzq (7*72)+(3*72)*(2 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(2 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(2 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(2 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(2 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(2 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(2 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(2 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(2 -1)+64+1*72(%rsp), %r12
                \\        cmpq $3, %rdi ; cmovzq (7*72)+(3*72)*(3 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(3 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(3 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(3 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(3 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(3 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(3 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(3 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(3 -1)+64+1*72(%rsp), %r12
                \\        cmpq $4, %rdi ; cmovzq (7*72)+(3*72)*(4 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(4 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(4 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(4 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(4 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(4 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(4 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(4 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(4 -1)+64+1*72(%rsp), %r12
                \\        cmpq $5, %rdi ; cmovzq (7*72)+(3*72)*(5 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(5 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(5 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(5 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(5 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(5 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(5 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(5 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(5 -1)+64+1*72(%rsp), %r12
                \\        cmpq $6, %rdi ; cmovzq (7*72)+(3*72)*(6 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(6 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(6 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(6 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(6 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(6 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(6 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(6 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(6 -1)+64+1*72(%rsp), %r12
                \\        cmpq $7, %rdi ; cmovzq (7*72)+(3*72)*(7 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(7 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(7 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(7 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(7 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(7 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(7 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(7 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(7 -1)+64+1*72(%rsp), %r12
                \\        cmpq $8, %rdi ; cmovzq (7*72)+(3*72)*(8 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(8 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(8 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(8 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(8 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(8 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(8 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(8 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(8 -1)+64+1*72(%rsp), %r12
                \\        cmpq $9, %rdi ; cmovzq (7*72)+(3*72)*(9 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(9 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(9 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(9 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(9 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(9 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(9 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(9 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(9 -1)+64+1*72(%rsp), %r12
                \\        cmpq $10, %rdi ; cmovzq (7*72)+(3*72)*(10 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(10 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(10 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(10 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(10 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(10 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(10 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(10 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(10 -1)+64+1*72(%rsp), %r12
                \\        cmpq $11, %rdi ; cmovzq (7*72)+(3*72)*(11 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(11 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(11 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(11 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(11 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(11 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(11 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(11 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(11 -1)+64+1*72(%rsp), %r12
                \\        cmpq $12, %rdi ; cmovzq (7*72)+(3*72)*(12 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(12 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(12 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(12 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(12 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(12 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(12 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(12 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(12 -1)+64+1*72(%rsp), %r12
                \\        cmpq $13, %rdi ; cmovzq (7*72)+(3*72)*(13 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(13 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(13 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(13 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(13 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(13 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(13 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(13 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(13 -1)+64+1*72(%rsp), %r12
                \\        cmpq $14, %rdi ; cmovzq (7*72)+(3*72)*(14 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(14 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(14 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(14 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(14 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(14 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(14 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(14 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(14 -1)+64+1*72(%rsp), %r12
                \\        cmpq $15, %rdi ; cmovzq (7*72)+(3*72)*(15 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(15 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(15 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(15 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(15 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(15 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(15 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(15 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(15 -1)+64+1*72(%rsp), %r12
                \\        cmpq $16, %rdi ; cmovzq (7*72)+(3*72)*(16 -1)+1*72(%rsp), %rax ; cmovzq (7*72)+(3*72)*(16 -1)+8+1*72(%rsp), %rbx ; cmovzq (7*72)+(3*72)*(16 -1)+16+1*72(%rsp), %rcx ; cmovzq (7*72)+(3*72)*(16 -1)+24+1*72(%rsp), %rdx ; cmovzq (7*72)+(3*72)*(16 -1)+32+1*72(%rsp), %r8 ; cmovzq (7*72)+(3*72)*(16 -1)+40+1*72(%rsp), %r9 ; cmovzq (7*72)+(3*72)*(16 -1)+48+1*72(%rsp), %r10 ; cmovzq (7*72)+(3*72)*(16 -1)+56+1*72(%rsp), %r11 ; cmovzq (7*72)+(3*72)*(16 -1)+64+1*72(%rsp), %r12
                \\LvailP521JacobianScalarMul_window_selected:
                \\        movq %rax, %r13
                \\        orq %rbx, %r13
                \\        movq %rcx, %r14
                \\        orq %rdx, %r14
                \\        movq %r8, %r15
                \\        orq %r9, %r15
                \\        movq %r10, %rdi
                \\        orq %r11, %rdi
                \\        orq %r14, %r13
                \\        orq %rdi, %r15
                \\        orq %r12, %r15
                \\        orq %r15, %r13
                \\        cmovzq %r13, %rsi
                \\        xorq %rsi, %rax
                \\        xorq %rsi, %rbx
                \\        xorq %rsi, %rcx
                \\        xorq %rsi, %rdx
                \\        xorq %rsi, %r8
                \\        xorq %rsi, %r9
                \\        xorq %rsi, %r10
                \\        xorq %rsi, %r11
                \\        andq $0x1FF, %rsi
                \\        xorq %rsi, %r12
                \\        movq %rax, (4*72)+72(%rsp)
                \\        movq %rbx, (4*72)+72 +8(%rsp)
                \\        movq %rcx, (4*72)+72 +16(%rsp)
                \\        movq %rdx, (4*72)+72 +24(%rsp)
                \\        movq %r8, (4*72)+72 +32(%rsp)
                \\        movq %r9, (4*72)+72 +40(%rsp)
                \\        movq %r10, (4*72)+72 +48(%rsp)
                \\        movq %r11, (4*72)+72 +56(%rsp)
                \\        movq %r12, (4*72)+72 +64(%rsp)
                \\        leaq (4*72)(%rsp), %rdx
                \\        leaq (1*72)(%rsp), %rsi
                \\        leaq (1*72)(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_jadd
                \\        testq %rbp, %rbp
                \\        jne LvailP521JacobianScalarMul_mainloop
                \\        movq (55*72)(%rsp), %rdi
                \\        movq (1*72)(%rsp), %rax
                \\        movq %rax, (%rdi)
                \\        movq (1*72)+8(%rsp), %rax
                \\        movq %rax, 8(%rdi)
                \\        movq (1*72)+16(%rsp), %rax
                \\        movq %rax, 16(%rdi)
                \\        movq (1*72)+24(%rsp), %rax
                \\        movq %rax, 24(%rdi)
                \\        movq (1*72)+32(%rsp), %rax
                \\        movq %rax, 32(%rdi)
                \\        movq (1*72)+40(%rsp), %rax
                \\        movq %rax, 40(%rdi)
                \\        movq (1*72)+48(%rsp), %rax
                \\        movq %rax, 48(%rdi)
                \\        movq (1*72)+56(%rsp), %rax
                \\        movq %rax, 56(%rdi)
                \\        movq (1*72)+64(%rsp), %rax
                \\        movq %rax, 64(%rdi)
                \\        movq (1*72)+72(%rsp), %rax
                \\        movq %rax, 72(%rdi)
                \\        movq (1*72)+80(%rsp), %rax
                \\        movq %rax, 80(%rdi)
                \\        movq (1*72)+88(%rsp), %rax
                \\        movq %rax, 88(%rdi)
                \\        movq (1*72)+96(%rsp), %rax
                \\        movq %rax, 96(%rdi)
                \\        movq (1*72)+104(%rsp), %rax
                \\        movq %rax, 104(%rdi)
                \\        movq (1*72)+112(%rsp), %rax
                \\        movq %rax, 112(%rdi)
                \\        movq (1*72)+120(%rsp), %rax
                \\        movq %rax, 120(%rdi)
                \\        movq (1*72)+128(%rsp), %rax
                \\        movq %rax, 128(%rdi)
                \\        movq (1*72)+136(%rsp), %rax
                \\        movq %rax, 136(%rdi)
                \\        movq (1*72)+144(%rsp), %rax
                \\        movq %rax, 144(%rdi)
                \\        movq (1*72)+152(%rsp), %rax
                \\        movq %rax, 152(%rdi)
                \\        movq (1*72)+160(%rsp), %rax
                \\        movq %rax, 160(%rdi)
                \\        movq (1*72)+168(%rsp), %rax
                \\        movq %rax, 168(%rdi)
                \\        movq (1*72)+176(%rsp), %rax
                \\        movq %rax, 176(%rdi)
                \\        movq (1*72)+184(%rsp), %rax
                \\        movq %rax, 184(%rdi)
                \\        movq (1*72)+192(%rsp), %rax
                \\        movq %rax, 192(%rdi)
                \\        movq (1*72)+200(%rsp), %rax
                \\        movq %rax, 200(%rdi)
                \\        movq (1*72)+208(%rsp), %rax
                \\        movq %rax, 208(%rdi)
                \\        subq $536, %rsp ; .cfi_adjust_cfa_offset 536
                \\        cld
                \\        xorl %eax, %eax
                \\        movq %rsp, %rdi
                \\        movl $571, %ecx
                \\        rep stosq
                \\        xorl %edx, %edx
                \\        xorl %esi, %esi
                \\        xorl %r8d, %r8d
                \\        xorl %r9d, %r9d
                \\        xorl %r10d, %r10d
                \\        xorl %r11d, %r11d
                \\        addq $536, %rsp ; .cfi_adjust_cfa_offset -536
                \\        addq $56*72, %rsp ; .cfi_adjust_cfa_offset -56*72
                \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
                \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
                \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
                \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
                \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
                \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
                \\        VAIL_P521_CLEAR_AVX
                \\        retq ; .cfi_endproc
                \\.size vailP521JacobianScalarMul, .-vailP521JacobianScalarMul
                \\.type LvailP521JacobianScalarMul_bignum_mod_p521_9, %function
                \\LvailP521JacobianScalarMul_bignum_mod_p521_9:
                \\        .cfi_startproc
                \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
                \\        movq 0x40(%rsi), %rax
                \\        movl $0x1ff, %edx
                \\        andq %rax, %rdx
                \\        shrq $0x9, %rax
                \\        stc
                \\        adcq (%rsi), %rax
                \\        movq 0x8(%rsi), %rcx
                \\        adcq $0x0, %rcx
                \\        movq 0x10(%rsi), %r8
                \\        adcq $0x0, %r8
                \\        movq 0x18(%rsi), %r9
                \\        adcq $0x0, %r9
                \\        movq 0x20(%rsi), %r10
                \\        adcq $0x0, %r10
                \\        movq 0x28(%rsi), %r11
                \\        adcq $0x0, %r11
                \\        movq 0x30(%rsi), %rbx
                \\        adcq $0x0, %rbx
                \\        movq 0x38(%rsi), %rsi
                \\        adcq $0x0, %rsi
                \\        adcq $0x0, %rdx
                \\        cmpq $0x200, %rdx
                \\        sbbq $0x0, %rax
                \\        movq %rax, (%rdi)
                \\        sbbq $0x0, %rcx
                \\        movq %rcx, 0x8(%rdi)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x10(%rdi)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x18(%rdi)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x20(%rdi)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x28(%rdi)
                \\        sbbq $0x0, %rbx
                \\        movq %rbx, 0x30(%rdi)
                \\        sbbq $0x0, %rsi
                \\        movq %rsi, 0x38(%rdi)
                \\        sbbq $0x0, %rdx
                \\        andq $0x1ff, %rdx
                \\        movq %rdx, 0x40(%rdi)
                \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
                \\        retq ; .cfi_endproc
                \\.size LvailP521JacobianScalarMul_bignum_mod_p521_9, .-LvailP521JacobianScalarMul_bignum_mod_p521_9
                \\.type LvailP521JacobianScalarMul_bignum_mod_n521_9, %function
                \\LvailP521JacobianScalarMul_bignum_mod_n521_9:
                \\        .cfi_startproc
                \\        movq 0x40(%rsi), %rdx
                \\        movq $0xfffffffffffffe00, %rax
                \\        orq %rdx, %rax
                \\        movq %rax, 0x40(%rdi)
                \\        shrq $0x9, %rdx
                \\        addq $0x1, %rdx
                \\        movq $0x449048e16ec79bf7, %r9
                \\        mulxq %r9, %rax, %rcx
                \\        adcxq (%rsi), %rax
                \\        movq %rax, (%rdi)
                \\        movq $0xc44a36477663b851, %r10
                \\        mulxq %r10, %rax, %r8
                \\        adcxq 0x8(%rsi), %rax
                \\        adoxq %rcx, %rax
                \\        movq %rax, 0x8(%rdi)
                \\        movq $0x8033feb708f65a2f, %r11
                \\        mulxq %r11, %rax, %rcx
                \\        adcxq 0x10(%rsi), %rax
                \\        adoxq %r8, %rax
                \\        movq %rax, 0x10(%rdi)
                \\        movq $0xae79787c40d06994, %rax
                \\        mulxq %rax, %rax, %r8
                \\        adcxq 0x18(%rsi), %rax
                \\        adoxq %rcx, %rax
                \\        movq %rax, 0x18(%rdi)
                \\        movl $0x5, %eax
                \\        mulxq %rax, %rax, %rcx
                \\        adcxq 0x20(%rsi), %rax
                \\        adoxq %r8, %rax
                \\        movq %rax, 0x20(%rdi)
                \\        movq %rcx, %rax
                \\        adoxq %rcx, %rcx
                \\        adcq 0x28(%rsi), %rcx
                \\        movq %rcx, 0x28(%rdi)
                \\        movq 0x30(%rsi), %rcx
                \\        adcq %rax, %rcx
                \\        movq %rcx, 0x30(%rdi)
                \\        movq 0x38(%rsi), %rcx
                \\        adcq %rax, %rcx
                \\        movq %rcx, 0x38(%rdi)
                \\        movq 0x40(%rdi), %rcx
                \\        adcq %rax, %rcx
                \\        cmc
                \\        sbbq %rdx, %rdx
                \\        andq %rdx, %r9
                \\        andq %rdx, %r10
                \\        andq %rdx, %r11
                \\        movq $0xae79787c40d06994, %r8
                \\        andq %rdx, %r8
                \\        andl $0x5, %edx
                \\        subq %r9, (%rdi)
                \\        sbbq %r10, 0x8(%rdi)
                \\        sbbq %r11, 0x10(%rdi)
                \\        sbbq %r8, 0x18(%rdi)
                \\        sbbq %rdx, 0x20(%rdi)
                \\        sbbq %rax, 0x28(%rdi)
                \\        sbbq %rax, 0x30(%rdi)
                \\        sbbq %rax, 0x38(%rdi)
                \\        sbbl %eax, %ecx
                \\        andl $0x1ff, %ecx
                \\        movq %rcx, 0x40(%rdi)
                \\        retq ; .cfi_endproc
                \\.size LvailP521JacobianScalarMul_bignum_mod_n521_9, .-LvailP521JacobianScalarMul_bignum_mod_n521_9
                \\.type LvailP521JacobianScalarMul_jadd, %function
                \\LvailP521JacobianScalarMul_jadd:
                \\        .cfi_startproc
                \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
                \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
                \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
                \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
                \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
                \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
                \\        subq $528, %rsp ; .cfi_adjust_cfa_offset 528
                \\        movq %rdi, 0x1f8(%rsp)
                \\        movq %rsi, 0x200(%rsp)
                \\        movq %rdx, 0x208(%rsp)
                \\        movq 0x200(%rsp), %rsi
                \\        leaq 0x90(%rsi), %rsi
                \\        leaq (%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        movq 0x208(%rsp), %rdi
                \\        leaq 0x90(%rdi), %rsi
                \\        leaq 0x168(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        movq 0x200(%rsp), %rsi
                \\        movq 0x208(%rsp), %rdi
                \\        leaq 0x48(%rsi), %rdx
                \\        leaq 0x90(%rdi), %rsi
                \\        leaq 0x1b0(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x200(%rsp), %rsi
                \\        movq 0x208(%rsp), %rdi
                \\        leaq 0x48(%rdi), %rdx
                \\        leaq 0x90(%rsi), %rsi
                \\        leaq 0x48(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x208(%rsp), %rdi
                \\        leaq (%rdi), %rdx
                \\        leaq (%rsp), %rsi
                \\        leaq 0x90(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x200(%rsp), %rsi
                \\        leaq (%rsi), %rdx
                \\        leaq 0x168(%rsp), %rsi
                \\        leaq 0x120(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        leaq 0x48(%rsp), %rdx
                \\        leaq (%rsp), %rsi
                \\        leaq 0x48(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        leaq 0x1b0(%rsp), %rdx
                \\        leaq 0x168(%rsp), %rsi
                \\        leaq 0x1b0(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x90(%rsp), %rax
                \\        subq 0x120(%rsp), %rax
                \\        movq 0x98(%rsp), %rdx
                \\        sbbq 0x128(%rsp), %rdx
                \\        movq 0xa0(%rsp), %r8
                \\        sbbq 0x130(%rsp), %r8
                \\        movq 0xa8(%rsp), %r9
                \\        sbbq 0x138(%rsp), %r9
                \\        movq 0xb0(%rsp), %r10
                \\        sbbq 0x140(%rsp), %r10
                \\        movq 0xb8(%rsp), %r11
                \\        sbbq 0x148(%rsp), %r11
                \\        movq 0xc0(%rsp), %r12
                \\        sbbq 0x150(%rsp), %r12
                \\        movq 0xc8(%rsp), %r13
                \\        sbbq 0x158(%rsp), %r13
                \\        movq 0xd0(%rsp), %r14
                \\        sbbq 0x160(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x168(%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x170(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x178(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x180(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x188(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x190(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x198(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x1a0(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x1a8(%rsp)
                \\        movq 0x48(%rsp), %rax
                \\        subq 0x1b0(%rsp), %rax
                \\        movq 0x50(%rsp), %rdx
                \\        sbbq 0x1b8(%rsp), %rdx
                \\        movq 0x58(%rsp), %r8
                \\        sbbq 0x1c0(%rsp), %r8
                \\        movq 0x60(%rsp), %r9
                \\        sbbq 0x1c8(%rsp), %r9
                \\        movq 0x68(%rsp), %r10
                \\        sbbq 0x1d0(%rsp), %r10
                \\        movq 0x70(%rsp), %r11
                \\        sbbq 0x1d8(%rsp), %r11
                \\        movq 0x78(%rsp), %r12
                \\        sbbq 0x1e0(%rsp), %r12
                \\        movq 0x80(%rsp), %r13
                \\        sbbq 0x1e8(%rsp), %r13
                \\        movq 0x88(%rsp), %r14
                \\        sbbq 0x1f0(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x48(%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x50(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x58(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x60(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x68(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x70(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x78(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x80(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x88(%rsp)
                \\        leaq 0x168(%rsp), %rsi
                \\        leaq 0xd8(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        leaq 0x48(%rsp), %rsi
                \\        leaq (%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        leaq 0x120(%rsp), %rdx
                \\        leaq 0xd8(%rsp), %rsi
                \\        leaq 0x120(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        leaq 0x90(%rsp), %rdx
                \\        leaq 0xd8(%rsp), %rsi
                \\        leaq 0x90(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq (%rsp), %rax
                \\        subq 0x120(%rsp), %rax
                \\        movq 0x8(%rsp), %rdx
                \\        sbbq 0x128(%rsp), %rdx
                \\        movq 0x10(%rsp), %r8
                \\        sbbq 0x130(%rsp), %r8
                \\        movq 0x18(%rsp), %r9
                \\        sbbq 0x138(%rsp), %r9
                \\        movq 0x20(%rsp), %r10
                \\        sbbq 0x140(%rsp), %r10
                \\        movq 0x28(%rsp), %r11
                \\        sbbq 0x148(%rsp), %r11
                \\        movq 0x30(%rsp), %r12
                \\        sbbq 0x150(%rsp), %r12
                \\        movq 0x38(%rsp), %r13
                \\        sbbq 0x158(%rsp), %r13
                \\        movq 0x40(%rsp), %r14
                \\        sbbq 0x160(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, (%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x8(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x10(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x18(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x20(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x28(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x30(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x38(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x40(%rsp)
                \\        movq 0x90(%rsp), %rax
                \\        subq 0x120(%rsp), %rax
                \\        movq 0x98(%rsp), %rdx
                \\        sbbq 0x128(%rsp), %rdx
                \\        movq 0xa0(%rsp), %r8
                \\        sbbq 0x130(%rsp), %r8
                \\        movq 0xa8(%rsp), %r9
                \\        sbbq 0x138(%rsp), %r9
                \\        movq 0xb0(%rsp), %r10
                \\        sbbq 0x140(%rsp), %r10
                \\        movq 0xb8(%rsp), %r11
                \\        sbbq 0x148(%rsp), %r11
                \\        movq 0xc0(%rsp), %r12
                \\        sbbq 0x150(%rsp), %r12
                \\        movq 0xc8(%rsp), %r13
                \\        sbbq 0x158(%rsp), %r13
                \\        movq 0xd0(%rsp), %r14
                \\        sbbq 0x160(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0xd8(%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0xe0(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0xe8(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0xf0(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0xf8(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x100(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x108(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x110(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x118(%rsp)
                \\        movq 0x200(%rsp), %rsi
                \\        leaq 0x90(%rsi), %rdx
                \\        leaq 0x168(%rsp), %rsi
                \\        leaq 0x168(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq (%rsp), %rax
                \\        subq 0x90(%rsp), %rax
                \\        movq 0x8(%rsp), %rdx
                \\        sbbq 0x98(%rsp), %rdx
                \\        movq 0x10(%rsp), %r8
                \\        sbbq 0xa0(%rsp), %r8
                \\        movq 0x18(%rsp), %r9
                \\        sbbq 0xa8(%rsp), %r9
                \\        movq 0x20(%rsp), %r10
                \\        sbbq 0xb0(%rsp), %r10
                \\        movq 0x28(%rsp), %r11
                \\        sbbq 0xb8(%rsp), %r11
                \\        movq 0x30(%rsp), %r12
                \\        sbbq 0xc0(%rsp), %r12
                \\        movq 0x38(%rsp), %r13
                \\        sbbq 0xc8(%rsp), %r13
                \\        movq 0x40(%rsp), %r14
                \\        sbbq 0xd0(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, (%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x8(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x10(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x18(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x20(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x28(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x30(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x38(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x40(%rsp)
                \\        movq 0x120(%rsp), %rax
                \\        subq (%rsp), %rax
                \\        movq 0x128(%rsp), %rdx
                \\        sbbq 0x8(%rsp), %rdx
                \\        movq 0x130(%rsp), %r8
                \\        sbbq 0x10(%rsp), %r8
                \\        movq 0x138(%rsp), %r9
                \\        sbbq 0x18(%rsp), %r9
                \\        movq 0x140(%rsp), %r10
                \\        sbbq 0x20(%rsp), %r10
                \\        movq 0x148(%rsp), %r11
                \\        sbbq 0x28(%rsp), %r11
                \\        movq 0x150(%rsp), %r12
                \\        sbbq 0x30(%rsp), %r12
                \\        movq 0x158(%rsp), %r13
                \\        sbbq 0x38(%rsp), %r13
                \\        movq 0x160(%rsp), %r14
                \\        sbbq 0x40(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x120(%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x128(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x130(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x138(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x140(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x148(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x150(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x158(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x160(%rsp)
                \\        leaq 0x1b0(%rsp), %rdx
                \\        leaq 0xd8(%rsp), %rsi
                \\        leaq 0xd8(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x208(%rsp), %rdi
                \\        leaq 0x90(%rdi), %rdx
                \\        leaq 0x168(%rsp), %rsi
                \\        leaq 0x168(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        leaq 0x120(%rsp), %rdx
                \\        leaq 0x48(%rsp), %rsi
                \\        leaq 0x120(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x120(%rsp), %rax
                \\        subq 0xd8(%rsp), %rax
                \\        movq 0x128(%rsp), %rdx
                \\        sbbq 0xe0(%rsp), %rdx
                \\        movq 0x130(%rsp), %r8
                \\        sbbq 0xe8(%rsp), %r8
                \\        movq 0x138(%rsp), %r9
                \\        sbbq 0xf0(%rsp), %r9
                \\        movq 0x140(%rsp), %r10
                \\        sbbq 0xf8(%rsp), %r10
                \\        movq 0x148(%rsp), %r11
                \\        sbbq 0x100(%rsp), %r11
                \\        movq 0x150(%rsp), %r12
                \\        sbbq 0x108(%rsp), %r12
                \\        movq 0x158(%rsp), %r13
                \\        sbbq 0x110(%rsp), %r13
                \\        movq 0x160(%rsp), %r14
                \\        sbbq 0x118(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x120(%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x128(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x130(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x138(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x140(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x148(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x150(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x158(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x160(%rsp)
                \\        movq 0x200(%rsp), %rsi
                \\        movq 0x90(%rsi), %r8
                \\        movq 0x98(%rsi), %r9
                \\        movq 0xa0(%rsi), %r10
                \\        movq 0xa8(%rsi), %r11
                \\        movq 0xb0(%rsi), %r12
                \\        movq 0xb8(%rsi), %r13
                \\        movq 0xc0(%rsi), %r14
                \\        movq 0xc8(%rsi), %r15
                \\        movq 0xd0(%rsi), %rbp
                \\        orq %r9, %r8
                \\        orq %r11, %r10
                \\        orq %r13, %r12
                \\        orq %r15, %r14
                \\        orq %r10, %r8
                \\        orq %r14, %r12
                \\        orq %rbp, %r8
                \\        orq %r12, %r8
                \\        negq %r8
                \\        sbbq %rax, %rax
                \\        movq 0x208(%rsp), %rdi
                \\        movq 0x90(%rdi), %r8
                \\        movq 0x98(%rdi), %r9
                \\        movq 0xa0(%rdi), %r10
                \\        movq 0xa8(%rdi), %r11
                \\        movq 0xb0(%rdi), %r12
                \\        movq 0xb8(%rdi), %r13
                \\        movq 0xc0(%rdi), %r14
                \\        movq 0xc8(%rdi), %r15
                \\        movq 0xd0(%rdi), %rbp
                \\        orq %r9, %r8
                \\        orq %r11, %r10
                \\        orq %r13, %r12
                \\        orq %r15, %r14
                \\        orq %r10, %r8
                \\        orq %r14, %r12
                \\        orq %rbp, %r8
                \\        orq %r12, %r8
                \\        negq %r8
                \\        sbbq %rdx, %rdx
                \\        cmpq %rax, %rdx
                \\        movq 0x120(%rsp), %r8
                \\        cmovbq 0x48(%rsi), %r8
                \\        cmova 0x48(%rdi), %r8
                \\        movq 0x128(%rsp), %r9
                \\        cmovbq 0x50(%rsi), %r9
                \\        cmova 0x50(%rdi), %r9
                \\        movq 0x130(%rsp), %r10
                \\        cmovbq 0x58(%rsi), %r10
                \\        cmova 0x58(%rdi), %r10
                \\        movq 0x138(%rsp), %r11
                \\        cmovbq 0x60(%rsi), %r11
                \\        cmova 0x60(%rdi), %r11
                \\        movq 0x140(%rsp), %r12
                \\        cmovbq 0x68(%rsi), %r12
                \\        cmova 0x68(%rdi), %r12
                \\        movq 0x148(%rsp), %r13
                \\        cmovbq 0x70(%rsi), %r13
                \\        cmova 0x70(%rdi), %r13
                \\        movq 0x150(%rsp), %r14
                \\        cmovbq 0x78(%rsi), %r14
                \\        cmova 0x78(%rdi), %r14
                \\        movq 0x158(%rsp), %r15
                \\        cmovbq 0x80(%rsi), %r15
                \\        cmova 0x80(%rdi), %r15
                \\        movq 0x160(%rsp), %rbp
                \\        cmovbq 0x88(%rsi), %rbp
                \\        cmova 0x88(%rdi), %rbp
                \\        movq %r8, 0x120(%rsp)
                \\        movq %r9, 0x128(%rsp)
                \\        movq %r10, 0x130(%rsp)
                \\        movq %r11, 0x138(%rsp)
                \\        movq %r12, 0x140(%rsp)
                \\        movq %r13, 0x148(%rsp)
                \\        movq %r14, 0x150(%rsp)
                \\        movq %r15, 0x158(%rsp)
                \\        movq %rbp, 0x160(%rsp)
                \\        movq 0x168(%rsp), %r8
                \\        cmovbq 0x90(%rsi), %r8
                \\        cmova 0x90(%rdi), %r8
                \\        movq 0x170(%rsp), %r9
                \\        cmovbq 0x98(%rsi), %r9
                \\        cmova 0x98(%rdi), %r9
                \\        movq 0x178(%rsp), %r10
                \\        cmovbq 0xa0(%rsi), %r10
                \\        cmova 0xa0(%rdi), %r10
                \\        movq 0x180(%rsp), %r11
                \\        cmovbq 0xa8(%rsi), %r11
                \\        cmova 0xa8(%rdi), %r11
                \\        movq 0x188(%rsp), %r12
                \\        cmovbq 0xb0(%rsi), %r12
                \\        cmova 0xb0(%rdi), %r12
                \\        movq 0x190(%rsp), %r13
                \\        cmovbq 0xb8(%rsi), %r13
                \\        cmova 0xb8(%rdi), %r13
                \\        movq 0x198(%rsp), %r14
                \\        cmovbq 0xc0(%rsi), %r14
                \\        cmova 0xc0(%rdi), %r14
                \\        movq 0x1a0(%rsp), %r15
                \\        cmovbq 0xc8(%rsi), %r15
                \\        cmova 0xc8(%rdi), %r15
                \\        movq 0x1a8(%rsp), %rbp
                \\        cmovbq 0xd0(%rsi), %rbp
                \\        cmova 0xd0(%rdi), %rbp
                \\        movq %r8, 0x168(%rsp)
                \\        movq %r9, 0x170(%rsp)
                \\        movq %r10, 0x178(%rsp)
                \\        movq %r11, 0x180(%rsp)
                \\        movq %r12, 0x188(%rsp)
                \\        movq %r13, 0x190(%rsp)
                \\        movq %r14, 0x198(%rsp)
                \\        movq %r15, 0x1a0(%rsp)
                \\        movq %rbp, 0x1a8(%rsp)
                \\        movq (%rsp), %r8
                \\        cmovbq (%rsi), %r8
                \\        cmova (%rdi), %r8
                \\        movq 0x8(%rsp), %r9
                \\        cmovbq 0x8(%rsi), %r9
                \\        cmova 0x8(%rdi), %r9
                \\        movq 0x10(%rsp), %r10
                \\        cmovbq 0x10(%rsi), %r10
                \\        cmova 0x10(%rdi), %r10
                \\        movq 0x18(%rsp), %r11
                \\        cmovbq 0x18(%rsi), %r11
                \\        cmova 0x18(%rdi), %r11
                \\        movq 0x20(%rsp), %r12
                \\        cmovbq 0x20(%rsi), %r12
                \\        cmova 0x20(%rdi), %r12
                \\        movq 0x28(%rsp), %r13
                \\        cmovbq 0x28(%rsi), %r13
                \\        cmova 0x28(%rdi), %r13
                \\        movq 0x30(%rsp), %r14
                \\        cmovbq 0x30(%rsi), %r14
                \\        cmova 0x30(%rdi), %r14
                \\        movq 0x38(%rsp), %r15
                \\        cmovbq 0x38(%rsi), %r15
                \\        cmova 0x38(%rdi), %r15
                \\        movq 0x40(%rsp), %rbp
                \\        cmovbq 0x40(%rsi), %rbp
                \\        cmova 0x40(%rdi), %rbp
                \\        movq 0x1f8(%rsp), %rdi
                \\        movq %r8, (%rdi)
                \\        movq %r9, 0x8(%rdi)
                \\        movq %r10, 0x10(%rdi)
                \\        movq %r11, 0x18(%rdi)
                \\        movq %r12, 0x20(%rdi)
                \\        movq %r13, 0x28(%rdi)
                \\        movq %r14, 0x30(%rdi)
                \\        movq %r15, 0x38(%rdi)
                \\        movq %rbp, 0x40(%rdi)
                \\        movq 0x120(%rsp), %rax
                \\        movq %rax, 0x48(%rdi)
                \\        movq 0x128(%rsp), %rax
                \\        movq %rax, 0x50(%rdi)
                \\        movq 0x130(%rsp), %rax
                \\        movq %rax, 0x58(%rdi)
                \\        movq 0x138(%rsp), %rax
                \\        movq %rax, 0x60(%rdi)
                \\        movq 0x140(%rsp), %rax
                \\        movq %rax, 0x68(%rdi)
                \\        movq 0x148(%rsp), %rax
                \\        movq %rax, 0x70(%rdi)
                \\        movq 0x150(%rsp), %rax
                \\        movq %rax, 0x78(%rdi)
                \\        movq 0x158(%rsp), %rax
                \\        movq %rax, 0x80(%rdi)
                \\        movq 0x160(%rsp), %rax
                \\        movq %rax, 0x88(%rdi)
                \\        movq 0x168(%rsp), %rax
                \\        movq %rax, 0x90(%rdi)
                \\        movq 0x170(%rsp), %rax
                \\        movq %rax, 0x98(%rdi)
                \\        movq 0x178(%rsp), %rax
                \\        movq %rax, 0xa0(%rdi)
                \\        movq 0x180(%rsp), %rax
                \\        movq %rax, 0xa8(%rdi)
                \\        movq 0x188(%rsp), %rax
                \\        movq %rax, 0xb0(%rdi)
                \\        movq 0x190(%rsp), %rax
                \\        movq %rax, 0xb8(%rdi)
                \\        movq 0x198(%rsp), %rax
                \\        movq %rax, 0xc0(%rdi)
                \\        movq 0x1a0(%rsp), %rax
                \\        movq %rax, 0xc8(%rdi)
                \\        movq 0x1a8(%rsp), %rax
                \\        movq %rax, 0xd0(%rdi)
                \\        addq $528, %rsp ; .cfi_adjust_cfa_offset -528
                \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
                \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
                \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
                \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
                \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
                \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
                \\        retq ; .cfi_endproc
                \\.size LvailP521JacobianScalarMul_jadd, .-LvailP521JacobianScalarMul_jadd
                \\.type LvailP521JacobianScalarMul_jdouble, %function
                \\LvailP521JacobianScalarMul_jdouble:
                \\        .cfi_startproc
                \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
                \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
                \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
                \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
                \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
                \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
                \\        subq $520, %rsp ; .cfi_adjust_cfa_offset 520
                \\        movq %rdi, 0x1f8(%rsp)
                \\        movq %rsi, 0x200(%rsp)
                \\        movq 0x200(%rsp), %rdi
                \\        leaq 0x90(%rdi), %rsi
                \\        leaq (%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        movq 0x200(%rsp), %rdi
                \\        leaq 0x48(%rdi), %rsi
                \\        leaq 0x48(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        movq 0x200(%rsp), %rdi
                \\        stc
                \\        movq (%rdi), %rax
                \\        adcq (%rsp), %rax
                \\        movq 0x8(%rdi), %rbx
                \\        adcq 0x8(%rsp), %rbx
                \\        movq 0x10(%rdi), %r8
                \\        adcq 0x10(%rsp), %r8
                \\        movq 0x18(%rdi), %r9
                \\        adcq 0x18(%rsp), %r9
                \\        movq 0x20(%rdi), %r10
                \\        adcq 0x20(%rsp), %r10
                \\        movq 0x28(%rdi), %r11
                \\        adcq 0x28(%rsp), %r11
                \\        movq 0x30(%rdi), %r12
                \\        adcq 0x30(%rsp), %r12
                \\        movq 0x38(%rdi), %r13
                \\        adcq 0x38(%rsp), %r13
                \\        movq 0x40(%rdi), %r14
                \\        adcq 0x40(%rsp), %r14
                \\        movq $0x200, %rdx
                \\        andq %r14, %rdx
                \\        cmpq $0x200, %rdx
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x168(%rsp)
                \\        sbbq $0x0, %rbx
                \\        movq %rbx, 0x170(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x178(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x180(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x188(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x190(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x198(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x1a0(%rsp)
                \\        sbbq %rdx, %r14
                \\        movq %r14, 0x1a8(%rsp)
                \\        movq 0x200(%rsp), %rdi
                \\        movq (%rdi), %rax
                \\        subq (%rsp), %rax
                \\        movq 0x8(%rdi), %rdx
                \\        sbbq 0x8(%rsp), %rdx
                \\        movq 0x10(%rdi), %r8
                \\        sbbq 0x10(%rsp), %r8
                \\        movq 0x18(%rdi), %r9
                \\        sbbq 0x18(%rsp), %r9
                \\        movq 0x20(%rdi), %r10
                \\        sbbq 0x20(%rsp), %r10
                \\        movq 0x28(%rdi), %r11
                \\        sbbq 0x28(%rsp), %r11
                \\        movq 0x30(%rdi), %r12
                \\        sbbq 0x30(%rsp), %r12
                \\        movq 0x38(%rdi), %r13
                \\        sbbq 0x38(%rsp), %r13
                \\        movq 0x40(%rdi), %r14
                \\        sbbq 0x40(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x120(%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x128(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x130(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x138(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x140(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x148(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x150(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x158(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x160(%rsp)
                \\        leaq 0x120(%rsp), %rdx
                \\        leaq 0x168(%rsp), %rsi
                \\        leaq 0x90(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x200(%rsp), %rdi
                \\        stc
                \\        movq 0x48(%rdi), %rax
                \\        adcq 0x90(%rdi), %rax
                \\        movq 0x50(%rdi), %rbx
                \\        adcq 0x98(%rdi), %rbx
                \\        movq 0x58(%rdi), %r8
                \\        adcq 0xa0(%rdi), %r8
                \\        movq 0x60(%rdi), %r9
                \\        adcq 0xa8(%rdi), %r9
                \\        movq 0x68(%rdi), %r10
                \\        adcq 0xb0(%rdi), %r10
                \\        movq 0x70(%rdi), %r11
                \\        adcq 0xb8(%rdi), %r11
                \\        movq 0x78(%rdi), %r12
                \\        adcq 0xc0(%rdi), %r12
                \\        movq 0x80(%rdi), %r13
                \\        adcq 0xc8(%rdi), %r13
                \\        movq 0x88(%rdi), %r14
                \\        adcq 0xd0(%rdi), %r14
                \\        movq $0x200, %rdx
                \\        andq %r14, %rdx
                \\        cmpq $0x200, %rdx
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x168(%rsp)
                \\        sbbq $0x0, %rbx
                \\        movq %rbx, 0x170(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x178(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x180(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x188(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x190(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x198(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x1a0(%rsp)
                \\        sbbq %rdx, %r14
                \\        movq %r14, 0x1a8(%rsp)
                \\        leaq 0x90(%rsp), %rsi
                \\        leaq 0x1b0(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        movq 0x200(%rsp), %rdi
                \\        leaq 0x48(%rsp), %rdx
                \\        leaq (%rdi), %rsi
                \\        leaq 0xd8(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        leaq 0x168(%rsp), %rsi
                \\        leaq 0x120(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        movq $0x9, %rdx
                \\        movq 0x1f0(%rsp), %rbx
                \\        xorq $0x1ff, %rbx
                \\        movq 0x1b0(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %r8, %r9
                \\        movq 0x1b8(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %rax, %r10
                \\        addq %rax, %r9
                \\        movq 0x1c0(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %rax, %r11
                \\        adcq %rax, %r10
                \\        movq 0x1c8(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %rax, %r12
                \\        adcq %rax, %r11
                \\        movq 0x1d0(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %rax, %r13
                \\        adcq %rax, %r12
                \\        movq 0x1d8(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %rax, %r14
                \\        adcq %rax, %r13
                \\        movq 0x1e0(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %rax, %r15
                \\        adcq %rax, %r14
                \\        movq 0x1e8(%rsp), %rax
                \\        notq %rax
                \\        mulxq %rax, %rax, %rcx
                \\        adcq %rax, %r15
                \\        mulxq %rbx, %rbx, %rax
                \\        adcq %rcx, %rbx
                \\        xorl %eax, %eax
                \\        movq $0xc, %rdx
                \\        mulxq 0xd8(%rsp), %rax, %rcx
                \\        adcxq %rax, %r8
                \\        adoxq %rcx, %r9
                \\        mulxq 0xe0(%rsp), %rax, %rcx
                \\        adcxq %rax, %r9
                \\        adoxq %rcx, %r10
                \\        mulxq 0xe8(%rsp), %rax, %rcx
                \\        adcxq %rax, %r10
                \\        adoxq %rcx, %r11
                \\        mulxq 0xf0(%rsp), %rax, %rcx
                \\        adcxq %rax, %r11
                \\        adoxq %rcx, %r12
                \\        mulxq 0xf8(%rsp), %rax, %rcx
                \\        adcxq %rax, %r12
                \\        adoxq %rcx, %r13
                \\        mulxq 0x100(%rsp), %rax, %rcx
                \\        adcxq %rax, %r13
                \\        adoxq %rcx, %r14
                \\        mulxq 0x108(%rsp), %rax, %rcx
                \\        adcxq %rax, %r14
                \\        adoxq %rcx, %r15
                \\        mulxq 0x110(%rsp), %rax, %rcx
                \\        adcxq %rax, %r15
                \\        adoxq %rcx, %rbx
                \\        mulxq 0x118(%rsp), %rax, %rcx
                \\        adcxq %rax, %rbx
                \\        movq %r9, %rax
                \\        andq %r10, %rax
                \\        andq %r11, %rax
                \\        andq %r12, %rax
                \\        andq %r13, %rax
                \\        andq %r14, %rax
                \\        andq %r15, %rax
                \\        movq %rbx, %rdx
                \\        shrq $0x9, %rdx
                \\        orq $0xfffffffffffffe00, %rbx
                \\        leaq 0x1(%rdx), %rcx
                \\        addq %r8, %rcx
                \\        movl $0x0, %ecx
                \\        adcq %rcx, %rax
                \\        movq %rbx, %rax
                \\        adcq %rcx, %rax
                \\        adcq %rdx, %r8
                \\        movq %r8, 0x1b0(%rsp)
                \\        adcq %rcx, %r9
                \\        movq %r9, 0x1b8(%rsp)
                \\        adcq %rcx, %r10
                \\        movq %r10, 0x1c0(%rsp)
                \\        adcq %rcx, %r11
                \\        movq %r11, 0x1c8(%rsp)
                \\        adcq %rcx, %r12
                \\        movq %r12, 0x1d0(%rsp)
                \\        adcq %rcx, %r13
                \\        movq %r13, 0x1d8(%rsp)
                \\        adcq %rcx, %r14
                \\        movq %r14, 0x1e0(%rsp)
                \\        adcq %rcx, %r15
                \\        movq %r15, 0x1e8(%rsp)
                \\        adcq %rcx, %rbx
                \\        andq $0x1ff, %rbx
                \\        movq %rbx, 0x1f0(%rsp)
                \\        movq 0x120(%rsp), %rax
                \\        subq (%rsp), %rax
                \\        movq 0x128(%rsp), %rdx
                \\        sbbq 0x8(%rsp), %rdx
                \\        movq 0x130(%rsp), %r8
                \\        sbbq 0x10(%rsp), %r8
                \\        movq 0x138(%rsp), %r9
                \\        sbbq 0x18(%rsp), %r9
                \\        movq 0x140(%rsp), %r10
                \\        sbbq 0x20(%rsp), %r10
                \\        movq 0x148(%rsp), %r11
                \\        sbbq 0x28(%rsp), %r11
                \\        movq 0x150(%rsp), %r12
                \\        sbbq 0x30(%rsp), %r12
                \\        movq 0x158(%rsp), %r13
                \\        sbbq 0x38(%rsp), %r13
                \\        movq 0x160(%rsp), %r14
                \\        sbbq 0x40(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x168(%rsp)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x170(%rsp)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0x178(%rsp)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x180(%rsp)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x188(%rsp)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x190(%rsp)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x198(%rsp)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x1a0(%rsp)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0x1a8(%rsp)
                \\        leaq 0x48(%rsp), %rsi
                \\        leaq 0x120(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_sqr_p521
                \\        movq 0x1f8(%rsp), %rdi
                \\        movq 0x168(%rsp), %rax
                \\        subq 0x48(%rsp), %rax
                \\        movq 0x170(%rsp), %rdx
                \\        sbbq 0x50(%rsp), %rdx
                \\        movq 0x178(%rsp), %r8
                \\        sbbq 0x58(%rsp), %r8
                \\        movq 0x180(%rsp), %r9
                \\        sbbq 0x60(%rsp), %r9
                \\        movq 0x188(%rsp), %r10
                \\        sbbq 0x68(%rsp), %r10
                \\        movq 0x190(%rsp), %r11
                \\        sbbq 0x70(%rsp), %r11
                \\        movq 0x198(%rsp), %r12
                \\        sbbq 0x78(%rsp), %r12
                \\        movq 0x1a0(%rsp), %r13
                \\        sbbq 0x80(%rsp), %r13
                \\        movq 0x1a8(%rsp), %r14
                \\        sbbq 0x88(%rsp), %r14
                \\        sbbq $0x0, %rax
                \\        movq %rax, 0x90(%rdi)
                \\        sbbq $0x0, %rdx
                \\        movq %rdx, 0x98(%rdi)
                \\        sbbq $0x0, %r8
                \\        movq %r8, 0xa0(%rdi)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0xa8(%rdi)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0xb0(%rdi)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0xb8(%rdi)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0xc0(%rdi)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0xc8(%rdi)
                \\        sbbq $0x0, %r14
                \\        andq $0x1ff, %r14
                \\        movq %r14, 0xd0(%rdi)
                \\        leaq 0x90(%rsp), %rdx
                \\        leaq 0x1b0(%rsp), %rsi
                \\        leaq 0x168(%rsp), %rdi
                \\        callq LvailP521JacobianScalarMul_mul_p521
                \\        movq 0x1f8(%rsp), %rdi
                \\        movq 0x118(%rsp), %rbx
                \\        movq 0x110(%rsp), %r15
                \\        shldq $0x2, %r15, %rbx
                \\        movq 0x108(%rsp), %r14
                \\        shldq $0x2, %r14, %r15
                \\        movq 0x100(%rsp), %r13
                \\        shldq $0x2, %r13, %r14
                \\        movq 0xf8(%rsp), %r12
                \\        shldq $0x2, %r12, %r13
                \\        movq 0xf0(%rsp), %r11
                \\        shldq $0x2, %r11, %r12
                \\        movq 0xe8(%rsp), %r10
                \\        shldq $0x2, %r10, %r11
                \\        movq 0xe0(%rsp), %r9
                \\        shldq $0x2, %r9, %r10
                \\        movq 0xd8(%rsp), %r8
                \\        shldq $0x2, %r8, %r9
                \\        shlq $0x2, %r8
                \\        movq 0x1f0(%rsp), %rcx
                \\        xorq $0x1ff, %rcx
                \\        movq 0x1b0(%rsp), %rax
                \\        notq %rax
                \\        addq %rax, %r8
                \\        movq 0x1b8(%rsp), %rax
                \\        notq %rax
                \\        adcq %rax, %r9
                \\        movq 0x1c0(%rsp), %rax
                \\        notq %rax
                \\        adcq %rax, %r10
                \\        movq 0x1c8(%rsp), %rax
                \\        notq %rax
                \\        adcq %rax, %r11
                \\        movq 0x1d0(%rsp), %rax
                \\        notq %rax
                \\        adcq %rax, %r12
                \\        movq 0x1d8(%rsp), %rax
                \\        notq %rax
                \\        adcq %rax, %r13
                \\        movq 0x1e0(%rsp), %rax
                \\        notq %rax
                \\        adcq %rax, %r14
                \\        movq 0x1e8(%rsp), %rax
                \\        notq %rax
                \\        adcq %rax, %r15
                \\        adcq %rcx, %rbx
                \\        movq %r9, %rax
                \\        andq %r10, %rax
                \\        andq %r11, %rax
                \\        andq %r12, %rax
                \\        andq %r13, %rax
                \\        andq %r14, %rax
                \\        andq %r15, %rax
                \\        movq %rbx, %rdx
                \\        shrq $0x9, %rdx
                \\        orq $0xfffffffffffffe00, %rbx
                \\        leaq 0x1(%rdx), %rcx
                \\        addq %r8, %rcx
                \\        movl $0x0, %ecx
                \\        adcq %rcx, %rax
                \\        movq %rbx, %rax
                \\        adcq %rcx, %rax
                \\        adcq %rdx, %r8
                \\        movq %r8, (%rdi)
                \\        adcq %rcx, %r9
                \\        movq %r9, 0x8(%rdi)
                \\        adcq %rcx, %r10
                \\        movq %r10, 0x10(%rdi)
                \\        adcq %rcx, %r11
                \\        movq %r11, 0x18(%rdi)
                \\        adcq %rcx, %r12
                \\        movq %r12, 0x20(%rdi)
                \\        adcq %rcx, %r13
                \\        movq %r13, 0x28(%rdi)
                \\        adcq %rcx, %r14
                \\        movq %r14, 0x30(%rdi)
                \\        adcq %rcx, %r15
                \\        movq %r15, 0x38(%rdi)
                \\        adcq %rcx, %rbx
                \\        andq $0x1ff, %rbx
                \\        movq %rbx, 0x40(%rdi)
                \\        movq 0x1f8(%rsp), %rdi
                \\        movq 0x160(%rsp), %rbx
                \\        xorq $0x1ff, %rbx
                \\        movq 0x158(%rsp), %r15
                \\        notq %r15
                \\        shldq $0x3, %r15, %rbx
                \\        movq 0x150(%rsp), %r14
                \\        notq %r14
                \\        shldq $0x3, %r14, %r15
                \\        movq 0x148(%rsp), %r13
                \\        notq %r13
                \\        shldq $0x3, %r13, %r14
                \\        movq 0x140(%rsp), %r12
                \\        notq %r12
                \\        shldq $0x3, %r12, %r13
                \\        movq 0x138(%rsp), %r11
                \\        notq %r11
                \\        shldq $0x3, %r11, %r12
                \\        movq 0x130(%rsp), %r10
                \\        notq %r10
                \\        shldq $0x3, %r10, %r11
                \\        movq 0x128(%rsp), %r9
                \\        notq %r9
                \\        shldq $0x3, %r9, %r10
                \\        movq 0x120(%rsp), %r8
                \\        notq %r8
                \\        shldq $0x3, %r8, %r9
                \\        shlq $0x3, %r8
                \\        movq $0x3, %rdx
                \\        xorl %eax, %eax
                \\        mulxq 0x168(%rsp), %rax, %rcx
                \\        adcxq %rax, %r8
                \\        adoxq %rcx, %r9
                \\        mulxq 0x170(%rsp), %rax, %rcx
                \\        adcxq %rax, %r9
                \\        adoxq %rcx, %r10
                \\        mulxq 0x178(%rsp), %rax, %rcx
                \\        adcxq %rax, %r10
                \\        adoxq %rcx, %r11
                \\        mulxq 0x180(%rsp), %rax, %rcx
                \\        adcxq %rax, %r11
                \\        adoxq %rcx, %r12
                \\        mulxq 0x188(%rsp), %rax, %rcx
                \\        adcxq %rax, %r12
                \\        adoxq %rcx, %r13
                \\        mulxq 0x190(%rsp), %rax, %rcx
                \\        adcxq %rax, %r13
                \\        adoxq %rcx, %r14
                \\        mulxq 0x198(%rsp), %rax, %rcx
                \\        adcxq %rax, %r14
                \\        adoxq %rcx, %r15
                \\        mulxq 0x1a0(%rsp), %rax, %rcx
                \\        adcxq %rax, %r15
                \\        adoxq %rcx, %rbx
                \\        mulxq 0x1a8(%rsp), %rax, %rcx
                \\        adcxq %rax, %rbx
                \\        movq %r9, %rax
                \\        andq %r10, %rax
                \\        andq %r11, %rax
                \\        andq %r12, %rax
                \\        andq %r13, %rax
                \\        andq %r14, %rax
                \\        andq %r15, %rax
                \\        movq %rbx, %rdx
                \\        shrq $0x9, %rdx
                \\        orq $0xfffffffffffffe00, %rbx
                \\        leaq 0x1(%rdx), %rcx
                \\        addq %r8, %rcx
                \\        movl $0x0, %ecx
                \\        adcq %rcx, %rax
                \\        movq %rbx, %rax
                \\        adcq %rcx, %rax
                \\        adcq %rdx, %r8
                \\        movq %r8, 0x48(%rdi)
                \\        adcq %rcx, %r9
                \\        movq %r9, 0x50(%rdi)
                \\        adcq %rcx, %r10
                \\        movq %r10, 0x58(%rdi)
                \\        adcq %rcx, %r11
                \\        movq %r11, 0x60(%rdi)
                \\        adcq %rcx, %r12
                \\        movq %r12, 0x68(%rdi)
                \\        adcq %rcx, %r13
                \\        movq %r13, 0x70(%rdi)
                \\        adcq %rcx, %r14
                \\        movq %r14, 0x78(%rdi)
                \\        adcq %rcx, %r15
                \\        movq %r15, 0x80(%rdi)
                \\        adcq %rcx, %rbx
                \\        andq $0x1ff, %rbx
                \\        movq %rbx, 0x88(%rdi)
                \\        addq $520, %rsp ; .cfi_adjust_cfa_offset -520
                \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
                \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
                \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
                \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
                \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
                \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
                \\        retq ; .cfi_endproc
                \\.size LvailP521JacobianScalarMul_jdouble, .-LvailP521JacobianScalarMul_jdouble
                \\.type LvailP521JacobianScalarMul_mul_p521, %function
                \\LvailP521JacobianScalarMul_mul_p521:
                \\        .cfi_startproc
                \\        subq $64, %rsp ; .cfi_adjust_cfa_offset 64
                \\        movq %rdx, %rcx
                \\        xorl %ebp, %ebp
                \\        movq (%rcx), %rdx
                \\        mulxq (%rsi), %r8, %r9
                \\        movq %r8, (%rsp)
                \\        mulxq 0x8(%rsi), %rbx, %r10
                \\        adcq %rbx, %r9
                \\        mulxq 0x10(%rsi), %rbx, %r11
                \\        adcq %rbx, %r10
                \\        mulxq 0x18(%rsi), %rbx, %r12
                \\        adcq %rbx, %r11
                \\        mulxq 0x20(%rsi), %rbx, %r13
                \\        adcq %rbx, %r12
                \\        mulxq 0x28(%rsi), %rbx, %r14
                \\        adcq %rbx, %r13
                \\        mulxq 0x30(%rsi), %rbx, %r15
                \\        adcq %rbx, %r14
                \\        mulxq 0x38(%rsi), %rbx, %r8
                \\        adcq %rbx, %r15
                \\        adcq %rbp, %r8
                \\        movq 0x8(%rcx), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        movq %r9, 0x8(%rsp)
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %r8
                \\        mulxq 0x38(%rsi), %rax, %r9
                \\        adcxq %rax, %r8
                \\        adoxq %rbp, %r9
                \\        adcq %rbp, %r9
                \\        movq 0x10(%rcx), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        movq %r10, 0x10(%rsp)
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %r8
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x38(%rsi), %rax, %r10
                \\        adcxq %rax, %r9
                \\        adoxq %rbp, %r10
                \\        adcq %rbp, %r10
                \\        movq 0x18(%rcx), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        movq %r11, 0x18(%rsp)
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %r8
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        mulxq 0x38(%rsi), %rax, %r11
                \\        adcxq %rax, %r10
                \\        adoxq %rbp, %r11
                \\        adcq %rbp, %r11
                \\        movq 0x20(%rcx), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        movq %r12, 0x20(%rsp)
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %r8
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        mulxq 0x38(%rsi), %rax, %r12
                \\        adcxq %rax, %r11
                \\        adoxq %rbp, %r12
                \\        adcq %rbp, %r12
                \\        movq 0x28(%rcx), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        movq %r13, 0x28(%rsp)
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %r8
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        mulxq 0x38(%rsi), %rax, %r13
                \\        adcxq %rax, %r12
                \\        adoxq %rbp, %r13
                \\        adcq %rbp, %r13
                \\        movq 0x30(%rcx), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        movq %r14, 0x30(%rsp)
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %r8
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        mulxq 0x38(%rsi), %rax, %r14
                \\        adcxq %rax, %r13
                \\        adoxq %rbp, %r14
                \\        adcq %rbp, %r14
                \\        movq 0x38(%rcx), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %r8
                \\        movq %r15, 0x38(%rsp)
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        mulxq 0x38(%rsi), %rax, %r15
                \\        adcxq %rax, %r14
                \\        adoxq %rbp, %r15
                \\        adcq %rbp, %r15
                \\        movq 0x40(%rsi), %rdx
                \\        xorl %ebp, %ebp
                \\        mulxq (%rcx), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x8(%rcx), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        mulxq 0x10(%rcx), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        mulxq 0x18(%rcx), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        mulxq 0x20(%rcx), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        mulxq 0x28(%rcx), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        mulxq 0x30(%rcx), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        mulxq 0x38(%rcx), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbp, %rbx
                \\        adcq %rbx, %rbp
                \\        movq 0x40(%rcx), %rdx
                \\        xorl %eax, %eax
                \\        mulxq (%rsi), %rax, %rbx
                \\        adcxq %rax, %r8
                \\        adoxq %rbx, %r9
                \\        mulxq 0x8(%rsi), %rax, %rbx
                \\        adcxq %rax, %r9
                \\        adoxq %rbx, %r10
                \\        mulxq 0x10(%rsi), %rax, %rbx
                \\        adcxq %rax, %r10
                \\        adoxq %rbx, %r11
                \\        mulxq 0x18(%rsi), %rax, %rbx
                \\        adcxq %rax, %r11
                \\        adoxq %rbx, %r12
                \\        mulxq 0x20(%rsi), %rax, %rbx
                \\        adcxq %rax, %r12
                \\        adoxq %rbx, %r13
                \\        mulxq 0x28(%rsi), %rax, %rbx
                \\        adcxq %rax, %r13
                \\        adoxq %rbx, %r14
                \\        mulxq 0x30(%rsi), %rax, %rbx
                \\        adcxq %rax, %r14
                \\        adoxq %rbx, %r15
                \\        mulxq 0x38(%rsi), %rax, %rbx
                \\        adcxq %rax, %r15
                \\        adoxq %rbx, %rbp
                \\        mulxq 0x40(%rsi), %rax, %rbx
                \\        adcq %rax, %rbp
                \\        movq %r8, %rax
                \\        andq $0x1ff, %rax
                \\        shrdq $0x9, %r9, %r8
                \\        shrdq $0x9, %r10, %r9
                \\        shrdq $0x9, %r11, %r10
                \\        shrdq $0x9, %r12, %r11
                \\        shrdq $0x9, %r13, %r12
                \\        shrdq $0x9, %r14, %r13
                \\        shrdq $0x9, %r15, %r14
                \\        shrdq $0x9, %rbp, %r15
                \\        shrq $0x9, %rbp
                \\        addq %rax, %rbp
                \\        stc
                \\        adcq (%rsp), %r8
                \\        adcq 0x8(%rsp), %r9
                \\        adcq 0x10(%rsp), %r10
                \\        adcq 0x18(%rsp), %r11
                \\        adcq 0x20(%rsp), %r12
                \\        adcq 0x28(%rsp), %r13
                \\        adcq 0x30(%rsp), %r14
                \\        adcq 0x38(%rsp), %r15
                \\        adcq $0xfffffffffffffe00, %rbp
                \\        cmc
                \\        sbbq $0x0, %r8
                \\        movq %r8, (%rdi)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x8(%rdi)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x10(%rdi)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x18(%rdi)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x20(%rdi)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x28(%rdi)
                \\        sbbq $0x0, %r14
                \\        movq %r14, 0x30(%rdi)
                \\        sbbq $0x0, %r15
                \\        movq %r15, 0x38(%rdi)
                \\        sbbq $0x0, %rbp
                \\        andq $0x1ff, %rbp
                \\        movq %rbp, 0x40(%rdi)
                \\        addq $64, %rsp ; .cfi_adjust_cfa_offset -64
                \\        retq ; .cfi_endproc
                \\.size LvailP521JacobianScalarMul_mul_p521, .-LvailP521JacobianScalarMul_mul_p521
                \\.type LvailP521JacobianScalarMul_sqr_p521, %function
                \\LvailP521JacobianScalarMul_sqr_p521:
                \\        .cfi_startproc
                \\        subq $64, %rsp ; .cfi_adjust_cfa_offset 64
                \\        xorl %ebp, %ebp
                \\        movq (%rsi), %rdx
                \\        mulxq 0x8(%rsi), %r9, %rax
                \\        movq %r9, 0x8(%rsp)
                \\        mulxq 0x10(%rsi), %r10, %rcx
                \\        adcxq %rax, %r10
                \\        movq %r10, 0x10(%rsp)
                \\        mulxq 0x18(%rsi), %r11, %rax
                \\        adcxq %rcx, %r11
                \\        mulxq 0x20(%rsi), %r12, %rcx
                \\        adcxq %rax, %r12
                \\        mulxq 0x28(%rsi), %r13, %rax
                \\        adcxq %rcx, %r13
                \\        mulxq 0x30(%rsi), %r14, %rcx
                \\        adcxq %rax, %r14
                \\        mulxq 0x38(%rsi), %r15, %r8
                \\        adcxq %rcx, %r15
                \\        adcxq %rbp, %r8
                \\        xorl %ebp, %ebp
                \\        movq 0x8(%rsi), %rdx
                \\        mulxq 0x10(%rsi), %rax, %rcx
                \\        adcxq %rax, %r11
                \\        adoxq %rcx, %r12
                \\        movq %r11, 0x18(%rsp)
                \\        mulxq 0x18(%rsi), %rax, %rcx
                \\        adcxq %rax, %r12
                \\        adoxq %rcx, %r13
                \\        movq %r12, 0x20(%rsp)
                \\        mulxq 0x20(%rsi), %rax, %rcx
                \\        adcxq %rax, %r13
                \\        adoxq %rcx, %r14
                \\        mulxq 0x28(%rsi), %rax, %rcx
                \\        adcxq %rax, %r14
                \\        adoxq %rcx, %r15
                \\        mulxq 0x30(%rsi), %rax, %rcx
                \\        adcxq %rax, %r15
                \\        adoxq %rcx, %r8
                \\        mulxq 0x38(%rsi), %rax, %r9
                \\        adcxq %rax, %r8
                \\        adoxq %rbp, %r9
                \\        movq 0x20(%rsi), %rdx
                \\        mulxq 0x28(%rsi), %rax, %r10
                \\        adcxq %rax, %r9
                \\        adoxq %rbp, %r10
                \\        adcxq %rbp, %r10
                \\        xorl %ebp, %ebp
                \\        movq 0x10(%rsi), %rdx
                \\        mulxq 0x18(%rsi), %rax, %rcx
                \\        adcxq %rax, %r13
                \\        adoxq %rcx, %r14
                \\        movq %r13, 0x28(%rsp)
                \\        mulxq 0x20(%rsi), %rax, %rcx
                \\        adcxq %rax, %r14
                \\        adoxq %rcx, %r15
                \\        movq %r14, 0x30(%rsp)
                \\        mulxq 0x28(%rsi), %rax, %rcx
                \\        adcxq %rax, %r15
                \\        adoxq %rcx, %r8
                \\        mulxq 0x30(%rsi), %rax, %rcx
                \\        adcxq %rax, %r8
                \\        adoxq %rcx, %r9
                \\        mulxq 0x38(%rsi), %rax, %rcx
                \\        adcxq %rax, %r9
                \\        adoxq %rcx, %r10
                \\        movq 0x30(%rsi), %rdx
                \\        mulxq 0x20(%rsi), %rax, %r11
                \\        adcxq %rax, %r10
                \\        adoxq %rbp, %r11
                \\        mulxq 0x28(%rsi), %rax, %r12
                \\        adcxq %rax, %r11
                \\        adoxq %rbp, %r12
                \\        adcxq %rbp, %r12
                \\        xorl %ebp, %ebp
                \\        movq 0x18(%rsi), %rdx
                \\        mulxq 0x20(%rsi), %rax, %rcx
                \\        adcxq %rax, %r15
                \\        adoxq %rcx, %r8
                \\        movq %r15, 0x38(%rsp)
                \\        mulxq 0x28(%rsi), %rax, %rcx
                \\        adcxq %rax, %r8
                \\        adoxq %rcx, %r9
                \\        mulxq 0x30(%rsi), %rax, %rcx
                \\        adcxq %rax, %r9
                \\        adoxq %rcx, %r10
                \\        mulxq 0x38(%rsi), %rax, %rcx
                \\        adcxq %rax, %r10
                \\        adoxq %rcx, %r11
                \\        movq 0x38(%rsi), %rdx
                \\        mulxq 0x20(%rsi), %rax, %rcx
                \\        adcxq %rax, %r11
                \\        adoxq %rcx, %r12
                \\        mulxq 0x28(%rsi), %rax, %r13
                \\        adcxq %rax, %r12
                \\        adoxq %rbp, %r13
                \\        mulxq 0x30(%rsi), %rax, %r14
                \\        adcxq %rax, %r13
                \\        adoxq %rbp, %r14
                \\        adcxq %rbp, %r14
                \\        xorl %ebp, %ebp
                \\        movq (%rsi), %rdx
                \\        mulxq %rdx, %rax, %rcx
                \\        movq %rax, (%rsp)
                \\        movq 0x8(%rsp), %rax
                \\        adcxq %rax, %rax
                \\        adoxq %rcx, %rax
                \\        movq %rax, 0x8(%rsp)
                \\        movq 0x10(%rsp), %rax
                \\        movq 0x8(%rsi), %rdx
                \\        mulxq %rdx, %rdx, %rcx
                \\        adcxq %rax, %rax
                \\        adoxq %rdx, %rax
                \\        movq %rax, 0x10(%rsp)
                \\        movq 0x18(%rsp), %rax
                \\        adcxq %rax, %rax
                \\        adoxq %rcx, %rax
                \\        movq %rax, 0x18(%rsp)
                \\        movq 0x20(%rsp), %rax
                \\        movq 0x10(%rsi), %rdx
                \\        mulxq %rdx, %rdx, %rcx
                \\        adcxq %rax, %rax
                \\        adoxq %rdx, %rax
                \\        movq %rax, 0x20(%rsp)
                \\        movq 0x28(%rsp), %rax
                \\        adcxq %rax, %rax
                \\        adoxq %rcx, %rax
                \\        movq %rax, 0x28(%rsp)
                \\        movq 0x30(%rsp), %rax
                \\        movq 0x18(%rsi), %rdx
                \\        mulxq %rdx, %rdx, %rcx
                \\        adcxq %rax, %rax
                \\        adoxq %rdx, %rax
                \\        movq %rax, 0x30(%rsp)
                \\        movq 0x38(%rsp), %rax
                \\        adcxq %rax, %rax
                \\        adoxq %rcx, %rax
                \\        movq %rax, 0x38(%rsp)
                \\        movq 0x20(%rsi), %rdx
                \\        mulxq %rdx, %rdx, %rcx
                \\        adcxq %r8, %r8
                \\        adoxq %rdx, %r8
                \\        adcxq %r9, %r9
                \\        adoxq %rcx, %r9
                \\        movq 0x28(%rsi), %rdx
                \\        mulxq %rdx, %rdx, %rcx
                \\        adcxq %r10, %r10
                \\        adoxq %rdx, %r10
                \\        adcxq %r11, %r11
                \\        adoxq %rcx, %r11
                \\        movq 0x30(%rsi), %rdx
                \\        mulxq %rdx, %rdx, %rcx
                \\        adcxq %r12, %r12
                \\        adoxq %rdx, %r12
                \\        adcxq %r13, %r13
                \\        adoxq %rcx, %r13
                \\        movq 0x38(%rsi), %rdx
                \\        mulxq %rdx, %rdx, %r15
                \\        adcxq %r14, %r14
                \\        adoxq %rdx, %r14
                \\        adcxq %rbp, %r15
                \\        adoxq %rbp, %r15
                \\        movq 0x40(%rsi), %rdx
                \\        movq %rdx, %rbp
                \\        imulq %rbp, %rbp
                \\        addq %rdx, %rdx
                \\        mulxq (%rsi), %rax, %rcx
                \\        adcxq %rax, %r8
                \\        adoxq %rcx, %r9
                \\        mulxq 0x8(%rsi), %rax, %rcx
                \\        adcxq %rax, %r9
                \\        adoxq %rcx, %r10
                \\        mulxq 0x10(%rsi), %rax, %rcx
                \\        adcxq %rax, %r10
                \\        adoxq %rcx, %r11
                \\        mulxq 0x18(%rsi), %rax, %rcx
                \\        adcxq %rax, %r11
                \\        adoxq %rcx, %r12
                \\        mulxq 0x20(%rsi), %rax, %rcx
                \\        adcxq %rax, %r12
                \\        adoxq %rcx, %r13
                \\        mulxq 0x28(%rsi), %rax, %rcx
                \\        adcxq %rax, %r13
                \\        adoxq %rcx, %r14
                \\        mulxq 0x30(%rsi), %rax, %rcx
                \\        adcxq %rax, %r14
                \\        adoxq %rcx, %r15
                \\        mulxq 0x38(%rsi), %rax, %rcx
                \\        adcxq %rax, %r15
                \\        adoxq %rcx, %rbp
                \\        adcq $0x0, %rbp
                \\        movq %r8, %rax
                \\        andq $0x1ff, %rax
                \\        shrdq $0x9, %r9, %r8
                \\        shrdq $0x9, %r10, %r9
                \\        shrdq $0x9, %r11, %r10
                \\        shrdq $0x9, %r12, %r11
                \\        shrdq $0x9, %r13, %r12
                \\        shrdq $0x9, %r14, %r13
                \\        shrdq $0x9, %r15, %r14
                \\        shrdq $0x9, %rbp, %r15
                \\        shrq $0x9, %rbp
                \\        addq %rax, %rbp
                \\        stc
                \\        adcq (%rsp), %r8
                \\        adcq 0x8(%rsp), %r9
                \\        adcq 0x10(%rsp), %r10
                \\        adcq 0x18(%rsp), %r11
                \\        adcq 0x20(%rsp), %r12
                \\        adcq 0x28(%rsp), %r13
                \\        adcq 0x30(%rsp), %r14
                \\        adcq 0x38(%rsp), %r15
                \\        adcq $0xfffffffffffffe00, %rbp
                \\        cmc
                \\        sbbq $0x0, %r8
                \\        movq %r8, (%rdi)
                \\        sbbq $0x0, %r9
                \\        movq %r9, 0x8(%rdi)
                \\        sbbq $0x0, %r10
                \\        movq %r10, 0x10(%rdi)
                \\        sbbq $0x0, %r11
                \\        movq %r11, 0x18(%rdi)
                \\        sbbq $0x0, %r12
                \\        movq %r12, 0x20(%rdi)
                \\        sbbq $0x0, %r13
                \\        movq %r13, 0x28(%rdi)
                \\        sbbq $0x0, %r14
                \\        movq %r14, 0x30(%rdi)
                \\        sbbq $0x0, %r15
                \\        movq %r15, 0x38(%rdi)
                \\        sbbq $0x0, %rbp
                \\        andq $0x1ff, %rbp
                \\        movq %rbp, 0x40(%rdi)
                \\        addq $64, %rsp ; .cfi_adjust_cfa_offset -64
                \\        retq ; .cfi_endproc
                \\.size LvailP521JacobianScalarMul_sqr_p521, .-LvailP521JacobianScalarMul_sqr_p521
        );
    }
}
