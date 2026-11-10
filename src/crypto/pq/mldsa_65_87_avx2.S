# Copyright (c) The mldsa-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored from mldsa-native's formally verified AVX2 gamma2=(q-1)/32
# use-hint and gamma1=2^19 unpack schedules, preprocessed for ELF x86_64 SysV.
.pushsection ".note.gnu.property", "a"
 .p2align 3
 .long 1f - 0f
 .long 4f - 1f
 .long 5
0:
 .asciz "GNU"
1:
 .p2align 3
 .long 0xc0000002
 .long 3f - 2f
2:
 .long (0x1 | 0x2)
3:
 .p2align 3
4:
 .popsection
.text
.balign 4
        .globl vailMldsaUseHint32
       
vailMldsaUseHint32:
        .cfi_startproc
        movl $0x7f, %ecx
        movl $0x401, %r8d # imm = 0x401
        vmovd %r8d, %xmm8
        vpbroadcastd %xmm8, %ymm8
        xorl %eax, %eax
        vpxor %xmm6, %xmm6, %xmm6
        vmovd %ecx, %xmm5
        movl $0x7be100, %ecx # imm = 0x7BE100
        movl $0x200, %r9d # imm = 0x200
        vmovd %r9d, %xmm7
        vpbroadcastd %xmm7, %ymm7
        vmovd %ecx, %xmm4
        movl $0xf, %ecx
        vpbroadcastd %xmm5, %ymm5
        vmovd %ecx, %xmm3
        vpbroadcastd %xmm4, %ymm4
        vpbroadcastd %xmm3, %ymm3
Lmld_poly_use_hint_32_avx2_asm_loop:
        vmovdqa (%rdi), %ymm0
        vmovdqa (%rsi), %ymm2
        vpaddd %ymm0, %ymm5, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm8, %ymm1, %ymm1
        vpmulhrsw %ymm7, %ymm1, %ymm1
        vpcmpgtd %ymm4, %ymm0, %ymm11
        vpandn %ymm1, %ymm11, %ymm9
        vpslld $0xa, %ymm1, %ymm10
        vpsubd %ymm1, %ymm10, %ymm1
        vpslld $0x9, %ymm1, %ymm1
        vpsubd %ymm1, %ymm0, %ymm0
        vpaddd %ymm11, %ymm0, %ymm0
        vpcmpgtd %ymm6, %ymm0, %ymm0
        vpandn %ymm2, %ymm0, %ymm0
        vpslld $0x1, %ymm0, %ymm0
        vpsubd %ymm0, %ymm2, %ymm2
        vpaddd %ymm9, %ymm2, %ymm2
        vpand %ymm3, %ymm2, %ymm2
        vmovdqa %ymm2, (%rdi)
        addq $0x20, %rdi
        addq $0x20, %rsi
        addq $0x20, %rax
        cmpq $0x400, %rax # imm = 0x400
        jne Lmld_poly_use_hint_32_avx2_asm_loop
        retq
        .cfi_endproc
.size vailMldsaUseHint32, .-vailMldsaUseHint32
.section .note.GNU-stack,"",%progbits
.pushsection ".note.gnu.property", "a"
 .p2align 3
 .long 1f - 0f
 .long 4f - 1f
 .long 5
0:
 .asciz "GNU"
1:
 .p2align 3
 .long 0xc0000002
 .long 3f - 2f
2:
 .long (0x1 | 0x2)
3:
 .p2align 3
4:
 .popsection
.text
.balign 4
        .globl vailMldsaUnpackZ19
       
vailMldsaUnpackZ19:
        .cfi_startproc
        movabsq $-0xfbfcfd00fdff00, %rax # imm = 0xFF040302FF020100
        vmovq %rax, %xmm1
        movabsq $-0xf6f7f800f8f9fb, %rax # imm = 0xFF090807FF070605
        vpinsrq $0x1, %rax, %xmm1, %xmm1
        movabsq $-0xe5e6e700e7e8ea, %rax # imm = 0xFF1A1918FF181716
        vmovq %rax, %xmm5
        movabsq $-0xe0e1e200e2e3e5, %rax # imm = 0xFF1F1E1DFF1D1C1B
        vpinsrq $0x1, %rax, %xmm5, %xmm5
        vinserti128 $0x1, %xmm5, %ymm1, %ymm1
        movabsq $0x400000000, %rax # imm = 0x400000000
        vmovq %rax, %xmm2
        movabsq $0x400000000, %rax # imm = 0x400000000
        vpinsrq $0x1, %rax, %xmm2, %xmm2
        vinserti128 $0x1, %xmm2, %ymm2, %ymm2
        movl $0xfffff, %eax # imm = 0xFFFFF
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $0x80000, %eax # imm = 0x80000
        vmovd %eax, %xmm4
        vpbroadcastd %xmm4, %ymm4
        vmovdqu (%rsi), %xmm0
        vmovdqu 0x4(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, (%rdi)
        vmovdqu 0x14(%rsi), %xmm0
        vmovdqu 0x18(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x20(%rdi)
        vmovdqu 0x28(%rsi), %xmm0
        vmovdqu 0x2c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x40(%rdi)
        vmovdqu 0x3c(%rsi), %xmm0
        vmovdqu 0x40(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x60(%rdi)
        vmovdqu 0x50(%rsi), %xmm0
        vmovdqu 0x54(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x80(%rdi)
        vmovdqu 0x64(%rsi), %xmm0
        vmovdqu 0x68(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0xa0(%rdi)
        vmovdqu 0x78(%rsi), %xmm0
        vmovdqu 0x7c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0xc0(%rdi)
        vmovdqu 0x8c(%rsi), %xmm0
        vmovdqu 0x90(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0xe0(%rdi)
        vmovdqu 0xa0(%rsi), %xmm0
        vmovdqu 0xa4(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x100(%rdi)
        vmovdqu 0xb4(%rsi), %xmm0
        vmovdqu 0xb8(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x120(%rdi)
        vmovdqu 0xc8(%rsi), %xmm0
        vmovdqu 0xcc(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x140(%rdi)
        vmovdqu 0xdc(%rsi), %xmm0
        vmovdqu 0xe0(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x160(%rdi)
        vmovdqu 0xf0(%rsi), %xmm0
        vmovdqu 0xf4(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x180(%rdi)
        vmovdqu 0x104(%rsi), %xmm0
        vmovdqu 0x108(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x1a0(%rdi)
        vmovdqu 0x118(%rsi), %xmm0
        vmovdqu 0x11c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x1c0(%rdi)
        vmovdqu 0x12c(%rsi), %xmm0
        vmovdqu 0x130(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x1e0(%rdi)
        vmovdqu 0x140(%rsi), %xmm0
        vmovdqu 0x144(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x200(%rdi)
        vmovdqu 0x154(%rsi), %xmm0
        vmovdqu 0x158(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x220(%rdi)
        vmovdqu 0x168(%rsi), %xmm0
        vmovdqu 0x16c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x240(%rdi)
        vmovdqu 0x17c(%rsi), %xmm0
        vmovdqu 0x180(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x260(%rdi)
        vmovdqu 0x190(%rsi), %xmm0
        vmovdqu 0x194(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x280(%rdi)
        vmovdqu 0x1a4(%rsi), %xmm0
        vmovdqu 0x1a8(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x2a0(%rdi)
        vmovdqu 0x1b8(%rsi), %xmm0
        vmovdqu 0x1bc(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x2c0(%rdi)
        vmovdqu 0x1cc(%rsi), %xmm0
        vmovdqu 0x1d0(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x2e0(%rdi)
        vmovdqu 0x1e0(%rsi), %xmm0
        vmovdqu 0x1e4(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x300(%rdi)
        vmovdqu 0x1f4(%rsi), %xmm0
        vmovdqu 0x1f8(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x320(%rdi)
        vmovdqu 0x208(%rsi), %xmm0
        vmovdqu 0x20c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x340(%rdi)
        vmovdqu 0x21c(%rsi), %xmm0
        vmovdqu 0x220(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x360(%rdi)
        vmovdqu 0x230(%rsi), %xmm0
        vmovdqu 0x234(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x380(%rdi)
        vmovdqu 0x244(%rsi), %xmm0
        vmovdqu 0x248(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x3a0(%rdi)
        vmovdqu 0x258(%rsi), %xmm0
        vmovdqu 0x25c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x3c0(%rdi)
        vmovdqu 0x26c(%rsi), %xmm0
        vmovdqu 0x270(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x3e0(%rdi)
        retq
        .cfi_endproc
.size vailMldsaUnpackZ19, .-vailMldsaUnpackZ19
.section .note.GNU-stack,"",%progbits

