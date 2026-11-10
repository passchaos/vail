# Copyright (c) The mldsa-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored from mldsa-native's formally verified AVX2 gamma2=(q-1)/88
# decomposition schedule and preprocessed for the ELF x86_64 SysV ABI.
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
        .globl vailMldsaDecompose88
       
vailMldsaDecompose88:
        .cfi_startproc
        movl $0x7f, %eax
        vmovd %eax, %xmm10
        vpbroadcastd %xmm10, %ymm10
        movl $0x2c0b, %eax # imm = 0x2C0B
        vmovd %eax, %xmm11
        vpbroadcastd %xmm11, %ymm11
        movl $0x80, %eax
        vmovd %eax, %xmm12
        vpbroadcastd %xmm12, %ymm12
        movl $0x7e6c00, %eax # imm = 0x7E6C00
        vmovd %eax, %xmm13
        vpbroadcastd %xmm13, %ymm13
        movl $0x2e800, %eax # imm = 0x2E800
        vmovd %eax, %xmm14
        vpbroadcastd %xmm14, %ymm14
        vmovdqa (%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, (%rdi)
        vmovdqa %ymm2, (%rsi)
        vmovdqa 0x20(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x20(%rdi)
        vmovdqa %ymm2, 0x20(%rsi)
        vmovdqa 0x40(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x40(%rdi)
        vmovdqa %ymm2, 0x40(%rsi)
        vmovdqa 0x60(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x60(%rdi)
        vmovdqa %ymm2, 0x60(%rsi)
        vmovdqa 0x80(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x80(%rdi)
        vmovdqa %ymm2, 0x80(%rsi)
        vmovdqa 0xa0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0xa0(%rdi)
        vmovdqa %ymm2, 0xa0(%rsi)
        vmovdqa 0xc0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0xc0(%rdi)
        vmovdqa %ymm2, 0xc0(%rsi)
        vmovdqa 0xe0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0xe0(%rdi)
        vmovdqa %ymm2, 0xe0(%rsi)
        vmovdqa 0x100(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x100(%rdi)
        vmovdqa %ymm2, 0x100(%rsi)
        vmovdqa 0x120(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x120(%rdi)
        vmovdqa %ymm2, 0x120(%rsi)
        vmovdqa 0x140(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x140(%rdi)
        vmovdqa %ymm2, 0x140(%rsi)
        vmovdqa 0x160(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x160(%rdi)
        vmovdqa %ymm2, 0x160(%rsi)
        vmovdqa 0x180(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x180(%rdi)
        vmovdqa %ymm2, 0x180(%rsi)
        vmovdqa 0x1a0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x1a0(%rdi)
        vmovdqa %ymm2, 0x1a0(%rsi)
        vmovdqa 0x1c0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x1c0(%rdi)
        vmovdqa %ymm2, 0x1c0(%rsi)
        vmovdqa 0x1e0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x1e0(%rdi)
        vmovdqa %ymm2, 0x1e0(%rsi)
        vmovdqa 0x200(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x200(%rdi)
        vmovdqa %ymm2, 0x200(%rsi)
        vmovdqa 0x220(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x220(%rdi)
        vmovdqa %ymm2, 0x220(%rsi)
        vmovdqa 0x240(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x240(%rdi)
        vmovdqa %ymm2, 0x240(%rsi)
        vmovdqa 0x260(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x260(%rdi)
        vmovdqa %ymm2, 0x260(%rsi)
        vmovdqa 0x280(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x280(%rdi)
        vmovdqa %ymm2, 0x280(%rsi)
        vmovdqa 0x2a0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x2a0(%rdi)
        vmovdqa %ymm2, 0x2a0(%rsi)
        vmovdqa 0x2c0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x2c0(%rdi)
        vmovdqa %ymm2, 0x2c0(%rsi)
        vmovdqa 0x2e0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x2e0(%rdi)
        vmovdqa %ymm2, 0x2e0(%rsi)
        vmovdqa 0x300(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x300(%rdi)
        vmovdqa %ymm2, 0x300(%rsi)
        vmovdqa 0x320(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x320(%rdi)
        vmovdqa %ymm2, 0x320(%rsi)
        vmovdqa 0x340(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x340(%rdi)
        vmovdqa %ymm2, 0x340(%rsi)
        vmovdqa 0x360(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x360(%rdi)
        vmovdqa %ymm2, 0x360(%rsi)
        vmovdqa 0x380(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x380(%rdi)
        vmovdqa %ymm2, 0x380(%rsi)
        vmovdqa 0x3a0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x3a0(%rdi)
        vmovdqa %ymm2, 0x3a0(%rsi)
        vmovdqa 0x3c0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x3c0(%rdi)
        vmovdqa %ymm2, 0x3c0(%rsi)
        vmovdqa 0x3e0(%rsi), %ymm0
        vpaddd %ymm10, %ymm0, %ymm1
        vpsrld $0x7, %ymm1, %ymm1
        vpmulhuw %ymm11, %ymm1, %ymm1
        vpmulhrsw %ymm12, %ymm1, %ymm1
        vpcmpgtd %ymm13, %ymm0, %ymm3
        vpmulld %ymm14, %ymm1, %ymm2
        vpsubd %ymm2, %ymm0, %ymm2
        vpandn %ymm1, %ymm3, %ymm1
        vpaddd %ymm3, %ymm2, %ymm2
        vmovdqa %ymm1, 0x3e0(%rdi)
        vmovdqa %ymm2, 0x3e0(%rsi)
        retq
        .cfi_endproc
.size vailMldsaDecompose88, .-vailMldsaDecompose88
.section .note.GNU-stack,"",%progbits
.section .note.GNU-stack,"",%progbits

