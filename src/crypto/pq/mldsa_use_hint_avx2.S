# Copyright (c) The mldsa-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored from mldsa-native's formally verified AVX2 use-hint schedule and
# preprocessed for the ELF x86_64 SysV ABI.
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
        .globl vailMldsaUseHint88
       
vailMldsaUseHint88:
        .cfi_startproc
        movl $0x7f, %ecx
        xorl %eax, %eax
        vpxor %xmm5, %xmm5, %xmm5
        movl $0x2c0b, %r8d # imm = 0x2C0B
        vmovd %r8d, %xmm8
        vpbroadcastd %xmm8, %ymm8
        vmovd %ecx, %xmm4
        movl $0x7e6c00, %ecx # imm = 0x7E6C00
        movl $0x80, %r9d
        vmovd %r9d, %xmm7
        vpbroadcastd %xmm7, %ymm7
        movl $0x2b, %r10d
        vmovd %r10d, %xmm6
        vpbroadcastd %xmm6, %ymm6
        vmovd %ecx, %xmm3
        vpbroadcastd %xmm4, %ymm4
        vpbroadcastd %xmm3, %ymm3
Lmld_poly_use_hint_88_avx2_asm_loop:
        vmovdqa (%rdi), %ymm0
        vmovdqa (%rsi), %ymm1
        vpaddd %ymm0, %ymm4, %ymm10
        vpsrld $0x7, %ymm10, %ymm10
        vpmulhuw %ymm8, %ymm10, %ymm10
        vpmulhrsw %ymm7, %ymm10, %ymm10
        vpcmpgtd %ymm3, %ymm0, %ymm11
        vpandn %ymm10, %ymm11, %ymm9
        vpslld $0x1, %ymm10, %ymm12
        vpaddd %ymm10, %ymm12, %ymm12
        vpslld $0x5, %ymm12, %ymm10
        vpsubd %ymm12, %ymm10, %ymm10
        vpslld $0xb, %ymm10, %ymm10
        vpsubd %ymm10, %ymm0, %ymm0
        vpaddd %ymm11, %ymm0, %ymm0
        vpcmpgtd %ymm5, %ymm0, %ymm0
        vpandn %ymm1, %ymm0, %ymm0
        vpslld $0x1, %ymm0, %ymm0
        vpsubd %ymm0, %ymm1, %ymm0
        vpaddd %ymm9, %ymm0, %ymm0
        vpblendvb %ymm0, %ymm6, %ymm0, %ymm0
        vpcmpgtd %ymm6, %ymm0, %ymm1
        vpandn %ymm0, %ymm1, %ymm0
        vmovdqa %ymm0, (%rdi)
        addq $0x20, %rdi
        addq $0x20, %rsi
        addq $0x20, %rax
        cmpq $0x400, %rax # imm = 0x400
        jne Lmld_poly_use_hint_88_avx2_asm_loop
        retq
        .cfi_endproc
.size vailMldsaUseHint88, .-vailMldsaUseHint88
.section .note.GNU-stack,"",%progbits

