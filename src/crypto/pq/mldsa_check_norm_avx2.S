# Copyright (c) The mldsa-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored from mldsa-native's formally verified AVX2 norm check and
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
        .globl vailMldsaCheckNorm
       
vailMldsaCheckNorm:
        .cfi_startproc
        subl $0x1, %esi
        vpxor %xmm1, %xmm1, %xmm1
        vmovd %esi, %xmm2
        vpbroadcastd %xmm2, %ymm2
        vpabsd (%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0x20(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0x40(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0x60(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        vpabsd 0x80(%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0xa0(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0xc0(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0xe0(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        vpabsd 0x100(%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0x120(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0x140(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0x160(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        vpabsd 0x180(%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0x1a0(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0x1c0(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0x1e0(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        vpabsd 0x200(%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0x220(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0x240(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0x260(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        vpabsd 0x280(%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0x2a0(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0x2c0(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0x2e0(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        vpabsd 0x300(%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0x320(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0x340(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0x360(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        vpabsd 0x380(%rdi), %ymm0
        vpcmpgtd %ymm2, %ymm0, %ymm0
        vpor %ymm0, %ymm1, %ymm1
        vpabsd 0x3a0(%rdi), %ymm3
        vpcmpgtd %ymm2, %ymm3, %ymm3
        vpor %ymm3, %ymm1, %ymm1
        vpabsd 0x3c0(%rdi), %ymm4
        vpcmpgtd %ymm2, %ymm4, %ymm4
        vpor %ymm4, %ymm1, %ymm1
        vpabsd 0x3e0(%rdi), %ymm5
        vpcmpgtd %ymm2, %ymm5, %ymm5
        vpor %ymm5, %ymm1, %ymm1
        xorl %eax, %eax
        vptest %ymm1, %ymm1
        setne %al
        retq
        .cfi_endproc
.size vailMldsaCheckNorm, .-vailMldsaCheckNorm
.section .note.GNU-stack,"",%progbits

