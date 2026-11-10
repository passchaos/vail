# Copyright (c) The mldsa-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored from mldsa-native's formally verified AVX2 rejection sampler and
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
        .globl vailMldsaRejectUniform
       
vailMldsaRejectUniform:
        .cfi_startproc
        movabsq $-0xfafbfc00fdff00, %r10 # imm = 0xFF050403FF020100
        vmovq %r10, %xmm0
        movabsq $-0xf4f5f600f7f8fa, %r10 # imm = 0xFF0B0A09FF080706
        vpinsrq $0x1, %r10, %xmm0, %xmm0
        movabsq $-0xf6f7f800f9fafc, %r10 # imm = 0xFF090807FF060504
        vmovq %r10, %xmm3
        movabsq $-0xf0f1f200f3f4f6, %r10 # imm = 0xFF0F0E0DFF0C0B0A
        vpinsrq $0x1, %r10, %xmm3, %xmm3
        vinserti128 $0x1, %xmm3, %ymm0, %ymm0
        movl $0x7fffff, %r8d # imm = 0x7FFFFF
        vmovd %r8d, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $0x7fe001, %r8d # imm = 0x7FE001
        vmovd %r8d, %xmm2
        vpbroadcastd %xmm2, %ymm2
        xorl %eax, %eax
        xorl %ecx, %ecx
Lmld_rej_uniform_avx2_asm_loop:
        cmpl $0xf8, %eax
        ja Lmld_rej_uniform_avx2_asm_scalar
        cmpl $0x328, %ecx # imm = 0x328
        ja Lmld_rej_uniform_avx2_asm_scalar
        vmovdqu (%rsi,%rcx), %ymm3
        addl $0x18, %ecx
        vpermq $0x94, %ymm3, %ymm3 # ymm3 = ymm3[0,1,1,2]
        vpshufb %ymm0, %ymm3, %ymm3
        vpand %ymm1, %ymm3, %ymm3
        vpsubd %ymm2, %ymm3, %ymm4
        vmovmskps %ymm4, %r8d
        popcntl %r8d, %r9d
        vmovq (%rdx,%r8,8), %xmm4
        vpmovzxbd %xmm4, %ymm4 # ymm4 = xmm4[0],zero,zero,zero,xmm4[1],zero,zero,zero,xmm4[2],zero,zero,zero,xmm4[3],zero,zero,zero,xmm4[4],zero,zero,zero,xmm4[5],zero,zero,zero,xmm4[6],zero,zero,zero,xmm4[7],zero,zero,zero
        vpermd %ymm3, %ymm4, %ymm3
        vmovdqu %ymm3, (%rdi,%rax,4)
        addl %r9d, %eax
        jmp Lmld_rej_uniform_avx2_asm_loop
Lmld_rej_uniform_avx2_asm_scalar:
        cmpl $0x100, %eax # imm = 0x100
        jae Lmld_rej_uniform_avx2_asm_done
        cmpl $0x345, %ecx # imm = 0x345
        ja Lmld_rej_uniform_avx2_asm_done
        movzwl (%rsi,%rcx), %r8d
        movzbl 0x2(%rsi,%rcx), %r9d
        shll $0x10, %r9d
        orl %r9d, %r8d
        andl $0x7fffff, %r8d # imm = 0x7FFFFF
        addl $0x3, %ecx
        cmpl $0x7fe001, %r8d # imm = 0x7FE001
        jae Lmld_rej_uniform_avx2_asm_scalar
        movl %r8d, (%rdi,%rax,4)
        addl $0x1, %eax
        jmp Lmld_rej_uniform_avx2_asm_scalar
Lmld_rej_uniform_avx2_asm_done:
        retq
        .cfi_endproc
.size vailMldsaRejectUniform, .-vailMldsaRejectUniform
.section .note.GNU-stack,"",%progbits

