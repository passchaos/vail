# Copyright (c) The mlkem-native and mldsa-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Derived from mldsa-native's formally verified AVX2 eta=2 rejection sampler
# for the FIPS 204 eta=4 acceptance and coefficient mapping.
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
        .globl vailMldsaRejectEta4

vailMldsaRejectEta4:
        .cfi_startproc
        movl $0xf0f0f0f, %r8d
        vmovd %r8d, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $0x4040404, %r8d
        vmovd %r8d, %xmm4
        vpbroadcastd %xmm4, %ymm4
        movl $0x9090909, %r8d
        vmovd %r8d, %xmm5
        vpbroadcastd %xmm5, %ymm5
        movl %ecx, %r9d
        xorl %eax, %eax
        xorl %ecx, %ecx
        cmpl $0x8, %r9d
        jb Lmld_rej_uniform_eta4_avx2_asm_scalar
Lmld_rej_uniform_eta4_avx2_asm_loop:
        leal -0x8(%r9), %r11d
        cmpl %r11d, %eax
        ja Lmld_rej_uniform_eta4_avx2_asm_scalar
        cmpl $0x100, %ecx
        ja Lmld_rej_uniform_eta4_avx2_asm_scalar
        vpmovzxbw (%rsi,%rcx), %ymm0
        vpsllw $0x4, %ymm0, %ymm1
        vpor %ymm1, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubb %ymm5, %ymm0, %ymm1
        vpsubb %ymm0, %ymm4, %ymm0
        vpmovmskb %ymm1, %r8d
        vextracti128 $0x0, %ymm0, %xmm8
        movzbl %r8b, %r10d
        vmovq (%rdx,%r10,8), %xmm9
        vpshufb %xmm9, %xmm8, %xmm9
        vpmovsxbd %xmm9, %ymm1
        vmovdqu %ymm1, (%rdi,%rax,4)
        popcntl %r10d, %r11d
        addl %r11d, %eax
        shrl $0x8, %r8d
        addl $0x4, %ecx
        leal -0x8(%r9), %r11d
        cmpl %r11d, %eax
        ja Lmld_rej_uniform_eta4_avx2_asm_scalar
        vpsrldq $0x8, %xmm8, %xmm8
        movzbl %r8b, %r10d
        vmovq (%rdx,%r10,8), %xmm9
        vpshufb %xmm9, %xmm8, %xmm9
        vpmovsxbd %xmm9, %ymm1
        vmovdqu %ymm1, (%rdi,%rax,4)
        popcntl %r10d, %r11d
        addl %r11d, %eax
        shrl $0x8, %r8d
        addl $0x4, %ecx
        leal -0x8(%r9), %r11d
        cmpl %r11d, %eax
        ja Lmld_rej_uniform_eta4_avx2_asm_scalar
        vextracti128 $0x1, %ymm0, %xmm8
        movzbl %r8b, %r10d
        vmovq (%rdx,%r10,8), %xmm9
        vpshufb %xmm9, %xmm8, %xmm9
        vpmovsxbd %xmm9, %ymm1
        vmovdqu %ymm1, (%rdi,%rax,4)
        popcntl %r10d, %r11d
        addl %r11d, %eax
        shrl $0x8, %r8d
        addl $0x4, %ecx
        leal -0x8(%r9), %r11d
        cmpl %r11d, %eax
        ja Lmld_rej_uniform_eta4_avx2_asm_scalar
        vpsrldq $0x8, %xmm8, %xmm8
        movzbl %r8b, %r10d
        vmovq (%rdx,%r10,8), %xmm9
        vpshufb %xmm9, %xmm8, %xmm9
        vpmovsxbd %xmm9, %ymm1
        vmovdqu %ymm1, (%rdi,%rax,4)
        popcntl %r10d, %r11d
        addl %r11d, %eax
        addl $0x4, %ecx
        jmp Lmld_rej_uniform_eta4_avx2_asm_loop
Lmld_rej_uniform_eta4_avx2_asm_scalar:
        cmpl %r9d, %eax
        jae Lmld_rej_uniform_eta4_avx2_asm_done
        cmpl $0x110, %ecx
        jae Lmld_rej_uniform_eta4_avx2_asm_done
        movzbl (%rsi,%rcx), %r11d
        incl %ecx
        movl %r11d, %r10d
        andl $0xf, %r10d
        cmpl $0x9, %r10d
        jae Lmld_rej_uniform_eta4_avx2_asm_high_nibble
        movl $0x4, %r11d
        subl %r10d, %r11d
        movl %r11d, (%rdi,%rax,4)
        incl %eax
        cmpl %r9d, %eax
        jae Lmld_rej_uniform_eta4_avx2_asm_done
Lmld_rej_uniform_eta4_avx2_asm_high_nibble:
        movzbl -0x1(%rsi,%rcx), %r11d
        shrl $0x4, %r11d
        andl $0xf, %r11d
        cmpl $0x9, %r11d
        jae Lmld_rej_uniform_eta4_avx2_asm_scalar
        movl $0x4, %r10d
        subl %r11d, %r10d
        movl %r10d, (%rdi,%rax,4)
        incl %eax
        jmp Lmld_rej_uniform_eta4_avx2_asm_scalar
Lmld_rej_uniform_eta4_avx2_asm_done:
        retq
        .cfi_endproc
.size vailMldsaRejectEta4, .-vailMldsaRejectEta4
.section .note.GNU-stack,"",%progbits
