# Copyright (c) 2024 The mlkem-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored s2n-bignum/mlkem-native AVX2 kernels, preprocessed for the ELF
# x86_64 SysV ABI. The generated instruction schedules are kept separate from
# the Zig ABI wrapper so each layer remains independently reviewable.
        .text
        .balign 4
vailMlKemRejectUniform:
        .cfi_startproc
        endbr64
        vzeroupper
        subq $0x210, %rsp
        .cfi_adjust_cfa_offset 0x210
        xorl %eax, %eax
        testq %rdx, %rdx
        jz .LvailMlKemRejectUniformEnd
        movabsq $0xd010d010d010d01, %rax
        movq %rax, %xmm0
        pinsrq $0x1, %rax, %xmm0
        movabsq $0xfff0fff0fff0fff, %rax
        movq %rax, %xmm5
        pinsrq $0x1, %rax, %xmm5
        movabsq $0x504040302010100, %rax
        movq %rax, %xmm4
        movabsq $0xb0a0a0908070706, %rax
        pinsrq $0x1, %rax, %xmm4
        xorq %rax, %rax
        xorq %r8, %r8
        movq $0x5555, %r9
.LvailMlKemRejectUniformLoop:
        movq (%rsi,%r8), %xmm2
        pinsrd $0x2, 8(%rsi,%r8), %xmm2
        pshufb %xmm4, %xmm2
        movdqa %xmm2, %xmm3
        psrlw $0x4, %xmm3
        pblendw $0xaa, %xmm3, %xmm2
        pand %xmm5, %xmm2
        movdqa %xmm0, %xmm1
        pcmpgtw %xmm2, %xmm1
        pmovmskb %xmm1, %r11d
        pextq %r9, %r11, %r11
        movq %r11, %r10
        shlq $4, %r10
        movdqu (%rcx,%r10), %xmm3
        pshufb %xmm3, %xmm2
        movdqu %xmm2, (%rsp,%rax,2)
        popcntq %r11, %r11
        addq %r11, %rax
        cmpq $0x100, %rax
        jae .LvailMlKemRejectUniformCopy
        addq $0xc, %r8
        cmpq %r8, %rdx
        ja .LvailMlKemRejectUniformLoop
.LvailMlKemRejectUniformCopy:
        movq $0x100, %r8
        cmpq $0x100, %rax
        cmovaq %r8, %rax
        movq %rsp, %rsi
        movq %rax, %rcx
        shlq $1, %rcx
        rep movsb
.LvailMlKemRejectUniformEnd:
        addq $0x210, %rsp
        .cfi_adjust_cfa_offset -0x210
        vzeroupper
        retq
        .cfi_endproc
        .balign 4
vailMlKemToMont:
        .cfi_startproc
        endbr64
        movl $0xd010d01, %eax
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x50495049, %eax
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $0x5490549, %eax
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $2, %ecx
.LvailMlKemToMontLoop:
        vmovdqa 0x00(%rdi), %ymm3
        vmovdqa 0x20(%rdi), %ymm4
        vmovdqa 0x40(%rdi), %ymm5
        vmovdqa 0x60(%rdi), %ymm6
        vmovdqa 0x80(%rdi), %ymm7
        vmovdqa 0xa0(%rdi), %ymm8
        vmovdqa 0xc0(%rdi), %ymm9
        vmovdqa 0xe0(%rdi), %ymm10
        vpmullw %ymm1, %ymm3, %ymm11
        vpmulhw %ymm2, %ymm3, %ymm3
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm11, %ymm3, %ymm3
        vpmullw %ymm1, %ymm4, %ymm12
        vpmulhw %ymm2, %ymm4, %ymm4
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm4, %ymm4
        vpmullw %ymm1, %ymm5, %ymm13
        vpmulhw %ymm2, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm13, %ymm13
        vpsubw %ymm13, %ymm5, %ymm5
        vpmullw %ymm1, %ymm6, %ymm14
        vpmulhw %ymm2, %ymm6, %ymm6
        vpmulhw %ymm0, %ymm14, %ymm14
        vpsubw %ymm14, %ymm6, %ymm6
        vpmullw %ymm1, %ymm7, %ymm15
        vpmulhw %ymm2, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm15, %ymm15
        vpsubw %ymm15, %ymm7, %ymm7
        vpmullw %ymm1, %ymm8, %ymm11
        vpmulhw %ymm2, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm11, %ymm8, %ymm8
        vpmullw %ymm1, %ymm9, %ymm12
        vpmulhw %ymm2, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm9, %ymm9
        vpmullw %ymm1, %ymm10, %ymm13
        vpmulhw %ymm2, %ymm10, %ymm10
        vpmulhw %ymm0, %ymm13, %ymm13
        vpsubw %ymm13, %ymm10, %ymm10
        vmovdqa %ymm3, 0x00(%rdi)
        vmovdqa %ymm4, 0x20(%rdi)
        vmovdqa %ymm5, 0x40(%rdi)
        vmovdqa %ymm6, 0x60(%rdi)
        vmovdqa %ymm7, 0x80(%rdi)
        vmovdqa %ymm8, 0xa0(%rdi)
        vmovdqa %ymm9, 0xc0(%rdi)
        vmovdqa %ymm10, 0xe0(%rdi)
        addq $0x100, %rdi
        decl %ecx
        jnz .LvailMlKemToMontLoop
        vzeroall
        retq
        .cfi_endproc
        .balign 4
vailMlKemNormalize:
        .cfi_startproc
        endbr64
        movl $0xd010d01, %eax
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x4ebf4ebf, %eax
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $2, %ecx
.LvailMlKemNormalizeLoop:
        vmovdqa 0x00(%rdi), %ymm2
        vmovdqa 0x20(%rdi), %ymm3
        vmovdqa 0x40(%rdi), %ymm4
        vmovdqa 0x60(%rdi), %ymm5
        vmovdqa 0x80(%rdi), %ymm6
        vmovdqa 0xa0(%rdi), %ymm7
        vmovdqa 0xc0(%rdi), %ymm8
        vmovdqa 0xe0(%rdi), %ymm9
        vpmulhw %ymm1, %ymm2, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm2, %ymm2
        vpmulhw %ymm1, %ymm3, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm3, %ymm3
        vpmulhw %ymm1, %ymm4, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm4, %ymm4
        vpmulhw %ymm1, %ymm5, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm5, %ymm5
        vpmulhw %ymm1, %ymm6, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm6, %ymm6
        vpmulhw %ymm1, %ymm7, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm7, %ymm7
        vpmulhw %ymm1, %ymm8, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm8, %ymm8
        vpmulhw %ymm1, %ymm9, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm9, %ymm9
        vpsubw %ymm0, %ymm2, %ymm2
        vpsraw $15, %ymm2, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm2, %ymm2
        vpsubw %ymm0, %ymm3, %ymm3
        vpsraw $15, %ymm3, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm3, %ymm3
        vpsubw %ymm0, %ymm4, %ymm4
        vpsraw $15, %ymm4, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm4, %ymm4
        vpsubw %ymm0, %ymm5, %ymm5
        vpsraw $15, %ymm5, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm5, %ymm5
        vpsubw %ymm0, %ymm6, %ymm6
        vpsraw $15, %ymm6, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm6, %ymm6
        vpsubw %ymm0, %ymm7, %ymm7
        vpsraw $15, %ymm7, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm7, %ymm7
        vpsubw %ymm0, %ymm8, %ymm8
        vpsraw $15, %ymm8, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm8, %ymm8
        vpsubw %ymm0, %ymm9, %ymm9
        vpsraw $15, %ymm9, %ymm12
        vpand %ymm0, %ymm12, %ymm12
        vpaddw %ymm12, %ymm9, %ymm9
        vmovdqa %ymm2, 0x00(%rdi)
        vmovdqa %ymm3, 0x20(%rdi)
        vmovdqa %ymm4, 0x40(%rdi)
        vmovdqa %ymm5, 0x60(%rdi)
        vmovdqa %ymm6, 0x80(%rdi)
        vmovdqa %ymm7, 0xa0(%rdi)
        vmovdqa %ymm8, 0xc0(%rdi)
        vmovdqa %ymm9, 0xe0(%rdi)
        addq $0x100, %rdi
        decl %ecx
        jnz .LvailMlKemNormalizeLoop
        vzeroall
        retq
        .cfi_endproc
        .balign 4
vailMlKemBarrettReduce:
        .cfi_startproc
        endbr64
        movl $0xd010d01, %eax
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x4ebf4ebf, %eax
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $2, %ecx
.LvailMlKemBarrettReduceLoop:
        vmovdqa 0x00(%rdi), %ymm2
        vmovdqa 0x20(%rdi), %ymm3
        vmovdqa 0x40(%rdi), %ymm4
        vmovdqa 0x60(%rdi), %ymm5
        vmovdqa 0x80(%rdi), %ymm6
        vmovdqa 0xa0(%rdi), %ymm7
        vmovdqa 0xc0(%rdi), %ymm8
        vmovdqa 0xe0(%rdi), %ymm9
        vpmulhw %ymm1, %ymm2, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm2, %ymm2
        vpmulhw %ymm1, %ymm3, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm3, %ymm3
        vpmulhw %ymm1, %ymm4, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm4, %ymm4
        vpmulhw %ymm1, %ymm5, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm5, %ymm5
        vpmulhw %ymm1, %ymm6, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm6, %ymm6
        vpmulhw %ymm1, %ymm7, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm7, %ymm7
        vpmulhw %ymm1, %ymm8, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm8, %ymm8
        vpmulhw %ymm1, %ymm9, %ymm12
        vpsraw $10, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm9, %ymm9
        vmovdqa %ymm2, 0x00(%rdi)
        vmovdqa %ymm3, 0x20(%rdi)
        vmovdqa %ymm4, 0x40(%rdi)
        vmovdqa %ymm5, 0x60(%rdi)
        vmovdqa %ymm6, 0x80(%rdi)
        vmovdqa %ymm7, 0xa0(%rdi)
        vmovdqa %ymm8, 0xc0(%rdi)
        vmovdqa %ymm9, 0xe0(%rdi)
        addq $0x100, %rdi
        decl %ecx
        jnz .LvailMlKemBarrettReduceLoop
        vzeroall
        retq
        .cfi_endproc
        .balign 4
vailMlKemCbdEta2:
        .cfi_startproc
        endbr64
        movl $0x55555555, %eax
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x33333333, %eax
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $0x03030303, %eax
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $0x0f0f0f0f, %eax
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $4, %eax
.LvailMlKemCbdEta2Loop:
        vmovdqu (%rsi), %ymm4
        vpsrlw $1, %ymm4, %ymm5
        vpand %ymm0, %ymm4, %ymm4
        vpand %ymm0, %ymm5, %ymm5
        vpaddb %ymm5, %ymm4, %ymm4
        vpsrlw $2, %ymm4, %ymm5
        vpand %ymm1, %ymm4, %ymm4
        vpand %ymm1, %ymm5, %ymm5
        vpaddb %ymm1, %ymm4, %ymm4
        vpsubb %ymm5, %ymm4, %ymm4
        vpsrlw $4, %ymm4, %ymm5
        vpand %ymm3, %ymm4, %ymm4
        vpand %ymm3, %ymm5, %ymm5
        vpsubb %ymm2, %ymm4, %ymm4
        vpsubb %ymm2, %ymm5, %ymm5
        vpunpcklbw %ymm5, %ymm4, %ymm6
        vpunpckhbw %ymm5, %ymm4, %ymm7
        vextracti128 $1, %ymm6, %xmm10
        vextracti128 $1, %ymm7, %xmm11
        vpmovsxbw %xmm6, %ymm8
        vpmovsxbw %xmm7, %ymm9
        vpmovsxbw %xmm10, %ymm10
        vpmovsxbw %xmm11, %ymm11
        vmovdqa %ymm8, 0x00(%rdi)
        vmovdqa %ymm9, 0x20(%rdi)
        vmovdqa %ymm10, 0x40(%rdi)
        vmovdqa %ymm11, 0x60(%rdi)
        addq $0x20, %rsi
        addq $0x80, %rdi
        decl %eax
        jnz .LvailMlKemCbdEta2Loop
        vzeroall
        retq
        .cfi_endproc
