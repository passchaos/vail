# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored from s2n-bignum's formally verified ML-DSA inverse NTT and
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
        .globl vailMldsaInvNtt
        .type vailMldsaInvNtt, %function
       
        .text
.macro shuffle8 r0,r1,r2,r3
        vperm2i128 $0x20, \r1, \r0, \r2
        vperm2i128 $0x31, \r1, \r0, \r3
.endm
.macro shuffle4 r0,r1,r2,r3
        vpunpcklqdq \r1, \r0, \r2
        vpunpckhqdq \r1, \r0, \r3
.endm
.macro shuffle2 r0,r1,r2,r3
        vmovsldup \r1, \r2
        vpblendd $0xAA, \r2, \r0, \r2
        vpsrlq $32, \r0, \r0
        vpblendd $0xAA, \r1, \r0, \r3
.endm
.macro butterfly flip,l,h,zl0=%ymm1,zl1=%ymm1,zh0=%ymm2,zh1=%ymm2
        vpsubd \l, \h, %ymm12
.if \flip
        vpaddd \h, \l, \l
.else
        vpaddd \l, \h, \l
.endif
        vpmuldq \zl0, %ymm12, %ymm13
        vmovshdup %ymm12, \h
        vpmuldq \zl1, \h, %ymm14
        vpmuldq \zh0, %ymm12, %ymm12
        vpmuldq \zh1, \h, \h
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vpsubd %ymm13, %ymm12, %ymm12
        vpsubd %ymm14, \h, \h
        vmovshdup %ymm12, %ymm12
        vpblendd $0xAA, \h, %ymm12, \h
.endm
.macro levels0t5 off
        vmovdqa 256*\off+0(%rdi), %ymm4
        vmovdqa 256*\off+32(%rdi), %ymm5
        vmovdqa 256*\off+64(%rdi), %ymm6
        vmovdqa 256*\off+96(%rdi), %ymm7
        vmovdqa 256*\off+128(%rdi), %ymm8
        vmovdqa 256*\off+160(%rdi), %ymm9
        vmovdqa 256*\off+192(%rdi), %ymm10
        vmovdqa 256*\off+224(%rdi), %ymm11
        vpermq $0x1B, (4*(32 +296-8*\off-8))(%rsi), %ymm3
        vpermq $0x1B, (4*(328 +296-8*\off-8))(%rsi), %ymm15
        vmovshdup %ymm3, %ymm1
        vmovshdup %ymm15, %ymm2
        butterfly 0,%ymm4,%ymm5,%ymm1,%ymm3,%ymm2,%ymm15
        vpermq $0x1B, (4*(32 +296-8*\off-40))(%rsi), %ymm3
        vpermq $0x1B, (4*(328 +296-8*\off-40))(%rsi), %ymm15
        vmovshdup %ymm3, %ymm1
        vmovshdup %ymm15, %ymm2
        butterfly 0,%ymm6,%ymm7,%ymm1,%ymm3,%ymm2,%ymm15
        vpermq $0x1B, (4*(32 +296-8*\off-72))(%rsi), %ymm3
        vpermq $0x1B, (4*(328 +296-8*\off-72))(%rsi), %ymm15
        vmovshdup %ymm3, %ymm1
        vmovshdup %ymm15, %ymm2
        butterfly 0,%ymm8,%ymm9,%ymm1,%ymm3,%ymm2,%ymm15
        vpermq $0x1B, (4*(32 +296-8*\off-104))(%rsi), %ymm3
        vpermq $0x1B, (4*(328 +296-8*\off-104))(%rsi), %ymm15
        vmovshdup %ymm3, %ymm1
        vmovshdup %ymm15, %ymm2
        butterfly 0,%ymm10,%ymm11,%ymm1,%ymm3,%ymm2,%ymm15
        vpermq $0x1B, (4*(32 +168-8*\off-8))(%rsi), %ymm3
        vpermq $0x1B, (4*(328 +168-8*\off-8))(%rsi), %ymm15
        vmovshdup %ymm3, %ymm1
        vmovshdup %ymm15, %ymm2
        butterfly 0,%ymm4,%ymm6,%ymm1,%ymm3,%ymm2,%ymm15
        butterfly 0,%ymm5,%ymm7,%ymm1,%ymm3,%ymm2,%ymm15
        vpermq $0x1B, (4*(32 +168-8*\off-40))(%rsi), %ymm3
        vpermq $0x1B, (4*(328 +168-8*\off-40))(%rsi), %ymm15
        vmovshdup %ymm3, %ymm1
        vmovshdup %ymm15, %ymm2
        butterfly 0,%ymm8,%ymm10,%ymm1,%ymm3,%ymm2,%ymm15
        butterfly 0,%ymm9,%ymm11,%ymm1,%ymm3,%ymm2,%ymm15
        vpermq $0x1B, (4*(32 +104-8*\off-8))(%rsi), %ymm3
        vpermq $0x1B, (4*(328 +104-8*\off-8))(%rsi), %ymm15
        vmovshdup %ymm3, %ymm1
        vmovshdup %ymm15, %ymm2
        butterfly 0,%ymm4,%ymm8,%ymm1,%ymm3,%ymm2,%ymm15
        butterfly 0,%ymm5,%ymm9,%ymm1,%ymm3,%ymm2,%ymm15
        butterfly 0,%ymm6,%ymm10,%ymm1,%ymm3,%ymm2,%ymm15
        butterfly 0,%ymm7,%ymm11,%ymm1,%ymm3,%ymm2,%ymm15
        shuffle2 %ymm4,%ymm5,%ymm3,%ymm5
        shuffle2 %ymm6,%ymm7,%ymm4,%ymm7
        shuffle2 %ymm8,%ymm9,%ymm6,%ymm9
        shuffle2 %ymm10,%ymm11,%ymm8,%ymm11
        vpermq $0x1B, (4*(32 +72-8*\off-8))(%rsi), %ymm1
        vpermq $0x1B, (4*(328 +72-8*\off-8))(%rsi), %ymm2
        butterfly 0,%ymm3,%ymm5
        butterfly 0,%ymm4,%ymm7
        butterfly 0,%ymm6,%ymm9
        butterfly 0,%ymm8,%ymm11
        shuffle4 %ymm3,%ymm4,%ymm10,%ymm4
        shuffle4 %ymm6,%ymm8,%ymm3,%ymm8
        shuffle4 %ymm5,%ymm7,%ymm6,%ymm7
        shuffle4 %ymm9,%ymm11,%ymm5,%ymm11
        vpermq $0x1B, (4*(32 +40-8*\off-8))(%rsi), %ymm1
        vpermq $0x1B, (4*(328 +40-8*\off-8))(%rsi), %ymm2
        butterfly 1,%ymm10,%ymm4
        butterfly 0,%ymm3,%ymm8
        butterfly 0,%ymm6,%ymm7
        butterfly 0,%ymm5,%ymm11
        shuffle8 %ymm10,%ymm3,%ymm9,%ymm3
        shuffle8 %ymm6,%ymm5,%ymm10,%ymm5
        shuffle8 %ymm4,%ymm8,%ymm6,%ymm8
        shuffle8 %ymm7,%ymm11,%ymm4,%ymm11
        vpbroadcastd (4*(32 +7-\off))(%rsi), %ymm1
        vpbroadcastd (4*(328 +7-\off))(%rsi), %ymm2
        butterfly 1,%ymm9,%ymm3
        butterfly 1,%ymm10,%ymm5
        butterfly 0,%ymm6,%ymm8
        butterfly 0,%ymm4,%ymm11
        vmovdqa %ymm9, 256*\off+0(%rdi)
        vmovdqa %ymm10, 256*\off+32(%rdi)
        vmovdqa %ymm6, 256*\off+64(%rdi)
        vmovdqa %ymm4, 256*\off+96(%rdi)
        vmovdqa %ymm3, 256*\off+128(%rdi)
        vmovdqa %ymm5, 256*\off+160(%rdi)
        vmovdqa %ymm8, 256*\off+192(%rdi)
        vmovdqa %ymm11, 256*\off+224(%rdi)
.endm
.macro levels6t7 off
        vmovdqa 0+32*\off(%rdi), %ymm4
        vmovdqa 128+32*\off(%rdi), %ymm5
        vmovdqa 256+32*\off(%rdi), %ymm6
        vmovdqa 384+32*\off(%rdi), %ymm7
        vmovdqa 512+32*\off(%rdi), %ymm8
        vmovdqa 640+32*\off(%rdi), %ymm9
        vmovdqa 768+32*\off(%rdi), %ymm10
        vmovdqa 896+32*\off(%rdi), %ymm11
        vpbroadcastd (4*(32 +3))(%rsi), %ymm1
        vpbroadcastd (4*(328 +3))(%rsi), %ymm2
        butterfly 0,%ymm4,%ymm6
        butterfly 0,%ymm5,%ymm7
        vpbroadcastd (4*(32 +2))(%rsi), %ymm1
        vpbroadcastd (4*(328 +2))(%rsi), %ymm2
        butterfly 0,%ymm8,%ymm10
        butterfly 0,%ymm9,%ymm11
        vpbroadcastd (4*(32 +0))(%rsi), %ymm1
        vpbroadcastd (4*(328 +0))(%rsi), %ymm2
        butterfly 0,%ymm4,%ymm8
        butterfly 0,%ymm5,%ymm9
        butterfly 0,%ymm6,%ymm10
        butterfly 0,%ymm7,%ymm11
        vmovdqa %ymm8, 512+32*\off(%rdi)
        vmovdqa %ymm9, 640+32*\off(%rdi)
        vmovdqa %ymm10, 768+32*\off(%rdi)
        vmovdqa %ymm11, 896+32*\off(%rdi)
        vmovdqa (4*(16))(%rsi), %ymm1
        vmovdqa (4*(24))(%rsi), %ymm2
        vpmuldq %ymm1, %ymm4, %ymm12
        vpmuldq %ymm1, %ymm5, %ymm13
        vmovshdup %ymm4, %ymm8
        vmovshdup %ymm5, %ymm9
        vpmuldq %ymm1, %ymm8, %ymm14
        vpmuldq %ymm1, %ymm9, %ymm15
        vpmuldq %ymm2, %ymm4, %ymm4
        vpmuldq %ymm2, %ymm5, %ymm5
        vpmuldq %ymm2, %ymm8, %ymm8
        vpmuldq %ymm2, %ymm9, %ymm9
        vpmuldq %ymm0, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vpmuldq %ymm0, %ymm15, %ymm15
        vpsubd %ymm12, %ymm4, %ymm4
        vpsubd %ymm13, %ymm5, %ymm5
        vpsubd %ymm14, %ymm8, %ymm8
        vpsubd %ymm15, %ymm9, %ymm9
        vmovshdup %ymm4, %ymm4
        vmovshdup %ymm5, %ymm5
        vpblendd $0xAA, %ymm8, %ymm4, %ymm4
        vpblendd $0xAA, %ymm9, %ymm5, %ymm5
        vpmuldq %ymm1, %ymm6, %ymm12
        vpmuldq %ymm1, %ymm7, %ymm13
        vmovshdup %ymm6, %ymm8
        vmovshdup %ymm7, %ymm9
        vpmuldq %ymm1, %ymm8, %ymm14
        vpmuldq %ymm1, %ymm9, %ymm15
        vpmuldq %ymm2, %ymm6, %ymm6
        vpmuldq %ymm2, %ymm7, %ymm7
        vpmuldq %ymm2, %ymm8, %ymm8
        vpmuldq %ymm2, %ymm9, %ymm9
        vpmuldq %ymm0, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vpmuldq %ymm0, %ymm15, %ymm15
        vpsubd %ymm12, %ymm6, %ymm6
        vpsubd %ymm13, %ymm7, %ymm7
        vpsubd %ymm14, %ymm8, %ymm8
        vpsubd %ymm15, %ymm9, %ymm9
        vmovshdup %ymm6, %ymm6
        vmovshdup %ymm7, %ymm7
        vpblendd $0xAA, %ymm8, %ymm6, %ymm6
        vpblendd $0xAA, %ymm9, %ymm7, %ymm7
        vmovdqa %ymm4, 0+32*\off(%rdi)
        vmovdqa %ymm5, 128+32*\off(%rdi)
        vmovdqa %ymm6, 256+32*\off(%rdi)
        vmovdqa %ymm7, 384+32*\off(%rdi)
.endm
vailMldsaInvNtt:
        .cfi_startproc
        endbr64
        vmovdqa 0*4(%rsi), %ymm0
        levels0t5 0
        levels0t5 1
        levels0t5 2
        levels0t5 3
        levels6t7 0
        levels6t7 1
        levels6t7 2
        levels6t7 3
        retq ; .cfi_endproc
.size vailMldsaInvNtt, .-vailMldsaInvNtt
.section .note.GNU-stack,"",%progbits

