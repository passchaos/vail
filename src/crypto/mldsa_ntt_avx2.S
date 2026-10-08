# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored from s2n-bignum's formally verified ML-DSA forward NTT and
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
        .globl vailMldsaNtt
        .type vailMldsaNtt, %function
       
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
.macro butterfly l,h,zl0=%ymm1,zl1=%ymm1,zh0=%ymm2,zh1=%ymm2
        vpmuldq \zl0, \h, %ymm13
        vmovshdup \h, %ymm12
        vpmuldq \zl1, %ymm12, %ymm14
        vpmuldq \zh0, \h, \h
        vpmuldq \zh1, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup \h, \h
        vpblendd $0xAA, %ymm12, \h, \h
        vpsubd \h, \l, %ymm12
        vpaddd \h, \l, \l
        vmovshdup %ymm13, %ymm13
        vpblendd $0xAA, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, \h
        vpsubd %ymm13, \l, \l
.endm
.macro levels0t1 off
        vpbroadcastd (4*(32 +1))(%rsi), %ymm1
        vpbroadcastd (4*(328 +1))(%rsi), %ymm2
        vmovdqa 0+32*\off(%rdi), %ymm4
        vmovdqa 128+32*\off(%rdi), %ymm5
        vmovdqa 256+32*\off(%rdi), %ymm6
        vmovdqa 384+32*\off(%rdi), %ymm7
        vmovdqa 512+32*\off(%rdi), %ymm8
        vmovdqa 640+32*\off(%rdi), %ymm9
        vmovdqa 768+32*\off(%rdi), %ymm10
        vmovdqa 896+32*\off(%rdi), %ymm11
        butterfly %ymm4,%ymm8
        butterfly %ymm5,%ymm9
        butterfly %ymm6,%ymm10
        butterfly %ymm7,%ymm11
        vpbroadcastd (4*(32 +2))(%rsi), %ymm1
        vpbroadcastd (4*(328 +2))(%rsi), %ymm2
        butterfly %ymm4,%ymm6
        butterfly %ymm5,%ymm7
        vpbroadcastd (4*(32 +3))(%rsi), %ymm1
        vpbroadcastd (4*(328 +3))(%rsi), %ymm2
        butterfly %ymm8,%ymm10
        butterfly %ymm9,%ymm11
        vmovdqa %ymm4, 0+32*\off(%rdi)
        vmovdqa %ymm5, 128+32*\off(%rdi)
        vmovdqa %ymm6, 256+32*\off(%rdi)
        vmovdqa %ymm7, 384+32*\off(%rdi)
        vmovdqa %ymm8, 512+32*\off(%rdi)
        vmovdqa %ymm9, 640+32*\off(%rdi)
        vmovdqa %ymm10, 768+32*\off(%rdi)
        vmovdqa %ymm11, 896+32*\off(%rdi)
.endm
.macro levels2t7 off
        vmovdqa 0+256*\off(%rdi), %ymm4
        vmovdqa 32+256*\off(%rdi), %ymm5
        vmovdqa 64+256*\off(%rdi), %ymm6
        vmovdqa 96+256*\off(%rdi), %ymm7
        vmovdqa 128+256*\off(%rdi), %ymm8
        vmovdqa 160+256*\off(%rdi), %ymm9
        vmovdqa 192+256*\off(%rdi), %ymm10
        vmovdqa 224+256*\off(%rdi), %ymm11
        vpbroadcastd (4*(32 +4+\off))(%rsi), %ymm1
        vpbroadcastd (4*(328 +4+\off))(%rsi), %ymm2
        butterfly %ymm4,%ymm8
        butterfly %ymm5,%ymm9
        butterfly %ymm6,%ymm10
        butterfly %ymm7,%ymm11
        shuffle8 %ymm4,%ymm8,%ymm3,%ymm8
        shuffle8 %ymm5,%ymm9,%ymm4,%ymm9
        shuffle8 %ymm6,%ymm10,%ymm5,%ymm10
        shuffle8 %ymm7,%ymm11,%ymm6,%ymm11
        vmovdqa (4*(32 +8+8*\off))(%rsi), %ymm1
        vmovdqa (4*(328 +8+8*\off))(%rsi), %ymm2
        butterfly %ymm3,%ymm5
        butterfly %ymm8,%ymm10
        butterfly %ymm4,%ymm6
        butterfly %ymm9,%ymm11
        shuffle4 %ymm3,%ymm5,%ymm7,%ymm5
        shuffle4 %ymm8,%ymm10,%ymm3,%ymm10
        shuffle4 %ymm4,%ymm6,%ymm8,%ymm6
        shuffle4 %ymm9,%ymm11,%ymm4,%ymm11
        vmovdqa (4*(32 +40+8*\off))(%rsi), %ymm1
        vmovdqa (4*(328 +40+8*\off))(%rsi), %ymm2
        butterfly %ymm7,%ymm8
        butterfly %ymm5,%ymm6
        butterfly %ymm3,%ymm4
        butterfly %ymm10,%ymm11
        shuffle2 %ymm7,%ymm8,%ymm9,%ymm8
        shuffle2 %ymm5,%ymm6,%ymm7,%ymm6
        shuffle2 %ymm3,%ymm4,%ymm5,%ymm4
        shuffle2 %ymm10,%ymm11,%ymm3,%ymm11
        vmovdqa (4*(32 +72+8*\off))(%rsi), %ymm1
        vmovdqa (4*(328 +72+8*\off))(%rsi), %ymm2
        vpsrlq $32, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        butterfly %ymm9,%ymm5,%ymm1,%ymm10,%ymm2,%ymm15
        butterfly %ymm8,%ymm4,%ymm1,%ymm10,%ymm2,%ymm15
        butterfly %ymm7,%ymm3,%ymm1,%ymm10,%ymm2,%ymm15
        butterfly %ymm6,%ymm11,%ymm1,%ymm10,%ymm2,%ymm15
        vmovdqa (4*(32 +104+8*\off))(%rsi), %ymm1
        vmovdqa (4*(328 +104+8*\off))(%rsi), %ymm2
        vpsrlq $32, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        butterfly %ymm9,%ymm7,%ymm1,%ymm10,%ymm2,%ymm15
        butterfly %ymm8,%ymm6,%ymm1,%ymm10,%ymm2,%ymm15
        vmovdqa (4*(32 +104+8*\off+32))(%rsi), %ymm1
        vmovdqa (4*(328 +104+8*\off+32))(%rsi), %ymm2
        vpsrlq $32, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        butterfly %ymm5,%ymm3,%ymm1,%ymm10,%ymm2,%ymm15
        butterfly %ymm4,%ymm11,%ymm1,%ymm10,%ymm2,%ymm15
        vmovdqa (4*(32 +168+8*\off))(%rsi), %ymm1
        vmovdqa (4*(328 +168+8*\off))(%rsi), %ymm2
        vpsrlq $32, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        butterfly %ymm9,%ymm8,%ymm1,%ymm10,%ymm2,%ymm15
        vmovdqa (4*(32 +168+8*\off+32))(%rsi), %ymm1
        vmovdqa (4*(328 +168+8*\off+32))(%rsi), %ymm2
        vpsrlq $32, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        butterfly %ymm7,%ymm6,%ymm1,%ymm10,%ymm2,%ymm15
        vmovdqa (4*(32 +168+8*\off+64))(%rsi), %ymm1
        vmovdqa (4*(328 +168+8*\off+64))(%rsi), %ymm2
        vpsrlq $32, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        butterfly %ymm5,%ymm4,%ymm1,%ymm10,%ymm2,%ymm15
        vmovdqa (4*(32 +168+8*\off+96))(%rsi), %ymm1
        vmovdqa (4*(328 +168+8*\off+96))(%rsi), %ymm2
        vpsrlq $32, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        butterfly %ymm3,%ymm11,%ymm1,%ymm10,%ymm2,%ymm15
        vmovdqa %ymm9, 0+256*\off(%rdi)
        vmovdqa %ymm8, 32+256*\off(%rdi)
        vmovdqa %ymm7, 64+256*\off(%rdi)
        vmovdqa %ymm6, 96+256*\off(%rdi)
        vmovdqa %ymm5, 128+256*\off(%rdi)
        vmovdqa %ymm4, 160+256*\off(%rdi)
        vmovdqa %ymm3, 192+256*\off(%rdi)
        vmovdqa %ymm11, 224+256*\off(%rdi)
.endm
vailMldsaNtt:
        .cfi_startproc
        endbr64
        vmovdqa 0*4(%rsi), %ymm0
        levels0t1 0
        levels0t1 1
        levels0t1 2
        levels0t1 3
        levels2t7 0
        levels2t7 1
        levels2t7 2
        levels2t7 3
        retq ; .cfi_endproc
.size vailMldsaNtt, .-vailMldsaNtt
.purgem shuffle8
.purgem shuffle4
.purgem shuffle2
.purgem butterfly
.purgem levels0t1
.purgem levels2t7
.section .note.GNU-stack,"",%progbits

