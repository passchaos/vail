# Copyright (c) 2024 The mlkem-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored s2n-bignum/mlkem-native AVX2 NTT, permutation, k=3 pointwise,
# cache, and serialization schedules, preprocessed for the ELF x86_64 SysV ABI.
        .text
        .balign 4
vailMlKemNtt:
        .cfi_startproc
        endbr64
 mov $0xd010d01, %eax
 vmovd %eax, %xmm0
 vpbroadcastd %xmm0, %ymm0
 vpbroadcastq 64(%rsi), %ymm15
 vmovdqa 256(%rdi), %ymm8
 vmovdqa 288(%rdi), %ymm9
 vmovdqa 320(%rdi), %ymm10
 vmovdqa 352(%rdi), %ymm11
 vpbroadcastq 72(%rsi), %ymm2
 vpmullw %ymm15, %ymm8, %ymm12
 vpmullw %ymm15, %ymm9, %ymm13
 vpmullw %ymm15, %ymm10, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm11, %ymm11
 vmovdqa (%rdi), %ymm4
 vmovdqa 32(%rdi), %ymm5
 vmovdqa 64(%rdi), %ymm6
 vmovdqa 96(%rdi), %ymm7
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm8, %ymm4, %ymm3
 vpsubw %ymm8, %ymm4, %ymm8
 vpaddw %ymm9, %ymm5, %ymm4
 vpsubw %ymm9, %ymm5, %ymm9
 vpaddw %ymm10, %ymm6, %ymm5
 vpsubw %ymm10, %ymm6, %ymm10
 vpaddw %ymm11, %ymm7, %ymm6
 vpsubw %ymm11, %ymm7, %ymm11
 vpsubw %ymm12, %ymm3, %ymm3
 vpaddw %ymm12, %ymm8, %ymm8
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm9, %ymm9
 vpsubw %ymm14, %ymm5, %ymm5
 vpaddw %ymm14, %ymm10, %ymm10
 vpsubw %ymm15, %ymm6, %ymm6
 vpaddw %ymm15, %ymm11, %ymm11
 vmovdqa %ymm3, (%rdi)
 vmovdqa %ymm4, 32(%rdi)
 vmovdqa %ymm5, 64(%rdi)
 vmovdqa %ymm6, 96(%rdi)
 vmovdqa %ymm8, 256(%rdi)
 vmovdqa %ymm9, 288(%rdi)
 vmovdqa %ymm10, 320(%rdi)
 vmovdqa %ymm11, 352(%rdi)
 vpbroadcastq 64(%rsi), %ymm15
 vmovdqa 384(%rdi), %ymm8
 vmovdqa 416(%rdi), %ymm9
 vmovdqa 448(%rdi), %ymm10
 vmovdqa 480(%rdi), %ymm11
 vpbroadcastq 72(%rsi), %ymm2
 vpmullw %ymm15, %ymm8, %ymm12
 vpmullw %ymm15, %ymm9, %ymm13
 vpmullw %ymm15, %ymm10, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm11, %ymm11
 vmovdqa 128(%rdi), %ymm4
 vmovdqa 160(%rdi), %ymm5
 vmovdqa 192(%rdi), %ymm6
 vmovdqa 224(%rdi), %ymm7
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm8, %ymm4, %ymm3
 vpsubw %ymm8, %ymm4, %ymm8
 vpaddw %ymm9, %ymm5, %ymm4
 vpsubw %ymm9, %ymm5, %ymm9
 vpaddw %ymm10, %ymm6, %ymm5
 vpsubw %ymm10, %ymm6, %ymm10
 vpaddw %ymm11, %ymm7, %ymm6
 vpsubw %ymm11, %ymm7, %ymm11
 vpsubw %ymm12, %ymm3, %ymm3
 vpaddw %ymm12, %ymm8, %ymm8
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm9, %ymm9
 vpsubw %ymm14, %ymm5, %ymm5
 vpaddw %ymm14, %ymm10, %ymm10
 vpsubw %ymm15, %ymm6, %ymm6
 vpaddw %ymm15, %ymm11, %ymm11
 vmovdqa %ymm3, 128(%rdi)
 vmovdqa %ymm4, 160(%rdi)
 vmovdqa %ymm5, 192(%rdi)
 vmovdqa %ymm6, 224(%rdi)
 vmovdqa %ymm8, 384(%rdi)
 vmovdqa %ymm9, 416(%rdi)
 vmovdqa %ymm10, 448(%rdi)
 vmovdqa %ymm11, 480(%rdi)
 vmovdqa 96(%rsi), %ymm15
 vmovdqa 128(%rdi), %ymm8
 vmovdqa 160(%rdi), %ymm9
 vmovdqa 192(%rdi), %ymm10
 vmovdqa 224(%rdi), %ymm11
 vmovdqa 128(%rsi), %ymm2
 vpmullw %ymm15, %ymm8, %ymm12
 vpmullw %ymm15, %ymm9, %ymm13
 vpmullw %ymm15, %ymm10, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm11, %ymm11
 vmovdqa (%rdi), %ymm4
 vmovdqa 32(%rdi), %ymm5
 vmovdqa 64(%rdi), %ymm6
 vmovdqa 96(%rdi), %ymm7
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm8, %ymm4, %ymm3
 vpsubw %ymm8, %ymm4, %ymm8
 vpaddw %ymm9, %ymm5, %ymm4
 vpsubw %ymm9, %ymm5, %ymm9
 vpaddw %ymm10, %ymm6, %ymm5
 vpsubw %ymm10, %ymm6, %ymm10
 vpaddw %ymm11, %ymm7, %ymm6
 vpsubw %ymm11, %ymm7, %ymm11
 vpsubw %ymm12, %ymm3, %ymm3
 vpaddw %ymm12, %ymm8, %ymm8
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm9, %ymm9
 vpsubw %ymm14, %ymm5, %ymm5
 vpaddw %ymm14, %ymm10, %ymm10
 vpsubw %ymm15, %ymm6, %ymm6
 vpaddw %ymm15, %ymm11, %ymm11
 vperm2i128 $0x20, %ymm10, %ymm5, %ymm7
 vperm2i128 $0x31, %ymm10, %ymm5, %ymm10
 vperm2i128 $0x20, %ymm11, %ymm6, %ymm5
 vperm2i128 $0x31, %ymm11, %ymm6, %ymm11
 vmovdqa 160(%rsi), %ymm15
 vmovdqa 192(%rsi), %ymm2
 vpmullw %ymm15, %ymm7, %ymm12
 vpmullw %ymm15, %ymm10, %ymm13
 vpmullw %ymm15, %ymm5, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm7, %ymm7
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm5, %ymm5
 vpmulhw %ymm2, %ymm11, %ymm11
 vperm2i128 $0x20, %ymm8, %ymm3, %ymm6
 vperm2i128 $0x31, %ymm8, %ymm3, %ymm8
 vperm2i128 $0x20, %ymm9, %ymm4, %ymm3
 vperm2i128 $0x31, %ymm9, %ymm4, %ymm9
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm7, %ymm6, %ymm4
 vpsubw %ymm7, %ymm6, %ymm7
 vpaddw %ymm10, %ymm8, %ymm6
 vpsubw %ymm10, %ymm8, %ymm10
 vpaddw %ymm5, %ymm3, %ymm8
 vpsubw %ymm5, %ymm3, %ymm5
 vpaddw %ymm11, %ymm9, %ymm3
 vpsubw %ymm11, %ymm9, %ymm11
 vpsubw %ymm12, %ymm4, %ymm4
 vpaddw %ymm12, %ymm7, %ymm7
 vpsubw %ymm13, %ymm6, %ymm6
 vpaddw %ymm13, %ymm10, %ymm10
 vpsubw %ymm14, %ymm8, %ymm8
 vpaddw %ymm14, %ymm5, %ymm5
 vpsubw %ymm15, %ymm3, %ymm3
 vpaddw %ymm15, %ymm11, %ymm11
 vpunpcklqdq %ymm5, %ymm8, %ymm9
 vpunpckhqdq %ymm5, %ymm8, %ymm5
 vpunpcklqdq %ymm11, %ymm3, %ymm8
 vpunpckhqdq %ymm11, %ymm3, %ymm11
 vmovdqa 224(%rsi), %ymm15
 vmovdqa 256(%rsi), %ymm2
 vpmullw %ymm15, %ymm9, %ymm12
 vpmullw %ymm15, %ymm5, %ymm13
 vpmullw %ymm15, %ymm8, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm5, %ymm5
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm11, %ymm11
 vpunpcklqdq %ymm7, %ymm4, %ymm3
 vpunpckhqdq %ymm7, %ymm4, %ymm7
 vpunpcklqdq %ymm10, %ymm6, %ymm4
 vpunpckhqdq %ymm10, %ymm6, %ymm10
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm9, %ymm3, %ymm6
 vpsubw %ymm9, %ymm3, %ymm9
 vpaddw %ymm5, %ymm7, %ymm3
 vpsubw %ymm5, %ymm7, %ymm5
 vpaddw %ymm8, %ymm4, %ymm7
 vpsubw %ymm8, %ymm4, %ymm8
 vpaddw %ymm11, %ymm10, %ymm4
 vpsubw %ymm11, %ymm10, %ymm11
 vpsubw %ymm12, %ymm6, %ymm6
 vpaddw %ymm12, %ymm9, %ymm9
 vpsubw %ymm13, %ymm3, %ymm3
 vpaddw %ymm13, %ymm5, %ymm5
 vpsubw %ymm14, %ymm7, %ymm7
 vpaddw %ymm14, %ymm8, %ymm8
 vpsubw %ymm15, %ymm4, %ymm4
 vpaddw %ymm15, %ymm11, %ymm11
 vmovsldup %ymm8, %ymm10
 vpblendd $0xaa, %ymm10, %ymm7, %ymm10
 vpsrlq $0x20, %ymm7, %ymm7
 vpblendd $0xaa, %ymm8, %ymm7, %ymm8
 vmovsldup %ymm11, %ymm7
 vpblendd $0xaa, %ymm7, %ymm4, %ymm7
 vpsrlq $0x20, %ymm4, %ymm4
 vpblendd $0xaa, %ymm11, %ymm4, %ymm11
 vmovdqa 288(%rsi), %ymm15
 vmovdqa 320(%rsi), %ymm2
 vpmullw %ymm15, %ymm10, %ymm12
 vpmullw %ymm15, %ymm8, %ymm13
 vpmullw %ymm15, %ymm7, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm7, %ymm7
 vpmulhw %ymm2, %ymm11, %ymm11
 vmovsldup %ymm9, %ymm4
 vpblendd $0xaa, %ymm4, %ymm6, %ymm4
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm9, %ymm6, %ymm9
 vmovsldup %ymm5, %ymm6
 vpblendd $0xaa, %ymm6, %ymm3, %ymm6
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm5, %ymm3, %ymm5
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm10, %ymm4, %ymm3
 vpsubw %ymm10, %ymm4, %ymm10
 vpaddw %ymm8, %ymm9, %ymm4
 vpsubw %ymm8, %ymm9, %ymm8
 vpaddw %ymm7, %ymm6, %ymm9
 vpsubw %ymm7, %ymm6, %ymm7
 vpaddw %ymm11, %ymm5, %ymm6
 vpsubw %ymm11, %ymm5, %ymm11
 vpsubw %ymm12, %ymm3, %ymm3
 vpaddw %ymm12, %ymm10, %ymm10
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm8, %ymm8
 vpsubw %ymm14, %ymm9, %ymm9
 vpaddw %ymm14, %ymm7, %ymm7
 vpsubw %ymm15, %ymm6, %ymm6
 vpaddw %ymm15, %ymm11, %ymm11
 vpslld $0x10, %ymm7, %ymm5
 vpblendw $0xaa, %ymm5, %ymm9, %ymm5
 vpsrld $0x10, %ymm9, %ymm9
 vpblendw $0xaa, %ymm7, %ymm9, %ymm7
 vpslld $0x10, %ymm11, %ymm9
 vpblendw $0xaa, %ymm9, %ymm6, %ymm9
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm11, %ymm6, %ymm11
 vmovdqa 352(%rsi), %ymm15
 vmovdqa 384(%rsi), %ymm2
 vpmullw %ymm15, %ymm5, %ymm12
 vpmullw %ymm15, %ymm7, %ymm13
 vpmullw %ymm15, %ymm9, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm5, %ymm5
 vpmulhw %ymm2, %ymm7, %ymm7
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm11, %ymm11
 vpslld $0x10, %ymm10, %ymm6
 vpblendw $0xaa, %ymm6, %ymm3, %ymm6
 vpsrld $0x10, %ymm3, %ymm3
 vpblendw $0xaa, %ymm10, %ymm3, %ymm10
 vpslld $0x10, %ymm8, %ymm3
 vpblendw $0xaa, %ymm3, %ymm4, %ymm3
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm8, %ymm4, %ymm8
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm5, %ymm6, %ymm4
 vpsubw %ymm5, %ymm6, %ymm5
 vpaddw %ymm7, %ymm10, %ymm6
 vpsubw %ymm7, %ymm10, %ymm7
 vpaddw %ymm9, %ymm3, %ymm10
 vpsubw %ymm9, %ymm3, %ymm9
 vpaddw %ymm11, %ymm8, %ymm3
 vpsubw %ymm11, %ymm8, %ymm11
 vpsubw %ymm12, %ymm4, %ymm4
 vpaddw %ymm12, %ymm5, %ymm5
 vpsubw %ymm13, %ymm6, %ymm6
 vpaddw %ymm13, %ymm7, %ymm7
 vpsubw %ymm14, %ymm10, %ymm10
 vpaddw %ymm14, %ymm9, %ymm9
 vpsubw %ymm15, %ymm3, %ymm3
 vpaddw %ymm15, %ymm11, %ymm11
 vmovdqa 416(%rsi), %ymm14
 vmovdqa 480(%rsi), %ymm15
 vmovdqa 448(%rsi), %ymm8
 vmovdqa 512(%rsi), %ymm2
 vpmullw %ymm14, %ymm10, %ymm12
 vpmullw %ymm14, %ymm3, %ymm13
 vpmullw %ymm15, %ymm9, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm8, %ymm10, %ymm10
 vpmulhw %ymm8, %ymm3, %ymm3
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm11, %ymm11
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm10, %ymm4, %ymm8
 vpsubw %ymm10, %ymm4, %ymm10
 vpaddw %ymm3, %ymm6, %ymm4
 vpsubw %ymm3, %ymm6, %ymm3
 vpaddw %ymm9, %ymm5, %ymm6
 vpsubw %ymm9, %ymm5, %ymm9
 vpaddw %ymm11, %ymm7, %ymm5
 vpsubw %ymm11, %ymm7, %ymm11
 vpsubw %ymm12, %ymm8, %ymm8
 vpaddw %ymm12, %ymm10, %ymm10
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm3, %ymm3
 vpsubw %ymm14, %ymm6, %ymm6
 vpaddw %ymm14, %ymm9, %ymm9
 vpsubw %ymm15, %ymm5, %ymm5
 vpaddw %ymm15, %ymm11, %ymm11
 vmovdqa %ymm8, (%rdi)
 vmovdqa %ymm4, 32(%rdi)
 vmovdqa %ymm10, 64(%rdi)
 vmovdqa %ymm3, 96(%rdi)
 vmovdqa %ymm6, 128(%rdi)
 vmovdqa %ymm5, 160(%rdi)
 vmovdqa %ymm9, 192(%rdi)
 vmovdqa %ymm11, 224(%rdi)
 vmovdqa 544(%rsi), %ymm15
 vmovdqa 384(%rdi), %ymm8
 vmovdqa 416(%rdi), %ymm9
 vmovdqa 448(%rdi), %ymm10
 vmovdqa 480(%rdi), %ymm11
 vmovdqa 576(%rsi), %ymm2
 vpmullw %ymm15, %ymm8, %ymm12
 vpmullw %ymm15, %ymm9, %ymm13
 vpmullw %ymm15, %ymm10, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm11, %ymm11
 vmovdqa 256(%rdi), %ymm4
 vmovdqa 288(%rdi), %ymm5
 vmovdqa 320(%rdi), %ymm6
 vmovdqa 352(%rdi), %ymm7
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm8, %ymm4, %ymm3
 vpsubw %ymm8, %ymm4, %ymm8
 vpaddw %ymm9, %ymm5, %ymm4
 vpsubw %ymm9, %ymm5, %ymm9
 vpaddw %ymm10, %ymm6, %ymm5
 vpsubw %ymm10, %ymm6, %ymm10
 vpaddw %ymm11, %ymm7, %ymm6
 vpsubw %ymm11, %ymm7, %ymm11
 vpsubw %ymm12, %ymm3, %ymm3
 vpaddw %ymm12, %ymm8, %ymm8
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm9, %ymm9
 vpsubw %ymm14, %ymm5, %ymm5
 vpaddw %ymm14, %ymm10, %ymm10
 vpsubw %ymm15, %ymm6, %ymm6
 vpaddw %ymm15, %ymm11, %ymm11
 vperm2i128 $0x20, %ymm10, %ymm5, %ymm7
 vperm2i128 $0x31, %ymm10, %ymm5, %ymm10
 vperm2i128 $0x20, %ymm11, %ymm6, %ymm5
 vperm2i128 $0x31, %ymm11, %ymm6, %ymm11
 vmovdqa 608(%rsi), %ymm15
 vmovdqa 640(%rsi), %ymm2
 vpmullw %ymm15, %ymm7, %ymm12
 vpmullw %ymm15, %ymm10, %ymm13
 vpmullw %ymm15, %ymm5, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm7, %ymm7
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm5, %ymm5
 vpmulhw %ymm2, %ymm11, %ymm11
 vperm2i128 $0x20, %ymm8, %ymm3, %ymm6
 vperm2i128 $0x31, %ymm8, %ymm3, %ymm8
 vperm2i128 $0x20, %ymm9, %ymm4, %ymm3
 vperm2i128 $0x31, %ymm9, %ymm4, %ymm9
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm7, %ymm6, %ymm4
 vpsubw %ymm7, %ymm6, %ymm7
 vpaddw %ymm10, %ymm8, %ymm6
 vpsubw %ymm10, %ymm8, %ymm10
 vpaddw %ymm5, %ymm3, %ymm8
 vpsubw %ymm5, %ymm3, %ymm5
 vpaddw %ymm11, %ymm9, %ymm3
 vpsubw %ymm11, %ymm9, %ymm11
 vpsubw %ymm12, %ymm4, %ymm4
 vpaddw %ymm12, %ymm7, %ymm7
 vpsubw %ymm13, %ymm6, %ymm6
 vpaddw %ymm13, %ymm10, %ymm10
 vpsubw %ymm14, %ymm8, %ymm8
 vpaddw %ymm14, %ymm5, %ymm5
 vpsubw %ymm15, %ymm3, %ymm3
 vpaddw %ymm15, %ymm11, %ymm11
 vpunpcklqdq %ymm5, %ymm8, %ymm9
 vpunpckhqdq %ymm5, %ymm8, %ymm5
 vpunpcklqdq %ymm11, %ymm3, %ymm8
 vpunpckhqdq %ymm11, %ymm3, %ymm11
 vmovdqa 672(%rsi), %ymm15
 vmovdqa 704(%rsi), %ymm2
 vpmullw %ymm15, %ymm9, %ymm12
 vpmullw %ymm15, %ymm5, %ymm13
 vpmullw %ymm15, %ymm8, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm5, %ymm5
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm11, %ymm11
 vpunpcklqdq %ymm7, %ymm4, %ymm3
 vpunpckhqdq %ymm7, %ymm4, %ymm7
 vpunpcklqdq %ymm10, %ymm6, %ymm4
 vpunpckhqdq %ymm10, %ymm6, %ymm10
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm9, %ymm3, %ymm6
 vpsubw %ymm9, %ymm3, %ymm9
 vpaddw %ymm5, %ymm7, %ymm3
 vpsubw %ymm5, %ymm7, %ymm5
 vpaddw %ymm8, %ymm4, %ymm7
 vpsubw %ymm8, %ymm4, %ymm8
 vpaddw %ymm11, %ymm10, %ymm4
 vpsubw %ymm11, %ymm10, %ymm11
 vpsubw %ymm12, %ymm6, %ymm6
 vpaddw %ymm12, %ymm9, %ymm9
 vpsubw %ymm13, %ymm3, %ymm3
 vpaddw %ymm13, %ymm5, %ymm5
 vpsubw %ymm14, %ymm7, %ymm7
 vpaddw %ymm14, %ymm8, %ymm8
 vpsubw %ymm15, %ymm4, %ymm4
 vpaddw %ymm15, %ymm11, %ymm11
 vmovsldup %ymm8, %ymm10
 vpblendd $0xaa, %ymm10, %ymm7, %ymm10
 vpsrlq $0x20, %ymm7, %ymm7
 vpblendd $0xaa, %ymm8, %ymm7, %ymm8
 vmovsldup %ymm11, %ymm7
 vpblendd $0xaa, %ymm7, %ymm4, %ymm7
 vpsrlq $0x20, %ymm4, %ymm4
 vpblendd $0xaa, %ymm11, %ymm4, %ymm11
 vmovdqa 736(%rsi), %ymm15
 vmovdqa 768(%rsi), %ymm2
 vpmullw %ymm15, %ymm10, %ymm12
 vpmullw %ymm15, %ymm8, %ymm13
 vpmullw %ymm15, %ymm7, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm10, %ymm10
 vpmulhw %ymm2, %ymm8, %ymm8
 vpmulhw %ymm2, %ymm7, %ymm7
 vpmulhw %ymm2, %ymm11, %ymm11
 vmovsldup %ymm9, %ymm4
 vpblendd $0xaa, %ymm4, %ymm6, %ymm4
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm9, %ymm6, %ymm9
 vmovsldup %ymm5, %ymm6
 vpblendd $0xaa, %ymm6, %ymm3, %ymm6
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm5, %ymm3, %ymm5
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm10, %ymm4, %ymm3
 vpsubw %ymm10, %ymm4, %ymm10
 vpaddw %ymm8, %ymm9, %ymm4
 vpsubw %ymm8, %ymm9, %ymm8
 vpaddw %ymm7, %ymm6, %ymm9
 vpsubw %ymm7, %ymm6, %ymm7
 vpaddw %ymm11, %ymm5, %ymm6
 vpsubw %ymm11, %ymm5, %ymm11
 vpsubw %ymm12, %ymm3, %ymm3
 vpaddw %ymm12, %ymm10, %ymm10
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm8, %ymm8
 vpsubw %ymm14, %ymm9, %ymm9
 vpaddw %ymm14, %ymm7, %ymm7
 vpsubw %ymm15, %ymm6, %ymm6
 vpaddw %ymm15, %ymm11, %ymm11
 vpslld $0x10, %ymm7, %ymm5
 vpblendw $0xaa, %ymm5, %ymm9, %ymm5
 vpsrld $0x10, %ymm9, %ymm9
 vpblendw $0xaa, %ymm7, %ymm9, %ymm7
 vpslld $0x10, %ymm11, %ymm9
 vpblendw $0xaa, %ymm9, %ymm6, %ymm9
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm11, %ymm6, %ymm11
 vmovdqa 800(%rsi), %ymm15
 vmovdqa 832(%rsi), %ymm2
 vpmullw %ymm15, %ymm5, %ymm12
 vpmullw %ymm15, %ymm7, %ymm13
 vpmullw %ymm15, %ymm9, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm2, %ymm5, %ymm5
 vpmulhw %ymm2, %ymm7, %ymm7
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm11, %ymm11
 vpslld $0x10, %ymm10, %ymm6
 vpblendw $0xaa, %ymm6, %ymm3, %ymm6
 vpsrld $0x10, %ymm3, %ymm3
 vpblendw $0xaa, %ymm10, %ymm3, %ymm10
 vpslld $0x10, %ymm8, %ymm3
 vpblendw $0xaa, %ymm3, %ymm4, %ymm3
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm8, %ymm4, %ymm8
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm5, %ymm6, %ymm4
 vpsubw %ymm5, %ymm6, %ymm5
 vpaddw %ymm7, %ymm10, %ymm6
 vpsubw %ymm7, %ymm10, %ymm7
 vpaddw %ymm9, %ymm3, %ymm10
 vpsubw %ymm9, %ymm3, %ymm9
 vpaddw %ymm11, %ymm8, %ymm3
 vpsubw %ymm11, %ymm8, %ymm11
 vpsubw %ymm12, %ymm4, %ymm4
 vpaddw %ymm12, %ymm5, %ymm5
 vpsubw %ymm13, %ymm6, %ymm6
 vpaddw %ymm13, %ymm7, %ymm7
 vpsubw %ymm14, %ymm10, %ymm10
 vpaddw %ymm14, %ymm9, %ymm9
 vpsubw %ymm15, %ymm3, %ymm3
 vpaddw %ymm15, %ymm11, %ymm11
 vmovdqa 864(%rsi), %ymm14
 vmovdqa 928(%rsi), %ymm15
 vmovdqa 896(%rsi), %ymm8
 vmovdqa 960(%rsi), %ymm2
 vpmullw %ymm14, %ymm10, %ymm12
 vpmullw %ymm14, %ymm3, %ymm13
 vpmullw %ymm15, %ymm9, %ymm14
 vpmullw %ymm15, %ymm11, %ymm15
 vpmulhw %ymm8, %ymm10, %ymm10
 vpmulhw %ymm8, %ymm3, %ymm3
 vpmulhw %ymm2, %ymm9, %ymm9
 vpmulhw %ymm2, %ymm11, %ymm11
 vpmulhw %ymm0, %ymm12, %ymm12
 vpmulhw %ymm0, %ymm13, %ymm13
 vpmulhw %ymm0, %ymm14, %ymm14
 vpmulhw %ymm0, %ymm15, %ymm15
 vpaddw %ymm10, %ymm4, %ymm8
 vpsubw %ymm10, %ymm4, %ymm10
 vpaddw %ymm3, %ymm6, %ymm4
 vpsubw %ymm3, %ymm6, %ymm3
 vpaddw %ymm9, %ymm5, %ymm6
 vpsubw %ymm9, %ymm5, %ymm9
 vpaddw %ymm11, %ymm7, %ymm5
 vpsubw %ymm11, %ymm7, %ymm11
 vpsubw %ymm12, %ymm8, %ymm8
 vpaddw %ymm12, %ymm10, %ymm10
 vpsubw %ymm13, %ymm4, %ymm4
 vpaddw %ymm13, %ymm3, %ymm3
 vpsubw %ymm14, %ymm6, %ymm6
 vpaddw %ymm14, %ymm9, %ymm9
 vpsubw %ymm15, %ymm5, %ymm5
 vpaddw %ymm15, %ymm11, %ymm11
 vmovdqa %ymm8, 256(%rdi)
 vmovdqa %ymm4, 288(%rdi)
 vmovdqa %ymm10, 320(%rdi)
 vmovdqa %ymm3, 352(%rdi)
 vmovdqa %ymm6, 384(%rdi)
 vmovdqa %ymm5, 416(%rdi)
 vmovdqa %ymm9, 448(%rdi)
 vmovdqa %ymm11, 480(%rdi)
        retq ; .cfi_endproc
.size vailMlKemNtt, .-vailMlKemNtt
        .text
        .balign 4
vailMlKemUnpack:
 .cfi_startproc
 endbr64
 vmovdqa (%rdi), %ymm4
 vmovdqa 32(%rdi), %ymm5
 vmovdqa 64(%rdi), %ymm6
 vmovdqa 96(%rdi), %ymm7
 vmovdqa 128(%rdi), %ymm8
 vmovdqa 160(%rdi), %ymm9
 vmovdqa 192(%rdi), %ymm10
 vmovdqa 224(%rdi), %ymm11
 vperm2i128 $0x20, %ymm8, %ymm4, %ymm3
 vperm2i128 $0x31, %ymm8, %ymm4, %ymm8
 vperm2i128 $0x20, %ymm9, %ymm5, %ymm4
 vperm2i128 $0x31, %ymm9, %ymm5, %ymm9
 vperm2i128 $0x20, %ymm10, %ymm6, %ymm5
 vperm2i128 $0x31, %ymm10, %ymm6, %ymm10
 vperm2i128 $0x20, %ymm11, %ymm7, %ymm6
 vperm2i128 $0x31, %ymm11, %ymm7, %ymm11
 vpunpcklqdq %ymm5, %ymm3, %ymm7
 vpunpckhqdq %ymm5, %ymm3, %ymm5
 vpunpcklqdq %ymm10, %ymm8, %ymm3
 vpunpckhqdq %ymm10, %ymm8, %ymm10
 vpunpcklqdq %ymm6, %ymm4, %ymm8
 vpunpckhqdq %ymm6, %ymm4, %ymm6
 vpunpcklqdq %ymm11, %ymm9, %ymm4
 vpunpckhqdq %ymm11, %ymm9, %ymm11
 vmovsldup %ymm8, %ymm9
 vpblendd $0xaa, %ymm9, %ymm7, %ymm9
 vpsrlq $0x20, %ymm7, %ymm7
 vpblendd $0xaa, %ymm8, %ymm7, %ymm8
 vmovsldup %ymm6, %ymm7
 vpblendd $0xaa, %ymm7, %ymm5, %ymm7
 vpsrlq $0x20, %ymm5, %ymm5
 vpblendd $0xaa, %ymm6, %ymm5, %ymm6
 vmovsldup %ymm4, %ymm5
 vpblendd $0xaa, %ymm5, %ymm3, %ymm5
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm4, %ymm3, %ymm4
 vmovsldup %ymm11, %ymm3
 vpblendd $0xaa, %ymm3, %ymm10, %ymm3
 vpsrlq $0x20, %ymm10, %ymm10
 vpblendd $0xaa, %ymm11, %ymm10, %ymm11
 vpslld $0x10, %ymm5, %ymm10
 vpblendw $0xaa, %ymm10, %ymm9, %ymm10
 vpsrld $0x10, %ymm9, %ymm9
 vpblendw $0xaa, %ymm5, %ymm9, %ymm5
 vpslld $0x10, %ymm4, %ymm9
 vpblendw $0xaa, %ymm9, %ymm8, %ymm9
 vpsrld $0x10, %ymm8, %ymm8
 vpblendw $0xaa, %ymm4, %ymm8, %ymm4
 vpslld $0x10, %ymm3, %ymm8
 vpblendw $0xaa, %ymm8, %ymm7, %ymm8
 vpsrld $0x10, %ymm7, %ymm7
 vpblendw $0xaa, %ymm3, %ymm7, %ymm3
 vpslld $0x10, %ymm11, %ymm7
 vpblendw $0xaa, %ymm7, %ymm6, %ymm7
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm11, %ymm6, %ymm11
 vmovdqa %ymm10, (%rdi)
 vmovdqa %ymm5, 32(%rdi)
 vmovdqa %ymm9, 64(%rdi)
 vmovdqa %ymm4, 96(%rdi)
 vmovdqa %ymm8, 128(%rdi)
 vmovdqa %ymm3, 160(%rdi)
 vmovdqa %ymm7, 192(%rdi)
 vmovdqa %ymm11, 224(%rdi)
 vmovdqa 256(%rdi), %ymm4
 vmovdqa 288(%rdi), %ymm5
 vmovdqa 320(%rdi), %ymm6
 vmovdqa 352(%rdi), %ymm7
 vmovdqa 384(%rdi), %ymm8
 vmovdqa 416(%rdi), %ymm9
 vmovdqa 448(%rdi), %ymm10
 vmovdqa 480(%rdi), %ymm11
 vperm2i128 $0x20, %ymm8, %ymm4, %ymm3
 vperm2i128 $0x31, %ymm8, %ymm4, %ymm8
 vperm2i128 $0x20, %ymm9, %ymm5, %ymm4
 vperm2i128 $0x31, %ymm9, %ymm5, %ymm9
 vperm2i128 $0x20, %ymm10, %ymm6, %ymm5
 vperm2i128 $0x31, %ymm10, %ymm6, %ymm10
 vperm2i128 $0x20, %ymm11, %ymm7, %ymm6
 vperm2i128 $0x31, %ymm11, %ymm7, %ymm11
 vpunpcklqdq %ymm5, %ymm3, %ymm7
 vpunpckhqdq %ymm5, %ymm3, %ymm5
 vpunpcklqdq %ymm10, %ymm8, %ymm3
 vpunpckhqdq %ymm10, %ymm8, %ymm10
 vpunpcklqdq %ymm6, %ymm4, %ymm8
 vpunpckhqdq %ymm6, %ymm4, %ymm6
 vpunpcklqdq %ymm11, %ymm9, %ymm4
 vpunpckhqdq %ymm11, %ymm9, %ymm11
 vmovsldup %ymm8, %ymm9
 vpblendd $0xaa, %ymm9, %ymm7, %ymm9
 vpsrlq $0x20, %ymm7, %ymm7
 vpblendd $0xaa, %ymm8, %ymm7, %ymm8
 vmovsldup %ymm6, %ymm7
 vpblendd $0xaa, %ymm7, %ymm5, %ymm7
 vpsrlq $0x20, %ymm5, %ymm5
 vpblendd $0xaa, %ymm6, %ymm5, %ymm6
 vmovsldup %ymm4, %ymm5
 vpblendd $0xaa, %ymm5, %ymm3, %ymm5
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm4, %ymm3, %ymm4
 vmovsldup %ymm11, %ymm3
 vpblendd $0xaa, %ymm3, %ymm10, %ymm3
 vpsrlq $0x20, %ymm10, %ymm10
 vpblendd $0xaa, %ymm11, %ymm10, %ymm11
 vpslld $0x10, %ymm5, %ymm10
 vpblendw $0xaa, %ymm10, %ymm9, %ymm10
 vpsrld $0x10, %ymm9, %ymm9
 vpblendw $0xaa, %ymm5, %ymm9, %ymm5
 vpslld $0x10, %ymm4, %ymm9
 vpblendw $0xaa, %ymm9, %ymm8, %ymm9
 vpsrld $0x10, %ymm8, %ymm8
 vpblendw $0xaa, %ymm4, %ymm8, %ymm4
 vpslld $0x10, %ymm3, %ymm8
 vpblendw $0xaa, %ymm8, %ymm7, %ymm8
 vpsrld $0x10, %ymm7, %ymm7
 vpblendw $0xaa, %ymm3, %ymm7, %ymm3
 vpslld $0x10, %ymm11, %ymm7
 vpblendw $0xaa, %ymm7, %ymm6, %ymm7
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm11, %ymm6, %ymm11
 vmovdqa %ymm10, 256(%rdi)
 vmovdqa %ymm5, 288(%rdi)
 vmovdqa %ymm9, 320(%rdi)
 vmovdqa %ymm4, 352(%rdi)
 vmovdqa %ymm8, 384(%rdi)
 vmovdqa %ymm3, 416(%rdi)
 vmovdqa %ymm7, 448(%rdi)
 vmovdqa %ymm11, 480(%rdi)
 retq ; .cfi_endproc
.size vailMlKemUnpack, .-vailMlKemUnpack
        .text
        .balign 4
vailMlKemInvNtt:
 .cfi_startproc
  endbr64
 mov $0xd010d01, %eax
 vmovd %eax, %xmm0
 vpbroadcastd %xmm0, %ymm0
 mov $0xd8a1d8a1, %eax
 vmovd %eax, %xmm2
 vpbroadcastd %xmm2, %ymm2
 mov $0x5a105a1, %eax
 vmovd %eax, %xmm3
 vpbroadcastd %xmm3, %ymm3
 vmovdqa (%rdi), %ymm4
 vmovdqa 64(%rdi), %ymm6
 vmovdqa 32(%rdi), %ymm5
 vmovdqa 96(%rdi), %ymm7
 vpmullw %ymm2, %ymm4, %ymm12
 vpmulhw %ymm3, %ymm4, %ymm4
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm4, %ymm4
 vpmullw %ymm2, %ymm6, %ymm12
 vpmulhw %ymm3, %ymm6, %ymm6
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm6, %ymm6
 vpmullw %ymm2, %ymm5, %ymm12
 vpmulhw %ymm3, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm5, %ymm5
 vpmullw %ymm2, %ymm7, %ymm12
 vpmulhw %ymm3, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm7, %ymm7
 vmovdqa 128(%rdi), %ymm8
 vmovdqa 192(%rdi), %ymm10
 vmovdqa 160(%rdi), %ymm9
 vmovdqa 224(%rdi), %ymm11
 vpmullw %ymm2, %ymm8, %ymm12
 vpmulhw %ymm3, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm8, %ymm8
 vpmullw %ymm2, %ymm10, %ymm12
 vpmulhw %ymm3, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm10, %ymm10
 vpmullw %ymm2, %ymm9, %ymm12
 vpmulhw %ymm3, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm9, %ymm9
 vpmullw %ymm2, %ymm11, %ymm12
 vpmulhw %ymm3, %ymm11, %ymm11
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm11, %ymm11
 vpermq $0x4e, 928(%rsi), %ymm15
 vpermq $0x4e, 864(%rsi), %ymm1
 vpermq $0x4e, 960(%rsi), %ymm2
 vpermq $0x4e, 896(%rsi), %ymm3
 vmovdqa (%rsi), %ymm12
 vpshufb %ymm12, %ymm15, %ymm15
 vpshufb %ymm12, %ymm1, %ymm1
 vpshufb %ymm12, %ymm2, %ymm2
 vpshufb %ymm12, %ymm3, %ymm3
 vpsubw %ymm4, %ymm6, %ymm12
 vpaddw %ymm6, %ymm4, %ymm4
 vpsubw %ymm5, %ymm7, %ymm13
 vpmullw %ymm15, %ymm12, %ymm6
 vpaddw %ymm7, %ymm5, %ymm5
 vpsubw %ymm8, %ymm10, %ymm14
 vpmullw %ymm15, %ymm13, %ymm7
 vpaddw %ymm10, %ymm8, %ymm8
 vpsubw %ymm9, %ymm11, %ymm15
 vpmullw %ymm1, %ymm14, %ymm10
 vpaddw %ymm11, %ymm9, %ymm9
 vpmullw %ymm1, %ymm15, %ymm11
 vpmulhw %ymm2, %ymm12, %ymm12
 vpmulhw %ymm2, %ymm13, %ymm13
 vpmulhw %ymm3, %ymm14, %ymm14
 vpmulhw %ymm3, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm6, %ymm6
 vpmulhw %ymm0, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm6, %ymm12, %ymm6
 vpsubw %ymm7, %ymm13, %ymm7
 vpsubw %ymm10, %ymm14, %ymm10
 vpsubw %ymm11, %ymm15, %ymm11
 vpermq $0x4e, 800(%rsi), %ymm2
 vpermq $0x4e, 832(%rsi), %ymm3
 vmovdqa (%rsi), %ymm1
 vpshufb %ymm1, %ymm2, %ymm2
 vpshufb %ymm1, %ymm3, %ymm3
 vpsubw %ymm4, %ymm8, %ymm12
 vpaddw %ymm8, %ymm4, %ymm4
 vpsubw %ymm5, %ymm9, %ymm13
 vpmullw %ymm2, %ymm12, %ymm8
 vpaddw %ymm9, %ymm5, %ymm5
 vpsubw %ymm6, %ymm10, %ymm14
 vpmullw %ymm2, %ymm13, %ymm9
 vpaddw %ymm10, %ymm6, %ymm6
 vpsubw %ymm7, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm10
 vpaddw %ymm11, %ymm7, %ymm7
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm3, %ymm12, %ymm12
 vpmulhw %ymm3, %ymm13, %ymm13
 vpmulhw %ymm3, %ymm14, %ymm14
 vpmulhw %ymm3, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm8, %ymm12, %ymm8
 vpsubw %ymm9, %ymm13, %ymm9
 vpsubw %ymm10, %ymm14, %ymm10
 vpsubw %ymm11, %ymm15, %ymm11
 vpslld $0x10, %ymm5, %ymm3
 vpblendw $0xaa, %ymm3, %ymm4, %ymm3
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm5, %ymm4, %ymm5
 vpslld $0x10, %ymm7, %ymm4
 vpblendw $0xaa, %ymm4, %ymm6, %ymm4
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm7, %ymm6, %ymm7
 vpslld $0x10, %ymm9, %ymm6
 vpblendw $0xaa, %ymm6, %ymm8, %ymm6
 vpsrld $0x10, %ymm8, %ymm8
 vpblendw $0xaa, %ymm9, %ymm8, %ymm9
 vpslld $0x10, %ymm11, %ymm8
 vpblendw $0xaa, %ymm8, %ymm10, %ymm8
 vpsrld $0x10, %ymm10, %ymm10
 vpblendw $0xaa, %ymm11, %ymm10, %ymm11
 vmovdqa 32(%rsi), %ymm12
 vpermd 736(%rsi), %ymm12, %ymm2
 vpermd 768(%rsi), %ymm12, %ymm10
 vpsubw %ymm3, %ymm5, %ymm12
 vpaddw %ymm5, %ymm3, %ymm3
 vpsubw %ymm4, %ymm7, %ymm13
 vpmullw %ymm2, %ymm12, %ymm5
 vpaddw %ymm7, %ymm4, %ymm4
 vpsubw %ymm6, %ymm9, %ymm14
 vpmullw %ymm2, %ymm13, %ymm7
 vpaddw %ymm9, %ymm6, %ymm6
 vpsubw %ymm8, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm9
 vpaddw %ymm11, %ymm8, %ymm8
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm10, %ymm12, %ymm12
 vpmulhw %ymm10, %ymm13, %ymm13
 vpmulhw %ymm10, %ymm14, %ymm14
 vpmulhw %ymm10, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm5, %ymm12, %ymm5
 vpsubw %ymm7, %ymm13, %ymm7
 vpsubw %ymm9, %ymm14, %ymm9
 vpsubw %ymm11, %ymm15, %ymm11
 mov $0x4ebf4ebf, %eax
 vmovd %eax, %xmm1
 vpbroadcastd %xmm1, %ymm1
 vpmulhw %ymm1, %ymm3, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm3, %ymm3
 vmovsldup %ymm4, %ymm10
 vpblendd $0xaa, %ymm10, %ymm3, %ymm10
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm4, %ymm3, %ymm4
 vmovsldup %ymm8, %ymm3
 vpblendd $0xaa, %ymm3, %ymm6, %ymm3
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm8, %ymm6, %ymm8
 vmovsldup %ymm7, %ymm6
 vpblendd $0xaa, %ymm6, %ymm5, %ymm6
 vpsrlq $0x20, %ymm5, %ymm5
 vpblendd $0xaa, %ymm7, %ymm5, %ymm7
 vmovsldup %ymm11, %ymm5
 vpblendd $0xaa, %ymm5, %ymm9, %ymm5
 vpsrlq $0x20, %ymm9, %ymm9
 vpblendd $0xaa, %ymm11, %ymm9, %ymm11
 vpermq $0x1b, 672(%rsi), %ymm2
 vpermq $0x1b, 704(%rsi), %ymm9
 vpsubw %ymm10, %ymm4, %ymm12
 vpaddw %ymm4, %ymm10, %ymm10
 vpsubw %ymm3, %ymm8, %ymm13
 vpmullw %ymm2, %ymm12, %ymm4
 vpaddw %ymm8, %ymm3, %ymm3
 vpsubw %ymm6, %ymm7, %ymm14
 vpmullw %ymm2, %ymm13, %ymm8
 vpaddw %ymm7, %ymm6, %ymm6
 vpsubw %ymm5, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm7
 vpaddw %ymm11, %ymm5, %ymm5
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm9, %ymm12, %ymm12
 vpmulhw %ymm9, %ymm13, %ymm13
 vpmulhw %ymm9, %ymm14, %ymm14
 vpmulhw %ymm9, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm4, %ymm4
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm4, %ymm12, %ymm4
 vpsubw %ymm8, %ymm13, %ymm8
 vpsubw %ymm7, %ymm14, %ymm7
 vpsubw %ymm11, %ymm15, %ymm11
 vpmulhw %ymm1, %ymm10, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm10, %ymm10
 vpunpcklqdq %ymm3, %ymm10, %ymm9
 vpunpckhqdq %ymm3, %ymm10, %ymm3
 vpunpcklqdq %ymm5, %ymm6, %ymm10
 vpunpckhqdq %ymm5, %ymm6, %ymm5
 vpunpcklqdq %ymm8, %ymm4, %ymm6
 vpunpckhqdq %ymm8, %ymm4, %ymm8
 vpunpcklqdq %ymm11, %ymm7, %ymm4
 vpunpckhqdq %ymm11, %ymm7, %ymm11
 vpermq $0x4e, 608(%rsi), %ymm2
 vpermq $0x4e, 640(%rsi), %ymm7
 vpsubw %ymm9, %ymm3, %ymm12
 vpaddw %ymm3, %ymm9, %ymm9
 vpsubw %ymm10, %ymm5, %ymm13
 vpmullw %ymm2, %ymm12, %ymm3
 vpaddw %ymm5, %ymm10, %ymm10
 vpsubw %ymm6, %ymm8, %ymm14
 vpmullw %ymm2, %ymm13, %ymm5
 vpaddw %ymm8, %ymm6, %ymm6
 vpsubw %ymm4, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm8
 vpaddw %ymm11, %ymm4, %ymm4
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm7, %ymm12, %ymm12
 vpmulhw %ymm7, %ymm13, %ymm13
 vpmulhw %ymm7, %ymm14, %ymm14
 vpmulhw %ymm7, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm3, %ymm3
 vpmulhw %ymm0, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm3, %ymm12, %ymm3
 vpsubw %ymm5, %ymm13, %ymm5
 vpsubw %ymm8, %ymm14, %ymm8
 vpsubw %ymm11, %ymm15, %ymm11
 vpmulhw %ymm1, %ymm9, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm9, %ymm9
 vperm2i128 $0x20, %ymm10, %ymm9, %ymm7
 vperm2i128 $0x31, %ymm10, %ymm9, %ymm10
 vperm2i128 $0x20, %ymm4, %ymm6, %ymm9
 vperm2i128 $0x31, %ymm4, %ymm6, %ymm4
 vperm2i128 $0x20, %ymm5, %ymm3, %ymm6
 vperm2i128 $0x31, %ymm5, %ymm3, %ymm5
 vperm2i128 $0x20, %ymm11, %ymm8, %ymm3
 vperm2i128 $0x31, %ymm11, %ymm8, %ymm11
 vmovdqa 544(%rsi), %ymm2
 vmovdqa 576(%rsi), %ymm8
 vpsubw %ymm7, %ymm10, %ymm12
 vpaddw %ymm10, %ymm7, %ymm7
 vpsubw %ymm9, %ymm4, %ymm13
 vpmullw %ymm2, %ymm12, %ymm10
 vpaddw %ymm4, %ymm9, %ymm9
 vpsubw %ymm6, %ymm5, %ymm14
 vpmullw %ymm2, %ymm13, %ymm4
 vpaddw %ymm5, %ymm6, %ymm6
 vpsubw %ymm3, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm5
 vpaddw %ymm11, %ymm3, %ymm3
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm8, %ymm12, %ymm12
 vpmulhw %ymm8, %ymm13, %ymm13
 vpmulhw %ymm8, %ymm14, %ymm14
 vpmulhw %ymm8, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm4, %ymm4
 vpmulhw %ymm0, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm10, %ymm12, %ymm10
 vpsubw %ymm4, %ymm13, %ymm4
 vpsubw %ymm5, %ymm14, %ymm5
 vpsubw %ymm11, %ymm15, %ymm11
 vpmulhw %ymm1, %ymm7, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm7, %ymm7
 vmovdqa %ymm7, (%rdi)
 vmovdqa %ymm9, 32(%rdi)
 vmovdqa %ymm6, 64(%rdi)
 vmovdqa %ymm3, 96(%rdi)
 vmovdqa %ymm10, 128(%rdi)
 vmovdqa %ymm4, 160(%rdi)
 vmovdqa %ymm5, 192(%rdi)
 vmovdqa %ymm11, 224(%rdi)
 mov $0xd8a1d8a1, %eax
 vmovd %eax, %xmm2
 vpbroadcastd %xmm2, %ymm2
 mov $0x5a105a1, %eax
 vmovd %eax, %xmm3
 vpbroadcastd %xmm3, %ymm3
 vmovdqa 256(%rdi), %ymm4
 vmovdqa 320(%rdi), %ymm6
 vmovdqa 288(%rdi), %ymm5
 vmovdqa 352(%rdi), %ymm7
 vpmullw %ymm2, %ymm4, %ymm12
 vpmulhw %ymm3, %ymm4, %ymm4
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm4, %ymm4
 vpmullw %ymm2, %ymm6, %ymm12
 vpmulhw %ymm3, %ymm6, %ymm6
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm6, %ymm6
 vpmullw %ymm2, %ymm5, %ymm12
 vpmulhw %ymm3, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm5, %ymm5
 vpmullw %ymm2, %ymm7, %ymm12
 vpmulhw %ymm3, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm7, %ymm7
 vmovdqa 384(%rdi), %ymm8
 vmovdqa 448(%rdi), %ymm10
 vmovdqa 416(%rdi), %ymm9
 vmovdqa 480(%rdi), %ymm11
 vpmullw %ymm2, %ymm8, %ymm12
 vpmulhw %ymm3, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm8, %ymm8
 vpmullw %ymm2, %ymm10, %ymm12
 vpmulhw %ymm3, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm10, %ymm10
 vpmullw %ymm2, %ymm9, %ymm12
 vpmulhw %ymm3, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm9, %ymm9
 vpmullw %ymm2, %ymm11, %ymm12
 vpmulhw %ymm3, %ymm11, %ymm11
 vpmulhw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm11, %ymm11
 vpermq $0x4e, 480(%rsi), %ymm15
 vpermq $0x4e, 416(%rsi), %ymm1
 vpermq $0x4e, 512(%rsi), %ymm2
 vpermq $0x4e, 448(%rsi), %ymm3
 vmovdqa (%rsi), %ymm12
 vpshufb %ymm12, %ymm15, %ymm15
 vpshufb %ymm12, %ymm1, %ymm1
 vpshufb %ymm12, %ymm2, %ymm2
 vpshufb %ymm12, %ymm3, %ymm3
 vpsubw %ymm4, %ymm6, %ymm12
 vpaddw %ymm6, %ymm4, %ymm4
 vpsubw %ymm5, %ymm7, %ymm13
 vpmullw %ymm15, %ymm12, %ymm6
 vpaddw %ymm7, %ymm5, %ymm5
 vpsubw %ymm8, %ymm10, %ymm14
 vpmullw %ymm15, %ymm13, %ymm7
 vpaddw %ymm10, %ymm8, %ymm8
 vpsubw %ymm9, %ymm11, %ymm15
 vpmullw %ymm1, %ymm14, %ymm10
 vpaddw %ymm11, %ymm9, %ymm9
 vpmullw %ymm1, %ymm15, %ymm11
 vpmulhw %ymm2, %ymm12, %ymm12
 vpmulhw %ymm2, %ymm13, %ymm13
 vpmulhw %ymm3, %ymm14, %ymm14
 vpmulhw %ymm3, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm6, %ymm6
 vpmulhw %ymm0, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm6, %ymm12, %ymm6
 vpsubw %ymm7, %ymm13, %ymm7
 vpsubw %ymm10, %ymm14, %ymm10
 vpsubw %ymm11, %ymm15, %ymm11
 vpermq $0x4e, 352(%rsi), %ymm2
 vpermq $0x4e, 384(%rsi), %ymm3
 vmovdqa (%rsi), %ymm1
 vpshufb %ymm1, %ymm2, %ymm2
 vpshufb %ymm1, %ymm3, %ymm3
 vpsubw %ymm4, %ymm8, %ymm12
 vpaddw %ymm8, %ymm4, %ymm4
 vpsubw %ymm5, %ymm9, %ymm13
 vpmullw %ymm2, %ymm12, %ymm8
 vpaddw %ymm9, %ymm5, %ymm5
 vpsubw %ymm6, %ymm10, %ymm14
 vpmullw %ymm2, %ymm13, %ymm9
 vpaddw %ymm10, %ymm6, %ymm6
 vpsubw %ymm7, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm10
 vpaddw %ymm11, %ymm7, %ymm7
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm3, %ymm12, %ymm12
 vpmulhw %ymm3, %ymm13, %ymm13
 vpmulhw %ymm3, %ymm14, %ymm14
 vpmulhw %ymm3, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm8, %ymm12, %ymm8
 vpsubw %ymm9, %ymm13, %ymm9
 vpsubw %ymm10, %ymm14, %ymm10
 vpsubw %ymm11, %ymm15, %ymm11
 vpslld $0x10, %ymm5, %ymm3
 vpblendw $0xaa, %ymm3, %ymm4, %ymm3
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm5, %ymm4, %ymm5
 vpslld $0x10, %ymm7, %ymm4
 vpblendw $0xaa, %ymm4, %ymm6, %ymm4
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm7, %ymm6, %ymm7
 vpslld $0x10, %ymm9, %ymm6
 vpblendw $0xaa, %ymm6, %ymm8, %ymm6
 vpsrld $0x10, %ymm8, %ymm8
 vpblendw $0xaa, %ymm9, %ymm8, %ymm9
 vpslld $0x10, %ymm11, %ymm8
 vpblendw $0xaa, %ymm8, %ymm10, %ymm8
 vpsrld $0x10, %ymm10, %ymm10
 vpblendw $0xaa, %ymm11, %ymm10, %ymm11
 vmovdqa 32(%rsi), %ymm12
 vpermd 288(%rsi), %ymm12, %ymm2
 vpermd 320(%rsi), %ymm12, %ymm10
 vpsubw %ymm3, %ymm5, %ymm12
 vpaddw %ymm5, %ymm3, %ymm3
 vpsubw %ymm4, %ymm7, %ymm13
 vpmullw %ymm2, %ymm12, %ymm5
 vpaddw %ymm7, %ymm4, %ymm4
 vpsubw %ymm6, %ymm9, %ymm14
 vpmullw %ymm2, %ymm13, %ymm7
 vpaddw %ymm9, %ymm6, %ymm6
 vpsubw %ymm8, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm9
 vpaddw %ymm11, %ymm8, %ymm8
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm10, %ymm12, %ymm12
 vpmulhw %ymm10, %ymm13, %ymm13
 vpmulhw %ymm10, %ymm14, %ymm14
 vpmulhw %ymm10, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm5, %ymm12, %ymm5
 vpsubw %ymm7, %ymm13, %ymm7
 vpsubw %ymm9, %ymm14, %ymm9
 vpsubw %ymm11, %ymm15, %ymm11
 mov $0x4ebf4ebf, %eax
 vmovd %eax, %xmm1
 vpbroadcastd %xmm1, %ymm1
 vpmulhw %ymm1, %ymm3, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm3, %ymm3
 vmovsldup %ymm4, %ymm10
 vpblendd $0xaa, %ymm10, %ymm3, %ymm10
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm4, %ymm3, %ymm4
 vmovsldup %ymm8, %ymm3
 vpblendd $0xaa, %ymm3, %ymm6, %ymm3
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm8, %ymm6, %ymm8
 vmovsldup %ymm7, %ymm6
 vpblendd $0xaa, %ymm6, %ymm5, %ymm6
 vpsrlq $0x20, %ymm5, %ymm5
 vpblendd $0xaa, %ymm7, %ymm5, %ymm7
 vmovsldup %ymm11, %ymm5
 vpblendd $0xaa, %ymm5, %ymm9, %ymm5
 vpsrlq $0x20, %ymm9, %ymm9
 vpblendd $0xaa, %ymm11, %ymm9, %ymm11
 vpermq $0x1b, 224(%rsi), %ymm2
 vpermq $0x1b, 256(%rsi), %ymm9
 vpsubw %ymm10, %ymm4, %ymm12
 vpaddw %ymm4, %ymm10, %ymm10
 vpsubw %ymm3, %ymm8, %ymm13
 vpmullw %ymm2, %ymm12, %ymm4
 vpaddw %ymm8, %ymm3, %ymm3
 vpsubw %ymm6, %ymm7, %ymm14
 vpmullw %ymm2, %ymm13, %ymm8
 vpaddw %ymm7, %ymm6, %ymm6
 vpsubw %ymm5, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm7
 vpaddw %ymm11, %ymm5, %ymm5
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm9, %ymm12, %ymm12
 vpmulhw %ymm9, %ymm13, %ymm13
 vpmulhw %ymm9, %ymm14, %ymm14
 vpmulhw %ymm9, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm4, %ymm4
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm7, %ymm7
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm4, %ymm12, %ymm4
 vpsubw %ymm8, %ymm13, %ymm8
 vpsubw %ymm7, %ymm14, %ymm7
 vpsubw %ymm11, %ymm15, %ymm11
 vpmulhw %ymm1, %ymm10, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm10, %ymm10
 vpunpcklqdq %ymm3, %ymm10, %ymm9
 vpunpckhqdq %ymm3, %ymm10, %ymm3
 vpunpcklqdq %ymm5, %ymm6, %ymm10
 vpunpckhqdq %ymm5, %ymm6, %ymm5
 vpunpcklqdq %ymm8, %ymm4, %ymm6
 vpunpckhqdq %ymm8, %ymm4, %ymm8
 vpunpcklqdq %ymm11, %ymm7, %ymm4
 vpunpckhqdq %ymm11, %ymm7, %ymm11
 vpermq $0x4e, 160(%rsi), %ymm2
 vpermq $0x4e, 192(%rsi), %ymm7
 vpsubw %ymm9, %ymm3, %ymm12
 vpaddw %ymm3, %ymm9, %ymm9
 vpsubw %ymm10, %ymm5, %ymm13
 vpmullw %ymm2, %ymm12, %ymm3
 vpaddw %ymm5, %ymm10, %ymm10
 vpsubw %ymm6, %ymm8, %ymm14
 vpmullw %ymm2, %ymm13, %ymm5
 vpaddw %ymm8, %ymm6, %ymm6
 vpsubw %ymm4, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm8
 vpaddw %ymm11, %ymm4, %ymm4
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm7, %ymm12, %ymm12
 vpmulhw %ymm7, %ymm13, %ymm13
 vpmulhw %ymm7, %ymm14, %ymm14
 vpmulhw %ymm7, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm3, %ymm3
 vpmulhw %ymm0, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm3, %ymm12, %ymm3
 vpsubw %ymm5, %ymm13, %ymm5
 vpsubw %ymm8, %ymm14, %ymm8
 vpsubw %ymm11, %ymm15, %ymm11
 vpmulhw %ymm1, %ymm9, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm9, %ymm9
 vperm2i128 $0x20, %ymm10, %ymm9, %ymm7
 vperm2i128 $0x31, %ymm10, %ymm9, %ymm10
 vperm2i128 $0x20, %ymm4, %ymm6, %ymm9
 vperm2i128 $0x31, %ymm4, %ymm6, %ymm4
 vperm2i128 $0x20, %ymm5, %ymm3, %ymm6
 vperm2i128 $0x31, %ymm5, %ymm3, %ymm5
 vperm2i128 $0x20, %ymm11, %ymm8, %ymm3
 vperm2i128 $0x31, %ymm11, %ymm8, %ymm11
 vmovdqa 96(%rsi), %ymm2
 vmovdqa 128(%rsi), %ymm8
 vpsubw %ymm7, %ymm10, %ymm12
 vpaddw %ymm10, %ymm7, %ymm7
 vpsubw %ymm9, %ymm4, %ymm13
 vpmullw %ymm2, %ymm12, %ymm10
 vpaddw %ymm4, %ymm9, %ymm9
 vpsubw %ymm6, %ymm5, %ymm14
 vpmullw %ymm2, %ymm13, %ymm4
 vpaddw %ymm5, %ymm6, %ymm6
 vpsubw %ymm3, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm5
 vpaddw %ymm11, %ymm3, %ymm3
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm8, %ymm12, %ymm12
 vpmulhw %ymm8, %ymm13, %ymm13
 vpmulhw %ymm8, %ymm14, %ymm14
 vpmulhw %ymm8, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm4, %ymm4
 vpmulhw %ymm0, %ymm5, %ymm5
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm10, %ymm12, %ymm10
 vpsubw %ymm4, %ymm13, %ymm4
 vpsubw %ymm5, %ymm14, %ymm5
 vpsubw %ymm11, %ymm15, %ymm11
 vpmulhw %ymm1, %ymm7, %ymm12
 vpsraw $0xa, %ymm12, %ymm12
 vpmullw %ymm0, %ymm12, %ymm12
 vpsubw %ymm12, %ymm7, %ymm7
 vmovdqa %ymm7, 256(%rdi)
 vmovdqa %ymm9, 288(%rdi)
 vmovdqa %ymm6, 320(%rdi)
 vmovdqa %ymm3, 352(%rdi)
 vmovdqa %ymm10, 384(%rdi)
 vmovdqa %ymm4, 416(%rdi)
 vmovdqa %ymm5, 448(%rdi)
 vmovdqa %ymm11, 480(%rdi)
 vmovdqa (%rdi), %ymm4
 vmovdqa 256(%rdi), %ymm8
 vmovdqa 32(%rdi), %ymm5
 vmovdqa 288(%rdi), %ymm9
 vpbroadcastq 64(%rsi), %ymm2
 vmovdqa 64(%rdi), %ymm6
 vmovdqa 320(%rdi), %ymm10
 vmovdqa 96(%rdi), %ymm7
 vmovdqa 352(%rdi), %ymm11
 vpbroadcastq 72(%rsi), %ymm3
 vpsubw %ymm4, %ymm8, %ymm12
 vpaddw %ymm8, %ymm4, %ymm4
 vpsubw %ymm5, %ymm9, %ymm13
 vpmullw %ymm2, %ymm12, %ymm8
 vpaddw %ymm9, %ymm5, %ymm5
 vpsubw %ymm6, %ymm10, %ymm14
 vpmullw %ymm2, %ymm13, %ymm9
 vpaddw %ymm10, %ymm6, %ymm6
 vpsubw %ymm7, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm10
 vpaddw %ymm11, %ymm7, %ymm7
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm3, %ymm12, %ymm12
 vpmulhw %ymm3, %ymm13, %ymm13
 vpmulhw %ymm3, %ymm14, %ymm14
 vpmulhw %ymm3, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm8, %ymm12, %ymm8
 vpsubw %ymm9, %ymm13, %ymm9
 vpsubw %ymm10, %ymm14, %ymm10
 vpsubw %ymm11, %ymm15, %ymm11
 vmovdqa %ymm4, (%rdi)
 vmovdqa %ymm5, 32(%rdi)
 vmovdqa %ymm6, 64(%rdi)
 vmovdqa %ymm7, 96(%rdi)
 vmovdqa %ymm8, 256(%rdi)
 vmovdqa %ymm9, 288(%rdi)
 vmovdqa %ymm10, 320(%rdi)
 vmovdqa %ymm11, 352(%rdi)
 vmovdqa 128(%rdi), %ymm4
 vmovdqa 384(%rdi), %ymm8
 vmovdqa 160(%rdi), %ymm5
 vmovdqa 416(%rdi), %ymm9
 vpbroadcastq 64(%rsi), %ymm2
 vmovdqa 192(%rdi), %ymm6
 vmovdqa 448(%rdi), %ymm10
 vmovdqa 224(%rdi), %ymm7
 vmovdqa 480(%rdi), %ymm11
 vpbroadcastq 72(%rsi), %ymm3
 vpsubw %ymm4, %ymm8, %ymm12
 vpaddw %ymm8, %ymm4, %ymm4
 vpsubw %ymm5, %ymm9, %ymm13
 vpmullw %ymm2, %ymm12, %ymm8
 vpaddw %ymm9, %ymm5, %ymm5
 vpsubw %ymm6, %ymm10, %ymm14
 vpmullw %ymm2, %ymm13, %ymm9
 vpaddw %ymm10, %ymm6, %ymm6
 vpsubw %ymm7, %ymm11, %ymm15
 vpmullw %ymm2, %ymm14, %ymm10
 vpaddw %ymm11, %ymm7, %ymm7
 vpmullw %ymm2, %ymm15, %ymm11
 vpmulhw %ymm3, %ymm12, %ymm12
 vpmulhw %ymm3, %ymm13, %ymm13
 vpmulhw %ymm3, %ymm14, %ymm14
 vpmulhw %ymm3, %ymm15, %ymm15
 vpmulhw %ymm0, %ymm8, %ymm8
 vpmulhw %ymm0, %ymm9, %ymm9
 vpmulhw %ymm0, %ymm10, %ymm10
 vpmulhw %ymm0, %ymm11, %ymm11
 vpsubw %ymm8, %ymm12, %ymm8
 vpsubw %ymm9, %ymm13, %ymm9
 vpsubw %ymm10, %ymm14, %ymm10
 vpsubw %ymm11, %ymm15, %ymm11
 vmovdqa %ymm4, 128(%rdi)
 vmovdqa %ymm5, 160(%rdi)
 vmovdqa %ymm6, 192(%rdi)
 vmovdqa %ymm7, 224(%rdi)
 vmovdqa %ymm8, 384(%rdi)
 vmovdqa %ymm9, 416(%rdi)
 vmovdqa %ymm10, 448(%rdi)
 vmovdqa %ymm11, 480(%rdi)
 retq ; .cfi_endproc
.size vailMlKemInvNtt, .-vailMlKemInvNtt
        .text
        .balign 4
vailMlKemBaseMulK3:
        .cfi_startproc
        endbr64
  mov $0xd010d01, %eax
  vmovd %eax, %xmm0
  vpbroadcastd %xmm0, %ymm0
  mov $0xf301f301, %eax
  vmovd %eax, %xmm1
  vpbroadcastd %xmm1, %ymm1
  vmovdqa (%rsi), %ymm2
  vmovdqa 32(%rsi), %ymm3
  vmovdqa (%rdx), %ymm4
  vmovdqa 32(%rdx), %ymm5
  vmovdqa (%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, (%rdi)
  vmovdqa %ymm9, 32(%rdi)
  vmovdqa 64(%rsi), %ymm2
  vmovdqa 96(%rsi), %ymm3
  vmovdqa 64(%rdx), %ymm4
  vmovdqa 96(%rdx), %ymm5
  vmovdqa 32(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 64(%rdi)
  vmovdqa %ymm9, 96(%rdi)
  vmovdqa 128(%rsi), %ymm2
  vmovdqa 160(%rsi), %ymm3
  vmovdqa 128(%rdx), %ymm4
  vmovdqa 160(%rdx), %ymm5
  vmovdqa 64(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 128(%rdi)
  vmovdqa %ymm9, 160(%rdi)
  vmovdqa 192(%rsi), %ymm2
  vmovdqa 224(%rsi), %ymm3
  vmovdqa 192(%rdx), %ymm4
  vmovdqa 224(%rdx), %ymm5
  vmovdqa 96(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 192(%rdi)
  vmovdqa %ymm9, 224(%rdi)
  vmovdqa 256(%rsi), %ymm2
  vmovdqa 288(%rsi), %ymm3
  vmovdqa 256(%rdx), %ymm4
  vmovdqa 288(%rdx), %ymm5
  vmovdqa 128(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 256(%rdi)
  vmovdqa %ymm9, 288(%rdi)
  vmovdqa 320(%rsi), %ymm2
  vmovdqa 352(%rsi), %ymm3
  vmovdqa 320(%rdx), %ymm4
  vmovdqa 352(%rdx), %ymm5
  vmovdqa 160(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 320(%rdi)
  vmovdqa %ymm9, 352(%rdi)
  vmovdqa 384(%rsi), %ymm2
  vmovdqa 416(%rsi), %ymm3
  vmovdqa 384(%rdx), %ymm4
  vmovdqa 416(%rdx), %ymm5
  vmovdqa 192(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 384(%rdi)
  vmovdqa %ymm9, 416(%rdi)
  vmovdqa 448(%rsi), %ymm2
  vmovdqa 480(%rsi), %ymm3
  vmovdqa 448(%rdx), %ymm4
  vmovdqa 480(%rdx), %ymm5
  vmovdqa 224(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 448(%rdi)
  vmovdqa %ymm9, 480(%rdi)
  vmovdqa 512(%rsi), %ymm2
  vmovdqa 544(%rsi), %ymm3
  vmovdqa 512(%rdx), %ymm4
  vmovdqa 544(%rdx), %ymm5
  vmovdqa 256(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa (%rdi), %ymm8
  vmovdqa 32(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, (%rdi)
  vmovdqa %ymm9, 32(%rdi)
  vmovdqa 576(%rsi), %ymm2
  vmovdqa 608(%rsi), %ymm3
  vmovdqa 576(%rdx), %ymm4
  vmovdqa 608(%rdx), %ymm5
  vmovdqa 288(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 64(%rdi), %ymm8
  vmovdqa 96(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 64(%rdi)
  vmovdqa %ymm9, 96(%rdi)
  vmovdqa 640(%rsi), %ymm2
  vmovdqa 672(%rsi), %ymm3
  vmovdqa 640(%rdx), %ymm4
  vmovdqa 672(%rdx), %ymm5
  vmovdqa 320(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 128(%rdi), %ymm8
  vmovdqa 160(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 128(%rdi)
  vmovdqa %ymm9, 160(%rdi)
  vmovdqa 704(%rsi), %ymm2
  vmovdqa 736(%rsi), %ymm3
  vmovdqa 704(%rdx), %ymm4
  vmovdqa 736(%rdx), %ymm5
  vmovdqa 352(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 192(%rdi), %ymm8
  vmovdqa 224(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 192(%rdi)
  vmovdqa %ymm9, 224(%rdi)
  vmovdqa 768(%rsi), %ymm2
  vmovdqa 800(%rsi), %ymm3
  vmovdqa 768(%rdx), %ymm4
  vmovdqa 800(%rdx), %ymm5
  vmovdqa 384(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 256(%rdi), %ymm8
  vmovdqa 288(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 256(%rdi)
  vmovdqa %ymm9, 288(%rdi)
  vmovdqa 832(%rsi), %ymm2
  vmovdqa 864(%rsi), %ymm3
  vmovdqa 832(%rdx), %ymm4
  vmovdqa 864(%rdx), %ymm5
  vmovdqa 416(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 320(%rdi), %ymm8
  vmovdqa 352(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 320(%rdi)
  vmovdqa %ymm9, 352(%rdi)
  vmovdqa 896(%rsi), %ymm2
  vmovdqa 928(%rsi), %ymm3
  vmovdqa 896(%rdx), %ymm4
  vmovdqa 928(%rdx), %ymm5
  vmovdqa 448(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 384(%rdi), %ymm8
  vmovdqa 416(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 384(%rdi)
  vmovdqa %ymm9, 416(%rdi)
  vmovdqa 960(%rsi), %ymm2
  vmovdqa 992(%rsi), %ymm3
  vmovdqa 960(%rdx), %ymm4
  vmovdqa 992(%rdx), %ymm5
  vmovdqa 480(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 448(%rdi), %ymm8
  vmovdqa 480(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 448(%rdi)
  vmovdqa %ymm9, 480(%rdi)
  vmovdqa 1024(%rsi), %ymm2
  vmovdqa 1056(%rsi), %ymm3
  vmovdqa 1024(%rdx), %ymm4
  vmovdqa 1056(%rdx), %ymm5
  vmovdqa 512(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa (%rdi), %ymm8
  vmovdqa 32(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, (%rdi)
  vmovdqa %ymm9, 32(%rdi)
  vmovdqa 1088(%rsi), %ymm2
  vmovdqa 1120(%rsi), %ymm3
  vmovdqa 1088(%rdx), %ymm4
  vmovdqa 1120(%rdx), %ymm5
  vmovdqa 544(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 64(%rdi), %ymm8
  vmovdqa 96(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 64(%rdi)
  vmovdqa %ymm9, 96(%rdi)
  vmovdqa 1152(%rsi), %ymm2
  vmovdqa 1184(%rsi), %ymm3
  vmovdqa 1152(%rdx), %ymm4
  vmovdqa 1184(%rdx), %ymm5
  vmovdqa 576(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 128(%rdi), %ymm8
  vmovdqa 160(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 128(%rdi)
  vmovdqa %ymm9, 160(%rdi)
  vmovdqa 1216(%rsi), %ymm2
  vmovdqa 1248(%rsi), %ymm3
  vmovdqa 1216(%rdx), %ymm4
  vmovdqa 1248(%rdx), %ymm5
  vmovdqa 608(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 192(%rdi), %ymm8
  vmovdqa 224(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 192(%rdi)
  vmovdqa %ymm9, 224(%rdi)
  vmovdqa 1280(%rsi), %ymm2
  vmovdqa 1312(%rsi), %ymm3
  vmovdqa 1280(%rdx), %ymm4
  vmovdqa 1312(%rdx), %ymm5
  vmovdqa 640(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 256(%rdi), %ymm8
  vmovdqa 288(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 256(%rdi)
  vmovdqa %ymm9, 288(%rdi)
  vmovdqa 1344(%rsi), %ymm2
  vmovdqa 1376(%rsi), %ymm3
  vmovdqa 1344(%rdx), %ymm4
  vmovdqa 1376(%rdx), %ymm5
  vmovdqa 672(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 320(%rdi), %ymm8
  vmovdqa 352(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 320(%rdi)
  vmovdqa %ymm9, 352(%rdi)
  vmovdqa 1408(%rsi), %ymm2
  vmovdqa 1440(%rsi), %ymm3
  vmovdqa 1408(%rdx), %ymm4
  vmovdqa 1440(%rdx), %ymm5
  vmovdqa 704(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm8, %ymm13, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 384(%rdi), %ymm8
  vmovdqa 416(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 384(%rdi)
  vmovdqa %ymm9, 416(%rdi)
  vmovdqa 1472(%rsi), %ymm2
  vmovdqa 1504(%rsi), %ymm3
  vmovdqa 1472(%rdx), %ymm4
  vmovdqa 1504(%rdx), %ymm5
  vmovdqa 736(%rcx), %ymm6
  vpmullw %ymm2, %ymm1, %ymm13
  vpmullw %ymm3, %ymm1, %ymm14
  vpmullw %ymm13, %ymm4, %ymm7
  vpmullw %ymm13, %ymm5, %ymm9
  vpmullw %ymm14, %ymm6, %ymm8
  vpmullw %ymm14, %ymm4, %ymm10
  vpmulhw %ymm7, %ymm0, %ymm7
  vpmulhw %ymm9, %ymm0, %ymm9
  vpmulhw %ymm8, %ymm0, %ymm8
  vpmulhw %ymm10, %ymm0, %ymm10
  vpmulhw %ymm2, %ymm4, %ymm11
  vpmulhw %ymm2, %ymm5, %ymm12
  vpmulhw %ymm3, %ymm6, %ymm13
  vpmulhw %ymm3, %ymm4, %ymm14
  vpsubw %ymm7, %ymm11, %ymm7
  vpsubw %ymm9, %ymm12, %ymm9
  vpsubw %ymm13, %ymm8, %ymm8
  vpsubw %ymm10, %ymm14, %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa 448(%rdi), %ymm8
  vmovdqa 480(%rdi), %ymm10
  vpaddw %ymm7, %ymm8, %ymm7
  vpaddw %ymm9, %ymm10, %ymm9
  vmovdqa %ymm7, 448(%rdi)
  vmovdqa %ymm9, 480(%rdi)
 retq ; .cfi_endproc
.size vailMlKemBaseMulK3, .-vailMlKemBaseMulK3
        .text
        .balign 4
vailMlKemMulCache:
        .cfi_startproc
        endbr64
 mov $0xd010d01, %eax
 vmovd %eax, %xmm0
 vpbroadcastd %xmm0, %ymm0
 vmovdqa 32(%rsi), %ymm2
 vmovdqa 96(%rsi), %ymm3
 vmovdqa 992(%rdx), %ymm4
 vmovdqa 1120(%rdx), %ymm1
 vpmullw %ymm2, %ymm1, %ymm5
 vpmullw %ymm3, %ymm1, %ymm6
 vpmulhw %ymm2, %ymm4, %ymm7
 vpmulhw %ymm3, %ymm4, %ymm8
 vpmulhw %ymm5, %ymm0, %ymm9
 vpmulhw %ymm6, %ymm0, %ymm10
 vpsubw %ymm9, %ymm7, %ymm7
 vpsubw %ymm10, %ymm8, %ymm8
 vmovdqa %ymm7, (%rdi)
 vmovdqa %ymm8, 32(%rdi)
 vmovdqa 160(%rsi), %ymm2
 vmovdqa 224(%rsi), %ymm3
 vmovdqa 1024(%rdx), %ymm4
 vmovdqa 1152(%rdx), %ymm1
 vpmullw %ymm2, %ymm1, %ymm5
 vpmullw %ymm3, %ymm1, %ymm6
 vpmulhw %ymm2, %ymm4, %ymm7
 vpmulhw %ymm3, %ymm4, %ymm8
 vpmulhw %ymm5, %ymm0, %ymm9
 vpmulhw %ymm6, %ymm0, %ymm10
 vpsubw %ymm9, %ymm7, %ymm7
 vpsubw %ymm10, %ymm8, %ymm8
 vmovdqa %ymm7, 64(%rdi)
 vmovdqa %ymm8, 96(%rdi)
 vmovdqa 288(%rsi), %ymm2
 vmovdqa 352(%rsi), %ymm3
 vmovdqa 1056(%rdx), %ymm4
 vmovdqa 1184(%rdx), %ymm1
 vpmullw %ymm2, %ymm1, %ymm5
 vpmullw %ymm3, %ymm1, %ymm6
 vpmulhw %ymm2, %ymm4, %ymm7
 vpmulhw %ymm3, %ymm4, %ymm8
 vpmulhw %ymm5, %ymm0, %ymm9
 vpmulhw %ymm6, %ymm0, %ymm10
 vpsubw %ymm9, %ymm7, %ymm7
 vpsubw %ymm10, %ymm8, %ymm8
 vmovdqa %ymm7, 128(%rdi)
 vmovdqa %ymm8, 160(%rdi)
 vmovdqa 416(%rsi), %ymm2
 vmovdqa 480(%rsi), %ymm3
 vmovdqa 1088(%rdx), %ymm4
 vmovdqa 1216(%rdx), %ymm1
 vpmullw %ymm2, %ymm1, %ymm5
 vpmullw %ymm3, %ymm1, %ymm6
 vpmulhw %ymm2, %ymm4, %ymm7
 vpmulhw %ymm3, %ymm4, %ymm8
 vpmulhw %ymm5, %ymm0, %ymm9
 vpmulhw %ymm6, %ymm0, %ymm10
 vpsubw %ymm9, %ymm7, %ymm7
 vpsubw %ymm10, %ymm8, %ymm8
 vmovdqa %ymm7, 192(%rdi)
 vmovdqa %ymm8, 224(%rdi)
        retq ; .cfi_endproc
.size vailMlKemMulCache, .-vailMlKemMulCache
        .text
        .balign 4
vailMlKemToBytes:
 .cfi_startproc
 endbr64
 mov $0xd010d01, %eax
 vmovd %eax, %xmm0
 vpbroadcastd %xmm0, %ymm0
 vmovdqa (%rsi), %ymm5
 vmovdqa 32(%rsi), %ymm6
 vmovdqa 64(%rsi), %ymm7
 vmovdqa 96(%rsi), %ymm8
 vmovdqa 128(%rsi), %ymm9
 vmovdqa 160(%rsi), %ymm10
 vmovdqa 192(%rsi), %ymm11
 vmovdqa 224(%rsi), %ymm12
 vpsllw $0xc, %ymm6, %ymm4
 vpor %ymm4, %ymm5, %ymm4
 vpsrlw $0x4, %ymm6, %ymm5
 vpsllw $0x8, %ymm7, %ymm6
 vpor %ymm5, %ymm6, %ymm5
 vpsrlw $0x8, %ymm7, %ymm6
 vpsllw $0x4, %ymm8, %ymm7
 vpor %ymm6, %ymm7, %ymm6
 vpsllw $0xc, %ymm10, %ymm7
 vpor %ymm7, %ymm9, %ymm7
 vpsrlw $0x4, %ymm10, %ymm8
 vpsllw $0x8, %ymm11, %ymm9
 vpor %ymm8, %ymm9, %ymm8
 vpsrlw $0x8, %ymm11, %ymm9
 vpsllw $0x4, %ymm12, %ymm10
 vpor %ymm9, %ymm10, %ymm9
 vpslld $0x10, %ymm5, %ymm3
 vpblendw $0xaa, %ymm3, %ymm4, %ymm3
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm5, %ymm4, %ymm5
 vpslld $0x10, %ymm7, %ymm4
 vpblendw $0xaa, %ymm4, %ymm6, %ymm4
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm7, %ymm6, %ymm7
 vpslld $0x10, %ymm9, %ymm6
 vpblendw $0xaa, %ymm6, %ymm8, %ymm6
 vpsrld $0x10, %ymm8, %ymm8
 vpblendw $0xaa, %ymm9, %ymm8, %ymm9
 vmovsldup %ymm4, %ymm8
 vpblendd $0xaa, %ymm8, %ymm3, %ymm8
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm4, %ymm3, %ymm4
 vmovsldup %ymm5, %ymm3
 vpblendd $0xaa, %ymm3, %ymm6, %ymm3
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm5, %ymm6, %ymm5
 vmovsldup %ymm9, %ymm6
 vpblendd $0xaa, %ymm6, %ymm7, %ymm6
 vpsrlq $0x20, %ymm7, %ymm7
 vpblendd $0xaa, %ymm9, %ymm7, %ymm9
 vpunpcklqdq %ymm3, %ymm8, %ymm7
 vpunpckhqdq %ymm3, %ymm8, %ymm3
 vpunpcklqdq %ymm4, %ymm6, %ymm8
 vpunpckhqdq %ymm4, %ymm6, %ymm4
 vpunpcklqdq %ymm9, %ymm5, %ymm6
 vpunpckhqdq %ymm9, %ymm5, %ymm9
 vperm2i128 $0x20, %ymm8, %ymm7, %ymm5
 vperm2i128 $0x31, %ymm8, %ymm7, %ymm8
 vperm2i128 $0x20, %ymm3, %ymm6, %ymm7
 vperm2i128 $0x31, %ymm3, %ymm6, %ymm3
 vperm2i128 $0x20, %ymm9, %ymm4, %ymm6
 vperm2i128 $0x31, %ymm9, %ymm4, %ymm9
 vmovdqu %ymm5, (%rdi)
 vmovdqu %ymm7, 32(%rdi)
 vmovdqu %ymm6, 64(%rdi)
 vmovdqu %ymm8, 96(%rdi)
 vmovdqu %ymm3, 128(%rdi)
 vmovdqu %ymm9, 160(%rdi)
 vmovdqa 256(%rsi), %ymm5
 vmovdqa 288(%rsi), %ymm6
 vmovdqa 320(%rsi), %ymm7
 vmovdqa 352(%rsi), %ymm8
 vmovdqa 384(%rsi), %ymm9
 vmovdqa 416(%rsi), %ymm10
 vmovdqa 448(%rsi), %ymm11
 vmovdqa 480(%rsi), %ymm12
 vpsllw $0xc, %ymm6, %ymm4
 vpor %ymm4, %ymm5, %ymm4
 vpsrlw $0x4, %ymm6, %ymm5
 vpsllw $0x8, %ymm7, %ymm6
 vpor %ymm5, %ymm6, %ymm5
 vpsrlw $0x8, %ymm7, %ymm6
 vpsllw $0x4, %ymm8, %ymm7
 vpor %ymm6, %ymm7, %ymm6
 vpsllw $0xc, %ymm10, %ymm7
 vpor %ymm7, %ymm9, %ymm7
 vpsrlw $0x4, %ymm10, %ymm8
 vpsllw $0x8, %ymm11, %ymm9
 vpor %ymm8, %ymm9, %ymm8
 vpsrlw $0x8, %ymm11, %ymm9
 vpsllw $0x4, %ymm12, %ymm10
 vpor %ymm9, %ymm10, %ymm9
 vpslld $0x10, %ymm5, %ymm3
 vpblendw $0xaa, %ymm3, %ymm4, %ymm3
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm5, %ymm4, %ymm5
 vpslld $0x10, %ymm7, %ymm4
 vpblendw $0xaa, %ymm4, %ymm6, %ymm4
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm7, %ymm6, %ymm7
 vpslld $0x10, %ymm9, %ymm6
 vpblendw $0xaa, %ymm6, %ymm8, %ymm6
 vpsrld $0x10, %ymm8, %ymm8
 vpblendw $0xaa, %ymm9, %ymm8, %ymm9
 vmovsldup %ymm4, %ymm8
 vpblendd $0xaa, %ymm8, %ymm3, %ymm8
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm4, %ymm3, %ymm4
 vmovsldup %ymm5, %ymm3
 vpblendd $0xaa, %ymm3, %ymm6, %ymm3
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm5, %ymm6, %ymm5
 vmovsldup %ymm9, %ymm6
 vpblendd $0xaa, %ymm6, %ymm7, %ymm6
 vpsrlq $0x20, %ymm7, %ymm7
 vpblendd $0xaa, %ymm9, %ymm7, %ymm9
 vpunpcklqdq %ymm3, %ymm8, %ymm7
 vpunpckhqdq %ymm3, %ymm8, %ymm3
 vpunpcklqdq %ymm4, %ymm6, %ymm8
 vpunpckhqdq %ymm4, %ymm6, %ymm4
 vpunpcklqdq %ymm9, %ymm5, %ymm6
 vpunpckhqdq %ymm9, %ymm5, %ymm9
 vperm2i128 $0x20, %ymm8, %ymm7, %ymm5
 vperm2i128 $0x31, %ymm8, %ymm7, %ymm8
 vperm2i128 $0x20, %ymm3, %ymm6, %ymm7
 vperm2i128 $0x31, %ymm3, %ymm6, %ymm3
 vperm2i128 $0x20, %ymm9, %ymm4, %ymm6
 vperm2i128 $0x31, %ymm9, %ymm4, %ymm9
 vmovdqu %ymm5, 192(%rdi)
 vmovdqu %ymm7, 224(%rdi)
 vmovdqu %ymm6, 256(%rdi)
 vmovdqu %ymm8, 288(%rdi)
 vmovdqu %ymm3, 320(%rdi)
 vmovdqu %ymm9, 352(%rdi)
 retq ; .cfi_endproc
.size vailMlKemToBytes, .-vailMlKemToBytes
        .text
        .balign 4
vailMlKemFromBytes:
 .cfi_startproc
 endbr64
 mov $0xfff0fff, %eax
 vmovd %eax, %xmm0
 vpbroadcastd %xmm0, %ymm0
 vmovdqu (%rsi), %ymm4
 vmovdqu 32(%rsi), %ymm5
 vmovdqu 64(%rsi), %ymm6
 vmovdqu 96(%rsi), %ymm7
 vmovdqu 128(%rsi), %ymm8
 vmovdqu 160(%rsi), %ymm9
 vperm2i128 $0x20, %ymm7, %ymm4, %ymm3
 vperm2i128 $0x31, %ymm7, %ymm4, %ymm7
 vperm2i128 $0x20, %ymm8, %ymm5, %ymm4
 vperm2i128 $0x31, %ymm8, %ymm5, %ymm8
 vperm2i128 $0x20, %ymm9, %ymm6, %ymm5
 vperm2i128 $0x31, %ymm9, %ymm6, %ymm9
 vpunpcklqdq %ymm8, %ymm3, %ymm6
 vpunpckhqdq %ymm8, %ymm3, %ymm8
 vpunpcklqdq %ymm5, %ymm7, %ymm3
 vpunpckhqdq %ymm5, %ymm7, %ymm5
 vpunpcklqdq %ymm9, %ymm4, %ymm7
 vpunpckhqdq %ymm9, %ymm4, %ymm9
 vmovsldup %ymm5, %ymm4
 vpblendd $0xaa, %ymm4, %ymm6, %ymm4
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm5, %ymm6, %ymm5
 vmovsldup %ymm7, %ymm6
 vpblendd $0xaa, %ymm6, %ymm8, %ymm6
 vpsrlq $0x20, %ymm8, %ymm8
 vpblendd $0xaa, %ymm7, %ymm8, %ymm7
 vmovsldup %ymm9, %ymm8
 vpblendd $0xaa, %ymm8, %ymm3, %ymm8
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm9, %ymm3, %ymm9
 vpslld $0x10, %ymm7, %ymm10
 vpblendw $0xaa, %ymm10, %ymm4, %ymm10
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm7, %ymm4, %ymm7
 vpslld $0x10, %ymm8, %ymm4
 vpblendw $0xaa, %ymm4, %ymm5, %ymm4
 vpsrld $0x10, %ymm5, %ymm5
 vpblendw $0xaa, %ymm8, %ymm5, %ymm8
 vpslld $0x10, %ymm9, %ymm5
 vpblendw $0xaa, %ymm5, %ymm6, %ymm5
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm9, %ymm6, %ymm9
 vpsrlw $0xc, %ymm10, %ymm11
 vpsllw $0x4, %ymm7, %ymm12
 vpor %ymm11, %ymm12, %ymm11
 vpand %ymm0, %ymm10, %ymm10
 vpand %ymm0, %ymm11, %ymm11
 vpsrlw $0x8, %ymm7, %ymm12
 vpsllw $0x8, %ymm4, %ymm13
 vpor %ymm12, %ymm13, %ymm12
 vpand %ymm0, %ymm12, %ymm12
 vpsrlw $0x4, %ymm4, %ymm13
 vpand %ymm0, %ymm13, %ymm13
 vpsrlw $0xc, %ymm8, %ymm14
 vpsllw $0x4, %ymm5, %ymm15
 vpor %ymm14, %ymm15, %ymm14
 vpand %ymm0, %ymm8, %ymm8
 vpand %ymm0, %ymm14, %ymm14
 vpsrlw $0x8, %ymm5, %ymm15
 vpsllw $0x8, %ymm9, %ymm1
 vpor %ymm15, %ymm1, %ymm15
 vpand %ymm0, %ymm15, %ymm15
 vpsrlw $0x4, %ymm9, %ymm1
 vpand %ymm0, %ymm1, %ymm1
 vmovdqa %ymm10, (%rdi)
 vmovdqa %ymm11, 32(%rdi)
 vmovdqa %ymm12, 64(%rdi)
 vmovdqa %ymm13, 96(%rdi)
 vmovdqa %ymm8, 128(%rdi)
 vmovdqa %ymm14, 160(%rdi)
 vmovdqa %ymm15, 192(%rdi)
 vmovdqa %ymm1, 224(%rdi)
 vmovdqu 192(%rsi), %ymm4
 vmovdqu 224(%rsi), %ymm5
 vmovdqu 256(%rsi), %ymm6
 vmovdqu 288(%rsi), %ymm7
 vmovdqu 320(%rsi), %ymm8
 vmovdqu 352(%rsi), %ymm9
 vperm2i128 $0x20, %ymm7, %ymm4, %ymm3
 vperm2i128 $0x31, %ymm7, %ymm4, %ymm7
 vperm2i128 $0x20, %ymm8, %ymm5, %ymm4
 vperm2i128 $0x31, %ymm8, %ymm5, %ymm8
 vperm2i128 $0x20, %ymm9, %ymm6, %ymm5
 vperm2i128 $0x31, %ymm9, %ymm6, %ymm9
 vpunpcklqdq %ymm8, %ymm3, %ymm6
 vpunpckhqdq %ymm8, %ymm3, %ymm8
 vpunpcklqdq %ymm5, %ymm7, %ymm3
 vpunpckhqdq %ymm5, %ymm7, %ymm5
 vpunpcklqdq %ymm9, %ymm4, %ymm7
 vpunpckhqdq %ymm9, %ymm4, %ymm9
 vmovsldup %ymm5, %ymm4
 vpblendd $0xaa, %ymm4, %ymm6, %ymm4
 vpsrlq $0x20, %ymm6, %ymm6
 vpblendd $0xaa, %ymm5, %ymm6, %ymm5
 vmovsldup %ymm7, %ymm6
 vpblendd $0xaa, %ymm6, %ymm8, %ymm6
 vpsrlq $0x20, %ymm8, %ymm8
 vpblendd $0xaa, %ymm7, %ymm8, %ymm7
 vmovsldup %ymm9, %ymm8
 vpblendd $0xaa, %ymm8, %ymm3, %ymm8
 vpsrlq $0x20, %ymm3, %ymm3
 vpblendd $0xaa, %ymm9, %ymm3, %ymm9
 vpslld $0x10, %ymm7, %ymm10
 vpblendw $0xaa, %ymm10, %ymm4, %ymm10
 vpsrld $0x10, %ymm4, %ymm4
 vpblendw $0xaa, %ymm7, %ymm4, %ymm7
 vpslld $0x10, %ymm8, %ymm4
 vpblendw $0xaa, %ymm4, %ymm5, %ymm4
 vpsrld $0x10, %ymm5, %ymm5
 vpblendw $0xaa, %ymm8, %ymm5, %ymm8
 vpslld $0x10, %ymm9, %ymm5
 vpblendw $0xaa, %ymm5, %ymm6, %ymm5
 vpsrld $0x10, %ymm6, %ymm6
 vpblendw $0xaa, %ymm9, %ymm6, %ymm9
 vpsrlw $0xc, %ymm10, %ymm11
 vpsllw $0x4, %ymm7, %ymm12
 vpor %ymm11, %ymm12, %ymm11
 vpand %ymm0, %ymm10, %ymm10
 vpand %ymm0, %ymm11, %ymm11
 vpsrlw $0x8, %ymm7, %ymm12
 vpsllw $0x8, %ymm4, %ymm13
 vpor %ymm12, %ymm13, %ymm12
 vpand %ymm0, %ymm12, %ymm12
 vpsrlw $0x4, %ymm4, %ymm13
 vpand %ymm0, %ymm13, %ymm13
 vpsrlw $0xc, %ymm8, %ymm14
 vpsllw $0x4, %ymm5, %ymm15
 vpor %ymm14, %ymm15, %ymm14
 vpand %ymm0, %ymm8, %ymm8
 vpand %ymm0, %ymm14, %ymm14
 vpsrlw $0x8, %ymm5, %ymm15
 vpsllw $0x8, %ymm9, %ymm1
 vpor %ymm15, %ymm1, %ymm15
 vpand %ymm0, %ymm15, %ymm15
 vpsrlw $0x4, %ymm9, %ymm1
 vpand %ymm0, %ymm1, %ymm1
 vmovdqa %ymm10, 256(%rdi)
 vmovdqa %ymm11, 288(%rdi)
 vmovdqa %ymm12, 320(%rdi)
 vmovdqa %ymm13, 352(%rdi)
 vmovdqa %ymm8, 384(%rdi)
 vmovdqa %ymm14, 416(%rdi)
 vmovdqa %ymm15, 448(%rdi)
 vmovdqa %ymm1, 480(%rdi)
 retq ; .cfi_endproc
.size vailMlKemFromBytes, .-vailMlKemFromBytes
