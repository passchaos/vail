# Copyright (c) 2024 The mlkem-native project authors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
# Vendored s2n-bignum/mlkem-native AVX2 compression kernels, preprocessed for
# the ELF x86_64 SysV ABI. The generated instruction schedules stay separate
# from the Zig ABI wrapper and its constant tables.
        .text
        .balign 4
vailMlKemCompressD4:

        .cfi_startproc
        movl $0x4ebf4ebf, %eax       # imm = 0x4EBF4EBF
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x2000200, %eax        # imm = 0x2000200
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $0xf000f, %eax          # imm = 0xF000F
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $0x10011001, %eax       # imm = 0x10011001
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        vmovdqa (%rdx), %ymm4
        vmovdqa (%rsi), %ymm5
        vmovdqa 0x20(%rsi), %ymm6
        vmovdqa 0x40(%rsi), %ymm7
        vmovdqa 0x60(%rsi), %ymm8
        vpmulhw %ymm0, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm6, %ymm6
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm5, %ymm5
        vpmulhrsw %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm5, %ymm5
        vpand %ymm2, %ymm6, %ymm6
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm6, %ymm5, %ymm5
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm5, %ymm5
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpackuswb %ymm7, %ymm5, %ymm5
        vpermd %ymm5, %ymm4, %ymm5
        vmovdqu %ymm5, (%rdi)
        vmovdqa 0x80(%rsi), %ymm5
        vmovdqa 0xa0(%rsi), %ymm6
        vmovdqa 0xc0(%rsi), %ymm7
        vmovdqa 0xe0(%rsi), %ymm8
        vpmulhw %ymm0, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm6, %ymm6
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm5, %ymm5
        vpmulhrsw %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm5, %ymm5
        vpand %ymm2, %ymm6, %ymm6
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm6, %ymm5, %ymm5
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm5, %ymm5
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpackuswb %ymm7, %ymm5, %ymm5
        vpermd %ymm5, %ymm4, %ymm5
        vmovdqu %ymm5, 0x20(%rdi)
        vmovdqa 0x100(%rsi), %ymm5
        vmovdqa 0x120(%rsi), %ymm6
        vmovdqa 0x140(%rsi), %ymm7
        vmovdqa 0x160(%rsi), %ymm8
        vpmulhw %ymm0, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm6, %ymm6
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm5, %ymm5
        vpmulhrsw %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm5, %ymm5
        vpand %ymm2, %ymm6, %ymm6
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm6, %ymm5, %ymm5
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm5, %ymm5
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpackuswb %ymm7, %ymm5, %ymm5
        vpermd %ymm5, %ymm4, %ymm5
        vmovdqu %ymm5, 0x40(%rdi)
        vmovdqa 0x180(%rsi), %ymm5
        vmovdqa 0x1a0(%rsi), %ymm6
        vmovdqa 0x1c0(%rsi), %ymm7
        vmovdqa 0x1e0(%rsi), %ymm8
        vpmulhw %ymm0, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm6, %ymm6
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm5, %ymm5
        vpmulhrsw %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm5, %ymm5
        vpand %ymm2, %ymm6, %ymm6
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm6, %ymm5, %ymm5
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm5, %ymm5
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpackuswb %ymm7, %ymm5, %ymm5
        vpermd %ymm5, %ymm4, %ymm5
        vmovdqu %ymm5, 0x60(%rdi)
        retq
        .cfi_endproc

        .balign 4
vailMlKemDecompressD4:

        .cfi_startproc
        movl $0xd010d01, %eax        # imm = 0xD010D01
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0xf0000f, %eax         # imm = 0xF0000F
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $0x800800, %eax         # imm = 0x800800
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        vmovdqa (%rdx), %ymm3
        vmovq (%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, (%rdi)
        vmovq 0x8(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x20(%rdi)
        vmovq 0x10(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x40(%rdi)
        vmovq 0x18(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x60(%rdi)
        vmovq 0x20(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x80(%rdi)
        vmovq 0x28(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xa0(%rdi)
        vmovq 0x30(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xc0(%rdi)
        vmovq 0x38(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xe0(%rdi)
        vmovq 0x40(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x100(%rdi)
        vmovq 0x48(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x120(%rdi)
        vmovq 0x50(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x140(%rdi)
        vmovq 0x58(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x160(%rdi)
        vmovq 0x60(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x180(%rdi)
        vmovq 0x68(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1a0(%rdi)
        vmovq 0x70(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1c0(%rdi)
        vmovq 0x78(%rsi), %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm3, %ymm4, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpmullw %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1e0(%rdi)
        retq
        .cfi_endproc

        .balign 4
vailMlKemCompressD5:

        .cfi_startproc
        movl $0x4ebf4ebf, %eax       # imm = 0x4EBF4EBF
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x4000400, %eax        # imm = 0x4000400
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        movl $0x1f001f, %eax         # imm = 0x1F001F
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $0x20012001, %eax       # imm = 0x20012001
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $0x4000001, %eax        # imm = 0x4000001
        vmovd %eax, %xmm4
        vpbroadcastd %xmm4, %ymm4
        movl $0xc, %eax
        vmovq %rax, %xmm5
        vpbroadcastq %xmm5, %ymm5
        vmovdqa (%rdx), %ymm6
        vmovdqa (%rsi), %ymm7
        vmovdqa 0x20(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, (%rdi)
        vmovd %xmm8, 0x10(%rdi)
        vmovdqa 0x40(%rsi), %ymm7
        vmovdqa 0x60(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, 0x14(%rdi)
        vmovd %xmm8, 0x24(%rdi)
        vmovdqa 0x80(%rsi), %ymm7
        vmovdqa 0xa0(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, 0x28(%rdi)
        vmovd %xmm8, 0x38(%rdi)
        vmovdqa 0xc0(%rsi), %ymm7
        vmovdqa 0xe0(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, 0x3c(%rdi)
        vmovd %xmm8, 0x4c(%rdi)
        vmovdqa 0x100(%rsi), %ymm7
        vmovdqa 0x120(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, 0x50(%rdi)
        vmovd %xmm8, 0x60(%rdi)
        vmovdqa 0x140(%rsi), %ymm7
        vmovdqa 0x160(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, 0x64(%rdi)
        vmovd %xmm8, 0x74(%rdi)
        vmovdqa 0x180(%rsi), %ymm7
        vmovdqa 0x1a0(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, 0x78(%rdi)
        vmovd %xmm8, 0x88(%rdi)
        vmovdqa 0x1c0(%rsi), %ymm7
        vmovdqa 0x1e0(%rsi), %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhrsw %ymm1, %ymm7, %ymm7
        vpmulhrsw %ymm1, %ymm8, %ymm8
        vpand %ymm2, %ymm7, %ymm7
        vpand %ymm2, %ymm8, %ymm8
        vpackuswb %ymm8, %ymm7, %ymm7
        vpmaddubsw %ymm3, %ymm7, %ymm7
        vpmaddwd %ymm4, %ymm7, %ymm7
        vpsllvd %ymm5, %ymm7, %ymm7
        vpsrlvq %ymm5, %ymm7, %ymm7
        vpshufb %ymm6, %ymm7, %ymm7
        vextracti128 $0x1, %ymm7, %xmm8
        vpblendvb %xmm6, %xmm8, %xmm7, %xmm7
        vmovdqu %xmm7, 0x8c(%rdi)
        vmovd %xmm8, 0x9c(%rdi)
        retq
        .cfi_endproc

        .balign 4
vailMlKemDecompressD5:

        .cfi_startproc
        movl $0xd010d01, %eax        # imm = 0xD010D01
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        vmovdqa (%rdx), %ymm1
        vmovdqa 0x20(%rdx), %ymm2
        vmovdqa 0x40(%rdx), %ymm3
        vmovq (%rsi), %xmm4
        vpinsrw $0x4, 0x8(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, (%rdi)
        vmovq 0xa(%rsi), %xmm4
        vpinsrw $0x4, 0x12(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x20(%rdi)
        vmovq 0x14(%rsi), %xmm4
        vpinsrw $0x4, 0x1c(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x40(%rdi)
        vmovq 0x1e(%rsi), %xmm4
        vpinsrw $0x4, 0x26(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x60(%rdi)
        vmovq 0x28(%rsi), %xmm4
        vpinsrw $0x4, 0x30(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x80(%rdi)
        vmovq 0x32(%rsi), %xmm4
        vpinsrw $0x4, 0x3a(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xa0(%rdi)
        vmovq 0x3c(%rsi), %xmm4
        vpinsrw $0x4, 0x44(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xc0(%rdi)
        vmovq 0x46(%rsi), %xmm4
        vpinsrw $0x4, 0x4e(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xe0(%rdi)
        vmovq 0x50(%rsi), %xmm4
        vpinsrw $0x4, 0x58(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x100(%rdi)
        vmovq 0x5a(%rsi), %xmm4
        vpinsrw $0x4, 0x62(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x120(%rdi)
        vmovq 0x64(%rsi), %xmm4
        vpinsrw $0x4, 0x6c(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x140(%rdi)
        vmovq 0x6e(%rsi), %xmm4
        vpinsrw $0x4, 0x76(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x160(%rdi)
        vmovq 0x78(%rsi), %xmm4
        vpinsrw $0x4, 0x80(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x180(%rdi)
        vmovq 0x82(%rsi), %xmm4
        vpinsrw $0x4, 0x8a(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1a0(%rdi)
        vmovq 0x8c(%rsi), %xmm4
        vpinsrw $0x4, 0x94(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1c0(%rdi)
        vmovq 0x96(%rsi), %xmm4
        vpinsrw $0x4, 0x9e(%rsi), %xmm4, %xmm4
        vinserti128 $0x1, %xmm4, %ymm4, %ymm4
        vpshufb %ymm1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmullw %ymm3, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1e0(%rdi)
        retq
        .cfi_endproc

        .balign 4
vailMlKemCompressD10:

        .cfi_startproc
        movl $0x4ebf4ebf, %eax       # imm = 0x4EBF4EBF
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        vpsllw $0x3, %ymm0, %ymm1
        movl $0xf000f, %eax          # imm = 0xF000F
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $0x10001000, %eax       # imm = 0x10001000
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $0x3ff03ff, %eax        # imm = 0x3FF03FF
        vmovd %eax, %xmm4
        vpbroadcastd %xmm4, %ymm4
        movabsq $0x400000104000001, %rax # imm = 0x400000104000001
        vmovq %rax, %xmm5
        vpbroadcastq %xmm5, %ymm5
        movl $0xc, %eax
        vmovq %rax, %xmm6
        vpbroadcastq %xmm6, %ymm6
        vmovdqa (%rdx), %ymm7
        vmovdqa (%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, (%rdi)
        vmovd %xmm9, 0x10(%rdi)
        vmovdqa 0x20(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x14(%rdi)
        vmovd %xmm9, 0x24(%rdi)
        vmovdqa 0x40(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x28(%rdi)
        vmovd %xmm9, 0x38(%rdi)
        vmovdqa 0x60(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x3c(%rdi)
        vmovd %xmm9, 0x4c(%rdi)
        vmovdqa 0x80(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x50(%rdi)
        vmovd %xmm9, 0x60(%rdi)
        vmovdqa 0xa0(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x64(%rdi)
        vmovd %xmm9, 0x74(%rdi)
        vmovdqa 0xc0(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x78(%rdi)
        vmovd %xmm9, 0x88(%rdi)
        vmovdqa 0xe0(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x8c(%rdi)
        vmovd %xmm9, 0x9c(%rdi)
        vmovdqa 0x100(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0xa0(%rdi)
        vmovd %xmm9, 0xb0(%rdi)
        vmovdqa 0x120(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0xb4(%rdi)
        vmovd %xmm9, 0xc4(%rdi)
        vmovdqa 0x140(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0xc8(%rdi)
        vmovd %xmm9, 0xd8(%rdi)
        vmovdqa 0x160(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0xdc(%rdi)
        vmovd %xmm9, 0xec(%rdi)
        vmovdqa 0x180(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0xf0(%rdi)
        vmovd %xmm9, 0x100(%rdi)
        vmovdqa 0x1a0(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x104(%rdi)
        vmovd %xmm9, 0x114(%rdi)
        vmovdqa 0x1c0(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x118(%rdi)
        vmovd %xmm9, 0x128(%rdi)
        vmovdqa 0x1e0(%rsi), %ymm8
        vpmullw %ymm1, %ymm8, %ymm9
        vpaddw %ymm2, %ymm8, %ymm10
        vpsllw $0x3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm8, %ymm8
        vpsubw %ymm10, %ymm9, %ymm10
        vpandn %ymm10, %ymm9, %ymm9
        vpsrlw $0xf, %ymm9, %ymm9
        vpsubw %ymm9, %ymm8, %ymm8
        vpmulhrsw %ymm3, %ymm8, %ymm8
        vpand %ymm4, %ymm8, %ymm8
        vpmaddwd %ymm5, %ymm8, %ymm8
        vpsllvd %ymm6, %ymm8, %ymm8
        vpsrlq $0xc, %ymm8, %ymm8
        vpshufb %ymm7, %ymm8, %ymm8
        vextracti128 $0x1, %ymm8, %xmm9
        vpblendw $0xe0, %xmm9, %xmm8, %xmm8 # xmm8 = xmm8[0,1,2,3,4],xmm9[5,6,7]
        vmovdqu %xmm8, 0x12c(%rdi)
        vmovd %xmm9, 0x13c(%rdi)
        retq
        .cfi_endproc

        .balign 4
vailMlKemDecompressD10:

        .cfi_startproc
        movl $0xd013404, %eax        # imm = 0xD013404
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x4, %eax
        vmovq %rax, %xmm1
        vpbroadcastq %xmm1, %ymm1
        movl $0x7fe01ff8, %eax       # imm = 0x7FE01FF8
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        vmovdqa (%rdx), %ymm3
        vmovdqu (%rsi), %xmm4
        vmovd 0x10(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, (%rdi)
        vmovdqu 0x14(%rsi), %xmm4
        vmovd 0x24(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x20(%rdi)
        vmovdqu 0x28(%rsi), %xmm4
        vmovd 0x38(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x40(%rdi)
        vmovdqu 0x3c(%rsi), %xmm4
        vmovd 0x4c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x60(%rdi)
        vmovdqu 0x50(%rsi), %xmm4
        vmovd 0x60(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x80(%rdi)
        vmovdqu 0x64(%rsi), %xmm4
        vmovd 0x74(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xa0(%rdi)
        vmovdqu 0x78(%rsi), %xmm4
        vmovd 0x88(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xc0(%rdi)
        vmovdqu 0x8c(%rsi), %xmm4
        vmovd 0x9c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0xe0(%rdi)
        vmovdqu 0xa0(%rsi), %xmm4
        vmovd 0xb0(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x100(%rdi)
        vmovdqu 0xb4(%rsi), %xmm4
        vmovd 0xc4(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x120(%rdi)
        vmovdqu 0xc8(%rsi), %xmm4
        vmovd 0xd8(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x140(%rdi)
        vmovdqu 0xdc(%rsi), %xmm4
        vmovd 0xec(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x160(%rdi)
        vmovdqu 0xf0(%rsi), %xmm4
        vmovd 0x100(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x180(%rdi)
        vmovdqu 0x104(%rsi), %xmm4
        vmovd 0x114(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1a0(%rdi)
        vmovdqu 0x118(%rsi), %xmm4
        vmovd 0x128(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1c0(%rdi)
        vmovdqu 0x12c(%rsi), %xmm4
        vmovd 0x13c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm4, %ymm4
        vpermq $0x94, %ymm4, %ymm4     # ymm4 = ymm4[0,1,1,2]
        vpshufb %ymm3, %ymm4, %ymm4
        vpsllvd %ymm1, %ymm4, %ymm4
        vpsrlw $0x1, %ymm4, %ymm4
        vpand %ymm2, %ymm4, %ymm4
        vpmulhrsw %ymm0, %ymm4, %ymm4
        vmovdqu %ymm4, 0x1e0(%rdi)
        retq
        .cfi_endproc

        .balign 4
vailMlKemCompressD11:

        .cfi_startproc
        movl $0x4ebf4ebf, %eax       # imm = 0x4EBF4EBF
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        vpsllw $0x3, %ymm0, %ymm1
        movl $0x240024, %eax         # imm = 0x240024
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $0x20002000, %eax       # imm = 0x20002000
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $0x7ff07ff, %eax        # imm = 0x7FF07FF
        vmovd %eax, %xmm4
        vpbroadcastd %xmm4, %ymm4
        movabsq $0x800000108000001, %rax # imm = 0x800000108000001
        vmovq %rax, %xmm5
        vpbroadcastq %xmm5, %ymm5
        movl $0xa, %eax
        vmovq %rax, %xmm6
        vpbroadcastq %xmm6, %ymm6
        vmovdqa (%rdx), %ymm7
        vmovdqa 0x20(%rdx), %ymm8
        vmovdqa (%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, (%rdi)
        vmovd %xmm10, 0x10(%rdi)
        vpextrw $0x2, %xmm10, 0x14(%rdi)
        vmovdqa 0x20(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x16(%rdi)
        vmovd %xmm10, 0x26(%rdi)
        vpextrw $0x2, %xmm10, 0x2a(%rdi)
        vmovdqa 0x40(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x2c(%rdi)
        vmovd %xmm10, 0x3c(%rdi)
        vpextrw $0x2, %xmm10, 0x40(%rdi)
        vmovdqa 0x60(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x42(%rdi)
        vmovd %xmm10, 0x52(%rdi)
        vpextrw $0x2, %xmm10, 0x56(%rdi)
        vmovdqa 0x80(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x58(%rdi)
        vmovd %xmm10, 0x68(%rdi)
        vpextrw $0x2, %xmm10, 0x6c(%rdi)
        vmovdqa 0xa0(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x6e(%rdi)
        vmovd %xmm10, 0x7e(%rdi)
        vpextrw $0x2, %xmm10, 0x82(%rdi)
        vmovdqa 0xc0(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x84(%rdi)
        vmovd %xmm10, 0x94(%rdi)
        vpextrw $0x2, %xmm10, 0x98(%rdi)
        vmovdqa 0xe0(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x9a(%rdi)
        vmovd %xmm10, 0xaa(%rdi)
        vpextrw $0x2, %xmm10, 0xae(%rdi)
        vmovdqa 0x100(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0xb0(%rdi)
        vmovd %xmm10, 0xc0(%rdi)
        vpextrw $0x2, %xmm10, 0xc4(%rdi)
        vmovdqa 0x120(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0xc6(%rdi)
        vmovd %xmm10, 0xd6(%rdi)
        vpextrw $0x2, %xmm10, 0xda(%rdi)
        vmovdqa 0x140(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0xdc(%rdi)
        vmovd %xmm10, 0xec(%rdi)
        vpextrw $0x2, %xmm10, 0xf0(%rdi)
        vmovdqa 0x160(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0xf2(%rdi)
        vmovd %xmm10, 0x102(%rdi)
        vpextrw $0x2, %xmm10, 0x106(%rdi)
        vmovdqa 0x180(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x108(%rdi)
        vmovd %xmm10, 0x118(%rdi)
        vpextrw $0x2, %xmm10, 0x11c(%rdi)
        vmovdqa 0x1a0(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x11e(%rdi)
        vmovd %xmm10, 0x12e(%rdi)
        vpextrw $0x2, %xmm10, 0x132(%rdi)
        vmovdqa 0x1c0(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x134(%rdi)
        vmovd %xmm10, 0x144(%rdi)
        vpextrw $0x2, %xmm10, 0x148(%rdi)
        vmovdqa 0x1e0(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x14a(%rdi)
        vmovd %xmm10, 0x15a(%rdi)
        vpextrw $0x2, %xmm10, 0x15e(%rdi)
        retq
        .cfi_endproc

        .balign 4
vailMlKemDecompressD11:

        .cfi_startproc
        movl $0xd010d01, %eax        # imm = 0xD010D01
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        movl $0x7ff07ff0, %eax       # imm = 0x7FF07FF0
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        vmovdqa (%rdx), %ymm2
        vmovdqa 0x20(%rdx), %ymm3
        vmovdqa 0x40(%rdx), %ymm4
        vmovdqa 0x60(%rdx), %ymm5
        vmovdqu (%rsi), %xmm6
        vmovd 0x10(%rsi), %xmm7
        vpinsrw $0x2, 0x14(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, (%rdi)
        vmovdqu 0x16(%rsi), %xmm6
        vmovd 0x26(%rsi), %xmm7
        vpinsrw $0x2, 0x2a(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x20(%rdi)
        vmovdqu 0x2c(%rsi), %xmm6
        vmovd 0x3c(%rsi), %xmm7
        vpinsrw $0x2, 0x40(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x40(%rdi)
        vmovdqu 0x42(%rsi), %xmm6
        vmovd 0x52(%rsi), %xmm7
        vpinsrw $0x2, 0x56(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x60(%rdi)
        vmovdqu 0x58(%rsi), %xmm6
        vmovd 0x68(%rsi), %xmm7
        vpinsrw $0x2, 0x6c(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x80(%rdi)
        vmovdqu 0x6e(%rsi), %xmm6
        vmovd 0x7e(%rsi), %xmm7
        vpinsrw $0x2, 0x82(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0xa0(%rdi)
        vmovdqu 0x84(%rsi), %xmm6
        vmovd 0x94(%rsi), %xmm7
        vpinsrw $0x2, 0x98(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0xc0(%rdi)
        vmovdqu 0x9a(%rsi), %xmm6
        vmovd 0xaa(%rsi), %xmm7
        vpinsrw $0x2, 0xae(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0xe0(%rdi)
        vmovdqu 0xb0(%rsi), %xmm6
        vmovd 0xc0(%rsi), %xmm7
        vpinsrw $0x2, 0xc4(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x100(%rdi)
        vmovdqu 0xc6(%rsi), %xmm6
        vmovd 0xd6(%rsi), %xmm7
        vpinsrw $0x2, 0xda(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x120(%rdi)
        vmovdqu 0xdc(%rsi), %xmm6
        vmovd 0xec(%rsi), %xmm7
        vpinsrw $0x2, 0xf0(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x140(%rdi)
        vmovdqu 0xf2(%rsi), %xmm6
        vmovd 0x102(%rsi), %xmm7
        vpinsrw $0x2, 0x106(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x160(%rdi)
        vmovdqu 0x108(%rsi), %xmm6
        vmovd 0x118(%rsi), %xmm7
        vpinsrw $0x2, 0x11c(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x180(%rdi)
        vmovdqu 0x11e(%rsi), %xmm6
        vmovd 0x12e(%rsi), %xmm7
        vpinsrw $0x2, 0x132(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x1a0(%rdi)
        vmovdqu 0x134(%rsi), %xmm6
        vmovd 0x144(%rsi), %xmm7
        vpinsrw $0x2, 0x148(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x1c0(%rdi)
        vmovdqu 0x14a(%rsi), %xmm6
        vmovd 0x15a(%rsi), %xmm7
        vpinsrw $0x2, 0x15e(%rsi), %xmm7, %xmm7
        vinserti128 $0x1, %xmm7, %ymm6, %ymm6
        vpermq $0x94, %ymm6, %ymm6     # ymm6 = ymm6[0,1,1,2]
        vpshufb %ymm2, %ymm6, %ymm6
        vpsrlvd %ymm3, %ymm6, %ymm6
        vpsrlvq %ymm4, %ymm6, %ymm6
        vpmullw %ymm5, %ymm6, %ymm6
        vpsrlw $0x1, %ymm6, %ymm6
        vpand %ymm1, %ymm6, %ymm6
        vpmulhrsw %ymm0, %ymm6, %ymm6
        vmovdqu %ymm6, 0x1e0(%rdi)
        retq
        .cfi_endproc

