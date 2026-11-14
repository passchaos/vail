// ARM64 P-256 Montgomery field squaring (alt schedule) from s2n-bignum.
// Source snapshot: AWS-LC as bundled by aws-lc-sys 0.45.0.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0



        .globl vailP256MontgomerySquareAltArm64
        .type vailP256MontgomerySquareAltArm64, %function
        .text
        .balign 4
vailP256MontgomerySquareAltArm64:
        .cfi_startproc
        ldp x2, x3, [x1]
        mul x9, x2, x3
        umulh x10, x2, x3
        ldp x4, x5, [x1, #16]
        mul x11, x2, x5
        umulh x12, x2, x5
        mul x6, x2, x4
        umulh x7, x2, x4
        adds x10, x10, x6
        adcs x11, x11, x7
        mul x6, x3, x4
        umulh x7, x3, x4
        adc x7, x7, xzr
        adds x11, x11, x6
        mul x13, x4, x5
        umulh x14, x4, x5
        adcs x12, x12, x7
        mul x6, x3, x5
        umulh x7, x3, x5
        adc x7, x7, xzr
        adds x12, x12, x6
        adcs x13, x13, x7
        adc x14, x14, xzr
        adds x9, x9, x9
        adcs x10, x10, x10
        adcs x11, x11, x11
        adcs x12, x12, x12
        adcs x13, x13, x13
        adcs x14, x14, x14
        cset x7, cs
        umulh x6, x2, x2
        mul x8, x2, x2
        adds x9, x9, x6
        mul x6, x3, x3
        adcs x10, x10, x6
        umulh x6, x3, x3
        adcs x11, x11, x6
        mul x6, x4, x4
        adcs x12, x12, x6
        umulh x6, x4, x4
        adcs x13, x13, x6
        mul x6, x5, x5
        adcs x14, x14, x6
        umulh x6, x5, x5
        adc x7, x7, x6
        mov x5, #0xFFFFFFFF00000001
        adds x9, x9, x8, lsl #32 ; lsr x2, x8, #32 ; adcs x10, x10, x2 ; mul x2, x8, x5 ; umulh x8, x8, x5 ; adcs x11, x11, x2 ; adc x8, x8, xzr
        adds x10, x10, x9, lsl #32 ; lsr x2, x9, #32 ; adcs x11, x11, x2 ; mul x2, x9, x5 ; umulh x9, x9, x5 ; adcs x8, x8, x2 ; adc x9, x9, xzr
        adds x11, x11, x10, lsl #32 ; lsr x2, x10, #32 ; adcs x8, x8, x2 ; mul x2, x10, x5 ; umulh x10, x10, x5 ; adcs x9, x9, x2 ; adc x10, x10, xzr
        adds x8, x8, x11, lsl #32 ; lsr x2, x11, #32 ; adcs x9, x9, x2 ; mul x2, x11, x5 ; umulh x11, x11, x5 ; adcs x10, x10, x2 ; adc x11, x11, xzr
        adds x8, x8, x12
        adcs x9, x9, x13
        adcs x10, x10, x14
        adcs x11, x11, x7
        cset x2, cs
        mov x3, #0x00000000ffffffff
        subs x12, x8, #-1
        sbcs x13, x9, x3
        sbcs x14, x10, xzr
        sbcs x7, x11, x5
        sbcs xzr, x2, xzr
        csel x8, x8, x12, cc
        csel x9, x9, x13, cc
        csel x10, x10, x14, cc
        csel x11, x11, x7, cc
        stp x8, x9, [x0]
        stp x10, x11, [x0, #16]
        ret ; .cfi_endproc
.size vailP256MontgomerySquareAltArm64, .-vailP256MontgomerySquareAltArm64
