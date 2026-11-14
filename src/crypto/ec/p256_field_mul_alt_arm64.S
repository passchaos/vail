// ARM64 P-256 Montgomery field multiplication (alt schedule) from s2n-bignum.
// Source snapshot: AWS-LC as bundled by aws-lc-sys 0.45.0.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0



        .globl vailP256MontgomeryMulAltArm64
        .type vailP256MontgomeryMulAltArm64, %function
        .text
        .balign 4
vailP256MontgomeryMulAltArm64:
        .cfi_startproc
        ldp x3, x4, [x1]
        ldp x7, x8, [x2]
        mul x12, x3, x7
        umulh x13, x3, x7
        mul x11, x3, x8
        umulh x14, x3, x8
        adds x13, x13, x11
        ldp x9, x10, [x2, #16]
        mul x11, x3, x9
        umulh x15, x3, x9
        adcs x14, x14, x11
        mul x11, x3, x10
        umulh x16, x3, x10
        adcs x15, x15, x11
        adc x16, x16, xzr
        ldp x5, x6, [x1, #16]
        mul x11, x4, x7
        adds x13, x13, x11
        mul x11, x4, x8
        adcs x14, x14, x11
        mul x11, x4, x9
        adcs x15, x15, x11
        mul x11, x4, x10
        adcs x16, x16, x11
        umulh x3, x4, x10
        adc x3, x3, xzr
        umulh x11, x4, x7
        adds x14, x14, x11
        umulh x11, x4, x8
        adcs x15, x15, x11
        umulh x11, x4, x9
        adcs x16, x16, x11
        adc x3, x3, xzr
        mul x11, x5, x7
        adds x14, x14, x11
        mul x11, x5, x8
        adcs x15, x15, x11
        mul x11, x5, x9
        adcs x16, x16, x11
        mul x11, x5, x10
        adcs x3, x3, x11
        umulh x4, x5, x10
        adc x4, x4, xzr
        umulh x11, x5, x7
        adds x15, x15, x11
        umulh x11, x5, x8
        adcs x16, x16, x11
        umulh x11, x5, x9
        adcs x3, x3, x11
        adc x4, x4, xzr
        mul x11, x6, x7
        adds x15, x15, x11
        mul x11, x6, x8
        adcs x16, x16, x11
        mul x11, x6, x9
        adcs x3, x3, x11
        mul x11, x6, x10
        adcs x4, x4, x11
        umulh x5, x6, x10
        adc x5, x5, xzr
        mov x10, 0xFFFFFFFF00000001
        adds x13, x13, x12, lsl #32 ; lsr x11, x12, #32 ; adcs x14, x14, x11 ; mul x11, x12, x10 ; umulh x12, x12, x10 ; adcs x15, x15, x11 ; adc x12, x12, xzr
        umulh x11, x6, x7
        adds x16, x16, x11
        umulh x11, x6, x8
        adcs x3, x3, x11
        umulh x11, x6, x9
        adcs x4, x4, x11
        adc x5, x5, xzr
        adds x14, x14, x13, lsl #32 ; lsr x11, x13, #32 ; adcs x15, x15, x11 ; mul x11, x13, x10 ; umulh x13, x13, x10 ; adcs x12, x12, x11 ; adc x13, x13, xzr
        adds x15, x15, x14, lsl #32 ; lsr x11, x14, #32 ; adcs x12, x12, x11 ; mul x11, x14, x10 ; umulh x14, x14, x10 ; adcs x13, x13, x11 ; adc x14, x14, xzr
        adds x12, x12, x15, lsl #32 ; lsr x11, x15, #32 ; adcs x13, x13, x11 ; mul x11, x15, x10 ; umulh x15, x15, x10 ; adcs x14, x14, x11 ; adc x15, x15, xzr
        adds x12, x12, x16
        adcs x13, x13, x3
        adcs x14, x14, x4
        adcs x15, x15, x5
        cset x8, cs
        mov x11, #0x00000000ffffffff
        subs x16, x12, #-1
        sbcs x3, x13, x11
        sbcs x4, x14, xzr
        sbcs x5, x15, x10
        sbcs xzr, x8, xzr
        csel x12, x12, x16, cc
        csel x13, x13, x3, cc
        csel x14, x14, x4, cc
        csel x15, x15, x5, cc
        stp x12, x13, [x0]
        stp x14, x15, [x0, #16]
        ret ; .cfi_endproc
.size vailP256MontgomeryMulAltArm64, .-vailP256MontgomeryMulAltArm64
