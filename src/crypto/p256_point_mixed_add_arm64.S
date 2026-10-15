// ARM64 P-256 Montgomery-Jacobian mixed-add kernel from s2n-bignum.
// Source: awslabs/s2n-bignum 4d1356a7470663c752660a59375dc3a9ef548428.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

.globl vailP256MontgomeryJacobianMixedAddArm64
        .type vailP256MontgomeryJacobianMixedAddArm64, %function
        .hidden vailP256MontgomeryJacobianMixedAddArm64
        .text
        .balign 4
vailP256MontgomeryJacobianMixedAddArm64:
        .cfi_startproc
        stp x19, x20, [sp, #-16]!
        .cfi_adjust_cfa_offset 16
        .cfi_rel_offset x19, 0
        .cfi_rel_offset x20, 8
        sub sp, sp, #(32*6 +0)
        .cfi_adjust_cfa_offset 32*6
        mov x17, x0
        mov x19, x1
        mov x20, x2
        ldp x2, x3, [x19, #(2*32)]
        ldp x4, x5, [x19, #(2*32)+16]
        umull x15, w2, w2
        lsr x11, x2, #32
        umull x16, w11, w11
        umull x11, w2, w11
        adds x15, x15, x11, lsl #33
        lsr x11, x11, #31
        adc x16, x16, x11
        umull x0, w3, w3
        lsr x11, x3, #32
        umull x1, w11, w11
        umull x11, w3, w11
        mul x12, x2, x3
        umulh x13, x2, x3
        adds x0, x0, x11, lsl #33
        lsr x11, x11, #31
        adc x1, x1, x11
        adds x12, x12, x12
        adcs x13, x13, x13
        adc x1, x1, xzr
        adds x16, x16, x12
        adcs x0, x0, x13
        adc x1, x1, xzr
        lsl x12, x15, #32
        subs x13, x15, x12
        lsr x11, x15, #32
        sbc x15, x15, x11
        adds x16, x16, x12
        adcs x0, x0, x11
        adcs x1, x1, x13
        adc x15, x15, xzr
        lsl x12, x16, #32
        subs x13, x16, x12
        lsr x11, x16, #32
        sbc x16, x16, x11
        adds x0, x0, x12
        adcs x1, x1, x11
        adcs x15, x15, x13
        adc x16, x16, xzr
        mul x6, x2, x4
        mul x14, x3, x5
        umulh x8, x2, x4
        subs x10, x2, x3
        cneg x10, x10, lo
        csetm x13, lo
        subs x12, x5, x4
        cneg x12, x12, lo
        mul x11, x10, x12
        umulh x12, x10, x12
        cinv x13, x13, lo
        eor x11, x11, x13
        eor x12, x12, x13
        adds x7, x6, x8
        adc x8, x8, xzr
        umulh x9, x3, x5
        adds x7, x7, x14
        adcs x8, x8, x9
        adc x9, x9, xzr
        adds x8, x8, x14
        adc x9, x9, xzr
        cmn x13, #1
        adcs x7, x7, x11
        adcs x8, x8, x12
        adc x9, x9, x13
        adds x6, x6, x6
        adcs x7, x7, x7
        adcs x8, x8, x8
        adcs x9, x9, x9
        adc x10, xzr, xzr
        adds x6, x6, x0
        adcs x7, x7, x1
        adcs x8, x8, x15
        adcs x9, x9, x16
        adc x10, x10, xzr
        lsl x12, x6, #32
        subs x13, x6, x12
        lsr x11, x6, #32
        sbc x6, x6, x11
        adds x7, x7, x12
        adcs x8, x8, x11
        adcs x9, x9, x13
        adcs x10, x10, x6
        adc x6, xzr, xzr
        lsl x12, x7, #32
        subs x13, x7, x12
        lsr x11, x7, #32
        sbc x7, x7, x11
        adds x8, x8, x12
        adcs x9, x9, x11
        adcs x10, x10, x13
        adcs x6, x6, x7
        adc x7, xzr, xzr
        mul x11, x4, x4
        adds x8, x8, x11
        mul x12, x5, x5
        umulh x11, x4, x4
        adcs x9, x9, x11
        adcs x10, x10, x12
        umulh x12, x5, x5
        adcs x6, x6, x12
        adc x7, x7, xzr
        mul x11, x4, x5
        umulh x12, x4, x5
        adds x11, x11, x11
        adcs x12, x12, x12
        adc x13, xzr, xzr
        adds x9, x9, x11
        adcs x10, x10, x12
        adcs x6, x6, x13
        adcs x7, x7, xzr
        mov x11, #4294967295
        adds x5, x8, #1
        sbcs x11, x9, x11
        mov x13, #-4294967295
        sbcs x12, x10, xzr
        sbcs x13, x6, x13
        sbcs xzr, x7, xzr
        csel x8, x5, x8, hs
        csel x9, x11, x9, hs
        csel x10, x12, x10, hs
        csel x6, x13, x6, hs
        stp x8, x9, [sp, #(32*0)]
        stp x10, x6, [sp, #(32*0)+16]
        ldp x3, x4, [x19, #(2*32)]
        ldp x5, x6, [x19, #(2*32)+16]
        ldp x7, x8, [x20, #32]
        ldp x9, x10, [x20, #32 +16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*1)]
        stp x11, x12, [sp, #(32*1)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*1)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*1)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*1)]
        stp x3, x4, [sp, #(32*1)+16]
        ldp x3, x4, [sp, #(32*0)]
        ldp x5, x6, [sp, #(32*0)+16]
        ldp x7, x8, [x20, #0]
        ldp x9, x10, [x20, #0 +16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*2)]
        stp x11, x12, [sp, #(32*2)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*2)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*2)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*2)]
        stp x3, x4, [sp, #(32*2)+16]
        ldp x3, x4, [sp, #(32*0)]
        ldp x5, x6, [sp, #(32*0)+16]
        ldp x7, x8, [sp, #(32*1)]
        ldp x9, x10, [sp, #(32*1)+16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*1)]
        stp x11, x12, [sp, #(32*1)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*1)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*1)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*1)]
        stp x3, x4, [sp, #(32*1)+16]
        ldp x5, x6, [sp, #(32*2)]
        ldp x4, x3, [x19, #0]
        subs x5, x5, x4
        sbcs x6, x6, x3
        ldp x7, x8, [sp, #(32*2)+16]
        ldp x4, x3, [x19, #0 +16]
        sbcs x7, x7, x4
        sbcs x8, x8, x3
        csetm x3, cc
        adds x5, x5, x3
        mov x4, #0xffffffff
        and x4, x4, x3
        adcs x6, x6, x4
        adcs x7, x7, xzr
        mov x4, #0xffffffff00000001
        and x4, x4, x3
        adc x8, x8, x4
        stp x5, x6, [sp, #(32*5)]
        stp x7, x8, [sp, #(32*5)+16]
        ldp x5, x6, [sp, #(32*1)]
        ldp x4, x3, [x19, #32]
        subs x5, x5, x4
        sbcs x6, x6, x3
        ldp x7, x8, [sp, #(32*1)+16]
        ldp x4, x3, [x19, #32 +16]
        sbcs x7, x7, x4
        sbcs x8, x8, x3
        csetm x3, cc
        adds x5, x5, x3
        mov x4, #0xffffffff
        and x4, x4, x3
        adcs x6, x6, x4
        adcs x7, x7, xzr
        mov x4, #0xffffffff00000001
        and x4, x4, x3
        adc x8, x8, x4
        stp x5, x6, [sp, #(32*1)]
        stp x7, x8, [sp, #(32*1)+16]
        ldp x2, x3, [sp, #(32*5)]
        ldp x4, x5, [sp, #(32*5)+16]
        umull x15, w2, w2
        lsr x11, x2, #32
        umull x16, w11, w11
        umull x11, w2, w11
        adds x15, x15, x11, lsl #33
        lsr x11, x11, #31
        adc x16, x16, x11
        umull x0, w3, w3
        lsr x11, x3, #32
        umull x1, w11, w11
        umull x11, w3, w11
        mul x12, x2, x3
        umulh x13, x2, x3
        adds x0, x0, x11, lsl #33
        lsr x11, x11, #31
        adc x1, x1, x11
        adds x12, x12, x12
        adcs x13, x13, x13
        adc x1, x1, xzr
        adds x16, x16, x12
        adcs x0, x0, x13
        adc x1, x1, xzr
        lsl x12, x15, #32
        subs x13, x15, x12
        lsr x11, x15, #32
        sbc x15, x15, x11
        adds x16, x16, x12
        adcs x0, x0, x11
        adcs x1, x1, x13
        adc x15, x15, xzr
        lsl x12, x16, #32
        subs x13, x16, x12
        lsr x11, x16, #32
        sbc x16, x16, x11
        adds x0, x0, x12
        adcs x1, x1, x11
        adcs x15, x15, x13
        adc x16, x16, xzr
        mul x6, x2, x4
        mul x14, x3, x5
        umulh x8, x2, x4
        subs x10, x2, x3
        cneg x10, x10, lo
        csetm x13, lo
        subs x12, x5, x4
        cneg x12, x12, lo
        mul x11, x10, x12
        umulh x12, x10, x12
        cinv x13, x13, lo
        eor x11, x11, x13
        eor x12, x12, x13
        adds x7, x6, x8
        adc x8, x8, xzr
        umulh x9, x3, x5
        adds x7, x7, x14
        adcs x8, x8, x9
        adc x9, x9, xzr
        adds x8, x8, x14
        adc x9, x9, xzr
        cmn x13, #1
        adcs x7, x7, x11
        adcs x8, x8, x12
        adc x9, x9, x13
        adds x6, x6, x6
        adcs x7, x7, x7
        adcs x8, x8, x8
        adcs x9, x9, x9
        adc x10, xzr, xzr
        adds x6, x6, x0
        adcs x7, x7, x1
        adcs x8, x8, x15
        adcs x9, x9, x16
        adc x10, x10, xzr
        lsl x12, x6, #32
        subs x13, x6, x12
        lsr x11, x6, #32
        sbc x6, x6, x11
        adds x7, x7, x12
        adcs x8, x8, x11
        adcs x9, x9, x13
        adcs x10, x10, x6
        adc x6, xzr, xzr
        lsl x12, x7, #32
        subs x13, x7, x12
        lsr x11, x7, #32
        sbc x7, x7, x11
        adds x8, x8, x12
        adcs x9, x9, x11
        adcs x10, x10, x13
        adcs x6, x6, x7
        adc x7, xzr, xzr
        mul x11, x4, x4
        adds x8, x8, x11
        mul x12, x5, x5
        umulh x11, x4, x4
        adcs x9, x9, x11
        adcs x10, x10, x12
        umulh x12, x5, x5
        adcs x6, x6, x12
        adc x7, x7, xzr
        mul x11, x4, x5
        umulh x12, x4, x5
        adds x11, x11, x11
        adcs x12, x12, x12
        adc x13, xzr, xzr
        adds x9, x9, x11
        adcs x10, x10, x12
        adcs x6, x6, x13
        adcs x7, x7, xzr
        mov x11, #4294967295
        adds x5, x8, #1
        sbcs x11, x9, x11
        mov x13, #-4294967295
        sbcs x12, x10, xzr
        sbcs x13, x6, x13
        sbcs xzr, x7, xzr
        csel x8, x5, x8, hs
        csel x9, x11, x9, hs
        csel x10, x12, x10, hs
        csel x6, x13, x6, hs
        stp x8, x9, [sp, #(32*3)]
        stp x10, x6, [sp, #(32*3)+16]
        ldp x2, x3, [sp, #(32*1)]
        ldp x4, x5, [sp, #(32*1)+16]
        umull x15, w2, w2
        lsr x11, x2, #32
        umull x16, w11, w11
        umull x11, w2, w11
        adds x15, x15, x11, lsl #33
        lsr x11, x11, #31
        adc x16, x16, x11
        umull x0, w3, w3
        lsr x11, x3, #32
        umull x1, w11, w11
        umull x11, w3, w11
        mul x12, x2, x3
        umulh x13, x2, x3
        adds x0, x0, x11, lsl #33
        lsr x11, x11, #31
        adc x1, x1, x11
        adds x12, x12, x12
        adcs x13, x13, x13
        adc x1, x1, xzr
        adds x16, x16, x12
        adcs x0, x0, x13
        adc x1, x1, xzr
        lsl x12, x15, #32
        subs x13, x15, x12
        lsr x11, x15, #32
        sbc x15, x15, x11
        adds x16, x16, x12
        adcs x0, x0, x11
        adcs x1, x1, x13
        adc x15, x15, xzr
        lsl x12, x16, #32
        subs x13, x16, x12
        lsr x11, x16, #32
        sbc x16, x16, x11
        adds x0, x0, x12
        adcs x1, x1, x11
        adcs x15, x15, x13
        adc x16, x16, xzr
        mul x6, x2, x4
        mul x14, x3, x5
        umulh x8, x2, x4
        subs x10, x2, x3
        cneg x10, x10, lo
        csetm x13, lo
        subs x12, x5, x4
        cneg x12, x12, lo
        mul x11, x10, x12
        umulh x12, x10, x12
        cinv x13, x13, lo
        eor x11, x11, x13
        eor x12, x12, x13
        adds x7, x6, x8
        adc x8, x8, xzr
        umulh x9, x3, x5
        adds x7, x7, x14
        adcs x8, x8, x9
        adc x9, x9, xzr
        adds x8, x8, x14
        adc x9, x9, xzr
        cmn x13, #1
        adcs x7, x7, x11
        adcs x8, x8, x12
        adc x9, x9, x13
        adds x6, x6, x6
        adcs x7, x7, x7
        adcs x8, x8, x8
        adcs x9, x9, x9
        adc x10, xzr, xzr
        adds x6, x6, x0
        adcs x7, x7, x1
        adcs x8, x8, x15
        adcs x9, x9, x16
        adc x10, x10, xzr
        lsl x12, x6, #32
        subs x13, x6, x12
        lsr x11, x6, #32
        sbc x6, x6, x11
        adds x7, x7, x12
        adcs x8, x8, x11
        adcs x9, x9, x13
        adcs x10, x10, x6
        adc x6, xzr, xzr
        lsl x12, x7, #32
        subs x13, x7, x12
        lsr x11, x7, #32
        sbc x7, x7, x11
        adds x8, x8, x12
        adcs x9, x9, x11
        adcs x10, x10, x13
        adcs x6, x6, x7
        adc x7, xzr, xzr
        mul x11, x4, x4
        adds x8, x8, x11
        mul x12, x5, x5
        umulh x11, x4, x4
        adcs x9, x9, x11
        adcs x10, x10, x12
        umulh x12, x5, x5
        adcs x6, x6, x12
        adc x7, x7, xzr
        mul x11, x4, x5
        umulh x12, x4, x5
        adds x11, x11, x11
        adcs x12, x12, x12
        adc x13, xzr, xzr
        adds x9, x9, x11
        adcs x10, x10, x12
        adcs x6, x6, x13
        adcs x7, x7, xzr
        mov x11, #4294967295
        adds x5, x8, #1
        sbcs x11, x9, x11
        mov x13, #-4294967295
        sbcs x12, x10, xzr
        sbcs x13, x6, x13
        sbcs xzr, x7, xzr
        csel x8, x5, x8, hs
        csel x9, x11, x9, hs
        csel x10, x12, x10, hs
        csel x6, x13, x6, hs
        stp x8, x9, [sp, #(32*0)]
        stp x10, x6, [sp, #(32*0)+16]
        ldp x3, x4, [sp, #(32*3)]
        ldp x5, x6, [sp, #(32*3)+16]
        ldp x7, x8, [x19, #0]
        ldp x9, x10, [x19, #0 +16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*4)]
        stp x11, x12, [sp, #(32*4)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*4)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*4)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*4)]
        stp x3, x4, [sp, #(32*4)+16]
        ldp x3, x4, [sp, #(32*3)]
        ldp x5, x6, [sp, #(32*3)+16]
        ldp x7, x8, [sp, #(32*2)]
        ldp x9, x10, [sp, #(32*2)+16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*2)]
        stp x11, x12, [sp, #(32*2)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*2)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*2)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*2)]
        stp x3, x4, [sp, #(32*2)+16]
        ldp x5, x6, [sp, #(32*0)]
        ldp x4, x3, [sp, #(32*4)]
        subs x5, x5, x4
        sbcs x6, x6, x3
        ldp x7, x8, [sp, #(32*0)+16]
        ldp x4, x3, [sp, #(32*4)+16]
        sbcs x7, x7, x4
        sbcs x8, x8, x3
        csetm x3, cc
        adds x5, x5, x3
        mov x4, #0xffffffff
        and x4, x4, x3
        adcs x6, x6, x4
        adcs x7, x7, xzr
        mov x4, #0xffffffff00000001
        and x4, x4, x3
        adc x8, x8, x4
        stp x5, x6, [sp, #(32*0)]
        stp x7, x8, [sp, #(32*0)+16]
        ldp x5, x6, [sp, #(32*2)]
        ldp x4, x3, [sp, #(32*4)]
        subs x5, x5, x4
        sbcs x6, x6, x3
        ldp x7, x8, [sp, #(32*2)+16]
        ldp x4, x3, [sp, #(32*4)+16]
        sbcs x7, x7, x4
        sbcs x8, x8, x3
        csetm x3, cc
        adds x5, x5, x3
        mov x4, #0xffffffff
        and x4, x4, x3
        adcs x6, x6, x4
        adcs x7, x7, xzr
        mov x4, #0xffffffff00000001
        and x4, x4, x3
        adc x8, x8, x4
        stp x5, x6, [sp, #(32*3)]
        stp x7, x8, [sp, #(32*3)+16]
        ldp x3, x4, [sp, #(32*5)]
        ldp x5, x6, [sp, #(32*5)+16]
        ldp x7, x8, [x19, #(2*32)]
        ldp x9, x10, [x19, #(2*32)+16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*5)]
        stp x11, x12, [sp, #(32*5)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*5)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*5)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*5)]
        stp x3, x4, [sp, #(32*5)+16]
        ldp x5, x6, [sp, #(32*0)]
        ldp x4, x3, [sp, #(32*2)]
        subs x5, x5, x4
        sbcs x6, x6, x3
        ldp x7, x8, [sp, #(32*0)+16]
        ldp x4, x3, [sp, #(32*2)+16]
        sbcs x7, x7, x4
        sbcs x8, x8, x3
        csetm x3, cc
        adds x5, x5, x3
        mov x4, #0xffffffff
        and x4, x4, x3
        adcs x6, x6, x4
        adcs x7, x7, xzr
        mov x4, #0xffffffff00000001
        and x4, x4, x3
        adc x8, x8, x4
        stp x5, x6, [sp, #(32*0)]
        stp x7, x8, [sp, #(32*0)+16]
        ldp x5, x6, [sp, #(32*4)]
        ldp x4, x3, [sp, #(32*0)]
        subs x5, x5, x4
        sbcs x6, x6, x3
        ldp x7, x8, [sp, #(32*4)+16]
        ldp x4, x3, [sp, #(32*0)+16]
        sbcs x7, x7, x4
        sbcs x8, x8, x3
        csetm x3, cc
        adds x5, x5, x3
        mov x4, #0xffffffff
        and x4, x4, x3
        adcs x6, x6, x4
        adcs x7, x7, xzr
        mov x4, #0xffffffff00000001
        and x4, x4, x3
        adc x8, x8, x4
        stp x5, x6, [sp, #(32*4)]
        stp x7, x8, [sp, #(32*4)+16]
        ldp x3, x4, [sp, #(32*3)]
        ldp x5, x6, [sp, #(32*3)+16]
        ldp x7, x8, [x19, #32]
        ldp x9, x10, [x19, #32 +16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*3)]
        stp x11, x12, [sp, #(32*3)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*3)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*3)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*3)]
        stp x3, x4, [sp, #(32*3)+16]
        ldp x3, x4, [sp, #(32*1)]
        ldp x5, x6, [sp, #(32*1)+16]
        ldp x7, x8, [sp, #(32*4)]
        ldp x9, x10, [sp, #(32*4)+16]
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x3, x4
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        stp x13, x14, [sp, #(32*4)]
        stp x11, x12, [sp, #(32*4)+16]
        mul x11, x5, x9
        mul x13, x6, x10
        umulh x12, x5, x9
        adds x16, x11, x13
        umulh x14, x6, x10
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x15, x5, x6
        cneg x15, x15, lo
        csetm x1, lo
        subs x0, x10, x9
        cneg x0, x0, lo
        mul x16, x15, x0
        umulh x0, x15, x0
        cinv x1, x1, lo
        eor x16, x16, x1
        eor x0, x0, x1
        cmn x1, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x1
        subs x3, x5, x3
        sbcs x4, x6, x4
        ngc x5, xzr
        cmn x5, #1
        eor x3, x3, x5
        adcs x3, x3, xzr
        eor x4, x4, x5
        adcs x4, x4, xzr
        subs x7, x7, x9
        sbcs x8, x8, x10
        ngc x9, xzr
        cmn x9, #1
        eor x7, x7, x9
        adcs x7, x7, xzr
        eor x8, x8, x9
        adcs x8, x8, xzr
        eor x10, x5, x9
        ldp x15, x1, [sp, #(32*4)]
        adds x15, x11, x15
        adcs x1, x12, x1
        ldp x5, x9, [sp, #(32*4)+16]
        adcs x5, x13, x5
        adcs x9, x14, x9
        adc x2, xzr, xzr
        mul x11, x3, x7
        mul x13, x4, x8
        umulh x12, x3, x7
        adds x16, x11, x13
        umulh x14, x4, x8
        adcs x0, x12, x14
        adcs x14, x14, xzr
        adds x12, x12, x16
        adcs x13, x13, x0
        adcs x14, x14, xzr
        subs x3, x3, x4
        cneg x3, x3, lo
        csetm x4, lo
        subs x0, x8, x7
        cneg x0, x0, lo
        mul x16, x3, x0
        umulh x0, x3, x0
        cinv x4, x4, lo
        eor x16, x16, x4
        eor x0, x0, x4
        cmn x4, #1
        adcs x12, x12, x16
        adcs x13, x13, x0
        adc x14, x14, x4
        cmn x10, #1
        eor x11, x11, x10
        adcs x11, x11, x15
        eor x12, x12, x10
        adcs x12, x12, x1
        eor x13, x13, x10
        adcs x13, x13, x5
        eor x14, x14, x10
        adcs x14, x14, x9
        adcs x3, x2, x10
        adcs x4, x10, xzr
        adc x10, x10, xzr
        adds x13, x13, x15
        adcs x14, x14, x1
        adcs x3, x3, x5
        adcs x4, x4, x9
        adc x10, x10, x2
        lsl x0, x11, #32
        subs x1, x11, x0
        lsr x16, x11, #32
        sbc x11, x11, x16
        adds x12, x12, x0
        adcs x13, x13, x16
        adcs x14, x14, x1
        adc x11, x11, xzr
        lsl x0, x12, #32
        subs x1, x12, x0
        lsr x16, x12, #32
        sbc x12, x12, x16
        adds x13, x13, x0
        adcs x14, x14, x16
        adcs x11, x11, x1
        adc x12, x12, xzr
        adds x3, x3, x11
        adcs x4, x4, x12
        adc x10, x10, xzr
        add x2, x10, #1
        lsl x16, x2, #32
        adds x4, x4, x16
        adc x10, x10, xzr
        neg x15, x2
        sub x16, x16, #1
        subs x13, x13, x15
        sbcs x14, x14, x16
        sbcs x3, x3, xzr
        sbcs x4, x4, x2
        sbcs x7, x10, x2
        adds x13, x13, x7
        mov x10, #4294967295
        and x10, x10, x7
        adcs x14, x14, x10
        adcs x3, x3, xzr
        mov x10, #-4294967295
        and x10, x10, x7
        adc x4, x4, x10
        stp x13, x14, [sp, #(32*4)]
        stp x3, x4, [sp, #(32*4)+16]
        ldp x5, x6, [sp, #(32*4)]
        ldp x4, x3, [sp, #(32*3)]
        subs x5, x5, x4
        sbcs x6, x6, x3
        ldp x7, x8, [sp, #(32*4)+16]
        ldp x4, x3, [sp, #(32*3)+16]
        sbcs x7, x7, x4
        sbcs x8, x8, x3
        csetm x3, cc
        adds x5, x5, x3
        mov x4, #0xffffffff
        and x4, x4, x3
        adcs x6, x6, x4
        adcs x7, x7, xzr
        mov x4, #0xffffffff00000001
        and x4, x4, x3
        adc x8, x8, x4
        stp x5, x6, [sp, #(32*4)]
        stp x7, x8, [sp, #(32*4)+16]
        ldp x0, x1, [x19, #(2*32)]
        ldp x2, x3, [x19, #(2*32)+16]
        orr x4, x0, x1
        orr x5, x2, x3
        orr x4, x4, x5
        cmp x4, xzr
        ldp x0, x1, [sp, #(32*0)]
        ldp x12, x13, [x20, #0]
        csel x0, x0, x12, ne
        csel x1, x1, x13, ne
        ldp x2, x3, [sp, #(32*0)+16]
        ldp x12, x13, [x20, #0 +16]
        csel x2, x2, x12, ne
        csel x3, x3, x13, ne
        ldp x4, x5, [sp, #(32*4)]
        ldp x12, x13, [x20, #32]
        csel x4, x4, x12, ne
        csel x5, x5, x13, ne
        ldp x6, x7, [sp, #(32*4)+16]
        ldp x12, x13, [x20, #32 +16]
        csel x6, x6, x12, ne
        csel x7, x7, x13, ne
        ldp x8, x9, [sp, #(32*5)]
        mov x12, #0x0000000000000001
        mov x13, #0xffffffff00000000
        csel x8, x8, x12, ne
        csel x9, x9, x13, ne
        ldp x10, x11, [sp, #(32*5)+16]
        mov x12, #0xffffffffffffffff
        mov x13, #0x00000000fffffffe
        csel x10, x10, x12, ne
        csel x11, x11, x13, ne
        stp x0, x1, [x17, #0]
        stp x2, x3, [x17, #0 +16]
        stp x4, x5, [x17, #32]
        stp x6, x7, [x17, #32 +16]
        stp x8, x9, [x17, #(2*32)]
        stp x10, x11, [x17, #(2*32)+16]
        add sp, sp, #(32*6 +0)
        .cfi_adjust_cfa_offset -32*6
        ldp x19, x20, [sp], #16
        .cfi_adjust_cfa_offset -16
        .cfi_restore x19
        .cfi_restore x20
        ret
        .cfi_endproc
.size vailP256MontgomeryJacobianMixedAddArm64, .-vailP256MontgomeryJacobianMixedAddArm64
.section .note.GNU-stack, "", %progbits
