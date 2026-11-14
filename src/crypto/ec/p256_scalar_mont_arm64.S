// ARM64 P-256 scalar-order Montgomery kernels from AWS-LC (BoringSSL).
// Source snapshot: aws-lc-sys 0.45.0, p256-armv8-asm.S.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

.section .rodata
.align 5
.Lord:
.quad	0xf3b9cac2fc632551,0xbce6faada7179e84,0xffffffffffffffff,0xffffffff00000000
.LordK:
.quad	0xccd1c8aaee00bc4f

.align 2
.text

// void vailP256ScalarMontMulArm64(uint64_t res[4], uint64_t a[4],
//                                uint64_t b[4]);
.globl	vailP256ScalarMontMulArm64
.hidden	vailP256ScalarMontMulArm64
.type	vailP256ScalarMontMulArm64,%function
.align	4
vailP256ScalarMontMulArm64:
	// Armv8.3-A PAuth: even though x30 is pushed to stack it is not popped later.
	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	adrp	x23,.Lord
	add	x23,x23,:lo12:.Lord
	ldr	x3,[x2]		// bp[0]
	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	ldp	x12,x13,[x23,#0]
	ldp	x21,x22,[x23,#16]
	ldr	x23,[x23,#32]

	mul	x14,x4,x3		// a[0]*b[0]
	umulh	x8,x4,x3

	mul	x15,x5,x3		// a[1]*b[0]
	umulh	x9,x5,x3

	mul	x16,x6,x3		// a[2]*b[0]
	umulh	x10,x6,x3

	mul	x17,x7,x3		// a[3]*b[0]
	umulh	x19,x7,x3

	mul	x24,x14,x23

	adds	x15,x15,x8		// accumulate high parts of multiplication
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adc	x19,x19,xzr
	mov	x20,xzr
	ldr	x3,[x2,#8*1]		// b[i]

	lsl	x8,x24,#32
	subs	x16,x16,x24
	lsr	x9,x24,#32
	sbcs	x17,x17,x8
	sbcs	x19,x19,x9
	sbc	x20,x20,xzr

	subs	xzr,x14,#1
	umulh	x9,x12,x24
	mul	x10,x13,x24
	umulh	x11,x13,x24

	adcs	x10,x10,x9
	mul	x8,x4,x3
	adc	x11,x11,xzr
	mul	x9,x5,x3

	adds	x14,x15,x10
	mul	x10,x6,x3
	adcs	x15,x16,x11
	mul	x11,x7,x3
	adcs	x16,x17,x24
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	adds	x14,x14,x8		// accumulate low parts
	umulh	x8,x4,x3
	adcs	x15,x15,x9
	umulh	x9,x5,x3
	adcs	x16,x16,x10
	umulh	x10,x6,x3
	adcs	x17,x17,x11
	umulh	x11,x7,x3
	adc	x19,x19,xzr
	mul	x24,x14,x23
	adds	x15,x15,x8		// accumulate high parts
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adcs	x19,x19,x11
	adc	x20,xzr,xzr
	ldr	x3,[x2,#8*2]		// b[i]

	lsl	x8,x24,#32
	subs	x16,x16,x24
	lsr	x9,x24,#32
	sbcs	x17,x17,x8
	sbcs	x19,x19,x9
	sbc	x20,x20,xzr

	subs	xzr,x14,#1
	umulh	x9,x12,x24
	mul	x10,x13,x24
	umulh	x11,x13,x24

	adcs	x10,x10,x9
	mul	x8,x4,x3
	adc	x11,x11,xzr
	mul	x9,x5,x3

	adds	x14,x15,x10
	mul	x10,x6,x3
	adcs	x15,x16,x11
	mul	x11,x7,x3
	adcs	x16,x17,x24
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	adds	x14,x14,x8		// accumulate low parts
	umulh	x8,x4,x3
	adcs	x15,x15,x9
	umulh	x9,x5,x3
	adcs	x16,x16,x10
	umulh	x10,x6,x3
	adcs	x17,x17,x11
	umulh	x11,x7,x3
	adc	x19,x19,xzr
	mul	x24,x14,x23
	adds	x15,x15,x8		// accumulate high parts
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adcs	x19,x19,x11
	adc	x20,xzr,xzr
	ldr	x3,[x2,#8*3]		// b[i]

	lsl	x8,x24,#32
	subs	x16,x16,x24
	lsr	x9,x24,#32
	sbcs	x17,x17,x8
	sbcs	x19,x19,x9
	sbc	x20,x20,xzr

	subs	xzr,x14,#1
	umulh	x9,x12,x24
	mul	x10,x13,x24
	umulh	x11,x13,x24

	adcs	x10,x10,x9
	mul	x8,x4,x3
	adc	x11,x11,xzr
	mul	x9,x5,x3

	adds	x14,x15,x10
	mul	x10,x6,x3
	adcs	x15,x16,x11
	mul	x11,x7,x3
	adcs	x16,x17,x24
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	adds	x14,x14,x8		// accumulate low parts
	umulh	x8,x4,x3
	adcs	x15,x15,x9
	umulh	x9,x5,x3
	adcs	x16,x16,x10
	umulh	x10,x6,x3
	adcs	x17,x17,x11
	umulh	x11,x7,x3
	adc	x19,x19,xzr
	mul	x24,x14,x23
	adds	x15,x15,x8		// accumulate high parts
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adcs	x19,x19,x11
	adc	x20,xzr,xzr
	lsl	x8,x24,#32		// last reduction
	subs	x16,x16,x24
	lsr	x9,x24,#32
	sbcs	x17,x17,x8
	sbcs	x19,x19,x9
	sbc	x20,x20,xzr

	subs	xzr,x14,#1
	umulh	x9,x12,x24
	mul	x10,x13,x24
	umulh	x11,x13,x24

	adcs	x10,x10,x9
	adc	x11,x11,xzr

	adds	x14,x15,x10
	adcs	x15,x16,x11
	adcs	x16,x17,x24
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	subs	x8,x14,x12		// ret -= modulus
	sbcs	x9,x15,x13
	sbcs	x10,x16,x21
	sbcs	x11,x17,x22
	sbcs	xzr,x19,xzr

	csel	x14,x14,x8,lo	// ret = borrow ? ret : ret-modulus
	csel	x15,x15,x9,lo
	csel	x16,x16,x10,lo
	stp	x14,x15,[x0]
	csel	x17,x17,x11,lo
	stp	x16,x17,[x0,#16]

	ldp	x19,x20,[sp,#16]
	ldp	x21,x22,[sp,#32]
	ldp	x23,x24,[sp,#48]
	ldr	x29,[sp],#64
	ret
.size	vailP256ScalarMontMulArm64,.-vailP256ScalarMontMulArm64

// void vailP256ScalarMontSqrArm64(uint64_t res[4], uint64_t a[4],
//                                uint64_t rep);
.globl	vailP256ScalarMontSqrArm64
.hidden	vailP256ScalarMontSqrArm64
.type	vailP256ScalarMontSqrArm64,%function
.align	4
vailP256ScalarMontSqrArm64:
	// Armv8.3-A PAuth: even though x30 is pushed to stack it is not popped later.
	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	adrp	x23,.Lord
	add	x23,x23,:lo12:.Lord
	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	ldp	x12,x13,[x23,#0]
	ldp	x21,x22,[x23,#16]
	ldr	x23,[x23,#32]
	b	.Loop_ord_sqr

.align	4
.Loop_ord_sqr:
	sub	x2,x2,#1
	////////////////////////////////////////////////////////////////
	//  |  |  |  |  |  |a1*a0|  |
	//  |  |  |  |  |a2*a0|  |  |
	//  |  |a3*a2|a3*a0|  |  |  |
	//  |  |  |  |a2*a1|  |  |  |
	//  |  |  |a3*a1|  |  |  |  |
	// *|  |  |  |  |  |  |  | 2|
	// +|a3*a3|a2*a2|a1*a1|a0*a0|
	//  |--+--+--+--+--+--+--+--|
	//  |A7|A6|A5|A4|A3|A2|A1|A0|, where Ax is , i.e. follow 
	//
	//  "can't overflow" below mark carrying into high part of
	//  multiplication result, which can't overflow, because it
	//  can never be all ones.

	mul	x15,x5,x4		// a[1]*a[0]
	umulh	x9,x5,x4
	mul	x16,x6,x4		// a[2]*a[0]
	umulh	x10,x6,x4
	mul	x17,x7,x4		// a[3]*a[0]
	umulh	x19,x7,x4

	adds	x16,x16,x9		// accumulate high parts of multiplication
	mul	x8,x6,x5		// a[2]*a[1]
	umulh	x9,x6,x5
	adcs	x17,x17,x10
	mul	x10,x7,x5		// a[3]*a[1]
	umulh	x11,x7,x5
	adc	x19,x19,xzr		// can't overflow

	mul	x20,x7,x6		// a[3]*a[2]
	umulh	x1,x7,x6

	adds	x9,x9,x10		// accumulate high parts of multiplication
	mul	x14,x4,x4		// a[0]*a[0]
	adc	x10,x11,xzr		// can't overflow

	adds	x17,x17,x8		// accumulate low parts of multiplication
	umulh	x4,x4,x4
	adcs	x19,x19,x9
	mul	x9,x5,x5		// a[1]*a[1]
	adcs	x20,x20,x10
	umulh	x5,x5,x5
	adc	x1,x1,xzr		// can't overflow

	adds	x15,x15,x15	// acc[1-6]*=2
	mul	x10,x6,x6		// a[2]*a[2]
	adcs	x16,x16,x16
	umulh	x6,x6,x6
	adcs	x17,x17,x17
	mul	x11,x7,x7		// a[3]*a[3]
	adcs	x19,x19,x19
	umulh	x7,x7,x7
	adcs	x20,x20,x20
	adcs	x1,x1,x1
	adc	x3,xzr,xzr

	adds	x15,x15,x4		// +a[i]*a[i]
	mul	x24,x14,x23
	adcs	x16,x16,x9
	adcs	x17,x17,x5
	adcs	x19,x19,x10
	adcs	x20,x20,x6
	adcs	x1,x1,x11
	adc	x3,x3,x7
	subs	xzr,x14,#1
	umulh	x9,x12,x24
	mul	x10,x13,x24
	umulh	x11,x13,x24

	adcs	x10,x10,x9
	adc	x11,x11,xzr

	adds	x14,x15,x10
	adcs	x15,x16,x11
	adcs	x16,x17,x24
	adc	x17,xzr,x24		// can't overflow
	mul	x11,x14,x23
	lsl	x8,x24,#32
	subs	x15,x15,x24
	lsr	x9,x24,#32
	sbcs	x16,x16,x8
	sbc	x17,x17,x9		// can't borrow
	subs	xzr,x14,#1
	umulh	x9,x12,x11
	mul	x10,x13,x11
	umulh	x24,x13,x11

	adcs	x10,x10,x9
	adc	x24,x24,xzr

	adds	x14,x15,x10
	adcs	x15,x16,x24
	adcs	x16,x17,x11
	adc	x17,xzr,x11		// can't overflow
	mul	x24,x14,x23
	lsl	x8,x11,#32
	subs	x15,x15,x11
	lsr	x9,x11,#32
	sbcs	x16,x16,x8
	sbc	x17,x17,x9		// can't borrow
	subs	xzr,x14,#1
	umulh	x9,x12,x24
	mul	x10,x13,x24
	umulh	x11,x13,x24

	adcs	x10,x10,x9
	adc	x11,x11,xzr

	adds	x14,x15,x10
	adcs	x15,x16,x11
	adcs	x16,x17,x24
	adc	x17,xzr,x24		// can't overflow
	mul	x11,x14,x23
	lsl	x8,x24,#32
	subs	x15,x15,x24
	lsr	x9,x24,#32
	sbcs	x16,x16,x8
	sbc	x17,x17,x9		// can't borrow
	subs	xzr,x14,#1
	umulh	x9,x12,x11
	mul	x10,x13,x11
	umulh	x24,x13,x11

	adcs	x10,x10,x9
	adc	x24,x24,xzr

	adds	x14,x15,x10
	adcs	x15,x16,x24
	adcs	x16,x17,x11
	adc	x17,xzr,x11		// can't overflow
	lsl	x8,x11,#32
	subs	x15,x15,x11
	lsr	x9,x11,#32
	sbcs	x16,x16,x8
	sbc	x17,x17,x9		// can't borrow
	adds	x14,x14,x19	// accumulate upper half
	adcs	x15,x15,x20
	adcs	x16,x16,x1
	adcs	x17,x17,x3
	adc	x19,xzr,xzr

	subs	x8,x14,x12		// ret -= modulus
	sbcs	x9,x15,x13
	sbcs	x10,x16,x21
	sbcs	x11,x17,x22
	sbcs	xzr,x19,xzr

	csel	x4,x14,x8,lo	// ret = borrow ? ret : ret-modulus
	csel	x5,x15,x9,lo
	csel	x6,x16,x10,lo
	csel	x7,x17,x11,lo

	cbnz	x2,.Loop_ord_sqr

	stp	x4,x5,[x0]
	stp	x6,x7,[x0,#16]

	ldp	x19,x20,[sp,#16]
	ldp	x21,x22,[sp,#32]
	ldp	x23,x24,[sp,#48]
	ldr	x29,[sp],#64
	ret
.size	vailP256ScalarMontSqrArm64,.-vailP256ScalarMontSqrArm64
