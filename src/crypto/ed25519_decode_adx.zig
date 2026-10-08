//! Public-input x86_64 ADX Ed25519 point decoder.
//!
//! The instruction schedule comes from the formally verified s2n-bignum
//! implementation.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

pub fn decode(output: *[8]u64, encoded: *const [32]u8) bool {
    if (comptime !enabled) @compileError("ADX Ed25519 decode is unavailable");
    return vailEd25519Decode(output, encoded) == 0;
}

/// Multiply two canonical 4x64-bit p25519 field elements. The underlying
/// schedule is the same formally verified routine used by the decoder.
pub fn fieldMul(
    output: *[4]u64,
    left: *const [4]u64,
    right: *const [4]u64,
) void {
    if (comptime !enabled) @compileError("ADX Ed25519 is unavailable");
    vailEd25519FieldMul(output, left, right);
}

extern fn vailEd25519Decode(
    output: *[8]u64,
    encoded: *const [32]u8,
) callconv(.c) u64;

extern fn vailEd25519FieldMul(
    output: *[4]u64,
    left: *const [4]u64,
    right: *const [4]u64,
) callconv(.c) void;

comptime {
    if (enabled) {
        asm (
            \\        .text
            \\        .balign 32
            \\vailEd25519Decode:
            \\        .cfi_startproc
            \\        endbr64
            \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
            \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
            \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
            \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
            \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
            \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
            \\        subq $32*8, %rsp ; .cfi_adjust_cfa_offset 32*8
            \\        movq %rdi, (28*8)(%rsp)
            \\        movq (%rsi), %rax
            \\        movq %rax, 0(%rsp)
            \\        movq 8(%rsi), %rbx
            \\        movq %rbx, 0 +8(%rsp)
            \\        xorl %ebp, %ebp
            \\        movq 16(%rsi), %rcx
            \\        movq %rcx, 0 +16(%rsp)
            \\        movq 24(%rsi), %rdx
            \\        btr $63, %rdx
            \\        movq %rdx, 0 +24(%rsp)
            \\        adcq %rbp, %rbp
            \\        movq %rbp, (29*8)(%rsp)
            \\        addq $19, %rax
            \\        adcq $0, %rbx
            \\        adcq $0, %rcx
            \\        adcq $0, %rdx
            \\        shrq $63, %rdx
            \\        movq %rdx, (30*8)(%rsp)
            \\        leaq (16*8)(%rsp), %rdi
            \\        movq $1, %rsi
            \\        leaq 0(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        movq (16*8)(%rsp), %rax
            \\        subq $20, %rax
            \\        movq (16*8)+8(%rsp), %rbx
            \\        sbbq $0, %rbx
            \\        movq (16*8)+16(%rsp), %rcx
            \\        sbbq $0, %rcx
            \\        movq (16*8)+24(%rsp), %rdx
            \\        sbbq $0, %rdx
            \\        btc $63, %rdx
            \\        movq %rax, (12*8)(%rsp)
            \\        movq %rbx, (12*8)+8(%rsp)
            \\        movq %rcx, (12*8)+16(%rsp)
            \\        movq %rdx, (12*8)+24(%rsp)
            \\        movq $0x75eb4dca135978a3, %rax
            \\        movq %rax, (20*8)(%rsp)
            \\        movq $0x00700a4d4141d8ab, %rax
            \\        movq %rax, (20*8)+8(%rsp)
            \\        movq $0x8cc740797779e898, %rax
            \\        movq %rax, (20*8)+16(%rsp)
            \\        movq $0x52036cee2b6ffe73, %rax
            \\        movq %rax, (20*8)+24(%rsp)
            \\        leaq (16*8)(%rsp), %rdi
            \\        leaq (20*8)(%rsp), %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        movq (16*8)(%rsp), %rax
            \\        addq $1, %rax
            \\        movq (16*8)+8(%rsp), %rbx
            \\        adcq $0, %rbx
            \\        movq (16*8)+16(%rsp), %rcx
            \\        adcq $0, %rcx
            \\        movq (16*8)+24(%rsp), %rdx
            \\        adcq $0, %rdx
            \\        movq %rax, (16*8)(%rsp)
            \\        movq %rbx, (16*8)+8(%rsp)
            \\        movq %rcx, (16*8)+16(%rsp)
            \\        movq %rdx, (16*8)+24(%rsp)
            \\        leaq (20*8)(%rsp), %rdi
            \\        leaq (12*8)(%rsp), %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (8*8)(%rsp), %rdi
            \\        movq $1, %rsi
            \\        leaq (20*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (8*8)(%rsp), %rdi
            \\        leaq (8*8)(%rsp), %rsi
            \\        leaq (20*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $2, %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (8*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $1, %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (16*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (20*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $5, %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (8*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $10, %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (8*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $5, %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (16*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $25, %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (8*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $50, %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (8*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $25, %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (16*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $125, %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (16*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        movq $2, %rsi
            \\        leaq (16*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (20*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (16*8)(%rsp), %rdi
            \\        movq $1, %rsi
            \\        leaq (4*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_nsqr_p25519
            \\        leaq (16*8)(%rsp), %rdi
            \\        leaq (16*8)(%rsp), %rsi
            \\        leaq (20*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        leaq (4*8)(%rsp), %rdi
            \\        leaq (12*8)(%rsp), %rsi
            \\        leaq (4*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        movq $0xc4ee1b274a0ea0b0, %rax
            \\        movq %rax, (8*8)(%rsp)
            \\        movq $0x2f431806ad2fe478, %rax
            \\        movq %rax, (8*8)+8(%rsp)
            \\        movq $0x2b4d00993dfbd7a7, %rax
            \\        movq %rax, (8*8)+16(%rsp)
            \\        movq $0x2b8324804fc1df0b, %rax
            \\        movq %rax, (8*8)+24(%rsp)
            \\        leaq (8*8)(%rsp), %rdi
            \\        leaq (4*8)(%rsp), %rsi
            \\        leaq (8*8)(%rsp), %rdx
            \\        callq LvailEd25519Decode_mul_p25519
            \\        movq (16*8)(%rsp), %r8
            \\        movq (16*8)+8(%rsp), %r9
            \\        movq (16*8)+16(%rsp), %r10
            \\        movq (16*8)+24(%rsp), %r11
            \\        movl $1, %eax
            \\        notq %rax
            \\        andq %r8, %rax
            \\        orq %r9, %rax
            \\        orq %r10, %rax
            \\        orq %r11, %rax
            \\        addq $20, %r8
            \\        notq %r9
            \\        notq %r10
            \\        bts $63, %r11
            \\        addq $1, %r11
            \\        orq %r9, %r8
            \\        orq %r11, %r10
            \\        orq %r10, %r8
            \\        testq %rax, %rax
            \\        movq (4*8)(%rsp), %r12
            \\        movq (8*8)(%rsp), %rbx
            \\        cmovnzq %rbx, %r12
            \\        movq (4*8)+8(%rsp), %r13
            \\        movq (8*8)+8(%rsp), %rbx
            \\        cmovnzq %rbx, %r13
            \\        movq (4*8)+16(%rsp), %r14
            \\        movq (8*8)+16(%rsp), %rbx
            \\        cmovnzq %rbx, %r14
            \\        movq (4*8)+24(%rsp), %r15
            \\        movq (8*8)+24(%rsp), %rbx
            \\        cmovnzq %rbx, %r15
            \\        movq %r12, (4*8)(%rsp)
            \\        movq %r13, (4*8)+8(%rsp)
            \\        movq %r14, (4*8)+16(%rsp)
            \\        movq %r15, (4*8)+24(%rsp)
            \\        cmovzq %rax, %r8
            \\        negq %r8
            \\        sbbq %r8, %r8
            \\        negq %r8
            \\        orq %r8, (30*8)(%rsp)
            \\        movq (4*8)(%rsp), %r8
            \\        movq $-19, %r12
            \\        subq %r8, %r12
            \\        movq (4*8)+8(%rsp), %r9
            \\        movq $-1, %r13
            \\        sbbq %r9, %r13
            \\        movq (4*8)+16(%rsp), %r10
            \\        movq $-1, %r14
            \\        sbbq %r10, %r14
            \\        movq (4*8)+24(%rsp), %r11
            \\        movq $0x7FFFFFFFFFFFFFFF, %r15
            \\        sbbq %r11, %r15
            \\        movl $1, %ecx
            \\        andq %r8, %rcx
            \\        xorq (29*8)(%rsp), %rcx
            \\        movq (30*8)(%rsp), %rdx
            \\        movq %rdx, %rsi
            \\        orq %rcx, %rdx
            \\        xorl %ebp, %ebp
            \\        movq %r8, %rax
            \\        movq %r9, %rbx
            \\        orq %r10, %rax
            \\        orq %r11, %rbx
            \\        orq %rbx, %rax
            \\        cmovzq %rbp, %rcx
            \\        cmovnzq %rsi, %rdx
            \\        testq %rcx, %rcx
            \\        cmovnzq %r12, %r8
            \\        cmovnzq %r13, %r9
            \\        cmovnzq %r14, %r10
            \\        cmovnzq %r15, %r11
            \\        movq (28*8)(%rsp), %rdi
            \\        movq %r8, (%rdi)
            \\        movq %r9, 8(%rdi)
            \\        movq %r10, 16(%rdi)
            \\        movq %r11, 24(%rdi)
            \\        movq 0(%rsp), %rcx
            \\        movq %rcx, 32(%rdi)
            \\        movq 0 +8(%rsp), %rcx
            \\        movq %rcx, 40(%rdi)
            \\        movq 0 +16(%rsp), %rcx
            \\        movq %rcx, 48(%rdi)
            \\        movq 0 +24(%rsp), %rcx
            \\        movq %rcx, 56(%rdi)
            \\        movq %rdx, %rax
            \\        addq $32*8, %rsp ; .cfi_adjust_cfa_offset -32*8
            \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
            \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
            \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
            \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
            \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
            \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
            \\        retq ; .cfi_endproc
            \\.size vailEd25519Decode, .-vailEd25519Decode
            \\        .text
            \\vailEd25519FieldMul:
            \\        .cfi_startproc
            \\        endbr64
            \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
            \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
            \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
            \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
            \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
            \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
            \\        subq $8, %rsp ; .cfi_adjust_cfa_offset 8
            \\        callq LvailEd25519Decode_mul_p25519
            \\        addq $8, %rsp ; .cfi_adjust_cfa_offset -8
            \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
            \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
            \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
            \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
            \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
            \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
            \\        retq ; .cfi_endproc
            \\.size vailEd25519FieldMul, .-vailEd25519FieldMul
            \\.type LvailEd25519Decode_mul_p25519, %function
            \\LvailEd25519Decode_mul_p25519:
            \\        .cfi_startproc
            \\        movq %rdx, %rcx
            \\        xorl %ebp, %ebp
            \\        movq (%rcx), %rdx
            \\        mulxq (%rsi), %r8, %r9
            \\        mulxq 0x8(%rsi), %rax, %r10
            \\        addq %rax, %r9
            \\        mulxq 0x10(%rsi), %rax, %r11
            \\        adcq %rax, %r10
            \\        mulxq 0x18(%rsi), %rax, %r12
            \\        adcq %rax, %r11
            \\        adcq %rbp, %r12
            \\        xorl %ebp, %ebp
            \\        movq 0x8(%rcx), %rdx
            \\        mulxq (%rsi), %rax, %rbx
            \\        adcxq %rax, %r9
            \\        adoxq %rbx, %r10
            \\        mulxq 0x8(%rsi), %rax, %rbx
            \\        adcxq %rax, %r10
            \\        adoxq %rbx, %r11
            \\        mulxq 0x10(%rsi), %rax, %rbx
            \\        adcxq %rax, %r11
            \\        adoxq %rbx, %r12
            \\        mulxq 0x18(%rsi), %rax, %r13
            \\        adcxq %rax, %r12
            \\        adoxq %rbp, %r13
            \\        adcq %rbp, %r13
            \\        xorl %ebp, %ebp
            \\        movq 0x10(%rcx), %rdx
            \\        mulxq (%rsi), %rax, %rbx
            \\        adcxq %rax, %r10
            \\        adoxq %rbx, %r11
            \\        mulxq 0x8(%rsi), %rax, %rbx
            \\        adcxq %rax, %r11
            \\        adoxq %rbx, %r12
            \\        mulxq 0x10(%rsi), %rax, %rbx
            \\        adcxq %rax, %r12
            \\        adoxq %rbx, %r13
            \\        mulxq 0x18(%rsi), %rax, %r14
            \\        adcxq %rax, %r13
            \\        adoxq %rbp, %r14
            \\        adcq %rbp, %r14
            \\        xorl %ebp, %ebp
            \\        movq 0x18(%rcx), %rdx
            \\        mulxq (%rsi), %rax, %rbx
            \\        adcxq %rax, %r11
            \\        adoxq %rbx, %r12
            \\        mulxq 0x18(%rsi), %rcx, %r15
            \\        mulxq 0x8(%rsi), %rax, %rbx
            \\        adcxq %rax, %r12
            \\        adoxq %rbx, %r13
            \\        mulxq 0x10(%rsi), %rax, %rbx
            \\        adcxq %rax, %r13
            \\        adoxq %rbx, %r14
            \\        movl $0x26, %edx
            \\        mulxq %r15, %rax, %rbx
            \\        adcxq %rcx, %r14
            \\        adoxq %rbp, %r15
            \\        adcq %rbp, %r15
            \\        addq %r11, %rax
            \\        adcq %rbp, %rbx
            \\        btq $0x3f, %rax
            \\        adcq %rbx, %rbx
            \\        leaq 0x1(%rbx), %rcx
            \\        imulq $0x13, %rcx, %rcx
            \\        xorl %ebp, %ebp
            \\        adoxq %rcx, %r8
            \\        mulxq %r12, %rax, %rbx
            \\        adcxq %rax, %r8
            \\        adoxq %rbx, %r9
            \\        mulxq %r13, %rax, %rbx
            \\        adcxq %rax, %r9
            \\        adoxq %rbx, %r10
            \\        mulxq %r14, %rax, %rbx
            \\        adcxq %rax, %r10
            \\        adoxq %rbx, %r11
            \\        mulxq %r15, %rax, %rbx
            \\        adcq %rax, %r11
            \\        shlq $0x3f, %rcx
            \\        cmpq %rcx, %r11
            \\        movl $0x13, %eax
            \\        cmovns %rbp, %rax
            \\        subq %rax, %r8
            \\        sbbq %rbp, %r9
            \\        sbbq %rbp, %r10
            \\        sbbq %rbp, %r11
            \\        btr $0x3f, %r11
            \\        movq %r8, (%rdi)
            \\        movq %r9, 0x8(%rdi)
            \\        movq %r10, 0x10(%rdi)
            \\        movq %r11, 0x18(%rdi)
            \\        retq ; .cfi_endproc
            \\.size LvailEd25519Decode_mul_p25519, .-LvailEd25519Decode_mul_p25519
            \\.type LvailEd25519Decode_nsqr_p25519, %function
            \\LvailEd25519Decode_nsqr_p25519:
            \\        .cfi_startproc
            \\        movq (%rdx), %rax
            \\        movq 8(%rdx), %rbx
            \\        movq 16(%rdx), %rcx
            \\        movq 24(%rdx), %rdx
            \\        movq %rax, (25*8)(%rsp)
            \\        movq %rbx, (25*8)+8(%rsp)
            \\        movq %rcx, (25*8)+16(%rsp)
            \\        movq %rdx, (25*8)+24(%rsp)
            \\LvailEd25519Decode_loop:
            \\        movq (25*8)(%rsp), %rdx
            \\        mulxq %rdx, %r8, %r15
            \\        mulxq (25*8)+0x8(%rsp), %r9, %r10
            \\        mulxq (25*8)+0x18(%rsp), %r11, %r12
            \\        movq (25*8)+0x10(%rsp), %rdx
            \\        mulxq (25*8)+0x18(%rsp), %r13, %r14
            \\        xorl %ebx, %ebx
            \\        mulxq (25*8)(%rsp), %rax, %rcx
            \\        adcxq %rax, %r10
            \\        adoxq %rcx, %r11
            \\        mulxq (25*8)+0x8(%rsp), %rax, %rcx
            \\        adcxq %rax, %r11
            \\        adoxq %rcx, %r12
            \\        movq (25*8)+0x18(%rsp), %rdx
            \\        mulxq (25*8)+0x8(%rsp), %rax, %rcx
            \\        adcxq %rax, %r12
            \\        adoxq %rcx, %r13
            \\        adcxq %rbx, %r13
            \\        adoxq %rbx, %r14
            \\        adcq %rbx, %r14
            \\        xorl %ebx, %ebx
            \\        adcxq %r9, %r9
            \\        adoxq %r15, %r9
            \\        movq (25*8)+0x8(%rsp), %rdx
            \\        mulxq %rdx, %rax, %rdx
            \\        adcxq %r10, %r10
            \\        adoxq %rax, %r10
            \\        adcxq %r11, %r11
            \\        adoxq %rdx, %r11
            \\        movq (25*8)+0x10(%rsp), %rdx
            \\        mulxq %rdx, %rax, %rdx
            \\        adcxq %r12, %r12
            \\        adoxq %rax, %r12
            \\        adcxq %r13, %r13
            \\        adoxq %rdx, %r13
            \\        movq (25*8)+0x18(%rsp), %rdx
            \\        mulxq %rdx, %rax, %r15
            \\        adcxq %r14, %r14
            \\        adoxq %rax, %r14
            \\        adcxq %rbx, %r15
            \\        adoxq %rbx, %r15
            \\        movl $0x26, %edx
            \\        xorl %ebx, %ebx
            \\        mulxq %r12, %rax, %rcx
            \\        adcxq %rax, %r8
            \\        adoxq %rcx, %r9
            \\        mulxq %r13, %rax, %rcx
            \\        adcxq %rax, %r9
            \\        adoxq %rcx, %r10
            \\        mulxq %r14, %rax, %rcx
            \\        adcxq %rax, %r10
            \\        adoxq %rcx, %r11
            \\        mulxq %r15, %rax, %r12
            \\        adcxq %rax, %r11
            \\        adoxq %rbx, %r12
            \\        adcxq %rbx, %r12
            \\        shldq $0x1, %r11, %r12
            \\        btr $0x3f, %r11
            \\        movl $0x13, %edx
            \\        imulq %r12, %rdx
            \\        addq %rdx, %r8
            \\        adcq %rbx, %r9
            \\        adcq %rbx, %r10
            \\        adcq %rbx, %r11
            \\        movq %r8, (25*8)(%rsp)
            \\        movq %r9, (25*8)+0x8(%rsp)
            \\        movq %r10, (25*8)+0x10(%rsp)
            \\        movq %r11, (25*8)+0x18(%rsp)
            \\        decq %rsi
            \\        jnz LvailEd25519Decode_loop
            \\        movl $19, %eax
            \\        xorl %ebx, %ebx
            \\        xorl %ecx, %ecx
            \\        xorl %edx, %edx
            \\        addq %r8, %rax
            \\        adcq %r9, %rbx
            \\        adcq %r10, %rcx
            \\        adcq %r11, %rdx
            \\        cmovns %r8, %rax
            \\        cmovns %r9, %rbx
            \\        cmovns %r10, %rcx
            \\        cmovns %r11, %rdx
            \\        btr $63, %rdx
            \\        movq %rax, (%rdi)
            \\        movq %rbx, 8(%rdi)
            \\        movq %rcx, 16(%rdi)
            \\        movq %rdx, 24(%rdi)
            \\        retq ; .cfi_endproc
            \\.size LvailEd25519Decode_nsqr_p25519, .-LvailEd25519Decode_nsqr_p25519
        );
    }
}

test "ADX p25519 multiplication matches Zig std" {
    if (comptime !enabled) return error.SkipZigTest;
    const Fe = std.crypto.ecc.Edwards25519.Fe;
    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..256) |_| {
        var left_bytes: [32]u8 = undefined;
        var right_bytes: [32]u8 = undefined;
        inline for (0..8) |index| {
            state +%= 0x9e37_79b9_7f4a_7c15;
            var value = state;
            value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
            value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
            value ^= value >> 31;
            const output = if (index < 4) &left_bytes else &right_bytes;
            std.mem.writeInt(u64, output[(index % 4) * 8 ..][0..8], value, .little);
        }
        left_bytes = Fe.fromBytes(left_bytes).toBytes();
        right_bytes = Fe.fromBytes(right_bytes).toBytes();

        var left: [4]u64 = undefined;
        var right: [4]u64 = undefined;
        inline for (0..4) |index| {
            left[index] = std.mem.readInt(
                u64,
                left_bytes[index * 8 ..][0..8],
                .little,
            );
            right[index] = std.mem.readInt(
                u64,
                right_bytes[index * 8 ..][0..8],
                .little,
            );
        }
        var product: [4]u64 = undefined;
        fieldMul(&product, &left, &right);
        var product_bytes: [32]u8 = undefined;
        inline for (0..4) |index| {
            std.mem.writeInt(
                u64,
                product_bytes[index * 8 ..][0..8],
                product[index],
                .little,
            );
        }
        try std.testing.expectEqual(
            Fe.fromBytes(left_bytes).mul(Fe.fromBytes(right_bytes)).toBytes(),
            product_bytes,
        );
    }
}
