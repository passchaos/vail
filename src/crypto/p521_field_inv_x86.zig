//! Constant-time x86_64 P-521 field inversion embedded in Zig.
//!
//! The instruction schedule comes from the formally verified s2n-bignum
//! implementation.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const std = @import("std");
const builtin = @import("builtin");

pub const enabled = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug;

pub fn invert(input: *const [9]u64) [9]u64 {
    if (comptime !enabled) @compileError("x86_64 P-521 inversion is unavailable");
    var output: [9]u64 = undefined;
    vailP521FieldInvert(&output, input);
    return output;
}

extern fn vailP521FieldInvert(
    output: *[9]u64,
    input: *const [9]u64,
) callconv(.c) void;

comptime {
    if (enabled) {
        asm (
            \\       
            \\        .text
            \\vailP521FieldInvert:
            \\        .cfi_startproc
            \\        endbr64
            \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
            \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
            \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
            \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
            \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
            \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
            \\        subq $45*8, %rsp ; .cfi_adjust_cfa_offset 45*8
            \\        movq %rdi, (44*8)(%rsp)
            \\        xorl %eax, %eax
            \\        notq %rax
            \\        movq %rax, 0(%rsp)
            \\        movq %rax, 0 +8(%rsp)
            \\        movq %rax, 0 +16(%rsp)
            \\        movq %rax, 0 +24(%rsp)
            \\        movq %rax, 0 +32(%rsp)
            \\        movq %rax, 0 +40(%rsp)
            \\        movq %rax, 0 +48(%rsp)
            \\        movq %rax, 0 +56(%rsp)
            \\        movl $0x1FF, %eax
            \\        movq %rax, 0 +64(%rsp)
            \\        movq 64(%rsi), %r8
            \\        movl $0x1FF, %ebx
            \\        andq %r8, %rbx
            \\        shrq $9, %r8
            \\        stc
            \\        adcq (%rsi), %r8
            \\        movq 8(%rsi), %r9
            \\        adcq $0, %r9
            \\        movq 16(%rsi), %r10
            \\        adcq $0, %r10
            \\        movq 24(%rsi), %r11
            \\        adcq $0, %r11
            \\        movq 32(%rsi), %r12
            \\        adcq $0, %r12
            \\        movq 40(%rsi), %r13
            \\        adcq $0, %r13
            \\        movq 48(%rsi), %r14
            \\        adcq $0, %r14
            \\        movq 56(%rsi), %r15
            \\        adcq $0, %r15
            \\        adcq $0, %rbx
            \\        cmpq $512, %rbx
            \\        sbbq $0, %r8
            \\        movq %r8, (9*8)(%rsp)
            \\        sbbq $0, %r9
            \\        movq %r9, (9*8)+8(%rsp)
            \\        sbbq $0, %r10
            \\        movq %r10, (9*8)+16(%rsp)
            \\        sbbq $0, %r11
            \\        movq %r11, (9*8)+24(%rsp)
            \\        sbbq $0, %r12
            \\        movq %r12, (9*8)+32(%rsp)
            \\        sbbq $0, %r13
            \\        movq %r13, (9*8)+40(%rsp)
            \\        sbbq $0, %r14
            \\        movq %r14, (9*8)+48(%rsp)
            \\        sbbq $0, %r15
            \\        movq %r15, (9*8)+56(%rsp)
            \\        sbbq $0, %rbx
            \\        andq $0x1FF, %rbx
            \\        movq %rbx, (9*8)+64(%rsp)
            \\        xorl %eax, %eax
            \\        movq %rax, (18*8)(%rsp)
            \\        movq %rax, (18*8)+8(%rsp)
            \\        movq %rax, (18*8)+16(%rsp)
            \\        movq %rax, (18*8)+24(%rsp)
            \\        movq %rax, (18*8)+32(%rsp)
            \\        movq %rax, (18*8)+40(%rsp)
            \\        movq %rax, (18*8)+48(%rsp)
            \\        movq %rax, (18*8)+56(%rsp)
            \\        movq %rax, (18*8)+64(%rsp)
            \\        movl $16, %ebx
            \\        movq %rax, (27*8)(%rsp)
            \\        movq %rax, (27*8)+8(%rsp)
            \\        movq %rax, (27*8)+16(%rsp)
            \\        movq %rax, (27*8)+24(%rsp)
            \\        movq %rax, (27*8)+32(%rsp)
            \\        movq %rbx, (27*8)+40(%rsp)
            \\        movq %rax, (27*8)+48(%rsp)
            \\        movq %rax, (27*8)+56(%rsp)
            \\        movq %rax, (27*8)+64(%rsp)
            \\        movq $21, (38*8)(%rsp)
            \\        movq $1, (39*8)(%rsp)
            \\        jmp Lvail_p521_inv_midloop
            \\Lvail_p521_inv_loop:
            \\        movq %r8, %r9
            \\        sarq $63, %r9
            \\        xorq %r9, %r8
            \\        subq %r9, %r8
            \\        movq %r10, %r11
            \\        sarq $63, %r11
            \\        xorq %r11, %r10
            \\        subq %r11, %r10
            \\        movq %r12, %r13
            \\        sarq $63, %r13
            \\        xorq %r13, %r12
            \\        subq %r13, %r12
            \\        movq %r14, %r15
            \\        sarq $63, %r15
            \\        xorq %r15, %r14
            \\        subq %r15, %r14
            \\        movq %r8, %rax
            \\        andq %r9, %rax
            \\        movq %r10, %rdi
            \\        andq %r11, %rdi
            \\        addq %rax, %rdi
            \\        movq %rdi, (36*8)(%rsp)
            \\        movq %r12, %rax
            \\        andq %r13, %rax
            \\        movq %r14, %rsi
            \\        andq %r15, %rsi
            \\        addq %rax, %rsi
            \\        movq %rsi, (37*8)(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq 0(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        movq (9*8)(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        xorl %ebp, %ebp
            \\        movq 0(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (9*8)(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        xorl %ecx, %ecx
            \\        movq 0 +8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (9*8)+8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        shrdq $59, %rbx, %rdi
            \\        movq %rdi, 0(%rsp)
            \\        xorl %edi, %edi
            \\        movq 0 +8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rdi
            \\        movq (9*8)+8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rdi
            \\        shrdq $59, %rbp, %rsi
            \\        movq %rsi, (9*8)(%rsp)
            \\        xorl %esi, %esi
            \\        movq 0 +2*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rsi
            \\        movq (9*8)+2*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rsi
            \\        shrdq $59, %rcx, %rbx
            \\        movq %rbx, 0 +8(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq 0 +2*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        movq (9*8)+2*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        shrdq $59, %rdi, %rbp
            \\        movq %rbp, (9*8)+8(%rsp)
            \\        xorl %ebp, %ebp
            \\        movq 0 +3*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (9*8)+3*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        shrdq $59, %rsi, %rcx
            \\        movq %rcx, 0 +2*8(%rsp)
            \\        xorl %ecx, %ecx
            \\        movq 0 +3*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (9*8)+3*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        shrdq $59, %rbx, %rdi
            \\        movq %rdi, (9*8)+2*8(%rsp)
            \\        xorl %edi, %edi
            \\        movq 0 +4*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rdi
            \\        movq (9*8)+4*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rdi
            \\        shrdq $59, %rbp, %rsi
            \\        movq %rsi, 0 +3*8(%rsp)
            \\        xorl %esi, %esi
            \\        movq 0 +4*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rsi
            \\        movq (9*8)+4*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rsi
            \\        shrdq $59, %rcx, %rbx
            \\        movq %rbx, (9*8)+3*8(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq 0 +5*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        movq (9*8)+5*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        shrdq $59, %rdi, %rbp
            \\        movq %rbp, 0 +4*8(%rsp)
            \\        xorl %ebp, %ebp
            \\        movq 0 +5*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (9*8)+5*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        shrdq $59, %rsi, %rcx
            \\        movq %rcx, (9*8)+4*8(%rsp)
            \\        xorl %ecx, %ecx
            \\        movq 0 +6*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (9*8)+6*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        shrdq $59, %rbx, %rdi
            \\        movq %rdi, 0 +5*8(%rsp)
            \\        xorl %edi, %edi
            \\        movq 0 +6*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rdi
            \\        movq (9*8)+6*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rdi
            \\        shrdq $59, %rbp, %rsi
            \\        movq %rsi, (9*8)+5*8(%rsp)
            \\        xorl %esi, %esi
            \\        movq 0 +7*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rsi
            \\        movq (9*8)+7*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rsi
            \\        shrdq $59, %rcx, %rbx
            \\        movq %rbx, 0 +6*8(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq 0 +7*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        movq (9*8)+7*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        shrdq $59, %rdi, %rbp
            \\        movq %rbp, (9*8)+6*8(%rsp)
            \\        movq 0 +8*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        movq %rax, %rbp
            \\        sarq $63, %rbp
            \\        andq %r8, %rbp
            \\        negq %rbp
            \\        mulq %r8
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (9*8)+8*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        movq %rax, %rdx
            \\        sarq $63, %rdx
            \\        andq %r10, %rdx
            \\        subq %rdx, %rbp
            \\        mulq %r10
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        shrdq $59, %rsi, %rcx
            \\        movq %rcx, 0 +7*8(%rsp)
            \\        shrdq $59, %rbp, %rsi
            \\        movq 0 +8*8(%rsp), %rax
            \\        movq %rsi, 0 +8*8(%rsp)
            \\        xorq %r13, %rax
            \\        movq %rax, %rsi
            \\        sarq $63, %rsi
            \\        andq %r12, %rsi
            \\        negq %rsi
            \\        mulq %r12
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rsi
            \\        movq (9*8)+8*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        movq %rax, %rdx
            \\        sarq $63, %rdx
            \\        andq %r14, %rdx
            \\        subq %rdx, %rsi
            \\        mulq %r14
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rsi
            \\        shrdq $59, %rbx, %rdi
            \\        movq %rdi, (9*8)+7*8(%rsp)
            \\        shrdq $59, %rsi, %rbx
            \\        movq %rbx, (9*8)+8*8(%rsp)
            \\        movq (36*8)(%rsp), %rbx
            \\        movq (37*8)(%rsp), %rbp
            \\        xorl %ecx, %ecx
            \\        movq (18*8)(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        xorl %esi, %esi
            \\        movq (18*8)(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rbx, (18*8)(%rsp)
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq (27*8)(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq %rbp, (27*8)(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        xorl %ebp, %ebp
            \\        movq (18*8)+8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rcx, (18*8)+8(%rsp)
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (27*8)+8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq %rsi, (27*8)+8(%rsp)
            \\        xorl %ecx, %ecx
            \\        movq (18*8)+2*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+2*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        xorl %esi, %esi
            \\        movq (18*8)+2*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rbx, (18*8)+2*8(%rsp)
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq (27*8)+2*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq %rbp, (27*8)+2*8(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+3*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+3*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        xorl %ebp, %ebp
            \\        movq (18*8)+3*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rcx, (18*8)+3*8(%rsp)
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (27*8)+3*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq %rsi, (27*8)+3*8(%rsp)
            \\        xorl %ecx, %ecx
            \\        movq (18*8)+4*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+4*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        xorl %esi, %esi
            \\        movq (18*8)+4*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rbx, (18*8)+4*8(%rsp)
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq (27*8)+4*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq %rbp, (27*8)+4*8(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+5*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+5*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        xorl %ebp, %ebp
            \\        movq (18*8)+5*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rcx, (18*8)+5*8(%rsp)
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (27*8)+5*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq %rsi, (27*8)+5*8(%rsp)
            \\        xorl %ecx, %ecx
            \\        movq (18*8)+6*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+6*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        xorl %esi, %esi
            \\        movq (18*8)+6*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rbx, (18*8)+6*8(%rsp)
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq (27*8)+6*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq %rbp, (27*8)+6*8(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+7*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+7*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        xorl %ebp, %ebp
            \\        movq (18*8)+7*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rcx, (18*8)+7*8(%rsp)
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (27*8)+7*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq %rsi, (27*8)+7*8(%rsp)
            \\        movq (18*8)+8*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        movq %r9, %rcx
            \\        andq %r8, %rcx
            \\        negq %rcx
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+8*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        movq %r11, %rdx
            \\        andq %r10, %rdx
            \\        subq %rdx, %rcx
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rcx, %rdx
            \\        movq %rdx, %rax
            \\        shldq $55, %rbx, %rdx
            \\        sarq $63, %rax
            \\        addq %rax, %rdx
            \\        movq %rdx, %rax
            \\        shlq $9, %rdx
            \\        subq %rdx, %rbx
            \\        movq %rax, %rdx
            \\        sarq $63, %rax
            \\        movq (18*8)(%rsp), %rcx
            \\        addq %rdx, %rcx
            \\        movq %rcx, (18*8)(%rsp)
            \\        movq (18*8)+8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+8(%rsp)
            \\        movq (18*8)+2*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+2*8(%rsp)
            \\        movq (18*8)+3*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+3*8(%rsp)
            \\        movq (18*8)+4*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+4*8(%rsp)
            \\        movq (18*8)+5*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+5*8(%rsp)
            \\        movq (18*8)+6*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+6*8(%rsp)
            \\        movq (18*8)+7*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+7*8(%rsp)
            \\        adcq %rax, %rbx
            \\        movq (18*8)+8*8(%rsp), %rax
            \\        movq %rbx, (18*8)+8*8(%rsp)
            \\        xorq %r13, %rax
            \\        movq %r13, %rbx
            \\        andq %r12, %rbx
            \\        negq %rbx
            \\        mulq %r12
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+8*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        movq %r15, %rdx
            \\        andq %r14, %rdx
            \\        subq %rdx, %rbx
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rbx, %rdx
            \\        movq %rdx, %rax
            \\        shldq $55, %rbp, %rdx
            \\        sarq $63, %rax
            \\        addq %rax, %rdx
            \\        movq %rdx, %rax
            \\        shlq $9, %rdx
            \\        subq %rdx, %rbp
            \\        movq %rax, %rdx
            \\        sarq $63, %rax
            \\        movq (27*8)(%rsp), %rcx
            \\        addq %rdx, %rcx
            \\        movq %rcx, (27*8)(%rsp)
            \\        movq (27*8)+8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (27*8)+8(%rsp)
            \\        movq (27*8)+2*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (27*8)+2*8(%rsp)
            \\        movq (27*8)+3*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (27*8)+3*8(%rsp)
            \\        movq (27*8)+4*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (27*8)+4*8(%rsp)
            \\        movq (27*8)+5*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (27*8)+5*8(%rsp)
            \\        movq (27*8)+6*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (27*8)+6*8(%rsp)
            \\        movq (27*8)+7*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (27*8)+7*8(%rsp)
            \\        adcq %rax, %rbp
            \\        movq %rbp, (27*8)+8*8(%rsp)
            \\Lvail_p521_inv_midloop:
            \\        movq (39*8)(%rsp), %rsi ; movq (%rsp), %rdx ; movq (9*8)(%rsp), %rcx ; movq %rdx, %rbx ; andq $0xfffff, %rbx ; movabsq $0xfffffe0000000000, %rax ; orq %rax, %rbx ; andq $0xfffff, %rcx ; movabsq $0xc000000000000000, %rax ; orq %rax, %rcx ; movq $0xfffffffffffffffe, %rax ; xorl %ebp, %ebp ; movl $0x2, %edx ; movq %rbx, %rdi ; movq %rax, %r8 ; testq %rsi, %rsi ; cmovs %rbp, %r8 ; testq $0x1, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; sarq $1, %rcx ; movl $0x100000, %eax ; leaq (%rbx,%rax), %rdx ; leaq (%rcx,%rax), %rdi ; shlq $0x16, %rdx ; shlq $0x16, %rdi ; sarq $0x2b, %rdx ; sarq $0x2b, %rdi ; movabsq $0x20000100000, %rax ; leaq (%rbx,%rax), %rbx ; leaq (%rcx,%rax), %rcx ; sarq $0x2a, %rbx ; sarq $0x2a, %rcx ; movq %rdx, (40*8)(%rsp) ; movq %rbx, (40*8)+0x8(%rsp) ; movq %rdi, (40*8)+0x10(%rsp) ; movq %rcx, (40*8)+0x18(%rsp) ; movq (%rsp), %r12 ; imulq %r12, %rdi ; imulq %rdx, %r12 ; movq (9*8)(%rsp), %r13 ; imulq %r13, %rbx ; imulq %rcx, %r13 ; addq %rbx, %r12 ; addq %rdi, %r13 ; sarq $0x14, %r12 ; sarq $0x14, %r13 ; movq %r12, %rbx ; andq $0xfffff, %rbx ; movabsq $0xfffffe0000000000, %rax ; orq %rax, %rbx ; movq %r13, %rcx ; andq $0xfffff, %rcx ; movabsq $0xc000000000000000, %rax ; orq %rax, %rcx ; movq $0xfffffffffffffffe, %rax ; movl $0x2, %edx ; movq %rbx, %rdi ; movq %rax, %r8 ; testq %rsi, %rsi ; cmovs %rbp, %r8 ; testq $0x1, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; sarq $1, %rcx ; movl $0x100000, %eax ; leaq (%rbx,%rax), %r8 ; leaq (%rcx,%rax), %r10 ; shlq $0x16, %r8 ; shlq $0x16, %r10 ; sarq $0x2b, %r8 ; sarq $0x2b, %r10 ; movabsq $0x20000100000, %rax ; leaq (%rbx,%rax), %r15 ; leaq (%rcx,%rax), %r11 ; sarq $0x2a, %r15 ; sarq $0x2a, %r11 ; movq %r13, %rbx ; movq %r12, %rcx ; imulq %r8, %r12 ; imulq %r15, %rbx ; addq %rbx, %r12 ; imulq %r11, %r13 ; imulq %r10, %rcx ; addq %rcx, %r13 ; sarq $0x14, %r12 ; sarq $0x14, %r13 ; movq %r12, %rbx ; andq $0xfffff, %rbx ; movabsq $0xfffffe0000000000, %rax ; orq %rax, %rbx ; movq %r13, %rcx ; andq $0xfffff, %rcx ; movabsq $0xc000000000000000, %rax ; orq %rax, %rcx ; movq (40*8)(%rsp), %rax ; imulq %r8, %rax ; movq (40*8)+0x10(%rsp), %rdx ; imulq %r15, %rdx ; imulq (40*8)+0x8(%rsp), %r8 ; imulq (40*8)+0x18(%rsp), %r15 ; addq %r8, %r15 ; leaq (%rax,%rdx), %r9 ; movq (40*8)(%rsp), %rax ; imulq %r10, %rax ; movq (40*8)+0x10(%rsp), %rdx ; imulq %r11, %rdx ; imulq (40*8)+0x8(%rsp), %r10 ; imulq (40*8)+0x18(%rsp), %r11 ; addq %r10, %r11 ; leaq (%rax,%rdx), %r13 ; movq $0xfffffffffffffffe, %rax ; movl $0x2, %edx ; movq %rbx, %rdi ; movq %rax, %r8 ; testq %rsi, %rsi ; cmovs %rbp, %r8 ; testq $0x1, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; sarq $1, %rcx ; movl $0x100000, %eax ; leaq (%rbx,%rax), %r8 ; leaq (%rcx,%rax), %r12 ; shlq $0x15, %r8 ; shlq $0x15, %r12 ; sarq $0x2b, %r8 ; sarq $0x2b, %r12 ; movabsq $0x20000100000, %rax ; leaq (%rbx,%rax), %r10 ; leaq (%rcx,%rax), %r14 ; sarq $0x2b, %r10 ; sarq $0x2b, %r14 ; movq %r9, %rax ; imulq %r8, %rax ; movq %r13, %rdx ; imulq %r10, %rdx ; imulq %r15, %r8 ; imulq %r11, %r10 ; addq %r8, %r10 ; leaq (%rax,%rdx), %r8 ; movq %r9, %rax ; imulq %r12, %rax ; movq %r13, %rdx ; imulq %r14, %rdx ; imulq %r15, %r12 ; imulq %r11, %r14 ; addq %r12, %r14 ; leaq (%rax,%rdx), %r12
            \\        movq %rsi, (39*8)(%rsp)
            \\        decq (38*8)(%rsp)
            \\        jnz Lvail_p521_inv_loop
            \\        movq 0(%rsp), %rax
            \\        movq (9*8)(%rsp), %rcx
            \\        imulq %r8, %rax
            \\        imulq %r10, %rcx
            \\        addq %rcx, %rax
            \\        sarq $63, %rax
            \\        movq %r8, %r9
            \\        sarq $63, %r9
            \\        xorq %r9, %r8
            \\        subq %r9, %r8
            \\        xorq %rax, %r9
            \\        movq %r10, %r11
            \\        sarq $63, %r11
            \\        xorq %r11, %r10
            \\        subq %r11, %r10
            \\        xorq %rax, %r11
            \\        movq %r12, %r13
            \\        sarq $63, %r13
            \\        xorq %r13, %r12
            \\        subq %r13, %r12
            \\        xorq %rax, %r13
            \\        movq %r14, %r15
            \\        sarq $63, %r15
            \\        xorq %r15, %r14
            \\        subq %r15, %r14
            \\        xorq %rax, %r15
            \\        movq %r8, %rax
            \\        andq %r9, %rax
            \\        movq %r10, %rbx
            \\        andq %r11, %rbx
            \\        addq %rax, %rbx
            \\        xorl %ecx, %ecx
            \\        movq (18*8)(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        movq %rbx, (18*8)(%rsp)
            \\        adcq %rdx, %rcx
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        movq %rcx, (18*8)+8(%rsp)
            \\        adcq %rdx, %rbx
            \\        xorl %ecx, %ecx
            \\        movq (18*8)+2*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+2*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        movq %rbx, (18*8)+2*8(%rsp)
            \\        adcq %rdx, %rcx
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+3*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+3*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        movq %rcx, (18*8)+3*8(%rsp)
            \\        adcq %rdx, %rbx
            \\        xorl %ecx, %ecx
            \\        movq (18*8)+4*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+4*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        movq %rbx, (18*8)+4*8(%rsp)
            \\        adcq %rdx, %rcx
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+5*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+5*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        movq %rcx, (18*8)+5*8(%rsp)
            \\        adcq %rdx, %rbx
            \\        xorl %ecx, %ecx
            \\        movq (18*8)+6*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+6*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        movq %rbx, (18*8)+6*8(%rsp)
            \\        adcq %rdx, %rcx
            \\        xorl %ebx, %ebx
            \\        movq (18*8)+7*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (27*8)+7*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        movq %rcx, (18*8)+7*8(%rsp)
            \\        adcq %rdx, %rbx
            \\        movq (18*8)+8*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        movq %r9, %rcx
            \\        andq %r8, %rcx
            \\        negq %rcx
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (27*8)+8*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        movq %r11, %rdx
            \\        andq %r10, %rdx
            \\        subq %rdx, %rcx
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rcx, %rdx
            \\        movq %rdx, %rax
            \\        shldq $55, %rbx, %rdx
            \\        sarq $63, %rax
            \\        addq %rax, %rdx
            \\        movq %rdx, %rax
            \\        shlq $9, %rdx
            \\        subq %rdx, %rbx
            \\        movq %rax, %rdx
            \\        sarq $63, %rax
            \\        movq (18*8)(%rsp), %rcx
            \\        addq %rdx, %rcx
            \\        movq %rcx, (18*8)(%rsp)
            \\        movq (18*8)+8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+8(%rsp)
            \\        movq (18*8)+2*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+2*8(%rsp)
            \\        movq (18*8)+3*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+3*8(%rsp)
            \\        movq (18*8)+4*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+4*8(%rsp)
            \\        movq (18*8)+5*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+5*8(%rsp)
            \\        movq (18*8)+6*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+6*8(%rsp)
            \\        movq (18*8)+7*8(%rsp), %rcx
            \\        adcq %rax, %rcx
            \\        movq %rcx, (18*8)+7*8(%rsp)
            \\        adcq %rax, %rbx
            \\        movq %rbx, (18*8)+8*8(%rsp)
            \\        xorl %eax, %eax
            \\        notq %rax
            \\        movq (18*8)(%rsp), %r8
            \\        subq %rax, %r8
            \\        movq (18*8)+8(%rsp), %r9
            \\        sbbq %rax, %r9
            \\        movq (18*8)+2*8(%rsp), %r10
            \\        sbbq %rax, %r10
            \\        movq (18*8)+3*8(%rsp), %r11
            \\        sbbq %rax, %r11
            \\        movq (18*8)+4*8(%rsp), %r12
            \\        sbbq %rax, %r12
            \\        movq (18*8)+5*8(%rsp), %r13
            \\        sbbq %rax, %r13
            \\        movq (18*8)+6*8(%rsp), %r14
            \\        sbbq %rax, %r14
            \\        movq (18*8)+7*8(%rsp), %r15
            \\        sbbq %rax, %r15
            \\        movl $0x1FF, %eax
            \\        movq (18*8)+8*8(%rsp), %rbp
            \\        sbbq %rax, %rbp
            \\        cmovcq (18*8)(%rsp), %r8
            \\        cmovcq (18*8)+8(%rsp), %r9
            \\        cmovcq (18*8)+2*8(%rsp), %r10
            \\        cmovcq (18*8)+3*8(%rsp), %r11
            \\        cmovcq (18*8)+4*8(%rsp), %r12
            \\        cmovcq (18*8)+5*8(%rsp), %r13
            \\        cmovcq (18*8)+6*8(%rsp), %r14
            \\        cmovcq (18*8)+7*8(%rsp), %r15
            \\        cmovcq (18*8)+8*8(%rsp), %rbp
            \\        movq (44*8)(%rsp), %rdi
            \\        movq %r8, (%rdi)
            \\        movq %r9, 8(%rdi)
            \\        movq %r10, 2*8(%rdi)
            \\        movq %r11, 3*8(%rdi)
            \\        movq %r12, 4*8(%rdi)
            \\        movq %r13, 5*8(%rdi)
            \\        movq %r14, 6*8(%rdi)
            \\        movq %r15, 7*8(%rdi)
            \\        movq %rbp, 8*8(%rdi)
            \\        pxor %xmm0, %xmm0
            \\        .irp offset, 0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 272, 288, 304, 320, 336
            \\        movdqu %xmm0, \offset(%rsp)
            \\        .endr
            \\        movq $0, 352(%rsp)
            \\        addq $45*8, %rsp ; .cfi_adjust_cfa_offset -45*8
            \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
            \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
            \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
            \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
            \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
            \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
            \\        xorl %eax, %eax
            \\        xorl %ecx, %ecx
            \\        xorl %edx, %edx
            \\        xorl %esi, %esi
            \\        xorl %edi, %edi
            \\        xorl %r8d, %r8d
            \\        xorl %r9d, %r9d
            \\        xorl %r10d, %r10d
            \\        xorl %r11d, %r11d
            \\        retq ; .cfi_endproc
            \\.size vailP521FieldInvert, .-vailP521FieldInvert
        );
    }
}
