//! Constant-time x86_64 P-256 Montgomery field inversion.
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

pub fn invert(input: *const [4]u64) [4]u64 {
    if (comptime !enabled) @compileError("x86_64 P-256 inversion is unavailable");
    var output: [4]u64 = undefined;
    vailP256FieldInvert(&output, input);
    return output;
}

extern fn vailP256FieldInvert(
    output: *[4]u64,
    input: *const [4]u64,
) callconv(.c) void;

comptime {
    if (enabled) {
        asm (
            \\        .text
            \\        .balign 32
            \\vailP256FieldInvert:
            \\        .cfi_startproc
            \\        endbr64
            \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
            \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
            \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
            \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
            \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
            \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
            \\        subq $30*8, %rsp ; .cfi_adjust_cfa_offset 30*8
            \\        movq %rdi, (28*8)(%rsp)
            \\        xorl %ecx, %ecx
            \\        movl $0x00000000ffffffff, %edx
            \\        movq %rdx, %rbx
            \\        leaq -1(%rcx), %rax
            \\        negq %rdx
            \\        movq %rax, 0(%rsp)
            \\        movq %rbx, 0 +8(%rsp)
            \\        movq %rcx, 0 +16(%rsp)
            \\        movq %rdx, 0 +24(%rsp)
            \\        movq %rcx, 0 +32(%rsp)
            \\        movq (%rsi), %r8
            \\        movq 8(%rsi), %r9
            \\        movq 16(%rsi), %r10
            \\        movq 24(%rsi), %r11
            \\        leaq 1(%rcx), %rax
            \\        addq %r8, %rax
            \\        leaq -1(%rdx), %rbx
            \\        adcq %r9, %rbx
            \\        notq %rcx
            \\        adcq %r10, %rcx
            \\        notq %rdx
            \\        adcq %r11, %rdx
            \\        cmovncq %r8, %rax
            \\        cmovncq %r9, %rbx
            \\        cmovncq %r10, %rcx
            \\        cmovncq %r11, %rdx
            \\        movq %rax, (5*8)(%rsp)
            \\        movq %rbx, (5*8)+8(%rsp)
            \\        movq %rcx, (5*8)+16(%rsp)
            \\        movq %rdx, (5*8)+24(%rsp)
            \\        xorl %eax, %eax
            \\        movq %rax, (5*8)+32(%rsp)
            \\        xorl %eax, %eax
            \\        movq %rax, (10*8)(%rsp)
            \\        movq %rax, (10*8)+8(%rsp)
            \\        movq %rax, (10*8)+16(%rsp)
            \\        movq %rax, (10*8)+24(%rsp)
            \\        movq $0x000c000000140000, %rax
            \\        movq %rax, (15*8)(%rsp)
            \\        movq $0xffe8000000000000, %rax
            \\        movq %rax, (15*8)+8(%rsp)
            \\        movq $0xfffbffffffefffff, %rax
            \\        movq %rax, (15*8)+16(%rsp)
            \\        movq $0x000bffffffebffff, %rax
            \\        movq %rax, (15*8)+24(%rsp)
            \\        movq $10, (22*8)(%rsp)
            \\        movq $1, (23*8)(%rsp)
            \\        jmp LvailP256FieldInvert_midloop
            \\LvailP256FieldInvert_loop:
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
            \\        movq %rdi, (20*8)(%rsp)
            \\        movq %r12, %rax
            \\        andq %r13, %rax
            \\        movq %r14, %rsi
            \\        andq %r15, %rsi
            \\        addq %rax, %rsi
            \\        movq %rsi, (21*8)(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq 0(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        movq (5*8)(%rsp), %rax
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
            \\        movq (5*8)(%rsp), %rax
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
            \\        movq (5*8)+8(%rsp), %rax
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
            \\        movq (5*8)+8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rdi
            \\        shrdq $59, %rbp, %rsi
            \\        movq %rsi, (5*8)(%rsp)
            \\        xorl %esi, %esi
            \\        movq 0 +2*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rsi
            \\        movq (5*8)+2*8(%rsp), %rax
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
            \\        movq (5*8)+2*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rdi
            \\        adcq %rdx, %rbx
            \\        shrdq $59, %rdi, %rbp
            \\        movq %rbp, (5*8)+8(%rsp)
            \\        movq 0 +3*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        movq 0 +4*8(%rsp), %rbp
            \\        xorq %r9, %rbp
            \\        andq %r8, %rbp
            \\        negq %rbp
            \\        mulq %r8
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (5*8)+3*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        movq (5*8)+4*8(%rsp), %rdx
            \\        xorq %r11, %rdx
            \\        andq %r10, %rdx
            \\        subq %rdx, %rbp
            \\        mulq %r10
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        shrdq $59, %rsi, %rcx
            \\        movq %rcx, 0 +2*8(%rsp)
            \\        shrdq $59, %rbp, %rsi
            \\        sarq $59, %rbp
            \\        movq 0 +3*8(%rsp), %rax
            \\        movq %rsi, 0 +3*8(%rsp)
            \\        movq 0 +4*8(%rsp), %rsi
            \\        movq %rbp, 0 +4*8(%rsp)
            \\        xorq %r13, %rax
            \\        xorq %r13, %rsi
            \\        andq %r12, %rsi
            \\        negq %rsi
            \\        mulq %r12
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rsi
            \\        movq (5*8)+3*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        movq (5*8)+4*8(%rsp), %rdx
            \\        xorq %r15, %rdx
            \\        andq %r14, %rdx
            \\        subq %rdx, %rsi
            \\        mulq %r14
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rsi
            \\        shrdq $59, %rbx, %rdi
            \\        movq %rdi, (5*8)+2*8(%rsp)
            \\        shrdq $59, %rsi, %rbx
            \\        movq %rbx, (5*8)+3*8(%rsp)
            \\        sarq $59, %rsi
            \\        movq %rsi, (5*8)+4*8(%rsp)
            \\        movq (20*8)(%rsp), %rbx
            \\        movq (21*8)(%rsp), %rbp
            \\        xorl %ecx, %ecx
            \\        movq (10*8)(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (15*8)(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        xorl %esi, %esi
            \\        movq (10*8)(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rbx, (10*8)(%rsp)
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq (15*8)(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq %rbp, (15*8)(%rsp)
            \\        xorl %ebx, %ebx
            \\        movq (10*8)+8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (15*8)+8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        xorl %ebp, %ebp
            \\        movq (10*8)+8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rcx, (10*8)+8(%rsp)
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq (15*8)+8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rbp
            \\        movq %rsi, (15*8)+8(%rsp)
            \\        xorl %ecx, %ecx
            \\        movq (10*8)+2*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        movq (15*8)+2*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %rbx
            \\        adcq %rdx, %rcx
            \\        xorl %esi, %esi
            \\        movq (10*8)+2*8(%rsp), %rax
            \\        xorq %r13, %rax
            \\        mulq %r12
            \\        movq %rbx, (10*8)+2*8(%rsp)
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq (15*8)+2*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        mulq %r14
            \\        addq %rax, %rbp
            \\        adcq %rdx, %rsi
            \\        movq %rbp, (15*8)+2*8(%rsp)
            \\        movq (10*8)+3*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        movq %r9, %rbx
            \\        andq %r8, %rbx
            \\        negq %rbx
            \\        mulq %r8
            \\        addq %rax, %rcx
            \\        adcq %rdx, %rbx
            \\        movq (15*8)+3*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        movq %r11, %rdx
            \\        andq %r10, %rdx
            \\        subq %rdx, %rbx
            \\        mulq %r10
            \\        addq %rax, %rcx
            \\        adcq %rbx, %rdx
            \\        movq (10*8)+3*8(%rsp), %rax
            \\        movq %rcx, (10*8)+3*8(%rsp)
            \\        movq %rdx, (10*8)+4*8(%rsp)
            \\        xorq %r13, %rax
            \\        movq %r13, %rcx
            \\        andq %r12, %rcx
            \\        negq %rcx
            \\        mulq %r12
            \\        addq %rax, %rsi
            \\        adcq %rdx, %rcx
            \\        movq (15*8)+3*8(%rsp), %rax
            \\        xorq %r15, %rax
            \\        movq %r15, %rdx
            \\        andq %r14, %rdx
            \\        subq %rdx, %rcx
            \\        mulq %r14
            \\        addq %rax, %rsi
            \\        adcq %rcx, %rdx
            \\        movq %rsi, (15*8)+3*8(%rsp)
            \\        movq %rdx, (15*8)+4*8(%rsp)
            \\        movq $0xe000000000000000, %r8 ; addq (10*8)(%rsp), %r8 ; movq $0xffffffffffffffff, %r9 ; adcq 8+(10*8)(%rsp), %r9 ; movq $0x000000001fffffff, %r10 ; adcq 16+(10*8)(%rsp), %r10 ; movq $0x2000000000000000, %r11 ; adcq 24+(10*8)(%rsp), %r11 ; movq $0x1fffffffe0000000, %r12 ; adcq 32+(10*8)(%rsp), %r12 ; movq %r8, %rbx ; shlq $32, %rbx ; movq $0xffffffff00000001, %rax ; mulq %r8; shrq $32, %r8 ; addq %rbx, %r9 ; adcq %r8, %r10 ; adcq %rax, %r11 ; adcq %rdx, %r12 ; sbbq %rax, %rax ; movl $0x00000000ffffffff, %ebx ; andq %rax, %rbx ; movq $0xffffffff00000001, %rdx ; andq %rax, %rdx ; subq %rax, %r9 ; movq %r9, (10*8)(%rsp) ; sbbq %rbx, %r10 ; movq %r10, 8+(10*8)(%rsp) ; sbbq $0, %r11 ; movq %r11, 16+(10*8)(%rsp) ; sbbq %rdx, %r12 ; movq %r12, 24+(10*8)(%rsp)
            \\        movq $0xe000000000000000, %r8 ; addq (15*8)(%rsp), %r8 ; movq $0xffffffffffffffff, %r9 ; adcq 8+(15*8)(%rsp), %r9 ; movq $0x000000001fffffff, %r10 ; adcq 16+(15*8)(%rsp), %r10 ; movq $0x2000000000000000, %r11 ; adcq 24+(15*8)(%rsp), %r11 ; movq $0x1fffffffe0000000, %r12 ; adcq 32+(15*8)(%rsp), %r12 ; movq %r8, %rbx ; shlq $32, %rbx ; movq $0xffffffff00000001, %rax ; mulq %r8; shrq $32, %r8 ; addq %rbx, %r9 ; adcq %r8, %r10 ; adcq %rax, %r11 ; adcq %rdx, %r12 ; sbbq %rax, %rax ; movl $0x00000000ffffffff, %ebx ; andq %rax, %rbx ; movq $0xffffffff00000001, %rdx ; andq %rax, %rdx ; subq %rax, %r9 ; movq %r9, (15*8)(%rsp) ; sbbq %rbx, %r10 ; movq %r10, 8+(15*8)(%rsp) ; sbbq $0, %r11 ; movq %r11, 16+(15*8)(%rsp) ; sbbq %rdx, %r12 ; movq %r12, 24+(15*8)(%rsp)
            \\LvailP256FieldInvert_midloop:
            \\        movq (23*8)(%rsp), %rsi ; movq (%rsp), %rdx ; movq (5*8)(%rsp), %rcx ; movq %rdx, %rbx ; andq $0xfffff, %rbx ; movabsq $0xfffffe0000000000, %rax ; orq %rax, %rbx ; andq $0xfffff, %rcx ; movabsq $0xc000000000000000, %rax ; orq %rax, %rcx ; movq $0xfffffffffffffffe, %rax ; xorl %ebp, %ebp ; movl $0x2, %edx ; movq %rbx, %rdi ; movq %rax, %r8 ; testq %rsi, %rsi ; cmovs %rbp, %r8 ; testq $0x1, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; sarq $1, %rcx ; movl $0x100000, %eax ; leaq (%rbx,%rax), %rdx ; leaq (%rcx,%rax), %rdi ; shlq $0x16, %rdx ; shlq $0x16, %rdi ; sarq $0x2b, %rdx ; sarq $0x2b, %rdi ; movabsq $0x20000100000, %rax ; leaq (%rbx,%rax), %rbx ; leaq (%rcx,%rax), %rcx ; sarq $0x2a, %rbx ; sarq $0x2a, %rcx ; movq %rdx, (24*8)(%rsp) ; movq %rbx, (24*8)+0x8(%rsp) ; movq %rdi, (24*8)+0x10(%rsp) ; movq %rcx, (24*8)+0x18(%rsp) ; movq (%rsp), %r12 ; imulq %r12, %rdi ; imulq %rdx, %r12 ; movq (5*8)(%rsp), %r13 ; imulq %r13, %rbx ; imulq %rcx, %r13 ; addq %rbx, %r12 ; addq %rdi, %r13 ; sarq $0x14, %r12 ; sarq $0x14, %r13 ; movq %r12, %rbx ; andq $0xfffff, %rbx ; movabsq $0xfffffe0000000000, %rax ; orq %rax, %rbx ; movq %r13, %rcx ; andq $0xfffff, %rcx ; movabsq $0xc000000000000000, %rax ; orq %rax, %rcx ; movq $0xfffffffffffffffe, %rax ; movl $0x2, %edx ; movq %rbx, %rdi ; movq %rax, %r8 ; testq %rsi, %rsi ; cmovs %rbp, %r8 ; testq $0x1, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; sarq $1, %rcx ; movl $0x100000, %eax ; leaq (%rbx,%rax), %r8 ; leaq (%rcx,%rax), %r10 ; shlq $0x16, %r8 ; shlq $0x16, %r10 ; sarq $0x2b, %r8 ; sarq $0x2b, %r10 ; movabsq $0x20000100000, %rax ; leaq (%rbx,%rax), %r15 ; leaq (%rcx,%rax), %r11 ; sarq $0x2a, %r15 ; sarq $0x2a, %r11 ; movq %r13, %rbx ; movq %r12, %rcx ; imulq %r8, %r12 ; imulq %r15, %rbx ; addq %rbx, %r12 ; imulq %r11, %r13 ; imulq %r10, %rcx ; addq %rcx, %r13 ; sarq $0x14, %r12 ; sarq $0x14, %r13 ; movq %r12, %rbx ; andq $0xfffff, %rbx ; movabsq $0xfffffe0000000000, %rax ; orq %rax, %rbx ; movq %r13, %rcx ; andq $0xfffff, %rcx ; movabsq $0xc000000000000000, %rax ; orq %rax, %rcx ; movq (24*8)(%rsp), %rax ; imulq %r8, %rax ; movq (24*8)+0x10(%rsp), %rdx ; imulq %r15, %rdx ; imulq (24*8)+0x8(%rsp), %r8 ; imulq (24*8)+0x18(%rsp), %r15 ; addq %r8, %r15 ; leaq (%rax,%rdx), %r9 ; movq (24*8)(%rsp), %rax ; imulq %r10, %rax ; movq (24*8)+0x10(%rsp), %rdx ; imulq %r11, %rdx ; imulq (24*8)+0x8(%rsp), %r10 ; imulq (24*8)+0x18(%rsp), %r11 ; addq %r10, %r11 ; leaq (%rax,%rdx), %r13 ; movq $0xfffffffffffffffe, %rax ; movl $0x2, %edx ; movq %rbx, %rdi ; movq %rax, %r8 ; testq %rsi, %rsi ; cmovs %rbp, %r8 ; testq $0x1, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; cmovs %rbp, %r8 ; movq %rbx, %rdi ; testq %rdx, %rcx ; cmoveq %rbp, %r8 ; cmoveq %rbp, %rdi ; sarq $1, %rcx ; xorq %r8, %rdi ; xorq %r8, %rsi ; btq $0x3f, %r8 ; cmovbq %rcx, %rbx ; movq %rax, %r8 ; subq %rax, %rsi ; leaq (%rcx,%rdi), %rcx ; sarq $1, %rcx ; movl $0x100000, %eax ; leaq (%rbx,%rax), %r8 ; leaq (%rcx,%rax), %r12 ; shlq $0x15, %r8 ; shlq $0x15, %r12 ; sarq $0x2b, %r8 ; sarq $0x2b, %r12 ; movabsq $0x20000100000, %rax ; leaq (%rbx,%rax), %r10 ; leaq (%rcx,%rax), %r14 ; sarq $0x2b, %r10 ; sarq $0x2b, %r14 ; movq %r9, %rax ; imulq %r8, %rax ; movq %r13, %rdx ; imulq %r10, %rdx ; imulq %r15, %r8 ; imulq %r11, %r10 ; addq %r8, %r10 ; leaq (%rax,%rdx), %r8 ; movq %r9, %rax ; imulq %r12, %rax ; movq %r13, %rdx ; imulq %r14, %rdx ; imulq %r15, %r12 ; imulq %r11, %r14 ; addq %r12, %r14 ; leaq (%rax,%rdx), %r12
            \\        movq %rsi, (23*8)(%rsp)
            \\        decq (22*8)(%rsp)
            \\        jnz LvailP256FieldInvert_loop
            \\        movq 0(%rsp), %rax
            \\        movq (5*8)(%rsp), %rcx
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
            \\        movq %r10, %r12
            \\        andq %r11, %r12
            \\        addq %rax, %r12
            \\        xorl %r13d, %r13d
            \\        movq (10*8)(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %r12
            \\        adcq %rdx, %r13
            \\        movq (15*8)(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %r12
            \\        adcq %rdx, %r13
            \\        xorl %r14d, %r14d
            \\        movq (10*8)+8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %r13
            \\        adcq %rdx, %r14
            \\        movq (15*8)+8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %r13
            \\        adcq %rdx, %r14
            \\        xorl %r15d, %r15d
            \\        movq (10*8)+2*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        mulq %r8
            \\        addq %rax, %r14
            \\        adcq %rdx, %r15
            \\        movq (15*8)+2*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        mulq %r10
            \\        addq %rax, %r14
            \\        adcq %rdx, %r15
            \\        movq (10*8)+3*8(%rsp), %rax
            \\        xorq %r9, %rax
            \\        andq %r8, %r9
            \\        negq %r9
            \\        mulq %r8
            \\        addq %rax, %r15
            \\        adcq %rdx, %r9
            \\        movq (15*8)+3*8(%rsp), %rax
            \\        xorq %r11, %rax
            \\        movq %r11, %rdx
            \\        andq %r10, %rdx
            \\        subq %rdx, %r9
            \\        mulq %r10
            \\        addq %rax, %r15
            \\        adcq %rdx, %r9
            \\        movq %r12, (10*8)(%rsp)
            \\        movq %r13, (10*8)+8(%rsp)
            \\        movq %r14, (10*8)+2*8(%rsp)
            \\        movq %r15, (10*8)+3*8(%rsp)
            \\        movq %r9, (10*8)+4*8(%rsp)
            \\        movq $0xe000000000000000, %r8 ; addq (10*8)(%rsp), %r8 ; movq $0xffffffffffffffff, %r9 ; adcq 8+(10*8)(%rsp), %r9 ; movq $0x000000001fffffff, %r10 ; adcq 16+(10*8)(%rsp), %r10 ; movq $0x2000000000000000, %r11 ; adcq 24+(10*8)(%rsp), %r11 ; movq $0x1fffffffe0000000, %r12 ; adcq 32+(10*8)(%rsp), %r12 ; movq %r8, %rbx ; shlq $32, %rbx ; movq $0xffffffff00000001, %rax ; mulq %r8; shrq $32, %r8 ; addq %rbx, %r9 ; adcq %r8, %r10 ; adcq %rax, %r11 ; adcq %rdx, %r12 ; sbbq %rax, %rax ; movl $0x00000000ffffffff, %ebx ; andq %rax, %rbx ; movq $0xffffffff00000001, %rdx ; andq %rax, %rdx ; subq %rax, %r9 ; movq %r9, (10*8)(%rsp) ; sbbq %rbx, %r10 ; movq %r10, 8+(10*8)(%rsp) ; sbbq $0, %r11 ; movq %r11, 16+(10*8)(%rsp) ; sbbq %rdx, %r12 ; movq %r12, 24+(10*8)(%rsp)
            \\        movq (10*8)(%rsp), %r8
            \\        movq (10*8)+8(%rsp), %r9
            \\        movq (10*8)+2*8(%rsp), %r10
            \\        movq (10*8)+3*8(%rsp), %r11
            \\        movl $1, %eax
            \\        movl $0xffffffff, %ebx
            \\        leaq -2(%rax), %rcx
            \\        leaq -1(%rbx), %rdx
            \\        notq %rbx
            \\        addq %r8, %rax
            \\        adcq %r9, %rbx
            \\        adcq %r10, %rcx
            \\        adcq %r11, %rdx
            \\        cmovncq %r8, %rax
            \\        cmovncq %r9, %rbx
            \\        cmovncq %r10, %rcx
            \\        cmovncq %r11, %rdx
            \\        movq (28*8)(%rsp), %rdi
            \\        movq %rax, (%rdi)
            \\        movq %rbx, 8(%rdi)
            \\        movq %rcx, 2*8(%rdi)
            \\        movq %rdx, 3*8(%rdi)
            \\        cld
            \\        xorl %eax, %eax
            \\        movq %rsp, %rdi
            \\        movl $30, %ecx
            \\        rep stosq
            \\        xorl %edx, %edx
            \\        xorl %esi, %esi
            \\        xorl %r8d, %r8d
            \\        xorl %r9d, %r9d
            \\        xorl %r10d, %r10d
            \\        xorl %r11d, %r11d
            \\        addq $30*8, %rsp ; .cfi_adjust_cfa_offset -30*8
            \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
            \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
            \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
            \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
            \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
            \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
            \\        retq ; .cfi_endproc
            \\.size vailP256FieldInvert, .-vailP256FieldInvert
        );
    }
}
