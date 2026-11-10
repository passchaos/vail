//! Constant-time Ed25519 scalar reduction and multiply-add on x86_64 ADX.
//!
//! The instruction schedules come from the formally verified s2n-bignum
//! implementation and are embedded directly in Zig.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

const std = @import("std");
const builtin = @import("builtin");

const Scalar = std.crypto.sign.Ed25519.Curve.scalar;

pub const enabled = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

pub fn reduce64(input: *const [64]u8) [32]u8 {
    if (comptime enabled) {
        var output: [4]u64 = undefined;
        vailEd25519ScalarReduce(&output, 8, @ptrCast(input));
        return @bitCast(output);
    }
    return Scalar.reduce64(input.*);
}

pub fn mulAdd(
    x: *const [32]u8,
    y: *const [32]u8,
    addend: *const [32]u8,
) [32]u8 {
    if (comptime enabled) {
        var output: [4]u64 = undefined;
        vailEd25519ScalarMulAdd(
            &output,
            @ptrCast(x),
            @ptrCast(y),
            @ptrCast(addend),
        );
        return @bitCast(output);
    }
    return Scalar.mulAdd(x.*, y.*, addend.*);
}

extern fn vailEd25519ScalarReduce(
    output: *[4]u64,
    input_limb_count: usize,
    input: *align(1) const [8]u64,
) callconv(.c) void;

extern fn vailEd25519ScalarMulAdd(
    output: *[4]u64,
    x: *align(1) const [4]u64,
    y: *align(1) const [4]u64,
    addend: *align(1) const [4]u64,
) callconv(.c) void;

test "Ed25519 ADX scalar operations match Zig std" {
    var state: u64 = 0x243f_6a88_85a3_08d3;
    for (0..4096) |_| {
        var wide: [64]u8 = undefined;
        fillDeterministic(&wide, &state);
        const expected_reduced = Scalar.reduce64(wide);
        const actual_reduced = reduce64(&wide);
        try std.testing.expectEqual(expected_reduced, actual_reduced);

        fillDeterministic(&wide, &state);
        const x = Scalar.reduce64(wide);
        fillDeterministic(&wide, &state);
        const y = Scalar.reduce64(wide);
        fillDeterministic(&wide, &state);
        const addend = Scalar.reduce64(wide);
        try std.testing.expectEqual(
            Scalar.mulAdd(x, y, addend),
            mulAdd(&x, &y, &addend),
        );
    }
}

fn fillDeterministic(output: []u8, state: *u64) void {
    for (output) |*byte| {
        state.* ^= state.* << 13;
        state.* ^= state.* >> 7;
        state.* ^= state.* << 17;
        byte.* = @truncate(state.*);
    }
}

comptime {
    if (enabled) {
        asm (
            \\       
            \\        .text
            \\vailEd25519ScalarMulAdd:
            \\        .cfi_startproc
            \\        endbr64
            \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
            \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
            \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
            \\        pushq %r13 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r13, 0
            \\        pushq %r14 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r14, 0
            \\        pushq %r15 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r15, 0
            \\        movq (%rcx), %r8
            \\        movq 8(%rcx), %r9
            \\        movq 16(%rcx), %r10
            \\        movq 24(%rcx), %r11
            \\        movq %rdx, %rcx
            \\        xorl %ebp, %ebp
            \\        movq (%rcx), %rdx
            \\        mulxq (%rsi), %rax, %rbx
            \\        adcxq %rax, %r8
            \\        adoxq %rbx, %r9
            \\        mulxq 0x8(%rsi), %rax, %rbx
            \\        adcxq %rax, %r9
            \\        adoxq %rbx, %r10
            \\        mulxq 0x10(%rsi), %rax, %rbx
            \\        adcxq %rax, %r10
            \\        adoxq %rbx, %r11
            \\        mulxq 0x18(%rsi), %rax, %r12
            \\        adcxq %rax, %r11
            \\        adoxq %rbp, %r12
            \\        adcxq %rbp, %r12
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
            \\        adcxq %rbp, %r13
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
            \\        adcxq %rbp, %r14
            \\        xorl %ebp, %ebp
            \\        movq 0x18(%rcx), %rdx
            \\        mulxq (%rsi), %rax, %rbx
            \\        adcxq %rax, %r11
            \\        adoxq %rbx, %r12
            \\        mulxq 0x8(%rsi), %rax, %rbx
            \\        adcxq %rax, %r12
            \\        adoxq %rbx, %r13
            \\        mulxq 0x10(%rsi), %rax, %rbx
            \\        adcxq %rax, %r13
            \\        adoxq %rbx, %r14
            \\        mulxq 0x18(%rsi), %rax, %r15
            \\        adcxq %rax, %r14
            \\        adoxq %rbp, %r15
            \\        adcxq %rbp, %r15
            \\        movq %r15, %rbx ; shrq $60, %rbx ; shlq $4, %r15 ; shrq $4, %r15 ; movabsq $0x5812631a5cf5d3ed, %rax ; mulq %rbx; movq %rax, %rbp ; movq %rdx, %rcx ; movabsq $0x14def9dea2f79cd6, %rax ; mulq %rbx; addq %rax, %rcx ; adcq $0x0, %rdx ; subq %rbp, %r12 ; sbbq %rcx, %r13 ; sbbq %rdx, %r14 ; sbbq $0x0, %r15 ; sbbq %rbx, %rbx ; movabsq $0x5812631a5cf5d3ed, %rax ; andq %rbx, %rax ; movabsq $0x14def9dea2f79cd6, %rdx ; andq %rbx, %rdx ; movabsq $0x1000000000000000, %rbx ; andq %rax, %rbx ; addq %rax, %r12 ; adcq %rdx, %r13 ; adcq $0x0, %r14 ; adcq %rbx, %r15
            \\        movq %r15, %rbx ; shldq $0x4, %r14, %rbx ; shrq $0x3c, %r15 ; subq %r15, %rbx ; shlq $0x4, %r14 ; shrdq $0x4, %r15, %r14 ; movabsq $0x5812631a5cf5d3ed, %rax ; mulq %rbx; movq %rax, %rbp ; movq %rdx, %rcx ; movabsq $0x14def9dea2f79cd6, %rax ; mulq %rbx; addq %rax, %rcx ; adcq $0x0, %rdx ; subq %rbp, %r11 ; sbbq %rcx, %r12 ; sbbq %rdx, %r13 ; sbbq $0x0, %r14 ; sbbq %rbx, %rbx ; movabsq $0x5812631a5cf5d3ed, %rax ; andq %rbx, %rax ; movabsq $0x14def9dea2f79cd6, %rdx ; andq %rbx, %rdx ; movabsq $0x1000000000000000, %rbx ; andq %rax, %rbx ; addq %rax, %r11 ; adcq %rdx, %r12 ; adcq $0x0, %r13 ; adcq %rbx, %r14
            \\        movq %r14, %rbx ; shldq $0x4, %r13, %rbx ; shrq $0x3c, %r14 ; subq %r14, %rbx ; shlq $0x4, %r13 ; shrdq $0x4, %r14, %r13 ; movabsq $0x5812631a5cf5d3ed, %rax ; mulq %rbx; movq %rax, %rbp ; movq %rdx, %rcx ; movabsq $0x14def9dea2f79cd6, %rax ; mulq %rbx; addq %rax, %rcx ; adcq $0x0, %rdx ; subq %rbp, %r10 ; sbbq %rcx, %r11 ; sbbq %rdx, %r12 ; sbbq $0x0, %r13 ; sbbq %rbx, %rbx ; movabsq $0x5812631a5cf5d3ed, %rax ; andq %rbx, %rax ; movabsq $0x14def9dea2f79cd6, %rdx ; andq %rbx, %rdx ; movabsq $0x1000000000000000, %rbx ; andq %rax, %rbx ; addq %rax, %r10 ; adcq %rdx, %r11 ; adcq $0x0, %r12 ; adcq %rbx, %r13
            \\        movq %r13, %rbx ; shldq $0x4, %r12, %rbx ; shrq $0x3c, %r13 ; subq %r13, %rbx ; shlq $0x4, %r12 ; shrdq $0x4, %r13, %r12 ; movabsq $0x5812631a5cf5d3ed, %rax ; mulq %rbx; movq %rax, %rbp ; movq %rdx, %rcx ; movabsq $0x14def9dea2f79cd6, %rax ; mulq %rbx; addq %rax, %rcx ; adcq $0x0, %rdx ; subq %rbp, %r9 ; sbbq %rcx, %r10 ; sbbq %rdx, %r11 ; sbbq $0x0, %r12 ; sbbq %rbx, %rbx ; movabsq $0x5812631a5cf5d3ed, %rax ; andq %rbx, %rax ; movabsq $0x14def9dea2f79cd6, %rdx ; andq %rbx, %rdx ; movabsq $0x1000000000000000, %rbx ; andq %rax, %rbx ; addq %rax, %r9 ; adcq %rdx, %r10 ; adcq $0x0, %r11 ; adcq %rbx, %r12
            \\        movq %r12, %rbx ; shldq $0x4, %r11, %rbx ; shrq $0x3c, %r12 ; subq %r12, %rbx ; shlq $0x4, %r11 ; shrdq $0x4, %r12, %r11 ; movabsq $0x5812631a5cf5d3ed, %rax ; mulq %rbx; movq %rax, %rbp ; movq %rdx, %rcx ; movabsq $0x14def9dea2f79cd6, %rax ; mulq %rbx; addq %rax, %rcx ; adcq $0x0, %rdx ; subq %rbp, %r8 ; sbbq %rcx, %r9 ; sbbq %rdx, %r10 ; sbbq $0x0, %r11 ; sbbq %rbx, %rbx ; movabsq $0x5812631a5cf5d3ed, %rax ; andq %rbx, %rax ; movabsq $0x14def9dea2f79cd6, %rdx ; andq %rbx, %rdx ; movabsq $0x1000000000000000, %rbx ; andq %rax, %rbx ; addq %rax, %r8 ; adcq %rdx, %r9 ; adcq $0x0, %r10 ; adcq %rbx, %r11
            \\        movq %r8, (%rdi)
            \\        movq %r9, 8(%rdi)
            \\        movq %r10, 16(%rdi)
            \\        movq %r11, 24(%rdi)
            \\        xorl %eax, %eax
            \\        xorl %ecx, %ecx
            \\        xorl %edx, %edx
            \\        xorl %esi, %esi
            \\        xorl %r8d, %r8d
            \\        xorl %r9d, %r9d
            \\        xorl %r10d, %r10d
            \\        xorl %r11d, %r11d
            \\        popq %r15 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r15
            \\        popq %r14 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r14
            \\        popq %r13 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r13
            \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
            \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
            \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
            \\        retq ; .cfi_endproc
            \\.size vailEd25519ScalarMulAdd, .-vailEd25519ScalarMulAdd
            \\       
            \\        .text
            \\vailEd25519ScalarReduce:
            \\        .cfi_startproc
            \\        endbr64
            \\        pushq %rbx ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbx, 0
            \\        pushq %rbp ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %rbp, 0
            \\        pushq %r12 ; .cfi_adjust_cfa_offset 8 ; .cfi_rel_offset %r12, 0
            \\        cmpq $4, %rsi
            \\        jc Lvail_ed25519_scalar_shortinput
            \\        subq $4, %rsi
            \\        movq 24(%rdx,%rsi,8), %r11
            \\        movq 16(%rdx,%rsi,8), %r10
            \\        movq 8(%rdx,%rsi,8), %r9
            \\        movq (%rdx,%rsi,8), %r8
            \\        movq %rdx, %rcx
            \\        movq %r11, %rbx
            \\        shrq $60, %rbx
            \\        shlq $4, %r11
            \\        shrq $4, %r11
            \\        movq $0x5812631a5cf5d3ed, %rax
            \\        mulq %rbx
            \\        movq %rax, %rbp
            \\        movq %rdx, %r12
            \\        movq $0x14def9dea2f79cd6, %rax
            \\        mulq %rbx
            \\        addq %rax, %r12
            \\        adcq $0, %rdx
            \\        subq %rbp, %r8
            \\        sbbq %r12, %r9
            \\        sbbq %rdx, %r10
            \\        sbbq $0, %r11
            \\        sbbq %rbx, %rbx
            \\        movq $0x5812631a5cf5d3ed, %rax
            \\        andq %rbx, %rax
            \\        movq $0x14def9dea2f79cd6, %rdx
            \\        andq %rbx, %rdx
            \\        movq $0x1000000000000000, %rbx
            \\        andq %rax, %rbx
            \\        addq %rax, %r8
            \\        adcq %rdx, %r9
            \\        adcq $0, %r10
            \\        adcq %rbx, %r11
            \\        testq %rsi, %rsi
            \\        jz Lvail_ed25519_scalar_writeback
            \\Lvail_ed25519_scalar_loop:
            \\        movq %r11, %rbx
            \\        shldq $4, %r10, %rbx
            \\        shrq $60, %r11
            \\        subq %r11, %rbx
            \\        shlq $4, %r10
            \\        shrdq $4, %r11, %r10
            \\        movq $0x5812631a5cf5d3ed, %rax
            \\        mulq %rbx
            \\        movq %rax, %rbp
            \\        movq %rdx, %r11
            \\        movq $0x14def9dea2f79cd6, %rax
            \\        mulq %rbx
            \\        addq %rax, %r11
            \\        adcq $0, %rdx
            \\        movq -8(%rcx,%rsi,8), %r12
            \\        subq %rbp, %r12
            \\        sbbq %r11, %r8
            \\        sbbq %rdx, %r9
            \\        sbbq $0, %r10
            \\        sbbq %rbx, %rbx
            \\        movq $0x5812631a5cf5d3ed, %rax
            \\        andq %rbx, %rax
            \\        movq $0x14def9dea2f79cd6, %rdx
            \\        andq %rbx, %rdx
            \\        movq $0x1000000000000000, %rbx
            \\        andq %rax, %rbx
            \\        addq %rax, %r12
            \\        adcq %rdx, %r8
            \\        adcq $0, %r9
            \\        adcq %rbx, %r10
            \\        movq %r10, %r11
            \\        movq %r9, %r10
            \\        movq %r8, %r9
            \\        movq %r12, %r8
            \\        decq %rsi
            \\        jnz Lvail_ed25519_scalar_loop
            \\        jmp Lvail_ed25519_scalar_writeback
            \\Lvail_ed25519_scalar_shortinput:
            \\        xorq %r8, %r8
            \\        xorq %r9, %r9
            \\        xorq %r10, %r10
            \\        xorq %r11, %r11
            \\        testq %rsi, %rsi
            \\        jz Lvail_ed25519_scalar_writeback
            \\        movq (%rdx), %r8
            \\        decq %rsi
            \\        jz Lvail_ed25519_scalar_writeback
            \\        movq 8(%rdx), %r9
            \\        decq %rsi
            \\        jz Lvail_ed25519_scalar_writeback
            \\        movq 16(%rdx), %r10
            \\Lvail_ed25519_scalar_writeback:
            \\        movq %r8, (%rdi)
            \\        movq %r9, 8(%rdi)
            \\        movq %r10, 16(%rdi)
            \\        movq %r11, 24(%rdi)
            \\        xorl %eax, %eax
            \\        xorl %ecx, %ecx
            \\        xorl %edx, %edx
            \\        xorl %esi, %esi
            \\        xorl %r8d, %r8d
            \\        xorl %r9d, %r9d
            \\        xorl %r10d, %r10d
            \\        xorl %r11d, %r11d
            \\        popq %r12 ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %r12
            \\        popq %rbp ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbp
            \\        popq %rbx ; .cfi_adjust_cfa_offset -8 ; .cfi_restore %rbx
            \\        retq ; .cfi_endproc
            \\.size vailEd25519ScalarReduce, .-vailEd25519ScalarReduce
        );
    }
}
