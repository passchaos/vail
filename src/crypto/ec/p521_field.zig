//! P-521 field and limb arithmetic.
//!
//! This module contains the field representation, limb helpers, modular
//! reduction, inversion schedules, and constant-time secret-field operations
//! used by `p521.zig`.

const std = @import("std");
const field_inv_x86 = @import("p521_field_inv_x86.zig");

pub const limb_count = 9;
pub const encoded_length = 66;
pub const Limbs = [limb_count]u64;
pub const FieldLimbs = [limb_count]u64;
pub const field_radix_bits = 58;
pub const field_mask: u64 = (@as(u64, 1) << field_radix_bits) - 1;
pub const field_top_mask: u64 = (@as(u64, 1) << 57) - 1;

pub const field_modulus_hex =
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ++
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
pub const field_modulus = fieldLimbsFromHex(field_modulus_hex);
pub const field_modulus_binary = limbsFromHex(field_modulus_hex);

pub const inversion_window_width = 5;
pub const inversion_leading_ones = 262;
pub const inversion_tail_bits = 521 - inversion_leading_ones;
pub const InversionStep = struct { squares: u8, table_index: u4 };
pub const InversionSchedule = struct {
    steps: [128]InversionStep,
    len: usize,
};
pub const inversion_schedule = buildInversionSchedule();

pub const Fe = struct {
    value: FieldLimbs,

    pub const zero = Fe{ .value = [_]u64{0} ** limb_count };
    pub const one_fe = Fe{ .value = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 } };

    pub fn fromBytes(encoded: []const u8) !Fe {
        if (encoded.len != encoded_length or encoded[0] > 1) {
            return error.NonCanonical;
        }
        const value = decodeField(encoded);
        if (!fieldLessThan(value, field_modulus)) return error.NonCanonical;
        return .{ .value = value };
    }

    pub inline fn fromCanonicalLimbs(value: Limbs) Fe {
        return .{ .value = fieldLimbsFromLimbs(value) };
    }

    pub inline fn add(a: Fe, b: Fe) Fe {
        return .{ .value = fieldAdd(a.value, b.value) };
    }

    pub inline fn sub(a: Fe, b: Fe) Fe {
        return .{ .value = fieldSub(a.value, b.value) };
    }

    pub inline fn neg(self: Fe) Fe {
        if (self.isZero()) return zero;
        return .{ .value = fieldSubRaw(field_modulus, self.value) };
    }

    pub inline fn dbl(self: Fe) Fe {
        return self.add(self);
    }

    pub inline fn mulSmall(self: Fe, comptime multiplier: u4) Fe {
        return .{ .value = fieldMulSmall(self.value, multiplier) };
    }

    pub inline fn mul(a: Fe, b: Fe) Fe {
        return .{ .value = fieldMul(a.value, b.value) };
    }

    pub inline fn sq(self: Fe) Fe {
        return .{ .value = fieldSquare(self.value) };
    }

    pub fn invert(self: Fe) Fe {
        if (!@inComptime() and comptime field_inv_x86.enabled) {
            return .{ .value = invertFieldX86(self.value) };
        }
        // p - 2 = 4 * (2^519 - 1) + 1. Building x^(2^519-1) with
        // f(a+b)=f(a)^(2^b)*f(b) keeps the 520 required squarings while
        // reducing general multiplications from 519 to a short addition chain.
        return powTwoMinusOne(self, 519).sq().sq().mul(self);
    }

    pub fn sqrt(self: Fe) !Fe {
        // p = 3 mod 4, hence sqrt(a) = a^((p + 1) / 4) = a^(2^519).
        var root = self;
        for (0..519) |_| root = root.sq();
        if (!root.sq().equivalent(self)) return error.NotSquare;
        return root;
    }

    pub inline fn equivalent(a: Fe, b: Fe) bool {
        return fieldEqual(a.value, b.value);
    }

    pub inline fn isZero(self: Fe) bool {
        return fieldEqual(self.value, [_]u64{0} ** limb_count);
    }

    pub inline fn isOdd(self: Fe) bool {
        return (self.value[0] & 1) != 0;
    }
};

pub fn powTwoMinusOne(base: Fe, count: usize) Fe {
    std.debug.assert(count != 0);
    if (count == 1) return base;
    const half_count = count / 2;
    const half = powTwoMinusOne(base, half_count);
    var result = half;
    for (0..half_count) |_| result = result.sq();
    result = result.mul(half);
    if (count % 2 != 0) result = result.sq().mul(base);
    return result;
}

pub const SecretFe = struct {
    value: FieldLimbs,

    pub const zero = SecretFe{ .value = [_]u64{0} ** limb_count };
    pub const one_fe = SecretFe{ .value = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 } };

    pub inline fn add(a: SecretFe, b: SecretFe) SecretFe {
        return .{ .value = fieldAddSecret(a.value, b.value) };
    }

    pub inline fn sub(a: SecretFe, b: SecretFe) SecretFe {
        return .{ .value = fieldSubSecret(a.value, b.value) };
    }

    pub inline fn dbl(self: SecretFe) SecretFe {
        return self.add(self);
    }

    pub inline fn mulSmall(self: SecretFe, comptime multiplier: u4) SecretFe {
        return .{ .value = fieldMulSmallSecret(self.value, multiplier) };
    }

    pub inline fn mul(a: SecretFe, b: SecretFe) SecretFe {
        return .{ .value = fieldMulSecret(a.value, b.value) };
    }

    pub inline fn sq(self: SecretFe) SecretFe {
        return .{ .value = fieldSquareSecret(self.value) };
    }

    pub fn invert(self: SecretFe) SecretFe {
        if (comptime field_inv_x86.enabled) {
            return .{ .value = invertFieldX86(self.value) };
        }
        return self.invertPortable();
    }

    pub fn invertPortable(self: SecretFe) SecretFe {
        return powTwoMinusOneSecret(self, 519).sq().sq().mul(self);
    }

    pub inline fn canonical(self: SecretFe) Fe {
        const reduced = fieldSubWithBorrow(self.value, field_modulus);
        return .{ .value = selectFieldLimbs(
            self.value,
            reduced.value,
            reduced.borrow ^ 1,
        ) };
    }

    pub inline fn isZeroChoice(self: SecretFe) u1 {
        var combined: u64 = 0;
        inline for (self.value) |limb| combined |= limb;
        return @truncate((@as(u65, combined) -% 1) >> 64);
    }
};

pub const FieldSubResult = struct { value: FieldLimbs, borrow: u1 };

pub inline fn fieldSubWithBorrow(
    a: FieldLimbs,
    b: FieldLimbs,
) FieldSubResult {
    var result: FieldLimbs = undefined;
    var borrow: u1 = 0;
    inline for (0..limb_count) |index| {
        const bits: u7 = if (index == limb_count - 1)
            57
        else
            field_radix_bits;
        const first = @subWithOverflow(a[index], b[index]);
        const second = @subWithOverflow(first[0], borrow);
        borrow = first[1] | second[1];
        result[index] = second[0] +%
            (@as(u64, borrow) << bits);
    }
    return .{ .value = result, .borrow = borrow };
}

pub inline fn fieldMul(a: FieldLimbs, b: FieldLimbs) FieldLimbs {
    @setEvalBranchQuota(100_000);
    var product = [_]u128{0} ** limb_count;
    var low = [_]u128{0} ** 9;
    var high = [_]u128{0} ** 9;
    var middle = [_]u128{0} ** 9;
    var left_sum: [5]u64 = undefined;
    var right_sum: [5]u64 = undefined;

    inline for (0..5) |index| {
        left_sum[index] = a[index] + if (index < 4) a[index + 5] else 0;
        right_sum[index] = b[index] + if (index < 4) b[index + 5] else 0;
    }
    inline for (0..5) |left| {
        inline for (0..5) |right| {
            low[left + right] += @as(u128, a[left]) * b[right];
            middle[left + right] +=
                @as(u128, left_sum[left]) * right_sum[right];
        }
    }
    inline for (0..4) |left| {
        inline for (0..4) |right| {
            high[left + right] += @as(u128, a[left + 5]) * b[right + 5];
        }
    }
    inline for (0..9) |index| {
        middle[index] -= low[index] + high[index];
        product[index] += low[index];
        if (index < 4) {
            product[index + 5] += middle[index];
        } else {
            product[index - 4] += 2 * middle[index];
        }
        if (index < 8) product[index + 1] += 2 * high[index];
    }
    return fieldReduceFolded(product);
}

pub const FieldSquareTerm = struct {
    left: u4,
    right: u4,
    factor: u3,
};

pub const field_square_schedule = blk: {
    const term_count = limb_count * (limb_count + 1) / 2;
    var terms: [term_count]FieldSquareTerm = undefined;
    var offsets: [limb_count + 1]u8 = undefined;
    var term_index: usize = 0;
    for (0..limb_count) |output_index| {
        offsets[output_index] = @intCast(term_index);
        for (0..limb_count) |left| {
            for (left..limb_count) |right| {
                const product_index = left + right;
                const folded_index = if (product_index < limb_count)
                    product_index
                else
                    product_index - limb_count;
                if (folded_index != output_index) continue;
                const symmetry_factor = if (left == right) 1 else 2;
                const fold_factor = if (product_index < limb_count) 1 else 2;
                terms[term_index] = .{
                    .left = @intCast(left),
                    .right = @intCast(right),
                    .factor = @intCast(symmetry_factor * fold_factor),
                };
                term_index += 1;
            }
        }
    }
    offsets[limb_count] = @intCast(term_index);
    std.debug.assert(term_index == term_count);
    break :blk .{ .terms = terms, .offsets = offsets };
};

pub noinline fn fieldSquare(a: FieldLimbs) FieldLimbs {
    @setEvalBranchQuota(100_000);
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count) |output_index| {
        var coefficient: u128 = carry;
        const start = field_square_schedule.offsets[output_index];
        const end = field_square_schedule.offsets[output_index + 1];
        inline for (field_square_schedule.terms[start..end]) |term| {
            coefficient +%= @as(
                u128,
                a[term.left] *% @as(u64, term.factor),
            ) *% a[term.right];
        }
        const bits: u7 = if (output_index == limb_count - 1)
            57
        else
            field_radix_bits;
        result[output_index] = @truncate(
            coefficient & ((@as(u128, 1) << bits) - 1),
        );
        carry = @intCast(coefficient >> bits);
    }
    while (carry != 0) {
        inline for (0..limb_count) |index| {
            const bits: u7 = if (index == limb_count - 1)
                57
            else
                field_radix_bits;
            const value = result[index] +% carry;
            result[index] = value & ((@as(u64, 1) << bits) - 1);
            carry = value >> bits;
        }
    }
    if (!fieldLessThan(result, field_modulus)) {
        result = fieldSubRaw(result, field_modulus);
    }
    return result;
}

pub inline fn fieldReduceFolded(product: [limb_count]u128) FieldLimbs {
    // Callers already fold every radix-58 coefficient at index 9 or above
    // onto index - 9 with a factor of two, using 2^522 == 2 (mod p).
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count - 1) |index| {
        const value = product[index] + carry;
        result[index] = @truncate(value & field_mask);
        carry = @intCast(value >> field_radix_bits);
    }
    const top = product[limb_count - 1] + carry;
    result[limb_count - 1] = @truncate(top & field_top_mask);
    carry = @intCast(top >> 57);
    while (carry != 0) {
        inline for (0..limb_count) |index| {
            const bits: u7 = if (index == limb_count - 1)
                57
            else
                field_radix_bits;
            const value = result[index] + carry;
            result[index] = value & ((@as(u64, 1) << bits) - 1);
            carry = value >> bits;
        }
    }
    if (!fieldLessThan(result, field_modulus)) {
        result = fieldSubRaw(result, field_modulus);
    }
    return result;
}

pub inline fn fieldReduce(unreduced: FieldLimbs) FieldLimbs {
    var result = unreduced;
    while (result[8] > field_top_mask) {
        var carry: u64 = result[8] >> 57;
        result[8] &= field_top_mask;
        inline for (0..limb_count) |index| {
            const sum = result[index] + carry;
            result[index] = sum & field_mask;
            carry = sum >> field_radix_bits;
        }
        std.debug.assert(carry == 0);
    }
    if (!fieldLessThan(result, field_modulus)) {
        result = fieldSubRaw(result, field_modulus);
    }
    return result;
}

pub inline fn fieldAddSecret(a: FieldLimbs, b: FieldLimbs) FieldLimbs {
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count) |index| {
        const sum = a[index] + b[index] + carry;
        result[index] = sum & field_mask;
        carry = sum >> field_radix_bits;
    }
    std.debug.assert(carry == 0);
    return fieldReduceSecret(result);
}

pub inline fn fieldSubSecret(a: FieldLimbs, b: FieldLimbs) FieldLimbs {
    const difference = fieldSubWithBorrow(a, b);
    const mask = opaqueWord(0 -% @as(u64, difference.borrow));
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count) |index| {
        const bits: u7 = if (index == limb_count - 1)
            57
        else
            field_radix_bits;
        const sum = difference.value[index] +%
            (field_modulus[index] & mask) + carry;
        result[index] = sum & ((@as(u64, 1) << bits) - 1);
        carry = sum >> bits;
    }
    std.debug.assert(carry == difference.borrow);
    return result;
}

pub inline fn fieldMulSmallSecret(
    a: FieldLimbs,
    comptime multiplier: u4,
) FieldLimbs {
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count - 1) |index| {
        const product = a[index] * multiplier + carry;
        result[index] = product & field_mask;
        carry = product >> field_radix_bits;
    }
    const top = a[limb_count - 1] * multiplier + carry;
    result[limb_count - 1] = top;
    return fieldReduceSecret(result);
}

pub inline fn fieldMulSecret(a: FieldLimbs, b: FieldLimbs) FieldLimbs {
    @setEvalBranchQuota(100_000);
    var product = [_]u128{0} ** limb_count;
    var low = [_]u128{0} ** limb_count;
    var high = [_]u128{0} ** limb_count;
    var middle = [_]u128{0} ** limb_count;
    var left_sum: [5]u64 = undefined;
    var right_sum: [5]u64 = undefined;
    inline for (0..5) |index| {
        left_sum[index] = a[index] + if (index < 4) a[index + 5] else 0;
        right_sum[index] = b[index] + if (index < 4) b[index + 5] else 0;
    }
    inline for (0..5) |left| {
        inline for (0..5) |right| {
            low[left + right] += @as(u128, a[left]) * b[right];
            middle[left + right] +=
                @as(u128, left_sum[left]) * right_sum[right];
        }
    }
    inline for (0..4) |left| {
        inline for (0..4) |right| {
            high[left + right] += @as(u128, a[left + 5]) * b[right + 5];
        }
    }
    inline for (0..limb_count) |index| {
        middle[index] -= low[index] + high[index];
        product[index] += low[index];
        if (index < 4) {
            product[index + 5] += middle[index];
        } else {
            product[index - 4] += 2 * middle[index];
        }
        if (index < 8) product[index + 1] += 2 * high[index];
    }
    return fieldReduceFoldedSecret(product);
}

pub noinline fn fieldSquareSecret(a: FieldLimbs) FieldLimbs {
    @setEvalBranchQuota(100_000);
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count) |output_index| {
        var coefficient: u128 = carry;
        const start = field_square_schedule.offsets[output_index];
        const end = field_square_schedule.offsets[output_index + 1];
        inline for (field_square_schedule.terms[start..end]) |term| {
            coefficient +%= @as(
                u128,
                a[term.left] *% @as(u64, term.factor),
            ) *% a[term.right];
        }
        const bits: u7 = if (output_index == limb_count - 1)
            57
        else
            field_radix_bits;
        result[output_index] = @truncate(
            coefficient & ((@as(u128, 1) << bits) - 1),
        );
        carry = @intCast(coefficient >> bits);
    }
    return fieldFoldSecret(result, carry);
}

pub fn fieldReduceFoldedSecret(product: [limb_count]u128) FieldLimbs {
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count - 1) |index| {
        const value = product[index] + carry;
        result[index] = @truncate(value & field_mask);
        carry = @intCast(value >> field_radix_bits);
    }
    const top = product[limb_count - 1] + carry;
    result[limb_count - 1] = @truncate(top & field_top_mask);
    return fieldFoldSecret(result, @intCast(top >> 57));
}

pub fn fieldReduceSecret(unreduced: FieldLimbs) FieldLimbs {
    var result = unreduced;
    const carry: u64 = result[limb_count - 1] >> 57;
    result[limb_count - 1] &= field_top_mask;
    return fieldFoldSecret(result, carry);
}

pub inline fn fieldFoldSecret(
    value: FieldLimbs,
    initial_carry: u64,
) FieldLimbs {
    var result = value;
    var carry = initial_carry;
    // Folding modulo 2^521-1 may carry through an all-ones value once. Two
    // fixed passes handle that boundary without leaking whether it occurred.
    inline for (0..2) |_| {
        inline for (0..limb_count) |index| {
            const bits: u7 = if (index == limb_count - 1)
                57
            else
                field_radix_bits;
            const sum = result[index] +% carry;
            result[index] = sum & ((@as(u64, 1) << bits) - 1);
            carry = sum >> bits;
        }
    }
    std.debug.assert(carry == 0);

    return result;
}

pub inline fn selectFieldLimbs(
    a: FieldLimbs,
    b: FieldLimbs,
    select_b: u1,
) FieldLimbs {
    const mask = opaqueWord(0 -% @as(u64, select_b));
    var result: FieldLimbs = undefined;
    inline for (0..limb_count) |index| {
        result[index] = (b[index] & mask) | (a[index] & ~mask);
    }
    return result;
}

pub fn fieldLessThan(a: FieldLimbs, b: FieldLimbs) bool {
    var index: usize = limb_count;
    while (index != 0) {
        index -= 1;
        if (a[index] != b[index]) return a[index] < b[index];
    }
    return false;
}

pub inline fn fieldEqual(a: FieldLimbs, b: FieldLimbs) bool {
    var difference: u64 = 0;
    inline for (a, b) |a_limb, b_limb| difference |= a_limb ^ b_limb;
    return difference == 0;
}

pub fn decodeField(encoded: []const u8) FieldLimbs {
    var result = [_]u64{0} ** limb_count;
    for (encoded) |byte| {
        var carry: u128 = byte;
        for (&result) |*limb| {
            const value = (@as(u128, limb.*) << 8) | carry;
            limb.* = @truncate(value & field_mask);
            carry = value >> field_radix_bits;
        }
        std.debug.assert(carry == 0);
    }
    return result;
}

pub inline fn fieldLimbsFromLimbs(value: Limbs) FieldLimbs {
    var result: FieldLimbs = undefined;
    inline for (0..limb_count) |index| {
        const bit_offset = index * field_radix_bits;
        const limb_index = bit_offset / 64;
        const shift: u6 = @intCast(bit_offset % 64);
        var bits = value[limb_index] >> shift;
        if (shift != 0 and limb_index + 1 < value.len) {
            bits |= value[limb_index + 1] <<
                @intCast(64 - @as(u7, shift));
        }
        result[index] = bits & if (index == limb_count - 1)
            field_top_mask
        else
            field_mask;
    }
    return result;
}

pub inline fn limbsFromFieldLimbs(value: FieldLimbs) Limbs {
    var result: Limbs = undefined;
    inline for (0..limb_count) |index| {
        const bit_offset = index * 64;
        const source_index = bit_offset / field_radix_bits;
        const shift: u6 = @intCast(bit_offset % field_radix_bits);
        var bits = value[source_index] >> shift;
        if (source_index + 1 < value.len) {
            bits |= value[source_index + 1] <<
                @intCast(field_radix_bits - @as(u7, shift));
        }
        result[index] = bits;
    }
    return result;
}

pub inline fn invertFieldX86(value: FieldLimbs) FieldLimbs {
    var canonical_limbs = limbsFromFieldLimbs(value);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&canonical_limbs));
    var inverse = field_inv_x86.invert(&canonical_limbs);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&inverse));
    return fieldLimbsFromLimbs(inverse);
}

pub fn encodeField(value: FieldLimbs) [encoded_length]u8 {
    var result: [encoded_length]u8 = undefined;
    for (&result, 0..) |*byte, output_index| {
        const bit_offset = (encoded_length - 1 - output_index) * 8;
        const limb_index = bit_offset / field_radix_bits;
        const shift: u6 = @intCast(bit_offset % field_radix_bits);
        var bits = value[limb_index] >> shift;
        if (shift > 50 and limb_index + 1 < value.len) {
            bits |= value[limb_index + 1] <<
                @intCast(field_radix_bits - @as(u7, shift));
        }
        byte.* = @truncate(bits);
    }
    return result;
}

pub fn encodeScalar(value: Limbs) [encoded_length]u8 {
    var result: [encoded_length]u8 = undefined;
    for (&result, 0..) |*byte, output_index| {
        const bit_offset = (encoded_length - 1 - output_index) * 8;
        const limb_index = bit_offset / 64;
        const shift: u6 = @intCast(bit_offset % 64);
        var bits = value[limb_index] >> shift;
        if (shift > 56 and limb_index + 1 < value.len) {
            bits |= value[limb_index + 1] <<
                @intCast(64 - @as(u7, shift));
        }
        byte.* = @truncate(bits);
    }
    return result;
}

pub const AddResult = struct { value: Limbs, carry: u1 };
pub const SubResult = struct { value: Limbs, borrow: u1 };

pub inline fn addRaw(a: Limbs, b: Limbs) AddResult {
    var result: Limbs = undefined;
    var carry: u1 = 0;
    inline for (0..limb_count) |index| {
        const first = @addWithOverflow(a[index], b[index]);
        const second = @addWithOverflow(first[0], carry);
        result[index] = second[0];
        carry = first[1] | second[1];
    }
    return .{ .value = result, .carry = carry };
}

pub inline fn subRaw(a: Limbs, b: Limbs) SubResult {
    @setEvalBranchQuota(100_000);
    var result: Limbs = undefined;
    var borrow: u1 = 0;
    inline for (0..limb_count) |index| {
        const first = @subWithOverflow(a[index], b[index]);
        const second = @subWithOverflow(first[0], borrow);
        result[index] = second[0];
        borrow = first[1] | second[1];
    }
    return .{ .value = result, .borrow = borrow };
}

pub fn subSmall(value: Limbs, amount: u64) Limbs {
    var result = value;
    var borrow = @subWithOverflow(result[0], amount);
    result[0] = borrow[0];
    var index: usize = 1;
    while (borrow[1] != 0 and index < result.len) : (index += 1) {
        borrow = @subWithOverflow(result[index], @as(u64, borrow[1]));
        result[index] = borrow[0];
    }
    std.debug.assert(borrow[1] == 0);
    return result;
}

pub fn shiftRightOne(value: Limbs) Limbs {
    var result: Limbs = undefined;
    var carry: u64 = 0;
    var index: usize = limb_count;
    while (index != 0) {
        index -= 1;
        result[index] = (value[index] >> 1) | carry;
        carry = value[index] << 63;
    }
    return result;
}

pub fn trailingZeroBits(value: Limbs) u7 {
    std.debug.assert(!limbsZero(value));
    // One machine word is enough per iteration. A zero low limb is shifted
    // out whole; the next iteration handles any additional zero limbs.
    return if (value[0] == 0) 64 else @ctz(value[0]);
}

pub fn shiftRightBits(value: Limbs, shift: u7) Limbs {
    std.debug.assert(shift != 0 and shift <= 64);
    var result: Limbs = undefined;
    if (shift == 64) {
        for (0..limb_count - 1) |index| result[index] = value[index + 1];
        result[limb_count - 1] = 0;
        return result;
    }
    const low_shift: u6 = @intCast(shift);
    const high_shift: u6 = @intCast(64 - shift);
    for (0..limb_count - 1) |index| {
        result[index] = (value[index] >> low_shift) |
            (value[index + 1] << high_shift);
    }
    result[limb_count - 1] = value[limb_count - 1] >> low_shift;
    return result;
}

pub fn dividePowerOfTwoModulo(
    value: Limbs,
    shift: u7,
    modulus: Limbs,
    negative_inverse: u64,
) Limbs {
    std.debug.assert(shift != 0 and shift <= 64);
    // Choose t so value + t * modulus is divisible by 2^shift. The quotient
    // is canonical because value < modulus and t < 2^shift.
    const mask = if (shift == 64)
        std.math.maxInt(u64)
    else
        (@as(u64, 1) << @as(u6, @intCast(shift))) - 1;
    const multiplier = value[0] *% negative_inverse & mask;
    var sum: [limb_count + 1]u64 = undefined;
    var carry: u128 = 0;
    inline for (0..limb_count) |index| {
        const accumulated = @as(u128, modulus[index]) * multiplier +
            value[index] + carry;
        sum[index] = @truncate(accumulated);
        carry = accumulated >> 64;
    }
    sum[limb_count] = @truncate(carry);
    std.debug.assert((sum[0] & mask) == 0);

    var result: Limbs = undefined;
    if (shift == 64) {
        @memcpy(&result, sum[1..]);
    } else {
        const low_shift: u6 = @intCast(shift);
        const high_shift: u6 = @intCast(64 - shift);
        inline for (0..limb_count) |index| {
            result[index] = (sum[index] >> low_shift) |
                (sum[index + 1] << high_shift);
        }
    }
    std.debug.assert(lessThan(result, modulus));
    return result;
}

pub fn halfModulo(value: Limbs, modulus: Limbs) Limbs {
    if ((value[0] & 1) == 0) return shiftRightOne(value);
    const sum = addRaw(value, modulus);
    std.debug.assert(sum.carry == 0);
    return shiftRightOne(sum.value);
}

pub inline fn subModulo(a: Limbs, b: Limbs, modulus: Limbs) Limbs {
    const difference = subRaw(a, b);
    if (difference.borrow == 0) return difference.value;
    const corrected = addRaw(difference.value, modulus);
    return corrected.value;
}

pub fn lessThan(a: Limbs, b: Limbs) bool {
    var index: usize = limb_count;
    while (index != 0) {
        index -= 1;
        if (a[index] != b[index]) return a[index] < b[index];
    }
    return false;
}

pub fn equal(a: Limbs, b: Limbs) bool {
    var difference: u64 = 0;
    for (a, b) |a_limb, b_limb| difference |= a_limb ^ b_limb;
    return difference == 0;
}

pub fn limbsZero(value: Limbs) bool {
    return equal(value, [_]u64{0} ** limb_count);
}

pub fn bit(value: Limbs, index: usize) bool {
    return ((value[index / 64] >> @intCast(index % 64)) & 1) != 0;
}

pub fn buildInversionSchedule() InversionSchedule {
    @setEvalBranchQuota(100_000);
    const exponent = subSmall(scalar_modulus, 2);
    comptime {
        for (inversion_tail_bits..521) |index| {
            if (!bit(exponent, index)) {
                @compileError("P-521 inverse leading-one decomposition changed");
            }
        }
    }
    var schedule = InversionSchedule{
        .steps = undefined,
        .len = 0,
    };
    var pending_squares: usize = 0;
    var bit_end: usize = inversion_tail_bits;
    while (bit_end != 0) {
        if (!bit(exponent, bit_end - 1)) {
            pending_squares += 1;
            bit_end -= 1;
            continue;
        }
        var bit_start = bit_end - @min(bit_end, inversion_window_width);
        while (!bit(exponent, bit_start)) bit_start += 1;
        var window_value: u5 = 0;
        var bit_index = bit_end;
        while (bit_index != bit_start) {
            bit_index -= 1;
            window_value = (window_value << 1) |
                @as(u1, @intFromBool(bit(exponent, bit_index)));
        }
        pending_squares += bit_end - bit_start;
        schedule.steps[schedule.len] = .{
            .squares = @intCast(pending_squares),
            .table_index = @truncate(window_value >> 1),
        };
        schedule.len += 1;
        pending_squares = 0;
        bit_end = bit_start;
    }
    std.debug.assert(pending_squares == 0);
    return schedule;
}

pub fn one() Limbs {
    return .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 };
}

pub fn decode(encoded: []const u8) Limbs {
    var result = [_]u64{0} ** limb_count;
    var source_end = encoded.len;
    var destination: usize = 0;
    while (source_end != 0) : (destination += 1) {
        const source_start = source_end - @min(source_end, @sizeOf(u64));
        var limb: u64 = 0;
        for (encoded[source_start..source_end]) |byte| {
            limb = (limb << 8) | byte;
        }
        result[destination] = limb;
        source_end = source_start;
    }
    return result;
}

pub fn limbsFromHex(comptime encoded: []const u8) Limbs {
    @setEvalBranchQuota(10_000);
    if (encoded.len > 2 * limb_count * @sizeOf(u64)) {
        @compileError("integer does not fit P-521 limb representation");
    }
    var result = [_]u64{0} ** limb_count;
    for (encoded) |character| {
        const nibble: u64 = switch (character) {
            '0'...'9' => character - '0',
            'a'...'f' => character - 'a' + 10,
            'A'...'F' => character - 'A' + 10,
            else => @compileError("invalid hexadecimal integer"),
        };
        var carry = nibble;
        for (&result) |*limb| {
            const next = limb.* >> 60;
            limb.* = (limb.* << 4) | carry;
            carry = next;
        }
        if (carry != 0) @compileError("integer overflow");
    }
    return result;
}

pub inline fn fieldAdd(a: FieldLimbs, b: FieldLimbs) FieldLimbs {
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count) |index| {
        const sum = a[index] + b[index] + carry;
        result[index] = sum & field_mask;
        carry = sum >> field_radix_bits;
    }
    std.debug.assert(carry == 0);
    return fieldReduce(result);
}

pub inline fn fieldMulSmall(
    a: FieldLimbs,
    comptime multiplier: u4,
) FieldLimbs {
    var result: FieldLimbs = undefined;
    var carry: u64 = 0;
    inline for (0..limb_count - 1) |index| {
        const product = a[index] * multiplier + carry;
        result[index] = product & field_mask;
        carry = product >> field_radix_bits;
    }
    const top = a[limb_count - 1] * multiplier + carry;
    result[limb_count - 1] = top;
    return fieldReduce(result);
}

pub inline fn fieldSub(a: FieldLimbs, b: FieldLimbs) FieldLimbs {
    if (!fieldLessThan(a, b)) return fieldSubRaw(a, b);
    return fieldSubRaw(field_modulus, fieldSubRaw(b, a));
}

pub inline fn fieldSubRaw(a: FieldLimbs, b: FieldLimbs) FieldLimbs {
    var result: FieldLimbs = undefined;
    var borrow: u64 = 0;
    inline for (0..limb_count) |index| {
        const subtrahend = b[index] + borrow;
        if (a[index] >= subtrahend) {
            result[index] = a[index] - subtrahend;
            borrow = 0;
        } else {
            result[index] = (@as(u64, 1) << field_radix_bits) +
                a[index] - subtrahend;
            borrow = 1;
        }
    }
    std.debug.assert(borrow == 0);
    return result;
}

pub fn powTwoMinusOneSecret(base: SecretFe, count: usize) SecretFe {
    std.debug.assert(count != 0);
    if (count == 1) return base;
    const half_count = count / 2;
    const half = powTwoMinusOneSecret(base, half_count);
    var result = half;
    for (0..half_count) |_| result = result.sq();
    result = result.mul(half);
    if (count % 2 != 0) result = result.sq().mul(base);
    return result;
}

pub fn fieldLimbsFromHex(comptime encoded: []const u8) FieldLimbs {
    @setEvalBranchQuota(10_000);
    var result = [_]u64{0} ** limb_count;
    for (encoded) |character| {
        const nibble: u64 = switch (character) {
            '0'...'9' => character - '0',
            'a'...'f' => character - 'a' + 10,
            'A'...'F' => character - 'A' + 10,
            else => @compileError("invalid hexadecimal field element"),
        };
        var carry: u128 = nibble;
        for (&result) |*limb| {
            const value = (@as(u128, limb.*) << 4) | carry;
            limb.* = @truncate(value & field_mask);
            carry = value >> field_radix_bits;
        }
        if (carry != 0) @compileError("field element overflow");
    }
    return result;
}

pub inline fn opaqueWord(value: u64) u64 {
    if (@inComptime()) return value;
    return asm volatile (""
        : [result] "=r" (-> u64),
        : [input] "0" (value),
    );
}

pub const scalar_modulus = limbsFromHex(
    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa" ++
        "51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
);
