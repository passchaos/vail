//! Fixed-width RSA Montgomery arithmetic.
//!
//! This module contains the specialized 1024-bit paired-prime and 2048-bit
//! public-exponent Montgomery kernels used by `rsa.zig`.

const std = @import("std");
const builtin = @import("builtin");

const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFieldElement = RsaModulus.Fe;
const PrimeModulus = std.crypto.ff.Modulus(2048);
const PrimeFieldElement = PrimeModulus.Fe;

pub const Error = error{InvalidPrivateKey};

const use_x86_64_adx_montgomery = builtin.cpu.arch == .x86_64 and
    builtin.os.tag == .linux and
    builtin.mode != .Debug and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

/// Keep secret-derived masks opaque to LLVM. Without this barrier LLVM can
/// legally turn mask-and-select expressions into secret-dependent branches or
/// table loads, even though the Zig source expression itself is branchless.
inline fn opaqueWord(value: u64) u64 {
    if (@inComptime()) return value;
    return asm volatile (""
        : [result] "=r" (-> u64),
        : [input] "0" (value),
    );
}

/// Fixed-width Montgomery arithmetic for the two 1024-bit prime fields in an
/// RSA-2048 CRT operation. `std.crypto.ff` deliberately reserves one carry bit
/// per machine word; this specialized path instead uses full 64-bit limbs and
/// `u128` products, reducing both the limb count and the inner-loop traffic.
pub const Montgomery1024 = struct {
    pub const limb_count = 16;
    pub const encoded_length = limb_count * @sizeOf(u64);
    pub const Limbs = [limb_count]u64;
    pub const Pair = struct {
        first: Limbs,
        second: Limbs,
    };
    pub const PairWorkspace = struct {
        first: [limb_count + 2]u64 = [_]u64{0} ** (limb_count + 2),
        second: [limb_count + 2]u64 = [_]u64{0} ** (limb_count + 2),

        pub fn reset(self: *PairWorkspace) void {
            @memset(&self.first, 0);
            @memset(&self.second, 0);
        }

        pub fn clear(self: *PairWorkspace) void {
            std.crypto.secureZero(PairWorkspace, self[0..1]);
        }
    };
    pub const ProductPairWorkspace = struct {
        first: [2 * limb_count + 1]u64 =
            [_]u64{0} ** (2 * limb_count + 1),
        second: [2 * limb_count + 1]u64 =
            [_]u64{0} ** (2 * limb_count + 1),

        pub fn clear(self: *ProductPairWorkspace) void {
            std.crypto.secureZero(ProductPairWorkspace, self[0..1]);
        }
    };
    modulus: Limbs,
    negative_inverse: u64,
    r_squared: Limbs,
    one_montgomery: Limbs,

    pub fn init(modulus_bytes: []const u8) Error!Montgomery1024 {
        if (modulus_bytes.len == 0 or
            modulus_bytes.len > encoded_length or
            (modulus_bytes[modulus_bytes.len - 1] & 1) == 0)
        {
            return error.InvalidPrivateKey;
        }
        const modulus = decode(modulus_bytes);
        if (isZero(modulus)) return error.InvalidPrivateKey;

        var inverse: u64 = 1;
        inline for (0..6) |_| {
            inverse *%= 2 -% modulus[0] *% inverse;
        }
        var r_squared = one();
        for (0..2 * limb_count * @bitSizeOf(u64)) |_| {
            r_squared = doubleMod(r_squared, modulus);
        }
        var result = Montgomery1024{
            .modulus = modulus,
            .negative_inverse = 0 -% inverse,
            .r_squared = r_squared,
            .one_montgomery = undefined,
        };
        result.one_montgomery = result.mul(one(), result.r_squared);
        return result;
    }

    pub fn powSecret(
        self: *const Montgomery1024,
        base_bytes: []const u8,
        exponent_bytes: []const u8,
    ) Error!Limbs {
        if (base_bytes.len > encoded_length or
            exponent_bytes.len > encoded_length or
            exponent_bytes.len == 0)
        {
            return error.InvalidPrivateKey;
        }
        const base = decode(base_bytes);
        if (!lessThan(base, self.modulus)) return error.InvalidPrivateKey;

        var exponent = [_]u8{0} ** encoded_length;
        defer std.crypto.secureZero(u8, &exponent);
        @memcpy(exponent[encoded_length - exponent_bytes.len ..], exponent_bytes);

        var table: [16]Limbs = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&table));
        table[0] = self.toMontgomery(one());
        table[1] = self.toMontgomery(base);
        for (2..table.len) |index| {
            table[index] = self.mul(table[index - 1], table[1]);
        }

        var result = table[0];
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
        for (exponent) |byte| {
            inline for ([_]u3{ 4, 0 }) |shift| {
                inline for (0..4) |_| result = self.mul(result, result);
                var selected = selectTable(
                    table.len,
                    &table,
                    (byte >> shift) & 0x0f,
                );
                result = self.mul(result, selected);
                std.crypto.secureZero(u8, std.mem.asBytes(&selected));
            }
        }
        return self.fromMontgomery(result);
    }

    pub fn powSecretPair(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        base_values: Pair,
        first_exponent_bytes: []const u8,
        second_exponent_bytes: []const u8,
    ) Error!Pair {
        if (first_exponent_bytes.len > encoded_length or
            second_exponent_bytes.len > encoded_length or
            first_exponent_bytes.len == 0 or
            second_exponent_bytes.len == 0)
        {
            return error.InvalidPrivateKey;
        }
        var bases = base_values;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&bases));
        if (!lessThan(bases.first, first_context.modulus) or
            !lessThan(bases.second, second_context.modulus))
        {
            return error.InvalidPrivateKey;
        }

        var first_exponent = [_]u8{0} ** encoded_length;
        defer std.crypto.secureZero(u8, &first_exponent);
        @memcpy(
            first_exponent[encoded_length - first_exponent_bytes.len ..],
            first_exponent_bytes,
        );
        var second_exponent = [_]u8{0} ** encoded_length;
        defer std.crypto.secureZero(u8, &second_exponent);
        @memcpy(
            second_exponent[encoded_length - second_exponent_bytes.len ..],
            second_exponent_bytes,
        );
        var workspace = PairWorkspace{};
        defer workspace.clear();
        var product_workspace = ProductPairWorkspace{};
        defer product_workspace.clear();
        var first_table: [32]Limbs = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&first_table));
        var second_table: [32]Limbs = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&second_table));
        first_table[0] = first_context.one_montgomery;
        second_table[0] = second_context.one_montgomery;
        const base_pair = mulPairOptimizedWithWorkspaces(
            first_context,
            second_context,
            &workspace,
            &product_workspace,
            bases.first,
            bases.second,
            first_context.r_squared,
            second_context.r_squared,
        );
        first_table[1] = base_pair.first;
        second_table[1] = base_pair.second;
        for (1..first_table.len / 2) |index| {
            const squares = squarePairWithWorkspaces(
                first_context,
                second_context,
                &workspace,
                &product_workspace,
                first_table[index],
                second_table[index],
            );
            first_table[2 * index] = squares.first;
            second_table[2 * index] = squares.second;
            const odd_powers = mulPairOptimizedWithWorkspaces(
                first_context,
                second_context,
                &workspace,
                &product_workspace,
                squares.first,
                squares.second,
                first_table[1],
                second_table[1],
            );
            first_table[2 * index + 1] = odd_powers.first;
            second_table[2 * index + 1] = odd_powers.second;
        }

        var result = selectTablePair(
            first_table.len,
            &first_table,
            &second_table,
            readBits(&first_exponent, 0, 4),
            readBits(&second_exponent, 0, 4),
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));

        var bit_offset: usize = 4;
        while (bit_offset < encoded_length * 8) : (bit_offset += 5) {
            inline for (0..5) |_| {
                result = squarePairWithWorkspaces(
                    first_context,
                    second_context,
                    &workspace,
                    &product_workspace,
                    result.first,
                    result.second,
                );
            }
            var selected = selectTablePair(
                first_table.len,
                &first_table,
                &second_table,
                readBits(&first_exponent, bit_offset, 5),
                readBits(&second_exponent, bit_offset, 5),
            );
            result = mulPairOptimizedWithWorkspaces(
                first_context,
                second_context,
                &workspace,
                &product_workspace,
                result.first,
                result.second,
                selected.first,
                selected.second,
            );
            std.crypto.secureZero(u8, std.mem.asBytes(&selected));
        }
        return mulPairOptimizedWithWorkspaces(
            first_context,
            second_context,
            &workspace,
            &product_workspace,
            result.first,
            result.second,
            one(),
            one(),
        );
    }

    pub fn pow65537Pair(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        base_values: Pair,
    ) Pair {
        std.debug.assert(lessThan(base_values.first, first_context.modulus));
        std.debug.assert(lessThan(base_values.second, second_context.modulus));
        var workspace = PairWorkspace{};
        defer workspace.clear();
        var product_workspace = ProductPairWorkspace{};
        defer product_workspace.clear();
        var base_montgomery = mulPairOptimizedWithWorkspaces(
            first_context,
            second_context,
            &workspace,
            &product_workspace,
            base_values.first,
            base_values.second,
            first_context.r_squared,
            second_context.r_squared,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&base_montgomery));
        var result = base_montgomery;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
        inline for (0..16) |_| {
            result = squarePairWithWorkspaces(
                first_context,
                second_context,
                &workspace,
                &product_workspace,
                result.first,
                result.second,
            );
        }
        result = mulPairOptimizedWithWorkspaces(
            first_context,
            second_context,
            &workspace,
            &product_workspace,
            result.first,
            result.second,
            base_montgomery.first,
            base_montgomery.second,
        );
        return mulPairOptimizedWithWorkspaces(
            first_context,
            second_context,
            &workspace,
            &product_workspace,
            result.first,
            result.second,
            one(),
            one(),
        );
    }

    pub fn toMontgomery(self: *const Montgomery1024, value: Limbs) Limbs {
        return self.mul(value, self.r_squared);
    }

    pub fn fromMontgomery(self: *const Montgomery1024, value: Limbs) Limbs {
        return self.mul(value, one());
    }

    pub fn mul(self: *const Montgomery1024, a: Limbs, b: Limbs) Limbs {
        var intermediate = [_]u64{0} ** (limb_count + 2);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&intermediate));

        for (0..limb_count) |i| {
            var carry: u128 = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, a[j]) * b[i] +
                    intermediate[j] + carry;
                intermediate[j] = @truncate(wide);
                carry = wide >> 64;
            }
            const upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count] = upper[0];
            intermediate[limb_count + 1] = upper[1];

            const factor = intermediate[0] *% self.negative_inverse;
            carry = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, factor) * self.modulus[j] +
                    intermediate[j] + carry;
                if (j != 0) intermediate[j - 1] = @truncate(wide);
                carry = wide >> 64;
            }
            const reduced_upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count - 1] = reduced_upper[0];
            intermediate[limb_count] = intermediate[limb_count + 1] +%
                reduced_upper[1];
            intermediate[limb_count + 1] = 0;
        }

        const unreduced: Limbs = intermediate[0..limb_count].*;
        return self.reduceLimbs(unreduced, intermediate[limb_count]);
    }

    pub fn mulPair(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        first_a: Limbs,
        second_a: Limbs,
        first_b: Limbs,
        second_b: Limbs,
    ) Pair {
        var first_intermediate = [_]u64{0} ** (limb_count + 2);
        defer std.crypto.secureZero(
            u8,
            std.mem.asBytes(&first_intermediate),
        );
        var second_intermediate = [_]u64{0} ** (limb_count + 2);
        defer std.crypto.secureZero(
            u8,
            std.mem.asBytes(&second_intermediate),
        );

        for (0..limb_count) |i| {
            var first_carry: u128 = 0;
            var second_carry: u128 = 0;
            inline for (0..limb_count) |j| {
                const first_wide = @as(u128, first_a[j]) * first_b[i] +
                    first_intermediate[j] + first_carry;
                first_intermediate[j] = @truncate(first_wide);
                first_carry = first_wide >> 64;
                const second_wide = @as(u128, second_a[j]) * second_b[i] +
                    second_intermediate[j] + second_carry;
                second_intermediate[j] = @truncate(second_wide);
                second_carry = second_wide >> 64;
            }
            const first_upper = @addWithOverflow(
                first_intermediate[limb_count],
                @as(u64, @truncate(first_carry)),
            );
            first_intermediate[limb_count] = first_upper[0];
            first_intermediate[limb_count + 1] = first_upper[1];
            const second_upper = @addWithOverflow(
                second_intermediate[limb_count],
                @as(u64, @truncate(second_carry)),
            );
            second_intermediate[limb_count] = second_upper[0];
            second_intermediate[limb_count + 1] = second_upper[1];

            const first_factor = first_intermediate[0] *%
                first_context.negative_inverse;
            const second_factor = second_intermediate[0] *%
                second_context.negative_inverse;
            first_carry = 0;
            second_carry = 0;
            inline for (0..limb_count) |j| {
                const first_wide = @as(u128, first_factor) *
                    first_context.modulus[j] +
                    first_intermediate[j] + first_carry;
                if (j != 0) first_intermediate[j - 1] = @truncate(first_wide);
                first_carry = first_wide >> 64;
                const second_wide = @as(u128, second_factor) *
                    second_context.modulus[j] +
                    second_intermediate[j] + second_carry;
                if (j != 0) second_intermediate[j - 1] = @truncate(second_wide);
                second_carry = second_wide >> 64;
            }
            const first_reduced_upper = @addWithOverflow(
                first_intermediate[limb_count],
                @as(u64, @truncate(first_carry)),
            );
            first_intermediate[limb_count - 1] = first_reduced_upper[0];
            first_intermediate[limb_count] =
                first_intermediate[limb_count + 1] +%
                first_reduced_upper[1];
            first_intermediate[limb_count + 1] = 0;
            const second_reduced_upper = @addWithOverflow(
                second_intermediate[limb_count],
                @as(u64, @truncate(second_carry)),
            );
            second_intermediate[limb_count - 1] = second_reduced_upper[0];
            second_intermediate[limb_count] =
                second_intermediate[limb_count + 1] +%
                second_reduced_upper[1];
            second_intermediate[limb_count + 1] = 0;
        }

        return .{
            .first = first_context.reduceLimbs(
                first_intermediate[0..limb_count].*,
                first_intermediate[limb_count],
            ),
            .second = second_context.reduceLimbs(
                second_intermediate[0..limb_count].*,
                second_intermediate[limb_count],
            ),
        };
    }

    pub fn mulPairFios(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        first_a: Limbs,
        second_a: Limbs,
        first_b: Limbs,
        second_b: Limbs,
    ) Pair {
        var workspace = PairWorkspace{};
        defer workspace.clear();
        return mulPairFiosWithWorkspace(
            first_context,
            second_context,
            &workspace,
            first_a,
            second_a,
            first_b,
            second_b,
        );
    }

    pub fn squarePairWithWorkspaces(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        multiply_workspace: *PairWorkspace,
        product_workspace: *ProductPairWorkspace,
        first_value: Limbs,
        second_value: Limbs,
    ) Pair {
        if (comptime !use_x86_64_adx_montgomery) {
            return mulPairFiosWithWorkspace(
                first_context,
                second_context,
                multiply_workspace,
                first_value,
                second_value,
                first_value,
                second_value,
            );
        }

        vailMontgomery1024SquareProductPair(
            &product_workspace.first,
            &product_workspace.second,
            &first_value,
            &second_value,
        );
        vailMontgomery1024ReduceProductPair(
            first_context,
            second_context,
            &product_workspace.first,
            &product_workspace.second,
        );
        var reduced: Pair = undefined;
        vailMontgomery1024FinishPair(
            &reduced,
            first_context,
            second_context,
            product_workspace.first[limb_count .. 2 * limb_count],
            product_workspace.second[limb_count .. 2 * limb_count],
            product_workspace.first[2 * limb_count],
            product_workspace.second[2 * limb_count],
        );
        return reduced;
    }

    pub fn mulPairOptimizedWithWorkspaces(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        multiply_workspace: *PairWorkspace,
        product_workspace: *ProductPairWorkspace,
        first_a: Limbs,
        second_a: Limbs,
        first_b: Limbs,
        second_b: Limbs,
    ) Pair {
        if (comptime !use_x86_64_adx_montgomery) {
            return mulPairFiosWithWorkspace(
                first_context,
                second_context,
                multiply_workspace,
                first_a,
                second_a,
                first_b,
                second_b,
            );
        }

        vailMontgomery1024ProductPair(
            &product_workspace.first,
            &product_workspace.second,
            &first_a,
            &second_a,
            &first_b,
            &second_b,
        );
        vailMontgomery1024ReduceProductPair(
            first_context,
            second_context,
            &product_workspace.first,
            &product_workspace.second,
        );
        var reduced: Pair = undefined;
        vailMontgomery1024FinishPair(
            &reduced,
            first_context,
            second_context,
            product_workspace.first[limb_count .. 2 * limb_count],
            product_workspace.second[limb_count .. 2 * limb_count],
            product_workspace.first[2 * limb_count],
            product_workspace.second[2 * limb_count],
        );
        return reduced;
    }

    pub fn mulPairFiosWithWorkspace(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        workspace: *PairWorkspace,
        first_a: Limbs,
        second_a: Limbs,
        first_b: Limbs,
        second_b: Limbs,
    ) Pair {
        const first_intermediate = &workspace.first;
        const second_intermediate = &workspace.second;

        for (0..limb_count) |i| {
            const first_initial = @as(u128, first_a[0]) * first_b[i] +
                first_intermediate[0];
            var first_multiply_carry: u64 = @truncate(first_initial >> 64);
            const first_factor = @as(u64, @truncate(first_initial)) *%
                first_context.negative_inverse;
            const first_reduced_initial = @as(u128, first_factor) *
                first_context.modulus[0] + @as(u64, @truncate(first_initial));
            std.debug.assert(@as(u64, @truncate(first_reduced_initial)) == 0);
            var first_reduce_carry: u64 = @truncate(
                first_reduced_initial >> 64,
            );

            const second_initial = @as(u128, second_a[0]) * second_b[i] +
                second_intermediate[0];
            var second_multiply_carry: u64 = @truncate(second_initial >> 64);
            const second_factor = @as(u64, @truncate(second_initial)) *%
                second_context.negative_inverse;
            const second_reduced_initial = @as(u128, second_factor) *
                second_context.modulus[0] + @as(u64, @truncate(second_initial));
            std.debug.assert(@as(u64, @truncate(second_reduced_initial)) == 0);
            var second_reduce_carry: u64 = @truncate(
                second_reduced_initial >> 64,
            );

            inline for (1..limb_count) |j| {
                const first_product = @as(u128, first_a[j]) * first_b[i] +
                    first_intermediate[j] + first_multiply_carry;
                first_multiply_carry = @truncate(first_product >> 64);
                const first_reduced = @as(u128, first_factor) *
                    first_context.modulus[j] +
                    @as(u64, @truncate(first_product)) + first_reduce_carry;
                first_intermediate[j - 1] = @truncate(first_reduced);
                first_reduce_carry = @truncate(first_reduced >> 64);

                const second_product = @as(u128, second_a[j]) * second_b[i] +
                    second_intermediate[j] + second_multiply_carry;
                second_multiply_carry = @truncate(second_product >> 64);
                const second_reduced = @as(u128, second_factor) *
                    second_context.modulus[j] +
                    @as(u64, @truncate(second_product)) + second_reduce_carry;
                second_intermediate[j - 1] = @truncate(second_reduced);
                second_reduce_carry = @truncate(second_reduced >> 64);
            }

            const first_upper = @addWithOverflow(
                first_intermediate[limb_count],
                first_multiply_carry,
            );
            const first_reduced_upper = @addWithOverflow(
                first_upper[0],
                first_reduce_carry,
            );
            first_intermediate[limb_count - 1] = first_reduced_upper[0];
            first_intermediate[limb_count] =
                first_intermediate[limb_count + 1] +%
                first_upper[1] +% first_reduced_upper[1];
            first_intermediate[limb_count + 1] = 0;

            const second_upper = @addWithOverflow(
                second_intermediate[limb_count],
                second_multiply_carry,
            );
            const second_reduced_upper = @addWithOverflow(
                second_upper[0],
                second_reduce_carry,
            );
            second_intermediate[limb_count - 1] = second_reduced_upper[0];
            second_intermediate[limb_count] =
                second_intermediate[limb_count + 1] +%
                second_upper[1] +% second_reduced_upper[1];
            second_intermediate[limb_count + 1] = 0;
        }

        const result = reduceLimbsPair(
            first_context,
            second_context,
            first_intermediate[0..limb_count].*,
            second_intermediate[0..limb_count].*,
            first_intermediate[limb_count],
            second_intermediate[limb_count],
        );
        workspace.reset();
        return result;
    }

    pub fn mulProduct(self: *const Montgomery1024, a: Limbs, b: Limbs) Limbs {
        var product = [_]u64{0} ** (2 * limb_count + 1);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&product));

        for (0..limb_count) |i| {
            var carry: u128 = 0;
            for (0..limb_count) |j| {
                const column = i + j;
                const wide = @as(u128, a[i]) * b[j] +
                    product[column] + carry;
                product[column] = @truncate(wide);
                carry = wide >> 64;
            }
            product[i + limb_count] = @truncate(carry);
        }
        return self.reduceProduct(&product);
    }

    pub fn crtRecombine(
        self: *const Montgomery1024,
        first_residue: Limbs,
        second_residue: Limbs,
        second_prime_bytes: []const u8,
        coefficient_bytes: []const u8,
    ) Error![2 * limb_count]u64 {
        if (second_prime_bytes.len > encoded_length or
            coefficient_bytes.len > encoded_length)
        {
            return error.InvalidPrivateKey;
        }
        var second_prime = decode(second_prime_bytes);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&second_prime));
        var coefficient = decode(coefficient_bytes);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&coefficient));
        if (!lessThan(coefficient, self.modulus)) {
            return error.InvalidPrivateKey;
        }

        var second_mod_first = self.reduceLimbs(second_residue, 0);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&second_mod_first));
        var difference = subMod(
            first_residue,
            second_mod_first,
            self.modulus,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&difference));
        var difference_montgomery = self.toMontgomery(difference);
        defer std.crypto.secureZero(
            u8,
            std.mem.asBytes(&difference_montgomery),
        );
        var multiplier = self.mul(difference_montgomery, coefficient);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&multiplier));

        var recombined = multiplyWide(second_prime, multiplier);
        var carry: u1 = 0;
        for (0..2 * limb_count) |index| {
            const addend = if (index < limb_count)
                second_residue[index]
            else
                0;
            const first_sum = @addWithOverflow(recombined[index], addend);
            const second_sum = @addWithOverflow(first_sum[0], carry);
            recombined[index] = second_sum[0];
            carry = first_sum[1] | second_sum[1];
        }
        if (carry != 0) return error.InvalidPrivateKey;
        return recombined;
    }

    pub fn reduceWidePair(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        encoded: *const [2 * encoded_length]u8,
    ) Pair {
        var wide = decodeWide(encoded);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&wide));
        var low: Limbs = wide[0..limb_count].*;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&low));
        var high: Limbs = wide[limb_count .. 2 * limb_count].*;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&high));
        const first_low = first_context.reduceLimbs(low, 0);
        const second_low = second_context.reduceLimbs(low, 0);
        const high_shifted = mulPairFios(
            first_context,
            second_context,
            first_context.reduceLimbs(high, 0),
            second_context.reduceLimbs(high, 0),
            first_context.r_squared,
            second_context.r_squared,
        );
        return .{
            .first = addMod(
                high_shifted.first,
                first_low,
                first_context.modulus,
            ),
            .second = addMod(
                high_shifted.second,
                second_low,
                second_context.modulus,
            ),
        };
    }

    pub fn multiplyWide(a: Limbs, b: Limbs) [2 * limb_count]u64 {
        var product = [_]u64{0} ** (2 * limb_count);
        for (0..limb_count) |i| {
            var carry: u128 = 0;
            for (0..limb_count) |j| {
                const column = i + j;
                const wide = @as(u128, a[i]) * b[j] +
                    product[column] + carry;
                product[column] = @truncate(wide);
                carry = wide >> 64;
            }
            product[i + limb_count] = @truncate(carry);
        }
        return product;
    }

    pub fn reduceProduct(
        self: *const Montgomery1024,
        product: *[2 * limb_count + 1]u64,
    ) Limbs {
        for (0..limb_count) |i| {
            const factor = product[i] *% self.negative_inverse;
            var carry: u128 = 0;
            for (0..limb_count) |j| {
                const column = i + j;
                const wide = @as(u128, factor) * self.modulus[j] +
                    product[column] + carry;
                product[column] = @truncate(wide);
                carry = wide >> 64;
            }

            var column = i + limb_count;
            var sum = @addWithOverflow(product[column], @as(u64, @truncate(carry)));
            product[column] = sum[0];
            var propagation = sum[1];
            column += 1;
            while (column < product.len) : (column += 1) {
                sum = @addWithOverflow(product[column], propagation);
                product[column] = sum[0];
                propagation = sum[1];
            }
        }

        var unreduced: Limbs = undefined;
        @memcpy(&unreduced, product[limb_count .. 2 * limb_count]);
        return self.reduceLimbs(unreduced, product[2 * limb_count]);
    }

    pub fn reduceLimbs(
        self: *const Montgomery1024,
        unreduced_value: Limbs,
        extra: u64,
    ) Limbs {
        var unreduced = unreduced_value;
        var reduced: Limbs = undefined;
        var borrow: u1 = 0;
        for (0..limb_count) |i| {
            const first = @subWithOverflow(unreduced[i], self.modulus[i]);
            const second = @subWithOverflow(first[0], borrow);
            reduced[i] = second[0];
            borrow = first[1] | second[1];
        }
        const has_extra: u1 = @intFromBool(extra != 0);
        const use_reduced = has_extra | (borrow ^ 1);
        const mask = opaqueWord(0 -% @as(u64, use_reduced));
        for (&unreduced, reduced) |*out, candidate| {
            out.* = (candidate & mask) | (out.* & ~mask);
        }
        return unreduced;
    }

    pub fn reduceLimbsPair(
        first_context: *const Montgomery1024,
        second_context: *const Montgomery1024,
        first_unreduced_value: Limbs,
        second_unreduced_value: Limbs,
        first_extra: u64,
        second_extra: u64,
    ) Pair {
        var first_unreduced = first_unreduced_value;
        var second_unreduced = second_unreduced_value;
        var first_reduced: Limbs = undefined;
        var second_reduced: Limbs = undefined;
        var first_borrow: u1 = 0;
        var second_borrow: u1 = 0;
        for (0..limb_count) |i| {
            const first_subtract = @subWithOverflow(
                first_unreduced[i],
                first_context.modulus[i],
            );
            const second_subtract = @subWithOverflow(
                second_unreduced[i],
                second_context.modulus[i],
            );
            const first_with_borrow = @subWithOverflow(
                first_subtract[0],
                first_borrow,
            );
            const second_with_borrow = @subWithOverflow(
                second_subtract[0],
                second_borrow,
            );
            first_reduced[i] = first_with_borrow[0];
            second_reduced[i] = second_with_borrow[0];
            first_borrow = first_subtract[1] | first_with_borrow[1];
            second_borrow = second_subtract[1] | second_with_borrow[1];
        }
        const first_use_reduced = @as(u1, @intFromBool(first_extra != 0)) |
            (first_borrow ^ 1);
        const second_use_reduced = @as(u1, @intFromBool(second_extra != 0)) |
            (second_borrow ^ 1);
        const first_mask = opaqueWord(0 -% @as(u64, first_use_reduced));
        const second_mask = opaqueWord(0 -% @as(u64, second_use_reduced));
        for (
            &first_unreduced,
            &second_unreduced,
            first_reduced,
            second_reduced,
        ) |*first_out, *second_out, first_candidate, second_candidate| {
            first_out.* = (first_candidate & first_mask) |
                (first_out.* & ~first_mask);
            second_out.* = (second_candidate & second_mask) |
                (second_out.* & ~second_mask);
        }
        return .{ .first = first_unreduced, .second = second_unreduced };
    }

    pub fn subMod(a: Limbs, b: Limbs, modulus: Limbs) Limbs {
        var difference: Limbs = undefined;
        var borrow: u1 = 0;
        for (0..limb_count) |index| {
            const first = @subWithOverflow(a[index], b[index]);
            const second = @subWithOverflow(first[0], borrow);
            difference[index] = second[0];
            borrow = first[1] | second[1];
        }

        var corrected: Limbs = undefined;
        var carry: u1 = 0;
        for (0..limb_count) |index| {
            const first = @addWithOverflow(difference[index], modulus[index]);
            const second = @addWithOverflow(first[0], carry);
            corrected[index] = second[0];
            carry = first[1] | second[1];
        }
        const mask = opaqueWord(0 -% @as(u64, borrow));
        for (&difference, corrected) |*out, candidate| {
            out.* = (candidate & mask) | (out.* & ~mask);
        }
        return difference;
    }

    pub fn addMod(a: Limbs, b: Limbs, modulus: Limbs) Limbs {
        var sum: Limbs = undefined;
        var carry: u1 = 0;
        for (0..limb_count) |index| {
            const first = @addWithOverflow(a[index], b[index]);
            const second = @addWithOverflow(first[0], carry);
            sum[index] = second[0];
            carry = first[1] | second[1];
        }

        var reduced: Limbs = undefined;
        var borrow: u1 = 0;
        for (0..limb_count) |index| {
            const first = @subWithOverflow(sum[index], modulus[index]);
            const second = @subWithOverflow(first[0], borrow);
            reduced[index] = second[0];
            borrow = first[1] | second[1];
        }
        const use_reduced = carry | (borrow ^ 1);
        const mask = opaqueWord(0 -% @as(u64, use_reduced));
        for (&sum, reduced) |*out, candidate| {
            out.* = (candidate & mask) | (out.* & ~mask);
        }
        return sum;
    }

    pub fn selectTable(
        comptime count: usize,
        table: *const [count]Limbs,
        index: u8,
    ) Limbs {
        var selected = [_]u64{0} ** limb_count;
        for (table, 0..) |entry, candidate_index| {
            const difference: u16 = index ^ @as(u8, @intCast(candidate_index));
            const equal: u1 = @truncate((difference -% 1) >> 8);
            const mask = opaqueWord(0 -% @as(u64, equal));
            for (&selected, entry) |*out, limb| out.* |= limb & mask;
        }
        return selected;
    }

    pub fn selectTablePair(
        comptime count: usize,
        first_table: *const [count]Limbs,
        second_table: *const [count]Limbs,
        first_index: u8,
        second_index: u8,
    ) Pair {
        var selected = Pair{
            .first = [_]u64{0} ** limb_count,
            .second = [_]u64{0} ** limb_count,
        };
        for (0..count) |candidate_index| {
            const candidate: u8 = @intCast(candidate_index);
            const first_difference: u16 = first_index ^ candidate;
            const second_difference: u16 = second_index ^ candidate;
            const first_equal: u1 = @truncate(
                (first_difference -% 1) >> 8,
            );
            const second_equal: u1 = @truncate(
                (second_difference -% 1) >> 8,
            );
            const first_mask = opaqueWord(0 -% @as(u64, first_equal));
            const second_mask = opaqueWord(0 -% @as(u64, second_equal));
            for (
                &selected.first,
                &selected.second,
                first_table[candidate_index],
                second_table[candidate_index],
            ) |*first_out, *second_out, first_limb, second_limb| {
                first_out.* |= first_limb & first_mask;
                second_out.* |= second_limb & second_mask;
            }
        }
        return selected;
    }

    pub fn readBits(
        encoded: *const [encoded_length]u8,
        bit_offset: usize,
        comptime count: usize,
    ) u8 {
        var result: u8 = 0;
        inline for (0..count) |relative| {
            const position = bit_offset + relative;
            const byte = encoded[position / 8];
            const shift: u3 = @intCast(7 - position % 8);
            result = (result << 1) | @as(u1, @truncate(byte >> shift));
        }
        return result;
    }

    pub fn doubleMod(value: Limbs, modulus: Limbs) Limbs {
        var doubled: Limbs = undefined;
        var carry: u1 = 0;
        for (value, 0..) |limb, index| {
            const sum = @addWithOverflow(limb, limb);
            doubled[index] = sum[0] | carry;
            carry = sum[1];
        }

        var reduced: Limbs = undefined;
        var borrow: u1 = 0;
        for (0..limb_count) |index| {
            const first = @subWithOverflow(doubled[index], modulus[index]);
            const second = @subWithOverflow(first[0], borrow);
            reduced[index] = second[0];
            borrow = first[1] | second[1];
        }
        const use_reduced = carry | (borrow ^ 1);
        const mask = opaqueWord(0 -% @as(u64, use_reduced));
        for (&doubled, reduced) |*out, candidate| {
            out.* = (candidate & mask) | (out.* & ~mask);
        }
        return doubled;
    }

    pub fn decode(bytes: []const u8) Limbs {
        var result = [_]u64{0} ** limb_count;
        var source_end = bytes.len;
        var destination: usize = 0;
        while (source_end != 0) : (destination += 1) {
            const source_start = source_end - @min(source_end, @sizeOf(u64));
            var limb: u64 = 0;
            for (bytes[source_start..source_end]) |byte| {
                limb = (limb << 8) | byte;
            }
            result[destination] = limb;
            source_end = source_start;
        }
        return result;
    }

    pub fn decodeWide(bytes: *const [2 * encoded_length]u8) [2 * limb_count]u64 {
        var result = [_]u64{0} ** (2 * limb_count);
        for (&result, 0..) |*limb, index| {
            limb.* = std.mem.readInt(
                u64,
                bytes[2 * encoded_length - (index + 1) * 8 ..][0..8],
                .big,
            );
        }
        return result;
    }

    pub fn encode(value: Limbs, output: *[encoded_length]u8) void {
        for (value, 0..) |limb, index| {
            std.mem.writeInt(
                u64,
                output[encoded_length - (index + 1) * 8 ..][0..8],
                limb,
                .big,
            );
        }
    }

    pub fn encodeWide(
        value: [2 * limb_count]u64,
        output: *[2 * encoded_length]u8,
    ) void {
        for (value, 0..) |limb, index| {
            std.mem.writeInt(
                u64,
                output[2 * encoded_length - (index + 1) * 8 ..][0..8],
                limb,
                .big,
            );
        }
    }

    pub fn one() Limbs {
        var value = [_]u64{0} ** limb_count;
        value[0] = 1;
        return value;
    }

    pub fn isZero(value: Limbs) bool {
        var combined: u64 = 0;
        for (value) |limb| combined |= limb;
        return combined == 0;
    }

    pub fn lessThan(a: Limbs, b: Limbs) bool {
        return std.crypto.timing_safe.compare(u64, &a, &b, .little) == .lt;
    }

    pub fn equalLimbs(a: Limbs, b: Limbs) bool {
        var difference: u64 = 0;
        for (a, b) |first, second| difference |= first ^ second;
        return difference == 0;
    }
};

extern fn vailMontgomery1024SquareProductPair(
    first_output: *[2 * Montgomery1024.limb_count + 1]u64,
    second_output: *[2 * Montgomery1024.limb_count + 1]u64,
    first_value: *const Montgomery1024.Limbs,
    second_value: *const Montgomery1024.Limbs,
) callconv(.c) void;
extern fn vailMontgomery1024ProductPair(
    first_output: *[2 * Montgomery1024.limb_count + 1]u64,
    second_output: *[2 * Montgomery1024.limb_count + 1]u64,
    first_a: *const Montgomery1024.Limbs,
    second_a: *const Montgomery1024.Limbs,
    first_b: *const Montgomery1024.Limbs,
    second_b: *const Montgomery1024.Limbs,
) callconv(.c) void;
extern fn vailMontgomery1024ReduceProductPair(
    first_context: *const Montgomery1024,
    second_context: *const Montgomery1024,
    first_product: *[2 * Montgomery1024.limb_count + 1]u64,
    second_product: *[2 * Montgomery1024.limb_count + 1]u64,
) callconv(.c) void;
extern fn vailMontgomery1024FinishPair(
    output: *Montgomery1024.Pair,
    first_context: *const Montgomery1024,
    second_context: *const Montgomery1024,
    first_value: *const Montgomery1024.Limbs,
    second_value: *const Montgomery1024.Limbs,
    first_extra: u64,
    second_extra: u64,
) callconv(.c) void;

comptime {
    if (use_x86_64_adx_montgomery) {
        asm (
            \\.text
            \\.p2align 5
            \\.globl vailMontgomery1024SquareProductPair
            \\.hidden vailMontgomery1024SquareProductPair
            \\.type vailMontgomery1024SquareProductPair,@function
            \\vailMontgomery1024SquareProductPair:
            \\pushq %rbx
            \\pushq %rbp
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\pushq %r15
            \\subq $32, %rsp
            \\movq %rdi, %r12
            \\movq %rsi, %r13
            \\movq %rdx, %r14
            \\movq %rcx, %r15
            \\xorl %eax, %eax
            \\movq %rax, 0(%rsp)
            \\movq %rax, 8(%rsp)
            \\movq %rax, 16(%rsp)
            \\movq %rax, 24(%rsp)
            \\
            \\# Each generated column first accumulates i < j products once.
            \\# ADCX and ADOX keep the two residues on independent flag chains.
            \\.irp column, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30
            \\xorl %r8d, %r8d
            \\xorl %r9d, %r9d
            \\xorl %r10d, %r10d
            \\xorl %r11d, %r11d
            \\xorl %ebx, %ebx
            \\xorl %ebp, %ebp
            \\xorl %edi, %edi
            \\.irp left, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
            \\.if ((\column-\left) > \left)
            \\.if ((\column-\left) < 16)
            \\movq 8*\left(%r14), %rdx
            \\mulxq 8*(\column-\left)(%r14), %rax, %rcx
            \\adcxq %rax, %r8
            \\adcxq %rcx, %r9
            \\adcxq %rdi, %r10
            \\movq 8*\left(%r15), %rdx
            \\mulxq 8*(\column-\left)(%r15), %rax, %rcx
            \\adoxq %rax, %r11
            \\adoxq %rcx, %rbx
            \\adoxq %rdi, %rbp
            \\.endif
            \\.endif
            \\.endr
            \\
            \\# Double the aggregate cross terms once, add the carry from the
            \\# previous coefficient, then add the diagonal square if present.
            \\addq %r8, %r8
            \\adcq %r9, %r9
            \\adcq %r10, %r10
            \\addq %r11, %r11
            \\adcq %rbx, %rbx
            \\adcq %rbp, %rbp
            \\addq 0(%rsp), %r8
            \\adcq 8(%rsp), %r9
            \\adcq $0, %r10
            \\addq 16(%rsp), %r11
            \\adcq 24(%rsp), %rbx
            \\adcq $0, %rbp
            \\.if ((\column & 1) == 0)
            \\movq 8*(\column/2)(%r14), %rdx
            \\mulxq 8*(\column/2)(%r14), %rax, %rcx
            \\addq %rax, %r8
            \\adcq %rcx, %r9
            \\adcq $0, %r10
            \\movq 8*(\column/2)(%r15), %rdx
            \\mulxq 8*(\column/2)(%r15), %rax, %rcx
            \\addq %rax, %r11
            \\adcq %rcx, %rbx
            \\adcq $0, %rbp
            \\.endif
            \\movq %r8, 8*\column(%r12)
            \\movq %r11, 8*\column(%r13)
            \\movq %r9, 0(%rsp)
            \\movq %r10, 8(%rsp)
            \\movq %rbx, 16(%rsp)
            \\movq %rbp, 24(%rsp)
            \\.endr
            \\
            \\movq 0(%rsp), %rax
            \\movq %rax, 248(%r12)
            \\movq 8(%rsp), %rax
            \\movq %rax, 256(%r12)
            \\movq 16(%rsp), %rax
            \\movq %rax, 248(%r13)
            \\movq 24(%rsp), %rax
            \\movq %rax, 256(%r13)
            \\xorl %eax, %eax
            \\movq %rax, 0(%rsp)
            \\movq %rax, 8(%rsp)
            \\movq %rax, 16(%rsp)
            \\movq %rax, 24(%rsp)
            \\addq $32, %rsp
            \\popq %r15
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbp
            \\popq %rbx
            \\retq
            \\.size vailMontgomery1024SquareProductPair, .-vailMontgomery1024SquareProductPair
        );
        asm (
            \\.text
            \\.macro vail_montgomery1024_product_row multiplicand, product
            \\movq 0(\product), %r8
            \\xorl %eax, %eax
            \\mulxq 0(\multiplicand), %r9, %r10
            \\adcxq %r8, %r9
            \\movq %r9, 0(\product)
            \\movq 8(\product), %r8
            \\adoxq %r8, %r10
            \\.irp offset, 8, 24, 40, 56, 72, 88, 104
            \\mulxq \offset(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, \offset(\product)
            \\movq \offset+8(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq \offset+8(\multiplicand), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, \offset+8(\product)
            \\movq \offset+16(\product), %r8
            \\adoxq %r8, %r10
            \\.endr
            \\mulxq 120(\multiplicand), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 120(\product)
            \\adoxq %rax, %r11
            \\adcxq %rax, %r11
            \\addq %r11, 128(\product)
            \\adcq $0, 136(\product)
            \\.endm
            \\
            \\.p2align 5
            \\.globl vailMontgomery1024ProductPair
            \\.hidden vailMontgomery1024ProductPair
            \\.type vailMontgomery1024ProductPair,@function
            \\vailMontgomery1024ProductPair:
            \\pushq %rbx
            \\pushq %rbp
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\pushq %r15
            \\subq $24, %rsp
            \\movq %r8, 0(%rsp)
            \\movq %r9, 8(%rsp)
            \\movq $16, 16(%rsp)
            \\movq %rdi, %r12
            \\movq %rsi, %r13
            \\movq %rdx, %r14
            \\movq %rcx, %r15
            \\vpxor %ymm0, %ymm0, %ymm0
            \\.irp offset, 0, 32, 64, 96, 128, 160, 192, 224
            \\vmovdqu %ymm0, \offset(%r12)
            \\vmovdqu %ymm0, \offset(%r13)
            \\.endr
            \\movq $0, 256(%r12)
            \\movq $0, 256(%r13)
            \\.Lmontgomery1024_product_outer:
            \\movq 0(%rsp), %rax
            \\movq 0(%rax), %rdx
            \\vail_montgomery1024_product_row %r14, %r12
            \\movq 8(%rsp), %rax
            \\movq 0(%rax), %rdx
            \\vail_montgomery1024_product_row %r15, %r13
            \\addq $8, %r12
            \\addq $8, %r13
            \\addq $8, 0(%rsp)
            \\addq $8, 8(%rsp)
            \\subq $1, 16(%rsp)
            \\jnz .Lmontgomery1024_product_outer
            \\vzeroupper
            \\xorl %eax, %eax
            \\movq %rax, 0(%rsp)
            \\movq %rax, 8(%rsp)
            \\movq %rax, 16(%rsp)
            \\addq $24, %rsp
            \\popq %r15
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbp
            \\popq %rbx
            \\retq
            \\.size vailMontgomery1024ProductPair, .-vailMontgomery1024ProductPair
            \\.purgem vail_montgomery1024_product_row
        );
        asm (
            \\.text
            \\.macro vail_montgomery1024_reduce_row product, modulus, pending, pending_byte
            \\movq 0(\product), %r8
            \\movq %r8, %rdx
            \\imulq 128(\modulus), %rdx
            \\xorl %eax, %eax
            \\mulxq 0(\modulus), %r9, %r10
            \\adcxq %r8, %r9
            \\movq 8(\product), %r8
            \\adoxq %r8, %r10
            \\.irp offset, 8, 24, 40, 56, 72, 88, 104
            \\mulxq \offset(\modulus), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, \offset(\product)
            \\movq \offset+8(\product), %r8
            \\adoxq %r8, %r11
            \\mulxq \offset+8(\modulus), %r9, %r10
            \\adcxq %r9, %r11
            \\movq %r11, \offset+8(\product)
            \\movq \offset+16(\product), %r8
            \\adoxq %r8, %r10
            \\.endr
            \\mulxq 120(\modulus), %r9, %r11
            \\adcxq %r9, %r10
            \\movq %r10, 120(\product)
            \\adoxq %rax, %r11
            \\adcxq %rax, %r11
            \\addq %r11, 128(\product)
            \\adcq \pending, 136(\product)
            \\setc \pending_byte
            \\.endm
            \\
            \\.p2align 5
            \\.globl vailMontgomery1024ReduceProductPair
            \\.hidden vailMontgomery1024ReduceProductPair
            \\.type vailMontgomery1024ReduceProductPair,@function
            \\vailMontgomery1024ReduceProductPair:
            \\pushq %rbx
            \\pushq %rbp
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\pushq %r15
            \\subq $8, %rsp
            \\movq %rdi, %r12
            \\movq %rsi, %r13
            \\movq %rdx, %r14
            \\movq %rcx, %r15
            \\movq $16, 0(%rsp)
            \\xorl %ebx, %ebx
            \\xorl %ebp, %ebp
            \\.Lmontgomery1024_reduce_outer:
            \\vail_montgomery1024_reduce_row %r14, %r12, %rbx, %bl
            \\vail_montgomery1024_reduce_row %r15, %r13, %rbp, %bpl
            \\addq $8, %r14
            \\addq $8, %r15
            \\subq $1, 0(%rsp)
            \\jnz .Lmontgomery1024_reduce_outer
            \\movq $0, 0(%rsp)
            \\addq $8, %rsp
            \\popq %r15
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbp
            \\popq %rbx
            \\retq
            \\.size vailMontgomery1024ReduceProductPair, .-vailMontgomery1024ReduceProductPair
            \\.purgem vail_montgomery1024_reduce_row
        );
        asm (
            \\.text
            \\.macro vail_montgomery1024_finish value, modulus, output, extra
            \\clc
            \\.irp offset, 0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120
            \\movq \offset(\value), %r8
            \\sbbq \offset(\modulus), %r8
            \\movq %r8, \offset(\output)
            \\.endr
            \\sbbq %r8, %r8
            \\movq \extra, %r9
            \\negq %r9
            \\sbbq %r9, %r9
            \\notq %r9
            \\andq %r9, %r8
            \\vmovq %r8, %xmm0
            \\vpbroadcastq %xmm0, %ymm0
            \\.irp offset, 0, 32, 64, 96
            \\vmovdqu \offset(\value), %ymm1
            \\vmovdqu \offset(\output), %ymm2
            \\vpxor %ymm2, %ymm1, %ymm1
            \\vpand %ymm0, %ymm1, %ymm1
            \\vpxor %ymm1, %ymm2, %ymm2
            \\vmovdqu %ymm2, \offset(\output)
            \\.endr
            \\.endm
            \\
            \\.p2align 5
            \\.globl vailMontgomery1024FinishPair
            \\.hidden vailMontgomery1024FinishPair
            \\.type vailMontgomery1024FinishPair,@function
            \\vailMontgomery1024FinishPair:
            \\movq 8(%rsp), %r11
            \\pushq %rbx
            \\pushq %rbp
            \\pushq %r12
            \\pushq %r13
            \\pushq %r14
            \\pushq %r15
            \\subq $8, %rsp
            \\movq %rdi, %r12
            \\movq %rsi, %r13
            \\movq %rdx, %r14
            \\movq %rcx, %r15
            \\movq %r8, %rbx
            \\movq %r9, %rbp
            \\movq %r11, 0(%rsp)
            \\vail_montgomery1024_finish %r15, %r13, %r12, %rbp
            \\addq $128, %r12
            \\vail_montgomery1024_finish %rbx, %r14, %r12, 0(%rsp)
            \\vzeroupper
            \\movq $0, 0(%rsp)
            \\addq $8, %rsp
            \\popq %r15
            \\popq %r14
            \\popq %r13
            \\popq %r12
            \\popq %rbp
            \\popq %rbx
            \\retq
            \\.size vailMontgomery1024FinishPair, .-vailMontgomery1024FinishPair
            \\.purgem vail_montgomery1024_finish
        );
    }
}

/// Full-width Montgomery arithmetic for the common RSA-2048 public exponent
/// 65537. This keeps the mandatory post-CRT fault check on the specialized
/// fixed-limb path instead of re-entering the generic finite-field engine.
pub const Montgomery2048 = struct {
    pub const limb_count = 32;
    pub const encoded_length = limb_count * @sizeOf(u64);
    pub const Limbs = [limb_count]u64;

    modulus: Limbs,
    negative_inverse: u64,
    r_squared: Limbs,

    pub fn init(modulus_bytes: []const u8) Error!Montgomery2048 {
        if (modulus_bytes.len != encoded_length or
            (modulus_bytes[modulus_bytes.len - 1] & 1) == 0)
        {
            return error.InvalidPrivateKey;
        }
        const modulus = decode(modulus_bytes);
        if (isZero(modulus)) return error.InvalidPrivateKey;

        var inverse: u64 = 1;
        inline for (0..6) |_| {
            inverse *%= 2 -% modulus[0] *% inverse;
        }
        var r_squared = one();
        for (0..2 * limb_count * @bitSizeOf(u64)) |_| {
            r_squared = doubleMod(r_squared, modulus);
        }
        return .{
            .modulus = modulus,
            .negative_inverse = 0 -% inverse,
            .r_squared = r_squared,
        };
    }

    pub fn pow65537(self: *const Montgomery2048, base: Limbs) Limbs {
        std.debug.assert(lessThan(base, self.modulus));
        var base_montgomery = self.mul(base, self.r_squared);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&base_montgomery));
        var result = base_montgomery;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
        inline for (0..16) |_| result = self.mul(result, result);
        result = self.mul(result, base_montgomery);
        return self.mul(result, one());
    }

    pub fn mul(self: *const Montgomery2048, a: Limbs, b: Limbs) Limbs {
        var intermediate = [_]u64{0} ** (limb_count + 2);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&intermediate));

        for (0..limb_count) |i| {
            var carry: u128 = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, a[j]) * b[i] +
                    intermediate[j] + carry;
                intermediate[j] = @truncate(wide);
                carry = wide >> 64;
            }
            const upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count] = upper[0];
            intermediate[limb_count + 1] = upper[1];

            const factor = intermediate[0] *% self.negative_inverse;
            carry = 0;
            inline for (0..limb_count) |j| {
                const wide = @as(u128, factor) * self.modulus[j] +
                    intermediate[j] + carry;
                if (j != 0) intermediate[j - 1] = @truncate(wide);
                carry = wide >> 64;
            }
            const reduced_upper = @addWithOverflow(
                intermediate[limb_count],
                @as(u64, @truncate(carry)),
            );
            intermediate[limb_count - 1] = reduced_upper[0];
            intermediate[limb_count] = intermediate[limb_count + 1] +%
                reduced_upper[1];
            intermediate[limb_count + 1] = 0;
        }

        const unreduced: Limbs = intermediate[0..limb_count].*;
        return self.reduceLimbs(unreduced, intermediate[limb_count]);
    }

    pub fn reduceLimbs(
        self: *const Montgomery2048,
        unreduced_value: Limbs,
        extra: u64,
    ) Limbs {
        var unreduced = unreduced_value;
        var reduced: Limbs = undefined;
        var borrow: u1 = 0;
        for (0..limb_count) |index| {
            const first = @subWithOverflow(unreduced[index], self.modulus[index]);
            const second = @subWithOverflow(first[0], borrow);
            reduced[index] = second[0];
            borrow = first[1] | second[1];
        }
        const has_extra: u1 = @intFromBool(extra != 0);
        const use_reduced = has_extra | (borrow ^ 1);
        const mask = opaqueWord(0 -% @as(u64, use_reduced));
        for (&unreduced, reduced) |*out, candidate| {
            out.* = (candidate & mask) | (out.* & ~mask);
        }
        return unreduced;
    }

    pub fn doubleMod(value: Limbs, modulus: Limbs) Limbs {
        var doubled: Limbs = undefined;
        var carry: u1 = 0;
        for (value, 0..) |limb, index| {
            const sum = @addWithOverflow(limb, limb);
            doubled[index] = sum[0] | carry;
            carry = sum[1];
        }

        var reduced: Limbs = undefined;
        var borrow: u1 = 0;
        for (0..limb_count) |index| {
            const first = @subWithOverflow(doubled[index], modulus[index]);
            const second = @subWithOverflow(first[0], borrow);
            reduced[index] = second[0];
            borrow = first[1] | second[1];
        }
        const use_reduced = carry | (borrow ^ 1);
        const mask = opaqueWord(0 -% @as(u64, use_reduced));
        for (&doubled, reduced) |*out, candidate| {
            out.* = (candidate & mask) | (out.* & ~mask);
        }
        return doubled;
    }

    pub fn decode(bytes: []const u8) Limbs {
        var result = [_]u64{0} ** limb_count;
        var source_end = bytes.len;
        var destination: usize = 0;
        while (source_end != 0) : (destination += 1) {
            const source_start = source_end - @min(source_end, @sizeOf(u64));
            var limb: u64 = 0;
            for (bytes[source_start..source_end]) |byte| {
                limb = (limb << 8) | byte;
            }
            result[destination] = limb;
            source_end = source_start;
        }
        return result;
    }

    pub fn encode(value: Limbs, output: *[encoded_length]u8) void {
        for (value, 0..) |limb, index| {
            std.mem.writeInt(
                u64,
                output[encoded_length - (index + 1) * 8 ..][0..8],
                limb,
                .big,
            );
        }
    }

    pub fn one() Limbs {
        var value = [_]u64{0} ** limb_count;
        value[0] = 1;
        return value;
    }

    pub fn isZero(value: Limbs) bool {
        var combined: u64 = 0;
        for (value) |limb| combined |= limb;
        return combined == 0;
    }

    pub fn lessThan(a: Limbs, b: Limbs) bool {
        return std.crypto.timing_safe.compare(u64, &a, &b, .little) == .lt;
    }

    pub fn equal(a: Limbs, b: Limbs) bool {
        var difference: u64 = 0;
        for (a, b) |first, second| difference |= first ^ second;
        return difference == 0;
    }
};
