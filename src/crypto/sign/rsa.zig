//! Allocation-free RSA private-key operations for TLS signatures.
//!
//! PKCS#1 and unencrypted PKCS#8 DER keys are parsed as borrowed slices,
//! including RFC 4055 and RFC 8692 constrained RSASSA-PSS keys. RSA
//! exponentiation uses PKCS#1 CRT parameters and a fixed-width constant-time
//! RSA-2048 path, with `std.crypto.ff` retained for larger keys. Prepared keys
//! cache Montgomery moduli so handshake signing performs no heap allocation.

const std = @import("std");
const builtin = @import("builtin");
const rsa_pss = @import("../rsa_pss.zig");

const Sha224 = std.crypto.hash.sha2.Sha224;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha512_224 = std.crypto.hash.sha2.Sha512_224;
const Sha512_256 = std.crypto.hash.sha2.Sha512_256;
const Sha3_224 = std.crypto.hash.sha3.Sha3_224;
const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const Sha3_384 = std.crypto.hash.sha3.Sha3_384;
const Sha3_512 = std.crypto.hash.sha3.Sha3_512;
const Shake128 = std.crypto.hash.sha3.Shake128;
const Shake256 = std.crypto.hash.sha3.Shake256;
const RsaModulus = std.crypto.ff.Modulus(4096);
const RsaFieldElement = RsaModulus.Fe;
const PrimeModulus = std.crypto.ff.Modulus(2048);
const PrimeFieldElement = PrimeModulus.Fe;

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
const Montgomery1024 = struct {
    const limb_count = 16;
    const encoded_length = limb_count * @sizeOf(u64);
    const Limbs = [limb_count]u64;
    const Pair = struct {
        first: Limbs,
        second: Limbs,
    };
    const PairWorkspace = struct {
        first: [limb_count + 2]u64 = [_]u64{0} ** (limb_count + 2),
        second: [limb_count + 2]u64 = [_]u64{0} ** (limb_count + 2),

        fn reset(self: *PairWorkspace) void {
            @memset(&self.first, 0);
            @memset(&self.second, 0);
        }

        fn clear(self: *PairWorkspace) void {
            std.crypto.secureZero(PairWorkspace, self[0..1]);
        }
    };
    const ProductPairWorkspace = struct {
        first: [2 * limb_count + 1]u64 =
            [_]u64{0} ** (2 * limb_count + 1),
        second: [2 * limb_count + 1]u64 =
            [_]u64{0} ** (2 * limb_count + 1),

        fn clear(self: *ProductPairWorkspace) void {
            std.crypto.secureZero(ProductPairWorkspace, self[0..1]);
        }
    };
    modulus: Limbs,
    negative_inverse: u64,
    r_squared: Limbs,
    one_montgomery: Limbs,

    fn init(modulus_bytes: []const u8) Error!Montgomery1024 {
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

    fn powSecret(
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

    fn powSecretPair(
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

    fn pow65537Pair(
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

    fn toMontgomery(self: *const Montgomery1024, value: Limbs) Limbs {
        return self.mul(value, self.r_squared);
    }

    fn fromMontgomery(self: *const Montgomery1024, value: Limbs) Limbs {
        return self.mul(value, one());
    }

    fn mul(self: *const Montgomery1024, a: Limbs, b: Limbs) Limbs {
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

    fn mulPair(
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

    fn mulPairFios(
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

    fn squarePairWithWorkspaces(
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

    fn mulPairOptimizedWithWorkspaces(
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

    fn mulPairFiosWithWorkspace(
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

    fn mulProduct(self: *const Montgomery1024, a: Limbs, b: Limbs) Limbs {
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

    fn crtRecombine(
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

    fn reduceWidePair(
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

    fn multiplyWide(a: Limbs, b: Limbs) [2 * limb_count]u64 {
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

    fn reduceProduct(
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

    fn reduceLimbs(
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

    fn reduceLimbsPair(
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

    fn subMod(a: Limbs, b: Limbs, modulus: Limbs) Limbs {
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

    fn addMod(a: Limbs, b: Limbs, modulus: Limbs) Limbs {
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

    fn selectTable(
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

    fn selectTablePair(
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

    fn readBits(
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

    fn doubleMod(value: Limbs, modulus: Limbs) Limbs {
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

    fn decode(bytes: []const u8) Limbs {
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

    fn decodeWide(bytes: *const [2 * encoded_length]u8) [2 * limb_count]u64 {
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

    fn encode(value: Limbs, output: *[encoded_length]u8) void {
        for (value, 0..) |limb, index| {
            std.mem.writeInt(
                u64,
                output[encoded_length - (index + 1) * 8 ..][0..8],
                limb,
                .big,
            );
        }
    }

    fn encodeWide(
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

    fn one() Limbs {
        var value = [_]u64{0} ** limb_count;
        value[0] = 1;
        return value;
    }

    fn isZero(value: Limbs) bool {
        var combined: u64 = 0;
        for (value) |limb| combined |= limb;
        return combined == 0;
    }

    fn lessThan(a: Limbs, b: Limbs) bool {
        return std.crypto.timing_safe.compare(u64, &a, &b, .little) == .lt;
    }

    fn equalLimbs(a: Limbs, b: Limbs) bool {
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
const Montgomery2048 = struct {
    const limb_count = 32;
    const encoded_length = limb_count * @sizeOf(u64);
    const Limbs = [limb_count]u64;

    modulus: Limbs,
    negative_inverse: u64,
    r_squared: Limbs,

    fn init(modulus_bytes: []const u8) Error!Montgomery2048 {
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

    fn pow65537(self: *const Montgomery2048, base: Limbs) Limbs {
        std.debug.assert(lessThan(base, self.modulus));
        var base_montgomery = self.mul(base, self.r_squared);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&base_montgomery));
        var result = base_montgomery;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
        inline for (0..16) |_| result = self.mul(result, result);
        result = self.mul(result, base_montgomery);
        return self.mul(result, one());
    }

    fn mul(self: *const Montgomery2048, a: Limbs, b: Limbs) Limbs {
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

    fn reduceLimbs(
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

    fn doubleMod(value: Limbs, modulus: Limbs) Limbs {
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

    fn decode(bytes: []const u8) Limbs {
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

    fn encode(value: Limbs, output: *[encoded_length]u8) void {
        for (value, 0..) |limb, index| {
            std.mem.writeInt(
                u64,
                output[encoded_length - (index + 1) * 8 ..][0..8],
                limb,
                .big,
            );
        }
    }

    fn one() Limbs {
        var value = [_]u64{0} ** limb_count;
        value[0] = 1;
        return value;
    }

    fn isZero(value: Limbs) bool {
        var combined: u64 = 0;
        for (value) |limb| combined |= limb;
        return combined == 0;
    }

    fn lessThan(a: Limbs, b: Limbs) bool {
        return std.crypto.timing_safe.compare(u64, &a, &b, .little) == .lt;
    }

    fn equal(a: Limbs, b: Limbs) bool {
        var difference: u64 = 0;
        for (a, b) |first, second| difference |= first ^ second;
        return difference == 0;
    }
};

const oid_rsa_encryption = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
};
const oid_rsassa_pss = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
};
const oid_rsassa_pss_shake128 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e,
};
const oid_rsassa_pss_shake256 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f,
};

pub const Error = error{
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    UnsupportedModulusBits,
    UnsupportedPublicExponent,
    InvalidSaltLength,
    SignatureBufferTooSmall,
    MessageTooLong,
    KeyAlgorithmMismatch,
};

/// Reusable RSA-2048 public-key state for the common exponent 65537.
/// The Montgomery context is public data and does not require wiping.
pub const PreparedPublicKey = struct {
    context: Montgomery2048,
    modulus_bits: usize,

    pub fn init(
        exponent: []const u8,
        modulus: []const u8,
    ) Error!PreparedPublicKey {
        if (!std.mem.eql(u8, exponent, "\x01\x00\x01")) {
            return error.UnsupportedPublicExponent;
        }
        if (modulus.len != Montgomery2048.encoded_length or modulus[0] == 0) {
            return error.UnsupportedModulusBits;
        }
        return .{
            .context = Montgomery2048.init(modulus) catch
                return error.InvalidPublicKey,
            .modulus_bits = modulus.len * 8 - @clz(modulus[0]),
        };
    }

    pub fn verifyPssSha224(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha224, message_parts, signature);
    }

    pub fn verifyPssSha256(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha256, message_parts, signature);
    }

    pub fn verifyPssSha384(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha384, message_parts, signature);
    }

    pub fn verifyPssSha512(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPss(std.crypto.hash.sha2.Sha512, message_parts, signature);
    }

    pub fn verifyPkcs1v15Sha224(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha224, message_parts, signature);
    }

    pub fn verifyPkcs1v15Sha256(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha256, message_parts, signature);
    }

    pub fn verifyPkcs1v15Sha384(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha384, message_parts, signature);
    }

    pub fn verifyPkcs1v15Sha512(
        self: *const PreparedPublicKey,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        return self.verifyPkcs1v15(Sha512, message_parts, signature);
    }

    fn verifyPss(
        self: *const PreparedPublicKey,
        comptime Hash: type,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        if (signature.len != Montgomery2048.encoded_length) {
            return error.InvalidSignature;
        }
        const encoded_signature = signature[0..Montgomery2048.encoded_length].*;
        const signature_limbs = Montgomery2048.decode(&encoded_signature);
        if (!Montgomery2048.lessThan(
            signature_limbs,
            self.context.modulus,
        )) return error.InvalidSignature;
        const recovered_limbs = self.context.pow65537(signature_limbs);
        var encoded_message: [Montgomery2048.encoded_length]u8 = undefined;
        Montgomery2048.encode(recovered_limbs, &encoded_message);
        return verifyPssEncoding(
            Hash,
            message_parts,
            &encoded_message,
            self.modulus_bits - 1,
        );
    }

    fn verifyPkcs1v15(
        self: *const PreparedPublicKey,
        comptime Hash: type,
        message_parts: []const []const u8,
        signature: []const u8,
    ) Error!void {
        if (signature.len != Montgomery2048.encoded_length) {
            return error.InvalidSignature;
        }
        const encoded_signature = signature[0..Montgomery2048.encoded_length].*;
        const signature_limbs = Montgomery2048.decode(&encoded_signature);
        if (!Montgomery2048.lessThan(
            signature_limbs,
            self.context.modulus,
        )) return error.InvalidSignature;
        const recovered_limbs = self.context.pow65537(signature_limbs);
        var encoded_message: [Montgomery2048.encoded_length]u8 = undefined;
        Montgomery2048.encode(recovered_limbs, &encoded_message);

        const digest_info_prefix: []const u8 = &switch (Hash) {
            Sha224 => .{
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                0x00, 0x04, 0x1c,
            },
            Sha256 => .{
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            },
            Sha384 => .{
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                0x00, 0x04, 0x30,
            },
            Sha512 => .{
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00, 0x04, 0x40,
            },
            else => @compileError("unsupported PKCS#1 v1.5 hash"),
        };
        const digest_info_len = digest_info_prefix.len + Hash.digest_length;
        if (encoded_message.len < digest_info_len + 11 or
            encoded_message[0] != 0 or encoded_message[1] != 1)
        {
            return error.InvalidSignature;
        }
        const separator = encoded_message.len - digest_info_len - 1;
        var invalid_padding: u8 = encoded_message[separator];
        for (encoded_message[2..separator]) |byte| {
            invalid_padding |= byte ^ 0xff;
        }
        if (invalid_padding != 0 or !std.mem.eql(
            u8,
            encoded_message[separator + 1 ..][0..digest_info_prefix.len],
            digest_info_prefix,
        )) return error.InvalidSignature;

        var digest: [Hash.digest_length]u8 = undefined;
        var hasher = Hash.init(.{});
        for (message_parts) |part| hasher.update(part);
        hasher.final(&digest);
        if (!std.crypto.timing_safe.eql(
            [Hash.digest_length]u8,
            digest,
            encoded_message[encoded_message.len - Hash.digest_length ..].*,
        )) return error.InvalidSignature;
    }
};

fn verifyPssEncoding(
    comptime Hash: type,
    message_parts: []const []const u8,
    encoded_message: []u8,
    encoded_bits: usize,
) Error!void {
    const encoded_len = (encoded_bits + 7) / 8;
    if (encoded_len != encoded_message.len or
        encoded_len < 2 * Hash.digest_length + 2 or
        encoded_message[encoded_message.len - 1] != 0xbc)
    {
        return error.InvalidSignature;
    }
    const database_len = encoded_len - Hash.digest_length - 1;
    const digest = encoded_message[database_len..][0..Hash.digest_length];
    const unused_bits = encoded_len * 8 - encoded_bits;
    if (unused_bits != 0 and
        encoded_message[0] >> @intCast(8 - unused_bits) != 0)
    {
        return error.InvalidSignature;
    }

    var seed: [Hash.digest_length + 4]u8 = undefined;
    @memcpy(seed[0..Hash.digest_length], digest);
    var offset: usize = 0;
    var counter: u32 = 0;
    while (offset < database_len) : (counter += 1) {
        std.mem.writeInt(u32, seed[Hash.digest_length..], counter, .big);
        var mask_block: [Hash.digest_length]u8 = undefined;
        Hash.hash(&seed, &mask_block, .{});
        const count = @min(mask_block.len, database_len - offset);
        for (encoded_message[offset..][0..count], mask_block[0..count]) |*byte, mask| {
            byte.* ^= mask;
        }
        offset += count;
    }
    encoded_message[0] &= @as(u8, 0xff) >> @intCast(unused_bits);

    const delimiter_index = database_len - Hash.digest_length - 1;
    var nonzero: u8 = 0;
    for (encoded_message[0..delimiter_index]) |byte| nonzero |= byte;
    if (nonzero != 0 or encoded_message[delimiter_index] != 1) {
        return error.InvalidSignature;
    }
    const salt = encoded_message[database_len - Hash.digest_length .. database_len];
    var message_hash: [Hash.digest_length]u8 = undefined;
    var message_hasher = Hash.init(.{});
    for (message_parts) |part| message_hasher.update(part);
    message_hasher.final(&message_hash);
    var final_input: [8 + 2 * Hash.digest_length]u8 =
        [_]u8{0} ** (8 + 2 * Hash.digest_length);
    @memcpy(final_input[8..][0..Hash.digest_length], &message_hash);
    @memcpy(final_input[8 + Hash.digest_length ..], salt);
    var expected: [Hash.digest_length]u8 = undefined;
    Hash.hash(&final_input, &expected, .{});
    if (!std.crypto.timing_safe.eql(
        [Hash.digest_length]u8,
        digest[0..Hash.digest_length].*,
        expected,
    )) return error.InvalidSignature;
}

pub const PrivateKey = struct {
    /// Unsigned, minimally encoded big-endian values borrowed from the DER.
    modulus: []const u8,
    public_exponent: []const u8,
    private_exponent: []const u8,
    prime1: []const u8,
    prime2: []const u8,
    exponent1: []const u8,
    exponent2: []const u8,
    coefficient: []const u8,
    /// Non-null for PKCS#8 id-RSASSA-PSS keys. This also marks the key as
    /// PSS-only even when the AlgorithmIdentifier omits optional constraints.
    pss_constraints: ?rsa_pss.PssKeyConstraints = null,

    pub fn fromDer(der: []const u8) Error!PrivateKey {
        var outer = Reader{ .bytes = der };
        const sequence = outer.require(0x30) catch
            return error.InvalidPrivateKey;
        if (!outer.done()) return error.InvalidPrivateKey;
        var fields = Reader{ .bytes = sequence.value };
        const version = fields.require(0x02) catch
            return error.InvalidPrivateKey;
        if (!std.mem.eql(u8, version.value, &.{0})) {
            return error.InvalidPrivateKey;
        }
        const second = (fields.next() catch
            return error.InvalidPrivateKey) orelse
            return error.InvalidPrivateKey;
        return switch (second.tag) {
            0x02 => parsePkcs1Fields(&fields, second),
            0x30 => parsePkcs8Fields(&fields, second),
            else => error.InvalidPrivateKey,
        };
    }

    pub fn modulusBits(self: PrivateKey) usize {
        return self.modulus.len * 8 - @clz(self.modulus[0]);
    }

    pub fn signatureLength(self: PrivateKey) usize {
        return self.modulus.len;
    }

    pub fn matchesPublicKey(
        self: PrivateKey,
        modulus: []const u8,
        exponent: []const u8,
    ) bool {
        return timingSafeEql(self.modulus, stripUnsignedPadding(modulus)) and
            timingSafeEql(
                self.public_exponent,
                stripUnsignedPadding(exponent),
            );
    }

    pub fn signPssSha256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha256(message, salt, output);
    }

    pub fn signPssSha224(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha224(message, salt, output);
    }

    pub fn signPssSha384(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha384(message, salt, output);
    }

    pub fn signPssSha512(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha512(message, salt, output);
    }

    pub fn signPssSha512_224(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha512_224(message, salt, output);
    }

    pub fn signPssSha512_256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha512_256(message, salt, output);
    }

    pub fn signPssShake128(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssShake128(message, salt, output);
    }

    pub fn signPssShake256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssShake256(message, salt, output);
    }

    pub fn signPssSha3_224(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_224(message, salt, output);
    }

    pub fn signPssSha3_256(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_256(message, salt, output);
    }

    pub fn signPssSha3_384(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_384(message, salt, output);
    }

    pub fn signPssSha3_512(
        self: PrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPssSha3_512(message, salt, output);
    }

    pub fn signPkcs1v15Sha256(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha256(message, output);
    }

    pub fn signPkcs1v15Sha224(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha224(message, output);
    }

    pub fn signPkcs1v15Sha384(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha384(message, output);
    }

    pub fn signPkcs1v15Sha512(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha512(message, output);
    }

    pub fn signPkcs1v15Sha512_224(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha512_224(message, output);
    }

    pub fn signPkcs1v15Sha512_256(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha512_256(message, output);
    }

    pub fn signPkcs1v15Sha3_224(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_224(message, output);
    }

    pub fn signPkcs1v15Sha3_256(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_256(message, output);
    }

    pub fn signPkcs1v15Sha3_384(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_384(message, output);
    }

    pub fn signPkcs1v15Sha3_512(
        self: PrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        var prepared = try PreparedPrivateKey.init(self);
        defer prepared.deinit();
        return prepared.signPkcs1v15Sha3_512(message, output);
    }

    pub fn prepare(self: PrivateKey) Error!PreparedPrivateKey {
        return PreparedPrivateKey.init(self);
    }
};

pub const PreparedPrivateKey = struct {
    key: PrivateKey,
    modulus: RsaModulus,
    prime1: PrimeModulus,
    prime2: PrimeModulus,
    q_inverse_mod_p: PrimeFieldElement,
    q_full: RsaFieldElement,
    prime1_1024: ?Montgomery1024,
    prime2_1024: ?Montgomery1024,

    pub fn init(key: PrivateKey) Error!PreparedPrivateKey {
        const modulus = RsaModulus.fromBytes(key.modulus, .big) catch
            return error.InvalidPrivateKey;
        const prime1 = PrimeModulus.fromBytes(key.prime1, .big) catch
            return error.InvalidPrivateKey;
        const prime2 = PrimeModulus.fromBytes(key.prime2, .big) catch
            return error.InvalidPrivateKey;
        _ = RsaFieldElement.fromBytes(
            modulus,
            key.private_exponent,
            .big,
        ) catch return error.InvalidPrivateKey;
        _ = PrimeFieldElement.fromBytes(
            prime1,
            key.exponent1,
            .big,
        ) catch return error.InvalidPrivateKey;
        _ = PrimeFieldElement.fromBytes(
            prime2,
            key.exponent2,
            .big,
        ) catch return error.InvalidPrivateKey;
        const q_inverse_mod_p = PrimeFieldElement.fromBytes(
            prime1,
            key.coefficient,
            .big,
        ) catch return error.InvalidPrivateKey;
        const q_full = RsaFieldElement.fromBytes(
            modulus,
            key.prime2,
            .big,
        ) catch return error.InvalidPrivateKey;
        var prepared = PreparedPrivateKey{
            .key = key,
            .modulus = modulus,
            .prime1 = prime1,
            .prime2 = prime2,
            .q_inverse_mod_p = q_inverse_mod_p,
            .q_full = q_full,
            .prime1_1024 = if (key.modulus.len == 256)
                try Montgomery1024.init(key.prime1)
            else
                null,
            .prime2_1024 = if (key.modulus.len == 256)
                try Montgomery1024.init(key.prime2)
            else
                null,
        };
        errdefer prepared.deinit();
        try validateKeyConsistency(&prepared);
        return prepared;
    }

    pub fn deinit(self: *PreparedPrivateKey) void {
        std.crypto.secureZero(PreparedPrivateKey, self[0..1]);
    }

    pub fn signatureLength(self: *const PreparedPrivateKey) usize {
        return self.key.signatureLength();
    }

    pub fn matchesPublicKey(
        self: *const PreparedPrivateKey,
        modulus: []const u8,
        exponent: []const u8,
    ) bool {
        return self.key.matchesPublicKey(modulus, exponent);
    }

    pub fn signPssSha256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha256, message, salt, output);
    }

    pub fn signPssSha224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha224, message, salt, output);
    }

    pub fn signPssSha384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha384, message, salt, output);
    }

    pub fn signPssSha512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha512, message, salt, output);
    }

    pub fn signPssSha512_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha512_224, message, salt, output);
    }

    pub fn signPssSha512_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha512_256, message, salt, output);
    }

    pub fn signPssShake128(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPssShake(self, Shake128, message, salt, output);
    }

    pub fn signPssShake256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPssShake(self, Shake256, message, salt, output);
    }

    pub fn signPssSha3_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_224, message, salt, output);
    }

    pub fn signPssSha3_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_256, message, salt, output);
    }

    pub fn signPssSha3_384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_384, message, salt, output);
    }

    pub fn signPssSha3_512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        salt: []const u8,
        output: []u8,
    ) Error!usize {
        return signPss(self, Sha3_512, message, salt, output);
    }

    pub fn signPkcs1v15Sha256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha256, message, output);
    }

    pub fn signPkcs1v15Sha224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha224, message, output);
    }

    pub fn signPkcs1v15Sha384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha384, message, output);
    }

    pub fn signPkcs1v15Sha512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha512, message, output);
    }

    pub fn signPkcs1v15Sha512_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha512_224, message, output);
    }

    pub fn signPkcs1v15Sha512_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha512_256, message, output);
    }

    pub fn signPkcs1v15Sha3_224(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_224, message, output);
    }

    pub fn signPkcs1v15Sha3_256(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_256, message, output);
    }

    pub fn signPkcs1v15Sha3_384(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_384, message, output);
    }

    pub fn signPkcs1v15Sha3_512(
        self: *const PreparedPrivateKey,
        message: []const u8,
        output: []u8,
    ) Error!usize {
        return signPkcs1v15(self, Sha3_512, message, output);
    }
};

fn parsePkcs1Fields(fields: *Reader, modulus_element: Element) Error!PrivateKey {
    const modulus = positiveInteger(modulus_element) catch
        return error.InvalidPrivateKey;
    const public_exponent = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const private_exponent = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const prime1 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const prime2 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const exponent1 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const exponent2 = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    const coefficient = positiveInteger(
        fields.require(0x02) catch return error.InvalidPrivateKey,
    ) catch return error.InvalidPrivateKey;
    if (!fields.done()) return error.InvalidPrivateKey;
    return validateComponents(
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
    );
}

fn parsePkcs8Fields(
    fields: *Reader,
    algorithm: Element,
) Error!PrivateKey {
    var algorithm_fields = Reader{ .bytes = algorithm.value };
    const oid = algorithm_fields.require(0x06) catch
        return error.InvalidPrivateKey;
    const is_rsa_encryption = std.mem.eql(
        u8,
        oid.value,
        &oid_rsa_encryption,
    );
    const is_rsa_pss = std.mem.eql(u8, oid.value, &oid_rsassa_pss) or
        std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake128) or
        std.mem.eql(u8, oid.value, &oid_rsassa_pss_shake256);
    if (!is_rsa_encryption and !is_rsa_pss) {
        return error.InvalidPrivateKey;
    }
    const pss_constraints: ?rsa_pss.PssKeyConstraints = if (is_rsa_pss)
        rsa_pss.parsePssPublicKeyAlgorithmIdentifier(
            algorithm.value,
        ) catch return error.InvalidPrivateKey
    else blk: {
        if (algorithm_fields.next() catch
            return error.InvalidPrivateKey) |params|
        {
            if (params.tag != 0x05 or params.value.len != 0 or
                !algorithm_fields.done())
            {
                return error.InvalidPrivateKey;
            }
        }
        break :blk null;
    };
    const private_key = fields.require(0x04) catch
        return error.InvalidPrivateKey;
    if (!fields.done()) return error.InvalidPrivateKey;
    var parsed = try PrivateKey.fromDer(private_key.value);
    parsed.pss_constraints = pss_constraints;
    return parsed;
}

fn validateComponents(
    modulus: []const u8,
    public_exponent: []const u8,
    private_exponent: []const u8,
    prime1: []const u8,
    prime2: []const u8,
    exponent1: []const u8,
    exponent2: []const u8,
    coefficient: []const u8,
) Error!PrivateKey {
    if (modulus.len != 256 and modulus.len != 384 and modulus.len != 512) {
        return error.UnsupportedModulusBits;
    }
    if ((modulus[modulus.len - 1] & 1) == 0 or
        @clz(modulus[0]) != 0 or
        private_exponent.len > modulus.len or
        prime1.len > 256 or prime2.len > 256 or
        prime1.len + 1 < modulus.len / 2 or
        prime2.len + 1 < modulus.len / 2 or
        exponent1.len > prime1.len or exponent2.len > prime2.len or
        coefficient.len > prime1.len)
    {
        return error.InvalidPrivateKey;
    }
    if (public_exponent.len == 0 or public_exponent.len > 4 or
        (public_exponent[public_exponent.len - 1] & 1) == 0)
    {
        return error.InvalidPrivateKey;
    }
    var exponent: u32 = 0;
    for (public_exponent) |byte| exponent = (exponent << 8) | byte;
    if (exponent < 3) return error.InvalidPrivateKey;
    const modulus_field = RsaModulus.fromBytes(modulus, .big) catch
        return error.InvalidPrivateKey;
    _ = RsaFieldElement.fromBytes(
        modulus_field,
        private_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    return .{
        .modulus = modulus,
        .public_exponent = public_exponent,
        .private_exponent = private_exponent,
        .prime1 = prime1,
        .prime2 = prime2,
        .exponent1 = exponent1,
        .exponent2 = exponent2,
        .coefficient = coefficient,
    };
}

fn signPss(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    message: []const u8,
    salt: []const u8,
    output: []u8,
) Error!usize {
    return signPssWithMask(
        private_key,
        Hash,
        .mgf1,
        message,
        salt,
        output,
    );
}

fn signPssShake(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    message: []const u8,
    salt: []const u8,
    output: []u8,
) Error!usize {
    return signPssWithMask(
        private_key,
        Hash,
        .shake,
        message,
        salt,
        output,
    );
}

const PssMaskGeneration = enum { mgf1, shake };

fn signPssWithMask(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    comptime mask_generation: PssMaskGeneration,
    message: []const u8,
    salt: []const u8,
    output: []u8,
) Error!usize {
    if (salt.len != Hash.digest_length) return error.InvalidSaltLength;
    if (private_key.key.pss_constraints) |constraints| {
        @branchHint(.unlikely);
        const algorithm: rsa_pss.Algorithm = if (Hash == Sha224)
            .rsa_pss_sha224
        else if (Hash == Sha256)
            .rsa_pss_sha256
        else if (Hash == Sha384)
            .rsa_pss_sha384
        else if (Hash == Sha512)
            .rsa_pss_sha512
        else if (Hash == Sha512_224)
            .rsa_pss_sha512_224
        else if (Hash == Sha512_256)
            .rsa_pss_sha512_256
        else if (Hash == Sha3_224)
            .rsa_pss_sha3_224
        else if (Hash == Sha3_256)
            .rsa_pss_sha3_256
        else if (Hash == Sha3_384)
            .rsa_pss_sha3_384
        else if (Hash == Sha3_512)
            .rsa_pss_sha3_512
        else if (Hash == Shake128)
            .rsa_pss_shake128
        else if (Hash == Shake256)
            .rsa_pss_shake256
        else
            return error.KeyAlgorithmMismatch;
        if (!constraints.permits(algorithm)) {
            return error.KeyAlgorithmMismatch;
        }
    }
    const modulus_len = private_key.key.modulus.len;
    if (output.len < modulus_len) return error.SignatureBufferTooSmall;
    const modulus = private_key.modulus;
    const modulus_bits = modulus.bits();
    if (modulus_bits != modulus_len * 8) {
        return error.UnsupportedModulusBits;
    }
    const encoded_bits = modulus_bits - 1;
    const encoded_len = (encoded_bits + 7) / 8;
    if (encoded_len < 2 * Hash.digest_length + 2) {
        return error.MessageTooLong;
    }

    var encoded_message: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded_message);
    const encoded = encoded_message[0..encoded_len];
    @memset(encoded, 0);
    var message_hash: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &message_hash);
    Hash.hash(message, &message_hash, .{});
    var final_hash: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &final_hash);
    var hash_input: [8 + 2 * Sha512.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &hash_input);
    @memset(hash_input[0..8], 0);
    @memcpy(hash_input[8..][0..Hash.digest_length], &message_hash);
    @memcpy(
        hash_input[8 + Hash.digest_length ..][0..salt.len],
        salt,
    );
    Hash.hash(
        hash_input[0 .. 8 + Hash.digest_length + salt.len],
        &final_hash,
        .{},
    );

    const data_block_len = encoded_len - Hash.digest_length - 1;
    const delimiter = data_block_len - salt.len - 1;
    encoded[delimiter] = 1;
    @memcpy(encoded[data_block_len - salt.len .. data_block_len], salt);
    switch (mask_generation) {
        .mgf1 => mgf1Xor(Hash, encoded[0..data_block_len], &final_hash),
        .shake => shakeXor(Hash, encoded[0..data_block_len], &final_hash),
    }
    const unused_bits: u3 = @intCast(encoded_len * 8 - encoded_bits);
    encoded[0] &= @as(u8, 0xff) >> unused_bits;
    @memcpy(encoded[data_block_len..][0..Hash.digest_length], &final_hash);
    encoded[encoded_len - 1] = 0xbc;

    const representative = RsaFieldElement.fromBytes(
        modulus,
        encoded,
        .big,
    ) catch return error.MessageTooLong;
    var signature = try privateOperation(
        private_key,
        representative,
    );
    defer std.crypto.secureZero(RsaFieldElement, (&signature)[0..1]);
    signature.toBytes(output[0..modulus_len], .big) catch
        return error.InvalidPrivateKey;
    return modulus_len;
}

fn signPkcs1v15(
    private_key: *const PreparedPrivateKey,
    comptime Hash: type,
    message: []const u8,
    output: []u8,
) Error!usize {
    if (private_key.key.pss_constraints != null) {
        @branchHint(.unlikely);
        return error.KeyAlgorithmMismatch;
    }
    const modulus_len = private_key.key.modulus.len;
    if (output.len < modulus_len) return error.SignatureBufferTooSmall;
    const digest_info_prefix: []const u8 = &switch (Hash) {
        Sha224 => .{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
            0x00, 0x04, 0x1c,
        },
        Sha256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        Sha384 => .{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        },
        Sha512 => .{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        Sha512_224 => .{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05,
            0x00, 0x04, 0x1c,
        },
        Sha512_256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05,
            0x00, 0x04, 0x20,
        },
        Sha3_224 => .{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
            0x00, 0x04, 0x1c,
        },
        Sha3_256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
            0x00, 0x04, 0x20,
        },
        Sha3_384 => .{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
            0x00, 0x04, 0x30,
        },
        Sha3_512 => .{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unsupported PKCS#1 v1.5 hash"),
    };
    const digest_info_len = digest_info_prefix.len + Hash.digest_length;
    if (modulus_len < digest_info_len + 11) return error.MessageTooLong;

    var encoded_message: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded_message);
    const encoded = encoded_message[0..modulus_len];
    encoded[0] = 0;
    encoded[1] = 1;
    const separator = modulus_len - digest_info_len - 1;
    @memset(encoded[2..separator], 0xff);
    encoded[separator] = 0;
    @memcpy(
        encoded[separator + 1 ..][0..digest_info_prefix.len],
        digest_info_prefix,
    );
    var digest: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    Hash.hash(message, &digest, .{});
    @memcpy(encoded[modulus_len - digest.len ..], &digest);

    const modulus = private_key.modulus;
    const representative = RsaFieldElement.fromBytes(
        modulus,
        encoded,
        .big,
    ) catch return error.MessageTooLong;
    var signature = try privateOperation(private_key, representative);
    defer std.crypto.secureZero(RsaFieldElement, (&signature)[0..1]);
    signature.toBytes(output[0..modulus_len], .big) catch
        return error.InvalidPrivateKey;
    return modulus_len;
}

fn validateKeyConsistency(
    private_key: *const PreparedPrivateKey,
) Error!void {
    const modulus = private_key.modulus;
    const message = RsaFieldElement.fromPrimitive(
        u8,
        modulus,
        @as(u8, 2),
    ) catch return error.InvalidPrivateKey;
    var signed = try privateOperation(private_key, message);
    defer std.crypto.secureZero(RsaFieldElement, (&signed)[0..1]);
    var full_exponent_result = modulus.powWithEncodedExponent(
        message,
        private_key.key.private_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(
        RsaFieldElement,
        (&full_exponent_result)[0..1],
    );
    if (!signed.eql(full_exponent_result)) return error.InvalidPrivateKey;
}

fn verifyPrivateResult1024Pair(
    private_key: *const PreparedPrivateKey,
    signature: RsaFieldElement,
    expected_residues: Montgomery1024.Pair,
) Error!void {
    // For canonical values below n = p*q, equality modulo both private primes
    // is equivalent to equality modulo n. Reduce the final recombined result,
    // not the pre-CRT residues, so recombination faults remain detectable.
    const first_context = if (private_key.prime1_1024) |*value|
        value
    else
        unreachable;
    const second_context = if (private_key.prime2_1024) |*value|
        value
    else
        unreachable;
    var signature_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &signature_bytes);
    signature.toBytes(&signature_bytes, .big) catch
        return error.InvalidPrivateKey;

    var signature_residues = Montgomery1024.reduceWidePair(
        first_context,
        second_context,
        &signature_bytes,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&signature_residues));
    var recovered = Montgomery1024.pow65537Pair(
        first_context,
        second_context,
        signature_residues,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&recovered));
    if (!Montgomery1024.equalLimbs(
        recovered.first,
        expected_residues.first,
    ) or !Montgomery1024.equalLimbs(
        recovered.second,
        expected_residues.second,
    )) {
        return error.InvalidPrivateKey;
    }
}

fn verifyPrivateResultGeneric(
    private_key: *const PreparedPrivateKey,
    signature: RsaFieldElement,
    expected: RsaFieldElement,
) Error!void {
    const modulus = private_key.modulus;
    var recovered = modulus.powWithEncodedPublicExponent(
        signature,
        private_key.key.public_exponent,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(RsaFieldElement, (&recovered)[0..1]);
    if (!recovered.eql(expected)) return error.InvalidPrivateKey;
}

fn privateOperation(
    private_key: *const PreparedPrivateKey,
    message: RsaFieldElement,
) Error!RsaFieldElement {
    const modulus = private_key.modulus;
    const p = private_key.prime1;
    const q = private_key.prime2;
    if (private_key.prime1_1024) |*first_context| {
        const second_context = if (private_key.prime2_1024) |*value|
            value
        else
            unreachable;
        var message_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &message_bytes);
        message.toBytes(&message_bytes, .big) catch
            return error.InvalidPrivateKey;
        var residues = Montgomery1024.reduceWidePair(
            first_context,
            second_context,
            &message_bytes,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&residues));
        var powered = try Montgomery1024.powSecretPair(
            first_context,
            second_context,
            residues,
            private_key.key.exponent1,
            private_key.key.exponent2,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&powered));
        var recombined = try first_context.crtRecombine(
            powered.first,
            powered.second,
            private_key.key.prime2,
            private_key.key.coefficient,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&recombined));
        var encoded: [2 * Montgomery1024.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &encoded);
        Montgomery1024.encodeWide(recombined, &encoded);
        const signature = RsaFieldElement.fromBytes(modulus, &encoded, .big) catch
            return error.InvalidPrivateKey;
        if (std.mem.eql(u8, private_key.key.public_exponent, "\x01\x00\x01")) {
            try verifyPrivateResult1024Pair(
                private_key,
                signature,
                residues,
            );
        } else {
            @branchHint(.unlikely);
            try verifyPrivateResultGeneric(private_key, signature, message);
        }
        return signature;
    }

    const message_mod_p = p.reduce(message.v);
    const message_mod_q = q.reduce(message.v);
    var m1 = p.powWithEncodedExponent(
        message_mod_p,
        private_key.key.exponent1,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(PrimeFieldElement, (&m1)[0..1]);
    var m2 = q.powWithEncodedExponent(
        message_mod_q,
        private_key.key.exponent2,
        .big,
    ) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(PrimeFieldElement, (&m2)[0..1]);

    const m2_mod_p = p.reduce(m2.v);
    var h = p.mul(
        p.sub(m1, m2_mod_p),
        private_key.q_inverse_mod_p,
    );
    defer std.crypto.secureZero(PrimeFieldElement, (&h)[0..1]);

    var h_bytes: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &h_bytes);
    h.toBytes(h_bytes[0..private_key.key.prime1.len], .big) catch
        return error.InvalidPrivateKey;
    const h_full = RsaFieldElement.fromBytes(
        modulus,
        h_bytes[0..private_key.key.prime1.len],
        .big,
    ) catch return error.InvalidPrivateKey;
    var m2_bytes: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &m2_bytes);
    m2.toBytes(m2_bytes[0..private_key.key.prime2.len], .big) catch
        return error.InvalidPrivateKey;
    const m2_full = RsaFieldElement.fromBytes(
        modulus,
        m2_bytes[0..private_key.key.prime2.len],
        .big,
    ) catch return error.InvalidPrivateKey;
    const signature = modulus.add(
        modulus.mul(private_key.q_full, h_full),
        m2_full,
    );
    try verifyPrivateResultGeneric(private_key, signature, message);
    return signature;
}

fn mgf1Xor(
    comptime Hash: type,
    output: []u8,
    seed: *const [Hash.digest_length]u8,
) void {
    var digest: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    var counter: u32 = 0;
    var offset: usize = 0;
    while (offset < output.len) : (counter += 1) {
        var hasher = Hash.init(.{});
        hasher.update(seed);
        var encoded_counter: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded_counter, counter, .big);
        hasher.update(&encoded_counter);
        hasher.final(&digest);
        const take = @min(digest.len, output.len - offset);
        for (output[offset..][0..take], digest[0..take]) |*byte, mask| {
            byte.* ^= mask;
        }
        offset += take;
    }
}

fn shakeXor(
    comptime Hash: type,
    output: []u8,
    seed: []const u8,
) void {
    var mask: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &mask);
    var xof = Hash.init(.{});
    xof.update(seed);
    xof.final(mask[0..output.len]);
    for (output, mask[0..output.len]) |*byte, mask_byte| {
        byte.* ^= mask_byte;
    }
}

fn positiveInteger(element: Element) ![]const u8 {
    if (element.tag != 0x02 or element.value.len == 0 or
        (element.value[0] & 0x80) != 0)
    {
        return error.InvalidPrivateKey;
    }
    if (element.value.len > 1 and element.value[0] == 0) {
        if ((element.value[1] & 0x80) == 0) {
            return error.InvalidPrivateKey;
        }
        return element.value[1..];
    }
    if (element.value.len == 1 and element.value[0] == 0) {
        return error.InvalidPrivateKey;
    }
    return element.value;
}

fn stripUnsignedPadding(value: []const u8) []const u8 {
    var offset: usize = 0;
    while (offset < value.len and value[offset] == 0) : (offset += 1) {}
    return value[offset..];
}

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |a_byte, b_byte| difference |= a_byte ^ b_byte;
    return difference == 0;
}

const Element = struct {
    tag: u8,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn require(self: *Reader, tag: u8) !Element {
        const element = (try self.next()) orelse
            return error.InvalidPrivateKey;
        if (element.tag != tag) return error.InvalidPrivateKey;
        return element;
    }

    fn next(self: *Reader) !?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidPrivateKey;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidPrivateKey;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidPrivateKey;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidPrivateKey;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidPrivateKey;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidPrivateKey;
        }
        if (length > self.bytes.len - self.offset) {
            return error.InvalidPrivateKey;
        }
        const start = self.offset;
        self.offset += length;
        return .{ .tag = tag, .value = self.bytes[start..self.offset] };
    }

    fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

fn expectMontgomeryPower(
    specialized: *const Montgomery1024,
    generic: PrimeModulus,
    exponent: []const u8,
    base: *const [Montgomery1024.encoded_length]u8,
) !void {
    const generic_base = try PrimeFieldElement.fromBytes(generic, base, .big);
    var expected = try generic.powWithEncodedExponent(
        generic_base,
        exponent,
        .big,
    );
    defer std.crypto.secureZero(PrimeFieldElement, (&expected)[0..1]);
    var expected_bytes: [Montgomery1024.encoded_length]u8 = undefined;
    try expected.toBytes(&expected_bytes, .big);

    var actual = try specialized.powSecret(base, exponent);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
    var actual_bytes: [Montgomery1024.encoded_length]u8 = undefined;
    Montgomery1024.encode(actual, &actual_bytes);
    try std.testing.expectEqualSlices(u8, &expected_bytes, &actual_bytes);
}

fn testMontgomeryProducts(modulus_bytes: []const u8) !void {
    const specialized = try Montgomery1024.init(modulus_bytes);
    const generic = try PrimeModulus.fromBytes(modulus_bytes, .big);
    var state: u64 = 0x6a09e667f3bcc909;
    for (0..64) |_| {
        var a_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        var b_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        for (&a_bytes, &b_bytes) |*a_byte, *b_byte| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            a_byte.* = @truncate(state);
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b_byte.* = @truncate(state);
        }
        a_bytes[0] &= 0x7f;
        b_bytes[0] &= 0x7f;

        const generic_a = try PrimeFieldElement.fromBytes(
            generic,
            &a_bytes,
            .big,
        );
        const generic_b = try PrimeFieldElement.fromBytes(
            generic,
            &b_bytes,
            .big,
        );
        var expected = generic.mul(generic_a, generic_b);
        defer std.crypto.secureZero(
            PrimeFieldElement,
            (&expected)[0..1],
        );
        var expected_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        try expected.toBytes(&expected_bytes, .big);

        const a = specialized.toMontgomery(Montgomery1024.decode(&a_bytes));
        const b = specialized.toMontgomery(Montgomery1024.decode(&b_bytes));
        const integrated_product = specialized.mul(a, b);
        const product_then_reduce = specialized.mulProduct(a, b);
        try std.testing.expectEqualSlices(
            u64,
            &product_then_reduce,
            &integrated_product,
        );
        var actual = specialized.fromMontgomery(integrated_product);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
        var actual_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        Montgomery1024.encode(actual, &actual_bytes);
        try std.testing.expectEqualSlices(u8, &expected_bytes, &actual_bytes);
    }
}

fn testMontgomeryPrime(modulus_bytes: []const u8, exponent: []const u8) !void {
    const specialized = try Montgomery1024.init(modulus_bytes);
    const generic = try PrimeModulus.fromBytes(modulus_bytes, .big);

    var zero = [_]u8{0} ** Montgomery1024.encoded_length;
    try expectMontgomeryPower(&specialized, generic, exponent, &zero);
    zero[zero.len - 1] = 1;
    try expectMontgomeryPower(&specialized, generic, exponent, &zero);

    var patterned = [_]u8{0x5a} ** Montgomery1024.encoded_length;
    patterned[0] &= 0x7f;
    try expectMontgomeryPower(&specialized, generic, exponent, &patterned);

    var modulus_minus_one = [_]u8{0} ** Montgomery1024.encoded_length;
    @memcpy(
        modulus_minus_one[modulus_minus_one.len - modulus_bytes.len ..],
        modulus_bytes,
    );
    var index = modulus_minus_one.len;
    while (index != 0) {
        index -= 1;
        if (modulus_minus_one[index] != 0) {
            modulus_minus_one[index] -= 1;
            break;
        }
        modulus_minus_one[index] = 0xff;
    }
    try expectMontgomeryPower(
        &specialized,
        generic,
        exponent,
        &modulus_minus_one,
    );
}

fn testMontgomeryWideReduction(key: PrivateKey) !void {
    const first_context = try Montgomery1024.init(key.prime1);
    const second_context = try Montgomery1024.init(key.prime2);
    const modulus = try RsaModulus.fromBytes(key.modulus, .big);
    const first_modulus = try PrimeModulus.fromBytes(key.prime1, .big);
    const second_modulus = try PrimeModulus.fromBytes(key.prime2, .big);
    var state: u64 = 0xbb67ae8584caa73b;

    for (0..64) |_| {
        var encoded: [2 * Montgomery1024.encoded_length]u8 = undefined;
        for (&encoded) |*byte| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            byte.* = @truncate(state);
        }
        encoded[0] &= 0x7f;
        const value = try RsaFieldElement.fromBytes(modulus, &encoded, .big);
        var first_expected = first_modulus.reduce(value.v);
        defer std.crypto.secureZero(
            PrimeFieldElement,
            (&first_expected)[0..1],
        );
        var second_expected = second_modulus.reduce(value.v);
        defer std.crypto.secureZero(
            PrimeFieldElement,
            (&second_expected)[0..1],
        );
        var first_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        try first_expected.toBytes(&first_bytes, .big);
        var second_bytes: [Montgomery1024.encoded_length]u8 = undefined;
        try second_expected.toBytes(&second_bytes, .big);

        var actual = Montgomery1024.reduceWidePair(
            &first_context,
            &second_context,
            &encoded,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
        var actual_first: [Montgomery1024.encoded_length]u8 = undefined;
        Montgomery1024.encode(actual.first, &actual_first);
        var actual_second: [Montgomery1024.encoded_length]u8 = undefined;
        Montgomery1024.encode(actual.second, &actual_second);
        try std.testing.expectEqualSlices(u8, &first_bytes, &actual_first);
        try std.testing.expectEqualSlices(u8, &second_bytes, &actual_second);
    }
}

fn testMontgomeryPublic65537(modulus_bytes: []const u8) !void {
    const specialized = try Montgomery2048.init(modulus_bytes);
    const generic = RsaModulus.fromBytes(modulus_bytes, .big) catch
        return error.InvalidPrivateKey;
    var inputs = [_][Montgomery2048.encoded_length]u8{
        [_]u8{0} ** Montgomery2048.encoded_length,
        [_]u8{0} ** Montgomery2048.encoded_length,
        [_]u8{0x5a} ** Montgomery2048.encoded_length,
        [_]u8{0x7f} ** Montgomery2048.encoded_length,
    };
    inputs[1][inputs[1].len - 1] = 1;
    for (inputs) |encoded| {
        const generic_base = RsaFieldElement.fromBytes(
            generic,
            &encoded,
            .big,
        ) catch return error.InvalidPrivateKey;
        var expected = generic.powWithEncodedPublicExponent(
            generic_base,
            "\x01\x00\x01",
            .big,
        ) catch return error.InvalidPrivateKey;
        defer std.crypto.secureZero(RsaFieldElement, (&expected)[0..1]);
        var expected_bytes: [Montgomery2048.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected_bytes);
        expected.toBytes(&expected_bytes, .big) catch
            return error.InvalidPrivateKey;

        var actual = specialized.pow65537(Montgomery2048.decode(&encoded));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
        var actual_bytes: [Montgomery2048.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &actual_bytes);
        Montgomery2048.encode(actual, &actual_bytes);
        try std.testing.expectEqualSlices(u8, &expected_bytes, &actual_bytes);
    }
}

fn testMontgomeryPairFios(
    first_context: *const Montgomery1024,
    second_context: *const Montgomery1024,
) !void {
    var first_boundary = first_context.modulus;
    first_boundary[0] -= 1;
    var second_boundary = second_context.modulus;
    second_boundary[0] -= 1;
    const boundary_cios = Montgomery1024.mulPair(
        first_context,
        second_context,
        first_boundary,
        second_boundary,
        first_boundary,
        second_boundary,
    );
    var boundary_multiply_workspace = Montgomery1024.PairWorkspace{};
    defer boundary_multiply_workspace.clear();
    var boundary_product_workspace = Montgomery1024.ProductPairWorkspace{};
    defer boundary_product_workspace.clear();
    const boundary_optimized = Montgomery1024.mulPairOptimizedWithWorkspaces(
        first_context,
        second_context,
        &boundary_multiply_workspace,
        &boundary_product_workspace,
        first_boundary,
        second_boundary,
        first_boundary,
        second_boundary,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.first,
        &boundary_optimized.first,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.second,
        &boundary_optimized.second,
    );
    const boundary_square = Montgomery1024.squarePairWithWorkspaces(
        first_context,
        second_context,
        &boundary_multiply_workspace,
        &boundary_product_workspace,
        first_boundary,
        second_boundary,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.first,
        &boundary_square.first,
    );
    try std.testing.expectEqualSlices(
        u64,
        &boundary_cios.second,
        &boundary_square.second,
    );

    var state: u64 = 0x9e37_79b9_7f4a_7c15;
    for (0..64) |_| {
        var encoded: [4][Montgomery1024.encoded_length]u8 = undefined;
        for (&encoded) |*value| {
            for (value) |*byte| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                byte.* = @truncate(state);
            }
            value[0] &= 0x7f;
        }
        const first_a = Montgomery1024.decode(&encoded[0]);
        const second_a = Montgomery1024.decode(&encoded[1]);
        const first_b = Montgomery1024.decode(&encoded[2]);
        const second_b = Montgomery1024.decode(&encoded[3]);
        const cios = Montgomery1024.mulPair(
            first_context,
            second_context,
            first_a,
            second_a,
            first_b,
            second_b,
        );
        const fios = Montgomery1024.mulPairFios(
            first_context,
            second_context,
            first_a,
            second_a,
            first_b,
            second_b,
        );
        try std.testing.expectEqualSlices(u64, &cios.first, &fios.first);
        try std.testing.expectEqualSlices(u64, &cios.second, &fios.second);
        var multiply_workspace = Montgomery1024.PairWorkspace{};
        defer multiply_workspace.clear();
        var product_workspace = Montgomery1024.ProductPairWorkspace{};
        defer product_workspace.clear();
        const optimized = Montgomery1024.mulPairOptimizedWithWorkspaces(
            first_context,
            second_context,
            &multiply_workspace,
            &product_workspace,
            first_a,
            second_a,
            first_b,
            second_b,
        );
        try std.testing.expectEqualSlices(
            u64,
            &cios.first,
            &optimized.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &cios.second,
            &optimized.second,
        );
        const square = Montgomery1024.squarePairWithWorkspaces(
            first_context,
            second_context,
            &multiply_workspace,
            &product_workspace,
            first_a,
            second_a,
        );
        const square_cios = Montgomery1024.mulPair(
            first_context,
            second_context,
            first_a,
            second_a,
            first_a,
            second_a,
        );
        try std.testing.expectEqualSlices(
            u64,
            &square_cios.first,
            &square.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &square_cios.second,
            &square.second,
        );

        const first_extra: u64 = encoded[0][0] & 1;
        const second_extra: u64 = encoded[1][0] & 1;
        const reduced_pair = Montgomery1024.reduceLimbsPair(
            first_context,
            second_context,
            first_a,
            second_a,
            first_extra,
            second_extra,
        );
        const first_reduced = first_context.reduceLimbs(
            first_a,
            first_extra,
        );
        const second_reduced = second_context.reduceLimbs(
            second_a,
            second_extra,
        );
        try std.testing.expectEqualSlices(
            u64,
            &first_reduced,
            &reduced_pair.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &second_reduced,
            &reduced_pair.second,
        );
    }
}

test "RSA-2048 paired table selection covers every index" {
    var first_table: [32]Montgomery1024.Limbs = undefined;
    var second_table: [32]Montgomery1024.Limbs = undefined;
    for (0..first_table.len) |entry_index| {
        for (0..Montgomery1024.limb_count) |limb_index| {
            const value = (@as(u64, entry_index) << 32) | limb_index;
            first_table[entry_index][limb_index] = value;
            second_table[entry_index][limb_index] = ~value;
        }
    }
    for (0..first_table.len) |first_index| {
        const second_index = second_table.len - 1 - first_index;
        const selected = Montgomery1024.selectTablePair(
            first_table.len,
            &first_table,
            &second_table,
            @intCast(first_index),
            @intCast(second_index),
        );
        try std.testing.expectEqualSlices(
            u64,
            &first_table[first_index],
            &selected.first,
        );
        try std.testing.expectEqualSlices(
            u64,
            &second_table[second_index],
            &selected.second,
        );
    }
}

test "RSA-2048 Montgomery exponentiation matches the generic finite field" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    try testMontgomeryWideReduction(key);
    try testMontgomeryProducts(key.prime1);
    try testMontgomeryProducts(key.prime2);
    try testMontgomeryPrime(key.prime1, key.exponent1);
    try testMontgomeryPrime(key.prime2, key.exponent2);
    try testMontgomeryPublic65537(key.modulus);

    const first_context = try Montgomery1024.init(key.prime1);
    const second_context = try Montgomery1024.init(key.prime2);
    try testMontgomeryPairFios(&first_context, &second_context);
    var first_base = [_]u8{0x36} ** Montgomery1024.encoded_length;
    var second_base = [_]u8{0x5c} ** Montgomery1024.encoded_length;
    first_base[0] &= 0x7f;
    second_base[0] &= 0x7f;
    var base_pair = Montgomery1024.Pair{
        .first = Montgomery1024.decode(&first_base),
        .second = Montgomery1024.decode(&second_base),
    };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&base_pair));
    var paired = try Montgomery1024.powSecretPair(
        &first_context,
        &second_context,
        base_pair,
        key.exponent1,
        key.exponent2,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&paired));
    var first_independent = try first_context.powSecret(
        &first_base,
        key.exponent1,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&first_independent));
    var second_independent = try second_context.powSecret(
        &second_base,
        key.exponent2,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&second_independent));
    try std.testing.expectEqualSlices(
        u64,
        &first_independent,
        &paired.first,
    );
    try std.testing.expectEqualSlices(
        u64,
        &second_independent,
        &paired.second,
    );

    var public_pair = Montgomery1024.pow65537Pair(
        &first_context,
        &second_context,
        base_pair,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&public_pair));
    var first_public = try first_context.powSecret(
        &first_base,
        "\x01\x00\x01",
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&first_public));
    var second_public = try second_context.powSecret(
        &second_base,
        "\x01\x00\x01",
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&second_public));
    try std.testing.expectEqualSlices(u64, &first_public, &public_pair.first);
    try std.testing.expectEqualSlices(u64, &second_public, &public_pair.second);
}

test "RSA-2048 paired-prime fault check rejects a corrupted result" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const message = RsaFieldElement.fromPrimitive(
        u8,
        prepared.modulus,
        42,
    ) catch return error.InvalidPrivateKey;
    var message_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &message_bytes);
    message.toBytes(&message_bytes, .big) catch
        return error.InvalidPrivateKey;
    const first_context = if (prepared.prime1_1024) |*value|
        value
    else
        unreachable;
    const second_context = if (prepared.prime2_1024) |*value|
        value
    else
        unreachable;
    var expected_residues = Montgomery1024.reduceWidePair(
        first_context,
        second_context,
        &message_bytes,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&expected_residues));

    var signature = try privateOperation(&prepared, message);
    defer std.crypto.secureZero(RsaFieldElement, (&signature)[0..1]);
    try verifyPrivateResult1024Pair(&prepared, signature, expected_residues);
    var corrupted_bytes: [2 * Montgomery1024.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &corrupted_bytes);
    signature.toBytes(&corrupted_bytes, .big) catch
        return error.InvalidPrivateKey;
    corrupted_bytes[corrupted_bytes.len - 1] ^= 1;
    const corrupted = RsaFieldElement.fromBytes(
        prepared.modulus,
        &corrupted_bytes,
        .big,
    ) catch return error.InvalidPrivateKey;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        verifyPrivateResult1024Pair(&prepared, corrupted, expected_residues),
    );
}

test "PKCS1 and PKCS8 RSA keys produce verifiable PSS signatures" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs1 = decodeHex(vectors.private_key_pkcs1_hex);
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key1 = try PrivateKey.fromDer(&pkcs1);
    const key8 = try PrivateKey.fromDer(&pkcs8);
    try std.testing.expectEqual(@as(usize, 2048), key1.modulusBits());
    try std.testing.expectEqualSlices(u8, key1.modulus, key8.modulus);
    try std.testing.expectEqualSlices(
        u8,
        key1.private_exponent,
        key8.private_exponent,
    );

    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const public_parts = try std.crypto.Certificate.rsa.PublicKey.parseDer(
        certificate.pubKey(),
    );
    try std.testing.expect(key1.matchesPublicKey(
        public_parts.modulus,
        public_parts.exponent,
    ));
    const public_key = try std.crypto.Certificate.rsa.PublicKey.fromBytes(
        public_parts.exponent,
        public_parts.modulus,
    );
    const prepared_public = try PreparedPublicKey.init(
        public_parts.exponent,
        public_parts.modulus,
    );
    const message = "pure Zig RSA-PSS signing";

    inline for (.{
        .{ Sha224, &([_]u8{0x11} ** Sha224.digest_length) },
        .{ Sha256, &([_]u8{0x21} ** Sha256.digest_length) },
        .{ Sha384, &([_]u8{0x31} ** Sha384.digest_length) },
        .{ Sha512, &([_]u8{0x41} ** Sha512.digest_length) },
    }) |case| {
        const Hash = case[0];
        const salt = case[1];
        var signature: [512]u8 = undefined;
        const signature_len = if (Hash == Sha224)
            try key8.signPssSha224(message, salt, &signature)
        else if (Hash == Sha256)
            try key8.signPssSha256(message, salt, &signature)
        else if (Hash == Sha384)
            try key8.signPssSha384(message, salt, &signature)
        else
            try key8.signPssSha512(message, salt, &signature);
        try std.testing.expectEqual(@as(usize, 256), signature_len);
        try std.crypto.Certificate.rsa.PSSSignature.verify(
            256,
            signature[0..256].*,
            message,
            public_key,
            Hash,
        );
        const parts = [_][]const u8{message};
        if (Hash == Sha224)
            try prepared_public.verifyPssSha224(&parts, signature[0..signature_len])
        else if (Hash == Sha256)
            try prepared_public.verifyPssSha256(&parts, signature[0..signature_len])
        else if (Hash == Sha384)
            try prepared_public.verifyPssSha384(&parts, signature[0..signature_len])
        else
            try prepared_public.verifyPssSha512(&parts, signature[0..signature_len]);
        signature[signature_len - 1] ^= 1;
        if (Hash == Sha224)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha224(&parts, signature[0..signature_len]),
            )
        else if (Hash == Sha256)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha256(&parts, signature[0..signature_len]),
            )
        else if (Hash == Sha384)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha384(&parts, signature[0..signature_len]),
            )
        else
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPssSha512(&parts, signature[0..signature_len]),
            );
    }

    inline for (.{ Sha224, Sha256, Sha384, Sha512 }) |Hash| {
        var signature: [512]u8 = undefined;
        const signature_len = if (Hash == Sha224)
            try key8.signPkcs1v15Sha224(message, &signature)
        else if (Hash == Sha256)
            try key8.signPkcs1v15Sha256(message, &signature)
        else if (Hash == Sha384)
            try key8.signPkcs1v15Sha384(message, &signature)
        else
            try key8.signPkcs1v15Sha512(message, &signature);
        try std.testing.expectEqual(@as(usize, 256), signature_len);
        try std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(
            256,
            signature[0..256].*,
            message,
            public_key,
            Hash,
        );
        const parts = [_][]const u8{message};
        if (Hash == Sha224)
            try prepared_public.verifyPkcs1v15Sha224(
                &parts,
                signature[0..signature_len],
            )
        else if (Hash == Sha256)
            try prepared_public.verifyPkcs1v15Sha256(
                &parts,
                signature[0..signature_len],
            )
        else if (Hash == Sha384)
            try prepared_public.verifyPkcs1v15Sha384(
                &parts,
                signature[0..signature_len],
            )
        else
            try prepared_public.verifyPkcs1v15Sha512(
                &parts,
                signature[0..signature_len],
            );
        signature[signature_len - 1] ^= 1;
        if (Hash == Sha224)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha224(
                    &parts,
                    signature[0..signature_len],
                ),
            )
        else if (Hash == Sha256)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha256(
                    &parts,
                    signature[0..signature_len],
                ),
            )
        else if (Hash == Sha384)
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha384(
                    &parts,
                    signature[0..signature_len],
                ),
            )
        else
            try std.testing.expectError(
                error.InvalidSignature,
                prepared_public.verifyPkcs1v15Sha512(
                    &parts,
                    signature[0..signature_len],
                ),
            );
        try std.testing.expectError(
            error.InvalidSignature,
            std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(
                256,
                signature[0..256].*,
                message,
                public_key,
                Hash,
            ),
        );
    }

    var malformed = pkcs1;
    malformed[6] = 1;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        PrivateKey.fromDer(&malformed),
    );
    var inconsistent = pkcs1;
    inconsistent[inconsistent.len - 1] ^= 1;
    const inconsistent_key = try PrivateKey.fromDer(&inconsistent);
    try std.testing.expectError(
        error.InvalidPrivateKey,
        inconsistent_key.prepare(),
    );
    var unused_signature: [512]u8 = undefined;
    try std.testing.expectError(
        error.InvalidSaltLength,
        key1.signPssSha256(message, &.{}, &unused_signature),
    );
}

test "RSA private keys sign SHA3 PSS and PKCS1 signatures" {
    const x509_signature = @import("../../x509/signature.zig");
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const message = "pure Zig RSA SHA3 signing";

    inline for (.{
        .{ Sha3_224, rsa_pss.Algorithm.rsa_pss_sha3_224, @as(u8, 0x52) },
        .{ Sha3_256, rsa_pss.Algorithm.rsa_pss_sha3_256, @as(u8, 0x62) },
        .{ Sha3_384, rsa_pss.Algorithm.rsa_pss_sha3_384, @as(u8, 0x72) },
        .{ Sha3_512, rsa_pss.Algorithm.rsa_pss_sha3_512, @as(u8, 0x82) },
    }) |case| {
        const Hash = case[0];
        const algorithm = case[1];
        const salt = [_]u8{case[2]} ** Hash.digest_length;
        var signature: [512]u8 = undefined;
        const pss_len = if (Hash == Sha3_224)
            try prepared.signPssSha3_224(message, &salt, &signature)
        else if (Hash == Sha3_256)
            try prepared.signPssSha3_256(message, &salt, &signature)
        else if (Hash == Sha3_384)
            try prepared.signPssSha3_384(message, &salt, &signature)
        else
            try prepared.signPssSha3_512(message, &salt, &signature);
        try std.testing.expectEqual(@as(usize, 256), pss_len);
        try x509_signature.verify(
            algorithm,
            certificate,
            message,
            signature[0..pss_len],
        );

        const pkcs1_algorithm: rsa_pss.Algorithm = if (Hash == Sha3_224)
            .rsa_pkcs1_sha3_224
        else if (Hash == Sha3_256)
            .rsa_pkcs1_sha3_256
        else if (Hash == Sha3_384)
            .rsa_pkcs1_sha3_384
        else
            .rsa_pkcs1_sha3_512;
        const pkcs1_len = if (Hash == Sha3_224)
            try prepared.signPkcs1v15Sha3_224(message, &signature)
        else if (Hash == Sha3_256)
            try prepared.signPkcs1v15Sha3_256(message, &signature)
        else if (Hash == Sha3_384)
            try prepared.signPkcs1v15Sha3_384(message, &signature)
        else
            try prepared.signPkcs1v15Sha3_512(message, &signature);
        try std.testing.expectEqual(@as(usize, 256), pkcs1_len);
        try x509_signature.verify(
            pkcs1_algorithm,
            certificate,
            message,
            signature[0..pkcs1_len],
        );
    }

    var one_shot_signature: [512]u8 = undefined;
    const one_shot_len = try key.signPssSha3_256(
        message,
        &([_]u8{0x92} ** Sha3_256.digest_length),
        &one_shot_signature,
    );
    try x509_signature.verify(
        .rsa_pss_sha3_256,
        certificate,
        message,
        one_shot_signature[0..one_shot_len],
    );
    _ = try key.signPkcs1v15Sha3_256(message, &one_shot_signature);
    try x509_signature.verify(
        .rsa_pkcs1_sha3_256,
        certificate,
        message,
        one_shot_signature[0..key.signatureLength()],
    );
}

test "RSA private keys sign SHA-512 truncated PSS and PKCS1 signatures" {
    const x509_signature = @import("../../x509/signature.zig");
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const message = "pure Zig RSA SHA-512 truncated signing";

    inline for (.{
        .{
            Sha512_224,
            rsa_pss.Algorithm.rsa_pss_sha512_224,
            rsa_pss.Algorithm.rsa_pkcs1_sha512_224,
            @as(u8, 0xa2),
        },
        .{
            Sha512_256,
            rsa_pss.Algorithm.rsa_pss_sha512_256,
            rsa_pss.Algorithm.rsa_pkcs1_sha512_256,
            @as(u8, 0xb2),
        },
    }) |case| {
        const Hash = case[0];
        const salt = [_]u8{case[3]} ** Hash.digest_length;
        var signature: [512]u8 = undefined;
        const pss_len = if (Hash == Sha512_224)
            try prepared.signPssSha512_224(message, &salt, &signature)
        else
            try prepared.signPssSha512_256(message, &salt, &signature);
        try x509_signature.verify(
            case[1],
            certificate,
            message,
            signature[0..pss_len],
        );

        const pkcs1_len = if (Hash == Sha512_224)
            try prepared.signPkcs1v15Sha512_224(message, &signature)
        else
            try prepared.signPkcs1v15Sha512_256(message, &signature);
        try x509_signature.verify(
            case[2],
            certificate,
            message,
            signature[0..pkcs1_len],
        );

        const one_shot_pss_len = if (Hash == Sha512_224)
            try key.signPssSha512_224(message, &salt, &signature)
        else
            try key.signPssSha512_256(message, &salt, &signature);
        try x509_signature.verify(
            case[1],
            certificate,
            message,
            signature[0..one_shot_pss_len],
        );

        const one_shot_pkcs1_len = if (Hash == Sha512_224)
            try key.signPkcs1v15Sha512_224(message, &signature)
        else
            try key.signPkcs1v15Sha512_256(message, &signature);
        try x509_signature.verify(
            case[2],
            certificate,
            message,
            signature[0..one_shot_pkcs1_len],
        );
    }
}

test "RSA private keys sign RFC 8692 PSS-SHAKE signatures" {
    const x509_signature = @import("../../x509/signature.zig");
    const vectors = @import("../testdata/rsa_signing.zig");
    const pkcs8 = decodeHex(vectors.private_key_pkcs8_hex);
    const certificate_der = decodeHex(vectors.certificate_hex);
    const key = try PrivateKey.fromDer(&pkcs8);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const certificate = try std.crypto.Certificate.parse(.{
        .buffer = &certificate_der,
        .index = 0,
    });
    const message = "pure Zig RFC 8692 RSA-PSS-SHAKE signing";

    inline for (.{
        .{ Shake128, rsa_pss.Algorithm.rsa_pss_shake128, @as(u8, 0xc2) },
        .{ Shake256, rsa_pss.Algorithm.rsa_pss_shake256, @as(u8, 0xd2) },
    }) |case| {
        const Hash = case[0];
        const salt = [_]u8{case[2]} ** Hash.digest_length;
        var signature: [512]u8 = undefined;
        const signature_len = if (Hash == Shake128)
            try prepared.signPssShake128(message, &salt, &signature)
        else
            try prepared.signPssShake256(message, &salt, &signature);
        try x509_signature.verify(
            case[1],
            certificate,
            message,
            signature[0..signature_len],
        );
        signature[signature_len - 1] ^= 1;
        try std.testing.expectError(
            error.InvalidSignature,
            x509_signature.verify(
                case[1],
                certificate,
                message,
                signature[0..signature_len],
            ),
        );
    }

    var wrong_mgf_signature: [512]u8 = undefined;
    const wrong_mgf_len = try signPss(
        &prepared,
        Shake128,
        message,
        &([_]u8{0xc2} ** Shake128.digest_length),
        &wrong_mgf_signature,
    );
    try std.testing.expectError(
        error.InvalidSignature,
        x509_signature.verify(
            .rsa_pss_shake128,
            certificate,
            message,
            wrong_mgf_signature[0..wrong_mgf_len],
        ),
    );

    var signature: [512]u8 = undefined;
    const shake128_len = try key.signPssShake128(
        message,
        &([_]u8{0xe2} ** Shake128.digest_length),
        &signature,
    );
    try x509_signature.verify(
        .rsa_pss_shake128,
        certificate,
        message,
        signature[0..shake128_len],
    );
    const shake256_len = try key.signPssShake256(
        message,
        &([_]u8{0xf2} ** Shake256.digest_length),
        &signature,
    );
    try x509_signature.verify(
        .rsa_pss_shake256,
        certificate,
        message,
        signature[0..shake256_len],
    );
}

test "RFC 8692 PSS-only PKCS8 keys enforce their SHAKE profile" {
    const vectors = @import("../testdata/rsa_signing.zig");
    const standard = decodeHex(vectors.private_key_pkcs8_hex);
    const rsa_algorithm = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    const shake_algorithm = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x06\x1e";
    const algorithm_offset = std.mem.indexOf(
        u8,
        &standard,
        rsa_algorithm,
    ) orelse return error.TestUnexpectedResult;
    var restricted: [standard.len - 3]u8 = undefined;
    @memcpy(restricted[0..algorithm_offset], standard[0..algorithm_offset]);
    @memcpy(
        restricted[algorithm_offset..][0..shake_algorithm.len],
        shake_algorithm,
    );
    @memcpy(
        restricted[algorithm_offset + shake_algorithm.len ..],
        standard[algorithm_offset + rsa_algorithm.len ..],
    );
    std.mem.writeInt(
        u16,
        restricted[2..4],
        @intCast(restricted.len - 4),
        .big,
    );

    const key = try PrivateKey.fromDer(&restricted);
    try std.testing.expect(key.pss_constraints.?.permits(.rsa_pss_shake128));
    try std.testing.expect(!key.pss_constraints.?.permits(.rsa_pss_shake256));
    var prepared = try key.prepare();
    defer prepared.deinit();
    const message = "RFC 8692 constrained private key";
    var signature: [512]u8 = undefined;
    _ = try prepared.signPssShake128(
        message,
        &([_]u8{0x71} ** Shake128.digest_length),
        &signature,
    );
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPssShake256(
            message,
            &([_]u8{0x72} ** Shake256.digest_length),
            &signature,
        ),
    );
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPkcs1v15Sha256(message, &signature),
    );
}

test "constrained RSA-PSS PKCS8 keys preserve signing restrictions" {
    const encoded = @embedFile(
        "../testdata/rsa-pss-constrained-private.pkcs8.der",
    );
    const key = try PrivateKey.fromDer(encoded);
    try std.testing.expect(key.pss_constraints != null);
    var prepared = try key.prepare();
    defer prepared.deinit();
    const message = "constrained RSA-PSS private key";
    var signature: [512]u8 = undefined;
    const salt = [_]u8{0x84} ** Sha384.digest_length;
    const signature_len = try prepared.signPssSha384(
        message,
        &salt,
        &signature,
    );
    const public_key = try std.crypto.Certificate.rsa.PublicKey.fromBytes(
        key.public_exponent,
        key.modulus,
    );
    try std.crypto.Certificate.rsa.PSSSignature.verify(
        256,
        signature[0..256].*,
        message,
        public_key,
        Sha384,
    );
    try std.testing.expectEqual(@as(usize, 256), signature_len);
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPssSha256(
            message,
            &([_]u8{0x25} ** Sha256.digest_length),
            &signature,
        ),
    );
    try std.testing.expectError(
        error.KeyAlgorithmMismatch,
        prepared.signPkcs1v15Sha384(message, &signature),
    );
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
