//! Regenerates the fixed-generator tables used by `src/crypto/ec/p256.zig`.

const std = @import("std");

const P256 = std.crypto.ecc.P256;
const table_entries = 256;
const comb_groups = 4;
const comb_width = 8;
const comb_entries = 1 << comb_width;
const comb_windows = 8;
const secret_comb_width = 6;
const secret_comb_entries = 1 << secret_comb_width;
const secret_comb_windows = 11;
const ecdh_block_size = 6;
// Signed radix-64 recoding covers bit 256 as well as the 256 scalar bits.
const ecdh_blocks = (257 + ecdh_block_size - 1) / ecdh_block_size;
const ecdh_entries_per_block = 1 << (ecdh_block_size - 1);
const ecdh_entries = ecdh_blocks * ecdh_entries_per_block;

pub fn main(init: std.process.Init) !void {
    var coordinates: [2][table_entries][4]u64 = undefined;
    for (0..table_entries) |index| {
        var scalar = [_]u8{0} ** 32;
        std.mem.writeInt(u16, scalar[0..2], @intCast(2 * index + 1), .little);
        const point = try P256.basePoint.mulPublic(scalar, .little);
        const affine = point.affineCoordinates();
        coordinates[0][index] = affine.x.limbs;
        coordinates[1][index] = affine.y.limbs;
    }
    var comb: [comb_groups][2][comb_entries][4]u64 = undefined;
    for (0..comb_groups) |group| {
        comb[group][0][0] = P256.Fe.zero.limbs;
        comb[group][1][0] = P256.Fe.one.limbs;
        for (1..comb_entries) |index| {
            var scalar = [_]u8{0} ** 32;
            for (0..comb_width) |column| {
                if ((index & (@as(usize, 1) << @intCast(column))) == 0) {
                    continue;
                }
                const bit_index =
                    (group * comb_width + column) * comb_windows;
                scalar[bit_index / 8] |=
                    @as(u8, 1) << @intCast(bit_index % 8);
            }
            const point = try P256.basePoint.mulPublic(scalar, .little);
            const affine = point.affineCoordinates();
            comb[group][0][index] = affine.x.limbs;
            comb[group][1][index] = affine.y.limbs;
        }
    }
    var secret_comb: [comb_groups][2][4][secret_comb_entries]u64 = undefined;
    for (0..comb_groups) |group| {
        for (0..secret_comb_entries) |index| {
            // Entry zero is the same harmless dummy as entry one; the secret
            // multiplier discards it with a conditional move.
            const effective_index = if (index == 0) 1 else index;
            var scalar = [_]u8{0} ** 32;
            for (0..secret_comb_width) |column| {
                if ((effective_index &
                    (@as(usize, 1) << @intCast(column))) == 0)
                {
                    continue;
                }
                const bit_index =
                    (group * secret_comb_width + column) *
                    secret_comb_windows;
                scalar[bit_index / 8] |=
                    @as(u8, 1) << @intCast(bit_index % 8);
            }
            const point = try P256.basePoint.mulPublic(scalar, .little);
            const affine = point.affineCoordinates();
            for (0..4) |limb| {
                secret_comb[group][0][limb][index] = affine.x.limbs[limb];
                secret_comb[group][1][limb][index] = affine.y.limbs[limb];
            }
        }
    }
    var scalarmul: [520][8]u64 = undefined;
    for (0..64) |block| {
        for (1..9) |multiple| {
            const value: u256 = @as(u256, multiple) << @intCast(4 * block);
            var scalar = [_]u8{0} ** 32;
            std.mem.writeInt(u256, &scalar, value, .little);
            const point = try P256.basePoint.mulPublic(scalar, .little);
            const affine = point.affineCoordinates();
            const entry = 8 * block + (multiple - 1);
            scalarmul[entry][0..4].* = affine.x.limbs;
            scalarmul[entry][4..8].* = affine.y.limbs;
        }
    }
    // The kernel's loop covers blocksize * block <= 256, so the 65th block
    // holds 2^256 * multiple * P. Its scalar digits are always zero, but the
    // table entries are still read by the constant-time scan.
    var base256 = P256.basePoint;
    for (0..256) |_| base256 = base256.dbl();
    for (1..9) |multiple| {
        var scalar = [_]u8{0} ** 32;
        scalar[0] = @intCast(multiple);
        const point = try base256.mulPublic(scalar, .little);
        const affine = point.affineCoordinates();
        const entry = 512 + (multiple - 1);
        scalarmul[entry][0..4].* = affine.x.limbs;
        scalarmul[entry][4..8].* = affine.y.limbs;
    }
    var ecdh: [ecdh_entries][8]u64 = undefined;
    var block_point = P256.basePoint;
    for (0..ecdh_blocks) |block| {
        for (0..ecdh_entries_per_block) |entry| {
            var scalar = [_]u8{0} ** 32;
            scalar[0] = @intCast(entry + 1);
            const point = try block_point.mulPublic(scalar, .little);
            const affine = point.affineCoordinates();
            const index = block * ecdh_entries_per_block + entry;
            ecdh[index][0..4].* = affine.x.limbs;
            ecdh[index][4..8].* = affine.y.limbs;
        }
        if (block + 1 != ecdh_blocks) {
            for (0..ecdh_block_size) |_| block_point = block_point.dbl();
        }
    }

    const file = try std.Io.Dir.cwd().createFile(
        init.io,
        "src/crypto/ec/p256_tables.zig",
        .{},
    );
    defer file.close(init.io);
    var buffer: [16 * 1024]u8 = undefined;
    var file_writer = file.writer(init.io, &buffer);
    const writer = &file_writer.interface;
    try writer.writeAll(
        "//! Generated by `tools/generate_p256_tables.zig`; do not edit.\n\n" ++
            "pub const base_wnaf_10: [2][256][4]u64 = .{\n",
    );
    for (coordinates) |coordinate| {
        try writer.writeAll("    .{\n");
        for (coordinate) |limbs| {
            try writer.writeAll("        .{\n");
            for (limbs) |limb| try writer.print("            {d},\n", .{limb});
            try writer.writeAll("        },\n");
        }
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("};\n");
    try writer.writeByte('\n');
    try writer.writeAll("pub const base_comb_4x8: [4][2][256][4]u64 = .{\n");
    for (comb) |group| {
        try writer.writeAll("    .{\n");
        for (group) |coordinate| {
            try writer.writeAll("        .{\n");
            for (coordinate) |limbs| {
                try writer.writeAll("            .{\n");
                for (limbs) |limb| {
                    try writer.print("                {d},\n", .{limb});
                }
                try writer.writeAll("            },\n");
            }
            try writer.writeAll("        },\n");
        }
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("};\n");
    try writer.writeByte('\n');
    try writer.writeAll("pub const base_comb_4x6: [4][2][4][64]u64 = .{\n");
    for (secret_comb) |group| {
        try writer.writeAll("    .{\n");
        for (group) |coordinate| {
            try writer.writeAll("        .{\n");
            for (coordinate) |entries| {
                try writer.writeAll("            .{");
                for (entries) |value| try writer.print(" {d},", .{value});
                try writer.writeAll(" },\n");
            }
            try writer.writeAll("        },\n");
        }
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("};\n");
    try writer.writeByte('\n');
    try writer.writeAll("pub const base_scalarmul_4: [520][8]u64 = .{\n");
    for (scalarmul) |entry| {
        try writer.writeAll("    .{\n");
        for (entry) |limb| try writer.print("        {d},\n", .{limb});
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("};\n");
    try writer.writeByte('\n');
    try writer.writeAll(
        "pub const base_ecdh_block6: [1376][8]u64 align(64) = .{\n",
    );
    for (ecdh) |entry| {
        try writer.writeAll("    .{\n");
        for (entry) |limb| try writer.print("        {d},\n", .{limb});
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("};\n");
    try writer.flush();
}
