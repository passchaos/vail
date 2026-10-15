const std = @import("std");
const target = @import("pkware_strong.zig");

const block_len = target.block_len;
const max_key_len = target.max_key_len;
const Strength = target.Strength;
const Key = target.Key;
const CbcEncryptor = target.CbcEncryptor;
const CbcDecryptor = target.CbcDecryptor;
const derivePasswordKey = target.derivePasswordKey;
const deriveFileKey = target.deriveFileKey;
const encryptAlloc = target.encryptAlloc;
const decryptAlloc = target.decryptAlloc;

test "PKWARE key derivation matches independent SHA-1 vectors" {
    const expected_master = [_]u8{
        0x60, 0xcc, 0xb8, 0xe9, 0x5d, 0x09, 0x8f, 0xd8,
        0xdf, 0xd1, 0xa5, 0x23, 0x4d, 0x45, 0xbc, 0x93,
        0xb3, 0xd7, 0xc1, 0xe2, 0x9b, 0xcc, 0x6d, 0x41,
        0xd2, 0x2e, 0xf1, 0x4c, 0x42, 0x36, 0x73, 0x2f,
    };
    var master = derivePasswordKey("PKWARE strong password", .aes256);
    defer master.deinit();
    try std.testing.expectEqualSlices(u8, &expected_master, master.bytes());

    const iv = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const random_data = [_]u8{
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    const expected_file = [_]u8{
        0x7a, 0x7d, 0xb0, 0xb1, 0xbe, 0xae, 0x83, 0xa7,
        0xdc, 0xb3, 0xea, 0x99, 0x2c, 0x8e, 0x90, 0x6a,
        0xb7, 0xf1, 0xb4, 0xe5, 0xb2, 0x95, 0x3c, 0x13,
        0x69, 0x2c, 0xbe, 0x8b, 0xfe, 0x98, 0xaf, 0xdc,
    };
    var file = deriveFileKey(&iv, &random_data, .aes256);
    defer file.deinit();
    try std.testing.expectEqualSlices(u8, &expected_file, file.bytes());
}

test "PKWARE AES-CBC matches NIST vectors at every strength" {
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plaintext = [_]u8{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    const vectors = [_]struct {
        strength: Strength,
        key: []const u8,
        ciphertext: [block_len]u8,
    }{
        .{
            .strength = .aes128,
            .key = &.{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
            .ciphertext = .{ 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d },
        },
        .{
            .strength = .aes192,
            .key = &.{ 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b },
            .ciphertext = .{ 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8 },
        },
        .{
            .strength = .aes256,
            .key = &.{ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 },
            .ciphertext = .{ 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6 },
        },
    };

    for (vectors) |vector| {
        var material: [max_key_len]u8 = @splat(0);
        @memcpy(material[0..vector.key.len], vector.key);
        var key = Key{ .material = material, .strength = vector.strength };
        defer key.deinit();
        var encrypted: [block_len]u8 = undefined;
        var encryptor = CbcEncryptor.init(&key, iv);
        defer encryptor.deinit();
        try encryptor.encryptBlocks(&plaintext, &encrypted);
        try std.testing.expectEqualSlices(u8, &vector.ciphertext, &encrypted);

        var decrypted: [block_len]u8 = undefined;
        var decryptor = CbcDecryptor.init(&key, iv);
        defer decryptor.deinit();
        try decryptor.decryptBlocks(&encrypted, &decrypted);
        try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
    }
}

test "PKWARE Strong one-shot protocol round trips every AES strength" {
    const allocator = std.testing.allocator;
    const iv = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const random_data = [_]u8{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
    const validation_data = [_]u8{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b };
    const data = "compressed payload whose length is not block aligned";

    inline for (std.meta.tags(Strength)) |strength| {
        var encrypted = try encryptAlloc(allocator, data, .{
            .password = "correct password",
            .strength = strength,
            .cbc_iv = iv,
            .iv_material = &iv,
            .random_data = &random_data,
            .validation_data = &validation_data,
        });
        defer encrypted.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 32), encrypted.encrypted_random_data.len);
        try std.testing.expectEqual(@as(usize, 16), encrypted.validation_size);

        const decrypted = try decryptAlloc(
            allocator,
            encrypted.encrypted_random_data,
            encrypted.encrypted_payload,
            .{
                .password = "correct password",
                .strength = strength,
                .cbc_iv = iv,
                .iv_material = &iv,
                .validation_size = encrypted.validation_size,
            },
        );
        defer allocator.free(decrypted);
        try std.testing.expectEqualSlices(u8, data, decrypted);
        try std.testing.expectError(
            error.InvalidPasswordValidation,
            decryptAlloc(
                allocator,
                encrypted.encrypted_random_data,
                encrypted.encrypted_payload,
                .{
                    .password = "wrong password",
                    .strength = strength,
                    .cbc_iv = iv,
                    .iv_material = &iv,
                    .validation_size = encrypted.validation_size,
                },
            ),
        );
    }
}

test "PKWARE Strong protocol matches OpenSSL AES-CBC fixture" {
    const allocator = std.testing.allocator;
    const iv = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const random_data = [_]u8{
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    const validation_data = [_]u8{
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    };
    var encrypted = try encryptAlloc(allocator, "PKWARE payload", .{
        .password = "PKWARE strong password",
        .cbc_iv = iv,
        .iv_material = &iv,
        .random_data = &random_data,
        .validation_data = &validation_data,
    });
    defer encrypted.deinit(allocator);
    var expected_random_data: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_random_data,
        "251333c926048e1683c7f3abf4660bb2d7f6218d32d739ba3f9b54ed3b93d836",
    );
    var expected_payload: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_payload,
        "a00895855a91a53e799c9cf8d8fd2d83728f78957052d5b496506f0b6ddebea3",
    );
    try std.testing.expectEqualSlices(u8, &expected_random_data, encrypted.encrypted_random_data);
    try std.testing.expectEqualSlices(u8, &expected_payload, encrypted.encrypted_payload);
}

test "PKWARE Strong rejects corrupted validation and padding" {
    const allocator = std.testing.allocator;
    const iv: [block_len]u8 = @splat(0x11);
    const random_data: [block_len]u8 = @splat(0x22);
    const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x33);
    var encrypted = try encryptAlloc(allocator, "payload", .{
        .password = "password",
        .cbc_iv = iv,
        .iv_material = &iv,
        .random_data = &random_data,
        .validation_data = &validation_data,
    });
    defer encrypted.deinit(allocator);

    encrypted.encrypted_payload[0] ^= 1;
    try std.testing.expectError(
        error.InvalidPasswordValidation,
        decryptAlloc(allocator, encrypted.encrypted_random_data, encrypted.encrypted_payload, .{
            .password = "password",
            .strength = .aes256,
            .cbc_iv = iv,
            .iv_material = &iv,
            .validation_size = encrypted.validation_size,
        }),
    );
    encrypted.encrypted_payload[0] ^= 1;
    encrypted.encrypted_payload[encrypted.encrypted_payload.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidPadding,
        decryptAlloc(allocator, encrypted.encrypted_random_data, encrypted.encrypted_payload, .{
            .password = "password",
            .strength = .aes256,
            .cbc_iv = iv,
            .iv_material = &iv,
            .validation_size = encrypted.validation_size,
        }),
    );
}

test "PKWARE Strong enforces interoperable entropy and validation sizes" {
    const allocator = std.testing.allocator;
    const iv: [block_len]u8 = @splat(0);
    try std.testing.expectError(
        error.InvalidRandomDataLength,
        encryptAlloc(allocator, "payload", .{
            .password = "password",
            .cbc_iv = iv,
            .iv_material = &iv,
            .random_data = "short",
            .validation_data = "123456789012",
        }),
    );
    try std.testing.expectError(
        error.InvalidValidationDataLength,
        encryptAlloc(allocator, "payload", .{
            .password = "password",
            .cbc_iv = iv,
            .iv_material = &iv,
            .random_data = &iv,
            .validation_data = "short",
        }),
    );
}

test "PKWARE Strong releases every allocation failure" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const iv: [block_len]u8 = @splat(0x11);
            const random_data: [block_len]u8 = @splat(0x22);
            const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x33);
            var encrypted = try encryptAlloc(allocator, "allocation-safe payload", .{
                .password = "allocation-safe password",
                .cbc_iv = iv,
                .iv_material = &iv,
                .random_data = &random_data,
                .validation_data = &validation_data,
            });
            defer encrypted.deinit(allocator);
            const decrypted = try decryptAlloc(
                allocator,
                encrypted.encrypted_random_data,
                encrypted.encrypted_payload,
                .{
                    .password = "allocation-safe password",
                    .strength = .aes256,
                    .cbc_iv = iv,
                    .iv_material = &iv,
                    .validation_size = encrypted.validation_size,
                },
            );
            defer allocator.free(decrypted);
            try std.testing.expectEqualSlices(u8, "allocation-safe payload", decrypted);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}
