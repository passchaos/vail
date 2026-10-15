//! Bounded streaming decryption for PKWARE Strong Encryption file payloads.
//!
//! Preparation validates the password before returning a data decryptor. The
//! decryptor retains the final plaintext block until `finish` verifies PKCS#7,
//! so padding bytes are never exposed as compressed payload.

const std = @import("std");
const protocol = @import("pkware_strong.zig");

pub const block_len = protocol.block_len;
pub const Strength = protocol.Strength;

pub const Error = protocol.Error || error{
    InvalidStreamState,
    TrailingData,
};

pub const Status = enum {
    need_input,
    need_output,
    done,
};

pub const StepResult = struct {
    input_read: usize = 0,
    output_written: usize = 0,
    status: Status,
};

pub const PrepareOptions = struct {
    password: []const u8,
    strength: Strength,
    cbc_iv: [block_len]u8,
    iv_material: []const u8,
};

pub const Decryptor = struct {
    cipher: protocol.CbcDecryptor,
    ciphertext: [block_len]u8 = undefined,
    ciphertext_len: usize = 0,
    plaintext: [block_len]u8 = undefined,
    plaintext_pos: usize = 0,
    plaintext_len: usize = 0,
    plaintext_releasable: bool = false,
    finish_requested: bool = false,
    final_plaintext: bool = false,
    done: bool = false,

    const Self = @This();

    fn init(cipher: protocol.CbcDecryptor) Self {
        return .{ .cipher = cipher };
    }

    /// Accepts complete or fragmented ciphertext blocks. The final plaintext
    /// block remains withheld until `finish` validates its padding.
    pub fn update(self: *Self, input: []const u8, output: []u8) Error!StepResult {
        if (self.done or self.finish_requested) {
            if (input.len != 0) return error.TrailingData;
            return .{ .status = if (self.done) .done else .need_output };
        }
        return self.step(input, output);
    }

    /// Declares ciphertext EOF. Repeat until `.done`; a partial final block or
    /// invalid PKCS#7 suffix fails without exposing that final block.
    pub fn finish(self: *Self, output: []u8) Error!StepResult {
        if (self.done) return .{ .status = .done };
        self.finish_requested = true;
        return self.step("", output);
    }

    pub fn deinit(self: *Self) void {
        self.cipher.deinit();
        std.crypto.secureZero(u8, &self.ciphertext);
        std.crypto.secureZero(u8, &self.plaintext);
        self.* = undefined;
    }

    fn step(self: *Self, input: []const u8, output: []u8) Error!StepResult {
        var input_read: usize = 0;
        var output_written: usize = 0;
        while (true) {
            if (self.plaintext_releasable) {
                const take = @min(
                    self.plaintext_len - self.plaintext_pos,
                    output.len - output_written,
                );
                @memcpy(
                    output[output_written..][0..take],
                    self.plaintext[self.plaintext_pos..][0..take],
                );
                self.plaintext_pos += take;
                output_written += take;
                if (self.plaintext_pos != self.plaintext_len)
                    return result(input_read, output_written, .need_output);
                std.crypto.secureZero(u8, &self.plaintext);
                self.plaintext_pos = 0;
                self.plaintext_len = 0;
                self.plaintext_releasable = false;
                if (self.final_plaintext) {
                    self.done = true;
                    return result(input_read, output_written, .done);
                }
                continue;
            }

            if (self.ciphertext_len == block_len) {
                if (self.plaintext_len != 0) {
                    self.plaintext_releasable = true;
                    continue;
                }
                try self.cipher.decryptBlocks(&self.ciphertext, &self.plaintext);
                std.crypto.secureZero(u8, &self.ciphertext);
                self.ciphertext_len = 0;
                self.plaintext_len = block_len;
                continue;
            }

            if (input_read < input.len) {
                const take = @min(
                    block_len - self.ciphertext_len,
                    input.len - input_read,
                );
                @memcpy(
                    self.ciphertext[self.ciphertext_len..][0..take],
                    input[input_read..][0..take],
                );
                self.ciphertext_len += take;
                input_read += take;
                continue;
            }

            if (self.finish_requested) {
                if (self.ciphertext_len != 0) return error.InvalidBlockLength;
                if (self.plaintext_len != block_len) return error.InvalidPadding;
                self.plaintext_len = try unpaddedLength(&self.plaintext);
                self.plaintext_pos = 0;
                self.plaintext_releasable = true;
                self.final_plaintext = true;
                if (self.plaintext_len == 0) {
                    std.crypto.secureZero(u8, &self.plaintext);
                    self.plaintext_releasable = false;
                    self.done = true;
                    return result(input_read, output_written, .done);
                }
                continue;
            }

            return result(input_read, output_written, .need_input);
        }
    }

    fn result(input_read: usize, output_written: usize, status: Status) StepResult {
        return .{
            .input_read = input_read,
            .output_written = output_written,
            .status = status,
        };
    }
};

pub fn prepareDecryptAlloc(
    allocator: std.mem.Allocator,
    encrypted_random_data: []const u8,
    encrypted_validation: []const u8,
    options: PrepareOptions,
) Error!Decryptor {
    if (options.iv_material.len == 0 or options.iv_material.len > block_len)
        return error.InvalidIvLength;
    if (encrypted_random_data.len < block_len or encrypted_random_data.len % block_len != 0)
        return error.InvalidEncryptedRandomData;
    if (encrypted_validation.len <= @sizeOf(u32) or
        encrypted_validation.len % block_len != 0)
        return error.InvalidValidationDataLength;

    var master_key = protocol.derivePasswordKey(options.password, options.strength);
    defer master_key.deinit();
    const padded_random = try allocator.alloc(u8, encrypted_random_data.len);
    defer {
        std.crypto.secureZero(u8, padded_random);
        allocator.free(padded_random);
    }
    var random_cipher = protocol.CbcDecryptor.init(&master_key, options.cbc_iv);
    defer random_cipher.deinit();
    try random_cipher.decryptBlocks(encrypted_random_data, padded_random);
    const random_len = unpaddedLength(padded_random) catch |err| switch (err) {
        error.InvalidPadding => return error.InvalidPasswordValidation,
        else => return err,
    };

    var file_key = protocol.deriveFileKey(
        options.iv_material,
        padded_random[0..random_len],
        options.strength,
    );
    defer file_key.deinit();
    const validation_plain = try allocator.alloc(u8, encrypted_validation.len);
    defer {
        std.crypto.secureZero(u8, validation_plain);
        allocator.free(validation_plain);
    }
    var data_cipher = protocol.CbcDecryptor.init(&file_key, options.cbc_iv);
    errdefer data_cipher.deinit();
    try data_cipher.decryptBlocks(encrypted_validation, validation_plain);
    const validation_data = validation_plain[0 .. validation_plain.len - @sizeOf(u32)];
    const expected_crc = validation_plain[validation_data.len..][0..@sizeOf(u32)].*;
    var actual_crc: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &actual_crc, std.hash.Crc32.hash(validation_data), .little);
    if (!std.crypto.timing_safe.eql([@sizeOf(u32)]u8, actual_crc, expected_crc))
        return error.InvalidPasswordValidation;
    return Decryptor.init(data_cipher);
}

fn unpaddedLength(input: []const u8) Error!usize {
    if (input.len == 0 or input.len % block_len != 0) return error.InvalidPadding;
    const padding_len = input[input.len - 1];
    if (padding_len == 0 or padding_len > block_len) return error.InvalidPadding;
    var difference: u8 = 0;
    for (input[input.len - block_len ..], 0..) |byte, index| {
        const distance_from_end = block_len - index;
        if (distance_from_end <= padding_len)
            difference |= byte ^ padding_len;
    }
    if (difference != 0) return error.InvalidPadding;
    return input.len - padding_len;
}

test "PKWARE Strong streaming decryption matches one-shot across tiny schedules" {
    const allocator = std.testing.allocator;
    const iv: [block_len]u8 = @splat(0x11);
    const random_data: [block_len]u8 = @splat(0x22);
    const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x33);
    const payload = "fragmented PKWARE Strong encrypted payload";
    var encrypted = try protocol.encryptAlloc(allocator, payload, .{
        .password = "stream password",
        .strength = .aes192,
        .cbc_iv = iv,
        .iv_material = &iv,
        .random_data = &random_data,
        .validation_data = &validation_data,
    });
    defer encrypted.deinit(allocator);
    var decryptor = try prepareDecryptAlloc(
        allocator,
        encrypted.encrypted_random_data,
        encrypted.encrypted_payload[0..encrypted.validation_size],
        .{
            .password = "stream password",
            .strength = .aes192,
            .cbc_iv = iv,
            .iv_material = &iv,
        },
    );
    defer decryptor.deinit();
    const ciphertext = encrypted.encrypted_payload[encrypted.validation_size..];
    var actual: std.ArrayList(u8) = .empty;
    defer actual.deinit(allocator);
    var input_offset: usize = 0;
    var output_buffer: [3]u8 = undefined;
    while (input_offset < ciphertext.len) {
        const input_end = @min(ciphertext.len, input_offset + 2);
        const step = try decryptor.update(
            ciphertext[input_offset..input_end],
            &output_buffer,
        );
        input_offset += step.input_read;
        try actual.appendSlice(allocator, output_buffer[0..step.output_written]);
    }
    while (true) {
        const step = try decryptor.finish(&output_buffer);
        try actual.appendSlice(allocator, output_buffer[0..step.output_written]);
        if (step.status == .done) break;
        try std.testing.expectEqual(Status.need_output, step.status);
    }
    try std.testing.expectEqualSlices(u8, payload, actual.items);
}

test "PKWARE Strong streaming decryption rejects password padding and truncation" {
    const allocator = std.testing.allocator;
    const iv: [block_len]u8 = @splat(0x44);
    const random_data: [block_len]u8 = @splat(0x55);
    const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x66);
    var encrypted = try protocol.encryptAlloc(allocator, "payload", .{
        .password = "correct",
        .cbc_iv = iv,
        .iv_material = &iv,
        .random_data = &random_data,
        .validation_data = &validation_data,
    });
    defer encrypted.deinit(allocator);
    try std.testing.expectError(
        error.InvalidPasswordValidation,
        prepareDecryptAlloc(
            allocator,
            encrypted.encrypted_random_data,
            encrypted.encrypted_payload[0..encrypted.validation_size],
            .{
                .password = "wrong",
                .strength = .aes256,
                .cbc_iv = iv,
                .iv_material = &iv,
            },
        ),
    );

    var decryptor = try prepareDecryptAlloc(
        allocator,
        encrypted.encrypted_random_data,
        encrypted.encrypted_payload[0..encrypted.validation_size],
        .{
            .password = "correct",
            .strength = .aes256,
            .cbc_iv = iv,
            .iv_material = &iv,
        },
    );
    defer decryptor.deinit();
    const ciphertext = encrypted.encrypted_payload[encrypted.validation_size..];
    var output: [64]u8 = undefined;
    _ = try decryptor.update(ciphertext[0 .. ciphertext.len - 1], &output);
    try std.testing.expectError(error.InvalidBlockLength, decryptor.finish(&output));

    const corrupt = try allocator.dupe(u8, ciphertext);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    var padding_decryptor = try prepareDecryptAlloc(
        allocator,
        encrypted.encrypted_random_data,
        encrypted.encrypted_payload[0..encrypted.validation_size],
        .{
            .password = "correct",
            .strength = .aes256,
            .cbc_iv = iv,
            .iv_material = &iv,
        },
    );
    defer padding_decryptor.deinit();
    _ = try padding_decryptor.update(corrupt, &output);
    try std.testing.expectError(error.InvalidPadding, padding_decryptor.finish(&output));
}

test "PKWARE Strong streaming decryption preparation releases allocation failures" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const iv: [block_len]u8 = @splat(0x77);
            const random_data: [block_len]u8 = @splat(0x88);
            const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x99);
            var encrypted = try protocol.encryptAlloc(allocator, "payload", .{
                .password = "password",
                .cbc_iv = iv,
                .iv_material = &iv,
                .random_data = &random_data,
                .validation_data = &validation_data,
            });
            defer encrypted.deinit(allocator);
            var decryptor = try prepareDecryptAlloc(
                allocator,
                encrypted.encrypted_random_data,
                encrypted.encrypted_payload[0..encrypted.validation_size],
                .{
                    .password = "password",
                    .strength = .aes256,
                    .cbc_iv = iv,
                    .iv_material = &iv,
                },
            );
            defer decryptor.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}
