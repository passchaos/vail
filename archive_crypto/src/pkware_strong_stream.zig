//! Bounded streaming encryption for PKWARE Strong Encryption file payloads.
//!
//! Header preparation encrypts random and password-validation data through the
//! one-shot protocol primitives, then transfers the advanced CBC state into an
//! encryptor that retains at most one plaintext and one ciphertext block.

const std = @import("std");
const protocol = @import("pkware_strong.zig");

pub const block_len = protocol.block_len;
pub const Strength = protocol.Strength;
pub const PrepareOptions = protocol.EncryptOptions;

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

pub const Encryptor = struct {
    cipher: protocol.CbcEncryptor,
    plaintext: [block_len]u8 = undefined,
    plaintext_len: usize = 0,
    ciphertext: [block_len]u8 = undefined,
    ciphertext_pos: usize = block_len,
    finish_requested: bool = false,
    final_ciphertext: bool = false,
    done: bool = false,

    const Self = @This();

    fn init(cipher: protocol.CbcEncryptor) Self {
        return .{ .cipher = cipher };
    }

    /// Accepts compressed plaintext and emits complete CBC blocks. Input may
    /// be partially consumed when caller output cannot drain a queued block.
    pub fn update(self: *Self, input: []const u8, output: []u8) Error!StepResult {
        if (self.done or self.finish_requested) {
            if (input.len != 0) return error.TrailingData;
            return .{ .status = if (self.done) .done else .need_output };
        }
        return self.step(input, output);
    }

    /// Requests the final PKCS#7 block. Call only after all `update` input has
    /// been consumed, then repeat until `.done` is returned.
    pub fn finish(self: *Self, output: []u8) Error!StepResult {
        if (self.done) return .{ .status = .done };
        self.finish_requested = true;
        return self.step("", output);
    }

    pub fn deinit(self: *Self) void {
        self.cipher.deinit();
        std.crypto.secureZero(u8, &self.plaintext);
        std.crypto.secureZero(u8, &self.ciphertext);
        self.* = undefined;
    }

    fn step(self: *Self, input: []const u8, output: []u8) Error!StepResult {
        var input_read: usize = 0;
        var output_written: usize = 0;
        while (true) {
            if (self.ciphertext_pos < block_len) {
                const take = @min(
                    block_len - self.ciphertext_pos,
                    output.len - output_written,
                );
                @memcpy(
                    output[output_written..][0..take],
                    self.ciphertext[self.ciphertext_pos..][0..take],
                );
                self.ciphertext_pos += take;
                output_written += take;
                if (self.ciphertext_pos != block_len)
                    return result(input_read, output_written, .need_output);
                if (self.final_ciphertext) {
                    self.done = true;
                    return result(input_read, output_written, .done);
                }
                continue;
            }

            if (self.plaintext_len == block_len) {
                try self.encryptPendingBlock(false);
                continue;
            }

            if (input_read < input.len) {
                const take = @min(
                    block_len - self.plaintext_len,
                    input.len - input_read,
                );
                @memcpy(
                    self.plaintext[self.plaintext_len..][0..take],
                    input[input_read..][0..take],
                );
                self.plaintext_len += take;
                input_read += take;
                continue;
            }

            if (self.finish_requested) {
                const padding_len: u8 = @intCast(block_len - self.plaintext_len);
                @memset(self.plaintext[self.plaintext_len..], padding_len);
                self.plaintext_len = block_len;
                try self.encryptPendingBlock(true);
                continue;
            }

            return result(input_read, output_written, .need_input);
        }
    }

    fn encryptPendingBlock(self: *Self, final: bool) Error!void {
        std.debug.assert(self.plaintext_len == block_len);
        std.debug.assert(self.ciphertext_pos == block_len);
        try self.cipher.encryptBlocks(&self.plaintext, &self.ciphertext);
        std.crypto.secureZero(u8, &self.plaintext);
        self.plaintext_len = 0;
        self.ciphertext_pos = 0;
        self.final_ciphertext = final;
    }

    fn result(input_read: usize, output_written: usize, status: Status) StepResult {
        return .{
            .input_read = input_read,
            .output_written = output_written,
            .status = status,
        };
    }
};

pub const PreparedEncryptor = struct {
    encrypted_random_data: []u8,
    encrypted_validation: []u8,
    encryptor: Encryptor,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.encrypted_random_data);
        allocator.free(self.encrypted_validation);
        self.encryptor.deinit();
        self.* = undefined;
    }

    /// Frees prepared header ciphertext and transfers the live data cipher.
    pub fn takeEncryptor(self: *Self, allocator: std.mem.Allocator) Encryptor {
        allocator.free(self.encrypted_random_data);
        allocator.free(self.encrypted_validation);
        const encryptor = self.encryptor;
        self.* = undefined;
        return encryptor;
    }
};

pub fn prepareEncryptAlloc(
    allocator: std.mem.Allocator,
    options: PrepareOptions,
) Error!PreparedEncryptor {
    if (options.iv_material.len == 0 or options.iv_material.len > block_len)
        return error.InvalidIvLength;
    if (options.random_data.len == 0 or options.random_data.len % block_len != 0)
        return error.InvalidRandomDataLength;
    const validation_size = std.math.add(usize, options.validation_data.len, @sizeOf(u32)) catch
        return error.IntegerOverflow;
    if (options.validation_data.len == 0 or validation_size % block_len != 0)
        return error.InvalidValidationDataLength;

    var master_key = protocol.derivePasswordKey(options.password, options.strength);
    defer master_key.deinit();
    const random_plain_len = std.math.add(usize, options.random_data.len, block_len) catch
        return error.IntegerOverflow;
    const random_plain = try allocator.alloc(u8, random_plain_len);
    defer {
        std.crypto.secureZero(u8, random_plain);
        allocator.free(random_plain);
    }
    @memcpy(random_plain[0..options.random_data.len], options.random_data);
    @memset(random_plain[options.random_data.len..], block_len);
    const encrypted_random_data = try allocator.alloc(u8, random_plain_len);
    errdefer allocator.free(encrypted_random_data);
    var random_cipher = protocol.CbcEncryptor.init(&master_key, options.cbc_iv);
    defer random_cipher.deinit();
    try random_cipher.encryptBlocks(random_plain, encrypted_random_data);

    const validation_plain = try allocator.alloc(u8, validation_size);
    defer {
        std.crypto.secureZero(u8, validation_plain);
        allocator.free(validation_plain);
    }
    @memcpy(validation_plain[0..options.validation_data.len], options.validation_data);
    std.mem.writeInt(
        u32,
        validation_plain[options.validation_data.len..][0..@sizeOf(u32)],
        std.hash.Crc32.hash(options.validation_data),
        .little,
    );
    const encrypted_validation = try allocator.alloc(u8, validation_size);
    errdefer allocator.free(encrypted_validation);
    var file_key = protocol.deriveFileKey(
        options.iv_material,
        options.random_data,
        options.strength,
    );
    defer file_key.deinit();
    var data_cipher = protocol.CbcEncryptor.init(&file_key, options.cbc_iv);
    errdefer data_cipher.deinit();
    try data_cipher.encryptBlocks(validation_plain, encrypted_validation);

    return .{
        .encrypted_random_data = encrypted_random_data,
        .encrypted_validation = encrypted_validation,
        .encryptor = Encryptor.init(data_cipher),
    };
}

test "PKWARE Strong streaming encryption matches one-shot across tiny schedules" {
    const allocator = std.testing.allocator;
    const iv: [block_len]u8 = @splat(0x11);
    const random_data: [block_len]u8 = @splat(0x22);
    const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x33);
    const payload = "fragmented PKWARE Strong compressed payload";
    const options: PrepareOptions = .{
        .password = "stream password",
        .strength = .aes192,
        .cbc_iv = iv,
        .iv_material = &iv,
        .random_data = &random_data,
        .validation_data = &validation_data,
    };
    var expected = try protocol.encryptAlloc(allocator, payload, options);
    defer expected.deinit(allocator);

    var prepared = try prepareEncryptAlloc(allocator, options);
    try std.testing.expectEqualSlices(
        u8,
        expected.encrypted_random_data,
        prepared.encrypted_random_data,
    );
    try std.testing.expectEqualSlices(
        u8,
        expected.encrypted_payload[0..expected.validation_size],
        prepared.encrypted_validation,
    );
    var encryptor = prepared.takeEncryptor(allocator);
    defer encryptor.deinit();
    var actual: std.ArrayList(u8) = .empty;
    defer actual.deinit(allocator);
    var input_offset: usize = 0;
    var output_buffer: [3]u8 = undefined;
    while (input_offset < payload.len) {
        const input_end = @min(payload.len, input_offset + 2);
        const step = try encryptor.update(
            payload[input_offset..input_end],
            &output_buffer,
        );
        input_offset += step.input_read;
        try actual.appendSlice(allocator, output_buffer[0..step.output_written]);
    }
    while (true) {
        const step = try encryptor.finish(&output_buffer);
        try actual.appendSlice(allocator, output_buffer[0..step.output_written]);
        if (step.status == .done) break;
        try std.testing.expectEqual(Status.need_output, step.status);
    }
    try std.testing.expectEqualSlices(
        u8,
        expected.encrypted_payload[expected.validation_size..],
        actual.items,
    );
}

test "PKWARE Strong streaming encryption handles empty and aligned payloads" {
    const allocator = std.testing.allocator;
    const iv: [block_len]u8 = @splat(0x44);
    const random_data: [block_len]u8 = @splat(0x55);
    const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x66);
    inline for (.{ "", "0123456789abcdef" }) |payload| {
        const options: PrepareOptions = .{
            .password = "stream password",
            .cbc_iv = iv,
            .iv_material = &iv,
            .random_data = &random_data,
            .validation_data = &validation_data,
        };
        var expected = try protocol.encryptAlloc(allocator, payload, options);
        defer expected.deinit(allocator);
        var prepared = try prepareEncryptAlloc(allocator, options);
        var encryptor = prepared.takeEncryptor(allocator);
        defer encryptor.deinit();
        var output: [2 * block_len]u8 = undefined;
        const update = try encryptor.update(payload, &output);
        const finish = try encryptor.finish(output[update.output_written..]);
        try std.testing.expectEqual(Status.done, finish.status);
        try std.testing.expectEqualSlices(
            u8,
            expected.encrypted_payload[expected.validation_size..],
            output[0 .. update.output_written + finish.output_written],
        );
    }
}

test "PKWARE Strong streaming preparation releases every allocation failure" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const iv: [block_len]u8 = @splat(0x77);
            const random_data: [block_len]u8 = @splat(0x88);
            const validation_data: [block_len - @sizeOf(u32)]u8 = @splat(0x99);
            var prepared = try prepareEncryptAlloc(allocator, .{
                .password = "allocation password",
                .cbc_iv = iv,
                .iv_material = &iv,
                .random_data = &random_data,
                .validation_data = &validation_data,
            });
            defer prepared.deinit(allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}
