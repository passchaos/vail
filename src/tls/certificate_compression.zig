//! RFC 8879 TLS 1.3 certificate compression.
//!
//! Zlib is provided by Zig's standard library; Brotli and Zstandard use the
//! sibling pure-Zig Vort package. Servers prepare compressed certificate bodies
//! once and reuse the immutable result across handshakes. Clients enforce the
//! advertised algorithm and an explicit uncompressed-size limit before
//! allocating or decompressing.

const std = @import("std");
const vort = @import("vort");

pub const handshake_type_compressed_certificate: u8 = 0x19;
pub const extension_type_compress_certificate: u16 = 0x001b;

pub const Algorithm = enum(u16) {
    zlib = 1,
    brotli = 2,
    zstd = 3,
    _,

    pub fn supported(self: Algorithm) bool {
        return self == .zlib or self == .brotli or self == .zstd;
    }
};

pub const CompressionLevel = enum {
    interactive,
    amortized,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidCertificateMessage,
    CertificateTooLarge,
    CompressionFailed,
    InvalidCompressedCertificate,
    UnsupportedCompressionAlgorithm,
    SelectedUnofferedCompressionAlgorithm,
};

pub const PreparedView = struct {
    algorithm: Algorithm,
    uncompressed_length: u24,
    uncompressed_sha256: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    compressed: []const u8,

    pub fn matchesCertificateMessage(
        self: PreparedView,
        certificate_message: []const u8,
    ) bool {
        const body = certificateBody(certificate_message) catch return false;
        if (body.len != self.uncompressed_length) return false;
        var actual: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(body, &actual, .{});
        return std.crypto.timing_safe.eql(
            [std.crypto.hash.sha2.Sha256.digest_length]u8,
            actual,
            self.uncompressed_sha256,
        );
    }

    pub fn savesBytes(
        self: PreparedView,
        certificate_message_len: usize,
    ) bool {
        return 12 + self.compressed.len < certificate_message_len;
    }

    pub fn write(
        self: PreparedView,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
    ) Error!void {
        if (!self.algorithm.supported() or self.compressed.len == 0 or
            self.compressed.len > std.math.maxInt(u24))
        {
            return error.InvalidCompressedCertificate;
        }
        const body_len = std.math.add(
            usize,
            2 + 3 + 3,
            self.compressed.len,
        ) catch return error.CertificateTooLarge;
        if (body_len > std.math.maxInt(u24)) {
            return error.CertificateTooLarge;
        }
        const original_len = out.items.len;
        errdefer out.items.len = original_len;
        try out.append(allocator, handshake_type_compressed_certificate);
        try appendU24(out, allocator, @intCast(body_len));
        try appendInt(out, allocator, u16, @intFromEnum(self.algorithm));
        try appendU24(out, allocator, self.uncompressed_length);
        try appendU24(out, allocator, @intCast(self.compressed.len));
        try out.appendSlice(allocator, self.compressed);
    }
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    algorithm: Algorithm,
    uncompressed_length: u24,
    uncompressed_sha256: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    compressed: []u8,

    pub fn initZlib(
        allocator: std.mem.Allocator,
        certificate_message: []const u8,
        level: CompressionLevel,
    ) Error!Prepared {
        const body = try certificateBody(certificate_message);
        const output_capacity = std.math.add(
            usize,
            body.len,
            body.len / 8 + 64,
        ) catch return error.CertificateTooLarge;
        var output = try allocator.alloc(u8, output_capacity);
        errdefer allocator.free(output);
        var output_writer: std.Io.Writer = .fixed(output);
        const work = try allocator.alloc(
            u8,
            std.compress.flate.max_window_len,
        );
        defer allocator.free(work);
        const compressor = try allocator.create(std.compress.flate.Compress);
        defer allocator.destroy(compressor);
        compressor.* = std.compress.flate.Compress.init(
            &output_writer,
            work,
            .zlib,
            switch (level) {
                .interactive => .fastest,
                .amortized => .best,
            },
        ) catch return error.CompressionFailed;
        compressor.writer.writeAll(body) catch
            return error.CompressionFailed;
        compressor.finish() catch return error.CompressionFailed;
        if (output_writer.end == 0 or
            output_writer.end > std.math.maxInt(u24))
        {
            return error.CompressionFailed;
        }
        output = try allocator.realloc(output, output_writer.end);
        var uncompressed_sha256: [
            std.crypto.hash.sha2.Sha256.digest_length
        ]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(body, &uncompressed_sha256, .{});
        return .{
            .allocator = allocator,
            .algorithm = .zlib,
            .uncompressed_length = @intCast(body.len),
            .uncompressed_sha256 = uncompressed_sha256,
            .compressed = output,
        };
    }

    pub fn initBrotli(
        allocator: std.mem.Allocator,
        certificate_message: []const u8,
        level: CompressionLevel,
    ) Error!Prepared {
        const body = try certificateBody(certificate_message);
        const output = vort.brEncodePlannedStreamWithOptionsAlloc(
            allocator,
            body,
            .{ .level = switch (level) {
                .interactive => .fast,
                .amortized => .ratio,
            } },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.CompressionFailed,
        };
        errdefer allocator.free(output);
        if (output.len == 0 or output.len > std.math.maxInt(u24)) {
            return error.CompressionFailed;
        }
        var uncompressed_sha256: [
            std.crypto.hash.sha2.Sha256.digest_length
        ]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(body, &uncompressed_sha256, .{});
        return .{
            .allocator = allocator,
            .algorithm = .brotli,
            .uncompressed_length = @intCast(body.len),
            .uncompressed_sha256 = uncompressed_sha256,
            .compressed = output,
        };
    }

    pub fn initZstd(
        allocator: std.mem.Allocator,
        certificate_message: []const u8,
        level: CompressionLevel,
    ) Error!Prepared {
        const body = try certificateBody(certificate_message);
        const output = vort.zstdEncodeFrameWithLevelAndOptionsAlloc(
            allocator,
            body,
            switch (level) {
                .interactive => 1,
                .amortized => 3,
            },
            .{
                .include_content_size = true,
                .content_checksum = true,
            },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.CompressionFailed,
        };
        errdefer allocator.free(output);
        if (output.len == 0 or output.len > std.math.maxInt(u24)) {
            return error.CompressionFailed;
        }
        var uncompressed_sha256: [
            std.crypto.hash.sha2.Sha256.digest_length
        ]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(body, &uncompressed_sha256, .{});
        return .{
            .allocator = allocator,
            .algorithm = .zstd,
            .uncompressed_length = @intCast(body.len),
            .uncompressed_sha256 = uncompressed_sha256,
            .compressed = output,
        };
    }

    pub fn view(self: *const Prepared) PreparedView {
        return .{
            .algorithm = self.algorithm,
            .uncompressed_length = self.uncompressed_length,
            .uncompressed_sha256 = self.uncompressed_sha256,
            .compressed = self.compressed,
        };
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.compressed);
        self.* = undefined;
    }
};

pub const Parsed = struct {
    algorithm: Algorithm,
    uncompressed_length: u24,
    compressed: []const u8,
};

pub fn parse(message: []const u8) Error!Parsed {
    if (message.len < 12 or
        message[0] != handshake_type_compressed_certificate)
    {
        return error.InvalidCompressedCertificate;
    }
    const body_len = readU24(message[1..4]);
    if (body_len != message.len - 4) {
        return error.InvalidCompressedCertificate;
    }
    const algorithm: Algorithm = @enumFromInt(std.mem.readInt(
        u16,
        message[4..6],
        .big,
    ));
    const uncompressed_length: u24 = @intCast(readU24(message[6..9]));
    const compressed_len = readU24(message[9..12]);
    if (compressed_len == 0 or compressed_len != message.len - 12) {
        return error.InvalidCompressedCertificate;
    }
    return .{
        .algorithm = algorithm,
        .uncompressed_length = uncompressed_length,
        .compressed = message[12..],
    };
}

/// Return an owned ordinary Certificate handshake message. The transcript must
/// contain the original CompressedCertificate message, not this reconstruction.
pub noinline fn decompressCertificate(
    allocator: std.mem.Allocator,
    message: []const u8,
    offered: []const Algorithm,
    max_uncompressed_length: usize,
) Error![]u8 {
    const parsed = try parse(message);
    var was_offered = false;
    for (offered) |algorithm| {
        if (algorithm == parsed.algorithm) was_offered = true;
    }
    if (!was_offered) return error.SelectedUnofferedCompressionAlgorithm;
    if (!parsed.algorithm.supported()) {
        return error.UnsupportedCompressionAlgorithm;
    }
    const uncompressed_length: usize = parsed.uncompressed_length;
    if (uncompressed_length == 0 or
        uncompressed_length > max_uncompressed_length)
    {
        return error.CertificateTooLarge;
    }
    const total_len = std.math.add(usize, 4, uncompressed_length) catch
        return error.CertificateTooLarge;
    var result = try allocator.alloc(u8, total_len);
    errdefer allocator.free(result);
    result[0] = 0x0b;
    result[1] = @truncate(uncompressed_length >> 16);
    result[2] = @truncate(uncompressed_length >> 8);
    result[3] = @truncate(uncompressed_length);

    if (parsed.algorithm == .zstd) {
        @branchHint(.unlikely);
        try decompressZstd(
            parsed.compressed,
            result[4..],
            uncompressed_length,
        );
        return result;
    }
    switch (parsed.algorithm) {
        .zlib => try decompressZlib(parsed.compressed, result[4..], allocator),
        .brotli => {
            const written = vort.brDecodeStreamIntoExactSize(
                parsed.compressed,
                result[4..],
                uncompressed_length,
            ) catch return error.InvalidCompressedCertificate;
            if (written != uncompressed_length) {
                return error.InvalidCompressedCertificate;
            }
        },
        else => unreachable,
    }
    return result;
}

noinline fn decompressZstd(
    compressed: []const u8,
    output: []u8,
    expected_length: usize,
) Error!void {
    const written = vort.zstdDecodeFrameIntoExactSize(
        compressed,
        output,
        expected_length,
    ) catch return error.InvalidCompressedCertificate;
    if (written != expected_length) {
        return error.InvalidCompressedCertificate;
    }
}

fn decompressZlib(
    compressed: []const u8,
    output_bytes: []u8,
    allocator: std.mem.Allocator,
) Error!void {
    var input: std.Io.Reader = .fixed(compressed);
    var output: std.Io.Writer = .fixed(output_bytes);
    const decompression_buffer = try allocator.alloc(
        u8,
        std.compress.flate.max_window_len,
    );
    defer allocator.free(decompression_buffer);
    var decompressor: std.compress.flate.Decompress = .init(
        &input,
        .zlib,
        decompression_buffer,
    );
    const written = decompressor.reader.streamRemaining(&output) catch
        return error.InvalidCompressedCertificate;
    if (decompressor.reader.takeByte()) |_| {
        return error.InvalidCompressedCertificate;
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.ReadFailed => return error.InvalidCompressedCertificate,
    }
    const expected_adler = switch (decompressor.container_metadata) {
        .zlib => |metadata| metadata.adler,
        else => unreachable,
    };
    if (decompressor.err != null or written != output_bytes.len or
        output.end != output_bytes.len or input.seek != input.end or
        expected_adler != std.hash.Adler32.hash(output_bytes))
    {
        return error.InvalidCompressedCertificate;
    }
}

pub fn validateAlgorithms(algorithms: []const Algorithm) Error!void {
    if (algorithms.len > std.math.maxInt(u8) / 2) {
        return error.InvalidCompressedCertificate;
    }
    for (algorithms, 0..) |algorithm, index| {
        if (!algorithm.supported()) {
            return error.UnsupportedCompressionAlgorithm;
        }
        for (algorithms[0..index]) |previous| {
            if (algorithm == previous) {
                return error.InvalidCompressedCertificate;
            }
        }
    }
}

fn certificateBody(message: []const u8) Error![]const u8 {
    if (message.len < 4 or message[0] != 0x0b) {
        return error.InvalidCertificateMessage;
    }
    const body_len = readU24(message[1..4]);
    if (body_len == 0 or body_len != message.len - 4) {
        return error.InvalidCertificateMessage;
    }
    return message[4..];
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn appendU24(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u24,
) std.mem.Allocator.Error!void {
    try out.appendSlice(allocator, &.{
        @truncate(value >> 16),
        @truncate(value >> 8),
        @truncate(value),
    });
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: anytype,
) std.mem.Allocator.Error!void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .big);
    try out.appendSlice(allocator, &encoded);
}

test "zlib certificate compression round trips and enforces bounds" {
    const allocator = std.testing.allocator;
    const body = ([_]u8{0x42} ** 8192);
    var certificate: [4 + body.len]u8 = undefined;
    certificate[0] = 0x0b;
    certificate[1] = @truncate(body.len >> 16);
    certificate[2] = @truncate(body.len >> 8);
    certificate[3] = @truncate(body.len);
    @memcpy(certificate[4..], &body);

    var prepared = try Prepared.initZlib(
        allocator,
        &certificate,
        .amortized,
    );
    defer prepared.deinit();
    try std.testing.expect(prepared.compressed.len < body.len);
    try std.testing.expect(prepared.view().matchesCertificateMessage(
        &certificate,
    ));
    try std.testing.expect(prepared.view().savesBytes(certificate.len));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try prepared.view().write(&encoded, allocator);
    const parsed = try parse(encoded.items);
    try std.testing.expectEqual(Algorithm.zlib, parsed.algorithm);
    try std.testing.expectEqual(@as(u24, body.len), parsed.uncompressed_length);

    const decompressed = try decompressCertificate(
        allocator,
        encoded.items,
        &.{.zlib},
        certificate.len,
    );
    defer allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, &certificate, decompressed);
    try std.testing.expectError(
        error.SelectedUnofferedCompressionAlgorithm,
        decompressCertificate(allocator, encoded.items, &.{}, certificate.len),
    );
    try std.testing.expectError(
        error.CertificateTooLarge,
        decompressCertificate(
            allocator,
            encoded.items,
            &.{.zlib},
            body.len - 1,
        ),
    );

    var declared_too_long = try allocator.dupe(u8, encoded.items);
    defer allocator.free(declared_too_long);
    const too_long_len = body.len + 1;
    declared_too_long[6] = @truncate(too_long_len >> 16);
    declared_too_long[7] = @truncate(too_long_len >> 8);
    declared_too_long[8] = @truncate(too_long_len);
    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        decompressCertificate(
            allocator,
            declared_too_long,
            &.{.zlib},
            certificate.len + 1,
        ),
    );

    var declared_too_short = try allocator.dupe(u8, encoded.items);
    defer allocator.free(declared_too_short);
    const too_short_len = body.len - 1;
    declared_too_short[6] = @truncate(too_short_len >> 16);
    declared_too_short[7] = @truncate(too_short_len >> 8);
    declared_too_short[8] = @truncate(too_short_len);
    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        decompressCertificate(
            allocator,
            declared_too_short,
            &.{.zlib},
            certificate.len,
        ),
    );

    var unsupported = try allocator.dupe(u8, encoded.items);
    defer allocator.free(unsupported);
    const unknown: Algorithm = @enumFromInt(0x1234);
    std.mem.writeInt(u16, unsupported[4..6], @intFromEnum(unknown), .big);
    try std.testing.expectError(
        error.UnsupportedCompressionAlgorithm,
        decompressCertificate(
            allocator,
            unsupported,
            &.{unknown},
            certificate.len,
        ),
    );
    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        validateAlgorithms(&.{ .zlib, .zlib }),
    );

    var corrupted = try allocator.dupe(u8, encoded.items);
    defer allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        decompressCertificate(
            allocator,
            corrupted,
            &.{.zlib},
            certificate.len,
        ),
    );
}

test "Brotli certificate compression round trips and decodes libbrotli" {
    const allocator = std.testing.allocator;
    const body = [_]u8{0x42} ** 8192;
    var certificate: [4 + body.len]u8 = undefined;
    certificate[0] = 0x0b;
    certificate[1] = @truncate(body.len >> 16);
    certificate[2] = @truncate(body.len >> 8);
    certificate[3] = @truncate(body.len);
    @memcpy(certificate[4..], &body);

    var prepared = try Prepared.initBrotli(
        allocator,
        &certificate,
        .interactive,
    );
    defer prepared.deinit();
    try std.testing.expectEqual(Algorithm.brotli, prepared.algorithm);
    try std.testing.expect(prepared.compressed.len < body.len);
    try std.testing.expect(prepared.view().savesBytes(certificate.len));
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try prepared.view().write(&encoded, allocator);
    const decompressed = try decompressCertificate(
        allocator,
        encoded.items,
        &.{.brotli},
        certificate.len,
    );
    defer allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, &certificate, decompressed);

    const external_compressed = try hexBytes(
        "8bc7000080aaaaaaeadfdd6df1c5dcdcdd36775b16df36f1653335f3ed7456505" ++
            "0035700073b28283880c3061cb88609603888cf017026348472c10a46b0a0403" ++
            "e9895404bc1fff90fb32ff082209466101f9b57aa354956d47aa3d9d2da7aa7" ++
            "db334ccb76fa03d7f383308a93e1683c99cee68be56abdd9c26e7f389ece97e" ++
            "b2d45597e7f3c5fef01",
    );
    var external_message: [12 + external_compressed.len]u8 = undefined;
    external_message[0] = handshake_type_compressed_certificate;
    const message_body_len = external_message.len - 4;
    external_message[1] = @truncate(message_body_len >> 16);
    external_message[2] = @truncate(message_body_len >> 8);
    external_message[3] = @truncate(message_body_len);
    std.mem.writeInt(u16, external_message[4..6], @intFromEnum(Algorithm.brotli), .big);
    external_message[6..9].* = .{ 0, 1, 0x90 };
    external_message[9] = @truncate(external_compressed.len >> 16);
    external_message[10] = @truncate(external_compressed.len >> 8);
    external_message[11] = @truncate(external_compressed.len);
    @memcpy(external_message[12..], &external_compressed);
    const external_plain = try decompressCertificate(
        allocator,
        &external_message,
        &.{.brotli},
        400,
    );
    defer allocator.free(external_plain);
    const prefix = "certificate-chain-entry:" ++ ("vail-rfc8879-" ** 24);
    try std.testing.expectEqual(@as(usize, 400), external_plain.len - 4);
    try std.testing.expectEqualSlices(u8, prefix, external_plain[4..][0..prefix.len]);
    for (external_plain[4 + prefix.len ..], 0..) |byte, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index)), byte);
    }

    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        decompressCertificate(
            allocator,
            external_message[0 .. external_message.len - 1],
            &.{.brotli},
            400,
        ),
    );
}

test "Zstandard certificate compression round trips and decodes libzstd" {
    const allocator = std.testing.allocator;
    const body = [_]u8{0x42} ** 8192;
    var certificate: [4 + body.len]u8 = undefined;
    certificate[0] = 0x0b;
    certificate[1] = @truncate(body.len >> 16);
    certificate[2] = @truncate(body.len >> 8);
    certificate[3] = @truncate(body.len);
    @memcpy(certificate[4..], &body);

    var prepared = try Prepared.initZstd(
        allocator,
        &certificate,
        .amortized,
    );
    defer prepared.deinit();
    try std.testing.expectEqual(Algorithm.zstd, prepared.algorithm);
    try std.testing.expect(prepared.compressed.len < body.len);
    try std.testing.expect(prepared.view().savesBytes(certificate.len));
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try prepared.view().write(&encoded, allocator);
    const decompressed = try decompressCertificate(
        allocator,
        encoded.items,
        &.{.zstd},
        certificate.len,
    );
    defer allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, &certificate, decompressed);
    try validateAlgorithms(&.{.zstd});

    var corrupted = try allocator.dupe(u8, encoded.items);
    defer allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        decompressCertificate(
            allocator,
            corrupted,
            &.{.zstd},
            certificate.len,
        ),
    );

    var wrong_size = try allocator.dupe(u8, encoded.items);
    defer allocator.free(wrong_size);
    const wrong_uncompressed_len = body.len - 1;
    wrong_size[6] = @truncate(wrong_uncompressed_len >> 16);
    wrong_size[7] = @truncate(wrong_uncompressed_len >> 8);
    wrong_size[8] = @truncate(wrong_uncompressed_len);
    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        decompressCertificate(
            allocator,
            wrong_size,
            &.{.zstd},
            certificate.len,
        ),
    );

    // Independent libzstd frame for the five-byte payload "hello".
    const external_compressed = try hexBytes(
        "28b52ffd240529000068656c6c6fa36d9f88",
    );
    var external_message: [12 + external_compressed.len]u8 = undefined;
    external_message[0] = handshake_type_compressed_certificate;
    const message_body_len = external_message.len - 4;
    external_message[1] = @truncate(message_body_len >> 16);
    external_message[2] = @truncate(message_body_len >> 8);
    external_message[3] = @truncate(message_body_len);
    std.mem.writeInt(u16, external_message[4..6], @intFromEnum(Algorithm.zstd), .big);
    external_message[6..9].* = .{ 0, 0, 5 };
    external_message[9] = @truncate(external_compressed.len >> 16);
    external_message[10] = @truncate(external_compressed.len >> 8);
    external_message[11] = @truncate(external_compressed.len);
    @memcpy(external_message[12..], &external_compressed);
    const external_plain = try decompressCertificate(
        allocator,
        &external_message,
        &.{.zstd},
        5,
    );
    defer allocator.free(external_plain);
    const expected_external = [_]u8{ 0x0b, 0, 0, 5 } ++ "hello".*;
    try std.testing.expectEqualSlices(
        u8,
        &expected_external,
        external_plain,
    );

    try std.testing.expectError(
        error.InvalidCompressedCertificate,
        decompressCertificate(
            allocator,
            external_message[0 .. external_message.len - 1],
            &.{.zstd},
            5,
        ),
    );
    try std.testing.expectError(
        error.SelectedUnofferedCompressionAlgorithm,
        decompressCertificate(
            allocator,
            &external_message,
            &.{ .zlib, .brotli },
            5,
        ),
    );
}

fn hexBytes(comptime hex: []const u8) ![hex.len / 2]u8 {
    var result: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, hex);
    return result;
}
