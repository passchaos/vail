//! Native system-store loading: OpenSSL path overrides, tolerant PEM
//! parsing, and compatibility anchors.
const std = @import("std");
const builtin = @import("builtin");
const trust = @import("trust.zig");
const path_vectors = @import("testdata/path_vectors.zig");

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn pemCertificate(
    allocator: std.mem.Allocator,
    certificate_der: []const u8,
) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    const encoded_start = result.items.len;
    try result.resize(allocator, encoded_start + encoded_len);
    _ = std.base64.standard.Encoder.encode(
        result.items[encoded_start..],
        certificate_der,
    );
    try result.appendSlice(allocator, "\n-----END CERTIFICATE-----\n");
    return result.toOwnedSlice(allocator);
}

const malformed_block =
    "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n";

test "SystemStore initWithPaths skips malformed PEM and trusts valid roots" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.fromNanoseconds(
        1_800_000_000 * std.time.ns_per_s,
    );
    const root = decodeHex(path_vectors.p521_root_hex);
    const leaf = decodeHex(path_vectors.p521_leaf_hex);
    const root_pem = try pemCertificate(allocator, &root);
    defer allocator.free(root_pem);

    var pem: std.ArrayList(u8) = .empty;
    defer pem.deinit(allocator);
    try pem.appendSlice(allocator, malformed_block);
    try pem.appendSlice(allocator, root_pem);

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = pem.items,
    });
    const path = try temporary.dir.realPathFileAlloc(
        io,
        "ca.pem",
        allocator,
    );
    defer allocator.free(path);

    var store = try trust.SystemStore.initWithPaths(
        allocator,
        io,
        now,
        .{ .file = path },
    );
    defer store.deinit();
    try store.verifier(now.toSeconds()).verify(.{
        .server_name = "localhost",
        .chain = &.{&leaf},
    });
}

test "SystemStore initWithPaths reads directories and compatible roots" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.fromNanoseconds(
        1_800_000_000 * std.time.ns_per_s,
    );
    const ordinary_root = decodeHex(path_vectors.p521_root_hex);
    const ordinary_leaf = decodeHex(path_vectors.p521_leaf_hex);
    const sha3_root = decodeHex(path_vectors.p521_sha3_root_hex);
    const sha3_leaf = decodeHex(path_vectors.p521_sha3_leaf_hex);
    const ordinary_pem = try pemCertificate(allocator, &ordinary_root);
    defer allocator.free(ordinary_pem);
    const sha3_pem = try pemCertificate(allocator, &sha3_root);
    defer allocator.free(sha3_pem);

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(io, "certs", .default_dir);
    try temporary.dir.writeFile(io, .{
        .sub_path = "certs/ordinary.pem",
        .data = ordinary_pem,
    });
    try temporary.dir.writeFile(io, .{
        .sub_path = "certs/sha3.pem",
        .data = sha3_pem,
    });
    const path = try temporary.dir.realPathFileAlloc(
        io,
        "certs",
        allocator,
    );
    defer allocator.free(path);

    var store = try trust.SystemStore.initWithPaths(
        allocator,
        io,
        now,
        .{ .dirs = &.{path} },
    );
    defer store.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        store.compatibleAnchorCount(),
    );
    try store.verifier(now.toSeconds()).verify(.{
        .server_name = "localhost",
        .chain = &.{&ordinary_leaf},
    });
    try store.verifier(now.toSeconds()).verify(.{
        .server_name = "localhost",
        .chain = &.{&sha3_leaf},
    });
}

test "SystemStore initWithEnviron honors SSL_CERT_FILE and SSL_CERT_DIR" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.fromNanoseconds(
        1_800_000_000 * std.time.ns_per_s,
    );
    const ordinary_root = decodeHex(path_vectors.p521_root_hex);
    const ordinary_leaf = decodeHex(path_vectors.p521_leaf_hex);
    const sha3_root = decodeHex(path_vectors.p521_sha3_root_hex);
    const sha3_leaf = decodeHex(path_vectors.p521_sha3_leaf_hex);
    const ordinary_pem = try pemCertificate(allocator, &ordinary_root);
    defer allocator.free(ordinary_pem);
    const sha3_pem = try pemCertificate(allocator, &sha3_root);
    defer allocator.free(sha3_pem);

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(io, .{
        .sub_path = "file.pem",
        .data = ordinary_pem,
    });
    try temporary.dir.createDir(io, "first", .default_dir);
    try temporary.dir.createDir(io, "second", .default_dir);
    try temporary.dir.writeFile(io, .{
        .sub_path = "first/ordinary.pem",
        .data = ordinary_pem,
    });
    try temporary.dir.writeFile(io, .{
        .sub_path = "second/sha3.pem",
        .data = sha3_pem,
    });
    const file_path = try temporary.dir.realPathFileAlloc(
        io,
        "file.pem",
        allocator,
    );
    defer allocator.free(file_path);
    const first_dir = try temporary.dir.realPathFileAlloc(
        io,
        "first",
        allocator,
    );
    defer allocator.free(first_dir);
    const second_dir = try temporary.dir.realPathFileAlloc(
        io,
        "second",
        allocator,
    );
    defer allocator.free(second_dir);

    const file_entry = try std.fmt.allocPrintSentinel(
        allocator,
        "SSL_CERT_FILE={s}",
        .{file_path},
        0,
    );
    defer allocator.free(file_entry);
    const dir_entry = try std.fmt.allocPrintSentinel(
        allocator,
        "SSL_CERT_DIR={s}{c}{s}",
        .{ first_dir, std.fs.path.delimiter, second_dir },
        0,
    );
    defer allocator.free(dir_entry);
    var entries = [_]?[*:0]const u8{
        file_entry.ptr,
        dir_entry.ptr,
        null,
    };
    const block: std.process.Environ.PosixBlock = .{
        .slice = entries[0..2 :null],
    };
    const environ: std.process.Environ = .{ .block = block };

    var store = try trust.SystemStore.initWithEnviron(
        allocator,
        io,
        now,
        environ,
    );
    defer store.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        store.compatibleAnchorCount(),
    );
    try store.verifier(now.toSeconds()).verify(.{
        .server_name = "localhost",
        .chain = &.{&ordinary_leaf},
    });
    try store.verifier(now.toSeconds()).verify(.{
        .server_name = "localhost",
        .chain = &.{&sha3_leaf},
    });
}

test "SystemStore init loads Linux native roots tolerantly" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real);
    var store = try trust.SystemStore.init(allocator, io, now);
    defer store.deinit();

    const default_bundle = std.Io.Dir.openFileAbsolute(
        io,
        "/etc/ssl/certs/ca-certificates.crt",
        .{},
    ) catch null;
    if (default_bundle) |file| {
        file.close(io);
        try std.testing.expect(store.bundle.bytes.items.len != 0);
    }
}
