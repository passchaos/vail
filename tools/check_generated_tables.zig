//! Verify checked-in generated files against `tools/generated_manifest.txt`.
//!
//! Run through `zig build check-generated`; the build step sets the working
//! directory to the repository root.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    const io = init.io;

    const manifest = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "tools/generated_manifest.txt",
        allocator,
        std.Io.Limit.limited(1 << 20),
    );
    defer allocator.free(manifest);

    var checked: usize = 0;
    var failures: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, manifest, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var parts = std.mem.tokenizeAny(u8, line, " \t");
        const expected = parts.next() orelse return error.InvalidManifest;
        const path = parts.next() orelse return error.InvalidManifest;
        if (expected.len != 64) return error.InvalidManifest;

        const data = try std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            std.Io.Limit.limited(64 << 20),
        );
        defer allocator.free(data);

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        var actual: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&actual, "{x}", .{digest}) catch unreachable;

        checked += 1;
        if (!std.mem.eql(u8, &actual, expected)) {
            std.debug.print("generated file drift: {s}\n", .{path});
            failures += 1;
        }
    }

    if (failures != 0) {
        std.debug.print("{d} generated file(s) drifted\n", .{failures});
        return error.GeneratedFileDrift;
    }
    std.debug.print("checked {d} generated files\n", .{checked});
}
