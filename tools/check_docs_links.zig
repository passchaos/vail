//! Verify relative links in Vail's Markdown documentation.
//!
//! Run through `zig build check-docs`; the build step sets the working
//! directory to the repository root.

const std = @import("std");

const root_files = [_][]const u8{
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "THIRD_PARTY_NOTICES.md",
    "bench/README.md",
    "tools/README.md",
    "archive_crypto/README.md",
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    const io = init.io;
    var failures: usize = 0;

    for (root_files) |path| {
        try checkFile(io, allocator, path, &failures);
    }

    var docs = try std.Io.Dir.cwd().openDir(io, "docs", .{ .iterate = true });
    defer docs.close(io);
    var walker = try docs.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".md")) continue;
        const path = try std.fs.path.join(allocator, &.{ "docs", entry.path });
        defer allocator.free(path);
        try checkFile(io, allocator, path, &failures);
    }

    if (failures != 0) {
        std.debug.print("{d} broken documentation link(s)\n", .{failures});
        return error.BrokenDocumentationLink;
    }
    std.debug.print("documentation links ok\n", .{});
}

fn checkFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    failures: *usize,
) !void {
    const text = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        std.Io.Limit.limited(4 << 20),
    );
    defer allocator.free(text);

    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, text, cursor, "](")) |start| {
        const target_start = start + 2;
        const target_end = std.mem.indexOfScalarPos(
            u8,
            text,
            target_start,
            ')',
        ) orelse break;
        const target = text[target_start..target_end];
        cursor = target_end + 1;
        if (target.len == 0 or
            std.mem.startsWith(u8, target, "http://") or
            std.mem.startsWith(u8, target, "https://") or
            std.mem.startsWith(u8, target, "mailto:"))
        {
            continue;
        }
        const fragment = std.mem.indexOfScalar(u8, target, '#') orelse
            target.len;
        const link = target[0..fragment];
        if (link.len == 0) continue;

        const directory = std.fs.path.dirname(path) orelse ".";
        const resolved = try std.fs.path.join(
            allocator,
            &.{ directory, link },
        );
        defer allocator.free(resolved);
        _ = std.Io.Dir.cwd().statFile(io, resolved, .{}) catch {
            std.debug.print("broken link: {s}: {s}\n", .{ path, target });
            failures.* += 1;
        };
    }
}
