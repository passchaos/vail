//! Build-time ELF-to-Mach-O adaptation for the checked-in ARM64 assembly
//! snapshots. The build graph generates Mach-O objects from these files so the
//! Zig compiler does not have to carry the kernels as inline assembly.

const std = @import("std");

pub fn transform(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var rest = source;
    while (rest.len != 0) {
        const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..end];
        rest = if (end == rest.len) rest[rest.len..] else rest[end + 1 ..];

        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (isDirective(trimmed, ".type") or
            isDirective(trimmed, ".size") or
            isDirective(trimmed, ".hidden") or
            std.mem.startsWith(u8, trimmed, ".cfi_") or
            std.mem.startsWith(u8, trimmed, ".section .note.GNU-stack"))
        {
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, ".section .rodata")) {
            try output.appendSlice(allocator, "        .section __TEXT,__const\n");
            continue;
        }
        try appendLine(allocator, &output, line);
    }
    return output.toOwnedSlice(allocator);
}

fn appendLine(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    line: []const u8,
) !void {
    const trimmed = std.mem.trimStart(u8, line, " \t");
    if (trimmed.len == 0) {
        try output.append(allocator, '\n');
        return;
    }
    if (std.mem.startsWith(u8, trimmed, "//") or
        std.mem.startsWith(u8, trimmed, "/*") or
        std.mem.startsWith(u8, trimmed, "*") or
        std.mem.startsWith(u8, trimmed, "#"))
    {
        try appendTransformed(allocator, output, line);
        try output.append(allocator, '\n');
        return;
    }
    const comment_start = std.mem.indexOf(u8, line, "//") orelse line.len;
    var rest: []const u8 = line[0..comment_start];
    while (rest.len != 0) {
        const semi = std.mem.indexOfScalar(u8, rest, ';') orelse rest.len;
        const segment = rest[0..semi];
        rest = if (semi == rest.len) rest[rest.len..] else rest[semi + 1 ..];
        const segment_trimmed = std.mem.trimStart(u8, segment, " \t");
        if (segment_trimmed.len == 0) continue;
        if (std.mem.startsWith(u8, segment_trimmed, ".cfi_") or
            isDirective(segment_trimmed, ".type") or
            isDirective(segment_trimmed, ".size") or
            isDirective(segment_trimmed, ".hidden"))
        {
            continue;
        }
        try appendTransformed(allocator, output, segment);
        try output.append(allocator, '\n');
    }
}

fn appendTransformed(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    line: []const u8,
) !void {
    var i: usize = 0;
    var pending_pageoff = false;
    var pageoff_symbol_started = false;
    const trimmed = std.mem.trimStart(u8, line, " \t");
    const is_adrp = std.mem.startsWith(u8, trimmed, "adrp ") or
        std.mem.startsWith(u8, trimmed, "adrp\t");

    while (i < line.len) {
        const byte = line[i];
        if (pending_pageoff) {
            const symbol_byte = std.ascii.isAlphanumeric(byte) or
                byte == '_' or byte == '.';
            if (!symbol_byte and pageoff_symbol_started) {
                try output.appendSlice(allocator, "@PAGEOFF");
                pending_pageoff = false;
                pageoff_symbol_started = false;
            } else if (symbol_byte) {
                pageoff_symbol_started = true;
            }
        }
        if (i + 6 <= line.len and
            std.mem.eql(u8, line[i .. i + 6], ":lo12:"))
        {
            i += 6;
            pending_pageoff = true;
            pageoff_symbol_started = false;
            continue;
        }
        if (byte == '.' and
            (i == 0 or
                !(std.ascii.isAlphanumeric(line[i - 1]) or line[i - 1] == '_')) and
            i + 1 < line.len and line[i + 1] == 'L' and
            !isLocalDirective(line[i + 2 ..]))
        {
            try output.append(allocator, 'L');
            i += 2;
            continue;
        }
        const identifier = std.ascii.isAlphanumeric(byte) or byte == '_';
        const starts_identifier = identifier and
            (i == 0 or
                !(std.ascii.isAlphanumeric(line[i - 1]) or line[i - 1] == '_'));
        if (starts_identifier and std.mem.startsWith(u8, line[i..], "vail")) {
            try output.append(allocator, '_');
        }
        try output.append(allocator, byte);
        i += 1;
    }
    if (pending_pageoff) try output.appendSlice(allocator, "@PAGEOFF");
    if (is_adrp and std.mem.indexOf(u8, line, "@PAGE") == null) {
        try output.appendSlice(allocator, "@PAGE");
    }
}

fn isDirective(line: []const u8, name: []const u8) bool {
    if (!std.mem.startsWith(u8, line, name)) return false;
    if (line.len == name.len) return true;
    return line[name.len] == ' ' or line[name.len] == '\t';
}

fn isLocalDirective(rest: []const u8) bool {
    return std.mem.startsWith(u8, rest, "long") or
        std.mem.startsWith(u8, rest, "lsym") or
        std.mem.startsWith(u8, rest, "lcomm") or
        std.mem.startsWith(u8, rest, "loc") or
        std.mem.startsWith(u8, rest, "lflags");
}
