//! Object-format compatibility for embedded ARM64 assembly snapshots.
//!
//! The checked-in kernels use ELF/GAS spelling. Mach-O needs an underscore
//! prefix on C symbols and rejects the ELF-only `.type`, `.size`, `.hidden`,
//! and `.note.GNU-stack` directives, so the embedded source is rewritten at
//! compile time when the target object format is Mach-O.

const std = @import("std");
const builtin = @import("builtin");

/// True when the target can execute the checked-in ARM64 kernels.
pub const arm64_native = builtin.cpu.arch == .aarch64 and
    (builtin.os.tag == .linux or builtin.os.tag == .macos);

const is_macho = builtin.object_format == .macho;

/// True when the build graph assembles the ARM64 kernels as separate Mach-O
/// objects. In that mode the kernel modules only declare the extern symbols.
pub const external = is_macho;

/// Fixed-capacity buffer returned by `arm64`. Returning the array by value
/// keeps the rewritten source a comptime constant that `asm` can consume.
pub fn Source(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8,
        len: usize,
    };
}

/// Adapt an ELF-flavoured ARM64 assembly snapshot for the active object
/// format. ELF targets receive the source unchanged.
pub fn arm64(comptime source: []const u8) Source(source.len * 2 + 1024) {
    const Result = Source(source.len * 2 + 1024);
    if (comptime !is_macho) {
        var result: Result = undefined;
        @memcpy(result.bytes[0..source.len], source);
        result.len = source.len;
        return result;
    }
    comptime {
        @setEvalBranchQuota(10_000_000);
        var result: Result = undefined;
        var len: usize = 0;
        var rest = source;
        while (rest.len != 0) {
            const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
            const line = rest[0..end];
            rest = if (end == rest.len) rest[rest.len..] else rest[end + 1 ..];

            const trimmed = std.mem.trimStart(u8, line, " \t");
            if (isDirective(trimmed, ".type") or
                isDirective(trimmed, ".size") or
                isDirective(trimmed, ".hidden") or
                isDirective(trimmed, ".arch") or
                isDirective(trimmed, ".fpu") or
                isDirective(trimmed, ".popsection") or
                isDirective(trimmed, ".pushsection") or
                std.mem.startsWith(u8, trimmed, ".cfi_") or
                std.mem.startsWith(u8, trimmed, ".section .note.GNU-stack"))
            {
                continue;
            }
            if (std.mem.startsWith(u8, trimmed, ".section .rodata")) {
                const replacement = "        .section __TEXT,__const";
                @memcpy(result.bytes[len..][0..replacement.len], replacement);
                len += replacement.len;
                result.bytes[len] = '\n';
                len += 1;
                continue;
            }
            len = appendLine(&result.bytes, len, line);
        }
        result.len = len;
        return result;
    }
}

/// Emit one source line. Mach-O treats `;` as a comment delimiter, so
/// multi-statement GAS lines are split into one statement per line. Line and
/// block comments are copied verbatim and never split.
fn appendLine(output: []u8, start: usize, line: []const u8) usize {
    var len = start;
    const trimmed = std.mem.trimStart(u8, line, " \t");
    if (trimmed.len == 0) {
        output[len] = '\n';
        return len + 1;
    }
    if (std.mem.startsWith(u8, trimmed, "//") or
        std.mem.startsWith(u8, trimmed, "/*") or
        std.mem.startsWith(u8, trimmed, "*") or
        std.mem.startsWith(u8, trimmed, "#"))
    {
        len = appendWithSymbolPrefix(output, len, line);
        output[len] = '\n';
        return len + 1;
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
        len = appendWithSymbolPrefix(output, len, segment);
        output[len] = '\n';
        len += 1;
    }
    return len;
}

/// Convenience wrapper for call sites that only need the bytes.
pub fn slice(comptime source: []const u8) []const u8 {
    const transformed = arm64(source);
    return transformed.bytes[0..transformed.len];
}

/// Match an assembler directive name followed by whitespace or end of line.
fn isDirective(line: []const u8, name: []const u8) bool {
    if (!std.mem.startsWith(u8, line, name)) return false;
    if (line.len == name.len) return true;
    return line[name.len] == ' ' or line[name.len] == '\t';
}

/// Mach-O C symbols carry a leading underscore. Prefix every top-level
/// identifier that starts with `vail`; references inside each snapshot use the
/// same names, so one pass keeps definitions and references consistent.
/// ELF `:lo12:sym` operands become `sym@PAGEOFF`, and `adrp` targets gain the
/// matching `@PAGE` suffix.
fn appendWithSymbolPrefix(output: []u8, start: usize, line: []const u8) usize {
    var len = start;
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
                const suffix = "@PAGEOFF";
                @memcpy(output[len..][0..suffix.len], suffix);
                len += suffix.len;
                pending_pageoff = false;
                pageoff_symbol_started = false;
            } else if (symbol_byte) {
                pageoff_symbol_started = true;
            }
        }
        // ELF page-offset operand: `:lo12:symbol` -> `symbol@PAGEOFF`.
        if (i + 6 <= line.len and std.mem.eql(u8, line[i .. i + 6], ":lo12:")) {
            i += 6;
            pending_pageoff = true;
            pageoff_symbol_started = false;
            continue;
        }
        // Mach-O treats labels starting with `L` as assembler-local; `.L`
        // labels are external and cannot be used by conditional branches.
        if (byte == '.' and
            (i == 0 or !(std.ascii.isAlphanumeric(line[i - 1]) or line[i - 1] == '_')) and
            i + 1 < line.len and line[i + 1] == 'L' and
            !isLocalDirective(line[i + 2 ..]))
        {
            output[len] = 'L';
            len += 1;
            i += 2;
            continue;
        }
        const identifier = std.ascii.isAlphanumeric(byte) or byte == '_';
        const starts_identifier = identifier and
            (i == 0 or !(std.ascii.isAlphanumeric(line[i - 1]) or line[i - 1] == '_'));
        if (starts_identifier and std.mem.startsWith(u8, line[i..], "vail")) {
            output[len] = '_';
            len += 1;
        }
        output[len] = byte;
        len += 1;
        i += 1;
    }
    if (pending_pageoff) {
        const suffix = "@PAGEOFF";
        @memcpy(output[len..][0..suffix.len], suffix);
        len += suffix.len;
    }
    if (is_adrp and std.mem.indexOf(u8, line, "@PAGE") == null) {
        const suffix = "@PAGE";
        @memcpy(output[len..][0..suffix.len], suffix);
        len += suffix.len;
    }
    return len;
}

fn isLocalDirective(rest: []const u8) bool {
    return std.mem.startsWith(u8, rest, "long") or
        std.mem.startsWith(u8, rest, "lsym") or
        std.mem.startsWith(u8, rest, "lcomm") or
        std.mem.startsWith(u8, rest, "loc") or
        std.mem.startsWith(u8, rest, "lflags");
}
