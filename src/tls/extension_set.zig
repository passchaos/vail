const std = @import("std");

/// Duplicate detector for the complete 16-bit TLS extension namespace.
/// Only pages touched by the current message are initialized, avoiding an
/// unconditional 8 KiB clear for the handful of pages used by normal flights.
pub const Set = struct {
    initialized_pages: std.StaticBitSet(256),
    pages: [256]std.StaticBitSet(256),

    pub fn reset(self: *Set) void {
        self.initialized_pages = std.StaticBitSet(256).initEmpty();
    }

    /// Returns true when `extension_type` was already present.
    pub fn containsOrInsert(self: *Set, extension_type: u16) bool {
        const page_index: usize = extension_type >> 8;
        const bit_index: usize = extension_type & 0xff;
        if (!self.initialized_pages.isSet(page_index)) {
            self.pages[page_index] = std.StaticBitSet(256).initEmpty();
            self.initialized_pages.set(page_index);
        }
        const duplicate = self.pages[page_index].isSet(bit_index);
        self.pages[page_index].set(bit_index);
        return duplicate;
    }
};

test "extension set detects duplicates across lazily initialized pages" {
    var set: Set = undefined;
    set.reset();
    try std.testing.expect(!set.containsOrInsert(0x0000));
    try std.testing.expect(!set.containsOrInsert(0x00ff));
    try std.testing.expect(!set.containsOrInsert(0x0100));
    try std.testing.expect(!set.containsOrInsert(0xfe0d));
    try std.testing.expect(!set.containsOrInsert(0xffff));
    try std.testing.expect(set.containsOrInsert(0x0000));
    try std.testing.expect(set.containsOrInsert(0x00ff));
    try std.testing.expect(set.containsOrInsert(0x0100));
    try std.testing.expect(set.containsOrInsert(0xfe0d));
    try std.testing.expect(set.containsOrInsert(0xffff));
}

test "extension set matches a full bitset over every extension type" {
    var set: Set = undefined;
    set.reset();
    var oracle = std.StaticBitSet(65536).initEmpty();
    var state: u32 = 0x6d2b_79f5;
    for (0..2 * 65536) |_| {
        state = state *% 1_664_525 +% 1_013_904_223;
        const extension_type: u16 = @truncate(state);
        const expected = oracle.isSet(extension_type);
        oracle.set(extension_type);
        try std.testing.expectEqual(
            expected,
            set.containsOrInsert(extension_type),
        );
    }
}
