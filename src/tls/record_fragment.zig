//! Shared progress and validation for allocation-free TLS record fragmentation.

pub const SealResult = struct {
    plaintext_consumed: usize,
    output_written: usize,
};

/// Select the non-empty plaintext prefix for exactly one TLS record.
///
/// Empty input is rejected so a caller can safely loop until all plaintext is
/// consumed without a zero-progress success. The configured limit must itself
/// fit the protocol's per-record plaintext limit.
pub inline fn selectPlaintext(
    plaintext: []const u8,
    max_fragment_plaintext: usize,
    protocol_max_plaintext: usize,
) error{InvalidPlaintextLength}![]const u8 {
    if (plaintext.len == 0 or
        max_fragment_plaintext == 0 or
        max_fragment_plaintext > protocol_max_plaintext)
    {
        return error.InvalidPlaintextLength;
    }
    return plaintext[0..@min(plaintext.len, max_fragment_plaintext)];
}

test "fragment selection always makes bounded progress" {
    const std = @import("std");

    try std.testing.expectError(
        error.InvalidPlaintextLength,
        selectPlaintext("", 1, 16),
    );
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        selectPlaintext("payload", 0, 16),
    );
    try std.testing.expectError(
        error.InvalidPlaintextLength,
        selectPlaintext("payload", 17, 16),
    );
    try std.testing.expectEqualStrings(
        "payl",
        try selectPlaintext("payload", 4, 16),
    );
    try std.testing.expectEqualStrings(
        "payload",
        try selectPlaintext("payload", 16, 16),
    );
}
