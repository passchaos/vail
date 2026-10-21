//! ARJ legacy Garble cipher.
//!
//! Garble is the original ARJ password obfuscation algorithm. It has no
//! cryptographic security: every byte is XORed with the wrapping sum of the
//! per-file modifier and a cyclic password byte. Vort owns ARJ header policy,
//! compression composition, and CRC verification; this module owns only the
//! symmetric byte stream.

const std = @import("std");

pub const Error = error{InvalidArjPassword};

pub const Garble = struct {
    password: []const u8,
    modifier: u8,
    password_index: usize = 0,

    pub fn init(password: []const u8, modifier: u8) Error!Garble {
        if (password.len == 0) return error.InvalidArjPassword;
        return .{ .password = password, .modifier = modifier };
    }

    pub fn crypt(self: *Garble, bytes: []u8) void {
        for (bytes) |*byte| {
            byte.* ^= self.modifier +% self.password[self.password_index];
            self.password_index += 1;
            if (self.password_index == self.password.len)
                self.password_index = 0;
        }
    }

    pub fn cryptInto(
        self: *Garble,
        input: []const u8,
        output: []u8,
    ) error{OutputTooSmall}!usize {
        if (output.len < input.len) return error.OutputTooSmall;
        @memcpy(output[0..input.len], input);
        self.crypt(output[0..input.len]);
        return input.len;
    }
};

pub fn crypt(bytes: []u8, password: []const u8, modifier: u8) Error!void {
    var cipher = try Garble.init(password, modifier);
    cipher.crypt(bytes);
}

test "ARJ Garble matches the documented modifier and password stream" {
    var data = [_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff };
    try crypt(&data, "key", 0x20);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x8b, 0x84, 0xe6, 0x0b, 0x7b, 0x66 },
        &data,
    );
    try crypt(&data, "key", 0x20);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff },
        &data,
    );
}

test "ARJ Garble is invariant under input chunking" {
    const input = "ARJ legacy Garble is a stateful cyclic XOR stream.";
    var coalesced: [input.len]u8 = undefined;
    var whole = try Garble.init("password", 0xa5);
    _ = try whole.cryptInto(input, &coalesced);

    var fragmented = input.*;
    var chunks = try Garble.init("password", 0xa5);
    chunks.crypt(fragmented[0..1]);
    chunks.crypt(fragmented[1..17]);
    chunks.crypt(fragmented[17..]);
    try std.testing.expectEqualSlices(u8, &coalesced, &fragmented);
    try std.testing.expectError(
        error.InvalidArjPassword,
        Garble.init("", 0),
    );
}
