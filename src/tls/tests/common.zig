//! Shared helpers for TLS tests.

const std = @import("std");
const auth = @import("../handshake/auth.zig");
const certificate_compression = @import("../handshake/certificate_compression.zig");
const cipher_suite = @import("../crypto/cipher_suite.zig");
const client_auth = @import("../handshake/client_auth.zig");
const key_schedule = @import("../crypto/key_schedule.zig");
const key_exchange = @import("../key_exchange.zig");
const secret = @import("../crypto/secret.zig");
const ticket_keyring = @import("../crypto/ticket_keyring.zig");
const transcript = @import("../crypto/transcript.zig");
const p521 = @import("../../crypto/ec/p521.zig");
const sm2 = @import("../../crypto/sign/sm2.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

pub fn writeTestFinished(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    verify_data: []const u8,
) !void {
    try list.append(allocator, 0x14);
    try list.appendSlice(allocator, &.{
        @truncate(verify_data.len >> 16),
        @truncate(verify_data.len >> 8),
        @truncate(verify_data.len),
    });
    try list.appendSlice(allocator, verify_data);
}

pub fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected: [64]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, decoded, actual);
}

pub fn checkCertificateAllocationFailure(allocator: std.mem.Allocator) !void {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x55} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try auth.writeCertificate(&certificate, allocator, &.{&public_key});
    var parsed = try auth.parseCertificate(allocator, certificate.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &public_key, parsed.entries[0]);
}

pub fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
