//! QUIC Retry Integrity Tag helpers.
//!
//! Retry packets are not protected with ordinary packet keys. RFC 9001 instead
//! authenticates the bytes that would be sent on the wire, plus the Original
//! Destination Connection ID from the triggering Initial packet, with a fixed
//! AES-128-GCM key and nonce. Transport code owns Retry packet construction;
//! this module owns the version-specific integrity calculation.

const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const initial = @import("initial.zig");
const traffic = @import("traffic_crypto.zig");

pub const tag_len = traffic.tag_len;
pub const max_connection_id_len = initial.max_connection_id_len;

pub const key_v1 = [_]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

pub const nonce_v1 = [_]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
    0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

pub const key_v2 = [_]u8{
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
};

pub const nonce_v2 = [_]u8{
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c,
    0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
};

pub const Error = error{
    UnsupportedVersion,
    InvalidOriginalDestinationConnectionId,
    InvalidRetryPacket,
    RetryIntegrityTagMismatch,
    PseudoPacketBufferTooSmall,
};

pub const Config = struct {
    version: u32,
    key: [Aes128Gcm.key_length]u8,
    nonce: [Aes128Gcm.nonce_length]u8,
};

pub fn configForVersion(version: u32) Error!Config {
    return switch (version) {
        initial.version_1 => .{
            .version = initial.version_1,
            .key = key_v1,
            .nonce = nonce_v1,
        },
        initial.version_2 => .{
            .version = initial.version_2,
            .key = key_v2,
            .nonce = nonce_v2,
        },
        else => error.UnsupportedVersion,
    };
}

pub fn pseudoPacketLen(
    original_destination_connection_id: []const u8,
    retry_without_tag: []const u8,
) Error!usize {
    if (original_destination_connection_id.len > max_connection_id_len) {
        return error.InvalidOriginalDestinationConnectionId;
    }
    return 1 + original_destination_connection_id.len + retry_without_tag.len;
}

pub fn writePseudoPacket(
    out: []u8,
    original_destination_connection_id: []const u8,
    retry_without_tag: []const u8,
) Error![]u8 {
    const len = try pseudoPacketLen(
        original_destination_connection_id,
        retry_without_tag,
    );
    if (out.len < len) return error.PseudoPacketBufferTooSmall;
    out[0] = @intCast(original_destination_connection_id.len);
    @memcpy(
        out[1..][0..original_destination_connection_id.len],
        original_destination_connection_id,
    );
    @memcpy(
        out[1 + original_destination_connection_id.len ..][0..retry_without_tag.len],
        retry_without_tag,
    );
    return out[0..len];
}

pub fn computeIntegrityTagForVersion(
    version: u32,
    original_destination_connection_id: []const u8,
    retry_without_tag: []const u8,
    pseudo_packet_buffer: []u8,
) Error![tag_len]u8 {
    return computeIntegrityTag(
        try configForVersion(version),
        original_destination_connection_id,
        retry_without_tag,
        pseudo_packet_buffer,
    );
}

pub fn computeIntegrityTag(
    config: Config,
    original_destination_connection_id: []const u8,
    retry_without_tag: []const u8,
    pseudo_packet_buffer: []u8,
) Error![tag_len]u8 {
    const pseudo_packet = try writePseudoPacket(
        pseudo_packet_buffer,
        original_destination_connection_id,
        retry_without_tag,
    );
    var tag: [tag_len]u8 = undefined;
    var empty_ciphertext: [0]u8 = .{};
    Aes128Gcm.encrypt(
        &empty_ciphertext,
        &tag,
        &.{},
        pseudo_packet,
        config.nonce,
        config.key,
    );
    return tag;
}

pub fn verifyIntegrityTagForVersion(
    version: u32,
    original_destination_connection_id: []const u8,
    retry_packet: []const u8,
    pseudo_packet_buffer: []u8,
) Error!void {
    return verifyIntegrityTag(
        try configForVersion(version),
        original_destination_connection_id,
        retry_packet,
        pseudo_packet_buffer,
    );
}

pub fn verifyIntegrityTag(
    config: Config,
    original_destination_connection_id: []const u8,
    retry_packet: []const u8,
    pseudo_packet_buffer: []u8,
) Error!void {
    if (retry_packet.len < tag_len) return error.InvalidRetryPacket;
    const retry_without_tag = retry_packet[0 .. retry_packet.len - tag_len];
    const got = retry_packet[retry_packet.len - tag_len ..][0..tag_len].*;
    const expected = try computeIntegrityTag(
        config,
        original_destination_connection_id,
        retry_without_tag,
        pseudo_packet_buffer,
    );
    if (!std.crypto.timing_safe.eql([tag_len]u8, expected, got)) {
        return error.RetryIntegrityTagMismatch;
    }
}

comptime {
    std.debug.assert(Aes128Gcm.key_length == 16);
    std.debug.assert(Aes128Gcm.nonce_length == 12);
    std.debug.assert(Aes128Gcm.tag_length == tag_len);
}
