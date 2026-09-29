//! Bounded replay protection for TLS 1.3 0-RTT admission.
//!
//! A server must never accept early data solely because a ticket and binder are
//! valid: the same ClientHello can be replayed. This module provides a small,
//! allocation-free cache and a type-erased policy hook for deployments that
//! use a shared or distributed replay database.

const std = @import("std");

pub const Error = error{
    InvalidReplayWindow,
    ReplayDetected,
    ReplayCapacityExhausted,
};

pub const Guard = struct {
    context: *anyopaque,
    check_and_mark: *const fn (
        context: *anyopaque,
        identity: []const u8,
        now_ms: u64,
        expires_at_ms: u64,
    ) Error!void,

    pub fn checkAndMark(
        self: Guard,
        identity: []const u8,
        now_ms: u64,
        expires_at_ms: u64,
    ) Error!void {
        return self.check_and_mark(
            self.context,
            identity,
            now_ms,
            expires_at_ms,
        );
    }
};

/// Fixed-capacity replay cache. It fails closed when every slot contains an
/// unexpired identity; callers can shard it or provide a distributed `Guard`
/// implementation when a process-local bound is insufficient.
pub fn ReplayCache(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const Entry = struct {
            identity_hash: [32]u8 = [_]u8{0} ** 32,
            expires_at_ms: u64 = 0,
            occupied: bool = false,
        };

        entries: [capacity]Entry = [_]Entry{.{}} ** capacity,

        pub fn guard(self: *Self) Guard {
            return .{
                .context = self,
                .check_and_mark = checkAndMarkOpaque,
            };
        }

        pub fn checkAndMark(
            self: *Self,
            identity: []const u8,
            now_ms: u64,
            expires_at_ms: u64,
        ) Error!void {
            if (identity.len == 0 or expires_at_ms <= now_ms) {
                return error.InvalidReplayWindow;
            }
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(identity, &digest, .{});

            var reusable: ?usize = null;
            for (&self.entries, 0..) |*entry, index| {
                if (!entry.occupied or entry.expires_at_ms <= now_ms) {
                    if (reusable == null) reusable = index;
                    continue;
                }
                if (std.crypto.timing_safe.eql(
                    [32]u8,
                    entry.identity_hash,
                    digest,
                )) return error.ReplayDetected;
            }
            const index = reusable orelse
                return error.ReplayCapacityExhausted;
            self.entries[index] = .{
                .identity_hash = digest,
                .expires_at_ms = expires_at_ms,
                .occupied = true,
            };
        }

        fn checkAndMarkOpaque(
            context: *anyopaque,
            identity: []const u8,
            now_ms: u64,
            expires_at_ms: u64,
        ) Error!void {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.checkAndMark(identity, now_ms, expires_at_ms);
        }
    };
}

test "bounded replay cache accepts once, rejects replay, and reuses expiry" {
    var cache = ReplayCache(2){};
    try cache.checkAndMark("ticket-a", 100, 200);
    try std.testing.expectError(
        error.ReplayDetected,
        cache.checkAndMark("ticket-a", 101, 200),
    );
    try cache.checkAndMark("ticket-b", 100, 300);
    try std.testing.expectError(
        error.ReplayCapacityExhausted,
        cache.checkAndMark("ticket-c", 150, 400),
    );
    try cache.checkAndMark("ticket-c", 200, 400);
    try std.testing.expectError(
        error.InvalidReplayWindow,
        cache.checkAndMark("ticket-d", 500, 500),
    );
}
