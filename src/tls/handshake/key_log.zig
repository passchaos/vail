//! Allocation-free TLS secret logging callback compatible with NSS key-log
//! labels used by Wireshark and other protocol diagnostics.
//!
//! Logging is disabled unless a caller explicitly supplies `Logger`. Secret
//! and client-random slices are borrowed only for the duration of the callback.

const std = @import("std");

pub const client_random = "CLIENT_RANDOM";
pub const client_early_traffic_secret = "CLIENT_EARLY_TRAFFIC_SECRET";
pub const client_handshake_traffic_secret =
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
pub const server_handshake_traffic_secret =
    "SERVER_HANDSHAKE_TRAFFIC_SECRET";
pub const client_traffic_secret_0 = "CLIENT_TRAFFIC_SECRET_0";
pub const server_traffic_secret_0 = "SERVER_TRAFFIC_SECRET_0";
pub const exporter_secret = "EXPORTER_SECRET";

pub const Logger = struct {
    context: ?*anyopaque = null,
    log_fn: *const fn (
        context: ?*anyopaque,
        label: []const u8,
        client_random_bytes: *const [32]u8,
        secret_bytes: []const u8,
    ) void,
    will_log_fn: ?*const fn (
        context: ?*anyopaque,
        label: []const u8,
    ) bool = null,

    pub inline fn willLog(self: Logger, label: []const u8) bool {
        return if (self.will_log_fn) |callback|
            callback(self.context, label)
        else
            true;
    }

    pub inline fn log(
        self: Logger,
        label: []const u8,
        client_random_bytes: *const [32]u8,
        secret_bytes: []const u8,
    ) void {
        if (!self.willLog(label)) return;
        self.logEnabled(label, client_random_bytes, secret_bytes);
    }

    /// Invoke the callback after a successful `willLog` check. This avoids a
    /// second policy callback when producing the secret itself is expensive.
    pub inline fn logEnabled(
        self: Logger,
        label: []const u8,
        client_random_bytes: *const [32]u8,
        secret_bytes: []const u8,
    ) void {
        self.log_fn(
            self.context,
            label,
            client_random_bytes,
            secret_bytes,
        );
    }
};

pub inline fn emit(
    logger: ?Logger,
    label: []const u8,
    client_random_bytes: *const [32]u8,
    secret_bytes: []const u8,
) void {
    if (logger) |enabled| {
        enabled.log(label, client_random_bytes, secret_bytes);
    }
}

/// Write one line in the NSS `SSLKEYLOGFILE` format. The caller owns all I/O,
/// synchronization, file permissions, and secret-retention policy.
pub fn writeNssLine(
    writer: *std.Io.Writer,
    label: []const u8,
    client_random_bytes: *const [32]u8,
    secret_bytes: []const u8,
) std.Io.Writer.Error!void {
    try writer.writeAll(label);
    try writer.writeByte(' ');
    try writer.printHex(client_random_bytes, .lower);
    try writer.writeByte(' ');
    try writer.printHex(secret_bytes, .lower);
    try writer.writeByte('\n');
}

test "key logger filters labels and borrows exact secret bytes" {
    const Capture = struct {
        calls: usize = 0,
        random: [32]u8 = undefined,
        secret: [48]u8 = undefined,
        secret_len: usize = 0,

        fn willLog(_: ?*anyopaque, label: []const u8) bool {
            return std.mem.eql(u8, label, server_traffic_secret_0);
        }

        fn log(
            opaque_context: ?*anyopaque,
            label: []const u8,
            random: *const [32]u8,
            secret: []const u8,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(opaque_context.?));
            std.debug.assert(std.mem.eql(u8, label, server_traffic_secret_0));
            std.debug.assert(secret.len <= self.secret.len);
            self.calls += 1;
            self.random = random.*;
            self.secret_len = secret.len;
            @memcpy(self.secret[0..secret.len], secret);
        }
    };

    var capture: Capture = .{};
    const logger = Logger{
        .context = &capture,
        .log_fn = Capture.log,
        .will_log_fn = Capture.willLog,
    };
    const random = [_]u8{0x41} ** 32;
    const secret = [_]u8{0x51} ** 48;
    logger.log(client_traffic_secret_0, &random, &secret);
    logger.log(server_traffic_secret_0, &random, &secret);
    try std.testing.expectEqual(@as(usize, 1), capture.calls);
    try std.testing.expectEqual(random, capture.random);
    try std.testing.expectEqualSlices(
        u8,
        &secret,
        capture.secret[0..capture.secret_len],
    );

    var encoded: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try writeNssLine(
        &writer,
        server_traffic_secret_0,
        &random,
        secret[0..4],
    );
    try std.testing.expectEqualStrings(
        server_traffic_secret_0 ++ " " ++ ("41" ** 32) ++ " 51515151\n",
        encoded[0..writer.end],
    );
}
