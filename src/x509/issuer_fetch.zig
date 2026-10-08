//! Bounded, allocation-free AIA caIssuers retrieval orchestration.

const std = @import("std");
const certificate_set = @import("certificate_set.zig");
const ocsp = @import("ocsp.zig");

pub const hard_max_fetches = 64;

pub const Fetcher = struct {
    context: ?*anyopaque = null,
    fetch: *const fn (
        context: ?*anyopaque,
        uri: []const u8,
        output: []u8,
    ) anyerror!?usize,
};

pub const Options = struct {
    max_fetches: usize = 8,
    max_certificates: usize = 16,
    max_response_bytes: usize = 1024 * 1024,
    fail_on_fetch_error: bool = false,
    fail_on_invalid_response: bool = false,
    /// Accept bounded BER indefinite-length wrappers around CMS certs-only.
    /// Individual certificates remain strict DER.
    allow_ber_certs_only: bool = false,
};

pub const Result = struct {
    certificates: []const []const u8,
    storage_used: usize,
    fetches: usize,
};

/// Recursively fetch AIA caIssuers responses from `seed_certificates` and all
/// newly discovered certificates. Results borrow `storage`; `output` receives
/// one slice per unique fetched DER certificate. Network policy is entirely in
/// the caller callback.
pub fn resolve(
    storage: []u8,
    scratch: []u8,
    output: [][]const u8,
    seed_certificates: []const []const u8,
    fetcher: Fetcher,
    options: Options,
) !Result {
    if (options.max_fetches == 0 or
        options.max_fetches > hard_max_fetches or
        options.max_certificates == 0 or
        options.max_certificates > output.len or
        options.max_response_bytes == 0 or
        seed_certificates.len >
            std.math.maxInt(usize) - options.max_certificates)
    {
        return error.InvalidIssuerFetchLimits;
    }
    const response_limit = @min(options.max_response_bytes, scratch.len);
    const output_bytes = std.mem.sliceAsBytes(output);
    if (response_limit == 0 or
        slicesOverlap(storage, scratch[0..response_limit]) or
        slicesOverlap(storage, output_bytes) or
        slicesOverlap(scratch[0..response_limit], output_bytes))
    {
        return error.InvalidIssuerFetchLimits;
    }
    for (seed_certificates) |seed| {
        if (slicesOverlap(seed, storage) or
            slicesOverlap(seed, scratch[0..response_limit]) or
            slicesOverlap(seed, output_bytes))
        {
            return error.InvalidIssuerFetchLimits;
        }
    }

    var seen_uris: [hard_max_fetches][]const u8 = undefined;
    var seen_uri_count: usize = 0;
    var fetched_count: usize = 0;
    var storage_used: usize = 0;
    var fetch_count: usize = 0;
    var source_index: usize = 0;
    while (source_index < seed_certificates.len + fetched_count) : (source_index += 1) {
        const source = if (source_index < seed_certificates.len)
            seed_certificates[source_index]
        else
            output[source_index - seed_certificates.len];
        var urls = ocsp.caIssuerUrls(source) catch |err| {
            if (options.fail_on_invalid_response) return err;
            continue;
        };
        uri_loop: while (try urls.next()) |uri| {
            for (seen_uris[0..seen_uri_count]) |seen| {
                if (std.mem.eql(u8, seen, uri)) continue :uri_loop;
            }
            if (fetch_count == options.max_fetches) break;
            seen_uris[seen_uri_count] = uri;
            seen_uri_count += 1;
            fetch_count += 1;
            const response_len = (fetcher.fetch(
                fetcher.context,
                uri,
                scratch[0..response_limit],
            ) catch |err| {
                if (options.fail_on_fetch_error) return err;
                continue;
            }) orelse continue;
            if (response_len == 0 or response_len > response_limit) {
                if (options.fail_on_invalid_response) {
                    return error.InvalidIssuerResponse;
                }
                continue;
            }
            var certificates = (if (options.allow_ber_certs_only)
                certificate_set.parseBer(scratch[0..response_len])
            else
                certificate_set.parse(scratch[0..response_len])) catch |err| {
                if (options.fail_on_invalid_response) return err;
                continue;
            };
            while (try certificates.next()) |certificate| {
                if (containsCertificate(seed_certificates, certificate) or
                    containsCertificate(output[0..fetched_count], certificate))
                {
                    continue;
                }
                if (fetched_count == options.max_certificates) {
                    return error.TooManyFetchedCertificates;
                }
                if (certificate.len > storage.len -| storage_used) {
                    return error.IssuerStorageTooSmall;
                }
                const destination = storage[storage_used..][0..certificate.len];
                @memcpy(destination, certificate);
                output[fetched_count] = destination;
                fetched_count += 1;
                storage_used += certificate.len;
            }
        }
    }
    return .{
        .certificates = output[0..fetched_count],
        .storage_used = storage_used,
        .fetches = fetch_count,
    };
}

fn containsCertificate(
    certificates: []const []const u8,
    candidate: []const u8,
) bool {
    for (certificates) |certificate| {
        if (std.mem.eql(u8, certificate, candidate)) return true;
    }
    return false;
}

fn slicesOverlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    const a_end = std.math.add(usize, a_start, a.len) catch return true;
    const b_end = std.math.add(usize, b_start, b.len) catch return true;
    return a_start < b_end and b_start < a_end;
}

const TestFetcher = struct {
    responses: []const []const u8,
    calls: usize = 0,
    uris: [hard_max_fetches][]const u8 = undefined,

    fn callback(
        opaque_context: ?*anyopaque,
        uri: []const u8,
        output_buffer: []u8,
    ) anyerror!?usize {
        const self: *TestFetcher = @ptrCast(@alignCast(
            opaque_context orelse return error.MissingTestContext,
        ));
        if (self.calls >= self.responses.len) return null;
        self.uris[self.calls] = uri;
        const response = self.responses[self.calls];
        self.calls += 1;
        if (response.len > output_buffer.len) return response.len;
        @memcpy(output_buffer[0..response.len], response);
        return response.len;
    }

    fn fetcher(self: *TestFetcher) Fetcher {
        return .{ .context = self, .fetch = callback };
    }
};

test "caIssuers fetch accepts DER and deduplicates responses" {
    const vectors = @import("testdata/path_vectors.zig");
    var seed = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    // Keep a structurally valid certificate with the same AIA while making it
    // distinct from any fetched response. Signature verification is outside
    // the retrieval layer.
    seed[seed.len - 1] ^= 1;
    const issuer = @embedFile("testdata/ca.der");
    const responses = [_][]const u8{ issuer, issuer };
    var context = TestFetcher{ .responses = &responses };
    var storage: [4096]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    var output: [4][]const u8 = undefined;

    const result = try resolve(
        &storage,
        &scratch,
        &output,
        &.{&seed},
        context.fetcher(),
        .{ .max_certificates = output.len },
    );
    try std.testing.expectEqual(@as(usize, 2), result.fetches);
    try std.testing.expectEqual(@as(usize, 2), context.calls);
    try std.testing.expectEqual(@as(usize, 1), result.certificates.len);
    try std.testing.expectEqual(issuer.len, result.storage_used);
    try std.testing.expectEqualSlices(u8, issuer, result.certificates[0]);
    try std.testing.expectEqualStrings(
        "http://ca.example.test/issuer.der",
        context.uris[0],
    );
    try std.testing.expectEqualStrings(
        "https://backup.example.test/issuer.p7c",
        context.uris[1],
    );
}

test "caIssuers fetch accepts CMS and stops recursive URI cycles" {
    const vectors = @import("testdata/path_vectors.zig");
    var seed = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    seed[seed.len - 1] ^= 1;
    const fetched = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    const cms = decodeHex(vectors.aia_ca_issuers_certs_only_hex);
    const responses = [_][]const u8{ &cms, &cms };
    var context = TestFetcher{ .responses = &responses };
    var storage: [4096]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    var output: [4][]const u8 = undefined;

    const result = try resolve(
        &storage,
        &scratch,
        &output,
        &.{&seed},
        context.fetcher(),
        .{ .max_certificates = output.len },
    );
    // The fetched certificate repeats both source URIs. URI deduplication
    // prevents the recursive walk from fetching either one again.
    try std.testing.expectEqual(@as(usize, 2), result.fetches);
    try std.testing.expectEqual(@as(usize, 1), result.certificates.len);
    try std.testing.expectEqualSlices(u8, &fetched, result.certificates[0]);

    var budget_context = TestFetcher{ .responses = &responses };
    const budgeted = try resolve(
        &storage,
        &scratch,
        &output,
        &.{&seed},
        budget_context.fetcher(),
        .{ .max_fetches = 1, .max_certificates = output.len },
    );
    try std.testing.expectEqual(@as(usize, 1), budgeted.fetches);
    try std.testing.expectEqual(@as(usize, 1), budget_context.calls);
    try std.testing.expectEqual(@as(usize, 1), budgeted.certificates.len);
}

test "caIssuers fetch enforces caller storage output and response limits" {
    const vectors = @import("testdata/path_vectors.zig");
    var seed = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    seed[seed.len - 1] ^= 1;
    const first = @embedFile("testdata/ca.der");
    const second = @embedFile("testdata/server.der");
    const responses = [_][]const u8{ first, second };
    var scratch: [4096]u8 = undefined;
    var storage: [4096]u8 = undefined;
    var output: [2][]const u8 = undefined;

    var storage_context = TestFetcher{ .responses = &responses };
    try std.testing.expectError(
        error.IssuerStorageTooSmall,
        resolve(
            storage[0 .. first.len - 1],
            &scratch,
            &output,
            &.{&seed},
            storage_context.fetcher(),
            .{ .max_certificates = output.len },
        ),
    );

    var certificate_context = TestFetcher{ .responses = &responses };
    try std.testing.expectError(
        error.TooManyFetchedCertificates,
        resolve(
            &storage,
            &scratch,
            output[0..1],
            &.{&seed},
            certificate_context.fetcher(),
            .{ .max_certificates = 1 },
        ),
    );

    var response_context = TestFetcher{ .responses = &responses };
    try std.testing.expectError(
        error.InvalidIssuerResponse,
        resolve(
            &storage,
            scratch[0 .. first.len - 1],
            &output,
            &.{&seed},
            response_context.fetcher(),
            .{
                .max_certificates = output.len,
                .max_response_bytes = first.len - 1,
                .fail_on_invalid_response = true,
            },
        ),
    );

    var invalid_context = TestFetcher{ .responses = &responses };
    try std.testing.expectError(
        error.InvalidIssuerFetchLimits,
        resolve(
            &storage,
            &scratch,
            output[0..0],
            &.{&seed},
            invalid_context.fetcher(),
            .{},
        ),
    );
    try std.testing.expectError(
        error.InvalidIssuerFetchLimits,
        resolve(
            storage[0..1024],
            storage[512..1536],
            &output,
            &.{&seed},
            invalid_context.fetcher(),
            .{ .max_certificates = output.len },
        ),
    );
    try std.testing.expectError(
        error.InvalidIssuerFetchLimits,
        resolve(
            &storage,
            seed[0..256],
            &output,
            &.{&seed},
            invalid_context.fetcher(),
            .{ .max_certificates = output.len },
        ),
    );
}

test "caIssuers fetch requires explicit opt-in for BER certs-only" {
    const vectors = @import("testdata/path_vectors.zig");
    var seed = decodeHex(vectors.aia_ca_issuers_certificate_hex);
    seed[seed.len - 1] ^= 1;
    const issuer = @embedFile("testdata/ca.der");
    const ber = try berCertificateSet(std.testing.allocator, issuer);
    defer std.testing.allocator.free(ber);
    const responses = [_][]const u8{ber};
    var storage: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    var output: [2][]const u8 = undefined;

    var strict_context = TestFetcher{ .responses = &responses };
    try std.testing.expectError(
        error.InvalidCertificateResponse,
        resolve(
            &storage,
            &scratch,
            &output,
            &.{&seed},
            strict_context.fetcher(),
            .{
                .max_fetches = 1,
                .max_certificates = output.len,
                .fail_on_invalid_response = true,
            },
        ),
    );

    var ber_context = TestFetcher{ .responses = &responses };
    const result = try resolve(
        &storage,
        &scratch,
        &output,
        &.{&seed},
        ber_context.fetcher(),
        .{
            .max_fetches = 1,
            .max_certificates = output.len,
            .allow_ber_certs_only = true,
        },
    );
    try std.testing.expectEqual(@as(usize, 1), result.fetches);
    try std.testing.expectEqual(@as(usize, 1), result.certificates.len);
    try std.testing.expectEqualSlices(u8, issuer, result.certificates[0]);
}

fn berCertificateSet(
    allocator: std.mem.Allocator,
    certificate: []const u8,
) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(
        allocator,
        "\x30\x80" ++
            "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" ++
            "\xa0\x80\x30\x80\x02\x01\x01" ++
            "\x31\x80\x00\x00" ++
            "\x30\x80\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01" ++
            "\x00\x00\xa0\x80",
    );
    try result.appendSlice(allocator, certificate);
    try result.appendSlice(
        allocator,
        "\x00\x00\x31\x80\x00\x00" ++
            "\x00\x00\x00\x00\x00\x00",
    );
    return result.toOwnedSlice(allocator);
}

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var result: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
