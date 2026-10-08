//! Strict RFC 5280 certificate revocation lists.
//!
//! A list is returned only after issuer, signature, update-window, extension,
//! and revoked-entry validation succeeds. Base/delta composition and directly
//! delegated indirect CRLs preserve scope and reason coverage. Supported
//! signatures are Ed25519,
//! ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, and RSA PKCS#1
//! v1.5 or RSA-PSS with SHA-256/384/512 and 1024-4096-bit keys; other
//! algorithms fail explicitly.

const std = @import("std");
const certificate_compat = @import("certificate.zig");
const distinguished_name = @import("distinguished_name.zig");
const x509_signature = @import("signature.zig");
const trust = @import("trust.zig");

const Certificate = std.crypto.Certificate;

pub const Error = error{
    InvalidCrl,
    InvalidCrlSignature,
    UnsupportedSignatureAlgorithm,
    InvalidIssuer,
    IssuerMismatch,
    CrlNotYetValid,
    CrlExpired,
    UnsupportedCriticalExtension,
    CertificateSerialInvalid,
    InvalidDeltaCrl,
    CrlScopeMismatch,
    TooManyDistributionPoints,
    TooManyDistributionPointNames,
    TooManyDistributionPointUris,
    FetchedCrlTooLarge,
    InvalidFetchLimits,
    InvalidFetchResponse,
    FetchMetadataTooLarge,
};

const oid_crl_number = [_]u8{ 0x55, 0x1d, 0x14 };
const oid_reason_code = [_]u8{ 0x55, 0x1d, 0x15 };
const oid_invalidity_date = [_]u8{ 0x55, 0x1d, 0x18 };
const oid_delta_crl_indicator = [_]u8{ 0x55, 0x1d, 0x1b };
const oid_issuing_distribution_point = [_]u8{ 0x55, 0x1d, 0x1c };
const oid_certificate_issuer = [_]u8{ 0x55, 0x1d, 0x1d };
const oid_authority_key_identifier = [_]u8{ 0x55, 0x1d, 0x23 };

pub const Reason = enum(u8) {
    unspecified = 0,
    key_compromise = 1,
    ca_compromise = 2,
    affiliation_changed = 3,
    superseded = 4,
    cessation_of_operation = 5,
    certificate_hold = 6,
    remove_from_crl = 8,
    privilege_withdrawn = 9,
    aa_compromise = 10,
};

const EntryStatus = union(enum) {
    not_listed,
    revoked: Reason,
    remove_from_crl,
};

const all_reason_mask: u8 = 0xff;
const max_distribution_points = 32;
const max_names_per_distribution_point = 32;
const max_distribution_point_uris = 64;

/// Allocation-free iterator over ordered absolute URI names in an RFC 5280
/// CRLDistributionPoints or FreshestCRL extension. Returned slices borrow the
/// certificate or CRL supplied to the constructor.
pub const DistributionPointUrls = struct {
    encoded_points: []const u8 = &.{},
    point_offset: usize = 0,
    encoded_names: []const u8 = &.{},
    name_offset: usize = 0,
    point_count: usize = 0,
    name_count: usize = 0,
    seen_uris: [max_distribution_point_uris][]const u8 = undefined,
    seen_uri_count: usize = 0,

    pub fn next(self: *DistributionPointUrls) Error!?[]const u8 {
        while (true) {
            var names = Reader{
                .bytes = self.encoded_names,
                .offset = self.name_offset,
            };
            name_loop: while (names.next() catch return error.InvalidCrl) |name| {
                self.name_offset = names.offset;
                self.name_count += 1;
                if (self.name_count > max_names_per_distribution_point) {
                    return error.TooManyDistributionPointNames;
                }
                if (!validGeneralName(name)) return error.InvalidCrl;
                if (name.tag == 0x86) {
                    for (self.seen_uris[0..self.seen_uri_count]) |seen| {
                        if (std.mem.eql(u8, seen, name.value)) continue :name_loop;
                    }
                    if (self.seen_uri_count == self.seen_uris.len) {
                        return error.TooManyDistributionPointUris;
                    }
                    self.seen_uris[self.seen_uri_count] = name.value;
                    self.seen_uri_count += 1;
                    return name.value;
                }
            }

            var points = Reader{
                .bytes = self.encoded_points,
                .offset = self.point_offset,
            };
            const encoded_point = (points.next() catch
                return error.InvalidCrl) orelse return null;
            self.point_offset = points.offset;
            self.point_count += 1;
            if (self.point_count > max_distribution_points) {
                return error.TooManyDistributionPoints;
            }
            const point = try parseDistributionPoint(encoded_point);
            const point_name = point.name orelse continue;
            var wrapper = Reader{ .bytes = point_name };
            const choice = (wrapper.next() catch return error.InvalidCrl) orelse
                return error.InvalidCrl;
            if (!wrapper.done()) return error.InvalidCrl;
            if (choice.tag != 0xa0) continue;
            self.encoded_names = choice.value;
            self.name_offset = 0;
            self.name_count = 0;
        }
    }
};

pub fn distributionPointUrls(
    certificate_der: []const u8,
) Error!DistributionPointUrls {
    _ = parseCertificate(certificate_der) catch
        return error.CertificateSerialInvalid;
    const encoded = (certificateExtensionValue(
        certificate_der,
        &.{ 0x55, 0x1d, 0x1f },
    ) catch return error.InvalidCrl) orelse return .{};
    return distributionPointUrlsFromValue(encoded);
}

pub fn certificateFreshestCrlUrls(
    certificate_der: []const u8,
) Error!DistributionPointUrls {
    _ = parseCertificate(certificate_der) catch
        return error.CertificateSerialInvalid;
    const encoded = (certificateExtensionValue(
        certificate_der,
        &.{ 0x55, 0x1d, 0x2e },
    ) catch return error.InvalidCrl) orelse return .{};
    return distributionPointUrlsFromValue(encoded);
}

pub fn listFreshestCrlUrls(list: List) Error!DistributionPointUrls {
    return distributionPointUrlsFromValue(list.freshest_crl orelse return .{});
}

pub const Fetcher = struct {
    context: ?*anyopaque = null,
    fetch: *const fn (
        context: ?*anyopaque,
        uri: []const u8,
        output: []u8,
    ) anyerror!?usize,
};

pub const ConditionalRequest = struct {
    uri: []const u8,
    if_none_match: ?[]const u8 = null,
    if_modified_since: ?[]const u8 = null,
};

pub const ConditionalFetchResult = union(enum) {
    not_modified,
    fetched: struct {
        len: usize,
        etag: ?[]const u8 = null,
        last_modified: ?[]const u8 = null,
    },
};

pub const ConditionalFetcher = struct {
    context: ?*anyopaque = null,
    fetch: *const fn (
        context: ?*anyopaque,
        request: ConditionalRequest,
        output: []u8,
    ) anyerror!ConditionalFetchResult,
};

pub const CacheOptions = struct {
    max_response_bytes: usize = 1024 * 1024,
    initial_backoff_seconds: u32 = 1,
    max_backoff_seconds: u32 = 5 * 60,
};

pub const DeltaCache = struct {
    body_storage: []u8,
    uri_storage: []u8,
    etag_storage: []u8,
    last_modified_storage: []u8,
    body_len: usize = 0,
    uri_len: usize = 0,
    etag_len: ?usize = null,
    last_modified_len: ?usize = null,
    consecutive_failures: u8 = 0,
    retry_after_seconds: i64 = 0,

    pub fn init(
        body_storage: []u8,
        uri_storage: []u8,
        etag_storage: []u8,
        last_modified_storage: []u8,
    ) DeltaCache {
        return .{
            .body_storage = body_storage,
            .uri_storage = uri_storage,
            .etag_storage = etag_storage,
            .last_modified_storage = last_modified_storage,
        };
    }

    pub fn encoded(self: *const DeltaCache) ?[]const u8 {
        if (self.body_len == 0) return null;
        return self.body_storage[0..self.body_len];
    }

    pub fn sourceUri(self: *const DeltaCache) ?[]const u8 {
        if (self.uri_len == 0) return null;
        return self.uri_storage[0..self.uri_len];
    }

    pub fn etag(self: *const DeltaCache) ?[]const u8 {
        const len = self.etag_len orelse return null;
        return self.etag_storage[0..len];
    }

    pub fn lastModified(self: *const DeltaCache) ?[]const u8 {
        const len = self.last_modified_len orelse return null;
        return self.last_modified_storage[0..len];
    }
};

pub const CacheRefresh = union(enum) {
    updated: FetchedDelta,
    not_modified: FetchedDelta,
    deferred,
};

/// Conditionally refresh one delta-CRL location. The old cache remains intact
/// until the fetched CRL and all base/delta invariants have been verified.
pub fn refreshDeltaCache(
    cache: *DeltaCache,
    scratch_buffer: []u8,
    base: List,
    issuer_certificate_der: []const u8,
    now_seconds: i64,
    uri: []const u8,
    fetcher: ConditionalFetcher,
    options: CacheOptions,
) !CacheRefresh {
    if (now_seconds < 0 or !validAbsoluteIa5Uri(uri) or
        options.max_response_bytes == 0 or
        options.initial_backoff_seconds == 0 or
        options.max_backoff_seconds < options.initial_backoff_seconds)
    {
        return error.InvalidFetchLimits;
    }
    if (now_seconds < cache.retry_after_seconds) return .deferred;
    const response_limit = @min(
        options.max_response_bytes,
        @min(cache.body_storage.len, scratch_buffer.len),
    );
    if (response_limit == 0 or
        slicesOverlap(cache.body_storage[0..response_limit], scratch_buffer[0..response_limit]))
    {
        return error.InvalidFetchLimits;
    }
    const same_uri = cache.uri_len != 0 and
        std.mem.eql(u8, cache.uri_storage[0..cache.uri_len], uri);
    const request = ConditionalRequest{
        .uri = uri,
        .if_none_match = if (same_uri and cache.etag_len != null)
            cache.etag_storage[0..cache.etag_len.?]
        else
            null,
        .if_modified_since = if (same_uri and cache.last_modified_len != null)
            cache.last_modified_storage[0..cache.last_modified_len.?]
        else
            null,
    };
    const response = fetcher.fetch(
        fetcher.context,
        request,
        scratch_buffer[0..response_limit],
    ) catch |err| {
        recordCacheFailure(cache, now_seconds, options);
        return err;
    };
    switch (response) {
        .not_modified => {
            if (!same_uri or cache.body_len == 0) {
                recordCacheFailure(cache, now_seconds, options);
                return error.InvalidFetchResponse;
            }
            const encoded = cache.body_storage[0..cache.body_len];
            const list = parseAndVerify(
                encoded,
                issuer_certificate_der,
                now_seconds,
            ) catch |err| {
                recordCacheFailure(cache, now_seconds, options);
                return err;
            };
            _ = CombinedList.init(base, list) catch |err| {
                recordCacheFailure(cache, now_seconds, options);
                return err;
            };
            resetCacheFailures(cache);
            return .{ .not_modified = .{ .encoded = encoded, .list = list } };
        },
        .fetched => |fetched| {
            if (fetched.len == 0 or fetched.len > response_limit) {
                recordCacheFailure(cache, now_seconds, options);
                return error.FetchedCrlTooLarge;
            }
            if (uri.len > cache.uri_storage.len or
                !metadataFits(fetched.etag, cache.etag_storage) or
                !metadataFits(fetched.last_modified, cache.last_modified_storage))
            {
                recordCacheFailure(cache, now_seconds, options);
                return error.FetchMetadataTooLarge;
            }
            const candidate = parseAndVerify(
                scratch_buffer[0..fetched.len],
                issuer_certificate_der,
                now_seconds,
            ) catch |err| {
                recordCacheFailure(cache, now_seconds, options);
                return err;
            };
            _ = CombinedList.init(base, candidate) catch |err| {
                recordCacheFailure(cache, now_seconds, options);
                return err;
            };
            @memcpy(cache.body_storage[0..fetched.len], scratch_buffer[0..fetched.len]);
            @memcpy(cache.uri_storage[0..uri.len], uri);
            cache.body_len = fetched.len;
            cache.uri_len = uri.len;
            cache.etag_len = try copyMetadata(cache.etag_storage, fetched.etag);
            cache.last_modified_len = try copyMetadata(
                cache.last_modified_storage,
                fetched.last_modified,
            );
            resetCacheFailures(cache);
            const encoded = cache.body_storage[0..cache.body_len];
            return .{ .updated = .{
                .encoded = encoded,
                .list = try parseAndVerify(
                    encoded,
                    issuer_certificate_der,
                    now_seconds,
                ),
            } };
        },
    }
}

fn metadataFits(value: ?[]const u8, storage: []const u8) bool {
    const bytes = value orelse return true;
    if (bytes.len == 0 or bytes.len > storage.len) return false;
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn copyMetadata(storage: []u8, value: ?[]const u8) !?usize {
    const bytes = value orelse return null;
    if (!metadataFits(bytes, storage)) return error.FetchMetadataTooLarge;
    @memcpy(storage[0..bytes.len], bytes);
    return bytes.len;
}

fn resetCacheFailures(cache: *DeltaCache) void {
    cache.consecutive_failures = 0;
    cache.retry_after_seconds = 0;
}

fn recordCacheFailure(
    cache: *DeltaCache,
    now_seconds: i64,
    options: CacheOptions,
) void {
    cache.consecutive_failures +|= 1;
    const shift: u5 = @intCast(@min(cache.consecutive_failures - 1, 31));
    const scaled = @as(u64, options.initial_backoff_seconds) << shift;
    const delay = @min(scaled, options.max_backoff_seconds);
    cache.retry_after_seconds = std.math.add(
        i64,
        now_seconds,
        @intCast(delay),
    ) catch std.math.maxInt(i64);
}

pub const FetchOptions = struct {
    max_attempts: usize = 8,
    max_response_bytes: usize = 1024 * 1024,
    fail_on_fetch_error: bool = false,
    fail_on_invalid_response: bool = false,
};

pub const FetchedDelta = struct {
    encoded: []const u8,
    list: List,
};

/// Fetch every advertised location up to the configured bound and retain the
/// newest compatible current delta CRL. Network and storage policy remain in
/// the caller-provided callback; this function performs no allocation.
pub fn fetchLatestDelta(
    best_buffer: []u8,
    scratch_buffer: []u8,
    base: List,
    issuer_certificate_der: []const u8,
    now_seconds: i64,
    advertised_urls: DistributionPointUrls,
    fetcher: Fetcher,
    options: FetchOptions,
) !?FetchedDelta {
    if (base.isDelta() or options.max_attempts == 0 or
        options.max_attempts > max_distribution_point_uris or
        options.max_response_bytes == 0)
    {
        return error.InvalidFetchLimits;
    }
    const response_limit = @min(
        options.max_response_bytes,
        @min(best_buffer.len, scratch_buffer.len),
    );
    if (response_limit == 0 or
        slicesOverlap(
            best_buffer[0..response_limit],
            scratch_buffer[0..response_limit],
        ))
    {
        return error.InvalidFetchLimits;
    }
    var urls = advertised_urls;
    var attempts: usize = 0;
    var best_len: usize = 0;
    var best_this_update: u64 = 0;
    var best_number: [20]u8 = undefined;
    var best_number_len: usize = 0;
    while (try urls.next()) |uri| {
        if (attempts == options.max_attempts) break;
        attempts += 1;
        const fetched_len = (fetcher.fetch(
            fetcher.context,
            uri,
            scratch_buffer[0..response_limit],
        ) catch |err| {
            if (options.fail_on_fetch_error) return err;
            continue;
        }) orelse continue;
        if (fetched_len == 0 or fetched_len > response_limit) {
            if (options.fail_on_invalid_response) {
                return error.FetchedCrlTooLarge;
            }
            continue;
        }
        const candidate = parseAndVerify(
            scratch_buffer[0..fetched_len],
            issuer_certificate_der,
            now_seconds,
        ) catch |err| {
            if (options.fail_on_invalid_response) return err;
            continue;
        };
        _ = CombinedList.init(base, candidate) catch |err| {
            if (options.fail_on_invalid_response) return err;
            continue;
        };
        const number = candidate.crl_number orelse unreachable;
        if (best_len == 0 or candidate.this_update > best_this_update or
            (candidate.this_update == best_this_update and
                compareUnsigned(
                    number,
                    best_number[0..best_number_len],
                ) == .gt))
        {
            if (fetched_len > best_buffer.len) return error.FetchedCrlTooLarge;
            @memcpy(best_buffer[0..fetched_len], scratch_buffer[0..fetched_len]);
            best_len = fetched_len;
            best_this_update = candidate.this_update;
            @memcpy(best_number[0..number.len], number);
            best_number_len = number.len;
        }
    }
    if (best_len == 0) return null;
    const encoded = best_buffer[0..best_len];
    return .{
        .encoded = encoded,
        .list = try parseAndVerify(encoded, issuer_certificate_der, now_seconds),
    };
}

fn slicesOverlap(a: []const u8, b: []const u8) bool {
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    const a_end = std.math.add(usize, a_start, a.len) catch return true;
    const b_end = std.math.add(usize, b_start, b.len) catch return true;
    return a_start < b_end and b_start < a_end;
}

fn distributionPointUrlsFromValue(
    encoded: []const u8,
) Error!DistributionPointUrls {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCrl;
    const result = DistributionPointUrls{ .encoded_points = sequence.value };
    var validation = result;
    while (try validation.next()) |_| {}
    return result;
}

pub const IssuingDistributionPoint = struct {
    encoded: []const u8,
    distribution_point: ?[]const u8 = null,
    indirect_crl: bool = false,
    only_contains_user_certs: bool = false,
    only_contains_ca_certs: bool = false,
    only_some_reasons: ?[]const u8 = null,
};

pub const List = struct {
    der: []const u8,
    issuer_certificate_der: []const u8,
    issuer_name: []const u8,
    revoked_entries: []const u8,
    this_update: u64,
    next_update: u64,
    crl_number: ?[]const u8 = null,
    delta_base_number: ?[]const u8 = null,
    authority_key_identifier: ?[]const u8 = null,
    issuing_distribution_point: ?IssuingDistributionPoint = null,
    freshest_crl: ?[]const u8 = null,

    pub fn isRevoked(
        self: List,
        certificate_der: []const u8,
    ) Error!bool {
        if (self.isDelta()) return error.InvalidDeltaCrl;
        const certificate = parseCertificate(certificate_der) catch
            return error.CertificateSerialInvalid;
        const serial = certificateSerial(certificate_der) catch
            return error.CertificateSerialInvalid;
        return switch (try self.entryStatus(certificate.issuer(), serial)) {
            .not_listed, .remove_from_crl => false,
            .revoked => true,
        };
    }

    fn entryStatus(
        self: List,
        certificate_issuer: []const u8,
        serial: []const u8,
    ) Error!EntryStatus {
        var current_issuer_names: ?[]const u8 = null;
        var entries = Reader{ .bytes = self.revoked_entries };
        while (entries.next() catch return error.InvalidCrl) |entry| {
            const parsed = parseRevokedEntry(
                entry,
                self.delta_base_number != null,
                self.isIndirect(),
            ) catch
                return error.InvalidCrl;
            if (parsed.certificate_issuer_names) |names| {
                current_issuer_names = names;
            }
            const issuer_matches = if (current_issuer_names) |names|
                generalNamesContainDirectoryName(names, certificate_issuer)
            else
                distinguished_name.eql(
                    certificate_issuer,
                    self.issuer_name,
                ) catch false;
            if (!issuer_matches or !std.mem.eql(u8, parsed.serial, serial)) {
                continue;
            }
            if (parsed.reason == .remove_from_crl) return .remove_from_crl;
            return .{ .revoked = parsed.reason };
        }
        if (!self.isIndirect() and current_issuer_names == null and
            !(distinguished_name.eql(
                certificate_issuer,
                self.issuer_name,
            ) catch false))
        {
            return error.IssuerMismatch;
        }
        return .not_listed;
    }

    pub fn isDelta(self: List) bool {
        return self.delta_base_number != null;
    }

    pub fn isIndirect(self: List) bool {
        return if (self.issuing_distribution_point) |point|
            point.indirect_crl
        else
            false;
    }

    fn hasCompleteScope(self: List) bool {
        return self.issuing_distribution_point == null;
    }
};

pub const CombinedList = struct {
    base: List,
    delta: List,

    pub fn init(base: List, delta: List) Error!CombinedList {
        if (base.isDelta() or !delta.isDelta()) return error.InvalidDeltaCrl;
        if (!(distinguished_name.eql(
            base.issuer_name,
            delta.issuer_name,
        ) catch false)) return error.CrlScopeMismatch;
        if (!sameOptionalBytes(
            if (base.issuing_distribution_point) |point| point.encoded else null,
            if (delta.issuing_distribution_point) |point| point.encoded else null,
        )) return error.CrlScopeMismatch;
        if (!sameOptionalBytes(
            base.authority_key_identifier,
            delta.authority_key_identifier,
        )) return error.CrlScopeMismatch;
        if (!sameIssuerKey(base, delta)) return error.CrlScopeMismatch;
        const base_number = base.crl_number orelse return error.InvalidDeltaCrl;
        const delta_number = delta.crl_number orelse return error.InvalidDeltaCrl;
        const referenced = delta.delta_base_number orelse
            return error.InvalidDeltaCrl;
        if (compareUnsigned(base_number, referenced) == .lt or
            compareUnsigned(base_number, delta_number) != .lt or
            delta.this_update < base.this_update)
        {
            return error.InvalidDeltaCrl;
        }
        return .{ .base = base, .delta = delta };
    }

    pub fn isRevoked(
        self: CombinedList,
        certificate_der: []const u8,
    ) Error!bool {
        const certificate = parseCertificate(certificate_der) catch
            return error.CertificateSerialInvalid;
        const serial = certificateSerial(certificate_der) catch
            return error.CertificateSerialInvalid;
        return switch (try self.delta.entryStatus(
            certificate.issuer(),
            serial,
        )) {
            .remove_from_crl => false,
            .revoked => true,
            .not_listed => switch (try self.base.entryStatus(
                certificate.issuer(),
                serial,
            )) {
                .revoked => true,
                .not_listed, .remove_from_crl => false,
            },
        };
    }

    fn hasCompleteScope(self: CombinedList) bool {
        return self.delta.hasCompleteScope();
    }
};

pub const SignerPathOptions = struct {
    path_limits: trust.PathLimits = .{},
    certificate_policy: trust.CertificatePolicy = .{},
    /// Must be independent of the CRL currently being authorized.
    revocation: ?trust.RevocationPolicy = null,
};

pub const SharedAnchorPathOptions = struct {
    path_limits: trust.PathLimits = .{},
    certificate_policy: trust.CertificatePolicy = .{},
    /// Independent status source for the certificate-issuer path.
    certificate_issuer_revocation: ?trust.RevocationPolicy = null,
    /// Independent status source for the CRL-signer path.
    signer_revocation: ?trust.RevocationPolicy = null,
};

/// An indirect CRL whose signer is either the certificate issuer itself or a
/// directly issued cRLSign delegate. The target certificate must still name
/// this CRL issuer in a cRLIssuer distribution point before the list is used.
pub const AuthorizedIndirectList = struct {
    list: List,
    certificate_issuer_der: []const u8,

    pub fn init(
        list: List,
        certificate_issuer_der: []const u8,
        now_seconds: i64,
    ) Error!AuthorizedIndirectList {
        if (!list.isIndirect() or list.isDelta()) return error.InvalidCrl;
        try authorizeIndirectSigner(list, certificate_issuer_der, now_seconds);
        return .{
            .list = list,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithSignerChain(
        allocator: std.mem.Allocator,
        list: List,
        certificate_issuer_der: []const u8,
        signer_chain: []const []const u8,
        now_seconds: i64,
        limits: trust.PathLimits,
        policy: trust.CertificatePolicy,
    ) !AuthorizedIndirectList {
        if (!list.isIndirect() or list.isDelta()) return error.InvalidCrl;
        try authorizeIndirectSignerChain(
            allocator,
            list,
            certificate_issuer_der,
            signer_chain,
            now_seconds,
            limits,
            policy,
            null,
        );
        return .{
            .list = list,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithSignerChainOptions(
        allocator: std.mem.Allocator,
        list: List,
        certificate_issuer_der: []const u8,
        signer_chain: []const []const u8,
        now_seconds: i64,
        options: SignerPathOptions,
    ) !AuthorizedIndirectList {
        if (!list.isIndirect() or list.isDelta()) return error.InvalidCrl;
        try authorizeIndirectSignerChain(
            allocator,
            list,
            certificate_issuer_der,
            signer_chain,
            now_seconds,
            options.path_limits,
            options.certificate_policy,
            options.revocation,
        );
        return .{
            .list = list,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithTrustAnchor(
        allocator: std.mem.Allocator,
        list: List,
        certificate_issuer_der: []const u8,
        certificate_issuer_chain: []const []const u8,
        signer_chain: []const []const u8,
        trust_anchor_der: []const u8,
        now_seconds: i64,
        limits: trust.PathLimits,
        policy: trust.CertificatePolicy,
    ) !AuthorizedIndirectList {
        if (!list.isIndirect() or list.isDelta()) return error.InvalidCrl;
        try authorizeIndirectSignerToSharedAnchor(
            allocator,
            list,
            certificate_issuer_der,
            certificate_issuer_chain,
            signer_chain,
            trust_anchor_der,
            now_seconds,
            limits,
            policy,
            null,
            null,
        );
        return .{
            .list = list,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithTrustAnchorOptions(
        allocator: std.mem.Allocator,
        list: List,
        certificate_issuer_der: []const u8,
        certificate_issuer_chain: []const []const u8,
        signer_chain: []const []const u8,
        trust_anchor_der: []const u8,
        now_seconds: i64,
        options: SharedAnchorPathOptions,
    ) !AuthorizedIndirectList {
        if (!list.isIndirect() or list.isDelta()) return error.InvalidCrl;
        try authorizeIndirectSignerToSharedAnchor(
            allocator,
            list,
            certificate_issuer_der,
            certificate_issuer_chain,
            signer_chain,
            trust_anchor_der,
            now_seconds,
            options.path_limits,
            options.certificate_policy,
            options.certificate_issuer_revocation,
            options.signer_revocation,
        );
        return .{
            .list = list,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }
};

/// An authenticated indirect delta CRL combined with its matching complete
/// base. Both lists have already passed signature, issuer, AKI, scope, number,
/// and update-window checks.
pub const AuthorizedIndirectCombinedList = struct {
    combined: CombinedList,
    certificate_issuer_der: []const u8,

    pub fn init(
        combined: CombinedList,
        certificate_issuer_der: []const u8,
        now_seconds: i64,
    ) Error!AuthorizedIndirectCombinedList {
        if (!combined.base.isIndirect() or !combined.delta.isIndirect()) {
            return error.InvalidCrl;
        }
        try authorizeIndirectSigner(
            combined.delta,
            certificate_issuer_der,
            now_seconds,
        );
        return .{
            .combined = combined,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithSignerChain(
        allocator: std.mem.Allocator,
        combined: CombinedList,
        certificate_issuer_der: []const u8,
        signer_chain: []const []const u8,
        now_seconds: i64,
        limits: trust.PathLimits,
        policy: trust.CertificatePolicy,
    ) !AuthorizedIndirectCombinedList {
        if (!combined.base.isIndirect() or !combined.delta.isIndirect()) {
            return error.InvalidCrl;
        }
        try authorizeIndirectSignerChain(
            allocator,
            combined.delta,
            certificate_issuer_der,
            signer_chain,
            now_seconds,
            limits,
            policy,
            null,
        );
        return .{
            .combined = combined,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithSignerChainOptions(
        allocator: std.mem.Allocator,
        combined: CombinedList,
        certificate_issuer_der: []const u8,
        signer_chain: []const []const u8,
        now_seconds: i64,
        options: SignerPathOptions,
    ) !AuthorizedIndirectCombinedList {
        if (!combined.base.isIndirect() or !combined.delta.isIndirect()) {
            return error.InvalidCrl;
        }
        try authorizeIndirectSignerChain(
            allocator,
            combined.delta,
            certificate_issuer_der,
            signer_chain,
            now_seconds,
            options.path_limits,
            options.certificate_policy,
            options.revocation,
        );
        return .{
            .combined = combined,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithTrustAnchor(
        allocator: std.mem.Allocator,
        combined: CombinedList,
        certificate_issuer_der: []const u8,
        certificate_issuer_chain: []const []const u8,
        signer_chain: []const []const u8,
        trust_anchor_der: []const u8,
        now_seconds: i64,
        limits: trust.PathLimits,
        policy: trust.CertificatePolicy,
    ) !AuthorizedIndirectCombinedList {
        if (!combined.base.isIndirect() or !combined.delta.isIndirect()) {
            return error.InvalidCrl;
        }
        try authorizeIndirectSignerToSharedAnchor(
            allocator,
            combined.delta,
            certificate_issuer_der,
            certificate_issuer_chain,
            signer_chain,
            trust_anchor_der,
            now_seconds,
            limits,
            policy,
            null,
            null,
        );
        return .{
            .combined = combined,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }

    pub fn initWithTrustAnchorOptions(
        allocator: std.mem.Allocator,
        combined: CombinedList,
        certificate_issuer_der: []const u8,
        certificate_issuer_chain: []const []const u8,
        signer_chain: []const []const u8,
        trust_anchor_der: []const u8,
        now_seconds: i64,
        options: SharedAnchorPathOptions,
    ) !AuthorizedIndirectCombinedList {
        if (!combined.base.isIndirect() or !combined.delta.isIndirect()) {
            return error.InvalidCrl;
        }
        try authorizeIndirectSignerToSharedAnchor(
            allocator,
            combined.delta,
            certificate_issuer_der,
            certificate_issuer_chain,
            signer_chain,
            trust_anchor_der,
            now_seconds,
            options.path_limits,
            options.certificate_policy,
            options.certificate_issuer_revocation,
            options.signer_revocation,
        );
        return .{
            .combined = combined,
            .certificate_issuer_der = certificate_issuer_der,
        };
    }
};

/// A caller-owned set of already authenticated CRLs exposed as a trust-layer
/// revocation policy. Lists and their issuer certificates must outlive it.
pub const VerifiedSet = struct {
    lists: []const List,
    combined_lists: []const CombinedList = &.{},
    indirect_lists: []const AuthorizedIndirectList = &.{},
    indirect_combined_lists: []const AuthorizedIndirectCombinedList = &.{},

    pub fn policy(
        self: *const VerifiedSet,
        require_status: bool,
    ) trust.RevocationPolicy {
        return .{
            .context = self,
            .check = check,
            .require_status = require_status,
        };
    }

    fn check(
        context: *const anyopaque,
        certificate_der: []const u8,
        issuer_der: []const u8,
    ) anyerror!trust.RevocationStatus {
        const self: *const VerifiedSet = @ptrCast(@alignCast(context));
        const actual_issuer = try parseCertificate(issuer_der);
        var has_supplied_delta = false;
        for (self.lists) |list| {
            has_supplied_delta = has_supplied_delta or list.isDelta();
        }
        const certificate_advertises_delta = has_supplied_delta and
            try certificateAdvertisesDelta(certificate_der);
        var reasons_mask: u8 = 0;
        for (self.indirect_combined_lists) |authorized| {
            const expected_issuer = parseCertificate(
                authorized.certificate_issuer_der,
            ) catch continue;
            if (!sameCertificateIdentity(expected_issuer, actual_issuer)) {
                continue;
            }
            const coverage = certificateIndirectCrlCoverage(
                certificate_der,
                authorized.combined.delta,
            ) orelse continue;
            if (try authorized.combined.isRevoked(certificate_der)) {
                return .revoked;
            }
            reasons_mask |= coverage;
            if (reasons_mask == all_reason_mask) return .good;
        }
        for (self.indirect_lists) |authorized| {
            const expected_issuer = parseCertificate(
                authorized.certificate_issuer_der,
            ) catch continue;
            if (!sameCertificateIdentity(expected_issuer, actual_issuer)) {
                continue;
            }
            const coverage = certificateIndirectCrlCoverage(
                certificate_der,
                authorized.list,
            ) orelse continue;
            const certificate = parseCertificate(certificate_der) catch
                return error.CertificateSerialInvalid;
            const serial = certificateSerial(certificate_der) catch
                return error.CertificateSerialInvalid;
            switch (try authorized.list.entryStatus(
                certificate.issuer(),
                serial,
            )) {
                .revoked => return .revoked,
                .remove_from_crl, .not_listed => {},
            }
            reasons_mask |= coverage;
            if (reasons_mask == all_reason_mask) return .good;
        }
        for (self.combined_lists) |combined| {
            if (combined.delta.isIndirect() or
                !authenticatedIssuerMatches(combined.delta, actual_issuer))
            {
                continue;
            }
            const coverage = directCrlCoverage(
                certificate_der,
                combined.delta,
            ) orelse continue;
            const revoked = combined.isRevoked(certificate_der) catch |err| switch (err) {
                error.IssuerMismatch => continue,
                else => |other| return other,
            };
            if (revoked) return .revoked;
            reasons_mask |= coverage;
            if (reasons_mask == all_reason_mask) return .good;
        }

        for (self.lists) |list| {
            if (list.isDelta() or list.isIndirect() or
                isCombinedBase(self.combined_lists, list) or
                !authenticatedIssuerMatches(list, actual_issuer)) continue;
            const automatic_delta = if (list.freshest_crl != null or
                certificate_advertises_delta)
                latestDeltaForBase(self.lists, list)
            else
                null;
            if (automatic_delta) |combined| {
                const coverage = directCrlCoverage(
                    certificate_der,
                    combined.delta,
                ) orelse continue;
                if (try combined.isRevoked(certificate_der)) return .revoked;
                reasons_mask |= coverage;
                if (reasons_mask == all_reason_mask) return .good;
                continue;
            }
            const coverage = directCrlCoverage(
                certificate_der,
                list,
            ) orelse continue;
            const revoked = list.isRevoked(certificate_der) catch |err| switch (err) {
                error.IssuerMismatch => continue,
                else => |other| return other,
            };
            if (revoked) return .revoked;
            reasons_mask |= coverage;
            if (reasons_mask == all_reason_mask) return .good;
        }
        return .unknown;
    }
};

fn authorizeIndirectSigner(
    list: List,
    certificate_issuer_der: []const u8,
    now_seconds: i64,
) Error!void {
    const signer_compatible = certificate_compat.parse(
        list.issuer_certificate_der,
    ) catch return error.InvalidIssuer;
    const signer = signer_compatible.standard;
    const certificate_issuer = certificate_compat.parse(
        certificate_issuer_der,
    ) catch return error.InvalidIssuer;
    if (sameCertificateIdentity(signer, certificate_issuer.standard)) return;
    if (!(distinguished_name.eql(
        signer.issuer(),
        certificate_issuer.standard.subject(),
    ) catch false)) return error.InvalidIssuer;
    certificate_compat.verifySignatureAndValidity(
        signer,
        signer_compatible.signature_algorithm,
        certificate_issuer.standard,
        now_seconds,
    ) catch return error.InvalidIssuer;
}

fn authorizeIndirectSignerChain(
    allocator: std.mem.Allocator,
    list: List,
    certificate_issuer_der: []const u8,
    signer_chain: []const []const u8,
    now_seconds: i64,
    limits: trust.PathLimits,
    policy: trust.CertificatePolicy,
    revocation: ?trust.RevocationPolicy,
) !void {
    if (signer_chain.len == 0) return error.InvalidIssuer;
    const authenticated_signer = parseCertificate(
        list.issuer_certificate_der,
    ) catch return error.InvalidIssuer;
    const supplied_signer = parseCertificate(signer_chain[0]) catch
        return error.InvalidIssuer;
    if (!sameCertificateIdentity(authenticated_signer, supplied_signer)) {
        return error.InvalidIssuer;
    }

    var anchor_bundle: Certificate.Bundle = .empty;
    defer anchor_bundle.deinit(allocator);
    try anchor_bundle.bytes.appendSlice(allocator, certificate_issuer_der);
    anchor_bundle.parseCert(allocator, 0, now_seconds) catch
        return error.InvalidIssuer;
    (trust.CrlSignerBundleVerifier{
        .bundle = &anchor_bundle,
        .now_seconds = now_seconds,
        .path_limits = limits,
        .certificate_policy = policy,
        .revocation = revocation,
    }).verify(signer_chain) catch return error.InvalidIssuer;
}

fn authorizeIndirectSignerToSharedAnchor(
    allocator: std.mem.Allocator,
    list: List,
    certificate_issuer_der: []const u8,
    certificate_issuer_chain: []const []const u8,
    signer_chain: []const []const u8,
    trust_anchor_der: []const u8,
    now_seconds: i64,
    limits: trust.PathLimits,
    policy: trust.CertificatePolicy,
    certificate_issuer_revocation: ?trust.RevocationPolicy,
    signer_revocation: ?trust.RevocationPolicy,
) !void {
    if (certificate_issuer_chain.len == 0 or signer_chain.len == 0) {
        return error.InvalidIssuer;
    }
    const expected_issuer = parseCertificate(certificate_issuer_der) catch
        return error.InvalidIssuer;
    const supplied_issuer = parseCertificate(certificate_issuer_chain[0]) catch
        return error.InvalidIssuer;
    const authenticated_signer = parseCertificate(
        list.issuer_certificate_der,
    ) catch return error.InvalidIssuer;
    const supplied_signer = parseCertificate(signer_chain[0]) catch
        return error.InvalidIssuer;
    if (!sameCertificateIdentity(expected_issuer, supplied_issuer) or
        !sameCertificateIdentity(authenticated_signer, supplied_signer))
    {
        return error.InvalidIssuer;
    }

    var anchor_bundle: Certificate.Bundle = .empty;
    defer anchor_bundle.deinit(allocator);
    try anchor_bundle.bytes.appendSlice(allocator, trust_anchor_der);
    anchor_bundle.parseCert(allocator, 0, now_seconds) catch
        return error.InvalidIssuer;
    (trust.CertificateAuthorityBundleVerifier{
        .bundle = &anchor_bundle,
        .now_seconds = now_seconds,
        .path_limits = limits,
        .certificate_policy = policy,
        .revocation = certificate_issuer_revocation,
    }).verify(certificate_issuer_chain) catch return error.InvalidIssuer;
    (trust.CrlSignerBundleVerifier{
        .bundle = &anchor_bundle,
        .now_seconds = now_seconds,
        .path_limits = limits,
        .certificate_policy = policy,
        .revocation = signer_revocation,
    }).verify(signer_chain) catch return error.InvalidIssuer;
}

fn authenticatedIssuerMatches(
    list: List,
    actual_issuer: Certificate.Parsed,
) bool {
    const authenticated = parseCertificate(
        list.issuer_certificate_der,
    ) catch return false;
    return sameCertificateIdentity(authenticated, actual_issuer);
}

fn sameCertificateIdentity(
    a: Certificate.Parsed,
    b: Certificate.Parsed,
) bool {
    return (distinguished_name.eql(
        a.subject(),
        b.subject(),
    ) catch false) and std.meta.eql(
        a.pub_key_algo,
        b.pub_key_algo,
    ) and std.mem.eql(u8, a.pubKey(), b.pubKey());
}

fn certificateIndirectCrlCoverage(
    certificate_der: []const u8,
    list: List,
) ?u8 {
    const point = list.issuing_distribution_point orelse return null;
    if (!point.indirect_crl) return null;
    if (!crlKindMatchesCertificate(point, certificate_der)) return null;
    const distribution_points = (certificateCrlDistributionPoints(
        certificate_der,
    ) catch return null) orelse return null;
    const idp_reasons = reasonMaskOrAll(point.only_some_reasons) catch
        return null;
    var coverage: u8 = 0;
    var points = Reader{ .bytes = distribution_points };
    while (points.next() catch return null) |encoded_point| {
        const certificate_point = parseDistributionPoint(encoded_point) catch
            return null;
        const crl_issuers = certificate_point.crl_issuer_names orelse continue;
        if (!generalNamesContainDirectoryName(
            crl_issuers,
            list.issuer_name,
        )) continue;
        if (point.distribution_point) |idp_name| {
            if (certificate_point.name) |certificate_name| {
                const certificate_base = singleDirectoryName(crl_issuers) orelse
                    continue;
                if (!distributionPointNamesMatch(
                    idp_name,
                    list.issuer_name,
                    certificate_name,
                    certificate_base,
                )) continue;
            } else if (!distributionPointMatchesGeneralNames(
                idp_name,
                crl_issuers,
            )) continue;
        }
        const dp_reasons = reasonMaskOrAll(certificate_point.reasons) catch
            return null;
        coverage |= idp_reasons & dp_reasons;
    }
    return if (coverage == 0) null else coverage;
}

fn directCrlCoverage(certificate_der: []const u8, list: List) ?u8 {
    if (list.isIndirect()) return null;
    const certificate = parseCertificate(certificate_der) catch return null;
    if (!(distinguished_name.eql(
        certificate.issuer(),
        list.issuer_name,
    ) catch false)) return null;
    const point = list.issuing_distribution_point orelse
        return all_reason_mask;
    if (!crlKindMatchesCertificate(point, certificate_der)) return null;
    const idp_reasons = reasonMaskOrAll(point.only_some_reasons) catch
        return null;
    const idp_name = point.distribution_point orelse return idp_reasons;
    const distribution_points = (certificateCrlDistributionPoints(
        certificate_der,
    ) catch return null) orelse return null;
    var coverage: u8 = 0;
    var points = Reader{ .bytes = distribution_points };
    while (points.next() catch return null) |encoded_point| {
        const certificate_point = parseDistributionPoint(encoded_point) catch
            return null;
        if (certificate_point.crl_issuer_names != null or
            certificate_point.name == null or
            !distributionPointNamesMatch(
                idp_name,
                list.issuer_name,
                certificate_point.name.?,
                certificate.issuer(),
            )) continue;
        const dp_reasons = reasonMaskOrAll(certificate_point.reasons) catch
            return null;
        coverage |= idp_reasons & dp_reasons;
    }
    return if (coverage == 0) null else coverage;
}

fn crlKindMatchesCertificate(
    point: IssuingDistributionPoint,
    certificate_der: []const u8,
) bool {
    if (!point.only_contains_user_certs and
        !point.only_contains_ca_certs) return true;
    const certificate = parseCertificate(certificate_der) catch return false;
    if (certificate.version != .v3) return false;
    const is_ca = certificateIsCa(certificate_der) catch return false;
    return if (point.only_contains_user_certs) !is_ca else is_ca;
}

const DistributionPoint = struct {
    name: ?[]const u8 = null,
    reasons: ?[]const u8 = null,
    crl_issuer_names: ?[]const u8 = null,
};

fn parseDistributionPoint(encoded: Element) Error!DistributionPoint {
    if (encoded.tag != 0x30) return error.InvalidCrl;
    var result: DistributionPoint = .{};
    var fields = Reader{ .bytes = encoded.value };
    var previous_tag_number: ?u8 = null;
    while (fields.next() catch return error.InvalidCrl) |field| {
        const tag_number = field.tag & 0x1f;
        if (previous_tag_number != null and
            tag_number <= previous_tag_number.?) return error.InvalidCrl;
        previous_tag_number = tag_number;
        switch (field.tag) {
            0xa0 => {
                try validateDistributionPointName(field.value);
                result.name = field.value;
            },
            0x81 => {
                try validateReasonFlags(field.value);
                result.reasons = field.value;
            },
            0xa2 => {
                if (field.value.len == 0 or
                    !try validateCertificateIssuerNames(field.value))
                {
                    return error.InvalidCrl;
                }
                result.crl_issuer_names = field.value;
            },
            else => return error.InvalidCrl,
        }
    }
    if (result.name == null and result.crl_issuer_names == null) {
        return error.InvalidCrl;
    }
    return result;
}

fn validateFreshestCrl(encoded: []const u8) Error!void {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCrl;
    var points = Reader{ .bytes = sequence.value };
    while (points.next() catch return error.InvalidCrl) |encoded_point| {
        const point = try parseDistributionPoint(encoded_point);
        if (point.name == null or point.reasons != null or
            point.crl_issuer_names != null)
        {
            return error.InvalidCrl;
        }
    }
}

fn certificateCrlDistributionPoints(
    certificate_der: []const u8,
) !?[]const u8 {
    const encoded = try certificateExtensionValue(
        certificate_der,
        &.{ 0x55, 0x1d, 0x1f },
    ) orelse return null;
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidDer;
    return sequence.value;
}

fn certificateExtensionValue(
    certificate_der: []const u8,
    wanted_oid: []const u8,
) !?[]const u8 {
    var top = Reader{ .bytes = certificate_der };
    const certificate = try top.require(0x30);
    if (!top.done()) return error.InvalidDer;
    var certificate_fields = Reader{ .bytes = certificate.value };
    const tbs = try certificate_fields.require(0x30);
    var fields = Reader{ .bytes = tbs.value };
    var first = (try fields.next()) orelse return error.InvalidDer;
    if (first.tag == 0xa0) first = (try fields.next()) orelse
        return error.InvalidDer;
    if (first.tag != 0x02) return error.InvalidDer;
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    _ = try fields.require(0x30);
    while (try fields.next()) |optional| {
        if (optional.tag == 0x81 or optional.tag == 0x82) continue;
        if (optional.tag != 0xa3) return error.InvalidDer;
        var wrapper = Reader{ .bytes = optional.value };
        const extensions = try wrapper.require(0x30);
        if (!wrapper.done() or !fields.done()) return error.InvalidDer;
        var values = Reader{ .bytes = extensions.value };
        var result: ?[]const u8 = null;
        while (try values.next()) |extension| {
            if (extension.tag != 0x30) return error.InvalidDer;
            var extension_fields = Reader{ .bytes = extension.value };
            const oid = try extension_fields.require(0x06);
            var value = (try extension_fields.next()) orelse
                return error.InvalidDer;
            if (value.tag == 0x01) {
                if (value.value.len != 1 or value.value[0] != 0xff) {
                    return error.InvalidDer;
                }
                value = (try extension_fields.next()) orelse
                    return error.InvalidDer;
            }
            if (value.tag != 0x04 or !extension_fields.done()) {
                return error.InvalidDer;
            }
            if (!std.mem.eql(u8, oid.value, wanted_oid)) {
                continue;
            }
            if (result != null) return error.InvalidDer;
            result = value.value;
        }
        return result;
    }
    return null;
}

fn certificateIsCa(certificate_der: []const u8) !bool {
    const encoded = try certificateExtensionValue(
        certificate_der,
        &.{ 0x55, 0x1d, 0x13 },
    ) orelse return false;
    const sequence = try singleInner(encoded, 0x30);
    var fields = Reader{ .bytes = sequence.value };
    const ca = (try fields.next()) orelse return false;
    if (ca.tag != 0x01 or ca.value.len != 1 or ca.value[0] != 0xff) {
        return error.InvalidDer;
    }
    if (try fields.next()) |path_len| {
        if (path_len.tag != 0x02 or path_len.value.len == 0 or
            path_len.value[0] & 0x80 != 0 or try fields.next() != null)
        {
            return error.InvalidDer;
        }
    }
    return true;
}

fn distributionPointMatchesGeneralNames(
    encoded_point_name: []const u8,
    general_names: []const u8,
) bool {
    var wrapper = Reader{ .bytes = encoded_point_name };
    const point_name = (wrapper.next() catch return false) orelse return false;
    if (!wrapper.done() or point_name.tag != 0xa0) return false;
    var point_names = Reader{ .bytes = point_name.value };
    while (point_names.next() catch return false) |point_general_name| {
        var candidates = Reader{ .bytes = general_names };
        while (candidates.next() catch return false) |candidate| {
            if (point_general_name.tag == candidate.tag and
                std.mem.eql(u8, point_general_name.value, candidate.value))
            {
                return true;
            }
        }
    }
    return false;
}

fn distributionPointNamesMatch(
    a_encoded: []const u8,
    a_base: []const u8,
    b_encoded: []const u8,
    b_base: []const u8,
) bool {
    var a_wrapper = Reader{ .bytes = a_encoded };
    const a = (a_wrapper.next() catch return false) orelse return false;
    if (!a_wrapper.done()) return false;
    var b_wrapper = Reader{ .bytes = b_encoded };
    const b = (b_wrapper.next() catch return false) orelse return false;
    if (!b_wrapper.done()) return false;
    if (a.tag == 0xa0 and b.tag == 0xa0) {
        return generalNameSetsIntersect(a.value, b.value);
    }
    if (a.tag == 0xa1 and b.tag == 0xa1) {
        return distinguished_name.relativeNamesEqual(
            a.value,
            b.value,
        ) catch false;
    }
    if (a.tag == 0xa1 and b.tag == 0xa0) {
        return generalNamesContainAppendedRdn(b.value, a_base, a.value);
    }
    if (a.tag == 0xa0 and b.tag == 0xa1) {
        return generalNamesContainAppendedRdn(a.value, b_base, b.value);
    }
    return false;
}

fn generalNameSetsIntersect(a: []const u8, b: []const u8) bool {
    var a_names = Reader{ .bytes = a };
    while (a_names.next() catch return false) |a_name| {
        var b_names = Reader{ .bytes = b };
        while (b_names.next() catch return false) |b_name| {
            if (a_name.tag != b_name.tag) continue;
            if (a_name.tag == 0xa4) {
                const a_directory = singleInner(a_name.value, 0x30) catch
                    return false;
                const b_directory = singleInner(b_name.value, 0x30) catch
                    return false;
                if (distinguished_name.eql(
                    a_directory.value,
                    b_directory.value,
                ) catch false) return true;
            } else if (std.mem.eql(u8, a_name.value, b_name.value)) {
                return true;
            }
        }
    }
    return false;
}

fn generalNamesContainAppendedRdn(
    names: []const u8,
    base: []const u8,
    relative: []const u8,
) bool {
    var values = Reader{ .bytes = names };
    while (values.next() catch return false) |name| {
        if (name.tag != 0xa4) continue;
        const directory = singleInner(name.value, 0x30) catch return false;
        if (distinguished_name.eqlWithAppendedRdn(
            directory.value,
            base,
            relative,
        ) catch false) return true;
    }
    return false;
}

fn singleDirectoryName(names: []const u8) ?[]const u8 {
    var result: ?[]const u8 = null;
    var values = Reader{ .bytes = names };
    while (values.next() catch return null) |name| {
        if (name.tag != 0xa4) continue;
        if (result != null) return null;
        const directory = singleInner(name.value, 0x30) catch return null;
        result = directory.value;
    }
    return result;
}

fn isCombinedBase(combined_lists: []const CombinedList, list: List) bool {
    for (combined_lists) |combined| {
        if (list.der.ptr == combined.base.der.ptr and
            list.der.len == combined.base.der.len) return true;
    }
    return false;
}

fn latestDeltaForBase(lists: []const List, base: List) ?CombinedList {
    var latest: ?CombinedList = null;
    for (lists) |candidate| {
        if (!candidate.isDelta()) continue;
        const combined = CombinedList.init(base, candidate) catch continue;
        if (latest == null or
            combined.delta.this_update > latest.?.delta.this_update or
            (combined.delta.this_update == latest.?.delta.this_update and
                compareUnsigned(
                    combined.delta.crl_number.?,
                    latest.?.delta.crl_number.?,
                ) == .gt))
        {
            latest = combined;
        }
    }
    return latest;
}

fn certificateAdvertisesDelta(certificate_der: []const u8) Error!bool {
    const encoded = (certificateExtensionValue(
        certificate_der,
        &.{ 0x55, 0x1d, 0x2e },
    ) catch return error.InvalidCrl) orelse return false;
    const sequence = singleInner(encoded, 0x30) catch
        return error.InvalidCrl;
    if (sequence.value.len == 0) return error.InvalidCrl;
    var points = Reader{ .bytes = sequence.value };
    while (points.next() catch return error.InvalidCrl) |point| {
        _ = parseDistributionPoint(point) catch return error.InvalidCrl;
    }
    return true;
}

pub fn parseAndVerify(
    crl_der: []const u8,
    issuer_certificate_der: []const u8,
    now_seconds: i64,
) Error!List {
    if (now_seconds < 0) return error.CrlNotYetValid;
    const now: u64 = @intCast(now_seconds);
    const issuer_certificate = parseCertificate(
        issuer_certificate_der,
    ) catch return error.InvalidIssuer;
    trust.validateCertificateRevocationListSigner(
        issuer_certificate_der,
        now_seconds,
    ) catch return error.InvalidIssuer;

    var top = Reader{ .bytes = crl_der };
    const certificate_list = top.require(0x30) catch return error.InvalidCrl;
    if (!top.done()) return error.InvalidCrl;
    var fields = Reader{ .bytes = certificate_list.value };
    const tbs = fields.require(0x30) catch return error.InvalidCrl;
    const outer_algorithm = fields.require(0x30) catch return error.InvalidCrl;
    const signature_value = fields.require(0x03) catch return error.InvalidCrl;
    if (!fields.done()) return error.InvalidCrl;

    var tbs_fields = Reader{ .bytes = tbs.value };
    var first = (tbs_fields.next() catch return error.InvalidCrl) orelse
        return error.InvalidCrl;
    var version_two = false;
    if (first.tag == 0x02) {
        if (!std.mem.eql(u8, first.value, &.{0x01})) {
            return error.InvalidCrl;
        }
        version_two = true;
        first = (tbs_fields.next() catch return error.InvalidCrl) orelse
            return error.InvalidCrl;
    }
    if (first.tag != 0x30) return error.InvalidCrl;
    const inner_algorithm = first;
    const signature_algorithm = try parseSignatureAlgorithm(inner_algorithm);
    if (try parseSignatureAlgorithm(outer_algorithm) != signature_algorithm) {
        return error.InvalidCrl;
    }
    if (!std.mem.eql(
        u8,
        tbs.value[inner_algorithm.start..inner_algorithm.end],
        certificate_list.value[outer_algorithm.start..outer_algorithm.end],
    )) return error.InvalidCrl;

    const issuer = tbs_fields.require(0x30) catch return error.InvalidCrl;
    if (!(distinguished_name.eql(
        issuer.value,
        issuer_certificate.subject(),
    ) catch return error.InvalidCrl)) {
        return error.IssuerMismatch;
    }
    const this_update_element = (tbs_fields.next() catch
        return error.InvalidCrl) orelse return error.InvalidCrl;
    const this_update = parseTime(tbs.value, this_update_element) catch
        return error.InvalidCrl;
    const next_update_element = (tbs_fields.next() catch
        return error.InvalidCrl) orelse return error.InvalidCrl;
    const next_update = parseTime(tbs.value, next_update_element) catch
        return error.InvalidCrl;
    if (next_update <= this_update) return error.InvalidCrl;
    if (now < this_update) return error.CrlNotYetValid;
    if (now > next_update) return error.CrlExpired;

    var revoked_entries: []const u8 = &.{};
    var next = tbs_fields.next() catch return error.InvalidCrl;
    if (next != null and next.?.tag == 0x30) {
        revoked_entries = next.?.value;
        next = tbs_fields.next() catch return error.InvalidCrl;
    }
    var parsed_extensions: CrlExtensions = .{};
    if (next) |extensions| {
        if (!version_two or extensions.tag != 0xa0) return error.InvalidCrl;
        var explicit = Reader{ .bytes = extensions.value };
        const sequence = explicit.require(0x30) catch return error.InvalidCrl;
        if (!explicit.done()) return error.InvalidCrl;
        parsed_extensions = try parseCrlExtensions(sequence.value);
        if ((tbs_fields.next() catch return error.InvalidCrl) != null) {
            return error.InvalidCrl;
        }
    }
    const is_delta = parsed_extensions.delta_base_number != null;
    try validateRevokedEntries(
        revoked_entries,
        is_delta,
        if (parsed_extensions.issuing_distribution_point) |point|
            point.indirect_crl
        else
            false,
    );

    if (signature_value.value.len < 2 or signature_value.value[0] != 0) {
        return error.InvalidCrl;
    }
    try verifySignature(
        signature_algorithm,
        issuer_certificate,
        certificate_list.value[tbs.start..tbs.end],
        signature_value.value[1..],
    );

    return .{
        .der = crl_der,
        .issuer_certificate_der = issuer_certificate_der,
        .issuer_name = issuer.value,
        .revoked_entries = revoked_entries,
        .this_update = this_update,
        .next_update = next_update,
        .crl_number = parsed_extensions.crl_number,
        .delta_base_number = parsed_extensions.delta_base_number,
        .authority_key_identifier = parsed_extensions.authority_key_identifier,
        .issuing_distribution_point = parsed_extensions.issuing_distribution_point,
        .freshest_crl = parsed_extensions.freshest_crl,
    };
}

const SignatureAlgorithm = x509_signature.Algorithm;

fn parseSignatureAlgorithm(algorithm: Element) Error!SignatureAlgorithm {
    return x509_signature.parseAlgorithmIdentifier(algorithm.value) catch |err| switch (err) {
        error.UnsupportedSignatureAlgorithm => error.UnsupportedSignatureAlgorithm,
        else => error.InvalidCrl,
    };
}

fn verifySignature(
    algorithm: SignatureAlgorithm,
    issuer: Certificate.Parsed,
    message: []const u8,
    signature_bytes: []const u8,
) Error!void {
    x509_signature.verify(algorithm, issuer, message, signature_bytes) catch |err| switch (err) {
        error.InvalidIssuer => return error.InvalidIssuer,
        error.UnsupportedSignatureAlgorithm => return error.UnsupportedSignatureAlgorithm,
        else => return error.InvalidCrlSignature,
    };
}

const RevokedEntry = struct {
    serial: []const u8,
    reason: Reason = .unspecified,
    certificate_issuer_names: ?[]const u8 = null,
};

fn parseRevokedEntry(
    entry: Element,
    is_delta: bool,
    indirect: bool,
) Error!RevokedEntry {
    if (entry.tag != 0x30) return error.InvalidCrl;
    var fields = Reader{ .bytes = entry.value };
    const serial = fields.require(0x02) catch return error.InvalidCrl;
    validateSerial(serial.value) catch return error.InvalidCrl;
    const revocation_date = (fields.next() catch return error.InvalidCrl) orelse
        return error.InvalidCrl;
    _ = parseTime(entry.value, revocation_date) catch return error.InvalidCrl;
    var result = RevokedEntry{ .serial = serial.value };
    if (fields.next() catch return error.InvalidCrl) |extensions| {
        if (extensions.tag != 0x30) return error.InvalidCrl;
        result = try parseEntryExtensions(
            extensions.value,
            serial.value,
            is_delta,
            indirect,
        );
        if (!fields.done()) return error.InvalidCrl;
    }
    return result;
}

fn validateRevokedEntries(
    entries_bytes: []const u8,
    is_delta: bool,
    indirect: bool,
) Error!void {
    var entries = Reader{ .bytes = entries_bytes };
    while (entries.next() catch return error.InvalidCrl) |entry| {
        _ = try parseRevokedEntry(entry, is_delta, indirect);
    }
}

const CrlExtensions = struct {
    crl_number: ?[]const u8 = null,
    delta_base_number: ?[]const u8 = null,
    authority_key_identifier: ?[]const u8 = null,
    issuing_distribution_point: ?IssuingDistributionPoint = null,
    freshest_crl: ?[]const u8 = null,
};

fn parseCrlExtensions(bytes: []const u8) Error!CrlExtensions {
    var result: CrlExtensions = .{};
    var extensions = Reader{ .bytes = bytes };
    var checked_end: usize = 0;
    while (extensions.next() catch return error.InvalidCrl) |extension| {
        if (extension.tag != 0x30) return error.InvalidCrl;
        var fields = Reader{ .bytes = extension.value };
        const oid = fields.require(0x06) catch return error.InvalidCrl;
        try validateOid(oid.value);
        var prior = Reader{ .bytes = bytes[0..checked_end] };
        while (prior.next() catch return error.InvalidCrl) |prior_extension| {
            if (prior_extension.tag != 0x30) return error.InvalidCrl;
            var prior_fields = Reader{ .bytes = prior_extension.value };
            const prior_oid = prior_fields.require(0x06) catch
                return error.InvalidCrl;
            if (std.mem.eql(u8, prior_oid.value, oid.value)) {
                return error.InvalidCrl;
            }
        }
        var value = (fields.next() catch return error.InvalidCrl) orelse
            return error.InvalidCrl;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidCrl;
            }
            critical = true;
            value = (fields.next() catch return error.InvalidCrl) orelse
                return error.InvalidCrl;
        }
        if (value.tag != 0x04 or !fields.done()) return error.InvalidCrl;
        if (std.mem.eql(u8, oid.value, &oid_crl_number)) {
            if (critical) return error.InvalidCrl;
            result.crl_number = try parseCrlNumber(value.value);
        } else if (std.mem.eql(u8, oid.value, &oid_delta_crl_indicator)) {
            if (!critical) return error.InvalidDeltaCrl;
            result.delta_base_number = try parseCrlNumber(value.value);
        } else if (std.mem.eql(
            u8,
            oid.value,
            &oid_issuing_distribution_point,
        )) {
            if (!critical) return error.InvalidCrl;
            result.issuing_distribution_point = try parseIssuingDistributionPoint(
                value.value,
            );
        } else if (std.mem.eql(
            u8,
            oid.value,
            &oid_authority_key_identifier,
        )) {
            if (critical) return error.InvalidCrl;
            try validateAuthorityKeyIdentifier(value.value);
            result.authority_key_identifier = value.value;
        } else if (std.mem.eql(u8, oid.value, &.{ 0x55, 0x1d, 0x2e })) {
            if (critical) return error.InvalidCrl;
            try validateFreshestCrl(value.value);
            result.freshest_crl = value.value;
        } else if (critical) {
            return error.UnsupportedCriticalExtension;
        }
        checked_end = extension.end;
    }
    if (result.delta_base_number) |base_number| {
        const crl_number = result.crl_number orelse
            return error.InvalidDeltaCrl;
        if (compareUnsigned(base_number, crl_number) != .lt or
            result.freshest_crl != null)
        {
            return error.InvalidDeltaCrl;
        }
    }
    return result;
}

fn parseEntryExtensions(
    bytes: []const u8,
    serial: []const u8,
    is_delta: bool,
    indirect: bool,
) Error!RevokedEntry {
    var result = RevokedEntry{ .serial = serial };
    var extensions = Reader{ .bytes = bytes };
    var checked_end: usize = 0;
    while (extensions.next() catch return error.InvalidCrl) |extension| {
        if (extension.tag != 0x30) return error.InvalidCrl;
        var fields = Reader{ .bytes = extension.value };
        const oid = fields.require(0x06) catch return error.InvalidCrl;
        try validateOid(oid.value);
        var prior = Reader{ .bytes = bytes[0..checked_end] };
        while (prior.next() catch return error.InvalidCrl) |prior_extension| {
            if (prior_extension.tag != 0x30) return error.InvalidCrl;
            var prior_fields = Reader{ .bytes = prior_extension.value };
            const prior_oid = prior_fields.require(0x06) catch
                return error.InvalidCrl;
            if (std.mem.eql(u8, prior_oid.value, oid.value)) {
                return error.InvalidCrl;
            }
        }
        var value = (fields.next() catch return error.InvalidCrl) orelse
            return error.InvalidCrl;
        var critical = false;
        if (value.tag == 0x01) {
            if (value.value.len != 1 or value.value[0] != 0xff) {
                return error.InvalidCrl;
            }
            critical = true;
            value = (fields.next() catch return error.InvalidCrl) orelse
                return error.InvalidCrl;
        }
        if (value.tag != 0x04 or !fields.done()) return error.InvalidCrl;
        if (std.mem.eql(u8, oid.value, &oid_reason_code)) {
            if (critical) return error.InvalidCrl;
            const reason = try singleInner(value.value, 0x0a);
            if (reason.value.len != 1) return error.InvalidCrl;
            result.reason = std.enums.fromInt(
                Reason,
                reason.value[0],
            ) orelse return error.InvalidCrl;
            if (result.reason == .remove_from_crl and !is_delta) {
                return error.InvalidCrl;
            }
        } else if (std.mem.eql(u8, oid.value, &oid_invalidity_date)) {
            if (critical) return error.InvalidCrl;
            var time = Reader{ .bytes = value.value };
            const encoded_time = (time.next() catch return error.InvalidCrl) orelse
                return error.InvalidCrl;
            _ = parseTime(value.value, encoded_time) catch
                return error.InvalidCrl;
            if (!time.done()) return error.InvalidCrl;
        } else if (std.mem.eql(u8, oid.value, &oid_certificate_issuer)) {
            if (!critical or !indirect) return error.InvalidCrl;
            const names = try singleInner(value.value, 0x30);
            if (names.value.len == 0 or
                !try validateCertificateIssuerNames(names.value))
            {
                return error.InvalidCrl;
            }
            result.certificate_issuer_names = names.value;
        } else if (critical) {
            return error.UnsupportedCriticalExtension;
        }
        checked_end = extension.end;
    }
    return result;
}

fn parseCrlNumber(encoded: []const u8) Error![]const u8 {
    const number = try singleInner(encoded, 0x02);
    if (number.value.len == 0 or number.value.len > 20 or
        number.value[0] & 0x80 != 0 or
        (number.value.len > 1 and number.value[0] == 0 and
            number.value[1] & 0x80 == 0))
    {
        return error.InvalidCrl;
    }
    return number.value;
}

fn parseIssuingDistributionPoint(
    encoded: []const u8,
) Error!IssuingDistributionPoint {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCrl;
    var result = IssuingDistributionPoint{ .encoded = encoded };
    var fields = Reader{ .bytes = sequence.value };
    var previous_tag_number: ?u8 = null;
    var restricted_kinds: usize = 0;
    while (fields.next() catch return error.InvalidCrl) |field| {
        const tag_number = field.tag & 0x1f;
        if (previous_tag_number != null and
            tag_number <= previous_tag_number.?)
        {
            return error.InvalidCrl;
        }
        previous_tag_number = tag_number;
        switch (field.tag) {
            0xa0 => {
                try validateDistributionPointName(field.value);
                result.distribution_point = field.value;
            },
            0x81 => {
                try requireImplicitTrue(field.value);
                result.only_contains_user_certs = true;
                restricted_kinds += 1;
            },
            0x82 => {
                try requireImplicitTrue(field.value);
                result.only_contains_ca_certs = true;
                restricted_kinds += 1;
            },
            0x83 => {
                try validateReasonFlags(field.value);
                result.only_some_reasons = field.value;
            },
            0x84 => {
                try requireImplicitTrue(field.value);
                result.indirect_crl = true;
            },
            0x85 => {
                try requireImplicitTrue(field.value);
                // Attribute certificates are outside this X.509 public-key
                // certificate verifier.
                return error.UnsupportedCriticalExtension;
            },
            else => return error.InvalidCrl,
        }
    }
    if (restricted_kinds > 1) return error.InvalidCrl;
    return result;
}

fn validateDistributionPointName(encoded: []const u8) Error!void {
    var wrapper = Reader{ .bytes = encoded };
    const name = (wrapper.next() catch return error.InvalidCrl) orelse
        return error.InvalidCrl;
    if (!wrapper.done()) return error.InvalidCrl;
    switch (name.tag) {
        0xa0 => {
            if (name.value.len == 0) return error.InvalidCrl;
            var names = Reader{ .bytes = name.value };
            while (names.next() catch return error.InvalidCrl) |general_name| {
                if (!validGeneralName(general_name)) {
                    return error.InvalidCrl;
                }
            }
        },
        0xa1 => distinguished_name.validateRelativeName(name.value) catch
            return error.InvalidCrl,
        else => return error.InvalidCrl,
    }
}

fn requireImplicitTrue(value: []const u8) Error!void {
    if (value.len != 1 or value[0] != 0xff) return error.InvalidCrl;
}

fn validateReasonFlags(value: []const u8) Error!void {
    _ = try reasonMask(value);
}

fn reasonMaskOrAll(value: ?[]const u8) Error!u8 {
    return if (value) |encoded| reasonMask(encoded) else all_reason_mask;
}

fn reasonMask(value: []const u8) Error!u8 {
    if (value.len < 2 or value.len > 3 or value[0] > 7 or
        value[value.len - 1] == 0 or
        @ctz(value[value.len - 1]) != value[0] or
        (value[0] != 0 and
            value[value.len - 1] & ((@as(u8, 1) << @intCast(value[0])) - 1) != 0))
    {
        return error.InvalidCrl;
    }
    // Bit zero is `unused` and cannot be part of a Reasons value. The only
    // defined bit in a second content octet is aACompromise (bit eight).
    if (value[1] & 0x80 != 0 or
        (value.len == 3 and (value[2] & 0x7f) != 0))
    {
        return error.InvalidCrl;
    }
    var result: u8 = 0;
    if (value[1] & 0x40 != 0) result |= 1 << 0;
    if (value[1] & 0x20 != 0) result |= 1 << 1;
    if (value[1] & 0x10 != 0) result |= 1 << 2;
    if (value[1] & 0x08 != 0) result |= 1 << 3;
    if (value[1] & 0x04 != 0) result |= 1 << 4;
    if (value[1] & 0x02 != 0) result |= 1 << 5;
    if (value[1] & 0x01 != 0) result |= 1 << 6;
    if (value.len == 3 and value[2] & 0x80 != 0) result |= 1 << 7;
    if (result == 0) return error.InvalidCrl;
    return result;
}

fn validateCertificateIssuerNames(encoded: []const u8) Error!bool {
    var names = Reader{ .bytes = encoded };
    var saw_directory_name = false;
    while (names.next() catch return error.InvalidCrl) |name| {
        if (!validGeneralName(name)) return error.InvalidCrl;
        if (name.tag == 0xa4) {
            const directory = try singleInner(name.value, 0x30);
            distinguished_name.validate(directory.value) catch
                return error.InvalidCrl;
            saw_directory_name = true;
        }
    }
    return saw_directory_name;
}

fn generalNamesContainDirectoryName(
    encoded: []const u8,
    candidate: []const u8,
) bool {
    var names = Reader{ .bytes = encoded };
    while (names.next() catch return false) |name| {
        if (name.tag != 0xa4) continue;
        const directory = singleInner(name.value, 0x30) catch return false;
        if (distinguished_name.eql(directory.value, candidate) catch false) {
            return true;
        }
    }
    return false;
}

fn validGeneralName(name: Element) bool {
    return switch (name.tag) {
        0xa0, 0xa3, 0xa5 => name.value.len != 0,
        0xa4 => blk: {
            const directory = singleInner(name.value, 0x30) catch break :blk false;
            distinguished_name.validate(directory.value) catch break :blk false;
            break :blk true;
        },
        0x81, 0x82 => validNonEmptyIa5(name.value),
        0x86 => validAbsoluteIa5Uri(name.value),
        0x87 => name.value.len == 4 or name.value.len == 16,
        0x88 => blk: {
            validateOid(name.value) catch break :blk false;
            break :blk true;
        },
        else => false,
    };
}

fn validNonEmptyIa5(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte > 0x7f) return false;
    }
    return true;
}

fn validAbsoluteIa5Uri(uri: []const u8) bool {
    if (uri.len < 3 or !std.ascii.isAlphabetic(uri[0])) return false;
    for (uri[1..], 1..) |byte, index| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
        if (byte == ':') return index + 1 < uri.len;
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '+' and byte != '-' and byte != '.') return false;
    }
    return false;
}

fn validateAuthorityKeyIdentifier(encoded: []const u8) Error!void {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCrl;
    var fields = Reader{ .bytes = sequence.value };
    var previous_tag_number: ?u8 = null;
    while (fields.next() catch return error.InvalidCrl) |field| {
        const tag_number = field.tag & 0x1f;
        if ((field.tag != 0x80 and field.tag != 0xa1 and field.tag != 0x82) or
            (previous_tag_number != null and
                tag_number <= previous_tag_number.?) or
            field.value.len == 0)
        {
            return error.InvalidCrl;
        }
        previous_tag_number = tag_number;
    }
}

fn sameOptionalBytes(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn sameIssuerKey(a: List, b: List) bool {
    const a_issuer = parseCertificate(a.issuer_certificate_der) catch return false;
    const b_issuer = parseCertificate(b.issuer_certificate_der) catch return false;
    return std.meta.eql(a_issuer.pub_key_algo, b_issuer.pub_key_algo) and
        std.mem.eql(u8, a_issuer.pubKey(), b_issuer.pubKey());
}

fn compareUnsigned(a_encoded: []const u8, b_encoded: []const u8) std.math.Order {
    const a = if (a_encoded.len > 1 and a_encoded[0] == 0)
        a_encoded[1..]
    else
        a_encoded;
    const b = if (b_encoded.len > 1 and b_encoded[0] == 0)
        b_encoded[1..]
    else
        b_encoded;
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    return std.mem.order(u8, a, b);
}

fn singleInner(encoded: []const u8, tag: u8) Error!Element {
    var reader = Reader{ .bytes = encoded };
    const value = reader.require(tag) catch return error.InvalidCrl;
    if (!reader.done()) return error.InvalidCrl;
    return value;
}

fn validateOid(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidCrl;
    var at_subidentifier_start = true;
    for (value) |byte| {
        if (at_subidentifier_start and byte == 0x80) return error.InvalidCrl;
        at_subidentifier_start = (byte & 0x80) == 0;
    }
    if (!at_subidentifier_start) return error.InvalidCrl;
}

fn certificateSerial(certificate_der: []const u8) ![]const u8 {
    _ = try parseCertificate(certificate_der);
    var top = Reader{ .bytes = certificate_der };
    const certificate = try top.require(0x30);
    var fields = Reader{ .bytes = certificate.value };
    const tbs = try fields.require(0x30);
    var tbs_fields = Reader{ .bytes = tbs.value };
    var serial = (try tbs_fields.next()) orelse return error.InvalidDer;
    if (serial.tag == 0xa0) {
        serial = (try tbs_fields.next()) orelse return error.InvalidDer;
    }
    if (serial.tag != 0x02) return error.InvalidDer;
    try validateSerial(serial.value);
    return serial.value;
}

fn validateSerial(serial: []const u8) Error!void {
    if (serial.len == 0 or serial.len > 20 or (serial[0] & 0x80) != 0 or
        (serial.len > 1 and serial[0] == 0 and (serial[1] & 0x80) == 0))
    {
        return error.CertificateSerialInvalid;
    }
    var nonzero = false;
    for (serial) |byte| nonzero = nonzero or byte != 0;
    if (!nonzero) return error.CertificateSerialInvalid;
}

fn parseCertificate(der: []const u8) !Certificate.Parsed {
    var top = Reader{ .bytes = der };
    _ = try top.require(0x30);
    if (!top.done()) return error.InvalidDer;
    return (try certificate_compat.parse(der)).standard;
}

fn parseTime(bytes: []const u8, time: Element) !u64 {
    if ((time.tag == 0x17 and
        (time.value.len != 13 or time.value[12] != 'Z')) or
        (time.tag == 0x18 and
            (time.value.len != 15 or time.value[14] != 'Z')) or
        (time.tag != 0x17 and time.tag != 0x18) or
        time.value_start > std.math.maxInt(u32) or
        time.end > std.math.maxInt(u32))
    {
        return error.InvalidDer;
    }
    const identifier: Certificate.der.Identifier = @bitCast(time.tag);
    return Certificate.parseTime(.{ .buffer = bytes, .index = 0 }, .{
        .identifier = identifier,
        .slice = .{
            .start = @intCast(time.value_start),
            .end = @intCast(time.end),
        },
    });
}

const Element = struct {
    tag: u8,
    start: usize,
    value_start: usize,
    end: usize,
    value: []const u8,
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn require(self: *Reader, tag: u8) !Element {
        const value = (try self.next()) orelse return error.InvalidDer;
        if (value.tag != tag) return error.InvalidDer;
        return value;
    }

    fn next(self: *Reader) !?Element {
        if (self.offset == self.bytes.len) return null;
        if (self.offset + 2 > self.bytes.len) return error.InvalidDer;
        const start = self.offset;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidDer;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidDer;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidDer;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidDer;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidDer;
        }
        if (length > self.bytes.len - self.offset) return error.InvalidDer;
        const value_start = self.offset;
        const value = self.bytes[value_start .. value_start + length];
        self.offset += length;
        return .{
            .tag = tag,
            .start = start,
            .value_start = value_start,
            .end = self.offset,
            .value = value,
        };
    }

    fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

const ca_base64 =
    "MIIBhDCCASmgAwIBAgICEAAwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBgxFjAUBgNV" ++
    "BAMMDUNSTCBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQantue" ++
    "ZFhV35+7BoVoG9/+jPWbhpRoMPiTYHDqJfZk7qZab4SMQITgtsFnZ5n5up9IOZnP" ++
    "bgML6KLa9BKOmrxYo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB" ++
    "BjAdBgNVHQ4EFgQU4Y88Ik092FGXnPjSSa7GXltOPjQwHwYDVR0jBBgwFoAU4Y88" ++
    "Ik092FGXnPjSSa7GXltOPjQwCgYIKoZIzj0EAwIDSQAwRgIhAPUbM4y3hpf9d8SU" ++
    "VmCYJBEtqK4aEvFU6CF+czPw9xkTAiEAnz2ASewLVc2Uc42VgyUKR19yy8SlGYvX" ++
    "h7Mb4/RIYtM=";
const good_base64 =
    "MIIBlDCCATmgAwIBAgICEAEwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBYxFDASBgNV" ++
    "BAMMC2dvb2QtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWQ6bctG2" ++
    "c8QseTp/gBMXYeuqnNYn7TiCJr9E9+os+4kuiZ+AdSqPsorbp/VAONrhbjkyYwTy" ++
    "4iqeZEYmjy4h7KN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYD" ++
    "VR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFPbNjkXzEROtcFB/jpriCQRx5Xd+" ++
    "MB8GA1UdIwQYMBaAFOGPPCJNPdhRl5z40kmuxl5bTj40MAoGCCqGSM49BAMCA0kA" ++
    "MEYCIQDS2PsKUe7bgIU6ktMWa9J7z/dRt8ZskJT+QzggaiZ0hQIhAIuXlBXP0iGg" ++
    "W3MfGt8dY47up1C9sqSmlxMxpWG0tkKG";
const revoked_base64 =
    "MIIBlzCCATygAwIBAgICEAIwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBkxFzAVBgNV" ++
    "BAMMDnJldm9rZWQtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfOEs" ++
    "A83kNW0KeINCBpHrxhJW07yht+u4R+h/mriq0ohvAqq4xo+CYuPNYfVM8uDEpvFa" ++
    "W0mHf5ffORS3zcXFWKN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4Aw" ++
    "EwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHjbxgNaDfc+edyrH/FcgLXx" ++
    "lJnWMB8GA1UdIwQYMBaAFOGPPCJNPdhRl5z40kmuxl5bTj40MAoGCCqGSM49BAMC" ++
    "A0kAMEYCIQDmRnZBG6KpALNt5yfzutiD3wy4zU88qgI87M3csPE2pQIhAIk+S4vd" ++
    "vM8Mlu1nZe4M0YkCWi7omb60P32wFmllWa63";
const crl_base64 =
    "MIHUMH0CAQEwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRlc3QgUm9vdBcN" ++
    "MjYwOTAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjAjMCECAhACFw0yNjA5MjIxOTAy" ++
    "MzFaMAwwCgYDVR0VBAMKAQGgDzANMAsGA1UdFAQEAgIQADAKBggqhkjOPQQDAgNH" ++
    "ADBEAiAcMtii8815JG7qfPRtjkJKxxWmrCnIW01AFwAjEEgkqgIgJNMKp1VLVy22" ++
    "tfQaelszInC3rbiKsCifZE4eYEmms/8=";

fn decodeFixture(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, len);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, encoded);
    return decoded;
}

test "CRL verifies signature and distinguishes revoked serials" {
    const allocator = std.testing.allocator;
    const ca = try decodeFixture(allocator, ca_base64);
    defer allocator.free(ca);
    const good = try decodeFixture(allocator, good_base64);
    defer allocator.free(good);
    const revoked = try decodeFixture(allocator, revoked_base64);
    defer allocator.free(revoked);
    const crl_bytes = try decodeFixture(allocator, crl_base64);
    defer allocator.free(crl_bytes);

    const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));
}

test "CRL rejects tampering and invalid update windows" {
    const allocator = std.testing.allocator;
    const ca = try decodeFixture(allocator, ca_base64);
    defer allocator.free(ca);
    const crl_bytes = try decodeFixture(allocator, crl_base64);
    defer allocator.free(crl_bytes);

    const tampered = try allocator.dupe(u8, crl_bytes);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_800_000_000),
    );
    try std.testing.expectError(
        error.CrlNotYetValid,
        parseAndVerify(crl_bytes, ca, 1_770_000_000),
    );
    try std.testing.expectError(
        error.CrlExpired,
        parseAndVerify(crl_bytes, ca, 2_000_000_000),
    );

    const wrong_issuer = @embedFile("testdata/ca.der");
    try std.testing.expectError(
        error.IssuerMismatch,
        parseAndVerify(crl_bytes, wrong_issuer, 1_800_000_000),
    );
    const wrong_leaf = @embedFile("testdata/server.der");
    const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
    try std.testing.expectError(
        error.IssuerMismatch,
        list.isRevoked(wrong_leaf),
    );
}

test "CRL verifies Mosquitto RSA SHA256 fixtures" {
    const allocator = std.testing.allocator;
    const ca = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-signing-ca.pem"),
        "CERTIFICATE",
    );
    defer allocator.free(ca);
    const good = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-client.pem"),
        "CERTIFICATE",
    );
    defer allocator.free(good);
    const revoked = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-client-revoked.pem"),
        "CERTIFICATE",
    );
    defer allocator.free(revoked);
    const crl_bytes = try decodePemFixture(
        allocator,
        @embedFile("testdata/mosquitto-crl.pem"),
        "X509 CRL",
    );
    defer allocator.free(crl_bytes);

    const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));

    const tampered = try allocator.dupe(u8, crl_bytes);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_800_000_000),
    );
}

test "CRL verifies Ed25519 fixtures and rejects signature tampering" {
    const ca = @embedFile("testdata/ed25519-crl-ca.der");
    const good = @embedFile("testdata/ed25519-crl-good.der");
    const revoked = @embedFile("testdata/ed25519-crl-revoked.der");
    const crl_bytes = @embedFile("testdata/ed25519.crl.der");

    const list = try parseAndVerify(crl_bytes, ca, 1_790_419_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));

    const tampered = try std.testing.allocator.dupe(u8, crl_bytes);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_790_419_000),
    );
}

test "CRL verifies P384 SHA384 fixtures and rejects signature tampering" {
    const ca = @embedFile("testdata/p384-crl-ca.der");
    const good = @embedFile("testdata/p384-crl-good.der");
    const revoked = @embedFile("testdata/p384-crl-revoked.der");
    const crl_bytes = @embedFile("testdata/p384.crl.der");

    const list = try parseAndVerify(crl_bytes, ca, 1_790_420_000);
    try std.testing.expect(!try list.isRevoked(good));
    try std.testing.expect(try list.isRevoked(revoked));

    const tampered = try std.testing.allocator.dupe(u8, crl_bytes);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_790_420_000),
    );
}

test "CRL verifies OpenSSL RSA PKCS1 SHA-384 and SHA-512 fixtures" {
    const ca = @embedFile("testdata/rsa-pss-crl-ca.der");
    const crls = [_][]const u8{
        @embedFile("testdata/rsa-pkcs1-sha384.crl.der"),
        @embedFile("testdata/rsa-pkcs1-sha512.crl.der"),
    };
    for (crls) |crl_bytes| {
        const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
        try std.testing.expectEqual(@as(usize, 0), list.revoked_entries.len);
    }
}

test "CRL verifies OpenSSL RSA-PSS SHA-256 SHA-384 and SHA-512 fixtures" {
    const ca = @embedFile("testdata/rsa-pss-crl-ca.der");
    const pss_leaf = @embedFile("testdata/rsa-pss-leaf.der");
    const crls = [_][]const u8{
        @embedFile("testdata/rsa-pss-sha256.crl.der"),
        @embedFile("testdata/rsa-pss-sha384.crl.der"),
        @embedFile("testdata/rsa-pss-sha512.crl.der"),
    };
    for (crls) |crl_bytes| {
        const list = try parseAndVerify(crl_bytes, ca, 1_800_000_000);
        try std.testing.expectEqual(@as(usize, 0), list.revoked_entries.len);
        try std.testing.expect(!try list.isRevoked(pss_leaf));
        try std.testing.expectEqual(@as(u64, 1_767_225_600), list.this_update);
        try std.testing.expectEqual(@as(u64, 2_082_758_400), list.next_update);
    }

    const tampered = try std.testing.allocator.dupe(u8, crls[2]);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidCrlSignature,
        parseAndVerify(tampered, ca, 1_800_000_000),
    );

    const wrong_salt = try std.testing.allocator.dupe(u8, crls[0]);
    defer std.testing.allocator.free(wrong_salt);
    const encoded_salt_length = [_]u8{ 0xa2, 0x03, 0x02, 0x01, 0x20 };
    var search_from: usize = 0;
    var replacements: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        wrong_salt,
        search_from,
        &encoded_salt_length,
    )) |offset| {
        wrong_salt[offset + encoded_salt_length.len - 1] = 31;
        search_from = offset + encoded_salt_length.len;
        replacements += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), replacements);
    try std.testing.expectError(
        error.UnsupportedSignatureAlgorithm,
        parseAndVerify(wrong_salt, ca, 1_800_000_000),
    );
}

test "CRL rejects Ed25519 AlgorithmIdentifier parameters" {
    try std.testing.expectError(
        error.InvalidCrl,
        parseSignatureAlgorithm(.{
            .tag = 0x30,
            .start = 0,
            .value_start = 0,
            .end = 7,
            .value = &.{ 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00 },
        }),
    );
}

test "CRL delta and indirect extension codecs are strict" {
    const extensions = try parseCrlExtensions(
        "\x30\x0b\x06\x03\x55\x1d\x14\x04\x04\x02\x02\x10\x01" ++
            "\x30\x0e\x06\x03\x55\x1d\x1b\x01\x01\xff" ++
            "\x04\x04\x02\x02\x10\x00",
    );
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x01 }, extensions.crl_number.?);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x10, 0x00 },
        extensions.delta_base_number.?,
    );
    try std.testing.expect((try parseIssuingDistributionPoint(
        "\x30\x03\x84\x01\xff",
    )).indirect_crl);
    try std.testing.expectError(
        error.InvalidCrl,
        parseIssuingDistributionPoint("\x30\x03\x84\x01\x00"),
    );
    try std.testing.expectError(
        error.InvalidDeltaCrl,
        parseCrlExtensions(
            "\x30\x0d\x06\x03\x55\x1d\x1b\x04\x06\x02\x04\x00\x00\x00\x01",
        ),
    );
    try std.testing.expectEqual(@as(u8, 0x0f), try reasonMask(&.{ 3, 0x78 }));
    try std.testing.expectEqual(
        @as(u8, 0xf0),
        try reasonMask(&.{ 7, 0x07, 0x80 }),
    );
    try std.testing.expectError(
        error.InvalidCrl,
        reasonMask(&.{ 0, 0x40 }),
    );
}

test "CRL distribution-point URI iterator validates all names" {
    const valid =
        "\x30\x2c\x30\x2a\xa0\x28\xa0\x26" ++
        "\x86\x13http://a.test/a.crl" ++
        "\x86\x0fldap://b.test/b";
    var urls = try distributionPointUrlsFromValue(valid);
    try std.testing.expectEqualStrings("http://a.test/a.crl", (try urls.next()).?);
    try std.testing.expectEqualStrings("ldap://b.test/b", (try urls.next()).?);
    try std.testing.expect(try urls.next() == null);

    var relative = try distributionPointUrlsFromValue(
        "\x30\x13\x30\x11\xa0\x0f\xa1\x0d" ++
            "\x30\x0b\x06\x03\x55\x04\x03\x0c\x04unit",
    );
    try std.testing.expect(try relative.next() == null);
    try std.testing.expectError(
        error.InvalidCrl,
        distributionPointUrlsFromValue(
            "\x30\x26\x30\x24\xa0\x22\xa0\x20" ++
                "\x86\x10http://ok.test/a" ++
                "\x86\x0cbad relative",
        ),
    );
}

test "indirect CRL entries carry issuer state and removeFromCRL" {
    const encoded =
        "\x30\x0a\x06\x03\x55\x1d\x15\x04\x03\x0a\x01\x08" ++
        "\x30\x25\x06\x03\x55\x1d\x1d\x01\x01\xff\x04\x1b" ++
        "\x30\x19\xa4\x17\x30\x15\x31\x13\x30\x11" ++
        "\x06\x03\x55\x04\x03\x0c\x0aForeign CA";
    const parsed = try parseEntryExtensions(encoded, &.{1}, true, true);
    try std.testing.expectEqual(Reason.remove_from_crl, parsed.reason);
    try std.testing.expect(generalNamesContainDirectoryName(
        parsed.certificate_issuer_names.?,
        "\x31\x13\x30\x11\x06\x03\x55\x04\x03\x13\x0aforeign ca",
    ));
    try std.testing.expectError(
        error.InvalidCrl,
        parseEntryExtensions(encoded, &.{1}, false, true),
    );
    try std.testing.expectError(
        error.InvalidCrl,
        parseEntryExtensions(
            "\x30\x22\x06\x03\x55\x1d\x1d\x04\x1b" ++
                "\x30\x19\xa4\x17\x30\x15\x31\x13\x30\x11" ++
                "\x06\x03\x55\x04\x03\x0c\x0aForeign CA",
            &.{1},
            true,
            true,
        ),
    );
}

fn decodePemFixture(
    allocator: std.mem.Allocator,
    pem: []const u8,
    label: []const u8,
) ![]u8 {
    const begin = try std.fmt.allocPrint(
        allocator,
        "-----BEGIN {s}-----",
        .{label},
    );
    defer allocator.free(begin);
    const end = try std.fmt.allocPrint(
        allocator,
        "-----END {s}-----",
        .{label},
    );
    defer allocator.free(end);
    const begin_at = std.mem.indexOf(u8, pem, begin) orelse
        return error.InvalidCrl;
    const body_start = begin_at + begin.len;
    const end_at = std.mem.indexOfPos(u8, pem, body_start, end) orelse
        return error.InvalidCrl;
    var compact: std.ArrayList(u8) = .empty;
    defer compact.deinit(allocator);
    for (pem[body_start..end_at]) |byte| switch (byte) {
        ' ', '\t', '\r', '\n' => {},
        else => try compact.append(allocator, byte),
    };
    const len = try std.base64.standard.Decoder.calcSizeForSlice(compact.items);
    const decoded = try allocator.alloc(u8, len);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, compact.items);
    return decoded;
}
