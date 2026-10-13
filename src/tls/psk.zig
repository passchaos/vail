//! TLS 1.3 resumption-PSK helpers for QUIC PSK-DHE handshakes.
//!
//! The caller builds an otherwise complete ClientHello, then this module
//! appends `psk_key_exchange_modes` and the mandatory-last `pre_shared_key`
//! extension while computing the binder over the correctly truncated message.

const std = @import("std");
const sha256 = @import("../crypto/sha256.zig");

const Sha256 = sha256.Hash;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sm3 = @import("../crypto/sm3.zig").Hash;
const key_schedule = @import("key_schedule.zig");
const secret = @import("secret.zig");
const tls_transcript = @import("transcript.zig");

pub const ext_pre_shared_key: u16 = 0x0029;
pub const ext_early_data: u16 = 0x002a;
pub const ext_psk_key_exchange_modes: u16 = 0x002d;
pub const psk_dhe_ke: u8 = 1;
pub const selected_identity_first: u16 = 0;

pub const Error = std.mem.Allocator.Error || error{
    InvalidClientHello,
    InvalidServerHello,
    MissingPskOffer,
    InvalidPskIdentity,
    InvalidPskBinder,
    InvalidPskAge,
    ExpiredPsk,
    UnexpectedEarlyData,
    UnsupportedPskKeyExchangeMode,
    PskExtensionNotLast,
};

pub const Offer = struct {
    selected_identity: u16 = selected_identity_first,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    binder_hash: secret.Hash,
    binder: []const u8,
    binder_truncated_len: usize,
};

pub const OfferedIdentity = struct {
    selected_identity: u16,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    binder: []const u8,
    binder_truncated_len: usize,

    pub fn forHash(
        self: OfferedIdentity,
        expected_hash: secret.Hash,
    ) Error!Offer {
        if (self.binder.len != expected_hash.len()) {
            return error.InvalidPskBinder;
        }
        return .{
            .selected_identity = self.selected_identity,
            .identity = self.identity,
            .obfuscated_ticket_age = self.obfuscated_ticket_age,
            .binder_hash = expected_hash,
            .binder = self.binder,
            .binder_truncated_len = self.binder_truncated_len,
        };
    }

    fn inferHash(self: OfferedIdentity) Error!Offer {
        const binder_hash: secret.Hash = switch (self.binder.len) {
            // 32 bytes can be SHA-256 or SM3. The legacy parser keeps its
            // historical SHA-256 interpretation; RFC 8998 callers should use
            // parseClientOfferForHash(..., .sm3).
            Sha256.digest_length => .sha256,
            Sha384.digest_length => .sha384,
            else => return error.InvalidPskBinder,
        };
        return self.forHash(binder_hash);
    }
};

pub const ClientOffers = struct {
    identities: []const u8,
    binders: []const u8,
    binder_truncated_len: usize,

    pub fn iterator(self: ClientOffers) Iterator {
        return .{
            .identities = self.identities,
            .binders = self.binders,
            .binder_truncated_len = self.binder_truncated_len,
        };
    }

    pub const Iterator = struct {
        identities: []const u8,
        binders: []const u8,
        binder_truncated_len: usize,
        identity_pos: usize = 0,
        binder_pos: usize = 0,
        selected_identity: u16 = selected_identity_first,

        pub fn next(self: *Iterator) ?OfferedIdentity {
            if (self.identity_pos == self.identities.len) return null;
            const identity_len = std.mem.readInt(
                u16,
                self.identities[self.identity_pos..][0..2],
                .big,
            );
            const identity_start = self.identity_pos + 2;
            const identity_end = identity_start + identity_len;
            const age_start = identity_end;
            self.identity_pos = age_start + @sizeOf(u32);

            const binder_len = self.binders[self.binder_pos];
            const binder_start = self.binder_pos + 1;
            const binder_end = binder_start + binder_len;
            self.binder_pos = binder_end;

            const index = self.selected_identity;
            self.selected_identity += 1;
            return .{
                .selected_identity = index,
                .identity = self.identities[identity_start..identity_end],
                .obfuscated_ticket_age = std.mem.readInt(
                    u32,
                    self.identities[age_start..][0..4],
                    .big,
                ),
                .binder = self.binders[binder_start..binder_end],
                .binder_truncated_len = self.binder_truncated_len,
            };
        }
    };
};

pub const TicketAgePolicy = struct {
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    now_ms: u64,
    tolerance_ms: u32 = 10_000,
};

pub const ClientOfferInput = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk_secret: secret.Secret,
};

/// Advertise support for PSK-DHE so a server may issue a NewSessionTicket even
/// when this ClientHello does not yet carry a `pre_shared_key` offer.
pub fn appendPskDheMode(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) Error!void {
    const original_len = client_hello.items.len;
    errdefer client_hello.items.len = original_len;
    const offsets = try clientHelloOffsets(client_hello.items);
    try rejectExistingPskExtensions(
        client_hello.items,
        offsets.extensions_offset,
        offsets.extensions_len,
    );

    var extension: [6]u8 = undefined;
    std.mem.writeInt(u16, extension[0..2], ext_psk_key_exchange_modes, .big);
    std.mem.writeInt(u16, extension[2..4], 2, .big);
    extension[4] = 1;
    extension[5] = psk_dhe_ke;
    try client_hello.appendSlice(allocator, &extension);

    const new_extensions_len = std.math.add(
        usize,
        offsets.extensions_len,
        extension.len,
    ) catch return error.InvalidClientHello;
    const new_body_len = std.math.add(
        usize,
        offsets.body_len,
        extension.len,
    ) catch return error.InvalidClientHello;
    if (new_extensions_len > std.math.maxInt(u16) or
        new_body_len > std.math.maxInt(u24))
    {
        return error.InvalidClientHello;
    }
    std.mem.writeInt(
        u16,
        client_hello.items[offsets.extensions_len_offset..][0..2],
        @intCast(new_extensions_len),
        .big,
    );
    writeU24(client_hello.items[1..4], @intCast(new_body_len));
}

pub fn appendClientOffer(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [Sha256.digest_length]u8,
) Error!void {
    return appendClientOfferWithEarlyData(
        client_hello,
        allocator,
        identity,
        obfuscated_ticket_age,
        psk,
        false,
    );
}

pub fn appendClientOfferWithEarlyData(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [Sha256.digest_length]u8,
    offer_early_data: bool,
) Error!void {
    var psk_secret = secret.Secret.fromSha256(psk);
    defer psk_secret.deinit();
    return appendClientOfferForSecret(
        client_hello,
        allocator,
        identity,
        obfuscated_ticket_age,
        psk_secret,
        offer_early_data,
        null,
    );
}

pub fn appendClientOfferSha384(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [Sha384.digest_length]u8,
) Error!void {
    return appendClientOfferWithEarlyDataSha384(
        client_hello,
        allocator,
        identity,
        obfuscated_ticket_age,
        psk,
        false,
    );
}

pub fn appendClientOfferWithEarlyDataSha384(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [Sha384.digest_length]u8,
    offer_early_data: bool,
) Error!void {
    var psk_secret = secret.Secret.fromSha384(psk);
    defer psk_secret.deinit();
    return appendClientOfferForSecret(
        client_hello,
        allocator,
        identity,
        obfuscated_ticket_age,
        psk_secret,
        offer_early_data,
        null,
    );
}

pub fn appendClientOfferSm3(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [Sm3.digest_length]u8,
) Error!void {
    return appendClientOfferWithEarlyDataSm3(
        client_hello,
        allocator,
        identity,
        obfuscated_ticket_age,
        psk,
        false,
    );
}

pub fn appendClientOfferWithEarlyDataSm3(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [Sm3.digest_length]u8,
    offer_early_data: bool,
) Error!void {
    var psk_secret = secret.Secret.fromSm3(psk);
    defer psk_secret.deinit();
    return appendClientOfferForSecret(
        client_hello,
        allocator,
        identity,
        obfuscated_ticket_age,
        psk_secret,
        offer_early_data,
        null,
    );
}

/// Append a one-identity PSK offer for the runtime-selected suite hash.
/// `transcript_prefix` is null for ClientHello1, or the transcript through HRR
/// when recomputing the binder in ClientHello2.
pub fn appendClientOfferForSecret(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk_secret: secret.Secret,
    offer_early_data: bool,
    transcript_prefix: ?tls_transcript.State,
) Error!void {
    return appendClientOffersForSecrets(
        client_hello,
        allocator,
        &.{.{
            .identity = identity,
            .obfuscated_ticket_age = obfuscated_ticket_age,
            .psk_secret = psk_secret,
        }},
        offer_early_data,
        transcript_prefix,
    );
}

/// Append one or more RFC 8446 PSK identities and their index-aligned binders.
/// When early data is offered it is associated only with `offers[0]`, as
/// required by RFC 8446 section 4.2.10.
pub fn appendClientOffersForSecrets(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    offers: []const ClientOfferInput,
    offer_early_data: bool,
    transcript_prefix: ?tls_transcript.State,
) Error!void {
    if (offers.len == 0) return error.InvalidPskIdentity;
    var identities_len: usize = 0;
    var binders_len: usize = 0;
    for (offers) |offer| {
        if (offer.identity.len == 0 or
            offer.identity.len > std.math.maxInt(u16))
        {
            return error.InvalidPskIdentity;
        }
        identities_len = std.math.add(
            usize,
            identities_len,
            2 + offer.identity.len + @sizeOf(u32),
        ) catch return error.InvalidPskIdentity;
        binders_len = std.math.add(
            usize,
            binders_len,
            1 + offer.psk_secret.hash.len(),
        ) catch return error.InvalidPskBinder;
    }
    const psk_payload_len = std.math.add(
        usize,
        2 + identities_len,
        2 + binders_len,
    ) catch return error.InvalidClientHello;
    if (identities_len > std.math.maxInt(u16) or
        binders_len > std.math.maxInt(u16) or
        psk_payload_len > std.math.maxInt(u16))
    {
        return error.InvalidClientHello;
    }

    const original_len = client_hello.items.len;
    errdefer client_hello.items.len = original_len;
    const offsets = try clientHelloOffsets(client_hello.items);
    try rejectExistingPskExtensions(
        client_hello.items,
        offsets.extensions_offset,
        offsets.extensions_len,
    );

    var mode_extension: [6]u8 = undefined;
    std.mem.writeInt(u16, mode_extension[0..2], ext_psk_key_exchange_modes, .big);
    std.mem.writeInt(u16, mode_extension[2..4], 2, .big);
    mode_extension[4] = 1;
    mode_extension[5] = psk_dhe_ke;
    try client_hello.appendSlice(allocator, &mode_extension);
    if (offer_early_data) {
        var early_data_extension: [4]u8 = undefined;
        std.mem.writeInt(u16, early_data_extension[0..2], ext_early_data, .big);
        std.mem.writeInt(u16, early_data_extension[2..4], 0, .big);
        try client_hello.appendSlice(allocator, &early_data_extension);
    }

    var extension_header: [6]u8 = undefined;
    std.mem.writeInt(u16, extension_header[0..2], ext_pre_shared_key, .big);
    std.mem.writeInt(u16, extension_header[2..4], @intCast(psk_payload_len), .big);
    std.mem.writeInt(u16, extension_header[4..6], @intCast(identities_len), .big);
    try client_hello.appendSlice(allocator, &extension_header);
    for (offers) |offer| {
        var identity_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &identity_len, @intCast(offer.identity.len), .big);
        try client_hello.appendSlice(allocator, &identity_len);
        try client_hello.appendSlice(allocator, offer.identity);
        var age: [4]u8 = undefined;
        std.mem.writeInt(u32, &age, offer.obfuscated_ticket_age, .big);
        try client_hello.appendSlice(allocator, &age);
    }

    const binder_truncated_len = client_hello.items.len;
    var binders_header: [2]u8 = undefined;
    std.mem.writeInt(u16, &binders_header, @intCast(binders_len), .big);
    try client_hello.appendSlice(allocator, &binders_header);
    for (offers) |offer| {
        try client_hello.append(allocator, @intCast(offer.psk_secret.hash.len()));
        try client_hello.appendNTimes(
            allocator,
            0,
            offer.psk_secret.hash.len(),
        );
    }

    const added = client_hello.items.len - offsets.message_len;
    const new_extensions_len = std.math.add(
        usize,
        offsets.extensions_len,
        added,
    ) catch return error.InvalidClientHello;
    const new_body_len = std.math.add(
        usize,
        offsets.body_len,
        added,
    ) catch return error.InvalidClientHello;
    if (new_extensions_len > std.math.maxInt(u16) or
        new_body_len > std.math.maxInt(u24))
    {
        return error.InvalidClientHello;
    }
    std.mem.writeInt(
        u16,
        client_hello.items[offsets.extensions_len_offset..][0..2],
        @intCast(new_extensions_len),
        .big,
    );
    writeU24(client_hello.items[1..4], @intCast(new_body_len));

    var binder_pos = binder_truncated_len + 2;
    for (offers) |offer| {
        binder_pos += 1;
        const binder_end = binder_pos + offer.psk_secret.hash.len();
        try writeBinderForSecret(
            client_hello.items[binder_pos..binder_end],
            client_hello.items[0..binder_truncated_len],
            offer.psk_secret,
            transcript_prefix,
        );
        binder_pos = binder_end;
    }
}

fn writeBinderForSecret(
    output: []u8,
    truncated_client_hello: []const u8,
    psk_secret: secret.Secret,
    transcript_prefix: ?tls_transcript.State,
) Error!void {
    switch (psk_secret.hash) {
        .sha256 => {
            const binder_hash = try binderTranscriptHash(
                key_schedule.Sha256,
                truncated_client_hello,
                transcript_prefix,
            );
            const binder = key_schedule.Sha256.computeBinder(
                psk_secret.sha256() catch return error.InvalidPskBinder,
                binder_hash,
            );
            @memcpy(output, &binder);
        },
        .sha384 => {
            const binder_hash = try binderTranscriptHash(
                key_schedule.Sha384,
                truncated_client_hello,
                transcript_prefix,
            );
            const binder = key_schedule.Sha384.computeBinder(
                psk_secret.sha384() catch return error.InvalidPskBinder,
                binder_hash,
            );
            @memcpy(output, &binder);
        },
        .sm3 => {
            const binder_hash = try binderTranscriptHash(
                key_schedule.Sm3,
                truncated_client_hello,
                transcript_prefix,
            );
            const binder = key_schedule.Sm3.computeBinder(
                psk_secret.sm3() catch return error.InvalidPskBinder,
                binder_hash,
            );
            @memcpy(output, &binder);
        },
    }
}

fn rejectExistingPskExtensions(
    client_hello: []const u8,
    extensions_offset: usize,
    extensions_len: usize,
) Error!void {
    var pos = extensions_offset;
    const extensions_end = extensions_offset + extensions_len;
    while (pos < extensions_end) {
        if (extensions_end - pos < 4) return error.InvalidClientHello;
        const typ = std.mem.readInt(u16, client_hello[pos..][0..2], .big);
        const len = std.mem.readInt(
            u16,
            client_hello[pos + 2 ..][0..2],
            .big,
        );
        const payload_start = pos + 4;
        const payload_end = std.math.add(
            usize,
            payload_start,
            len,
        ) catch return error.InvalidClientHello;
        if (payload_end > extensions_end) return error.InvalidClientHello;
        if (typ == ext_psk_key_exchange_modes or
            typ == ext_pre_shared_key or
            typ == ext_early_data)
        {
            return error.InvalidClientHello;
        }
        pos = payload_end;
    }
}

pub fn parseClientOffer(client_hello: []const u8) Error!Offer {
    return parseClientOfferForExpectedHash(client_hello, null);
}

/// Parse and validate the complete RFC 8446 offered_psks vectors without
/// allocating. Identities and binders remain paired by their wire index.
pub fn parseClientOffers(client_hello: []const u8) Error!ClientOffers {
    const offsets = try clientHelloOffsets(client_hello);
    var pos = offsets.extensions_offset;
    const extensions_end = offsets.extensions_offset + offsets.extensions_len;
    var saw_mode_extension = false;
    var supports_psk_dhe = false;
    while (pos < extensions_end) {
        if (extensions_end - pos < 4) return error.InvalidClientHello;
        const typ = std.mem.readInt(u16, client_hello[pos..][0..2], .big);
        const len = std.mem.readInt(u16, client_hello[pos + 2 ..][0..2], .big);
        const payload_start = pos + 4;
        const payload_end = std.math.add(
            usize,
            payload_start,
            len,
        ) catch return error.InvalidClientHello;
        if (payload_end > extensions_end) return error.InvalidClientHello;
        if (typ == ext_psk_key_exchange_modes) {
            if (saw_mode_extension) return error.InvalidClientHello;
            saw_mode_extension = true;
            if (len < 2) return error.UnsupportedPskKeyExchangeMode;
            const modes_len = client_hello[payload_start];
            if (modes_len == 0 or @as(usize, modes_len) + 1 != len) {
                return error.UnsupportedPskKeyExchangeMode;
            }
            supports_psk_dhe = std.mem.indexOfScalar(
                u8,
                client_hello[payload_start + 1 .. payload_end],
                psk_dhe_ke,
            ) != null;
        } else if (typ == ext_pre_shared_key) {
            if (payload_end != extensions_end) {
                return error.PskExtensionNotLast;
            }
            if (!saw_mode_extension or !supports_psk_dhe) {
                return error.UnsupportedPskKeyExchangeMode;
            }
            return parseOffersPayload(
                client_hello,
                payload_start,
                payload_end,
            );
        }
        pos = payload_end;
    }
    return error.MissingPskOffer;
}

pub fn findClientOfferForIdentityForHash(
    client_hello: []const u8,
    expected_identity: []const u8,
    expected_hash: secret.Hash,
) Error!?Offer {
    var iterator = (try parseClientOffers(client_hello)).iterator();
    while (iterator.next()) |offered| {
        if (std.mem.eql(u8, offered.identity, expected_identity)) {
            return try offered.forHash(expected_hash);
        }
    }
    return null;
}

pub fn parseClientOfferAtForHash(
    client_hello: []const u8,
    selected_identity: u16,
    expected_hash: secret.Hash,
) Error!Offer {
    var iterator = (try parseClientOffers(client_hello)).iterator();
    while (iterator.next()) |offered| {
        if (offered.selected_identity == selected_identity) {
            return offered.forHash(expected_hash);
        }
    }
    return error.InvalidPskIdentity;
}

/// Parse a ClientHello PSK extension when the selected suite's binder hash is
/// already known. This is required for RFC 8998 SM3 because its 32-byte binder
/// length is intentionally indistinguishable from SHA-256 on the wire.
pub fn parseClientOfferForHash(
    client_hello: []const u8,
    expected_hash: secret.Hash,
) Error!Offer {
    return parseClientOfferForExpectedHash(client_hello, expected_hash);
}

fn parseClientOfferForExpectedHash(
    client_hello: []const u8,
    expected_hash: ?secret.Hash,
) Error!Offer {
    var iterator = (try parseClientOffers(client_hello)).iterator();
    const offered = iterator.next() orelse return error.InvalidPskIdentity;
    return if (expected_hash) |hash|
        offered.forHash(hash)
    else
        offered.inferHash();
}

pub fn verifyClientOffer(
    client_hello: []const u8,
    offer: Offer,
    expected_identity: []const u8,
    psk: [Sha256.digest_length]u8,
) Error!void {
    return verifyClientOfferForSchedule(
        key_schedule.Sha256,
        .sha256,
        client_hello,
        offer,
        expected_identity,
        psk,
        null,
    );
}

pub fn verifyClientOfferSha384(
    client_hello: []const u8,
    offer: Offer,
    expected_identity: []const u8,
    psk: [Sha384.digest_length]u8,
) Error!void {
    return verifyClientOfferForSchedule(
        key_schedule.Sha384,
        .sha384,
        client_hello,
        offer,
        expected_identity,
        psk,
        null,
    );
}

pub fn verifyClientOfferForSecret(
    client_hello: []const u8,
    offer: Offer,
    expected_identity: []const u8,
    psk_secret: secret.Secret,
    transcript_prefix: ?tls_transcript.State,
) Error!void {
    return switch (psk_secret.hash) {
        .sha256 => verifyClientOfferForSchedule(
            key_schedule.Sha256,
            .sha256,
            client_hello,
            offer,
            expected_identity,
            psk_secret.sha256() catch return error.InvalidPskBinder,
            transcript_prefix,
        ),
        .sha384 => verifyClientOfferForSchedule(
            key_schedule.Sha384,
            .sha384,
            client_hello,
            offer,
            expected_identity,
            psk_secret.sha384() catch return error.InvalidPskBinder,
            transcript_prefix,
        ),
        .sm3 => verifyClientOfferForSchedule(
            key_schedule.Sm3,
            .sm3,
            client_hello,
            offer,
            expected_identity,
            psk_secret.sm3() catch return error.InvalidPskBinder,
            transcript_prefix,
        ),
    };
}

pub fn verifyClientOfferSm3(
    client_hello: []const u8,
    offer: Offer,
    expected_identity: []const u8,
    psk: [Sm3.digest_length]u8,
) Error!void {
    return verifyClientOfferForSchedule(
        key_schedule.Sm3,
        .sm3,
        client_hello,
        offer,
        expected_identity,
        psk,
        null,
    );
}

fn verifyClientOfferForSchedule(
    comptime Schedule: type,
    expected_hash: secret.Hash,
    client_hello: []const u8,
    offer: Offer,
    expected_identity: []const u8,
    psk: [Schedule.secret_len]u8,
    transcript_prefix: ?tls_transcript.State,
) Error!void {
    if (!std.mem.eql(u8, offer.identity, expected_identity)) {
        return error.InvalidPskIdentity;
    }
    if (offer.binder_hash != expected_hash or
        offer.binder.len != Schedule.secret_len)
    {
        return error.InvalidPskBinder;
    }
    const binder_hash = try binderTranscriptHash(
        Schedule,
        client_hello[0..offer.binder_truncated_len],
        transcript_prefix,
    );
    const expected = Schedule.computeBinder(
        psk,
        binder_hash,
    );
    const actual: [Schedule.secret_len]u8 =
        offer.binder[0..Schedule.secret_len].*;
    if (!std.crypto.timing_safe.eql(
        [Schedule.secret_len]u8,
        actual,
        expected,
    )) {
        return error.InvalidPskBinder;
    }
}

/// Validate that a ticket is still usable for PSK resumption and return its
/// server-observed age in milliseconds.
pub fn validateTicketLifetime(policy: TicketAgePolicy) Error!u32 {
    if (policy.lifetime_seconds == 0 or policy.now_ms < policy.issued_at_ms) {
        return error.ExpiredPsk;
    }
    const actual_age = policy.now_ms - policy.issued_at_ms;
    const lifetime_ms = @as(u64, policy.lifetime_seconds) *
        std.time.ms_per_s;
    if (actual_age >= lifetime_ms or actual_age > std.math.maxInt(u32)) {
        return error.ExpiredPsk;
    }
    return @intCast(actual_age);
}

/// Report whether a valid ticket is fresh enough to permit 0-RTT. RFC 8446
/// allows PSK resumption to continue when this returns false.
pub fn ticketAgeWithinTolerance(
    offer: Offer,
    policy: TicketAgePolicy,
) Error!bool {
    const actual_age = try validateTicketLifetime(policy);
    const offered_age = offer.obfuscated_ticket_age -% policy.age_add;
    const skew = if (offered_age > actual_age)
        offered_age - actual_age
    else
        actual_age - offered_age;
    return skew <= policy.tolerance_ms;
}

/// Strict client-side validation for callers that require both a live ticket
/// and an age within tolerance.
pub fn validateTicketAge(
    offer: Offer,
    policy: TicketAgePolicy,
) Error!void {
    if (!try ticketAgeWithinTolerance(offer, policy)) {
        return error.InvalidPskAge;
    }
}

pub fn appendServerSelection(
    extensions: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) Error!void {
    return appendServerSelectionForIdentity(
        extensions,
        allocator,
        selected_identity_first,
    );
}

pub fn appendServerSelectionForIdentity(
    extensions: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    selected_identity: u16,
) Error!void {
    var extension: [6]u8 = undefined;
    std.mem.writeInt(u16, extension[0..2], ext_pre_shared_key, .big);
    std.mem.writeInt(u16, extension[2..4], 2, .big);
    std.mem.writeInt(u16, extension[4..6], selected_identity, .big);
    try extensions.appendSlice(allocator, &extension);
}

pub fn parseServerSelection(payload: []const u8) Error!u16 {
    if (payload.len != 2) return error.InvalidServerHello;
    return std.mem.readInt(u16, payload[0..2], .big);
}

pub fn clientOfferedEarlyData(client_hello: []const u8) Error!bool {
    const offsets = try clientHelloOffsets(client_hello);
    return containsEmptyEarlyDataExtension(
        client_hello,
        offsets.extensions_offset,
        offsets.extensions_len,
        error.InvalidClientHello,
    );
}

pub fn serverAcceptedEarlyData(extensions: []const u8) Error!bool {
    return containsEmptyEarlyDataExtension(
        extensions,
        0,
        extensions.len,
        error.InvalidServerHello,
    );
}

fn containsEmptyEarlyDataExtension(
    bytes: []const u8,
    extensions_offset: usize,
    extensions_len: usize,
    invalid_error: Error,
) Error!bool {
    var pos = extensions_offset;
    const extensions_end = std.math.add(
        usize,
        extensions_offset,
        extensions_len,
    ) catch return invalid_error;
    if (extensions_end > bytes.len) return invalid_error;
    var found = false;
    while (pos < extensions_end) {
        if (extensions_end - pos < 4) return invalid_error;
        const typ = std.mem.readInt(u16, bytes[pos..][0..2], .big);
        const len = std.mem.readInt(u16, bytes[pos + 2 ..][0..2], .big);
        const payload_start = pos + 4;
        const payload_end = std.math.add(
            usize,
            payload_start,
            len,
        ) catch return invalid_error;
        if (payload_end > extensions_end) return invalid_error;
        if (typ == ext_early_data) {
            if (found or len != 0) return invalid_error;
            found = true;
        }
        pos = payload_end;
    }
    return found;
}

pub fn computeBinder(
    psk: [Sha256.digest_length]u8,
    truncated_client_hello_hash: [Sha256.digest_length]u8,
) [Sha256.digest_length]u8 {
    return key_schedule.computeBinder(
        psk,
        truncated_client_hello_hash,
    );
}

pub fn earlySecret(
    psk: ?[Sha256.digest_length]u8,
) [Sha256.digest_length]u8 {
    return key_schedule.earlySecret(psk);
}

pub fn deriveClientEarlyTrafficSecret(
    psk: [Sha256.digest_length]u8,
    client_hello_hash: [Sha256.digest_length]u8,
) [Sha256.digest_length]u8 {
    return key_schedule
        .deriveClientEarlyTrafficSecret(
        psk,
        client_hello_hash,
    );
}

fn parseOffersPayload(
    client_hello: []const u8,
    payload_start: usize,
    payload_end: usize,
) Error!ClientOffers {
    var pos = payload_start;
    if (payload_end - pos < 2) return error.InvalidClientHello;
    const identities_len =
        std.mem.readInt(u16, client_hello[pos..][0..2], .big);
    pos += 2;
    const identities_start = pos;
    const identities_end = std.math.add(
        usize,
        pos,
        identities_len,
    ) catch return error.InvalidPskIdentity;
    if (identities_end > payload_end or identities_len < 7) {
        return error.InvalidPskIdentity;
    }
    var identity_count: usize = 0;
    while (pos < identities_end) : (identity_count += 1) {
        if (identities_end - pos < 2) return error.InvalidPskIdentity;
        const identity_len =
            std.mem.readInt(u16, client_hello[pos..][0..2], .big);
        pos += 2;
        const identity_end = std.math.add(
            usize,
            pos,
            identity_len,
        ) catch return error.InvalidPskIdentity;
        const age_end = std.math.add(
            usize,
            identity_end,
            @sizeOf(u32),
        ) catch return error.InvalidPskIdentity;
        if (identity_len == 0 or age_end > identities_end) {
            return error.InvalidPskIdentity;
        }
        pos = age_end;
    }
    if (pos != identities_end) return error.InvalidPskIdentity;
    if (payload_end - pos < 2) return error.InvalidPskBinder;

    const binder_truncated_len = pos;
    const binders_len =
        std.mem.readInt(u16, client_hello[pos..][0..2], .big);
    pos += 2;
    const binders_start = pos;
    const binders_end = std.math.add(
        usize,
        binders_start,
        binders_len,
    ) catch return error.InvalidPskBinder;
    if (binders_len < 33 or binders_end != payload_end) {
        return error.InvalidPskBinder;
    }
    var binder_count: usize = 0;
    while (pos < binders_end) : (binder_count += 1) {
        const binder_len = client_hello[pos];
        pos += 1;
        if (binder_len < 32 or binder_len > binders_end - pos) {
            return error.InvalidPskBinder;
        }
        pos += binder_len;
    }
    if (pos != binders_end or binder_count != identity_count) {
        return error.InvalidPskBinder;
    }
    return .{
        .identities = client_hello[identities_start..identities_end],
        .binders = client_hello[binders_start..binders_end],
        .binder_truncated_len = binder_truncated_len,
    };
}

const ClientHelloOffsets = struct {
    message_len: usize,
    body_len: usize,
    extensions_len_offset: usize,
    extensions_offset: usize,
    extensions_len: usize,
};

fn clientHelloOffsets(bytes: []const u8) Error!ClientHelloOffsets {
    if (bytes.len < 4 or bytes[0] != 1) return error.InvalidClientHello;
    const body_len = readU24(bytes[1..4]);
    if (body_len + 4 != bytes.len) return error.InvalidClientHello;
    var pos: usize = 4 + 2 + 32;
    if (pos >= bytes.len) return error.InvalidClientHello;
    const session_id_len = bytes[pos];
    pos = std.math.add(
        usize,
        pos + 1,
        session_id_len,
    ) catch return error.InvalidClientHello;
    if (pos + 2 > bytes.len) return error.InvalidClientHello;
    const cipher_suites_len = std.mem.readInt(u16, bytes[pos..][0..2], .big);
    pos = std.math.add(
        usize,
        pos + 2,
        cipher_suites_len,
    ) catch return error.InvalidClientHello;
    if (pos >= bytes.len) return error.InvalidClientHello;
    const compression_len = bytes[pos];
    pos = std.math.add(
        usize,
        pos + 1,
        compression_len,
    ) catch return error.InvalidClientHello;
    if (pos + 2 > bytes.len) return error.InvalidClientHello;
    const extensions_len_offset = pos;
    const extensions_len = std.mem.readInt(u16, bytes[pos..][0..2], .big);
    pos += 2;
    if (pos + extensions_len != bytes.len) return error.InvalidClientHello;
    return .{
        .message_len = bytes.len,
        .body_len = body_len,
        .extensions_len_offset = extensions_len_offset,
        .extensions_offset = pos,
        .extensions_len = extensions_len,
    };
}

fn transcriptHash(
    comptime Schedule: type,
    bytes: []const u8,
) [Schedule.secret_len]u8 {
    const Hash = if (Schedule == key_schedule.Sha256)
        Sha256
    else if (Schedule == key_schedule.Sha384)
        Sha384
    else if (Schedule == key_schedule.Sm3)
        Sm3
    else
        @compileError("unsupported TLS key schedule");
    var out: [Schedule.secret_len]u8 = undefined;
    Hash.hash(bytes, &out, .{});
    return out;
}

fn binderTranscriptHash(
    comptime Schedule: type,
    bytes: []const u8,
    prefix: ?tls_transcript.State,
) Error![Schedule.secret_len]u8 {
    if (prefix) |prefix_state| {
        var state = prefix_state;
        state.update(bytes);
        const digest = state.digest();
        return if (Schedule == key_schedule.Sha256)
            digest.sha256() catch error.InvalidPskBinder
        else if (Schedule == key_schedule.Sha384)
            digest.sha384() catch error.InvalidPskBinder
        else if (Schedule == key_schedule.Sm3)
            digest.sm3() catch error.InvalidPskBinder
        else
            @compileError("unsupported TLS key schedule");
    }
    return transcriptHash(Schedule, bytes);
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn writeU24(bytes: *[3]u8, value: u24) void {
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}

test "TLS client can advertise future PSK-DHE resumption without a ticket" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    try appendPskDheMode(&hello, allocator);
    const parsed = try @import("client_hello.zig").parse(hello.items);
    try std.testing.expectEqualSlices(
        u8,
        &.{psk_dhe_ke},
        parsed.psk_key_exchange_modes,
    );
    try std.testing.expect(parsed.pre_shared_key == null);

    const once = try allocator.dupe(u8, hello.items);
    defer allocator.free(once);
    try std.testing.expectError(
        error.InvalidClientHello,
        appendPskDheMode(&hello, allocator),
    );
    try std.testing.expectEqualSlices(u8, once, hello.items);
}

test "TLS PSK appends and verifies a mandatory-last binder" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    const psk = [_]u8{0x42} ** Sha256.digest_length;
    try appendClientOffer(
        &hello,
        allocator,
        "ticket-id",
        0x01020304,
        psk,
    );

    const offer = try parseClientOffer(hello.items);
    try std.testing.expectEqualStrings("ticket-id", offer.identity);
    try std.testing.expectEqual(@as(u32, 0x01020304), offer.obfuscated_ticket_age);
    try verifyClientOffer(hello.items, offer, "ticket-id", psk);

    var tampered = try hello.clone(allocator);
    defer tampered.deinit(allocator);
    tampered.items[offer.binder_truncated_len - 1] ^= 1;
    const tampered_offer = try parseClientOffer(tampered.items);
    try std.testing.expectError(
        error.InvalidPskBinder,
        verifyClientOffer(
            tampered.items,
            tampered_offer,
            "ticket-id",
            psk,
        ),
    );
    try std.testing.expectError(
        error.InvalidPskIdentity,
        verifyClientOffer(hello.items, offer, "other", psk),
    );
}

test "TLS PSK preserves multiple identity and binder indexes" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    var first_secret = secret.Secret.fromSha384([_]u8{0x31} ** 48);
    defer first_secret.deinit();
    var second_secret = secret.Secret.fromSha256([_]u8{0x32} ** 32);
    defer second_secret.deinit();
    try appendClientOffersForSecrets(
        &hello,
        allocator,
        &.{
            .{
                .identity = "first-ticket",
                .obfuscated_ticket_age = 11,
                .psk_secret = first_secret,
            },
            .{
                .identity = "second-ticket",
                .obfuscated_ticket_age = 22,
                .psk_secret = second_secret,
            },
        },
        true,
        null,
    );

    var iterator = (try parseClientOffers(hello.items)).iterator();
    const first_offered = iterator.next().?;
    try std.testing.expectEqual(@as(u16, 0), first_offered.selected_identity);
    try std.testing.expectEqualStrings("first-ticket", first_offered.identity);
    try std.testing.expectEqual(@as(u32, 11), first_offered.obfuscated_ticket_age);
    const first = try first_offered.forHash(.sha384);
    try verifyClientOfferForSecret(
        hello.items,
        first,
        first.identity,
        first_secret,
        null,
    );

    const second_offered = iterator.next().?;
    try std.testing.expectEqual(@as(u16, 1), second_offered.selected_identity);
    try std.testing.expectEqualStrings("second-ticket", second_offered.identity);
    try std.testing.expectEqual(@as(u32, 22), second_offered.obfuscated_ticket_age);
    const second = try second_offered.forHash(.sha256);
    try verifyClientOfferForSecret(
        hello.items,
        second,
        second.identity,
        second_secret,
        null,
    );
    try std.testing.expect(iterator.next() == null);

    const selected = (try findClientOfferForIdentityForHash(
        hello.items,
        "second-ticket",
        .sha256,
    )).?;
    try std.testing.expectEqual(@as(u16, 1), selected.selected_identity);

    var malformed = try hello.clone(allocator);
    defer malformed.deinit(allocator);
    const second_binder_len_offset =
        @intFromPtr(second_offered.binder.ptr) -
        @intFromPtr(hello.items.ptr) - 1;
    malformed.items[second_binder_len_offset] -= 1;
    try std.testing.expectError(
        error.InvalidPskBinder,
        parseClientOffers(malformed.items),
    );

    var server_extensions: std.ArrayList(u8) = .empty;
    defer server_extensions.deinit(allocator);
    try appendServerSelectionForIdentity(&server_extensions, allocator, 1);
    try std.testing.expectEqual(
        @as(u16, 1),
        try parseServerSelection(server_extensions.items[4..]),
    );
}

test "TLS PSK binder includes the HelloRetryRequest transcript prefix" {
    const allocator = std.testing.allocator;
    var second_hello = try baseClientHello(allocator);
    defer second_hello.deinit(allocator);
    const psk_secret = secret.Secret.fromSha256([_]u8{0x49} ** 32);
    const prefix = tls_transcript.afterHelloRetryRequest(
        .sha256,
        "first-client-hello",
        "hello-retry-request",
    );
    try appendClientOfferForSecret(
        &second_hello,
        allocator,
        "ticket-id",
        17,
        psk_secret,
        false,
        prefix,
    );
    const offer = try parseClientOfferForHash(second_hello.items, .sha256);
    try verifyClientOfferForSecret(
        second_hello.items,
        offer,
        "ticket-id",
        psk_secret,
        prefix,
    );
    try std.testing.expectError(
        error.InvalidPskBinder,
        verifyClientOfferForSecret(
            second_hello.items,
            offer,
            "ticket-id",
            psk_secret,
            null,
        ),
    );
}

test "TLS PSK SHA-384 binder uses 48 wire bytes and rejects SHA-256 verification" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    const psk = [_]u8{0x84} ** Sha384.digest_length;
    try appendClientOfferSha384(
        &hello,
        allocator,
        "sha384-ticket",
        0x11223344,
        psk,
    );
    const offer = try parseClientOffer(hello.items);
    try std.testing.expectEqual(secret.Hash.sha384, offer.binder_hash);
    try std.testing.expectEqual(
        @as(usize, Sha384.digest_length),
        offer.binder.len,
    );
    try verifyClientOfferSha384(
        hello.items,
        offer,
        "sha384-ticket",
        psk,
    );
    try std.testing.expectError(
        error.InvalidPskBinder,
        verifyClientOffer(
            hello.items,
            offer,
            "sha384-ticket",
            psk[0..Sha256.digest_length].*,
        ),
    );
}

test "TLS PSK SM3 binder requires hash-aware parsing" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    const psk = [_]u8{0xc3} ** Sm3.digest_length;
    try appendClientOfferSm3(
        &hello,
        allocator,
        "sm3-ticket",
        0x01020304,
        psk,
    );

    const legacy_offer = try parseClientOffer(hello.items);
    try std.testing.expectEqual(secret.Hash.sha256, legacy_offer.binder_hash);
    try std.testing.expectError(
        error.InvalidPskBinder,
        verifyClientOfferSm3(
            hello.items,
            legacy_offer,
            "sm3-ticket",
            psk,
        ),
    );

    const offer = try parseClientOfferForHash(hello.items, .sm3);
    try std.testing.expectEqual(secret.Hash.sm3, offer.binder_hash);
    try verifyClientOfferSm3(
        hello.items,
        offer,
        "sm3-ticket",
        psk,
    );
}

test "TLS PSK rejects malformed modes and non-last selection" {
    const allocator = std.testing.allocator;
    const offered_psk = [_]u8{0x33} ** Sha256.digest_length;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    try appendClientOffer(
        &hello,
        allocator,
        "ticket",
        0,
        offered_psk,
    );
    const offsets = try clientHelloOffsets(hello.items);
    // Locate psk_key_exchange_modes and replace psk_dhe_ke with psk_ke.
    var pos = offsets.extensions_offset;
    while (pos < hello.items.len) {
        const typ = std.mem.readInt(u16, hello.items[pos..][0..2], .big);
        const len = std.mem.readInt(u16, hello.items[pos + 2 ..][0..2], .big);
        if (typ == ext_psk_key_exchange_modes) {
            hello.items[pos + 5] = 0;
            break;
        }
        pos += 4 + len;
    }
    try std.testing.expectError(
        error.UnsupportedPskKeyExchangeMode,
        parseClientOffer(hello.items),
    );

    var multi_mode_hello = try baseClientHello(allocator);
    defer multi_mode_hello.deinit(allocator);
    try appendClientOffer(
        &multi_mode_hello,
        allocator,
        "ticket",
        0,
        offered_psk,
    );
    const multi_offsets = try clientHelloOffsets(multi_mode_hello.items);
    pos = multi_offsets.extensions_offset;
    while (pos < multi_mode_hello.items.len) {
        const typ = std.mem.readInt(
            u16,
            multi_mode_hello.items[pos..][0..2],
            .big,
        );
        const len = std.mem.readInt(
            u16,
            multi_mode_hello.items[pos + 2 ..][0..2],
            .big,
        );
        if (typ == ext_psk_key_exchange_modes) break;
        pos += 4 + len;
    }
    var both_modes: std.ArrayList(u8) = .empty;
    defer both_modes.deinit(allocator);
    try both_modes.appendSlice(allocator, multi_mode_hello.items[0 .. pos + 2]);
    try both_modes.appendSlice(allocator, &.{ 0, 3, 2, 0, psk_dhe_ke });
    try both_modes.appendSlice(allocator, multi_mode_hello.items[pos + 6 ..]);
    std.mem.writeInt(
        u16,
        both_modes.items[multi_offsets.extensions_len_offset..][0..2],
        @intCast(multi_offsets.extensions_len + 1),
        .big,
    );
    writeU24(both_modes.items[1..4], @intCast(multi_offsets.body_len + 1));
    try std.testing.expectEqualStrings(
        "ticket",
        (try parseClientOffer(both_modes.items)).identity,
    );

    var server_extensions: std.ArrayList(u8) = .empty;
    defer server_extensions.deinit(allocator);
    try appendServerSelection(&server_extensions, allocator);
    try std.testing.expectEqual(
        selected_identity_first,
        try parseServerSelection(server_extensions.items[4..]),
    );
    try std.testing.expectEqual(
        @as(u16, 1),
        try parseServerSelection(&.{ 0, 1 }),
    );
    try std.testing.expectError(
        error.InvalidServerHello,
        parseServerSelection(&.{1}),
    );
}

test "TLS PSK rejects duplicate offer extensions" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    const psk = [_]u8{0x35} ** Sha256.digest_length;
    try appendClientOffer(&hello, allocator, "ticket", 0, psk);
    try std.testing.expectError(
        error.InvalidClientHello,
        appendClientOffer(&hello, allocator, "ticket", 0, psk),
    );
    _ = try parseClientOffer(hello.items);

    // Turning the mode extension into a duplicate pre_shared_key extension
    // must fail before the payload can be interpreted as an identity vector.
    const offsets = try clientHelloOffsets(hello.items);
    std.mem.writeInt(
        u16,
        hello.items[offsets.extensions_offset..][0..2],
        ext_pre_shared_key,
        .big,
    );
    try std.testing.expectError(
        error.PskExtensionNotLast,
        parseClientOffer(hello.items),
    );
}

test "TLS PSK offers and parses early data before mandatory-last PSK" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    const psk = [_]u8{0x36} ** Sha256.digest_length;
    try appendClientOfferWithEarlyData(
        &hello,
        allocator,
        "ticket",
        0,
        psk,
        true,
    );
    const offer = try parseClientOffer(hello.items);
    try verifyClientOffer(hello.items, offer, "ticket", psk);
    try std.testing.expect(try clientOfferedEarlyData(hello.items));

    var server_extensions: std.ArrayList(u8) = .empty;
    defer server_extensions.deinit(allocator);
    var early_data_extension: [4]u8 = undefined;
    std.mem.writeInt(u16, early_data_extension[0..2], ext_early_data, .big);
    std.mem.writeInt(u16, early_data_extension[2..4], 0, .big);
    try server_extensions.appendSlice(allocator, &early_data_extension);
    try std.testing.expect(try serverAcceptedEarlyData(server_extensions.items));
}

test "TLS PSK changes handshake key schedule" {
    const psk = [_]u8{0x55} ** Sha256.digest_length;
    const with_psk = earlySecret(psk);
    const without_psk = earlySecret(null);
    try std.testing.expect(!std.mem.eql(u8, &with_psk, &without_psk));
    try std.testing.expectEqualSlices(u8, &with_psk, &earlySecret(psk));
    try std.testing.expectEqualSlices(
        u8,
        &@import("key_schedule.zig").earlySecret(null),
        &without_psk,
    );
    const early = deriveClientEarlyTrafficSecret(
        psk,
        [_]u8{0xa5} ** Sha256.digest_length,
    );
    try std.testing.expect(!std.mem.eql(u8, &early, &with_psk));
}

test "TLS PSK validates ticket age, lifetime, and skew" {
    var hello = try baseClientHello(std.testing.allocator);
    defer hello.deinit(std.testing.allocator);
    try appendClientOffer(
        &hello,
        std.testing.allocator,
        "ticket",
        500 +% 17,
        [_]u8{0x44} ** Sha256.digest_length,
    );
    const offer = try parseClientOffer(hello.items);
    try validateTicketAge(offer, .{
        .age_add = 17,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
        .now_ms = 1500,
        .tolerance_ms = 0,
    });
    try std.testing.expect(!(try ticketAgeWithinTolerance(offer, .{
        .age_add = 17,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
        .now_ms = 1600,
        .tolerance_ms = 10,
    })));
    try std.testing.expectError(
        error.InvalidPskAge,
        validateTicketAge(offer, .{
            .age_add = 17,
            .issued_at_ms = 1000,
            .lifetime_seconds = 10,
            .now_ms = 1600,
            .tolerance_ms = 10,
        }),
    );
    try std.testing.expectError(
        error.ExpiredPsk,
        validateTicketAge(offer, .{
            .age_add = 17,
            .issued_at_ms = 1000,
            .lifetime_seconds = 10,
            .now_ms = 999,
        }),
    );
    try std.testing.expectError(
        error.ExpiredPsk,
        validateTicketAge(offer, .{
            .age_add = 17,
            .issued_at_ms = 1000,
            .lifetime_seconds = 1,
            .now_ms = 2000,
        }),
    );
}

fn checkAppendClientOfferAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    try appendClientOffer(
        &hello,
        allocator,
        "ticket",
        1,
        [_]u8{0x77} ** Sha256.digest_length,
    );
    const offer = try parseClientOffer(hello.items);
    try verifyClientOffer(
        hello.items,
        offer,
        "ticket",
        [_]u8{0x77} ** Sha256.digest_length,
    );
}

test "TLS PSK ClientHello append is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkAppendClientOfferAllocationFailure,
        .{},
    );
}

fn baseClientHello(allocator: std.mem.Allocator) !std.ArrayList(u8) {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    // legacy_version + random + empty session ID + one cipher + null
    // compression + empty extension vector.
    try body.appendSlice(allocator, &.{ 0x03, 0x03 });
    try body.appendNTimes(allocator, 0x11, 32);
    try body.append(allocator, 0);
    try body.appendSlice(allocator, &.{ 0, 2, 0x13, 0x01, 1, 0 });
    try body.appendSlice(allocator, &.{ 0, 0 });

    var hello: std.ArrayList(u8) = .empty;
    errdefer hello.deinit(allocator);
    try hello.append(allocator, 1);
    var len_bytes: [3]u8 = undefined;
    writeU24(&len_bytes, @intCast(body.items.len));
    try hello.appendSlice(allocator, &len_bytes);
    try hello.appendSlice(allocator, body.items);
    body.deinit(allocator);
    return hello;
}
