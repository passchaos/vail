//! Optional cryptographic backend metadata.
//!
//! Vail's protocol APIs default to audited Zig implementations.  Builds may
//! point at an AWS-LC checkout with `-Daws-lc-path=...`; when libraries are
//! available, `-Daws-lc-link=true` also links libcrypto.  The local checkout at
//! `~/Work/aws-lc` currently disables SM2/SM3/SM4, so ShangMi primitives remain
//! provided by Vail's Zig modules until an AWS-LC provider is available.

const std = @import("std");
const options = @import("vail_build_options");
const c = @import("aws_lc_c");

pub const Backend = enum {
    pure_zig,
    aws_lc,
};

pub const selected: Backend = if (options.aws_lc_path != null)
    .aws_lc
else
    .pure_zig;

pub const aws_lc_path: ?[]const u8 = options.aws_lc_path;
pub const aws_lc_linked: bool = options.aws_lc_link;
pub const aws_lc_shangmi_available: bool = options.aws_lc_sm_available;

pub const ShangMiProvider = enum {
    vail_zig,
    aws_lc,
};

pub const shangmi_provider: ShangMiProvider = if (aws_lc_shangmi_available)
    .aws_lc
else
    .vail_zig;

pub fn isAwsLcConfigured() bool {
    return selected == .aws_lc;
}

/// Hash with AWS-LC libcrypto when the caller explicitly requested linking.
/// Returns null for metadata-only `-Daws-lc-path` builds so downstream code can
/// probe capability without accidentally requiring libcrypto symbols.
pub fn sha256AwsLc(bytes: []const u8) ?[32]u8 {
    if (!aws_lc_linked) return null;
    var out: [32]u8 = undefined;
    const result = c.SHA256(bytes.ptr, bytes.len, &out);
    if (result == null) return null;
    return out;
}

pub const AesGcmSuite = enum {
    aes_128_gcm,
    aes_256_gcm,
};

pub const AesGcmContext = if (aws_lc_linked) struct {
    ctx: c.EVP_AEAD_CTX,

    pub fn init(suite: AesGcmSuite, key: []const u8) ?AesGcmContext {
        var result = AesGcmContext{ .ctx = undefined };
        c.EVP_AEAD_CTX_zero(&result.ctx);
        const aead = switch (suite) {
            .aes_128_gcm => c.EVP_aead_aes_128_gcm(),
            .aes_256_gcm => c.EVP_aead_aes_256_gcm(),
        } orelse return null;
        if (c.EVP_AEAD_CTX_init(
            &result.ctx,
            aead,
            key.ptr,
            key.len,
            16,
            null,
        ) != 1) return null;
        return result;
    }

    pub fn deinit(self: *AesGcmContext) void {
        c.EVP_AEAD_CTX_cleanup(&self.ctx);
        self.* = undefined;
    }

    pub fn seal(
        self: *const AesGcmContext,
        nonce: *const [12]u8,
        associated_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) bool {
        if (ciphertext.len != plaintext.len) return false;
        var tag_len: usize = 0;
        return c.EVP_AEAD_CTX_seal_scatter(
            &self.ctx,
            ciphertext.ptr,
            tag,
            &tag_len,
            tag.len,
            nonce,
            nonce.len,
            plaintext.ptr,
            plaintext.len,
            null,
            0,
            associated_data.ptr,
            associated_data.len,
        ) == 1 and tag_len == tag.len;
    }

    pub fn open(
        self: *const AesGcmContext,
        nonce: *const [12]u8,
        associated_data: []const u8,
        ciphertext: []const u8,
        tag: *const [16]u8,
        plaintext: []u8,
    ) bool {
        if (plaintext.len != ciphertext.len) return false;
        return c.EVP_AEAD_CTX_open_gather(
            &self.ctx,
            plaintext.ptr,
            nonce,
            nonce.len,
            ciphertext.ptr,
            ciphertext.len,
            tag,
            tag.len,
            associated_data.ptr,
            associated_data.len,
        ) == 1;
    }
} else struct {
    pub fn init(suite: AesGcmSuite, key: []const u8) ?AesGcmContext {
        _ = suite;
        _ = key;
        return null;
    }

    pub fn deinit(self: *AesGcmContext) void {
        _ = self;
    }

    pub fn seal(
        self: *const AesGcmContext,
        nonce: *const [12]u8,
        associated_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) bool {
        _ = self;
        _ = nonce;
        _ = associated_data;
        _ = plaintext;
        _ = ciphertext;
        _ = tag;
        return false;
    }

    pub fn open(
        self: *const AesGcmContext,
        nonce: *const [12]u8,
        associated_data: []const u8,
        ciphertext: []const u8,
        tag: *const [16]u8,
        plaintext: []u8,
    ) bool {
        _ = self;
        _ = nonce;
        _ = associated_data;
        _ = ciphertext;
        _ = tag;
        _ = plaintext;
        return false;
    }
};

test "backend metadata is internally consistent" {
    if (aws_lc_path == null) {
        try @import("std").testing.expectEqual(Backend.pure_zig, selected);
        try @import("std").testing.expect(!aws_lc_linked);
    } else {
        try @import("std").testing.expectEqual(Backend.aws_lc, selected);
    }
    if (!aws_lc_shangmi_available) {
        try @import("std").testing.expectEqual(
            ShangMiProvider.vail_zig,
            shangmi_provider,
        );
    }
}

test "AWS-LC linked SHA-256 smoke matches Zig SHA-256" {
    const digest = sha256AwsLc("vail aws-lc smoke") orelse {
        try std.testing.expect(!aws_lc_linked);
        return;
    };
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("vail aws-lc smoke", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "AWS-LC linked AES-GCM smoke matches Zig AES-GCM" {
    if (!aws_lc_linked) return error.SkipZigTest;
    var ctx = AesGcmContext.init(.aes_128_gcm, &([_]u8{0x11} ** 16)) orelse
        return error.SkipZigTest;
    defer ctx.deinit();
    const nonce = [_]u8{0x22} ** 12;
    const plaintext = "aws-lc aes-gcm smoke";
    const ad = "ad";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try std.testing.expect(ctx.seal(&nonce, ad, plaintext, &ciphertext, &tag));

    var expected_ciphertext: [plaintext.len]u8 = undefined;
    var expected_tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
        &expected_ciphertext,
        &expected_tag,
        plaintext,
        ad,
        nonce,
        [_]u8{0x11} ** 16,
    );
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    var opened: [plaintext.len]u8 = undefined;
    try std.testing.expect(ctx.open(&nonce, ad, &ciphertext, &tag, &opened));
    try std.testing.expectEqualStrings(plaintext, &opened);
}
