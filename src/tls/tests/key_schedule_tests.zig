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

const common = @import("common.zig");
const decodeHex = common.decodeHex;
const writeTestFinished = common.writeTestFinished;
const expectHex = common.expectHex;
const checkCertificateAllocationFailure = common.checkCertificateAllocationFailure;

test "TLS 1.3 key schedule separates handshake application and PSK secrets" {
    const shared = [_]u8{0x71} ** key_schedule.secret_len;
    const transcript_hash = [_]u8{0x72} ** key_schedule.secret_len;
    const psk = [_]u8{0x73} ** key_schedule.secret_len;
    const plain = key_schedule.deriveHandshake(shared, transcript_hash, null);
    const resumed = key_schedule.deriveHandshake(shared, transcript_hash, psk);
    try std.testing.expect(!std.mem.eql(
        u8,
        &plain.handshake_secret,
        &resumed.handshake_secret,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &resumed.client_traffic_secret,
        &resumed.server_traffic_secret,
    ));

    const application = key_schedule.deriveApplication(
        resumed.handshake_secret,
        transcript_hash,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &application.client_traffic_secret,
        &application.server_traffic_secret,
    ));
    const finished = key_schedule.computeFinished(
        resumed.client_traffic_secret,
        transcript_hash,
    );
    try key_schedule.verifyFinished(
        resumed.client_traffic_secret,
        transcript_hash,
        finished,
    );
    var wrong = finished;
    wrong[0] ^= 1;
    try std.testing.expectError(
        error.BadFinished,
        key_schedule.verifyFinished(
            resumed.client_traffic_secret,
            transcript_hash,
            wrong,
        ),
    );

    const resumption_master = key_schedule.deriveResumptionMasterSecret(
        application.master_secret,
        transcript_hash,
    );
    const exporter_master = key_schedule.deriveExporterMasterSecret(
        application.master_secret,
        transcript_hash,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &exporter_master,
        &resumption_master,
    ));
    var exported_a: [42]u8 = undefined;
    var exported_b: [42]u8 = undefined;
    var exported_other_context: [42]u8 = undefined;
    try key_schedule.exportKeyingMaterial(
        exporter_master,
        "EXPORTER-vail-test",
        "context",
        &exported_a,
    );
    try key_schedule.exportKeyingMaterial(
        exporter_master,
        "EXPORTER-vail-test",
        "context",
        &exported_b,
    );
    try key_schedule.exportKeyingMaterial(
        exporter_master,
        "EXPORTER-vail-test",
        "other",
        &exported_other_context,
    );
    try std.testing.expectEqualSlices(u8, &exported_a, &exported_b);
    try std.testing.expect(!std.mem.eql(
        u8,
        &exported_a,
        &exported_other_context,
    ));
    const first_psk = key_schedule.deriveResumptionPsk(
        resumption_master,
        "one",
    );
    const second_psk = key_schedule.deriveResumptionPsk(
        resumption_master,
        "two",
    );
    try std.testing.expect(!std.mem.eql(u8, &first_psk, &second_psk));
    const updated = key_schedule.nextTrafficSecret(
        application.client_traffic_secret,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &updated,
        &application.client_traffic_secret,
    ));
}

test "TLS 1.3 exporter matches independently generated SHA-256 vector" {
    const master_secret = [_]u8{0x44} ** key_schedule.secret_len;
    var transcript_hash: [key_schedule.secret_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        "transcript",
        &transcript_hash,
        .{},
    );
    const exporter_master = key_schedule.deriveExporterMasterSecret(
        master_secret,
        transcript_hash,
    );
    try expectHex(
        "b1be727372802b8b8a02865283a50fe3ca6e1a7222ef5d3f15d077504e7ebcb2",
        &exporter_master,
    );
    var exported: [42]u8 = undefined;
    try key_schedule.exportKeyingMaterial(
        exporter_master,
        "EXPORTER-test",
        "context",
        &exported,
    );
    try expectHex(
        "6ec16a5753eb19eff8d2f0440d0f6e02d83ea71e06b46d14c27ba8de2653da7a936a454c88c8f5e1840d",
        &exported,
    );
}

test "runtime TLS traffic updates preserve every negotiated hash" {
    const cases = [_]struct {
        hash: secret.Hash,
        bytes: usize,
    }{
        .{ .hash = .sha256, .bytes = 32 },
        .{ .hash = .sha384, .bytes = 48 },
        .{ .hash = .sm3, .bytes = 32 },
    };
    for (cases) |case| {
        var input: [secret.max_len]u8 = [_]u8{0x6d} ** secret.max_len;
        var current = try secret.Secret.init(case.hash, input[0..case.bytes]);
        defer current.deinit();
        var updated = try key_schedule.nextTrafficSecretFor(current);
        defer updated.deinit();
        try std.testing.expectEqual(case.hash, updated.hash);
        try std.testing.expectEqual(case.bytes, updated.bytes().len);
        try std.testing.expect(!std.mem.eql(
            u8,
            current.bytes(),
            updated.bytes(),
        ));
    }
}

test "TLS 1.3 SHA-384 schedule keeps 48-byte secrets and Finished values" {
    const Schedule = key_schedule.Sha384;
    const shared = [_]u8{0x81} ** Schedule.secret_len;
    const transcript_hash = [_]u8{0x82} ** Schedule.secret_len;
    const psk = [_]u8{0x83} ** Schedule.secret_len;
    const handshake = Schedule.deriveHandshake(
        &shared,
        transcript_hash,
        psk,
    );
    try std.testing.expectEqual(
        @as(usize, 48),
        handshake.handshake_secret.len,
    );
    try expectHex(
        "fffef14f7d6ee618525454268d25ec5ff81d5c28bfd6ca38dc3df7acadb0ac16aaac1a81f6f08115550935b74afbf7ac",
        &handshake.handshake_secret,
    );
    try expectHex(
        "a54c4371989e45778aa9cf31ecb21a6c7ab1ffc13675257f0b072ea27074eb7fa9e74488eea18cb40135a37f33c8c7f3",
        &handshake.client_traffic_secret,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &handshake.client_traffic_secret,
        &handshake.server_traffic_secret,
    ));

    const application = Schedule.deriveApplication(
        handshake.handshake_secret,
        transcript_hash,
    );
    const finished = Schedule.computeFinished(
        application.client_traffic_secret,
        transcript_hash,
    );
    try expectHex(
        "b0f1f1f5e4665d80ff3e6ba0bf0c1095bfff9cdc79a9a23de31eba619f204151749243d66ed82b5af9a727efa774c02e",
        &finished,
    );
    try Schedule.verifyFinished(
        application.client_traffic_secret,
        transcript_hash,
        finished,
    );
    var wrong = finished;
    wrong[wrong.len - 1] ^= 1;
    try std.testing.expectError(
        error.BadFinished,
        Schedule.verifyFinished(
            application.client_traffic_secret,
            transcript_hash,
            wrong,
        ),
    );
}

test "runtime TLS key schedule dispatch preserves SHA-384 secret identity" {
    const shared = [_]u8{0x91} ** 32;
    const handshake_hash = transcript.hashFor(
        .sha384,
        &.{ "client hello", "server hello" },
    );
    const handshake = try key_schedule.deriveHandshakeFor(
        .sha384,
        &shared,
        handshake_hash,
        null,
    );
    try std.testing.expectEqual(
        secret.Hash.sha384,
        handshake.handshake_secret.hash,
    );
    const application_hash = transcript.hashFor(
        .sha384,
        &.{ "client hello", "server flight" },
    );
    const application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        application_hash,
    );
    const exporter_master = try key_schedule.deriveExporterMasterSecretFor(
        application.master_secret,
        application_hash,
    );
    var exported: [80]u8 = undefined;
    try key_schedule.exportKeyingMaterialFor(
        exporter_master,
        "EXPORTER-runtime-test",
        "sha384",
        &exported,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &exported, 0));
    const finished = try key_schedule.computeFinishedFor(
        application.client_traffic_secret,
        application_hash,
    );
    try key_schedule.verifyFinishedFor(
        application.client_traffic_secret,
        application_hash,
        finished,
    );
    try std.testing.expectError(
        error.HashMismatch,
        key_schedule.deriveApplicationFor(
            secret.Secret.fromSha256([_]u8{0} ** 32),
            application_hash,
        ),
    );
}

test "TLS 1.3 SM3 schedule matches independent HKDF/HMAC vectors" {
    const Schedule = key_schedule.Sm3;
    const shared = [_]u8{0xa1} ** Schedule.secret_len;
    const transcript_hash = [_]u8{0xa2} ** Schedule.secret_len;
    const pre_shared_key = [_]u8{0xa3} ** Schedule.secret_len;
    const handshake = Schedule.deriveHandshake(
        &shared,
        transcript_hash,
        pre_shared_key,
    );
    try expectHex(
        "6b6dd537c27cda9f89fc794b72c7fe68a82911f62c6038e073b12096f527570e",
        &handshake.handshake_secret,
    );
    try expectHex(
        "b22e419148ec08217e6a278aad1fef71339ea12165f7ad7cbfe35176c9dd9370",
        &handshake.client_traffic_secret,
    );
    try expectHex(
        "28444e8d916999098f337193ee2b67a7fbd77d9771bd58f86d2ca973c9cd3862",
        &handshake.server_traffic_secret,
    );
    const application = Schedule.deriveApplication(
        handshake.handshake_secret,
        transcript_hash,
    );
    try expectHex(
        "9ce50556da429235a8f402db078ff677cc491448b487a0e324dbfdf19b498d62",
        &application.master_secret,
    );
    try expectHex(
        "c2a7ed0b6d95d1a2263503656ef79c585cd8071f473e1ea072f4e445628a6d41",
        &application.client_traffic_secret,
    );
    const finished = Schedule.computeFinished(
        application.client_traffic_secret,
        transcript_hash,
    );
    try expectHex(
        "6c0b1f0e0bceba777a43fd5020de844628df64feef2df180ceab72e7991d70c0",
        &finished,
    );
}

test "runtime TLS key schedule dispatch preserves SM3 secret identity" {
    const shared = [_]u8{0x93} ** 32;
    const handshake_hash = transcript.hashFor(
        .sm3,
        &.{ "client hello", "server hello" },
    );
    const handshake = try key_schedule.deriveHandshakeFor(
        .sm3,
        &shared,
        handshake_hash,
        null,
    );
    try std.testing.expectEqual(
        secret.Hash.sm3,
        handshake.handshake_secret.hash,
    );
    const application_hash = transcript.hashFor(
        .sm3,
        &.{ "client hello", "server flight" },
    );
    const application = try key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        application_hash,
    );
    const finished = try key_schedule.computeFinishedFor(
        application.client_traffic_secret,
        application_hash,
    );
    try key_schedule.verifyFinishedFor(
        application.client_traffic_secret,
        application_hash,
        finished,
    );
}
