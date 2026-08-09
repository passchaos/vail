const std = @import("std");
const vail = @import("vail");

test "public modules are reachable" {
    try std.testing.expect(@hasDecl(vail, "crypto"));
    try std.testing.expect(@hasDecl(vail.crypto, "mac"));
    try std.testing.expect(@hasDecl(vail, "tls"));
    try std.testing.expect(@hasDecl(vail.tls, "auth"));
    try std.testing.expect(@hasDecl(vail.tls, "client_auth"));
    try std.testing.expect(@hasDecl(vail.tls, "key_schedule"));
    try std.testing.expect(@hasDecl(vail.tls, "key_exchange"));
    try std.testing.expect(@hasDecl(vail.tls, "psk"));
    try std.testing.expect(@hasDecl(vail.tls, "ticket"));
    try std.testing.expect(@hasDecl(vail.tls, "ticket_keyring"));
    try std.testing.expect(@hasDecl(vail.tls, "transcript"));
    try std.testing.expect(@hasDecl(vail, "x509"));
    try std.testing.expect(@hasDecl(vail.x509, "trust"));
    try std.testing.expect(@hasDecl(vail.tls.auth, "ServerIdentity"));
    try std.testing.expect(@hasDecl(vail.tls.auth, "Signer"));
}
