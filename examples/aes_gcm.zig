const std = @import("std");
const vail = @import("vail");

pub fn main() !void {
    const Aes128Gcm = vail.crypto.aes_gcm.Aes128Gcm;
    const key = [_]u8{0x42} ** Aes128Gcm.key_length;
    var context = Aes128Gcm.init(key);
    defer context.deinit();

    const plaintext = "hello vail";
    const nonce = [_]u8{0x01} ** Aes128Gcm.nonce_length;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    context.encrypt(&ciphertext, &tag, plaintext, "example", nonce);

    var decrypted: [plaintext.len]u8 = undefined;
    try context.decrypt(&decrypted, &ciphertext, tag, "example", nonce);
    std.debug.assert(std.mem.eql(u8, plaintext, &decrypted));
}
