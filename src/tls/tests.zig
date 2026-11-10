test {
    _ = @import("tests/common.zig");
    _ = @import("tests/cipher_suite_tests.zig");
    _ = @import("tests/certificate_verify_tests.zig");
    _ = @import("tests/certificate_request_tests.zig");
    _ = @import("tests/certificate_verify_more_tests.zig");
    _ = @import("tests/key_schedule_tests.zig");
    _ = @import("tests/ticket_keyring_tests.zig");
    _ = @import("tests/key_exchange_tests.zig");
    _ = @import("tests/certificate_codec_tests.zig");
}
