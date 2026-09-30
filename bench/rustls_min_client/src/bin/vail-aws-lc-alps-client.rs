use aws_lc_sys as ffi;
use std::ffi::CString;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::ptr;
use std::slice;
use std::time::Duration;

fn main() {
    let use_new_codepoint = std::env::args().nth(1).as_deref() == Some("new");
    let socket = TcpStream::connect("127.0.0.1:24444").expect("connect to Vail");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    unsafe {
        ffi::init();
        let context = ffi::SSL_CTX_new(ffi::TLS_method());
        assert!(!context.is_null());
        assert_eq!(
            ffi::SSL_CTX_set_min_proto_version(context, ffi::TLS1_3_VERSION as u16),
            1
        );
        assert_eq!(
            ffi::SSL_CTX_set_max_proto_version(context, ffi::TLS1_3_VERSION as u16),
            1
        );
        ffi::SSL_CTX_set_verify(context, ffi::SSL_VERIFY_NONE, None);

        let ssl = ffi::SSL_new(context);
        assert!(!ssl.is_null());
        assert_eq!(ffi::SSL_set_fd(ssl, socket.as_raw_fd()), 1);
        let server_name = CString::new("localhost").unwrap();
        assert_eq!(ffi::SSL_set_tlsext_host_name(ssl, server_name.as_ptr()), 1);
        let alpn = [2u8, b'h', b'2'];
        assert_eq!(ffi::SSL_set_alpn_protos(ssl, alpn.as_ptr(), alpn.len()), 0);
        let client_settings = b"aws-client-settings";
        assert_eq!(
            ffi::SSL_add_application_settings(
                ssl,
                b"h2".as_ptr(),
                2,
                client_settings.as_ptr(),
                client_settings.len(),
            ),
            1
        );
        ffi::SSL_set_alps_use_new_codepoint(ssl, i32::from(use_new_codepoint));

        let connected = ffi::SSL_connect(ssl);
        if connected != 1 {
            panic!(
                "AWS-LC handshake failed: {}",
                ffi::SSL_get_error(ssl, connected)
            );
        }
        assert_eq!(ffi::SSL_has_application_settings(ssl), 1);
        let mut peer_ptr = ptr::null();
        let mut peer_len = 0usize;
        ffi::SSL_get0_peer_application_settings(ssl, &mut peer_ptr, &mut peer_len);
        assert!(!peer_ptr.is_null() || peer_len == 0);
        let peer = slice::from_raw_parts(peer_ptr, peer_len);
        assert_eq!(peer, b"vail-server-settings");
        println!("AWS-LC ALPS connected and settings matched");

        let _ = ffi::SSL_shutdown(ssl);
        ffi::SSL_free(ssl);
        ffi::SSL_CTX_free(context);
    }
}
