//! Embedded NUL bytes in attacker-controlled DNS data must yield a clean error,
//! not a panic/abort across the FFI boundary.

use std::ffi::{c_int, c_long, c_void, CString};
use std::ptr;

use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const ARES_EBADRESP: c_int = 10;
const ARES_EBADSTR: c_int = 17;

/// Interior NUL previously panicked in `CString::from_vec_with_nul().unwrap()`.
#[test]
fn expand_string_with_embedded_nul_returns_ebadstr() {
    let abuf: [u8; 4] = [0x03, b'a', 0x00, b'c'];
    let mut s: *mut u8 = ptr::null_mut();
    let mut enclen: c_long = 0;
    let rc = unsafe {
        ares_expand_string(abuf.as_ptr(), abuf.as_ptr(), abuf.len() as c_int, &mut s, &mut enclen)
    };
    assert_eq!(rc, ARES_EBADSTR, "embedded NUL must be rejected, not panic");
    assert!(s.is_null(), "no string should be allocated on error");
}

/// An echoed question name containing an embedded NUL previously aborted via
/// `.unwrap()` in the shared `process_answers` path used by every `ares_parse_*_reply`.
#[test]
fn parse_reply_with_nul_in_question_name_returns_ebadresp() {
    #[rustfmt::skip]
    let resp: [u8; 35] = [
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0xC0, 0x0C,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04,
        0x7F, 0x00, 0x00, 0x01,
    ];

    let mut out: *mut c_void = ptr::null_mut();
    // ares_parse_caa_reply has the simplest signature; any parse fn hits the
    // same question-name path before record-type interpretation.
    let rc = unsafe {
        ares_parse_caa_reply(resp.as_ptr(), resp.len() as c_int, &mut out as *mut _ as *mut *mut _)
    };
    assert_eq!(rc, ARES_EBADRESP, "NUL in question name must be rejected, not panic");
    assert!(out.is_null(), "no data should be allocated on error");
}

/// `ares_create_query` returns a libc::malloc'd packet freed via
/// `ares_free_string`; id=0 previously went through the strlen-based
/// `CString::from_raw` free and must now free cleanly (Valgrind-checked).
#[test]
fn create_query_buffer_freed_cleanly_with_zero_id() {
    let name = CString::new("example.com").unwrap();
    let mut buf: *mut u8 = ptr::null_mut();
    let mut buflen: c_int = 0;
    let rc = unsafe {
        ares_create_query(name.as_ptr(), 1, 1, 0, 1, &mut buf, &mut buflen, 0)
    };
    assert_eq!(rc, ARES_SUCCESS, "create_query should succeed");
    assert!(!buf.is_null());
    assert!(buflen > 12, "a DNS query has at least a 12-byte header");
    unsafe {
        // Transaction id 0x0000 is the strlen-mishandled case.
        assert_eq!(*buf, 0);
        assert_eq!(*buf.add(1), 0);
        // Must free without abort/corruption (now libc::free of a libc::malloc buffer).
        ares_free_string(buf as *mut c_void);
    }
}
