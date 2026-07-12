//! Regression tests for H2: an embedded NUL byte in attacker-controlled DNS
//! data must yield a clean error, not a panic/abort across the FFI boundary.

use std::ffi::{c_int, c_long, c_void, CString};
use std::ptr;

use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const ARES_EBADRESP: c_int = 10;
const ARES_EBADSTR: c_int = 17;

/// `ares_expand_string` on a length-prefixed string whose body contains an
/// interior NUL byte. Previously panicked in `CString::from_vec_with_nul().unwrap()`.
#[test]
fn expand_string_with_embedded_nul_returns_ebadstr() {
    // length byte = 3, then bytes ['a', 0x00, 'c'] (embedded NUL).
    let abuf: [u8; 4] = [0x03, b'a', 0x00, b'c'];
    let mut s: *mut u8 = ptr::null_mut();
    let mut enclen: c_long = 0;
    let rc = unsafe {
        ares_expand_string(abuf.as_ptr(), abuf.as_ptr(), abuf.len() as c_int, &mut s, &mut enclen)
    };
    assert_eq!(rc, ARES_EBADSTR, "embedded NUL must be rejected, not panic");
    assert!(s.is_null(), "no string should be allocated on error");
}

/// A valid DNS response whose echoed question name contains an embedded NUL
/// byte. `process_answers` builds a `CString` from the question name on its
/// first line; previously that `.unwrap()` panicked (process abort). The answer
/// is A-record-framed (parsed generically by `from_buf`), so this exercises the
/// shared question-name path used by every `ares_parse_*_reply`.
#[test]
fn parse_reply_with_nul_in_question_name_returns_ebadresp() {
    #[rustfmt::skip]
    let resp: [u8; 35] = [
        // ---- Header (12 bytes) ----
        0x12, 0x34,             // id
        0x81, 0x80,             // flags: QR=1, RD=1, RA=1, rcode=0
        0x00, 0x01,             // qdcount = 1
        0x00, 0x01,             // ancount = 1
        0x00, 0x00,             // nscount = 0
        0x00, 0x00,             // arcount = 0
        // ---- Question (offset 12) ----
        0x01, 0x00,             // one label, length 1, content = NUL byte
        0x00,                   // root terminator
        0x00, 0x01,             // qtype = A
        0x00, 0x01,             // qclass = IN
        // ---- Answer ----
        0xC0, 0x0C,             // name = compression pointer -> offset 12
        0x00, 0x01,             // type = A
        0x00, 0x01,             // class = IN
        0x00, 0x00, 0x00, 0x3C, // ttl = 60
        0x00, 0x04,             // rdlength = 4
        0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
    ];

    let mut out: *mut c_void = ptr::null_mut();
    // ares_parse_caa_reply has the simplest signature; any parse fn hits the
    // same question-name code path before record-type interpretation.
    let rc = unsafe {
        ares_parse_caa_reply(resp.as_ptr(), resp.len() as c_int, &mut out as *mut _ as *mut *mut _)
    };
    assert_eq!(rc, ARES_EBADRESP, "NUL in question name must be rejected, not panic");
    assert!(out.is_null(), "no data should be allocated on error");
}

/// H3: `ares_create_query` returns a libc::malloc'd binary DNS packet freed via
/// `ares_free_string`. With id=0 the packet starts with a 0x00 transaction-id
/// byte, which the old strlen-based `CString::from_raw` free mishandled. The
/// allocate/free round-trip must be clean (verified under Valgrind in CI).
#[test]
fn create_query_buffer_freed_cleanly_with_zero_id() {
    let name = CString::new("example.com").unwrap();
    let mut buf: *mut u8 = ptr::null_mut();
    let mut buflen: c_int = 0;
    let rc = unsafe {
        // dnsclass=IN(1), qtype=A(1), id=0 -> transaction id 0x0000, rd=1, no EDNS.
        ares_create_query(name.as_ptr(), 1, 1, 0, 1, &mut buf, &mut buflen, 0)
    };
    assert_eq!(rc, ARES_SUCCESS, "create_query should succeed");
    assert!(!buf.is_null());
    assert!(buflen > 12, "a DNS query has at least a 12-byte header");
    unsafe {
        // First two bytes are the transaction id = 0x0000 (the strlen-mishandled case).
        assert_eq!(*buf, 0);
        assert_eq!(*buf.add(1), 0);
        // Must free without abort/corruption (now libc::free of a libc::malloc buffer).
        ares_free_string(buf as *mut c_void);
    }
}
