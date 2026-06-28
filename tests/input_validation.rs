//! Regression tests for H4: a negative length (`alen`/`addrlen`, a c_int that
//! becomes a huge usize) or a NULL buffer must produce a clean error, not a
//! `slice::from_raw_parts` out-of-bounds / UB across the FFI boundary.

use std::ffi::{c_int, c_long, c_void, CString};
use std::ptr;

use cares_rs::*;

const ARES_ENOTIMP: c_int = 5;
const ARES_EBADRESP: c_int = 10;
const ARES_EBADNAME: c_int = 8;
const ARES_EBADSTR: c_int = 17;

// A small non-null buffer so the guards are reached via the negative-length
// branch rather than the null branch.
const DUMMY: [u8; 4] = [0, 0, 0, 0];

#[test]
fn parse_a_reply_negative_alen_returns_error() {
    let mut host: *mut libc::hostent = ptr::null_mut();
    let mut naddrttls: c_int = 0;
    let rc = unsafe {
        ares_parse_a_reply(DUMMY.as_ptr(), -1, &mut host, ptr::null_mut(), &mut naddrttls)
    };
    assert_eq!(rc, ARES_EBADRESP, "negative alen must be rejected, not UB");
    assert!(host.is_null());
}

#[test]
fn parse_txt_reply_ext_negative_alen_returns_error() {
    let mut out: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        ares_parse_txt_reply_ext(DUMMY.as_ptr(), -1, &mut out as *mut _ as *mut *mut _)
    };
    assert_eq!(rc, ARES_EBADRESP);
}

#[test]
fn expand_name_negative_alen_returns_error() {
    let mut s: *mut std::ffi::c_char = ptr::null_mut();
    let mut enclen: c_long = 0;
    let rc = unsafe {
        ares_expand_name(DUMMY.as_ptr(), DUMMY.as_ptr(), -1, &mut s, &mut enclen)
    };
    assert_eq!(rc, ARES_EBADNAME);
    assert!(s.is_null());
}

#[test]
fn expand_string_negative_alen_returns_error() {
    let mut s: *mut u8 = ptr::null_mut();
    let mut enclen: c_long = 0;
    let rc = unsafe {
        ares_expand_string(DUMMY.as_ptr(), DUMMY.as_ptr(), -1, &mut s, &mut enclen)
    };
    assert_eq!(rc, ARES_EBADSTR);
    assert!(s.is_null());
}

struct CbResult {
    fired: bool,
    status: c_int,
}

unsafe extern "C" fn host_cb(arg: *mut c_void, status: c_int, _timeouts: c_int, _hostent: *mut libc::hostent) {
    let r = &mut *(arg as *mut CbResult);
    r.fired = true;
    r.status = status;
}

#[test]
fn gethostbyaddr_null_addr_calls_back_with_error() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), 0);
        assert!(!ch.is_null());

        let mut result = CbResult { fired: false, status: -1 };
        // NULL addr (and a positive addrlen) previously reached from_raw_parts.
        ares_gethostbyaddr(
            ch,
            ptr::null_mut(),
            4,
            libc::AF_INET,
            host_cb,
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.fired, "callback must fire on bad args");
        assert_eq!(result.status, ARES_ENOTIMP);

        ares_destroy(ch);
    }
}
