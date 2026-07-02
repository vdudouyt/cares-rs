//! Regression tests for H4: a negative length (`alen`/`addrlen`, a c_int that
//! becomes a huge usize) or a NULL buffer must produce a clean error, not a
//! `slice::from_raw_parts` out-of-bounds / UB across the FFI boundary.

use std::ffi::{c_char, c_int, c_long, c_void, CString};
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
            Some(host_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.fired, "callback must fire on bad args");
        assert_eq!(result.status, ARES_ENOTIMP);

        ares_destroy(ch);
    }
}

// ---- H5: NULL-pointer guards at entry points (match upstream c-ares) ----

const ARES_SUCCESS: c_int = 0;
const ARES_ENODATA: c_int = 1;

#[test]
fn init_options_null_options_optmask_zero_succeeds() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        // NULL options with optmask 0 == ares_init (supported upstream).
        let rc = cares_rs::ares_options::ares_init_options(&mut ch, ptr::null(), 0);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!ch.is_null());
        ares_destroy(ch);
    }
}

#[test]
fn init_options_null_options_with_optmask_is_enodata() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        // optmask != 0 with NULL options -> ARES_ENODATA (ARES_OPT_FLAGS = 1<<0).
        let rc = cares_rs::ares_options::ares_init_options(&mut ch, ptr::null(), 1);
        assert_eq!(rc, ARES_ENODATA);
        assert!(ch.is_null());
    }
}

#[test]
fn gethostbyname_null_channel_calls_back_with_error() {
    unsafe {
        let mut result = CbResult { fired: false, status: ARES_SUCCESS };
        let name = CString::new("example.com").unwrap();
        ares_gethostbyname(ptr::null_mut(), name.as_ptr(), libc::AF_INET, Some(host_cb),
                           &mut result as *mut _ as *mut c_void);
        assert!(result.fired);
        assert_ne!(result.status, ARES_SUCCESS);
    }
}

#[test]
fn gethostbyname_null_name_calls_back_with_error() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        let mut result = CbResult { fired: false, status: ARES_SUCCESS };
        ares_gethostbyname(ch, ptr::null(), libc::AF_INET, Some(host_cb),
                           &mut result as *mut _ as *mut c_void);
        assert!(result.fired);
        assert_ne!(result.status, ARES_SUCCESS);
        ares_destroy(ch);
    }
}

#[test]
fn timeout_null_channel_or_buf_returns_null() {
    unsafe {
        let mut tv: libc::timeval = std::mem::zeroed();
        assert!(ares_timeout(ptr::null_mut(), ptr::null_mut(), &mut tv).is_null());
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        assert!(ares_timeout(ch, ptr::null_mut(), ptr::null_mut()).is_null());
        ares_destroy(ch);
    }
}

#[test]
fn getsock_null_channel_returns_zero() {
    unsafe {
        let mut socks = [0 as c_int; 16];
        assert_eq!(ares_getsock(ptr::null_mut(), socks.as_mut_ptr(), 16), 0);
    }
}

#[test]
fn process_and_setters_null_channel_no_crash() {
    unsafe {
        let mut rfds: libc::fd_set = std::mem::zeroed();
        let mut wfds: libc::fd_set = std::mem::zeroed();
        ares_process(ptr::null_mut(), &mut rfds, &mut wfds); // no-op, must not crash
        ares_set_server_state_callback(ptr::null_mut(), None, ptr::null_mut()); // no-op
    }
}

// ---- Medium: NULL / negative-count free guards (match upstream c-ares) ----

/// Upstream `ares_free_hostent(NULL)` is a documented no-op; ours must not
/// `Box::from_raw(NULL)`.
#[test]
fn free_hostent_null_is_noop() {
    unsafe { ares_free_hostent(ptr::null_mut()); }
}

/// A negative `ndomains` must not turn into a huge `usize` loop bound that reads
/// and frees out of bounds. The per-domain loop is skipped; the array is freed.
#[test]
fn destroy_options_negative_ndomains_no_crash() {
    use cares_rs::ares_options::{ares_destroy_options, ares_options};
    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        let domains = libc::malloc(std::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
        *domains = ptr::null_mut();
        opts.domains = domains;
        opts.ndomains = -1; // negative count
        ares_destroy_options(&mut opts); // must not crash / OOB; frees `domains`
    }
}

// ---- H5 follow-up: nullable async callbacks (NULL callback must be a no-op) ----

/// `Option<extern "C" fn>` must use the function-pointer null niche, so a C NULL
/// maps to `None` with no ABI change. The whole approach relies on this.
#[test]
fn option_callback_has_fn_pointer_abi() {
    assert_eq!(std::mem::size_of::<Option<AresHostCallback>>(), std::mem::size_of::<usize>());
    assert_eq!(std::mem::size_of::<Option<AresAddrInfoCallback>>(), std::mem::size_of::<usize>());
}

/// A NULL (None) callback to the async query functions must be a graceful no-op
/// (the guard returns before any work), not UB / a crash.
#[test]
fn null_callback_is_noop_not_ub() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        let name = CString::new("example.com").unwrap();
        ares_gethostbyname(ch, name.as_ptr(), libc::AF_INET, None, ptr::null_mut());
        ares_gethostbyaddr(ch, ptr::null_mut(), 4, libc::AF_INET, None, ptr::null_mut());
        ares_getaddrinfo(ch, name.as_ptr(), ptr::null(), ptr::null(), None, ptr::null_mut());
        ares_search(ch, name.as_ptr(), 1, 1, None, ptr::null_mut());
        ares_query(ch, name.as_ptr(), 1, 1, None, ptr::null_mut());
        ares_destroy(ch);
    }
}

/// A tiny response claiming ancount=0xFFFF must not pre-allocate based on that
/// count. Answers grow on demand, so the first (missing) answer parse fails
/// cleanly with ARES_EBADRESP and no oversized reservation happens.
#[test]
fn parse_reply_inflated_ancount_no_huge_alloc() {
    #[rustfmt::skip]
    let resp: [u8; 17] = [
        0x12, 0x34,             // id
        0x81, 0x80,             // flags: QR=1, rcode=0
        0x00, 0x01,             // qdcount = 1
        0xFF, 0xFF,             // ancount = 65535 (attacker-inflated)
        0x00, 0x00,             // nscount = 0
        0x00, 0x00,             // arcount = 0
        0x00,                   // question name = root
        0x00, 0x01,             // qtype = A
        0x00, 0x01,             // qclass = IN
        // no answer records follow
    ];
    let mut host: *mut libc::hostent = ptr::null_mut();
    let mut naddrttls: c_int = 0;
    let rc = unsafe {
        ares_parse_a_reply(resp.as_ptr(), resp.len() as c_int, &mut host, ptr::null_mut(), &mut naddrttls)
    };
    assert_eq!(rc, ARES_EBADRESP);
    assert!(host.is_null());
}
