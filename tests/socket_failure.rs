//! #1: socket-creation failure must deliver ARES_ECONNREFUSED to the callback,
//! not panic/abort the process. We inject failure via a custom socket layer
//! whose socket() always returns ARES_SOCKET_BAD.

use std::ffi::{c_int, c_void, CString};
use std::ptr;

use cares_rs::*;
use cares_rs::ares_socket::ares_set_socket_functions;

const ARES_SUCCESS: c_int = 0;
const ARES_ECONNREFUSED: c_int = 11;

struct Rec { fired: bool, status: c_int }

unsafe extern "C" fn fail_socket(_d: c_int, _t: c_int, _p: c_int, _u: *mut c_void) -> c_int { -1 }

unsafe extern "C" fn host_cb(arg: *mut c_void, status: c_int, _t: c_int, _h: *mut libc::hostent) {
    let r = &mut *(arg as *mut Rec); r.fired = true; r.status = status;
}
unsafe extern "C" fn ai_cb(arg: *mut c_void, status: c_int, _t: c_int, _res: *mut ares_addrinfo) {
    let r = &mut *(arg as *mut Rec); r.fired = true; r.status = status;
}
unsafe extern "C" fn q_cb(arg: *mut c_void, status: c_int, _t: c_int, _a: *mut u8, _l: c_int) {
    let r = &mut *(arg as *mut Rec); r.fired = true; r.status = status;
}

unsafe fn channel_with_failing_sockets() -> Channel {
    let mut ch: Channel = ptr::null_mut();
    assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
    let servers = CString::new("8.8.8.8").unwrap();
    ares_set_servers_csv(ch, servers.as_ptr());
    let funcs = AresSocketFunctions {
        asocket: Some(fail_socket),
        aclose: None, aconnect: None, arecvfrom: None, asendv: None,
    };
    ares_set_socket_functions(ch, &funcs, ptr::null_mut());
    ch
}

#[test]
fn gethostbyname_socket_failure_is_econnrefused() {
    unsafe {
        let ch = channel_with_failing_sockets();
        let mut r = Rec { fired: false, status: ARES_SUCCESS };
        let name = CString::new("nonlocal.example.com").unwrap();
        ares_gethostbyname(ch, name.as_ptr(), libc::AF_INET, Some(host_cb),
                           &mut r as *mut _ as *mut c_void);
        assert!(r.fired, "callback must fire (no abort/hang) when sockets can't be created");
        assert_eq!(r.status, ARES_ECONNREFUSED);
        ares_destroy(ch);
    }
}

#[test]
fn getaddrinfo_socket_failure_is_econnrefused() {
    unsafe {
        let ch = channel_with_failing_sockets();
        let mut r = Rec { fired: false, status: ARES_SUCCESS };
        let name = CString::new("nonlocal.example.com").unwrap();
        // AF_UNSPEC launches both A and AAAA — exercises the 2-query pending batch.
        ares_getaddrinfo(ch, name.as_ptr(), ptr::null(), ptr::null(), Some(ai_cb),
                         &mut r as *mut _ as *mut c_void);
        assert!(r.fired);
        assert_eq!(r.status, ARES_ECONNREFUSED);
        ares_destroy(ch);
    }
}

#[test]
fn query_socket_failure_is_econnrefused() {
    unsafe {
        let ch = channel_with_failing_sockets();
        let mut r = Rec { fired: false, status: ARES_SUCCESS };
        let name = CString::new("nonlocal.example.com").unwrap();
        ares_query(ch, name.as_ptr(), 1, 1, Some(q_cb), &mut r as *mut _ as *mut c_void);
        assert!(r.fired);
        assert_eq!(r.status, ARES_ECONNREFUSED);
        ares_destroy(ch);
    }
}
