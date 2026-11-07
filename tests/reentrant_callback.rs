//! A completion callback may re-enter `ares_*` on the same channel; a cache-hit
//! path once held `cache.borrow_mut()` across the callback and aborted with
//! `BorrowMutError`, so this primes the cache and re-enters from the callback.

use std::ffi::{c_int, c_void, CString};
use std::net::UdpSocket;
use std::ptr;
use std::time::{Duration, Instant};

use cares_rs::ares_options::{ares_init_options, ares_options, ARES_OPT_QUERY_CACHE};
use cares_rs::dns_record::ares_dns_record_t;
use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const T_A: u32 = 1;
const C_IN: u32 = 1;

/// One cacheable A answer (TTL 600) echoing the question.
fn craft_reply(req: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(req.len() + 16);
    r.extend_from_slice(&req[0..2]);
    r.extend_from_slice(&[0x81, 0x80]);
    r.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    r.extend_from_slice(&req[12..]);
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&[0, 1, 0, 1]);
    r.extend_from_slice(&[0, 0, 2, 0x58]);
    r.extend_from_slice(&[0, 4, 127, 1, 2, 3]);
    r
}

unsafe fn drive(channel: Channel, server: &UdpSocket, done: &dyn Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 512];
    while !done() && Instant::now() < deadline {
        if let Ok((n, from)) = server.recv_from(&mut buf) {
            let reply = craft_reply(&buf[..n]);
            let _ = server.send_to(&reply, from);
        }
        let mut socks = [ARES_SOCKET_BAD; ARES_GETSOCK_MAXNUM];
        let bitmask = ares_getsock(channel, socks.as_mut_ptr(), ARES_GETSOCK_MAXNUM as c_int);
        if bitmask == 0 {
            ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        }
        for &sock in socks.iter().filter(|&&s| s != ARES_SOCKET_BAD) {
            ares_process_fd(channel, sock, sock);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct Reentrant {
    channel: Channel,
    name: *const libc::c_char,
    outer_done: bool,
    outer_status: c_int,
    inner_done: bool,
    inner_status: c_int,
}

unsafe extern "C" fn prime_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    let out = &mut *(arg as *mut (bool, c_int));
    *out = (true, status);
}

unsafe extern "C" fn inner_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    let st = &mut *(arg as *mut Reentrant);
    st.inner_done = true;
    st.inner_status = status;
}

unsafe extern "C" fn outer_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    let st = &mut *(arg as *mut Reentrant);
    st.outer_done = true;
    st.outer_status = status;
    // Re-enter the library from inside the completion callback; before the
    // guard-hoist fix this hit cache.borrow_mut() while the outer cache-hit held it.
    ares_query_dnsrec(st.channel, st.name, C_IN, T_A, Some(inner_cb), arg, ptr::null_mut());
}

#[test]
#[cfg_attr(miri, ignore = "real reactor: UDP sockets + syscalls; Miri can't run them")]
fn callback_may_reenter_on_cache_hit() {
    unsafe {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind mini server");
        server.set_nonblocking(true).expect("nonblocking");
        let port = server.local_addr().unwrap().port();

        let mut channel: Channel = ptr::null_mut();
        // Cache is off by default (max_ttl 0); this test needs synchronous cache hits.
        let mut opts: ares_options = std::mem::zeroed();
        opts.qcache_max_ttl = 3600;
        assert_eq!(
            ares_init_options(&mut channel, &opts, ARES_OPT_QUERY_CACHE),
            ARES_SUCCESS
        );
        let csv = CString::new(format!("127.0.0.1:{port}")).unwrap();
        assert_eq!(ares_set_servers_ports_csv(channel, csv.as_ptr()), ARES_SUCCESS);

        let name = CString::new("reentrant.example").unwrap();
        let mut primed: (bool, c_int) = (false, -1);
        ares_query_dnsrec(
            channel,
            name.as_ptr(),
            C_IN,
            T_A,
            Some(prime_cb),
            &mut primed as *mut _ as *mut c_void,
            ptr::null_mut(),
        );
        drive(channel, &server, &|| primed.0);
        assert!(primed.0, "priming query must complete");
        assert_eq!(primed.1, ARES_SUCCESS, "priming query must succeed");

        let mut st = Reentrant {
            channel,
            name: name.as_ptr(),
            outer_done: false,
            outer_status: -1,
            inner_done: false,
            inner_status: -1,
        };
        ares_query_dnsrec(
            channel,
            name.as_ptr(),
            C_IN,
            T_A,
            Some(outer_cb),
            &mut st as *mut _ as *mut c_void,
            ptr::null_mut(),
        );
        // Both hits are synchronous; drive briefly in case either went to the wire.
        drive(channel, &server, &|| st.outer_done && st.inner_done);

        assert!(st.outer_done, "outer (cache-hit) callback must fire");
        assert_eq!(st.outer_status, ARES_SUCCESS);
        assert!(st.inner_done, "re-entrant inner callback must fire");
        assert_eq!(st.inner_status, ARES_SUCCESS);

        ares_destroy(channel);
    }
}
