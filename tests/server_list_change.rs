//! Changing the server list must take effect for the next query: no state kept
//! for the old list (pooled connections in particular) may route it to a
//! server that is no longer configured.

use std::ffi::{c_int, c_void, CString};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cares_rs::ares_options::{ares_init_options, ares_options, ARES_FLAG_USEVC, ARES_OPT_FLAGS};
use cares_rs::dns_record::ares_dns_record_t;
use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const T_A: u32 = 1;
const C_IN: u32 = 1;

/// One A answer (127.1.2.3) echoing the question.
fn craft_reply(req: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(req.len() + 16);
    r.extend_from_slice(&req[0..2]);
    r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    r.extend_from_slice(&req[12..]);
    r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 1, 2, 3]);
    r
}

/// A DNS-over-TCP responder counting the queries it answers.
fn tcp_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || loop {
                let mut len = [0u8; 2];
                if s.read_exact(&mut len).is_err() {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if s.read_exact(&mut q).is_err() {
                    return;
                }
                seen.fetch_add(1, Ordering::SeqCst);
                let r = craft_reply(&q);
                let mut out = (r.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&r);
                if s.write_all(&out).is_err() {
                    return;
                }
            });
        }
    });
    (port, count)
}

unsafe extern "C" fn query_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    *(arg as *mut Option<c_int>) = Some(status);
}

/// Run one A query to completion and return its status.
unsafe fn query(channel: Channel, name: &str) -> Option<c_int> {
    let name = CString::new(name).unwrap();
    let mut status: Option<c_int> = None;
    let arg = &mut status as *mut _ as *mut c_void;
    ares_query_dnsrec(channel, name.as_ptr(), C_IN, T_A, Some(query_cb), arg, ptr::null_mut());
    let deadline = Instant::now() + Duration::from_secs(5);
    while status.is_none() && Instant::now() < deadline {
        let mut socks = [ARES_SOCKET_BAD; ARES_GETSOCK_MAXNUM];
        let mask = ares_getsock(channel, socks.as_mut_ptr(), ARES_GETSOCK_MAXNUM as c_int);
        if mask == 0 {
            ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        }
        for &sock in socks.iter().filter(|&&s| s != ARES_SOCKET_BAD) {
            ares_process_fd(channel, sock, sock);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    status
}

#[test]
#[cfg_attr(miri, ignore = "real reactor: TCP sockets + syscalls; Miri can't run them")]
fn tcp_query_after_server_change_reaches_the_new_server() {
    unsafe {
        let (port_a, seen_a) = tcp_server();
        let (port_b, seen_b) = tcp_server();

        let mut channel: Channel = ptr::null_mut();
        let mut opts: ares_options = std::mem::zeroed();
        opts.flags = ARES_FLAG_USEVC;
        assert_eq!(ares_init_options(&mut channel, &opts, ARES_OPT_FLAGS), ARES_SUCCESS);

        let a = CString::new(format!("127.0.0.1:{port_a}")).unwrap();
        assert_eq!(ares_set_servers_ports_csv(channel, a.as_ptr()), ARES_SUCCESS);
        assert_eq!(query(channel, "first.example"), Some(ARES_SUCCESS));
        assert_eq!(seen_a.load(Ordering::SeqCst), 1, "first query went to A");

        // Replace A with B: the pooled TCP connection to A must not be reused.
        let b = CString::new(format!("127.0.0.1:{port_b}")).unwrap();
        assert_eq!(ares_set_servers_ports_csv(channel, b.as_ptr()), ARES_SUCCESS);
        assert_eq!(query(channel, "second.example"), Some(ARES_SUCCESS));
        assert_eq!(seen_b.load(Ordering::SeqCst), 1, "second query must reach B");
        assert_eq!(seen_a.load(Ordering::SeqCst), 1, "A must not see the second query");

        ares_destroy(channel);
    }
}
