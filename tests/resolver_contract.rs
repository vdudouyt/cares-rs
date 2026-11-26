//! Resolver callback contracts from the c-ares audit: the addrinfo timeout
//! count reported to the callback, and per-DNS-query accounting for
//! `ares_queue_active_queries`.
//!
//! Deterministic loopback UDP: the server socket is bound but never read, so
//! request packets queue in its receive buffer and no ICMP unreachable is
//! generated; the client sees silence until its own timer fires. Global
//! channel state is serialized with a Mutex.

use std::ffi::{c_int, c_void, CString};
use std::net::UdpSocket;
use std::ptr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cares::ares_options::{
    ares_init_options, ares_options, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
};
use cares::*;

const ARES_SUCCESS: c_int = 0;
const ARES_ETIMEOUT: c_int = 12;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A bound-but-silent loopback UDP server: packets are queued and never read,
/// so the resolver must hit its own timeout.
fn silent_server() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind silent UDP socket");
    let port = socket.local_addr().expect("local addr").port();
    (socket, port)
}

fn base_options() -> ares_options {
    ares_options {
        timeout: 250,
        tries: 1,
        ..ares_options::default()
    }
}

unsafe fn init_channel(options: &ares_options, mask: c_int) -> Channel {
    let mut channel: Channel = ptr::null_mut();
    let rc = unsafe { ares_init_options(&mut channel, options, mask) };
    assert_eq!(rc, ARES_SUCCESS, "ares_init_options");
    assert!(!channel.is_null());
    channel
}

unsafe fn use_server(channel: Channel, port: u16) {
    let csv = CString::new(format!("127.0.0.1:{port}")).unwrap();
    assert_eq!(
        unsafe { ares_set_servers_csv(channel, csv.as_ptr()) },
        ARES_SUCCESS
    );
}

/// One manual-drive turn: hand every published socket to `ares_process_fd`,
/// or run a timer-only turn when the channel has no fd interest.
fn pump_channel(channel: Channel) {
    let mut socks = [ARES_SOCKET_BAD; ARES_GETSOCK_MAXNUM];
    let bitmask =
        unsafe { ares_getsock(channel, socks.as_mut_ptr(), ARES_GETSOCK_MAXNUM as c_int) };
    if bitmask == 0 {
        unsafe { ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD) };
    }
    for &sock in socks.iter().filter(|&&sock| sock != ARES_SOCKET_BAD) {
        unsafe { ares_process_fd(channel, sock, sock) };
    }
}

fn drive(channel: Channel, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() && Instant::now() < deadline {
        pump_channel(channel);
        std::thread::sleep(Duration::from_millis(1));
    }
    pump_channel(channel);
}

#[derive(Default)]
struct AiResult {
    done: bool,
    status: c_int,
    timeouts: c_int,
}

unsafe extern "C" fn ai_cb(
    arg: *mut c_void,
    status: c_int,
    timeouts: c_int,
    ai: *mut ares_addrinfo,
) {
    let result = unsafe { &mut *(arg as *mut AiResult) };
    result.done = true;
    result.status = status;
    result.timeouts = timeouts;
    if !ai.is_null() {
        unsafe { ares_freeaddrinfo(ai) };
    }
}

unsafe fn start_addrinfo(channel: Channel, name: &CString, family: c_int, result: &mut AiResult) {
    let mut hints: ares_addrinfo_hints = unsafe { std::mem::zeroed() };
    hints.ai_family = family;
    unsafe {
        ares_getaddrinfo(
            channel,
            name.as_ptr(),
            ptr::null(),
            &hints as *const ares_addrinfo_hints,
            Some(ai_cb),
            result as *mut AiResult as *mut c_void,
        )
    };
}

// ---------------------------------------------------------------------------
// 1. ares_getaddrinfo's callback must report the timeout count.
//
// upstream `ares_addrinfo_callback(..., int timeouts, ...)`: the count is the
// number of timeouts that occurred while resolving. Current code hard-codes 0
// in on_addrinfo_reply, so this test fails on the `timeouts >= 1` assertion.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn getaddrinfo_callback_reports_timeout_count() {
    let _serial = serial();
    let (_silent, port) = silent_server();
    unsafe {
        let options = base_options();
        let channel = init_channel(&options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES);
        use_server(channel, port);

        let name = CString::new("addrinfo-timeout.example").unwrap();
        let mut result = AiResult::default();
        start_addrinfo(channel, &name, libc::AF_INET, &mut result);
        drive(channel, || result.done);

        let done = result.done;
        let status = result.status;
        let timeouts = result.timeouts;
        ares_destroy(channel);

        assert!(done, "ares_getaddrinfo callback did not fire within 5s");
        assert_eq!(
            status, ARES_ETIMEOUT,
            "silent server must make the lookup time out"
        );
        assert!(
            timeouts >= 1,
            "ares_getaddrinfo callback reported {timeouts} timeouts; \
             at least one timeout occurred, so the count must be >= 1"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. ares_queue_active_queries counts DNS queries, not executor tasks.
//
// Documented upstream behavior: an AF_UNSPEC `ares_getaddrinfo` may launch an
// A and an AAAA query, and each active DNS query is reflected in the count.
// Current code reports `executor.active_count()` (one task per lookup), so the
// count stays 1 and this test fails on `count >= 2`.
//
// Observed on current code: the count is 1 synchronously right after
// `ares_getaddrinfo`, and remains 1 after two timer-only turns; both families
// are raced inside the same executor task. Two turns are attempted anyway in
// case a future per-family task model starts the second query on a later poll.
// The test never waits for the 250 ms timeout.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn queue_active_queries_counts_families_of_unspec_lookup() {
    let _serial = serial();
    let (_silent, port) = silent_server();
    unsafe {
        let options = base_options();
        let channel = init_channel(&options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES);

        // Sanity: an idle channel has no DNS query in flight.
        assert_eq!(
            ares_queue_active_queries(channel),
            0,
            "a freshly initialized channel must report zero active queries"
        );

        use_server(channel, port);
        let name = CString::new("queue-count.example").unwrap();
        let mut result = AiResult::default();
        start_addrinfo(channel, &name, libc::AF_UNSPEC, &mut result);
        assert!(
            !result.done,
            "the silent server must not answer an AF_UNSPEC lookup synchronously"
        );

        // Inspect before driving to completion; no sleeping, no timeout wait.
        let mut count = ares_queue_active_queries(channel);
        for _ in 0..2 {
            if count >= 2 {
                break;
            }
            ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
            count = ares_queue_active_queries(channel);
        }

        ares_destroy(channel);

        assert!(
            count >= 2,
            "an AF_UNSPEC ares_getaddrinfo issues an A and an AAAA query; \
             ares_queue_active_queries must count both DNS queries, got {count}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. ares_queue_wait_empty is a cheap no-op on an idle channel.
// ---------------------------------------------------------------------------

#[test]
fn queue_wait_empty_returns_success_with_no_queries() {
    let _serial = serial();
    unsafe {
        let options = base_options();
        let channel = init_channel(&options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES);

        assert_eq!(ares_queue_active_queries(channel), 0);
        assert_eq!(
            ares_queue_wait_empty(channel, 0),
            ARES_SUCCESS,
            "an idle channel must report empty immediately, even with timeout 0"
        );

        ares_destroy(channel);
    }
}
