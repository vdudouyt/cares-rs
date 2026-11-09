//! A completion callback may re-enter `ares_*` on the same channel; a cache-hit
//! path once held `cache.borrow_mut()` across the callback and aborted with
//! `BorrowMutError`, so this primes the cache and re-enters from the callback.

use std::ffi::{c_int, c_void, CString};
use std::net::UdpSocket;
use std::ptr;
use std::time::{Duration, Instant};

use cares_rs::ares_options::{
    ares_init_options, ares_options, ARES_OPT_QUERY_CACHE, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
};
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
    drive_with(channel, server, done, answer, Duration::from_secs(5));
}

/// The mock server's behavior: the reply to send for a query, or `None` to stay silent.
type Responder = fn(&[u8]) -> Option<Vec<u8>>;

fn answer(req: &[u8]) -> Option<Vec<u8>> {
    Some(craft_reply(req))
}

/// SERVFAIL echoing the question (no answer records).
fn servfail(req: &[u8]) -> Option<Vec<u8>> {
    let mut r = req.to_vec();
    r[2] = 0x81;
    r[3] = 0x82;
    Some(r)
}

fn silent(_req: &[u8]) -> Option<Vec<u8>> {
    None
}

/// Run the channel until `done` or `limit`; returns how many queries the mock server received.
unsafe fn drive_with(
    channel: Channel,
    server: &UdpSocket,
    done: &dyn Fn() -> bool,
    reply: Responder,
    limit: Duration,
) -> usize {
    let deadline = Instant::now() + limit;
    let mut buf = [0u8; 512];
    let mut received = 0;
    while !done() && Instant::now() < deadline {
        while let Ok((n, from)) = server.recv_from(&mut buf) {
            received += 1;
            if let Some(reply) = reply(&buf[..n]) {
                let _ = server.send_to(&reply, from);
            }
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
    received
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

struct MidTurn {
    channel: Channel,
    first_done: bool,
    first_status: c_int,
    second_done: bool,
    second_status: c_int,
}

unsafe extern "C" fn first_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    let st = &mut *(arg as *mut MidTurn);
    st.first_done = true;
    st.first_status = status;
    // Re-enter the reactor from inside a turn: the nested turn must run with no
    // run-queue lock or reactor borrow held by the outer one.
    ares_process_fd(st.channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}

unsafe extern "C" fn second_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    let st = &mut *(arg as *mut MidTurn);
    st.second_done = true;
    st.second_status = status;
}

#[test]
#[cfg_attr(miri, ignore = "real reactor: UDP sockets + syscalls; Miri can't run them")]
fn callback_may_call_ares_process_mid_turn() {
    unsafe {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind mini server");
        server.set_nonblocking(true).expect("nonblocking");
        let port = server.local_addr().unwrap().port();

        let mut channel: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut channel), ARES_SUCCESS);
        let csv = CString::new(format!("127.0.0.1:{port}")).unwrap();
        assert_eq!(ares_set_servers_ports_csv(channel, csv.as_ptr()), ARES_SUCCESS);

        let mut st = MidTurn { channel, first_done: false, first_status: -1, second_done: false, second_status: -1 };
        let arg = &mut st as *mut _ as *mut c_void;
        let first = CString::new("first.example").unwrap();
        let second = CString::new("second.example").unwrap();
        ares_query_dnsrec(channel, first.as_ptr(), C_IN, T_A, Some(first_cb), arg, ptr::null_mut());
        ares_query_dnsrec(channel, second.as_ptr(), C_IN, T_A, Some(second_cb), arg, ptr::null_mut());
        drive(channel, &server, &|| st.first_done && st.second_done);

        assert!(st.first_done && st.second_done, "both queries must complete");
        assert_eq!(st.first_status, ARES_SUCCESS);
        assert_eq!(st.second_status, ARES_SUCCESS);

        ares_destroy(channel);
    }
}

// --- Server-state callback re-entry ---------------------------------------
//
// The server-state callback fires synchronously from inside a task's poll
// (`AsyncClient::notify`). Re-entering the channel from it must not free or
// move the task being polled: a cancel only marks it, and a spawn may grow the
// executor's slot table without invalidating the poll in progress.

const ARES_ECANCELLED: c_int = 24;

struct ServState {
    channel: Channel,
    name: *const libc::c_char,
    /// How many queries to spawn from the first server-state callback.
    spawn: usize,
    /// Cancel the channel from the first server-state callback.
    cancel: bool,
    state_calls: usize,
    outer_calls: usize,
    outer_status: c_int,
    inner_calls: usize,
    inner_ok: usize,
}

unsafe extern "C" fn servstate_outer_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    let st = &mut *(arg as *mut ServState);
    st.outer_calls += 1;
    st.outer_status = status;
}

unsafe extern "C" fn servstate_inner_cb(arg: *mut c_void, status: c_int, _timeouts: usize, _rec: *const ares_dns_record_t) {
    let st = &mut *(arg as *mut ServState);
    st.inner_calls += 1;
    if status == ARES_SUCCESS {
        st.inner_ok += 1;
    }
}

unsafe extern "C" fn servstate_cb(_server: *const libc::c_char, _success: c_int, _flags: c_int, arg: *mut c_void) {
    let st = &mut *(arg as *mut ServState);
    st.state_calls += 1;
    if st.state_calls != 1 {
        return;
    }
    if st.cancel {
        ares_cancel(st.channel);
    }
    for _ in 0..st.spawn {
        ares_query_dnsrec(st.channel, st.name, C_IN, T_A, Some(servstate_inner_cb), arg, ptr::null_mut());
    }
}

/// One query against a mock server that behaves per `reply`, with the
/// server-state callback re-entering per `spawn`/`cancel`. Returns the final
/// state and how many queries the server received in total, including a
/// settle period after the query was delivered (to catch stray retries).
unsafe fn run_servstate(spawn: usize, cancel: bool, reply: Responder) -> (ServState, usize) {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind mini server");
    server.set_nonblocking(true).expect("nonblocking");
    let port = server.local_addr().unwrap().port();

    // Short timeouts and 2 tries, so a timeout path is hit quickly and a retry
    // after the cancel would show up within the settle period.
    let mut channel: Channel = ptr::null_mut();
    let mut opts: ares_options = std::mem::zeroed();
    opts.timeout = 100;
    opts.tries = 2;
    assert_eq!(ares_init_options(&mut channel, &opts, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES), ARES_SUCCESS);
    let csv = CString::new(format!("127.0.0.1:{port}")).unwrap();
    assert_eq!(ares_set_servers_ports_csv(channel, csv.as_ptr()), ARES_SUCCESS);

    let name = CString::new("servstate.example").unwrap();
    let mut st = ServState {
        channel,
        name: name.as_ptr(),
        spawn,
        cancel,
        state_calls: 0,
        outer_calls: 0,
        outer_status: -1,
        inner_calls: 0,
        inner_ok: 0,
    };
    let arg = &mut st as *mut _ as *mut c_void;
    ares_set_server_state_callback(channel, Some(servstate_cb), arg);
    ares_query_dnsrec(channel, name.as_ptr(), C_IN, T_A, Some(servstate_outer_cb), arg, ptr::null_mut());
    let done = || st.outer_calls > 0 && st.inner_calls == st.spawn;
    let mut received = drive_with(channel, &server, &done, reply, Duration::from_secs(5));
    received += drive_with(channel, &server, &|| false, reply, Duration::from_millis(500));
    ares_destroy(channel);
    (st, received)
}

#[test]
#[cfg_attr(miri, ignore = "real reactor: UDP sockets + syscalls; Miri can't run them")]
fn server_state_callback_may_cancel_the_polled_query() {
    let (st, _) = unsafe { run_servstate(0, true, answer) };
    assert_eq!(st.outer_calls, 1, "the polled query is delivered exactly once");
    assert_eq!(st.outer_status, ARES_ECANCELLED, "a cancel during its poll wins");
}

/// The failure callback on a timeout (upstream's `process_timeouts` →
/// `server_increment_failures` → `ares_requeue_query` shape): the query keeps
/// running after the callback, so a cancel from it must not free it.
#[test]
#[cfg_attr(miri, ignore = "real reactor: UDP sockets + syscalls; Miri can't run them")]
fn server_state_callback_may_cancel_on_timeout() {
    let (st, received) = unsafe { run_servstate(0, true, silent) };
    assert_eq!(st.state_calls, 1, "one failure report, none after the cancel");
    assert_eq!(st.outer_calls, 1, "the timed-out query is delivered exactly once");
    assert_eq!(st.outer_status, ARES_ECANCELLED);
    assert_eq!(received, 1, "no retry is sent after the cancel");
}

/// The failure callback on a SERVFAIL reply (upstream's `process_answer`
/// failure branch → `ares_requeue_query`).
#[test]
#[cfg_attr(miri, ignore = "real reactor: UDP sockets + syscalls; Miri can't run them")]
fn server_state_callback_may_cancel_on_servfail() {
    let (st, received) = unsafe { run_servstate(0, true, servfail) };
    assert_eq!(st.state_calls, 1, "one failure report, none after the cancel");
    assert_eq!(st.outer_calls, 1, "the failed query is delivered exactly once");
    assert_eq!(st.outer_status, ARES_ECANCELLED);
    assert_eq!(received, 1, "no retry is sent after the cancel");
}

#[test]
#[cfg_attr(miri, ignore = "real reactor: UDP sockets + syscalls; Miri can't run them")]
fn server_state_callback_may_spawn_queries() {
    // Enough spawns to reallocate the executor's slot table mid-poll.
    let (st, _) = unsafe { run_servstate(64, false, answer) };
    assert_eq!(st.outer_calls, 1);
    assert_eq!(st.outer_status, ARES_SUCCESS);
    assert_eq!(st.inner_calls, 64, "every spawned query completes");
    assert_eq!(st.inner_ok, 64);
}
