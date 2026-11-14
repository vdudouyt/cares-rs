//! Event-thread stress: callbacks fire on the event thread while other threads
//! issue queries, cancel and destroy the channel. Run per backend (epoll, poll).
//! Every query must complete exactly once, whatever the interleaving.

use std::ffi::{c_int, c_void, CString};
use std::net::UdpSocket;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cares_rs::ares_options::{ares_init_options, ares_options, ARES_OPT_EVENT_THREAD, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES};
use cares_rs::error::{ARES_ECANCELLED, ARES_EDESTRUCTION};
use cares_rs::*;

const T_A: c_int = 1;
const C_IN: c_int = 1;
const BACKENDS: [c_int; 2] = [ARES_EVSYS_EPOLL, ARES_EVSYS_POLL];

/// One A answer echoing the question.
fn craft_reply(req: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(req.len() + 16);
    r.extend_from_slice(&req[0..2]);
    r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    r.extend_from_slice(&req[12..]);
    r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 2, 0x58, 0, 4, 127, 1, 2, 3]);
    r
}

/// A mock DNS server thread (blocking I/O is fine in test code).
struct Server {
    addr: String,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Server {
    fn start(answer: bool) -> Server {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let addr = format!("127.0.0.1:{}", sock.local_addr().unwrap().port());
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let join = thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !flag.load(Ordering::Relaxed) {
                if let Ok((n, from)) = sock.recv_from(&mut buf) {
                    if answer && n > 12 {
                        let _ = sock.send_to(&craft_reply(&buf[..n]), from);
                    }
                }
            }
        });
        Server { addr, stop, join: Some(join) }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[derive(Default)]
struct Tally {
    done: AtomicUsize,
    ok: AtomicUsize,
    cancelled: AtomicUsize,
    destroyed: AtomicUsize,
    other: AtomicUsize,
}

unsafe extern "C" fn on_done(arg: *mut c_void, status: c_int, _timeouts: c_int, _abuf: *mut u8, _alen: c_int) {
    let tally = &*(arg as *const Tally);
    match status {
        ARES_SUCCESS => tally.ok.fetch_add(1, Ordering::SeqCst),
        ARES_ECANCELLED => tally.cancelled.fetch_add(1, Ordering::SeqCst),
        ARES_EDESTRUCTION => tally.destroyed.fetch_add(1, Ordering::SeqCst),
        _ => tally.other.fetch_add(1, Ordering::SeqCst),
    };
    tally.done.fetch_add(1, Ordering::SeqCst);
}

/// A channel with the event thread on `evsys`, pointed at `server`.
unsafe fn open(evsys: c_int, server: &Server, timeout_ms: c_int) -> Channel {
    let opts = ares_options { evsys, timeout: timeout_ms, tries: 1, ..ares_options::default() };
    let mut channel: Channel = ptr::null_mut();
    let mask = ARES_OPT_EVENT_THREAD | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;
    assert_eq!(ares_init_options(&mut channel, &opts, mask), ARES_SUCCESS);
    let csv = CString::new(server.addr.clone()).unwrap();
    assert_eq!(ares_set_servers_csv(channel, csv.as_ptr()), ARES_SUCCESS);
    channel
}

unsafe fn query(channel: Channel, tally: &Arc<Tally>) {
    let name = CString::new("example.com").unwrap();
    ares_query(channel, name.as_ptr(), C_IN, T_A, Some(on_done), Arc::as_ptr(tally) as *mut c_void);
}

/// Issue `total` queries in batches, letting each batch finish first. The mock
/// server is one UDP socket whose default receive buffer holds only a few
/// hundred datagrams: an unbounded burst gets dropped, and a dropped query
/// would then just sit until its timeout (test noise, not a library fault).
unsafe fn run_in_batches(channel: Channel, tally: &Arc<Tally>, total: usize, batch: usize) {
    let mut issued = 0;
    while issued < total {
        for _ in 0..batch.min(total - issued) {
            query(channel, tally);
            issued += 1;
        }
        assert_eq!(ares_queue_wait_empty(channel, 30_000), ARES_SUCCESS, "batch stuck after {issued} queries");
    }
}

#[test]
#[cfg_attr(miri, ignore)] // real sockets and threads: Miri can't emulate them
fn queries_complete_on_every_backend() {
    for evsys in BACKENDS {
        let server = Server::start(true);
        let tally = Arc::new(Tally::default());
        unsafe {
            let channel = open(evsys, &server, 20_000);
            run_in_batches(channel, &tally, 200, 50);
            ares_destroy(channel);
        }
        assert_eq!(tally.done.load(Ordering::SeqCst), 200, "evsys {evsys}");
        assert_eq!(tally.ok.load(Ordering::SeqCst), 200, "evsys {evsys}: all should be answered");
    }
}

/// Destroy while queries are in flight (the server never answers): every
/// callback fires exactly once, with `ARES_EDESTRUCTION`, before destroy returns.
#[test]
#[cfg_attr(miri, ignore)] // real sockets and threads: Miri can't emulate them
fn destroy_with_queries_in_flight() {
    for evsys in BACKENDS {
        let server = Server::start(false);
        for round in 0..60u64 {
            let tally = Arc::new(Tally::default());
            unsafe {
                let channel = open(evsys, &server, 30_000);
                for _ in 0..20 {
                    query(channel, &tally);
                }
                // Vary how far the event thread has got before destroy lands.
                thread::sleep(Duration::from_micros(round * 150));
                ares_destroy(channel);
            }
            assert_eq!(tally.done.load(Ordering::SeqCst), 20, "evsys {evsys} round {round}");
            assert_eq!(tally.destroyed.load(Ordering::SeqCst), 20, "evsys {evsys} round {round}");
        }
    }
}

/// `ares_cancel` from another thread while this one keeps issuing queries and
/// the event thread completes them.
#[test]
#[cfg_attr(miri, ignore)] // real sockets and threads: Miri can't emulate them
fn cancel_races_with_new_queries() {
    for evsys in BACKENDS {
        let server = Server::start(true);
        let tally = Arc::new(Tally::default());
        unsafe {
            let channel = open(evsys, &server, 20_000);
            let addr = channel as usize;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let canceller = thread::spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    ares_cancel(addr as Channel);
                    thread::sleep(Duration::from_micros(300));
                }
            });
            for _ in 0..300 {
                query(channel, &tally);
                thread::sleep(Duration::from_micros(200));
            }
            stop.store(true, Ordering::Relaxed);
            canceller.join().unwrap();
            assert_eq!(ares_queue_wait_empty(channel, 10_000), ARES_SUCCESS, "evsys {evsys}");
            ares_destroy(channel);
        }
        let (done, ok, cancelled) = (tally.done.load(Ordering::SeqCst), tally.ok.load(Ordering::SeqCst), tally.cancelled.load(Ordering::SeqCst));
        assert_eq!(done, 300, "evsys {evsys}: each query completes exactly once");
        assert_eq!(ok + cancelled, 300, "evsys {evsys}: only success or cancel expected");
    }
}

/// Many channels at once, each with its own event thread and backend instance.
#[test]
#[cfg_attr(miri, ignore)] // real sockets and threads: Miri can't emulate them
fn many_channels_in_parallel() {
    let server = Arc::new(Server::start(true));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let server = server.clone();
            thread::spawn(move || {
                let evsys = BACKENDS[i % 2];
                let tally = Arc::new(Tally::default());
                unsafe {
                    let channel = open(evsys, &server, 20_000);
                    run_in_batches(channel, &tally, 50, 8);
                    ares_destroy(channel);
                }
                let (done, ok) = (tally.done.load(Ordering::SeqCst), tally.ok.load(Ordering::SeqCst));
                assert_eq!(done, 50, "every query completes exactly once");
                assert_eq!(ok, 50, "other statuses: cancelled {} destroyed {} other {}", tally.cancelled.load(Ordering::SeqCst), tally.destroyed.load(Ordering::SeqCst), tally.other.load(Ordering::SeqCst));
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
