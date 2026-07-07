//! Perf gate for the async-executor spike: measure the per-query cost of the
//! `ares_query` lifecycle (which the spike routes through the custom executor)
//! end-to-end against an in-process mock DNS server. Reports wall-time and
//! allocation count per query via a counting global allocator.
//!
//! Run the SAME binary on `spike-async` and on the prev commit and compare:
//!   cargo run --release --example bench_query
//! (`ares_query`/`ares_fds`/`ares_timeout`/`ares_process` are stable exports, so
//! this builds unchanged on both branches.)

use cares_rs::*;
use libc::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::CString;
use std::net::{Ipv4Addr, UdpSocket};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

// ---- counting allocator -----------------------------------------------------
struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(l.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Counting = Counting;

// ---- in-process mock DNS server ---------------------------------------------
// Echoes the query's QID + question and appends a single A record (1.2.3.4).
fn spawn_mock() -> u16 {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let port = sock.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if n < 12 {
                continue;
            }
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80; // QR = 1 (response)
            resp[6] = 0; // ANCOUNT hi
            resp[7] = 1; // ANCOUNT lo = 1
            // answer: name ptr -> offset 12, type A, class IN, ttl 60, rdlen 4, 1.2.3.4
            resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 1, 2, 3, 4]);
            let _ = sock.send_to(&resp, from);
        }
    });
    port
}

// ---- callback ---------------------------------------------------------------
static DONE: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" fn cb(_arg: *mut c_void, status: c_int, _t: c_int, _abuf: *mut u8, _alen: c_int) {
    assert_eq!(status, ARES_SUCCESS, "mock query must succeed");
    DONE.fetch_add(1, Ordering::Relaxed);
}

fn set_server(channel: Channel, port: u16) {
    // point the channel at 127.0.0.1:<mock port>
    let s = CString::new(format!("127.0.0.1:{port}")).unwrap();
    unsafe { ares_set_servers_csv(channel, s.as_ptr()) };
}

fn drive(channel: Channel) {
    let mut readers: fd_set = unsafe { std::mem::zeroed() };
    let mut writers: fd_set = unsafe { std::mem::zeroed() };
    let mut tv_buf: timeval = unsafe { std::mem::zeroed() };
    loop {
        let nfds = unsafe { ares_fds(channel, &mut readers, &mut writers) };
        if nfds == 0 {
            break;
        }
        let tv = unsafe { ares_timeout(channel, ptr::null_mut(), &mut tv_buf) };
        unsafe { select(nfds, &mut readers, &mut writers, ptr::null_mut(), tv) };
        unsafe { ares_process(channel, &mut readers, &mut writers) };
    }
}

const BATCH: usize = 50;
const EPOCHS: usize = 2000; // 50 * 2000 = 100_000 queries

fn run_epochs(port: u16) {
    let name = CString::new("mydomain.local").unwrap();
    for _ in 0..EPOCHS {
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(unsafe { ares_init(&mut channel) }, ARES_SUCCESS);
        set_server(channel, port);
        for _ in 0..BATCH {
            // T_A = 1
            unsafe { ares_query(channel, name.as_ptr(), 1, 1, Some(cb), ptr::null_mut()) };
        }
        drive(channel);
        unsafe { ares_destroy(channel) };
    }
}

fn main() {
    assert_eq!(ares_library_init(ARES_LIB_INIT_ALL), ARES_SUCCESS);
    let port = spawn_mock();

    // warm-up (one epoch) so lazy inits don't skew the measured window.
    let name = CString::new("mydomain.local").unwrap();
    let mut ch: Channel = ptr::null_mut();
    assert_eq!(unsafe { ares_init(&mut ch) }, ARES_SUCCESS);
    set_server(ch, port);
    for _ in 0..BATCH {
        unsafe { ares_query(ch, name.as_ptr(), 1, 1, Some(cb), ptr::null_mut()) };
    }
    drive(ch);
    unsafe { ares_destroy(ch) };
    DONE.store(0, Ordering::Relaxed);

    // measured window
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let b0 = BYTES.load(Ordering::Relaxed);
    let t0 = Instant::now();
    run_epochs(port);
    let elapsed = t0.elapsed();
    let allocs = ALLOCS.load(Ordering::Relaxed) - a0;
    let bytes = BYTES.load(Ordering::Relaxed) - b0;

    let n = (BATCH * EPOCHS) as u64;
    assert_eq!(DONE.load(Ordering::Relaxed), n, "all queries must complete");
    println!("ares_query x{n}: {elapsed:?}");
    println!("  {:.0} queries/sec", n as f64 / elapsed.as_secs_f64());
    println!("  {:.2} ns/query", elapsed.as_nanos() as f64 / n as f64);
    println!("  {:.2} allocs/query ({} total)", allocs as f64 / n as f64, allocs);
    println!("  {:.1} bytes/query ({} total)", bytes as f64 / n as f64, bytes);
    let _ = Ipv4Addr::LOCALHOST;
}
