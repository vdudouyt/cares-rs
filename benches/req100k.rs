use cares_rs::*;
use libc::*;
use std::ffi::CString;
use std::ptr;
use std::net::Ipv4Addr;
use std::slice;
use std::time::Instant;
use std::sync::atomic::{AtomicU32, Ordering};
use libloading::Library;

// Some non-Rusty C API invocations for benchmarking purposes

#[derive(Debug)]
#[allow(dead_code)]
struct CAresVariant {
    ares_library_init: extern "C" fn(_flags: c_int) -> c_int,
    ares_init: unsafe extern "C" fn(out_channel: *mut Channel) -> c_int,
    ares_destroy: unsafe extern "C" fn(channel: Channel),
    ares_gethostbyname: unsafe extern "C" fn(channel: Channel, hostname: *const c_char, _family: c_int, callback: AresHostCallback, arg: *mut c_void),
    ares_timeout: unsafe extern "C" fn(_channel: Channel, _maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval,
    ares_fds: unsafe extern "C" fn(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int,
    ares_process: unsafe extern "C" fn(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set),
    ares_set_servers: unsafe extern "C" fn(channel: Channel, head: *mut ares_addr_node),
}

impl CAresVariant {
    fn ours() -> CAresVariant {
        CAresVariant {
            ares_library_init,
            ares_init,
            ares_destroy,
            ares_gethostbyname,
            ares_timeout,
            ares_fds,
            ares_process,
            ares_set_servers
        }
    }
}

struct DynCAres {
    lib: Library
}

impl DynCAres {
    fn load() -> DynCAres {
        let lib = unsafe { Library::new("libcares.so").unwrap() };
        DynCAres { lib }
    }
    fn get_api(&self) -> CAresVariant {
        let lib = &self.lib;
        CAresVariant {
            ares_library_init: unsafe { *lib.get(b"ares_library_init\0").unwrap() },
            ares_init: unsafe { *lib.get(b"ares_init\0").unwrap() },
            ares_destroy: unsafe { *lib.get(b"ares_destroy\0").unwrap() },
            ares_gethostbyname: unsafe { *lib.get(b"ares_gethostbyname\0").unwrap() },
            ares_timeout: unsafe { *lib.get(b"ares_timeout\0").unwrap() },
            ares_fds: unsafe { *lib.get(b"ares_fds\0").unwrap() },
            ares_process: unsafe { *lib.get(b"ares_process\0").unwrap() },
            ares_set_servers: unsafe { *lib.get(b"ares_set_servers\0").unwrap() },
        }
    }
}

struct BenchRunner {
    cares: CAresVariant
}

impl BenchRunner {
    fn new(cares: CAresVariant) -> BenchRunner {
        assert_eq!(ares_library_init(ARES_LIB_INIT_ALL), ARES_SUCCESS);
        BenchRunner { cares }
    }
    fn run(&mut self, label: &str) {
        let start = Instant::now();
        for _ in 1..=10000 { self.run_epoch(); }
        println!("{} took {:?}", label, start.elapsed());
    }
    fn run_epoch(&mut self) {
        let mut channel: Channel = std::ptr::null_mut();
        assert!(unsafe { (self.cares.ares_init)(&mut channel) == ARES_SUCCESS });
        self.set_localhost_nameservers(channel);
        
        let mut readers: fd_set = unsafe { std::mem::zeroed() };
        let mut writers: fd_set = unsafe { std::mem::zeroed() };
        let mut tv_buf: timeval = unsafe { std::mem::zeroed() };
        
        let domain_name = CString::new("mydomain.local").unwrap();
        for _ in 1..=10 {
            unsafe { (self.cares.ares_gethostbyname)(channel, domain_name.as_ptr(), AF_INET, cares_callback, std::ptr::null_mut()) };
        }
        
        loop {
            let nfds: c_int = unsafe { (self.cares.ares_fds)(channel, &mut readers, &mut writers) };
            if nfds == 0 { break; }
        
            let tv_ptr: *mut timeval = unsafe { (self.cares.ares_timeout)(channel, ptr::null_mut(), &mut tv_buf) };
        
            unsafe { libc::select(nfds, &mut readers as *mut fd_set, &mut writers as *mut fd_set, ptr::null_mut(), tv_ptr) };
            unsafe { (self.cares.ares_process)(channel, &mut readers, &mut writers) };
        }
        unsafe { (self.cares.ares_destroy)(channel) };
    }
    fn set_localhost_nameservers(&mut self, channel: Channel) {
        let localhost = [ &Ipv4Addr::LOCALHOST.octets()[..], &[0u8; 12][..] ].concat();
        let mut sentinel = ares_addr_node { next: ptr::null_mut(), family: 0, data: [0; 16] };
        let mut head = ares_addr_node { next: &mut sentinel, family: AF_INET, data: localhost.try_into().unwrap() };
        unsafe { (self.cares.ares_set_servers)(channel, &mut head) };
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn cares_callback(_arg: *mut c_void, status: c_int, _timeouts: c_int, host: *mut libc::hostent) {
    assert_eq!(status, ARES_SUCCESS);
    assert_eq!(unsafe { (*host).h_addrtype }, AF_INET);

    let addr_ptr = unsafe { *(*host).h_addr_list };
    let addr: [u8; 4] = unsafe { slice::from_raw_parts(addr_ptr as *const u8, 4).try_into().unwrap() };
    assert_eq!(&Ipv4Addr::from(addr).to_string(), "1.2.3.4");
    let _ = COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
}

fn main() {
    let theirs = DynCAres::load();
    let mut runner1 = BenchRunner::new(theirs.get_api());
    runner1.run("theirs");
    assert_eq!(COUNTER.load(Ordering::Relaxed), 100_000);

    let mut runner2 = BenchRunner::new(CAresVariant::ours());
    runner2.run("ours");
    assert_eq!(COUNTER.load(Ordering::Relaxed), 200_000);
}
