//! BATCH 1b contracts: defaults applied to a non-NULL `ares_options` init,
//! `ARES_FLAG_NO_DFLT_SVR` failure, the 250 ms timeout floor, and `ares_reinit`
//! not overriding explicitly supplied `ARES_OPT_FLAGS`.

use std::ffi::{c_char, c_int, c_void, CString};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cares::ares_options::{
    ares_destroy_options, ares_init_options, ares_options, ares_save_options, ARES_FLAG_NO_DFLT_SVR,
    ARES_FLAG_USEVC, ARES_OPT_FLAGS, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF,
    ARES_OPT_TIMEOUTMS,
};
use cares::dns_record::*;
use cares::*;

const ARES_SUCCESS: c_int = 0;
const ARES_ENOSERVER: c_int = 26;

static NONCE: AtomicU64 = AtomicU64::new(0);

/// A uniquely named resolv.conf that removes itself, so parallel tests never
/// share a path and a panic cannot leave a file behind.
struct TempConf {
    path: PathBuf,
}

impl TempConf {
    fn new(contents: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let seq = NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cares-rs-options-defaults-{}-{stamp}-{seq}.conf",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp resolv.conf");
        Self { path }
    }

    fn cstring(&self) -> CString {
        CString::new(self.path.to_string_lossy().as_bytes()).expect("path has no NUL")
    }
}

impl Drop for TempConf {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

unsafe fn save(channel: Channel) -> (ares_options, c_int) {
    let mut saved: ares_options = unsafe { std::mem::zeroed() };
    let mut mask: c_int = 0;
    let rc = unsafe { ares_save_options(channel, &mut saved, &mut mask) };
    assert_eq!(rc, ARES_SUCCESS, "ares_save_options");
    (saved, mask)
}

/// Since c-ares 1.31 the query cache is on by default with a 3600 s TTL.  A
/// non-NULL options struct without `ARES_OPT_QUERY_CACHE` must still get that
/// default, and `ares_save_options` must report it.
#[test]
fn init_options_without_query_cache_uses_3600s_default() {
    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.flags = 0;

        // Any harmless bit takes the caller-supplied options path.
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(
            ares_init_options(&mut channel, &opts, ARES_OPT_FLAGS),
            ARES_SUCCESS
        );
        assert!(!channel.is_null());

        let (mut saved, mask) = save(channel);
        assert_ne!(
            mask & ARES_OPT_QUERY_CACHE,
            0,
            "the documented default must be reported as ARES_OPT_QUERY_CACHE"
        );
        assert_eq!(
            saved.qcache_max_ttl, 3600,
            "query cache must default to a 3600 s TTL"
        );

        ares_destroy_options(&mut saved);
        ares_destroy(channel);
    }
}

/// `ARES_FLAG_NO_DFLT_SVR` with no configured server must fail initialization
/// with `ARES_ENOSERVER`, not produce a channel that fails later.
#[test]
fn init_options_no_dflt_svr_without_nameserver_fails() {
    let conf = TempConf::new("search example.test\noptions ndots:2\n");
    let path = conf.cstring();

    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.flags = ARES_FLAG_NO_DFLT_SVR;
        opts.resolvconf_path = path.as_ptr() as *mut c_char;

        let mut channel: Channel = ptr::null_mut();
        let rc = ares_init_options(
            &mut channel,
            &opts,
            ARES_OPT_FLAGS | ARES_OPT_RESOLVCONF,
        );

        // Release the channel before asserting so a regression does not also
        // leak in the failure report.
        if !channel.is_null() {
            ares_destroy(channel);
        }
        assert_eq!(
            rc, ARES_ENOSERVER,
            "init with ARES_FLAG_NO_DFLT_SVR and no nameserver must return ARES_ENOSERVER"
        );
        assert!(
            channel.is_null(),
            "a failed initialization must leave the channel NULL"
        );
    }
}

unsafe extern "C" fn query_cb(
    arg: *mut c_void,
    _status: c_int,
    _timeouts: c_int,
    _abuf: *mut u8,
    _alen: c_int,
) {
    unsafe { *(arg as *mut bool) = true };
}

/// Docs: timeouts below 250 ms are raised to 250 ms.  A query against a bound
/// but silent UDP socket must therefore make `ares_timeout` ask for at least
/// ~200 ms even though `ARES_OPT_TIMEOUTMS` was 100.
#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn sub_250ms_timeout_is_raised_to_250ms() {
    // Bound and never read: the packet is queued and no ICMP unreachable is
    // generated, so the query stays pending until its timer fires.
    let silent = UdpSocket::bind(("127.0.0.1", 0)).expect("bind silent UDP socket");
    let port = silent.local_addr().expect("local addr").port();
    let conf = TempConf::new(&format!("nameserver 127.0.0.1:{port}\n"));
    let path = conf.cstring();

    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.timeout = 100;
        opts.resolvconf_path = path.as_ptr() as *mut c_char;

        let mut channel: Channel = ptr::null_mut();
        assert_eq!(
            ares_init_options(
                &mut channel,
                &opts,
                ARES_OPT_TIMEOUTMS | ARES_OPT_RESOLVCONF,
            ),
            ARES_SUCCESS
        );
        assert!(!channel.is_null());

        let name = CString::new("timeout-floor.example").expect("name");
        let mut done = false;
        ares_query(
            channel,
            name.as_ptr(),
            c_int::from(ARES_CLASS_IN),
            c_int::from(ARES_REC_TYPE_A),
            Some(query_cb),
            &mut done as *mut bool as *mut c_void,
        );
        assert!(!done, "the silent server must not answer synchronously");

        let mut tv: libc::timeval = std::mem::zeroed();
        let ret = ares_timeout(channel, ptr::null_mut(), &mut tv);
        assert!(!ret.is_null(), "a pending query must have a timeout");
        let wait_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
        assert!(
            wait_ms >= 200,
            "a 100 ms timeout must be raised to the documented 250 ms floor (got {wait_ms} ms)"
        );

        ares_cancel(channel);
        ares_destroy(channel);
    }
}

/// `ares_reinit.3`: system configuration must never override caller settings.
/// Explicitly supplying `ARES_OPT_FLAGS` (here 0) must keep `use-vc` from
/// resolv.conf from changing the channel flags.
#[test]
fn reinit_does_not_override_explicit_flags() {
    let conf = TempConf::new("nameserver 127.0.0.1\noptions use-vc\n");
    let path = conf.cstring();

    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.flags = 0;
        opts.resolvconf_path = path.as_ptr() as *mut c_char;

        let mut channel: Channel = ptr::null_mut();
        assert_eq!(
            ares_init_options(
                &mut channel,
                &opts,
                ARES_OPT_FLAGS | ARES_OPT_RESOLVCONF,
            ),
            ARES_SUCCESS
        );
        assert!(!channel.is_null());

        assert_eq!(ares_reinit(channel), ARES_SUCCESS);

        let (mut saved, mask) = save(channel);
        assert_ne!(
            mask & ARES_OPT_FLAGS,
            0,
            "explicitly supplied flags must still be reported"
        );
        assert_eq!(
            saved.flags & ARES_FLAG_USEVC,
            0,
            "ares_reinit must not force use-vc when the caller supplied ARES_OPT_FLAGS"
        );

        ares_destroy_options(&mut saved);
        ares_destroy(channel);
    }
}
