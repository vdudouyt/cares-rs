//! Functional regressions from the external review (`REVIEW.md` findings 02-04).
//!
//! These exercise the public C ABI, not the internal Rust helpers:
//! - resolv.conf zero/overflow numeric options must be ignored without
//!   applying 250 ms / one-attempt values and without aborting init;
//! - legacy name expansion must use c-ares's `\DDD` / reserved-character
//!   escaping for attacker-controlled wire labels;
//! - a non-ASCII `ares_getaddrinfo` name must not panic across the C ABI.
//!
//! A panic in an `extern "C"` function aborts the process, so the cases that
//! would abort run in a child copy of this test binary.

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::net::UdpSocket;
#[cfg(not(miri))]
use std::process::Command;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cares::ares_options::{ares_init_options, ares_options, ARES_OPT_RESOLVCONF};
use cares::dns_record::{ARES_CLASS_IN, ARES_REC_TYPE_A};
use cares::*;

const ARES_SUCCESS: c_int = 0;
const ARES_EBADNAME: c_int = 8;

#[cfg(not(miri))]
const OVERFLOW_CASE_ENV: &str = "CARES_RS_REVIEW_RESOLVCONF_OVERFLOW_CHILD";
#[cfg(not(miri))]
const NONASCII_CASE_ENV: &str = "CARES_RS_REVIEW_NONASCII_ADDRINFO_CHILD";

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// resolv.conf helpers
// ---------------------------------------------------------------------------

static NONCE: AtomicU64 = AtomicU64::new(0);

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
            "cares-rs-review-{}-{stamp}-{seq}.conf",
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

fn silent_server() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind silent UDP socket");
    let port = socket.local_addr().expect("local addr").port();
    (socket, port)
}

#[derive(Default)]
struct QueryResult {
    done: bool,
    status: c_int,
}

unsafe extern "C" fn query_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    _abuf: *mut u8,
    _alen: c_int,
) {
    let result = unsafe { &mut *(arg as *mut QueryResult) };
    result.done = true;
    result.status = status;
}

fn pump(channel: Channel) {
    unsafe { ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD) };
}

unsafe fn start_query(channel: Channel, result: &mut QueryResult) {
    let name = CString::new("review.example").expect("name");
    unsafe {
        ares_query(
            channel,
            name.as_ptr(),
            c_int::from(ARES_CLASS_IN),
            c_int::from(ARES_REC_TYPE_A),
            Some(query_cb),
            result as *mut QueryResult as *mut c_void,
        )
    };
}

fn wait_ms(channel: Channel) -> u128 {
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    let ret = unsafe { ares_timeout(channel, ptr::null_mut(), &mut tv) };
    assert!(!ret.is_null(), "a pending query must have a timeout");
    tv.tv_sec as u128 * 1000 + tv.tv_usec as u128 / 1000
}

/// `timeout:0` must be ignored like upstream (the default 2000 ms remains),
/// not silently applied and floored to 250 ms.
#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn resolvconf_zero_timeout_uses_the_default() {
    let _serial = serial();
    let (_silent, port) = silent_server();
    let conf = TempConf::new(&format!(
        "nameserver 127.0.0.1:{port}\noptions timeout:0 attempts:1\n"
    ));
    let path = conf.cstring();

    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.resolvconf_path = path.as_ptr() as *mut c_char;
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(
            ares_init_options(&mut channel, &opts, ARES_OPT_RESOLVCONF),
            ARES_SUCCESS
        );

        let mut result = QueryResult::default();
        start_query(channel, &mut result);
        assert!(!result.done, "the silent server must not answer synchronously");
        let scheduled = wait_ms(channel);
        assert!(
            scheduled >= 1000,
            "timeout:0 must be ignored, leaving the 2000 ms default (got {scheduled} ms)"
        );

        ares_cancel(channel);
        ares_destroy(channel);
    }
}

/// `attempts:0` must be ignored like upstream (three attempts remain), not
/// collapse the query to a single send that times out at the first deadline.
#[test]
#[cfg_attr(miri, ignore = "real sockets: Miri cannot run socket syscalls")]
fn resolvconf_zero_attempts_still_retries() {
    let _serial = serial();
    let (_silent, port) = silent_server();
    let conf = TempConf::new(&format!(
        "nameserver 127.0.0.1:{port}\noptions timeout:1 attempts:0\n"
    ));
    let path = conf.cstring();

    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.resolvconf_path = path.as_ptr() as *mut c_char;
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(
            ares_init_options(&mut channel, &opts, ARES_OPT_RESOLVCONF),
            ARES_SUCCESS
        );

        let mut result = QueryResult::default();
        start_query(channel, &mut result);

        // The first 1 s attempt must time out, but a configured `attempts:3`
        // leaves the query pending for a retry instead of ending it.
        let deadline = Instant::now() + Duration::from_millis(1600);
        while Instant::now() < deadline && !result.done {
            pump(channel);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !result.done,
            "attempts:0 must be ignored; the query ended after one attempt (status {})",
            result.status
        );

        ares_cancel(channel);
        ares_destroy(channel);
    }
}

/// Child entry point for the overflow case: init from a resolv.conf containing
/// a value whose `* 1000` overflows `u32`, then require a normal default
/// schedule (not a panic, not a wrapped sub-second timeout).
#[cfg(not(miri))]
#[test]
fn resolvconf_timeout_overflow_case_child() {
    let Ok(value) = std::env::var(OVERFLOW_CASE_ENV) else {
        return;
    };
    assert_eq!(value, "1");
    let _serial = serial();

    let (_silent, port) = silent_server();
    let conf = TempConf::new(&format!(
        "nameserver 127.0.0.1:{port}\noptions timeout:4294968 attempts:1\n"
    ));
    let path = conf.cstring();

    unsafe {
        let mut opts: ares_options = std::mem::zeroed();
        opts.resolvconf_path = path.as_ptr() as *mut c_char;
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(
            ares_init_options(&mut channel, &opts, ARES_OPT_RESOLVCONF),
            ARES_SUCCESS,
            "overflowing timeout must not abort init"
        );

        let mut result = QueryResult::default();
        start_query(channel, &mut result);
        let scheduled = wait_ms(channel);
        assert!(
            scheduled >= 1000,
            "overflowing timeout must leave a sane default (got {scheduled} ms)"
        );

        ares_cancel(channel);
        ares_destroy(channel);
    }
}

/// Parent test: run the overflow case in a child so a debug-build arithmetic
/// panic is reported as a test failure instead of aborting the test runner.
#[cfg(not(miri))]
#[test]
fn resolvconf_timeout_overflow_does_not_abort() {
    let exe = std::env::current_exe().expect("test executable path");
    let output = Command::new(&exe)
        .args([
            "--exact",
            "resolvconf_timeout_overflow_case_child",
            "--test-threads",
            "1",
            "--nocapture",
        ])
        .env(OVERFLOW_CASE_ENV, "1")
        .env("RUST_BACKTRACE", "0")
        .output()
        .expect("spawn child test process");
    assert!(
        output.status.success(),
        "overflowing resolv.conf timeout aborted or failed:\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Legacy wire-name expansion (finding 03)
// ---------------------------------------------------------------------------

fn expand_label(label: &[u8]) -> (c_int, Vec<u8>) {
    let mut msg = vec![label.len() as u8];
    msg.extend_from_slice(label);
    msg.push(0);

    let mut out: *mut c_char = ptr::null_mut();
    let mut enclen: c_long = 0;
    let rc = unsafe {
        ares_expand_name(
            msg.as_ptr(),
            msg.as_ptr(),
            msg.len() as c_int,
            &mut out,
            &mut enclen,
        )
    };
    let bytes = if out.is_null() {
        Vec::new()
    } else {
        let bytes = unsafe { CStr::from_ptr(out) }.to_bytes().to_vec();
        unsafe { ares_free_string(out as *mut c_void) };
        bytes
    };
    (rc, bytes)
}

/// `ares_expand_name` is the legacy presentation formatter: reserved
/// characters get a backslash and non-printable bytes become `\DDD`.
#[test]
fn legacy_expand_name_escapes_like_c_ares() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"a.b\\c(d)e@f$g\"h", b"a\\.b\\\\c\\(d\\)e\\@f\\$g\\\"h"),
        (b"a;b\"c", b"a\\;b\\\"c"),
        (b"a\x01b", b"a\\001b"),
        ("aéb".as_bytes(), b"a\\195\\169b"),
        (b"a\x7fb", b"a\\127b"),
        (b"a\x80b", b"a\\128b"),
        (b"a\x00b", b"a\\000b"),
    ];
    for &(label, expected) in cases {
        let (rc, expanded) = expand_label(label);
        assert_eq!(rc, ARES_SUCCESS, "expand failed for {label:?}");
        assert_eq!(
            expanded, expected,
            "legacy expansion of {label:?} must match c-ares"
        );
    }
}

fn encode_wire_name(label: &[u8]) -> Vec<u8> {
    let mut out = vec![label.len() as u8];
    out.extend_from_slice(label);
    out.push(0);
    out
}

fn a_response(qname: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x1234u16.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&encode_wire_name(qname));
    out.extend_from_slice(&1u16.to_be_bytes()); // T_A
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    for answer in answers {
        out.extend_from_slice(answer);
    }
    out
}

fn a_rr() -> Vec<u8> {
    let mut out = vec![0xC0, 0x0C];
    out.extend_from_slice(&1u16.to_be_bytes()); // T_A
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&[1, 2, 3, 4]);
    out
}

fn cname_rr(target: &[u8]) -> Vec<u8> {
    let rdata = encode_wire_name(target);
    let mut out = vec![0xC0, 0x0C];
    out.extend_from_slice(&5u16.to_be_bytes()); // T_CNAME
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

unsafe fn parse_a_name(response: &[u8]) -> (c_int, Option<Vec<u8>>) {
    let mut host: *mut libc::hostent = ptr::null_mut();
    let rc = unsafe {
        ares_parse_a_reply(
            response.as_ptr(),
            response.len() as c_int,
            &mut host,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let name = if host.is_null() {
        None
    } else {
        let bytes = unsafe { (*host).h_name };
        let out = if bytes.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(bytes) }.to_bytes().to_vec())
        };
        unsafe { ares_free_hostent(host) };
        out
    };
    (rc, name)
}

/// The echoed question name is attacker-controlled.  A label with reserved,
/// control, non-UTF-8 and NUL bytes must parse successfully and be escaped,
/// not rejected as EBADRESP.
#[test]
fn legacy_parse_a_reply_escapes_question_name() {
    let qname = b"a;b\x01\x80\x00c";
    let response = a_response(qname, &[a_rr()]);
    let (rc, name) = unsafe { parse_a_name(&response) };
    assert_eq!(rc, ARES_SUCCESS, "legacy A parser must accept the wire name");
    assert_eq!(name.as_deref(), Some(&b"a\\;b\\001\\128\\000c"[..]));
}

/// CNAME targets go through the same legacy formatter (`build_cstring`); the
/// hostent `h_name` must escape reserved/control/UTF-8 bytes instead of
/// emitting them raw or mojibake.
#[test]
fn legacy_parse_a_reply_escapes_cname_target() {
    let response = a_response(b"q.example", &[cname_rr(b"a;b\x01\xc3\xa9c"), a_rr()]);
    let (rc, name) = unsafe { parse_a_name(&response) };
    assert_eq!(rc, ARES_SUCCESS, "legacy A parser must accept the CNAME");
    assert_eq!(name.as_deref(), Some(&b"a\\;b\\001\\195\\169c"[..]));
}

// ---------------------------------------------------------------------------
// Non-ASCII getaddrinfo (finding 04)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct AiResult {
    done: bool,
    status: c_int,
}

unsafe extern "C" fn ai_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    ai: *mut ares_addrinfo,
) {
    let result = unsafe { &mut *(arg as *mut AiResult) };
    result.done = true;
    result.status = status;
    if !ai.is_null() {
        unsafe { ares_freeaddrinfo(ai) };
    }
}

#[cfg(not(miri))]
#[test]
fn nonascii_getaddrinfo_case_child() {
    let Ok(value) = std::env::var(NONASCII_CASE_ENV) else {
        return;
    };
    assert_eq!(value, "1");
    let _serial = serial();

    unsafe {
        let mut channel: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut channel), ARES_SUCCESS);
        assert!(!channel.is_null());

        let name = CString::new("🚀🚀🚀").expect("name");
        let mut result = AiResult::default();
        ares_getaddrinfo(
            channel,
            name.as_ptr(),
            ptr::null(),
            ptr::null(),
            Some(ai_cb),
            &mut result as *mut AiResult as *mut c_void,
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        while !result.done && Instant::now() < deadline {
            pump(channel);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(result.done, "the addrinfo callback must fire");
        assert_eq!(
            result.status, ARES_EBADNAME,
            "a non-ASCII name must be rejected with ARES_EBADNAME, not crash"
        );

        ares_destroy(channel);
    }
}

/// `is_localhost` must not slice a `&str` at a non-UTF-8-boundary; a multibyte
/// name has to reach the normal error path instead of aborting the process.
#[cfg(not(miri))]
#[test]
fn nonascii_getaddrinfo_does_not_abort() {
    let exe = std::env::current_exe().expect("test executable path");
    let output = Command::new(&exe)
        .args([
            "--exact",
            "nonascii_getaddrinfo_case_child",
            "--test-threads",
            "1",
            "--nocapture",
        ])
        .env(NONASCII_CASE_ENV, "1")
        .env("RUST_BACKTRACE", "0")
        .output()
        .expect("spawn child test process");
    assert!(
        output.status.success(),
        "non-ASCII ares_getaddrinfo aborted or failed:\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
