//! One test/process: allocation callbacks are library-wide, so fault injection
//! must not race unrelated tests initializing or using the library.
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use cares::dns_record::*;
use cares::error::ARES_ENOMEM;
use cares::{ares_library_cleanup, ares_library_init_mem, ARES_SUCCESS};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static FAIL: AtomicUsize = AtomicUsize::new(usize::MAX);
static PERSISTENT: AtomicBool = AtomicBool::new(false);

fn failing() -> bool {
    let n = CALLS.fetch_add(1, SeqCst);
    n == FAIL.load(SeqCst) || (PERSISTENT.load(SeqCst) && n > FAIL.load(SeqCst))
}
unsafe extern "C" fn allocate(size: usize) -> *mut c_void {
    if failing() { return ptr::null_mut(); }
    let p = unsafe { libc::malloc(size) };
    if !p.is_null() { LIVE.fetch_add(1, SeqCst); }
    p
}
unsafe extern "C" fn release(p: *mut c_void) {
    if !p.is_null() { LIVE.fetch_sub(1, SeqCst); }
    unsafe { libc::free(p) };
}
unsafe extern "C" fn resize(p: *mut c_void, size: usize) -> *mut c_void {
    if failing() { return ptr::null_mut(); }
    let out = unsafe { libc::realloc(p, size) };
    if p.is_null() && !out.is_null() { LIVE.fetch_add(1, SeqCst); }
    out
}

fn arm(n: usize, persistent: bool) {
    CALLS.store(0, SeqCst);
    FAIL.store(n, SeqCst);
    PERSISTENT.store(persistent, SeqCst);
}

#[test]
fn dns_record_ownership_and_exhaustive_allocation_failures() {
    assert_eq!(ares_library_init_mem(0, Some(allocate), Some(release), Some(resize)), ARES_SUCCESS);
    // A question and a TXT answer with two character-strings. Compression,
    // owned names, field storage, binary arrays and buffer growth are exercised.
    let wire = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01a\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x08\x03one\x03two";

    for persistent in [false, true] {
        for fail in 0..256 {
            arm(fail, persistent);
            let mut rec = ptr::dangling_mut();
            let status = unsafe { ares_dns_parse(wire.as_ptr(), wire.len(), 0, &mut rec) };
            if status == ARES_SUCCESS {
                unsafe { ares_dns_record_destroy(rec) };
                assert_eq!(LIVE.load(SeqCst), 0, "parse success leaked");
                break;
            }
            assert_eq!(status, ARES_ENOMEM, "parse allocation {fail}");
            assert!(rec.is_null());
            assert_eq!(LIVE.load(SeqCst), 0, "parse allocation {fail} leaked");
            assert!(fail < 255, "parse never succeeded");
        }

        arm(usize::MAX, false);
        let mut rec = ptr::null_mut();
        assert_eq!(unsafe { ares_dns_parse(wire.as_ptr(), wire.len(), 0, &mut rec) }, ARES_SUCCESS);
        let baseline = LIVE.load(SeqCst);
        assert!(baseline > 0, "record allocations must use the callbacks");
        for fail in 0..256 {
            arm(fail, persistent);
            let mut out = ptr::dangling_mut();
            let mut len = usize::MAX;
            let status = unsafe { ares_dns_write(rec, &mut out, &mut len) };
            if status == ARES_SUCCESS {
                assert!(!out.is_null());
                unsafe { ares_free(out.cast()) };
                assert_eq!(LIVE.load(SeqCst), baseline);
                break;
            }
            assert_eq!(status, ARES_ENOMEM, "write allocation {fail}");
            assert!(out.is_null());
            assert_eq!(len, 0);
            assert_eq!(LIVE.load(SeqCst), baseline, "write allocation {fail} leaked");
            assert!(fail < 255, "write never succeeded");
        }
        for fail in 0..256 {
            arm(fail, persistent);
            let copy = unsafe { ares_dns_record_duplicate(rec) };
            let succeeded = !copy.is_null();
            unsafe { ares_dns_record_destroy(copy) };
            assert_eq!(LIVE.load(SeqCst), baseline, "duplicate allocation {fail} leaked");
            if succeeded { break; }
            assert!(fail < 255, "duplicate never succeeded");
        }
        // Destruction must succeed even while every allocation is failing.
        arm(0, true);
        unsafe { ares_dns_record_destroy(rec) };
        assert_eq!(CALLS.load(SeqCst), 0, "destruction allocated");
        assert_eq!(LIVE.load(SeqCst), 0);
    }

    arm(0, true);
    let mut rec = ptr::dangling_mut();
    assert_eq!(unsafe { ares_dns_record_create(&mut rec, 0, 0, 0, 0) }, ARES_ENOMEM);
    assert!(rec.is_null());
    assert_eq!(LIVE.load(SeqCst), 0);

    arm(usize::MAX, false);
    assert_eq!(unsafe { ares_dns_parse(wire.as_ptr(), wire.len(), 0, &mut rec) }, ARES_SUCCESS);
    // Allocation identity survives cleanup restoring the default callbacks.
    ares_library_cleanup();
    unsafe { ares_dns_record_destroy(rec) };
    assert_eq!(LIVE.load(SeqCst), 0, "destroy must reclaim the transferred Box and its fields");
}
