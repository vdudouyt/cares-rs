//! C ↔ Rust marshaling helpers shared by the FFI shims.
//!
//! Every helper preserves the exact per-site semantics the inlined idioms had:
//! `cstr_lossy` is the historical `.to_str().unwrap_or("")` (invalid UTF-8 →
//! empty string, deliberately no NULL check where callers had none), while
//! `cstr_opt` is for call sites that map invalid UTF-8 to their own error code.

use super::*;

/// C string → `&str`, mapping invalid UTF-8 to `""`.
///
/// # Safety
/// `p` must be a valid NUL-terminated C string (no NULL check — some public
/// entry points deliberately accept the crash-on-NULL contract of upstream).
pub(crate) unsafe fn cstr_lossy<'a>(p: *const c_char) -> &'a str {
    unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
}

/// C string → `Some(&str)`, `None` on invalid UTF-8 (caller picks the error code).
///
/// # Safety
/// `p` must be a valid NUL-terminated C string.
pub(crate) unsafe fn cstr_opt<'a>(p: *const c_char) -> Option<&'a str> {
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

/// Copy `bytes` into a fresh `libc::malloc` buffer with a NUL terminator
/// (callers hand these to C to be released via `ares_free_string`/`ares_free`).
///
/// # Safety
/// Only that the returned pointer is either NULL or a heap C string the caller
/// must free with `libc::free`.
pub(crate) unsafe fn malloc_cstr(bytes: &[u8]) -> *mut c_char {
    let len = bytes.len();
    let p = unsafe { libc::malloc(len + 1) as *mut u8 };
    if p.is_null() { return std::ptr::null_mut(); }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, len) };
    unsafe { *p.add(len) = 0 }; // NUL terminator
    p as *mut c_char
}

/// Copy `bytes` into a fresh `libc::malloc` buffer with no NUL terminator —
/// the length travels separately (callers hand these to C to be released via
/// `ares_free`/`ares_free_string`).
///
/// # Safety
/// Only that the returned pointer is either NULL or a heap buffer of
/// `bytes.len()` the caller must free with `libc::free`.
pub(crate) unsafe fn malloc_bytes(bytes: &[u8]) -> *mut u8 {
    let len = bytes.len();
    let p = unsafe { libc::malloc(len) as *mut u8 };
    if p.is_null() { return std::ptr::null_mut(); }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, len) };
    p
}

/// Run `f` and store its result through the C out-pointer (NULL out → ENOMEM).
///
/// # Safety
/// `out` must be NULL or valid for a single pointer write.
pub(crate) unsafe fn ares_fn_wrapper<T, F>(out: *mut *mut T, f: F) -> c_int
where F: FnOnce() -> Result<*mut T, c_int>
{
    if out.is_null() {
        return ARES_ENOMEM;
    }
    match f() {
        Ok(res) => {
            unsafe { *out = res };
            ARES_SUCCESS
        },
        Err(err) => err,
    }
}

use crate::core::preflight::AddrInfo;

/// Validate + decode a caller-supplied `sockaddr`/`salen` pair.
/// Error codes match upstream getnameinfo: NULL/short → ENOMEM, unknown
/// family → ENOTIMP.
pub(crate) fn extract_addr_port(sa: *const libc::sockaddr, salen: libc::socklen_t) -> Result<AddrInfo, c_int> {
    if sa.is_null() {
        return Err(ARES_ENOMEM);
    }

    let family = unsafe { (*sa).sa_family as c_int };

    match family {
        libc::AF_INET => {
            if (salen as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(ARES_ENOMEM);
            }
            let sa_in = sa as *const libc::sockaddr_in;
            let addr_bytes = unsafe { (*sa_in).sin_addr.s_addr.to_ne_bytes() };
            let ip = IpAddr::from(addr_bytes);
            let port = unsafe { u16::from_be((*sa_in).sin_port) };
            Ok(AddrInfo { ip, port, scope_id: 0 })
        }
        libc::AF_INET6 => {
            if (salen as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(ARES_ENOMEM);
            }
            let sa_in6 = sa as *const libc::sockaddr_in6;
            let addr_bytes = unsafe { (*sa_in6).sin6_addr.s6_addr };
            let ip = IpAddr::from(addr_bytes);
            let port = unsafe { u16::from_be((*sa_in6).sin6_port) };
            let scope_id = unsafe { (*sa_in6).sin6_scope_id };
            Ok(AddrInfo { ip, port, scope_id })
        }
        _ => Err(ARES_ENOTIMP),
    }
}
