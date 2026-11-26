//! Upstream legacy-API contracts: getnameinfo argument-error codes,
//! inet_pton's errno contract, and the hostent metadata that the PTR/NS
//! parsers must synthesize even when no address records are present.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::ptr;

use cares::*;

const ARES_SUCCESS: c_int = 0;
const ARES_ENOTIMP: c_int = 5;

// ---------------------------------------------------------------------------
// DNS message helpers (mirrors tests/miri_memory.rs; kept local so this file
// stays self-contained).
// ---------------------------------------------------------------------------

const T_NS: u16 = 2;
const T_PTR: u16 = 12;

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn name_bytes(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    encode_name(&mut v, name);
    v
}

/// Answer RR whose owner name points to the question at offset 12.
fn rr(rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut v = vec![0xC0, 0x0C];
    v.extend_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&60u32.to_be_bytes());
    v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

fn response(qname: &str, qtype: u16, answers: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x1234u16.to_be_bytes());
    b.extend_from_slice(&0x8180u16.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&mut b, qname);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    for a in answers {
        b.extend_from_slice(a);
    }
    b
}

// ---------------------------------------------------------------------------
// 1. ares_getnameinfo: bad sockaddr inputs report ARES_ENOTIMP (upstream),
//    not ARES_ENOMEM.
// ---------------------------------------------------------------------------

struct NameInfoResult {
    fired: bool,
    status: c_int,
}

unsafe extern "C" fn nameinfo_cb(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    _node: *mut c_char,
    _service: *mut c_char,
) {
    let r = &mut *(arg as *mut NameInfoResult);
    r.fired = true;
    r.status = status;
}

#[test]
fn getnameinfo_null_sockaddr_reports_enotimp() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        assert!(!ch.is_null());

        let mut result = NameInfoResult { fired: false, status: -1 };
        ares_getnameinfo(
            ch,
            ptr::null(),
            0,
            0,
            Some(nameinfo_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.fired, "callback must fire synchronously on a NULL sockaddr");
        assert_eq!(
            result.status, ARES_ENOTIMP,
            "NULL sockaddr must map to ARES_ENOTIMP (upstream), not ARES_ENOMEM"
        );

        ares_destroy(ch);
    }
}

#[test]
fn getnameinfo_short_salen_reports_enotimp() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);

        // Full-size storage so reading sa_family is safe; salen is deliberately
        // too small for a sockaddr_in.
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        storage.ss_family = libc::AF_INET as libc::sa_family_t;
        let sa = &storage as *const libc::sockaddr_storage as *const libc::sockaddr;

        let mut result = NameInfoResult { fired: false, status: -1 };
        ares_getnameinfo(
            ch,
            sa,
            1,
            0,
            Some(nameinfo_cb),
            &mut result as *mut _ as *mut c_void,
        );
        assert!(result.fired, "callback must fire synchronously on a short salen");
        assert_eq!(
            result.status, ARES_ENOTIMP,
            "salen shorter than sizeof(sockaddr_in) must map to ARES_ENOTIMP"
        );

        ares_destroy(ch);
    }
}

// ---------------------------------------------------------------------------
// 2. ares_inet_pton: unsupported family must return -1 *and* set errno.
// ---------------------------------------------------------------------------

#[test]
fn inet_pton_unsupported_family_sets_errno() {
    unsafe {
        let src = std::ffi::CString::new("127.0.0.1").unwrap();
        let mut dst = [0u8; 16];

        *libc::__errno_location() = 0;
        let rc = ares_inet_pton(9999, src.as_ptr(), dst.as_mut_ptr() as *mut c_void);
        let errno = *libc::__errno_location();

        assert_eq!(rc, -1, "unsupported family must return -1");
        assert_ne!(
            errno, 0,
            "unsupported family must set errno (upstream sets EAFNOSUPPORT)"
        );
        // Stock Linux inet_pton / c-ares use EAFNOSUPPORT here.
        assert_eq!(
            errno,
            libc::EAFNOSUPPORT,
            "expected EAFNOSUPPORT for an unsupported address family"
        );
    }
}

#[test]
fn inet_pton_inet_family_still_succeeds() {
    unsafe {
        let src = std::ffi::CString::new("127.0.0.1").unwrap();
        let mut dst = [0u8; 4];
        *libc::__errno_location() = 0;
        assert_eq!(
            ares_inet_pton(libc::AF_INET, src.as_ptr(), dst.as_mut_ptr() as *mut c_void),
            1
        );
        assert_eq!(dst, [127, 0, 0, 1]);
    }
}

// ---------------------------------------------------------------------------
// 3. ares_parse_ptr_reply: hostent addrtype/length/address are filled from the
//    (addr, addrlen, family) arguments, independently of the reply contents.
// ---------------------------------------------------------------------------

#[test]
fn parse_ptr_reply_fills_addr_fields_for_af_unspec() {
    let buf = response(
        "1.0.0.127.in-addr.arpa",
        T_PTR,
        &[rr(T_PTR, &name_bytes("host.example.com"))],
    );
    let addr: [u8; 4] = [127, 0, 0, 1];

    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        let rc = ares_parse_ptr_reply(
            buf.as_ptr(),
            buf.len() as c_int,
            addr.as_ptr() as *const c_void,
            4,
            libc::AF_UNSPEC,
            &mut he,
        );
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!he.is_null());

        let host = &*he;
        assert_eq!(
            host.h_addrtype,
            libc::AF_UNSPEC,
            "h_addrtype must be the caller's family, even when it is AF_UNSPEC"
        );
        assert_eq!(
            host.h_length, 4,
            "h_length must be the caller's addrlen, not 0 for AF_UNSPEC"
        );
        assert!(!host.h_addr_list.is_null(), "h_addr_list must be allocated");
        let first = *host.h_addr_list;
        assert!(
            !first.is_null(),
            "the supplied address must survive into h_addr_list[0]"
        );
        let copied = std::slice::from_raw_parts(first as *const u8, 4);
        assert_eq!(copied, &addr);
        assert!(
            (*host.h_addr_list.add(1)).is_null(),
            "h_addr_list must be NULL-terminated"
        );

        ares_free_hostent(he);
    }
}

// ---------------------------------------------------------------------------
// 4. ares_parse_ns_reply: upstream synthesizes an IPv4-shaped, empty address
//    list even though NS answers carry no address records.
// ---------------------------------------------------------------------------

#[test]
fn parse_ns_reply_sets_ipv4_metadata_and_empty_addr_list() {
    let buf = response(
        "example.com",
        T_NS,
        &[rr(T_NS, &name_bytes("ns1.example.com"))],
    );

    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        let rc = ares_parse_ns_reply(buf.as_ptr(), buf.len() as c_int, &mut he);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!he.is_null());

        let host = &*he;
        assert_eq!(
            host.h_addrtype,
            libc::AF_INET,
            "upstream reports AF_INET for an NS reply"
        );
        assert_eq!(
            host.h_length, 4,
            "upstream reports sizeof(struct in_addr) for an NS reply"
        );
        assert!(!host.h_addr_list.is_null(), "h_addr_list must be allocated");
        assert!(
            (*host.h_addr_list).is_null(),
            "NS replies have no addresses, so h_addr_list must be empty"
        );
        assert_eq!(
            CStr::from_ptr(host.h_name).to_str().unwrap(),
            "example.com"
        );

        ares_free_hostent(he);
    }
}

// 5. ares_search callback locking (audit item 11): not observable from the C
//    API without an injection hook. Deliberately left untested here to avoid a
//    flaky/racy test; the fix is reviewed by code inspection.
