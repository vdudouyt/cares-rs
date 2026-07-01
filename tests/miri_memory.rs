//! Comprehensive in-memory memory-safety suite, written to run under Miri
//! (`cargo +nightly miri test`) as well as normal `cargo test`.
//!
//! Everything here is hermetic: it builds DNS messages in memory and calls the
//! public parse / allocate / free entry points directly — no `ares_init`, no
//! files, no sockets, no syscalls. The goal is to exercise every alloc/free path
//! (hostent, `ares_data` linked lists, `libc::malloc`'d buffers, `ares_dns_record`)
//! on both success and error paths, so Miri flags use-after-free, out-of-bounds,
//! leaks, and allocator mismatches across the whole FFI surface.

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::ptr;

use cares_rs::ares_data::ares_free_data;
use cares_rs::dns_record::{
    ares_dns_parse, ares_dns_record_create, ares_dns_record_destroy, ares_dns_record_duplicate,
    ares_dns_record_query_add, ares_dns_record_rr_add, ares_dns_rr_set_addr, ares_dns_write,
    ARES_RR_A_ADDR, ARES_SECTION_ANSWER,
};
use cares_rs::*;

const ARES_SUCCESS: c_int = 0;
const AF_INET: c_int = libc::AF_INET;
const AF_INET6: c_int = libc::AF_INET6;

// DNS record types.
const T_A: u16 = 1;
const T_NS: u16 = 2;
const T_SOA: u16 = 6;
const T_PTR: u16 = 12;
const T_MX: u16 = 15;
const T_TXT: u16 = 16;
const T_AAAA: u16 = 28;
const T_SRV: u16 = 33;

// ---- in-memory DNS response builder ----

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root terminator
}

/// uncompressed name, as an rdata fragment.
fn name_bytes(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    encode_name(&mut v, name);
    v
}

/// One answer RR whose owner name is a compression pointer to the question
/// (always at offset 12, immediately after the fixed 12-byte header).
fn rr(rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut v = vec![0xC0, 0x0C]; // owner name -> question at offset 12
    v.extend_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // class IN
    v.extend_from_slice(&60u32.to_be_bytes()); // ttl
    v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

/// A complete DNS response message: header + one question + the answer RRs.
fn response(qname: &str, qtype: u16, answers: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    b.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: QR RD RA, rcode 0
    b.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    b.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ancount
    b.extend_from_slice(&0u16.to_be_bytes()); // nscount
    b.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_name(&mut b, qname);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    for a in answers {
        b.extend_from_slice(a);
    }
    b
}

// ---------- A / AAAA / NS / PTR -> hostent -> ares_free_hostent ----------

#[test]
fn parse_a_reply_single_and_free() {
    let buf = response("example.com", T_A, &[rr(T_A, &[93, 184, 216, 34])]);
    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        let rc =
            ares_parse_a_reply(buf.as_ptr(), buf.len() as c_int, &mut he, ptr::null_mut(), ptr::null_mut());
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!he.is_null());
        ares_free_hostent(he);
    }
}

#[test]
fn parse_a_reply_multi_with_addrttls_and_free() {
    let buf = response("example.com", T_A, &[rr(T_A, &[10, 0, 0, 1]), rr(T_A, &[10, 0, 0, 2])]);
    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        let mut ttls: [ares_addrttl; 4] = std::mem::zeroed();
        let mut n: c_int = 4;
        let rc = ares_parse_a_reply(buf.as_ptr(), buf.len() as c_int, &mut he, ttls.as_mut_ptr(), &mut n);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!he.is_null());
        assert_eq!(n, 2, "both A records reported in the addrttl out-array");
        ares_free_hostent(he);
    }
}

#[test]
fn parse_aaaa_reply_and_free() {
    let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // 2001:db8::1
    let buf = response("example.com", T_AAAA, &[rr(T_AAAA, &v6)]);
    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        let rc = ares_parse_aaaa_reply(
            buf.as_ptr(),
            buf.len() as c_int,
            &mut he,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!he.is_null());
        ares_free_hostent(he);
    }
}

#[test]
fn parse_ns_reply_and_free() {
    let buf = response("example.com", T_NS, &[rr(T_NS, &name_bytes("ns1.example.com"))]);
    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        let rc = ares_parse_ns_reply(buf.as_ptr(), buf.len() as c_int, &mut he);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!he.is_null());
        ares_free_hostent(he);
    }
}

#[test]
fn parse_ptr_reply_and_free() {
    let buf = response("1.0.0.127.in-addr.arpa", T_PTR, &[rr(T_PTR, &name_bytes("host.example.com"))]);
    let addr: [u8; 4] = [127, 0, 0, 1];
    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        let rc = ares_parse_ptr_reply(
            buf.as_ptr(),
            buf.len() as c_int,
            addr.as_ptr() as *const c_void,
            4,
            AF_INET,
            &mut he,
        );
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!he.is_null());
        ares_free_hostent(he);
    }
}

// ---------- ares_data linked lists -> ares_free_data ----------

#[test]
fn parse_txt_reply_and_free() {
    let rdata = [0x05u8, b'h', b'e', b'l', b'l', b'o']; // one char-string "hello"
    let buf = response("example.com", T_TXT, &[rr(T_TXT, &rdata)]);
    unsafe {
        let mut out: *mut c_void = ptr::null_mut();
        let rc = ares_parse_txt_reply(buf.as_ptr(), buf.len() as c_int, &mut out as *mut _ as *mut *mut _);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!out.is_null());
        ares_free_data(out); // exercises the NUL-terminated TXT Drop chain
    }
}

#[test]
fn parse_mx_reply_and_free() {
    let mut rdata = vec![0x00u8, 0x0A]; // preference 10
    rdata.extend(name_bytes("mail.example.com"));
    let buf = response("example.com", T_MX, &[rr(T_MX, &rdata)]);
    unsafe {
        let mut out: *mut c_void = ptr::null_mut();
        let rc = ares_parse_mx_reply(buf.as_ptr(), buf.len() as c_int, &mut out as *mut _ as *mut *mut _);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!out.is_null());
        ares_free_data(out);
    }
}

#[test]
fn parse_srv_reply_and_free() {
    let mut rdata = vec![0x00u8, 0x0A, 0x00, 0x05, 0x00, 0x50]; // prio 10, weight 5, port 80
    rdata.extend(name_bytes("srv.example.com"));
    let buf = response("example.com", T_SRV, &[rr(T_SRV, &rdata)]);
    unsafe {
        let mut out: *mut c_void = ptr::null_mut();
        let rc = ares_parse_srv_reply(buf.as_ptr(), buf.len() as c_int, &mut out as *mut _ as *mut *mut _);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!out.is_null());
        ares_free_data(out);
    }
}

#[test]
fn parse_soa_reply_and_free() {
    let mut rdata = Vec::new();
    rdata.extend(name_bytes("ns1.example.com")); // mname
    rdata.extend(name_bytes("hostmaster.example.com")); // rname
    rdata.extend_from_slice(&1u32.to_be_bytes()); // serial
    rdata.extend_from_slice(&3600u32.to_be_bytes()); // refresh
    rdata.extend_from_slice(&600u32.to_be_bytes()); // retry
    rdata.extend_from_slice(&86400u32.to_be_bytes()); // expire
    rdata.extend_from_slice(&60u32.to_be_bytes()); // minimum
    let buf = response("example.com", T_SOA, &[rr(T_SOA, &rdata)]);
    unsafe {
        let mut out: *mut c_void = ptr::null_mut();
        let rc = ares_parse_soa_reply(buf.as_ptr(), buf.len() as c_int, &mut out as *mut _ as *mut *mut _);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!out.is_null());
        ares_free_data(out);
    }
}

// ---------- ares_dns_record create -> write(malloc) -> parse -> duplicate -> free ----------

#[test]
fn dns_record_create_write_parse_duplicate_free() {
    unsafe {
        let mut rec = ptr::null_mut();
        assert_eq!(ares_dns_record_create(&mut rec, 0x1234, 0, 0, 0), ARES_SUCCESS);
        assert!(!rec.is_null());

        let qname = CString::new("example.com").unwrap();
        assert_eq!(ares_dns_record_query_add(rec, qname.as_ptr(), T_A as u32, 1), ARES_SUCCESS);

        let mut rr_ptr = ptr::null_mut();
        assert_eq!(
            ares_dns_record_rr_add(&mut rr_ptr, rec, ARES_SECTION_ANSWER, qname.as_ptr(), T_A as u32, 1, 60),
            ARES_SUCCESS
        );
        let addr = libc::in_addr { s_addr: u32::from_ne_bytes([93, 184, 216, 34]) };
        assert_eq!(ares_dns_rr_set_addr(rr_ptr, ARES_RR_A_ADDR, &addr), ARES_SUCCESS);

        // write -> libc::malloc'd wire buffer
        let mut buf: *mut u8 = ptr::null_mut();
        let mut buflen: libc::size_t = 0;
        assert_eq!(ares_dns_write(rec, &mut buf, &mut buflen), ARES_SUCCESS);
        assert!(!buf.is_null() && buflen > 12);

        // parse it back into a fresh record
        let mut rec2 = ptr::null_mut();
        assert_eq!(ares_dns_parse(buf, buflen, 0, &mut rec2), ARES_SUCCESS);
        assert!(!rec2.is_null());

        // deep duplicate
        let rec3 = ares_dns_record_duplicate(rec);
        assert!(!rec3.is_null());

        ares_dns_record_destroy(rec3);
        ares_dns_record_destroy(rec2);
        ares_dns_record_destroy(rec);
        ares_free_string(buf as *mut c_void); // libc::free of the libc::malloc'd buffer
    }
}

// ---------- expand_name / inet helpers ----------

#[test]
fn expand_name_and_free() {
    let mut msg = vec![0u8; 12]; // 12-byte header padding, name starts at offset 12
    encode_name(&mut msg, "ab.cd");
    unsafe {
        let mut s: *mut c_char = ptr::null_mut();
        let mut enclen: c_long = 0;
        let rc =
            ares_expand_name(msg.as_ptr().add(12), msg.as_ptr(), msg.len() as c_int, &mut s, &mut enclen);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!s.is_null());
        assert_eq!(CStr::from_ptr(s).to_str().unwrap(), "ab.cd");
        ares_free_string(s as *mut c_void);
    }
}

#[test]
fn inet_pton_ntop_roundtrip() {
    unsafe {
        // IPv4
        let src = CString::new("127.0.0.1").unwrap();
        let mut v4 = [0u8; 4];
        assert_eq!(ares_inet_pton(AF_INET, src.as_ptr(), v4.as_mut_ptr() as *mut c_void), 1);
        assert_eq!(v4, [127, 0, 0, 1]);
        let mut out = [0 as c_char; 64];
        let p = ares_inet_ntop(
            AF_INET,
            v4.as_ptr() as *const c_void,
            out.as_mut_ptr(),
            out.len() as libc::socklen_t,
        );
        assert!(!p.is_null());
        assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "127.0.0.1");

        // IPv6
        let src6 = CString::new("2001:db8::1").unwrap();
        let mut v6 = [0u8; 16];
        assert_eq!(ares_inet_pton(AF_INET6, src6.as_ptr(), v6.as_mut_ptr() as *mut c_void), 1);
        let mut out6 = [0 as c_char; 64];
        let p6 = ares_inet_ntop(
            AF_INET6,
            v6.as_ptr() as *const c_void,
            out6.as_mut_ptr(),
            out6.len() as libc::socklen_t,
        );
        assert!(!p6.is_null());
        assert_eq!(CStr::from_ptr(out6.as_ptr()).to_str().unwrap(), "2001:db8::1");
    }
}

// ---------- adversarial: every parser must error cleanly with no allocation ----------

#[test]
fn truncated_replies_error_cleanly_no_leak() {
    // Header claims qdcount=1/ancount=1 but the message is truncated right after.
    // Every parser must return an error and allocate nothing (Miri: no leak/UB).
    let short = [0x12u8, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0x00];
    unsafe {
        let mut he: *mut libc::hostent = ptr::null_mut();
        assert_ne!(
            ares_parse_a_reply(short.as_ptr(), short.len() as c_int, &mut he, ptr::null_mut(), ptr::null_mut()),
            ARES_SUCCESS
        );
        assert!(he.is_null());
        he = ptr::null_mut();
        assert_ne!(
            ares_parse_aaaa_reply(short.as_ptr(), short.len() as c_int, &mut he, ptr::null_mut(), ptr::null_mut()),
            ARES_SUCCESS
        );
        assert!(he.is_null());
        he = ptr::null_mut();
        assert_ne!(ares_parse_ns_reply(short.as_ptr(), short.len() as c_int, &mut he), ARES_SUCCESS);
        assert!(he.is_null());

        let mut out: *mut c_void = ptr::null_mut();
        for rc in [
            ares_parse_mx_reply(short.as_ptr(), short.len() as c_int, &mut out as *mut _ as *mut *mut _),
            ares_parse_txt_reply(short.as_ptr(), short.len() as c_int, &mut out as *mut _ as *mut *mut _),
            ares_parse_srv_reply(short.as_ptr(), short.len() as c_int, &mut out as *mut _ as *mut *mut _),
            ares_parse_soa_reply(short.as_ptr(), short.len() as c_int, &mut out as *mut _ as *mut *mut _),
            ares_parse_naptr_reply(short.as_ptr(), short.len() as c_int, &mut out as *mut _ as *mut *mut _),
            ares_parse_caa_reply(short.as_ptr(), short.len() as c_int, &mut out as *mut _ as *mut *mut _),
            ares_parse_uri_reply(short.as_ptr(), short.len() as c_int, &mut out as *mut _ as *mut *mut _),
        ] {
            assert_ne!(rc, ARES_SUCCESS);
            assert!(out.is_null());
        }
    }
}
