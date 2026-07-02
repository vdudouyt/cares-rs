//! Comprehensive in-memory memory-safety suite, written to run under Miri
//! (`cargo +nightly miri test`) as well as normal `cargo test`.
//!
//! Everything here is hermetic: it builds DNS messages in memory and calls the
//! public parse / allocate / free entry points directly — no `ares_init`, no
//! files, no sockets, no syscalls. The goal is to exercise every alloc/free path
//! (hostent, `ares_data` linked lists, `libc::malloc`'d buffers, `ares_dns_record`)
//! on both success and error paths, so Miri flags use-after-free, out-of-bounds,
//! leaks, and allocator mismatches across the whole FFI surface.

use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr, CString};
use std::ptr;

use cares_rs::ares_free_data;
use cares_rs::ares_data::AresAddrPortNode;
use cares_rs::{ares_destroy_options, ares_save_options};
use cares_rs::ares_options::ares_options;
use cares_rs::ares_set_socket_functions_ex;
use cares_rs::*;
use cares_rs::dns_record::*;
use cares_rs::ares_strerror;

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

// ---------- dns_record get/set accessor matrix (all datatypes) ----------

#[test]
fn dns_record_accessors_roundtrip() {
    const T_CAA: u16 = 257;
    const T_OPT: u16 = 41;
    unsafe {
        let mut rec = ptr::null_mut();
        assert_eq!(ares_dns_record_create(&mut rec, 0x1234, 0, 0, 0), ARES_SUCCESS);

        let apex = CString::new("example.com").unwrap();
        assert_eq!(ares_dns_record_query_add(rec, apex.as_ptr(), T_A as u32, 1), ARES_SUCCESS);

        // Add one RR per datatype family and set its fields.
        let mut rr_a = ptr::null_mut();
        assert_eq!(ares_dns_record_rr_add(&mut rr_a, rec, ARES_SECTION_ANSWER, apex.as_ptr(), T_A as u32, 1, 300), ARES_SUCCESS);
        let a4 = libc::in_addr { s_addr: u32::from_ne_bytes([10, 0, 0, 7]) };
        assert_eq!(ares_dns_rr_set_addr(rr_a, ARES_RR_A_ADDR, &a4), ARES_SUCCESS);

        let mut rr_aaaa = ptr::null_mut();
        assert_eq!(ares_dns_record_rr_add(&mut rr_aaaa, rec, ARES_SECTION_ANSWER, apex.as_ptr(), T_AAAA as u32, 1, 300), ARES_SUCCESS);
        let v6 = [0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        assert_eq!(ares_dns_rr_set_addr6(rr_aaaa, ARES_RR_AAAA_ADDR, v6.as_ptr() as *const _), ARES_SUCCESS);

        let mut rr_mx = ptr::null_mut();
        assert_eq!(ares_dns_record_rr_add(&mut rr_mx, rec, ARES_SECTION_ANSWER, apex.as_ptr(), T_MX as u32, 1, 300), ARES_SUCCESS);
        let mx_ex = CString::new("mail.example.com").unwrap();
        assert_eq!(ares_dns_rr_set_u16(rr_mx, ARES_RR_MX_PREFERENCE, 10), ARES_SUCCESS);
        assert_eq!(ares_dns_rr_set_str(rr_mx, ARES_RR_MX_EXCHANGE, mx_ex.as_ptr()), ARES_SUCCESS);

        let mut rr_soa = ptr::null_mut();
        assert_eq!(ares_dns_record_rr_add(&mut rr_soa, rec, ARES_SECTION_ANSWER, apex.as_ptr(), T_SOA as u32, 1, 300), ARES_SUCCESS);
        let mname = CString::new("ns1.example.com").unwrap();
        assert_eq!(ares_dns_rr_set_u32(rr_soa, ARES_RR_SOA_SERIAL, 2024), ARES_SUCCESS);
        assert_eq!(ares_dns_rr_set_str(rr_soa, ARES_RR_SOA_MNAME, mname.as_ptr()), ARES_SUCCESS);

        let mut rr_caa = ptr::null_mut();
        assert_eq!(ares_dns_record_rr_add(&mut rr_caa, rec, ARES_SECTION_ANSWER, apex.as_ptr(), T_CAA as u32, 1, 300), ARES_SUCCESS);
        let tag = CString::new("issue").unwrap();
        assert_eq!(ares_dns_rr_set_u8(rr_caa, ARES_RR_CAA_CRITICAL, 128), ARES_SUCCESS);
        assert_eq!(ares_dns_rr_set_str(rr_caa, ARES_RR_CAA_TAG, tag.as_ptr()), ARES_SUCCESS);
        let caa_val = b"ca.example.com";
        assert_eq!(ares_dns_rr_set_bin(rr_caa, ARES_RR_CAA_VALUE, caa_val.as_ptr(), caa_val.len()), ARES_SUCCESS);

        let mut rr_txt = ptr::null_mut();
        assert_eq!(ares_dns_record_rr_add(&mut rr_txt, rec, ARES_SECTION_ANSWER, apex.as_ptr(), T_TXT as u32, 1, 300), ARES_SUCCESS);
        let txt = b"hello";
        assert_eq!(ares_dns_rr_set_bin(rr_txt, ARES_RR_TXT_DATA, txt.as_ptr(), txt.len()), ARES_SUCCESS);

        let mut rr_opt = ptr::null_mut();
        assert_eq!(ares_dns_record_rr_add(&mut rr_opt, rec, ARES_SECTION_ANSWER, apex.as_ptr(), T_OPT as u32, 1232, 0), ARES_SUCCESS);
        let optval = b"optdata";
        assert_eq!(ares_dns_rr_set_opt(rr_opt, ARES_RR_OPT_OPTIONS, 5, optval.as_ptr(), optval.len()), ARES_SUCCESS);

        // rr_add grows the record's internal RR array, which can reallocate and
        // invalidate earlier rr pointers (same as upstream c-ares's ares_array), so
        // re-fetch each RR by index before reading.
        let rr_a = ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 0);
        let rr_aaaa = ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 1);
        let rr_mx = ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 2);
        let rr_soa = ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 3);
        let rr_caa = ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 4);
        let rr_txt = ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 5);
        let rr_opt = ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 6);

        // Getters return borrowed pointers into the record (no freeing).
        assert!(!ares_dns_rr_get_addr(rr_a, ARES_RR_A_ADDR).is_null());
        assert!(!ares_dns_rr_get_addr6(rr_aaaa, ARES_RR_AAAA_ADDR).is_null());
        assert_eq!(ares_dns_rr_get_u16(rr_mx, ARES_RR_MX_PREFERENCE), 10);
        assert_eq!(CStr::from_ptr(ares_dns_rr_get_str(rr_mx, ARES_RR_MX_EXCHANGE)).to_str().unwrap(), "mail.example.com");
        assert_eq!(ares_dns_rr_get_u32(rr_soa, ARES_RR_SOA_SERIAL), 2024);
        assert_eq!(ares_dns_rr_get_u8(rr_caa, ARES_RR_CAA_CRITICAL), 128);
        let mut blen: libc::size_t = 0;
        assert!(!ares_dns_rr_get_bin(rr_caa, ARES_RR_CAA_VALUE, &mut blen).is_null());
        assert!(!ares_dns_rr_get_bin(rr_txt, ARES_RR_TXT_DATA, &mut blen).is_null());
        if ares_dns_rr_get_abin_cnt(rr_txt, ARES_RR_TXT_DATA) > 0 {
            let mut alen: libc::size_t = 0;
            assert!(!ares_dns_rr_get_abin(rr_txt, ARES_RR_TXT_DATA, 0, &mut alen).is_null());
        }
        assert!(ares_dns_rr_get_opt_cnt(rr_opt, ARES_RR_OPT_OPTIONS) >= 1);
        let mut optid: c_uint = 0;
        let mut oval: *const u8 = ptr::null();
        let mut olen: libc::size_t = 0;
        let _ = ares_dns_rr_get_opt(rr_opt, ARES_RR_OPT_OPTIONS, 0, &mut optid, &mut oval, &mut olen);
        let _ = ares_dns_rr_get_opt_byid(rr_opt, ARES_RR_OPT_OPTIONS, 5, &mut oval, &mut olen);
        let _ = ares_dns_rr_del_opt_byid(rr_opt, ARES_RR_OPT_OPTIONS, 5);

        // Common per-RR getters.
        for &rr in &[rr_a, rr_aaaa, rr_mx, rr_soa, rr_caa, rr_txt, rr_opt] {
            assert!(!ares_dns_rr_get_name(rr).is_null());
            let _ = ares_dns_rr_get_type(rr);
            let _ = ares_dns_rr_get_class(rr);
            let _ = ares_dns_rr_get_ttl(rr);
        }
        let mut kcnt: libc::size_t = 0;
        assert!(!ares_dns_rr_get_keys(T_A as u32, &mut kcnt).is_null());
        assert!(kcnt >= 1);

        // Record-level getters/setters.
        assert_eq!(ares_dns_record_get_id(rec), 0x1234);
        ares_dns_record_set_id(rec, 0x5678);
        assert_eq!(ares_dns_record_get_id(rec), 0x5678);
        let _ = ares_dns_record_get_flags(rec);
        let _ = ares_dns_record_get_opcode(rec);
        let _ = ares_dns_record_get_rcode(rec);
        assert_eq!(ares_dns_record_query_cnt(rec), 1);
        let mut qname: *const c_char = ptr::null();
        let mut qtype: c_uint = 0;
        let mut qclass: c_uint = 0;
        assert_eq!(ares_dns_record_query_get(rec, 0, &mut qname, &mut qtype, &mut qclass), ARES_SUCCESS);
        let newq = CString::new("other.example.com").unwrap();
        assert_eq!(ares_dns_record_query_set_name(rec, 0, newq.as_ptr()), ARES_SUCCESS);
        assert_eq!(ares_dns_record_query_set_type(rec, 0, T_AAAA as u32), ARES_SUCCESS);
        let n = ares_dns_record_rr_cnt(rec, ARES_SECTION_ANSWER);
        assert!(n >= 7);
        assert!(!ares_dns_record_rr_get(rec, ARES_SECTION_ANSWER, 0).is_null());
        assert!(!ares_dns_record_rr_get_const(rec, ARES_SECTION_ANSWER, 0).is_null());
        assert_eq!(ares_dns_record_rr_del(rec, ARES_SECTION_ANSWER, n - 1), ARES_SUCCESS);

        ares_dns_record_destroy(rec);
    }
}

// ---------- pure enum/string converters ----------

#[test]
fn dns_record_converters() {
    unsafe {
        assert!(!ares_dns_rec_type_tostr(T_A as u32).is_null());
        let a = CString::new("A").unwrap();
        let mut rt: c_uint = 0;
        assert_ne!(ares_dns_rec_type_fromstr(&mut rt, a.as_ptr()), 0); // ares_bool_t (true)
        assert_eq!(rt, T_A as u32);

        assert!(!ares_dns_class_tostr(1).is_null());
        let inc = CString::new("IN").unwrap();
        let mut cl: c_uint = 0;
        assert_ne!(ares_dns_class_fromstr(inc.as_ptr(), &mut cl), 0); // ares_bool_t (true)

        assert!(!ares_dns_opcode_tostr(0).is_null());
        assert!(!ares_dns_rcode_tostr(0).is_null());
        assert!(!ares_dns_section_tostr(ARES_SECTION_ANSWER).is_null());
        assert!(!ares_dns_rr_key_tostr(ARES_RR_A_ADDR).is_null());
        let _ = ares_dns_rr_key_datatype(ARES_RR_A_ADDR);
        assert_eq!(ares_dns_rr_key_to_rec_type(ARES_RR_A_ADDR), T_A as u32);
    }
}

// ---------- globals / library / strerror / mkquery ----------

#[test]
fn library_globals_and_strerror() {
    unsafe {
        let mut v: c_int = 0;
        assert!(!ares_version(&mut v).is_null());
        assert!(!ares_version(ptr::null_mut()).is_null());
        let _ = ares_threadsafety();
        assert_eq!(ares_library_init(0), ARES_SUCCESS);
        let _ = ares_library_initialized();
        ares_library_cleanup();
        for code in 0..25 {
            assert!(!ares_strerror(code).is_null());
        }
        ares_free(ptr::null_mut()); // no-op
        let p = libc::malloc(16);
        ares_free(p); // libc::free of a libc::malloc'd block
    }
}

#[test]
fn mkquery_roundtrip() {
    let name = CString::new("example.com").unwrap();
    unsafe {
        let mut buf: *mut u8 = ptr::null_mut();
        let mut buflen: c_int = 0;
        // dnsclass=IN(1), qtype=A(1), id=0x1234, rd=1
        let rc = ares_mkquery(name.as_ptr(), 1, 1, 0x1234, 1, &mut buf, &mut buflen);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!buf.is_null() && buflen > 12);
        ares_free_string(buf as *mut c_void);
    }
}

// ---------- channel-level config (needs ares_init: a file read, no sockets) ----------

unsafe extern "C" fn ai_capture(arg: *mut c_void, _status: c_int, _t: c_int, res: *mut ares_addrinfo) {
    (*(arg as *mut *mut ares_addrinfo)) = res; // stash the addrinfo for the caller to free
}

#[test]
fn channel_config_smoke() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);

        // server setters: CSV + node-list forms
        let csv = CString::new("8.8.8.8,1.1.1.1").unwrap();
        assert_eq!(ares_set_servers_csv(ch, csv.as_ptr()), ARES_SUCCESS);
        assert_eq!(ares_set_servers_ports_csv(ch, csv.as_ptr()), ARES_SUCCESS);

        let mut node = ares_addr_node {
            next: ptr::null_mut(),
            family: AF_INET,
            addr: AresAddrUnion { addr4: libc::in_addr { s_addr: u32::from_ne_bytes([8, 8, 4, 4]) } },
        };
        assert_eq!(ares_set_servers(ch, &mut node), ARES_SUCCESS);

        let mut pnode = AresAddrPortNode {
            next: ptr::null_mut(),
            family: AF_INET,
            addr: AresAddrUnion { addr4: libc::in_addr { s_addr: u32::from_ne_bytes([1, 1, 1, 1]) } },
            udp_port: 53,
            tcp_port: 53,
        };
        assert_eq!(ares_set_servers_ports(ch, &mut pnode), ARES_SUCCESS);

        // server getters (allocate -> free)
        let mut servers: *mut ares_addr_node = ptr::null_mut();
        if ares_get_servers(ch, &mut servers) == ARES_SUCCESS && !servers.is_null() {
            ares_free_data(servers as *mut c_void);
        }
        let scsv = ares_get_servers_csv(ch);
        if !scsv.is_null() {
            ares_free_string(scsv as *mut c_void);
        }
        let mut sp: *mut AresAddrPortNode = ptr::null_mut();
        if ares_get_servers_ports(ch, &mut sp) == ARES_SUCCESS && !sp.is_null() {
            ares_free_data(sp as *mut c_void);
        }

        // misc channel config (all no-op or store-only, no sockets)
        let sortlist = CString::new("130.155.160.0/255.255.240.0").unwrap();
        let _ = ares_set_sortlist(ch, sortlist.as_ptr());
        ares_set_local_ip4(ch, 0x7f000001);
        let ip6 = [0u8; 16];
        ares_set_local_ip6(ch, ip6.as_ptr());
        let dev = CString::new("lo").unwrap();
        ares_set_local_dev(ch, dev.as_ptr());
        ares_set_socket_callback(ch, None, ptr::null_mut());
        ares_set_socket_configure_callback(ch, None, ptr::null_mut());
        assert_eq!(ares_set_socket_functions_ex(ch, ptr::null(), ptr::null_mut()), 0); // null-guarded

        // save/restore options round-trip (malloc'd arrays -> ares_destroy_options)
        let mut opts: ares_options = std::mem::zeroed();
        let mut optmask: c_int = 0;
        assert_eq!(ares_save_options(ch, &mut opts, &mut optmask), ARES_SUCCESS);
        ares_destroy_options(&mut opts);

        // dup -> destroy
        let mut ch2: Channel = ptr::null_mut();
        assert_eq!(ares_dup(&mut ch2, ch), ARES_SUCCESS);
        assert!(!ch2.is_null());
        ares_destroy(ch2);

        let _ = ares_reinit(ch);
        let _ = ares_queue_active_queries(ch);
        let _ = ares_queue_wait_empty(ch, 0);

        ares_destroy(ch);
    }
}

#[test]
fn gethostbyname_file_and_free() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        let name = CString::new("localhost").unwrap();
        let mut he: *mut libc::hostent = ptr::null_mut();
        // reads /etc/hosts; tolerate not-found, but free on success (no UB/leak either way)
        let _ = ares_gethostbyname_file(ch, name.as_ptr(), AF_INET, &mut he);
        if !he.is_null() {
            ares_free_hostent(he);
        }
        ares_destroy(ch);
    }
}

#[test]
fn getaddrinfo_ip_literal_freeaddrinfo() {
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        // An IP literal resolves synchronously (no socket); the caller owns the result.
        let mut got: *mut ares_addrinfo = ptr::null_mut();
        let name = CString::new("127.0.0.1").unwrap();
        ares_getaddrinfo(
            ch,
            name.as_ptr(),
            ptr::null(),
            ptr::null(),
            Some(ai_capture),
            &mut got as *mut _ as *mut c_void,
        );
        if !got.is_null() {
            ares_freeaddrinfo(got);
        }
        ares_freeaddrinfo(ptr::null_mut()); // null no-op
        ares_destroy(ch);
    }
}

#[test]
fn set_servers_stack_chain_no_bad_free() {
    // The USER-ALLOCATED role of these dual-role node types: the caller builds a
    // chain (here on the stack, as benches/req100k.rs does) for ares_set_servers
    // [_ports] and owns/frees it itself — it is NEVER passed to ares_free_data. So
    // the types must have no chain-walking Drop, else dropping the stack head would
    // Box::free a stack `next` (munmap_chunk: invalid pointer / Miri: invalid free).
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);

        let mut n2 = ares_addr_node {
            next: ptr::null_mut(),
            family: AF_INET,
            addr: AresAddrUnion { addr4: libc::in_addr { s_addr: u32::from_ne_bytes([1, 1, 1, 1]) } },
        };
        let mut n1 = ares_addr_node {
            next: &mut n2,
            family: AF_INET,
            addr: AresAddrUnion { addr4: libc::in_addr { s_addr: u32::from_ne_bytes([8, 8, 8, 8]) } },
        };
        assert_eq!(ares_set_servers(ch, &mut n1), ARES_SUCCESS);

        let mut p2 = AresAddrPortNode {
            next: ptr::null_mut(),
            family: AF_INET,
            addr: AresAddrUnion { addr4: libc::in_addr { s_addr: u32::from_ne_bytes([1, 0, 0, 1]) } },
            udp_port: 53,
            tcp_port: 53,
        };
        let mut p1 = AresAddrPortNode {
            next: &mut p2,
            family: AF_INET,
            addr: AresAddrUnion { addr4: libc::in_addr { s_addr: u32::from_ne_bytes([9, 9, 9, 9]) } },
            udp_port: 53,
            tcp_port: 53,
        };
        assert_eq!(ares_set_servers_ports(ch, &mut p1), ARES_SUCCESS);

        ares_destroy(ch);
        // n1/n2/p1/p2 drop here as plain stack values — must free nothing.
    }
}

#[test]
fn get_servers_result_is_freed_with_ares_free_data() {
    // The c-ares-ALLOCATED role of the same dual-role node types: ares_get_servers
    // [_ports] allocate and return the list, and the caller frees it with
    // ares_free_data (the documented c-ares contract). Set two servers so the
    // returned chain is genuinely multi-node — this exercises free_boxed_tail's
    // tail-walk in ares_free_data (the path the old ares_get_servers heap-corruption
    // bug lived on); Miri checks it for leak / use-after-free / double-free.
    unsafe {
        let mut ch: Channel = ptr::null_mut();
        assert_eq!(ares_init(&mut ch), ARES_SUCCESS);
        let csv = CString::new("8.8.8.8,1.1.1.1").unwrap();
        assert_eq!(ares_set_servers_csv(ch, csv.as_ptr()), ARES_SUCCESS);

        // ares_addr_node chain
        let mut nodes: *mut ares_addr_node = ptr::null_mut();
        assert_eq!(ares_get_servers(ch, &mut nodes), ARES_SUCCESS);
        assert!(!nodes.is_null());
        let mut n = 0;
        let mut cur = nodes;
        while !cur.is_null() {
            n += 1;
            cur = (*cur).next;
        }
        assert!(n >= 2, "multi-node chain so the tail-walk actually runs (got {n})");
        ares_free_data(nodes as *mut c_void);

        // ares_addr_port_node chain
        let mut pnodes: *mut AresAddrPortNode = ptr::null_mut();
        assert_eq!(ares_get_servers_ports(ch, &mut pnodes), ARES_SUCCESS);
        assert!(!pnodes.is_null());
        let mut pn = 0;
        let mut pcur = pnodes;
        while !pcur.is_null() {
            pn += 1;
            pcur = (*pcur).next;
        }
        assert!(pn >= 2, "multi-node port chain (got {pn})");
        ares_free_data(pnodes as *mut c_void);

        ares_destroy(ch);
    }
}

#[test]
fn parse_multi_record_reply_freed_via_free_chain() {
    // Two MX records -> a 2-node AresMxReply chain, each node owning a `host` CString.
    // ares_free_data -> free_chain must walk the tail AND each node's fields-only Drop must
    // free its own field exactly once (Miri: no leak / no double-free) — the multi-node
    // reply path that single-record parse tests never exercised.
    let mut mx1 = vec![0x00u8, 0x0A]; // preference 10
    mx1.extend(name_bytes("mail1.example.com"));
    let mut mx2 = vec![0x00u8, 0x14]; // preference 20
    mx2.extend(name_bytes("mail2.example.com"));
    let buf = response("example.com", T_MX, &[rr(T_MX, &mx1), rr(T_MX, &mx2)]);
    unsafe {
        let mut out: *mut c_void = ptr::null_mut();
        let rc = ares_parse_mx_reply(buf.as_ptr(), buf.len() as c_int, &mut out as *mut _ as *mut *mut _);
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!out.is_null());
        ares_free_data(out);
    }
}
