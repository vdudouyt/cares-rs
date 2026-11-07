//! DNS-record parity regressions against the c-ares 1.34.6 contract; all
//! packets are built in memory (no network or filesystem).

use std::ffi::{c_int, c_uint, CStr, CString};
use std::ptr;

use cares_rs::dns_record::*;
use cares_rs::*;

const T_A: u16 = ARES_REC_TYPE_A;
const T_CNAME: u16 = ARES_REC_TYPE_CNAME;
const T_HINFO: u16 = ARES_REC_TYPE_HINFO;
const T_TXT: u16 = ARES_REC_TYPE_TXT;
const T_NAPTR: u16 = ARES_REC_TYPE_NAPTR;
const T_OPT: u16 = ARES_REC_TYPE_OPT;
const T_CAA: u16 = ARES_REC_TYPE_CAA;

fn push_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn push_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn name_rdata(name: &str) -> Vec<u8> {
    let mut data = Vec::new();
    push_name(&mut data, name);
    data
}

fn answer(name: &str, rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_name(&mut buf, name);
    push_u16(&mut buf, rtype);
    push_u16(&mut buf, class);
    push_u32(&mut buf, ttl);
    push_u16(&mut buf, rdata.len() as u16);
    buf.extend_from_slice(rdata);
    buf
}

fn response(qname: &str, qtype: u16, answers: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u16(&mut buf, 0x1234);
    push_u16(&mut buf, 0x8180);
    push_u16(&mut buf, 1);
    push_u16(&mut buf, answers.len() as u16);
    push_u16(&mut buf, 0);
    push_u16(&mut buf, 0);
    push_name(&mut buf, qname);
    push_u16(&mut buf, qtype);
    push_u16(&mut buf, ARES_CLASS_IN);
    for rr in answers {
        buf.extend_from_slice(rr);
    }
    buf
}

fn opt_response(qname: &str, udp_size: u16, ext_rcode: u8, version: u8, flags: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u16(&mut buf, 0x1234);
    push_u16(&mut buf, 0x8180);
    push_u16(&mut buf, 1);
    push_u16(&mut buf, 0);
    push_u16(&mut buf, 0);
    push_u16(&mut buf, 1);
    push_name(&mut buf, qname);
    push_u16(&mut buf, T_A);
    push_u16(&mut buf, ARES_CLASS_IN);

    // OPT: root owner, class = UDP payload size, TTL = ext rcode/version/flags,
    // empty rdata.
    buf.push(0);
    push_u16(&mut buf, T_OPT);
    push_u16(&mut buf, udp_size);
    let ttl = (u32::from(ext_rcode) << 24) | (u32::from(version) << 16) | u32::from(flags);
    push_u32(&mut buf, ttl);
    push_u16(&mut buf, 0);
    buf
}

unsafe fn new_record() -> *mut ares_dns_record_t {
    let mut rec = ptr::null_mut();
    assert_eq!(
        unsafe { ares_dns_record_create(&mut rec, 0x1234, 0, 0, 0) },
        ARES_SUCCESS
    );
    assert!(!rec.is_null());
    rec
}

unsafe fn add_rr(
    rec: *mut ares_dns_record_t,
    section: c_uint,
    name: &CStr,
    rtype: u16,
    class: u16,
    ttl: u32,
) -> *mut ares_dns_rr_t {
    let mut rr = ptr::null_mut();
    assert_eq!(
        unsafe {
            ares_dns_record_rr_add(
                &mut rr,
                rec,
                section,
                name.as_ptr(),
                u32::from(rtype),
                u32::from(class),
                ttl,
            )
        },
        ARES_SUCCESS
    );
    assert!(!rr.is_null());
    rr
}

unsafe fn parse_packet(buf: &[u8]) -> *mut ares_dns_record_t {
    let mut rec = ptr::null_mut();
    let rc = unsafe { ares_dns_parse(buf.as_ptr(), buf.len(), 0, &mut rec) };
    assert_eq!(rc, ARES_SUCCESS, "ares_dns_parse failed");
    assert!(!rec.is_null());
    rec
}

fn bytes_from(ptr: *const u8, len: usize) -> Vec<u8> {
    assert!(!ptr.is_null(), "expected a non-null data pointer");
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

#[test]
fn txt_abinp_alias_is_safe_and_empty_string_is_preserved() {
    unsafe {
        let rec = new_record();
        let name = CString::new("txt.example.com").unwrap();
        let rr = add_rr(rec, ARES_SECTION_ANSWER, &name, T_TXT, ARES_CLASS_IN, 60);

        assert_eq!(
            ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, b"alpha".as_ptr(), 5),
            ARES_SUCCESS
        );
        // A zero-length character-string is still a real ABINP element.
        assert_eq!(
            ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, b"".as_ptr(), 0),
            ARES_SUCCESS
        );
        assert_eq!(
            ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, b"omega".as_ptr(), 5),
            ARES_SUCCESS
        );

        assert_eq!(ares_dns_rr_get_abin_cnt(rr, ARES_RR_TXT_DATA), 3);
        for (idx, expected) in [b"alpha".as_slice(), b"".as_slice(), b"omega".as_slice()]
            .iter()
            .enumerate()
        {
            let mut len = 0usize;
            let ptr = ares_dns_rr_get_abin(rr, ARES_RR_TXT_DATA, idx, &mut len);
            assert!(
                !ptr.is_null(),
                "empty ABINP element must have non-null storage"
            );
            assert_eq!(len, expected.len());
            assert_eq!(bytes_from(ptr, len), *expected);
        }

        let mut combined_len = 0usize;
        let combined = ares_dns_rr_get_bin(rr, ARES_RR_TXT_DATA, &mut combined_len);
        assert_eq!(bytes_from(combined, combined_len), b"alphaomega");

        // set_bin must be safe when the source aliases the combined cache.
        assert_eq!(
            ares_dns_rr_set_bin(rr, ARES_RR_TXT_DATA, combined, combined_len),
            ARES_SUCCESS
        );
        assert_eq!(ares_dns_rr_get_abin_cnt(rr, ARES_RR_TXT_DATA), 1);
        let mut len = 0usize;
        let ptr = ares_dns_rr_get_bin(rr, ARES_RR_TXT_DATA, &mut len);
        assert_eq!(bytes_from(ptr, len), b"alphaomega");

        // add_abin must be safe when the source aliases the combined cache.
        assert_eq!(
            ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, ptr, len),
            ARES_SUCCESS
        );
        assert_eq!(ares_dns_rr_get_abin_cnt(rr, ARES_RR_TXT_DATA), 2);
        let mut combined_len = 0usize;
        let combined = ares_dns_rr_get_bin(rr, ARES_RR_TXT_DATA, &mut combined_len);
        assert_eq!(bytes_from(combined, combined_len), b"alphaomegaalphaomega");

        ares_dns_record_destroy(rec);
    }
}

#[test]
fn txt_parse_multi_string_uses_one_abinp_element_per_string() {
    let mut rdata = Vec::new();
    rdata.push(5);
    rdata.extend_from_slice(b"first");
    rdata.push(6);
    rdata.extend_from_slice(b"second");
    let buf = response(
        "txt.example.com",
        T_TXT,
        &[answer("txt.example.com", T_TXT, ARES_CLASS_IN, 60, &rdata)],
    );

    unsafe {
        let rec = parse_packet(&buf);
        let rr = ares_dns_record_rr_get_const(rec, ARES_SECTION_ANSWER, 0);
        assert!(!rr.is_null());
        assert_eq!(ares_dns_rr_get_abin_cnt(rr, ARES_RR_TXT_DATA), 2);

        let mut len = 0usize;
        let ptr = ares_dns_rr_get_abin(rr, ARES_RR_TXT_DATA, 0, &mut len);
        assert_eq!(bytes_from(ptr, len), b"first");
        let ptr = ares_dns_rr_get_abin(rr, ARES_RR_TXT_DATA, 1, &mut len);
        assert_eq!(bytes_from(ptr, len), b"second");

        let ptr = ares_dns_rr_get_bin(rr, ARES_RR_TXT_DATA, &mut len);
        assert_eq!(bytes_from(ptr, len), b"firstsecond");
        ares_dns_record_destroy(rec);
    }
}

#[test]
fn opt_wire_fields_survive_write_reparse_and_duplicate() {
    // Extended rcode 1 + low nibble 0 = BADSIG (16); upstream normalizes other
    // 12-bit values to SERVFAIL.
    let buf = opt_response("example.com", 1232, 0x01, 5, 0x0123);
    unsafe {
        let rec = parse_packet(&buf);
        let check = |rec: *mut ares_dns_record_t| {
            let rr = ares_dns_record_rr_get_const(rec, ARES_SECTION_ADDITIONAL, 0);
            assert!(!rr.is_null());
            assert_eq!(ares_dns_rr_get_type(rr), u32::from(T_OPT));
            assert_eq!(ares_dns_rr_get_class(rr), u32::from(ARES_CLASS_IN));
            assert_eq!(ares_dns_rr_get_u16(rr, ARES_RR_OPT_UDP_SIZE), 1232);
            assert_eq!(ares_dns_rr_get_u8(rr, ARES_RR_OPT_VERSION), 5);
            assert_eq!(ares_dns_rr_get_u16(rr, ARES_RR_OPT_FLAGS), 0x0123);
            assert_eq!(ares_dns_record_get_rcode(rec), 16);
        };
        check(rec);

        let dup = ares_dns_record_duplicate(rec);
        assert!(!dup.is_null());
        check(dup);

        let mut out = ptr::null_mut();
        let mut out_len = 0usize;
        assert_eq!(ares_dns_write(rec, &mut out, &mut out_len), ARES_SUCCESS);
        assert!(!out.is_null() && out_len >= 12);
        let wire = std::slice::from_raw_parts(out, out_len).to_vec();
        ares_free(out as *mut std::ffi::c_void);

        let reparsed = parse_packet(&wire);
        check(reparsed);

        ares_dns_record_destroy(reparsed);
        ares_dns_record_destroy(dup);
        ares_dns_record_destroy(rec);
    }
}

#[test]
fn zero_length_raw_rr_is_not_writable() {
    let buf = response(
        "example.com",
        T_A,
        &[answer("example.com", 65000, ARES_CLASS_IN, 60, &[])],
    );

    unsafe {
        let rec = parse_packet(&buf);
        let rr = ares_dns_record_rr_get_const(rec, ARES_SECTION_ANSWER, 0);
        assert!(!rr.is_null());
        assert_eq!(ares_dns_rr_get_type(rr), ARES_REC_TYPE_RAW_RR);

        let mut out = std::ptr::dangling_mut::<u8>();
        let mut out_len = 7usize;
        let rc = ares_dns_write(rec, &mut out, &mut out_len);
        assert_eq!(rc, ARES_EFORMERR);
        assert!(out.is_null(), "failed write must clear the output pointer");
        assert_eq!(out_len, 0, "failed write must clear the output length");

        ares_dns_record_destroy(rec);
    }
}

#[test]
fn invalid_dns_classes_match_upstream() {
    // Upstream accepts CHAOS in an A answer; 17 and 255 are invalid for A.
    for (class, expected) in [
        (ARES_CLASS_CHAOS, ARES_SUCCESS),
        (17, ARES_EFORMERR),
        (255, ARES_EFORMERR),
    ] {
        let buf = response(
            "example.com",
            T_A,
            &[answer("example.com", T_A, class, 60, &[1, 2, 3, 4])],
        );
        let mut rec = ptr::null_mut();
        let rc = unsafe { ares_dns_parse(buf.as_ptr(), buf.len(), 0, &mut rec) };
        assert_eq!(rc, expected, "parse A answer class {class}");
        if rc == ARES_SUCCESS {
            assert!(!rec.is_null());
            unsafe { ares_dns_record_destroy(rec) };
        } else {
            assert!(rec.is_null());
        }
    }

    unsafe {
        let rec = new_record();
        let name = CString::new("example.com").unwrap();
        for (class, expected) in [
            (u32::from(ARES_CLASS_CHAOS), ARES_SUCCESS),
            (17, ARES_EFORMERR),
            (255, ARES_EFORMERR),
            (256, ARES_EFORMERR),
        ] {
            let mut rr = ptr::null_mut();
            let rc = ares_dns_record_rr_add(
                &mut rr,
                rec,
                ARES_SECTION_ANSWER,
                name.as_ptr(),
                u32::from(T_A),
                class,
                60,
            );
            assert_eq!(rc, expected, "rr_add A class {class}");
        }
        ares_dns_record_destroy(rec);
    }
}

#[test]
fn cname_class_filtering_preserves_hostname_and_ttl() {
    unsafe fn parse_name_and_ttl(packet: &[u8]) -> (String, c_int) {
        let mut host: *mut libc::hostent = ptr::null_mut();
        let mut ttls: [ares_addrttl; 4] = std::mem::zeroed();
        let mut count: c_int = 4;
        let rc = unsafe {
            ares_parse_a_reply(
                packet.as_ptr(),
                packet.len() as c_int,
                &mut host,
                ttls.as_mut_ptr(),
                &mut count,
            )
        };
        assert_eq!(rc, ARES_SUCCESS);
        assert!(!host.is_null());
        assert_eq!(count, 1);
        let name = unsafe { CStr::from_ptr((*host).h_name) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { ares_free_hostent(host) };
        (name, ttls[0].ttl)
    }

    // A CHAOS CNAME must not replace the hostname or clamp the IN A TTL.
    let chaos_cname = answer(
        "www.example.com",
        T_CNAME,
        ARES_CLASS_CHAOS,
        1,
        &name_rdata("chaos.example.net"),
    );
    let chaos_a = answer("chaos.example.net", T_A, ARES_CLASS_IN, 300, &[1, 2, 3, 4]);
    let chaos_packet = response("www.example.com", T_A, &[chaos_cname, chaos_a]);
    let (name, ttl) = unsafe { parse_name_and_ttl(&chaos_packet) };
    assert_eq!(name, "www.example.com");
    assert_eq!(ttl, 300);

    // An IN CNAME must become the hostname and clamp the A TTL.
    let in_cname = answer(
        "www.example.com",
        T_CNAME,
        ARES_CLASS_IN,
        5,
        &name_rdata("in.example.net"),
    );
    let in_a = answer("in.example.net", T_A, ARES_CLASS_IN, 300, &[5, 6, 7, 8]);
    let in_packet = response("www.example.com", T_A, &[in_cname, in_a]);
    let (name, ttl) = unsafe { parse_name_and_ttl(&in_packet) };
    assert_eq!(name, "in.example.net");
    assert_eq!(ttl, 5);
}

fn write_rr_expect(rec: *mut ares_dns_record_t, expected: c_int) {
    unsafe {
        let mut out = std::ptr::dangling_mut::<u8>();
        let mut out_len = 7usize;
        let rc = ares_dns_write(rec, &mut out, &mut out_len);
        assert_eq!(rc, expected, "ares_dns_write status");
        assert!(out.is_null(), "failed write must clear the output pointer");
        assert_eq!(out_len, 0, "failed write must clear the output length");
    }
}

#[test]
fn writer_rejects_invalid_names_and_long_strings() {
    const ARES_EBADNAME: c_int = 8;

    unsafe {
        let name = CString::new("example.com").unwrap();

        let rec = new_record();
        let rr = add_rr(rec, ARES_SECTION_ANSWER, &name, T_CNAME, ARES_CLASS_IN, 60);
        let long_label = CString::new(format!("{}.com", "a".repeat(64))).unwrap();
        assert_eq!(
            ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, long_label.as_ptr()),
            ARES_SUCCESS
        );
        write_rr_expect(rec, ARES_EBADNAME);
        ares_dns_record_destroy(rec);

        let rec = new_record();
        let rr = add_rr(rec, ARES_SECTION_ANSWER, &name, T_CNAME, ARES_CLASS_IN, 60);
        let empty_label = CString::new("foo..bar").unwrap();
        assert_eq!(
            ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, empty_label.as_ptr()),
            ARES_SUCCESS
        );
        write_rr_expect(rec, ARES_EBADNAME);
        ares_dns_record_destroy(rec);

        let rec = new_record();
        let rr = add_rr(rec, ARES_SECTION_ANSWER, &name, T_CNAME, ARES_CLASS_IN, 60);
        let long_name = CString::new(vec!["a".repeat(60); 5].join(".")).unwrap();
        assert_eq!(
            ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, long_name.as_ptr()),
            ARES_SUCCESS
        );
        write_rr_expect(rec, ARES_EBADNAME);
        ares_dns_record_destroy(rec);

        let long_string = CString::new("x".repeat(256)).unwrap();

        let rec = new_record();
        let rr = add_rr(rec, ARES_SECTION_ANSWER, &name, T_NAPTR, ARES_CLASS_IN, 60);
        assert_eq!(
            ares_dns_rr_set_str(rr, ARES_RR_NAPTR_FLAGS, long_string.as_ptr()),
            ARES_SUCCESS
        );
        write_rr_expect(rec, ARES_EFORMERR);
        ares_dns_record_destroy(rec);

        let rec = new_record();
        let rr = add_rr(rec, ARES_SECTION_ANSWER, &name, T_HINFO, ARES_CLASS_IN, 60);
        assert_eq!(
            ares_dns_rr_set_str(rr, ARES_RR_HINFO_CPU, long_string.as_ptr()),
            ARES_SUCCESS
        );
        write_rr_expect(rec, ARES_EFORMERR);
        ares_dns_record_destroy(rec);

        let rec = new_record();
        let rr = add_rr(rec, ARES_SECTION_ANSWER, &name, T_CAA, ARES_CLASS_IN, 60);
        assert_eq!(
            ares_dns_rr_set_str(rr, ARES_RR_CAA_TAG, long_string.as_ptr()),
            ARES_SUCCESS
        );
        assert_eq!(
            ares_dns_rr_set_bin(rr, ARES_RR_CAA_VALUE, b"value".as_ptr(), 5),
            ARES_SUCCESS
        );
        write_rr_expect(rec, ARES_EFORMERR);
        ares_dns_record_destroy(rec);
    }
}

#[test]
fn del_opt_byid_empty_and_missing_options() {
    unsafe {
        let rec = new_record();
        let root = CString::new("").unwrap();
        let rr = add_rr(rec, ARES_SECTION_ADDITIONAL, &root, T_OPT, ARES_CLASS_IN, 0);
        assert_eq!(
            ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, 1232),
            ARES_SUCCESS
        );

        // Upstream treats delete with no options as a no-op success.
        assert_eq!(
            ares_dns_rr_del_opt_byid(rr, ARES_RR_OPT_OPTIONS, 5),
            ARES_SUCCESS
        );

        assert_eq!(
            ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, 5, b"value".as_ptr(), 5),
            ARES_SUCCESS
        );
        // A non-empty option list missing the requested id is ENOTFOUND.
        assert_eq!(
            ares_dns_rr_del_opt_byid(rr, ARES_RR_OPT_OPTIONS, 6),
            ARES_ENOTFOUND
        );
        assert_eq!(
            ares_dns_rr_del_opt_byid(rr, ARES_RR_OPT_OPTIONS, 5),
            ARES_SUCCESS
        );

        ares_dns_record_destroy(rec);
    }
}
