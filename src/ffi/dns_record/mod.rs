#![allow(non_camel_case_types)]
// Thin c-ares C ABI shims: the safety contract is the documented c-ares API
// contract, so per-function `# Safety` docs would just be noise.
#![allow(clippy::missing_safety_doc)]

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ffi::convert::malloc_bytes;
use crate::ffi::error::{ARES_EBADRESP, ARES_ENOMEM, ARES_SUCCESS};

mod safe;
use safe::*;

// ---------------------------------------------------------------------------
// ARES_TRUE / ARES_FALSE
// ---------------------------------------------------------------------------
pub const ARES_TRUE: c_int = 1;
pub const ARES_FALSE: c_int = 0;

// ---------------------------------------------------------------------------
// ares_dns_rec_type_t
// ---------------------------------------------------------------------------
pub const ARES_REC_TYPE_A: u16 = 1;
pub const ARES_REC_TYPE_NS: u16 = 2;
pub const ARES_REC_TYPE_CNAME: u16 = 5;
pub const ARES_REC_TYPE_SOA: u16 = 6;
pub const ARES_REC_TYPE_PTR: u16 = 12;
pub const ARES_REC_TYPE_HINFO: u16 = 13;
pub const ARES_REC_TYPE_MX: u16 = 15;
pub const ARES_REC_TYPE_TXT: u16 = 16;
pub const ARES_REC_TYPE_AAAA: u16 = 28;
pub const ARES_REC_TYPE_SRV: u16 = 33;
pub const ARES_REC_TYPE_NAPTR: u16 = 35;
pub const ARES_REC_TYPE_OPT: u16 = 41;
pub const ARES_REC_TYPE_TLSA: u16 = 52;
pub const ARES_REC_TYPE_SVCB: u16 = 64;
pub const ARES_REC_TYPE_HTTPS: u16 = 65;
pub const ARES_REC_TYPE_ANY: u16 = 255;
pub const ARES_REC_TYPE_URI: u16 = 256;
pub const ARES_REC_TYPE_CAA: u16 = 257;
pub const ARES_REC_TYPE_RAW_RR: u32 = 65536;

// ---------------------------------------------------------------------------
// ares_dns_class_t
// ---------------------------------------------------------------------------
pub const ARES_CLASS_IN: u16 = 1;
pub const ARES_CLASS_CHAOS: u16 = 3;
pub const ARES_CLASS_HESOID: u16 = 4;
pub const ARES_CLASS_NONE: u16 = 254;
pub const ARES_CLASS_ANY: u16 = 255;

// ---------------------------------------------------------------------------
// ares_dns_section_t
// ---------------------------------------------------------------------------
pub const ARES_SECTION_ANSWER: u32 = 1;
pub const ARES_SECTION_AUTHORITY: u32 = 2;
pub const ARES_SECTION_ADDITIONAL: u32 = 3;

// ---------------------------------------------------------------------------
// ares_dns_opcode_t
// ---------------------------------------------------------------------------
pub const ARES_OPCODE_QUERY: u16 = 0;
pub const ARES_OPCODE_IQUERY: u16 = 1;
pub const ARES_OPCODE_STATUS: u16 = 2;
pub const ARES_OPCODE_NOTIFY: u16 = 4;
pub const ARES_OPCODE_UPDATE: u16 = 5;

// ---------------------------------------------------------------------------
// ares_dns_rcode_t
// ---------------------------------------------------------------------------
pub const ARES_RCODE_NOERROR: u16 = 0;
pub const ARES_RCODE_FORMERR: u16 = 1;
pub const ARES_RCODE_SERVFAIL: u16 = 2;
pub const ARES_RCODE_NXDOMAIN: u16 = 3;
pub const ARES_RCODE_NOTIMP: u16 = 4;
pub const ARES_RCODE_REFUSED: u16 = 5;
pub const ARES_RCODE_YXDOMAIN: u16 = 6;
pub const ARES_RCODE_YXRRSET: u16 = 7;
pub const ARES_RCODE_NXRRSET: u16 = 8;
pub const ARES_RCODE_NOTAUTH: u16 = 9;
pub const ARES_RCODE_NOTZONE: u16 = 10;
pub const ARES_RCODE_BADSIG: u16 = 16;
pub const ARES_RCODE_BADKEY: u16 = 17;
pub const ARES_RCODE_BADTIME: u16 = 18;
pub const ARES_RCODE_BADMODE: u16 = 19;
pub const ARES_RCODE_BADNAME: u16 = 20;
pub const ARES_RCODE_BADALG: u16 = 21;
pub const ARES_RCODE_BADTRUNC: u16 = 22;
pub const ARES_RCODE_BADCOOKIE: u16 = 23;

// ---------------------------------------------------------------------------
// ares_dns_flags_t (bitflags in u16)
// ---------------------------------------------------------------------------
pub const ARES_DNS_FLAGS_QR: u16 = 1 << 15;
pub const ARES_DNS_FLAGS_AA: u16 = 1 << 10;
pub const ARES_DNS_FLAGS_TC: u16 = 1 << 9;
pub const ARES_DNS_FLAGS_RD: u16 = 1 << 8;
pub const ARES_DNS_FLAGS_RA: u16 = 1 << 7;

// ---------------------------------------------------------------------------
// ares_dns_datatype_t
// ---------------------------------------------------------------------------
pub const ARES_DATATYPE_INADDR: u16 = 1;
pub const ARES_DATATYPE_INADDR6: u16 = 2;
pub const ARES_DATATYPE_U8: u16 = 3;
pub const ARES_DATATYPE_U16: u16 = 4;
pub const ARES_DATATYPE_U32: u16 = 5;
pub const ARES_DATATYPE_NAME: u16 = 6;
pub const ARES_DATATYPE_STR: u16 = 7;
pub const ARES_DATATYPE_BIN: u16 = 8;
pub const ARES_DATATYPE_BINP: u16 = 9;
pub const ARES_DATATYPE_OPT: u16 = 10;
pub const ARES_DATATYPE_ABINP: u16 = 11;

// ---------------------------------------------------------------------------
// ares_dns_rr_key_t
// ---------------------------------------------------------------------------
// RR keys — formula: RECORD_TYPE * 100 + index (matches c-ares ares_dns_rr_key_t)
// A record keys (type=1)
pub const ARES_RR_A_ADDR: u32 = 100 + 1;
// NS record keys (type=2)
pub const ARES_RR_NS_NSDNAME: u32 = 2 * 100 + 1;
// CNAME record keys (type=5)
pub const ARES_RR_CNAME_CNAME: u32 = 5 * 100 + 1;
// SOA record keys (type=6)
pub const ARES_RR_SOA_MNAME: u32 = 6 * 100 + 1;
pub const ARES_RR_SOA_RNAME: u32 = 6 * 100 + 2;
pub const ARES_RR_SOA_SERIAL: u32 = 6 * 100 + 3;
pub const ARES_RR_SOA_REFRESH: u32 = 6 * 100 + 4;
pub const ARES_RR_SOA_RETRY: u32 = 6 * 100 + 5;
pub const ARES_RR_SOA_EXPIRE: u32 = 6 * 100 + 6;
pub const ARES_RR_SOA_MINIMUM: u32 = 6 * 100 + 7;
// PTR record keys (type=12)
pub const ARES_RR_PTR_DNAME: u32 = 12 * 100 + 1;
// HINFO record keys (type=13)
pub const ARES_RR_HINFO_CPU: u32 = 13 * 100 + 1;
pub const ARES_RR_HINFO_OS: u32 = 13 * 100 + 2;
// MX record keys (type=15)
pub const ARES_RR_MX_PREFERENCE: u32 = 15 * 100 + 1;
pub const ARES_RR_MX_EXCHANGE: u32 = 15 * 100 + 2;
// TXT record keys (type=16)
pub const ARES_RR_TXT_DATA: u32 = 16 * 100 + 1;
// AAAA record keys (type=28)
pub const ARES_RR_AAAA_ADDR: u32 = 28 * 100 + 1;
// SRV record keys (type=33)
pub const ARES_RR_SRV_PRIORITY: u32 = 33 * 100 + 2;
pub const ARES_RR_SRV_WEIGHT: u32 = 33 * 100 + 3;
pub const ARES_RR_SRV_PORT: u32 = 33 * 100 + 4;
pub const ARES_RR_SRV_TARGET: u32 = 33 * 100 + 5;
// NAPTR record keys (type=35)
pub const ARES_RR_NAPTR_ORDER: u32 = 35 * 100 + 1;
pub const ARES_RR_NAPTR_PREFERENCE: u32 = 35 * 100 + 2;
pub const ARES_RR_NAPTR_FLAGS: u32 = 35 * 100 + 3;
pub const ARES_RR_NAPTR_SERVICES: u32 = 35 * 100 + 4;
pub const ARES_RR_NAPTR_REGEXP: u32 = 35 * 100 + 5;
pub const ARES_RR_NAPTR_REPLACEMENT: u32 = 35 * 100 + 6;
// OPT record keys (type=41)
pub const ARES_RR_OPT_UDP_SIZE: u32 = 41 * 100 + 1;
pub const ARES_RR_OPT_VERSION: u32 = 41 * 100 + 3;
pub const ARES_RR_OPT_FLAGS: u32 = 41 * 100 + 4;
pub const ARES_RR_OPT_OPTIONS: u32 = 41 * 100 + 5;
// TLSA record keys (type=52)
pub const ARES_RR_TLSA_CERT_USAGE: u32 = 52 * 100 + 1;
pub const ARES_RR_TLSA_SELECTOR: u32 = 52 * 100 + 2;
pub const ARES_RR_TLSA_MATCH: u32 = 52 * 100 + 3;
pub const ARES_RR_TLSA_DATA: u32 = 52 * 100 + 4;
// SVCB record keys (type=64)
pub const ARES_RR_SVCB_PRIORITY: u32 = 64 * 100 + 1;
pub const ARES_RR_SVCB_TARGET: u32 = 64 * 100 + 2;
pub const ARES_RR_SVCB_PARAMS: u32 = 64 * 100 + 3;
// HTTPS record keys (type=65)
pub const ARES_RR_HTTPS_PRIORITY: u32 = 65 * 100 + 1;
pub const ARES_RR_HTTPS_TARGET: u32 = 65 * 100 + 2;
pub const ARES_RR_HTTPS_PARAMS: u32 = 65 * 100 + 3;
// URI record keys (type=256)
pub const ARES_RR_URI_PRIORITY: u32 = 256 * 100 + 1;
pub const ARES_RR_URI_WEIGHT: u32 = 256 * 100 + 2;
pub const ARES_RR_URI_TARGET: u32 = 256 * 100 + 3;
// CAA record keys (type=257)
pub const ARES_RR_CAA_CRITICAL: u32 = 257 * 100 + 1;
pub const ARES_RR_CAA_TAG: u32 = 257 * 100 + 2;
pub const ARES_RR_CAA_VALUE: u32 = 257 * 100 + 3;
// RAW RR keys (type=65536)
pub const ARES_RR_RAW_RR_TYPE: u32 = 65536 * 100 + 1;
pub const ARES_RR_RAW_RR_DATA: u32 = 65536 * 100 + 2;

// ---------------------------------------------------------------------------
// RRValue - discriminated union for RR field values
// ---------------------------------------------------------------------------
enum RRValue {
    U8(u8),
    U16(u16),
    U32(u32),
    Addr(Ipv4Addr),
    Addr6(Ipv6Addr),
    Str(CString),
    Bin(Vec<u8>), // Always null-terminated: last byte is \0, not counted in logical length
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------
struct DnsRecordQuery {
    name: String,
    name_c: CString, // cached C string for lifetime management
    qtype: u16,
    qclass: u16,
}

pub struct ares_dns_rr_t {
    name: String,
    name_c: CString,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    data: HashMap<u32, RRValue>,
    opts: Vec<(u16, Vec<u8>)>,
    // Cached libc structs backing the pointer-returning getters — interior
    // mutable so a *const rr handle can refresh them without a *mut cast.
    cached_in_addr: std::cell::Cell<libc::in_addr>,
    cached_in6_addr: std::cell::Cell<crate::ffi::ares_in6_addr>,
}

pub struct ares_dns_record_t {
    id: u16,
    flags: u16,
    opcode: u16,
    rcode: u16,
    queries: Vec<DnsRecordQuery>,
    answers: Vec<ares_dns_rr_t>,
    authority: Vec<ares_dns_rr_t>,
    additional: Vec<ares_dns_rr_t>,
}

// =========================================================================
// FFI functions
// =========================================================================

// ---------------------------------------------------------------------------
// Record lifecycle
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_create(
    dnsrec: *mut *mut ares_dns_record_t,
    id: c_uint,
    flags: c_uint,
    opcode: c_uint,
    rcode: c_uint,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EBADRESP;
    }
    let rec = ares_dns_record_t::new(id as u16, flags as u16, opcode as u16, rcode as u16);
    unsafe { *dnsrec = Box::into_raw(Box::new(rec)); }
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_destroy(dnsrec: *mut ares_dns_record_t) {
    if !dnsrec.is_null() {
        let _ = unsafe { Box::from_raw(dnsrec) };
    }
}

/// Duplicate a DNS record via serialize/parse round-trip.
#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_duplicate(
    dnsrec: *const ares_dns_record_t,
) -> *mut ares_dns_record_t {
    if dnsrec.is_null() {
        return std::ptr::null_mut();
    }
    let buf = write_record(unsafe { &*dnsrec });
    match parse_record(&buf) {
        Ok(rec) => Box::into_raw(Box::new(rec)),
        Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Record header
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_id(
    dnsrec: *const ares_dns_record_t,
) -> c_uint {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.id() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_flags(
    dnsrec: *const ares_dns_record_t,
) -> c_uint {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.flags() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_opcode(
    dnsrec: *const ares_dns_record_t,
) -> c_uint {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.opcode() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_rcode(
    dnsrec: *const ares_dns_record_t,
) -> c_uint {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.rcode() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_set_id(
    dnsrec: *mut ares_dns_record_t,
    id: c_uint,
) {
    if !dnsrec.is_null() {
        unsafe { &mut *dnsrec }.set_id(id as u16);
    }
}

// ---------------------------------------------------------------------------
// Query section
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_add(
    dnsrec: *mut ares_dns_record_t,
    name: *const c_char,
    qtype: c_uint,
    qclass: c_uint,
) -> c_int {
    if dnsrec.is_null() || name.is_null() {
        return ARES_EBADRESP;
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADRESP,
    };
    match unsafe { &mut *dnsrec }.query_add(name_str, qtype as u16, qclass as u16) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_cnt(
    dnsrec: *const ares_dns_record_t,
) -> libc::size_t {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.query_cnt()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_get(
    dnsrec: *const ares_dns_record_t,
    idx: libc::size_t,
    name: *mut *const c_char,
    qtype: *mut c_uint,
    qclass: *mut c_uint,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EBADRESP;
    }
    let Some((q_name, q_type, q_class)) = (unsafe { &*dnsrec }).query_at(idx) else {
        return ARES_EBADRESP;
    };
    if !name.is_null() {
        unsafe { *name = q_name; }
    }
    if !qtype.is_null() {
        unsafe { *qtype = q_type as c_uint; }
    }
    if !qclass.is_null() {
        unsafe { *qclass = q_class as c_uint; }
    }
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_set_name(
    dnsrec: *mut ares_dns_record_t,
    idx: libc::size_t,
    name: *const c_char,
) -> c_int {
    if dnsrec.is_null() || name.is_null() {
        return ARES_EBADRESP;
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADRESP,
    };
    match unsafe { &mut *dnsrec }.query_set_name(idx, name_str) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_set_type(
    dnsrec: *mut ares_dns_record_t,
    idx: libc::size_t,
    qtype: c_uint,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EBADRESP;
    }
    match unsafe { &mut *dnsrec }.query_set_type(idx, qtype as u16) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// RR management
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_add(
    rr: *mut *mut ares_dns_rr_t,
    dnsrec: *mut ares_dns_record_t,
    sect: c_uint,
    name: *const c_char,
    rtype: c_uint,
    rclass: c_uint,
    ttl: c_uint,
) -> c_int {
    if dnsrec.is_null() || name.is_null() {
        return ARES_EBADRESP;
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADRESP,
    };
    match unsafe { &mut *dnsrec }.rr_add(sect, name_str, rtype as u16, rclass as u16, ttl) {
        Ok(new_rr) => {
            if !rr.is_null() {
                unsafe { *rr = new_rr as *mut ares_dns_rr_t; }
            }
            ARES_SUCCESS
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_cnt(
    dnsrec: *const ares_dns_record_t,
    sect: c_uint,
) -> libc::size_t {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.rr_cnt(sect)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_get(
    dnsrec: *mut ares_dns_record_t,
    sect: c_uint,
    idx: libc::size_t,
) -> *mut ares_dns_rr_t {
    if dnsrec.is_null() {
        return std::ptr::null_mut();
    }
    match unsafe { &mut *dnsrec }.rr_at_mut(sect, idx) {
        Some(r) => r as *mut ares_dns_rr_t,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_get_const(
    dnsrec: *const ares_dns_record_t,
    sect: c_uint,
    idx: libc::size_t,
) -> *const ares_dns_rr_t {
    if dnsrec.is_null() {
        return std::ptr::null();
    }
    match unsafe { &*dnsrec }.rr_at(sect, idx) {
        Some(r) => r as *const ares_dns_rr_t,
        None => std::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_del(
    dnsrec: *mut ares_dns_record_t,
    sect: c_uint,
    idx: libc::size_t,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EBADRESP;
    }
    match unsafe { &mut *dnsrec }.rr_del(sect, idx) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// RR getters
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_name(
    rr: *const ares_dns_rr_t,
) -> *const c_char {
    if rr.is_null() {
        return std::ptr::null();
    }
    unsafe { &*rr }.name_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_type(rr: *const ares_dns_rr_t) -> c_uint {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.rtype() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_class(rr: *const ares_dns_rr_t) -> c_uint {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.rclass() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_ttl(rr: *const ares_dns_rr_t) -> c_uint {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.ttl() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_addr(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> *const libc::in_addr {
    if rr.is_null() {
        return std::ptr::null();
    }
    unsafe { &*rr }.addr_cached(key).unwrap_or(std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_addr6(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> *const crate::ffi::ares_in6_addr {
    if rr.is_null() {
        return std::ptr::null();
    }
    unsafe { &*rr }.addr6_cached(key).unwrap_or(std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_str(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> *const c_char {
    if rr.is_null() {
        return std::ptr::null();
    }
    unsafe { &*rr }.str_ptr(key).unwrap_or(std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_u8(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> u8 {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.u8_val(key).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_u16(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> u16 {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.u16_val(key).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_u32(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> u32 {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.u32_val(key).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_bin(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    len: *mut libc::size_t,
) -> *const u8 {
    if rr.is_null() {
        if !len.is_null() { unsafe { *len = 0; } }
        return std::ptr::null();
    }
    match (unsafe { &*rr }).bin_val(key) {
        Some((data, logical_len)) => {
            if !len.is_null() {
                unsafe { *len = logical_len; }
            }
            if data.is_empty() {
                static EMPTY: u8 = 0;
                &EMPTY as *const u8
            } else {
                data.as_ptr()
            }
        }
        None => {
            if !len.is_null() {
                unsafe { *len = 0; }
            }
            std::ptr::null()
        }
    }
}

// ---------------------------------------------------------------------------
// RR setters
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_addr(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    addr: *const libc::in_addr,
) -> c_int {
    if rr.is_null() || addr.is_null() {
        return ARES_EBADRESP;
    }
    let octets = (unsafe { &*addr }).s_addr.to_ne_bytes();
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    unsafe { &mut *rr }.set_addr(key, ip);
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_addr6(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    addr: *const crate::ffi::ares_in6_addr,
) -> c_int {
    if rr.is_null() || addr.is_null() {
        return ARES_EBADRESP;
    }
    let ip = unsafe { Ipv6Addr::from((*addr)._S6_un._S6_u8) };
    unsafe { &mut *rr }.set_addr6(key, ip);
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_str(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: *const c_char,
) -> c_int {
    if rr.is_null() || val.is_null() {
        return ARES_EBADRESP;
    }
    let owned = CString::from(unsafe { CStr::from_ptr(val) });
    unsafe { &mut *rr }.set_str(key, owned);
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_u8(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: u8,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    unsafe { &mut *rr }.set_u8(key, val);
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_u16(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: u16,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    unsafe { &mut *rr }.set_u16(key, val);
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_u32(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: u32,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    unsafe { &mut *rr }.set_u32(key, val);
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_bin(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: *const u8,
    len: libc::size_t,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    let data = if val.is_null() || len == 0 {
        &[] as &[u8]
    } else {
        unsafe { std::slice::from_raw_parts(val, len) }
    };
    unsafe { &mut *rr }.set_bin(key, data);
    ARES_SUCCESS
}

// ---------------------------------------------------------------------------
// OPT handling
// ---------------------------------------------------------------------------

#[no_mangle]
#[allow(unused_variables)] // `key`/`flags`: C API params this impl ignores; names frozen by the header
pub unsafe extern "C" fn ares_dns_rr_set_opt(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
    val: *const u8,
    val_len: libc::size_t,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    let data = if val.is_null() || val_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(val, val_len) }.to_vec()
    };
    unsafe { &mut *rr }.set_opt(opt as u16, data);
    ARES_SUCCESS
}

#[no_mangle]
#[allow(unused_variables)] // `key`/`flags`: C API params this impl ignores; names frozen by the header
pub unsafe extern "C" fn ares_dns_rr_get_opt_cnt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> libc::size_t {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.opt_cnt()
}

#[no_mangle]
#[allow(unused_variables)] // `key`/`flags`: C API params this impl ignores; names frozen by the header
pub unsafe extern "C" fn ares_dns_rr_get_opt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    idx: libc::size_t,
    opt: *mut c_uint,
    val: *mut *const u8,
    val_len: *mut libc::size_t,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    let Some((code, data)) = (unsafe { &*rr }).opt_at(idx) else {
        return ARES_EBADRESP;
    };
    if !opt.is_null() {
        unsafe { *opt = code as c_uint; }
    }
    if !val.is_null() {
        unsafe { *val = data.as_ptr(); }
    }
    if !val_len.is_null() {
        unsafe { *val_len = data.len(); }
    }
    ARES_SUCCESS
}

#[no_mangle]
#[allow(unused_variables)] // `key`/`flags`: C API params this impl ignores; names frozen by the header
pub unsafe extern "C" fn ares_dns_rr_get_opt_byid(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
    val: *mut *const u8,
    val_len: *mut libc::size_t,
) -> c_int {
    if rr.is_null() {
        return ARES_FALSE;
    }
    let Some(data) = (unsafe { &*rr }).opt_by_id(opt as u16) else {
        return ARES_FALSE;
    };
    if !val.is_null() {
        unsafe { *val = data.as_ptr(); }
    }
    if !val_len.is_null() {
        unsafe { *val_len = data.len(); }
    }
    ARES_TRUE
}

#[no_mangle]
#[allow(unused_variables)] // `key`/`flags`: C API params this impl ignores; names frozen by the header
pub unsafe extern "C" fn ares_dns_rr_del_opt_byid(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    if unsafe { &mut *rr }.del_opt_by_id(opt as u16) {
        ARES_SUCCESS
    } else {
        ARES_EBADRESP
    }
}

// ---------------------------------------------------------------------------
// Serialization: ares_dns_parse
// ---------------------------------------------------------------------------

#[no_mangle]
#[allow(unused_variables)] // `key`/`flags`: C API params this impl ignores; names frozen by the header
pub unsafe extern "C" fn ares_dns_parse(
    buf: *const u8,
    buf_len: libc::size_t,
    flags: c_uint,
    dnsrec: *mut *mut ares_dns_record_t,
) -> c_int {
    if buf.is_null() || dnsrec.is_null() || buf_len < 12 {
        return ARES_EBADRESP;
    }
    let data = unsafe { std::slice::from_raw_parts(buf, buf_len) };
    match parse_record(data) {
        Ok(rec) => {
            unsafe { *dnsrec = Box::into_raw(Box::new(rec)); }
            ARES_SUCCESS
        }
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// Serialization: ares_dns_write
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_write(
    dnsrec: *const ares_dns_record_t,
    buf: *mut *mut u8,
    buf_len: *mut libc::size_t,
) -> c_int {
    if dnsrec.is_null() || buf.is_null() || buf_len.is_null() {
        return ARES_EBADRESP;
    }
    let out = write_record(unsafe { &*dnsrec });
    let ptr = unsafe { malloc_bytes(&out) };
    if ptr.is_null() {
        return ARES_ENOMEM;
    }
    unsafe { *buf = ptr; }
    unsafe { *buf_len = out.len(); }
    ARES_SUCCESS
}

// ---------------------------------------------------------------------------
// Metadata / string functions (the tables live in safe.rs)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rec_type_tostr(rtype: c_uint) -> *const c_char {
    rec_type_name(rtype)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rec_type_fromstr(
    rtype: *mut c_uint,
    str_ptr: *const c_char,
) -> c_int {
    if str_ptr.is_null() || rtype.is_null() {
        return ARES_FALSE;
    }
    let s = match unsafe { CStr::from_ptr(str_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_FALSE,
    };
    match rec_type_from_name(s) {
        Some(val) => {
            unsafe { *rtype = val };
            ARES_TRUE
        }
        None => ARES_FALSE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_class_tostr(qclass: c_uint) -> *const c_char {
    class_name(qclass)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_class_fromstr(
    str_ptr: *const c_char,
    qclass: *mut c_uint,
) -> c_int {
    if str_ptr.is_null() || qclass.is_null() {
        return ARES_FALSE;
    }
    let s = match unsafe { CStr::from_ptr(str_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_FALSE,
    };
    match class_from_name(s) {
        Some(val) => {
            unsafe { *qclass = val };
            ARES_TRUE
        }
        None => ARES_FALSE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_tostr(key: c_uint) -> *const c_char {
    rr_key_name(key)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_keys(
    rtype: c_uint,
    cnt: *mut libc::size_t,
) -> *const c_uint {
    if cnt.is_null() {
        return std::ptr::null();
    }
    match keys_for(rtype) {
        Some(keys) => {
            unsafe { *cnt = keys.len() };
            keys.as_ptr()
        }
        None => {
            unsafe { *cnt = 0 };
            std::ptr::null()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_datatype(key: c_uint) -> c_uint {
    rr_key_datatype_of(key)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_to_rec_type(key: c_uint) -> c_uint {
    rr_key_rec_type(key)
}

#[no_mangle]
pub extern "C" fn ares_dns_opcode_tostr(opcode: c_uint) -> *const c_char {
    opcode_name(opcode)
}

#[no_mangle]
pub extern "C" fn ares_dns_rcode_tostr(rcode: c_uint) -> *const c_char {
    rcode_name(rcode)
}

#[no_mangle]
pub extern "C" fn ares_dns_section_tostr(section: c_uint) -> *const c_char {
    section_name(section)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_abin_cnt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> libc::size_t {
    if rr.is_null() { return 0; }
    // We store TXT as a single Bin blob; for abin API, treat as 1 entry if non-empty
    match (unsafe { &*rr }).bin_val(key) {
        Some((_, logical_len)) if logical_len > 0 => 1,
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_abin(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    idx: libc::size_t,
    len: *mut libc::size_t,
) -> *const u8 {
    if rr.is_null() || len.is_null() { return std::ptr::null(); }
    if idx != 0 { unsafe { *len = 0; } return std::ptr::null(); }
    match (unsafe { &*rr }).bin_val(key) {
        Some((data, logical_len)) => {
            unsafe { *len = logical_len; }
            if data.is_empty() {
                static EMPTY: u8 = 0;
                &EMPTY as *const u8
            } else {
                data.as_ptr()
            }
        }
        None => {
            unsafe { *len = 0; }
            std::ptr::null()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { libc::free(ptr) };
    }
}

