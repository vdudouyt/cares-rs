#![allow(non_camel_case_types)]
// Thin c-ares C ABI shims; the documented c-ares API contract is the safety contract.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_uint, c_ushort, c_void, CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ffi::convert::{malloc_bytes, malloc_cstr};
use crate::ffi::error::{ARES_EBADRESP, ARES_EFORMERR, ARES_ENOMEM, ARES_SUCCESS};

pub use crate::core::dns_record::{ares_dns_record_t, ares_dns_rr_t};
pub(crate) use crate::core::dns_record::parse_record;
use crate::core::dns_record::write_record;

pub const ARES_TRUE: c_int = 1;
pub const ARES_FALSE: c_int = 0;

pub const ARES_REC_TYPE_A: u16 = 1;
pub const ARES_REC_TYPE_NS: u16 = 2;
pub const ARES_REC_TYPE_CNAME: u16 = 5;
pub const ARES_REC_TYPE_SOA: u16 = 6;
pub const ARES_REC_TYPE_PTR: u16 = 12;
pub const ARES_REC_TYPE_HINFO: u16 = 13;
pub const ARES_REC_TYPE_MX: u16 = 15;
pub const ARES_REC_TYPE_TXT: u16 = 16;
pub const ARES_REC_TYPE_SIG: u16 = 24;
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

pub const ARES_CLASS_IN: u16 = 1;
pub const ARES_CLASS_CHAOS: u16 = 3;
pub const ARES_CLASS_HESOID: u16 = 4;
pub const ARES_CLASS_NONE: u16 = 254;
pub const ARES_CLASS_ANY: u16 = 255;

pub const ARES_SECTION_ANSWER: u32 = 1;
pub const ARES_SECTION_AUTHORITY: u32 = 2;
pub const ARES_SECTION_ADDITIONAL: u32 = 3;

pub const ARES_OPCODE_QUERY: u16 = 0;
pub const ARES_OPCODE_IQUERY: u16 = 1;
pub const ARES_OPCODE_STATUS: u16 = 2;
pub const ARES_OPCODE_NOTIFY: u16 = 4;
pub const ARES_OPCODE_UPDATE: u16 = 5;

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
pub const ARES_RCODE_DSOTYPEI: u16 = 11;
pub const ARES_RCODE_BADSIG: u16 = 16;
pub const ARES_RCODE_BADKEY: u16 = 17;
pub const ARES_RCODE_BADTIME: u16 = 18;
pub const ARES_RCODE_BADMODE: u16 = 19;
pub const ARES_RCODE_BADNAME: u16 = 20;
pub const ARES_RCODE_BADALG: u16 = 21;
pub const ARES_RCODE_BADTRUNC: u16 = 22;
pub const ARES_RCODE_BADCOOKIE: u16 = 23;

pub const ARES_DNS_FLAGS_QR: u16 = 1 << 15;
pub const ARES_DNS_FLAGS_AA: u16 = 1 << 10;
pub const ARES_DNS_FLAGS_TC: u16 = 1 << 9;
pub const ARES_DNS_FLAGS_RD: u16 = 1 << 8;
pub const ARES_DNS_FLAGS_RA: u16 = 1 << 7;

// Header flag bits, also spelled `ARES_FLAG_*` upstream (distinct from the
// channel-level `ARES_FLAG_USEVC` family); keep both spellings source-compatible.
pub const ARES_FLAG_QR: u16 = 1 << 0;
pub const ARES_FLAG_AA: u16 = 1 << 1;
pub const ARES_FLAG_TC: u16 = 1 << 2;
pub const ARES_FLAG_RD: u16 = 1 << 3;
pub const ARES_FLAG_RA: u16 = 1 << 4;
pub const ARES_FLAG_AD: u16 = 1 << 5;
pub const ARES_FLAG_CD: u16 = 1 << 6;

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

pub const ARES_DNS_PARSE_AN_BASE_RAW: u32 = 1 << 0;
pub const ARES_DNS_PARSE_NS_BASE_RAW: u32 = 1 << 1;
pub const ARES_DNS_PARSE_AR_BASE_RAW: u32 = 1 << 2;
pub const ARES_DNS_PARSE_AN_EXT_RAW: u32 = 1 << 3;
pub const ARES_DNS_PARSE_NS_EXT_RAW: u32 = 1 << 4;
pub const ARES_DNS_PARSE_AR_EXT_RAW: u32 = 1 << 5;

pub const ARES_OPT_DATATYPE_NONE: u32 = 1;
pub const ARES_OPT_DATATYPE_STR_LIST: u32 = 2;
pub const ARES_OPT_DATATYPE_U8_LIST: u32 = 3;
pub const ARES_OPT_DATATYPE_U16: u32 = 4;
pub const ARES_OPT_DATATYPE_U16_LIST: u32 = 5;
pub const ARES_OPT_DATATYPE_U32: u32 = 6;
pub const ARES_OPT_DATATYPE_U32_LIST: u32 = 7;
pub const ARES_OPT_DATATYPE_INADDR4_LIST: u32 = 8;
pub const ARES_OPT_DATATYPE_INADDR6_LIST: u32 = 9;
pub const ARES_OPT_DATATYPE_BIN: u32 = 10;
pub const ARES_OPT_DATATYPE_NAME: u32 = 11;

pub const ARES_OPT_PARAM_LLQ: u32 = 1;
pub const ARES_OPT_PARAM_UL: u32 = 2;
pub const ARES_OPT_PARAM_NSID: u32 = 3;
pub const ARES_OPT_PARAM_DAU: u32 = 5;
pub const ARES_OPT_PARAM_DHU: u32 = 6;
pub const ARES_OPT_PARAM_N3U: u32 = 7;
pub const ARES_OPT_PARAM_EDNS_CLIENT_SUBNET: u32 = 8;
pub const ARES_OPT_PARAM_EDNS_EXPIRE: u32 = 9;
pub const ARES_OPT_PARAM_COOKIE: u32 = 10;
pub const ARES_OPT_PARAM_EDNS_TCP_KEEPALIVE: u32 = 11;
pub const ARES_OPT_PARAM_PADDING: u32 = 12;
pub const ARES_OPT_PARAM_CHAIN: u32 = 13;
pub const ARES_OPT_PARAM_EDNS_KEY_TAG: u32 = 14;
pub const ARES_OPT_PARAM_EXTENDED_DNS_ERROR: u32 = 15;

pub const ARES_SVCB_PARAM_MANDATORY: u32 = 0;
pub const ARES_SVCB_PARAM_ALPN: u32 = 1;
pub const ARES_SVCB_PARAM_NO_DEFAULT_ALPN: u32 = 2;
pub const ARES_SVCB_PARAM_PORT: u32 = 3;
pub const ARES_SVCB_PARAM_IPV4HINT: u32 = 4;
pub const ARES_SVCB_PARAM_ECH: u32 = 5;
pub const ARES_SVCB_PARAM_IPV6HINT: u32 = 6;

pub const ARES_TLSA_USAGE_CA: u32 = 0;
pub const ARES_TLSA_USAGE_SERVICE: u32 = 1;
pub const ARES_TLSA_USAGE_TRUSTANCHOR: u32 = 2;
pub const ARES_TLSA_USAGE_DOMAIN: u32 = 3;
pub const ARES_TLSA_SELECTOR_FULL: u32 = 0;
pub const ARES_TLSA_SELECTOR_SUBJPUBKEYINFO: u32 = 1;
pub const ARES_TLSA_MATCH_EXACT: u32 = 0;
pub const ARES_TLSA_MATCH_SHA256: u32 = 1;
pub const ARES_TLSA_MATCH_SHA512: u32 = 2;

// RR keys: RECORD_TYPE * 100 + index (matches c-ares ares_dns_rr_key_t).
pub const ARES_RR_A_ADDR: u32 = 100 + 1;
pub const ARES_RR_NS_NSDNAME: u32 = 2 * 100 + 1;
pub const ARES_RR_CNAME_CNAME: u32 = 5 * 100 + 1;
pub const ARES_RR_SOA_MNAME: u32 = 6 * 100 + 1;
pub const ARES_RR_SOA_RNAME: u32 = 6 * 100 + 2;
pub const ARES_RR_SOA_SERIAL: u32 = 6 * 100 + 3;
pub const ARES_RR_SOA_REFRESH: u32 = 6 * 100 + 4;
pub const ARES_RR_SOA_RETRY: u32 = 6 * 100 + 5;
pub const ARES_RR_SOA_EXPIRE: u32 = 6 * 100 + 6;
pub const ARES_RR_SOA_MINIMUM: u32 = 6 * 100 + 7;
pub const ARES_RR_PTR_DNAME: u32 = 12 * 100 + 1;
pub const ARES_RR_HINFO_CPU: u32 = 13 * 100 + 1;
pub const ARES_RR_HINFO_OS: u32 = 13 * 100 + 2;
pub const ARES_RR_MX_PREFERENCE: u32 = 15 * 100 + 1;
pub const ARES_RR_MX_EXCHANGE: u32 = 15 * 100 + 2;
pub const ARES_RR_TXT_DATA: u32 = 16 * 100 + 1;
pub const ARES_RR_SIG_TYPE_COVERED: u32 = 24 * 100 + 1;
pub const ARES_RR_SIG_ALGORITHM: u32 = 24 * 100 + 2;
pub const ARES_RR_SIG_LABELS: u32 = 24 * 100 + 3;
pub const ARES_RR_SIG_ORIGINAL_TTL: u32 = 24 * 100 + 4;
pub const ARES_RR_SIG_EXPIRATION: u32 = 24 * 100 + 5;
pub const ARES_RR_SIG_INCEPTION: u32 = 24 * 100 + 6;
pub const ARES_RR_SIG_KEY_TAG: u32 = 24 * 100 + 7;
pub const ARES_RR_SIG_SIGNERS_NAME: u32 = 24 * 100 + 8;
pub const ARES_RR_SIG_SIGNATURE: u32 = 24 * 100 + 9;
pub const ARES_RR_AAAA_ADDR: u32 = 28 * 100 + 1;
pub const ARES_RR_SRV_PRIORITY: u32 = 33 * 100 + 2;
pub const ARES_RR_SRV_WEIGHT: u32 = 33 * 100 + 3;
pub const ARES_RR_SRV_PORT: u32 = 33 * 100 + 4;
pub const ARES_RR_SRV_TARGET: u32 = 33 * 100 + 5;
pub const ARES_RR_NAPTR_ORDER: u32 = 35 * 100 + 1;
pub const ARES_RR_NAPTR_PREFERENCE: u32 = 35 * 100 + 2;
pub const ARES_RR_NAPTR_FLAGS: u32 = 35 * 100 + 3;
pub const ARES_RR_NAPTR_SERVICES: u32 = 35 * 100 + 4;
pub const ARES_RR_NAPTR_REGEXP: u32 = 35 * 100 + 5;
pub const ARES_RR_NAPTR_REPLACEMENT: u32 = 35 * 100 + 6;
pub const ARES_RR_OPT_UDP_SIZE: u32 = 41 * 100 + 1;
pub const ARES_RR_OPT_VERSION: u32 = 41 * 100 + 3;
pub const ARES_RR_OPT_FLAGS: u32 = 41 * 100 + 4;
pub const ARES_RR_OPT_OPTIONS: u32 = 41 * 100 + 5;
pub const ARES_RR_TLSA_CERT_USAGE: u32 = 52 * 100 + 1;
pub const ARES_RR_TLSA_SELECTOR: u32 = 52 * 100 + 2;
pub const ARES_RR_TLSA_MATCH: u32 = 52 * 100 + 3;
pub const ARES_RR_TLSA_DATA: u32 = 52 * 100 + 4;
pub const ARES_RR_SVCB_PRIORITY: u32 = 64 * 100 + 1;
pub const ARES_RR_SVCB_TARGET: u32 = 64 * 100 + 2;
pub const ARES_RR_SVCB_PARAMS: u32 = 64 * 100 + 3;
pub const ARES_RR_HTTPS_PRIORITY: u32 = 65 * 100 + 1;
pub const ARES_RR_HTTPS_TARGET: u32 = 65 * 100 + 2;
pub const ARES_RR_HTTPS_PARAMS: u32 = 65 * 100 + 3;
pub const ARES_RR_URI_PRIORITY: u32 = 256 * 100 + 1;
pub const ARES_RR_URI_WEIGHT: u32 = 256 * 100 + 2;
pub const ARES_RR_URI_TARGET: u32 = 256 * 100 + 3;
pub const ARES_RR_CAA_CRITICAL: u32 = 257 * 100 + 1;
pub const ARES_RR_CAA_TAG: u32 = 257 * 100 + 2;
pub const ARES_RR_CAA_VALUE: u32 = 257 * 100 + 3;
pub const ARES_RR_RAW_RR_TYPE: u32 = 65536 * 100 + 1;
pub const ARES_RR_RAW_RR_DATA: u32 = 65536 * 100 + 2;

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_create(
    dnsrec: *mut *mut ares_dns_record_t,
    id: c_ushort,
    flags: c_ushort,
    opcode: c_uint,
    rcode: c_uint,
) -> crate::ffi::ares_status_t {
    if dnsrec.is_null() {
        return ARES_EFORMERR;
    }
    match ares_dns_record_t::create(id, flags, opcode, rcode) {
        Ok(rec) => {
            unsafe { *dnsrec = Box::into_raw(Box::new(rec)); }
            ARES_SUCCESS
        }
        Err(e) => e.code(),
    }
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
    match crate::core::dns_record::duplicate_record(unsafe { &*dnsrec }) {
        Some(rec) => Box::into_raw(Box::new(rec)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_id(
    dnsrec: *const ares_dns_record_t,
) -> c_ushort {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.id()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_flags(
    dnsrec: *const ares_dns_record_t,
) -> c_ushort {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.flags()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_opcode(
    dnsrec: *const ares_dns_record_t,
) -> crate::ffi::ares_dns_opcode_t {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.opcode() as crate::ffi::ares_dns_opcode_t
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_rcode(
    dnsrec: *const ares_dns_record_t,
) -> crate::ffi::ares_dns_rcode_t {
    if dnsrec.is_null() {
        return 0;
    }
    unsafe { &*dnsrec }.rcode() as crate::ffi::ares_dns_rcode_t
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_set_id(
    dnsrec: *mut ares_dns_record_t,
    id: c_ushort,
) -> crate::ffi::ares_bool_t {
    if dnsrec.is_null() {
        return ARES_FALSE;
    }
    unsafe { &mut *dnsrec }.set_id(id);
    ARES_TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_add(
    dnsrec: *mut ares_dns_record_t,
    name: *const c_char,
    qtype: c_uint,
    qclass: c_uint,
) -> c_int {
    if dnsrec.is_null() || name.is_null() {
        return ARES_EFORMERR;
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADRESP,
    };
    match unsafe { &mut *dnsrec }.query_add(name_str, qtype, qclass) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
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
        return ARES_EFORMERR;
    }
    let Some((q_name, q_type, q_class)) = (unsafe { &*dnsrec }).query_at(idx) else {
        return ARES_EFORMERR;
    };
    if !name.is_null() {
        unsafe { *name = q_name.as_ptr(); }
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
        return ARES_EFORMERR;
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADRESP,
    };
    match unsafe { &mut *dnsrec }.query_set_name(idx, name_str) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
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
    match unsafe { &mut *dnsrec }.query_set_type(idx, qtype) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

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
    if dnsrec.is_null() || name.is_null() || rr.is_null() {
        return ARES_EFORMERR;
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADRESP,
    };
    match unsafe { &mut *dnsrec }.rr_add(sect, name_str, rtype, rclass, ttl) {
        Ok(new_rr) => {
            unsafe { *rr = new_rr as *mut ares_dns_rr_t; }
            ARES_SUCCESS
        }
        Err(e) => e.code(),
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
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_name(
    rr: *const ares_dns_rr_t,
) -> *const c_char {
    if rr.is_null() {
        return std::ptr::null();
    }
    unsafe { &*rr }.name_cstr().as_ptr()
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
    let rr = unsafe { &*rr };
    if rr.refresh_v4(key) {
        // Cell<u32> is layout-identical to struct in_addr { u32 }.
        rr.cached_v4.as_ptr() as *const libc::in_addr
    } else {
        std::ptr::null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_addr6(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> *const crate::ffi::ares_in6_addr {
    if rr.is_null() {
        return std::ptr::null();
    }
    let rr = unsafe { &*rr };
    if rr.refresh_v6(key) {
        // Cell<[u8; 16]> is layout-identical to struct ares_in6_addr.
        rr.cached_v6.as_ptr() as *const crate::ffi::ares_in6_addr
    } else {
        std::ptr::null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_str(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> *const c_char {
    if rr.is_null() {
        return std::ptr::null();
    }
    unsafe { &*rr }.str_val(key).map(|s| s.as_ptr()).unwrap_or(std::ptr::null())
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
    if !len.is_null() {
        unsafe { *len = 0; }
    }
    if rr.is_null() {
        return std::ptr::null();
    }
    let Some((ptr, logical_len)) = (unsafe { &*rr }).bin_checked(key) else {
        return std::ptr::null();
    };
    if !len.is_null() {
        unsafe { *len = logical_len; }
    }
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_addr(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    addr: *const libc::in_addr,
) -> c_int {
    if rr.is_null() || addr.is_null() {
        return ARES_EFORMERR;
    }
    let octets = (unsafe { &*addr }).s_addr.to_ne_bytes();
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    match unsafe { &mut *rr }.set_addr_checked(key, ip) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_addr6(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    addr: *const crate::ffi::ares_in6_addr,
) -> c_int {
    if rr.is_null() || addr.is_null() {
        return ARES_EFORMERR;
    }
    let ip = unsafe { Ipv6Addr::from((*addr)._S6_un._S6_u8) };
    match unsafe { &mut *rr }.set_addr6_checked(key, ip) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_str(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: *const c_char,
) -> c_int {
    if rr.is_null() || val.is_null() {
        return ARES_EFORMERR;
    }
    let owned = CString::from(unsafe { CStr::from_ptr(val) });
    match unsafe { &mut *rr }.set_str_checked(key, owned) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_u8(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: u8,
) -> c_int {
    if rr.is_null() {
        return ARES_EFORMERR;
    }
    match unsafe { &mut *rr }.set_u8_checked(key, val) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_u16(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: u16,
) -> c_int {
    if rr.is_null() {
        return ARES_EFORMERR;
    }
    match unsafe { &mut *rr }.set_u16_checked(key, val) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_u32(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: u32,
) -> c_int {
    if rr.is_null() {
        return ARES_EFORMERR;
    }
    match unsafe { &mut *rr }.set_u32_checked(key, val) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_bin(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: *const u8,
    len: libc::size_t,
) -> c_int {
    if rr.is_null() || (val.is_null() && len != 0) {
        return ARES_EFORMERR;
    }
    // Copied out first: `val` may point into this RR's own ABINP cache
    // (get_bin -> set_bin), which the setter frees; no borrow of it may be live
    // across that call.
    let data: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(val, len) }.to_vec()
    };
    match unsafe { &mut *rr }.set_bin_checked(key, &data) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_opt(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
    val: *const u8,
    val_len: libc::size_t,
) -> c_int {
    if rr.is_null() {
        return ARES_EFORMERR;
    }
    let data = if val.is_null() || val_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(val, val_len) }.to_vec()
    };
    match unsafe { &mut *rr }.set_opt_checked(key, opt as u16, data) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_opt_cnt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> libc::size_t {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.opt_cnt_checked(key)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_opt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    idx: libc::size_t,
    val: *mut *const u8,
    val_len: *mut libc::size_t,
) -> c_ushort {
    // ABI-mandated sentinel: 65535 means "misuse / not found".
    const NO_OPT: c_ushort = u16::MAX;
    // Clear optional outputs on every path so callers never see stale data after a miss.
    if !val.is_null() {
        unsafe { *val = std::ptr::null(); }
    }
    if !val_len.is_null() {
        unsafe { *val_len = 0; }
    }
    if rr.is_null() {
        return NO_OPT;
    }
    let Some((code, data)) = (unsafe { &*rr }).opt_at_checked(key, idx) else {
        return NO_OPT;
    };
    if !val.is_null() {
        unsafe { *val = data.as_ptr(); }
    }
    if !val_len.is_null() {
        unsafe { *val_len = data.len(); }
    }
    code
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_opt_byid(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
    val: *mut *const u8,
    val_len: *mut libc::size_t,
) -> c_int {
    if !val.is_null() {
        unsafe { *val = std::ptr::null(); }
    }
    if !val_len.is_null() {
        unsafe { *val_len = 0; }
    }
    if rr.is_null() {
        return ARES_FALSE;
    }
    let Some(data) = (unsafe { &*rr }).opt_by_id_checked(key, opt as u16) else {
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
pub unsafe extern "C" fn ares_dns_rr_del_opt_byid(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
) -> c_int {
    if rr.is_null() {
        return ARES_EFORMERR;
    }
    match unsafe { &mut *rr }.del_opt_byid_checked(key, opt as u16) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_parse(
    buf: *const u8,
    buf_len: libc::size_t,
    flags: c_uint,
    dnsrec: *mut *mut ares_dns_record_t,
) -> c_int {
    if buf.is_null() || dnsrec.is_null() || buf_len == 0 || buf_len > 0xFFFF {
        return ARES_EFORMERR;
    }
    let data = unsafe { std::slice::from_raw_parts(buf, buf_len) };
    match parse_record(data, flags) {
        Ok(rec) => {
            unsafe { *dnsrec = Box::into_raw(Box::new(rec)); }
            ARES_SUCCESS
        }
        Err(e) => e.code(),
    }
}

fn dns_write_impl(
    rec: &ares_dns_record_t,
    buf: *mut *mut u8,
    buf_len: *mut libc::size_t,
) -> c_int {
    if buf.is_null() || buf_len.is_null() {
        return ARES_EFORMERR;
    }
    unsafe { *buf = std::ptr::null_mut(); }
    unsafe { *buf_len = 0; }
    let out = match write_record(rec) {
        Ok(out) => out,
        Err(e) => return e.code(),
    };
    let ptr = unsafe { malloc_bytes(&out) };
    if ptr.is_null() {
        return ARES_ENOMEM;
    }
    unsafe { *buf = ptr; }
    unsafe { *buf_len = out.len(); }
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_write(
    dnsrec: *const ares_dns_record_t,
    buf: *mut *mut u8,
    buf_len: *mut libc::size_t,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EFORMERR;
    }
    dns_write_impl(unsafe { &*dnsrec }, buf, buf_len)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rec_type_tostr(rtype: c_uint) -> *const c_char {
    crate::core::dns_record::rec_type_name(rtype).as_ptr()
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
    match crate::core::dns_record::rec_type_from_name(s) {
        Some(val) => {
            unsafe { *rtype = val };
            ARES_TRUE
        }
        None => ARES_FALSE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_class_tostr(qclass: c_uint) -> *const c_char {
    crate::core::dns_record::class_name(qclass).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_class_fromstr(
    qclass: *mut crate::ffi::ares_dns_class_t,
    str_ptr: *const c_char,
) -> crate::ffi::ares_bool_t {
    if str_ptr.is_null() || qclass.is_null() {
        return ARES_FALSE;
    }
    let s = match unsafe { CStr::from_ptr(str_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_FALSE,
    };
    match crate::core::dns_record::class_from_name(s) {
        Some(val) => {
            unsafe { *qclass = val };
            ARES_TRUE
        }
        None => ARES_FALSE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_pton(
    ipaddr: *const c_char,
    addr: *mut crate::ffi::ares_addr,
    out_len: *mut libc::size_t,
) -> *const c_void {
    if ipaddr.is_null() || addr.is_null() || out_len.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the caller guarantees valid input pointer and a writable ares_addr.
    let parsed = unsafe { CStr::from_ptr(ipaddr) }
        .to_str()
        .ok()
        .and_then(|s| crate::core::dns_record::dns_pton(s, unsafe { (*addr).family }));
    let Some((new_family, parsed)) = parsed else {
        unsafe { *out_len = 0; }
        return std::ptr::null();
    };
    // SAFETY: `addr`/`out_len` are non-NULL and writable per the C contract.
    unsafe {
        (*addr).family = new_family;
        *out_len = parsed.len();
        match &parsed {
            crate::core::dns_record::PtonAddr::V4(octets) => {
                (*addr).addr.addr4 = libc::in_addr { s_addr: u32::from_ne_bytes(*octets) };
                &(*addr).addr.addr4 as *const _ as *const c_void
            }
            crate::core::dns_record::PtonAddr::V6(octets) => {
                (*addr).addr.addr6 = crate::ffi::ares_in6_addr::from_octets(*octets);
                &(*addr).addr.addr6 as *const _ as *const c_void
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_addr_to_ptr(
    addr: *const crate::ffi::ares_addr,
) -> *mut c_char {
    if addr.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `addr` is a valid, initialized ares_addr per the C contract.
    let family = unsafe { (*addr).family };
    let ptr = match family {
        libc::AF_INET => crate::core::dns_record::addr_to_ptr_v4(
            unsafe { (*addr).addr.addr4.s_addr.to_ne_bytes() },
        ),
        libc::AF_INET6 => crate::core::dns_record::addr_to_ptr_v6(
            unsafe { (*addr).addr.addr6._S6_un._S6_u8 },
        ),
        _ => return std::ptr::null_mut(),
    };
    // The PTR string never contains an interior NUL; NULL signals OOM.
    unsafe { malloc_cstr(ptr.as_bytes()) }
}

#[no_mangle]
pub extern "C" fn ares_dns_opt_get_datatype(
    key: crate::ffi::ares_dns_rr_key_t,
    opt: c_ushort,
) -> crate::ffi::ares_dns_opt_datatype_t {
    crate::core::dns_record::opt_datatype(key, opt)
}

#[no_mangle]
pub extern "C" fn ares_dns_opt_get_name(
    key: crate::ffi::ares_dns_rr_key_t,
    opt: c_ushort,
) -> *const c_char {
    match crate::core::dns_record::opt_name(key, opt) {
        Some(name) => name.as_ptr(),
        None => std::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_tostr(key: c_uint) -> *const c_char {
    crate::core::dns_record::rr_key_name(key).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_keys(
    rtype: c_uint,
    cnt: *mut libc::size_t,
) -> *const c_uint {
    if cnt.is_null() {
        return std::ptr::null();
    }
    match crate::core::dns_record::keys_for(rtype) {
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
    crate::core::dns_record::rr_key_datatype_of(key)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_to_rec_type(key: c_uint) -> c_uint {
    crate::core::dns_record::rr_key_rec_type(key)
}

#[no_mangle]
pub extern "C" fn ares_dns_opcode_tostr(opcode: c_uint) -> *const c_char {
    crate::core::dns_record::opcode_name(opcode).as_ptr()
}

#[no_mangle]
pub extern "C" fn ares_dns_rcode_tostr(rcode: c_uint) -> *const c_char {
    crate::core::dns_record::rcode_name(rcode).as_ptr()
}

#[no_mangle]
pub extern "C" fn ares_dns_section_tostr(section: c_uint) -> *const c_char {
    crate::core::dns_record::section_name(section).as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_abin_cnt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> libc::size_t {
    if rr.is_null() {
        return 0;
    }
    unsafe { &*rr }.abin_count_checked(key)
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_abin(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    idx: libc::size_t,
    len: *mut libc::size_t,
) -> *const u8 {
    if rr.is_null() || len.is_null() {
        return std::ptr::null();
    }
    match unsafe { &*rr }.abin_at_checked(key, idx) {
        Some(data) => {
            unsafe { *len = data.len(); }
            data.as_ptr()
        }
        None => std::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_add_abin(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: *const u8,
    len: libc::size_t,
) -> crate::ffi::ares_status_t {
    if rr.is_null() || (val.is_null() && len != 0) {
        return ARES_EFORMERR;
    }
    // Copied out first (see ares_dns_rr_set_bin): `val` may alias this RR's cache.
    let data: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        // SAFETY: `val` points to `len` readable bytes per the C contract.
        unsafe { std::slice::from_raw_parts(val, len) }.to_vec()
    };
    match unsafe { &mut *rr }.add_abin_checked(key, &data) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_del_abin(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    idx: libc::size_t,
) -> crate::ffi::ares_status_t {
    if rr.is_null() {
        return ARES_EFORMERR;
    }
    match unsafe { &mut *rr }.del_abin_checked(key, idx) {
        Ok(()) => ARES_SUCCESS,
        Err(e) => e.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { libc::free(ptr) };
    }
}

