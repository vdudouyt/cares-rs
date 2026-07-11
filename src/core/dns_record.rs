//! DNS-record metadata and wire-name helpers: the pure string/key tables of
//! the ares_dns_* metadata surface and the compression-aware name codec.
//! (The record model itself joins this module as the codec split completes.)

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::core::AresError;
use crate::ffi::error::ARES_EBADRESP;

use crate::ffi::dns_record::{
    ARES_SECTION_ADDITIONAL, ARES_SECTION_ANSWER, ARES_SECTION_AUTHORITY,
    ARES_CLASS_ANY, ARES_CLASS_CHAOS, ARES_CLASS_HESOID, ARES_CLASS_IN, ARES_CLASS_NONE,
    ARES_DATATYPE_ABINP, ARES_DATATYPE_BIN, ARES_DATATYPE_BINP, ARES_DATATYPE_INADDR,
    ARES_DATATYPE_INADDR6, ARES_DATATYPE_NAME, ARES_DATATYPE_OPT, ARES_DATATYPE_STR,
    ARES_DATATYPE_U16, ARES_DATATYPE_U32, ARES_DATATYPE_U8, ARES_REC_TYPE_A, ARES_REC_TYPE_AAAA,
    ARES_REC_TYPE_ANY, ARES_REC_TYPE_CAA, ARES_REC_TYPE_CNAME, ARES_REC_TYPE_HINFO,
    ARES_REC_TYPE_HTTPS, ARES_REC_TYPE_MX, ARES_REC_TYPE_NAPTR, ARES_REC_TYPE_NS,
    ARES_REC_TYPE_OPT, ARES_REC_TYPE_PTR, ARES_REC_TYPE_RAW_RR, ARES_REC_TYPE_SOA,
    ARES_REC_TYPE_SRV, ARES_REC_TYPE_SVCB, ARES_REC_TYPE_TLSA, ARES_REC_TYPE_TXT,
    ARES_REC_TYPE_URI, ARES_RR_AAAA_ADDR, ARES_RR_A_ADDR, ARES_RR_CAA_CRITICAL, ARES_RR_CAA_TAG,
    ARES_RR_CAA_VALUE, ARES_RR_CNAME_CNAME, ARES_RR_HINFO_CPU, ARES_RR_HINFO_OS,
    ARES_RR_HTTPS_PARAMS, ARES_RR_HTTPS_PRIORITY, ARES_RR_HTTPS_TARGET, ARES_RR_MX_EXCHANGE,
    ARES_RR_MX_PREFERENCE, ARES_RR_NAPTR_FLAGS, ARES_RR_NAPTR_ORDER, ARES_RR_NAPTR_PREFERENCE,
    ARES_RR_NAPTR_REGEXP, ARES_RR_NAPTR_REPLACEMENT, ARES_RR_NAPTR_SERVICES, ARES_RR_NS_NSDNAME,
    ARES_RR_OPT_FLAGS, ARES_RR_OPT_OPTIONS, ARES_RR_OPT_UDP_SIZE, ARES_RR_OPT_VERSION,
    ARES_RR_PTR_DNAME, ARES_RR_RAW_RR_DATA, ARES_RR_RAW_RR_TYPE, ARES_RR_SOA_EXPIRE,
    ARES_RR_SOA_MINIMUM, ARES_RR_SOA_MNAME, ARES_RR_SOA_REFRESH, ARES_RR_SOA_RETRY,
    ARES_RR_SOA_RNAME, ARES_RR_SOA_SERIAL, ARES_RR_SRV_PORT, ARES_RR_SRV_PRIORITY,
    ARES_RR_SRV_TARGET, ARES_RR_SRV_WEIGHT, ARES_RR_SVCB_PARAMS, ARES_RR_SVCB_PRIORITY,
    ARES_RR_SVCB_TARGET, ARES_RR_TLSA_CERT_USAGE, ARES_RR_TLSA_DATA, ARES_RR_TLSA_MATCH,
    ARES_RR_TLSA_SELECTOR, ARES_RR_TXT_DATA, ARES_RR_URI_PRIORITY, ARES_RR_URI_TARGET,
    ARES_RR_URI_WEIGHT,
};

/// Read a DNS name from wire format, handling label compression.
/// Returns the name as a dotted string, advancing `pos` past the name bytes.
pub(crate) fn parse_dns_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = *pos;
    let mut jumped = false;
    let mut end_pos = *pos;

    loop {
        if cur >= buf.len() {
            return None;
        }
        let len_byte = buf[cur];
        if len_byte == 0 {
            if !jumped {
                end_pos = cur + 1;
            }
            break;
        }
        if (len_byte & 0xC0) == 0xC0 {
            // compression pointer
            if cur + 1 >= buf.len() {
                return None;
            }
            let offset = (((len_byte & 0x3F) as usize) << 8) | (buf[cur + 1] as usize);
            // A compression pointer must reference strictly-earlier data (RFC 1035
            // §4.1.4). Enforcing offset < cur makes `cur` strictly decrease on every
            // jump, so the loop always terminates — this rejects self-referential and
            // forward/cyclic pointers that would otherwise spin forever (DoS).
            if offset >= cur {
                return None;
            }
            if !jumped {
                end_pos = cur + 2;
            }
            jumped = true;
            cur = offset;
            continue;
        }
        let label_len = len_byte as usize;
        cur += 1;
        if cur + label_len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[cur..cur + label_len]).ok()?;
        parts.push(label.to_string());
        cur += label_len;
    }

    *pos = end_pos;
    Some(parts.join("."))
}

/// Write a DNS name in wire format (uncompressed labels).
pub(crate) fn write_dns_name(name: &str, out: &mut Vec<u8>) {
    if !name.is_empty() {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0); // root label terminator
}


pub(crate) static KEYS_A: [u32; 1] = [ARES_RR_A_ADDR];
pub(crate) static KEYS_NS: [u32; 1] = [ARES_RR_NS_NSDNAME];
pub(crate) static KEYS_CNAME: [u32; 1] = [ARES_RR_CNAME_CNAME];
pub(crate) static KEYS_SOA: [u32; 7] = [
    ARES_RR_SOA_MNAME,
    ARES_RR_SOA_RNAME,
    ARES_RR_SOA_SERIAL,
    ARES_RR_SOA_REFRESH,
    ARES_RR_SOA_RETRY,
    ARES_RR_SOA_EXPIRE,
    ARES_RR_SOA_MINIMUM,
];
pub(crate) static KEYS_PTR: [u32; 1] = [ARES_RR_PTR_DNAME];
pub(crate) static KEYS_HINFO: [u32; 2] =
    [ARES_RR_HINFO_CPU, ARES_RR_HINFO_OS];
pub(crate) static KEYS_MX: [u32; 2] = [
    ARES_RR_MX_PREFERENCE,
    ARES_RR_MX_EXCHANGE,
];
pub(crate) static KEYS_TXT: [u32; 1] = [ARES_RR_TXT_DATA];
pub(crate) static KEYS_AAAA: [u32; 1] = [ARES_RR_AAAA_ADDR];
pub(crate) static KEYS_SRV: [u32; 4] = [
    ARES_RR_SRV_PRIORITY,
    ARES_RR_SRV_WEIGHT,
    ARES_RR_SRV_PORT,
    ARES_RR_SRV_TARGET,
];
pub(crate) static KEYS_NAPTR: [u32; 6] = [
    ARES_RR_NAPTR_ORDER,
    ARES_RR_NAPTR_PREFERENCE,
    ARES_RR_NAPTR_FLAGS,
    ARES_RR_NAPTR_SERVICES,
    ARES_RR_NAPTR_REGEXP,
    ARES_RR_NAPTR_REPLACEMENT,
];
pub(crate) static KEYS_OPT: [u32; 4] = [
    ARES_RR_OPT_UDP_SIZE,
    ARES_RR_OPT_VERSION,
    ARES_RR_OPT_FLAGS,
    ARES_RR_OPT_OPTIONS,
];
pub(crate) static KEYS_TLSA: [u32; 4] = [
    ARES_RR_TLSA_CERT_USAGE,
    ARES_RR_TLSA_SELECTOR,
    ARES_RR_TLSA_MATCH,
    ARES_RR_TLSA_DATA,
];
pub(crate) static KEYS_SVCB: [u32; 3] = [
    ARES_RR_SVCB_PRIORITY,
    ARES_RR_SVCB_TARGET,
    ARES_RR_SVCB_PARAMS,
];
pub(crate) static KEYS_HTTPS: [u32; 3] = [
    ARES_RR_HTTPS_PRIORITY,
    ARES_RR_HTTPS_TARGET,
    ARES_RR_HTTPS_PARAMS,
];
pub(crate) static KEYS_URI: [u32; 3] = [
    ARES_RR_URI_PRIORITY,
    ARES_RR_URI_WEIGHT,
    ARES_RR_URI_TARGET,
];
pub(crate) static KEYS_CAA: [u32; 3] = [
    ARES_RR_CAA_CRITICAL,
    ARES_RR_CAA_TAG,
    ARES_RR_CAA_VALUE,
];
pub(crate) static KEYS_RAW_RR: [u32; 2] =
    [ARES_RR_RAW_RR_TYPE, ARES_RR_RAW_RR_DATA];


// ---------------------------------------------------------------------------
// Metadata string/table logic (the pure bodies of the ares_dns_* metadata
// shims — each shim is one call into here)
// ---------------------------------------------------------------------------

pub(crate) fn rec_type_name(rtype: u32) -> &'static CStr {
    match rtype {
        1 => c"A",
        2 => c"NS",
        5 => c"CNAME",
        6 => c"SOA",
        12 => c"PTR",
        13 => c"HINFO",
        15 => c"MX",
        16 => c"TXT",
        28 => c"AAAA",
        33 => c"SRV",
        35 => c"NAPTR",
        41 => c"OPT",
        52 => c"TLSA",
        64 => c"SVCB",
        65 => c"HTTPS",
        255 => c"ANY",
        256 => c"URI",
        257 => c"CAA",
        65536 => c"RAW_RR",
        _ => c"",
    }
}

pub(crate) fn rec_type_from_name(s: &str) -> Option<u32> {
    Some(match s {
        "A" => ARES_REC_TYPE_A as u32,
        "NS" => ARES_REC_TYPE_NS as u32,
        "CNAME" => ARES_REC_TYPE_CNAME as u32,
        "SOA" => ARES_REC_TYPE_SOA as u32,
        "PTR" => ARES_REC_TYPE_PTR as u32,
        "HINFO" => ARES_REC_TYPE_HINFO as u32,
        "MX" => ARES_REC_TYPE_MX as u32,
        "TXT" => ARES_REC_TYPE_TXT as u32,
        "AAAA" => ARES_REC_TYPE_AAAA as u32,
        "SRV" => ARES_REC_TYPE_SRV as u32,
        "NAPTR" => ARES_REC_TYPE_NAPTR as u32,
        "OPT" => ARES_REC_TYPE_OPT as u32,
        "TLSA" => ARES_REC_TYPE_TLSA as u32,
        "SVCB" => ARES_REC_TYPE_SVCB as u32,
        "HTTPS" => ARES_REC_TYPE_HTTPS as u32,
        "ANY" => ARES_REC_TYPE_ANY as u32,
        "URI" => ARES_REC_TYPE_URI as u32,
        "CAA" => ARES_REC_TYPE_CAA as u32,
        "RAW_RR" => ARES_REC_TYPE_RAW_RR,
        _ => return None,
    })
}

pub(crate) fn class_name(qclass: u32) -> &'static CStr {
    match qclass as u16 {
        ARES_CLASS_IN => c"IN",
        ARES_CLASS_CHAOS => c"CH",
        ARES_CLASS_HESOID => c"HS",
        ARES_CLASS_NONE => c"NONE",
        ARES_CLASS_ANY => c"ANY",
        _ => c"",
    }
}

pub(crate) fn class_from_name(s: &str) -> Option<u32> {
    Some(match s {
        "IN" => ARES_CLASS_IN as u32,
        "CH" => ARES_CLASS_CHAOS as u32,
        "HS" => ARES_CLASS_HESOID as u32,
        "NONE" => ARES_CLASS_NONE as u32,
        "ANY" => ARES_CLASS_ANY as u32,
        _ => return None,
    })
}

pub(crate) fn rr_key_name(key: u32) -> &'static CStr {
    match key {
        ARES_RR_A_ADDR => c"A.ADDR",
        ARES_RR_NS_NSDNAME => c"NS.NSDNAME",
        ARES_RR_CNAME_CNAME => c"CNAME.CNAME",
        ARES_RR_SOA_MNAME => c"SOA.MNAME",
        ARES_RR_SOA_RNAME => c"SOA.RNAME",
        ARES_RR_SOA_SERIAL => c"SOA.SERIAL",
        ARES_RR_SOA_REFRESH => c"SOA.REFRESH",
        ARES_RR_SOA_RETRY => c"SOA.RETRY",
        ARES_RR_SOA_EXPIRE => c"SOA.EXPIRE",
        ARES_RR_SOA_MINIMUM => c"SOA.MINIMUM",
        ARES_RR_PTR_DNAME => c"PTR.DNAME",
        ARES_RR_HINFO_CPU => c"HINFO.CPU",
        ARES_RR_HINFO_OS => c"HINFO.OS",
        ARES_RR_MX_PREFERENCE => c"MX.PREFERENCE",
        ARES_RR_MX_EXCHANGE => c"MX.EXCHANGE",
        ARES_RR_TXT_DATA => c"TXT.DATA",
        ARES_RR_AAAA_ADDR => c"AAAA.ADDR",
        ARES_RR_SRV_PRIORITY => c"SRV.PRIORITY",
        ARES_RR_SRV_WEIGHT => c"SRV.WEIGHT",
        ARES_RR_SRV_PORT => c"SRV.PORT",
        ARES_RR_SRV_TARGET => c"SRV.TARGET",
        ARES_RR_NAPTR_ORDER => c"NAPTR.ORDER",
        ARES_RR_NAPTR_PREFERENCE => c"NAPTR.PREFERENCE",
        ARES_RR_NAPTR_FLAGS => c"NAPTR.FLAGS",
        ARES_RR_NAPTR_SERVICES => c"NAPTR.SERVICES",
        ARES_RR_NAPTR_REGEXP => c"NAPTR.REGEXP",
        ARES_RR_NAPTR_REPLACEMENT => c"NAPTR.REPLACEMENT",
        ARES_RR_OPT_UDP_SIZE => c"OPT.UDP_SIZE",
        ARES_RR_OPT_VERSION => c"OPT.VERSION",
        ARES_RR_OPT_FLAGS => c"OPT.FLAGS",
        ARES_RR_OPT_OPTIONS => c"OPT.OPTIONS",
        ARES_RR_TLSA_CERT_USAGE => c"TLSA.CERT_USAGE",
        ARES_RR_TLSA_SELECTOR => c"TLSA.SELECTOR",
        ARES_RR_TLSA_MATCH => c"TLSA.MATCH",
        ARES_RR_TLSA_DATA => c"TLSA.DATA",
        ARES_RR_SVCB_PRIORITY => c"SVCB.PRIORITY",
        ARES_RR_SVCB_TARGET => c"SVCB.TARGET",
        ARES_RR_SVCB_PARAMS => c"SVCB.PARAMS",
        ARES_RR_HTTPS_PRIORITY => c"HTTPS.PRIORITY",
        ARES_RR_HTTPS_TARGET => c"HTTPS.TARGET",
        ARES_RR_HTTPS_PARAMS => c"HTTPS.PARAMS",
        ARES_RR_URI_PRIORITY => c"URI.PRIORITY",
        ARES_RR_URI_WEIGHT => c"URI.WEIGHT",
        ARES_RR_URI_TARGET => c"URI.TARGET",
        ARES_RR_CAA_CRITICAL => c"CAA.CRITICAL",
        ARES_RR_CAA_TAG => c"CAA.TAG",
        ARES_RR_CAA_VALUE => c"CAA.VALUE",
        ARES_RR_RAW_RR_TYPE => c"RAW_RR.TYPE",
        ARES_RR_RAW_RR_DATA => c"RAW_RR.DATA",
        _ => c"",
    }
}

pub(crate) fn keys_for(rtype: u32) -> Option<&'static [u32]> {
    Some(match rtype {
        1 => &KEYS_A,
        2 => &KEYS_NS,
        5 => &KEYS_CNAME,
        6 => &KEYS_SOA,
        12 => &KEYS_PTR,
        13 => &KEYS_HINFO,
        15 => &KEYS_MX,
        16 => &KEYS_TXT,
        28 => &KEYS_AAAA,
        33 => &KEYS_SRV,
        35 => &KEYS_NAPTR,
        41 => &KEYS_OPT,
        52 => &KEYS_TLSA,
        64 => &KEYS_SVCB,
        65 => &KEYS_HTTPS,
        256 => &KEYS_URI,
        257 => &KEYS_CAA,
        65536 => &KEYS_RAW_RR,
        _ => return None,
    })
}

pub(crate) fn rr_key_datatype_of(key: u32) -> u32 {
    match key {
        ARES_RR_A_ADDR => ARES_DATATYPE_INADDR as u32,
        ARES_RR_NS_NSDNAME => ARES_DATATYPE_NAME as u32,
        ARES_RR_CNAME_CNAME => ARES_DATATYPE_NAME as u32,
        ARES_RR_SOA_MNAME => ARES_DATATYPE_NAME as u32,
        ARES_RR_SOA_RNAME => ARES_DATATYPE_NAME as u32,
        ARES_RR_SOA_SERIAL => ARES_DATATYPE_U32 as u32,
        ARES_RR_SOA_REFRESH => ARES_DATATYPE_U32 as u32,
        ARES_RR_SOA_RETRY => ARES_DATATYPE_U32 as u32,
        ARES_RR_SOA_EXPIRE => ARES_DATATYPE_U32 as u32,
        ARES_RR_SOA_MINIMUM => ARES_DATATYPE_U32 as u32,
        ARES_RR_PTR_DNAME => ARES_DATATYPE_NAME as u32,
        ARES_RR_HINFO_CPU => ARES_DATATYPE_STR as u32,
        ARES_RR_HINFO_OS => ARES_DATATYPE_STR as u32,
        ARES_RR_MX_PREFERENCE => ARES_DATATYPE_U16 as u32,
        ARES_RR_MX_EXCHANGE => ARES_DATATYPE_NAME as u32,
        ARES_RR_TXT_DATA => ARES_DATATYPE_ABINP as u32,
        ARES_RR_AAAA_ADDR => ARES_DATATYPE_INADDR6 as u32,
        ARES_RR_SRV_PRIORITY => ARES_DATATYPE_U16 as u32,
        ARES_RR_SRV_WEIGHT => ARES_DATATYPE_U16 as u32,
        ARES_RR_SRV_PORT => ARES_DATATYPE_U16 as u32,
        ARES_RR_SRV_TARGET => ARES_DATATYPE_NAME as u32,
        ARES_RR_NAPTR_ORDER => ARES_DATATYPE_U16 as u32,
        ARES_RR_NAPTR_PREFERENCE => ARES_DATATYPE_U16 as u32,
        ARES_RR_NAPTR_FLAGS => ARES_DATATYPE_STR as u32,
        ARES_RR_NAPTR_SERVICES => ARES_DATATYPE_STR as u32,
        ARES_RR_NAPTR_REGEXP => ARES_DATATYPE_STR as u32,
        ARES_RR_NAPTR_REPLACEMENT => ARES_DATATYPE_NAME as u32,
        ARES_RR_OPT_UDP_SIZE => ARES_DATATYPE_U16 as u32,
        ARES_RR_OPT_VERSION => ARES_DATATYPE_U8 as u32,
        ARES_RR_OPT_FLAGS => ARES_DATATYPE_U16 as u32,
        ARES_RR_OPT_OPTIONS => ARES_DATATYPE_OPT as u32,
        ARES_RR_TLSA_CERT_USAGE => ARES_DATATYPE_U8 as u32,
        ARES_RR_TLSA_SELECTOR => ARES_DATATYPE_U8 as u32,
        ARES_RR_TLSA_MATCH => ARES_DATATYPE_U8 as u32,
        ARES_RR_TLSA_DATA => ARES_DATATYPE_BIN as u32,
        ARES_RR_SVCB_PRIORITY => ARES_DATATYPE_U16 as u32,
        ARES_RR_SVCB_TARGET => ARES_DATATYPE_NAME as u32,
        ARES_RR_SVCB_PARAMS => ARES_DATATYPE_OPT as u32,
        ARES_RR_HTTPS_PRIORITY => ARES_DATATYPE_U16 as u32,
        ARES_RR_HTTPS_TARGET => ARES_DATATYPE_NAME as u32,
        ARES_RR_HTTPS_PARAMS => ARES_DATATYPE_OPT as u32,
        ARES_RR_URI_PRIORITY => ARES_DATATYPE_U16 as u32,
        ARES_RR_URI_WEIGHT => ARES_DATATYPE_U16 as u32,
        ARES_RR_URI_TARGET => ARES_DATATYPE_STR as u32,
        ARES_RR_CAA_CRITICAL => ARES_DATATYPE_U8 as u32,
        ARES_RR_CAA_TAG => ARES_DATATYPE_STR as u32,
        ARES_RR_CAA_VALUE => ARES_DATATYPE_BINP as u32,
        ARES_RR_RAW_RR_TYPE => ARES_DATATYPE_U16 as u32,
        ARES_RR_RAW_RR_DATA => ARES_DATATYPE_BIN as u32,
        _ => 0,
    }
}

pub(crate) fn rr_key_rec_type(key: u32) -> u32 {
    match key {
        ARES_RR_A_ADDR => ARES_REC_TYPE_A as u32,
        ARES_RR_NS_NSDNAME => ARES_REC_TYPE_NS as u32,
        ARES_RR_CNAME_CNAME => ARES_REC_TYPE_CNAME as u32,
        ARES_RR_SOA_MNAME | ARES_RR_SOA_RNAME | ARES_RR_SOA_SERIAL
        | ARES_RR_SOA_REFRESH | ARES_RR_SOA_RETRY | ARES_RR_SOA_EXPIRE
        | ARES_RR_SOA_MINIMUM => ARES_REC_TYPE_SOA as u32,
        ARES_RR_PTR_DNAME => ARES_REC_TYPE_PTR as u32,
        ARES_RR_HINFO_CPU | ARES_RR_HINFO_OS => ARES_REC_TYPE_HINFO as u32,
        ARES_RR_MX_PREFERENCE | ARES_RR_MX_EXCHANGE => ARES_REC_TYPE_MX as u32,
        ARES_RR_TXT_DATA => ARES_REC_TYPE_TXT as u32,
        ARES_RR_AAAA_ADDR => ARES_REC_TYPE_AAAA as u32,
        ARES_RR_SRV_PRIORITY | ARES_RR_SRV_WEIGHT | ARES_RR_SRV_PORT
        | ARES_RR_SRV_TARGET => ARES_REC_TYPE_SRV as u32,
        ARES_RR_NAPTR_ORDER | ARES_RR_NAPTR_PREFERENCE | ARES_RR_NAPTR_FLAGS
        | ARES_RR_NAPTR_SERVICES | ARES_RR_NAPTR_REGEXP
        | ARES_RR_NAPTR_REPLACEMENT => ARES_REC_TYPE_NAPTR as u32,
        ARES_RR_OPT_UDP_SIZE | ARES_RR_OPT_VERSION | ARES_RR_OPT_FLAGS
        | ARES_RR_OPT_OPTIONS => ARES_REC_TYPE_OPT as u32,
        ARES_RR_TLSA_CERT_USAGE | ARES_RR_TLSA_SELECTOR | ARES_RR_TLSA_MATCH
        | ARES_RR_TLSA_DATA => ARES_REC_TYPE_TLSA as u32,
        ARES_RR_SVCB_PRIORITY | ARES_RR_SVCB_TARGET | ARES_RR_SVCB_PARAMS => {
            ARES_REC_TYPE_SVCB as u32
        }
        ARES_RR_HTTPS_PRIORITY | ARES_RR_HTTPS_TARGET | ARES_RR_HTTPS_PARAMS => {
            ARES_REC_TYPE_HTTPS as u32
        }
        ARES_RR_URI_PRIORITY | ARES_RR_URI_WEIGHT | ARES_RR_URI_TARGET => {
            ARES_REC_TYPE_URI as u32
        }
        ARES_RR_CAA_CRITICAL | ARES_RR_CAA_TAG | ARES_RR_CAA_VALUE => {
            ARES_REC_TYPE_CAA as u32
        }
        ARES_RR_RAW_RR_TYPE | ARES_RR_RAW_RR_DATA => ARES_REC_TYPE_RAW_RR,
        _ => 0,
    }
}

pub(crate) fn opcode_name(opcode: u32) -> &'static CStr {
    match opcode {
        0 => c"QUERY",
        1 => c"IQUERY",
        2 => c"STATUS",
        4 => c"NOTIFY",
        5 => c"UPDATE",
        _ => c"UNKNOWN",
    }
}

pub(crate) fn rcode_name(rcode: u32) -> &'static CStr {
    match rcode {
        0 => c"NOERROR",
        1 => c"FORMERR",
        2 => c"SERVFAIL",
        3 => c"NXDOMAIN",
        4 => c"NOTIMP",
        5 => c"REFUSED",
        6 => c"YXDOMAIN",
        7 => c"YXRRSET",
        8 => c"NXRRSET",
        9 => c"NOTAUTH",
        10 => c"NOTZONE",
        _ => c"UNKNOWN",
    }
}

pub(crate) fn section_name(section: u32) -> &'static CStr {
    match section {
        1 => c"ANSWER",
        2 => c"AUTHORITY",
        3 => c"ADDITIONAL",
        _ => c"UNKNOWN",
    }
}


// ---------------------------------------------------------------------------
// The record model. RRValue is the discriminated union for RR field values;
// Str keeps a CString and Bin keeps a trailing NUL (not counted in logical
// length) so the C getters can hand out stable, strlen-safe borrowed
// pointers straight from the model.
// ---------------------------------------------------------------------------

pub(crate) enum RRValue {
    U8(u8),
    U16(u16),
    U32(u32),
    Addr(Ipv4Addr),
    Addr6(Ipv6Addr),
    Str(CString),
    Bin(Vec<u8>), // Always null-terminated: last byte is \0, not counted in logical length
}

pub(crate) struct DnsRecordQuery {
    pub(crate) name: String,
    pub(crate) name_c: CString, // cached C string for lifetime management
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
}

/// One resource record. The C-facing name is kept because the type IS the
/// opaque handle the header declares; the struct itself is pure Rust — the
/// two Cells back the pointer-returning C getters (the ffi shim casts
/// `Cell<u32>`/`Cell<[u8;16]>` pointers to the layout-identical
/// `struct in_addr` / `struct ares_in6_addr`).
#[allow(non_camel_case_types)]
pub struct ares_dns_rr_t {
    pub(crate) name: String,
    pub(crate) name_c: CString,
    pub(crate) rtype: u16,
    pub(crate) rclass: u16,
    pub(crate) ttl: u32,
    pub(crate) data: HashMap<u32, RRValue>,
    pub(crate) opts: Vec<(u16, Vec<u8>)>,
    pub(crate) cached_v4: Cell<u32>,
    pub(crate) cached_v6: Cell<[u8; 16]>,
}

/// A whole DNS message; the opaque handle type of the ares_dns_record API.
#[allow(non_camel_case_types)]
pub struct ares_dns_record_t {
    pub(crate) id: u16,
    pub(crate) flags: u16,
    pub(crate) opcode: u16,
    pub(crate) rcode: u16,
    pub(crate) queries: Vec<DnsRecordQuery>,
    pub(crate) answers: Vec<ares_dns_rr_t>,
    pub(crate) authority: Vec<ares_dns_rr_t>,
    pub(crate) additional: Vec<ares_dns_rr_t>,
}

/// Create a null-terminated Bin value. The trailing \0 is part of the Vec
/// but not part of the logical data length (ares_dns_rr_get_bin reports
/// len without the null). This ensures C code can safely strlen() the data.
pub(crate) fn bin_nul(data: &[u8]) -> RRValue {
    let mut v = Vec::with_capacity(data.len() + 1);
    v.extend_from_slice(data);
    v.push(0);
    RRValue::Bin(v)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn section_vec(rec: &ares_dns_record_t, sect: u32) -> Option<&Vec<ares_dns_rr_t>> {
    match sect {
        ARES_SECTION_ANSWER => Some(&rec.answers),
        ARES_SECTION_AUTHORITY => Some(&rec.authority),
        ARES_SECTION_ADDITIONAL => Some(&rec.additional),
        _ => None,
    }
}

pub(crate) fn section_vec_mut(rec: &mut ares_dns_record_t, sect: u32) -> Option<&mut Vec<ares_dns_rr_t>> {
    match sect {
        ARES_SECTION_ANSWER => Some(&mut rec.answers),
        ARES_SECTION_AUTHORITY => Some(&mut rec.authority),
        ARES_SECTION_ADDITIONAL => Some(&mut rec.additional),
        _ => None,
    }
}

pub(crate) fn new_rr(name: &str, rtype: u16, rclass: u16, ttl: u32) -> ares_dns_rr_t {
    ares_dns_rr_t {
        name: name.to_string(),
        name_c: CString::new(name).unwrap_or_default(),
        rtype,
        rclass,
        ttl,
        data: HashMap::new(),
        opts: Vec::new(),
        cached_v4: Cell::new(0),
        cached_v6: Cell::new([0u8; 16]),
    }
}

// ---------------------------------------------------------------------------
// DNS wire-format helpers (for ares_dns_parse / ares_dns_write)
// ---------------------------------------------------------------------------

/// Parse rdata fields for a given RR type from wire format into key/value pairs.
pub(crate) fn parse_rdata(
    rtype: u16,
    rdata: &[u8],
    full_buf: &[u8],
    rdata_start: usize,
    rr: &mut ares_dns_rr_t,
) {
    match rtype {
        ARES_REC_TYPE_A => {
            if rdata.len() >= 4 {
                let addr = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                rr.data.insert(ARES_RR_A_ADDR, RRValue::Addr(addr));
            }
        }
        ARES_REC_TYPE_AAAA => {
            if rdata.len() >= 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rdata[..16]);
                let addr = Ipv6Addr::from(octets);
                rr.data.insert(ARES_RR_AAAA_ADDR, RRValue::Addr6(addr));
            }
        }
        ARES_REC_TYPE_NS => {
            let mut pos = rdata_start;
            if let Some(name) = parse_dns_name(full_buf, &mut pos) {
                rr.data.insert(
                    ARES_RR_NS_NSDNAME,
                    RRValue::Str(CString::new(name).unwrap_or_default()),
                );
            }
        }
        ARES_REC_TYPE_CNAME => {
            let mut pos = rdata_start;
            if let Some(name) = parse_dns_name(full_buf, &mut pos) {
                rr.data.insert(
                    ARES_RR_CNAME_CNAME,
                    RRValue::Str(CString::new(name).unwrap_or_default()),
                );
            }
        }
        ARES_REC_TYPE_PTR => {
            let mut pos = rdata_start;
            if let Some(name) = parse_dns_name(full_buf, &mut pos) {
                rr.data.insert(
                    ARES_RR_PTR_DNAME,
                    RRValue::Str(CString::new(name).unwrap_or_default()),
                );
            }
        }
        ARES_REC_TYPE_MX => {
            if rdata.len() >= 2 {
                let pref = ((rdata[0] as u16) << 8) | rdata[1] as u16;
                rr.data.insert(ARES_RR_MX_PREFERENCE, RRValue::U16(pref));
                let mut pos = rdata_start + 2;
                if let Some(name) = parse_dns_name(full_buf, &mut pos) {
                    rr.data.insert(
                        ARES_RR_MX_EXCHANGE,
                        RRValue::Str(CString::new(name).unwrap_or_default()),
                    );
                }
            }
        }
        ARES_REC_TYPE_TXT => {
            // TXT records: concatenate all length-prefixed strings (strip length bytes)
            let mut txt_data = Vec::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let slen = rdata[pos] as usize;
                pos += 1;
                if pos + slen > rdata.len() { break; }
                txt_data.extend_from_slice(&rdata[pos..pos + slen]);
                pos += slen;
            }
            rr.data
                .insert(ARES_RR_TXT_DATA, bin_nul(&txt_data));
        }
        ARES_REC_TYPE_SOA => {
            let mut pos = rdata_start;
            if let Some(mname) = parse_dns_name(full_buf, &mut pos) {
                rr.data.insert(
                    ARES_RR_SOA_MNAME,
                    RRValue::Str(CString::new(mname).unwrap_or_default()),
                );
                if let Some(rname) = parse_dns_name(full_buf, &mut pos) {
                    rr.data.insert(
                        ARES_RR_SOA_RNAME,
                        RRValue::Str(CString::new(rname).unwrap_or_default()),
                    );
                    let remaining = &full_buf[pos..];
                    if remaining.len() >= 20 {
                        let serial = u32::from_be_bytes([
                            remaining[0],
                            remaining[1],
                            remaining[2],
                            remaining[3],
                        ]);
                        let refresh = u32::from_be_bytes([
                            remaining[4],
                            remaining[5],
                            remaining[6],
                            remaining[7],
                        ]);
                        let retry = u32::from_be_bytes([
                            remaining[8],
                            remaining[9],
                            remaining[10],
                            remaining[11],
                        ]);
                        let expire = u32::from_be_bytes([
                            remaining[12],
                            remaining[13],
                            remaining[14],
                            remaining[15],
                        ]);
                        let minimum = u32::from_be_bytes([
                            remaining[16],
                            remaining[17],
                            remaining[18],
                            remaining[19],
                        ]);
                        rr.data.insert(ARES_RR_SOA_SERIAL, RRValue::U32(serial));
                        rr.data
                            .insert(ARES_RR_SOA_REFRESH, RRValue::U32(refresh));
                        rr.data.insert(ARES_RR_SOA_RETRY, RRValue::U32(retry));
                        rr.data.insert(ARES_RR_SOA_EXPIRE, RRValue::U32(expire));
                        rr.data
                            .insert(ARES_RR_SOA_MINIMUM, RRValue::U32(minimum));
                    }
                }
            }
        }
        ARES_REC_TYPE_SRV => {
            if rdata.len() >= 6 {
                let priority = ((rdata[0] as u16) << 8) | rdata[1] as u16;
                let weight = ((rdata[2] as u16) << 8) | rdata[3] as u16;
                let port = ((rdata[4] as u16) << 8) | rdata[5] as u16;
                rr.data
                    .insert(ARES_RR_SRV_PRIORITY, RRValue::U16(priority));
                rr.data.insert(ARES_RR_SRV_WEIGHT, RRValue::U16(weight));
                rr.data.insert(ARES_RR_SRV_PORT, RRValue::U16(port));
                let mut pos = rdata_start + 6;
                if let Some(target) = parse_dns_name(full_buf, &mut pos) {
                    rr.data.insert(
                        ARES_RR_SRV_TARGET,
                        RRValue::Str(CString::new(target).unwrap_or_default()),
                    );
                }
            }
        }
        ARES_REC_TYPE_NAPTR => {
            if rdata.len() >= 4 {
                let order = ((rdata[0] as u16) << 8) | rdata[1] as u16;
                let preference = ((rdata[2] as u16) << 8) | rdata[3] as u16;
                rr.data.insert(ARES_RR_NAPTR_ORDER, RRValue::U16(order));
                rr.data
                    .insert(ARES_RR_NAPTR_PREFERENCE, RRValue::U16(preference));
                let mut off = 4usize;
                // flags (length-prefixed string)
                if off < rdata.len() {
                    let flen = rdata[off] as usize;
                    off += 1;
                    if off + flen <= rdata.len() {
                        let flags_str =
                            String::from_utf8_lossy(&rdata[off..off + flen]).to_string();
                        rr.data.insert(
                            ARES_RR_NAPTR_FLAGS,
                            RRValue::Str(CString::new(flags_str).unwrap_or_default()),
                        );
                        off += flen;
                    }
                }
                // services
                if off < rdata.len() {
                    let slen = rdata[off] as usize;
                    off += 1;
                    if off + slen <= rdata.len() {
                        let svc = String::from_utf8_lossy(&rdata[off..off + slen]).to_string();
                        rr.data.insert(
                            ARES_RR_NAPTR_SERVICES,
                            RRValue::Str(CString::new(svc).unwrap_or_default()),
                        );
                        off += slen;
                    }
                }
                // regexp
                if off < rdata.len() {
                    let rlen = rdata[off] as usize;
                    off += 1;
                    if off + rlen <= rdata.len() {
                        let regexp =
                            String::from_utf8_lossy(&rdata[off..off + rlen]).to_string();
                        rr.data.insert(
                            ARES_RR_NAPTR_REGEXP,
                            RRValue::Str(CString::new(regexp).unwrap_or_default()),
                        );
                        off += rlen;
                    }
                }
                // replacement (DNS name)
                let mut pos = rdata_start + off;
                if let Some(replacement) = parse_dns_name(full_buf, &mut pos) {
                    rr.data.insert(
                        ARES_RR_NAPTR_REPLACEMENT,
                        RRValue::Str(CString::new(replacement).unwrap_or_default()),
                    );
                }
            }
        }
        ARES_REC_TYPE_OPT => {
            // OPT pseudo-RR: class = UDP payload size, TTL encodes version/flags
            rr.data
                .insert(ARES_RR_OPT_UDP_SIZE, RRValue::U16(rr.rclass));
            let version = ((rr.ttl >> 16) & 0xFF) as u8;
            let opt_flags = (rr.ttl & 0xFFFF) as u16;
            rr.data.insert(ARES_RR_OPT_VERSION, RRValue::U8(version));
            rr.data
                .insert(ARES_RR_OPT_FLAGS, RRValue::U16(opt_flags));
            // rdata = sequence of (option-code: u16, option-length: u16, option-data)
            let mut off = 0usize;
            while off + 4 <= rdata.len() {
                let code = ((rdata[off] as u16) << 8) | rdata[off + 1] as u16;
                let olen = ((rdata[off + 2] as u16) << 8) | rdata[off + 3] as u16;
                off += 4;
                let end = off + olen as usize;
                if end > rdata.len() {
                    break;
                }
                rr.opts.push((code, rdata[off..end].to_vec()));
                off = end;
            }
        }
        ARES_REC_TYPE_TLSA => {
            if rdata.len() >= 3 {
                rr.data
                    .insert(ARES_RR_TLSA_CERT_USAGE, RRValue::U8(rdata[0]));
                rr.data
                    .insert(ARES_RR_TLSA_SELECTOR, RRValue::U8(rdata[1]));
                rr.data.insert(ARES_RR_TLSA_MATCH, RRValue::U8(rdata[2]));
                rr.data
                    .insert(ARES_RR_TLSA_DATA, bin_nul(&rdata[3..]));
            }
        }
        ARES_REC_TYPE_SVCB => {
            if rdata.len() >= 2 {
                let priority = ((rdata[0] as u16) << 8) | rdata[1] as u16;
                rr.data
                    .insert(ARES_RR_SVCB_PRIORITY, RRValue::U16(priority));
                let mut pos = rdata_start + 2;
                if let Some(target) = parse_dns_name(full_buf, &mut pos) {
                    rr.data.insert(
                        ARES_RR_SVCB_TARGET,
                        RRValue::Str(CString::new(target).unwrap_or_default()),
                    );
                }
                let consumed = pos - rdata_start;
                if consumed < rdata.len() {
                    rr.data.insert(
                        ARES_RR_SVCB_PARAMS,
                        bin_nul(&rdata[consumed..]),
                    );
                }
            }
        }
        ARES_REC_TYPE_HTTPS => {
            if rdata.len() >= 2 {
                let priority = ((rdata[0] as u16) << 8) | rdata[1] as u16;
                rr.data
                    .insert(ARES_RR_HTTPS_PRIORITY, RRValue::U16(priority));
                let mut pos = rdata_start + 2;
                if let Some(target) = parse_dns_name(full_buf, &mut pos) {
                    rr.data.insert(
                        ARES_RR_HTTPS_TARGET,
                        RRValue::Str(CString::new(target).unwrap_or_default()),
                    );
                }
                let consumed = pos - rdata_start;
                if consumed < rdata.len() {
                    rr.data.insert(
                        ARES_RR_HTTPS_PARAMS,
                        bin_nul(&rdata[consumed..]),
                    );
                }
            }
        }
        ARES_REC_TYPE_CAA => {
            if rdata.len() >= 2 {
                let critical = rdata[0];
                let tag_len = rdata[1] as usize;
                if 2 + tag_len <= rdata.len() {
                    rr.data
                        .insert(ARES_RR_CAA_CRITICAL, RRValue::U8(critical));
                    let tag =
                        String::from_utf8_lossy(&rdata[2..2 + tag_len]).to_string();
                    rr.data.insert(
                        ARES_RR_CAA_TAG,
                        RRValue::Str(CString::new(tag).unwrap_or_default()),
                    );
                    let val = &rdata[2 + tag_len..];
                    rr.data
                        .insert(ARES_RR_CAA_VALUE, bin_nul(val));
                }
            }
        }
        ARES_REC_TYPE_HINFO => {
            let mut off = 0usize;
            if off < rdata.len() {
                let clen = rdata[off] as usize;
                off += 1;
                if off + clen <= rdata.len() {
                    let cpu =
                        String::from_utf8_lossy(&rdata[off..off + clen]).to_string();
                    rr.data.insert(
                        ARES_RR_HINFO_CPU,
                        RRValue::Str(CString::new(cpu).unwrap_or_default()),
                    );
                    off += clen;
                }
            }
            if off < rdata.len() {
                let olen = rdata[off] as usize;
                off += 1;
                if off + olen <= rdata.len() {
                    let os =
                        String::from_utf8_lossy(&rdata[off..off + olen]).to_string();
                    rr.data.insert(
                        ARES_RR_HINFO_OS,
                        RRValue::Str(CString::new(os).unwrap_or_default()),
                    );
                }
            }
        }
        _ => {
            // Unknown type: store as RAW_RR
            rr.data.insert(ARES_RR_RAW_RR_TYPE, RRValue::U16(rtype));
            rr.data
                .insert(ARES_RR_RAW_RR_DATA, bin_nul(rdata));
        }
    }
}

/// Serialize rdata for a given RR to wire format.
pub(crate) fn write_rdata(rr: &ares_dns_rr_t, out: &mut Vec<u8>) {
    match rr.rtype {
        ARES_REC_TYPE_A => {
            if let Some(RRValue::Addr(addr)) = rr.data.get(&ARES_RR_A_ADDR) {
                out.extend_from_slice(&addr.octets());
            }
        }
        ARES_REC_TYPE_AAAA => {
            if let Some(RRValue::Addr6(addr)) = rr.data.get(&ARES_RR_AAAA_ADDR) {
                out.extend_from_slice(&addr.octets());
            }
        }
        ARES_REC_TYPE_NS => {
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_NS_NSDNAME) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        ARES_REC_TYPE_CNAME => {
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_CNAME_CNAME) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        ARES_REC_TYPE_PTR => {
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_PTR_DNAME) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        ARES_REC_TYPE_MX => {
            if let Some(RRValue::U16(pref)) = rr.data.get(&ARES_RR_MX_PREFERENCE) {
                out.push((*pref >> 8) as u8);
                out.push(*pref as u8);
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_MX_EXCHANGE) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        ARES_REC_TYPE_TXT => {
            if let Some(RRValue::Bin(data)) = rr.data.get(&ARES_RR_TXT_DATA) {
                // Re-encode as length-prefixed strings (split into 255-byte chunks max)
                if data.is_empty() {
                    out.push(0); // empty string: single 0-length prefix
                } else {
                    let mut pos = 0;
                    while pos < data.len() {
                        let chunk_len = std::cmp::min(255, data.len() - pos);
                        out.push(chunk_len as u8);
                        out.extend_from_slice(&data[pos..pos + chunk_len]);
                        pos += chunk_len;
                    }
                }
            }
        }
        ARES_REC_TYPE_SOA => {
            if let Some(RRValue::Str(mname)) = rr.data.get(&ARES_RR_SOA_MNAME) {
                write_dns_name(&mname.to_string_lossy(), out);
            }
            if let Some(RRValue::Str(rname)) = rr.data.get(&ARES_RR_SOA_RNAME) {
                write_dns_name(&rname.to_string_lossy(), out);
            }
            let fields = [
                ARES_RR_SOA_SERIAL,
                ARES_RR_SOA_REFRESH,
                ARES_RR_SOA_RETRY,
                ARES_RR_SOA_EXPIRE,
                ARES_RR_SOA_MINIMUM,
            ];
            for key in &fields {
                if let Some(RRValue::U32(v)) = rr.data.get(key) {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
        }
        ARES_REC_TYPE_SRV => {
            for key in &[ARES_RR_SRV_PRIORITY, ARES_RR_SRV_WEIGHT, ARES_RR_SRV_PORT] {
                if let Some(RRValue::U16(v)) = rr.data.get(key) {
                    out.push((*v >> 8) as u8);
                    out.push(*v as u8);
                }
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_SRV_TARGET) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        ARES_REC_TYPE_NAPTR => {
            for key in &[ARES_RR_NAPTR_ORDER, ARES_RR_NAPTR_PREFERENCE] {
                if let Some(RRValue::U16(v)) = rr.data.get(key) {
                    out.push((*v >> 8) as u8);
                    out.push(*v as u8);
                }
            }
            for key in &[
                ARES_RR_NAPTR_FLAGS,
                ARES_RR_NAPTR_SERVICES,
                ARES_RR_NAPTR_REGEXP,
            ] {
                if let Some(RRValue::Str(s)) = rr.data.get(key) {
                    let bytes = s.as_bytes();
                    out.push(bytes.len() as u8);
                    out.extend_from_slice(bytes);
                }
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_NAPTR_REPLACEMENT) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        ARES_REC_TYPE_OPT => {
            for (code, data) in &rr.opts {
                out.push((*code >> 8) as u8);
                out.push(*code as u8);
                let len = data.len() as u16;
                out.push((len >> 8) as u8);
                out.push(len as u8);
                out.extend_from_slice(data);
            }
        }
        ARES_REC_TYPE_TLSA => {
            if let Some(RRValue::U8(cu)) = rr.data.get(&ARES_RR_TLSA_CERT_USAGE) {
                out.push(*cu);
            }
            if let Some(RRValue::U8(sel)) = rr.data.get(&ARES_RR_TLSA_SELECTOR) {
                out.push(*sel);
            }
            if let Some(RRValue::U8(m)) = rr.data.get(&ARES_RR_TLSA_MATCH) {
                out.push(*m);
            }
            if let Some(RRValue::Bin(d)) = rr.data.get(&ARES_RR_TLSA_DATA) {
                out.extend_from_slice(d);
            }
        }
        ARES_REC_TYPE_SVCB => {
            if let Some(RRValue::U16(p)) = rr.data.get(&ARES_RR_SVCB_PRIORITY) {
                out.push((*p >> 8) as u8);
                out.push(*p as u8);
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_SVCB_TARGET) {
                write_dns_name(&s.to_string_lossy(), out);
            }
            if let Some(RRValue::Bin(params)) = rr.data.get(&ARES_RR_SVCB_PARAMS) {
                out.extend_from_slice(params);
            }
        }
        ARES_REC_TYPE_HTTPS => {
            if let Some(RRValue::U16(p)) = rr.data.get(&ARES_RR_HTTPS_PRIORITY) {
                out.push((*p >> 8) as u8);
                out.push(*p as u8);
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_HTTPS_TARGET) {
                write_dns_name(&s.to_string_lossy(), out);
            }
            if let Some(RRValue::Bin(params)) = rr.data.get(&ARES_RR_HTTPS_PARAMS) {
                out.extend_from_slice(params);
            }
        }
        ARES_REC_TYPE_CAA => {
            if let Some(RRValue::U8(crit)) = rr.data.get(&ARES_RR_CAA_CRITICAL) {
                out.push(*crit);
            }
            if let Some(RRValue::Str(tag)) = rr.data.get(&ARES_RR_CAA_TAG) {
                let bytes = tag.as_bytes();
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
            if let Some(RRValue::Bin(val)) = rr.data.get(&ARES_RR_CAA_VALUE) {
                out.extend_from_slice(val);
            }
        }
        ARES_REC_TYPE_HINFO => {
            if let Some(RRValue::Str(cpu)) = rr.data.get(&ARES_RR_HINFO_CPU) {
                let bytes = cpu.as_bytes();
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
            if let Some(RRValue::Str(os)) = rr.data.get(&ARES_RR_HINFO_OS) {
                let bytes = os.as_bytes();
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
        }
        _ => {
            // RAW RR or unknown: write raw data
            if let Some(RRValue::Bin(d)) = rr.data.get(&ARES_RR_RAW_RR_DATA) {
                out.extend_from_slice(d);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Static key arrays for ares_dns_rr_get_keys
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Record/RR accessors — the ffi shims never touch the model
// fields or RRValue directly; every read and mutation goes through these.
// ---------------------------------------------------------------------------

impl ares_dns_record_t {
    pub(crate) fn id(&self) -> u16 {
        self.id
    }

    pub(crate) fn flags(&self) -> u16 {
        self.flags
    }

    pub(crate) fn opcode(&self) -> u16 {
        self.opcode
    }

    pub(crate) fn rcode(&self) -> u16 {
        self.rcode
    }

    pub(crate) fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub(crate) fn query_add(&mut self, name: &str, qtype: u16, qclass: u16) -> Result<(), AresError> {
        let name_c = CString::new(name).map_err(|_| ARES_EBADRESP)?;
        self.queries.push(DnsRecordQuery {
            name: name.to_string(),
            name_c,
            qtype,
            qclass,
        });
        Ok(())
    }

    pub(crate) fn query_cnt(&self) -> usize {
        self.queries.len()
    }

    /// (name, qtype, qclass) — the name aliases the query's cached CString
    /// and stays valid until the query's name is rewritten.
    pub(crate) fn query_at(&self, idx: usize) -> Option<(&CStr, u16, u16)> {
        let q = self.queries.get(idx)?;
        Some((q.name_c.as_c_str(), q.qtype, q.qclass))
    }

    pub(crate) fn query_set_name(&mut self, idx: usize, name: &str) -> Result<(), AresError> {
        if idx >= self.queries.len() {
            return Err(ARES_EBADRESP.into());
        }
        let name_c = CString::new(name).map_err(|_| ARES_EBADRESP)?;
        self.queries[idx].name = name.to_string();
        self.queries[idx].name_c = name_c;
        Ok(())
    }

    pub(crate) fn query_set_type(&mut self, idx: usize, qtype: u16) -> Result<(), AresError> {
        if idx >= self.queries.len() {
            return Err(ARES_EBADRESP.into());
        }
        self.queries[idx].qtype = qtype;
        Ok(())
    }

    pub(crate) fn rr_add(
        &mut self,
        sect: u32,
        name: &str,
        rtype: u16,
        rclass: u16,
        ttl: u32,
    ) -> Result<&mut ares_dns_rr_t, AresError> {
        let vec = section_vec_mut(self, sect).ok_or(AresError::from(ARES_EBADRESP))?;
        vec.push(new_rr(name, rtype, rclass, ttl));
        // Just pushed, so never empty; the error arm is unreachable by construction.
        vec.last_mut().ok_or(AresError::from(ARES_EBADRESP))
    }

    pub(crate) fn rr_cnt(&self, sect: u32) -> usize {
        match section_vec(self, sect) {
            Some(v) => v.len(),
            None => 0,
        }
    }

    pub(crate) fn rr_at_mut(&mut self, sect: u32, idx: usize) -> Option<&mut ares_dns_rr_t> {
        section_vec_mut(self, sect)?.get_mut(idx)
    }

    pub(crate) fn rr_at(&self, sect: u32, idx: usize) -> Option<&ares_dns_rr_t> {
        section_vec(self, sect)?.get(idx)
    }

    pub(crate) fn rr_del(&mut self, sect: u32, idx: usize) -> Result<(), AresError> {
        let vec = section_vec_mut(self, sect).ok_or(AresError::from(ARES_EBADRESP))?;
        if idx >= vec.len() {
            return Err(ARES_EBADRESP.into());
        }
        vec.remove(idx);
        Ok(())
    }
}

impl ares_dns_rr_t {
    /// The RR name as a C string (the shim hands out `.as_ptr()`, valid
    /// while the RR is alive).
    pub(crate) fn name_cstr(&self) -> &CStr {
        &self.name_c
    }

    pub(crate) fn rtype(&self) -> u16 {
        self.rtype
    }

    pub(crate) fn rclass(&self) -> u16 {
        self.rclass
    }

    pub(crate) fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Refresh the cached v4 backing store for the pointer-returning C
    /// getter (upstream contract: the pointer stays valid while the RR is
    /// alive). Cell keeps this a purely safe interior mutation on a shared
    /// reference; true iff the key holds a v4 address.
    pub(crate) fn refresh_v4(&self, key: u32) -> bool {
        if let Some(RRValue::Addr(addr)) = self.data.get(&key) {
            self.cached_v4.set(u32::from_ne_bytes(addr.octets()));
            true
        } else {
            false
        }
    }

    /// v6 sibling of [`Self::refresh_v4`].
    pub(crate) fn refresh_v6(&self, key: u32) -> bool {
        if let Some(RRValue::Addr6(addr)) = self.data.get(&key) {
            self.cached_v6.set(addr.octets());
            true
        } else {
            false
        }
    }

    pub(crate) fn str_val(&self, key: u32) -> Option<&CStr> {
        if let Some(RRValue::Str(s)) = self.data.get(&key) {
            Some(s)
        } else {
            None
        }
    }

    pub(crate) fn u8_val(&self, key: u32) -> Option<u8> {
        if let Some(RRValue::U8(v)) = self.data.get(&key) {
            Some(*v)
        } else {
            None
        }
    }

    pub(crate) fn u16_val(&self, key: u32) -> Option<u16> {
        if let Some(RRValue::U16(v)) = self.data.get(&key) {
            Some(*v)
        } else {
            None
        }
    }

    pub(crate) fn u32_val(&self, key: u32) -> Option<u32> {
        if let Some(RRValue::U32(v)) = self.data.get(&key) {
            Some(*v)
        } else {
            None
        }
    }

    /// (full stored buffer incl. trailing NUL, logical length without it).
    pub(crate) fn bin_val(&self, key: u32) -> Option<(&[u8], usize)> {
        if let Some(RRValue::Bin(data)) = self.data.get(&key) {
            // Bin data is null-terminated; logical length excludes the trailing \0
            let logical_len = if data.last() == Some(&0) { data.len() - 1 } else { data.len() };
            Some((data.as_slice(), logical_len))
        } else {
            None
        }
    }

    pub(crate) fn set_addr(&mut self, key: u32, ip: Ipv4Addr) {
        self.data.insert(key, RRValue::Addr(ip));
    }

    pub(crate) fn set_addr6(&mut self, key: u32, ip: Ipv6Addr) {
        self.data.insert(key, RRValue::Addr6(ip));
    }

    pub(crate) fn set_str(&mut self, key: u32, val: CString) {
        self.data.insert(key, RRValue::Str(val));
    }

    pub(crate) fn set_u8(&mut self, key: u32, val: u8) {
        self.data.insert(key, RRValue::U8(val));
    }

    pub(crate) fn set_u16(&mut self, key: u32, val: u16) {
        self.data.insert(key, RRValue::U16(val));
    }

    pub(crate) fn set_u32(&mut self, key: u32, val: u32) {
        self.data.insert(key, RRValue::U32(val));
    }

    pub(crate) fn set_bin(&mut self, key: u32, data: &[u8]) {
        self.data.insert(key, bin_nul(data));
    }

    pub(crate) fn set_opt(&mut self, opt: u16, data: Vec<u8>) {
        // Remove existing opt with same code if present, then add
        self.opts.retain(|(code, _)| *code != opt);
        self.opts.push((opt, data));
    }

    pub(crate) fn opt_cnt(&self) -> usize {
        self.opts.len()
    }

    pub(crate) fn opt_at(&self, idx: usize) -> Option<(u16, &[u8])> {
        self.opts.get(idx).map(|(code, data)| (*code, data.as_slice()))
    }

    pub(crate) fn opt_by_id(&self, opt: u16) -> Option<&[u8]> {
        self.opts
            .iter()
            .find(|(code, _)| *code == opt)
            .map(|(_, data)| data.as_slice())
    }

    pub(crate) fn del_opt_by_id(&mut self, opt: u16) -> bool {
        let before = self.opts.len();
        self.opts.retain(|(code, _)| *code != opt);
        self.opts.len() < before
    }
}

// ---------------------------------------------------------------------------
// Whole-message codec (the pure bodies of ares_dns_parse/write)
// ---------------------------------------------------------------------------

impl ares_dns_record_t {
    pub(crate) fn new(id: u16, flags: u16, opcode: u16, rcode: u16) -> Self {
        ares_dns_record_t {
            id,
            flags,
            opcode,
            rcode,
            queries: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}

/// Decode a whole DNS message (header, questions, all three RR sections).
pub(crate) fn parse_record(data: &[u8]) -> Result<ares_dns_record_t, AresError> {
    let buf_len = data.len();
    if buf_len < 12 {
        return Err(ARES_EBADRESP.into());
    }

    // Parse header (12 bytes)
    let id = ((data[0] as u16) << 8) | data[1] as u16;
    let flags_val = ((data[2] as u16) << 8) | data[3] as u16;
    let qdcount = ((data[4] as u16) << 8) | data[5] as u16;
    let ancount = ((data[6] as u16) << 8) | data[7] as u16;
    let nscount = ((data[8] as u16) << 8) | data[9] as u16;
    let arcount = ((data[10] as u16) << 8) | data[11] as u16;

    let opcode = (flags_val >> 11) & 0x0F;
    let rcode = flags_val & 0x0F;

    let mut rec = ares_dns_record_t {
        id,
        flags: flags_val,
        opcode,
        rcode,
        queries: Vec::new(),
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
    };

    let mut pos = 12usize;

    // Parse questions
    for _ in 0..qdcount {
        let name = parse_dns_name(data, &mut pos).ok_or(ARES_EBADRESP)?;
        if pos + 4 > buf_len {
            return Err(ARES_EBADRESP.into());
        }
        let qtype = ((data[pos] as u16) << 8) | data[pos + 1] as u16;
        let qclass = ((data[pos + 2] as u16) << 8) | data[pos + 3] as u16;
        pos += 4;
        let name_c = CString::new(name.clone()).unwrap_or_default();
        rec.queries.push(DnsRecordQuery {
            name,
            name_c,
            qtype,
            qclass,
        });
    }

    // Parse RR sections: answers, authority, additional
    let section_counts = [
        (ancount, ARES_SECTION_ANSWER),
        (nscount, ARES_SECTION_AUTHORITY),
        (arcount, ARES_SECTION_ADDITIONAL),
    ];

    for (count, section) in &section_counts {
        for _ in 0..*count {
            let rr_name = parse_dns_name(data, &mut pos).ok_or(ARES_EBADRESP)?;
            if pos + 10 > buf_len {
                return Err(ARES_EBADRESP.into());
            }
            let rtype = ((data[pos] as u16) << 8) | data[pos + 1] as u16;
            let rclass = ((data[pos + 2] as u16) << 8) | data[pos + 3] as u16;
            let ttl = u32::from_be_bytes([
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            let rdlength = ((data[pos + 8] as u16) << 8) | data[pos + 9] as u16;
            pos += 10;

            let rdata_start = pos;
            if pos + rdlength as usize > buf_len {
                return Err(ARES_EBADRESP.into());
            }
            let rdata = &data[pos..pos + rdlength as usize];
            pos += rdlength as usize;

            let mut rr = new_rr(&rr_name, rtype, rclass, ttl);
            parse_rdata(rtype, rdata, data, rdata_start, &mut rr);

            let vec = section_vec_mut(&mut rec, *section).ok_or(ARES_EBADRESP)?;
            vec.push(rr);
        }
    }

    Ok(rec)
}

/// Encode a whole DNS message to wire format.
pub(crate) fn write_record(rec: &ares_dns_record_t) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);

    // Write header
    out.push((rec.id >> 8) as u8);
    out.push(rec.id as u8);
    out.push((rec.flags >> 8) as u8);
    out.push(rec.flags as u8);
    let qdcount = rec.queries.len() as u16;
    out.push((qdcount >> 8) as u8);
    out.push(qdcount as u8);
    let ancount = rec.answers.len() as u16;
    out.push((ancount >> 8) as u8);
    out.push(ancount as u8);
    let nscount = rec.authority.len() as u16;
    out.push((nscount >> 8) as u8);
    out.push(nscount as u8);
    let arcount = rec.additional.len() as u16;
    out.push((arcount >> 8) as u8);
    out.push(arcount as u8);

    // Write questions
    for q in &rec.queries {
        write_dns_name(&q.name, &mut out);
        out.push((q.qtype >> 8) as u8);
        out.push(q.qtype as u8);
        out.push((q.qclass >> 8) as u8);
        out.push(q.qclass as u8);
    }

    // Write RR sections
    let sections: [&Vec<ares_dns_rr_t>; 3] =
        [&rec.answers, &rec.authority, &rec.additional];
    for section in &sections {
        for rr in *section {
            write_dns_name(&rr.name, &mut out);
            out.push((rr.rtype >> 8) as u8);
            out.push(rr.rtype as u8);
            out.push((rr.rclass >> 8) as u8);
            out.push(rr.rclass as u8);
            out.extend_from_slice(&rr.ttl.to_be_bytes());

            // Serialize rdata to a temporary buffer to get rdlength
            let mut rdata_buf = Vec::new();
            write_rdata(rr, &mut rdata_buf);
            let rdlength = rdata_buf.len() as u16;
            out.push((rdlength >> 8) as u8);
            out.push(rdlength as u8);
            out.extend_from_slice(&rdata_buf);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::parse_dns_name;

    #[test]
    fn parses_simple_name() {
        // "ab.cd" as uncompressed labels.
        let buf = [2, b'a', b'b', 2, b'c', b'd', 0];
        let mut pos = 0usize;
        assert_eq!(parse_dns_name(&buf, &mut pos), Some("ab.cd".to_string()));
        assert_eq!(pos, buf.len()); // consumed through the root label
    }

    #[test]
    fn follows_backward_compression_pointer() {
        // "ab" at offset 0, then a pointer at offset 4 -> offset 0.
        let buf = [2, b'a', b'b', 0, 0xC0, 0x00];
        let mut pos = 4usize;
        assert_eq!(parse_dns_name(&buf, &mut pos), Some("ab".to_string()));
        assert_eq!(pos, 6); // pointer consumes exactly 2 bytes
    }

    #[test]
    fn rejects_self_referential_pointer() {
        // Pointer at offset 0 that points to offset 0 — would spin forever
        // without the strictly-backward guard. Must return None and not hang.
        let buf = [0xC0, 0x00];
        let mut pos = 0usize;
        assert_eq!(parse_dns_name(&buf, &mut pos), None);
    }

    #[test]
    fn rejects_forward_pointer() {
        // Pointer at offset 0 -> offset 4 (forward). Rejected.
        let buf = [0xC0, 0x04, 0, 0, 0, 0];
        let mut pos = 0usize;
        assert_eq!(parse_dns_name(&buf, &mut pos), None);
    }

    #[test]
    fn rejects_cyclic_pointers() {
        // A 2-pointer cycle: offset 2 -> offset 0 -> offset 2. The second
        // (forward) jump is rejected, so the loop terminates with None.
        let buf = [0xC0, 0x02, 0xC0, 0x00];
        let mut pos = 2usize;
        assert_eq!(parse_dns_name(&buf, &mut pos), None);
    }
}
