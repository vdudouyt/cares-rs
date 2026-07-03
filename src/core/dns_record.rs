//! DNS-record metadata and wire-name helpers: the pure string/key tables of
//! the ares_dns_* metadata surface and the compression-aware name codec.
//! (The record model itself joins this module as the codec split completes.)

use std::ffi::CStr;

use crate::ffi::dns_record::{
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
// Metadata string/table kernels (the pure bodies of the ares_dns_* metadata
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
