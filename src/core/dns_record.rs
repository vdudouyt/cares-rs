//! DNS-record metadata and wire-name helpers: the pure string/key tables of
//! the ares_dns_* metadata surface and the compression-aware name codec.
//! (The record model itself joins this module as the codec split completes.)

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::core::AresError;
use crate::ffi::error::{ARES_EBADNAME, ARES_EBADRESP, ARES_EBADSTR, ARES_EFORMERR};

use crate::ffi::dns_record::{
    ARES_SECTION_ADDITIONAL, ARES_SECTION_ANSWER, ARES_SECTION_AUTHORITY,
    ARES_CLASS_ANY, ARES_CLASS_CHAOS, ARES_CLASS_HESOID, ARES_CLASS_IN, ARES_CLASS_NONE,
    ARES_DATATYPE_ABINP, ARES_DATATYPE_BIN, ARES_DATATYPE_BINP, ARES_DATATYPE_INADDR,
    ARES_DATATYPE_INADDR6, ARES_DATATYPE_NAME, ARES_DATATYPE_OPT, ARES_DATATYPE_STR,
    ARES_DATATYPE_U16, ARES_DATATYPE_U32, ARES_DATATYPE_U8,
    ARES_DNS_PARSE_AN_BASE_RAW, ARES_DNS_PARSE_AN_EXT_RAW, ARES_DNS_PARSE_AR_BASE_RAW,
    ARES_DNS_PARSE_AR_EXT_RAW, ARES_DNS_PARSE_NS_BASE_RAW, ARES_DNS_PARSE_NS_EXT_RAW,
    ARES_FLAG_AA, ARES_FLAG_AD, ARES_FLAG_CD, ARES_FLAG_QR, ARES_FLAG_RA,
    ARES_FLAG_RD, ARES_FLAG_TC, ARES_RCODE_SERVFAIL,
    ARES_REC_TYPE_A, ARES_REC_TYPE_AAAA,
    ARES_REC_TYPE_ANY, ARES_REC_TYPE_CAA, ARES_REC_TYPE_CNAME, ARES_REC_TYPE_HINFO,
    ARES_REC_TYPE_HTTPS, ARES_REC_TYPE_MX, ARES_REC_TYPE_NAPTR, ARES_REC_TYPE_NS,
    ARES_REC_TYPE_OPT, ARES_REC_TYPE_PTR, ARES_REC_TYPE_RAW_RR, ARES_REC_TYPE_SIG,
    ARES_REC_TYPE_SOA, ARES_REC_TYPE_SRV, ARES_REC_TYPE_SVCB, ARES_REC_TYPE_TLSA,
    ARES_REC_TYPE_TXT, ARES_REC_TYPE_URI, ARES_RR_AAAA_ADDR, ARES_RR_A_ADDR,
    ARES_RR_CAA_CRITICAL, ARES_RR_CAA_TAG, ARES_RR_CAA_VALUE, ARES_RR_CNAME_CNAME,
    ARES_RR_HINFO_CPU, ARES_RR_HINFO_OS,
    ARES_RR_HTTPS_PARAMS, ARES_RR_HTTPS_PRIORITY, ARES_RR_HTTPS_TARGET, ARES_RR_MX_EXCHANGE,
    ARES_RR_MX_PREFERENCE, ARES_RR_NAPTR_FLAGS, ARES_RR_NAPTR_ORDER, ARES_RR_NAPTR_PREFERENCE,
    ARES_RR_NAPTR_REGEXP, ARES_RR_NAPTR_REPLACEMENT, ARES_RR_NAPTR_SERVICES, ARES_RR_NS_NSDNAME,
    ARES_RR_OPT_FLAGS, ARES_RR_OPT_OPTIONS, ARES_RR_OPT_UDP_SIZE, ARES_RR_OPT_VERSION,
    ARES_RR_PTR_DNAME, ARES_RR_RAW_RR_DATA, ARES_RR_RAW_RR_TYPE, ARES_RR_SIG_ALGORITHM,
    ARES_RR_SIG_EXPIRATION, ARES_RR_SIG_INCEPTION, ARES_RR_SIG_KEY_TAG, ARES_RR_SIG_LABELS,
    ARES_RR_SIG_ORIGINAL_TTL, ARES_RR_SIG_SIGNATURE, ARES_RR_SIG_SIGNERS_NAME,
    ARES_RR_SIG_TYPE_COVERED, ARES_RR_SOA_EXPIRE,
    ARES_RR_SOA_MINIMUM, ARES_RR_SOA_MNAME, ARES_RR_SOA_REFRESH, ARES_RR_SOA_RETRY,
    ARES_RR_SOA_RNAME, ARES_RR_SOA_SERIAL, ARES_RR_SRV_PORT, ARES_RR_SRV_PRIORITY,
    ARES_RR_SRV_TARGET, ARES_RR_SRV_WEIGHT, ARES_RR_SVCB_PARAMS, ARES_RR_SVCB_PRIORITY,
    ARES_RR_SVCB_TARGET, ARES_RR_TLSA_CERT_USAGE, ARES_RR_TLSA_DATA, ARES_RR_TLSA_MATCH,
    ARES_RR_TLSA_SELECTOR, ARES_RR_TXT_DATA, ARES_RR_URI_PRIORITY, ARES_RR_URI_TARGET,
    ARES_RR_URI_WEIGHT,
    ARES_OPT_DATATYPE_BIN, ARES_OPT_DATATYPE_INADDR4_LIST, ARES_OPT_DATATYPE_INADDR6_LIST,
    ARES_OPT_DATATYPE_NAME, ARES_OPT_DATATYPE_NONE, ARES_OPT_DATATYPE_STR_LIST,
    ARES_OPT_DATATYPE_U16, ARES_OPT_DATATYPE_U16_LIST, ARES_OPT_DATATYPE_U32,
    ARES_OPT_DATATYPE_U8_LIST, ARES_OPT_PARAM_CHAIN, ARES_OPT_PARAM_COOKIE,
    ARES_OPT_PARAM_DAU, ARES_OPT_PARAM_DHU, ARES_OPT_PARAM_EDNS_CLIENT_SUBNET,
    ARES_OPT_PARAM_EDNS_EXPIRE, ARES_OPT_PARAM_EDNS_KEY_TAG,
    ARES_OPT_PARAM_EDNS_TCP_KEEPALIVE, ARES_OPT_PARAM_EXTENDED_DNS_ERROR,
    ARES_OPT_PARAM_LLQ, ARES_OPT_PARAM_N3U, ARES_OPT_PARAM_NSID, ARES_OPT_PARAM_PADDING,
    ARES_OPT_PARAM_UL, ARES_SVCB_PARAM_ALPN, ARES_SVCB_PARAM_ECH,
    ARES_SVCB_PARAM_IPV4HINT, ARES_SVCB_PARAM_IPV6HINT, ARES_SVCB_PARAM_MANDATORY,
    ARES_SVCB_PARAM_NO_DEFAULT_ALPN, ARES_SVCB_PARAM_PORT,
};

/// Append one wire label to `out`, rendering non-printable and reserved bytes
/// as the escapes c-ares accepts (`\DDD` and `\c`).
fn push_escaped_label(label: &[u8], out: &mut String) {
    for &c in label {
        if !(0x20..=0x7e).contains(&c) {
            out.push('\\');
            out.push((b'0' + c / 100) as char);
            out.push((b'0' + (c % 100) / 10) as char);
            out.push((b'0' + c % 10) as char);
        } else {
            if matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') {
                out.push('\\');
            }
            out.push(c as char);
        }
    }
}

/// Read a DNS name from wire format, handling label compression. Returns the
/// escaped dotted name (exactly as c-ares renders it) and advances `pos` past
/// the bytes occupied by the name at its original location. Compression
/// pointers must point strictly before the earliest label seen so far, which
/// both enforces RFC 1035 §4.1.4 and guarantees termination.
pub(crate) fn parse_dns_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    let mut out = String::new();
    let mut cur = *pos;
    let mut jumped = false;
    let mut end_pos = *pos;
    let mut label_start = *pos;

    loop {
        if label_start > cur {
            label_start = cur;
        }
        if cur >= buf.len() {
            return None;
        }
        let len_byte = buf[cur];
        cur += 1;
        if (len_byte & 0xC0) == 0xC0 {
            // compression pointer
            if cur >= buf.len() {
                return None;
            }
            let offset = (((len_byte & 0x3F) as usize) << 8) | (buf[cur] as usize);
            cur += 1;
            if offset >= label_start {
                return None;
            }
            if !jumped {
                end_pos = cur;
            }
            jumped = true;
            cur = offset;
            continue;
        }
        if (len_byte & 0xC0) != 0 {
            return None;
        }
        if len_byte == 0 {
            if !jumped {
                end_pos = cur;
            }
            break;
        }
        let label_len = len_byte as usize;
        if cur + label_len > buf.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        push_escaped_label(&buf[cur..cur + label_len], &mut out);
        cur += label_len;
    }

    *pos = end_pos;
    Some(out)
}

/// Write a DNS name in wire format (uncompressed labels), decoding the
/// `\DDD`/`\c` escapes that [`parse_dns_name`] emits.
pub(crate) fn write_dns_name(name: &str, out: &mut Vec<u8>) {
    let bytes = name.as_bytes();
    let mut labels: Vec<Vec<u8>> = vec![Vec::new()];
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'.' {
            labels.push(Vec::new());
            i += 1;
            continue;
        }
        if b == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next.is_ascii_digit()
                && i + 3 < bytes.len()
                && bytes[i + 2].is_ascii_digit()
                && bytes[i + 3].is_ascii_digit()
            {
                let val = (next - b'0') as u16 * 100
                    + (bytes[i + 2] - b'0') as u16 * 10
                    + (bytes[i + 3] - b'0') as u16;
                if val <= 255 {
                    if let Some(label) = labels.last_mut() {
                        label.push(val as u8);
                    }
                    i += 4;
                    continue;
                }
            }
            if let Some(label) = labels.last_mut() {
                label.push(next);
            }
            i += 2;
            continue;
        }
        if let Some(label) = labels.last_mut() {
            label.push(b);
        }
        i += 1;
    }
    if labels.len() > 1 && labels.last().is_some_and(|l| l.is_empty()) {
        labels.pop();
    }
    if labels.len() == 1 && labels[0].is_empty() {
        // Root (or empty) name: just the terminator.
        out.push(0);
        return;
    }
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(&label);
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
pub(crate) static KEYS_SIG: [u32; 9] = [
    ARES_RR_SIG_TYPE_COVERED,
    ARES_RR_SIG_ALGORITHM,
    ARES_RR_SIG_LABELS,
    ARES_RR_SIG_ORIGINAL_TTL,
    ARES_RR_SIG_EXPIRATION,
    ARES_RR_SIG_INCEPTION,
    ARES_RR_SIG_KEY_TAG,
    ARES_RR_SIG_SIGNERS_NAME,
    ARES_RR_SIG_SIGNATURE,
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
        24 => c"SIG",
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
        "SIG" => ARES_REC_TYPE_SIG as u32,
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
        ARES_RR_SIG_TYPE_COVERED => c"SIG.TYPE_COVERED",
        ARES_RR_SIG_ALGORITHM => c"SIG.ALGORITHM",
        ARES_RR_SIG_LABELS => c"SIG.LABELS",
        ARES_RR_SIG_ORIGINAL_TTL => c"SIG.ORIGINAL_TTL",
        ARES_RR_SIG_EXPIRATION => c"SIG.EXPIRATION",
        ARES_RR_SIG_INCEPTION => c"SIG.INCEPTION",
        ARES_RR_SIG_KEY_TAG => c"SIG.KEY_TAG",
        ARES_RR_SIG_SIGNERS_NAME => c"SIG.SIGNERS_NAME",
        ARES_RR_SIG_SIGNATURE => c"SIG.SIGNATURE",
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
        24 => &KEYS_SIG,
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
        ARES_RR_SIG_TYPE_COVERED => ARES_DATATYPE_U16 as u32,
        ARES_RR_SIG_ALGORITHM => ARES_DATATYPE_U8 as u32,
        ARES_RR_SIG_LABELS => ARES_DATATYPE_U8 as u32,
        ARES_RR_SIG_ORIGINAL_TTL => ARES_DATATYPE_U32 as u32,
        ARES_RR_SIG_EXPIRATION => ARES_DATATYPE_U32 as u32,
        ARES_RR_SIG_INCEPTION => ARES_DATATYPE_U32 as u32,
        ARES_RR_SIG_KEY_TAG => ARES_DATATYPE_U16 as u32,
        ARES_RR_SIG_SIGNERS_NAME => ARES_DATATYPE_NAME as u32,
        ARES_RR_SIG_SIGNATURE => ARES_DATATYPE_BIN as u32,
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
        ARES_RR_SIG_TYPE_COVERED | ARES_RR_SIG_ALGORITHM | ARES_RR_SIG_LABELS
        | ARES_RR_SIG_ORIGINAL_TTL | ARES_RR_SIG_EXPIRATION | ARES_RR_SIG_INCEPTION
        | ARES_RR_SIG_KEY_TAG | ARES_RR_SIG_SIGNERS_NAME
        | ARES_RR_SIG_SIGNATURE => ARES_REC_TYPE_SIG as u32,
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
        11 => c"DSOTYPEI",
        16 => c"BADSIG",
        17 => c"BADKEY",
        18 => c"BADTIME",
        19 => c"BADMODE",
        20 => c"BADNAME",
        21 => c"BADALG",
        22 => c"BADTRUNC",
        23 => c"BADCOOKIE",
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
// Address text helpers (pure bodies of ares_dns_pton / ares_dns_addr_to_ptr)
// ---------------------------------------------------------------------------

pub(crate) enum PtonAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl PtonAddr {
    pub(crate) fn len(&self) -> usize {
        match self {
            PtonAddr::V4(_) => 4,
            PtonAddr::V6(_) => 16,
        }
    }
}

/// Parse an IP literal according to the caller-supplied family. Returns the
/// (possibly updated) family plus the network-order octets. AF_UNSPEC tries
/// IPv4 first, then IPv6, exactly like upstream ares_dns_pton().
pub(crate) fn dns_pton(ipaddr: &str, family: libc::c_int) -> Option<(libc::c_int, PtonAddr)> {
    if family == libc::AF_INET {
        ipaddr
            .parse::<Ipv4Addr>()
            .ok()
            .map(|ip| (libc::AF_INET, PtonAddr::V4(ip.octets())))
    } else if family == libc::AF_INET6 {
        ipaddr
            .parse::<Ipv6Addr>()
            .ok()
            .map(|ip| (libc::AF_INET6, PtonAddr::V6(ip.octets())))
    } else if family == libc::AF_UNSPEC {
        if let Ok(ip) = ipaddr.parse::<Ipv4Addr>() {
            Some((libc::AF_INET, PtonAddr::V4(ip.octets())))
        } else {
            ipaddr
                .parse::<Ipv6Addr>()
                .ok()
                .map(|ip| (libc::AF_INET6, PtonAddr::V6(ip.octets())))
        }
    } else {
        None
    }
}

/// `d.c.b.a.in-addr.arpa` for the network-order IPv4 octets.
pub(crate) fn addr_to_ptr_v4(octets: [u8; 4]) -> String {
    let mut out = String::with_capacity(24);
    for b in octets.iter().rev() {
        out.push_str(&b.to_string());
        out.push('.');
    }
    out.push_str("in-addr.arpa");
    out
}

/// Reverse nibble form `....ip6.arpa` for the network-order IPv6 octets.
pub(crate) fn addr_to_ptr_v6(octets: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(76);
    for b in octets.iter().rev() {
        out.push(HEX[(b & 0x0f) as usize] as char);
        out.push('.');
        out.push(HEX[(b >> 4) as usize] as char);
        out.push('.');
    }
    out.push_str("ip6.arpa");
    out
}

// ---------------------------------------------------------------------------
// OPT / SVCB option metadata (pure bodies of ares_dns_opt_get_*)
// ---------------------------------------------------------------------------

fn opt_datatype_opt(opt: u16) -> u32 {
    match opt as u32 {
        ARES_OPT_PARAM_LLQ => ARES_OPT_DATATYPE_BIN,
        ARES_OPT_PARAM_UL => ARES_OPT_DATATYPE_U32,
        ARES_OPT_PARAM_NSID => ARES_OPT_DATATYPE_BIN,
        ARES_OPT_PARAM_DAU => ARES_OPT_DATATYPE_U8_LIST,
        ARES_OPT_PARAM_DHU => ARES_OPT_DATATYPE_U8_LIST,
        ARES_OPT_PARAM_N3U => ARES_OPT_DATATYPE_U8_LIST,
        ARES_OPT_PARAM_EDNS_CLIENT_SUBNET => ARES_OPT_DATATYPE_BIN,
        ARES_OPT_PARAM_EDNS_EXPIRE => ARES_OPT_DATATYPE_U32,
        ARES_OPT_PARAM_COOKIE => ARES_OPT_DATATYPE_BIN,
        ARES_OPT_PARAM_EDNS_TCP_KEEPALIVE => ARES_OPT_DATATYPE_U16,
        ARES_OPT_PARAM_PADDING => ARES_OPT_DATATYPE_BIN,
        ARES_OPT_PARAM_CHAIN => ARES_OPT_DATATYPE_NAME,
        ARES_OPT_PARAM_EDNS_KEY_TAG => ARES_OPT_DATATYPE_U16_LIST,
        ARES_OPT_PARAM_EXTENDED_DNS_ERROR => ARES_OPT_DATATYPE_BIN,
        _ => ARES_OPT_DATATYPE_BIN,
    }
}

fn opt_datatype_svcb(opt: u16) -> u32 {
    match opt as u32 {
        ARES_SVCB_PARAM_NO_DEFAULT_ALPN => ARES_OPT_DATATYPE_NONE,
        ARES_SVCB_PARAM_ECH => ARES_OPT_DATATYPE_BIN,
        ARES_SVCB_PARAM_MANDATORY => ARES_OPT_DATATYPE_U16_LIST,
        ARES_SVCB_PARAM_ALPN => ARES_OPT_DATATYPE_STR_LIST,
        ARES_SVCB_PARAM_PORT => ARES_OPT_DATATYPE_U16,
        ARES_SVCB_PARAM_IPV4HINT => ARES_OPT_DATATYPE_INADDR4_LIST,
        ARES_SVCB_PARAM_IPV6HINT => ARES_OPT_DATATYPE_INADDR6_LIST,
        _ => ARES_OPT_DATATYPE_BIN,
    }
}

pub(crate) fn opt_datatype(key: u32, opt: u16) -> u32 {
    match key {
        ARES_RR_OPT_OPTIONS => opt_datatype_opt(opt),
        ARES_RR_SVCB_PARAMS | ARES_RR_HTTPS_PARAMS => opt_datatype_svcb(opt),
        _ => ARES_OPT_DATATYPE_BIN,
    }
}

fn opt_name_opt(opt: u16) -> Option<&'static CStr> {
    Some(match opt as u32 {
        ARES_OPT_PARAM_LLQ => c"LLQ",
        ARES_OPT_PARAM_UL => c"UL",
        ARES_OPT_PARAM_NSID => c"NSID",
        ARES_OPT_PARAM_DAU => c"DAU",
        ARES_OPT_PARAM_DHU => c"DHU",
        ARES_OPT_PARAM_N3U => c"N3U",
        ARES_OPT_PARAM_EDNS_CLIENT_SUBNET => c"edns-client-subnet",
        ARES_OPT_PARAM_EDNS_EXPIRE => c"edns-expire",
        ARES_OPT_PARAM_COOKIE => c"COOKIE",
        ARES_OPT_PARAM_EDNS_TCP_KEEPALIVE => c"edns-tcp-keepalive",
        ARES_OPT_PARAM_PADDING => c"Padding",
        ARES_OPT_PARAM_CHAIN => c"CHAIN",
        ARES_OPT_PARAM_EDNS_KEY_TAG => c"edns-key-tag",
        ARES_OPT_PARAM_EXTENDED_DNS_ERROR => c"extended-dns-error",
        _ => return None,
    })
}

fn opt_name_svcb(opt: u16) -> Option<&'static CStr> {
    Some(match opt as u32 {
        ARES_SVCB_PARAM_NO_DEFAULT_ALPN => c"no-default-alpn",
        ARES_SVCB_PARAM_ECH => c"ech",
        ARES_SVCB_PARAM_MANDATORY => c"mandatory",
        ARES_SVCB_PARAM_ALPN => c"alpn",
        ARES_SVCB_PARAM_PORT => c"port",
        ARES_SVCB_PARAM_IPV4HINT => c"ipv4hint",
        ARES_SVCB_PARAM_IPV6HINT => c"ipv6hint",
        _ => return None,
    })
}

pub(crate) fn opt_name(key: u32, opt: u16) -> Option<&'static CStr> {
    match key {
        ARES_RR_OPT_OPTIONS => opt_name_opt(opt),
        ARES_RR_SVCB_PARAMS | ARES_RR_HTTPS_PARAMS => opt_name_svcb(opt),
        _ => None,
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
    /// One entry per DNS character-string (TXT/ABINP). Each element carries
    /// its own trailing NUL for the stable C getter, not part of its length.
    BinArray(Vec<Vec<u8>>),
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
    pub(crate) rtype: u32,
    pub(crate) rclass: u16,
    pub(crate) ttl: u32,
    pub(crate) data: HashMap<u32, RRValue>,
    pub(crate) opts: Vec<(u16, Vec<u8>)>,
    pub(crate) cached_v4: Cell<u32>,
    pub(crate) cached_v6: Cell<[u8; 16]>,
    /// Cached concatenation of an ABINP value (upstream multistring cache).
    pub(crate) combined_cache: RefCell<Option<Vec<u8>>>,
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

/// One ABINP element: logical bytes plus the trailing NUL that backs the C
/// pointer contract (zero-length elements are still a non-null 1-byte buffer).
pub(crate) fn abin_nul(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 1);
    v.extend_from_slice(data);
    v.push(0);
    v
}

/// The logical bytes of an internally NUL-terminated `Bin`/ABINP element.
pub(crate) fn bin_logical(data: &[u8]) -> &[u8] {
    if data.last() == Some(&0) {
        &data[..data.len() - 1]
    } else {
        data
    }
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

pub(crate) fn new_rr(name: &str, rtype: u32, rclass: u16, ttl: u32) -> ares_dns_rr_t {
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
        combined_cache: RefCell::new(None),
    }
}

// ---------------------------------------------------------------------------
// DNS wire-format helpers (for ares_dns_parse / ares_dns_write)
// ---------------------------------------------------------------------------

pub(crate) fn opcode_isvalid(opcode: u32) -> bool {
    matches!(opcode, 0 | 1 | 2 | 4 | 5)
}

pub(crate) fn rcode_isvalid(rcode: u32) -> bool {
    matches!(rcode, 0..=11 | 16..=23)
}

/// `flags` uses the internal ARES_FLAG_* bit positions (bits 0..6).
pub(crate) fn flags_arevalid(flags: u16) -> bool {
    flags & !0x7f == 0
}

fn flags_from_wire(u16_flags: u16) -> u16 {
    let mut flags = 0u16;
    if u16_flags & 0x8000 != 0 {
        flags |= ARES_FLAG_QR;
    }
    if u16_flags & 0x400 != 0 {
        flags |= ARES_FLAG_AA;
    }
    if u16_flags & 0x200 != 0 {
        flags |= ARES_FLAG_TC;
    }
    if u16_flags & 0x100 != 0 {
        flags |= ARES_FLAG_RD;
    }
    if u16_flags & 0x80 != 0 {
        flags |= ARES_FLAG_RA;
    }
    if u16_flags & 0x20 != 0 {
        flags |= ARES_FLAG_AD;
    }
    if u16_flags & 0x10 != 0 {
        flags |= ARES_FLAG_CD;
    }
    flags
}

fn flags_to_wire(flags: u16, opcode: u16, rcode: u16) -> u16 {
    let mut wire = 0u16;
    if flags & ARES_FLAG_QR != 0 {
        wire |= 0x8000;
    }
    wire |= (opcode & 0xf) << 11;
    if flags & ARES_FLAG_AA != 0 {
        wire |= 0x400;
    }
    if flags & ARES_FLAG_TC != 0 {
        wire |= 0x200;
    }
    if flags & ARES_FLAG_RD != 0 {
        wire |= 0x100;
    }
    if flags & ARES_FLAG_RA != 0 {
        wire |= 0x80;
    }
    if flags & ARES_FLAG_AD != 0 {
        wire |= 0x20;
    }
    if flags & ARES_FLAG_CD != 0 {
        wire |= 0x10;
    }
    wire | (rcode & 0xf)
}

/// ares_dns_rec_type_isvalid() (the `is_query` variant matters only for
/// RAW_RR, which is a response-only pseudo type).
pub(crate) fn rec_type_isvalid(rtype: u32, is_query: bool) -> bool {
    match rtype {
        1 | 2 | 5 | 6 | 12 | 13 | 15 | 16 | 24 | 28 | 33 | 35 | 41 | 52 | 64
        | 65 | 255 | 256 | 257 => true,
        65536 => !is_query,
        _ => is_query,
    }
}

/// Only the RFC 1035 types permit name compression in RDATA.
pub(crate) fn allow_name_comp(rtype: u32) -> bool {
    matches!(rtype, 1 | 2 | 5 | 6 | 12 | 13 | 15 | 16)
}

/// ares_dns_class_isvalid(): unknown/raw types skip class validation.
pub(crate) fn class_isvalid(qclass: u16, rtype: u32, is_query: bool) -> bool {
    if rtype == ARES_REC_TYPE_RAW_RR {
        return true;
    }
    match qclass {
        ARES_CLASS_IN | ARES_CLASS_CHAOS | ARES_CLASS_HESOID | ARES_CLASS_NONE => true,
        ARES_CLASS_ANY => rtype == ARES_REC_TYPE_SIG as u32 || is_query,
        _ => false,
    }
}

fn printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x20..=0x7e).contains(b))
}

/// Parse one length-prefixed character-string from `rdata` (upstream
/// ares_buf_parse_dns_str), advancing `pos` past it.
fn parse_dns_str(
    rdata: &[u8],
    pos: &mut usize,
    blank_allowed: bool,
) -> Result<CString, AresError> {
    let len = *rdata.get(*pos).ok_or(AresError::from(ARES_EBADRESP))? as usize;
    *pos += 1;
    if *pos + len > rdata.len() {
        return Err(ARES_EBADRESP.into());
    }
    let bytes = &rdata[*pos..*pos + len];
    *pos += len;
    if !blank_allowed && bytes.is_empty() {
        return Err(ARES_EBADRESP.into());
    }
    if !printable(bytes) {
        return Err(ARES_EBADSTR.into());
    }
    CString::new(bytes).map_err(|_| ARES_EBADRESP.into())
}

/// Parse an (option, length, data) sequence that must exactly fill `rdata`.
fn parse_options(
    rdata: &[u8],
    opts: &mut Vec<(u16, Vec<u8>)>,
) -> Result<(), AresError> {
    let mut off = 0usize;
    while off < rdata.len() {
        if off + 4 > rdata.len() {
            return Err(ARES_EBADRESP.into());
        }
        let code = ((rdata[off] as u16) << 8) | rdata[off + 1] as u16;
        let olen = ((rdata[off + 2] as u16) << 8) | rdata[off + 3] as u16;
        off += 4;
        let end = off + olen as usize;
        if end > rdata.len() {
            return Err(ARES_EBADRESP.into());
        }
        // Keep the C getter contract: values carry a trailing NUL while the
        // logical length excludes it.
        let mut data = rdata[off..end].to_vec();
        data.push(0);
        opts.push((code, data));
        off = end;
    }
    Ok(())
}

fn set_name(rr: &mut ares_dns_rr_t, key: u32, name: String) -> Result<(), AresError> {
    rr.data
        .insert(key, RRValue::Str(CString::new(name).map_err(|_| ARES_EBADRESP)?));
    Ok(())
}

/// Parse rdata fields for a given RR type from wire format into key/value
/// pairs. `rtype` is the *stored* type (RAW_RR for unknown/forced-raw), while
/// `raw_type` is the original wire type preserved for RAW_RR. Field reads use
/// the full packet buffer like upstream, then the consumed byte count is
/// checked against RDLENGTH (trailing slack is ignored).
pub(crate) fn parse_rdata(
    rtype: u32,
    raw_type: u16,
    rdata: &[u8],
    full_buf: &[u8],
    rdata_start: usize,
    (raw_class, raw_ttl): (u16, u32),
    rr: &mut ares_dns_rr_t,
) -> Result<(), AresError> {
    let rdlength = rdata.len();
    let check = |pos: usize| -> Result<(), AresError> {
        if pos - rdata_start > rdlength {
            Err(ARES_EBADRESP.into())
        } else {
            Ok(())
        }
    };

    match rtype {
        x if x == ARES_REC_TYPE_A as u32 => {
            let bytes = full_buf
                .get(rdata_start..rdata_start + 4)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            rr.data.insert(
                ARES_RR_A_ADDR,
                RRValue::Addr(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            );
            check(rdata_start + 4)?;
        }
        x if x == ARES_REC_TYPE_AAAA as u32 => {
            let bytes = full_buf
                .get(rdata_start..rdata_start + 16)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            rr.data.insert(ARES_RR_AAAA_ADDR, RRValue::Addr6(Ipv6Addr::from(octets)));
            check(rdata_start + 16)?;
        }
        x if x == ARES_REC_TYPE_NS as u32 => {
            let mut pos = rdata_start;
            let name = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            check(pos)?;
            set_name(rr, ARES_RR_NS_NSDNAME, name)?;
        }
        x if x == ARES_REC_TYPE_CNAME as u32 => {
            let mut pos = rdata_start;
            let name = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            check(pos)?;
            set_name(rr, ARES_RR_CNAME_CNAME, name)?;
        }
        x if x == ARES_REC_TYPE_PTR as u32 => {
            let mut pos = rdata_start;
            let name = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            check(pos)?;
            set_name(rr, ARES_RR_PTR_DNAME, name)?;
        }
        x if x == ARES_REC_TYPE_MX as u32 => {
            let mut pos = rdata_start;
            let bytes = full_buf
                .get(pos..pos + 2)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            let pref = ((bytes[0] as u16) << 8) | bytes[1] as u16;
            pos += 2;
            let name = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            check(pos)?;
            rr.data.insert(ARES_RR_MX_PREFERENCE, RRValue::U16(pref));
            set_name(rr, ARES_RR_MX_EXCHANGE, name)?;
        }
        x if x == ARES_REC_TYPE_TXT as u32 => {
            if rdata.is_empty() {
                return Err(ARES_EBADRESP.into());
            }
            let mut strings = Vec::new();
            let mut pos = 0usize;
            while pos < rdata.len() {
                let slen = rdata[pos] as usize;
                pos += 1;
                if pos + slen > rdata.len() {
                    return Err(ARES_EBADRESP.into());
                }
                strings.push(abin_nul(&rdata[pos..pos + slen]));
                pos += slen;
            }
            rr.data.insert(ARES_RR_TXT_DATA, RRValue::BinArray(strings));
        }
        x if x == ARES_REC_TYPE_SOA as u32 => {
            let mut pos = rdata_start;
            let mname = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            let rname = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            let bytes = full_buf
                .get(pos..pos + 20)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            let u32_at = |off: usize| {
                u32::from_be_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                ])
            };
            pos += 20;
            check(pos)?;
            set_name(rr, ARES_RR_SOA_MNAME, mname)?;
            set_name(rr, ARES_RR_SOA_RNAME, rname)?;
            rr.data.insert(ARES_RR_SOA_SERIAL, RRValue::U32(u32_at(0)));
            rr.data.insert(ARES_RR_SOA_REFRESH, RRValue::U32(u32_at(4)));
            rr.data.insert(ARES_RR_SOA_RETRY, RRValue::U32(u32_at(8)));
            rr.data.insert(ARES_RR_SOA_EXPIRE, RRValue::U32(u32_at(12)));
            rr.data.insert(ARES_RR_SOA_MINIMUM, RRValue::U32(u32_at(16)));
        }
        x if x == ARES_REC_TYPE_SRV as u32 => {
            let mut pos = rdata_start;
            let bytes = full_buf
                .get(pos..pos + 6)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            let priority = ((bytes[0] as u16) << 8) | bytes[1] as u16;
            let weight = ((bytes[2] as u16) << 8) | bytes[3] as u16;
            let port = ((bytes[4] as u16) << 8) | bytes[5] as u16;
            pos += 6;
            let target = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            check(pos)?;
            rr.data.insert(ARES_RR_SRV_PRIORITY, RRValue::U16(priority));
            rr.data.insert(ARES_RR_SRV_WEIGHT, RRValue::U16(weight));
            rr.data.insert(ARES_RR_SRV_PORT, RRValue::U16(port));
            set_name(rr, ARES_RR_SRV_TARGET, target)?;
        }
        x if x == ARES_REC_TYPE_NAPTR as u32 => {
            if rdata.len() < 4 {
                return Err(ARES_EBADRESP.into());
            }
            let order = ((rdata[0] as u16) << 8) | rdata[1] as u16;
            let preference = ((rdata[2] as u16) << 8) | rdata[3] as u16;
            let mut off = 4usize;
            let flags = parse_dns_str(rdata, &mut off, true)?;
            let services = parse_dns_str(rdata, &mut off, true)?;
            let regexp = parse_dns_str(rdata, &mut off, true)?;
            let mut pos = rdata_start + off;
            let replacement =
                parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            check(pos)?;
            rr.data.insert(ARES_RR_NAPTR_ORDER, RRValue::U16(order));
            rr.data.insert(ARES_RR_NAPTR_PREFERENCE, RRValue::U16(preference));
            rr.data.insert(ARES_RR_NAPTR_FLAGS, RRValue::Str(flags));
            rr.data.insert(ARES_RR_NAPTR_SERVICES, RRValue::Str(services));
            rr.data.insert(ARES_RR_NAPTR_REGEXP, RRValue::Str(regexp));
            set_name(rr, ARES_RR_NAPTR_REPLACEMENT, replacement)?;
        }
        x if x == ARES_REC_TYPE_OPT as u32 => {
            rr.data.insert(ARES_RR_OPT_UDP_SIZE, RRValue::U16(raw_class));
            rr.data
                .insert(ARES_RR_OPT_VERSION, RRValue::U8(((raw_ttl >> 16) & 0xff) as u8));
            rr.data
                .insert(ARES_RR_OPT_FLAGS, RRValue::U16((raw_ttl & 0xffff) as u16));
            parse_options(rdata, &mut rr.opts)?;
        }
        x if x == ARES_REC_TYPE_TLSA as u32 => {
            let mut pos = rdata_start;
            let bytes = full_buf
                .get(pos..pos + 3)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            rr.data.insert(ARES_RR_TLSA_CERT_USAGE, RRValue::U8(bytes[0]));
            rr.data.insert(ARES_RR_TLSA_SELECTOR, RRValue::U8(bytes[1]));
            rr.data.insert(ARES_RR_TLSA_MATCH, RRValue::U8(bytes[2]));
            pos += 3;
            let len = rdlength.saturating_sub(pos - rdata_start);
            if len == 0 {
                return Err(ARES_EBADRESP.into());
            }
            let data = full_buf
                .get(pos..pos + len)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            rr.data.insert(ARES_RR_TLSA_DATA, bin_nul(data));
            pos += len;
            check(pos)?;
        }
        x if x == ARES_REC_TYPE_SVCB as u32 || x == ARES_REC_TYPE_HTTPS as u32 => {
            let mut pos = rdata_start;
            let bytes = full_buf
                .get(pos..pos + 2)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            let priority = ((bytes[0] as u16) << 8) | bytes[1] as u16;
            pos += 2;
            let target = parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            check(pos)?;
            let consumed = pos - rdata_start;
            parse_options(&rdata[consumed..], &mut rr.opts)?;
            if x == ARES_REC_TYPE_SVCB as u32 {
                rr.data.insert(ARES_RR_SVCB_PRIORITY, RRValue::U16(priority));
                set_name(rr, ARES_RR_SVCB_TARGET, target)?;
            } else {
                rr.data.insert(ARES_RR_HTTPS_PRIORITY, RRValue::U16(priority));
                set_name(rr, ARES_RR_HTTPS_TARGET, target)?;
            }
        }
        x if x == ARES_REC_TYPE_URI as u32 => {
            let mut pos = rdata_start;
            let bytes = full_buf
                .get(pos..pos + 4)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            let priority = ((bytes[0] as u16) << 8) | bytes[1] as u16;
            let weight = ((bytes[2] as u16) << 8) | bytes[3] as u16;
            pos += 4;
            let len = rdlength.saturating_sub(pos - rdata_start);
            if len == 0 {
                return Err(ARES_EBADRESP.into());
            }
            let target = full_buf
                .get(pos..pos + len)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            if !printable(target) {
                return Err(ARES_EBADSTR.into());
            }
            pos += len;
            check(pos)?;
            rr.data.insert(ARES_RR_URI_PRIORITY, RRValue::U16(priority));
            rr.data.insert(ARES_RR_URI_WEIGHT, RRValue::U16(weight));
            rr.data.insert(
                ARES_RR_URI_TARGET,
                RRValue::Str(CString::new(target).map_err(|_| ARES_EBADRESP)?),
            );
        }
        x if x == ARES_REC_TYPE_CAA as u32 => {
            if rdata.is_empty() {
                return Err(ARES_EBADRESP.into());
            }
            let critical = rdata[0];
            let mut off = 1usize;
            let tag = parse_dns_str(rdata, &mut off, false)?;
            if off >= rdata.len() {
                return Err(ARES_EBADRESP.into());
            }
            rr.data.insert(ARES_RR_CAA_CRITICAL, RRValue::U8(critical));
            rr.data.insert(ARES_RR_CAA_TAG, RRValue::Str(tag));
            rr.data.insert(ARES_RR_CAA_VALUE, bin_nul(&rdata[off..]));
        }
        x if x == ARES_REC_TYPE_HINFO as u32 => {
            let mut off = 0usize;
            let cpu = parse_dns_str(rdata, &mut off, true)?;
            let os = parse_dns_str(rdata, &mut off, true)?;
            rr.data.insert(ARES_RR_HINFO_CPU, RRValue::Str(cpu));
            rr.data.insert(ARES_RR_HINFO_OS, RRValue::Str(os));
        }
        x if x == ARES_REC_TYPE_SIG as u32 => {
            let mut pos = rdata_start;
            let bytes = full_buf
                .get(pos..pos + 18)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            let type_covered = ((bytes[0] as u16) << 8) | bytes[1] as u16;
            let algorithm = bytes[2];
            let labels = bytes[3];
            let original_ttl = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let expiration = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let inception = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
            let key_tag = ((bytes[16] as u16) << 8) | bytes[17] as u16;
            pos += 18;
            let signers =
                parse_dns_name(full_buf, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            let used = pos - rdata_start;
            if used >= rdlength {
                return Err(ARES_EBADRESP.into());
            }
            let sig_len = rdlength - used;
            let signature = full_buf
                .get(pos..pos + sig_len)
                .ok_or(AresError::from(ARES_EBADRESP))?;
            rr.data.insert(ARES_RR_SIG_TYPE_COVERED, RRValue::U16(type_covered));
            rr.data.insert(ARES_RR_SIG_ALGORITHM, RRValue::U8(algorithm));
            rr.data.insert(ARES_RR_SIG_LABELS, RRValue::U8(labels));
            rr.data.insert(ARES_RR_SIG_ORIGINAL_TTL, RRValue::U32(original_ttl));
            rr.data.insert(ARES_RR_SIG_EXPIRATION, RRValue::U32(expiration));
            rr.data.insert(ARES_RR_SIG_INCEPTION, RRValue::U32(inception));
            rr.data.insert(ARES_RR_SIG_KEY_TAG, RRValue::U16(key_tag));
            set_name(rr, ARES_RR_SIG_SIGNERS_NAME, signers)?;
            rr.data.insert(ARES_RR_SIG_SIGNATURE, bin_nul(signature));
        }
        x if x == ARES_REC_TYPE_ANY as u32 => {
            return Err(ARES_EBADRESP.into());
        }
        x if x == ARES_REC_TYPE_RAW_RR => {
            // Upstream leaves both keys unset for a zero-length raw record.
            if !rdata.is_empty() {
                rr.data.insert(ARES_RR_RAW_RR_TYPE, RRValue::U16(raw_type));
                rr.data.insert(ARES_RR_RAW_RR_DATA, bin_nul(rdata));
            }
        }
        _ => return Err(ARES_EFORMERR.into()),
    }
    Ok(())
}

fn write_binstr(data: &[u8], out: &mut Vec<u8>) {
    let logical = bin_logical(data);
    let mut pos = 0usize;
    loop {
        let len = std::cmp::min(255, logical.len() - pos);
        out.push(len as u8);
        out.extend_from_slice(&logical[pos..pos + len]);
        pos += len;
        if pos >= logical.len() {
            break;
        }
    }
}

/// Serialize rdata for a given RR to wire format.
pub(crate) fn write_rdata(rr: &ares_dns_rr_t, out: &mut Vec<u8>) {
    match rr.rtype {
        x if x == ARES_REC_TYPE_A as u32 => {
            if let Some(RRValue::Addr(addr)) = rr.data.get(&ARES_RR_A_ADDR) {
                out.extend_from_slice(&addr.octets());
            }
        }
        x if x == ARES_REC_TYPE_AAAA as u32 => {
            if let Some(RRValue::Addr6(addr)) = rr.data.get(&ARES_RR_AAAA_ADDR) {
                out.extend_from_slice(&addr.octets());
            }
        }
        x if x == ARES_REC_TYPE_NS as u32 => {
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_NS_NSDNAME) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        x if x == ARES_REC_TYPE_CNAME as u32 => {
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_CNAME_CNAME) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        x if x == ARES_REC_TYPE_PTR as u32 => {
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_PTR_DNAME) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        x if x == ARES_REC_TYPE_MX as u32 => {
            if let Some(RRValue::U16(pref)) = rr.data.get(&ARES_RR_MX_PREFERENCE) {
                out.extend_from_slice(&pref.to_be_bytes());
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_MX_EXCHANGE) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        x if x == ARES_REC_TYPE_TXT as u32 => match rr.data.get(&ARES_RR_TXT_DATA) {
            Some(RRValue::BinArray(strings)) => {
                for s in strings {
                    write_binstr(s, out);
                }
            }
            Some(RRValue::Bin(data)) => write_binstr(data, out),
            _ => {}
        },
        x if x == ARES_REC_TYPE_SOA as u32 => {
            if let Some(RRValue::Str(mname)) = rr.data.get(&ARES_RR_SOA_MNAME) {
                write_dns_name(&mname.to_string_lossy(), out);
            }
            if let Some(RRValue::Str(rname)) = rr.data.get(&ARES_RR_SOA_RNAME) {
                write_dns_name(&rname.to_string_lossy(), out);
            }
            for key in [
                ARES_RR_SOA_SERIAL,
                ARES_RR_SOA_REFRESH,
                ARES_RR_SOA_RETRY,
                ARES_RR_SOA_EXPIRE,
                ARES_RR_SOA_MINIMUM,
            ] {
                if let Some(RRValue::U32(v)) = rr.data.get(&key) {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
        }
        x if x == ARES_REC_TYPE_SRV as u32 => {
            for key in [ARES_RR_SRV_PRIORITY, ARES_RR_SRV_WEIGHT, ARES_RR_SRV_PORT] {
                if let Some(RRValue::U16(v)) = rr.data.get(&key) {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_SRV_TARGET) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        x if x == ARES_REC_TYPE_NAPTR as u32 => {
            for key in [ARES_RR_NAPTR_ORDER, ARES_RR_NAPTR_PREFERENCE] {
                if let Some(RRValue::U16(v)) = rr.data.get(&key) {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            for key in [
                ARES_RR_NAPTR_FLAGS,
                ARES_RR_NAPTR_SERVICES,
                ARES_RR_NAPTR_REGEXP,
            ] {
                if let Some(RRValue::Str(s)) = rr.data.get(&key) {
                    let bytes = s.as_bytes();
                    out.push(bytes.len() as u8);
                    out.extend_from_slice(bytes);
                }
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_NAPTR_REPLACEMENT) {
                write_dns_name(&s.to_string_lossy(), out);
            }
        }
        x if x == ARES_REC_TYPE_OPT as u32 => {
            write_options(&rr.opts, out);
        }
        x if x == ARES_REC_TYPE_TLSA as u32 => {
            for key in [
                ARES_RR_TLSA_CERT_USAGE,
                ARES_RR_TLSA_SELECTOR,
                ARES_RR_TLSA_MATCH,
            ] {
                if let Some(RRValue::U8(v)) = rr.data.get(&key) {
                    out.push(*v);
                }
            }
            if let Some(RRValue::Bin(d)) = rr.data.get(&ARES_RR_TLSA_DATA) {
                out.extend_from_slice(bin_logical(d));
            }
        }
        x if x == ARES_REC_TYPE_SVCB as u32 => {
            if let Some(RRValue::U16(p)) = rr.data.get(&ARES_RR_SVCB_PRIORITY) {
                out.extend_from_slice(&p.to_be_bytes());
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_SVCB_TARGET) {
                write_dns_name(&s.to_string_lossy(), out);
            }
            write_options(&rr.opts, out);
        }
        x if x == ARES_REC_TYPE_HTTPS as u32 => {
            if let Some(RRValue::U16(p)) = rr.data.get(&ARES_RR_HTTPS_PRIORITY) {
                out.extend_from_slice(&p.to_be_bytes());
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_HTTPS_TARGET) {
                write_dns_name(&s.to_string_lossy(), out);
            }
            write_options(&rr.opts, out);
        }
        x if x == ARES_REC_TYPE_URI as u32 => {
            for key in [ARES_RR_URI_PRIORITY, ARES_RR_URI_WEIGHT] {
                if let Some(RRValue::U16(v)) = rr.data.get(&key) {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_URI_TARGET) {
                out.extend_from_slice(s.as_bytes());
            }
        }
        x if x == ARES_REC_TYPE_CAA as u32 => {
            if let Some(RRValue::U8(crit)) = rr.data.get(&ARES_RR_CAA_CRITICAL) {
                out.push(*crit);
            }
            if let Some(RRValue::Str(tag)) = rr.data.get(&ARES_RR_CAA_TAG) {
                let bytes = tag.as_bytes();
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
            if let Some(RRValue::Bin(val)) = rr.data.get(&ARES_RR_CAA_VALUE) {
                out.extend_from_slice(bin_logical(val));
            }
        }
        x if x == ARES_REC_TYPE_HINFO as u32 => {
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
        x if x == ARES_REC_TYPE_SIG as u32 => {
            if let Some(RRValue::U16(v)) = rr.data.get(&ARES_RR_SIG_TYPE_COVERED) {
                out.extend_from_slice(&v.to_be_bytes());
            }
            for key in [ARES_RR_SIG_ALGORITHM, ARES_RR_SIG_LABELS] {
                if let Some(RRValue::U8(v)) = rr.data.get(&key) {
                    out.push(*v);
                }
            }
            for key in [
                ARES_RR_SIG_ORIGINAL_TTL,
                ARES_RR_SIG_EXPIRATION,
                ARES_RR_SIG_INCEPTION,
            ] {
                if let Some(RRValue::U32(v)) = rr.data.get(&key) {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            if let Some(RRValue::U16(v)) = rr.data.get(&ARES_RR_SIG_KEY_TAG) {
                out.extend_from_slice(&v.to_be_bytes());
            }
            if let Some(RRValue::Str(s)) = rr.data.get(&ARES_RR_SIG_SIGNERS_NAME) {
                write_dns_name(&s.to_string_lossy(), out);
            }
            if let Some(RRValue::Bin(d)) = rr.data.get(&ARES_RR_SIG_SIGNATURE) {
                out.extend_from_slice(bin_logical(d));
            }
        }
        x if x == ARES_REC_TYPE_RAW_RR => {
            if let Some(RRValue::Bin(d)) = rr.data.get(&ARES_RR_RAW_RR_DATA) {
                out.extend_from_slice(bin_logical(d));
            }
        }
        _ => {}
    }
}

fn write_options(opts: &[(u16, Vec<u8>)], out: &mut Vec<u8>) {
    for (code, data) in opts {
        let logical = bin_logical(data);
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&(logical.len() as u16).to_be_bytes());
        out.extend_from_slice(logical);
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

    pub(crate) fn query_add(
        &mut self,
        name: &str,
        qtype: u32,
        qclass: u32,
    ) -> Result<(), AresError> {
        if !rec_type_isvalid(qtype, true)
            || qclass > u16::MAX as u32
            || !class_isvalid(qclass as u16, qtype, true)
        {
            return Err(ARES_EFORMERR.into());
        }
        let name_c = CString::new(name).map_err(|_| ARES_EBADRESP)?;
        self.queries.push(DnsRecordQuery {
            name: name.to_string(),
            name_c,
            qtype: qtype as u16,
            qclass: qclass as u16,
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

    pub(crate) fn query_set_type(&mut self, idx: usize, qtype: u32) -> Result<(), AresError> {
        if idx >= self.queries.len() || !rec_type_isvalid(qtype, true) {
            return Err(ARES_EFORMERR.into());
        }
        self.queries[idx].qtype = qtype as u16;
        Ok(())
    }

    pub(crate) fn rr_add(
        &mut self,
        sect: u32,
        name: &str,
        rtype: u32,
        rclass: u32,
        ttl: u32,
    ) -> Result<&mut ares_dns_rr_t, AresError> {
        if !rec_type_isvalid(rtype, false)
            || rclass > u16::MAX as u32
            || (rtype != ARES_REC_TYPE_OPT as u32
                && !class_isvalid(rclass as u16, rtype, false))
        {
            return Err(ARES_EFORMERR.into());
        }
        let vec = section_vec_mut(self, sect).ok_or(AresError::from(ARES_EFORMERR))?;
        vec.push(new_rr(name, rtype, rclass as u16, ttl));
        // Just pushed, so never empty; the error arm is unreachable by construction.
        vec.last_mut().ok_or(AresError::from(ARES_EFORMERR))
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
        let vec = section_vec_mut(self, sect).ok_or(AresError::from(ARES_EFORMERR))?;
        if idx >= vec.len() {
            return Err(ARES_EFORMERR.into());
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

    pub(crate) fn rtype(&self) -> u32 {
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

    /// Pointer + logical length for a BIN/BINP/ABINP value. ABINP yields the
    /// concatenation of all strings (upstream multistring_combined), cached so
    /// the pointer stays valid until the RR is mutated.
    pub(crate) fn bin_ptr_len(&self, key: u32) -> Option<(*const u8, usize)> {
        match self.data.get(&key) {
            Some(RRValue::Bin(data)) => Some((data.as_ptr(), bin_logical(data).len())),
            Some(RRValue::BinArray(_)) => {
                let mut cache = self.combined_cache.borrow_mut();
                if cache.is_none() {
                    let mut v = Vec::new();
                    if let Some(RRValue::BinArray(strings)) = self.data.get(&key) {
                        for s in strings {
                            v.extend_from_slice(bin_logical(s));
                        }
                    }
                    v.push(0);
                    *cache = Some(v);
                }
                cache
                    .as_ref()
                    .map(|v| (v.as_ptr(), v.len().saturating_sub(1)))
            }
            _ => None,
        }
    }

    /// ABINP element count (0 for keys of another datatype or unset values).
    pub(crate) fn abin_count(&self, key: u32) -> usize {
        match self.data.get(&key) {
            Some(RRValue::BinArray(strings)) => strings.len(),
            _ => 0,
        }
    }

    /// Logical bytes of the idx-th ABINP element.
    pub(crate) fn abin_at(&self, key: u32, idx: usize) -> Option<&[u8]> {
        match self.data.get(&key) {
            Some(RRValue::BinArray(strings)) => strings.get(idx).map(|s| bin_logical(s)),
            _ => None,
        }
    }

    fn invalidate_combination(&mut self) {
        *self.combined_cache.borrow_mut() = None;
    }

    pub(crate) fn set_addr(&mut self, key: u32, ip: Ipv4Addr) {
        self.invalidate_combination();
        self.data.insert(key, RRValue::Addr(ip));
    }

    pub(crate) fn set_addr6(&mut self, key: u32, ip: Ipv6Addr) {
        self.invalidate_combination();
        self.data.insert(key, RRValue::Addr6(ip));
    }

    pub(crate) fn set_str(&mut self, key: u32, val: CString) {
        self.invalidate_combination();
        self.data.insert(key, RRValue::Str(val));
    }

    pub(crate) fn set_u8(&mut self, key: u32, val: u8) {
        self.invalidate_combination();
        self.data.insert(key, RRValue::U8(val));
    }

    pub(crate) fn set_u16(&mut self, key: u32, val: u16) {
        self.invalidate_combination();
        self.data.insert(key, RRValue::U16(val));
    }

    pub(crate) fn set_u32(&mut self, key: u32, val: u32) {
        self.invalidate_combination();
        self.data.insert(key, RRValue::U32(val));
    }

    pub(crate) fn set_bin(&mut self, key: u32, data: &[u8]) {
        self.invalidate_combination();
        if rr_key_datatype_of(key) == ARES_DATATYPE_ABINP as u32 {
            // Override semantics: replace the whole array with one string.
            self.data
                .insert(key, RRValue::BinArray(vec![abin_nul(data)]));
        } else {
            self.data.insert(key, bin_nul(data));
        }
    }

    /// Append one element to an ABINP value (ares_dns_rr_add_abin).
    pub(crate) fn append_bin(&mut self, key: u32, data: &[u8]) {
        self.invalidate_combination();
        if !matches!(self.data.get(&key), Some(RRValue::BinArray(_))) {
            self.data.insert(key, RRValue::BinArray(Vec::new()));
        }
        if let Some(RRValue::BinArray(strings)) = self.data.get_mut(&key) {
            strings.push(abin_nul(data));
        }
    }

    /// Remove the idx-th ABINP element; false when out of range.
    pub(crate) fn remove_bin(&mut self, key: u32, idx: usize) -> bool {
        self.invalidate_combination();
        if let Some(RRValue::BinArray(strings)) = self.data.get_mut(&key) {
            if idx < strings.len() {
                strings.remove(idx);
                return true;
            }
        }
        false
    }

    pub(crate) fn set_opt(&mut self, opt: u16, mut data: Vec<u8>) {
        // The C getter returns a NUL-terminated value; keep that guarantee in
        // the backing store while opt_at/opt_by_id expose the logical bytes.
        data.push(0);
        // Remove existing opt with same code if present, then add
        self.opts.retain(|(code, _)| *code != opt);
        self.opts.push((opt, data));
    }

    pub(crate) fn opt_cnt(&self) -> usize {
        self.opts.len()
    }

    pub(crate) fn opt_at(&self, idx: usize) -> Option<(u16, &[u8])> {
        let (code, data) = self.opts.get(idx)?;
        // Stored values always carry the trailing NUL; `len` is logical.
        Some((*code, &data[..data.len().saturating_sub(1)]))
    }

    pub(crate) fn opt_by_id(&self, opt: u16) -> Option<&[u8]> {
        self.opts
            .iter()
            .find(|(code, _)| *code == opt)
            .map(|(_, data)| &data[..data.len().saturating_sub(1)])
    }

    pub(crate) fn del_opt_by_id(&mut self, opt: u16) -> bool {
        let before = self.opts.len();
        self.opts.retain(|(code, _)| *code != opt);
        self.opts.len() < before
    }

    // -----------------------------------------------------------------
    // Checked C-API entry points: validation lives here (safe core) so the
    // unsafe FFI shims only dereference their pointers.
    // -----------------------------------------------------------------

    fn key_type_ok(&self, key: u32) -> bool {
        self.rtype == rr_key_rec_type(key)
    }

    fn key_has_datatype(&self, key: u32, datatype: u32) -> bool {
        rr_key_datatype_of(key) == datatype && self.key_type_ok(key)
    }

    pub(crate) fn bin_checked(&self, key: u32) -> Option<(*const u8, usize)> {
        let dt = rr_key_datatype_of(key);
        if dt != ARES_DATATYPE_BIN as u32
            && dt != ARES_DATATYPE_BINP as u32
            && dt != ARES_DATATYPE_ABINP as u32
        {
            return None;
        }
        if !self.key_type_ok(key) {
            return None;
        }
        self.bin_ptr_len(key)
    }

    pub(crate) fn abin_count_checked(&self, key: u32) -> usize {
        if !self.key_has_datatype(key, ARES_DATATYPE_ABINP as u32) {
            return 0;
        }
        self.abin_count(key)
    }

    pub(crate) fn abin_at_checked(&self, key: u32, idx: usize) -> Option<&[u8]> {
        if !self.key_has_datatype(key, ARES_DATATYPE_ABINP as u32) {
            return None;
        }
        self.abin_at(key, idx)
    }

    pub(crate) fn set_addr_checked(&mut self, key: u32, ip: Ipv4Addr) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_INADDR as u32) {
            return Err(ARES_EFORMERR.into());
        }
        self.set_addr(key, ip);
        Ok(())
    }

    pub(crate) fn set_addr6_checked(&mut self, key: u32, ip: Ipv6Addr) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_INADDR6 as u32) {
            return Err(ARES_EFORMERR.into());
        }
        self.set_addr6(key, ip);
        Ok(())
    }

    pub(crate) fn set_str_checked(&mut self, key: u32, val: CString) -> Result<(), AresError> {
        let dt = rr_key_datatype_of(key);
        if (dt != ARES_DATATYPE_STR as u32 && dt != ARES_DATATYPE_NAME as u32)
            || !self.key_type_ok(key)
        {
            return Err(ARES_EFORMERR.into());
        }
        self.set_str(key, val);
        Ok(())
    }

    pub(crate) fn set_u8_checked(&mut self, key: u32, val: u8) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_U8 as u32) {
            return Err(ARES_EFORMERR.into());
        }
        self.set_u8(key, val);
        Ok(())
    }

    pub(crate) fn set_u16_checked(&mut self, key: u32, val: u16) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_U16 as u32) {
            return Err(ARES_EFORMERR.into());
        }
        self.set_u16(key, val);
        Ok(())
    }

    pub(crate) fn set_u32_checked(&mut self, key: u32, val: u32) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_U32 as u32) {
            return Err(ARES_EFORMERR.into());
        }
        self.set_u32(key, val);
        Ok(())
    }

    pub(crate) fn set_bin_checked(&mut self, key: u32, data: &[u8]) -> Result<(), AresError> {
        let dt = rr_key_datatype_of(key);
        if (dt != ARES_DATATYPE_BIN as u32
            && dt != ARES_DATATYPE_BINP as u32
            && dt != ARES_DATATYPE_ABINP as u32)
            || !self.key_type_ok(key)
        {
            return Err(ARES_EFORMERR.into());
        }
        self.set_bin(key, data);
        Ok(())
    }

    pub(crate) fn add_abin_checked(&mut self, key: u32, data: &[u8]) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_ABINP as u32) {
            return Err(ARES_EFORMERR.into());
        }
        self.append_bin(key, data);
        Ok(())
    }

    pub(crate) fn del_abin_checked(&mut self, key: u32, idx: usize) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_ABINP as u32)
            || !self.remove_bin(key, idx)
        {
            return Err(ARES_EFORMERR.into());
        }
        Ok(())
    }

    pub(crate) fn set_opt_checked(
        &mut self,
        key: u32,
        opt: u16,
        data: Vec<u8>,
    ) -> Result<(), AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_OPT as u32) {
            return Err(ARES_EFORMERR.into());
        }
        self.set_opt(opt, data);
        Ok(())
    }

    pub(crate) fn opt_cnt_checked(&self, key: u32) -> usize {
        if !self.key_has_datatype(key, ARES_DATATYPE_OPT as u32) {
            return 0;
        }
        self.opt_cnt()
    }

    pub(crate) fn opt_at_checked(&self, key: u32, idx: usize) -> Option<(u16, &[u8])> {
        if !self.key_has_datatype(key, ARES_DATATYPE_OPT as u32) {
            return None;
        }
        self.opt_at(idx)
    }

    pub(crate) fn opt_by_id_checked(&self, key: u32, opt: u16) -> Option<&[u8]> {
        if !self.key_has_datatype(key, ARES_DATATYPE_OPT as u32) {
            return None;
        }
        self.opt_by_id(opt)
    }

    pub(crate) fn del_opt_byid_checked(&mut self, key: u32, opt: u16) -> Result<bool, AresError> {
        if !self.key_has_datatype(key, ARES_DATATYPE_OPT as u32) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(self.del_opt_by_id(opt))
    }
}

// ---------------------------------------------------------------------------
// Whole-message codec (the pure bodies of ares_dns_parse/write)
// ---------------------------------------------------------------------------

impl ares_dns_record_t {
    /// ares_dns_record_create() with upstream validation.
    pub(crate) fn create(
        id: u16,
        flags: u16,
        opcode: u32,
        rcode: u32,
    ) -> Result<Self, AresError> {
        if !opcode_isvalid(opcode)
            || !rcode_isvalid(rcode)
            || !flags_arevalid(flags)
        {
            return Err(ARES_EFORMERR.into());
        }
        Ok(Self::new(id, flags, opcode as u16, rcode as u16))
    }

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
pub(crate) fn parse_record(data: &[u8], flags: u32) -> Result<ares_dns_record_t, AresError> {
    let buf_len = data.len();
    if buf_len < 12 {
        return Err(ARES_EBADRESP.into());
    }

    // Parse header (12 bytes)
    let id = ((data[0] as u16) << 8) | data[1] as u16;
    let wire_flags = ((data[2] as u16) << 8) | data[3] as u16;
    let qdcount = ((data[4] as u16) << 8) | data[5] as u16;
    let ancount = ((data[6] as u16) << 8) | data[7] as u16;
    let nscount = ((data[8] as u16) << 8) | data[9] as u16;
    let arcount = ((data[10] as u16) << 8) | data[11] as u16;

    let opcode = (wire_flags >> 11) & 0x0F;
    let rcode = wire_flags & 0x0F;
    if !opcode_isvalid(opcode as u32) {
        return Err(ARES_EFORMERR.into());
    }

    let mut rec = ares_dns_record_t {
        id,
        flags: flags_from_wire(wire_flags),
        opcode,
        rcode,
        queries: Vec::new(),
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
    };

    // Upstream requires exactly one question (0 or >1 is malformed).
    if qdcount != 1 {
        return Err(ARES_EBADRESP.into());
    }

    let mut pos = 12usize;

    // Parse the question.
    let qname = parse_dns_name(data, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
    if pos + 4 > buf_len {
        return Err(ARES_EBADRESP.into());
    }
    let qtype = ((data[pos] as u16) << 8) | data[pos + 1] as u16;
    let qclass = ((data[pos + 2] as u16) << 8) | data[pos + 3] as u16;
    pos += 4;
    rec.query_add(&qname, qtype as u32, qclass as u32)?;

    // Parse RR sections: answers, authority, additional.
    let section_counts = [
        (ancount, ARES_SECTION_ANSWER),
        (nscount, ARES_SECTION_AUTHORITY),
        (arcount, ARES_SECTION_ADDITIONAL),
    ];

    for (count, section) in &section_counts {
        for _ in 0..*count {
            let rr_name =
                parse_dns_name(data, &mut pos).ok_or(AresError::from(ARES_EBADNAME))?;
            if pos + 10 > buf_len {
                return Err(ARES_EBADRESP.into());
            }
            let wire_type = ((data[pos] as u16) << 8) | data[pos + 1] as u16;
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

            // Unknown types become RAW_RR; then the per-section raw flags can
            // force even a supported type to be preserved verbatim.
            let mut rtype = wire_type as u32;
            if !rec_type_isvalid(rtype, false) {
                rtype = ARES_REC_TYPE_RAW_RR;
            }
            let namecomp = allow_name_comp(rtype);
            let raw_flag = match *section {
                ARES_SECTION_ANSWER => {
                    if namecomp { ARES_DNS_PARSE_AN_BASE_RAW } else { ARES_DNS_PARSE_AN_EXT_RAW }
                }
                ARES_SECTION_AUTHORITY => {
                    if namecomp { ARES_DNS_PARSE_NS_BASE_RAW } else { ARES_DNS_PARSE_NS_EXT_RAW }
                }
                _ => {
                    if namecomp { ARES_DNS_PARSE_AR_BASE_RAW } else { ARES_DNS_PARSE_AR_EXT_RAW }
                }
            };
            if flags & raw_flag != 0 {
                rtype = ARES_REC_TYPE_RAW_RR;
            }

            let is_opt = rtype == ARES_REC_TYPE_OPT as u32;
            let mut rr = new_rr(
                &rr_name,
                rtype,
                if is_opt { ARES_CLASS_IN } else { rclass },
                if is_opt { 0 } else { ttl },
            );
            parse_rdata(
                rtype,
                wire_type,
                rdata,
                data,
                rdata_start,
                (rclass, ttl),
                &mut rr,
            )?;
            if rtype == ARES_REC_TYPE_OPT as u32 {
                // The OPT TTL carries the high 8 bits of the extended RCODE.
                rec.rcode |= ((ttl >> 20) & 0x0ff0) as u16;
            }

            let vec = section_vec_mut(&mut rec, *section).ok_or(AresError::from(ARES_EBADRESP))?;
            vec.push(rr);
        }
    }

    if !rcode_isvalid(rec.rcode as u32) {
        rec.rcode = ARES_RCODE_SERVFAIL;
    }

    Ok(rec)
}

/// Encode a whole DNS message to wire format.
pub(crate) fn write_record(rec: &ares_dns_record_t) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);

    // Write header
    out.push((rec.id >> 8) as u8);
    out.push(rec.id as u8);
    let has_opt = rec.additional.iter().any(|r| r.rtype == ARES_REC_TYPE_OPT as u32);
    let wire_rcode = if rec.rcode > 15 && !has_opt {
        ARES_RCODE_SERVFAIL
    } else {
        rec.rcode & 0xf
    };
    let wire_flags = flags_to_wire(rec.flags, rec.opcode, wire_rcode);
    out.push((wire_flags >> 8) as u8);
    out.push(wire_flags as u8);
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
            let wire_type = if rr.rtype == ARES_REC_TYPE_RAW_RR {
                rr.u16_val(ARES_RR_RAW_RR_TYPE).unwrap_or(0)
            } else {
                rr.rtype as u16
            };
            out.push((wire_type >> 8) as u8);
            out.push(wire_type as u8);
            out.push((rr.rclass >> 8) as u8);
            out.push(rr.rclass as u8);
            let ttl = if rr.rtype == ARES_REC_TYPE_OPT as u32 {
                let version = rr.u8_val(ARES_RR_OPT_VERSION).unwrap_or(0) as u32;
                let opt_flags = rr.u16_val(ARES_RR_OPT_FLAGS).unwrap_or(0) as u32;
                (((rec.rcode >> 4) as u32) << 24) | (version << 16) | opt_flags
            } else {
                rr.ttl
            };
            out.extend_from_slice(&ttl.to_be_bytes());

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
