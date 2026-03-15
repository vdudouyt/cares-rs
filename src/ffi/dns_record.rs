#![allow(non_camel_case_types, dead_code, unused_variables)]

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cstr;
use crate::ffi::error::{ARES_EBADRESP, ARES_ENOMEM, ARES_SUCCESS};

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
// A record keys
pub const ARES_RR_A_ADDR: u16 = 1;
// NS record keys
pub const ARES_RR_NS_NSDNAME: u16 = 2;
// CNAME record keys
pub const ARES_RR_CNAME_CNAME: u16 = 3;
// SOA record keys
pub const ARES_RR_SOA_MNAME: u16 = 4;
pub const ARES_RR_SOA_RNAME: u16 = 5;
pub const ARES_RR_SOA_SERIAL: u16 = 6;
pub const ARES_RR_SOA_REFRESH: u16 = 7;
pub const ARES_RR_SOA_RETRY: u16 = 8;
pub const ARES_RR_SOA_EXPIRE: u16 = 9;
pub const ARES_RR_SOA_MINIMUM: u16 = 10;
// PTR record keys
pub const ARES_RR_PTR_DNAME: u16 = 11;
// HINFO record keys
pub const ARES_RR_HINFO_CPU: u16 = 12;
pub const ARES_RR_HINFO_OS: u16 = 13;
// MX record keys
pub const ARES_RR_MX_PREFERENCE: u16 = 14;
pub const ARES_RR_MX_EXCHANGE: u16 = 15;
// TXT record keys
pub const ARES_RR_TXT_DATA: u16 = 16;
// AAAA record keys
pub const ARES_RR_AAAA_ADDR: u16 = 17;
// SRV record keys
pub const ARES_RR_SRV_PRIORITY: u16 = 18;
pub const ARES_RR_SRV_WEIGHT: u16 = 19;
pub const ARES_RR_SRV_PORT: u16 = 20;
pub const ARES_RR_SRV_TARGET: u16 = 21;
// NAPTR record keys
pub const ARES_RR_NAPTR_ORDER: u16 = 22;
pub const ARES_RR_NAPTR_PREFERENCE: u16 = 23;
pub const ARES_RR_NAPTR_FLAGS: u16 = 24;
pub const ARES_RR_NAPTR_SERVICES: u16 = 25;
pub const ARES_RR_NAPTR_REGEXP: u16 = 26;
pub const ARES_RR_NAPTR_REPLACEMENT: u16 = 27;
// OPT record keys
pub const ARES_RR_OPT_UDP_SIZE: u16 = 28;
pub const ARES_RR_OPT_VERSION: u16 = 29;
pub const ARES_RR_OPT_FLAGS: u16 = 30;
pub const ARES_RR_OPT_OPTIONS: u16 = 31;
// TLSA record keys
pub const ARES_RR_TLSA_CERT_USAGE: u16 = 32;
pub const ARES_RR_TLSA_SELECTOR: u16 = 33;
pub const ARES_RR_TLSA_MATCH: u16 = 34;
pub const ARES_RR_TLSA_DATA: u16 = 35;
// SVCB record keys
pub const ARES_RR_SVCB_PRIORITY: u16 = 36;
pub const ARES_RR_SVCB_TARGET: u16 = 37;
pub const ARES_RR_SVCB_PARAMS: u16 = 38;
// HTTPS record keys
pub const ARES_RR_HTTPS_PRIORITY: u16 = 39;
pub const ARES_RR_HTTPS_TARGET: u16 = 40;
pub const ARES_RR_HTTPS_PARAMS: u16 = 41;
// URI record keys
pub const ARES_RR_URI_PRIORITY: u16 = 42;
pub const ARES_RR_URI_WEIGHT: u16 = 43;
pub const ARES_RR_URI_TARGET: u16 = 44;
// CAA record keys
pub const ARES_RR_CAA_CRITICAL: u16 = 45;
pub const ARES_RR_CAA_TAG: u16 = 46;
pub const ARES_RR_CAA_VALUE: u16 = 47;
// RAW RR keys
pub const ARES_RR_RAW_RR_TYPE: u16 = 48;
pub const ARES_RR_RAW_RR_DATA: u16 = 49;

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
    Bin(Vec<u8>),
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
    data: HashMap<u16, RRValue>,
    opts: Vec<(u16, Vec<u8>)>,
    // Cached libc structs for returning pointers
    cached_in_addr: libc::in_addr,
    cached_in6_addr: libc::in6_addr,
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
    raw_buf: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn section_vec(rec: &ares_dns_record_t, sect: u32) -> Option<&Vec<ares_dns_rr_t>> {
    match sect {
        ARES_SECTION_ANSWER => Some(&rec.answers),
        ARES_SECTION_AUTHORITY => Some(&rec.authority),
        ARES_SECTION_ADDITIONAL => Some(&rec.additional),
        _ => None,
    }
}

fn section_vec_mut(rec: &mut ares_dns_record_t, sect: u32) -> Option<&mut Vec<ares_dns_rr_t>> {
    match sect {
        ARES_SECTION_ANSWER => Some(&mut rec.answers),
        ARES_SECTION_AUTHORITY => Some(&mut rec.authority),
        ARES_SECTION_ADDITIONAL => Some(&mut rec.additional),
        _ => None,
    }
}

fn new_rr(name: &str, rtype: u16, rclass: u16, ttl: u32) -> ares_dns_rr_t {
    ares_dns_rr_t {
        name: name.to_string(),
        name_c: CString::new(name).unwrap_or_default(),
        rtype,
        rclass,
        ttl,
        data: HashMap::new(),
        opts: Vec::new(),
        cached_in_addr: libc::in_addr { s_addr: 0 },
        cached_in6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
    }
}

// ---------------------------------------------------------------------------
// DNS wire-format helpers (for ares_dns_parse / ares_dns_write)
// ---------------------------------------------------------------------------

/// Read a DNS name from wire format, handling label compression.
/// Returns the name as a dotted string, advancing `pos` past the name bytes.
fn parse_dns_name(buf: &[u8], pos: &mut usize) -> Option<String> {
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
fn write_dns_name(name: &str, out: &mut Vec<u8>) {
    if !name.is_empty() {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0); // root label terminator
}

/// Parse rdata fields for a given RR type from wire format into key/value pairs.
fn parse_rdata(
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
            // TXT records: one or more length-prefixed strings, stored as raw binary
            rr.data
                .insert(ARES_RR_TXT_DATA, RRValue::Bin(rdata.to_vec()));
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
                    .insert(ARES_RR_TLSA_DATA, RRValue::Bin(rdata[3..].to_vec()));
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
                        RRValue::Bin(rdata[consumed..].to_vec()),
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
                        RRValue::Bin(rdata[consumed..].to_vec()),
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
                        .insert(ARES_RR_CAA_VALUE, RRValue::Bin(val.to_vec()));
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
                .insert(ARES_RR_RAW_RR_DATA, RRValue::Bin(rdata.to_vec()));
        }
    }
}

/// Serialize rdata for a given RR to wire format.
fn write_rdata(rr: &ares_dns_rr_t, out: &mut Vec<u8>) {
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
                out.extend_from_slice(data);
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
    let rec = Box::new(ares_dns_record_t {
        id: id as u16,
        flags: flags as u16,
        opcode: opcode as u16,
        rcode: rcode as u16,
        queries: Vec::new(),
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        raw_buf: None,
    });
    *dnsrec = Box::into_raw(rec);
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_destroy(dnsrec: *mut ares_dns_record_t) {
    if !dnsrec.is_null() {
        let _ = Box::from_raw(dnsrec);
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
    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut buf_len: usize = 0;
    if ares_dns_write(dnsrec as *const _, &mut buf, &mut buf_len) != ARES_SUCCESS {
        return std::ptr::null_mut();
    }
    let mut out: *mut ares_dns_record_t = std::ptr::null_mut();
    let status = ares_dns_parse(buf, buf_len, 0, &mut out);
    libc::free(buf as *mut _);
    if status != ARES_SUCCESS {
        return std::ptr::null_mut();
    }
    out
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
    (*dnsrec).id as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_flags(
    dnsrec: *const ares_dns_record_t,
) -> c_uint {
    if dnsrec.is_null() {
        return 0;
    }
    (*dnsrec).flags as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_opcode(
    dnsrec: *const ares_dns_record_t,
) -> c_uint {
    if dnsrec.is_null() {
        return 0;
    }
    (*dnsrec).opcode as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_get_rcode(
    dnsrec: *const ares_dns_record_t,
) -> c_uint {
    if dnsrec.is_null() {
        return 0;
    }
    (*dnsrec).rcode as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_set_id(
    dnsrec: *mut ares_dns_record_t,
    id: c_uint,
) {
    if !dnsrec.is_null() {
        (*dnsrec).id = id as u16;
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
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ARES_EBADRESP,
    };
    let name_c = match CString::new(name_str.clone()) {
        Ok(c) => c,
        Err(_) => return ARES_EBADRESP,
    };
    (*dnsrec).queries.push(DnsRecordQuery {
        name: name_str,
        name_c,
        qtype: qtype as u16,
        qclass: qclass as u16,
    });
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_cnt(
    dnsrec: *const ares_dns_record_t,
) -> usize {
    if dnsrec.is_null() {
        return 0;
    }
    (*dnsrec).queries.len()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_get(
    dnsrec: *const ares_dns_record_t,
    idx: usize,
    name: *mut *const c_char,
    qtype: *mut c_uint,
    qclass: *mut c_uint,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EBADRESP;
    }
    let rec = &*dnsrec;
    if idx >= rec.queries.len() {
        return ARES_EBADRESP;
    }
    let q = &rec.queries[idx];
    if !name.is_null() {
        *name = q.name_c.as_ptr();
    }
    if !qtype.is_null() {
        *qtype = q.qtype as c_uint;
    }
    if !qclass.is_null() {
        *qclass = q.qclass as c_uint;
    }
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_set_name(
    dnsrec: *mut ares_dns_record_t,
    idx: usize,
    name: *const c_char,
) -> c_int {
    if dnsrec.is_null() || name.is_null() {
        return ARES_EBADRESP;
    }
    let rec = &mut *dnsrec;
    if idx >= rec.queries.len() {
        return ARES_EBADRESP;
    }
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ARES_EBADRESP,
    };
    let name_c = match CString::new(name_str.clone()) {
        Ok(c) => c,
        Err(_) => return ARES_EBADRESP,
    };
    rec.queries[idx].name = name_str;
    rec.queries[idx].name_c = name_c;
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_query_set_type(
    dnsrec: *mut ares_dns_record_t,
    idx: usize,
    qtype: c_uint,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EBADRESP;
    }
    let rec = &mut *dnsrec;
    if idx >= rec.queries.len() {
        return ARES_EBADRESP;
    }
    rec.queries[idx].qtype = qtype as u16;
    ARES_SUCCESS
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
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADRESP,
    };
    let rec = &mut *dnsrec;
    let vec = match section_vec_mut(rec, sect as u32) {
        Some(v) => v,
        None => return ARES_EBADRESP,
    };
    vec.push(new_rr(name_str, rtype as u16, rclass as u16, ttl as u32));
    if !rr.is_null() {
        *rr = vec.last_mut().unwrap() as *mut ares_dns_rr_t;
    }
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_cnt(
    dnsrec: *const ares_dns_record_t,
    sect: c_uint,
) -> usize {
    if dnsrec.is_null() {
        return 0;
    }
    match section_vec(&*dnsrec, sect as u32) {
        Some(v) => v.len(),
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_get(
    dnsrec: *mut ares_dns_record_t,
    sect: c_uint,
    idx: usize,
) -> *mut ares_dns_rr_t {
    if dnsrec.is_null() {
        return std::ptr::null_mut();
    }
    let rec = &mut *dnsrec;
    let vec = match section_vec_mut(rec, sect as u32) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    if idx >= vec.len() {
        return std::ptr::null_mut();
    }
    &mut vec[idx] as *mut ares_dns_rr_t
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_get_const(
    dnsrec: *const ares_dns_record_t,
    sect: c_uint,
    idx: usize,
) -> *const ares_dns_rr_t {
    if dnsrec.is_null() {
        return std::ptr::null();
    }
    let rec = &*dnsrec;
    let vec = match section_vec(rec, sect as u32) {
        Some(v) => v,
        None => return std::ptr::null(),
    };
    if idx >= vec.len() {
        return std::ptr::null();
    }
    &vec[idx] as *const ares_dns_rr_t
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_record_rr_del(
    dnsrec: *mut ares_dns_record_t,
    sect: c_uint,
    idx: usize,
) -> c_int {
    if dnsrec.is_null() {
        return ARES_EBADRESP;
    }
    let rec = &mut *dnsrec;
    let vec = match section_vec_mut(rec, sect as u32) {
        Some(v) => v,
        None => return ARES_EBADRESP,
    };
    if idx >= vec.len() {
        return ARES_EBADRESP;
    }
    vec.remove(idx);
    ARES_SUCCESS
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
    (*rr).name_c.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_type(rr: *const ares_dns_rr_t) -> c_uint {
    if rr.is_null() {
        return 0;
    }
    (*rr).rtype as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_class(rr: *const ares_dns_rr_t) -> c_uint {
    if rr.is_null() {
        return 0;
    }
    (*rr).rclass as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_ttl(rr: *const ares_dns_rr_t) -> c_uint {
    if rr.is_null() {
        return 0;
    }
    (*rr).ttl as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_addr(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> *const libc::in_addr {
    if rr.is_null() {
        return std::ptr::null();
    }
    let rr_mut = rr as *mut ares_dns_rr_t;
    if let Some(RRValue::Addr(addr)) = (*rr_mut).data.get(&(key as u16)) {
        let octets = addr.octets();
        (*rr_mut).cached_in_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(octets),
        };
        &(*rr_mut).cached_in_addr as *const libc::in_addr
    } else {
        std::ptr::null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_addr6(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> *const libc::in6_addr {
    if rr.is_null() {
        return std::ptr::null();
    }
    let rr_mut = rr as *mut ares_dns_rr_t;
    if let Some(RRValue::Addr6(addr)) = (*rr_mut).data.get(&(key as u16)) {
        (*rr_mut).cached_in6_addr = libc::in6_addr {
            s6_addr: addr.octets(),
        };
        &(*rr_mut).cached_in6_addr as *const libc::in6_addr
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
    if let Some(RRValue::Str(s)) = (*rr).data.get(&(key as u16)) {
        s.as_ptr()
    } else {
        std::ptr::null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_u8(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> u8 {
    if rr.is_null() {
        return 0;
    }
    if let Some(RRValue::U8(v)) = (*rr).data.get(&(key as u16)) {
        *v
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_u16(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> u16 {
    if rr.is_null() {
        return 0;
    }
    if let Some(RRValue::U16(v)) = (*rr).data.get(&(key as u16)) {
        *v
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_u32(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> u32 {
    if rr.is_null() {
        return 0;
    }
    if let Some(RRValue::U32(v)) = (*rr).data.get(&(key as u16)) {
        *v
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_bin(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    val: *mut *const u8,
    len: *mut usize,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    if let Some(RRValue::Bin(data)) = (*rr).data.get(&(key as u16)) {
        if !val.is_null() {
            *val = data.as_ptr();
        }
        if !len.is_null() {
            *len = data.len();
        }
        ARES_SUCCESS
    } else {
        if !val.is_null() {
            *val = std::ptr::null();
        }
        if !len.is_null() {
            *len = 0;
        }
        ARES_EBADRESP
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
    let octets = (*addr).s_addr.to_ne_bytes();
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    (*rr).data.insert(key as u16, RRValue::Addr(ip));
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_addr6(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    addr: *const libc::in6_addr,
) -> c_int {
    if rr.is_null() || addr.is_null() {
        return ARES_EBADRESP;
    }
    let ip = Ipv6Addr::from((*addr).s6_addr);
    (*rr).data.insert(key as u16, RRValue::Addr6(ip));
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
    let cstr = CStr::from_ptr(val);
    let owned = CString::from(cstr);
    (*rr).data.insert(key as u16, RRValue::Str(owned));
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
    (*rr).data.insert(key as u16, RRValue::U8(val));
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
    (*rr).data.insert(key as u16, RRValue::U16(val));
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
    (*rr).data.insert(key as u16, RRValue::U32(val));
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_bin(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    val: *const u8,
    len: usize,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    let data = if val.is_null() || len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(val, len).to_vec()
    };
    (*rr).data.insert(key as u16, RRValue::Bin(data));
    ARES_SUCCESS
}

// ---------------------------------------------------------------------------
// OPT handling
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_set_opt(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
    val: *const u8,
    val_len: usize,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    let data = if val.is_null() || val_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(val, val_len).to_vec()
    };
    // Remove existing opt with same code if present, then add
    (*rr).opts.retain(|(code, _)| *code != opt as u16);
    (*rr).opts.push((opt as u16, data));
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_opt_cnt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
) -> usize {
    if rr.is_null() {
        return 0;
    }
    (*rr).opts.len()
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_opt(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    idx: usize,
    opt: *mut c_uint,
    val: *mut *const u8,
    val_len: *mut usize,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    if idx >= (*rr).opts.len() {
        return ARES_EBADRESP;
    }
    let (code, data) = &(&(*rr).opts)[idx];
    if !opt.is_null() {
        *opt = *code as c_uint;
    }
    if !val.is_null() {
        *val = data.as_ptr();
    }
    if !val_len.is_null() {
        *val_len = data.len();
    }
    ARES_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_opt_byid(
    rr: *const ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
    val: *mut *const u8,
    val_len: *mut usize,
) -> c_int {
    if rr.is_null() {
        return ARES_FALSE;
    }
    let opt_u16 = opt as u16;
    for (code, data) in &(*rr).opts {
        if *code == opt_u16 {
            if !val.is_null() {
                *val = data.as_ptr();
            }
            if !val_len.is_null() {
                *val_len = data.len();
            }
            return ARES_TRUE;
        }
    }
    ARES_FALSE
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_del_opt_byid(
    rr: *mut ares_dns_rr_t,
    key: c_uint,
    opt: c_uint,
) -> c_int {
    if rr.is_null() {
        return ARES_EBADRESP;
    }
    let opt_u16 = opt as u16;
    let before = (*rr).opts.len();
    (*rr).opts.retain(|(code, _)| *code != opt_u16);
    if (*rr).opts.len() < before {
        ARES_SUCCESS
    } else {
        ARES_EBADRESP
    }
}

// ---------------------------------------------------------------------------
// Serialization: ares_dns_parse
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_parse(
    buf: *const u8,
    buf_len: usize,
    flags: c_uint,
    dnsrec: *mut *mut ares_dns_record_t,
) -> c_int {
    if buf.is_null() || dnsrec.is_null() || buf_len < 12 {
        return ARES_EBADRESP;
    }
    let data = std::slice::from_raw_parts(buf, buf_len);

    // Parse header (12 bytes)
    let id = ((data[0] as u16) << 8) | data[1] as u16;
    let flags_val = ((data[2] as u16) << 8) | data[3] as u16;
    let qdcount = ((data[4] as u16) << 8) | data[5] as u16;
    let ancount = ((data[6] as u16) << 8) | data[7] as u16;
    let nscount = ((data[8] as u16) << 8) | data[9] as u16;
    let arcount = ((data[10] as u16) << 8) | data[11] as u16;

    let opcode = (flags_val >> 11) & 0x0F;
    let rcode = flags_val & 0x0F;

    let mut rec = Box::new(ares_dns_record_t {
        id,
        flags: flags_val,
        opcode,
        rcode,
        queries: Vec::new(),
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        raw_buf: Some(data.to_vec()),
    });

    let mut pos = 12usize;

    // Parse questions
    for _ in 0..qdcount {
        let name = match parse_dns_name(data, &mut pos) {
            Some(n) => n,
            None => return ARES_EBADRESP,
        };
        if pos + 4 > buf_len {
            return ARES_EBADRESP;
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
            let rr_name = match parse_dns_name(data, &mut pos) {
                Some(n) => n,
                None => return ARES_EBADRESP,
            };
            if pos + 10 > buf_len {
                return ARES_EBADRESP;
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
                return ARES_EBADRESP;
            }
            let rdata = &data[pos..pos + rdlength as usize];
            pos += rdlength as usize;

            let mut rr = new_rr(&rr_name, rtype, rclass, ttl);
            parse_rdata(rtype, rdata, data, rdata_start, &mut rr);

            let vec = match section_vec_mut(&mut rec, *section) {
                Some(v) => v,
                None => return ARES_EBADRESP,
            };
            vec.push(rr);
        }
    }

    *dnsrec = Box::into_raw(rec);
    ARES_SUCCESS
}

// ---------------------------------------------------------------------------
// Serialization: ares_dns_write
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_write(
    dnsrec: *const ares_dns_record_t,
    buf: *mut *mut u8,
    buf_len: *mut usize,
) -> c_int {
    if dnsrec.is_null() || buf.is_null() || buf_len.is_null() {
        return ARES_EBADRESP;
    }
    let rec = &*dnsrec;

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

    // Allocate with libc::malloc for C interop
    let total_len = out.len();
    let ptr = libc::malloc(total_len) as *mut u8;
    if ptr.is_null() {
        return ARES_ENOMEM;
    }
    std::ptr::copy_nonoverlapping(out.as_ptr(), ptr, total_len);
    *buf = ptr;
    *buf_len = total_len;
    ARES_SUCCESS
}

// ---------------------------------------------------------------------------
// Metadata / string functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rec_type_tostr(rtype: c_uint) -> *const c_char {
    match rtype as u32 {
        1 => cstr!("A"),
        2 => cstr!("NS"),
        5 => cstr!("CNAME"),
        6 => cstr!("SOA"),
        12 => cstr!("PTR"),
        13 => cstr!("HINFO"),
        15 => cstr!("MX"),
        16 => cstr!("TXT"),
        28 => cstr!("AAAA"),
        33 => cstr!("SRV"),
        35 => cstr!("NAPTR"),
        41 => cstr!("OPT"),
        52 => cstr!("TLSA"),
        64 => cstr!("SVCB"),
        65 => cstr!("HTTPS"),
        255 => cstr!("ANY"),
        256 => cstr!("URI"),
        257 => cstr!("CAA"),
        65536 => cstr!("RAW_RR"),
        _ => cstr!(""),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rec_type_fromstr(
    str_ptr: *const c_char,
    rtype: *mut c_uint,
) -> c_int {
    if str_ptr.is_null() || rtype.is_null() {
        return ARES_FALSE;
    }
    let s = match CStr::from_ptr(str_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return ARES_FALSE,
    };
    let val: c_uint = match s {
        "A" => ARES_REC_TYPE_A as c_uint,
        "NS" => ARES_REC_TYPE_NS as c_uint,
        "CNAME" => ARES_REC_TYPE_CNAME as c_uint,
        "SOA" => ARES_REC_TYPE_SOA as c_uint,
        "PTR" => ARES_REC_TYPE_PTR as c_uint,
        "HINFO" => ARES_REC_TYPE_HINFO as c_uint,
        "MX" => ARES_REC_TYPE_MX as c_uint,
        "TXT" => ARES_REC_TYPE_TXT as c_uint,
        "AAAA" => ARES_REC_TYPE_AAAA as c_uint,
        "SRV" => ARES_REC_TYPE_SRV as c_uint,
        "NAPTR" => ARES_REC_TYPE_NAPTR as c_uint,
        "OPT" => ARES_REC_TYPE_OPT as c_uint,
        "TLSA" => ARES_REC_TYPE_TLSA as c_uint,
        "SVCB" => ARES_REC_TYPE_SVCB as c_uint,
        "HTTPS" => ARES_REC_TYPE_HTTPS as c_uint,
        "ANY" => ARES_REC_TYPE_ANY as c_uint,
        "URI" => ARES_REC_TYPE_URI as c_uint,
        "CAA" => ARES_REC_TYPE_CAA as c_uint,
        "RAW_RR" => ARES_REC_TYPE_RAW_RR as c_uint,
        _ => return ARES_FALSE,
    };
    *rtype = val;
    ARES_TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_class_tostr(qclass: c_uint) -> *const c_char {
    match qclass as u16 {
        ARES_CLASS_IN => cstr!("IN"),
        ARES_CLASS_CHAOS => cstr!("CH"),
        ARES_CLASS_HESOID => cstr!("HS"),
        ARES_CLASS_NONE => cstr!("NONE"),
        ARES_CLASS_ANY => cstr!("ANY"),
        _ => cstr!(""),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_class_fromstr(
    str_ptr: *const c_char,
    qclass: *mut c_uint,
) -> c_int {
    if str_ptr.is_null() || qclass.is_null() {
        return ARES_FALSE;
    }
    let s = match CStr::from_ptr(str_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return ARES_FALSE,
    };
    let val: c_uint = match s {
        "IN" => ARES_CLASS_IN as c_uint,
        "CH" => ARES_CLASS_CHAOS as c_uint,
        "HS" => ARES_CLASS_HESOID as c_uint,
        "NONE" => ARES_CLASS_NONE as c_uint,
        "ANY" => ARES_CLASS_ANY as c_uint,
        _ => return ARES_FALSE,
    };
    *qclass = val;
    ARES_TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_tostr(key: c_uint) -> *const c_char {
    match key as u16 {
        ARES_RR_A_ADDR => cstr!("A.ADDR"),
        ARES_RR_NS_NSDNAME => cstr!("NS.NSDNAME"),
        ARES_RR_CNAME_CNAME => cstr!("CNAME.CNAME"),
        ARES_RR_SOA_MNAME => cstr!("SOA.MNAME"),
        ARES_RR_SOA_RNAME => cstr!("SOA.RNAME"),
        ARES_RR_SOA_SERIAL => cstr!("SOA.SERIAL"),
        ARES_RR_SOA_REFRESH => cstr!("SOA.REFRESH"),
        ARES_RR_SOA_RETRY => cstr!("SOA.RETRY"),
        ARES_RR_SOA_EXPIRE => cstr!("SOA.EXPIRE"),
        ARES_RR_SOA_MINIMUM => cstr!("SOA.MINIMUM"),
        ARES_RR_PTR_DNAME => cstr!("PTR.DNAME"),
        ARES_RR_HINFO_CPU => cstr!("HINFO.CPU"),
        ARES_RR_HINFO_OS => cstr!("HINFO.OS"),
        ARES_RR_MX_PREFERENCE => cstr!("MX.PREFERENCE"),
        ARES_RR_MX_EXCHANGE => cstr!("MX.EXCHANGE"),
        ARES_RR_TXT_DATA => cstr!("TXT.DATA"),
        ARES_RR_AAAA_ADDR => cstr!("AAAA.ADDR"),
        ARES_RR_SRV_PRIORITY => cstr!("SRV.PRIORITY"),
        ARES_RR_SRV_WEIGHT => cstr!("SRV.WEIGHT"),
        ARES_RR_SRV_PORT => cstr!("SRV.PORT"),
        ARES_RR_SRV_TARGET => cstr!("SRV.TARGET"),
        ARES_RR_NAPTR_ORDER => cstr!("NAPTR.ORDER"),
        ARES_RR_NAPTR_PREFERENCE => cstr!("NAPTR.PREFERENCE"),
        ARES_RR_NAPTR_FLAGS => cstr!("NAPTR.FLAGS"),
        ARES_RR_NAPTR_SERVICES => cstr!("NAPTR.SERVICES"),
        ARES_RR_NAPTR_REGEXP => cstr!("NAPTR.REGEXP"),
        ARES_RR_NAPTR_REPLACEMENT => cstr!("NAPTR.REPLACEMENT"),
        ARES_RR_OPT_UDP_SIZE => cstr!("OPT.UDP_SIZE"),
        ARES_RR_OPT_VERSION => cstr!("OPT.VERSION"),
        ARES_RR_OPT_FLAGS => cstr!("OPT.FLAGS"),
        ARES_RR_OPT_OPTIONS => cstr!("OPT.OPTIONS"),
        ARES_RR_TLSA_CERT_USAGE => cstr!("TLSA.CERT_USAGE"),
        ARES_RR_TLSA_SELECTOR => cstr!("TLSA.SELECTOR"),
        ARES_RR_TLSA_MATCH => cstr!("TLSA.MATCH"),
        ARES_RR_TLSA_DATA => cstr!("TLSA.DATA"),
        ARES_RR_SVCB_PRIORITY => cstr!("SVCB.PRIORITY"),
        ARES_RR_SVCB_TARGET => cstr!("SVCB.TARGET"),
        ARES_RR_SVCB_PARAMS => cstr!("SVCB.PARAMS"),
        ARES_RR_HTTPS_PRIORITY => cstr!("HTTPS.PRIORITY"),
        ARES_RR_HTTPS_TARGET => cstr!("HTTPS.TARGET"),
        ARES_RR_HTTPS_PARAMS => cstr!("HTTPS.PARAMS"),
        ARES_RR_URI_PRIORITY => cstr!("URI.PRIORITY"),
        ARES_RR_URI_WEIGHT => cstr!("URI.WEIGHT"),
        ARES_RR_URI_TARGET => cstr!("URI.TARGET"),
        ARES_RR_CAA_CRITICAL => cstr!("CAA.CRITICAL"),
        ARES_RR_CAA_TAG => cstr!("CAA.TAG"),
        ARES_RR_CAA_VALUE => cstr!("CAA.VALUE"),
        ARES_RR_RAW_RR_TYPE => cstr!("RAW_RR.TYPE"),
        ARES_RR_RAW_RR_DATA => cstr!("RAW_RR.DATA"),
        _ => cstr!(""),
    }
}

// ---------------------------------------------------------------------------
// Static key arrays for ares_dns_rr_get_keys
// ---------------------------------------------------------------------------

static KEYS_A: [c_uint; 1] = [ARES_RR_A_ADDR as c_uint];
static KEYS_NS: [c_uint; 1] = [ARES_RR_NS_NSDNAME as c_uint];
static KEYS_CNAME: [c_uint; 1] = [ARES_RR_CNAME_CNAME as c_uint];
static KEYS_SOA: [c_uint; 7] = [
    ARES_RR_SOA_MNAME as c_uint,
    ARES_RR_SOA_RNAME as c_uint,
    ARES_RR_SOA_SERIAL as c_uint,
    ARES_RR_SOA_REFRESH as c_uint,
    ARES_RR_SOA_RETRY as c_uint,
    ARES_RR_SOA_EXPIRE as c_uint,
    ARES_RR_SOA_MINIMUM as c_uint,
];
static KEYS_PTR: [c_uint; 1] = [ARES_RR_PTR_DNAME as c_uint];
static KEYS_HINFO: [c_uint; 2] =
    [ARES_RR_HINFO_CPU as c_uint, ARES_RR_HINFO_OS as c_uint];
static KEYS_MX: [c_uint; 2] = [
    ARES_RR_MX_PREFERENCE as c_uint,
    ARES_RR_MX_EXCHANGE as c_uint,
];
static KEYS_TXT: [c_uint; 1] = [ARES_RR_TXT_DATA as c_uint];
static KEYS_AAAA: [c_uint; 1] = [ARES_RR_AAAA_ADDR as c_uint];
static KEYS_SRV: [c_uint; 4] = [
    ARES_RR_SRV_PRIORITY as c_uint,
    ARES_RR_SRV_WEIGHT as c_uint,
    ARES_RR_SRV_PORT as c_uint,
    ARES_RR_SRV_TARGET as c_uint,
];
static KEYS_NAPTR: [c_uint; 6] = [
    ARES_RR_NAPTR_ORDER as c_uint,
    ARES_RR_NAPTR_PREFERENCE as c_uint,
    ARES_RR_NAPTR_FLAGS as c_uint,
    ARES_RR_NAPTR_SERVICES as c_uint,
    ARES_RR_NAPTR_REGEXP as c_uint,
    ARES_RR_NAPTR_REPLACEMENT as c_uint,
];
static KEYS_OPT: [c_uint; 4] = [
    ARES_RR_OPT_UDP_SIZE as c_uint,
    ARES_RR_OPT_VERSION as c_uint,
    ARES_RR_OPT_FLAGS as c_uint,
    ARES_RR_OPT_OPTIONS as c_uint,
];
static KEYS_TLSA: [c_uint; 4] = [
    ARES_RR_TLSA_CERT_USAGE as c_uint,
    ARES_RR_TLSA_SELECTOR as c_uint,
    ARES_RR_TLSA_MATCH as c_uint,
    ARES_RR_TLSA_DATA as c_uint,
];
static KEYS_SVCB: [c_uint; 3] = [
    ARES_RR_SVCB_PRIORITY as c_uint,
    ARES_RR_SVCB_TARGET as c_uint,
    ARES_RR_SVCB_PARAMS as c_uint,
];
static KEYS_HTTPS: [c_uint; 3] = [
    ARES_RR_HTTPS_PRIORITY as c_uint,
    ARES_RR_HTTPS_TARGET as c_uint,
    ARES_RR_HTTPS_PARAMS as c_uint,
];
static KEYS_URI: [c_uint; 3] = [
    ARES_RR_URI_PRIORITY as c_uint,
    ARES_RR_URI_WEIGHT as c_uint,
    ARES_RR_URI_TARGET as c_uint,
];
static KEYS_CAA: [c_uint; 3] = [
    ARES_RR_CAA_CRITICAL as c_uint,
    ARES_RR_CAA_TAG as c_uint,
    ARES_RR_CAA_VALUE as c_uint,
];
static KEYS_RAW_RR: [c_uint; 2] =
    [ARES_RR_RAW_RR_TYPE as c_uint, ARES_RR_RAW_RR_DATA as c_uint];

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_get_keys(
    rtype: c_uint,
    cnt: *mut usize,
) -> *const c_uint {
    if cnt.is_null() {
        return std::ptr::null();
    }
    let (ptr, len): (*const c_uint, usize) = match rtype as u32 {
        1 => (KEYS_A.as_ptr(), KEYS_A.len()),
        2 => (KEYS_NS.as_ptr(), KEYS_NS.len()),
        5 => (KEYS_CNAME.as_ptr(), KEYS_CNAME.len()),
        6 => (KEYS_SOA.as_ptr(), KEYS_SOA.len()),
        12 => (KEYS_PTR.as_ptr(), KEYS_PTR.len()),
        13 => (KEYS_HINFO.as_ptr(), KEYS_HINFO.len()),
        15 => (KEYS_MX.as_ptr(), KEYS_MX.len()),
        16 => (KEYS_TXT.as_ptr(), KEYS_TXT.len()),
        28 => (KEYS_AAAA.as_ptr(), KEYS_AAAA.len()),
        33 => (KEYS_SRV.as_ptr(), KEYS_SRV.len()),
        35 => (KEYS_NAPTR.as_ptr(), KEYS_NAPTR.len()),
        41 => (KEYS_OPT.as_ptr(), KEYS_OPT.len()),
        52 => (KEYS_TLSA.as_ptr(), KEYS_TLSA.len()),
        64 => (KEYS_SVCB.as_ptr(), KEYS_SVCB.len()),
        65 => (KEYS_HTTPS.as_ptr(), KEYS_HTTPS.len()),
        256 => (KEYS_URI.as_ptr(), KEYS_URI.len()),
        257 => (KEYS_CAA.as_ptr(), KEYS_CAA.len()),
        65536 => (KEYS_RAW_RR.as_ptr(), KEYS_RAW_RR.len()),
        _ => {
            *cnt = 0;
            return std::ptr::null();
        }
    };
    *cnt = len;
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_datatype(key: c_uint) -> c_uint {
    match key as u16 {
        ARES_RR_A_ADDR => ARES_DATATYPE_INADDR as c_uint,
        ARES_RR_NS_NSDNAME => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_CNAME_CNAME => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_SOA_MNAME => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_SOA_RNAME => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_SOA_SERIAL => ARES_DATATYPE_U32 as c_uint,
        ARES_RR_SOA_REFRESH => ARES_DATATYPE_U32 as c_uint,
        ARES_RR_SOA_RETRY => ARES_DATATYPE_U32 as c_uint,
        ARES_RR_SOA_EXPIRE => ARES_DATATYPE_U32 as c_uint,
        ARES_RR_SOA_MINIMUM => ARES_DATATYPE_U32 as c_uint,
        ARES_RR_PTR_DNAME => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_HINFO_CPU => ARES_DATATYPE_STR as c_uint,
        ARES_RR_HINFO_OS => ARES_DATATYPE_STR as c_uint,
        ARES_RR_MX_PREFERENCE => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_MX_EXCHANGE => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_TXT_DATA => ARES_DATATYPE_ABINP as c_uint,
        ARES_RR_AAAA_ADDR => ARES_DATATYPE_INADDR6 as c_uint,
        ARES_RR_SRV_PRIORITY => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_SRV_WEIGHT => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_SRV_PORT => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_SRV_TARGET => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_NAPTR_ORDER => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_NAPTR_PREFERENCE => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_NAPTR_FLAGS => ARES_DATATYPE_STR as c_uint,
        ARES_RR_NAPTR_SERVICES => ARES_DATATYPE_STR as c_uint,
        ARES_RR_NAPTR_REGEXP => ARES_DATATYPE_STR as c_uint,
        ARES_RR_NAPTR_REPLACEMENT => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_OPT_UDP_SIZE => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_OPT_VERSION => ARES_DATATYPE_U8 as c_uint,
        ARES_RR_OPT_FLAGS => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_OPT_OPTIONS => ARES_DATATYPE_OPT as c_uint,
        ARES_RR_TLSA_CERT_USAGE => ARES_DATATYPE_U8 as c_uint,
        ARES_RR_TLSA_SELECTOR => ARES_DATATYPE_U8 as c_uint,
        ARES_RR_TLSA_MATCH => ARES_DATATYPE_U8 as c_uint,
        ARES_RR_TLSA_DATA => ARES_DATATYPE_BIN as c_uint,
        ARES_RR_SVCB_PRIORITY => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_SVCB_TARGET => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_SVCB_PARAMS => ARES_DATATYPE_OPT as c_uint,
        ARES_RR_HTTPS_PRIORITY => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_HTTPS_TARGET => ARES_DATATYPE_NAME as c_uint,
        ARES_RR_HTTPS_PARAMS => ARES_DATATYPE_OPT as c_uint,
        ARES_RR_URI_PRIORITY => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_URI_WEIGHT => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_URI_TARGET => ARES_DATATYPE_STR as c_uint,
        ARES_RR_CAA_CRITICAL => ARES_DATATYPE_U8 as c_uint,
        ARES_RR_CAA_TAG => ARES_DATATYPE_STR as c_uint,
        ARES_RR_CAA_VALUE => ARES_DATATYPE_BINP as c_uint,
        ARES_RR_RAW_RR_TYPE => ARES_DATATYPE_U16 as c_uint,
        ARES_RR_RAW_RR_DATA => ARES_DATATYPE_BIN as c_uint,
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_dns_rr_key_to_rec_type(key: c_uint) -> c_uint {
    match key as u16 {
        ARES_RR_A_ADDR => ARES_REC_TYPE_A as c_uint,
        ARES_RR_NS_NSDNAME => ARES_REC_TYPE_NS as c_uint,
        ARES_RR_CNAME_CNAME => ARES_REC_TYPE_CNAME as c_uint,
        ARES_RR_SOA_MNAME | ARES_RR_SOA_RNAME | ARES_RR_SOA_SERIAL
        | ARES_RR_SOA_REFRESH | ARES_RR_SOA_RETRY | ARES_RR_SOA_EXPIRE
        | ARES_RR_SOA_MINIMUM => ARES_REC_TYPE_SOA as c_uint,
        ARES_RR_PTR_DNAME => ARES_REC_TYPE_PTR as c_uint,
        ARES_RR_HINFO_CPU | ARES_RR_HINFO_OS => ARES_REC_TYPE_HINFO as c_uint,
        ARES_RR_MX_PREFERENCE | ARES_RR_MX_EXCHANGE => ARES_REC_TYPE_MX as c_uint,
        ARES_RR_TXT_DATA => ARES_REC_TYPE_TXT as c_uint,
        ARES_RR_AAAA_ADDR => ARES_REC_TYPE_AAAA as c_uint,
        ARES_RR_SRV_PRIORITY | ARES_RR_SRV_WEIGHT | ARES_RR_SRV_PORT
        | ARES_RR_SRV_TARGET => ARES_REC_TYPE_SRV as c_uint,
        ARES_RR_NAPTR_ORDER | ARES_RR_NAPTR_PREFERENCE | ARES_RR_NAPTR_FLAGS
        | ARES_RR_NAPTR_SERVICES | ARES_RR_NAPTR_REGEXP
        | ARES_RR_NAPTR_REPLACEMENT => ARES_REC_TYPE_NAPTR as c_uint,
        ARES_RR_OPT_UDP_SIZE | ARES_RR_OPT_VERSION | ARES_RR_OPT_FLAGS
        | ARES_RR_OPT_OPTIONS => ARES_REC_TYPE_OPT as c_uint,
        ARES_RR_TLSA_CERT_USAGE | ARES_RR_TLSA_SELECTOR | ARES_RR_TLSA_MATCH
        | ARES_RR_TLSA_DATA => ARES_REC_TYPE_TLSA as c_uint,
        ARES_RR_SVCB_PRIORITY | ARES_RR_SVCB_TARGET | ARES_RR_SVCB_PARAMS => {
            ARES_REC_TYPE_SVCB as c_uint
        }
        ARES_RR_HTTPS_PRIORITY | ARES_RR_HTTPS_TARGET | ARES_RR_HTTPS_PARAMS => {
            ARES_REC_TYPE_HTTPS as c_uint
        }
        ARES_RR_URI_PRIORITY | ARES_RR_URI_WEIGHT | ARES_RR_URI_TARGET => {
            ARES_REC_TYPE_URI as c_uint
        }
        ARES_RR_CAA_CRITICAL | ARES_RR_CAA_TAG | ARES_RR_CAA_VALUE => {
            ARES_REC_TYPE_CAA as c_uint
        }
        ARES_RR_RAW_RR_TYPE | ARES_RR_RAW_RR_DATA => ARES_REC_TYPE_RAW_RR as c_uint,
        _ => 0,
    }
}
