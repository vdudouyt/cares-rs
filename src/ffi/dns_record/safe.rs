//! The safe kernel of the DNS-record API: every decision the ares_dns_*
//! surface makes lives here as plain safe Rust — the wire codec
//! (parse/write), the per-type rdata match tables, and the metadata string
//! tables. The shims in `mod.rs` only null-check, dereference the opaque
//! handles, call in here, and write results back through C out-pointers.
#![forbid(unsafe_code)]

use super::*;
use crate::core::dns_record::{parse_dns_name, write_dns_name};

/// Create a null-terminated Bin value. The trailing \0 is part of the Vec
/// but not part of the logical data length (ares_dns_rr_get_bin reports
/// len without the null). This ensures C code can safely strlen() the data.
pub(super) fn bin_nul(data: &[u8]) -> RRValue {
    let mut v = Vec::with_capacity(data.len() + 1);
    v.extend_from_slice(data);
    v.push(0);
    RRValue::Bin(v)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn section_vec(rec: &ares_dns_record_t, sect: u32) -> Option<&Vec<ares_dns_rr_t>> {
    match sect {
        ARES_SECTION_ANSWER => Some(&rec.answers),
        ARES_SECTION_AUTHORITY => Some(&rec.authority),
        ARES_SECTION_ADDITIONAL => Some(&rec.additional),
        _ => None,
    }
}

pub(super) fn section_vec_mut(rec: &mut ares_dns_record_t, sect: u32) -> Option<&mut Vec<ares_dns_rr_t>> {
    match sect {
        ARES_SECTION_ANSWER => Some(&mut rec.answers),
        ARES_SECTION_AUTHORITY => Some(&mut rec.authority),
        ARES_SECTION_ADDITIONAL => Some(&mut rec.additional),
        _ => None,
    }
}

pub(super) fn new_rr(name: &str, rtype: u16, rclass: u16, ttl: u32) -> ares_dns_rr_t {
    ares_dns_rr_t {
        name: name.to_string(),
        name_c: CString::new(name).unwrap_or_default(),
        rtype,
        rclass,
        ttl,
        data: HashMap::new(),
        opts: Vec::new(),
        cached_in_addr: std::cell::Cell::new(libc::in_addr { s_addr: 0 }),
        cached_in6_addr: std::cell::Cell::new(crate::ffi::ares_in6_addr::from_octets([0u8; 16])),
    }
}

// ---------------------------------------------------------------------------
// DNS wire-format helpers (for ares_dns_parse / ares_dns_write)
// ---------------------------------------------------------------------------

/// Parse rdata fields for a given RR type from wire format into key/value pairs.
pub(super) fn parse_rdata(
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
pub(super) fn write_rdata(rr: &ares_dns_rr_t, out: &mut Vec<u8>) {
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
// Record/RR accessor kernels — the shims in mod.rs never touch the model
// fields or RRValue directly; every read and mutation goes through these.
// ---------------------------------------------------------------------------

impl ares_dns_record_t {
    pub(super) fn id(&self) -> u16 {
        self.id
    }

    pub(super) fn flags(&self) -> u16 {
        self.flags
    }

    pub(super) fn opcode(&self) -> u16 {
        self.opcode
    }

    pub(super) fn rcode(&self) -> u16 {
        self.rcode
    }

    pub(super) fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub(super) fn query_add(&mut self, name: &str, qtype: u16, qclass: u16) -> Result<(), c_int> {
        let name_c = match CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(ARES_EBADRESP),
        };
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

    /// (name pointer, qtype, qclass) — the pointer aliases the query's cached
    /// CString and stays valid until the query's name is rewritten.
    pub(crate) fn query_at(&self, idx: usize) -> Option<(*const c_char, u16, u16)> {
        let q = self.queries.get(idx)?;
        Some((q.name_c.as_ptr(), q.qtype, q.qclass))
    }

    pub(super) fn query_set_name(&mut self, idx: usize, name: &str) -> Result<(), c_int> {
        if idx >= self.queries.len() {
            return Err(ARES_EBADRESP);
        }
        let name_c = match CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(ARES_EBADRESP),
        };
        self.queries[idx].name = name.to_string();
        self.queries[idx].name_c = name_c;
        Ok(())
    }

    pub(super) fn query_set_type(&mut self, idx: usize, qtype: u16) -> Result<(), c_int> {
        if idx >= self.queries.len() {
            return Err(ARES_EBADRESP);
        }
        self.queries[idx].qtype = qtype;
        Ok(())
    }

    pub(super) fn rr_add(
        &mut self,
        sect: u32,
        name: &str,
        rtype: u16,
        rclass: u16,
        ttl: u32,
    ) -> Result<&mut ares_dns_rr_t, c_int> {
        let vec = section_vec_mut(self, sect).ok_or(ARES_EBADRESP)?;
        vec.push(new_rr(name, rtype, rclass, ttl));
        Ok(vec.last_mut().unwrap())
    }

    pub(super) fn rr_cnt(&self, sect: u32) -> usize {
        match section_vec(self, sect) {
            Some(v) => v.len(),
            None => 0,
        }
    }

    pub(super) fn rr_at_mut(&mut self, sect: u32, idx: usize) -> Option<&mut ares_dns_rr_t> {
        section_vec_mut(self, sect)?.get_mut(idx)
    }

    pub(super) fn rr_at(&self, sect: u32, idx: usize) -> Option<&ares_dns_rr_t> {
        section_vec(self, sect)?.get(idx)
    }

    pub(super) fn rr_del(&mut self, sect: u32, idx: usize) -> Result<(), c_int> {
        let vec = section_vec_mut(self, sect).ok_or(ARES_EBADRESP)?;
        if idx >= vec.len() {
            return Err(ARES_EBADRESP);
        }
        vec.remove(idx);
        Ok(())
    }
}

impl ares_dns_rr_t {
    /// Pointer into the RR's cached CString; valid while the RR is alive.
    pub(super) fn name_ptr(&self) -> *const c_char {
        self.name_c.as_ptr()
    }

    pub(super) fn rtype(&self) -> u16 {
        self.rtype
    }

    pub(super) fn rclass(&self) -> u16 {
        self.rclass
    }

    pub(super) fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Refresh the cached in_addr and return a pointer to it (upstream
    /// contract: valid while the RR is alive). Cell keeps this a purely
    /// safe interior mutation on a shared reference.
    pub(super) fn addr_cached(&self, key: u32) -> Option<*const libc::in_addr> {
        if let Some(RRValue::Addr(addr)) = self.data.get(&key) {
            self.cached_in_addr.set(libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.octets()),
            });
            Some(self.cached_in_addr.as_ptr() as *const libc::in_addr)
        } else {
            None
        }
    }

    pub(super) fn addr6_cached(&self, key: u32) -> Option<*const crate::ffi::ares_in6_addr> {
        if let Some(RRValue::Addr6(addr)) = self.data.get(&key) {
            self.cached_in6_addr
                .set(crate::ffi::ares_in6_addr::from_octets(addr.octets()));
            Some(self.cached_in6_addr.as_ptr() as *const crate::ffi::ares_in6_addr)
        } else {
            None
        }
    }

    pub(super) fn str_ptr(&self, key: u32) -> Option<*const c_char> {
        if let Some(RRValue::Str(s)) = self.data.get(&key) {
            Some(s.as_ptr())
        } else {
            None
        }
    }

    pub(super) fn u8_val(&self, key: u32) -> Option<u8> {
        if let Some(RRValue::U8(v)) = self.data.get(&key) {
            Some(*v)
        } else {
            None
        }
    }

    pub(super) fn u16_val(&self, key: u32) -> Option<u16> {
        if let Some(RRValue::U16(v)) = self.data.get(&key) {
            Some(*v)
        } else {
            None
        }
    }

    pub(super) fn u32_val(&self, key: u32) -> Option<u32> {
        if let Some(RRValue::U32(v)) = self.data.get(&key) {
            Some(*v)
        } else {
            None
        }
    }

    /// (full stored buffer incl. trailing NUL, logical length without it).
    pub(super) fn bin_val(&self, key: u32) -> Option<(&[u8], usize)> {
        if let Some(RRValue::Bin(data)) = self.data.get(&key) {
            // Bin data is null-terminated; logical length excludes the trailing \0
            let logical_len = if data.last() == Some(&0) { data.len() - 1 } else { data.len() };
            Some((data.as_slice(), logical_len))
        } else {
            None
        }
    }

    pub(super) fn set_addr(&mut self, key: u32, ip: Ipv4Addr) {
        self.data.insert(key, RRValue::Addr(ip));
    }

    pub(super) fn set_addr6(&mut self, key: u32, ip: Ipv6Addr) {
        self.data.insert(key, RRValue::Addr6(ip));
    }

    pub(super) fn set_str(&mut self, key: u32, val: CString) {
        self.data.insert(key, RRValue::Str(val));
    }

    pub(super) fn set_u8(&mut self, key: u32, val: u8) {
        self.data.insert(key, RRValue::U8(val));
    }

    pub(super) fn set_u16(&mut self, key: u32, val: u16) {
        self.data.insert(key, RRValue::U16(val));
    }

    pub(super) fn set_u32(&mut self, key: u32, val: u32) {
        self.data.insert(key, RRValue::U32(val));
    }

    pub(super) fn set_bin(&mut self, key: u32, data: &[u8]) {
        self.data.insert(key, bin_nul(data));
    }

    pub(super) fn set_opt(&mut self, opt: u16, data: Vec<u8>) {
        // Remove existing opt with same code if present, then add
        self.opts.retain(|(code, _)| *code != opt);
        self.opts.push((opt, data));
    }

    pub(super) fn opt_cnt(&self) -> usize {
        self.opts.len()
    }

    pub(super) fn opt_at(&self, idx: usize) -> Option<(u16, &[u8])> {
        self.opts.get(idx).map(|(code, data)| (*code, data.as_slice()))
    }

    pub(super) fn opt_by_id(&self, opt: u16) -> Option<&[u8]> {
        self.opts
            .iter()
            .find(|(code, _)| *code == opt)
            .map(|(_, data)| data.as_slice())
    }

    pub(super) fn del_opt_by_id(&mut self, opt: u16) -> bool {
        let before = self.opts.len();
        self.opts.retain(|(code, _)| *code != opt);
        self.opts.len() < before
    }
}

// ---------------------------------------------------------------------------
// Whole-message codec kernels (the pure bodies of ares_dns_parse/write)
// ---------------------------------------------------------------------------

impl ares_dns_record_t {
    pub(super) fn new(id: u16, flags: u16, opcode: u16, rcode: u16) -> Self {
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
pub(crate) fn parse_record(data: &[u8]) -> Result<ares_dns_record_t, c_int> {
    let buf_len = data.len();
    if buf_len < 12 {
        return Err(ARES_EBADRESP);
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
        let name = match parse_dns_name(data, &mut pos) {
            Some(n) => n,
            None => return Err(ARES_EBADRESP),
        };
        if pos + 4 > buf_len {
            return Err(ARES_EBADRESP);
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
                None => return Err(ARES_EBADRESP),
            };
            if pos + 10 > buf_len {
                return Err(ARES_EBADRESP);
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
                return Err(ARES_EBADRESP);
            }
            let rdata = &data[pos..pos + rdlength as usize];
            pos += rdlength as usize;

            let mut rr = new_rr(&rr_name, rtype, rclass, ttl);
            parse_rdata(rtype, rdata, data, rdata_start, &mut rr);

            let vec = match section_vec_mut(&mut rec, *section) {
                Some(v) => v,
                None => return Err(ARES_EBADRESP),
            };
            vec.push(rr);
        }
    }

    Ok(rec)
}

/// Encode a whole DNS message to wire format.
pub(super) fn write_record(rec: &ares_dns_record_t) -> Vec<u8> {
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

