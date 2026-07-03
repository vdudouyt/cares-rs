//! Parsed-reply engine shared by the legacy ares_parse_* API and the lookup
//! callbacks: classify a raw DNS reply by header rcode, walk the answer
//! section, follow CNAME chains, and collect typed records. Pure safe code —
//! the C-facing hostent/linked-list emission stays in src/ffi.

use std::ffi::{c_int, CString};

use crate::core::packets::{DnsAnswer, DnsHeader, DnsLabel, DnsQuery, RRParser, SliceBuf};
use crate::ffi::error::{
    ARES_EBADRESP, ARES_EFORMERR, ARES_ENODATA, ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED,
    ARES_ESERVFAIL,
};
use crate::ffi::{
    RECORD_TYPE_A, RECORD_TYPE_AAAA, RECORD_TYPE_CNAME, RECORD_TYPE_NS, RECORD_TYPE_PTR,
};

/// Expand a compressed DNS name that starts at `start` within `full_buf`.
/// Returns the dotted name and the number of bytes the encoding occupies at
/// `start` (the pure body of ares_expand_name).
pub fn expand_name_at(full_buf: &[u8], start: usize) -> Option<(CString, usize)> {
    let local_buf = &full_buf[start..];
    let mut sbuf = SliceBuf::new(local_buf);
    let label = DnsLabel::parse(&mut sbuf)?;
    let consumed = sbuf.pos;
    let name_str = label.build_string(full_buf)?;
    CString::new(name_str).ok().map(|c| (c, consumed))
}

/// Expand a length-prefixed DNS character-string at `start` within `full_buf`.
/// Returns the string bytes and the encoded length (length byte + body); a
/// body with an embedded NUL is rejected, since a strlen-based C consumer
/// would silently truncate it (the pure body of ares_expand_string).
pub fn expand_string_at(full_buf: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let remaining = &full_buf[start..];
    if remaining.is_empty() {
        return None;
    }
    let str_len = remaining[0] as usize;
    if str_len + 1 > remaining.len() {
        return None;
    }
    let str_data = &remaining[1..1 + str_len];
    if str_data.contains(&0) {
        return None;
    }
    Some((str_data, str_len + 1))
}

#[derive(Debug)]
pub struct ParsedResponse<'a> {
    pub query: DnsQuery<'a>,
    pub answers: Vec<DnsAnswer<'a>>,
}

#[derive(Debug)]
pub struct ParsedRRs<T> {
    pub items: Vec<T>,
    pub name: CString,
    pub aliases: Vec<CString>,
    pub _limit_ttl: Option<u32>,
    pub success: usize,
}

impl<'a> ParsedResponse<'a> {
    pub fn from_buf(buf: &'a [u8]) -> Result<Self, c_int> {
        let mut sbuf = SliceBuf::new(buf);
        let Some(header) = DnsHeader::parse(&mut sbuf) else {
            return Err(ARES_EBADRESP);
        };
        match header.flags & 0x0f {
            0 => {},
            1 => return Err(ARES_EFORMERR),
            2 => return Err(ARES_ESERVFAIL),
            3 => return Err(ARES_ENOTFOUND),
            4 => return Err(ARES_ENOTIMP),
            5 => return Err(ARES_EREFUSED),
            _ => return Err(ARES_ENODATA),
        };
        if header.qdcount != 1 {
            return Err(ARES_EBADRESP);
        }
        let Some(query) = DnsQuery::parse(&mut sbuf) else {
            return Err(ARES_EBADRESP);
        };
        let answer_count = header.ancount as usize;
        if answer_count == 0 {
            return Err(ARES_ENODATA);
        }
        // Grow on demand rather than pre-allocating `answer_count` (ancount is
        // attacker-controlled, up to 65535, and DnsAnswer is large, so a tiny
        // response could otherwise reserve tens of MB). The loop is self-bounding:
        // each DnsAnswer::parse consumes >= 11 bytes, so it stops when the buffer
        // is exhausted regardless of the claimed ancount.
        let mut answers = Vec::new();
        // Only parse answer section (ancount); authority and additional sections are skipped
        for _ in 0..answer_count {
            let Some(answer) = DnsAnswer::parse(&mut sbuf) else {
                return Err(ARES_EBADRESP);
            };
            answers.push(answer);
        }
        if answers.is_empty() {
            return Err(ARES_ENODATA);
        }
        Ok(Self {
            query,
            answers,
        })
    }

    pub fn process_answers<T: RRParser<'a>>(self, buf: &[u8], expected_record_type: u16) -> Result<ParsedRRs<T>, c_int> {
        // The echoed question name comes from the (untrusted) response and may
        // contain an embedded NUL byte; fail gracefully instead of panicking.
        let mut name = CString::new(self.query.name.join(".")).map_err(|_| ARES_EBADRESP)?;
        let mut items: Vec<T> = Vec::with_capacity(self.answers.len());
        let mut success = 0;
        let mut aliases: Vec<CString> = vec![];
        let mut limit_ttl: Option<u32> = None;
        for mut answer in self.answers {
            if answer.record_type == RECORD_TYPE_CNAME {
                let mut cname_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut cname_buf).ok_or(ARES_EBADRESP)?;
                let alias_of = alias_of.build_cstring(buf).ok_or(ARES_EBADRESP)?;
                if expected_record_type != RECORD_TYPE_PTR {
                    aliases.push(name);
                    name = alias_of;
                    limit_ttl = Some(answer.ttl);
                }
            }

            if answer.record_type != expected_record_type {
                success += 1;
                continue;
            }

            if answer.record_type == RECORD_TYPE_PTR || answer.record_type == RECORD_TYPE_NS {
                let mut ptr_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut ptr_buf).ok_or(ARES_EBADRESP)?;
                let alias_of = alias_of.build_cstring(buf).ok_or(ARES_EBADRESP)?;
                aliases.push(alias_of.clone());
                if answer.record_type == RECORD_TYPE_PTR { name = alias_of; }
                continue;
            }

            if expected_record_type == RECORD_TYPE_A || expected_record_type == RECORD_TYPE_AAAA {
                if let Some(limit_ttl) = limit_ttl {
                    if answer.ttl > limit_ttl {
                        answer.ttl = limit_ttl;
                    }
                }
            }

            let Some(parsed) = T::parse_rr(&answer) else {
                continue;
            };
            success += 1;
            items.push(parsed);
        }
        Ok(ParsedRRs { items, name, aliases, _limit_ttl: limit_ttl, success })
    }
}

/// What an address-record reply must contain to count as an answer — the
/// three historical acceptance rules of the hostent-producing paths.
pub enum ReplyRequire {
    /// gethostbyname's forward path: at least one address record.
    Items,
    /// The legacy a/aaaa/ns parsers: records or aliases.
    ItemsOrAliases,
    /// PTR replies: at least one name.
    Aliases,
}

/// Parse an address-record reply and apply the acceptance rule (ENODATA
/// when it fails) — the shared front half of every hostent producer.
pub fn addr_reply(buf: &[u8], expected_rtype: u16, require: ReplyRequire) -> Result<ParsedRRs<crate::core::packets::AddrRecord>, i32> {
    let res = ParsedResponse::from_buf(buf)?;
    let rrs = res.process_answers::<crate::core::packets::AddrRecord>(buf, expected_rtype)?;
    let ok = match require {
        ReplyRequire::Items => !rrs.items.is_empty(),
        ReplyRequire::ItemsOrAliases => !(rrs.items.is_empty() && rrs.aliases.is_empty()),
        ReplyRequire::Aliases => !rrs.aliases.is_empty(),
    };
    if !ok {
        return Err(ARES_ENODATA);
    }
    Ok(rrs)
}

/// PTR flows report the queried address itself as a zero-TTL record
/// alongside the resolved names (both the async and the legacy parser path).
pub fn push_synthetic_ptr(rrs: &mut ParsedRRs<crate::core::packets::AddrRecord>, ip: std::net::IpAddr) {
    rrs.items.push(crate::core::packets::AddrRecord { ip, ttl: 0 });
}

/// The TXT-ext answer set: per-answer chunk lists flattened in order, plus
/// how many RRs of the type parsed (the empty-chain status depends on it).
#[allow(clippy::type_complexity)]
pub fn txt_ext_items(buf: &[u8]) -> Result<(Vec<crate::core::packets::TxtReplyExt<'_>>, usize), i32> {
    let res = ParsedResponse::from_buf(buf)?;
    let rrs = res.process_answers::<Vec<crate::core::packets::TxtReplyExt>>(buf, crate::ffi::RECORD_TYPE_TXT)?;
    Ok((rrs.items.into_iter().flatten().collect(), rrs.success))
}

/// A reply whose typed chain came out empty still parsed: report success if
/// at least one RR of the type was seen, EBADRESP otherwise (the linked-list
/// parsers' shared tail rule).
pub fn empty_chain_status(success: usize) -> i32 {
    if success > 0 { crate::ffi::error::ARES_SUCCESS } else { ARES_EBADRESP }
}

/// ares_parse_soa_reply reports a missing SOA as EBADRESP where the generic
/// machinery says ENODATA.
pub fn soa_status(status: i32) -> i32 {
    if status == ARES_ENODATA { ARES_EBADRESP } else { status }
}
