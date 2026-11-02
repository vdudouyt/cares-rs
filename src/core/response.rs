//! Parsed-reply engine shared by the legacy ares_parse_* API and the lookup
//! callbacks: classify a raw DNS reply by header rcode, walk the answer
//! section, follow CNAME chains, and collect typed records. Pure safe code —
//! the C-facing hostent/linked-list emission stays in src/ffi.

use std::ffi::CString;

use crate::core::packets::{DnsAnswer, DnsHeader, DnsLabel, DnsQuery, RRParser, SliceBuf};
use crate::core::AresError;
use crate::core::dns_record::{class_isvalid, rec_type_isvalid};
use crate::ffi::dns_record::ARES_REC_TYPE_OPT;
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

/// One entry of the CNAME chain in a reply, in answer order. `alias` is the
/// owner name and `name` the target; both are absent only for synthetic
/// (hosts-file) canonical-name entries.
#[derive(Debug, Clone)]
pub struct CnameEntry {
    pub ttl: u32,
    pub alias: Option<CString>,
    pub name: Option<CString>,
}

#[derive(Debug)]
pub struct ParsedRRs<T> {
    pub items: Vec<T>,
    pub name: CString,
    pub aliases: Vec<CString>,
    /// Every IN-class CNAME answer, in reply order (owner/target/TTL).
    pub cnames: Vec<CnameEntry>,
    pub _limit_ttl: Option<u32>,
    pub success: usize,
}

impl<'a> ParsedResponse<'a> {
    pub(crate) fn from_buf(buf: &'a [u8]) -> Result<Self, AresError> {
        let mut sbuf = SliceBuf::new(buf);
        let header = DnsHeader::parse(&mut sbuf).ok_or(ARES_EBADRESP)?;
        match header.flags & 0x0f {
            0 => {},
            1 => return Err(ARES_EFORMERR.into()),
            2 => return Err(ARES_ESERVFAIL.into()),
            3 => return Err(ARES_ENOTFOUND.into()),
            4 => return Err(ARES_ENOTIMP.into()),
            5 => return Err(ARES_EREFUSED.into()),
            _ => return Err(ARES_ENODATA.into()),
        };
        if header.qdcount != 1 {
            return Err(ARES_EBADRESP.into());
        }
        let query = DnsQuery::parse(&mut sbuf).ok_or(ARES_EBADRESP)?;
        let answer_count = header.ancount as usize;
        if answer_count == 0 {
            return Err(ARES_ENODATA.into());
        }
        // Grow on demand rather than pre-allocating `answer_count` (ancount is
        // attacker-controlled, up to 65535, and DnsAnswer is large, so a tiny
        // response could otherwise reserve tens of MB). The loop is self-bounding:
        // each DnsAnswer::parse consumes >= 11 bytes, so it stops when the buffer
        // is exhausted regardless of the claimed ancount.
        let mut answers = Vec::new();
        // Only parse answer section (ancount); authority and additional sections are skipped
        for _ in 0..answer_count {
            let answer = DnsAnswer::parse(&mut sbuf).ok_or(ARES_EBADRESP)?;
            // Mirror ares_dns_parse's class validation: unknown/raw types skip
            // it, OPT is stored with class IN, and anything else must be a
            // valid class (ANY only for SIG). This is the same check the
            // ares_dns_record path applies, now enforced for the legacy parsers.
            if rec_type_isvalid(answer.record_type as u32, false)
                && answer.record_type != ARES_REC_TYPE_OPT
                && !class_isvalid(
                    answer.class,
                    answer.record_type as u32,
                    false,
                )
            {
                return Err(ARES_EFORMERR.into());
            }
            answers.push(answer);
        }
        if answers.is_empty() {
            return Err(ARES_ENODATA.into());
        }
        Ok(Self {
            query,
            answers,
        })
    }

    pub(crate) fn process_answers<T: RRParser<'a>>(self, buf: &[u8], expected_record_type: u16) -> Result<ParsedRRs<T>, AresError> {
        // The echoed question name comes from the (untrusted) response and may
        // contain an embedded NUL byte; fail gracefully instead of panicking.
        let mut name = CString::new(self.query.name.join(".")).map_err(|_| AresError::from(ARES_EBADRESP))?;
        let mut items: Vec<T> = Vec::with_capacity(self.answers.len());
        let mut success = 0;
        let mut aliases: Vec<CString> = vec![];
        let mut cnames: Vec<CnameEntry> = vec![];
        // Upstream clamps every A/AAAA TTL to the smallest CNAME TTL anywhere in
        // the answer section, regardless of record order.
        let min_cname_ttl = self
            .answers
            .iter()
            .filter(|a| {
                a.class == crate::ffi::dns_record::ARES_CLASS_IN
                    && a.record_type == RECORD_TYPE_CNAME
            })
            .map(|a| a.ttl)
            .min();
        let mut first_cname: Option<CString> = None;
        for mut answer in self.answers {
            // Upstream ares_parse_into_addrinfo only considers IN records, so
            // other classes must not affect CNAME chains, names or TTLs.
            if answer.class != crate::ffi::dns_record::ARES_CLASS_IN {
                continue;
            }
            if answer.record_type == RECORD_TYPE_CNAME {
                let mut cname_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut cname_buf).ok_or(AresError::from(ARES_EBADRESP))?;
                let alias_of = alias_of.build_cstring(buf).ok_or(AresError::from(ARES_EBADRESP))?;
                // `answer.name` is the CNAME owner (the previous name in the
                // chain); `alias_of` is the target. Keep the raw RR TTL.
                let owner = answer.name.build_cstring(buf).ok_or(AresError::from(ARES_EBADRESP))?;
                cnames.push(CnameEntry {
                    ttl: answer.ttl,
                    alias: Some(owner),
                    name: Some(alias_of.clone()),
                });
                if expected_record_type != RECORD_TYPE_PTR {
                    aliases.push(name);
                    if first_cname.is_none() {
                        first_cname = Some(alias_of.clone());
                    }
                    name = alias_of;
                }
            }

            if answer.record_type != expected_record_type {
                success += 1;
                continue;
            }

            if answer.record_type == RECORD_TYPE_PTR || answer.record_type == RECORD_TYPE_NS {
                let mut ptr_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut ptr_buf).ok_or(AresError::from(ARES_EBADRESP))?;
                let alias_of = alias_of.build_cstring(buf).ok_or(AresError::from(ARES_EBADRESP))?;
                aliases.push(alias_of.clone());
                if answer.record_type == RECORD_TYPE_PTR { name = alias_of; }
                continue;
            }

            if expected_record_type == RECORD_TYPE_A || expected_record_type == RECORD_TYPE_AAAA {
                if let Some(limit_ttl) = min_cname_ttl {
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
        // hostent h_name is the first CNAME target, not the end of the chain.
        if matches!(expected_record_type, RECORD_TYPE_A | RECORD_TYPE_AAAA) {
            if let Some(first) = first_cname {
                name = first;
            }
        }
        Ok(ParsedRRs { items, name, aliases, cnames, _limit_ttl: min_cname_ttl, success })
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
pub fn addr_reply(buf: &[u8], expected_rtype: u16, require: ReplyRequire) -> Result<ParsedRRs<crate::core::packets::AddrRecord>, AresError> {
    let res = ParsedResponse::from_buf(buf)?;
    let rrs = res.process_answers::<crate::core::packets::AddrRecord>(buf, expected_rtype)?;
    let ok = match require {
        ReplyRequire::Items => !rrs.items.is_empty(),
        ReplyRequire::ItemsOrAliases => !(rrs.items.is_empty() && rrs.aliases.is_empty()),
        ReplyRequire::Aliases => !rrs.aliases.is_empty(),
    };
    if !ok {
        return Err(ARES_ENODATA.into());
    }
    Ok(rrs)
}

/// PTR flows report the queried address itself as a zero-TTL record
/// alongside the resolved names (both the async and the legacy parser path).
pub fn push_synthetic_ptr(rrs: &mut ParsedRRs<crate::core::packets::AddrRecord>, ip: std::net::IpAddr) {
    rrs.items.push(crate::core::packets::AddrRecord { ip, ttl: 0 });
}

/// A reply whose typed chain came out empty still parsed: report success if
/// at least one RR of the type was seen, EBADRESP otherwise (the linked-list
/// parsers' shared tail rule).
pub(crate) fn empty_chain_status(success: usize) -> AresError {
    if success > 0 { crate::ffi::error::ARES_SUCCESS.into() } else { ARES_EBADRESP.into() }
}


/// ares_parse_soa_reply reports a missing SOA as EBADRESP where the generic
/// machinery says ENODATA.
pub fn soa_status(status: AresError) -> AresError {
    if status.code() == ARES_ENODATA { ARES_EBADRESP.into() } else { status }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal one-question/one-A-answer reply with a caller-chosen RR class.
    fn a_reply(class: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0, 1]); // id
        buf.extend_from_slice(&[0x80, 0]); // response
        buf.extend_from_slice(&[0, 1]); // qdcount
        buf.extend_from_slice(&[0, 1]); // ancount
        buf.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
        buf.extend_from_slice(&[1, b'a', 0]); // question name
        buf.extend_from_slice(&[0, 1]); // qtype A
        buf.extend_from_slice(&[0, 1]); // qclass IN
        buf.extend_from_slice(&[0xc0, 0x0c]); // answer name ptr
        buf.extend_from_slice(&[0, 1]); // type A
        buf.extend_from_slice(&class.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]); // ttl
        buf.extend_from_slice(&[0, 4, 1, 2, 3, 4]); // rdlength + rdata
        buf
    }

    #[test]
    fn valid_rr_classes_are_accepted() {
        for class in [1u16, 3, 4, 254] {
            let buf = a_reply(class);
            assert!(ParsedResponse::from_buf(&buf).is_ok(), "class {class}");
        }
    }

    #[test]
    fn invalid_rr_class_is_formerr() {
        let buf = a_reply(2);
        let err = ParsedResponse::from_buf(&buf).unwrap_err();
        assert_eq!(err.code(), ARES_EFORMERR);
    }

    fn push_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    /// A CNAME chain (two hops) followed by an A record. The hostent name is
    /// the first target, while the addrinfo chain retains both hops in order.
    #[test]
    fn cname_chain_records_owner_target_and_ttl() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0, 1]); // id
        buf.extend_from_slice(&[0x80, 0]); // response
        buf.extend_from_slice(&[0, 1]); // qdcount
        buf.extend_from_slice(&[0, 3]); // ancount
        buf.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
        push_name(&mut buf, "query.example");
        buf.extend_from_slice(&[0, 1, 0, 1]); // A IN

        // query.example CNAME first.example (TTL 120)
        buf.extend_from_slice(&[0xc0, 0x0c]);
        buf.extend_from_slice(&[0, 5, 0, 1]);
        buf.extend_from_slice(&120u32.to_be_bytes());
        let mut rdata = Vec::new();
        push_name(&mut rdata, "first.example");
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        // first.example CNAME second.example (TTL 60)
        push_name(&mut buf, "first.example");
        buf.extend_from_slice(&[0, 5, 0, 1]);
        buf.extend_from_slice(&60u32.to_be_bytes());
        let mut rdata = Vec::new();
        push_name(&mut rdata, "second.example");
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        // second.example A 1.2.3.4
        push_name(&mut buf, "second.example");
        buf.extend_from_slice(&[0, 1, 0, 1]);
        buf.extend_from_slice(&300u32.to_be_bytes());
        buf.extend_from_slice(&[0, 4, 1, 2, 3, 4]);

        let rrs = addr_reply(&buf, RECORD_TYPE_A, ReplyRequire::Items).expect("parse");
        assert_eq!(rrs.cnames.len(), 2);
        assert_eq!(rrs.cnames[0].ttl, 120);
        assert_eq!(rrs.cnames[0].alias.as_ref().map(|s| s.to_str().unwrap()), Some("query.example"));
        assert_eq!(rrs.cnames[0].name.as_ref().map(|s| s.to_str().unwrap()), Some("first.example"));
        assert_eq!(rrs.cnames[1].ttl, 60);
        assert_eq!(rrs.cnames[1].alias.as_ref().map(|s| s.to_str().unwrap()), Some("first.example"));
        assert_eq!(rrs.cnames[1].name.as_ref().map(|s| s.to_str().unwrap()), Some("second.example"));
        // Legacy hostent semantics use the first CNAME target.
        assert_eq!(rrs.name.to_str().unwrap(), "first.example");
        // The A TTL is clamped to the smallest CNAME TTL.
        assert_eq!(rrs.items[0].ttl, 60);
    }
}

