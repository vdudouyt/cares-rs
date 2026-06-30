use std::borrow::Cow;
use arrayvec::ArrayVec;
#[cfg(test)]
use bytes::BufMut;

/// Max DNS label segments (e.g. "www.example.com" = 3 segments).
/// IPv6 reverse DNS (ip6.arpa) needs up to 34 segments.
const MAX_LABEL_PARTS: usize = 40;

pub type LabelVec<'a> = ArrayVec<&'a str, MAX_LABEL_PARTS>;

pub struct SliceBuf<'a> {
    data: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> SliceBuf<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    pub fn remaining(&self) -> usize { self.data.len() - self.pos }
    #[cfg(test)]
    pub fn chunk(&self) -> &'a [u8] { &self.data[self.pos..] }

    pub fn get_u8(&mut self) -> Option<u8> {
        let val = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(val)
    }

    pub fn get_u16(&mut self) -> Option<u16> {
        let hi = *self.data.get(self.pos)? as u16;
        let lo = *self.data.get(self.pos + 1)? as u16;
        self.pos += 2;
        Some((hi << 8) | lo)
    }

    pub fn get_u32(&mut self) -> Option<u32> {
        let b0 = *self.data.get(self.pos)? as u32;
        let b1 = *self.data.get(self.pos + 1)? as u32;
        let b2 = *self.data.get(self.pos + 2)? as u32;
        let b3 = *self.data.get(self.pos + 3)? as u32;
        self.pos += 4;
        Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }

    pub fn get_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos + n;
        if end > self.data.len() { return None; }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    pub fn get_str(&mut self, n: usize) -> Option<&'a str> {
        let slice = self.get_slice(n)?;
        std::str::from_utf8(slice).ok()
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn parse(buf: &mut SliceBuf<'_>) -> Option<DnsHeader> {
        let h = DnsHeader {
            transaction_id: buf.get_u16()?,
            flags:   buf.get_u16()?,
            qdcount: buf.get_u16()?,
            ancount: buf.get_u16()?,
            nscount: buf.get_u16()?,
            arcount: buf.get_u16()?,
        };
        Some(h)
    }

    #[cfg(test)]
    pub fn write<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.transaction_id);
        b.put_u16(self.flags);
        b.put_u16(self.qdcount);
        b.put_u16(self.ancount);
        b.put_u16(self.nscount);
        b.put_u16(self.arcount);
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DnsQuery<'a> {
    pub name: LabelVec<'a>,
    pub qtype: u16,
    pub qclass: u16,
}

impl<'a> DnsQuery<'a> {
    #[cfg(test)]
    pub fn new(domain: &'a str, qtype: u16, qclass: u16) -> DnsQuery<'a> {
        DnsQuery {
            name: domain.split('.').collect(),
            qtype,
            qclass
        }
    }
    pub fn parse(buf: &mut SliceBuf<'a>) -> Option<DnsQuery<'a>> {
        let label = DnsLabel::parse(buf)?;
        let qtype = buf.get_u16()?;
        let qclass = buf.get_u16()?;
        Some(DnsQuery { name: label.name, qtype, qclass })
    }
    #[cfg(test)]
    pub fn write<B: BufMut>(&self, b: &mut B) {
        for label in &self.name {
            b.put_u8(label.len() as u8);
            b.put_slice(label.as_bytes());
        }
        b.put_u8(0);
        b.put_u16(self.qtype);
        b.put_u16(self.qclass);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DnsLabel<'a> {
    pub name: LabelVec<'a>,
    pub offset: Option<u16>,
}

impl<'a> DnsLabel<'a> {
    #[cfg(test)]
    pub fn new(name: &[&'a str], offset: Option<u16>) -> DnsLabel<'a> {
        let mut v = LabelVec::new();
        for &s in name { v.push(s); }
        DnsLabel { name: v, offset }
    }
    pub fn parse(buf: &mut SliceBuf<'a>) -> Option<DnsLabel<'a>> {
        let saved_pos = buf.pos;
        let mut name = LabelVec::new();
        let mut offset: Option<u16> = None;

        loop {
            let Some(len) = buf.get_u8() else { buf.pos = saved_pos; return None; };
            if len == 0 {
                break;
            }
            if len & 0xc0 == 0xc0 {
                // Compression pointer: top 2 bits are 11
                let high_byte = len & 0x3f;
                let Some(low_byte) = buf.get_u8() else { buf.pos = saved_pos; return None; };
                offset = Some(((high_byte as u16) << 8) | (low_byte as u16));
                break;
            }
            if len & 0xc0 != 0 {
                // Invalid top 2 bits (01 or 10) — not a valid label or compression pointer
                buf.pos = saved_pos;
                return None;
            }
            // Label length must be <= 63
            if len > 63 {
                buf.pos = saved_pos;
                return None;
            }

            let Some(s) = buf.get_str(len as usize) else { buf.pos = saved_pos; return None; };
            if name.try_push(s).is_err() { buf.pos = saved_pos; return None; }
        }

        Some(DnsLabel { name, offset })
    }
    pub fn build_string(&self, main_buf: &[u8]) -> Option<String> {
        if self.offset.is_none() {
            return Some(join_escaped_labels(self.name.iter()));
        }
        // Need to follow compression pointer chain — resolve fully
        let mut result = String::new();
        let mut idx = 0;
        for &s in self.name.iter() {
            if idx > 0 { result.push('.'); }
            for &b in s.as_bytes() {
                if b == b'.' || b == b'\\' { result.push('\\'); }
                result.push(b as char);
            }
            idx += 1;
        }

        // Follow compression pointer chain with loop detection
        let mut current_offset = self.offset;
        let mut visited = std::collections::HashSet::new();
        while let Some(off) = current_offset {
            if !visited.insert(off) {
                return None; // Loop detected
            }
            // Manually parse labels at offset, don't borrow from sub_buf
            let mut pos = off as usize;
            loop {
                let &len = main_buf.get(pos)?;
                pos += 1;
                if len == 0 {
                    current_offset = None;
                    break;
                }
                if len & 0xc0 == 0xc0 {
                    let &low = main_buf.get(pos)?;
                    pos += 1;
                    let _ = pos; // suppress unused
                    current_offset = Some(((len as u16 & 0x3f) << 8) | low as u16);
                    break;
                }
                if len & 0xc0 != 0 || len > 63 {
                    return None;
                }
                let end = pos + len as usize;
                let label_bytes = main_buf.get(pos..end)?;
                if idx > 0 { result.push('.'); }
                for &b in label_bytes {
                    if b == b'.' || b == b'\\' { result.push('\\'); }
                    result.push(b as char);
                }
                idx += 1;
                pos = end;
            }
        }
        Some(result)
    }
}

/// Join DNS labels with '.', escaping any '.' or '\\' characters within individual labels.
fn join_escaped_labels<'a, I: Iterator<Item = &'a &'a str>>(labels: I) -> String {
    let mut result = String::new();
    for (i, label) in labels.enumerate() {
        if i > 0 {
            result.push('.');
        }
        for &b in label.as_bytes() {
            if b == b'.' || b == b'\\' {
                result.push('\\');
            }
            result.push(b as char);
        }
    }
    result
}

#[derive(Debug, PartialEq)]
pub struct DnsAnswer<'a> {
    pub name: DnsLabel<'a>,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: &'a [u8],
}

impl<'a> DnsAnswer<'a> {
    pub fn parse(buf: &mut SliceBuf<'a>) -> Option<DnsAnswer<'a>> {
        let name = DnsLabel::parse(buf)?;
        let record_type = buf.get_u16()?;
        let class = buf.get_u16()?;
        let ttl = buf.get_u32()?;
        let data_length = buf.get_u16()? as usize;
        let data = buf.get_slice(data_length)?;
        Some(DnsAnswer { name, record_type, class, ttl, data })
    }
}

/// Test-only helper for building/parsing a whole DNS frame; the hot parse path
/// in ParsedResponse bypasses this.
#[cfg(test)]
#[derive(Debug, PartialEq)]
pub struct DnsFrame<'a> {
    pub transaction_id: u16,
    pub flags: u16,
    pub queries: Vec<DnsQuery<'a>>,
    pub answers: Vec<DnsAnswer<'a>>,
}

#[cfg(test)]
impl<'a> DnsFrame<'a> {
    pub fn parse(buf: &mut SliceBuf<'a>) -> Option<DnsFrame<'a>> {
        let header = DnsHeader::parse(buf)?;
        let mut queries: Vec<DnsQuery<'a>> = Vec::with_capacity(header.qdcount as usize);
        let mut answers: Vec<DnsAnswer<'a>> = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.qdcount {
            queries.push(DnsQuery::parse(buf)?);
        }
        for _ in 0..header.ancount {
            answers.push(DnsAnswer::parse(buf)?);
        }
        Some(DnsFrame { transaction_id: header.transaction_id, flags: header.flags, queries, answers })
    }
    pub fn write<B: BufMut>(&self, b: &mut B) {
        let header = DnsHeader {
            transaction_id: self.transaction_id,
            flags: self.flags,
            qdcount: self.queries.len() as u16,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        header.write(b);
        for query in &self.queries {
            query.write(b);
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct MxReply<'a> {
    pub priority: u16,
    pub label: DnsLabel<'a>,
}

pub trait Parser<'a> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<Self> where Self: Sized;
}

impl<'a> Parser<'a> for MxReply<'a> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<MxReply<'a>> {
        let priority = buf.get_u16()?;
        let label = DnsLabel::parse(buf)?;
        Some(MxReply { priority, label })
    }
}

#[derive(Debug, PartialEq)]
pub struct CaaReply<'a> {
    pub critical: u32,
    pub property: &'a str,
    pub plength: u64,
    pub value: &'a str,
    pub length: u64,
}

impl<'a> Parser<'a> for CaaReply<'a> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<CaaReply<'a>> {
        let flags = buf.get_u8()?;
        let tag_len = buf.get_u8()? as usize;

        let property = buf.get_str(tag_len)?;

        let val_len = buf.remaining();
        let value = buf.get_str(val_len)?;

        if tag_len == 0 {
            return None;
        }

        Some(CaaReply {
            critical: flags as u32,
            property,
            plength: tag_len as u64,
            value,
            length: val_len as u64,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct TxtReply<'a> {
    pub txt: Cow<'a, str>,
    pub length: usize,
}

impl<'a> Parser<'a> for TxtReply<'a> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<TxtReply<'a>> {
        // Fast path: single TXT segment (most common)
        let first = parse_prefixed_str(buf)?;
        if buf.remaining() == 0 {
            let length = first.len();
            return Some(TxtReply { txt: Cow::Borrowed(first), length });
        }
        // Multi-segment: must join
        let mut joined = String::from(first);
        while buf.remaining() > 0 {
            joined.push_str(parse_prefixed_str(buf)?);
        }
        let length = joined.len();
        Some(TxtReply { txt: Cow::Owned(joined), length })
    }
}

#[derive(Debug, PartialEq)]
pub struct TxtReplyExt<'a> {
    pub txt: &'a str,
    pub length: usize,
    pub record_start: bool,
}

impl<'a> Parser<'a> for Vec<TxtReplyExt<'a>> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<Vec<TxtReplyExt<'a>>> {
        let mut record_start = true;
        let mut ret: Vec<TxtReplyExt<'a>> = vec![];
        while buf.remaining() > 0 {
            let txt = parse_prefixed_str(buf)?;
            let length = txt.len();
            ret.push(TxtReplyExt { txt, length, record_start });
            record_start = false;
        }
        Some(ret)
    }
}

impl<'a, T: Parser<'a>> RRParser<'a> for T {
    fn parse_rr(answer: &DnsAnswer<'a>) -> Option<T> {
        let mut buf = SliceBuf::new(answer.data);
        T::parse(&mut buf)
    }
}

#[derive(Debug, PartialEq)]
pub struct NaptrReply<'a> {
    pub order: u16,
    pub preference: u16,
    pub flags: &'a str,
    pub service: &'a str,
    pub regexp: &'a str,
    pub replacement: &'a str,
}

fn parse_prefixed_str<'a>(buf: &mut SliceBuf<'a>) -> Option<&'a str> {
    let len = buf.get_u8()? as usize;
    buf.get_str(len)
}

impl<'a> Parser<'a> for NaptrReply<'a> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<NaptrReply<'a>> {
        let order = buf.get_u16()?;
        let preference = buf.get_u16()?;
        let flags = parse_prefixed_str(buf)?;
        let service = parse_prefixed_str(buf)?;
        let regexp = parse_prefixed_str(buf)?;
        let replacement = parse_prefixed_str(buf)?;

        Some(NaptrReply {
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct SoaReply<'a> {
    pub nsname: DnsLabel<'a>,
    pub hostmaster: DnsLabel<'a>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minttl: u32,
}

impl<'a> Parser<'a> for SoaReply<'a> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<SoaReply<'a>> {
        let nsname = DnsLabel::parse(buf)?;
        let hostmaster = DnsLabel::parse(buf)?;

        let serial = buf.get_u32()?;
        let refresh = buf.get_u32()?;
        let retry = buf.get_u32()?;
        let expire = buf.get_u32()?;
        let minttl = buf.get_u32()?;

        Some(SoaReply {
            nsname,
            hostmaster,
            serial,
            refresh,
            retry,
            expire,
            minttl,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SrvReply<'a> {
    pub host: DnsLabel<'a>,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
}

impl<'a> Parser<'a> for SrvReply<'a> {
    fn parse(buf: &mut SliceBuf<'a>) -> Option<SrvReply<'a>> {
        let priority = buf.get_u16()?;
        let weight = buf.get_u16()?;
        let port = buf.get_u16()?;
        let host = DnsLabel::parse(buf)?;

        Some(SrvReply {
            host,
            priority,
            weight,
            port,
        })
    }
}

pub trait RRParser<'a> {
    fn parse_rr(answer: &DnsAnswer<'a>) -> Option<Self> where Self: Sized;
}

#[derive(Debug, PartialEq)]
pub struct UriReply<'a> {
    pub priority: u16,
    pub weight: u16,
    pub uri: &'a str,
    pub ttl: u32,
}

impl<'a> RRParser<'a> for UriReply<'a> {
    fn parse_rr(answer: &DnsAnswer<'a>) -> Option<UriReply<'a>> {
        let mut buf = SliceBuf::new(answer.data);
        let priority = buf.get_u16()?;
        let weight = buf.get_u16()?;

        let uri_len = buf.remaining();
        let uri = buf.get_str(uri_len)?;

        if uri_len == 0 {
            return None;
        }

        Some(UriReply {
            priority,
            weight,
            uri,
            ttl: answer.ttl
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_dns_header() {
        let buf: Vec<u8> = b"\x8a\x70\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00ASDF".to_vec();
        let mut cur = SliceBuf::new(&buf);
        let expected = DnsHeader {
            transaction_id: 0x8a70,
            flags: 0x100,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0
        };
        assert_eq!(DnsHeader::parse(&mut cur), Some(expected));
        assert_eq!(cur.chunk(), b"ASDF");
    }
    #[test]
    fn test_write_dns_header() {
        let header = DnsHeader {
            transaction_id: 0x8a70,
            flags: 0x100,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0
        };
        let mut vec: Vec<u8> = vec![];
        header.write(&mut vec);
        let expected = b"\x8a\x70\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        assert_eq!(vec, expected);
    }
    #[test]
    fn test_parse_dns_label() {
        let buf: Vec<u8> = b"\x06google\x03com\x00asdf".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), Some(DnsLabel::new(&["google", "com"], None)));
        assert_eq!(cur.chunk(), b"asdf");

        let buf: Vec<u8> = b"\x06google\x03com".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.chunk(), b"\x06google\x03com");

        let buf: Vec<u8> = b"\x06google\x03com\xc0\x0casdf".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), Some(DnsLabel::new(&["google", "com"], Some(0x0c))));
        assert_eq!(cur.chunk(), b"asdf");

        let buf: Vec<u8> = b"\xff\xffasdf".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), Some(DnsLabel::new(&[], Some(0x3fff))));
        assert_eq!(cur.chunk(), b"asdf");
    }
    #[test]
    fn test_parse_dns_label_invalid_bits() {
        // Top 2 bits = 01 (0x40) — invalid, neither label nor compression pointer
        let buf: Vec<u8> = b"\x40abcd".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.pos, 0); // position restored

        // Top 2 bits = 10 (0x80) — also invalid
        let buf: Vec<u8> = b"\x80abcd".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.pos, 0);

        // 0x7f = 0b01111111 — top 2 bits are 01, invalid
        let buf: Vec<u8> = b"\x7fabcd".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.pos, 0);

        // Valid label followed by invalid bits
        let buf: Vec<u8> = b"\x03abc\x80xx".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.pos, 0);
    }
    #[test]
    fn test_parse_dns_label_truncated_compression() {
        // Compression pointer byte without the second byte
        let buf: Vec<u8> = b"\xc0".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.pos, 0);
    }
    #[test]
    fn test_parse_dns_label_truncated_label_data() {
        // Label says 5 bytes but only 3 available
        let buf: Vec<u8> = b"\x05abc".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.pos, 0);
    }
    #[test]
    fn test_parse_dns_query() {
        let buf: Vec<u8> = b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01ASDF".to_vec();
        let mut cur = SliceBuf::new(&buf);
        assert_eq!(DnsQuery::parse(&mut cur), Some(DnsQuery::new("google.com", 1, 1)));
        assert_eq!(cur.chunk(), b"ASDF");
    }
    #[test]
    fn test_write_dns_query() {
        let question = DnsQuery::new("google.com", 1, 1);
        let mut vec: Vec<u8> = vec![];
        question.write(&mut vec);
        assert_eq!(vec, b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01");
    }
    #[test]
    fn test_parse_dns_answer() {
        let buf: Vec<u8> = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\xb8\x8eASDF".to_vec();
        let mut cur = SliceBuf::new(&buf);
        let expected = DnsAnswer {
            name: DnsLabel::new(&[], Some(0x0c)),
            record_type: 1, // Host address
            class: 1, // IN
            ttl: 0x012c, // 5 minutes
            data: &[0x8e, 0xfa, 0xb8, 0x8e],
        };
        assert_eq!(DnsAnswer::parse(&mut cur), Some(expected));
        assert_eq!(cur.chunk(), b"ASDF");
    }
    #[test]
    fn test_parse_dns_frame() {
        let buf: Vec<u8> = b"\x8a\x70\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\xb8\x8e".to_vec();
        let mut cur = SliceBuf::new(&buf);
        let query = DnsQuery::new("google.com", 1, 1);
        let answer = DnsAnswer {
            name: DnsLabel::new(&[], Some(0x0c)),
            record_type: 1, // Host address
            class: 1, // IN
            ttl: 0x012c, // 5 minutes
            data: &[0x8e, 0xfa, 0xb8, 0x8e],
        };
        let expected = DnsFrame {
            transaction_id: 0x8a70,
            flags: 0x8180,
            queries: vec![query],
            answers: vec![answer],
        };
        assert_eq!(DnsFrame::parse(&mut cur), Some(expected));
    }
    #[test]
    fn test_write_dns_frame() {
        let query = DnsQuery::new("google.com", 1, 1);
        let frame = DnsFrame {
            transaction_id: 0x8a70,
            flags: 0x100,
            queries: vec![query],
            answers: vec![],
        };
        let mut vec: Vec<u8> = vec![];
        frame.write(&mut vec);
        assert_eq!(&vec[..], b"\x8a\x70\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01");
    }
    #[test]
    fn test_parse_mx_response() {
        let buf: Vec<u8> = b"\x00\x14\x07\x73\x6d\x74\x70\x69\x6e\x32\xc0\x0c".to_vec();
        let mut cur = SliceBuf::new(&buf);
        let expected = MxReply { priority: 20, label: DnsLabel::new(&["smtpin2"], Some(0x0c)) };
        assert_eq!(MxReply::parse(&mut cur), Some(expected));
    }
    #[test]
    fn test_parse_txt_response() {
        let buf: Vec<u8> = b"\x04abcd".to_vec();
        let mut cur = SliceBuf::new(&buf);
        let expected = TxtReply { length: 4, txt: Cow::Borrowed("abcd") };
        assert_eq!(TxtReply::parse(&mut cur), Some(expected));
    }
}
