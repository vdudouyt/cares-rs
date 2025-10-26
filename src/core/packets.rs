use std::io::Cursor;
use bytes::{ Buf, BufMut };

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
    pub fn parse<B: Buf>(buf: &mut B) -> Option<DnsHeader> {
        let h = DnsHeader {
            transaction_id: buf.try_get_u16().ok()?,
            flags:   buf.try_get_u16().ok()?,
            qdcount: buf.try_get_u16().ok()?,
            ancount: buf.try_get_u16().ok()?,
            nscount: buf.try_get_u16().ok()?,
            arcount: buf.try_get_u16().ok()?,
        };
        Some(h)
    }

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
pub struct DnsQuery {
    pub name: Vec<String>,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuery {
    #[cfg(test)]
    pub fn new(domain: &str, qtype: u16, qclass: u16) -> DnsQuery {
        DnsQuery {
            name: domain.split(".").map(str::to_owned).collect(),
            qtype,
            qclass
        }
    }
    pub fn parse<B: Buf>(buf: &mut B) -> Option<DnsQuery> {
        let label = DnsLabel::parse(buf)?;
        let qtype = buf.try_get_u16().ok()?;
        let qclass = buf.try_get_u16().ok()?;
        Some(DnsQuery { name: label.name.into_iter().collect(), qtype, qclass })
    }
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

#[derive(Debug, PartialEq, Eq)]
pub struct DnsLabel {
    pub name: Vec<String>,
    pub offset: Option<u16>,
}

impl DnsLabel {
    #[cfg(test)]
    pub fn new(name: &[&str], offset: Option<u16>) -> DnsLabel {
        DnsLabel { name: name.iter().map(ToString::to_string).collect(), offset }
    }
    pub fn parse<B: Buf>(buf: &mut B) -> Option<DnsLabel> {
        let mut cur = Cursor::new(buf.chunk());
        let mut name: Vec<String> = vec![];
        let mut offset: Option<u16> = None;

        loop {
            let len = cur.try_get_u8().ok()?;
            if len == 0 {
                break;
            }
            if len & 0xc0 > 0 {
                let high_byte = len & 0x3f;
                let low_byte = cur.try_get_u8().ok()?;
                offset = Some(((high_byte as u16) << 8) | (low_byte as u16));
                break;
            }

            let mut dst: Vec<u8> = vec![0; len as usize];
            cur.try_copy_to_slice(&mut dst[..]).ok()?;
            name.push(String::from_utf8(dst).ok()?);
        }

        let bytes_read = cur.position() as usize;
        buf.advance(bytes_read);
        Some(DnsLabel { name, offset })
    }
    pub fn build_string(&self, main_buf: &[u8]) -> Option<String> {
        let mut name = self.name.clone();
        if let Some(offset) = self.offset {
            let mut label = DnsLabel::parse(&mut Cursor::new(&main_buf[offset as usize..]))?;
            name.append(&mut label.name);
        }
        Some(name.join("."))
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsAnswer {
    pub name: DnsLabel,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsAnswer {
    pub fn parse<B: Buf>(buf: &mut B) -> Option<DnsAnswer> {
        let name = DnsLabel::parse(buf)?;
        let record_type = buf.try_get_u16().ok()?;
        let class = buf.try_get_u16().ok()?;
        let ttl = buf.try_get_u32().ok()?;
        let data_length = buf.try_get_u16().ok()?;

        let mut data: Vec<u8> = vec![0; data_length as usize];
        buf.try_copy_to_slice(&mut data[..]).ok()?;
        Some(DnsAnswer { name, record_type, class, ttl, data })
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsFrame {
    pub transaction_id: u16,
    pub flags: u16,
    pub queries: Vec<DnsQuery>,
    pub answers: Vec<DnsAnswer>,
    // pub authority_responses: Vec<DnsAuthorityResponse>
    // pub additional_responses: Vec<DnsAdditionalResponse>
}

impl DnsFrame {
    pub fn parse<B: Buf>(buf: &mut B) -> Option<DnsFrame> {
        let header = DnsHeader::parse(buf)?;
        let mut queries: Vec<DnsQuery> = vec![];
        let mut answers: Vec<DnsAnswer> = vec![];
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
pub struct MxReply {
    pub priority: u16,
    pub label: DnsLabel,
}

impl MxReply {
    pub fn parse<B: Buf>(buf: &mut B) -> Option<MxReply> {
        let priority = buf.try_get_u16().ok()?;
        let label = DnsLabel::parse(buf)?;
        Some(MxReply { priority, label })
    }
}

#[derive(Debug, PartialEq)]
pub struct TxtReply {
    pub txt: String,
    pub length: u8,
}

impl TxtReply {
    pub fn parse<B: Buf>(buf: &mut B) -> Option<TxtReply> {
        let length = buf.try_get_u8().ok()?;
        let txt_slice = buf.copy_to_bytes(std::cmp::min(length as usize, buf.remaining()));
        let txt = String::from_utf8_lossy(&txt_slice).to_string();
        Some(TxtReply { txt, length })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_dns_header() {
        let buf: Vec<u8> = b"\x8a\x70\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00ASDF".to_vec();
        let mut cur = Cursor::new(&buf);
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
        let mut cur = Cursor::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), Some(DnsLabel::new(&["google", "com"], None)));
        assert_eq!(cur.chunk(), b"asdf");

        let buf: Vec<u8> = b"\x06google\x03com".to_vec();
        let mut cur = Cursor::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), None);
        assert_eq!(cur.chunk(), b"\x06google\x03com");

        let buf: Vec<u8> = b"\x06google\x03com\xc0\x0casdf".to_vec();
        let mut cur = Cursor::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), Some(DnsLabel::new(&["google", "com"], Some(0x0c))));
        assert_eq!(cur.chunk(), b"asdf");

        let buf: Vec<u8> = b"\xff\xffasdf".to_vec();
        let mut cur = Cursor::new(&buf);
        assert_eq!(DnsLabel::parse(&mut cur), Some(DnsLabel::new(&[], Some(0x3fff))));
        assert_eq!(cur.chunk(), b"asdf");
    }
    #[test]
    fn test_parse_dns_query() {
        let buf: Vec<u8> = b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01ASDF".to_vec();
        let mut cur = Cursor::new(&buf);
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
        let mut cur = Cursor::new(&buf);
        let expected = DnsAnswer {
            name: DnsLabel::new(&[], Some(0x0c)),
            record_type: 1, // Host address
            class: 1, // IN
            ttl: 0x012c, // 5 minutes
            data: vec![0x8e, 0xfa, 0xb8, 0x8e],
        };
        assert_eq!(DnsAnswer::parse(&mut cur), Some(expected));
        assert_eq!(cur.chunk(), b"ASDF");
    }
    #[test]
    fn test_parse_dns_frame() {
        let buf: Vec<u8> = b"\x8a\x70\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\xb8\x8e".to_vec();
        let mut cur = Cursor::new(&buf);
        let query = DnsQuery::new("google.com", 1, 1);
        let answer = DnsAnswer {
            name: DnsLabel::new(&[], Some(0x0c)),
            record_type: 1, // Host address
            class: 1, // IN
            ttl: 0x012c, // 5 minutes
            data: vec![0x8e, 0xfa, 0xb8, 0x8e],
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
        let mut cur = Cursor::new(&buf);
        let expected = MxReply { priority: 20, label: DnsLabel::new(&["smtpin2"], Some(0x0c)) };
        assert_eq!(MxReply::parse(&mut cur), Some(expected));
    }
    #[test]
    fn test_parse_txt_response() {
        let buf: Vec<u8> = b"\x04abcd".to_vec();
        let mut cur = Cursor::new(&buf);
        let expected = TxtReply { length: 4, txt: "abcd".to_string() };
        assert_eq!(TxtReply::parse(&mut cur), Some(expected));
    }
}
