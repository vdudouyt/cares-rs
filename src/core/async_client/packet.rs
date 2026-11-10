//! Building outgoing query packets: the wire builders (`build_query`,
//! `dns_query_payload`, template rewrite, TCP framing, reverse names) and
//! `reserve` — stamping a channel-unique transaction id.

use super::*;

impl AsyncClient {
    /// ares_query / ares_query_dnsrec: `no_servers` preflight, then the wire
    /// payload. The caller's class and the channel's RD/NORECURSE flag reach the wire.
    pub(crate) fn query_payload(
        &self,
        name: &str,
        qtype: u32,
        qclass: u32,
    ) -> Result<ReservedQuery, AresError> {
        // Constructed queries validate the wide EDNSPSZ here, before spawning.
        self.edns_udp_size()?;
        let payload = self.with_edns(dns_query_payload(name, qtype, qclass, self.recursion_desired())?)?;
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        self.reserve(payload)
    }

    /// ares_send / ares_send_dnsrec: length + `no_servers` preflight, then the
    /// raw payload under a freshly reserved id (caller packets keep their own
    /// flags/class; their id is replaced, as upstream does).
    pub(crate) fn send_payload(&self, query_buf: &[u8]) -> Result<ReservedQuery, AresError> {
        if query_buf.len() < 12 || query_buf.len() >= (1 << 16) {
            return Err(ARES_EBADQUERY.into());
        }
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        self.reserve(BytesMut::from(query_buf))
    }

    /// Reserve a channel-unique transaction id (upstream `generate_unique_qid`)
    /// and stamp it on `payload`; it stays reserved until the query ends.
    /// `ARES_ENOMEM` when all 65536 ids are in flight.
    pub(crate) fn reserve(&self, mut payload: BytesMut) -> Result<ReservedQuery, AresError> {
        if payload.len() < 2 {
            return Err(ARES_EBADQUERY.into());
        }
        let lease = QidLease::reserve(&self.shared).ok_or(AresError::from(ARES_ENOMEM))?;
        payload[0..2].copy_from_slice(&lease.id().to_be_bytes());
        Ok(ReservedQuery { payload, lease })
    }
}

/// Wrap a DNS payload in the 2-byte big-endian length prefix (RFC 1035 §4.2.2).
pub(super) fn frame_tcp(payload: &[u8]) -> BytesMut {
    let mut framed = BytesMut::with_capacity(2 + payload.len());
    framed.put_u16(payload.len() as u16);
    framed.extend_from_slice(payload);
    framed
}

/// Validate an untruncated class/type pair like ares_dns_record_query_add: both
/// must fit 16 bits and pass validity checks (unknown in-range query types OK).
pub(crate) fn validate_query_class_type(qclass: u32, qtype: u32) -> Result<(), AresError> {
    if qclass > u16::MAX as u32
        || qtype > u16::MAX as u32
        || !rec_type_isvalid(qtype, true)
        || !class_isvalid(qclass as u16, qtype, true)
    {
        return Err(ARES_EFORMERR.into());
    }
    Ok(())
}

/// Build a UDP-form DNS query payload (fresh random transaction id) through the
/// shared `build_query` validator/writer.
pub(crate) fn dns_query_payload(
    name: &str,
    qtype: u32,
    qclass: u32,
    rd: bool,
) -> Result<BytesMut, AresError> {
    let transaction_id = rand::thread_rng().r#gen::<u16>();
    let packet = build_query(name, qclass, qtype, transaction_id, rd, 0)?;
    Ok(BytesMut::from(packet.as_slice()))
}

/// Duplicate a caller-supplied record via serialize/parse, replace query[0]'s
/// name, and stamp a fresh id.
pub(super) fn payload_from_template(template: &ares_dns_record_t, name: &str) -> Result<BytesMut, AresError> {
    let wire = write_record(template)?;
    let mut rec = parse_record(&wire, 0)?;
    rec.query_set_name(0, name)?;
    rec.set_id(rand::thread_rng().r#gen::<u16>());
    let out = write_record(&rec)?;
    Ok(BytesMut::from(out.as_slice()))
}

/// The pure body of ares_create_query/ares_mkquery: escaped-name analysis, RFC
/// 7686 .onion rejection, label validation, and wire assembly. A positive
/// `max_udp_size` appends an OPT RR; zero or negative means "no EDNS".
pub(crate) fn build_query(
    name_str: &str,
    dnsclass: u32,
    qtype: u32,
    id: u16,
    rd: bool,
    max_udp_size: i32,
) -> Result<Vec<u8>, AresError> {
    let max_udp_size: u16 = if max_udp_size > 0 {
        if max_udp_size > u16::MAX as i32 {
            return Err(ARES_EFORMERR.into());
        }
        max_udp_size as u16
    } else {
        0
    };
    let has_unescaped_trailing_dot = if let Some(prefix) = name_str.strip_suffix('.') {
        let backslash_count = prefix
            .as_bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        backslash_count % 2 == 0
    } else {
        false
    };

    let lower = name_str.to_lowercase();
    let check = if has_unescaped_trailing_dot {
        lower.strip_suffix('.').unwrap_or(&lower)
    } else {
        &lower
    };
    if check.ends_with(".onion") || check == "onion" {
        return Err(ARES_ENOTFOUND.into());
    }

    // class/type checked before the name is written (upstream order).
    validate_query_class_type(dnsclass, qtype)?;

    let clean_name = if has_unescaped_trailing_dot {
        name_str.strip_suffix('.').unwrap_or(name_str)
    } else {
        name_str
    };
    let labels: Vec<&str> = if clean_name.is_empty() {
        vec![]
    } else {
        let mut result = Vec::new();
        let mut current_start = 0;
        let bytes = clean_name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
            } else if bytes[i] == b'.' {
                result.push(&clean_name[current_start..i]);
                current_start = i + 1;
                i += 1;
            } else {
                i += 1;
            }
        }
        if current_start <= bytes.len() {
            let last = &clean_name[current_start..];
            if !last.is_empty() {
                result.push(last);
            }
        }
        result
    };

    // Total is the unescaped presentation length (upstream's 255-byte check).
    let mut total_len = 0usize;
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.is_empty() {
            return Err(ARES_EBADNAME.into());
        }
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
        total_len += unescaped.len();
    }
    if !labels.is_empty() && total_len + labels.len() - 1 > 255 {
        return Err(ARES_EBADNAME.into());
    }

    let flags: u16 = if rd { 0x0100 } else { 0x0000 };
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    let arcount: u16 = if max_udp_size > 0 { 1 } else { 0 };
    packet.extend_from_slice(&arcount.to_be_bytes());

    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
        packet.push(unescaped.len() as u8);
        packet.extend_from_slice(&unescaped);
    }
    packet.push(0);
    packet.extend_from_slice(&(qtype as u16).to_be_bytes());
    packet.extend_from_slice(&(dnsclass as u16).to_be_bytes());

    if max_udp_size > 0 {
        packet.push(0);
        packet.extend_from_slice(&41u16.to_be_bytes());
        packet.extend_from_slice(&max_udp_size.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
    }

    Ok(packet)
}

/// Decode a presentation-form label: `\.` escapes and `\DDD` numeric escapes.
fn unescape_label(label: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(label.len());
    let bytes = label.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if i + 3 < bytes.len() && bytes[i+1].is_ascii_digit() && bytes[i+2].is_ascii_digit() && bytes[i+3].is_ascii_digit() {
                let val = (bytes[i+1] - b'0') as u16 * 100 + (bytes[i+2] - b'0') as u16 * 10 + (bytes[i+3] - b'0') as u16;
                result.push(val as u8);
                i += 4;
            } else {
                result.push(bytes[i+1]);
                i += 2;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
}

pub(crate) fn rdns_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.octets().into_iter().rev().map(|b| b.to_string())
            .collect::<Vec<_>>().join(".") + ".in-addr.arpa",
        // IPv6 nibbles are emitted low nibble first.
        IpAddr::V6(v6) => v6.octets().into_iter().flat_map(|b| [b >> 4, b & 0x0f]).map(|n| format!("{:x}", n))
            .collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".") + ".ip6.arpa",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_payload_writes_class_and_rd_flag() {
        let p = dns_query_payload("example.com", 1, 3, true).expect("payload");
        assert_eq!(p[2], 0x01);
        assert_eq!(&p[p.len() - 2..], &3u16.to_be_bytes());

        let p = dns_query_payload("example.com", 1, 1, false).expect("payload");
        assert_eq!(p[2] & 0x01, 0);
        assert_eq!(&p[p.len() - 2..], &1u16.to_be_bytes());
    }

    #[test]
    fn legacy_query_validation_rejects_bad_class_and_name() {
        assert_eq!(
            validate_query_class_type(17, 1).expect_err("bad class").code(),
            ARES_EFORMERR
        );
        assert_eq!(
            validate_query_class_type(0x1_0000, 1)
                .expect_err("class too wide")
                .code(),
            ARES_EFORMERR
        );
        assert_eq!(
            validate_query_class_type(1, 0x1_0000)
                .expect_err("type too wide")
                .code(),
            ARES_EFORMERR
        );
        let long_label = "a".repeat(64);
        assert_eq!(
            build_query(&long_label, 1, 1, 0, true, 0)
                .expect_err("long label")
                .code(),
            ARES_EBADNAME
        );
        assert_eq!(
            build_query("example..com", 1, 1, 0, true, 0)
                .expect_err("empty label")
                .code(),
            ARES_EBADNAME
        );
        assert!(build_query("example.com", 1, 1, 0, true, 0).is_ok());
        assert!(validate_query_class_type(255, 255).is_ok());
    }

    #[test]
    fn create_query_rejects_oversized_edns_payload_size() {
        for oversized in [65536, 70000, i32::MAX] {
            assert_eq!(
                build_query("example.com", 1, 1, 0, true, oversized)
                    .expect_err("oversized EDNS must fail")
                    .code(),
                ARES_EFORMERR
            );
        }
        // 1..=65535 is valid EDNS; the OPT CLASS carries the exact size.
        for size in [1i32, 1280, 65535] {
            let p = build_query("example.com", 1, 1, 0, true, size).expect("valid EDNS size");
            assert_eq!(u16::from_be_bytes([p[10], p[11]]), 1, "arcount");
            let opt_class = u16::from_be_bytes([p[32], p[33]]);
            assert_eq!(u32::from(opt_class), size as u32);
        }
        // Zero and negative mean "no EDNS".
        for size in [0i32, -1] {
            let p = build_query("example.com", 1, 1, 0, true, size).expect("no EDNS");
            assert_eq!(u16::from_be_bytes([p[10], p[11]]), 0, "arcount");
        }
    }

    #[test]
    fn template_rewrite_preserves_flags_and_class() {
        use crate::ffi::dns_record::ARES_FLAG_RD;
        let mut rec = ares_dns_record_t::new(7, ARES_FLAG_RD, 0, 0);
        rec.query_add("a.example", 1, 3).expect("query_add");
        let payload = payload_from_template(&rec, "b.example").expect("template payload");
        let parsed = parse_record(&payload, 0).expect("parse payload");
        let (name, qtype, qclass) = parsed.query_at(0).expect("query");
        assert_eq!(name.to_str().expect("name"), "b.example");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 3);
        assert_ne!(parsed.flags() & ARES_FLAG_RD, 0);
    }
}
