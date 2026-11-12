//! EDNS(0) and DNS cookie wire helpers over a serialized message.
//! Unlike upstream `ares_cookie.c`, cookie rotation/regression timers are not enforced.

use std::time::Instant;

use rand::Rng;

/// Default advertised UDP payload size.
pub(crate) const EDNS_PACKETSZ: u16 = 1280;

/// OPT pseudo-RR type (RFC 6891).
const OPT_TYPE: u16 = 41;
/// DNS COOKIE EDNS option code (RFC 7873).
const OPT_COOKIE: u16 = 10;

/// Location of the OPT pseudo-RR inside a serialized message.
struct OptRecord {
    rr_start: usize,
    rr_end: usize,
    /// Offset of the TTL field (extended RCODE / version / flags).
    ttl_offset: usize,
    rdata_offset: usize,
    rdata_len: usize,
}

impl OptRecord {
    fn ttl(&self, buf: &[u8]) -> Option<u32> {
        let b = buf.get(self.ttl_offset..self.ttl_offset + 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn rdata<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        buf.get(self.rdata_offset..self.rdata_offset + self.rdata_len)
    }
}

fn header_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let b = buf.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn skip_name(buf: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let len = *buf.get(*pos)?;
        *pos += 1;
        if len == 0 {
            return Some(());
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer: one more byte, then the name ends.
            buf.get(*pos)?;
            *pos += 1;
            return Some(());
        }
        if len & 0xc0 != 0 {
            return None;
        }
        *pos = pos.checked_add(len as usize)?;
        if *pos > buf.len() {
            return None;
        }
    }
}

fn skip_rr(buf: &[u8], pos: &mut usize) -> Option<(u16, usize, usize)> {
    skip_name(buf, pos)?;
    let record_type = header_u16(buf, *pos)?;
    // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
    let rdata_offset = pos.checked_add(10)?;
    let rdata_len = header_u16(buf, rdata_offset - 2)? as usize;
    let end = rdata_offset.checked_add(rdata_len)?;
    if end > buf.len() {
        return None;
    }
    *pos = end;
    Some((record_type, rdata_offset, rdata_len))
}

/// Find the OPT pseudo-RR in the ADDITIONAL section.
fn find_opt(buf: &[u8]) -> Option<OptRecord> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = header_u16(buf, 4)? as usize;
    let ancount = header_u16(buf, 6)? as usize;
    let nscount = header_u16(buf, 8)? as usize;
    let arcount = header_u16(buf, 10)? as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        skip_name(buf, &mut pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
        if pos > buf.len() {
            return None;
        }
    }
    for _ in 0..ancount + nscount {
        skip_rr(buf, &mut pos)?;
    }
    for _ in 0..arcount {
        let rr_start = pos;
        skip_name(buf, &mut pos)?;
        let ttl_offset = pos.checked_add(4)?;
        let record_type = header_u16(buf, pos)?;
        let rdata_len = header_u16(buf, pos.checked_add(8)?)? as usize;
        let rdata_offset = pos.checked_add(10)?;
        let rr_end = rdata_offset.checked_add(rdata_len)?;
        if rr_end > buf.len() {
            return None;
        }
        pos = rr_end;
        if record_type == OPT_TYPE {
            return Some(OptRecord {
                rr_start,
                rr_end,
                ttl_offset,
                rdata_offset,
                rdata_len,
            });
        }
    }
    None
}

pub(crate) fn has_opt(buf: &[u8]) -> bool {
    find_opt(buf).is_some()
}

/// Append an empty OPT pseudo-RR (root name, CLASS = `udp_size`, TTL 0) as the
/// last additional record; false if malformed, already has an OPT, or ARCOUNT is full.
pub(crate) fn append_opt(buf: &mut Vec<u8>, udp_size: u16) -> bool {
    // Header + root name + TYPE/CLASS/TTL/RDLENGTH = 11 bytes; reject a
    // near-limit packet up front so it cannot be truncated by the 16-bit length.
    const OPT_WIRE_LEN: usize = 11;
    if buf.len() < 12
        || buf.len().saturating_add(OPT_WIRE_LEN) > u16::MAX as usize
        || find_opt(buf).is_some()
    {
        return false;
    }
    let Some(arcount) = header_u16(buf, 10) else { return false };
    let Some(new_arcount) = arcount.checked_add(1) else { return false };
    buf[10..12].copy_from_slice(&new_arcount.to_be_bytes());
    buf.push(0);
    buf.extend_from_slice(&OPT_TYPE.to_be_bytes());
    buf.extend_from_slice(&udp_size.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE / version / flags
    buf.extend_from_slice(&0u16.to_be_bytes());
    true
}

/// Remove the OPT pseudo-RR (FORMERR-with-EDNS fallback), keeping other
/// additional records and fixing ARCOUNT.
pub(crate) fn strip_opt(buf: &mut Vec<u8>) -> bool {
    let Some(opt) = find_opt(buf) else { return false };
    let Some(arcount) = header_u16(buf, 10) else { return false };
    if arcount == 0 {
        return false;
    }
    if opt.rr_start > opt.rr_end || opt.rr_end > buf.len() {
        return false;
    }
    buf.drain(opt.rr_start..opt.rr_end);
    buf[10..12].copy_from_slice(&(arcount - 1).to_be_bytes());
    true
}

/// The OPT extended RCODE combined with the header's low four bits.
pub(crate) fn extended_rcode(buf: &[u8], base: u8) -> u16 {
    let ext = find_opt(buf)
        .and_then(|o| o.ttl(buf))
        .map(|ttl| (ttl >> 24) as u16)
        .unwrap_or(0);
    (ext << 4) | u16::from(base & 0x0f)
}

pub(crate) fn cookie_option(buf: &[u8]) -> Option<&[u8]> {
    let opt = find_opt(buf)?;
    let mut rdata = opt.rdata(buf)?;
    while !rdata.is_empty() {
        if rdata.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([rdata[0], rdata[1]]);
        let len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
        rdata = &rdata[4..];
        let value = rdata.get(..len)?;
        if code == OPT_COOKIE {
            return Some(value);
        }
        rdata = &rdata[len..];
    }
    None
}

/// Replace (or remove, when `cookie` is `None`) the COOKIE option in an
/// existing OPT, preserving all other options. A missing OPT is a no-op;
/// malformed lists or a message over the 16-bit length limit return false.
pub(crate) fn set_cookie_option(buf: &mut Vec<u8>, cookie: Option<&[u8]>) -> bool {
    let Some(opt) = find_opt(buf) else { return true };
    let Some(old_rdata) = opt.rdata(buf) else { return false };

    let mut new_rdata: Vec<u8> = Vec::with_capacity(old_rdata.len() + cookie.map_or(0, |c| 4 + c.len()));
    let mut rest = old_rdata;
    while !rest.is_empty() {
        if rest.len() < 4 {
            return false;
        }
        let code = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.get(4..4 + len).is_none() {
            return false;
        }
        if code != OPT_COOKIE {
            new_rdata.extend_from_slice(&rest[..4 + len]);
        }
        rest = &rest[4 + len..];
    }
    if let Some(cookie) = cookie {
        if cookie.len() > u16::MAX as usize {
            return false;
        }
        new_rdata.extend_from_slice(&OPT_COOKIE.to_be_bytes());
        new_rdata.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        new_rdata.extend_from_slice(cookie);
    }
    if new_rdata.len() > u16::MAX as usize {
        return false;
    }
    // The whole message (RDATA can grow or shrink) must stay within the 16-bit
    // DNS/TCP length field.
    let Some(new_total) = buf
        .len()
        .checked_sub(opt.rdata_len)
        .and_then(|n| n.checked_add(new_rdata.len()))
    else {
        return false;
    };
    if new_total > u16::MAX as usize {
        return false;
    }

    let rdlen_offset = opt.rdata_offset.wrapping_sub(2);
    let Some(slot) = buf.get_mut(rdlen_offset..rdlen_offset + 2) else { return false };
    slot.copy_from_slice(&(new_rdata.len() as u16).to_be_bytes());
    buf.splice(opt.rdata_offset..opt.rdata_offset + opt.rdata_len, new_rdata);
    true
}

/// Cookie support state for one server (upstream `ares_cookie_t`, minus timers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CookieState {
    #[default]
    Initial,
    Generated,
    Supported,
    Unsupported,
}

/// Per-server DNS cookie state, shared by every lookup on a channel.
#[derive(Debug, Clone, Default)]
pub(crate) struct ServerCookie {
    pub state: CookieState,
    client: [u8; 8],
    server: Vec<u8>,
    client_ts: Option<Instant>,
}

/// The verdict of validating one response's COOKIE option.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CookieVerdict {
    /// Accept the response (state already updated).
    Accept,
    /// Drop the response silently and keep waiting for a valid reply.
    Drop,
    /// BADCOOKIE: immediately re-send the query to the same server.
    BadCookie,
}

impl ServerCookie {
    /// COOKIE value for this query, advancing INITIAL → GENERATED and regenerating
    /// the client cookie only from a cleared state. `None` means do not send a
    /// cookie (UNSUPPORTED).
    pub(crate) fn cookie_for_query(&mut self) -> Option<Vec<u8>> {
        match self.state {
            CookieState::Unsupported => None,
            CookieState::Initial => {
                self.client = rand::thread_rng().gen::<[u8; 8]>();
                self.client_ts = Some(Instant::now());
                self.server.clear();
                self.state = CookieState::Generated;
                Some(self.client.to_vec())
            }
            CookieState::Generated | CookieState::Supported => {
                let mut cookie = self.client.to_vec();
                cookie.extend_from_slice(&self.server);
                Some(cookie)
            }
        }
    }

    fn store_server(&mut self, cookie: &[u8]) {
        self.state = CookieState::Supported;
        self.server.clear();
        if cookie.len() > 8 {
            self.server.extend_from_slice(&cookie[8..]);
        }
    }

    fn clear(&mut self) {
        self.client = [0; 8];
        self.server.clear();
        self.client_ts = None;
        self.state = CookieState::Initial;
    }

    /// Validate a response's COOKIE option. `sent_client` is the client cookie put
    /// on the wire (`None` if none); `rcode` is the full extended RCODE.
    pub(crate) fn validate_response(
        &mut self,
        resp: &[u8],
        sent_client: Option<&[u8; 8]>,
        rcode: u16,
    ) -> CookieVerdict {
        let resp_cookie = cookie_option(resp);

        // Malformed COOKIE lengths are dropped as likely spoofs. An 8-byte echo is
        // client-only (no server cookie yet); 9..40 bytes carry a server cookie.
        if let Some(cookie) = resp_cookie {
            if !(8..=40).contains(&cookie.len()) {
                return CookieVerdict::Drop;
            }
        }

        let Some(sent) = sent_client else {
            return CookieVerdict::Accept;
        };

        if let Some(cookie) = resp_cookie {
            // The echoed client cookie must be the one we sent (spoof check).
            match cookie.get(..8) {
                Some(prefix) if prefix == sent => {}
                _ => return CookieVerdict::Drop,
            }
            // Only a real server cookie (>8 bytes) confirms support and is remembered.
            // An 8-byte echo leaves state for the GENERATED branch to mark UNSUPPORTED.
            if cookie.len() > 8 {
                self.store_server(cookie);
            }
        }

        const RCODE_BADCOOKIE: u16 = 23;
        if rcode == RCODE_BADCOOKIE {
            // BADCOOKIE without a server cookie is invalid (drop/spoof).
            return match resp_cookie {
                Some(_) => CookieVerdict::BadCookie,
                None => CookieVerdict::Drop,
            };
        }

        if resp_cookie.is_some_and(|c| c.len() > 8) {
            return CookieVerdict::Accept;
        }

        match self.state {
            // SUPPORTED: a reply without a cookie is dropped so a spoofed/regressed
            // reply cannot win.
            CookieState::Supported => CookieVerdict::Drop,
            // First attempt without a cookie: mark the server UNSUPPORTED and accept.
            CookieState::Generated => {
                self.clear();
                self.state = CookieState::Unsupported;
                CookieVerdict::Accept
            }
            CookieState::Initial | CookieState::Unsupported => CookieVerdict::Accept,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        assert!(append_opt(&mut q, 1280));
        q
    }

    #[test]
    fn append_and_strip_opt() {
        let mut q = query();
        assert!(has_opt(&q));
        assert_eq!(header_u16(&q, 10), Some(1));
        assert!(strip_opt(&mut q));
        assert!(!has_opt(&q));
        assert_eq!(header_u16(&q, 10), Some(0));
        assert_eq!(q.len(), 29);
    }

    #[test]
    fn cookie_append_checks_total_message_length() {
        // Header with one empty OPT at offset 12 plus padding, near the 16-bit limit.
        let make = |len: usize| {
            let mut buf = vec![0u8; len];
            buf[10..12].copy_from_slice(&1u16.to_be_bytes());
            buf[12] = 0;
            buf[13..15].copy_from_slice(&41u16.to_be_bytes());
            buf[15..17].copy_from_slice(&1280u16.to_be_bytes());
            buf
        };

        let mut too_big = make(65530);
        let original = too_big.clone();
        assert!(!set_cookie_option(&mut too_big, Some(&[1u8; 8])));
        assert_eq!(too_big, original, "failed append must not truncate/mutate");

        let mut fits = make(65520);
        assert!(set_cookie_option(&mut fits, Some(&[1u8; 8])));
        assert_eq!(fits.len(), 65532);
        assert_eq!(cookie_option(&fits), Some(&[1u8; 8][..]));
    }

    #[test]
    fn append_opt_rejects_messages_without_room_for_the_whole_rr() {
        // 65531 bytes + the 11-byte OPT overflows the 16-bit message length, so it
        // must be rejected without mutating the buffer.
        let mut buf = vec![0u8; 65531];
        assert!(!append_opt(&mut buf, 1280));
        assert_eq!(buf.len(), 65531);
        assert_eq!(header_u16(&buf, 10), Some(0));

        // Exactly 65535 bytes is still representable.
        let mut fits = vec![0u8; 65524];
        assert!(append_opt(&mut fits, 1280));
        assert_eq!(fits.len(), 65535);
        assert_eq!(header_u16(&fits, 10), Some(1));
    }

    #[test]
    fn strip_preserves_other_additions() {
        // One non-OPT additional (root-named TXT RR) before OPT.
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
            0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0xAA,
        ];
        assert!(append_opt(&mut q, 1232));
        assert!(strip_opt(&mut q));
        assert_eq!(header_u16(&q, 10), Some(1));
        assert_eq!(&q[q.len() - 3..], &[0, 1, 0xAA]);
    }

    #[test]
    fn cookie_option_roundtrip_and_preserves_other_options() {
        let mut q = query();
        let opt = find_opt(&q).expect("opt");
        let custom = [0x00, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        let mut rdata = custom.to_vec();
        rdata.extend_from_slice(&[0x00, 0x0A, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]);
        q.splice(opt.rdata_offset..opt.rdata_offset + opt.rdata_len, rdata);
        let rdlen_off = opt.rdata_offset - 2;
        q[rdlen_off..rdlen_off + 2].copy_from_slice(&18u16.to_be_bytes());

        assert_eq!(cookie_option(&q), Some(&[1, 2, 3, 4, 5, 6, 7, 8][..]));
        set_cookie_option(&mut q, Some(&[9, 9, 9, 9, 9, 9, 9, 9, 1, 2]));
        assert_eq!(cookie_option(&q), Some(&[9, 9, 9, 9, 9, 9, 9, 9, 1, 2][..]));
        assert_eq!(&find_opt(&q).and_then(|o| o.rdata(&q)).unwrap()[..6], &custom);
        set_cookie_option(&mut q, None);
        assert_eq!(cookie_option(&q), None);
        assert_eq!(&find_opt(&q).and_then(|o| o.rdata(&q)).unwrap()[..6], &custom);
    }

    #[test]
    fn malformed_messages_do_not_panic() {
        for len in 0..40 {
            let mut buf = vec![0xff; len];
            let _ = find_opt(&buf);
            let _ = has_opt(&buf);
            let _ = cookie_option(&buf);
            let _ = extended_rcode(&buf, 0);
            let _ = strip_opt(&mut buf);
            set_cookie_option(&mut buf, Some(&[1, 2, 3]));
        }
    }

    #[test]
    fn extended_rcode_combines_opt_ttl() {
        let mut q = query();
        let opt = find_opt(&q).unwrap();
        q[opt.ttl_offset] = 1; // extended rcode 1 => BADCOOKIE with low 7
        assert_eq!(extended_rcode(&q, 7), 23);
        assert_eq!(extended_rcode(&q, 0), 16);
    }

    #[test]
    fn cookie_state_machine() {
        let mut c = ServerCookie::default();
        let client = c.cookie_for_query().unwrap();
        assert_eq!(client.len(), 8);
        assert_eq!(c.state, CookieState::Generated);

        // A response with no cookie marks the server unsupported and accepts.
        let resp = [0, 1, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            c.validate_response(&resp, Some(&client[..8].try_into().unwrap()), 0),
            CookieVerdict::Accept
        );
        assert_eq!(c.state, CookieState::Unsupported);
    }

    fn response_with_cookie(cookie: &[u8]) -> Vec<u8> {
        let mut resp = vec![0, 1, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(append_opt(&mut resp, 1280));
        set_cookie_option(&mut resp, Some(cookie));
        resp
    }

    #[test]
    fn eight_byte_cookie_is_accepted_as_client_only() {
        // An 8-byte echoed client cookie is valid: nothing stored, server marked
        // UNSUPPORTED, reply accepted.
        let mut c = ServerCookie::default();
        let client = c.cookie_for_query().unwrap();
        let sent: [u8; 8] = client[..8].try_into().unwrap();
        assert_eq!(
            c.validate_response(&response_with_cookie(&client), Some(&sent), 0),
            CookieVerdict::Accept
        );
        assert_eq!(c.state, CookieState::Unsupported);

        // A real server cookie (16 bytes) instead confirms SUPPORTED.
        let mut c = ServerCookie::default();
        let mut client = c.cookie_for_query().unwrap();
        let sent: [u8; 8] = client[..8].try_into().unwrap();
        client.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            c.validate_response(&response_with_cookie(&client), Some(&sent), 0),
            CookieVerdict::Accept
        );
        assert_eq!(c.state, CookieState::Supported);
        // Once SUPPORTED, a client-only echo (8 bytes) is a regression: drop.
        assert_eq!(
            c.validate_response(&response_with_cookie(&client[..8]), Some(&sent), 0),
            CookieVerdict::Drop
        );
    }
}
