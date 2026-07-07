//! Query construction: the pure body of ares_create_query/ares_mkquery —
//! escaped-name analysis (trailing-dot and `\.`/`\DDD` handling), RFC 7686
//! .onion rejection, label validation, and wire-format packet assembly.
//! The FFI shim only decodes the C string and mallocs the returned packet.
//!
//! Also the neutral home of the lightweight wire codec the resolver engines
//! share — `dns_query_payload` (build a UDP-form query) plus the TCP length-
//! prefix helpers `frame_tcp`/`tcp_payload` — so neither the classic reactor
//! (`transport.rs`) nor the async engine (`executor.rs`) depends on the other.

use bytes::{BufMut, BytesMut};
use rand::Rng;

use crate::core::AresError;
use crate::ffi::error::{ARES_EBADNAME, ARES_ENOTFOUND};

/// Write a DNS query directly to the buffer from a hostname string,
/// avoiding intermediate Vec<String>, DnsQuery, and DnsFrame allocations.
fn write_dns_query_direct(buf: &mut BytesMut, hostname: &str, qtype: u16, transaction_id: u16) {
    // Header: 12 bytes
    buf.put_u16(transaction_id);
    buf.put_u16(0x0100); // flags: standard query, recursion desired
    buf.put_u16(1); // qdcount
    buf.put_u16(0); // ancount
    buf.put_u16(0); // nscount
    buf.put_u16(0); // arcount

    // Question: labels
    for label in hostname.split('.').filter(|t| !t.is_empty()) {
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0); // root label
    buf.put_u16(qtype);
    buf.put_u16(1); // qclass: IN
}

/// Build a UDP-form DNS query payload (with a fresh random transaction id).
pub fn dns_query_payload(name: &str, qtype: u16) -> BytesMut {
    let transaction_id = rand::thread_rng().r#gen::<u16>();
    let mut buf = BytesMut::with_capacity(12 + name.len() + 2 + 4);
    write_dns_query_direct(&mut buf, name, qtype, transaction_id);
    buf
}

/// Wrap a DNS payload in the 2-byte big-endian length prefix used for TCP framing.
pub fn frame_tcp(payload: &[u8]) -> BytesMut {
    let mut framed = BytesMut::with_capacity(2 + payload.len());
    framed.put_u16(payload.len() as u16);
    framed.extend_from_slice(payload);
    framed
}

/// Strip the 2-byte TCP length prefix, yielding the canonical UDP-form payload
/// (used when a query moves TCP → UDP on reissue).
pub(crate) fn tcp_payload(writebuf: &[u8], was_tcp: bool) -> &[u8] {
    if was_tcp && writebuf.len() > 2 {
        &writebuf[2..]
    } else {
        writebuf
    }
}

/// Build a DNS query packet for `name_str`. A positive `max_udp_size`
/// appends an EDNS OPT pseudo-RR advertising that payload size; zero or
/// negative means "no EDNS" (the historical ares_create_query gate).
pub fn build_query(
    name_str: &str,
    dnsclass: u16,
    qtype: u16,
    id: u16,
    rd: bool,
    max_udp_size: i32,
) -> Result<Vec<u8>, AresError> {
    let max_udp_size: u16 = if max_udp_size > 0 { max_udp_size as u16 } else { 0 };
    // Check if trailing dot is an unescaped separator (not a literal escaped dot)
    let has_unescaped_trailing_dot = if let Some(prefix) = name_str.strip_suffix('.') {
        // Count consecutive backslashes before the trailing dot
        let backslash_count = prefix
            .as_bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        // Even number of backslashes means dot is unescaped (separator)
        backslash_count % 2 == 0
    } else {
        false
    };

    // Reject .onion domains
    let lower = name_str.to_lowercase();
    let check = if has_unescaped_trailing_dot {
        lower.strip_suffix('.').unwrap_or(&lower)
    } else {
        &lower
    };
    if check.ends_with(".onion") || check == "onion" {
        return Err(ARES_ENOTFOUND.into());
    }

    // Validate name length
    let clean_name = if has_unescaped_trailing_dot {
        name_str.strip_suffix('.').unwrap_or(name_str)
    } else {
        name_str
    };
    if clean_name.len() > 253 {
        return Err(ARES_EBADNAME.into());
    }

    // Check for escaped dots and handle them
    let labels: Vec<&str> = if clean_name.is_empty() {
        vec![] // root query
    } else {
        // Handle escaped dots: split only on unescaped dots
        let mut result = Vec::new();
        let mut current_start = 0;
        let bytes = clean_name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2; // skip escaped char
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

    // Validate label lengths and reject empty labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.is_empty() {
            return Err(ARES_EBADNAME.into());
        }
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
    }

    // Build DNS packet
    let flags: u16 = if rd { 0x0100 } else { 0x0000 }; // RD flag
    let mut packet = Vec::with_capacity(512);
    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    packet.extend_from_slice(&0u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0u16.to_be_bytes()); // nscount
    let arcount: u16 = if max_udp_size > 0 { 1 } else { 0 };
    packet.extend_from_slice(&arcount.to_be_bytes()); // arcount

    // Question: encode labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
        packet.push(unescaped.len() as u8);
        packet.extend_from_slice(&unescaped);
    }
    packet.push(0); // root label
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&dnsclass.to_be_bytes());

    // OPT pseudo-RR for EDNS if max_udp_size > 0
    if max_udp_size > 0 {
        packet.push(0); // root name
        packet.extend_from_slice(&41u16.to_be_bytes()); // type OPT
        packet.extend_from_slice(&max_udp_size.to_be_bytes()); // class = UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL (extended RCODE + flags)
        packet.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    }

    Ok(packet)
}

/// Decode a presentation-form label: `\.` escapes and `\DDD` numeric escapes.
pub fn unescape_label(label: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(label.len());
    let bytes = label.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // Check for numeric escape \DDD
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
