//! DNS 0x20 (draft-vixie-dnsext-dns0x20, `ARES_FLAG_DNS0x20`): randomize the
//! case of the question name on UDP queries and drop replies whose question
//! does not echo it exactly, a cheap extra defence against spoofing. Stateless:
//! the expected case is read back from the packet as sent.

use rand::Rng;

use super::{Ctx, Plugin, Screen};
use crate::ffi::ares_options::ARES_FLAG_DNS0x20;

/// The DNS 0x20 query plugin.
pub(crate) struct Dns0x20Plugin;

impl Dns0x20Plugin {
    pub(crate) fn new() -> Self {
        Dns0x20Plugin
    }

    fn enabled(cx: &Ctx) -> bool {
        cx.client.flags & ARES_FLAG_DNS0x20 != 0 && !cx.use_tcp
    }
}

impl Plugin for Dns0x20Plugin {
    /// Randomize once per UDP query; retries keep the same case.
    fn start(&self, cx: &Ctx, payload: &mut Vec<u8>) {
        if Self::enabled(cx) {
            let _ = randomize_question_name(payload);
        }
    }

    /// On UDP, the reply's question must match the sent one's case exactly.
    fn screen(&self, cx: &Ctx, sent: &[u8], reply: &[u8]) -> Screen {
        if !Self::enabled(cx) {
            return Screen::Accept;
        }
        match question_name(sent) {
            Some(expected) if !question_matches_case(reply, &expected) => Screen::Drop,
            _ => Screen::Accept,
        }
    }
}

/// Question 0's label byte ranges, shared by the case-preserving reader and
/// the DNS 0x20 randomizer. A compressed question name returns `None`.
fn question_label_ranges(buf: &[u8]) -> Option<Vec<(usize, usize)>> {
    // QDCOUNT (header offset 4) must be non-zero.
    if buf.len() < 12 || buf.get(4..6)? == [0, 0] {
        return None;
    }
    let mut pos = 12usize;
    let mut ranges = Vec::new();
    loop {
        let len = *buf.get(pos)?;
        pos += 1;
        if len == 0 {
            return Some(ranges);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let end = pos.checked_add(len as usize)?;
        if end > buf.len() {
            return None;
        }
        ranges.push((pos, end));
        pos = end;
    }
}

fn join_question_name(buf: &[u8], ranges: &[(usize, usize)]) -> Option<Vec<u8>> {
    let mut name = Vec::new();
    for (i, &(start, end)) in ranges.iter().enumerate() {
        if i > 0 {
            name.push(b'.');
        }
        name.extend_from_slice(buf.get(start..end)?);
    }
    Some(name)
}

/// Randomize the case of each ASCII letter in question 0 (DNS 0x20,
/// draft-vixie-dnsext-dns0x20) and return the presentation-form name for
/// response validation.
fn randomize_question_name(buf: &mut [u8]) -> Option<Vec<u8>> {
    let ranges = question_label_ranges(buf)?;
    let mut rng = rand::thread_rng();
    for &(start, end) in &ranges {
        for byte in buf.get_mut(start..end)? {
            if byte.is_ascii_alphabetic() {
                if rng.r#gen::<bool>() {
                    *byte |= 0x20;
                } else {
                    *byte &= !0x20;
                }
            }
        }
    }
    join_question_name(buf, &ranges)
}

/// Question 0's presentation-form name, preserving case.
fn question_name(buf: &[u8]) -> Option<Vec<u8>> {
    let ranges = question_label_ranges(buf)?;
    join_question_name(buf, &ranges)
}

/// DNS 0x20 check: the response question must match the randomized query's case.
fn question_matches_case(resp: &[u8], expected: &[u8]) -> bool {
    question_name(resp).as_deref() == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]
    }

    #[test]
    fn question_name_case_and_randomization() {
        let mut q = query();
        assert_eq!(question_name(&q).as_deref(), Some(&b"example.com"[..]));
        let randomized = randomize_question_name(&mut q).unwrap();
        assert_eq!(randomized.len(), 11);
        assert!(question_matches_case(&q, &randomized));
        let mut lower = q.clone();
        for b in lower.iter_mut().skip(12).take(13) {
            *b = b.to_ascii_lowercase();
        }
        assert!(!question_matches_case(&lower, &randomized));
    }

    #[test]
    fn malformed_messages_do_not_panic() {
        for len in 0..40 {
            let mut buf = vec![0xff; len];
            let _ = question_name(&buf);
            let _ = randomize_question_name(&mut buf);
        }
    }
}
