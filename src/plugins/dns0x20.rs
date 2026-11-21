//! DNS 0x20 (draft-vixie-dnsext-dns0x20, `ARES_FLAG_DNS0x20`): randomize the
//! case of the question name on UDP queries and drop replies whose question
//! does not echo it exactly, a cheap extra defence against spoofing. Stateless:
//! the expected case is read back from the packet as sent.

use rand::Rng;
use std::ops::Range;

use super::{Ctx, Plugin, ReceiveVerdict};
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
    fn on_start(&self, cx: &Ctx, payload: &mut crate::mem::ByteBuf) {
        if Self::enabled(cx) {
            let _ = randomize_question_name(payload);
        }
    }

    /// On UDP, the reply's question must match the sent one's case exactly.
    fn on_receive(&self, cx: &Ctx, sent: &[u8], reply: &[u8]) -> ReceiveVerdict {
        if !Self::enabled(cx) {
            return ReceiveVerdict::Accept;
        }
        match question_name(sent) {
            Some(expected) if !question_matches_case(reply, expected) => ReceiveVerdict::Drop,
            _ => ReceiveVerdict::Accept,
        }
    }
}

/// Question 0's wire-encoded name, including label lengths and the root byte.
/// A compressed or overlong question name returns `None`.
fn question_range(buf: &[u8]) -> Option<Range<usize>> {
    // QDCOUNT (header offset 4) must be non-zero.
    if buf.len() < 12 || buf.get(4..6)? == [0, 0] {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *buf.get(pos)?;
        pos += 1;
        if len == 0 {
            return (pos - 12 <= 255).then_some(12..pos);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let end = pos.checked_add(len as usize)?;
        if end > buf.len() || end - 12 >= 255 {
            return None;
        }
        pos = end;
    }
}

/// Validate before mutating. Label lengths (0..=63) are never ASCII letters,
/// so the validated wire name can be randomized directly, without a buffer.
fn randomize_question_name(buf: &mut [u8]) -> Option<()> {
    let range = question_range(buf)?;
    let mut rng = rand::thread_rng();
    for byte in buf.get_mut(range)? {
        if byte.is_ascii_alphabetic() {
            if rng.r#gen::<bool>() {
                *byte |= 0x20;
            } else {
                *byte &= !0x20;
            }
        }
    }
    Some(())
}

/// Compare wire names so label boundaries are significant, including labels
/// containing a literal dot. Both reads borrow the original packets.
fn question_name(buf: &[u8]) -> Option<&[u8]> {
    buf.get(question_range(buf)?)
}

/// DNS 0x20 check: the response question must match the randomized query's case.
fn question_matches_case(resp: &[u8], expected: &[u8]) -> bool {
    question_name(resp) == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> crate::mem::ByteBuf {
        crate::mem::ByteBuf::from([
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ])
    }

    #[test]
    fn question_name_case_and_randomization() {
        let mut q = query();
        assert_eq!(question_name(&q), Some(&b"\x07example\x03com\0"[..]));
        randomize_question_name(&mut q).unwrap();
        let randomized = question_name(&q).unwrap();
        assert_eq!(randomized.len(), 13);
        assert!(question_matches_case(&q, randomized));
        let mut mismatch = q.clone();
        mismatch[13] ^= 0x20; // Always change one letter, independent of RNG output.
        assert!(!question_matches_case(&mismatch, randomized));
    }

    #[test]
    fn malformed_messages_do_not_panic() {
        for len in 0..40 {
            let mut buf = vec![0xff; len];
            let _ = question_name(&buf);
            let _ = randomize_question_name(&mut buf);
        }
    }

    #[test]
    fn comparison_preserves_label_boundaries() {
        let mut sent = query();
        sent.truncate(12);
        sent.extend_from_slice(b"\x03a.b\0\0\x01\0\x01");
        let mut reply = query();
        reply.truncate(12);
        reply.extend_from_slice(b"\x01a\x01b\0\0\x01\0\x01");
        assert!(!question_matches_case(&reply, question_name(&sent).unwrap()));
    }

    #[test]
    fn name_length_limit_is_checked_before_randomization() {
        let mut packet = query();
        packet.truncate(12);
        for len in [63, 63, 63, 61] {
            packet.push(len);
            packet.extend(std::iter::repeat_n(b'a', len as usize));
        }
        packet.push(0);
        assert_eq!(question_name(&packet).unwrap().len(), 255);
        randomize_question_name(&mut packet).unwrap();

        packet[204] = 62; // Increase the final label beyond the DNS name limit.
        let end = packet.len() - 1;
        packet.insert(end, b'a');
        let before = packet.clone();
        assert!(randomize_question_name(&mut packet).is_none());
        assert_eq!(packet, before);
    }
}
