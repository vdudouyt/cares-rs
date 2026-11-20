//! Validated, allocation-free views of compressed DNS names.
use std::fmt::{self, Write};

/// The packet remains borrowed; labels are followed on demand, not copied.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Name<'a> { packet: &'a [u8], start: usize }

impl<'a> Name<'a> {
    pub(crate) fn parse(packet: &'a [u8], pos: &mut usize) -> Option<Self> {
        let name = Self { packet, start: *pos };
        let mut labels = name.cursor();
        while labels.next_label()?.is_some() {}
        *pos = labels.end?;
        Some(name)
    }

    fn cursor(self) -> Labels<'a> {
        Labels { packet: self.packet, pos: self.start, barrier: self.start, end: None }
    }

    pub(crate) fn labels(self) -> impl Iterator<Item = &'a [u8]> {
        let mut cursor = self.cursor();
        // parse() has already checked this immutable packet's complete chain.
        std::iter::from_fn(move || cursor.next_label().flatten()).fuse()
    }

    /// The explicit ownership boundary used by the C DNS-record API.
    pub(crate) fn to_owned(self) -> Result<crate::mem::CString, crate::core::AresError> {
        let mut out = crate::mem::String::new();
        write!(out, "{self}").map_err(|_| crate::mem::NoMemory)?;
        crate::mem::CString::from_string(out)
    }
}

impl fmt::Display for Name<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, label) in self.labels().enumerate() {
            if i != 0 { out.write_char('.')?; }
            for &c in label {
                if !(0x20..=0x7e).contains(&c) {
                    write!(out, "\\{c:03}")?;
                } else {
                    if matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') {
                        out.write_char('\\')?;
                    }
                    out.write_char(c as char)?;
                }
            }
        }
        Ok(())
    }
}

struct Labels<'a> { packet: &'a [u8], pos: usize, barrier: usize, end: Option<usize> }
impl<'a> Labels<'a> {
    fn next_label(&mut self) -> Option<Option<&'a [u8]>> {
        loop {
            let len = *self.packet.get(self.pos)?;
            self.pos += 1;
            match len {
                0 => {
                    self.end.get_or_insert(self.pos);
                    return Some(None);
                }
                1..=63 => {
                    let end = self.pos.checked_add(len as usize)?;
                    let label = self.packet.get(self.pos..end)?;
                    self.pos = end;
                    return Some(Some(label));
                }
                0xc0..=0xff => {
                    let low = *self.packet.get(self.pos)?;
                    self.pos += 1;
                    let target = ((usize::from(len) & 0x3f) << 8) | usize::from(low);
                    // Every jump precedes the current name fragment, bounding
                    // traversal without recursion, a visited set, or allocation.
                    if target >= self.barrier { return None; }
                    self.end.get_or_insert(self.pos);
                    self.barrier = target;
                    self.pos = target;
                }
                _ => return None,
            }
        }
    }
}
