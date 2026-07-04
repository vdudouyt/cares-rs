//! resolv.conf-style sortlist parsing and result ordering (RES_OPT sortlist).

use crate::core::AresError;
use std::net::IpAddr;

use crate::core::packets::AddrRecord;
use crate::ffi::error::ARES_EBADSTR;

#[derive(Clone, Debug)]
pub struct SortlistEntry {
    addr: IpAddr,
    mask_bits: u8,
}

impl SortlistEntry {
    fn matches(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = if self.mask_bits >= 32 { u32::MAX } else { u32::MAX << (32 - self.mask_bits) };
                u32::from(net) & mask == u32::from(*candidate) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let net_bits = u128::from(net);
                let cand_bits = u128::from(*candidate);
                let mask = if self.mask_bits >= 128 { u128::MAX } else { u128::MAX << (128 - self.mask_bits) };
                net_bits & mask == cand_bits & mask
            }
            _ => false,
        }
    }
}

pub fn apply_sortlist(sortlist: &[SortlistEntry], items: &mut [AddrRecord]) {
    // Stable sort: items matching earlier sortlist entries come first
    items.sort_by(|a, b| {
        let a_idx = sortlist.iter().position(|s| s.matches(&a.ip)).unwrap_or(usize::MAX);
        let b_idx = sortlist.iter().position(|s| s.matches(&b.ip)).unwrap_or(usize::MAX);
        a_idx.cmp(&b_idx)
    });
}

pub(crate) fn parse_sortlist(s: &str) -> Result<Vec<SortlistEntry>, AresError> {
    let mut entries = Vec::new();
    for token in s.split(|c: char| c.is_whitespace() || c == ';').filter(|t| !t.is_empty()) {
        // Formats: "ip/mask" or "ip/bits" or just "ip"
        if let Some((addr_s, mask_s)) = token.split_once('/') {
            let addr: IpAddr = addr_s.parse().map_err(|_| ARES_EBADSTR)?;
            // Try as CIDR bits first
            if let Ok(bits) = mask_s.parse::<u8>() {
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if bits > max { return Err(ARES_EBADSTR.into()); }
                entries.push(SortlistEntry { addr, mask_bits: bits });
            } else {
                // Try as dotted netmask (IPv4 only)
                let mask: std::net::Ipv4Addr = mask_s.parse().map_err(|_| ARES_EBADSTR)?;
                let mask_u32 = u32::from(mask);
                let bits = mask_u32.leading_ones() as u8;
                entries.push(SortlistEntry { addr, mask_bits: bits });
            }
        } else {
            // Bare address - use /32 or /128 default
            let addr: IpAddr = token.parse().map_err(|_| ARES_EBADSTR)?;
            let bits = if addr.is_ipv4() { 32 } else { 128 };
            entries.push(SortlistEntry { addr, mask_bits: bits });
        }
    }
    Ok(entries)
}
