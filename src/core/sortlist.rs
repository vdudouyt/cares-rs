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
    /// Validate and build one entry (the same family/mask rules
    /// `ares_set_sortlist` applies to its textual form).
    pub(crate) fn from_parts(addr: IpAddr, mask_bits: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if mask_bits > max {
            return None;
        }
        Some(SortlistEntry { addr, mask_bits })
    }

    pub(crate) fn addr(&self) -> IpAddr {
        self.addr
    }

    pub(crate) fn mask_bits(&self) -> u8 {
        self.mask_bits
    }

    fn matches(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = if self.mask_bits == 0 {
                    0
                } else if self.mask_bits >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - self.mask_bits)
                };
                u32::from(net) & mask == u32::from(*candidate) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let net_bits = u128::from(net);
                let cand_bits = u128::from(*candidate);
                let mask = if self.mask_bits == 0 {
                    0
                } else if self.mask_bits >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - self.mask_bits)
                };
                net_bits & mask == cand_bits & mask
            }
            _ => false,
        }
    }
}

/// The first sortlist entry matching `ip`, or one past the end.
fn sortlist_index(sortlist: &[SortlistEntry], ip: &IpAddr) -> usize {
    sortlist
        .iter()
        .position(|entry| entry.matches(ip))
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
pub fn apply_sortlist(sortlist: &[SortlistEntry], items: &mut [AddrRecord]) {
    // Stable sort: items matching earlier sortlist entries come first.
    items.sort_by_key(|item| sortlist_index(sortlist, &item.ip));
}

/// Apply the channel sortlist to a hostent's address list.
pub(crate) fn apply_sortlist_ips(sortlist: &[SortlistEntry], ips: &mut [IpAddr]) {
    ips.sort_by_key(|ip| sortlist_index(sortlist, ip));
}

/// RFC 6724 address precedence (rules 6; source-address-dependent rules 1-5
/// and 7-9 are intentionally omitted). Higher values sort first.
fn rfc6724_precedence(ip: &IpAddr) -> i32 {
    match ip {
        IpAddr::V4(_) => 35,
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let loopback = v6 == &std::net::Ipv6Addr::LOCALHOST;
            let v4_mapped = octets[..10].iter().all(|&b| b == 0)
                && octets[10] == 0xff
                && octets[11] == 0xff;
            let v4_compat = octets[..12].iter().all(|&b| b == 0);
            let six_to_four = octets[0] == 0x20 && octets[1] == 0x02;
            let teredo = octets[..4] == [0x20, 0x01, 0x00, 0x00];
            let ula = octets[0] & 0xfe == 0xfc;
            let site_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0xc0;
            let six_bone = octets[0] == 0x3f && octets[1] == 0xfe;
            if loopback {
                50
            } else if v4_mapped {
                35
            } else if six_to_four {
                30
            } else if teredo {
                5
            } else if ula {
                3
            } else if v4_compat || site_local || six_bone {
                1
            } else {
                40
            }
        }
    }
}

/// RFC 6724 ordering used by getaddrinfo when ARES_AI_NOSORT is not set.
/// Rules 6 (precedence) and 10 (stable original order) are implemented;
/// source-address-dependent rules are omitted.
pub fn sort_addrinfo(items: &mut [AddrRecord]) {
    // `sort_by_key` is stable, so equal precedences keep their original order.
    items.sort_by_key(|item| std::cmp::Reverse(rfc6724_precedence(&item.ip)));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rec(ip: IpAddr) -> AddrRecord {
        AddrRecord { ip, ttl: 0 }
    }

    #[test]
    fn rejects_out_of_range_prefixes_and_accepts_valid_families() {
        assert!(SortlistEntry::from_parts(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).is_some());
        assert!(SortlistEntry::from_parts(IpAddr::V4(Ipv4Addr::LOCALHOST), 33).is_none());
        assert!(SortlistEntry::from_parts(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).is_some());
        assert!(SortlistEntry::from_parts(IpAddr::V6(Ipv6Addr::LOCALHOST), 129).is_none());
    }

    #[test]
    fn apply_prefers_earliest_matching_entry_and_is_stable() {
        let list = vec![
            SortlistEntry::from_parts(IpAddr::V4(Ipv4Addr::new(2, 0, 0, 0)), 8).unwrap(),
            SortlistEntry::from_parts(IpAddr::V4(Ipv4Addr::new(3, 0, 0, 0)), 8).unwrap(),
        ];
        let mut items = vec![
            rec(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            rec(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))),
            rec(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))),
            rec(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ];
        apply_sortlist(&list, &mut items);
        let got: Vec<_> = items.iter().map(|r| r.ip.to_string()).collect();
        assert_eq!(got, ["2.2.2.2", "3.3.3.3", "9.9.9.9", "8.8.8.8"]);
    }

    #[test]
    fn zero_prefix_matches_everything_without_panicking() {
        let v4 = vec![SortlistEntry::from_parts(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()];
        let mut items = vec![
            rec(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            rec(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ];
        apply_sortlist(&v4, &mut items);
        assert_eq!(items[0].ip, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));

        let v6 = vec![SortlistEntry::from_parts(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap()];
        let mut items = vec![
            rec(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            rec(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ];
        apply_sortlist(&v6, &mut items);
        assert_eq!(items[0].ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn rfc6724_precedence_prefers_loopback_then_ipv4_then_other_v6() {
        let mut items = vec![
            rec(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            rec("2002::1".parse().unwrap()),
            rec(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            rec(IpAddr::V6("2001:0:0:1::1".parse().unwrap())),
        ];
        sort_addrinfo(&mut items);
        let got: Vec<_> = items.iter().map(|r| r.ip.to_string()).collect();
        assert_eq!(got[0], "::1");
        assert_eq!(got[1], "9.9.9.9");
        assert_eq!(got[2], "2002::1");
        assert_eq!(got[3], "2001:0:0:1::1");
    }
}
