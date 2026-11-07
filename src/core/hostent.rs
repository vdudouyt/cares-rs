//! The pure shape of a hostent result: which names, aliases and addresses a
//! reply yields. The ffi layer only builds the C graph mechanically.

use std::ffi::CString;
use std::net::IpAddr;

use crate::core::hostfile::HostLookup;
use crate::core::packets::AddrRecord;
use crate::core::response::ParsedRRs;
use crate::core::sortlist::{apply_sortlist_ips, SortlistEntry};

/// A fully decided hostent: family, address filter, and NUL-safe aliases.
pub(crate) struct Hostent {
    pub name: CString,
    pub aliases: Vec<CString>,
    pub addrtype: i32,
    pub length: usize,
    pub addrs: Vec<IpAddr>,
}

impl Hostent {
    /// A synthetic result with no aliases (IP literal / localhost); `addrs`
    /// must be non-empty.
    pub fn new(canonical: String, addrs: Vec<IpAddr>) -> Self {
        Self::from_lookup(HostLookup { canonical, aliases: vec![], addrs })
    }

    /// A hosts-file/IP-literal result: family from the first address; aliases
    /// with an embedded NUL are dropped and such a canonical name becomes empty.
    pub fn from_lookup(lookup: HostLookup) -> Self {
        let (addrtype, length) = match lookup.addrs[0] {
            IpAddr::V4(_) => (libc::AF_INET, 4),
            IpAddr::V6(_) => (libc::AF_INET6, 16),
        };
        let addrs = lookup.addrs.iter().filter(|ip| ip_len(ip) == length).copied().collect();
        let aliases = lookup
            .aliases
            .into_iter()
            .filter_map(|s| CString::new(s).ok()) // drop NUL-containing aliases
            .collect();
        Hostent {
            name: CString::new(lookup.canonical).unwrap_or_default(),
            aliases,
            addrtype,
            length,
            addrs,
        }
    }

    /// A DNS result for an explicit family; an unknown family emits no addresses.
    pub fn from_parsed(rrs: ParsedRRs<AddrRecord>, family: i32) -> Self {
        let length = match family {
            libc::AF_INET => 4,
            libc::AF_INET6 => 16,
            _ => 0,
        };
        let addrs = rrs.items.iter().map(|r| r.ip).filter(|ip| ip_len(ip) == length).collect();
        Hostent { name: rrs.name, aliases: rrs.aliases, addrtype: family, length, addrs }
    }

    /// Apply the channel sortlist, whether the addresses came from hosts or DNS.
    pub fn sort_addrs(&mut self, sortlist: &[SortlistEntry]) {
        if !sortlist.is_empty() {
            apply_sortlist_ips(sortlist, &mut self.addrs);
        }
    }
}

fn ip_len(ip: &IpAddr) -> usize {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

pub(crate) fn addrttl_fill(items: &[AddrRecord], want_v4: bool, max: usize) -> Vec<(IpAddr, u32)> {
    items
        .iter()
        .filter(|r| matches!(r.ip, IpAddr::V4(_)) == want_v4)
        .take(max)
        .map(|r| (r.ip, r.ttl))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::sortlist::SortlistEntry;
    use std::net::Ipv4Addr;

    #[test]
    fn channel_sortlist_applies_to_hosts_derived_hostent() {
        let lookup = HostLookup {
            canonical: "example.test".into(),
            aliases: vec![],
            addrs: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ],
        };
        let mut host = Hostent::from_lookup(lookup);
        let sortlist = vec![
            SortlistEntry::from_parts(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)), 24).unwrap(),
        ];
        host.sort_addrs(&sortlist);
        assert_eq!(host.addrs[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }
}
