//! The pure shape of a hostent result — which names, aliases and addresses
//! a reply yields for which family. The ffi layer builds the C graph from a
//! blueprint mechanically; every inclusion/ordering decision is made here.

use std::ffi::CString;
use std::net::IpAddr;

use crate::core::hostfile::HostLookup;
use crate::core::packets::AddrRecord;
use crate::core::response::ParsedRRs;

/// Everything a `struct hostent` will say, decided: representative family,
/// per-family address filter, and the NUL-safety alias policy.
pub(crate) struct Hostent {
    pub name: CString,
    pub aliases: Vec<CString>,
    pub addrtype: i32,
    pub length: usize,
    pub addrs: Vec<IpAddr>,
}

impl Hostent {
    /// A synchronous (hosts-file / IP-literal / localhost) result: the
    /// representative family comes from the first address; aliases that
    /// cannot become C strings (embedded NUL) are dropped; a NUL-containing
    /// canonical name degrades to the empty string.
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

    /// A DNS result for an explicit family: only addresses whose width
    /// matches the family are emitted (an unknown family emits none).
    pub fn from_parsed(rrs: ParsedRRs<AddrRecord>, family: i32) -> Self {
        let length = match family {
            libc::AF_INET => 4,
            libc::AF_INET6 => 16,
            _ => 0,
        };
        let addrs = rrs.items.iter().map(|r| r.ip).filter(|ip| ip_len(ip) == length).collect();
        Hostent { name: rrs.name, aliases: rrs.aliases, addrtype: family, length, addrs }
    }
}

fn ip_len(ip: &IpAddr) -> usize {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

/// The addrttl report: records of the wanted family, in arrival order,
/// truncated to the caller's array size.
pub(crate) fn addrttl_fill(items: &[AddrRecord], want_v4: bool, max: usize) -> Vec<(IpAddr, u32)> {
    items
        .iter()
        .filter(|r| matches!(r.ip, IpAddr::V4(_)) == want_v4)
        .take(max)
        .map(|r| (r.ip, r.ttl))
        .collect()
}
