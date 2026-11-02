use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

/// Address family filter for lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 only (AF_INET)
    Ipv4,
    /// IPv6 only (AF_INET6)
    Ipv6,
    /// Both IPv4 and IPv6 (AF_UNSPEC)
    Any,
}

impl AddressFamily {
    /// The lookup filter for a POSIX `AF_*` constant, or `None` if it isn't one
    /// we recognize. Callers map `None` to their own status: `ares_gethostbyname`
    /// (DNS) → `ENOTIMP`, `ares_gethostbyname_file` (hosts) → `ENOTFOUND`; while
    /// `ares_getaddrinfo` treats an unknown family leniently (`unwrap_or(Any)`).
    pub fn from_af(af: libc::c_int) -> Option<Self> {
        match af {
            libc::AF_INET => Some(Self::Ipv4),
            libc::AF_INET6 => Some(Self::Ipv6),
            libc::AF_UNSPEC => Some(Self::Any),
            _ => None,
        }
    }
}

/// A merged entry from the hosts file: every IP and name that upstream's
/// parser would fold together because they share an IP or any hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub ips: Vec<IpAddr>,
    /// File order; the first name is the primary/canonical hostname.
    pub names: Vec<String>,
}

impl HostEntry {
    /// The primary hostname (first name seen in the file).
    fn canonical(&self) -> &str {
        self.names.first().map(String::as_str).unwrap_or("")
    }

    /// Check if this entry contains the given name (case-insensitive)
    pub fn has_name(&self, name: &str) -> bool {
        self.names.iter().any(|n| n.eq_ignore_ascii_case(name))
    }
}

/// Result of a hostname lookup
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLookup {
    pub canonical: String,
    pub aliases: Vec<String>,
    pub addrs: Vec<IpAddr>,
}

/// Upstream caps the CNAME/alias list derived from one hosts entry at 100.
const MAX_HOST_ALIASES: usize = 100;

/// Parsed hosts file
#[derive(Debug, Clone, Default)]
pub struct Hosts {
    entries: Vec<HostEntry>,
}

impl Hosts {
    /// Parse hosts file content from a string.
    ///
    /// Matching upstream `ares_hosts_file_add`: a new line merges into the
    /// first existing entry that shares an IP (checked first) or any hostname;
    /// merged IPs/names append in file order, and duplicate names are skipped.
    pub fn parse(content: &str) -> Self {
        let mut hosts = Self::default();

        for line in content.lines() {
            if let Some(entry) = Self::parse_line(line) {
                hosts.add_entry(entry);
            }
        }

        hosts
    }

    /// Load and parse hosts file from a path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// Parse a single line, returning None for comments/empty/malformed lines.
    /// The returned entry is a single-line fragment to be merged by `add_entry`.
    fn parse_line(line: &str) -> Option<HostEntry> {
        // Strip comments (everything after #)
        let line = match line.find('#') {
            Some(pos) => &line[..pos],
            None => line,
        };

        // Split on whitespace
        let mut parts = line.split_whitespace();

        // First part is the IP address
        let ip_str = parts.next()?;
        let ip = IpAddr::from_str(ip_str).ok()?;

        // Second part is the primary hostname; the rest are aliases.
        let mut names = Vec::new();
        for name in parts {
            if !names.iter().any(|n: &String| n.eq_ignore_ascii_case(name)) {
                names.push(name.to_string());
            }
        }
        if names.is_empty() {
            return None;
        }

        Some(HostEntry { ips: vec![ip], names })
    }

    /// Fold one parsed line into the matching entry, or start a new one.
    fn add_entry(&mut self, entry: HostEntry) {
        let Some(ip) = entry.ips.first().copied() else { return; };
        let Some(match_idx) = self.find_merge_target(ip, &entry.names) else {
            self.entries.push(entry);
            return;
        };

        let mut new_names = Vec::new();
        for name in entry.names {
            if self.entries[match_idx].has_name(&name) {
                continue;
            }
            // Upstream's host hash has first-wins semantics: a name already
            // owned by a different group is not moved into this one.
            if self
                .entries
                .iter()
                .enumerate()
                .any(|(i, e)| i != match_idx && e.has_name(&name))
            {
                continue;
            }
            new_names.push(name);
        }

        let target = &mut self.entries[match_idx];
        if !target.ips.contains(&ip) {
            target.ips.push(ip);
        }
        target.names.extend(new_names);
    }

    /// Upstream checks an IP match before any hostname match, then takes the
    /// first hostname match in file order.
    fn find_merge_target(&self, ip: IpAddr, names: &[String]) -> Option<usize> {
        if let Some(idx) = self.entries.iter().position(|e| e.ips.contains(&ip)) {
            return Some(idx);
        }
        for name in names {
            if let Some(idx) = self.entries.iter().position(|e| e.has_name(name)) {
                return Some(idx);
            }
        }
        None
    }

    /// Lookup a hostname, returning every address in its merged entry.
    pub fn lookup(&self, name: &str, family: AddressFamily) -> Option<HostLookup> {
        let entry = self.entries.iter().find(|e| e.has_name(name))?;

        let addrs: Vec<IpAddr> = entry
            .ips
            .iter()
            .copied()
            .filter(|ip| match family {
                AddressFamily::Any => true,
                AddressFamily::Ipv4 => ip.is_ipv4(),
                AddressFamily::Ipv6 => ip.is_ipv6(),
            })
            .collect();
        if addrs.is_empty() {
            return None;
        }

        Some(HostLookup {
            canonical: entry.canonical().to_string(),
            aliases: entry_alias_list(entry),
            addrs,
        })
    }

    /// Lookup by IP address, matching any IP in a merged entry.
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<HostLookup> {
        let entry = self.entries.iter().find(|e| e.ips.contains(&ip))?;
        let addrs: Vec<IpAddr> = entry
            .ips
            .iter()
            .copied()
            .filter(|candidate| candidate.is_ipv4() == ip.is_ipv4())
            .collect();

        Some(HostLookup {
            canonical: entry.canonical().to_string(),
            aliases: entry_alias_list(entry),
            addrs,
        })
    }
}

/// All names after the primary, preserving file order and capping at the
/// upstream 100-alias limit.
fn entry_alias_list(entry: &HostEntry) -> Vec<String> {
    entry
        .names
        .iter()
        .skip(1)
        .take(MAX_HOST_ALIASES)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SAMPLE_HOSTS: &str = r#"
# This is a comment
127.0.0.1       localhost localhost.localdomain loopback
::1             localhost ip6-localhost

# Server entries
192.168.1.10    myserver myserver.local
192.168.1.11    myserver
fd00::10        myserver

10.0.0.1        gateway router
"#;

    #[test]
    fn test_parse_basic() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);
        // Lines merge by shared hostname: localhost (v4+v6), the three
        // myserver lines, and gateway.
        assert_eq!(hosts.entries.len(), 3);
        assert_eq!(hosts.entries[0].ips.len(), 2);
        assert_eq!(hosts.entries[1].ips.len(), 3);
    }

    #[test]
    fn test_parse_line_with_comment() {
        let entry = Hosts::parse_line("127.0.0.1 localhost # this is a comment");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        assert_eq!(entry.names, vec!["localhost"]);
        assert_eq!(entry.canonical(), "localhost");
    }

    #[test]
    fn test_parse_line_with_aliases() {
        let entry = Hosts::parse_line("127.0.0.1 localhost localhost.localdomain loopback");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.names[0], "localhost");
        assert_eq!(&entry.names[1..], &["localhost.localdomain", "loopback"]);
    }

    #[test]
    fn test_parse_ipv6() {
        let entry = Hosts::parse_line("::1 localhost");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(
            entry.ips,
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );
    }

    #[test]
    fn test_parse_empty_line() {
        assert!(Hosts::parse_line("").is_none());
        assert!(Hosts::parse_line("   ").is_none());
        assert!(Hosts::parse_line("# comment only").is_none());
    }

    #[test]
    fn test_parse_malformed() {
        assert!(Hosts::parse_line("not-an-ip hostname").is_none());
        assert!(Hosts::parse_line("127.0.0.1").is_none()); // no hostname
    }

    #[test]
    fn test_lookup_localhost() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.lookup("localhost", AddressFamily::Any);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.addrs.len(), 2); // 127.0.0.1 and ::1
        assert_eq!(
            result.aliases,
            vec!["localhost.localdomain", "loopback", "ip6-localhost"]
        );
    }

    #[test]
    fn test_lookup_ipv4_only() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.lookup("localhost", AddressFamily::Ipv4);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.addrs.len(), 1);
        assert!(result.addrs[0].is_ipv4());
    }

    #[test]
    fn test_lookup_ipv6_only() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.lookup("localhost", AddressFamily::Ipv6);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.addrs.len(), 1);
        assert!(result.addrs[0].is_ipv6());
    }

    #[test]
    fn test_lookup_multiple_ips() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.lookup("myserver", AddressFamily::Any);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.addrs.len(), 3); // two IPv4, one IPv6
        assert_eq!(result.canonical, "myserver");
        assert_eq!(result.aliases, vec!["myserver.local"]);
    }

    #[test]
    fn test_merge_by_alias_and_ip_across_lines() {
        let hosts = Hosts::parse(
            "1.2.3.4 primary.example alias1 alias2\n\
             5.6.7.8 primary.example alias3\n",
        );
        assert_eq!(hosts.entries.len(), 1);

        let result = hosts.lookup("alias1", AddressFamily::Any).unwrap();
        assert_eq!(result.canonical, "primary.example");
        assert_eq!(result.aliases, vec!["alias1", "alias2", "alias3"]);
        assert_eq!(
            result.addrs,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            ]
        );

        // A reverse lookup of the second line's address sees the whole group.
        let rev = hosts
            .reverse_lookup(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)))
            .unwrap();
        assert_eq!(rev.canonical, "primary.example");
        assert_eq!(rev.aliases, vec!["alias1", "alias2", "alias3"]);
        assert_eq!(rev.addrs.len(), 2);
    }

    #[test]
    fn test_alias_output_is_capped_at_100() {
        let mut line = String::from("1.2.3.4 primary");
        for i in 0..150 {
            line.push_str(&format!(" alias{i}"));
        }
        let hosts = Hosts::parse(&line);
        let result = hosts.lookup("primary", AddressFamily::Any).unwrap();
        assert_eq!(result.aliases.len(), MAX_HOST_ALIASES);
    }

    #[test]
    fn test_lookup_by_alias() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.lookup("loopback", AddressFamily::Any);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.canonical, "localhost");
    }

    #[test]
    fn test_lookup_case_insensitive() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.lookup("LOCALHOST", AddressFamily::Any);
        assert!(result.is_some());

        let result = hosts.lookup("MyServer", AddressFamily::Any);
        assert!(result.is_some());
    }

    #[test]
    fn test_lookup_not_found() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.lookup("nonexistent", AddressFamily::Any);
        assert!(result.is_none());
    }

    #[test]
    fn test_reverse_lookup() {
        let hosts = Hosts::parse(SAMPLE_HOSTS);

        let result = hosts.reverse_lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.canonical, "gateway");
        assert!(result.aliases.contains(&"router".to_string()));
    }
}
