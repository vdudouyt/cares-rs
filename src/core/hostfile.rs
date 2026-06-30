use std::collections::HashSet;
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

/// A single entry from the hosts file (one line)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub ip: IpAddr,
    pub canonical: String,
    pub aliases: Vec<String>,
}

impl HostEntry {
    /// Returns all names (canonical + aliases)
    pub fn all_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.canonical.as_str()).chain(self.aliases.iter().map(|s| s.as_str()))
    }

    /// Check if this entry contains the given name (case-insensitive)
    pub fn has_name(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.all_names().any(|n| n.to_lowercase() == name_lower)
    }

    /// Check if this entry matches the address family filter
    pub fn matches_family(&self, family: AddressFamily) -> bool {
        match family {
            AddressFamily::Any => true,
            AddressFamily::Ipv4 => self.ip.is_ipv4(),
            AddressFamily::Ipv6 => self.ip.is_ipv6(),
        }
    }
}

/// Result of a hostname lookup
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLookup {
    pub canonical: String,
    pub aliases: Vec<String>,
    pub addrs: Vec<IpAddr>,
}

/// Parsed hosts file
#[derive(Debug, Clone, Default)]
pub struct Hosts {
    entries: Vec<HostEntry>,
}

impl Hosts {
    /// Parse hosts file content from a string
    pub fn parse(content: &str) -> Self {
        let mut entries = Vec::new();

        for line in content.lines() {
            if let Some(entry) = Self::parse_line(line) {
                entries.push(entry);
            }
        }

        Self { entries }
    }

    /// Load and parse hosts file from a path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// Parse a single line, returning None for comments/empty/malformed lines
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

        // Second part is the canonical hostname
        let canonical = parts.next()?.to_string();

        // Remaining parts are aliases
        let aliases: Vec<String> = parts.map(|s| s.to_string()).collect();

        Some(HostEntry {
            ip,
            canonical,
            aliases,
        })
    }

    /// Lookup a hostname, aggregating results across all matching entries
    pub fn lookup(&self, name: &str, family: AddressFamily) -> Option<HostLookup> {
        let matching_entries: Vec<&HostEntry> = self
            .entries
            .iter()
            .filter(|e| e.has_name(name) && e.matches_family(family))
            .collect();

        if matching_entries.is_empty() {
            return None;
        }

        // Collect all addresses
        let addrs: Vec<IpAddr> = matching_entries.iter().map(|e| e.ip).collect();

        // Use canonical name from the first matching entry
        let canonical = matching_entries[0].canonical.clone();

        // Collect all unique aliases across all matching entries
        let mut alias_set: HashSet<String> = HashSet::new();
        for entry in &matching_entries {
            for alias in &entry.aliases {
                let alias_lower = alias.to_lowercase();
                if alias_lower != canonical.to_lowercase() {
                    alias_set.insert(alias.clone());
                }
            }
            // Also add canonical names from other entries as aliases
            if entry.canonical.to_lowercase() != canonical.to_lowercase() {
                alias_set.insert(entry.canonical.clone());
            }
        }

        let aliases: Vec<String> = alias_set.into_iter().collect();

        Some(HostLookup {
            canonical,
            aliases,
            addrs,
        })
    }

    /// Lookup by IP address, returning all hostnames associated with it
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<HostLookup> {
        let matching_entries: Vec<&HostEntry> =
            self.entries.iter().filter(|e| e.ip == ip).collect();

        if matching_entries.is_empty() {
            return None;
        }

        let canonical = matching_entries[0].canonical.clone();

        let mut alias_set: HashSet<String> = HashSet::new();
        for entry in &matching_entries {
            for alias in &entry.aliases {
                if alias.to_lowercase() != canonical.to_lowercase() {
                    alias_set.insert(alias.clone());
                }
            }
            if entry.canonical.to_lowercase() != canonical.to_lowercase() {
                alias_set.insert(entry.canonical.clone());
            }
        }

        let aliases: Vec<String> = alias_set.into_iter().collect();

        Some(HostLookup {
            canonical,
            aliases,
            addrs: vec![ip],
        })
    }
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
        assert_eq!(hosts.entries.len(), 6);
    }

    #[test]
    fn test_parse_line_with_comment() {
        let entry = Hosts::parse_line("127.0.0.1 localhost # this is a comment");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(entry.canonical, "localhost");
        assert!(entry.aliases.is_empty());
    }

    #[test]
    fn test_parse_line_with_aliases() {
        let entry = Hosts::parse_line("127.0.0.1 localhost localhost.localdomain loopback");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.canonical, "localhost");
        assert_eq!(entry.aliases, vec!["localhost.localdomain", "loopback"]);
    }

    #[test]
    fn test_parse_ipv6() {
        let entry = Hosts::parse_line("::1 localhost");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.ip, IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
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
