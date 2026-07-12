//! Module for looking up service names from /etc/services

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    Dccp,
}

#[derive(Debug)]
pub struct Services {
    // Map from (port, protocol) to service name
    entries: HashMap<(u16, Protocol), String>,
}

impl Default for Services {
    fn default() -> Self {
        Self::from_path("/etc/services").unwrap_or_else(|_| Services {
            entries: HashMap::new(),
        })
    }
}

impl Services {
    pub fn from_path(path: &str) -> Result<Self, std::io::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = HashMap::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Remove inline comments
            let line = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            };

            // Parse: service_name port/protocol [aliases...]
            let mut parts = line.split_whitespace();
            let Some(service_name) = parts.next() else {
                continue;
            };
            let Some(port_proto) = parts.next() else {
                continue;
            };

            // Parse port/protocol
            let mut port_proto_parts = port_proto.split('/');
            let Some(port_str) = port_proto_parts.next() else {
                continue;
            };
            let Some(proto_str) = port_proto_parts.next() else {
                continue;
            };

            let Ok(port) = port_str.parse::<u16>() else {
                continue;
            };

            let protocol = match proto_str.to_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                "sctp" => Protocol::Sctp,
                "dccp" => Protocol::Dccp,
                _ => continue,
            };

            entries.insert((port, protocol), service_name.to_string());
        }

        Ok(Services { entries })
    }

    /// Look up a service name by port and protocol
    pub fn lookup(&self, port: u16, protocol: Protocol) -> Option<&str> {
        self.entries.get(&(port, protocol)).map(|s| s.as_str())
    }

    /// Look up a service name, trying TCP first, then UDP
    pub fn lookup_any(&self, port: u16, prefer_udp: bool) -> Option<&str> {
        if prefer_udp {
            self.lookup(port, Protocol::Udp)
                .or_else(|| self.lookup(port, Protocol::Tcp))
        } else {
            self.lookup(port, Protocol::Tcp)
                .or_else(|| self.lookup(port, Protocol::Udp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_well_known_services() {
        let services = Services::default();
        // These should exist on most systems
        assert_eq!(services.lookup(80, Protocol::Tcp), Some("http"));
        assert_eq!(services.lookup(443, Protocol::Tcp), Some("https"));
        assert_eq!(services.lookup(22, Protocol::Tcp), Some("ssh"));
        assert_eq!(services.lookup(53, Protocol::Udp), Some("domain"));
    }
}
