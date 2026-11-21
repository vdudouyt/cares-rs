use crate::mem::{ByteBuf, HashMap, String};
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    Dccp,
}

#[derive(Debug)]
pub struct Services {
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
        let mut file = std::fs::File::open(path)?;
        let mut bytes = ByteBuf::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = file.read(&mut chunk)?;
            if n == 0 { break; }
            bytes.extend_from_slice(&chunk[..n]);
        }
        let content = std::str::from_utf8(&bytes).map_err(|_| std::io::ErrorKind::InvalidData)?;
        let mut entries = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let line = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            };

            // Format: service_name port/protocol [aliases...]
            let mut parts = line.split_whitespace();
            let Some(service_name) = parts.next() else {
                continue;
            };
            let Some(port_proto) = parts.next() else {
                continue;
            };

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

            let protocol = if proto_str.eq_ignore_ascii_case("tcp") {
                Protocol::Tcp
            } else if proto_str.eq_ignore_ascii_case("udp") {
                Protocol::Udp
            } else if proto_str.eq_ignore_ascii_case("sctp") {
                Protocol::Sctp
            } else if proto_str.eq_ignore_ascii_case("dccp") {
                Protocol::Dccp
            } else {
                continue;
            };

            entries.insert((port, protocol), String::from(service_name));
        }

        Ok(Services { entries })
    }

    pub fn lookup(&self, port: u16, protocol: Protocol) -> Option<&str> {
        self.entries.get(&(port, protocol)).map(|s| s.as_str())
    }

    /// Look up a service name, preferring UDP or TCP as requested.
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
