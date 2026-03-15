use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SysConfig {
    pub nameservers: Vec<(IpAddr, Option<u16>)>, // (ip, udp_port_override)
    pub tcp_ports: Vec<Option<u16>>, // per-server TCP port overrides
    pub domain: Option<String>,
    pub search: Vec<String>,
    pub options: SysConfigOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysConfigOptions {
    pub ndots: u32,
    pub attempts: u32,
    pub timeout_ms: u32,
    pub use_vc: bool,
    pub rotate: bool,
    pub inet6: bool,
    pub edns0: bool,
}

impl Default for SysConfigOptions {
    fn default() -> Self {
        SysConfigOptions { ndots: 1, attempts: 4, timeout_ms: 5000, use_vc: false, rotate: false, inet6: false, edns0: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MissingValue { keyword: String },
    InvalidNumber { keyword: String, value: String },
}

impl FromStr for SysConfig {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut conf = SysConfig::default();

        for raw_line in s.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() { continue; }

            let mut parts = line.split_whitespace();
            let keyword = parts.next().unwrap();
            let rest = parts.collect::<Vec<_>>();
            let [arg1, ..] = rest[..] else { return Err(ParseError::MissingValue { keyword: keyword.into() })  };

            match keyword {
                "nameserver" => {
                    for tok in rest {
                        conf.nameservers.push(parse_ns_addr(tok).unwrap());
                        conf.tcp_ports.push(None);
                    }
                }
                "domain" => conf.domain = Some(arg1.to_string()),
                "search" => conf.search.extend(rest.iter().map(|s| s.to_string())),
                "options" => parse_options_into(&mut conf.options, &rest.join(" "))?,
                _ => continue,
            }
        }

        Ok(conf)
    }
}

fn strip_comment(line: &str) -> &str {
    let idx = line.find(|c| ";#".contains(c)).unwrap_or(line.len());
    line[..idx].trim()
}

fn parse_options_into(opts: &mut SysConfigOptions, src: &str) -> Result<(), ParseError> {
    for token in src.split_whitespace() {
        let (key, val) = token.split_once(['=', ':']).unwrap_or((token, ""));

        match key {
            "ndots" => opts.ndots = take_num_arg(key, val)?,
            "attempts" => opts.attempts = take_num_arg(key, val)?,
            "timeout" | "retrans" => opts.timeout_ms = take_num_arg::<u32>(key, val)? * 1000,
            "use-vc" | "usevc" => opts.use_vc = true,
            "rotate" => opts.rotate = true,
            "inet6" => opts.inet6 = true,
            "edns0" => opts.edns0 = true,
            _ => {},
        }
    }
    Ok(())
}

fn take_num_arg<T: FromStr>(keyword: &str, val: &str) -> Result<T, ParseError> {
    match val {
        "" => Err(ParseError::MissingValue { keyword: keyword.into() }),
        _ => val.parse().map_err(|_| ParseError::InvalidNumber { keyword: keyword.into(), value: val.into() }),
    }
    
}

pub fn parse_ns_addr(s: &str) -> Option<(IpAddr, Option<u16>)> {
    if let Ok(sa) = SocketAddr::from_str(s) {
        return Some((sa.ip(), Some(sa.port())));
    }

    if let Ok(ip) = IpAddr::from_str(s) {
        return Some((ip, None))
    }

    // Handle bracketed IPv6 without port, e.g. "[::1]"
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len()-1];
        if let Ok(ip) = IpAddr::from_str(inner) {
            return Some((ip, None));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let input = "nameserver 1.1.1.1\n";
        let conf: SysConfig = input.parse().unwrap();
        assert_eq!(conf.nameservers.len(), 1);
        assert_eq!(conf.domain, None);
        assert!(conf.search.is_empty());
        assert_eq!(conf.options.timeout_ms, 5000);
        assert_eq!(conf.options.attempts, 4);
    }

    #[test]
    fn parse_multiple_nameservers_and_search() {
        let input = r#"
            # Sample resolv.conf
            nameserver 1.1.1.1 8.8.8.8
            nameserver 2001:4860:4860::8888 ; inline comment
            domain example.com
            search corp.local example.org
            options ndots:2 attempts:4 timeout:3 rotate use-vc
        "#;
        let conf: SysConfig = input.parse().unwrap();
        assert_eq!(conf.nameservers.len(), 3);
        assert_eq!(conf.search, vec!["corp.local", "example.org"]);
        assert_eq!(conf.options.ndots, 2);
        assert_eq!(conf.options.attempts, 4);
        assert_eq!(conf.options.timeout_ms, 3000);
        assert!(conf.options.rotate);
        assert!(conf.options.use_vc);
    }

    #[test]
    fn parse_options_variants() {
        let input = "options retrans=7 edns0 foo=bar baz:9 qux";
        let conf: SysConfig = input.parse().unwrap();
        assert_eq!(conf.options.timeout_ms, 7000);
        assert!(conf.options.edns0);
    }

    #[test]
    fn missing_value_errors() {
        let input = "domain\nsearch\noptions ndots";
        let err = input.parse::<SysConfig>().unwrap_err();
        match err {
            ParseError::MissingValue { .. } => {},
            _ => panic!("unexpected error: {:?}", err),
        }
    }
}
