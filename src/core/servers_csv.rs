use std::io::Read;
use std::net::IpAddr;
use crate::core::sysconfig::parse_ns_addr;

/// Parse from any `Read` (e.g., `Cursor<&[u8]>`).
/// Accepts CSV and/or newline separators.
/// Rules (std-only):
/// - `IP`           => port defaults to 53
/// - `IP:port`      => OK for IPv4
/// - `[IPv6]:port`  => OK for IPv6 with port
/// - `IPv6`         => OK (no port) -> defaults to 53
pub fn parse_from_reader<R: Read>(mut r: R) -> Option<Vec<(IpAddr, Option<u16>)>> {
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).ok()?;
    let s = String::from_utf8(buf).ok()?;
    parse_servers_str(&s)
}

pub fn parse_servers_str(s: &str) -> Option<Vec<(IpAddr, Option<u16>)>> {
    let mut out = Vec::new();

    for item in s.split([',', '\n']).filter(|t| !t.is_empty()) {
        out.push(parse_ns_addr(item.trim())?);
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::IpAddr;

    fn addr(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn test_ipv4_and_default_port() {
        let input = Cursor::new("8.8.8.8:5353,1.1.1.1".as_bytes());
        let out = parse_from_reader(input).unwrap();
        assert_eq!(out, vec![
            (addr("8.8.8.8"), Some(5353)),
            (addr("1.1.1.1"), None),
        ]);
    }

    #[test]
    fn test_ipv6_bare_defaults_to_53() {
        let input = Cursor::new("2001:db8::dead:beef".as_bytes());
        let out = parse_from_reader(input).unwrap();
        assert_eq!(out, vec![(addr("2001:db8::dead:beef"), None)]);
    }

    #[test]
    fn test_ipv6_bracketed_with_port() {
        let input = Cursor::new("[2001:db8::dead:beef]:5300".as_bytes());
        let out = parse_from_reader(input).unwrap();
        assert_eq!(out, vec![(addr("2001:db8::dead:beef"), Some(5300))]);
    }

    #[test]
    fn test_mixed_separators() {
        let input = Cursor::new("8.8.4.4:53,\n[::1]:5353\n2001:4860:4860::8888".as_bytes());
        let out = parse_from_reader(input).unwrap();
        assert_eq!(out, vec![
            (addr("8.8.4.4"), Some(53)),
            (addr("::1"), Some(5353)),
            (addr("2001:4860:4860::8888"), None),
        ]);
    }

    #[test]
    fn test_ignores_empty_tokens() {
        let input = Cursor::new(",, 8.8.8.8 ,, [::1]:5353 ,".as_bytes());
        let out = parse_from_reader(input).unwrap();
        assert_eq!(out, vec![
            (addr("8.8.8.8"), None),
            (addr("::1"), Some(5353)),
        ]);
    }

    #[test]
    fn test_ipv4_with_and_without_port() {
        let input = Cursor::new("8.8.8.8:5353,1.1.1.1".as_bytes());
        let out = parse_from_reader(input).unwrap();
        assert_eq!(out, vec![
            (addr("8.8.8.8"), Some(5353)),
            (addr("1.1.1.1"), None)
        ]);
    }

    #[test]
    fn test_mixed_separators_and_whitespace() {
        let input = Cursor::new(
            "8.8.4.4:53,\n 9.9.9.9  , [::1]:5353 \n 2001:4860:4860::8888".as_bytes(),
        );
        let out = parse_from_reader(input).unwrap();
        assert_eq!(
            out,
            vec![
                (addr("8.8.4.4"), Some(53)),
                (addr("9.9.9.9"), None),
                (addr("::1"), Some(5353)),
                (addr("2001:4860:4860::8888"), None),
            ]
        );
    }
}
