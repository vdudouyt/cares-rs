use std::io::Read;
use std::net::IpAddr;

use crate::core::sysconfig::parse_ns_addr;
use crate::mem::{ByteBuf, String, Vec};

/// One parsed CSV server entry. `iface` is the optional `%<interface>` scope
/// specifier for a link-local IPv6 address (c-ares resolves it to a scope id
/// through the channel's `aif_nametoindex` adapter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServer {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub iface: Option<String>,
}

fn read_text(r: &mut impl Read) -> Option<String> {
    let mut bytes = ByteBuf::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = r.read(&mut chunk).ok()?;
        if n == 0 { break; }
        bytes.extend_from_slice(&chunk[..n]);
    }
    std::str::from_utf8(&bytes).ok().map(String::from)
}

/// Parse a comma/newline/space-separated server list; `[IPv6]:port` and bare
/// addresses are accepted, and a missing port defaults to 53.
// Kept for callers that do not need scopes; the ffi CSV path uses the
// scope-aware variant below.
#[allow(dead_code)]
pub fn parse_from_reader<R: Read>(mut r: R) -> Option<Vec<(IpAddr, Option<u16>)>> {
    let s = read_text(&mut r)?;
    parse_servers_str(&s)
}

#[allow(dead_code)]
pub fn parse_servers_str(s: &str) -> Option<Vec<(IpAddr, Option<u16>)>> {
    let mut out = Vec::new();

    // c-ares also accepts space-separated entries.
    for item in s.split([',', '\n', ' ']).map(|t| t.trim()).filter(|t| !t.is_empty()) {
        // Skip link-local entries with a % interface specifier.
        if item.contains('%') {
            continue;
        }
        out.push(parse_ns_addr(item)?);
    }

    Some(out)
}

/// Scope-aware variant of [`parse_from_reader`]: preserves `%<interface>`
/// suffixes instead of skipping those entries.
pub fn parse_from_reader_scoped<R: Read>(mut r: R) -> Option<Vec<ParsedServer>> {
    let s = read_text(&mut r)?;
    parse_servers_scoped_str(&s)
}

/// Scope-aware variant of [`parse_servers_str`]. Accepts `ip[:port][%iface]`,
/// `[ipv6]:port%iface` and the natural `[ipv6%iface]:port` spelling.
pub fn parse_servers_scoped_str(s: &str) -> Option<Vec<ParsedServer>> {
    let mut out = Vec::new();

    for item in s.split([',', '\n', ' ']).map(|t| t.trim()).filter(|t| !t.is_empty()) {
        out.push(parse_scoped_server(item)?);
    }

    Some(out)
}

/// Split a `%<iface>` suffix off one entry, returning the address/port text
/// and the interface name. `[fe80::1%lo]:5353` keeps the scope inside the
/// brackets while `[fe80::1]:5353%lo` and `fe80::1%lo` carry it at the end.
fn parse_scoped_server(item: &str) -> Option<ParsedServer> {
    let (addr_text, iface) = match item.find('%') {
        None => (String::from(item), None),
        Some(pct) => {
            if let Some(close) = item.find(']') {
                if item.starts_with('[') && pct < close {
                    let iface = &item[pct + 1..close];
                    // Rebuild "[ip]" plus anything after the closing bracket.
                    let mut addr_text = String::from("[");
                    addr_text.push_str(&item[1..pct]);
                    addr_text.push_str("]");
                    addr_text.push_str(&item[close + 1..]);
                    (addr_text, Some(String::from(iface)))
                } else {
                    (String::from(&item[..pct]), Some(String::from(&item[pct + 1..])))
                }
            } else {
                (String::from(&item[..pct]), Some(String::from(&item[pct + 1..])))
            }
        }
    };
    if iface.as_deref().is_some_and(str::is_empty) {
        return None;
    }

    let (ip, port) = parse_ns_addr(&addr_text)?;
    Some(ParsedServer { ip, port, iface })
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
