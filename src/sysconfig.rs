use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvConf {
    pub nameservers: Vec<IpAddr>,
    pub domain: Option<String>,
    pub search: Vec<String>,
    pub options: Options,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Options {
    pub ndots: u32,
    pub attempts: u32,
    pub timeout_secs: u64,
    pub use_vc: bool,
    pub rotate: bool,
    pub inet6: bool,
    pub edns0: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidIp(String),
    MissingValue { keyword: String },
    InvalidNumber { keyword: String, value: String },
}

impl FromStr for ResolvConf {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let options = Options { timeout_secs: 5, attempts: 4, ..Options::default() };
        let mut conf = ResolvConf { options, ..ResolvConf::default() };

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
                        let ip = tok.parse::<IpAddr>().map_err(|_| ParseError::InvalidIp(tok.into()))?;
                        conf.nameservers.push(ip);
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

fn parse_options_into(opts: &mut Options, src: &str) -> Result<(), ParseError> {
    for token in src.split_whitespace() {
        let (key, val) = token.split_once(['=', ':']).unwrap_or((token, ""));

        match key {
            "ndots" => opts.ndots = take_num_arg(key, val)?,
            "attempts" => opts.attempts = take_num_arg(key, val)?,
            "timeout" | "retrans" => opts.timeout_secs = take_num_arg(key, val)?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let input = "nameserver 1.1.1.1\n";
        let conf: ResolvConf = input.parse().unwrap();
        assert_eq!(conf.nameservers.len(), 1);
        assert_eq!(conf.domain, None);
        assert!(conf.search.is_empty());
        assert_eq!(conf.options.timeout_secs, 5);
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
        let conf: ResolvConf = input.parse().unwrap();
        assert_eq!(conf.nameservers.len(), 3);
        assert_eq!(conf.search, vec!["corp.local", "example.org"]);
        assert_eq!(conf.options.ndots, 2);
        assert_eq!(conf.options.attempts, 4);
        assert_eq!(conf.options.timeout_secs, 3);
        assert!(conf.options.rotate);
        assert!(conf.options.use_vc);
    }

    #[test]
    fn parse_options_variants() {
        let input = "options retrans=7 edns0 foo=bar baz:9 qux";
        let conf: ResolvConf = input.parse().unwrap();
        assert_eq!(conf.options.timeout_secs, 7);
        assert!(conf.options.edns0);
    }

    #[test]
    fn invalid_ip_errors() {
        let input = "nameserver not_an_ip";
        let err = input.parse::<ResolvConf>().unwrap_err();
        match err { ParseError::InvalidIp(_) => {}, _ => panic!("unexpected error: {:?}", err) }
    }

    #[test]
    fn missing_value_errors() {
        let input = "domain\nsearch\noptions ndots";
        let err = input.parse::<ResolvConf>().unwrap_err();
        match err {
            ParseError::MissingValue { .. } | ParseError::InvalidNumber { .. } => {},
            _ => panic!("unexpected error: {:?}", err),
        }
    }
}
