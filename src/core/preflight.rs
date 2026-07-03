//! Entry-point preflight logic: everything a lookup export decides before
//! (or instead of) touching the network, as pure verdict-returning functions (moved from ffi/kernels).
//! Kernels never invoke C callbacks and never hold RefCell borrows at return
//! — the shim matches on the verdict, marshals, and dispatches.

use std::net::IpAddr;
use std::time::Instant;

use std::ffi::CString;

use crate::core::hostfile::{AddressFamily, HostLookup};
use crate::core::services::Services;
use crate::core::lookup::{is_localhost, is_onion_domain, AddrInfoSm, HostByNameSm, SearchPlan, SearchSm};
use crate::core::packets::{buf_to_ip, AddrRecord};
use crate::core::response::{ParsedRRs, ParsedResponse};
use crate::core::sortlist::apply_sortlist;
use crate::core::channel::ChannelState;
use crate::ffi::error::{
    ARES_EBADNAME, ARES_EFILE, ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP,
};
use crate::ffi::error::ARES_EBADFLAGS;
use crate::ffi::{
    ARES_NI_DGRAM, ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD,
    ARES_NI_NUMERICHOST, ARES_NI_NUMERICSCOPE, ARES_NI_NUMERICSERV, RECORD_TYPE_A,
    RECORD_TYPE_AAAA,
};

/// A decoded socket address (the pure result of the shim-side sockaddr
/// unmarshal): what getnameinfo works from.
pub(crate) struct AddrInfo {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) family: i32,
    pub(crate) scope_id: u32,
}

/// The verdict of ares_gethostbyname's pre-DNS phase.
pub(crate) enum HostPreflight {
    /// Deliver `status` with a NULL hostent.
    Fail(i32),
    /// Synchronous hit (IP literal / hosts file / localhost): deliver a
    /// hostent built from this lookup, then free it.
    DeliverHost(HostLookup),
    /// Query-cache hit: sortlist already applied; the i32 is the hostent
    /// address family to emit.
    DeliverParsed(ParsedRRs<AddrRecord>, i32),
    /// No short-circuit applies — seed the state machine and go to DNS.
    StartDns {
        sm: HostByNameSm,
        query_hostname: String,
        first_server: usize,
        use_tcp: bool,
    },
}

/// Check order is behavior (each stage may deliver before the next runs):
/// ascii -> onion -> family-validate -> IP literal -> hosts file ->
/// localhost -> HOSTALIASES (fs read; PermissionDenied => Fail(EFILE)) ->
/// no-servers -> query cache (evict expired; parse; sortlist; a cache-hit
/// parse error falls through to DNS) -> StartDns.
pub(crate) fn gethostbyname_preflight<T>(
    st: &mut ChannelState<T>,
    hostname: &str,
    family: i32,
    now: Instant,
) -> HostPreflight {
    // Reject non-ASCII names
    if !hostname.is_ascii() {
        return HostPreflight::Fail(ARES_EBADNAME);
    }

    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(hostname) {
        return HostPreflight::Fail(ARES_ENOTFOUND);
    }

    // Family validation; the A/AAAA mapping itself lives in HostByNameSm::new.
    match family {
        libc::AF_INET | libc::AF_INET6 | libc::AF_UNSPEC => {}
        _ => return HostPreflight::Fail(ARES_ENOTIMP),
    }

    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => AddressFamily::Any,
    };

    // Check IP literal first
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let matches = match family_filter {
            AddressFamily::Ipv4 => ip.is_ipv4(),
            AddressFamily::Ipv6 => ip.is_ipv6(),
            AddressFamily::Any => true,
        };
        if matches {
            return HostPreflight::DeliverHost(HostLookup {
                canonical: hostname.to_string(),
                aliases: vec![],
                addrs: vec![ip],
            });
        }
    }

    // Check hosts file
    let hosts_result = st.ares.hosts().lookup(hostname, family_filter);
    if let Some(ref lookup) = hosts_result {
        if !lookup.addrs.is_empty() {
            return HostPreflight::DeliverHost(lookup.clone());
        }
    }

    // RFC 6761 section 6.3: recognize "localhost" and any name under ".localhost"
    // as special and always return the loopback address.
    if is_localhost(hostname) {
        let addrs = match family_filter {
            AddressFamily::Ipv4 => vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            AddressFamily::Ipv6 => vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
            AddressFamily::Any => vec![
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            ],
        };
        return HostPreflight::DeliverHost(HostLookup {
            canonical: hostname.to_string(),
            aliases: vec![],
            addrs,
        });
    }

    // Check HOSTALIASES env var for single-label names
    let hostname_str = hostname.to_string();
    let resolved_name = if !hostname.contains('.') {
        if let Ok(aliases_path) = std::env::var("HOSTALIASES") {
            match std::fs::read_to_string(&aliases_path) {
                Ok(content) => {
                    let mut alias_found = None;
                    for line in content.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(hostname) {
                            alias_found = Some(parts[1].to_string());
                            break;
                        }
                    }
                    alias_found.unwrap_or_else(|| hostname_str.clone())
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return HostPreflight::Fail(ARES_EFILE);
                }
                Err(_) => hostname_str.clone(),
            }
        } else {
            hostname_str.clone()
        }
    } else {
        hostname_str.clone()
    };

    // No servers configured — return ENOSERVER immediately
    if st.ares.config.nameservers.is_empty() {
        return HostPreflight::Fail(ARES_ENOSERVER);
    }

    // Check query cache
    if st.query_cache_max_ttl > 0 {
        let record_type = match family {
            libc::AF_INET => RECORD_TYPE_A,
            libc::AF_INET6 => RECORD_TYPE_AAAA,
            libc::AF_UNSPEC => RECORD_TYPE_AAAA,
            _ => RECORD_TYPE_A,
        };
        let cache_key = (resolved_name.clone(), record_type);
        if let Some((cached_buf, expires_at)) = st.query_cache.get(&cache_key) {
            if now < *expires_at {
                let cached_buf = cached_buf.clone();
                let parsed = (|| -> Result<ParsedRRs<AddrRecord>, i32> {
                    let response = ParsedResponse::from_buf(&cached_buf)?;
                    let parsed_rrs = response.process_answers::<AddrRecord>(&cached_buf, record_type)?;
                    if parsed_rrs.items.is_empty() {
                        return Err(ARES_ENODATA);
                    }
                    Ok(parsed_rrs)
                })();
                // On a cache-hit parse error, fall through to a fresh DNS query.
                if let Ok(mut parsed_rrs) = parsed {
                    if !st.sortlist.is_empty() {
                        apply_sortlist(&st.sortlist, &mut parsed_rrs.items);
                    }
                    let current_family = match family {
                        libc::AF_INET => libc::AF_INET,
                        libc::AF_INET6 => libc::AF_INET6,
                        _ => libc::AF_INET6,
                    };
                    return HostPreflight::DeliverParsed(parsed_rrs, current_family);
                }
            } else {
                st.query_cache.remove(&cache_key);
            }
        }
    }

    // Build the search plan + state machine; the shim launches the first query.
    let use_tcp = st.ares.config.options.use_vc;
    let plan = SearchPlan::for_gethostbyname(
        &resolved_name,
        st.ares.config.options.ndots,
        &st.ares.config.search,
    );
    let query_hostname = plan.current.clone();
    let sm = HostByNameSm::new(plan, family, use_tcp);
    let first_server = st.server_health.pick_next();
    HostPreflight::StartDns { sm, query_hostname, first_server, use_tcp }
}

/// The pure body of ares_gethostbyname_file: hosts-file-only lookup.
pub(crate) fn hosts_file_lookup<T>(
    st: &mut ChannelState<T>,
    name: &str,
    family: i32,
) -> Result<HostLookup, i32> {
    // Convert C family constant to our Family enum
    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => return Err(ARES_ENOTFOUND),
    };

    // Lookup in the hosts file cache
    let Some(lookup) = st.ares.hosts().lookup(name, family_filter) else {
        return Err(ARES_ENOTFOUND);
    };
    if lookup.addrs.is_empty() {
        return Err(ARES_ENOTFOUND);
    }
    Ok(lookup)
}

/// The verdict of ares_getaddrinfo's pre-DNS phase.
pub(crate) enum AddrInfoPreflight {
    /// Deliver `status` with a NULL result.
    Fail(i32),
    /// IP-literal or hosts-file hit: the shim builds family-filtered nodes
    /// from these addresses under `canonical` and delivers ARES_SUCCESS.
    DeliverAddrs { addrs: Vec<IpAddr>, canonical: String },
    /// No short-circuit applies — the shim begins the parallel A+AAAA batch.
    StartDns { sm: AddrInfoSm, first_server: usize },
}

/// The well-known service table ares_getaddrinfo consults before falling
/// back to libc::getservbyname (which stays in the shim).
pub(crate) fn well_known_port(svc: &str) -> Option<u16> {
    Some(match svc {
        "http" => 80,
        "https" => 443,
        "ftp" => 21,
        "ssh" => 22,
        "smtp" => 25,
        "dns" => 53,
        "pop3" => 110,
        "imap" => 143,
        _ => return None,
    })
}

/// Check order is behavior: empty-name -> onion -> IP literal (family
/// mismatch fails, no fall-through) -> hosts file -> no-servers -> StartDns.
/// The raw name keeps its trailing dot for the SearchPlan; checks and the
/// delivered canonical name use the stripped form.
pub(crate) fn getaddrinfo_preflight<T>(
    st: &mut ChannelState<T>,
    hostname_raw: &str,
    ai_family: i32,
) -> AddrInfoPreflight {
    let hostname = hostname_raw.strip_suffix('.').unwrap_or(hostname_raw);

    if hostname.is_empty() {
        return AddrInfoPreflight::Fail(ARES_ENOTFOUND);
    }

    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(hostname) {
        return AddrInfoPreflight::Fail(ARES_ENOTFOUND);
    }

    // IP literal check
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let matches = match ai_family {
            libc::AF_INET => ip.is_ipv4(),
            libc::AF_INET6 => ip.is_ipv6(),
            libc::AF_UNSPEC => true,
            _ => false,
        };
        if matches {
            return AddrInfoPreflight::DeliverAddrs {
                addrs: vec![ip],
                canonical: hostname.to_string(),
            };
        } else {
            return AddrInfoPreflight::Fail(ARES_ENOTFOUND);
        }
    }

    // Hosts file check
    let family_filter = match ai_family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        _ => AddressFamily::Any,
    };
    if let Some(lookup) = st.ares.hosts().lookup(hostname, family_filter) {
        if !lookup.addrs.is_empty() {
            return AddrInfoPreflight::DeliverAddrs {
                addrs: lookup.addrs,
                canonical: hostname.to_string(),
            };
        }
    }

    // No servers configured
    if st.ares.config.nameservers.is_empty() {
        return AddrInfoPreflight::Fail(ARES_ENOSERVER);
    }

    // DNS path: build the search plan + state machine
    // (the raw name carries the trailing dot the plan needs to see)
    let use_tcp = st.ares.config.options.use_vc;
    let plan = SearchPlan::for_search(
        hostname_raw,
        st.ares.config.options.ndots,
        &st.ares.config.search,
    );
    let first_server = st.server_health.pick_next();
    AddrInfoPreflight::StartDns {
        sm: AddrInfoSm::new(plan, ai_family, use_tcp),
        first_server,
    }
}

/// The verdict of ares_getnameinfo's pre-DNS phase.
pub(crate) enum NameinfoPreflight {
    /// Deliver `status` with NULL node and service.
    Fail(i32),
    /// Service-only lookup: deliver (NULL node, service).
    DeliverService(Option<CString>),
    /// Numeric-host path: deliver both without DNS.
    DeliverNumeric { node: CString, service: Option<CString> },
    /// PTR lookup required; `flags` carries the defaulted flag set.
    StartPtr { flags: i32 },
}

/// Flag defaulting and the service-only / numeric-host short-circuits.
pub(crate) fn getnameinfo_preflight<T>(
    st: &mut ChannelState<T>,
    addr: &AddrInfo,
    flags: i32,
) -> NameinfoPreflight {
    // Adjust flags: if neither LOOKUPSERVICE nor LOOKUPHOST, default to LOOKUPHOST
    let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
        flags | ARES_NI_LOOKUPHOST
    } else {
        flags
    };

    let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    // If only service lookup requested (no host), deliver immediately
    if want_service && !want_host {
        return NameinfoPreflight::DeliverService(get_service_string(
            st.ares.services(),
            addr.port,
            flags,
        ));
    }

    // Host lookup requested (guaranteed by the defaulting above).
    // Numeric host can be handled without DNS
    if (flags & ARES_NI_NUMERICHOST) != 0 {
        // ARES_NI_NUMERICHOST + ARES_NI_NAMEREQD is illegal (contradiction)
        if (flags & ARES_NI_NAMEREQD) != 0 {
            return NameinfoPreflight::Fail(ARES_EBADFLAGS);
        }
        let node = CString::new(format_ip_with_scope(&addr.ip, addr.scope_id, flags)).unwrap();
        let service = if want_service {
            get_service_string(st.ares.services(), addr.port, flags)
        } else {
            None
        };
        return NameinfoPreflight::DeliverNumeric { node, service };
    }

    NameinfoPreflight::StartPtr { flags }
}

/// Format an IP address with scope ID for IPv6 (e.g., "fe80::1%0")
pub(crate) fn format_ip_with_scope(ip: &IpAddr, scope_id: u32, flags: i32) -> String {
    match ip {
        // The scope id is currently appended regardless of the flag/scope_id
        // check; the branches are intentionally identical for now.
        #[allow(clippy::if_same_then_else)]
        IpAddr::V6(_) => {
            if flags & ARES_NI_NUMERICSCOPE != 0 || scope_id != 0 {
                format!("{}%{}", ip, scope_id)
            } else {
                format!("{}%{}", ip, scope_id)
            }
        }
        IpAddr::V4(_) => ip.to_string(),
    }
}

/// Get the service string based on flags
pub(crate) fn get_service_string(services: &Services, port: u16, flags: i32) -> Option<CString> {
    if port == 0 {
        return None;
    }

    if flags & ARES_NI_NUMERICSERV != 0 {
        // Return numeric port
        return Some(CString::new(port.to_string()).unwrap());
    }

    // Determine protocol preference based on flags
    let prefer_udp = (flags & ARES_NI_DGRAM) != 0;

    // Try to look up the service name
    if let Some(name) = services.lookup_any(port, prefer_udp) {
        Some(CString::new(name).unwrap())
    } else {
        // Fall back to numeric port
        Some(CString::new(port.to_string()).unwrap())
    }
}

/// Empty/onion rejection shared by ares_search and ares_search_dnsrec —
/// checked before the channel is even dereferenced (order is behavior:
/// these fire even on a NULL channel).
pub(crate) fn search_name_check(name_str: &str) -> Option<i32> {
    if name_str.is_empty() {
        return Some(ARES_ENOTFOUND);
    }
    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(name_str) {
        return Some(ARES_ENOTFOUND);
    }
    None
}

/// Seed a search-domain iteration (ares_search / ares_search_dnsrec):
/// no-servers guard, then the SearchPlan + machine.
pub(crate) fn search_start<T>(
    st: &mut ChannelState<T>,
    name_str: &str,
    retry_server_error: bool,
) -> Result<(SearchSm, String), i32> {
    if st.ares.config.nameservers.is_empty() {
        return Err(ARES_ENOSERVER);
    }
    let plan = SearchPlan::for_search(
        name_str,
        st.ares.config.options.ndots,
        &st.ares.config.search,
    );
    let query_hostname = plan.current.clone();
    Ok((SearchSm::new(plan, retry_server_error), query_hostname))
}

/// ENOSERVER guard shared by ares_query / ares_query_dnsrec / ares_send.
pub(crate) fn no_servers<T>(st: &ChannelState<T>) -> bool {
    st.ares.config.nameservers.is_empty()
}

/// The ares_query_dnsrec cache probe: a fresh cached reply for
/// (name, qtype), evicting an expired entry on the way.
pub(crate) fn cached_reply<T>(
    st: &mut ChannelState<T>,
    name_clean: &str,
    qtype: u16,
    now: Instant,
) -> Option<Vec<u8>> {
    if st.query_cache_max_ttl == 0 {
        return None;
    }
    let cache_key = (name_clean.to_string(), qtype);
    if let Some((cached_buf, expires_at)) = st.query_cache.get(&cache_key) {
        if now < *expires_at {
            return Some(cached_buf.clone());
        } else {
            st.query_cache.remove(&cache_key);
        }
    }
    None
}

/// The verdict of ares_gethostbyaddr's pre-DNS phase.
pub(crate) enum AddrPreflight {
    /// Deliver `status` with a NULL hostent.
    Fail(i32),
    /// Hosts-file reverse hit: deliver a hostent from this lookup, then free.
    DeliverHost(HostLookup),
    /// Issue the PTR query for this address.
    StartPtr(IpAddr),
}

/// family-validate -> buf_to_ip -> hosts reverse lookup -> no-servers -> PTR.
pub(crate) fn gethostbyaddr_preflight<T>(
    st: &mut ChannelState<T>,
    addrbuf: &[u8],
    family: i32,
) -> AddrPreflight {
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return AddrPreflight::Fail(ARES_ENOTIMP);
    }
    let addr = match buf_to_ip(addrbuf) {
        Ok(ip) => ip,
        Err(_) => return AddrPreflight::Fail(ARES_ENOTIMP),
    };
    // Check hosts file first
    if let Some(lookup) = st.ares.hosts().reverse_lookup(addr) {
        return AddrPreflight::DeliverHost(lookup);
    }
    // No servers configured
    if st.ares.config.nameservers.is_empty() {
        return AddrPreflight::Fail(ARES_ENOSERVER);
    }
    AddrPreflight::StartPtr(addr)
}
