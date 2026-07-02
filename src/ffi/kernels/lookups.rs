//! Entry-point preflight kernels: everything a lookup export decides before
//! (or instead of) touching the network, as pure verdict-returning functions.
//! Kernels never invoke C callbacks and never hold RefCell borrows at return
//! — the shim matches on the verdict, marshals, and dispatches.

use std::ffi::c_int;
use std::net::IpAddr;
use std::time::Instant;

use crate::core::hostfile::{AddressFamily, HostLookup};
use crate::core::lookup::{is_localhost, is_onion_domain, HostByNameSm, SearchPlan};
use crate::core::packets::AddrRecord;
use crate::core::response::{ParsedRRs, ParsedResponse};
use crate::core::sortlist::apply_sortlist;
use crate::ffi::channel::ChannelData;
use crate::ffi::error::{
    ARES_EBADNAME, ARES_EFILE, ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP,
};
use crate::ffi::{RECORD_TYPE_A, RECORD_TYPE_AAAA};

/// The verdict of ares_gethostbyname's pre-DNS phase.
pub(crate) enum HostPreflight {
    /// Deliver `status` with a NULL hostent.
    Fail(c_int),
    /// Synchronous hit (IP literal / hosts file / localhost): deliver a
    /// hostent built from this lookup, then free it.
    DeliverHost(HostLookup),
    /// Query-cache hit: sortlist already applied; the c_int is the hostent
    /// address family to emit.
    DeliverParsed(ParsedRRs<AddrRecord>, c_int),
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
pub(crate) fn gethostbyname_preflight(
    channeldata: &mut ChannelData,
    hostname: &str,
    family: c_int,
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
    let hosts_result = channeldata.ares.hosts().lookup(hostname, family_filter);
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
    if channeldata.ares.config.nameservers.is_empty() {
        return HostPreflight::Fail(ARES_ENOSERVER);
    }

    // Check query cache
    if channeldata.query_cache_max_ttl > 0 {
        let record_type = match family {
            libc::AF_INET => RECORD_TYPE_A,
            libc::AF_INET6 => RECORD_TYPE_AAAA,
            libc::AF_UNSPEC => RECORD_TYPE_AAAA,
            _ => RECORD_TYPE_A,
        };
        let cache_key = (resolved_name.clone(), record_type);
        if let Some((cached_buf, expires_at)) = channeldata.query_cache.get(&cache_key) {
            if now < *expires_at {
                let cached_buf = cached_buf.clone();
                let parsed = (|| -> Result<ParsedRRs<AddrRecord>, c_int> {
                    let response = ParsedResponse::from_buf(&cached_buf)?;
                    let parsed_rrs = response.process_answers::<AddrRecord>(&cached_buf, record_type)?;
                    if parsed_rrs.items.is_empty() {
                        return Err(ARES_ENODATA);
                    }
                    Ok(parsed_rrs)
                })();
                // On a cache-hit parse error, fall through to a fresh DNS query.
                if let Ok(mut parsed_rrs) = parsed {
                    if !channeldata.sortlist.is_empty() {
                        apply_sortlist(&channeldata.sortlist, &mut parsed_rrs.items);
                    }
                    let current_family = match family {
                        libc::AF_INET => libc::AF_INET,
                        libc::AF_INET6 => libc::AF_INET6,
                        _ => libc::AF_INET6,
                    };
                    return HostPreflight::DeliverParsed(parsed_rrs, current_family);
                }
            } else {
                channeldata.query_cache.remove(&cache_key);
            }
        }
    }

    // Build the search plan + state machine; the shim launches the first query.
    let use_tcp = channeldata.ares.config.options.use_vc;
    let plan = SearchPlan::for_gethostbyname(
        &resolved_name,
        channeldata.ares.config.options.ndots,
        &channeldata.ares.config.search,
    );
    let query_hostname = plan.current.clone();
    let sm = HostByNameSm::new(plan, family, use_tcp);
    let first_server = channeldata.server_health.pick_next();
    HostPreflight::StartDns { sm, query_hostname, first_server, use_tcp }
}

/// The pure body of ares_gethostbyname_file: hosts-file-only lookup.
pub(crate) fn hosts_file_lookup(
    channeldata: &mut ChannelData,
    name: &str,
    family: c_int,
) -> Result<HostLookup, c_int> {
    // Convert C family constant to our Family enum
    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => return Err(ARES_ENOTFOUND),
    };

    // Lookup in the hosts file cache
    let Some(lookup) = channeldata.ares.hosts().lookup(name, family_filter) else {
        return Err(ARES_ENOTFOUND);
    };
    if lookup.addrs.is_empty() {
        return Err(ARES_ENOTFOUND);
    }
    Ok(lookup)
}
