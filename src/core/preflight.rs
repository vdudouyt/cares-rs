//! Entry-point preflight logic: everything a lookup export decides before
//! (or instead of) touching the network, as pure verdict-returning functions consumed by core::api.
//! Nothing here invokes C callbacks or holds a RefCell borrow at return
//! — the shim matches on the verdict, marshals, and dispatches.

use std::net::IpAddr;
use std::time::Instant;

use std::ffi::CString;

use crate::core::hostfile::{AddressFamily, HostLookup};
use crate::core::services::Services;
use crate::core::lookup::{is_onion_domain, SearchPlan, SearchSm};
use crate::core::response::ParsedResponse;
use crate::core::channel::ChannelState;
use crate::ffi::error::{ARES_EBADSTR, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_SUCCESS};
use crate::ffi::{
    ARES_NI_DGRAM, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NOFQDN, ARES_NI_NUMERICSCOPE,
    ARES_NI_NUMERICSERV, RECORD_TYPE_PTR,
};

/// Everything getnameinfo's PTR delivery needs, assembled per the NI flag
/// semantics: NOFQDN truncation, the ENOTFOUND+!NAMEREQD numeric fallback,
/// and the LOOKUPSERVICE gate. Error deliveries carry zero timeouts (as
/// historically); success carries the task's accumulated count.
pub(crate) struct NameinfoReply {
    pub status: i32,
    pub node: Option<CString>,
    pub service: Option<CString>,
    pub timeouts: i32,
}

pub(crate) fn assemble_nameinfo(
    res: Result<&[u8], i32>,
    ip: IpAddr,
    scope_id: u32,
    port: u16,
    flags: i32,
    io_timeouts: i32,
) -> NameinfoReply {
    let services = Services::default();
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    let hostname_result = (|| -> Result<CString, i32> {
        let buf = res?;
        let parsed = ParsedResponse::from_buf(buf)?;
        let ptr_records = parsed.process_answers::<CString>(buf, RECORD_TYPE_PTR)?;

        if ptr_records.aliases.is_empty() {
            return Err(ARES_ENOTFOUND);
        }

        let mut name = ptr_records.name;

        if flags & ARES_NI_NOFQDN != 0 {
            let name_str = name.to_string_lossy();
            if let Some(dot_pos) = name_str.find('.') {
                name = CString::new(&name_str[..dot_pos]).map_err(|_| ARES_EBADSTR)?;
            }
        }

        Ok(name)
    })();

    let (status, node) = match hostname_result {
        Ok(name) => (ARES_SUCCESS, Some(name)),
        Err(err) => {
            if err == ARES_ENOTFOUND && (flags & ARES_NI_NAMEREQD) == 0 {
                let ip_str = format_ip_with_scope(&ip, scope_id, flags);
                match CString::new(ip_str) {
                    Ok(name) => (ARES_SUCCESS, Some(name)),
                    Err(_) => return NameinfoReply { status: ARES_EBADSTR, node: None, service: None, timeouts: 0 },
                }
            } else {
                return NameinfoReply { status: err, node: None, service: None, timeouts: 0 };
            }
        }
    };

    let service = if want_service {
        get_service_string(&services, port, flags)
    } else {
        None
    };

    NameinfoReply { status, node, service, timeouts: io_timeouts }
}

/// How a getaddrinfo service string resolves to a port.
pub(crate) enum ServicePort {
    Port(u16),
    /// Not numeric and not in the well-known table: the shim asks the system
    /// resolver (getservbyname — inherently a C call), defaulting to 0.
    NeedSystemLookup,
}

/// Service→port resolution order: numeric, then the built-in well-known
/// table, then the system services database.
pub(crate) fn service_to_port(svc: &str) -> ServicePort {
    if let Ok(p) = svc.parse::<u16>() {
        return ServicePort::Port(p);
    }
    if let Some(p) = well_known_port(svc) {
        return ServicePort::Port(p);
    }
    ServicePort::NeedSystemLookup
}

/// A decoded socket address (the pure result of the shim-side sockaddr
/// unmarshal): what getnameinfo works from.
pub(crate) struct AddrInfo {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) family: i32,
    pub(crate) scope_id: u32,
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
