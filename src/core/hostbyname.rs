//! The self-contained async `ares_gethostbyname` lifecycle: the full pre-DNS
//! cascade (ASCII/onion/family/IP-literal/hosts/localhost/HOSTALIASES/no-servers/
//! query-cache) followed by the DNS phase (search-domain iteration + AF_UNSPEC
//! fallback), all in one `async fn`. It owns its resources ([`HostCtx`]) and
//! depends only on the neutral core + the engine's shared `resolve_query` — never
//! on `client.rs`/`transport.rs`. The ffi only builds a C hostent from the
//! returned core [`Hostent`] and fires the callback.

use std::cell::RefCell;
use std::ffi::c_int;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::Instant;

use crate::core::cache::QueryCache;
use crate::core::executor::{resolve_query, QueryIo, Resources};
use crate::core::hostent::Hostent;
use crate::core::hostfile::{AddressFamily, Hosts};
use crate::core::lookup::{
    is_localhost, is_onion_domain, AF_INET, AF_INET6, AF_UNSPEC, RTYPE_A, RTYPE_AAAA,
};
use crate::core::query_builder::dns_query_payload;
use crate::core::response::{addr_reply, ReplyRequire};
use crate::core::sortlist::{apply_sortlist, SortlistEntry};
use crate::core::AresError;
use crate::ffi::error::{
    ARES_EBADNAME, ARES_EFILE, ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP,
    ARES_ETIMEOUT,
};

/// Everything the async gethostbyname future owns — the engine's shared socket
/// resources plus the preflight's config snapshots. Built by the ffi from
/// `Client`; the future itself names no `Client`/`Transport`.
pub(crate) struct HostCtx {
    pub res: Resources,
    pub hosts: Rc<Hosts>,
    pub cache: Rc<RefCell<QueryCache>>,
    pub sortlist: Rc<[SortlistEntry]>,
    pub ndots: u32,
    pub search: Rc<[String]>,
    pub use_vc: bool,
}

/// The whole lifecycle, request to delivery. The preflight has no `.await`, so a
/// synchronous hit completes on the spawn's first poll and fires re-entrantly
/// (matching c-ares); otherwise it falls into the DNS loop. The accumulated
/// timeout count is written to `io.timeouts` for the ffi to read (a sync hit
/// leaves it at its `0` default).
pub(crate) async fn gethostbyname(ctx: HostCtx, io: Rc<RefCell<QueryIo>>, hostname: String, family: c_int) -> Result<Hostent, AresError> {
    // ===== preflight (synchronous) — order is behavior =====
    if !hostname.is_ascii() {
        return Err(ARES_EBADNAME.into());
    }
    if is_onion_domain(&hostname) {
        return Err(ARES_ENOTFOUND.into());
    }
    let filter = match family {
        AF_INET => AddressFamily::Ipv4,
        AF_INET6 => AddressFamily::Ipv6,
        AF_UNSPEC => AddressFamily::Any,
        _ => return Err(ARES_ENOTIMP.into()),
    };

    // IP literal (a family mismatch falls through, not fails).
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let matches = match filter {
            AddressFamily::Ipv4 => ip.is_ipv4(),
            AddressFamily::Ipv6 => ip.is_ipv6(),
            AddressFamily::Any => true,
        };
        if matches {
            return Ok(Hostent::new(hostname, vec![ip]));
        }
    }

    // Hosts file.
    if let Some(lookup) = ctx.hosts.lookup(&hostname, filter) {
        if !lookup.addrs.is_empty() {
            return Ok(Hostent::from_lookup(lookup));
        }
    }

    // RFC 6761: localhost / *.localhost → loopback.
    if is_localhost(&hostname) {
        let addrs = match filter {
            AddressFamily::Ipv4 => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            AddressFamily::Ipv6 => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            AddressFamily::Any => vec![IpAddr::V6(Ipv6Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::LOCALHOST)],
        };
        return Ok(Hostent::new(hostname, addrs));
    }

    // HOSTALIASES (single-label names): resolve via env-pointed file.
    let resolved = match resolve_hostaliases(&hostname) {
        Ok(name) => name,
        Err(status) => return Err(status.into()),
    };

    if ctx.res.endpoints.is_empty() {
        return Err(ARES_ENOSERVER.into());
    }

    // Query-cache probe: a fresh cached reply that parses to a non-empty answer
    // delivers now; an expired entry is evicted; a parse error falls through.
    let cache_rtype = if matches!(filter, AddressFamily::Ipv4) { RTYPE_A } else { RTYPE_AAAA };
    let cache_family = if matches!(filter, AddressFamily::Ipv4) { AF_INET } else { AF_INET6 };
    if let Some(cached) = ctx.cache.borrow_mut().get(&resolved, cache_rtype, Instant::now()) {
        if let Ok(mut rrs) = addr_reply(&cached, cache_rtype, ReplyRequire::Items) {
            if !ctx.sortlist.is_empty() {
                apply_sortlist(&ctx.sortlist, &mut rrs.items);
            }
            return Ok(Hostent::from_parsed(rrs, cache_family));
        }
    }

    // ===== DNS phase =====
    // The candidate names to try, in order (was SearchPlan::for_gethostbyname):
    // below ndots with a search list, each `name.domain` then the bare name;
    // otherwise just the name. Trailing dots are kept verbatim (unlike
    // ares_search) so the query / cache-store / cache-probe keys all match.
    let dots = resolved.chars().filter(|&c| c == '.').count() as u32;
    let mut names: Vec<String> = if dots < ctx.ndots && !ctx.search.is_empty() {
        let mut v: Vec<String> = ctx.search.iter().map(|d| format!("{resolved}.{d}")).collect();
        v.push(resolved.clone());
        v
    } else {
        vec![resolved.clone()]
    };
    let mut idx = 0;
    let (mut current_family, mut rtype) = match family {
        AF_INET => (AF_INET, RTYPE_A),
        _ => (AF_INET6, RTYPE_AAAA),
    };
    let mut tried_aaaa = family == AF_UNSPEC;
    let mut timeouts: c_int = 0;
    let mut had_nodata = false;
    let mut first = true;

    loop {
        let payload = dns_query_payload(&names[idx], rtype);
        // Only a lookup's first query is eligible to spawn a probe.
        let probe_payload = if first { Some(dns_query_payload(&names[idx], rtype)) } else { None };
        first = false;
        let (result, io_timeouts) = resolve_query(io.clone(), ctx.res.clone(), payload, ctx.use_vc, probe_payload).await;

        let last_error: AresError = match result {
            Ok(buf) => match addr_reply(&buf, rtype, ReplyRequire::Items) {
                Ok(mut rrs) => {
                    // Cache the raw reply under the query name (+ the bare name,
                    // when a search domain was appended), then sort + build.
                    if ctx.cache.borrow().enabled() {
                        let mut store = vec![names[idx].clone()];
                        if resolved != names[idx] {
                            store.push(resolved.clone());
                        }
                        let ttl = rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        ctx.cache.borrow_mut().store_names(store, rtype, ttl, &buf, Instant::now());
                    }
                    if !ctx.sortlist.is_empty() {
                        apply_sortlist(&ctx.sortlist, &mut rrs.items);
                    }
                    io.borrow_mut().timeouts = timeouts + io_timeouts;
                    return Ok(Hostent::from_parsed(rrs, current_family));
                }
                Err(e) => {
                    if e.code() == ARES_ENODATA {
                        had_nodata = true;
                    }
                    e
                }
            },
            Err(status) => {
                if status == ARES_ETIMEOUT {
                    timeouts += 1;
                }
                AresError::from(status)
            }
        };

        // Next candidate name on NXDOMAIN/NODATA.
        if matches!(last_error.code(), ARES_ENOTFOUND | ARES_ENODATA) && idx + 1 < names.len() {
            idx += 1;
            continue;
        }
        // AF_UNSPEC: the AAAA list is exhausted → retry just the bare name over A.
        if family == AF_UNSPEC && tried_aaaa && current_family == AF_INET6 {
            current_family = AF_INET;
            rtype = RTYPE_A;
            tried_aaaa = false;
            names = vec![resolved.clone()];
            idx = 0;
            continue;
        }
        // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
        let status = if had_nodata && last_error.code() == ARES_ENOTFOUND {
            ARES_ENODATA
        } else {
            last_error.code()
        };
        io.borrow_mut().timeouts = timeouts;
        return Err(status.into());
    }
}

/// HOSTALIASES for single-label names: read the env-pointed file, return the
/// alias target (or the name unchanged). `PermissionDenied` → `ARES_EFILE`.
fn resolve_hostaliases(hostname: &str) -> Result<String, c_int> {
    if hostname.contains('.') {
        return Ok(hostname.to_string());
    }
    let Ok(aliases_path) = std::env::var("HOSTALIASES") else {
        return Ok(hostname.to_string());
    };
    match std::fs::read_to_string(&aliases_path) {
        Ok(content) => {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(hostname) {
                    return Ok(parts[1].to_string());
                }
            }
            Ok(hostname.to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(ARES_EFILE),
        Err(_) => Ok(hostname.to_string()),
    }
}
