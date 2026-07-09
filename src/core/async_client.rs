//! `AsyncClient` — the shared config snapshot every async resolver lifecycle
//! owns, plus the lifecycles themselves as methods. Consolidates what used to be
//! five near-duplicate per-op context structs (`HostCtx`/`HostByAddrCtx`/
//! `NameinfoCtx`/`SearchCtx`/`AddrInfoCtx`) and five free `async fn`s.
//!
//! Built by `Client::async_client` into an `Rc<AsyncClient>`. Methods take
//! `self: Rc<Self>` so the spawned lifecycle futures are `'static` (they are
//! `Box::pin`'d into the ffi `AsyncKind`) while still allowing cheap sharing and
//! nested calls (`self.clone().other(…)`). Depends only on the neutral core +
//! the engine's shared `resolve_query`/`ParallelQueries` — never on
//! `client.rs`/`transport.rs`.

use std::cell::RefCell;
use std::ffi::{c_int, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::Instant;

use crate::core::api;
use crate::core::cache::QueryCache;
use crate::core::executor::{resolve_query, Delivery, DnsMailbox, ParallelQueries, Resources};
use bytes::BytesMut;
use crate::core::hostent::Hostent;
use crate::core::hostfile::{AddressFamily, Hosts};
use crate::core::lookup::{
    is_localhost, is_onion_domain, summarize, SearchPlan, AF_INET, AF_INET6, AF_UNSPEC, RTYPE_A,
    RTYPE_AAAA,
};
use crate::core::packets::AddrRecord;
use crate::core::preflight::{
    assemble_nameinfo, format_ip_with_scope, get_service_string, AddrInfo, NameinfoReply,
};
use crate::core::query_builder::dns_query_payload;
use crate::core::response::{addr_reply, ReplyRequire};
use crate::core::services::Services;
use crate::core::sortlist::{apply_sortlist, SortlistEntry};
use crate::core::transport::rdns_name;
use crate::core::AresError;
use crate::ffi::error::{
    ARES_EBADFLAGS, ARES_EBADNAME, ARES_EFILE, ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND,
    ARES_ENOTIMP, ARES_EREFUSED, ARES_ESERVFAIL, ARES_ETIMEOUT,
};
use crate::ffi::{
    ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NUMERICHOST, ARES_SUCCESS,
    RECORD_TYPE_PTR,
};

/// The per-channel resolver client: the shared config snapshot plus a [`QueryIo`]
/// mailbox. All `Rc` clones + `Copy` scalars; the futures never name
/// `Client`/`Transport`. One instance is owned by the channel (`Client` caches it,
/// rebuilding on config change); every lookup derives a cheap per-lookup copy via
/// [`with_fresh_io`](Self::with_fresh_io) — same config `Rc`s, its own fresh
/// mailbox — so concurrent lookups on a channel never share a `QueryIo`. The
/// channel-owned base's `io` is an inert placeholder, replaced on each derive.
/// The ffi grabs the derived copy's `self.io.clone()` to drive that mailbox;
/// nested inline sub-calls (`self.clone().other(…)`) share it.
pub(crate) struct AsyncClient {
    pub io: Rc<RefCell<DnsMailbox>>,
    pub res: Resources,
    pub hosts: Rc<Hosts>,
    pub cache: Rc<RefCell<QueryCache>>,
    pub sortlist: Rc<[SortlistEntry]>,
    pub ndots: u32,
    pub search: Rc<[String]>,
    pub use_vc: bool,
}

impl AsyncClient {
    /// Derive a per-lookup copy of the channel-owned client: clone the config
    /// `Rc`s (cheap) but mint a **fresh** mailbox, so each concurrent lookup owns
    /// its own `QueryIo`. Cloning `self.io` here instead would make every lookup
    /// on the channel share one mailbox — the bug this avoids.
    pub(crate) fn with_fresh_io(&self) -> Rc<Self> {
        Rc::new(AsyncClient {
            io: Rc::new(RefCell::new(DnsMailbox::default())),
            res: self.res.clone(),
            hosts: self.hosts.clone(),
            cache: self.cache.clone(),
            sortlist: self.sortlist.clone(),
            ndots: self.ndots,
            search: self.search.clone(),
            use_vc: self.use_vc,
        })
    }

    /// ares_query / ares_send: one query delivered raw. Keeps the historical
    /// UDP-start behavior (`use_tcp = false`); unlike the resolver ops it does
    /// **not** honor `ARES_FLAG_USEVC`. (Replaces the free `raw_lifecycle`.)
    pub(crate) async fn query_raw(self: Rc<Self>, payload: BytesMut) -> Delivery {
        let (result, timeouts) = resolve_query(self.io.clone(), self.res.clone(), payload, false, None).await;
        Delivery::Raw { result, timeouts }
    }

    /// ares_gethostbyname: the full pre-DNS cascade (ASCII/onion/family/
    /// IP-literal/hosts/localhost/HOSTALIASES/no-servers/query-cache) then the
    /// DNS phase (search-domain iteration + AF_UNSPEC fallback). The preflight
    /// has no `.await`, so a synchronous hit fires re-entrantly on the first
    /// poll; the timeout count is written to `io.timeouts` for the ffi.
    pub(crate) async fn gethostbyname(
        self: Rc<Self>,
        hostname: String,
        family: c_int,
    ) -> Result<Hostent, AresError> {
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
        if let Some(lookup) = self.hosts.lookup(&hostname, filter) {
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

        if self.res.endpoints.is_empty() {
            return Err(ARES_ENOSERVER.into());
        }

        // Query-cache probe: a fresh cached reply that parses to a non-empty
        // answer delivers now; an expired entry is evicted; a parse error falls
        // through.
        let cache_rtype = if matches!(filter, AddressFamily::Ipv4) { RTYPE_A } else { RTYPE_AAAA };
        let cache_family = if matches!(filter, AddressFamily::Ipv4) { AF_INET } else { AF_INET6 };
        if let Some(cached) = self.cache.borrow_mut().get(&resolved, cache_rtype, Instant::now()) {
            if let Ok(mut rrs) = addr_reply(&cached, cache_rtype, ReplyRequire::Items) {
                if !self.sortlist.is_empty() {
                    apply_sortlist(&self.sortlist, &mut rrs.items);
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
        let mut names: Vec<String> = if dots < self.ndots && !self.search.is_empty() {
            let mut v: Vec<String> = self.search.iter().map(|d| format!("{resolved}.{d}")).collect();
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
            let (result, io_timeouts) = resolve_query(self.io.clone(), self.res.clone(), payload, self.use_vc, probe_payload).await;

            let last_error: AresError = match result {
                Ok(buf) => match addr_reply(&buf, rtype, ReplyRequire::Items) {
                    Ok(mut rrs) => {
                        // Cache the raw reply under the query name (+ the bare
                        // name, when a search domain was appended), then sort + build.
                        if self.cache.borrow().enabled() {
                            let mut store = vec![names[idx].clone()];
                            if resolved != names[idx] {
                                store.push(resolved.clone());
                            }
                            let ttl = rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                            self.cache.borrow_mut().store_names(store, rtype, ttl, &buf, Instant::now());
                        }
                        if !self.sortlist.is_empty() {
                            apply_sortlist(&self.sortlist, &mut rrs.items);
                        }
                        self.io.borrow_mut().app.timeouts = timeouts + io_timeouts;
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
            self.io.borrow_mut().app.timeouts = timeouts;
            return Err(status.into());
        }
    }

    /// ares_gethostbyaddr: hosts-file reverse lookup, then a single PTR query.
    /// Family validation is done in the ffi shim (raw C args).
    pub(crate) async fn gethostbyaddr(
        self: Rc<Self>,
        ip: IpAddr,
        family: c_int,
    ) -> Result<Hostent, AresError> {
        // Hosts file reverse lookup.
        if let Some(lookup) = self.hosts.reverse_lookup(ip) {
            return Ok(Hostent::from_lookup(lookup));
        }

        if self.res.endpoints.is_empty() {
            return Err(ARES_ENOSERVER.into());
        }

        // ===== DNS phase: single PTR query =====
        let payload = dns_query_payload(&rdns_name(ip), RECORD_TYPE_PTR);
        let (result, io_timeouts) = resolve_query(self.io.clone(), self.res.clone(), payload, false, None).await;

        match result {
            Ok(buf) => {
                let hostent = api::on_host_reply(Ok(&buf), RECORD_TYPE_PTR, family, Some(ip))?;
                self.io.borrow_mut().app.timeouts = io_timeouts;
                Ok(hostent)
            }
            Err(status) => {
                self.io.borrow_mut().app.timeouts = io_timeouts;
                Err(AresError::from(status))
            }
        }
    }

    /// ares_getnameinfo: the three synchronous short-circuits (service-only /
    /// NUMERICHOST / no-servers), else a single PTR query + `assemble_nameinfo`.
    pub(crate) async fn getnameinfo(
        self: Rc<Self>,
        addr: AddrInfo,
        flags: c_int,
    ) -> NameinfoReply {
        // Flag defaulting: if neither LOOKUPSERVICE nor LOOKUPHOST, default to LOOKUPHOST.
        let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
            flags | ARES_NI_LOOKUPHOST
        } else {
            flags
        };

        let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
        let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

        // Service-only: no DNS needed.
        if want_service && !want_host {
            let service = get_service_string(&Services::default(), addr.port, flags);
            return NameinfoReply { status: ARES_SUCCESS.into(), node: None, service, timeouts: 0 };
        }

        // NUMERICHOST: the address string is the answer.
        if (flags & ARES_NI_NUMERICHOST) != 0 {
            if (flags & ARES_NI_NAMEREQD) != 0 {
                return NameinfoReply { status: ARES_EBADFLAGS.into(), node: None, service: None, timeouts: 0 };
            }
            let node = CString::new(format_ip_with_scope(&addr.ip, addr.scope_id, flags)).unwrap();
            let service = if want_service {
                get_service_string(&Services::default(), addr.port, flags)
            } else {
                None
            };
            return NameinfoReply { status: ARES_SUCCESS.into(), node: Some(node), service, timeouts: 0 };
        }

        if self.res.endpoints.is_empty() {
            return NameinfoReply { status: ARES_ENOSERVER.into(), node: None, service: None, timeouts: 0 };
        }

        // ===== DNS phase: single PTR query =====
        let payload = dns_query_payload(&rdns_name(addr.ip), RECORD_TYPE_PTR);
        let (result, io_timeouts) = resolve_query(self.io.clone(), self.res.clone(), payload, false, None).await;

        let dns_result: Result<&[u8], AresError> = match result {
            Ok(ref buf) => Ok(&buf[..]),
            Err(status) => Err(AresError::from(status)),
        };
        let reply = assemble_nameinfo(dns_result, addr.ip, addr.scope_id, addr.port, flags, io_timeouts);
        // `assemble_nameinfo` carries io_timeouts in its `NameinfoReply.timeouts`.
        self.io.borrow_mut().app.timeouts = reply.timeouts;
        reply
    }

    /// ares_search / ares_search_dnsrec: iterate the search plan, retrying on
    /// NXDOMAIN/NODATA/timeout (and, for the dnsrec flavor with
    /// `retry_server_error`, also on SERVFAIL/REFUSED/NOTIMP). The rcode→status
    /// mapping mirrors the classic `SearchSm::step`.
    pub(crate) async fn search(
        self: Rc<Self>,
        name: String,
        dnstype: u16,
        retry_server_error: bool,
    ) -> Delivery {
        if self.res.endpoints.is_empty() {
            return Delivery::Raw { result: Err(ARES_ENOSERVER), timeouts: 0 };
        }

        let mut plan = SearchPlan::for_search(&name, self.ndots, &self.search);
        let mut had_nodata = false;
        let mut timeouts: c_int = 0;
        let mut first = true;

        loop {
            let payload = dns_query_payload(&plan.current, dnstype);
            // Only the first query of a lookup is eligible to spawn a failover probe.
            let probe_payload = if first { Some(dns_query_payload(&plan.current, dnstype)) } else { None };
            first = false;
            let (result, io_timeouts) = resolve_query(self.io.clone(), self.res.clone(), payload, self.use_vc, probe_payload).await;
            timeouts += io_timeouts;

            let last_error: AresError = match result {
                Ok(buf) => {
                    let summary = summarize(&buf, 0);
                    match summary.rcode {
                        3 => ARES_ENOTFOUND.into(),  // NXDOMAIN
                        2 => ARES_ESERVFAIL.into(),  // SERVFAIL
                        4 => ARES_ENOTIMP.into(),    // NOTIMP
                        5 => ARES_EREFUSED.into(),   // REFUSED
                        0 if summary.ancount > 0 => {
                            // Success — deliver the raw response.
                            self.io.borrow_mut().app.timeouts = timeouts;
                            return Delivery::Raw { result: Ok(buf), timeouts };
                        }
                        // NOERROR-with-no-answers, or any other rcode → NODATA.
                        _ => {
                            had_nodata = true;
                            ARES_ENODATA.into()
                        }
                    }
                }
                Err(status) => AresError::from(status),
            };

            // Search-domain iteration: on NXDOMAIN/NODATA/TIMEOUT — and, for the
            // dnsrec flavor, also on server errors — try the next name in the plan.
            let code = last_error.code();
            let iterate = matches!(code, ARES_ENOTFOUND | ARES_ENODATA | ARES_ETIMEOUT)
                || (retry_server_error && matches!(code, ARES_ESERVFAIL | ARES_EREFUSED | ARES_ENOTIMP));
            if iterate && plan.advance().is_some() {
                continue;
            }

            // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
            let mut status = last_error;
            if had_nodata && status.code() == ARES_ENOTFOUND {
                status = ARES_ENODATA.into();
            }
            self.io.borrow_mut().app.timeouts = timeouts;
            return Delivery::Raw { result: Err(status.code()), timeouts };
        }
    }

    /// ares_getaddrinfo: preflight (empty/onion/IP-literal/hosts/no-servers),
    /// then per search-plan name a parallel A+AAAA batch via [`ParallelQueries`],
    /// merging the address records. Policy (not the executor): once the A/ipv4
    /// query returns addresses, cancel the sibling AAAA query's retries.
    pub(crate) async fn getaddrinfo(
        self: Rc<Self>,
        hostname_raw: String,
        ai_family: c_int,
    ) -> AddrInfoOut {
        // ===== preflight (synchronous) — order is behavior =====
        // The raw name keeps its trailing dot for the SearchPlan; the checks and
        // the delivered canonical name use the stripped form.
        let hostname = hostname_raw.strip_suffix('.').unwrap_or(&hostname_raw);

        if hostname.is_empty() || is_onion_domain(hostname) {
            return fail(ARES_ENOTFOUND);
        }

        // IP literal (a family mismatch fails — no fall-through).
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            let matches = match ai_family {
                libc::AF_INET => ip.is_ipv4(),
                libc::AF_INET6 => ip.is_ipv6(),
                libc::AF_UNSPEC => true,
                _ => false,
            };
            if matches {
                return AddrInfoOut {
                    name: hostname.to_string(),
                    records: vec![AddrRecord { ip, ttl: u32::MAX }],
                    status: ARES_SUCCESS.into(),
                };
            }
            return fail(ARES_ENOTFOUND);
        }

        // Hosts file.
        let family_filter = match ai_family {
            libc::AF_INET => AddressFamily::Ipv4,
            libc::AF_INET6 => AddressFamily::Ipv6,
            _ => AddressFamily::Any,
        };
        if let Some(lookup) = self.hosts.lookup(hostname, family_filter) {
            if !lookup.addrs.is_empty() {
                return AddrInfoOut {
                    name: hostname.to_string(),
                    records: lookup.addrs.iter().map(|&ip| AddrRecord { ip, ttl: u32::MAX }).collect(),
                    status: ARES_SUCCESS.into(),
                };
            }
        }

        if self.res.endpoints.is_empty() {
            return fail(ARES_ENOSERVER);
        }

        // ===== DNS phase: parallel A+AAAA per search-plan name =====
        let mut plan = SearchPlan::for_search(&hostname_raw, self.ndots, &self.search);
        let mut timeouts: c_int = 0;
        let mut last_error: AresError = ARES_ENODATA.into();
        let mut had_nodata = false;

        loop {
            let rtypes: Vec<u16> = match ai_family {
                libc::AF_INET => vec![RTYPE_A],
                libc::AF_INET6 => vec![RTYPE_AAAA],
                _ => vec![RTYPE_A, RTYPE_AAAA],
            };
            let payloads: Vec<_> =
                rtypes.iter().map(|&rt| (dns_query_payload(&plan.current, rt), self.use_vc)).collect();
            let a_idx = rtypes.iter().position(|&rt| rt == RTYPE_A);

            // Drive A+AAAA in parallel. Policy (here, not in the executor): once
            // the A/ipv4 query returns actual addresses, cancel the sibling AAAA
            // query — its retries stop so it isn't sent again. (ipv6 success does
            // NOT cancel A: an ipv4-only host may still need the A answer.)
            let mut par = ParallelQueries::new(self.io.clone(), self.res.clone(), payloads);
            while !par.all_done() {
                par.step().await;
                if let Some(ai) = a_idx {
                    if let Some((Ok(buf), _)) = par.result(ai) {
                        let s = summarize(buf, 0);
                        if s.rcode == 0 && s.ancount > 0 {
                            for j in 0..rtypes.len() {
                                if j != ai {
                                    par.cancel(j);
                                }
                            }
                        }
                    }
                }
            }

            // Merge every family's records (arrival order); note the last error.
            // A cancelled query has no result — it contributes nothing.
            let mut records: Vec<AddrRecord> = Vec::new();
            let mut any_success = false;
            for (i, &rtype) in rtypes.iter().enumerate() {
                match par.result(i) {
                    Some((Ok(buf), io_timeouts)) => {
                        timeouts += io_timeouts;
                        match addr_reply(buf, rtype, ReplyRequire::Items) {
                            Ok(mut rrs) => {
                                records.append(&mut rrs.items);
                                any_success = true;
                            }
                            Err(e) => {
                                if e.code() == ARES_ENODATA {
                                    had_nodata = true;
                                }
                                last_error = e;
                            }
                        }
                    }
                    Some((Err(status), io_timeouts)) => {
                        timeouts += io_timeouts;
                        last_error = AresError::from(*status);
                    }
                    None => {}
                }
            }

            if any_success {
                self.io.borrow_mut().app.timeouts = timeouts;
                return AddrInfoOut { name: plan.current.clone(), records, status: ARES_SUCCESS.into() };
            }

            // All families failed for this name — try the next search domain.
            let code = last_error.code();
            let retryable = matches!(
                code,
                ARES_ENODATA | ARES_ENOTFOUND | ARES_ETIMEOUT | ARES_ESERVFAIL | ARES_ENOTIMP | ARES_EREFUSED
            );
            if retryable && plan.advance().is_some() {
                last_error = ARES_ENODATA.into();
                continue;
            }

            // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
            let status = if had_nodata && code == ARES_ENOTFOUND { ARES_ENODATA } else { code };
            self.io.borrow_mut().app.timeouts = timeouts;
            return fail(status);
        }
    }
}

/// The safe result the FFI turns into an `ares_addrinfo`: the canonical name,
/// the merged address records (arrival order), and the status.
pub(crate) struct AddrInfoOut {
    pub name: String,
    pub records: Vec<AddrRecord>,
    pub status: AresError,
}

fn fail(status: c_int) -> AddrInfoOut {
    AddrInfoOut { name: String::new(), records: Vec::new(), status: status.into() }
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
