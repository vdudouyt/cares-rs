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
use std::collections::HashMap;
use std::ffi::{c_int, CString};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::BytesMut;

use crate::core::api;
use crate::core::cache::QueryCache;
use crate::core::executor::{
    noop_waker, poll_deadline, poll_recv, recv_datagram, recv_stream, select2, select3,
    send_when_writable, wait_io, QueryIo, Recv, RecvReady, Wait, Which2, Which3,
};
use crate::core::hostent::Hostent;
use crate::core::hostfile::{AddressFamily, Hosts};
use crate::core::lookup::{
    extract_tcp_frame, is_localhost, is_onion_domain, on_datagram, on_timeout, qid_matches,
    summarize, ReactorAction, SearchPlan, ServerHealth, TaskVerdict, TimeoutVerdict, AF_INET,
    AF_INET6, AF_UNSPEC, RTYPE_A, RTYPE_AAAA,
};
use crate::core::packets::AddrRecord;
use crate::core::preflight::{
    assemble_nameinfo, format_ip_with_scope, get_service_string, AddrInfo, NameinfoReply,
};
use crate::core::query_builder::{dns_query_payload, frame_tcp};
use crate::core::response::{addr_reply, ReplyRequire};
use crate::core::services::Services;
use crate::core::socket::{Socket, SocketFactory};
use crate::core::sortlist::{apply_sortlist, SortlistEntry};
use crate::core::transport::rdns_name;
use crate::core::AresError;
use crate::ffi::error::{
    ARES_ECONNREFUSED, ARES_EBADFLAGS, ARES_EBADNAME, ARES_EFILE, ARES_ENODATA, ARES_ENOSERVER,
    ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED, ARES_ESERVFAIL, ARES_ETIMEOUT,
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
        // Inlined single-query driver (WET, see the module note): pick server →
        // socket → send → recv → QID-match → TC/failover/timeout verdicts. The raw
        // path: UDP-start (`use_tcp = false`), no probe, no USEVC. The connection
        // is a `Conn` with `send`/`read`/`register`/`clear_slot` methods.
        let (result, timeouts) = 'drive: {
            let io = self.io.clone();
            let res = self.res.clone();
            let mut use_tcp = false;
            let mut timeouts: c_int = 0;
            let mut tries: u32 = 0;
            let mut failover_tries: u32 = 0;
            let qid = qid_of(&payload);
            let mut server = res.health.borrow().pick_next();
            'attempt: loop {
                // Inlined connect-with-failover (WET): create + connect the socket
                // for `server`, retrying across servers on creation failure.
                let (mut conn, si) = 'connect: {
                    let mut s = server;
                    for _ in 0..res.opts.attempts.max(1) {
                        let Some(ep) = res.endpoints.get(s) else { break };
                        let wire = if use_tcp {
                            res.tcp_pool.borrow_mut().get_or_create(s, &res.factory, ep).ok().map(|c| Wire::Shared(c, qid))
                        } else {
                            res.factory.create_udp(ep.bind).ok().map(|sk| Wire::Owned(OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }))
                        };
                        if let Some(wire) = wire {
                            break 'connect (Conn { io: io.clone(), wire }, s);
                        }
                        if res.health.borrow().len() > 1 {
                            res.health.borrow_mut().record_failure(s);
                            s = res.health.borrow().pick_next();
                        }
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                };
                server = si;
                let ep = res.endpoints[server].clone();
                let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                let deadline = Instant::now() + res.opts.timeout;
                conn.register();
                if !conn.send(&ep, wire, deadline).await {
                    conn.clear_slot();
                    if use_tcp {
                        res.tcp_pool.borrow_mut().remove(server);
                    }
                    if tries + 1 < res.opts.attempts.max(1) {
                        tries += 1;
                        if res.health.borrow().len() > 1 {
                            res.health.borrow_mut().record_failure(server);
                            server = res.health.borrow().pick_next();
                        }
                        continue 'attempt;
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                }
                loop {
                    match conn.recv(deadline).await {
                        RecvOutcome::Reply(buf) => {
                            if !qid_matches(&buf, wire, use_tcp) {
                                continue; // stray datagram — await the next reply
                            }
                            let summary = summarize(&buf, 0);
                            let (actions, verdict) = on_datagram(
                                &summary,
                                server,
                                use_tcp,
                                res.opts.attempts,
                                failover_tries,
                                &mut res.health.borrow_mut(),
                            );
                            notify(&io, actions);
                            match verdict {
                                TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                    conn.clear_slot();
                                    server = next;
                                    failover_tries = ft;
                                    continue 'attempt;
                                }
                                TaskVerdict::RetryTcp => {
                                    use_tcp = true;
                                    continue 'attempt;
                                }
                                TaskVerdict::Deliver => {
                                    conn.clear_slot();
                                    break 'drive (Ok(buf), timeouts);
                                }
                            }
                        }
                        RecvOutcome::Timeout => {
                            conn.clear_slot();
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                            match verdict {
                                TimeoutVerdict::Retry { server: next } => {
                                    tries += 1;
                                    timeouts += 1;
                                    server = next;
                                    continue 'attempt;
                                }
                                TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                            }
                        }
                        RecvOutcome::Dead => {
                            conn.clear_slot();
                            if use_tcp {
                                res.tcp_pool.borrow_mut().remove(server);
                            }
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                            match verdict {
                                TimeoutVerdict::Retry { server: next } => {
                                    tries += 1;
                                    timeouts += 1;
                                    server = next;
                                    continue 'attempt;
                                }
                                TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                            }
                        }
                    }
                }
            }
        };
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
            let (result, io_timeouts) = 'drive: {
                let io = self.io.clone();
                let res = self.res.clone();
                let mut use_tcp = self.use_vc;
                let mut timeouts: c_int = 0;
                let mut tries: u32 = 0;
                let mut failover_tries: u32 = 0;
                let qid = qid_of(&payload);
                let mut server = res.health.borrow().pick_next();
                let mut probe = probe_payload.and_then(|pp| {
                    // Inlined probe setup (WET): a one-shot failover probe to a stale
                    // server, raced alongside the primary. `None` if failover is off /
                    // no server is due / a socket fails.
                    if res.opts.failover_chance == 0 {
                        return None;
                    }
                    let primary_server = res.health.borrow().pick_next();
                    let pserver = res.health.borrow().pick_probe(res.opts.failover_delay, primary_server)?;
                    let ep = res.endpoints.get(pserver)?;
                    let psock = if use_tcp {
                        let sk = res.factory.create_tcp(ep.bind).ok()?;
                        let _ = sk.connect(ep.tcp_addr);
                        OwnedSock { sock: sk, is_tcp: true, rbuf: Vec::new() }
                    } else {
                        let sk = res.factory.create_udp(ep.bind).ok()?;
                        let _ = sk.connect(ep.udp_addr);
                        OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }
                    };
                    let framed = if use_tcp { frame_tcp(&pp) } else { pp.clone() };
                    let _ = psock.sock.send(&framed);
                    Some(Probe {
                        conn: Conn { io: io.clone(), wire: Wire::Owned(psock) },
                        server: pserver,
                        deadline: Instant::now() + res.opts.timeout,
                        payload: framed,
                    })
                });
                'attempt: loop {
                    // Inlined connect-with-failover (WET).
                    let (mut conn, si) = 'connect: {
                        let mut s = server;
                        for _ in 0..res.opts.attempts.max(1) {
                            let Some(ep) = res.endpoints.get(s) else { break };
                            let wire = if use_tcp {
                                res.tcp_pool.borrow_mut().get_or_create(s, &res.factory, ep).ok().map(|c| Wire::Shared(c, qid))
                            } else {
                                res.factory.create_udp(ep.bind).ok().map(|sk| Wire::Owned(OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }))
                            };
                            if let Some(wire) = wire {
                                break 'connect (Conn { io: io.clone(), wire }, s);
                            }
                            if res.health.borrow().len() > 1 {
                                res.health.borrow_mut().record_failure(s);
                                s = res.health.borrow().pick_next();
                            }
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    };
                    server = si;
                    let ep = res.endpoints[server].clone();
                    let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                    let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                    let deadline = Instant::now() + res.opts.timeout;
                    conn.register();
                    if !conn.send(&ep, wire, deadline).await {
                        conn.clear_slot();
                        if use_tcp {
                            res.tcp_pool.borrow_mut().remove(server);
                        }
                        if tries + 1 < res.opts.attempts.max(1) {
                            tries += 1;
                            if res.health.borrow().len() > 1 {
                                res.health.borrow_mut().record_failure(server);
                                server = res.health.borrow().pick_next();
                            }
                            continue 'attempt;
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    }
                    loop {
                        // Race the live probe, the deadline, and the primary reply.
                        // Biased probe -> deadline -> primary (expiry preempts a
                        // same-cycle primary read, as before). No probe => 2-arm recv.
                        let event = if let Some(p) = probe.as_mut() {
                            let wake_deadline = deadline.min(p.deadline);
                            match select3(&io, |_| p.conn.recv_arm(), |io| poll_deadline(io, wake_deadline), |_| conn.recv_arm()).await {
                                Which3::A(r) => ReplyEvent::Probe(r),
                                Which3::B(()) => ReplyEvent::Deadline,
                                Which3::C(r) => ReplyEvent::Primary(r),
                            }
                        } else {
                            match conn.recv(deadline).await {
                                RecvOutcome::Reply(b) => ReplyEvent::Primary(RecvReady::Msg(b)),
                                RecvOutcome::Timeout => ReplyEvent::Deadline,
                                RecvOutcome::Dead => ReplyEvent::Primary(RecvReady::Dead),
                            }
                        };
                        match event {
                            ReplyEvent::Probe(r) => {
                                match r {
                                    RecvReady::Msg(buf) => {
                                        if probe.as_ref().is_some_and(|p| qid_matches(&buf, &p.payload, p.conn.is_tcp())) {
                                            let p_taken = probe.take().unwrap();
                                            settle_probe(&io, &res, &p_taken, Some(&buf));
                                        }
                                    }
                                    RecvReady::Dead => probe = None,
                                }
                                continue;
                            }
                            ReplyEvent::Deadline => {
                                let now = Instant::now();
                                if let Some(p) = &probe {
                                    if now >= p.deadline {
                                        let p_taken = probe.take().unwrap();
                                        settle_probe(&io, &res, &p_taken, None);
                                    }
                                }
                                if now >= deadline {
                                    conn.clear_slot();
                                    if io.borrow().app.cancelled {
                                        break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                                    match verdict {
                                        TimeoutVerdict::Retry { server: next } => {
                                            tries += 1;
                                            timeouts += 1;
                                            server = next;
                                            continue 'attempt;
                                        }
                                        TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                                    }
                                }
                                continue;
                            }
                            ReplyEvent::Primary(r) => {
                                let buf = match r {
                                    RecvReady::Msg(buf) => buf,
                                    RecvReady::Dead => {
                                        conn.clear_slot();
                                        if use_tcp {
                                            res.tcp_pool.borrow_mut().remove(server);
                                        }
                                        if io.borrow().app.cancelled {
                                            break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                        }
                                        notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                        let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                                        match verdict {
                                            TimeoutVerdict::Retry { server: next } => {
                                                tries += 1;
                                                timeouts += 1;
                                                server = next;
                                                continue 'attempt;
                                            }
                                            TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                                        }
                                    }
                                };
                                if !qid_matches(&buf, wire, use_tcp) {
                                    continue;
                                }
                                let summary = summarize(&buf, 0);
                                let (actions, verdict) = on_datagram(
                                    &summary,
                                    server,
                                    use_tcp,
                                    res.opts.attempts,
                                    failover_tries,
                                    &mut res.health.borrow_mut(),
                                );
                                notify(&io, actions);
                                match verdict {
                                    TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                        conn.clear_slot();
                                        server = next;
                                        failover_tries = ft;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::RetryTcp => {
                                        use_tcp = true;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::Deliver => {
                                        conn.clear_slot();
                                        break 'drive (Ok(buf), timeouts);
                                    }
                                }
                            }
                        }
                    }
                }
            };

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
        let (result, io_timeouts) = 'drive: {
            let io = self.io.clone();
            let res = self.res.clone();
            let mut use_tcp = false;
            let mut timeouts: c_int = 0;
            let mut tries: u32 = 0;
            let mut failover_tries: u32 = 0;
            let qid = qid_of(&payload);
            let mut server = res.health.borrow().pick_next();
            'attempt: loop {
                // Inlined connect-with-failover (WET): create + connect the socket
                // for `server`, retrying across servers on creation failure.
                let (mut conn, si) = 'connect: {
                    let mut s = server;
                    for _ in 0..res.opts.attempts.max(1) {
                        let Some(ep) = res.endpoints.get(s) else { break };
                        let wire = if use_tcp {
                            res.tcp_pool.borrow_mut().get_or_create(s, &res.factory, ep).ok().map(|c| Wire::Shared(c, qid))
                        } else {
                            res.factory.create_udp(ep.bind).ok().map(|sk| Wire::Owned(OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }))
                        };
                        if let Some(wire) = wire {
                            break 'connect (Conn { io: io.clone(), wire }, s);
                        }
                        if res.health.borrow().len() > 1 {
                            res.health.borrow_mut().record_failure(s);
                            s = res.health.borrow().pick_next();
                        }
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                };
                server = si;
                let ep = res.endpoints[server].clone();
                let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                let deadline = Instant::now() + res.opts.timeout;
                conn.register();
                if !conn.send(&ep, wire, deadline).await {
                    conn.clear_slot();
                    if use_tcp {
                        res.tcp_pool.borrow_mut().remove(server);
                    }
                    if tries + 1 < res.opts.attempts.max(1) {
                        tries += 1;
                        if res.health.borrow().len() > 1 {
                            res.health.borrow_mut().record_failure(server);
                            server = res.health.borrow().pick_next();
                        }
                        continue 'attempt;
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                }
                loop {
                    match conn.recv(deadline).await {
                        RecvOutcome::Reply(buf) => {
                            if !qid_matches(&buf, wire, use_tcp) {
                                continue; // stray datagram — await the next reply
                            }
                            let summary = summarize(&buf, 0);
                            let (actions, verdict) = on_datagram(
                                &summary,
                                server,
                                use_tcp,
                                res.opts.attempts,
                                failover_tries,
                                &mut res.health.borrow_mut(),
                            );
                            notify(&io, actions);
                            match verdict {
                                TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                    conn.clear_slot();
                                    server = next;
                                    failover_tries = ft;
                                    continue 'attempt;
                                }
                                TaskVerdict::RetryTcp => {
                                    use_tcp = true;
                                    continue 'attempt;
                                }
                                TaskVerdict::Deliver => {
                                    conn.clear_slot();
                                    break 'drive (Ok(buf), timeouts);
                                }
                            }
                        }
                        RecvOutcome::Timeout => {
                            conn.clear_slot();
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                            match verdict {
                                TimeoutVerdict::Retry { server: next } => {
                                    tries += 1;
                                    timeouts += 1;
                                    server = next;
                                    continue 'attempt;
                                }
                                TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                            }
                        }
                        RecvOutcome::Dead => {
                            conn.clear_slot();
                            if use_tcp {
                                res.tcp_pool.borrow_mut().remove(server);
                            }
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                            match verdict {
                                TimeoutVerdict::Retry { server: next } => {
                                    tries += 1;
                                    timeouts += 1;
                                    server = next;
                                    continue 'attempt;
                                }
                                TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                            }
                        }
                    }
                }
            }
        };

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
        let (result, io_timeouts) = 'drive: {
            let io = self.io.clone();
            let res = self.res.clone();
            let mut use_tcp = false;
            let mut timeouts: c_int = 0;
            let mut tries: u32 = 0;
            let mut failover_tries: u32 = 0;
            let qid = qid_of(&payload);
            let mut server = res.health.borrow().pick_next();
            'attempt: loop {
                // Inlined connect-with-failover (WET): create + connect the socket
                // for `server`, retrying across servers on creation failure.
                let (mut conn, si) = 'connect: {
                    let mut s = server;
                    for _ in 0..res.opts.attempts.max(1) {
                        let Some(ep) = res.endpoints.get(s) else { break };
                        let wire = if use_tcp {
                            res.tcp_pool.borrow_mut().get_or_create(s, &res.factory, ep).ok().map(|c| Wire::Shared(c, qid))
                        } else {
                            res.factory.create_udp(ep.bind).ok().map(|sk| Wire::Owned(OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }))
                        };
                        if let Some(wire) = wire {
                            break 'connect (Conn { io: io.clone(), wire }, s);
                        }
                        if res.health.borrow().len() > 1 {
                            res.health.borrow_mut().record_failure(s);
                            s = res.health.borrow().pick_next();
                        }
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                };
                server = si;
                let ep = res.endpoints[server].clone();
                let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                let deadline = Instant::now() + res.opts.timeout;
                conn.register();
                if !conn.send(&ep, wire, deadline).await {
                    conn.clear_slot();
                    if use_tcp {
                        res.tcp_pool.borrow_mut().remove(server);
                    }
                    if tries + 1 < res.opts.attempts.max(1) {
                        tries += 1;
                        if res.health.borrow().len() > 1 {
                            res.health.borrow_mut().record_failure(server);
                            server = res.health.borrow().pick_next();
                        }
                        continue 'attempt;
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                }
                loop {
                    match conn.recv(deadline).await {
                        RecvOutcome::Reply(buf) => {
                            if !qid_matches(&buf, wire, use_tcp) {
                                continue; // stray datagram — await the next reply
                            }
                            let summary = summarize(&buf, 0);
                            let (actions, verdict) = on_datagram(
                                &summary,
                                server,
                                use_tcp,
                                res.opts.attempts,
                                failover_tries,
                                &mut res.health.borrow_mut(),
                            );
                            notify(&io, actions);
                            match verdict {
                                TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                    conn.clear_slot();
                                    server = next;
                                    failover_tries = ft;
                                    continue 'attempt;
                                }
                                TaskVerdict::RetryTcp => {
                                    use_tcp = true;
                                    continue 'attempt;
                                }
                                TaskVerdict::Deliver => {
                                    conn.clear_slot();
                                    break 'drive (Ok(buf), timeouts);
                                }
                            }
                        }
                        RecvOutcome::Timeout => {
                            conn.clear_slot();
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                            match verdict {
                                TimeoutVerdict::Retry { server: next } => {
                                    tries += 1;
                                    timeouts += 1;
                                    server = next;
                                    continue 'attempt;
                                }
                                TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                            }
                        }
                        RecvOutcome::Dead => {
                            conn.clear_slot();
                            if use_tcp {
                                res.tcp_pool.borrow_mut().remove(server);
                            }
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                            match verdict {
                                TimeoutVerdict::Retry { server: next } => {
                                    tries += 1;
                                    timeouts += 1;
                                    server = next;
                                    continue 'attempt;
                                }
                                TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                            }
                        }
                    }
                }
            }
        };

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
            let (result, io_timeouts) = 'drive: {
                let io = self.io.clone();
                let res = self.res.clone();
                let mut use_tcp = self.use_vc;
                let mut timeouts: c_int = 0;
                let mut tries: u32 = 0;
                let mut failover_tries: u32 = 0;
                let qid = qid_of(&payload);
                let mut server = res.health.borrow().pick_next();
                let mut probe = probe_payload.and_then(|pp| {
                    // Inlined probe setup (WET): a one-shot failover probe to a stale
                    // server, raced alongside the primary. `None` if failover is off /
                    // no server is due / a socket fails.
                    if res.opts.failover_chance == 0 {
                        return None;
                    }
                    let primary_server = res.health.borrow().pick_next();
                    let pserver = res.health.borrow().pick_probe(res.opts.failover_delay, primary_server)?;
                    let ep = res.endpoints.get(pserver)?;
                    let psock = if use_tcp {
                        let sk = res.factory.create_tcp(ep.bind).ok()?;
                        let _ = sk.connect(ep.tcp_addr);
                        OwnedSock { sock: sk, is_tcp: true, rbuf: Vec::new() }
                    } else {
                        let sk = res.factory.create_udp(ep.bind).ok()?;
                        let _ = sk.connect(ep.udp_addr);
                        OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }
                    };
                    let framed = if use_tcp { frame_tcp(&pp) } else { pp.clone() };
                    let _ = psock.sock.send(&framed);
                    Some(Probe {
                        conn: Conn { io: io.clone(), wire: Wire::Owned(psock) },
                        server: pserver,
                        deadline: Instant::now() + res.opts.timeout,
                        payload: framed,
                    })
                });
                'attempt: loop {
                    // Inlined connect-with-failover (WET).
                    let (mut conn, si) = 'connect: {
                        let mut s = server;
                        for _ in 0..res.opts.attempts.max(1) {
                            let Some(ep) = res.endpoints.get(s) else { break };
                            let wire = if use_tcp {
                                res.tcp_pool.borrow_mut().get_or_create(s, &res.factory, ep).ok().map(|c| Wire::Shared(c, qid))
                            } else {
                                res.factory.create_udp(ep.bind).ok().map(|sk| Wire::Owned(OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }))
                            };
                            if let Some(wire) = wire {
                                break 'connect (Conn { io: io.clone(), wire }, s);
                            }
                            if res.health.borrow().len() > 1 {
                                res.health.borrow_mut().record_failure(s);
                                s = res.health.borrow().pick_next();
                            }
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    };
                    server = si;
                    let ep = res.endpoints[server].clone();
                    let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                    let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                    let deadline = Instant::now() + res.opts.timeout;
                    conn.register();
                    if !conn.send(&ep, wire, deadline).await {
                        conn.clear_slot();
                        if use_tcp {
                            res.tcp_pool.borrow_mut().remove(server);
                        }
                        if tries + 1 < res.opts.attempts.max(1) {
                            tries += 1;
                            if res.health.borrow().len() > 1 {
                                res.health.borrow_mut().record_failure(server);
                                server = res.health.borrow().pick_next();
                            }
                            continue 'attempt;
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    }
                    loop {
                        // Race the live probe, the deadline, and the primary reply.
                        // Biased probe -> deadline -> primary (expiry preempts a
                        // same-cycle primary read, as before). No probe => 2-arm recv.
                        let event = if let Some(p) = probe.as_mut() {
                            let wake_deadline = deadline.min(p.deadline);
                            match select3(&io, |_| p.conn.recv_arm(), |io| poll_deadline(io, wake_deadline), |_| conn.recv_arm()).await {
                                Which3::A(r) => ReplyEvent::Probe(r),
                                Which3::B(()) => ReplyEvent::Deadline,
                                Which3::C(r) => ReplyEvent::Primary(r),
                            }
                        } else {
                            match conn.recv(deadline).await {
                                RecvOutcome::Reply(b) => ReplyEvent::Primary(RecvReady::Msg(b)),
                                RecvOutcome::Timeout => ReplyEvent::Deadline,
                                RecvOutcome::Dead => ReplyEvent::Primary(RecvReady::Dead),
                            }
                        };
                        match event {
                            ReplyEvent::Probe(r) => {
                                match r {
                                    RecvReady::Msg(buf) => {
                                        if probe.as_ref().is_some_and(|p| qid_matches(&buf, &p.payload, p.conn.is_tcp())) {
                                            let p_taken = probe.take().unwrap();
                                            settle_probe(&io, &res, &p_taken, Some(&buf));
                                        }
                                    }
                                    RecvReady::Dead => probe = None,
                                }
                                continue;
                            }
                            ReplyEvent::Deadline => {
                                let now = Instant::now();
                                if let Some(p) = &probe {
                                    if now >= p.deadline {
                                        let p_taken = probe.take().unwrap();
                                        settle_probe(&io, &res, &p_taken, None);
                                    }
                                }
                                if now >= deadline {
                                    conn.clear_slot();
                                    if io.borrow().app.cancelled {
                                        break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                                    match verdict {
                                        TimeoutVerdict::Retry { server: next } => {
                                            tries += 1;
                                            timeouts += 1;
                                            server = next;
                                            continue 'attempt;
                                        }
                                        TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                                    }
                                }
                                continue;
                            }
                            ReplyEvent::Primary(r) => {
                                let buf = match r {
                                    RecvReady::Msg(buf) => buf,
                                    RecvReady::Dead => {
                                        conn.clear_slot();
                                        if use_tcp {
                                            res.tcp_pool.borrow_mut().remove(server);
                                        }
                                        if io.borrow().app.cancelled {
                                            break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                        }
                                        notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                        let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                                        match verdict {
                                            TimeoutVerdict::Retry { server: next } => {
                                                tries += 1;
                                                timeouts += 1;
                                                server = next;
                                                continue 'attempt;
                                            }
                                            TimeoutVerdict::Expire => break 'drive (Err(ARES_ETIMEOUT), timeouts),
                                        }
                                    }
                                };
                                if !qid_matches(&buf, wire, use_tcp) {
                                    continue;
                                }
                                let summary = summarize(&buf, 0);
                                let (actions, verdict) = on_datagram(
                                    &summary,
                                    server,
                                    use_tcp,
                                    res.opts.attempts,
                                    failover_tries,
                                    &mut res.health.borrow_mut(),
                                );
                                notify(&io, actions);
                                match verdict {
                                    TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                        conn.clear_slot();
                                        server = next;
                                        failover_tries = ft;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::RetryTcp => {
                                        use_tcp = true;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::Deliver => {
                                        conn.clear_slot();
                                        break 'drive (Ok(buf), timeouts);
                                    }
                                }
                            }
                        }
                    }
                }
            };
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

// ===================================================================
// DNS resolver lifecycle (the "application" over the pure-IO reactor).
// Moved out of executor.rs so the reactor names nothing DNS. Speaks the
// reactor's socket primitives (send_when_writable/recv_datagram/recv_stream/
// wait_io) + the neutral lookup.rs decision tables.
// ===================================================================

/// A fire-and-forget side effect the ffi applies after a poll — the one thing a
/// `forbid(unsafe_code)` future cannot do itself: fire the C server-state
/// callback.
pub(crate) enum Effect {
    /// Fire the C server-state callback.
    NotifyServerState { server: usize, ok: bool, tcp: bool },
}

/// The application-owned half of the mailbox: everything the *reactor* need not
/// understand. The reactor drives readiness (`waits`/`deadline`/`fired`/`expired`)
/// and never touches these fields; the DNS lifecycle + the ffi do.
#[derive(Default)]
pub(crate) struct DnsSignals {
    /// Effects the ffi drains + applies after every poll.
    pub effects: Vec<Effect>,
    /// Accumulated timeout count, written by the future before it completes so
    /// the ffi can pass it to the C callback (the host future's `Result` output
    /// has no room for it; the raw path still carries it in `Delivery::Raw`).
    pub timeouts: c_int,
    /// A caller-set request to stop **retrying**: `resolve_query` honours it at
    /// its retry branches (timeout / dead socket), returning terminal instead of
    /// re-sending. A reply already in flight still delivers. Set by
    /// [`ParallelQueries::cancel`]; the *policy* of when to cancel lives in the
    /// caller (e.g. getaddrinfo cancels AAAA once A returns addresses).
    pub cancelled: bool,
}

/// The DNS-application instantiation of the reactor mailbox — the only one the
/// crate builds. The reactor primitives stay generic over `A`; everything DNS
/// speaks `DnsMailbox`.
pub(crate) type DnsMailbox = QueryIo<DnsSignals>;

fn push_effect(io: &Rc<RefCell<DnsMailbox>>, e: Effect) {
    io.borrow_mut().app.effects.push(e);
}

fn notify(io: &Rc<RefCell<DnsMailbox>>, actions: Vec<ReactorAction>) {
    for a in actions {
        match a {
            ReactorAction::NotifyServerState { server, ok, tcp } => {
                push_effect(io, Effect::NotifyServerState { server, ok, tcp })
            }
        }
    }
}

/// What the raw (ares_query / ares_send) lifecycle future delivers to C: reply
/// bytes or a status code, plus the timeout count. (ares_gethostbyname's future
/// returns `Result<Hostent, AresError>` directly and carries its timeout count
/// via the mailbox.)
pub(crate) enum Delivery {
    Raw { result: Result<Vec<u8>, c_int>, timeouts: c_int },
}

/// A server's connect targets, precomputed from the channel config at launch so
/// the future needs no `Transport`/`Client`.
#[derive(Clone)]
pub(crate) struct ServerEndpoint {
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub bind: SocketAddr,
}

/// The retry/timeout knobs a query needs, snapshotted at launch.
#[derive(Clone, Copy)]
pub(crate) struct QueryOpts {
    pub attempts: u32,
    pub timeout: Duration,
    pub failover_chance: u16,
    pub failover_delay: u64,
}

/// Everything an async lifecycle owns. Cloneable `Rc` handles + a config
/// snapshot; the future never borrows the channel.
#[derive(Clone)]
pub(crate) struct Resources {
    pub factory: Rc<dyn SocketFactory>,
    pub health: Rc<RefCell<ServerHealth>>,
    pub endpoints: Rc<Vec<ServerEndpoint>>,
    pub tcp_pool: Rc<RefCell<TcpPool>>,
    pub opts: QueryOpts,
}

/// An owned socket (UDP, or a one-shot TCP probe) with its own TCP reassembly
/// buffer.
struct OwnedSock {
    sock: Rc<dyn Socket>,
    is_tcp: bool,
    rbuf: Vec<u8>,
}

impl OwnedSock {
    fn fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }
    fn recv_msg(&mut self) -> Recv {
        if !self.is_tcp {
            return recv_datagram(&*self.sock);
        }
        // One-shot TCP: drain bytes (IO), then try to pop one length-framed DNS
        // message (framing is DNS). A buffered frame delivers even on a dead
        // socket; else a dead socket is `Dead`, a live-but-incomplete is `Pending`.
        let alive = recv_stream(&*self.sock, &mut self.rbuf);
        match extract_tcp_frame(&mut self.rbuf) {
            Some(frame) => Recv::Msg(frame),
            None if !alive => Recv::Dead,
            None => Recv::Pending,
        }
    }
}

/// A shared TCP connection to one server, cooperatively driven by every future
/// that has an outstanding query on it. Ports the classic reactor's per-fd
/// reassembly buffer + QID demux into an object the futures share.
pub(crate) struct TcpConn {
    sock: Rc<dyn Socket>,
    fd: i32,
    rbuf: Vec<u8>,
    /// qid -> reply slot: `None` = still awaited, `Some` = delivered, waiting to
    /// be taken by that future.
    inbox: HashMap<u16, Option<Vec<u8>>>,
}

impl TcpConn {
    /// Drain the socket, reassemble frames, and route each by its header QID
    /// into `inbox` (frames with no registered waiter are dropped). Returns
    /// `false` if the connection died (EOF / hard error). Idempotent: a sibling
    /// future calling this after the socket is drained just no-ops.
    fn recv_and_route(&mut self) -> bool {
        let alive = recv_stream(&*self.sock, &mut self.rbuf);
        while let Some(frame) = extract_tcp_frame(&mut self.rbuf) {
            if frame.len() >= 2 {
                let qid = u16::from_be_bytes([frame[0], frame[1]]);
                if let Some(slot) = self.inbox.get_mut(&qid) {
                    *slot = Some(frame);
                }
                // Unknown qid → drop (a stray/late reply).
            } else if let Some((_, slot)) = self.inbox.iter_mut().find(|(_, s)| s.is_none()) {
                // A frame too short to carry a qid (malformed): hand it to one
                // awaiting waiter so it fails to parse (EBADRESP), matching
                // qid_matches's acceptance of short buffers.
                *slot = Some(frame);
            }
        }
        alive
    }
}

/// Per-server shared TCP connections. A future consults this before opening a
/// TCP socket so parallel lookups to one server share a connection.
#[derive(Default)]
pub(crate) struct TcpPool(HashMap<usize, Rc<RefCell<TcpConn>>>);

impl TcpPool {
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
    /// Drop a dead connection so the next query to that server reconnects.
    fn remove(&mut self, server: usize) {
        self.0.remove(&server);
    }
    /// Reuse the live connection to `server`, else open + connect one.
    fn get_or_create(
        &mut self,
        server: usize,
        factory: &Rc<dyn SocketFactory>,
        ep: &ServerEndpoint,
    ) -> Result<Rc<RefCell<TcpConn>>, ()> {
        if let Some(c) = self.0.get(&server) {
            return Ok(c.clone());
        }
        let sock = factory.create_tcp(ep.bind).map_err(|_| ())?;
        let _ = sock.connect(ep.tcp_addr); // optimistic (EINPROGRESS → Ok)
        let fd = sock.as_raw_fd();
        let conn = Rc::new(RefCell::new(TcpConn { sock, fd, rbuf: Vec::new(), inbox: HashMap::new() }));
        self.0.insert(server, conn.clone());
        Ok(conn)
    }
}

fn qid_of(payload: &[u8]) -> u16 {
    if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        0
    }
}

/// A query's connection — the socket object the handler drives, tokio-style.
/// It **owns its mailbox** (`io`), so `send`/`recv` take no reactor handle:
/// `conn.send(&ep, bytes, deadline).await` / `conn.recv(deadline).await`, just
/// like `socket.recv(..).await`. `wire` is the transport: an owned socket (UDP
/// primary, or a one-shot probe) or a shared TCP connection multiplexed by `qid`;
/// the datagram-vs-QID-demuxed-stream asymmetry is hidden behind the methods.
struct Conn {
    io: Rc<RefCell<DnsMailbox>>,
    wire: Wire,
}

enum Wire {
    Owned(OwnedSock),
    Shared(Rc<RefCell<TcpConn>>, u16),
}

impl Conn {
    fn fd(&self) -> i32 {
        match &self.wire {
            Wire::Owned(s) => s.fd(),
            Wire::Shared(c, _) => c.borrow().fd,
        }
    }

    fn is_tcp(&self) -> bool {
        match &self.wire {
            Wire::Owned(s) => s.is_tcp,
            Wire::Shared(..) => true,
        }
    }

    /// Register this query's qid on a shared TCP conn before sending, so a
    /// sibling future's read routes our reply into our slot. No-op for owned.
    fn register(&self) {
        if let Wire::Shared(c, qid) = &self.wire {
            c.borrow_mut().inbox.insert(*qid, None);
        }
    }

    /// Drop this query's slot on a shared TCP conn (on retry/deliver) so its
    /// inbox doesn't accumulate stale entries. No-op for owned. (was `clear_tcp_slot`.)
    fn clear_slot(&self) {
        if let Wire::Shared(c, qid) = &self.wire {
            c.borrow_mut().inbox.remove(qid);
        }
    }

    /// Await writability, then send `framed` once (WouldBlock re-awaits, matching
    /// the classic `Writing`→`Reading` flow). UDP connects lazily here; TCP was
    /// connected at create. `false` on a hard failure or timeout. (was `send_primary`.)
    async fn send(&self, ep: &ServerEndpoint, framed: &[u8], deadline: Instant) -> bool {
        let sock: Rc<dyn Socket> = match &self.wire {
            Wire::Owned(s) => {
                let _ = s.sock.connect(ep.udp_addr);
                s.sock.clone()
            }
            Wire::Shared(c, _) => c.borrow().sock.clone(),
        };
        send_when_writable(&self.io, &*sock, framed, deadline).await
    }

    /// One non-blocking read of this conn's next reply: a UDP datagram / one-shot
    /// TCP frame (owned), or this qid's routed frame off the shared TCP conn.
    /// `Recv::Pending` = nothing yet (WouldBlock / incomplete). (was `recv_primary`.)
    fn read(&mut self) -> Recv {
        match &mut self.wire {
            Wire::Owned(s) => s.recv_msg(),
            Wire::Shared(c, qid) => {
                let mut conn = c.borrow_mut();
                let alive = conn.recv_and_route();
                match conn.inbox.get_mut(qid).and_then(|slot| slot.take()) {
                    Some(msg) => Recv::Msg(msg),
                    None if !alive => Recv::Dead,
                    None => Recv::Pending,
                }
            }
        }
    }

    /// The readiness-driven recv arm for `select2`/`select3`: on this conn's fd
    /// firing, do one non-blocking [`read`](Self::read). Uses the conn's own mailbox.
    fn recv_arm(&mut self) -> std::task::Poll<RecvReady> {
        let fd = self.fd();
        let io = self.io.clone();
        poll_recv(&io, fd, || self.read())
    }

    /// tokio-style `conn.recv(deadline).await`: await this conn's next reply,
    /// bounded by `deadline` (a 2-arm select over the conn's own mailbox,
    /// deadline-biased to match the classic expiry-preempts-read order).
    async fn recv(&mut self, deadline: Instant) -> RecvOutcome {
        let io = self.io.clone();
        match select2(&io, |io| poll_deadline(io, deadline), |_| self.recv_arm()).await {
            Which2::A(()) => RecvOutcome::Timeout,
            Which2::B(RecvReady::Msg(b)) => RecvOutcome::Reply(b),
            Which2::B(RecvReady::Dead) => RecvOutcome::Dead,
        }
    }
}

/// The outcome of [`Conn::recv`]: a reply's bytes, a deadline, or a dead socket.
enum RecvOutcome {
    Reply(Vec<u8>),
    Timeout,
    Dead,
}

/// One `select` result in the probe ops (`gethostbyname`/`search`): which of the
/// raced arms — the concurrent failover probe, the deadline, or the primary
/// reply — fired. Unifies the 3-arm (probe live) and 2-arm (no probe) branches.
enum ReplyEvent {
    Probe(RecvReady),
    Deadline,
    Primary(RecvReady),
}

/// A one-shot failover probe running alongside the primary query.
struct Probe {
    conn: Conn,
    server: usize,
    deadline: Instant,
    payload: BytesMut, // framed form actually sent (for qid_matches)
}

/// Fold a probe reply into server health (the old `on_probe_reply` verdict),
/// emitted as effects. `None` reply = the probe timed out (failure timestamp only).
fn settle_probe(io: &Rc<RefCell<DnsMailbox>>, res: &Resources, probe: &Probe, reply: Option<&[u8]>) {
    let mut health = res.health.borrow_mut();
    match reply {
        Some(buf) => {
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0xff };
            if rcode == 0 || rcode == 3 {
                if health.record_success(probe.server) {
                    drop(health);
                    push_effect(io, Effect::NotifyServerState { server: probe.server, ok: true, tcp: probe.conn.is_tcp() });
                }
            } else if health.record_failure(probe.server) {
                drop(health);
                push_effect(io, Effect::NotifyServerState { server: probe.server, ok: false, tcp: probe.conn.is_tcp() });
            }
        }
        None => health.record_failure_time(probe.server),
    }
}

/// One query's `(reply-or-status, timeout-count)` outcome.
type QueryOutcome = (Result<Vec<u8>, c_int>, c_int);
type QueryFut = Pin<Box<dyn Future<Output = QueryOutcome>>>;

/// One sub-query inside a [`ParallelQueries`] set.
struct ParSub {
    io: Rc<RefCell<DnsMailbox>>,
    fut: Option<QueryFut>,
    result: Option<QueryOutcome>,
}

/// N query futures driven concurrently over one shared mailbox — the generic
/// multiplex **mechanism** for parallel lookups (getaddrinfo's A+AAAA). This
/// type has **no getaddrinfo knowledge**: the caller `step`s it and applies its
/// own retry/cancel **policy** (e.g. "cancel AAAA once A returns addresses").
///
/// Each sub-query is a full [`resolve_query`] on its own sub-mailbox; `step`
/// merges their published waits/effects into the outer mailbox the ffi drives,
/// awaits it, and routes readiness back by fd + each sub's own deadline.
pub(crate) struct ParallelQueries {
    io: Rc<RefCell<DnsMailbox>>,
    subs: Vec<ParSub>,
}

impl ParallelQueries {
    /// Build one `resolve_query` future per `(payload, use_tcp)` (no probe).
    pub(crate) fn new(io: Rc<RefCell<DnsMailbox>>, res: Resources, payloads: Vec<(BytesMut, bool)>) -> Self {
        let subs = payloads
            .into_iter()
            .map(|(payload, use_tcp)| {
                let sub_io = Rc::new(RefCell::new(DnsMailbox::default()));
                // Inlined single-query driver (WET) on this sub-mailbox — the
                // getaddrinfo A/AAAA sub-queries (no probe). In an async block
                // `return` yields the future's output directly.
                let io = sub_io.clone();
                let res = res.clone();
                let fut = Box::pin(async move {
                    let mut use_tcp = use_tcp;
                    let mut timeouts: c_int = 0;
                    let mut tries: u32 = 0;
                    let mut failover_tries: u32 = 0;
                    let qid = qid_of(&payload);
                    let mut server = res.health.borrow().pick_next();
                    'attempt: loop {
                        // Inlined connect-with-failover (WET).
                        let (mut conn, si) = 'connect: {
                            let mut s = server;
                            for _ in 0..res.opts.attempts.max(1) {
                                let Some(ep) = res.endpoints.get(s) else { break };
                                let wire = if use_tcp {
                                    res.tcp_pool.borrow_mut().get_or_create(s, &res.factory, ep).ok().map(|c| Wire::Shared(c, qid))
                                } else {
                                    res.factory.create_udp(ep.bind).ok().map(|sk| Wire::Owned(OwnedSock { sock: sk, is_tcp: false, rbuf: Vec::new() }))
                                };
                                if let Some(wire) = wire {
                                    break 'connect (Conn { io: io.clone(), wire }, s);
                                }
                                if res.health.borrow().len() > 1 {
                                    res.health.borrow_mut().record_failure(s);
                                    s = res.health.borrow().pick_next();
                                }
                            }
                            return (Err(ARES_ECONNREFUSED), timeouts);
                        };
                        server = si;
                        let ep = res.endpoints[server].clone();
                        // The wire buffer for this attempt's transport: TCP needs the framed
                        // copy, UDP sends the payload as-is (borrowed — no clone).
                        let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                        let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                        let deadline = Instant::now() + res.opts.timeout;

                        // Register this qid on the shared TCP conn before sending, so a sibling
                        // future's read routes our reply into our slot.
                        conn.register();
                        if !conn.send(&ep, wire, deadline).await {
                            // Send failed (a hard socket error): recreate the socket and retry,
                            // bounded by the attempt budget — mirrors the classic write_impl's
                            // recreate-and-resend. (SetReplyAndFailSend fails one send, then the
                            // retry succeeds.)
                            conn.clear_slot();
                            if use_tcp {
                                res.tcp_pool.borrow_mut().remove(server);
                            }
                            if tries + 1 < res.opts.attempts.max(1) {
                                tries += 1;
                                if res.health.borrow().len() > 1 {
                                    res.health.borrow_mut().record_failure(server);
                                    server = res.health.borrow().pick_next();
                                }
                                continue 'attempt;
                            }
                            return (Err(ARES_ECONNREFUSED), timeouts);
                        }

                        // Await the primary reply, servicing the probe socket concurrently.
                        loop {
                            match conn.recv(deadline).await {
                                RecvOutcome::Reply(buf) => {
                                    if !qid_matches(&buf, wire, use_tcp) {
                                        continue; // stray datagram — await the next reply
                                    }
                                    let summary = summarize(&buf, 0);
                                    let (actions, verdict) = on_datagram(
                                        &summary,
                                        server,
                                        use_tcp,
                                        res.opts.attempts,
                                        failover_tries,
                                        &mut res.health.borrow_mut(),
                                    );
                                    notify(&io, actions);
                                    match verdict {
                                        TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                            conn.clear_slot();
                                            server = next;
                                            failover_tries = ft;
                                            continue 'attempt;
                                        }
                                        TaskVerdict::RetryTcp => {
                                            use_tcp = true;
                                            continue 'attempt;
                                        }
                                        TaskVerdict::Deliver => {
                                            conn.clear_slot();
                                            return (Ok(buf), timeouts);
                                        }
                                    }
                                }
                                RecvOutcome::Timeout => {
                                    conn.clear_slot();
                                    if io.borrow().app.cancelled {
                                        return (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                                    match verdict {
                                        TimeoutVerdict::Retry { server: next } => {
                                            tries += 1;
                                            timeouts += 1;
                                            server = next;
                                            continue 'attempt;
                                        }
                                        TimeoutVerdict::Expire => return (Err(ARES_ETIMEOUT), timeouts),
                                    }
                                }
                                RecvOutcome::Dead => {
                                    conn.clear_slot();
                                    if use_tcp {
                                        res.tcp_pool.borrow_mut().remove(server);
                                    }
                                    if io.borrow().app.cancelled {
                                        return (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, res.opts.attempts, server, &mut res.health.borrow_mut());
                                    match verdict {
                                        TimeoutVerdict::Retry { server: next } => {
                                            tries += 1;
                                            timeouts += 1;
                                            server = next;
                                            continue 'attempt;
                                        }
                                        TimeoutVerdict::Expire => return (Err(ARES_ETIMEOUT), timeouts),
                                    }
                                }
                            }
                        }
                    }
                }) as QueryFut;
                ParSub { io: sub_io, fut: Some(fut), result: None }
            })
            .collect();
        ParallelQueries { io, subs }
    }

    /// The settled outcome of query `i`, or `None` if still running or cancelled.
    pub(crate) fn result(&self, i: usize) -> Option<&QueryOutcome> {
        self.subs[i].result.as_ref()
    }

    /// Cancel query `i`'s **retries**: it won't be re-sent after its current
    /// attempt, but a reply already in flight still delivers. (Implemented via
    /// the sub-mailbox `cancelled` flag `resolve_query` honours.)
    pub(crate) fn cancel(&mut self, i: usize) {
        self.subs[i].io.borrow_mut().app.cancelled = true;
    }

    /// Every query has settled.
    pub(crate) fn all_done(&self) -> bool {
        self.subs.iter().all(|s| s.result.is_some())
    }

    /// Advance every live sub-future one readiness cycle.
    pub(crate) async fn step(&mut self) {
        let waker = noop_waker();
        {
            let mut cx = Context::from_waker(&waker);
            for s in &mut self.subs {
                if let Some(fut) = &mut s.fut {
                    if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
                        s.result = Some(r);
                        s.fut = None;
                    }
                }
            }
        }
        if self.all_done() {
            return;
        }

        // Merge every live sub's waits + earliest deadline into the outer mailbox,
        // and lift its effects up so the ffi applies them.
        let mut merged: Vec<Wait> = Vec::new();
        let mut deadline: Option<Instant> = None;
        for s in &self.subs {
            if s.fut.is_none() {
                continue;
            }
            let drained: Vec<Effect> = {
                let mut sub = s.io.borrow_mut();
                merged.extend(sub.waits.iter().copied());
                if let Some(d) = sub.deadline {
                    deadline = Some(deadline.map_or(d, |m: Instant| m.min(d)));
                }
                std::mem::take(&mut sub.app.effects)
            };
            self.io.borrow_mut().app.effects.extend(drained);
        }
        let deadline = match deadline {
            Some(d) => d,
            None => return, // nothing published a wait — avoid an unbounded await
        };

        // Await the outer mailbox (the ffi sets fired/expired against `merged`),
        // then route readiness back to each live sub.
        let woke = wait_io(&self.io, &merged, deadline).await;
        let now = Instant::now();
        for s in &self.subs {
            if s.fut.is_none() {
                continue;
            }
            let mut sub = s.io.borrow_mut();
            let wants: Vec<i32> = sub.waits.iter().map(|w| w.fd).collect();
            sub.fired = woke.fds.iter().copied().filter(|fd| wants.contains(fd)).collect();
            sub.expired = sub.deadline.is_some_and(|d| now >= d);
        }
    }
}
