//! `AsyncClient` — the shared config snapshot every async resolver lifecycle
//! owns, plus the lifecycles themselves as methods. Consolidates what used to be
//! five near-duplicate per-op context structs (`HostCtx`/`HostByAddrCtx`/
//! `NameinfoCtx`/`SearchCtx`/`AddrInfoCtx`) and five free `async fn`s.
//!
//! `AsyncClient` is also THE channel state: the ffi `ChannelData` wraps one
//! instance (config, options, server list, shared pools), and every entry
//! shim mints a per-lookup copy via [`AsyncClient::derive`] (fresh mailbox,
//! shared `Rc`s). Lifecycle methods take `self: Rc<Self>` so the spawned
//! futures are `'static` (they are `Box::pin`'d into the ffi `AsyncKind`)
//! while still allowing cheap sharing and nested calls
//! (`self.clone().other(…)`). Also here: the entry preflights and the DNS
//! wire builders; see the section markers.

use std::cell::RefCell;
use std::ffi::{c_int, CString};
use std::io;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use rand::Rng;

use crate::core::cache::QueryCache;
use crate::async_runtime::conn::{Conn, TcpPool};
use crate::async_runtime::executor::{noop_waker, poll_timeout, select3, wait_io, QueryIo, Wait, Which3};
use crate::core::hostent::Hostent;
use crate::core::hostfile::{AddressFamily, HostLookup, Hosts};
use crate::core::lookup::{
    is_localhost, is_onion_domain, on_datagram, on_timeout, qid_matches,
    summarize, ReactorAction, SearchPlan, ServerHealth, TaskVerdict, TimeoutVerdict, AF_INET,
    AF_INET6, AF_UNSPEC, RTYPE_A, RTYPE_AAAA,
};
use crate::core::packets::AddrRecord;
use crate::core::response::{addr_reply, push_synthetic_ptr, ParsedResponse, ReplyRequire};
use crate::core::services::Services;
use crate::async_runtime::socket::SocketFactory;
use crate::core::sortlist::{apply_sortlist, SortlistEntry};
use crate::core::sysconfig::SysConfig;
use crate::core::AresError;
use crate::ffi::ares_options::{
    ARES_FLAG_EDNS, ARES_FLAG_PRIMARY, ARES_FLAG_USEVC, ARES_OPT_DOMAINS, ARES_OPT_FLAGS,
    ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS,
    ARES_OPT_NOROTATE, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF, ARES_OPT_ROTATE,
    ARES_OPT_SERVERS, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SORTLIST, ARES_OPT_TCP_PORT,
    ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
    ARES_OPT_UDP_PORT,
};
use crate::ffi::error::{
    ARES_ECONNREFUSED, ARES_EBADFLAGS, ARES_EBADNAME, ARES_EBADQUERY, ARES_EBADSTR, ARES_EFILE,
    ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED, ARES_ESERVFAIL,
    ARES_ETIMEOUT,
};
use crate::ffi::{
    ARES_NI_DGRAM, ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NOFQDN,
    ARES_NI_NUMERICHOST, ARES_NI_NUMERICSCOPE, ARES_NI_NUMERICSERV, ARES_SUCCESS, RECORD_TYPE_PTR,
};

/// THE channel: the pure channel state the ffi `ChannelData` wraps (config,
/// health/cache bookkeeping, shared socket pools — the shims only marshal C
/// values in and out) *and* the resolver client the async lifecycles run on.
/// One instance is owned by the channel; every lookup runs on a per-lookup
/// copy minted by [`derive`](Self::derive) — same shared `Rc`s, a fresh
/// [`QueryIo`] mailbox — so concurrent lookups on a channel never share a
/// `QueryIo`. The channel-owned instance's `io` is an inert placeholder. The
/// ffi grabs the derived copy's `self.io.clone()` to drive that mailbox;
/// nested inline sub-calls (`self.clone().other(…)`) share it.
pub(crate) struct AsyncClient {
    /// The system/user resolver config (resolv.conf shape: nameservers,
    /// search domains, options, per-server TCP port overrides).
    pub config: SysConfig,
    pub factory: Rc<dyn SocketFactory>,
    /// The `/etc/hosts` table, lazily loaded once (see [`AsyncClient::hosts`]);
    /// always `Some` on a lookup copy ([`derive`](Self::derive) loads it).
    hosts: Option<Rc<Hosts>>,
    pub default_udp_port: u16,
    pub default_tcp_port: u16,
    /// Shared with the in-flight lookup futures (`Rc<RefCell<_>>`) so
    /// failover accounting and the probe agree across queries.
    pub health: Rc<RefCell<ServerHealth>>,
    pub sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    pub maxtimeout: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    /// TTL-bounded reply cache, shared with the in-flight lookups and the
    /// dnsrec post-delivery hook.
    pub cache: Rc<RefCell<QueryCache>>,
    /// Shared TCP connections (parallel lookups to one server share a socket).
    pub tcp_pool: Rc<RefCell<TcpPool>>,
    /// Per-server connect endpoints, snapshotted from `config` by `derive` so
    /// the lookup futures never re-read the config.
    pub endpoints: Rc<Vec<ServerEndpoint>>,
    pub server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub server_failover_retry_delay: u64,  // milliseconds
    /// This lookup's mailbox (inert on the channel-owned instance).
    pub io: Rc<RefCell<DnsMailbox>>,
}

impl AsyncClient {
    /// Mint the per-lookup copy every entry shim runs on: clone the config +
    /// shared `Rc`s, load the hosts table, snapshot the per-server endpoints
    /// from the current config, and mint a **fresh** mailbox so each
    /// concurrent lookup owns its own `QueryIo`. Cloning `self.io` here
    /// instead would make every lookup on the channel share one mailbox — the
    /// bug this avoids.
    pub(crate) fn derive(&mut self) -> Rc<Self> {
        let hosts = self.hosts();
        Rc::new(AsyncClient {
            config: self.config.clone(),
            factory: self.factory.clone(),
            hosts: Some(hosts),
            default_udp_port: self.default_udp_port,
            default_tcp_port: self.default_tcp_port,
            health: self.health.clone(),
            sortlist: self.sortlist.clone(),
            flags: self.flags,
            maxtimeout: self.maxtimeout,
            lookups: self.lookups.clone(),
            resolvconf_path: self.resolvconf_path.clone(),
            hosts_path: self.hosts_path.clone(),
            cache: self.cache.clone(),
            tcp_pool: self.tcp_pool.clone(),
            endpoints: Rc::new(self.endpoint_snapshot()),
            server_failover_retry_chance: self.server_failover_retry_chance,
            server_failover_retry_delay: self.server_failover_retry_delay,
            io: Rc::new(RefCell::new(DnsMailbox::default())),
        })
    }

    /// The hosts table as seen by a lookup copy (always loaded by `derive`;
    /// empty only on the channel-owned instance before first use).
    fn hostsfile(&self) -> Rc<Hosts> {
        self.hosts.clone().unwrap_or_default()
    }

    /// ares_query / ares_send: one query delivered raw. Keeps the historical
    /// UDP-start behavior (`use_tcp = false`); unlike the resolver ops it does
    /// **not** honor `ARES_FLAG_USEVC`. (Replaces the free `raw_lifecycle`.)
    pub(crate) async fn query_raw(self: Rc<Self>, payload: BytesMut) -> Delivery {
        // Inlined single-query driver (WET, see the module note): pick server →
        // socket → send → recv → QID-match → TC/failover/timeout verdicts. The raw
        // path: UDP-start (`use_tcp = false`), no probe, no USEVC. The connection
        // is a `Conn` with async `send`/`recv`; its shared-TCP slot is RAII.
        let (result, timeouts) = 'drive: {
            let io = self.io.clone();
            let opts = self.opts();
            let mut use_tcp = false;
            let mut timeouts: c_int = 0;
            let mut tries: u32 = 0;
            let mut failover_tries: u32 = 0;
            let qid = qid_of(&payload);
            let mut server = self.health.borrow().pick_next();
            'attempt: loop {
                // Inlined connect-with-failover (WET): create + connect the socket
                // for `server`, retrying across servers on creation failure.
                let (mut conn, si) = 'connect: {
                    let mut s = server;
                    for _ in 0..opts.attempts.max(1) {
                        let Some(ep) = self.endpoints.get(s) else { break };
                        let conn = if use_tcp {
                            self.tcp_pool.borrow_mut().get_or_create(s, &self.factory, ep.bind, ep.tcp_addr).ok().map(|c| Conn::shared(io.clone(), c, qid))
                        } else {
                            self.factory.create_udp(ep.bind).ok().map(|sk| {
                                let _ = sk.connect(ep.udp_addr);
                                Conn::datagram(io.clone(), sk)
                            })
                        };
                        if let Some(conn) = conn {
                            break 'connect (conn, s);
                        }
                        if self.health.borrow().len() > 1 {
                            self.health.borrow_mut().record_failure(s);
                            s = self.health.borrow().pick_next();
                        }
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                };
                server = si;
                let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                let timeout = Instant::now() + opts.timeout;
                if conn.send(wire, timeout).await.is_err() {
                    if use_tcp {
                        self.tcp_pool.borrow_mut().remove(server);
                    }
                    if tries + 1 < opts.attempts.max(1) {
                        tries += 1;
                        if self.health.borrow().len() > 1 {
                            self.health.borrow_mut().record_failure(server);
                            server = self.health.borrow().pick_next();
                        }
                        continue 'attempt;
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                }
                loop {
                    match conn.recv(timeout).await {
                        Ok(buf) => {
                            if !qid_matches(&buf, wire, use_tcp) {
                                continue; // stray datagram — await the next reply
                            }
                            let summary = summarize(&buf, 0);
                            let (actions, verdict) = on_datagram(
                                &summary,
                                server,
                                use_tcp,
                                opts.attempts,
                                failover_tries,
                                &mut self.health.borrow_mut(),
                            );
                            notify(&io, actions);
                            match verdict {
                                TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                    server = next;
                                    failover_tries = ft;
                                    continue 'attempt;
                                }
                                TaskVerdict::RetryTcp => {
                                    use_tcp = true;
                                    continue 'attempt;
                                }
                                TaskVerdict::Deliver => {
                                    break 'drive (Ok(buf), timeouts);
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                        Err(_) => {
                            // Dead socket (EOF / hard error).
                            if use_tcp {
                                self.tcp_pool.borrow_mut().remove(server);
                            }
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
        if let Some(lookup) = self.hostsfile().lookup(&hostname, filter) {
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

        if self.endpoints.is_empty() {
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
        let mut names: Vec<String> = if dots < self.config.options.ndots && !self.config.search.is_empty() {
            let mut v: Vec<String> = self.config.search.iter().map(|d| format!("{resolved}.{d}")).collect();
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
                let opts = self.opts();
                let mut use_tcp = self.config.options.use_vc;
                let mut timeouts: c_int = 0;
                let mut tries: u32 = 0;
                let mut failover_tries: u32 = 0;
                let qid = qid_of(&payload);
                let mut server = self.health.borrow().pick_next();
                let mut probe = probe_payload.and_then(|pp| {
                    // Inlined probe setup (WET): a one-shot failover probe to a stale
                    // server, raced alongside the primary. `None` if failover is off /
                    // no server is due / a socket fails.
                    if opts.failover_chance == 0 {
                        return None;
                    }
                    let primary_server = self.health.borrow().pick_next();
                    let pserver = self.health.borrow().pick_probe(opts.failover_delay, primary_server)?;
                    let ep = self.endpoints.get(pserver)?;
                    let sk = if use_tcp {
                        let sk = self.factory.create_tcp(ep.bind).ok()?;
                        let _ = sk.connect(ep.tcp_addr);
                        sk
                    } else {
                        let sk = self.factory.create_udp(ep.bind).ok()?;
                        let _ = sk.connect(ep.udp_addr);
                        sk
                    };
                    let framed = if use_tcp { frame_tcp(&pp) } else { pp.clone() };
                    let _ = sk.send(&framed);
                    Some(Probe {
                        conn: if use_tcp {
                            Conn::stream(io.clone(), sk, dns_frame)
                        } else {
                            Conn::datagram(io.clone(), sk)
                        },
                        server: pserver,
                        timeout: Instant::now() + opts.timeout,
                        payload: framed,
                    })
                });
                'attempt: loop {
                    // Inlined connect-with-failover (WET).
                    let (mut conn, si) = 'connect: {
                        let mut s = server;
                        for _ in 0..opts.attempts.max(1) {
                            let Some(ep) = self.endpoints.get(s) else { break };
                            let conn = if use_tcp {
                                self.tcp_pool.borrow_mut().get_or_create(s, &self.factory, ep.bind, ep.tcp_addr).ok().map(|c| Conn::shared(io.clone(), c, qid))
                            } else {
                                self.factory.create_udp(ep.bind).ok().map(|sk| {
                                    let _ = sk.connect(ep.udp_addr);
                                    Conn::datagram(io.clone(), sk)
                                })
                            };
                            if let Some(conn) = conn {
                                break 'connect (conn, s);
                            }
                            if self.health.borrow().len() > 1 {
                                self.health.borrow_mut().record_failure(s);
                                s = self.health.borrow().pick_next();
                            }
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    };
                    server = si;
                    let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                    let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                    let timeout = Instant::now() + opts.timeout;
                    if conn.send(wire, timeout).await.is_err() {
                        if use_tcp {
                            self.tcp_pool.borrow_mut().remove(server);
                        }
                        if tries + 1 < opts.attempts.max(1) {
                            tries += 1;
                            if self.health.borrow().len() > 1 {
                                self.health.borrow_mut().record_failure(server);
                                server = self.health.borrow().pick_next();
                            }
                            continue 'attempt;
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    }
                    loop {
                        // Race the live probe, the timeout, and the primary reply.
                        // Biased probe -> timeout -> primary (expiry preempts a
                        // same-cycle primary read, as before). No probe => 2-arm recv.
                        let event = if let Some(p) = probe.as_mut() {
                            let wake_timeout = timeout.min(p.timeout);
                            match select3(&io, |_| p.conn.recv_arm(), |io| poll_timeout(io, wake_timeout), |_| conn.recv_arm()).await {
                                Which3::A(r) => ReplyEvent::Probe(r),
                                Which3::B(()) => ReplyEvent::Timeout,
                                Which3::C(r) => ReplyEvent::Primary(r),
                            }
                        } else {
                            match conn.recv(timeout).await {
                                Err(e) if e.kind() == io::ErrorKind::TimedOut => ReplyEvent::Timeout,
                                r => ReplyEvent::Primary(r),
                            }
                        };
                        match event {
                            ReplyEvent::Probe(r) => {
                                match r {
                                    Ok(buf) => {
                                        if probe.as_ref().is_some_and(|p| qid_matches(&buf, &p.payload, p.conn.is_tcp())) {
                                            let p_taken = probe.take().unwrap();
                                            settle_probe(&io, &self.health, &p_taken, Some(&buf));
                                        }
                                    }
                                    Err(_) => probe = None, // probe socket died
                                }
                                continue;
                            }
                            ReplyEvent::Timeout => {
                                let now = Instant::now();
                                if let Some(p) = &probe {
                                    if now >= p.timeout {
                                        let p_taken = probe.take().unwrap();
                                        settle_probe(&io, &self.health, &p_taken, None);
                                    }
                                }
                                if now >= timeout {
                                    if io.borrow().app.cancelled {
                                        break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                                    Ok(buf) => buf,
                                    Err(_) => {
                                        // Dead socket (EOF / hard error).
                                        if use_tcp {
                                            self.tcp_pool.borrow_mut().remove(server);
                                        }
                                        if io.borrow().app.cancelled {
                                            break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                        }
                                        notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                        let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                                    opts.attempts,
                                    failover_tries,
                                    &mut self.health.borrow_mut(),
                                );
                                notify(&io, actions);
                                match verdict {
                                    TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                        server = next;
                                        failover_tries = ft;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::RetryTcp => {
                                        use_tcp = true;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::Deliver => {
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
        if let Some(lookup) = self.hostsfile().reverse_lookup(ip) {
            return Ok(Hostent::from_lookup(lookup));
        }

        if self.endpoints.is_empty() {
            return Err(ARES_ENOSERVER.into());
        }

        // ===== DNS phase: single PTR query =====
        let payload = dns_query_payload(&rdns_name(ip), RECORD_TYPE_PTR);
        let (result, io_timeouts) = 'drive: {
            let io = self.io.clone();
            let opts = self.opts();
            let mut use_tcp = false;
            let mut timeouts: c_int = 0;
            let mut tries: u32 = 0;
            let mut failover_tries: u32 = 0;
            let qid = qid_of(&payload);
            let mut server = self.health.borrow().pick_next();
            'attempt: loop {
                // Inlined connect-with-failover (WET): create + connect the socket
                // for `server`, retrying across servers on creation failure.
                let (mut conn, si) = 'connect: {
                    let mut s = server;
                    for _ in 0..opts.attempts.max(1) {
                        let Some(ep) = self.endpoints.get(s) else { break };
                        let conn = if use_tcp {
                            self.tcp_pool.borrow_mut().get_or_create(s, &self.factory, ep.bind, ep.tcp_addr).ok().map(|c| Conn::shared(io.clone(), c, qid))
                        } else {
                            self.factory.create_udp(ep.bind).ok().map(|sk| {
                                let _ = sk.connect(ep.udp_addr);
                                Conn::datagram(io.clone(), sk)
                            })
                        };
                        if let Some(conn) = conn {
                            break 'connect (conn, s);
                        }
                        if self.health.borrow().len() > 1 {
                            self.health.borrow_mut().record_failure(s);
                            s = self.health.borrow().pick_next();
                        }
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                };
                server = si;
                let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                let timeout = Instant::now() + opts.timeout;
                if conn.send(wire, timeout).await.is_err() {
                    if use_tcp {
                        self.tcp_pool.borrow_mut().remove(server);
                    }
                    if tries + 1 < opts.attempts.max(1) {
                        tries += 1;
                        if self.health.borrow().len() > 1 {
                            self.health.borrow_mut().record_failure(server);
                            server = self.health.borrow().pick_next();
                        }
                        continue 'attempt;
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                }
                loop {
                    match conn.recv(timeout).await {
                        Ok(buf) => {
                            if !qid_matches(&buf, wire, use_tcp) {
                                continue; // stray datagram — await the next reply
                            }
                            let summary = summarize(&buf, 0);
                            let (actions, verdict) = on_datagram(
                                &summary,
                                server,
                                use_tcp,
                                opts.attempts,
                                failover_tries,
                                &mut self.health.borrow_mut(),
                            );
                            notify(&io, actions);
                            match verdict {
                                TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                    server = next;
                                    failover_tries = ft;
                                    continue 'attempt;
                                }
                                TaskVerdict::RetryTcp => {
                                    use_tcp = true;
                                    continue 'attempt;
                                }
                                TaskVerdict::Deliver => {
                                    break 'drive (Ok(buf), timeouts);
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                        Err(_) => {
                            // Dead socket (EOF / hard error).
                            if use_tcp {
                                self.tcp_pool.borrow_mut().remove(server);
                            }
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                let hostent = on_host_reply(Ok(&buf), RECORD_TYPE_PTR, family, Some(ip))?;
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

        if self.endpoints.is_empty() {
            return NameinfoReply { status: ARES_ENOSERVER.into(), node: None, service: None, timeouts: 0 };
        }

        // ===== DNS phase: single PTR query =====
        let payload = dns_query_payload(&rdns_name(addr.ip), RECORD_TYPE_PTR);
        let (result, io_timeouts) = 'drive: {
            let io = self.io.clone();
            let opts = self.opts();
            let mut use_tcp = false;
            let mut timeouts: c_int = 0;
            let mut tries: u32 = 0;
            let mut failover_tries: u32 = 0;
            let qid = qid_of(&payload);
            let mut server = self.health.borrow().pick_next();
            'attempt: loop {
                // Inlined connect-with-failover (WET): create + connect the socket
                // for `server`, retrying across servers on creation failure.
                let (mut conn, si) = 'connect: {
                    let mut s = server;
                    for _ in 0..opts.attempts.max(1) {
                        let Some(ep) = self.endpoints.get(s) else { break };
                        let conn = if use_tcp {
                            self.tcp_pool.borrow_mut().get_or_create(s, &self.factory, ep.bind, ep.tcp_addr).ok().map(|c| Conn::shared(io.clone(), c, qid))
                        } else {
                            self.factory.create_udp(ep.bind).ok().map(|sk| {
                                let _ = sk.connect(ep.udp_addr);
                                Conn::datagram(io.clone(), sk)
                            })
                        };
                        if let Some(conn) = conn {
                            break 'connect (conn, s);
                        }
                        if self.health.borrow().len() > 1 {
                            self.health.borrow_mut().record_failure(s);
                            s = self.health.borrow().pick_next();
                        }
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                };
                server = si;
                let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                let timeout = Instant::now() + opts.timeout;
                if conn.send(wire, timeout).await.is_err() {
                    if use_tcp {
                        self.tcp_pool.borrow_mut().remove(server);
                    }
                    if tries + 1 < opts.attempts.max(1) {
                        tries += 1;
                        if self.health.borrow().len() > 1 {
                            self.health.borrow_mut().record_failure(server);
                            server = self.health.borrow().pick_next();
                        }
                        continue 'attempt;
                    }
                    break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                }
                loop {
                    match conn.recv(timeout).await {
                        Ok(buf) => {
                            if !qid_matches(&buf, wire, use_tcp) {
                                continue; // stray datagram — await the next reply
                            }
                            let summary = summarize(&buf, 0);
                            let (actions, verdict) = on_datagram(
                                &summary,
                                server,
                                use_tcp,
                                opts.attempts,
                                failover_tries,
                                &mut self.health.borrow_mut(),
                            );
                            notify(&io, actions);
                            match verdict {
                                TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                    server = next;
                                    failover_tries = ft;
                                    continue 'attempt;
                                }
                                TaskVerdict::RetryTcp => {
                                    use_tcp = true;
                                    continue 'attempt;
                                }
                                TaskVerdict::Deliver => {
                                    break 'drive (Ok(buf), timeouts);
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                        Err(_) => {
                            // Dead socket (EOF / hard error).
                            if use_tcp {
                                self.tcp_pool.borrow_mut().remove(server);
                            }
                            if io.borrow().app.cancelled {
                                break 'drive (Err(ARES_ETIMEOUT), timeouts);
                            }
                            notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                            let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
    /// mapping mirrors the old search state machine step.
    pub(crate) async fn search(
        self: Rc<Self>,
        name: String,
        dnstype: u16,
        retry_server_error: bool,
    ) -> Delivery {
        if self.endpoints.is_empty() {
            return Delivery::Raw { result: Err(ARES_ENOSERVER), timeouts: 0 };
        }

        let mut plan = SearchPlan::for_search(&name, self.config.options.ndots, &self.config.search);
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
                let opts = self.opts();
                let mut use_tcp = self.config.options.use_vc;
                let mut timeouts: c_int = 0;
                let mut tries: u32 = 0;
                let mut failover_tries: u32 = 0;
                let qid = qid_of(&payload);
                let mut server = self.health.borrow().pick_next();
                let mut probe = probe_payload.and_then(|pp| {
                    // Inlined probe setup (WET): a one-shot failover probe to a stale
                    // server, raced alongside the primary. `None` if failover is off /
                    // no server is due / a socket fails.
                    if opts.failover_chance == 0 {
                        return None;
                    }
                    let primary_server = self.health.borrow().pick_next();
                    let pserver = self.health.borrow().pick_probe(opts.failover_delay, primary_server)?;
                    let ep = self.endpoints.get(pserver)?;
                    let sk = if use_tcp {
                        let sk = self.factory.create_tcp(ep.bind).ok()?;
                        let _ = sk.connect(ep.tcp_addr);
                        sk
                    } else {
                        let sk = self.factory.create_udp(ep.bind).ok()?;
                        let _ = sk.connect(ep.udp_addr);
                        sk
                    };
                    let framed = if use_tcp { frame_tcp(&pp) } else { pp.clone() };
                    let _ = sk.send(&framed);
                    Some(Probe {
                        conn: if use_tcp {
                            Conn::stream(io.clone(), sk, dns_frame)
                        } else {
                            Conn::datagram(io.clone(), sk)
                        },
                        server: pserver,
                        timeout: Instant::now() + opts.timeout,
                        payload: framed,
                    })
                });
                'attempt: loop {
                    // Inlined connect-with-failover (WET).
                    let (mut conn, si) = 'connect: {
                        let mut s = server;
                        for _ in 0..opts.attempts.max(1) {
                            let Some(ep) = self.endpoints.get(s) else { break };
                            let conn = if use_tcp {
                                self.tcp_pool.borrow_mut().get_or_create(s, &self.factory, ep.bind, ep.tcp_addr).ok().map(|c| Conn::shared(io.clone(), c, qid))
                            } else {
                                self.factory.create_udp(ep.bind).ok().map(|sk| {
                                    let _ = sk.connect(ep.udp_addr);
                                    Conn::datagram(io.clone(), sk)
                                })
                            };
                            if let Some(conn) = conn {
                                break 'connect (conn, s);
                            }
                            if self.health.borrow().len() > 1 {
                                self.health.borrow_mut().record_failure(s);
                                s = self.health.borrow().pick_next();
                            }
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    };
                    server = si;
                    let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                    let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                    let timeout = Instant::now() + opts.timeout;
                    if conn.send(wire, timeout).await.is_err() {
                        if use_tcp {
                            self.tcp_pool.borrow_mut().remove(server);
                        }
                        if tries + 1 < opts.attempts.max(1) {
                            tries += 1;
                            if self.health.borrow().len() > 1 {
                                self.health.borrow_mut().record_failure(server);
                                server = self.health.borrow().pick_next();
                            }
                            continue 'attempt;
                        }
                        break 'drive (Err(ARES_ECONNREFUSED), timeouts);
                    }
                    loop {
                        // Race the live probe, the timeout, and the primary reply.
                        // Biased probe -> timeout -> primary (expiry preempts a
                        // same-cycle primary read, as before). No probe => 2-arm recv.
                        let event = if let Some(p) = probe.as_mut() {
                            let wake_timeout = timeout.min(p.timeout);
                            match select3(&io, |_| p.conn.recv_arm(), |io| poll_timeout(io, wake_timeout), |_| conn.recv_arm()).await {
                                Which3::A(r) => ReplyEvent::Probe(r),
                                Which3::B(()) => ReplyEvent::Timeout,
                                Which3::C(r) => ReplyEvent::Primary(r),
                            }
                        } else {
                            match conn.recv(timeout).await {
                                Err(e) if e.kind() == io::ErrorKind::TimedOut => ReplyEvent::Timeout,
                                r => ReplyEvent::Primary(r),
                            }
                        };
                        match event {
                            ReplyEvent::Probe(r) => {
                                match r {
                                    Ok(buf) => {
                                        if probe.as_ref().is_some_and(|p| qid_matches(&buf, &p.payload, p.conn.is_tcp())) {
                                            let p_taken = probe.take().unwrap();
                                            settle_probe(&io, &self.health, &p_taken, Some(&buf));
                                        }
                                    }
                                    Err(_) => probe = None, // probe socket died
                                }
                                continue;
                            }
                            ReplyEvent::Timeout => {
                                let now = Instant::now();
                                if let Some(p) = &probe {
                                    if now >= p.timeout {
                                        let p_taken = probe.take().unwrap();
                                        settle_probe(&io, &self.health, &p_taken, None);
                                    }
                                }
                                if now >= timeout {
                                    if io.borrow().app.cancelled {
                                        break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                                    Ok(buf) => buf,
                                    Err(_) => {
                                        // Dead socket (EOF / hard error).
                                        if use_tcp {
                                            self.tcp_pool.borrow_mut().remove(server);
                                        }
                                        if io.borrow().app.cancelled {
                                            break 'drive (Err(ARES_ETIMEOUT), timeouts);
                                        }
                                        notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                        let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
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
                                    opts.attempts,
                                    failover_tries,
                                    &mut self.health.borrow_mut(),
                                );
                                notify(&io, actions);
                                match verdict {
                                    TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                        server = next;
                                        failover_tries = ft;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::RetryTcp => {
                                        use_tcp = true;
                                        continue 'attempt;
                                    }
                                    TaskVerdict::Deliver => {
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
        if let Some(lookup) = self.hostsfile().lookup(hostname, family_filter) {
            if !lookup.addrs.is_empty() {
                return AddrInfoOut {
                    name: hostname.to_string(),
                    records: lookup.addrs.iter().map(|&ip| AddrRecord { ip, ttl: u32::MAX }).collect(),
                    status: ARES_SUCCESS.into(),
                };
            }
        }

        if self.endpoints.is_empty() {
            return fail(ARES_ENOSERVER);
        }

        // ===== DNS phase: parallel A+AAAA per search-plan name =====
        let mut plan = SearchPlan::for_search(&hostname_raw, self.config.options.ndots, &self.config.search);
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
                rtypes.iter().map(|&rt| (dns_query_payload(&plan.current, rt), self.config.options.use_vc)).collect();
            let a_idx = rtypes.iter().position(|&rt| rt == RTYPE_A);

            // Drive A+AAAA in parallel. Policy (here, not in the executor): once
            // the A/ipv4 query returns actual addresses, cancel the sibling AAAA
            // query — its retries stop so it isn't sent again. (ipv6 success does
            // NOT cancel A: an ipv4-only host may still need the A answer.)
            let mut par = ParallelQueries::new(self.io.clone(), self.clone(), payloads);
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
// conn layer's async sockets (async_runtime::conn — Conn::send/recv over the reactor)
// + the neutral lookup.rs decision tables.
// ===================================================================

/// A fire-and-forget side effect the ffi applies after a poll — the one thing a
/// `forbid(unsafe_code)` future cannot do itself: fire the C server-state
/// callback.
pub(crate) enum Effect {
    /// Fire the C server-state callback.
    NotifyServerState { server: usize, ok: bool, tcp: bool },
}

/// The application-owned half of the mailbox: everything the *reactor* need not
/// understand. The reactor drives readiness (`waits`/`timeout`/`fired`/`expired`)
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

/// The mux tag of a DNS frame — its transaction ID (header bytes 0..2), the
/// demux key the conn layer routes shared-TCP replies by. `None` for a frame
/// too short to carry one: the conn layer then hands it to any awaiting
/// waiter, which rejects it in parsing (EBADRESP) — matching `qid_matches`'s
/// acceptance of short buffers.
pub(crate) fn dns_tag(frame: &[u8]) -> Option<u16> {
    frame.get(0..2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// DNS-over-TCP message framing (RFC 1035 §4.2.2): each message is preceded
/// by a u16-BE length. Pop one complete message off a stream's reassembly
/// buffer, or `None` until it has accumulated. Supplied to the runtime's
/// stream conns — the wire format is DNS's, not the runtime's. (`frame_tcp`
/// below is the encode side.)
pub(crate) fn dns_frame(rbuf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if rbuf.len() < 2 {
        return None;
    }
    let payload_len = u16::from_be_bytes([rbuf[0], rbuf[1]]) as usize;
    if rbuf.len() < 2 + payload_len {
        return None;
    }
    let msg = rbuf[2..2 + payload_len].to_vec();
    rbuf.drain(..2 + payload_len);
    Some(msg)
}

/// Wrap a DNS payload in the 2-byte big-endian length prefix used for TCP framing.
fn frame_tcp(payload: &[u8]) -> BytesMut {
    let mut framed = BytesMut::with_capacity(2 + payload.len());
    framed.put_u16(payload.len() as u16);
    framed.extend_from_slice(payload);
    framed
}

/// Write a DNS query directly to the buffer from a hostname string,
/// avoiding intermediate Vec<String>, DnsQuery, and DnsFrame allocations.
fn write_dns_query_direct(buf: &mut BytesMut, hostname: &str, qtype: u16, transaction_id: u16) {
    // Header: 12 bytes
    buf.put_u16(transaction_id);
    buf.put_u16(0x0100); // flags: standard query, recursion desired
    buf.put_u16(1); // qdcount
    buf.put_u16(0); // ancount
    buf.put_u16(0); // nscount
    buf.put_u16(0); // arcount

    // Question: labels
    for label in hostname.split('.').filter(|t| !t.is_empty()) {
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0); // root label
    buf.put_u16(qtype);
    buf.put_u16(1); // qclass: IN
}

/// Build a UDP-form DNS query payload (with a fresh random transaction id).
pub(crate) fn dns_query_payload(name: &str, qtype: u16) -> BytesMut {
    let transaction_id = rand::thread_rng().r#gen::<u16>();
    let mut buf = BytesMut::with_capacity(12 + name.len() + 2 + 4);
    write_dns_query_direct(&mut buf, name, qtype, transaction_id);
    buf
}

/// The pure body of ares_create_query/ares_mkquery: escaped-name analysis
/// (trailing-dot and `\.`/`\DDD` handling), RFC 7686 .onion rejection, label
/// validation, and wire-format packet assembly. A positive `max_udp_size`
/// appends an EDNS OPT pseudo-RR advertising that payload size; zero or
/// negative means "no EDNS" (the historical ares_create_query gate).
pub(crate) fn build_query(
    name_str: &str,
    dnsclass: u16,
    qtype: u16,
    id: u16,
    rd: bool,
    max_udp_size: i32,
) -> Result<Vec<u8>, AresError> {
    let max_udp_size: u16 = if max_udp_size > 0 { max_udp_size as u16 } else { 0 };
    // Check if trailing dot is an unescaped separator (not a literal escaped dot)
    let has_unescaped_trailing_dot = if let Some(prefix) = name_str.strip_suffix('.') {
        // Count consecutive backslashes before the trailing dot
        let backslash_count = prefix
            .as_bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        // Even number of backslashes means dot is unescaped (separator)
        backslash_count % 2 == 0
    } else {
        false
    };

    // Reject .onion domains
    let lower = name_str.to_lowercase();
    let check = if has_unescaped_trailing_dot {
        lower.strip_suffix('.').unwrap_or(&lower)
    } else {
        &lower
    };
    if check.ends_with(".onion") || check == "onion" {
        return Err(ARES_ENOTFOUND.into());
    }

    // Validate name length
    let clean_name = if has_unescaped_trailing_dot {
        name_str.strip_suffix('.').unwrap_or(name_str)
    } else {
        name_str
    };
    if clean_name.len() > 253 {
        return Err(ARES_EBADNAME.into());
    }

    // Check for escaped dots and handle them
    let labels: Vec<&str> = if clean_name.is_empty() {
        vec![] // root query
    } else {
        // Handle escaped dots: split only on unescaped dots
        let mut result = Vec::new();
        let mut current_start = 0;
        let bytes = clean_name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2; // skip escaped char
            } else if bytes[i] == b'.' {
                result.push(&clean_name[current_start..i]);
                current_start = i + 1;
                i += 1;
            } else {
                i += 1;
            }
        }
        if current_start <= bytes.len() {
            let last = &clean_name[current_start..];
            if !last.is_empty() {
                result.push(last);
            }
        }
        result
    };

    // Validate label lengths and reject empty labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.is_empty() {
            return Err(ARES_EBADNAME.into());
        }
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
    }

    // Build DNS packet
    let flags: u16 = if rd { 0x0100 } else { 0x0000 }; // RD flag
    let mut packet = Vec::with_capacity(512);
    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    packet.extend_from_slice(&0u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0u16.to_be_bytes()); // nscount
    let arcount: u16 = if max_udp_size > 0 { 1 } else { 0 };
    packet.extend_from_slice(&arcount.to_be_bytes()); // arcount

    // Question: encode labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
        packet.push(unescaped.len() as u8);
        packet.extend_from_slice(&unescaped);
    }
    packet.push(0); // root label
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&dnsclass.to_be_bytes());

    // OPT pseudo-RR for EDNS if max_udp_size > 0
    if max_udp_size > 0 {
        packet.push(0); // root name
        packet.extend_from_slice(&41u16.to_be_bytes()); // type OPT
        packet.extend_from_slice(&max_udp_size.to_be_bytes()); // class = UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL (extended RCODE + flags)
        packet.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    }

    Ok(packet)
}

/// Decode a presentation-form label: `\.` escapes and `\DDD` numeric escapes.
fn unescape_label(label: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(label.len());
    let bytes = label.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // Check for numeric escape \DDD
            if i + 3 < bytes.len() && bytes[i+1].is_ascii_digit() && bytes[i+2].is_ascii_digit() && bytes[i+3].is_ascii_digit() {
                let val = (bytes[i+1] - b'0') as u16 * 100 + (bytes[i+2] - b'0') as u16 * 10 + (bytes[i+3] - b'0') as u16;
                result.push(val as u8);
                i += 4;
            } else {
                result.push(bytes[i+1]);
                i += 2;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
}

// ===== Entry preflights + nameinfo assembly (pure, no channel state) =====

/// Everything getnameinfo's PTR delivery needs, assembled per the NI flag
/// semantics: NOFQDN truncation, the ENOTFOUND+!NAMEREQD numeric fallback,
/// and the LOOKUPSERVICE gate. Error deliveries carry zero timeouts (as
/// historically); success carries the task's accumulated count.
pub(crate) struct NameinfoReply {
    pub status: AresError,
    pub node: Option<CString>,
    pub service: Option<CString>,
    pub timeouts: i32,
}

pub(crate) fn assemble_nameinfo(
    res: Result<&[u8], AresError>,
    ip: IpAddr,
    scope_id: u32,
    port: u16,
    flags: i32,
    io_timeouts: i32,
) -> NameinfoReply {
    let services = Services::default();
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    let hostname_result = (|| -> Result<CString, AresError> {
        let buf = res?;
        let parsed = ParsedResponse::from_buf(buf)?;
        let ptr_records = parsed.process_answers::<CString>(buf, RECORD_TYPE_PTR)?;

        if ptr_records.aliases.is_empty() {
            return Err(ARES_ENOTFOUND.into());
        }

        let mut name = ptr_records.name;

        if flags & ARES_NI_NOFQDN != 0 {
            let name_str = name.to_string_lossy();
            if let Some(dot_pos) = name_str.find('.') {
                name = CString::new(&name_str[..dot_pos]).map_err(|_| AresError::from(ARES_EBADSTR))?;
            }
        }

        Ok(name)
    })();

    let (status, node): (AresError, _) = match hostname_result {
        Ok(name) => (ARES_SUCCESS.into(), Some(name)),
        Err(err) => {
            if err.code() == ARES_ENOTFOUND && (flags & ARES_NI_NAMEREQD) == 0 {
                let ip_str = format_ip_with_scope(&ip, scope_id, flags);
                match CString::new(ip_str) {
                    Ok(name) => (ARES_SUCCESS.into(), Some(name)),
                    Err(_) => return NameinfoReply { status: ARES_EBADSTR.into(), node: None, service: None, timeouts: 0 },
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

/// The well-known service table ares_getaddrinfo consults before falling
/// back to libc::getservbyname (which stays in the shim).
fn well_known_port(svc: &str) -> Option<u16> {
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

/// A decoded socket address (the pure result of the shim-side sockaddr
/// unmarshal): what getnameinfo works from.
pub(crate) struct AddrInfo {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) scope_id: u32,
}

/// Empty/onion rejection shared by ares_search and ares_search_dnsrec —
/// checked before the channel is even dereferenced (order is behavior:
/// these fire even on a NULL channel).
pub(crate) fn search_precheck(name_str: &str) -> Option<AresError> {
    if name_str.is_empty() {
        return Some(ARES_ENOTFOUND.into());
    }
    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(name_str) {
        return Some(ARES_ENOTFOUND.into());
    }
    None
}

/// The plain host-callback path (ares_gethostbyaddr's direct PTR delivery):
/// parse under the flow's acceptance rule, add the synthetic record for the
/// queried address, and shape the hostent.
pub(crate) fn on_host_reply(res: Result<&[u8], AresError>, rtype: u16, family: i32, ip: Option<IpAddr>) -> Result<Hostent, AresError> {
    let buf = res?;
    let is_ptr = rtype == RECORD_TYPE_PTR;
    let require = if is_ptr { ReplyRequire::ItemsOrAliases } else { ReplyRequire::Items };
    let mut rrs = addr_reply(buf, rtype, require)?;
    if is_ptr {
        push_synthetic_ptr(&mut rrs, ip.expect("PTR flows carry the queried ip"));
    }
    Ok(Hostent::from_parsed(rrs, family))
}

/// ares_timeout's clamp decision: nothing pending → report via maxtv;
/// otherwise write `ms` into tv and return whichever of tv/maxtv is sooner.
pub(crate) enum TimeoutChoice {
    NoTasks,
    Wait { ms: u128, use_max: bool },
}

pub(crate) fn clamp_timeout(wait: Option<u128>, maxtv_ms: Option<u128>) -> TimeoutChoice {
    match wait {
        None => TimeoutChoice::NoTasks,
        Some(ms) => TimeoutChoice::Wait { ms, use_max: maxtv_ms.is_some_and(|m| m < ms) },
    }
}

/// ares_fds' nfds tally: highest fd + 1 across the pollable set.
pub(crate) fn nfds(fds: &[(i32, bool)]) -> i32 {
    fds.iter().map(|(fd, _)| fd + 1).max().unwrap_or(0)
}

// ===== The channel-state methods (config/lifecycle; the ffi shims only marshal) =====

impl AsyncClient {
    /// A fresh channel from the system config (resolv.conf + env overrides) —
    /// shared by ares_init and ares_init_options.
    pub fn from_sysconfig(factory: Rc<dyn SocketFactory>) -> Self {
        AsyncClient::build(build_sysconfig(), factory, 53, 53)
    }

    fn build(
        config: SysConfig,
        factory: Rc<dyn SocketFactory>,
        default_udp_port: u16,
        default_tcp_port: u16,
    ) -> Self {
        AsyncClient {
            config,
            factory,
            hosts: None,
            default_udp_port,
            default_tcp_port,
            health: Rc::new(RefCell::new(ServerHealth::default())),
            sortlist: vec![],
            flags: 0,
            maxtimeout: 0,
            lookups: String::new(),
            resolvconf_path: String::new(),
            hosts_path: String::new(),
            cache: Rc::new(RefCell::new(QueryCache::default())),
            tcp_pool: Rc::new(RefCell::new(TcpPool::new(dns_frame, dns_tag))),
            endpoints: Rc::new(Vec::new()),
            server_failover_retry_chance: 0,
            server_failover_retry_delay: 0,
            io: Rc::new(RefCell::new(DnsMailbox::default())),
        }
    }

    /// The `/etc/hosts` table as a shared `Rc` (lazily loaded once); `derive`
    /// hands a clone to every lookup copy.
    pub fn hosts(&mut self) -> Rc<Hosts> {
        self.hosts.get_or_insert_with(|| Rc::new(Hosts::from_path("/etc/hosts").unwrap_or_default())).clone()
    }

    /// The pure body of ares_dup: clone configuration, start with a fresh
    /// reactor state (empty query cache, no pooled connections, cleared
    /// failure timestamps — but cloned failure counts).
    pub fn duplicate(&self) -> AsyncClient {
        let mut dup = AsyncClient::build(
            self.config.clone(),
            self.factory.clone(),
            self.default_udp_port,
            self.default_tcp_port,
        );
        {
            let src = self.health.borrow();
            dup.health = Rc::new(RefCell::new(ServerHealth {
                failures: src.failures.clone(),
                last_failure: vec![None; src.last_failure.len()],
            }));
        }
        dup.sortlist = self.sortlist.clone();
        dup.flags = self.flags;
        dup.maxtimeout = self.maxtimeout;
        dup.lookups = self.lookups.clone();
        dup.resolvconf_path = self.resolvconf_path.clone();
        dup.hosts_path = self.hosts_path.clone();
        dup.cache.borrow_mut().set_max_ttl(self.cache.borrow().max_ttl());
        dup.server_failover_retry_chance = self.server_failover_retry_chance;
        dup.server_failover_retry_delay = self.server_failover_retry_delay;
        dup
    }

    /// The optmask cascade from ares_init_options — order preserved bit for
    /// bit, ending with the unconditional server-health reset.
    pub fn apply_options(&mut self, optmask: i32, o: DecodedOptions) {
        if optmask & ARES_OPT_SERVERS != 0 {
            // Clear sysconfig servers when user explicitly provides servers
            self.config.nameservers.clear();
            self.config.tcp_ports.clear();
            for v4 in &o.servers {
                self.config.nameservers.push((IpAddr::V4(*v4), None));
                self.config.tcp_ports.push(None);
            }
        }
        if optmask & ARES_OPT_UDP_PORT != 0 {
            self.default_udp_port = o.udp_port;
        }
        if optmask & ARES_OPT_TCP_PORT != 0 {
            self.default_tcp_port = o.tcp_port;
        }
        if optmask & ARES_OPT_TIMEOUTMS != 0 {
            self.config.options.timeout_ms = std::cmp::max(1, o.timeout as u32);
        }
        if optmask & ARES_OPT_TIMEOUT != 0 {
            self.config.options.timeout_ms = o.timeout as u32 * 1000;
        }
        if optmask & ARES_OPT_TRIES != 0 {
            self.config.options.attempts = o.tries as u32;
        }
        if optmask & ARES_OPT_NDOTS != 0 {
            self.config.options.ndots = o.ndots as u32;
        }
        if optmask & ARES_OPT_FLAGS != 0 {
            self.flags = o.flags;
            self.config.options.use_vc = (o.flags & ARES_FLAG_USEVC) != 0;
            self.config.options.edns0 = (o.flags & ARES_FLAG_EDNS) != 0;
            // ARES_FLAG_PRIMARY: truncate to first server only
            if (o.flags & ARES_FLAG_PRIMARY) != 0 {
                self.config.nameservers.truncate(1);
                self.config.tcp_ports.truncate(1);
            }
        }
        if optmask & ARES_OPT_DOMAINS != 0 {
            if let Some(domains) = o.domains {
                self.config.search = domains;
            }
        }
        if optmask & ARES_OPT_NOROTATE != 0 {
            self.config.options.rotate = false;
        }
        if optmask & ARES_OPT_ROTATE != 0 {
            self.config.options.rotate = true;
        }
        if optmask & ARES_OPT_MAXTIMEOUTMS != 0 {
            self.maxtimeout = o.maxtimeout;
        }
        if optmask & ARES_OPT_LOOKUPS != 0 {
            if let Some(lookups) = o.lookups {
                self.lookups = lookups;
            }
        }
        if optmask & ARES_OPT_RESOLVCONF != 0 {
            if let Some(path) = o.resolvconf_path {
                self.resolvconf_path = path;
            }
        }
        if optmask & ARES_OPT_HOSTS_FILE != 0 {
            if let Some(path) = o.hosts_path {
                self.hosts_path = path;
            }
        }
        if optmask & ARES_OPT_QUERY_CACHE != 0 {
            self.cache.borrow_mut().set_max_ttl(o.qcache_max_ttl);
        }
        if optmask & ARES_OPT_SERVER_FAILOVER != 0 {
            self.server_failover_retry_chance = o.failover_retry_chance;
            self.server_failover_retry_delay = o.failover_retry_delay;
        }
        self.health.borrow_mut().reset(self.config.nameservers.len());
    }

    /// The pure inverse of the cascade: read the channel back into option fields.
    pub fn saved_options(&self) -> SavedOptions {
        let config = &self.config;
        let opts = &config.options;

        let mut base_mask = ARES_OPT_FLAGS
            | ARES_OPT_TIMEOUTMS
            | ARES_OPT_TRIES
            | ARES_OPT_NDOTS
            | ARES_OPT_UDP_PORT
            | ARES_OPT_TCP_PORT;
        base_mask |= if opts.rotate { ARES_OPT_ROTATE } else { ARES_OPT_NOROTATE };
        if !self.sortlist.is_empty() {
            base_mask |= ARES_OPT_SORTLIST;
        }

        // servers (IPv4 only in ares_options)
        let v4_servers: Vec<Ipv4Addr> = config
            .nameservers
            .iter()
            .filter_map(|(ip, _)| match ip {
                IpAddr::V4(v4) => Some(*v4),
                _ => None,
            })
            .collect();

        let domains: Vec<CString> = config
            .search
            .iter()
            .map(|domain| CString::new(domain.as_str()).unwrap_or_default())
            .collect();

        let maxtimeout = (self.maxtimeout != 0).then_some(self.maxtimeout);
        if maxtimeout.is_some() {
            base_mask |= ARES_OPT_MAXTIMEOUTMS;
        }
        let lookups = (!self.lookups.is_empty())
            .then(|| CString::new(self.lookups.as_str()).unwrap_or_default());
        if lookups.is_some() {
            base_mask |= ARES_OPT_LOOKUPS;
        }
        let resolvconf_path = (!self.resolvconf_path.is_empty())
            .then(|| CString::new(self.resolvconf_path.as_str()).unwrap_or_default());
        if resolvconf_path.is_some() {
            base_mask |= ARES_OPT_RESOLVCONF;
        }
        let hosts_path = (!self.hosts_path.is_empty())
            .then(|| CString::new(self.hosts_path.as_str()).unwrap_or_default());
        if hosts_path.is_some() {
            base_mask |= ARES_OPT_HOSTS_FILE;
        }

        SavedOptions {
            flags: self.flags,
            timeout: opts.timeout_ms as i32,
            tries: opts.attempts as i32,
            ndots: opts.ndots as i32,
            udp_port: self.default_udp_port,
            tcp_port: self.default_tcp_port,
            v4_servers,
            domains,
            maxtimeout,
            lookups,
            resolvconf_path,
            hosts_path,
            base_mask,
        }
    }

    /// Install a decoded server list (ares_set_servers / ares_set_servers_ports).
    pub fn set_servers(&mut self, servers: Vec<ServerSpec>) {
        self.config.nameservers.clear();
        self.config.tcp_ports.clear();
        for server in servers {
            self.config.nameservers.push((server.ip, server.udp_port));
            self.config.tcp_ports.push(server.tcp_port);
        }
        self.health.borrow_mut().reset(self.config.nameservers.len());
    }

    /// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
    pub fn clear_servers(&mut self) {
        self.config.nameservers.clear();
        self.config.tcp_ports.clear();
        self.health.borrow_mut().clear();
    }

    /// Install a parsed CSV server list (ares_set_servers_ports_csv).
    pub fn install_csv_servers(&mut self, ns: Vec<(IpAddr, Option<u16>)>) {
        self.config.tcp_ports = vec![None; ns.len()];
        self.health.borrow_mut().reset(ns.len());
        self.config.nameservers = ns;
    }

    /// The configured servers with per-entry defaults applied, in order:
    /// (ip, udp_port, tcp_port) — the report behind ares_get_servers[_ports].
    pub fn server_list(&self) -> Vec<(IpAddr, u16, u16)> {
        self.config
            .nameservers
            .iter()
            .map(|(ip, port)| {
                (
                    *ip,
                    port.unwrap_or(self.default_udp_port),
                    port.unwrap_or(self.default_tcp_port),
                )
            })
            .collect()
    }

    /// The `ip:port` CSV report behind ares_get_servers_csv (IPv6 bracketed).
    pub fn servers_csv_string(&self) -> String {
        let default_port = self.default_udp_port;
        self.config
            .nameservers
            .iter()
            .map(|(ip, port_opt)| {
                let port = port_opt.unwrap_or(default_port);
                match ip {
                    IpAddr::V6(_) => format!("[{}]:{}", ip, port),
                    _ => format!("{}:{}", ip, port),
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The `ip:port` string reported to the server-state callback (IPv6
    /// bracketed); None when the index is stale.
    pub fn server_state_string(&self, server_index: usize, is_tcp: bool) -> Option<String> {
        let (ip, port) = self.config.nameservers.get(server_index)?;
        let port_val = port.unwrap_or(if is_tcp {
            self.default_tcp_port
        } else {
            self.default_udp_port
        });
        Some(match ip {
            IpAddr::V4(v4) => format!("{}:{}", v4, port_val),
            IpAddr::V6(v6) => format!("[{}]:{}", v6, port_val),
        })
    }
}

/// The per-lookup snapshot builders + the pure entry helpers the ffi shims
/// compose (query/send payloads, the gethostbyname/getaddrinfo/... contexts).
impl AsyncClient {
    /// Snapshot the per-server connect endpoints from config, so a lookup
    /// future never re-reads the config.
    fn endpoint_snapshot(&self) -> Vec<ServerEndpoint> {
        let default_udp = self.default_udp_port;
        let default_tcp = self.default_tcp_port;
        self.config
            .nameservers
            .iter()
            .enumerate()
            .map(|(i, &(ip, udp_override))| {
                let udp_port = udp_override.unwrap_or(default_udp);
                let tcp_port = self.config.tcp_ports.get(i).copied().flatten().unwrap_or(default_tcp);
                let bind = if ip.is_ipv6() {
                    SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
                };
                ServerEndpoint {
                    udp_addr: SocketAddr::from((ip, udp_port)),
                    tcp_addr: SocketAddr::from((ip, tcp_port)),
                    bind,
                }
            })
            .collect()
    }

    /// The retry/timeout knobs an async lifecycle needs.
    fn opts(&self) -> QueryOpts {
        QueryOpts {
            attempts: self.config.options.attempts,
            timeout: Duration::from_millis(self.config.options.timeout_ms as u64),
            failover_chance: self.server_failover_retry_chance,
            failover_delay: self.server_failover_retry_delay,
        }
    }

    // ===== Entry points (one method per ares_* export) =====

    /// ares_query: `no_servers` preflight, then the wire payload for the async
    /// lifecycle. The `AsyncClient` (built by the shim) supplies the resources.
    pub(crate) fn query_payload(&self, name: &str, qtype: u16) -> Result<BytesMut, AresError> {
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        Ok(dns_query_payload(name, qtype))
    }

    /// ares_send: min-DNS-length + `no_servers` preflight, then the wire payload.
    pub(crate) fn send_payload(&self, query_buf: &[u8]) -> Result<BytesMut, AresError> {
        if query_buf.len() < 12 {
            return Err(ARES_EBADQUERY.into());
        }
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        Ok(BytesMut::from(query_buf))
    }

    /// ares_gethostbyname_file: the hosts-file-only lookup, shaped for C.
    pub(crate) fn gethostbyname_file(&mut self, name: &str, family: i32) -> Result<Hostent, AresError> {
        hosts_file_lookup(self, name, family).map(Hostent::from_lookup)
    }
}

/// The pure body of ares_gethostbyname_file: hosts-file-only lookup.
fn hosts_file_lookup(st: &mut AsyncClient, name: &str, family: i32) -> Result<HostLookup, AresError> {
    // Convert C family constant to our Family enum
    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => return Err(ARES_ENOTFOUND.into()),
    };

    // Lookup in the hosts file cache
    let lookup = st.hosts().lookup(name, family_filter).ok_or(ARES_ENOTFOUND)?;
    if lookup.addrs.is_empty() {
        return Err(ARES_ENOTFOUND.into());
    }
    Ok(lookup)
}

/// ENOSERVER guard shared by ares_query / ares_query_dnsrec / ares_send.
fn no_servers(st: &AsyncClient) -> bool {
    st.config.nameservers.is_empty()
}

/// The reverse-DNS (PTR) query name for an address.
pub(crate) fn rdns_name(ip: IpAddr) -> String {
    match ip {
        // decimal
        IpAddr::V4(v4) => v4.octets().into_iter().rev().map(|b| b.to_string())
            .collect::<Vec<_>>().join(".") + ".in-addr.arpa",
        // hex (low nibble first)
        IpAddr::V6(v6) => v6.octets().into_iter().flat_map(|b| [b >> 4, b & 0x0f]).map(|n| format!("{:x}", n))
            .collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".") + ".ip6.arpa",
    }
}

/// The system resolver config: /etc/resolv.conf + the env overrides
/// (RES_OPTIONS / LOCALDOMAIN).
fn build_sysconfig() -> SysConfig {
    let try_resolv_conf = || std::fs::read_to_string("/etc/resolv.conf").ok()?.parse::<SysConfig>().ok();
    let mut config = try_resolv_conf().unwrap_or_else(SysConfig::default);
    crate::core::sysconfig::apply_env_overrides(&mut config);
    config
}

/// One decoded entry of a caller-supplied server list.
pub(crate) struct ServerSpec {
    pub ip: IpAddr,
    pub udp_port: Option<u16>,
    pub tcp_port: Option<u16>,
}

/// 0 and the default DNS port mean "no override" (matches upstream).
pub(crate) fn normalize_port(port: u16) -> Option<u16> {
    if port == 0 || port == 53 { None } else { Some(port) }
}

/// ares_getsock's bitmask: bit i = slot readable, bit i+16 = slot writable.
pub(crate) fn getsock_mask(fds: &[(i32, bool)], slots: usize) -> i32 {
    let mut mask: i32 = 0;
    for (i, (_, writing)) in fds.iter().take(slots).enumerate() {
        if *writing {
            mask |= 1 << (i + 16); // writable
        }
        mask |= 1 << i; // readable
    }
    mask
}

/// A fully-owned mirror of the caller's `ares_options`, decoded by the shim
/// before any logic runs. `None`/empty encode the NULL-pointer cases so the
/// cascade can reproduce the exact per-field guards.
pub(crate) struct DecodedOptions {
    pub flags: i32,
    pub timeout: i32,
    pub tries: i32,
    pub ndots: i32,
    pub udp_port: u16,
    pub tcp_port: u16,
    /// Decoded OPT_SERVERS list. Empty when the C pointer was NULL — the
    /// mask bit alone still clears the sysconfig servers.
    pub servers: Vec<Ipv4Addr>,
    /// None when the C pointer was NULL: the bit is then ignored entirely.
    pub domains: Option<Vec<String>>,
    pub lookups: Option<String>,
    pub resolvconf_path: Option<String>,
    pub hosts_path: Option<String>,
    pub maxtimeout: i32,
    pub qcache_max_ttl: u32,
    pub failover_retry_chance: u16,
    pub failover_retry_delay: u64,
}

/// Everything ares_save_options reports, precomputed. `base_mask` carries all
/// bits except SERVERS/DOMAINS, whose emission depends on libc::malloc
/// succeeding — the shim adds those two after the copies land.
pub(crate) struct SavedOptions {
    pub flags: i32,
    pub timeout: i32,
    pub tries: i32,
    pub ndots: i32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub v4_servers: Vec<Ipv4Addr>,
    pub domains: Vec<CString>,
    pub maxtimeout: Option<i32>,
    pub lookups: Option<CString>,
    pub resolvconf_path: Option<CString>,
    pub hosts_path: Option<CString>,
    pub base_mask: i32,
}

fn qid_of(payload: &[u8]) -> u16 {
    if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        0
    }
}

/// One `select` result in the probe ops (`gethostbyname`/`search`): which of the
/// raced arms — the concurrent failover probe, the timeout, or the primary
/// reply — fired. Unifies the 3-arm (probe live) and 2-arm (no probe) branches.
enum ReplyEvent {
    Probe(io::Result<Vec<u8>>),
    Timeout,
    Primary(io::Result<Vec<u8>>),
}

/// A one-shot failover probe running alongside the primary query.
struct Probe {
    conn: Conn<DnsSignals>,
    server: usize,
    timeout: Instant,
    payload: BytesMut, // framed form actually sent (for qid_matches)
}

/// Fold a probe reply into server health (the old `on_probe_reply` verdict),
/// emitted as effects. `None` reply = the probe timed out (failure timestamp only).
fn settle_probe(io: &Rc<RefCell<DnsMailbox>>, health: &RefCell<ServerHealth>, probe: &Probe, reply: Option<&[u8]>) {
    let mut health = health.borrow_mut();
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
/// awaits it, and routes readiness back by fd + each sub's own timeout.
pub(crate) struct ParallelQueries {
    io: Rc<RefCell<DnsMailbox>>,
    subs: Vec<ParSub>,
}

impl ParallelQueries {
    /// Build one `resolve_query` future per `(payload, use_tcp)` (no probe).
    pub(crate) fn new(io: Rc<RefCell<DnsMailbox>>, client: Rc<AsyncClient>, payloads: Vec<(BytesMut, bool)>) -> Self {
        let subs = payloads
            .into_iter()
            .map(|(payload, use_tcp)| {
                let sub_io = Rc::new(RefCell::new(DnsMailbox::default()));
                // Inlined single-query driver (WET) on this sub-mailbox — the
                // getaddrinfo A/AAAA sub-queries (no probe). In an async block
                // `return` yields the future's output directly.
                let io = sub_io.clone();
                let client = client.clone();
                let fut = Box::pin(async move {
                    let opts = client.opts();
                    let mut use_tcp = use_tcp;
                    let mut timeouts: c_int = 0;
                    let mut tries: u32 = 0;
                    let mut failover_tries: u32 = 0;
                    let qid = qid_of(&payload);
                    let mut server = client.health.borrow().pick_next();
                    'attempt: loop {
                        // Inlined connect-with-failover (WET).
                        let (mut conn, si) = 'connect: {
                            let mut s = server;
                            for _ in 0..opts.attempts.max(1) {
                                let Some(ep) = client.endpoints.get(s) else { break };
                                let conn = if use_tcp {
                                    client.tcp_pool.borrow_mut().get_or_create(s, &client.factory, ep.bind, ep.tcp_addr).ok().map(|c| Conn::shared(io.clone(), c, qid))
                                } else {
                                    client.factory.create_udp(ep.bind).ok().map(|sk| {
                                        let _ = sk.connect(ep.udp_addr);
                                        Conn::datagram(io.clone(), sk)
                                    })
                                };
                                if let Some(conn) = conn {
                                    break 'connect (conn, s);
                                }
                                if client.health.borrow().len() > 1 {
                                    client.health.borrow_mut().record_failure(s);
                                    s = client.health.borrow().pick_next();
                                }
                            }
                            return (Err(ARES_ECONNREFUSED), timeouts);
                        };
                        server = si;
                        // The wire buffer for this attempt's transport: TCP needs the framed
                        // copy, UDP sends the payload as-is (borrowed — no clone).
                        let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
                        let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
                        let timeout = Instant::now() + opts.timeout;

                        if conn.send(wire, timeout).await.is_err() {
                            // Send failed (a hard socket error): recreate the socket and retry,
                            // bounded by the attempt budget — mirrors the classic write_impl's
                            // recreate-and-resend. (SetReplyAndFailSend fails one send, then the
                            // retry succeeds.)
                            if use_tcp {
                                client.tcp_pool.borrow_mut().remove(server);
                            }
                            if tries + 1 < opts.attempts.max(1) {
                                tries += 1;
                                if client.health.borrow().len() > 1 {
                                    client.health.borrow_mut().record_failure(server);
                                    server = client.health.borrow().pick_next();
                                }
                                continue 'attempt;
                            }
                            return (Err(ARES_ECONNREFUSED), timeouts);
                        }

                        // Await the primary reply, servicing the probe socket concurrently.
                        loop {
                            match conn.recv(timeout).await {
                                Ok(buf) => {
                                    if !qid_matches(&buf, wire, use_tcp) {
                                        continue; // stray datagram — await the next reply
                                    }
                                    let summary = summarize(&buf, 0);
                                    let (actions, verdict) = on_datagram(
                                        &summary,
                                        server,
                                        use_tcp,
                                        opts.attempts,
                                        failover_tries,
                                        &mut client.health.borrow_mut(),
                                    );
                                    notify(&io, actions);
                                    match verdict {
                                        TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                            server = next;
                                            failover_tries = ft;
                                            continue 'attempt;
                                        }
                                        TaskVerdict::RetryTcp => {
                                            use_tcp = true;
                                            continue 'attempt;
                                        }
                                        TaskVerdict::Deliver => {
                                            return (Ok(buf), timeouts);
                                        }
                                    }
                                }
                                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                                    if io.borrow().app.cancelled {
                                        return (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, opts.attempts, server, &mut client.health.borrow_mut());
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
                                Err(_) => {
                            // Dead socket (EOF / hard error).
                                    if use_tcp {
                                        client.tcp_pool.borrow_mut().remove(server);
                                    }
                                    if io.borrow().app.cancelled {
                                        return (Err(ARES_ETIMEOUT), timeouts);
                                    }
                                    notify(&io, vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                                    let verdict = on_timeout(tries, opts.attempts, server, &mut client.health.borrow_mut());
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

        // Merge every live sub's waits + earliest timeout into the outer mailbox,
        // and lift its effects up so the ffi applies them.
        let mut merged: Vec<Wait> = Vec::new();
        let mut timeout: Option<Instant> = None;
        for s in &self.subs {
            if s.fut.is_none() {
                continue;
            }
            let drained: Vec<Effect> = {
                let mut sub = s.io.borrow_mut();
                merged.extend(sub.waits.iter().copied());
                if let Some(d) = sub.timeout {
                    timeout = Some(timeout.map_or(d, |m: Instant| m.min(d)));
                }
                std::mem::take(&mut sub.app.effects)
            };
            self.io.borrow_mut().app.effects.extend(drained);
        }
        let timeout = match timeout {
            Some(d) => d,
            None => return, // nothing published a wait — avoid an unbounded await
        };

        // Await the outer mailbox (the ffi sets fired/expired against `merged`),
        // then route readiness back to each live sub.
        let woke = wait_io(&self.io, &merged, timeout).await;
        let now = Instant::now();
        for s in &self.subs {
            if s.fut.is_none() {
                continue;
            }
            let mut sub = s.io.borrow_mut();
            let wants: Vec<i32> = sub.waits.iter().map(|w| w.fd).collect();
            sub.fired = woke.fds.iter().copied().filter(|fd| wants.contains(fd)).collect();
            sub.expired = sub.timeout.is_some_and(|d| now >= d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dns_frame;

    #[test]
    fn dns_frame_extraction() {
        let mut rbuf = vec![0x00, 0x03, 1, 2, 3, 0x00];
        assert_eq!(dns_frame(&mut rbuf), Some(vec![1, 2, 3]));
        assert_eq!(rbuf, vec![0x00]); // partial next frame stays buffered
        assert_eq!(dns_frame(&mut rbuf), None);
        rbuf.push(0x02);
        assert_eq!(dns_frame(&mut rbuf), None); // length known, payload missing
        rbuf.extend_from_slice(&[9, 8]);
        assert_eq!(dns_frame(&mut rbuf), Some(vec![9, 8]));
        assert!(rbuf.is_empty());
    }
}
