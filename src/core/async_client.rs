//! `AsyncClient` is both the ffi channel state and the resolver client; every
//! lookup runs on a [`AsyncClient::derive`]d copy (shared `Rc`s, fresh mailbox).

use std::cell::{Cell, RefCell};
use std::ffi::{c_int, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::task::Poll;
use std::rc::Rc;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use futures_util::{select_biased, FutureExt};
use rand::Rng;

use crate::core::cache::{CacheKey, QueryCache};
use crate::core::conn::Conn;
use crate::core::tcp_pool::{TcpConn, TcpPool};
use crate::core::udp_pool::{UdpConn, UdpPool};
use crate::async_runtime::reactor::Runtime;
use crate::core::hostent::Hostent;
use crate::core::hostfile::{AddressFamily, HostLookup, Hosts};
use crate::core::lookup::{
    is_localhost, is_onion_domain, on_datagram, on_timeout, qid_matches,
    summarize, ReactorAction, ReplyPolicy, SearchPlan, ServerHealth, TaskVerdict,
    TimeoutVerdict, AF_INET, AF_INET6, RTYPE_A, RTYPE_AAAA,
};
use crate::core::dns_record::{ares_dns_record_t, class_isvalid, parse_record, rec_type_isvalid, write_record};
use crate::core::edns::{self, CookieVerdict, EDNS_PACKETSZ, ServerCookie};
use crate::core::packets::AddrRecord;
use crate::core::response::{addr_reply, push_synthetic_ptr, CnameEntry, ParsedRRs, ParsedResponse, ReplyRequire};
use crate::core::services::Services;
use crate::async_runtime::socket::SocketFactory;
use crate::core::sortlist::{parse_sortlist, sort_addrinfo, SortlistEntry};
use crate::core::sysconfig::SysConfig;
use crate::core::AresError;
use crate::ffi::dns_record::ARES_CLASS_IN;
use crate::ffi::ares_options::{
    ARES_FLAG_DNS0x20, ARES_FLAG_EDNS, ARES_FLAG_IGNTC, ARES_FLAG_NO_DFLT_SVR, ARES_FLAG_NOALIASES,
    ARES_FLAG_NOCHECKRESP, ARES_FLAG_NORECURSE, ARES_FLAG_NOSEARCH, ARES_FLAG_PRIMARY,
    ARES_FLAG_STAYOPEN, ARES_FLAG_USEVC, ARES_OPT_DOMAINS, ARES_OPT_EDNSPSZ,
    ARES_OPT_EVENT_THREAD, ARES_OPT_FLAGS,
    ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS,
    ARES_OPT_NOROTATE, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF, ARES_OPT_ROTATE,
    ARES_OPT_SERVERS, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SOCK_RCVBUF,
    ARES_OPT_SOCK_SNDBUF, ARES_OPT_SORTLIST, ARES_OPT_TCP_PORT,
    ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
    ARES_OPT_UDP_MAX_QUERIES, ARES_OPT_UDP_PORT,
};
use crate::ffi::error::{
    ARES_ECONNREFUSED, ARES_EBADFLAGS, ARES_EBADNAME, ARES_EBADQUERY, ARES_EBADSTR, ARES_EFILE,
    ARES_EFORMERR, ARES_ENODATA, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED,
    ARES_ESERVFAIL, ARES_ETIMEOUT,
};
use crate::ffi::{
    ARES_NI_DGRAM, ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NOFQDN,
    ARES_NI_NUMERICHOST, ARES_NI_NUMERICSCOPE, ARES_NI_NUMERICSERV, ARES_SUCCESS, RECORD_TYPE_PTR,
};

/// THE channel: the state the ffi `ChannelData` wraps, and the resolver client
/// the async lifecycles run on. Each lookup uses a `derive`d copy (shared `Rc`s
/// and the same runtime handle).
pub(crate) struct AsyncClient {
    pub config: SysConfig,
    /// The channel's runtime handle (reactor + socket factory); every lookup
    /// copy shares it.
    pub rt: Runtime,
    /// Lazily loaded `/etc/hosts`; always `Some` on a lookup copy.
    hosts: Option<Rc<Hosts>>,
    pub default_udp_port: u16,
    pub default_tcp_port: u16,
    pub socket_send_buffer_size: i32,
    pub socket_receive_buffer_size: i32,
    pub local_ip4: u32,
    pub local_ip6: [u8; 16],
    pub local_dev: String,
    /// Shared with in-flight lookups so failover accounting and probes agree.
    pub health: Rc<RefCell<ServerHealth>>,
    pub sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    /// `ARES_OPT_EDNSPSZ` kept full-width until query construction, where
    /// values above 65535 are rejected with `ARES_EFORMERR`.
    pub ednspsz: i32,
    /// Per-server DNS cookie state, shared across lookups; reset by `duplicate`.
    pub cookies: Rc<RefCell<Vec<ServerCookie>>>,
    pub maxtimeout: i32,
    /// Option mask the channel was initialized with; `ares_reinit` preserves
    /// explicitly-set values.
    pub optmask: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    pub cache: Rc<RefCell<QueryCache>>,
    /// Shared TCP sockets (parallel lookups to one server share a connection).
    pub tcp_pool: Rc<RefCell<TcpPool>>,
    /// Shared UDP sockets (parallel lookups to one server share a socket, split
    /// across several once [`udp_max_queries`](Self::udp_max_queries) is reached).
    pub udp_pool: Rc<RefCell<UdpPool>>,
    /// `ARES_OPT_UDP_MAX_QUERIES`: max in-flight queries per UDP socket; 0 =
    /// unlimited (upstream default).
    pub udp_max_queries: usize,
    /// Per-server endpoints snapshotted by `derive` so lookup futures never
    /// re-read the config.
    pub endpoints: Rc<Vec<ServerEndpoint>>,
    pub server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub server_failover_retry_delay: u64,  // milliseconds
    /// Server-state notifications raised by in-flight lookups, drained by the
    /// host after each task poll (shared by every lookup copy).
    pub effects: Rc<RefCell<Vec<Effect>>>,
}

impl AsyncClient {
    /// Mint the per-lookup copy every entry shim runs on: clone config and
    /// shared `Rc`s, and snapshot endpoints.
    pub(crate) fn derive(&mut self) -> Self {
        let hosts = self.hosts();
        AsyncClient {
            config: self.config.clone(),
            rt: self.rt.clone(),
            hosts: Some(hosts),
            default_udp_port: self.default_udp_port,
            default_tcp_port: self.default_tcp_port,
            socket_send_buffer_size: self.socket_send_buffer_size,
            socket_receive_buffer_size: self.socket_receive_buffer_size,
            local_ip4: self.local_ip4,
            local_ip6: self.local_ip6,
            local_dev: self.local_dev.clone(),
            health: self.health.clone(),
            sortlist: self.sortlist.clone(),
            flags: self.flags,
            ednspsz: self.ednspsz,
            cookies: self.cookies.clone(),
            maxtimeout: self.maxtimeout,
            optmask: self.optmask,
            lookups: self.lookups.clone(),
            resolvconf_path: self.resolvconf_path.clone(),
            hosts_path: self.hosts_path.clone(),
            cache: self.cache.clone(),
            tcp_pool: self.tcp_pool.clone(),
            udp_pool: self.udp_pool.clone(),
            udp_max_queries: self.udp_max_queries,
            endpoints: Rc::new(self.endpoint_snapshot()),
            server_failover_retry_chance: self.server_failover_retry_chance,
            server_failover_retry_delay: self.server_failover_retry_delay,
            effects: self.effects.clone(),
        }
    }

    /// The hosts table; empty only on the channel-owned instance before first use.
    fn hostsfile(&self) -> Rc<Hosts> {
        self.hosts.clone().unwrap_or_default()
    }

    /// Hosts lookup honouring ARES_AI_ENVHOSTS (`CARES_HOSTS`); HOSTALIASES
    /// remains on the legacy alias path.
    fn hosts_lookup(
        &self,
        name: &str,
        family: AddressFamily,
        use_env: bool,
    ) -> Option<HostLookup> {
        if use_env {
            if let Ok(path) = std::env::var("CARES_HOSTS") {
                return Hosts::from_path(path).ok().and_then(|h| h.lookup(name, family));
            }
        }
        self.hostsfile().lookup(name, family)
    }

    fn finalize_hostent(&self, mut hostent: Hostent) -> Hostent {
        hostent.sort_addrs(&self.sortlist);
        hostent
    }

    /// The single-query driver every lookup runs on: pick a server, connect with
    /// failover, send, then loop until a verdict. Starts on TCP iff ARES_FLAG_USEVC;
    /// `cancelled` stops retries but still delivers an in-flight reply.
    async fn request(&self, payload: BytesMut, synthesize_edns: bool, sig: &QuerySignals) -> QueryOutcome {
        let opts = self.opts();
        // Starting transport; a TC reply or persistent BADCOOKIE upgrades to TCP.
        let mut use_tcp = self.config.options.use_vc;
        let mut timeouts: c_int = 0;
        // Per-query EDNS/0x20/cookie state lives in locals, not the mailbox:
        // concurrent A/AAAA siblings share it. Raw send (`synthesize_edns =
        // false`) forwards caller bytes (incl. any OPT) untouched.
        let mut payload = payload.to_vec();
        if synthesize_edns && !edns::has_opt(&payload) {
            match self.edns_udp_size() {
                Ok(Some(size)) => {
                    if !edns::append_opt(&mut payload, size) {
                        return (Err(ARES_EFORMERR), timeouts);
                    }
                }
                Ok(None) => {}
                // EDNSPSZ wider than the 16-bit OPT CLASS: rejected before any send.
                Err(e) => return (Err(e.code()), timeouts),
            }
        }
        // DNS 0x20: randomize question 0's case once per UDP query; the exact
        // case is retained for retries and validated against the reply.
        let dns0x20_expected = if self.flags & ARES_FLAG_DNS0x20 != 0 && !use_tcp {
            edns::randomize_question_name(&mut payload)
        } else {
            None
        };
        let mut cookie_try_count: u32 = 0;
        let mut tries: u32 = 0;
        // A packet over the 16-bit wire length cannot be framed; upstream's TCP
        // writer reports EBADQUERY rather than truncating the length prefix.
        if payload.len() > u16::MAX as usize {
            return (Err(ARES_EBADQUERY), timeouts);
        }
        let mut failover_tries: u32 = 0;
        // Upstream query->try_count: every retry across all servers; drives the
        // timeout backoff below.
        let mut try_count: u32 = 0;
        let mut server = self.health.borrow().pick_next();
        'attempt: loop {
            let (mut conn, si) = match self.connect_failover(&mut payload, server, use_tcp) {
                Ok(v) => v,
                Err(()) => return (Err(ARES_ECONNREFUSED), timeouts),
            };
            sig.qid.set(qid_of(&payload));
            server = si;
            // Cookies are re-evaluated per server/transport before every send: a
            // BADCOOKIE retry must pick up the learned server cookie, a TCP
            // upgrade must strip it. No OPT on the payload → untouched.
            let sent_cookie = match self.apply_cookie(&mut payload, server, use_tcp) {
                Ok(c) => c,
                Err(e) => return (Err(e.code()), timeouts),
            };
            let framed_tcp = if use_tcp { Some(frame_tcp(&payload)) } else { None };
            let wire: &[u8] = framed_tcp.as_deref().unwrap_or(&payload);
            let timeout = Instant::now()
                + calc_query_timeout(
                    opts.timeout,
                    try_count,
                    self.endpoints.len(),
                    opts.maxtimeout,
                );
            if conn.send(wire, timeout).await.is_err() {
                if use_tcp {
                    self.tcp_pool.borrow_mut().remove(server);
                } else if self.optmask & ARES_OPT_EVENT_THREAD != 0 {
                    conn.mark_dead();
                } else {
                    self.retire_udp(server, &conn);
                }
                if tries + 1 < opts.attempts.max(1) {
                    tries += 1;
                    try_count += 1;
                    if self.health.borrow().len() > 1 {
                        self.health.borrow_mut().record_failure(server);
                        server = self.health.borrow().pick_next();
                    }
                    continue 'attempt;
                }
                return (Err(ARES_ECONNREFUSED), timeouts);
            }
            loop {
                // Timeout-biased recv, with a last non-blocking read when the
                // timer and socket readiness land in the same reactor cycle: a
                // pending ICMP error must not report as a timeout.
                let received = match conn.recv(timeout).await {
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => match conn.try_recv() {
                        Poll::Ready(result) => result,
                        Poll::Pending => Err(e),
                    },
                    other => other,
                };
                match received {
                    Ok(buf) => {
                        if !qid_matches(&buf, wire, use_tcp) {
                            continue;
                        }
                        // DNS 0x20: the reply must echo the exact randomized
                        // question case, else it is a stray/spoofed datagram.
                        if !use_tcp {
                            if let Some(expected) = dns0x20_expected.as_deref() {
                                if !edns::question_matches_case(&buf, expected) {
                                    continue;
                                }
                            }
                        }
                        let summary = summarize(&buf, 0);
                        let full_rcode = edns::extended_rcode(&buf, summary.rcode);
                        match self.validate_cookie(&buf, sent_cookie.as_ref(), server, full_rcode) {
                            CookieVerdict::Drop => continue,
                            CookieVerdict::BadCookie => {
                                cookie_try_count += 1;
                                if cookie_try_count >= 3 {
                                    // Persistent BADCOOKIE (e.g. AnyCast rotation):
                                    // upgrade to TCP, where cookies are not used.
                                    use_tcp = true;
                                }
                                continue 'attempt;
                            }
                            CookieVerdict::Accept => {}
                        }
                        // FORMERR fallback: a server that does not understand EDNS
                        // answers the OPT-bearing query with FORMERR. Strip the OPT
                        // (and cookie) and retry the same server uncounted.
                        if summary.rcode == 1 && edns::has_opt(&payload) && edns::strip_opt(&mut payload) {
                            continue 'attempt;
                        }
                        let (actions, verdict) = on_datagram(
                            &summary,
                            server,
                            use_tcp,
                            opts.attempts,
                            failover_tries,
                            ReplyPolicy {
                                ignore_tc: opts.ignore_tc,
                                no_check_resp: opts.no_check_resp,
                            },
                            &mut self.health.borrow_mut(),
                        );
                        self.notify(actions);
                        match verdict {
                            TaskVerdict::RetryNextServer { server: next, tries: ft } => {
                                server = next;
                                failover_tries = ft;
                                try_count += 1;
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
                        // If any UDP socket to this server already died, a timeout
                        // is the same unreachable condition (the kernel may rate-limit
                        // ICMP across parallel sockets); mark dead and retry uncounted.
                        if !use_tcp && self.optmask & ARES_OPT_EVENT_THREAD != 0 && self.udp_pool.borrow().has_dead(server) {
                            conn.mark_dead();
                            if sig.cancelled.get() {
                                return (Err(ARES_ETIMEOUT), timeouts);
                            }
                            self.notify(vec![ReactorAction::NotifyServerState { server, ok: false, tcp: false }]);
                            let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
                            match verdict {
                                TimeoutVerdict::Retry { server: next } => {
                                    tries += 1;
                                    try_count += 1;
                                    server = next;
                                    continue 'attempt;
                                }
                                TimeoutVerdict::Expire => {
                                    return (Err(ARES_ECONNREFUSED), timeouts);
                                }
                            }
                        }
                        if sig.cancelled.get() {
                            return (Err(ARES_ETIMEOUT), timeouts);
                        }
                        self.notify(vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                        let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
                        match verdict {
                            TimeoutVerdict::Retry { server: next } => {
                                if !use_tcp {
                                    self.retire_udp(server, &conn);
                                }
                                tries += 1;
                                timeouts += 1;
                                try_count += 1;
                                server = next;
                                continue 'attempt;
                            }
                            TimeoutVerdict::Expire => return (Err(ARES_ETIMEOUT), timeouts),
                        }
                    }
                    Err(_) => {
                        // Dead socket (EOF/hard error); for UDP this is ICMP
                        // port-unreachable (upstream issue #819), treated as a critical
                        // failure, not a timeout: retry uncounted, report ECONNREFUSED.
                        let refused = !use_tcp;
                        if use_tcp {
                            self.tcp_pool.borrow_mut().remove(server);
                        } else if self.optmask & ARES_OPT_EVENT_THREAD != 0 {
                            // Event-driven bursts keep a dead shared UDP conn
                            // pooled briefly: retries fail fast instead of each
                            // opening a socket that needs its own ICMP error.
                            conn.mark_dead();
                        } else {
                            self.retire_udp(server, &conn);
                        }
                        if sig.cancelled.get() {
                            return (Err(ARES_ETIMEOUT), timeouts);
                        }
                        self.notify(vec![ReactorAction::NotifyServerState { server, ok: false, tcp: use_tcp }]);
                        let verdict = on_timeout(tries, opts.attempts, server, &mut self.health.borrow_mut());
                        match verdict {
                            TimeoutVerdict::Retry { server: next } => {
                                tries += 1;
                                if !refused {
                                    timeouts += 1;
                                }
                                try_count += 1;
                                server = next;
                                continue 'attempt;
                            }
                            TimeoutVerdict::Expire => {
                                return (Err(if refused { ARES_ECONNREFUSED } else { ARES_ETIMEOUT }), timeouts);
                            }
                        }
                    }
                }
            }
        }
    }

    /// ares_query / ares_send: the raw single query, wrapped into `Delivery::Raw`.
    /// The starting transport honors ARES_FLAG_USEVC; `synthesize_edns` is false
    /// for raw send APIs, whose bytes must go on the wire unchanged.
    /// `sig.qid` reports the transaction id actually reserved on the wire.
    pub(crate) async fn query_raw(self, payload: BytesMut, synthesize_edns: bool, sig: Rc<QuerySignals>) -> Delivery {
        let (result, timeouts) = self.request(payload, synthesize_edns, &sig).await;
        Delivery::Raw { result, timeouts }
    }

    /// One-shot failover probe to a stale server, raced against the primary; reply-
    /// biased, looping past stray (non-QID) datagrams, and folding its outcome into
    /// `ServerHealth`.
    async fn run_probe(&self, probe_payload: BytesMut) {
        let opts = self.opts();
        let use_tcp = self.config.options.use_vc;
        if opts.failover_chance == 0 {
            return;
        }
        let primary_server = self.health.borrow().pick_next();
        let Some(pserver) = self.health.borrow().pick_probe(opts.failover_delay, primary_server) else {
            return;
        };
        let Some(ep) = self.endpoints.get(pserver) else {
            return;
        };
        let sk = if use_tcp {
            let Ok(sk) = self.rt.tcp(ep.bind) else { return };
            let _ = sk.get_ref().connect(ep.tcp_addr);
            sk
        } else {
            let Ok(sk) = self.rt.udp(ep.bind) else { return };
            let _ = sk.get_ref().connect(ep.udp_addr);
            sk
        };
        let framed = if use_tcp { frame_tcp(&probe_payload) } else { probe_payload.clone() };
        let _ = sk.get_ref().send(&framed);
        let mut conn = if use_tcp { Conn::stream(sk) } else { Conn::datagram(sk) };
        let is_tcp = conn.is_tcp();
        let timeout = Instant::now() + opts.timeout;
        loop {
            let mut reply = pin!(conn.recv_msg().fuse());
            let mut t = pin!(self.rt.timer_at(timeout).fuse());
            select_biased! {
                r = reply => match r {
                    Ok(buf) => {
                        if qid_matches(&buf, &framed, use_tcp) {
                            settle_probe(&self.effects, &self.health, pserver, is_tcp, Some(&buf));
                            return;
                        }
                    }
                    Err(_) => return,
                },
                _ = t => {
                    settle_probe(&self.effects, &self.health, pserver, is_tcp, None);
                    return;
                }
            }
        }
    }

    /// ares_gethostbyname: the pre-DNS cascade (ASCII/onion/family/IP-literal/
    /// hosts/localhost/HOSTALIASES/no-servers/query-cache) then search-domain DNS.
    /// Preflight has no `.await`, so a sync hit fires re-entrantly on first poll.
    pub(crate) async fn gethostbyname(self, hostname: String, family: c_int) -> HostReply {
        let timeouts = Cell::new(0);
        let result = self.gethostbyname_inner(hostname, family, &timeouts).await;
        (result, timeouts.get())
    }

    async fn gethostbyname_inner(
        &self,
        hostname: String,
        family: c_int,
        timeouts: &Cell<c_int>,
    ) -> Result<Hostent, AresError> {
        if !hostname.is_ascii() {
            return Err(ARES_EBADNAME.into());
        }
        if is_onion_domain(&hostname) {
            return Err(ARES_ENOTFOUND.into());
        }
        let filter = AddressFamily::from_af(family).ok_or(ARES_ENOTIMP)?;

        // IP literal (a family mismatch falls through, not fails).
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            let matches = match filter {
                AddressFamily::Ipv4 => ip.is_ipv4(),
                AddressFamily::Ipv6 => ip.is_ipv6(),
                AddressFamily::Any => true,
            };
            if matches {
                return Ok(self.finalize_hostent(Hostent::new(hostname, vec![ip])));
            }
        }

        // Resolver order (`lookup` from resolv.conf, default "fb"): 'f' = hosts
        // file, 'b' = DNS; unknown chars ignored (upstream next_lookup).
        let order: Vec<char> = self.lookups.chars().collect();
        let mut last_error: AresError = ARES_ECONNREFUSED.into();
        for ch in order {
            match ch {
                'f' => {
                    if let Some(lookup) = self.hostsfile().lookup(&hostname, filter) {
                        if !lookup.addrs.is_empty() {
                            return Ok(self.finalize_hostent(Hostent::from_lookup(lookup)));
                        }
                    }

                    // RFC 6761: localhost / *.localhost → loopback (part of the
                    // upstream file lookup).
                    if is_localhost(&hostname) {
                        let addrs = match filter {
                            AddressFamily::Ipv4 => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                            AddressFamily::Ipv6 => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                            AddressFamily::Any => vec![IpAddr::V6(Ipv6Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::LOCALHOST)],
                        };
                        return Ok(self.finalize_hostent(Hostent::new(hostname, addrs)));
                    }
                }
                'b' => {
                    // RFC 6761: localhost names never reach the nameservers.
                    if is_localhost(&hostname) {
                        continue;
                    }

                    // HOSTALIASES (single-label names); NOALIASES disables it.
                    let (resolved, alias_found) = match hostaliases_lookup(
                        &hostname,
                        self.flags & ARES_FLAG_NOALIASES != 0,
                    ) {
                        Ok(Some(alias)) => (alias, true),
                        Ok(None) => (hostname.clone(), false),
                        Err(status) => return Err(status.into()),
                    };

                    if self.endpoints.is_empty() {
                        last_error = ARES_ENOSERVER.into();
                        continue;
                    }

                    let cache_rtype = if matches!(filter, AddressFamily::Ipv4) { RTYPE_A } else { RTYPE_AAAA };
                    let cache_family = if matches!(filter, AddressFamily::Ipv4) { AF_INET } else { AF_INET6 };
                    let cache_key = CacheKey::new(
                        &resolved,
                        cache_rtype,
                        ARES_CLASS_IN,
                        0,
                        self.recursion_desired(),
                        false,
                    );
                    let cached = self.cache.borrow_mut().get(&cache_key, Instant::now());
                    if let Some(cached) = cached {
                        if let Ok(rrs) = addr_reply(&cached, cache_rtype, ReplyRequire::Items) {
                            return Ok(self.finalize_hostent(Hostent::from_parsed(rrs, cache_family)));
                        }
                    }

                    // Candidate names in order; trailing dots kept verbatim
                    // (unlike ares_search) so query/cache/store keys match.
                    let dots = resolved.chars().filter(|&c| c == '.').count() as u32;
                    let no_search = alias_found || self.flags & ARES_FLAG_NOSEARCH != 0;
                    let names: Vec<String> = if !no_search && dots < self.config.options.ndots && !self.config.search.is_empty() {
                        let mut v: Vec<String> = self.config.search.iter().map(|d| format!("{resolved}.{d}")).collect();
                        v.push(resolved.clone());
                        v
                    } else {
                        vec![resolved.clone()]
                    };
                    // AF_UNSPEC queries A+AAAA in parallel via the shared core;
                    // the Hostent holds one family, preferring IPv6.
                    let rtypes: Vec<u16> = match family {
                        AF_INET => vec![RTYPE_A],
                        AF_INET6 => vec![RTYPE_AAAA],
                        _ => vec![RTYPE_A, RTYPE_AAAA],
                    };
                    let lookup = self.resolve_addrinfo(&names, &rtypes, true).await;
                    timeouts.set(lookup.timeouts);
                    if lookup.replies.is_empty() {
                        last_error = lookup.status;
                        continue;
                    }
                    let pick = lookup.replies.iter().position(|f| f.rtype == RTYPE_AAAA).unwrap_or(0);
                    let Some(reply) = lookup.replies.into_iter().nth(pick) else {
                        last_error = ARES_ENODATA.into();
                        continue;
                    };
                    let hfamily = if reply.rtype == RTYPE_AAAA { AF_INET6 } else { AF_INET };

                    if self.cache.borrow().enabled() {
                        let mut store = vec![lookup.name.clone()];
                        if resolved != lookup.name {
                            store.push(resolved.clone());
                        }
                        let ttl = reply.rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        let template = CacheKey::new(
                            &lookup.name,
                            reply.rtype,
                            ARES_CLASS_IN,
                            0,
                            self.recursion_desired(),
                            false,
                        );
                        self.cache.borrow_mut().store_names(store, &template, ttl, &reply.buf, Instant::now());
                    }
                    let rrs = reply.rrs;
                    return Ok(self.finalize_hostent(Hostent::from_parsed(rrs, hfamily)));
                }
                _ => {}
            }
        }
        Err(last_error)
    }

    /// ares_gethostbyaddr: hosts-file reverse lookup, then a single PTR query.
    pub(crate) async fn gethostbyaddr(self, ip: IpAddr, family: c_int) -> HostReply {
        if let Some(lookup) = self.hostsfile().reverse_lookup(ip) {
            return (Ok(Hostent::from_lookup(lookup)), 0);
        }

        if self.endpoints.is_empty() {
            return (Err(ARES_ENOSERVER.into()), 0);
        }

        let payload = match dns_query_payload(
            &rdns_name(ip),
            u32::from(RECORD_TYPE_PTR),
            u32::from(ARES_CLASS_IN),
            self.recursion_desired(),
        ) {
            Ok(p) => p,
            Err(e) => return (Err(e), 0),
        };
        let (result, timeouts) = self.request(payload, true, &QuerySignals::default()).await;
        let result = match result {
            Ok(buf) => on_host_reply(Ok(&buf), RECORD_TYPE_PTR, family, Some(ip)),
            Err(status) => Err(AresError::from(status)),
        };
        (result, timeouts)
    }

    /// ares_getnameinfo: three synchronous short-circuits (service-only /
    /// NUMERICHOST / no-servers), else a single PTR query + `assemble_nameinfo`.
    pub(crate) async fn getnameinfo(
        self,
        addr: AddrInfo,
        flags: c_int,
    ) -> NameinfoReply {
        let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
            flags | ARES_NI_LOOKUPHOST
        } else {
            flags
        };

        let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
        let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

        if want_service && !want_host {
            let service = get_service_string(&Services::default(), addr.port, flags);
            return NameinfoReply { status: ARES_SUCCESS.into(), node: None, service, timeouts: 0 };
        }

        if (flags & ARES_NI_NUMERICHOST) != 0 {
            if (flags & ARES_NI_NAMEREQD) != 0 {
                return NameinfoReply { status: ARES_EBADFLAGS.into(), node: None, service: None, timeouts: 0 };
            }
            // IP strings never contain NUL; degrade to an empty node if violated.
            let node = CString::new(format_ip_with_scope(&addr.ip, addr.scope_id, flags)).unwrap_or_default();
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

        let payload = match dns_query_payload(
            &rdns_name(addr.ip),
            u32::from(RECORD_TYPE_PTR),
            u32::from(ARES_CLASS_IN),
            self.recursion_desired(),
        ) {
            Ok(p) => p,
            Err(e) => {
                return NameinfoReply {
                    status: e,
                    node: None,
                    service: None,
                    timeouts: 0,
                }
            }
        };
        let (result, io_timeouts) = self.request(payload, true, &QuerySignals::default()).await;

        let dns_result: Result<&[u8], AresError> = match result {
            Ok(ref buf) => Ok(&buf[..]),
            Err(status) => Err(AresError::from(status)),
        };
        assemble_nameinfo(dns_result, addr.ip, addr.scope_id, addr.port, flags, io_timeouts)
    }

    /// ares_search (legacy): iterate the search plan with freshly built payloads
    /// carrying the caller's class/type.
    pub(crate) async fn search(
        self,
        name: String,
        dnsclass: u32,
        dnstype: u32,
        retry_server_error: bool,
    ) -> Delivery {
        if let Err(e) = validate_query_class_type(dnsclass, dnstype) {
            return Delivery::Raw { result: Err(e.code()), timeouts: 0 };
        }
        let rd = self.recursion_desired();
        self.search_plan(
            name,
            move |candidate| dns_query_payload(candidate, dnstype, dnsclass, rd),
            retry_server_error,
            true,
        )
        .await
    }

    /// ares_search_dnsrec: iterate the search plan over a duplicate of the
    /// caller's record, replacing only query[0]'s name.
    pub(crate) async fn search_dnsrec(
        self,
        template: ares_dns_record_t,
        retry_server_error: bool,
    ) -> Delivery {
        let name = match template.query_at(0) {
            Some((name, _, _)) => name.to_string_lossy().into_owned(),
            None => return Delivery::Raw { result: Err(ARES_EBADQUERY), timeouts: 0 },
        };
        self.search_plan(
            name,
            move |candidate| payload_from_template(&template, candidate),
            retry_server_error,
            // Upstream duplicates the record unchanged: never synthesize an OPT.
            false,
        )
        .await
    }

    /// Shared search-domain driver: retry NXDOMAIN/NODATA/timeout, plus (for the
    /// dnsrec flavor) SERVFAIL/REFUSED/NOTIMP when `retry_server_error`.
    async fn search_plan<F>(
        &self,
        name: String,
        make_payload: F,
        retry_server_error: bool,
        synthesize_edns: bool,
    ) -> Delivery
    where
        F: Fn(&str) -> Result<BytesMut, AresError>,
    {
        if self.endpoints.is_empty() {
            return Delivery::Raw { result: Err(ARES_ENOSERVER), timeouts: 0 };
        }

        let (search_name, alias_found) = match hostaliases_lookup(
            &name,
            self.flags & ARES_FLAG_NOALIASES != 0,
        ) {
            Ok(Some(alias)) => (alias, true),
            Ok(None) => (name, false),
            Err(status) => return Delivery::Raw { result: Err(status), timeouts: 0 },
        };
        let no_search = alias_found || self.flags & ARES_FLAG_NOSEARCH != 0;
        let mut plan =
            SearchPlan::for_search(&search_name, self.config.options.ndots, &self.config.search, no_search);
        let mut had_nodata = false;
        let mut timeouts: c_int = 0;
        let mut first = true;
        let sig = QuerySignals::default();

        loop {
            let payload = match make_payload(&plan.current) {
                Ok(p) => p,
                Err(e) => return Delivery::Raw { result: Err(e.code()), timeouts },
            };
            // Only the first query of a lookup is eligible to spawn a failover probe.
            let probe_payload = if first { make_payload(&plan.current).ok() } else { None };
            first = false;
            let mut primary = pin!(self.request(payload, synthesize_edns, &sig).fuse());
            let (result, io_timeouts) = match probe_payload {
                Some(pp) => {
                    let mut probe = pin!(self.run_probe(pp).fuse());
                    // Probe-biased race, but still drive an in-flight probe to
                    // completion: upstream's probe is independent, and dropping it
                    // would leave a recovered server marked failed.
                    match select_biased! {
                        _ = probe => None,
                        r = primary => Some(r),
                    } {
                        Some(r) => {
                            probe.await;
                            r
                        }
                        None => primary.await,
                    }
                }
                None => primary.await,
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

            // Search-domain iteration: NXDOMAIN/NODATA/TIMEOUT, plus server
            // errors for the dnsrec flavor.
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
            return Delivery::Raw { result: Err(status.code()), timeouts };
        }
    }

    /// Query `name` for each family concurrently on the shared mailbox (replies
    /// self-demux by fd). An A answer with real records sets `cancelled` so the AAAA
    /// sibling stops retrying; IPv6 success does NOT cancel A.
    async fn query_families(&self, name: &str, rtypes: &[u16]) -> Vec<QueryOutcome> {
        let rd = self.recursion_desired();
        let a_idx = rtypes.iter().position(|&rt| rt == RTYPE_A);
        // Shared by both families: an A answer cancels the AAAA sibling's retries.
        let sig = QuerySignals::default();
        let mut results: Vec<Option<QueryOutcome>> = (0..rtypes.len()).map(|_| None).collect();

        let sig = &sig;
        let sub = |i: usize| {
            let payload = dns_query_payload(name, u32::from(rtypes[i]), u32::from(ARES_CLASS_IN), rd);
            async move {
                match payload {
                    Ok(p) => self.request(p, true, sig).await,
                    Err(e) => (Err(e.code()), 0),
                }
            }
        };
        if rtypes.len() == 1 {
            results[0] = Some(sub(0).await);
        } else {
            let mut f0 = pin!(sub(0).fuse());
            let mut f1 = pin!(sub(1).fuse());
            while results.iter().any(Option::is_none) {
                select_biased! {
                    r = f0 => {
                        // A completed: cancel the AAAA sibling on a real answer.
                        if Some(0) == a_idx {
                            if let (Ok(buf), _) = &r {
                                let s = summarize(buf, 0);
                                if s.rcode == 0 && s.ancount > 0 {
                                    sig.cancelled.set(true);
                                }
                            }
                        }
                        results[0] = Some(r);
                    }
                    r = f1 => { results[1] = Some(r); }
                }
            }
        }
        results.into_iter().flatten().collect()
    }

    /// Shared address-resolution DNS phase for `gethostbyname`/`getaddrinfo`: try
    /// each candidate name, querying its families with an optional one-shot probe.
    /// A name succeeds if any family yields records.
    async fn resolve_addrinfo(&self, names: &[String], rtypes: &[u16], probe: bool) -> AddrLookup {
        let rd = self.recursion_desired();
        let mut timeouts: c_int = 0;
        let mut last_error: AresError = ARES_ENODATA.into();
        let mut had_nodata = false;

        for (i, name) in names.iter().enumerate() {
            let batch = self.query_families(name, rtypes);
            let probe_payload = if probe && i == 0 {
                dns_query_payload(name, u32::from(rtypes[0]), u32::from(ARES_CLASS_IN), rd).ok()
            } else {
                None
            };
            let results = match probe_payload {
                Some(probe_payload) => {
                    let mut b = pin!(batch.fuse());
                    let mut p = pin!(self.run_probe(probe_payload).fuse());
                    // Probe-biased race; still drive an in-flight probe to
                    // completion so a recovered server is not left marked failed.
                    match select_biased! {
                        _ = p => None,
                        r = b => Some(r),
                    } {
                        Some(r) => {
                            p.await;
                            r
                        }
                        None => b.await,
                    }
                }
                None => batch.await,
            };

            let mut replies: Vec<FamilyReply> = Vec::new();
            for (&rtype, (result, io_timeouts)) in rtypes.iter().zip(results) {
                match result {
                    Ok(buf) => match addr_reply(&buf, rtype, ReplyRequire::Items) {
                        Ok(rrs) => {
                            timeouts += io_timeouts;
                            replies.push(FamilyReply { rtype, buf, rrs });
                        }
                        Err(e) => {
                            if e.code() == ARES_ENODATA {
                                had_nodata = true;
                            }
                            last_error = e;
                        }
                    },
                    Err(status) => {
                        if status == ARES_ETIMEOUT {
                            timeouts += 1;
                        }
                        last_error = AresError::from(status);
                    }
                }
            }

            if !replies.is_empty() {
                return AddrLookup { name: name.clone(), replies, status: ARES_SUCCESS.into(), timeouts };
            }

            // Advance while the aggregate code is retryable.
            let code = last_error.code();
            let retryable = matches!(
                code,
                ARES_ENODATA | ARES_ENOTFOUND | ARES_ETIMEOUT | ARES_ESERVFAIL | ARES_ENOTIMP | ARES_EREFUSED
            );
            if !(retryable && i + 1 < names.len()) {
                break;
            }
            last_error = ARES_ENODATA.into();
        }

        // Finalize: NXDOMAIN after an earlier empty answer reports as ENODATA.
        let code = last_error.code();
        let status = if had_nodata && code == ARES_ENOTFOUND { ARES_ENODATA } else { code };
        let name = names.last().cloned().unwrap_or_default();
        AddrLookup { name, replies: Vec::new(), status: status.into(), timeouts }
    }

    /// ares_getaddrinfo: preflight, then the configured lookup order (hosts `f` /
    /// DNS `b`), merging family records, RFC 6724 sorting unless ARES_AI_NOSORT,
    /// and carrying the CNAME chain + canonical name.
    pub(crate) async fn getaddrinfo(
        self,
        hostname_raw: String,
        ai_family: c_int,
        ai_flags: c_int,
        socktype: c_int,
        protocol: c_int,
    ) -> AddrInfoOut {
        // The raw name keeps its trailing dot for the SearchPlan; checks and the
        // delivered canonical name use the stripped form.
        let hostname = hostname_raw.strip_suffix('.').unwrap_or(&hostname_raw);

        if !matches!(ai_family, libc::AF_INET | libc::AF_INET6 | libc::AF_UNSPEC) {
            return fail(ARES_ENOTIMP);
        }
        if hostname.is_empty() || is_onion_domain(hostname) {
            return fail(ARES_ENOTFOUND);
        }

        let can_name = ai_flags & crate::ffi::ARES_AI_CANONNAME != 0;
        let env_hosts = ai_flags & crate::ffi::ARES_AI_ENVHOSTS != 0;
        let no_sort = ai_flags & crate::ffi::ARES_AI_NOSORT != 0;

        // IP literal (a family mismatch fails — no fall-through).
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            let matches = match ai_family {
                libc::AF_INET => ip.is_ipv4(),
                libc::AF_INET6 => ip.is_ipv6(),
                libc::AF_UNSPEC => true,
                _ => false,
            };
            if matches {
                let cnames = if can_name {
                    vec![CnameEntry {
                        ttl: 0,
                        alias: None,
                        name: CString::new(hostname).ok(),
                    }]
                } else {
                    Vec::new()
                };
                return AddrInfoOut::success(
                    hostname.to_string(),
                    vec![AddrRecord { ip, ttl: 0 }],
                    cnames,
                    socktype,
                    protocol,
                );
            }
            return fail(ARES_ENOTFOUND);
        }

        let family_filter = AddressFamily::from_af(ai_family).unwrap_or(AddressFamily::Any);
        let order: Vec<char> = self.lookups.chars().collect();
        let mut last_error: AresError = ARES_ECONNREFUSED.into();

        for ch in order {
            match ch {
                'f' => {
                    // Hosts file, honouring ARES_AI_ENVHOSTS when requested.
                    if let Some(lookup) = self.hosts_lookup(hostname, family_filter, env_hosts) {
                        if !lookup.addrs.is_empty() {
                            let mut records: Vec<AddrRecord> = lookup
                                .addrs
                                .iter()
                                .map(|&ip| AddrRecord { ip, ttl: 0 })
                                .collect();
                            // Upstream merges the loopback fallback for localhost
                            // even when the hosts entry covered only one family.
                            if is_localhost(hostname) {
                                merge_loopback(&mut records, family_filter);
                            }
                            if !no_sort {
                                sort_addrinfo(&mut records);
                            }
                            let cnames = if can_name {
                                hosts_cnames(&lookup)
                            } else {
                                Vec::new()
                            };
                            return AddrInfoOut::success(
                                hostname.to_string(),
                                records,
                                cnames,
                                socktype,
                                protocol,
                            );
                        }
                    }

                    // RFC 6761 loopback fallback (also the whole answer when no
                    // hosts entry exists).
                    if is_localhost(hostname) {
                        let mut records: Vec<AddrRecord> = Vec::new();
                        merge_loopback(&mut records, family_filter);
                        if !no_sort {
                            sort_addrinfo(&mut records);
                        }
                        return AddrInfoOut::success(
                            hostname.to_string(),
                            records,
                            Vec::new(),
                            socktype,
                            protocol,
                        );
                    }
                }
                'b' => {
                    if is_localhost(hostname) {
                        continue;
                    }
                    if self.endpoints.is_empty() {
                        last_error = ARES_ENOSERVER.into();
                        continue;
                    }

                    let rtypes: Vec<u16> = match ai_family {
                        libc::AF_INET => vec![RTYPE_A],
                        libc::AF_INET6 => vec![RTYPE_AAAA],
                        _ => vec![RTYPE_A, RTYPE_AAAA],
                    };
                    let no_aliases = self.flags & ARES_FLAG_NOALIASES != 0;
                    let (search_name, alias_found) = match hostaliases_lookup(&hostname_raw, no_aliases) {
                        Ok(Some(alias)) => (alias, true),
                        Ok(None) => (hostname_raw.clone(), false),
                        Err(status) => return fail(status),
                    };
                    let no_search = alias_found || self.flags & ARES_FLAG_NOSEARCH != 0;
                    let names = SearchPlan::for_search(
                        &search_name,
                        self.config.options.ndots,
                        &self.config.search,
                        no_search,
                    )
                    .into_names();
                    let lookup = self.resolve_addrinfo(&names, &rtypes, false).await;
                    if lookup.replies.is_empty() {
                        last_error = lookup.status;
                        continue;
                    }
                    let mut cnames: Vec<CnameEntry> = Vec::new();
                    let mut records: Vec<AddrRecord> = Vec::new();
                    for reply in lookup.replies {
                        records.extend(reply.rrs.items);
                        cnames.extend(reply.rrs.cnames);
                    }
                    let name = cnames
                        .iter()
                        .rev()
                        .find_map(|c| c.name.clone())
                        .map(|c| c.to_string_lossy().into_owned())
                        .unwrap_or(lookup.name);
                    if !no_sort {
                        sort_addrinfo(&mut records);
                    }
                    return AddrInfoOut::success(name, records, cnames, socktype, protocol);
                }
                _ => {}
            }
        }
        fail(last_error.code())
    }
}

/// One family's reply within an address lookup: wire type, raw reply (kept for
/// the gethostbyname query cache), and parsed address records.
struct FamilyReply {
    rtype: u16,
    buf: Vec<u8>,
    rrs: ParsedRRs<AddrRecord>,
}

/// Outcome of [`AsyncClient::resolve_addrinfo`]: the name that produced records
/// (or the last tried), per-family replies, status, and timeout count.
struct AddrLookup {
    name: String,
    replies: Vec<FamilyReply>,
    status: AresError,
    timeouts: c_int,
}

/// The safe result the FFI turns into an `ares_addrinfo`.
pub(crate) struct AddrInfoOut {
    pub name: String,
    pub records: Vec<AddrRecord>,
    pub cnames: Vec<CnameEntry>,
    pub socktype: c_int,
    pub protocol: c_int,
    pub status: AresError,
}

impl AddrInfoOut {
    fn success(
        name: String,
        records: Vec<AddrRecord>,
        cnames: Vec<CnameEntry>,
        socktype: c_int,
        protocol: c_int,
    ) -> Self {
        AddrInfoOut {
            name,
            records,
            cnames,
            socktype,
            protocol,
            status: ARES_SUCCESS.into(),
        }
    }
}

fn fail(status: c_int) -> AddrInfoOut {
    AddrInfoOut {
        name: String::new(),
        records: Vec::new(),
        cnames: Vec::new(),
        socktype: 0,
        protocol: 0,
        status: status.into(),
    }
}

/// Add RFC 6761 loopback addresses for any requested family the hosts entry did
/// not provide. IPv6 before IPv4, matching upstream.
fn merge_loopback(records: &mut Vec<AddrRecord>, filter: AddressFamily) {
    let has_v4 = records.iter().any(|r| r.ip.is_ipv4());
    let has_v6 = records.iter().any(|r| r.ip.is_ipv6());
    if matches!(filter, AddressFamily::Any | AddressFamily::Ipv6) && !has_v6 {
        records.push(AddrRecord { ip: IpAddr::V6(Ipv6Addr::LOCALHOST), ttl: 0 });
    }
    if matches!(filter, AddressFamily::Any | AddressFamily::Ipv4) && !has_v4 {
        records.push(AddrRecord { ip: IpAddr::V4(Ipv4Addr::LOCALHOST), ttl: 0 });
    }
}

/// Hosts-file CNAME chain: each alias points at the entry's primary host; with
/// no aliases, a single alias-less entry names the primary.
fn hosts_cnames(lookup: &HostLookup) -> Vec<CnameEntry> {
    let primary = CString::new(lookup.canonical.as_str()).ok();
    if lookup.aliases.is_empty() {
        return vec![CnameEntry { ttl: 0, alias: None, name: primary }];
    }
    lookup
        .aliases
        .iter()
        .map(|alias| CnameEntry {
            ttl: 0,
            alias: CString::new(alias.as_str()).ok(),
            name: primary.clone(),
        })
        .collect()
}

/// HOSTALIASES for single-label names: `Ok(Some)` means use exactly that target
/// as the sole query name (no search-domain expansion); `Ok(None)` means normal
/// search applies. `PermissionDenied` → `ARES_EFILE`.
fn hostaliases_lookup(hostname: &str, no_aliases: bool) -> Result<Option<String>, c_int> {
    if no_aliases || hostname.contains('.') {
        return Ok(None);
    }
    let Ok(aliases_path) = std::env::var("HOSTALIASES") else {
        return Ok(None);
    };
    match std::fs::read_to_string(&aliases_path) {
        Ok(content) => {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(hostname) {
                    return Ok(Some(parts[1].to_string()));
                }
            }
            Ok(None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(ARES_EFILE),
        Err(_) => Ok(None),
    }
}

/// A fire-and-forget side effect the ffi applies after a poll.
pub(crate) enum Effect {
    NotifyServerState { server: usize, ok: bool, tcp: bool },
}

/// Signals shared between the `request`s of one lookup and their host.
#[derive(Default)]
pub(crate) struct QuerySignals {
    /// Intra-lookup coordination: `query_families` sets this once its A answer
    /// has real records so the sibling AAAA `request` stops retrying (an
    /// in-flight reply still delivers).
    pub cancelled: Cell<bool>,
    /// The transaction id actually reserved on the wire for the current query
    /// (after any shared-socket reroll); `0` means none was reserved.
    pub qid: Cell<u16>,
}

/// A hostent lifecycle's result plus its timeout count, for `ares_host_callback`.
pub(crate) type HostReply = (Result<Hostent, AresError>, c_int);

impl AsyncClient {
    fn notify(&self, actions: Vec<ReactorAction>) {
        let mut effects = self.effects.borrow_mut();
        for a in actions {
            match a {
                ReactorAction::NotifyServerState { server, ok, tcp } => {
                    effects.push(Effect::NotifyServerState { server, ok, tcp })
                }
            }
        }
    }
}

/// What the raw (ares_query / ares_send) lifecycle delivers to C.
pub(crate) enum Delivery {
    Raw { result: Result<Vec<u8>, c_int>, timeouts: c_int },
}

/// A server's precomputed connect targets.
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
    pub maxtimeout: Option<Duration>,
    pub failover_chance: u16,
    pub failover_delay: u64,
    pub ignore_tc: bool,
    pub no_check_resp: bool,
}

/// Upstream `ares_calc_query_timeout`: base timeout doubled per full server
/// round, capped by ARES_OPT_MAXTIMEOUTMS, jittered into [0.5, 1.0]× for retries.
/// Never below the base.
fn calc_query_timeout(
    base: Duration,
    try_count: u32,
    nservers: usize,
    maxtimeout: Option<Duration>,
) -> Duration {
    let mut timeout = base;
    let rounds = (try_count as usize)
        .checked_div(nservers)
        .unwrap_or(0);
    if rounds > 0 {
        let factor = 1u32.checked_shl(rounds as u32).unwrap_or(u32::MAX);
        timeout = timeout.saturating_mul(factor);
        if let Some(max) = maxtimeout.filter(|m| !m.is_zero()) {
            if timeout > max {
                timeout = max;
            }
        }
        // Jitter: r / u16::MAX * 0.5 subtracted (upstream float arithmetic).
        let r = rand::thread_rng().r#gen::<u16>();
        let delta_multiplier = (r as f64 / u16::MAX as f64) * 0.5;
        timeout = timeout.mul_f64(1.0 - delta_multiplier);
    }
    if timeout < base {
        timeout = base;
    }
    timeout
}

/// Wrap a DNS payload in the 2-byte big-endian length prefix (RFC 1035 §4.2.2).
fn frame_tcp(payload: &[u8]) -> BytesMut {
    let mut framed = BytesMut::with_capacity(2 + payload.len());
    framed.put_u16(payload.len() as u16);
    framed.extend_from_slice(payload);
    framed
}

/// Validate an untruncated class/type pair like ares_dns_record_query_add: both
/// must fit 16 bits and pass validity checks (unknown in-range query types OK).
pub(crate) fn validate_query_class_type(qclass: u32, qtype: u32) -> Result<(), AresError> {
    if qclass > u16::MAX as u32
        || qtype > u16::MAX as u32
        || !rec_type_isvalid(qtype, true)
        || !class_isvalid(qclass as u16, qtype, true)
    {
        return Err(ARES_EFORMERR.into());
    }
    Ok(())
}

/// Build a UDP-form DNS query payload (fresh random transaction id) through the
/// shared `build_query` validator/writer.
pub(crate) fn dns_query_payload(
    name: &str,
    qtype: u32,
    qclass: u32,
    rd: bool,
) -> Result<BytesMut, AresError> {
    let transaction_id = rand::thread_rng().r#gen::<u16>();
    let packet = build_query(name, qclass, qtype, transaction_id, rd, 0)?;
    Ok(BytesMut::from(packet.as_slice()))
}

/// Duplicate a caller-supplied record via serialize/parse, replace query[0]'s
/// name, and stamp a fresh id.
fn payload_from_template(template: &ares_dns_record_t, name: &str) -> Result<BytesMut, AresError> {
    let wire = write_record(template)?;
    let mut rec = parse_record(&wire, 0)?;
    rec.query_set_name(0, name)?;
    rec.set_id(rand::thread_rng().r#gen::<u16>());
    let out = write_record(&rec)?;
    Ok(BytesMut::from(out.as_slice()))
}

/// The pure body of ares_create_query/ares_mkquery: escaped-name analysis, RFC
/// 7686 .onion rejection, label validation, and wire assembly. A positive
/// `max_udp_size` appends an OPT RR; zero or negative means "no EDNS".
pub(crate) fn build_query(
    name_str: &str,
    dnsclass: u32,
    qtype: u32,
    id: u16,
    rd: bool,
    max_udp_size: i32,
) -> Result<Vec<u8>, AresError> {
    let max_udp_size: u16 = if max_udp_size > 0 {
        if max_udp_size > u16::MAX as i32 {
            return Err(ARES_EFORMERR.into());
        }
        max_udp_size as u16
    } else {
        0
    };
    let has_unescaped_trailing_dot = if let Some(prefix) = name_str.strip_suffix('.') {
        let backslash_count = prefix
            .as_bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        backslash_count % 2 == 0
    } else {
        false
    };

    let lower = name_str.to_lowercase();
    let check = if has_unescaped_trailing_dot {
        lower.strip_suffix('.').unwrap_or(&lower)
    } else {
        &lower
    };
    if check.ends_with(".onion") || check == "onion" {
        return Err(ARES_ENOTFOUND.into());
    }

    // class/type checked before the name is written (upstream order).
    validate_query_class_type(dnsclass, qtype)?;

    let clean_name = if has_unescaped_trailing_dot {
        name_str.strip_suffix('.').unwrap_or(name_str)
    } else {
        name_str
    };
    let labels: Vec<&str> = if clean_name.is_empty() {
        vec![]
    } else {
        let mut result = Vec::new();
        let mut current_start = 0;
        let bytes = clean_name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
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

    // Total is the unescaped presentation length (upstream's 255-byte check).
    let mut total_len = 0usize;
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.is_empty() {
            return Err(ARES_EBADNAME.into());
        }
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
        total_len += unescaped.len();
    }
    if !labels.is_empty() && total_len + labels.len() - 1 > 255 {
        return Err(ARES_EBADNAME.into());
    }

    let flags: u16 = if rd { 0x0100 } else { 0x0000 };
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    let arcount: u16 = if max_udp_size > 0 { 1 } else { 0 };
    packet.extend_from_slice(&arcount.to_be_bytes());

    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.len() > 63 {
            return Err(ARES_EBADNAME.into());
        }
        packet.push(unescaped.len() as u8);
        packet.extend_from_slice(&unescaped);
    }
    packet.push(0);
    packet.extend_from_slice(&(qtype as u16).to_be_bytes());
    packet.extend_from_slice(&(dnsclass as u16).to_be_bytes());

    if max_udp_size > 0 {
        packet.push(0);
        packet.extend_from_slice(&41u16.to_be_bytes());
        packet.extend_from_slice(&max_udp_size.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
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

/// Everything getnameinfo's PTR delivery needs: NOFQDN truncation, the
/// ENOTFOUND+!NAMEREQD numeric fallback, and the LOOKUPSERVICE gate.
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

pub(crate) fn format_ip_with_scope(ip: &IpAddr, scope_id: u32, flags: i32) -> String {
    match ip {
        // The scope id is appended regardless of the flag/scope_id check; the
        // branches are intentionally identical.
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

pub(crate) fn get_service_string(services: &Services, port: u16, flags: i32) -> Option<CString> {
    if port == 0 {
        return None;
    }

    // A numeric port string never contains NUL, so this is always `Some`.
    let numeric = || CString::new(port.to_string()).ok();

    if flags & ARES_NI_NUMERICSERV != 0 {
        return numeric();
    }

    let prefer_udp = (flags & ARES_NI_DGRAM) != 0;

    // Fall back to numeric (also when a service name has an embedded NUL).
    services
        .lookup_any(port, prefer_udp)
        .and_then(|name| CString::new(name).ok())
        .or_else(numeric)
}

/// How a getaddrinfo service string resolves to a port.
pub(crate) enum ServicePort {
    Port(u16),
    /// Not numeric and not in the well-known table: the shim asks the system
    /// resolver (getservbyname), defaulting to 0.
    NeedSystemLookup,
}

pub(crate) fn service_to_port(svc: &str) -> ServicePort {
    if let Ok(p) = svc.parse::<u16>() {
        return ServicePort::Port(p);
    }
    if let Some(p) = well_known_port(svc) {
        return ServicePort::Port(p);
    }
    ServicePort::NeedSystemLookup
}

/// The well-known service table consulted before libc::getservbyname.
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

/// A decoded socket address for getnameinfo.
pub(crate) struct AddrInfo {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) scope_id: u32,
}

/// Empty/onion rejection shared by ares_search and ares_search_dnsrec — checked
/// before the channel is dereferenced (fires even on a NULL channel).
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

/// ares_gethostbyaddr's direct PTR delivery: parse, add the synthetic record for
/// the queried address, and shape the hostent.
pub(crate) fn on_host_reply(res: Result<&[u8], AresError>, rtype: u16, family: i32, ip: Option<IpAddr>) -> Result<Hostent, AresError> {
    let buf = res?;
    let is_ptr = rtype == RECORD_TYPE_PTR;
    let require = if is_ptr { ReplyRequire::ItemsOrAliases } else { ReplyRequire::Items };
    let mut rrs = addr_reply(buf, rtype, require)?;
    // PTR flows always carry the ip; if that invariant broke, deliver without
    // the synthetic record rather than panic.
    if is_ptr {
        if let Some(ip) = ip {
            push_synthetic_ptr(&mut rrs, ip);
        }
    }
    Ok(Hostent::from_parsed(rrs, family))
}

/// ares_timeout's clamp decision: nothing pending → `NoTasks`; otherwise
/// whichever of the task wait and maxtv is sooner.
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

/// ares_fds' nfds tally: highest fd + 1.
pub(crate) fn nfds(fds: &[(i32, bool)]) -> i32 {
    fds.iter().map(|(fd, _)| fd + 1).max().unwrap_or(0)
}

impl AsyncClient {
    /// A fresh channel from the system config (resolv.conf + env overrides).
    /// Defaults are applied separately so options/flags set afterwards win.
    pub fn from_sysconfig_path(factory: Rc<dyn SocketFactory>, path: Option<&str>) -> Self {
        let mut client = AsyncClient::build(build_sysconfig(path), factory, 53, 53);
        let n = client.config.nameservers.len();
        client.health.borrow_mut().reset(n);
        // Upstream init_by_defaults: hosts file first, then DNS.
        client.lookups = "fb".to_string();
        if let Some(lookups) = client.config.lookups.clone() {
            client.lookups = lookups;
        }
        if let Some(sortlist) = client.config.sortlist.as_deref() {
            client.sortlist = parse_sortlist(sortlist).unwrap_or_default();
        }
        client
    }

    /// Re-read system configuration and apply it like upstream
    /// `ares_init_by_sysconfig`: explicitly-set `ARES_OPT_*` values win, then
    /// the query cache is flushed.
    pub fn reinit(&mut self) -> Result<(), AresError> {
        let path = (!self.resolvconf_path.is_empty()).then_some(self.resolvconf_path.as_str());
        let sys = build_sysconfig(path);

        let mut servers_changed = false;
        if self.optmask & ARES_OPT_SERVERS == 0
            && !sys.nameservers.is_empty()
            && sys.nameservers != self.config.nameservers
        {
            self.config.nameservers = sys.nameservers;
            self.config.tcp_ports = sys.tcp_ports;
            servers_changed = true;
        }
        if self.optmask & ARES_OPT_DOMAINS == 0 && !sys.search.is_empty() {
            self.config.search = sys.search;
        }
        if self.optmask & ARES_OPT_NDOTS == 0 {
            self.config.options.ndots = sys.options.ndots;
        }
        if self.optmask & ARES_OPT_TRIES == 0 && sys.options.attempts != 0 {
            self.config.options.attempts = sys.options.attempts;
        }
        if self.optmask & (ARES_OPT_TIMEOUTMS | ARES_OPT_TIMEOUT) == 0
            && sys.options.timeout_ms != 0
        {
            self.config.options.timeout_ms = sys.options.timeout_ms;
        }
        if self.optmask & (ARES_OPT_ROTATE | ARES_OPT_NOROTATE) == 0 {
            self.config.options.rotate = sys.options.rotate;
        }
        if self.optmask & ARES_OPT_LOOKUPS == 0 {
            if let Some(lookups) = sys.lookups {
                self.lookups = lookups;
            }
        }
        if self.optmask & ARES_OPT_SORTLIST == 0 {
            if let Some(sortlist) = sys.sortlist.as_deref() {
                self.sortlist = parse_sortlist(sortlist).unwrap_or_default();
            }
        }
        if sys.options.use_vc {
            self.flags |= ARES_FLAG_USEVC;
            self.config.options.use_vc = true;
        }
        if servers_changed {
            self.health.borrow_mut().reset(self.config.nameservers.len());
            self.cookies.borrow_mut().clear();
            let retired = self.udp_pool.borrow_mut().clear();
            drop(retired);
        }
        self.cache.borrow_mut().flush();
        Ok(())
    }

    /// Upstream `init_by_defaults`: with no nameserver configured, add the
    /// loopback default unless ARES_FLAG_NO_DFLT_SVR asks for an empty list.
    pub fn apply_defaults(&mut self) {
        // EDNS is on unless the caller explicitly supplied ARES_OPT_FLAGS.
        if self.optmask & ARES_OPT_FLAGS == 0 {
            self.flags |= ARES_FLAG_EDNS;
        }
        if self.ednspsz == 0 {
            self.ednspsz = EDNS_PACKETSZ as i32;
        }
        if self.config.nameservers.is_empty() && self.flags & ARES_FLAG_NO_DFLT_SVR == 0 {
            self.config.nameservers.push((IpAddr::V4(Ipv4Addr::LOCALHOST), None));
            self.config.tcp_ports.push(None);
        }
        self.health.borrow_mut().reset(self.config.nameservers.len());
        self.cookies.borrow_mut().clear();
    }

    /// ARES_FLAG_NORECURSE clears the RD bit in constructed queries.
    pub(crate) fn recursion_desired(&self) -> bool {
        self.flags & ARES_FLAG_NORECURSE == 0
    }

    /// The OPT UDP payload size for constructed queries: `None` when EDNS is
    /// disabled, `Some(EDNS_PACKETSZ)` for zero, and `ARES_EFORMERR` when the
    /// value does not fit the 16-bit OPT CLASS field.
    pub(crate) fn edns_udp_size(&self) -> Result<Option<u16>, AresError> {
        if self.flags & ARES_FLAG_EDNS == 0 {
            return Ok(None);
        }
        let size = if self.ednspsz == 0 { EDNS_PACKETSZ as i32 } else { self.ednspsz };
        if !(1..=u16::MAX as i32).contains(&size) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(Some(size as u16))
    }

    fn build(
        config: SysConfig,
        factory: Rc<dyn SocketFactory>,
        default_udp_port: u16,
        default_tcp_port: u16,
    ) -> Self {
        AsyncClient {
            config,
            rt: Runtime::new(factory),
            hosts: None,
            default_udp_port,
            default_tcp_port,
            socket_send_buffer_size: 0,
            socket_receive_buffer_size: 0,
            local_ip4: 0,
            local_ip6: [0; 16],
            local_dev: String::new(),
            health: Rc::new(RefCell::new(ServerHealth::default())),
            sortlist: vec![],
            flags: 0,
            ednspsz: EDNS_PACKETSZ as i32,
            cookies: Rc::new(RefCell::new(Vec::new())),
            maxtimeout: 0,
            optmask: 0,
            lookups: String::new(),
            resolvconf_path: String::new(),
            hosts_path: String::new(),
            cache: Rc::new(RefCell::new(QueryCache::default())),
            tcp_pool: Rc::new(RefCell::new(TcpPool::new())),
            udp_pool: Rc::new(RefCell::new(UdpPool::new())),
            udp_max_queries: 0,
            endpoints: Rc::new(Vec::new()),
            server_failover_retry_chance: 0,
            server_failover_retry_delay: 0,
            effects: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// The hosts table as a shared `Rc`, lazily loaded once. An empty
    /// `ARES_OPT_HOSTS_FILE` path means the system `/etc/hosts`.
    pub fn hosts(&mut self) -> Rc<Hosts> {
        let path = if self.hosts_path.is_empty() {
            "/etc/hosts".to_string()
        } else {
            self.hosts_path.clone()
        };
        self.hosts
            .get_or_insert_with(|| Rc::new(Hosts::from_path(path).unwrap_or_default()))
            .clone()
    }

    /// ares_dup: clone configuration but start with fresh reactor state (empty
    /// cache, no pooled connections, cleared failure timestamps — cloned counts).
    pub fn duplicate(&self) -> AsyncClient {
        let mut dup = AsyncClient::build(
            self.config.clone(),
            self.rt.factory(),
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
        dup.ednspsz = self.ednspsz;
        dup.maxtimeout = self.maxtimeout;
        dup.udp_max_queries = self.udp_max_queries;
        dup.socket_send_buffer_size = self.socket_send_buffer_size;
        dup.socket_receive_buffer_size = self.socket_receive_buffer_size;
        dup.local_ip4 = self.local_ip4;
        dup.local_ip6 = self.local_ip6;
        dup.local_dev = self.local_dev.clone();
        dup.optmask = self.optmask;
        dup.lookups = self.lookups.clone();
        dup.resolvconf_path = self.resolvconf_path.clone();
        dup.hosts_path = self.hosts_path.clone();
        dup.cache.borrow_mut().set_max_ttl(self.cache.borrow().max_ttl());
        dup.server_failover_retry_chance = self.server_failover_retry_chance;
        dup.server_failover_retry_delay = self.server_failover_retry_delay;
        dup
    }

    /// The optmask cascade from ares_init_options, ending with the unconditional
    /// server-health reset.
    pub fn apply_options(&mut self, optmask: i32, o: DecodedOptions) {
        // Upstream drops the SERVERS bit when no server was actually supplied.
        let mut stored_mask = optmask;
        if stored_mask & ARES_OPT_SERVERS != 0 && o.servers.is_empty() {
            stored_mask &= !ARES_OPT_SERVERS;
        }
        if optmask & ARES_OPT_SERVERS != 0 && !o.servers.is_empty() {
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
        if optmask & ARES_OPT_EDNSPSZ != 0 {
            if o.ednspsz <= 0 {
                // Non-positive drops the bit; init_by_defaults applies the default.
                stored_mask &= !ARES_OPT_EDNSPSZ;
                self.ednspsz = EDNS_PACKETSZ as i32;
            } else {
                self.ednspsz = o.ednspsz;
            }
        }
        if optmask & ARES_OPT_FLAGS != 0 {
            self.flags = o.flags;
            self.config.options.use_vc = (o.flags & ARES_FLAG_USEVC) != 0;
            self.config.options.edns0 = (o.flags & ARES_FLAG_EDNS) != 0;
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
        if optmask & ARES_OPT_SORTLIST != 0 {
            // An explicitly empty list clears the resolv.conf sortlist.
            self.sortlist = o
                .sortlist
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(addr, bits)| SortlistEntry::from_parts(addr, bits))
                .collect();
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
        if optmask & ARES_OPT_UDP_MAX_QUERIES != 0 {
            // Upstream drops the bit for a non-positive value (= unlimited).
            if o.udp_max_queries <= 0 {
                stored_mask &= !ARES_OPT_UDP_MAX_QUERIES;
            } else {
                self.udp_max_queries = o.udp_max_queries as usize;
            }
        }
        if optmask & ARES_OPT_SOCK_SNDBUF != 0 {
            if o.socket_send_buffer_size <= 0 {
                stored_mask &= !ARES_OPT_SOCK_SNDBUF;
            } else {
                self.socket_send_buffer_size = o.socket_send_buffer_size;
            }
        }
        if optmask & ARES_OPT_SOCK_RCVBUF != 0 {
            if o.socket_receive_buffer_size <= 0 {
                stored_mask &= !ARES_OPT_SOCK_RCVBUF;
            } else {
                self.socket_receive_buffer_size = o.socket_receive_buffer_size;
            }
        }
        if optmask & ARES_OPT_SERVER_FAILOVER != 0 {
            self.server_failover_retry_chance = o.failover_retry_chance;
            self.server_failover_retry_delay = o.failover_retry_delay;
        }
        self.optmask = stored_mask;
        self.apply_defaults();
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
        // Preserve explicit sortlist state (including an explicit empty list);
        // a sortlist merely inherited from resolv.conf is not reported.
        if self.optmask & ARES_OPT_SORTLIST != 0 {
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

        if self.optmask & ARES_OPT_UDP_MAX_QUERIES != 0 && self.udp_max_queries > 0 {
            base_mask |= ARES_OPT_UDP_MAX_QUERIES;
        }
        if self.optmask & ARES_OPT_SOCK_SNDBUF != 0 && self.socket_send_buffer_size > 0 {
            base_mask |= ARES_OPT_SOCK_SNDBUF;
        }
        if self.optmask & ARES_OPT_SOCK_RCVBUF != 0 && self.socket_receive_buffer_size > 0 {
            base_mask |= ARES_OPT_SOCK_RCVBUF;
        }
        if self.optmask & ARES_OPT_EDNSPSZ != 0 && self.ednspsz > 0 {
            base_mask |= ARES_OPT_EDNSPSZ;
        }

        SavedOptions {
            flags: self.flags,
            ednspsz: self.ednspsz,
            timeout: opts.timeout_ms as i32,
            tries: opts.attempts as i32,
            ndots: opts.ndots as i32,
            udp_port: self.default_udp_port,
            tcp_port: self.default_tcp_port,
            v4_servers,
            domains,
            sortlist: self.sortlist.clone(),
            maxtimeout,
            lookups,
            resolvconf_path,
            hosts_path,
            udp_max_queries: self.udp_max_queries as i32,
            socket_send_buffer_size: self.socket_send_buffer_size,
            socket_receive_buffer_size: self.socket_receive_buffer_size,
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
        self.optmask |= ARES_OPT_SERVERS;
        self.health.borrow_mut().reset(self.config.nameservers.len());
        self.cookies.borrow_mut().clear();
        let retired = self.udp_pool.borrow_mut().clear();
        drop(retired);
    }

    /// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
    pub fn clear_servers(&mut self) {
        self.config.nameservers.clear();
        self.config.tcp_ports.clear();
        self.optmask |= ARES_OPT_SERVERS;
        self.health.borrow_mut().clear();
        self.cookies.borrow_mut().clear();
        let retired = self.udp_pool.borrow_mut().clear();
        drop(retired);
    }

    /// Install a parsed CSV server list (ares_set_servers_ports_csv). A CSV
    /// `ip:port` sets both transports; the ports variant can still override TCP.
    pub fn install_csv_servers(&mut self, ns: Vec<(IpAddr, Option<u16>)>) {
        self.config.tcp_ports = ns.iter().map(|&(_, port)| port).collect();
        self.health.borrow_mut().reset(ns.len());
        self.config.nameservers = ns;
        self.optmask |= ARES_OPT_SERVERS;
        self.cookies.borrow_mut().clear();
        let retired = self.udp_pool.borrow_mut().clear();
        drop(retired);
    }

    /// The configured servers with per-entry defaults, in order.
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

impl AsyncClient {
    /// Snapshot per-server connect endpoints so a lookup never re-reads config.
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
            maxtimeout: (self.maxtimeout > 0)
                .then(|| Duration::from_millis(self.maxtimeout as u64)),
            failover_chance: self.server_failover_retry_chance,
            failover_delay: self.server_failover_retry_delay,
            ignore_tc: self.flags & ARES_FLAG_IGNTC != 0,
            no_check_resp: self.flags & ARES_FLAG_NOCHECKRESP != 0,
        }
    }

    /// Remove a dead/timed-out shared UDP conn so the next attempt opens a fresh
    /// socket. The `Rc` drops after the pool borrow ends (it may close a socket).
    fn retire_udp(&self, server: usize, conn: &Conn) {
        let Some(c) = conn.shared_udp_handle() else { return };
        let retired = self.udp_pool.borrow_mut().remove(server, &c);
        drop(retired);
    }

    /// Grow the per-server cookie table to cover `server` and pass it to `f`.
    fn with_cookie<R>(&self, server: usize, f: impl FnOnce(&mut ServerCookie) -> R) -> Option<R> {
        let mut cookies = self.cookies.borrow_mut();
        let needed = self.endpoints.len().max(server + 1);
        if cookies.len() < needed {
            cookies.resize_with(needed, ServerCookie::default);
        }
        cookies.get_mut(server).map(f)
    }

    /// Attach the COOKIE option for this send (UDP only; removed on TCP). Returns
    /// the 8-byte client cookie placed on the wire, which the response must echo.
    /// `ARES_EFORMERR` means the rewrite would exceed the 16-bit DNS limit.
    fn apply_cookie(
        &self,
        payload: &mut Vec<u8>,
        server: usize,
        use_tcp: bool,
    ) -> Result<Option<[u8; 8]>, AresError> {
        if !edns::has_opt(payload) {
            return Ok(None);
        }
        if use_tcp {
            // Cookies are deliberately not used over TCP; strip a stale one
            // (e.g. after a BADCOOKIE-driven upgrade).
            if !edns::set_cookie_option(payload, None) {
                return Err(ARES_EFORMERR.into());
            }
            return Ok(None);
        }
        let cookie = self.with_cookie(server, ServerCookie::cookie_for_query).flatten();
        let Some(cookie) = cookie else {
            // Server is known to be unsupported: no cookie.
            if !edns::set_cookie_option(payload, None) {
                return Err(ARES_EFORMERR.into());
            }
            return Ok(None);
        };
        if cookie.len() < 8 {
            return Ok(None);
        }
        let mut client = [0u8; 8];
        client.copy_from_slice(&cookie[..8]);
        if !edns::set_cookie_option(payload, Some(&cookie)) {
            return Err(ARES_EFORMERR.into());
        }
        Ok(Some(client))
    }

    /// Validate a response's COOKIE option against this server's state.
    fn validate_cookie(
        &self,
        resp: &[u8],
        sent_client: Option<&[u8; 8]>,
        server: usize,
        rcode: u16,
    ) -> CookieVerdict {
        self.with_cookie(server, |cookie| {
            cookie.validate_response(resp, sent_client, rcode)
        })
        .unwrap_or(CookieVerdict::Accept)
    }

    /// Connect-with-failover: create + connect the socket for `start`, retrying
    /// across servers; returns the live `Conn` and server index, or `Err(())` when
    /// the budget is spent. A colliding in-flight qid is re-rolled and re-stamped.
    fn connect_failover(&self, payload: &mut [u8], start: usize, use_tcp: bool) -> Result<(Conn, usize), ()> {
        let opts = self.opts();
        let stayopen = self.flags & ARES_FLAG_STAYOPEN != 0;
        let event_driven = self.optmask & ARES_OPT_EVENT_THREAD != 0;
        let mut s = start;
        for _ in 0..opts.attempts.max(1) {
            let Some(ep) = self.endpoints.get(s) else { break };
            let conn = if use_tcp {
                // Checkout-then-release: no pool guard is live while the C socket
                // callbacks fire during creation, nor while `Conn::shared` borrows.
                let pooled = self.tcp_pool.borrow().get(s);
                let checked_out = pooled.or_else(|| {
                    let sock = self.rt.tcp(ep.bind).ok()?;
                    let _ = sock.get_ref().connect(ep.tcp_addr); // optimistic (EINPROGRESS → Ok)
                    let c = TcpConn::new(sock);
                    self.tcp_pool.borrow_mut().insert(s, c.clone());
                    Some(c)
                });
                checked_out.map(|c| {
                    let (conn, tag) =
                        Conn::shared(c, qid_of(payload), || rand::thread_rng().r#gen());
                    if payload.len() >= 2 {
                        payload[0..2].copy_from_slice(&tag.to_be_bytes());
                    }
                    conn
                })
            } else {
                // Checkout an existing shared datagram conn (pruning idle ones when
                // not staying open), or create one if `udp_max_queries` is hit.
                // Creation runs with the pool unborrowed so C callbacks fire cleanly.
                let (pooled, retired) = {
                    let mut pool = self.udp_pool.borrow_mut();
                    pool.pick_or_none(s, self.udp_max_queries, stayopen)
                };
                drop(retired);
                let checked_out = pooled.or_else(|| {
                    let sk = self.rt.udp(ep.bind).ok()?;
                    let _ = sk.get_ref().connect(ep.udp_addr);
                    let c = UdpConn::new(sk, event_driven);
                    self.udp_pool.borrow_mut().insert(s, c.clone());
                    Some(c)
                });
                checked_out.map(|c| {
                    let (conn, tag) = Conn::shared_udp(
                        c,
                        qid_of(payload),
                        || rand::thread_rng().r#gen(),
                    );
                    if payload.len() >= 2 {
                        payload[0..2].copy_from_slice(&tag.to_be_bytes());
                    }
                    conn.with_udp_lease(
                        self.udp_pool.clone(),
                        s,
                        stayopen,
                        self.udp_max_queries,
                    )
                })
            };
            if let Some(conn) = conn {
                return Ok((conn, s));
            }
            if self.health.borrow().len() > 1 {
                self.health.borrow_mut().record_failure(s);
                s = self.health.borrow().pick_next();
            }
        }
        Err(())
    }

    /// ares_query / ares_query_dnsrec: `no_servers` preflight, then the wire
    /// payload. The caller's class and the channel's RD/NORECURSE flag reach the wire.
    pub(crate) fn query_payload(
        &self,
        name: &str,
        qtype: u32,
        qclass: u32,
    ) -> Result<BytesMut, AresError> {
        // Constructed queries validate the wide EDNSPSZ here, before spawning.
        self.edns_udp_size()?;
        let payload = dns_query_payload(name, qtype, qclass, self.recursion_desired())?;
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        Ok(payload)
    }

    /// ares_send / ares_send_dnsrec: length + `no_servers` preflight, then the
    /// raw payload (caller packets keep their own flags/class).
    pub(crate) fn send_payload(&self, query_buf: &[u8]) -> Result<BytesMut, AresError> {
        if query_buf.len() < 12 || query_buf.len() >= (1 << 16) {
            return Err(ARES_EBADQUERY.into());
        }
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        Ok(BytesMut::from(query_buf))
    }

    pub(crate) fn gethostbyname_file(&mut self, name: &str, family: i32) -> Result<Hostent, AresError> {
        hosts_file_lookup(self, name, family).map(Hostent::from_lookup)
    }
}

fn hosts_file_lookup(st: &mut AsyncClient, name: &str, family: i32) -> Result<HostLookup, AresError> {
    let family_filter = AddressFamily::from_af(family).ok_or(ARES_ENOTFOUND)?;

    let lookup = st.hosts().lookup(name, family_filter).ok_or(ARES_ENOTFOUND)?;
    if lookup.addrs.is_empty() {
        return Err(ARES_ENOTFOUND.into());
    }
    Ok(lookup)
}

fn no_servers(st: &AsyncClient) -> bool {
    st.config.nameservers.is_empty()
}

pub(crate) fn rdns_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.octets().into_iter().rev().map(|b| b.to_string())
            .collect::<Vec<_>>().join(".") + ".in-addr.arpa",
        // IPv6 nibbles are emitted low nibble first.
        IpAddr::V6(v6) => v6.octets().into_iter().flat_map(|b| [b >> 4, b & 0x0f]).map(|n| format!("{:x}", n))
            .collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".") + ".ip6.arpa",
    }
}

fn build_sysconfig(path: Option<&str>) -> SysConfig {
    let path = path.unwrap_or("/etc/resolv.conf");
    let try_resolv_conf = || std::fs::read_to_string(path).ok()?.parse::<SysConfig>().ok();
    let mut config = try_resolv_conf().unwrap_or_else(SysConfig::default);
    crate::core::sysconfig::apply_env_overrides(&mut config);
    config
}

pub(crate) struct ServerSpec {
    pub ip: IpAddr,
    pub udp_port: Option<u16>,
    pub tcp_port: Option<u16>,
}

/// 0 and 53 mean "no override".
pub(crate) fn normalize_port(port: u16) -> Option<u16> {
    if port == 0 || port == 53 { None } else { Some(port) }
}

/// ares_getsock's bitmask: bit i = slot readable, bit i+16 = slot writable.
pub(crate) fn getsock_mask(fds: &[(i32, bool)], slots: usize) -> i32 {
    let mut mask: i32 = 0;
    for (i, (_, writing)) in fds.iter().take(slots).enumerate() {
        if *writing {
            mask |= 1 << (i + 16);
        }
        mask |= 1 << i;
    }
    mask
}

/// A fully-owned mirror of the caller's `ares_options`. `None`/empty encode the
/// NULL-pointer cases so the cascade reproduces the exact per-field guards.
pub(crate) struct DecodedOptions {
    pub flags: i32,
    pub timeout: i32,
    pub tries: i32,
    pub ndots: i32,
    pub udp_port: u16,
    pub tcp_port: u16,
    /// Empty when the C pointer was NULL — the mask bit alone clears sysconfig
    /// servers.
    pub servers: Vec<Ipv4Addr>,
    /// None when the C pointer was NULL: the bit is then ignored.
    pub domains: Option<Vec<String>>,
    pub lookups: Option<String>,
    /// `Some` distinguishes an explicitly empty list (clear) from "not supplied".
    pub sortlist: Option<Vec<(IpAddr, u8)>>,
    pub resolvconf_path: Option<String>,
    pub hosts_path: Option<String>,
    pub maxtimeout: i32,
    pub qcache_max_ttl: u32,
    pub ednspsz: i32,
    pub udp_max_queries: i32,
    pub socket_send_buffer_size: i32,
    pub socket_receive_buffer_size: i32,
    pub failover_retry_chance: u16,
    pub failover_retry_delay: u64,
}

/// Everything ares_save_options reports. `base_mask` carries all bits except
/// SERVERS/DOMAINS, which the shim adds after the malloc'd copies land.
pub(crate) struct SavedOptions {
    pub flags: i32,
    pub ednspsz: i32,
    pub timeout: i32,
    pub tries: i32,
    pub ndots: i32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub v4_servers: Vec<Ipv4Addr>,
    pub domains: Vec<CString>,
    pub sortlist: Vec<SortlistEntry>,
    pub maxtimeout: Option<i32>,
    pub lookups: Option<CString>,
    pub resolvconf_path: Option<CString>,
    pub hosts_path: Option<CString>,
    pub udp_max_queries: i32,
    pub socket_send_buffer_size: i32,
    pub socket_receive_buffer_size: i32,
    pub base_mask: i32,
}

fn qid_of(payload: &[u8]) -> u16 {
    if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        0
    }
}

/// Fold a probe reply into server health. `None` = the probe timed out (failure
/// timestamp only).
fn settle_probe(effects: &RefCell<Vec<Effect>>, health: &RefCell<ServerHealth>, server: usize, is_tcp: bool, reply: Option<&[u8]>) {
    let mut health = health.borrow_mut();
    match reply {
        Some(buf) => {
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0xff };
            if rcode == 0 || rcode == 3 {
                if health.record_success(server) {
                    drop(health);
                    effects.borrow_mut().push(Effect::NotifyServerState { server, ok: true, tcp: is_tcp });
                }
            } else if health.record_failure(server) {
                drop(health);
                effects.borrow_mut().push(Effect::NotifyServerState { server, ok: false, tcp: is_tcp });
            }
        }
        None => health.record_failure_time(server),
    }
}

type QueryOutcome = (Result<Vec<u8>, c_int>, c_int);

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopFactory;
    impl SocketFactory for NoopFactory {
        fn create_udp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
            Err(io::Error::other("no sockets in unit tests"))
        }
        fn create_tcp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
            Err(io::Error::other("no sockets in unit tests"))
        }
    }

    pub(super) fn noop_factory() -> Rc<dyn SocketFactory> {
        Rc::new(NoopFactory)
    }

    #[test]
    fn query_payload_writes_class_and_rd_flag() {
        let p = dns_query_payload("example.com", 1, 3, true).expect("payload");
        assert_eq!(p[2], 0x01);
        assert_eq!(&p[p.len() - 2..], &3u16.to_be_bytes());

        let p = dns_query_payload("example.com", 1, 1, false).expect("payload");
        assert_eq!(p[2] & 0x01, 0);
        assert_eq!(&p[p.len() - 2..], &1u16.to_be_bytes());
    }

    struct TestSock;
    impl crate::async_runtime::socket::Socket for TestSock {
        fn as_raw_fd(&self) -> i32 {
            21
        }
        fn connect(&self, _addr: SocketAddr) -> io::Result<()> {
            Ok(())
        }
        fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
        fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }
    }

    struct TestFactory;
    impl SocketFactory for TestFactory {
        fn create_udp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
            Ok(Rc::new(TestSock))
        }
        fn create_tcp(&self, _bind: SocketAddr) -> io::Result<Rc<dyn crate::async_runtime::socket::Socket>> {
            Ok(Rc::new(TestSock))
        }
    }

    /// A shared-socket collision rerolls the tag and re-stamps the payload, so
    /// the payload carries the reserved qid (which `request` reports to the ffi).
    #[test]
    fn shared_udp_reroll_updates_payload_qid() {
        let config = SysConfig {
            nameservers: vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), None)],
            ..SysConfig::default()
        };
        let mut client = AsyncClient::build(config, Rc::new(TestFactory), 53, 53);
        client.endpoints = Rc::new(client.endpoint_snapshot());

        let payload = || BytesMut::from(&[0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        let mut first = payload();
        let (conn_a, _) = client.connect_failover(&mut first, 0, false).expect("first checkout");
        assert_eq!(qid_of(&first), 0x1234);

        let mut second = payload();
        let (conn_b, _) = client.connect_failover(&mut second, 0, false).expect("second checkout");
        assert_ne!(qid_of(&second), 0x1234, "colliding qid must be rerolled");

        drop(conn_a);
        drop(conn_b);
    }

    #[test]
    fn query_timeout_doubles_per_round_and_caps() {
        let base = Duration::from_millis(100);
        // First attempt: exactly the base timeout.
        assert_eq!(calc_query_timeout(base, 0, 2, None), base);
        // After one full round: 2x, jittered into [1x, 2x].
        let t = calc_query_timeout(base, 2, 2, None);
        assert!(t >= Duration::from_millis(100) && t <= Duration::from_millis(200));
        // Two rounds: 4x, capped at 250ms, jittered into [125, 250].
        let t = calc_query_timeout(base, 4, 2, Some(Duration::from_millis(250)));
        assert!(t >= Duration::from_millis(125) && t <= Duration::from_millis(250));
        // A cap below the base never reduces the base timeout.
        let t = calc_query_timeout(base, 0, 1, Some(Duration::from_millis(10)));
        assert_eq!(t, base);
    }

    #[test]
    fn defaults_add_loopback_unless_no_dflt_svr() {
        let mut client = AsyncClient::build(SysConfig::default(), noop_factory(), 53, 53);
        client.apply_defaults();
        assert_eq!(
            client.config.nameservers,
            vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), None)]
        );

        let mut client = AsyncClient::build(SysConfig::default(), noop_factory(), 53, 53);
        client.flags = ARES_FLAG_NO_DFLT_SVR;
        client.apply_defaults();
        assert!(client.config.nameservers.is_empty());
    }

    #[test]
    fn legacy_query_validation_rejects_bad_class_and_name() {
        assert_eq!(
            validate_query_class_type(17, 1).expect_err("bad class").code(),
            ARES_EFORMERR
        );
        assert_eq!(
            validate_query_class_type(0x1_0000, 1)
                .expect_err("class too wide")
                .code(),
            ARES_EFORMERR
        );
        assert_eq!(
            validate_query_class_type(1, 0x1_0000)
                .expect_err("type too wide")
                .code(),
            ARES_EFORMERR
        );
        let long_label = "a".repeat(64);
        assert_eq!(
            build_query(&long_label, 1, 1, 0, true, 0)
                .expect_err("long label")
                .code(),
            ARES_EBADNAME
        );
        assert_eq!(
            build_query("example..com", 1, 1, 0, true, 0)
                .expect_err("empty label")
                .code(),
            ARES_EBADNAME
        );
        assert!(build_query("example.com", 1, 1, 0, true, 0).is_ok());
        assert!(validate_query_class_type(255, 255).is_ok());
    }

    #[test]
    fn create_query_rejects_oversized_edns_payload_size() {
        for oversized in [65536, 70000, i32::MAX] {
            assert_eq!(
                build_query("example.com", 1, 1, 0, true, oversized)
                    .expect_err("oversized EDNS must fail")
                    .code(),
                ARES_EFORMERR
            );
        }
        // 1..=65535 is valid EDNS; the OPT CLASS carries the exact size.
        for size in [1i32, 1280, 65535] {
            let p = build_query("example.com", 1, 1, 0, true, size).expect("valid EDNS size");
            assert_eq!(u16::from_be_bytes([p[10], p[11]]), 1, "arcount");
            let opt_class = u16::from_be_bytes([p[32], p[33]]);
            assert_eq!(u32::from(opt_class), size as u32);
        }
        // Zero and negative mean "no EDNS".
        for size in [0i32, -1] {
            let p = build_query("example.com", 1, 1, 0, true, size).expect("no EDNS");
            assert_eq!(u16::from_be_bytes([p[10], p[11]]), 0, "arcount");
        }
    }

    #[test]
    fn template_rewrite_preserves_flags_and_class() {
        use crate::ffi::dns_record::ARES_FLAG_RD;
        let mut rec = ares_dns_record_t::new(7, ARES_FLAG_RD, 0, 0);
        rec.query_add("a.example", 1, 3).expect("query_add");
        let payload = payload_from_template(&rec, "b.example").expect("template payload");
        let parsed = parse_record(&payload, 0).expect("parse payload");
        let (name, qtype, qclass) = parsed.query_at(0).expect("query");
        assert_eq!(name.to_str().expect("name"), "b.example");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 3);
        assert_ne!(parsed.flags() & ARES_FLAG_RD, 0);
    }
}

#[cfg(test)]
mod reinit_tests {
    use super::*;

    fn temp_conf(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cares-rs-reinit-{}-{:?}.conf",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, contents).expect("write temp resolv.conf");
        path
    }

    #[test]
    fn reinit_reloads_sysconfig_and_flushes_cache() {
        let path = temp_conf(
            "nameserver 9.9.9.9\nsearch example.test\nlookup bind files\nsortlist 10.0.0.0/8\noptions ndots:3 attempts:2 timeout:1\n",
        );
        let mut client = AsyncClient::build(SysConfig::default(), super::tests::noop_factory(), 53, 53);
        client.resolvconf_path = path.to_string_lossy().into_owned();
        client.cache.borrow_mut().set_max_ttl(3600);
        let key = CacheKey::new("cached.test", 1, ARES_CLASS_IN, 0, true, false);
        client.cache.borrow_mut().store_names(
            vec![key.name.clone()],
            &key,
            60,
            &[0u8; 12],
            Instant::now(),
        );
        assert!(client.cache.borrow_mut().get(&key, Instant::now()).is_some());

        client.reinit().expect("reinit");

        assert_eq!(
            client.config.nameservers,
            vec![(IpAddr::from([9, 9, 9, 9]), None)]
        );
        assert_eq!(client.config.search, vec!["example.test".to_string()]);
        assert_eq!(client.config.options.ndots, 3);
        assert_eq!(client.config.options.attempts, 2);
        assert_eq!(client.config.options.timeout_ms, 1000);
        assert_eq!(client.lookups, "bf");
        assert!(!client.sortlist.is_empty());
        assert!(client.cache.borrow_mut().get(&key, Instant::now()).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reinit_preserves_explicitly_set_servers() {
        let path = temp_conf("nameserver 9.9.9.9\n");
        let mut client = AsyncClient::build(SysConfig::default(), super::tests::noop_factory(), 53, 53);
        client.resolvconf_path = path.to_string_lossy().into_owned();
        client.set_servers(vec![ServerSpec {
            ip: IpAddr::from([8, 8, 4, 4]),
            udp_port: None,
            tcp_port: None,
        }]);

        client.reinit().expect("reinit");

        assert_eq!(
            client.config.nameservers,
            vec![(IpAddr::from([8, 8, 4, 4]), None)]
        );
        let _ = std::fs::remove_file(path);
    }
}
