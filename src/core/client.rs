//! The pure channel state and its configuration/lifecycle logic: everything
//! a channel owns except the C callbacks (which live in ffi::ChannelData
//! around this struct). Options application, server-list install/report,
//! reactor fd/timeout reporting, query-cache stores, and pool retention all
//! live here; the ffi shims only marshal C values in and out.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use bytes::BytesMut;

use crate::core::api::{AddrInfoResult, NameinfoResult, Operation, SearchReplyDelivery};
use crate::core::cache::QueryCache;
use crate::core::executor;
use crate::core::hostent::Hostent;
use crate::core::hostfile::AddressFamily;
use crate::core::launch::AddrInfoDelivery;
use crate::core::lookup::{
    is_onion_domain, AddrInfoAction, AddrInfoEvent, AddrInfoSm, LookupEvent, SearchAction,
    SearchPlan, SearchSm, ServerHealth,
};
use crate::core::packets::buf_to_ip;
use crate::core::preflight::{
    cached_reply, format_ip_with_scope, get_service_string, hosts_file_lookup, no_servers,
    search_start, AddrInfo,
};
use crate::core::query_builder::dns_query_payload;
use crate::core::sortlist::SortlistEntry;
use crate::core::transport::{
    qtype_of, rdns_name, Family, SocketSource, Status, TaskMachine, Transport,
};
use crate::core::AresError;
use crate::ffi::ares_options::{
    ARES_FLAG_EDNS, ARES_FLAG_PRIMARY, ARES_FLAG_USEVC, ARES_OPT_DOMAINS, ARES_OPT_FLAGS,
    ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS,
    ARES_OPT_NOROTATE, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF, ARES_OPT_ROTATE,
    ARES_OPT_SERVERS, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SORTLIST, ARES_OPT_TCP_PORT,
    ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES, ARES_OPT_UDP_MAX_QUERIES,
    ARES_OPT_UDP_PORT,
};
use crate::ffi::error::{
    ARES_EBADFLAGS, ARES_EBADQUERY, ARES_ECONNREFUSED, ARES_ENOSERVER, ARES_ENOTFOUND,
    ARES_ENOTIMP,
};
use crate::ffi::{
    ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD, ARES_NI_NUMERICHOST, RECORD_TYPE_A,
    RECORD_TYPE_AAAA, RECORD_TYPE_PTR,
};

/// Everything a channel owns that is pure Rust: the engine, health/cache
/// bookkeeping, configuration strings, and the shared-socket pools. Generic
/// over the per-task userdata `T`, which core never inspects.
pub(crate) struct Client<T> {
    pub transport: Transport<T>,
    pub readbuf: Vec<u8>,
    /// Shared with the async engine's in-flight futures (`Rc<RefCell<_>>`) so
    /// failover accounting, the probe, and the classic reactor agree.
    pub server_health: Rc<RefCell<ServerHealth>>,
    pub sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    pub maxtimeout: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    /// TTL-bounded reply cache, shared (via `Rc<RefCell<_>>`) with the async
    /// engine (gethostbyname) and the classic dnsrec post-delivery hook.
    pub cache: Rc<RefCell<QueryCache>>,
    pub udp_max_queries: u32, // 0 = unlimited
    /// Shared TCP connections for the async engine (parallel lookups to one
    /// server share a connection); handed to each future via its descriptor.
    pub tcp_pool: Rc<RefCell<crate::core::executor::TcpPool>>,
    /// Per-server connect endpoints, cached (rebuilt on server change) so each
    /// async launch clones an `Rc` instead of re-snapshotting the config.
    endpoints: Rc<Vec<executor::ServerEndpoint>>,
    pub tcp_recv_buffers: HashMap<i32, Vec<u8>>, // classic reactor TCP reassembly (fd -> data)
    pub server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub server_failover_retry_delay: u64,  // milliseconds
}

impl<T> Client<T> {
    /// A fresh channel around `transport` — shared by ares_init and ares_init_options.
    pub fn new(transport: Transport<T>) -> Self {
        let mut client = Client {
            transport,
            readbuf: vec![0u8; 65_535],
            server_health: Rc::new(RefCell::new(ServerHealth::default())),
            sortlist: vec![],
            flags: 0,
            maxtimeout: 0,
            lookups: String::new(),
            resolvconf_path: String::new(),
            hosts_path: String::new(),
            cache: Rc::new(RefCell::new(QueryCache::default())),
            udp_max_queries: 0,
            tcp_pool: Rc::new(RefCell::new(crate::core::executor::TcpPool::default())),
            endpoints: Rc::new(Vec::new()),
            tcp_recv_buffers: HashMap::new(),
            server_failover_retry_chance: 0,
            server_failover_retry_delay: 0,
        };
        client.rebuild_endpoints();
        client
    }

    /// The pure body of ares_dup: clone configuration, start with a fresh
    /// reactor state (empty query cache, no pooled connections, cleared
    /// failure timestamps — but cloned failure counts).
    pub fn duplicate(&self) -> Client<T> {
        let mut transport = Transport::new(self.transport.config.clone(), self.transport.socket_factory.clone());
        transport.default_udp_port = self.transport.default_udp_port;
        transport.default_tcp_port = self.transport.default_tcp_port;
        let mut dup = Client::new(transport);
        {
            let src = self.server_health.borrow();
            dup.server_health = Rc::new(RefCell::new(ServerHealth {
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
        dup.udp_max_queries = self.udp_max_queries;
        dup.server_failover_retry_chance = self.server_failover_retry_chance;
        dup.server_failover_retry_delay = self.server_failover_retry_delay;
        dup
    }

    /// The optmask cascade from ares_init_options — order preserved bit for
    /// bit, ending with the unconditional server-health reset.
    pub fn apply_options(&mut self, optmask: i32, o: DecodedOptions) {
        if optmask & ARES_OPT_SERVERS != 0 {
            // Clear sysconfig servers when user explicitly provides servers
            self.transport.config.nameservers.clear();
            self.transport.config.tcp_ports.clear();
            for v4 in &o.servers {
                self.transport.config.nameservers.push((IpAddr::V4(*v4), None));
                self.transport.config.tcp_ports.push(None);
            }
        }
        if optmask & ARES_OPT_UDP_PORT != 0 {
            self.transport.default_udp_port = o.udp_port;
        }
        if optmask & ARES_OPT_TCP_PORT != 0 {
            self.transport.default_tcp_port = o.tcp_port;
        }
        if optmask & ARES_OPT_TIMEOUTMS != 0 {
            self.transport.config.options.timeout_ms = std::cmp::max(1, o.timeout as u32);
        }
        if optmask & ARES_OPT_TIMEOUT != 0 {
            self.transport.config.options.timeout_ms = o.timeout as u32 * 1000;
        }
        if optmask & ARES_OPT_TRIES != 0 {
            self.transport.config.options.attempts = o.tries as u32;
        }
        if optmask & ARES_OPT_NDOTS != 0 {
            self.transport.config.options.ndots = o.ndots as u32;
        }
        if optmask & ARES_OPT_FLAGS != 0 {
            self.flags = o.flags;
            self.transport.config.options.use_vc = (o.flags & ARES_FLAG_USEVC) != 0;
            self.transport.config.options.edns0 = (o.flags & ARES_FLAG_EDNS) != 0;
            // ARES_FLAG_PRIMARY: truncate to first server only
            if (o.flags & ARES_FLAG_PRIMARY) != 0 {
                self.transport.config.nameservers.truncate(1);
                self.transport.config.tcp_ports.truncate(1);
            }
        }
        if optmask & ARES_OPT_DOMAINS != 0 {
            if let Some(domains) = o.domains {
                self.transport.config.search = domains;
            }
        }
        if optmask & ARES_OPT_NOROTATE != 0 {
            self.transport.config.options.rotate = false;
        }
        if optmask & ARES_OPT_ROTATE != 0 {
            self.transport.config.options.rotate = true;
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
        if optmask & ARES_OPT_UDP_MAX_QUERIES != 0 {
            self.udp_max_queries = o.udp_max_queries as u32;
        }
        if optmask & ARES_OPT_SERVER_FAILOVER != 0 {
            self.server_failover_retry_chance = o.failover_retry_chance;
            self.server_failover_retry_delay = o.failover_retry_delay;
        }
        self.server_health.borrow_mut().reset(self.transport.config.nameservers.len());
        self.rebuild_endpoints();
    }

    /// The pure inverse of the cascade: read the channel back into option fields.
    pub fn saved_options(&self) -> SavedOptions {
        let config = &self.transport.config;
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
            udp_port: self.transport.default_udp_port,
            tcp_port: self.transport.default_tcp_port,
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
        self.transport.config.nameservers.clear();
        self.transport.config.tcp_ports.clear();
        for server in servers {
            self.transport.config.nameservers.push((server.ip, server.udp_port));
            self.transport.config.tcp_ports.push(server.tcp_port);
        }
        self.server_health.borrow_mut().reset(self.transport.config.nameservers.len());
        self.rebuild_endpoints();
    }

    /// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
    pub fn clear_servers(&mut self) {
        self.transport.config.nameservers.clear();
        self.transport.config.tcp_ports.clear();
        self.server_health.borrow_mut().clear();
        self.rebuild_endpoints();
    }

    /// Install a parsed CSV server list (ares_set_servers_ports_csv).
    pub fn install_csv_servers(&mut self, ns: Vec<(IpAddr, Option<u16>)>) {
        self.transport.config.tcp_ports = vec![None; ns.len()];
        self.server_health.borrow_mut().reset(ns.len());
        self.transport.config.nameservers = ns;
        self.rebuild_endpoints();
    }

    /// The configured servers with per-entry defaults applied, in order:
    /// (ip, udp_port, tcp_port) — the report behind ares_get_servers[_ports].
    pub fn server_list(&self) -> Vec<(IpAddr, u16, u16)> {
        self.transport
            .config
            .nameservers
            .iter()
            .map(|(ip, port)| {
                (
                    *ip,
                    port.unwrap_or(self.transport.default_udp_port),
                    port.unwrap_or(self.transport.default_tcp_port),
                )
            })
            .collect()
    }

    /// The `ip:port` CSV report behind ares_get_servers_csv (IPv6 bracketed).
    pub fn servers_csv_string(&self) -> String {
        let default_port = self.transport.default_udp_port;
        self.transport
            .config
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

    /// (fd, wants_write) for every non-completed task, in task order — the
    /// status mapping behind ares_fds and ares_getsock.
    pub fn poll_fds(&self) -> Vec<(i32, bool)> {
        self.transport
            .tasks
            .iter()
            .filter_map(|task| match task.status {
                Status::Writing => Some((task.sock.as_raw_fd(), true)),
                Status::Reading => Some((task.sock.as_raw_fd(), false)),
                Status::Completed => None,
            })
            .collect()
    }

    /// The pending-query wait budget in milliseconds; None when no tasks are
    /// pending (ares_timeout then reports maxtv/NULL).
    pub fn timeout_millis(&self) -> Option<u128> {
        if self.transport.tasks.is_empty() {
            return None;
        }
        Some(self.transport.max_wait_time().as_millis())
    }

    /// Non-completed task count (ares_queue_active_queries).
    pub fn active_query_count(&self) -> usize {
        self.transport
            .tasks
            .iter()
            .filter(|t| t.status != Status::Completed)
            .count()
    }

    /// Store a dnsrec-flavored reply in the query cache (no-op when the
    /// cache is disabled) — the reactor's post-delivery hook.
    pub fn cache_dnsrec_reply(&mut self, buf: &[u8], now: Instant) {
        self.cache.borrow_mut().store_reply(buf, now);
    }

    /// Drop the classic reactor's TCP reassembly buffers (ares_cancel). The
    /// async engine's shared TCP pool is cleared separately by the ffi.
    pub fn clear_pools(&mut self) {
        self.tcp_recv_buffers.clear();
    }

    /// The `ip:port` string reported to the server-state callback (IPv6
    /// bracketed); None when the index is stale.
    pub fn server_state_string(&self, server_index: usize, is_tcp: bool) -> Option<String> {
        let (ip, port) = self.transport.config.nameservers.get(server_index)?;
        let port_val = port.unwrap_or(if is_tcp {
            self.transport.default_tcp_port
        } else {
            self.transport.default_udp_port
        });
        Some(match ip {
            IpAddr::V4(v4) => format!("{}:{}", v4, port_val),
            IpAddr::V6(v6) => format!("[{}]:{}", v6, port_val),
        })
    }
}

/// The resolver operations — one method per `ares_*` export, plus the enqueue
/// primitives and reply executors they compose. Each ffi shim marshals its C
/// arguments and makes exactly one call in here; preflights, launch loops and
/// cache policy are private details of these methods, never seams the ffi
/// layer reassembles.
///
/// Handlers take the ffi userdata as a plain value (a `Callback` binding the
/// shim builds eagerly), not a factory closure: core owns the per-task data
/// (the state-machine handle on `Task.machine`, plus family/rtype/timeouts/
/// queried-ip), mints the machine, and clones the binding into each task — so
/// nothing here constructs a C userdata.
impl<T> Client<T> {
    // ===== Enqueue primitives (formerly free fns in core::launch) =====

    /// Stamp the core-owned per-task data onto the task `enqueue` just pushed:
    /// the state-machine handle plus the query's family/record-type (and, for a
    /// batch send, the accumulated timeout count). The ffi userdata carries none
    /// of this now — the reply reads it from the `Task`.
    fn stamp(&mut self, machine: TaskMachine, family: i32, rtype: u16, timeouts: i32) {
        if let Some(t) = self.transport.tasks.last_mut() {
            t.machine = machine;
            t.family = family;
            t.rtype = rtype;
            t.timeouts = timeouts;
        }
    }

    /// Plain enqueue (no socket-callback involvement — ares_query/ares_send/
    /// search flows). `Ok(fd)` of the task's socket; a socket that could not be
    /// created is `Err(ARES_ECONNREFUSED)` — the status every caller delivers —
    /// so call sites just use `?`.
    pub(crate) fn enqueue(
        &mut self,
        payload: BytesMut,
        source: SocketSource,
        server: usize,
        userdata: T,
    ) -> Result<i32, AresError> {
        self.transport.enqueue(payload, source, server, userdata).map_err(|_| AresError::from(ARES_ECONNREFUSED))?;
        Ok(self.transport.tasks.last().expect("enqueue pushed a task").sock.as_raw_fd())
    }

    /// Re-enqueue for a retry (TC upgrade, rcode failover, timeout): carries the
    /// retry counter onto the new task. False when the socket could not be created
    /// — including a callback-refused fd — in which case the caller delivers
    /// ECONNREFUSED.
    pub(crate) fn reissue(
        &mut self,
        payload: BytesMut,
        source: SocketSource,
        server: usize,
        userdata: T,
        tries: u32,
    ) -> bool {
        if self.enqueue(payload, source, server, userdata).is_err() {
            return false;
        }
        self.transport.tasks.last_mut().expect("enqueue pushed a task").tries_remaining = tries;
        true
    }

    /// Drive the getaddrinfo machine's action queue: perform every Send (a failed
    /// socket — creation error or a callback-refused fd — feeds LaunchFailed for a
    /// batch send, or ResendFailed for a re-send, back into the machine) and
    /// collect the Deliver* actions for the shim.
    pub(crate) fn drive_addrinfo(
        &mut self,
        sm: &Rc<RefCell<AddrInfoSm>>,
        actions: Vec<AddrInfoAction>,
        binding: T,
    ) -> Vec<AddrInfoDelivery>
    where
        T: Copy,
    {
        let mut deliveries = Vec::new();
        let mut queue: std::collections::VecDeque<AddrInfoAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                AddrInfoAction::Send { name, family, tcp, server, timeouts, batch } => {
                    let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
                    let rtype = if family == libc::AF_INET { RECORD_TYPE_A } else { RECORD_TYPE_AAAA };
                    let failed = self.transport.enqueue(dns_query_payload(&name, qtype_of(core_family)), SocketSource::fresh(tcp), server, binding).is_err();
                    if !failed {
                        self.stamp(TaskMachine::AddrInfo(sm.clone()), family, rtype, timeouts);
                    }
                    if failed {
                        let ev = if batch { AddrInfoEvent::LaunchFailed } else { AddrInfoEvent::ResendFailed };
                        let more = {
                            let mut machine = sm.borrow_mut();
                            machine.step(ev, &mut self.server_health.borrow_mut())
                        };
                        queue.extend(more);
                    }
                }
                AddrInfoAction::DeliverSuccess { name } => {
                    let records = std::mem::take(&mut sm.borrow_mut().addrs);
                    deliveries.push(AddrInfoDelivery::Success { name, records });
                }
                AddrInfoAction::DeliverFail { status } => {
                    deliveries.push(AddrInfoDelivery::Fail { status });
                }
            }
        }
        deliveries
    }

    // ===== Async-engine resource builders =====

    /// Rebuild the cached endpoint snapshot after a server/port change.
    pub fn rebuild_endpoints(&mut self) {
        self.endpoints = Rc::new(self.endpoint_snapshot());
    }

    /// Snapshot the per-server connect endpoints from config, so an async
    /// lifecycle future needs no `Transport`.
    fn endpoint_snapshot(&self) -> Vec<executor::ServerEndpoint> {
        let default_udp = self.transport.default_udp_port;
        let default_tcp = self.transport.default_tcp_port;
        self.transport
            .config
            .nameservers
            .iter()
            .enumerate()
            .map(|(i, &(ip, udp_override))| {
                let udp_port = udp_override.unwrap_or(default_udp);
                let tcp_port = self.transport.config.tcp_ports.get(i).copied().flatten().unwrap_or(default_tcp);
                let bind = if ip.is_ipv6() {
                    SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
                };
                executor::ServerEndpoint {
                    udp_addr: SocketAddr::from((ip, udp_port)),
                    tcp_addr: SocketAddr::from((ip, tcp_port)),
                    bind,
                }
            })
            .collect()
    }

    /// The retry/timeout knobs an async lifecycle needs.
    fn query_opts(&self) -> executor::QueryOpts {
        executor::QueryOpts {
            attempts: self.transport.config.options.attempts,
            timeout: Duration::from_millis(self.transport.config.options.timeout_ms as u64),
            failover_chance: self.server_failover_retry_chance,
            failover_delay: self.server_failover_retry_delay,
        }
    }

    /// Bundle the owned resources an async lifecycle future carries. Cheap: all
    /// `Rc` clones (endpoints cached, rebuilt only on server change).
    fn resources(&self) -> executor::Resources {
        executor::Resources {
            factory: self.transport.socket_factory.clone(),
            health: self.server_health.clone(),
            endpoints: self.endpoints.clone(),
            tcp_pool: self.tcp_pool.clone(),
            opts: self.query_opts(),
        }
    }

    /// Bundle everything the self-contained async `gethostbyname` future owns:
    /// the socket resources plus `Rc`/snapshot handles for the preflight (hosts
    /// file, query cache, sortlist, ndots/search/use_vc). The one spot that reads
    /// `Client` for the host lifecycle — the future itself names no channel.
    pub(crate) fn host_ctx(&mut self) -> crate::core::hostbyname::HostCtx {
        crate::core::hostbyname::HostCtx {
            res: self.resources(),
            hosts: self.transport.hosts(),
            cache: self.cache.clone(),
            sortlist: Rc::from(self.sortlist.clone()),
            ndots: self.transport.config.options.ndots,
            search: Rc::from(self.transport.config.search.clone()),
            use_vc: self.transport.config.options.use_vc,
        }
    }

    // ===== Entry points (one method per ares_* export) =====

    /// ares_query: `no_servers` preflight, then a launch descriptor carrying the
    /// owned resources + wire payload for the async lifecycle.
    pub(crate) fn query_payload(&self, name: &str, qtype: u16) -> Result<executor::RawLaunch, AresError> {
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        Ok(executor::RawLaunch { res: self.resources(), payload: dns_query_payload(name, qtype) })
    }

    /// ares_send: min-DNS-length + `no_servers` preflight, then a launch descriptor.
    pub(crate) fn send_payload(&self, query_buf: &[u8]) -> Result<executor::RawLaunch, AresError> {
        if query_buf.len() < 12 {
            return Err(ARES_EBADQUERY.into());
        }
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        Ok(executor::RawLaunch { res: self.resources(), payload: BytesMut::from(query_buf) })
    }

    /// ares_query_dnsrec: server guard, then the query cache (keyed without the
    /// trailing dot; a cached reply that fails to parse falls through), then a
    /// fresh query. A cache hit is parsed right here (`Ready`); the shim boxes the
    /// record, delivers, and destroys.
    pub(crate) fn query_dnsrec(
        &mut self,
        name_raw: &str,
        qtype: u16,
        now: Instant,
        userdata: T,
    ) -> Result<Operation<crate::core::dns_record::ares_dns_record_t>, AresError> {
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        let name_clean = name_raw.strip_suffix('.').unwrap_or(name_raw);
        if let Some(cached_buf) = cached_reply(self, name_clean, qtype, now) {
            if let Ok(rec) = crate::core::dns_record::parse_record(&cached_buf) {
                return Ok(Operation::Ready(rec));
            }
        }
        self.enqueue(dns_query_payload(name_raw, qtype), SocketSource::Udp, 0, userdata)?;
        Ok(Operation::Pending)
    }

    /// ares_search / ares_search_dnsrec: seed the search plan, mint the shared
    /// state-machine handle, and issue the first query.
    ///
    /// NULL-pointer ordering note: the name sanity check runs in the shim (via
    /// `search_precheck`) *before* the channel is dereferenced — a bad name is
    /// reported even on a NULL channel, so it cannot live in here.
    pub(crate) fn search(
        &mut self,
        name: &str,
        dnstype: u16,
        retry_server_error: bool,
        binding: T,
    ) -> Result<(), AresError> {
        let (sm, query_hostname) = search_start(self, name, retry_server_error)?;
        let handle = Rc::new(RefCell::new(sm));
        self.enqueue(dns_query_payload(&query_hostname, dnstype), SocketSource::Udp, 0, binding)?;
        if let Some(t) = self.transport.tasks.last_mut() { t.machine = TaskMachine::Search(handle); }
        Ok(())
    }

    /// ares_gethostbyname_file: the hosts-file-only lookup, shaped for C.
    pub(crate) fn gethostbyname_file(&mut self, name: &str, family: i32) -> Result<Hostent, AresError> {
        hosts_file_lookup(self, name, family).map(Hostent::from_lookup)
    }

    /// ares_gethostbyaddr: preflight (family/length validation, hosts-file
    /// reverse hit, no-servers), then the PTR query — whose fresh socket the
    /// channel's socket callback may refuse (→ ECONNREFUSED).
    ///
    /// The `userdata` is a plain value the shim built eagerly (no factory
    /// closure): the only per-task datum core computes here — the queried
    /// address — is recorded on the `Task` itself (`queried_ip`), not stamped
    /// into the ffi userdata, and the reply reads it back from there.
    pub(crate) fn gethostbyaddr(
        &mut self,
        addrbuf: &[u8],
        family: i32,
        userdata: T,
    ) -> Result<Operation<Hostent>, AresError> {
        // family-validate -> buf_to_ip -> hosts reverse lookup -> no-servers -> PTR.
        if family != libc::AF_INET && family != libc::AF_INET6 {
            return Err(ARES_ENOTIMP.into());
        }
        let addr = buf_to_ip(addrbuf).map_err(|_| ARES_ENOTIMP)?;
        // Check hosts file first
        if let Some(lookup) = self.transport.hosts().reverse_lookup(addr) {
            return Ok(Operation::Ready(Hostent::from_lookup(lookup)));
        }
        // No servers configured
        if self.transport.config.nameservers.is_empty() {
            return Err(ARES_ENOSERVER.into());
        }
        self.enqueue(dns_query_payload(&rdns_name(addr), RECORD_TYPE_PTR), SocketSource::fresh(false), 0, userdata)?;
        if let Some(t) = self.transport.tasks.last_mut() {
            t.queried_ip = Some(addr);
            t.family = family;
            t.rtype = RECORD_TYPE_PTR;
        }
        Ok(Operation::Pending)
    }

    /// ares_getnameinfo: flag defaulting + the numeric/service short-circuits,
    /// then the PTR query (whose fresh socket the channel's socket callback may
    /// refuse → ECONNREFUSED). `userdata` is built by the shim and passed by
    /// value (no factory closure); it is consumed only on the PTR-query path.
    /// The LOOKUPHOST default applied here affects only the path decision —
    /// never the reply — so the shim's raw-flag userdata is correct.
    pub(crate) fn getnameinfo(
        &mut self,
        addr: &AddrInfo,
        flags: i32,
        userdata: T,
    ) -> Result<Operation<NameinfoResult>, AresError> {
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
            return Ok(Operation::Ready(NameinfoResult::Service(get_service_string(self.transport.services(), addr.port, flags))));
        }

        // Host lookup requested (guaranteed by the defaulting above).
        // Numeric host can be handled without DNS
        if (flags & ARES_NI_NUMERICHOST) != 0 {
            // ARES_NI_NUMERICHOST + ARES_NI_NAMEREQD is illegal (contradiction)
            if (flags & ARES_NI_NAMEREQD) != 0 {
                return Err(ARES_EBADFLAGS.into());
            }
            let node = CString::new(format_ip_with_scope(&addr.ip, addr.scope_id, flags)).unwrap();
            let service = if want_service {
                get_service_string(self.transport.services(), addr.port, flags)
            } else {
                None
            };
            return Ok(Operation::Ready(NameinfoResult::Numeric { node, service }));
        }

        // PTR lookup required.
        self.enqueue(dns_query_payload(&rdns_name(addr.ip), RECORD_TYPE_PTR), SocketSource::fresh(false), 0, userdata)?;
        Ok(Operation::Pending)
    }

    /// ares_getaddrinfo: preflight (empty/onion/IP-literal/hosts/no-servers),
    /// then mint the machine and drive the A/AAAA batch.
    pub(crate) fn getaddrinfo(
        &mut self,
        hostname_raw: &str,
        ai_family: i32,
        binding: T,
    ) -> Result<Operation<AddrInfoResult>, AresError>
    where
        T: Copy,
    {
        // Check order is behavior: empty-name -> onion -> IP literal (family
        // mismatch fails, no fall-through) -> hosts file -> no-servers -> DNS.
        // The raw name keeps its trailing dot for the SearchPlan; checks and the
        // delivered canonical name use the stripped form.

        // A synchronous (IP-literal / hosts-file) hit: only addresses of the
        // requested family reach the node list.
        let deliver = |mut addrs: Vec<IpAddr>, canonical: String| {
            addrs.retain(|ip| match ip {
                IpAddr::V4(_) => ai_family == libc::AF_UNSPEC || ai_family == libc::AF_INET,
                IpAddr::V6(_) => ai_family == libc::AF_UNSPEC || ai_family == libc::AF_INET6,
            });
            Ok(Operation::Ready(AddrInfoResult { addrs, canonical }))
        };

        let hostname = hostname_raw.strip_suffix('.').unwrap_or(hostname_raw);

        if hostname.is_empty() {
            return Err(ARES_ENOTFOUND.into());
        }

        // Reject .onion domains immediately (RFC 7686)
        if is_onion_domain(hostname) {
            return Err(ARES_ENOTFOUND.into());
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
                return deliver(vec![ip], hostname.to_string());
            } else {
                return Err(ARES_ENOTFOUND.into());
            }
        }

        // Hosts file check
        let family_filter = match ai_family {
            libc::AF_INET => AddressFamily::Ipv4,
            libc::AF_INET6 => AddressFamily::Ipv6,
            _ => AddressFamily::Any,
        };
        if let Some(lookup) = self.transport.hosts().lookup(hostname, family_filter) {
            if !lookup.addrs.is_empty() {
                return deliver(lookup.addrs, hostname.to_string());
            }
        }

        // No servers configured
        if self.transport.config.nameservers.is_empty() {
            return Err(ARES_ENOSERVER.into());
        }

        // DNS path: mint the machine and drive the parallel A/AAAA batch.
        // (the raw name carries the trailing dot the plan needs to see)
        let use_tcp = self.transport.config.options.use_vc;
        let plan = SearchPlan::for_search(
            hostname_raw,
            self.transport.config.options.ndots,
            &self.transport.config.search,
        );
        let first_server = self.server_health.borrow().pick_next();
        let sm = AddrInfoSm::new(plan, ai_family, use_tcp);

        let handle = Rc::new(RefCell::new(sm));
        let actions = handle.borrow_mut().begin_batch(first_server);
        // At entry the batch can only yield nothing (still in flight) or a single
        // all-sockets-refused failure — never a synchronous success, which needs a
        // reply. `Ready` is terminal; the async result arrives via the reply path.
        match self.drive_addrinfo(&handle, actions, binding).as_slice() {
            [] => Ok(Operation::Pending),
            [AddrInfoDelivery::Fail { status }] => Err(*status),
            _ => unreachable!("getaddrinfo entry yields nothing or a single ECONNREFUSED"),
        }
    }

    // ===== Reply executors =====

    /// A search task settled: feed the machine, re-issue the next plan name if
    /// asked (a failed re-issue reports ECONNREFUSED with zero timeouts, as
    /// historically), or hand the delivery back to the shim.
    pub(crate) fn on_search_reply(
        &mut self,
        sm: &Rc<RefCell<SearchSm>>,
        res: Result<&[u8], AresError>,
        dnstype: u16,
        io_timeouts: i32,
        binding: T,
    ) -> Option<SearchReplyDelivery> {
        let ev = match res {
            Ok(buf) => LookupEvent::Reply(buf),
            Err(status) => LookupEvent::Error(status),
        };
        let action = sm.borrow_mut().step(ev);
        match action {
            SearchAction::Send(next_name) => {
                match self.enqueue(dns_query_payload(&next_name, dnstype), SocketSource::Udp, 0, binding) {
                    Ok(_) => {
                        if let Some(t) = self.transport.tasks.last_mut() { t.machine = TaskMachine::Search(sm.clone()); }
                        None
                    }
                    Err(status) => Some(SearchReplyDelivery::Fail { status, timeouts: 0 }),
                }
            }
            SearchAction::DeliverSuccess => Some(SearchReplyDelivery::Success { timeouts: io_timeouts }),
            SearchAction::DeliverFail(status) => Some(SearchReplyDelivery::Fail { status, timeouts: io_timeouts }),
        }
    }

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
    pub udp_max_queries: i32,
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


