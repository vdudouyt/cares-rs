//! The pure channel state and its configuration/lifecycle logic: everything
//! a channel owns except the C callbacks (which live in ffi::ChannelData
//! around this struct). Options application, server-list install/report,
//! reactor fd/timeout reporting, query-cache stores, and pool retention all
//! live here; the ffi shims only marshal C values in and out.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use bytes::BytesMut;

use crate::core::api::{
    AddrInfoResult, HostDelivery, NameinfoResult, Operation, SearchReplyDelivery,
};
use crate::core::hostent::Hostent;
use crate::core::hostfile::AddressFamily;
use crate::core::launch::{AddrInfoDelivery, LaunchOutcome};
use crate::core::lookup::{
    is_localhost, is_onion_domain, AddrInfoAction, AddrInfoEvent, AddrInfoSm, HostAction,
    HostByNameSm, HostEvent, LookupCfg, LookupEvent, SearchAction, SearchPlan, SearchSm,
    ServerHealth,
};
use crate::core::packets::{buf_to_ip, AddrRecord};
use crate::core::preflight::{
    cached_reply, format_ip_with_scope, get_service_string, hosts_file_lookup, no_servers,
    search_start, AddrInfo,
};
use crate::core::response::{addr_reply, ParsedRRs, ParsedResponse, ReplyRequire};
use crate::core::socket::Socket;
use crate::core::sortlist::{apply_sortlist, SortlistEntry};
use crate::core::transport::{
    dns_query_payload, qtype_of, rdns_name, Family, SocketSource, Status, TaskMachine, Transport,
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
    ARES_EBADFLAGS, ARES_EBADNAME, ARES_EBADQUERY, ARES_ECONNREFUSED, ARES_EFILE, ARES_ENODATA,
    ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP,
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
    pub server_health: ServerHealth,
    pub sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    pub maxtimeout: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    pub query_cache: HashMap<(String, u16), (Vec<u8>, Instant)>,
    pub query_cache_max_ttl: u32, // 0 = disabled
    pub udp_max_queries: u32, // 0 = unlimited
    pub udp_connections: Vec<(usize, Rc<dyn Socket>, u32)>, // (server_index, shared_socket, query_count)
    pub tcp_connections: Vec<(usize, Rc<dyn Socket>)>, // (server_index, shared_socket)
    pub tcp_recv_buffers: HashMap<i32, Vec<u8>>, // fd -> accumulated TCP receive data
    pub server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub server_failover_retry_delay: u64,  // milliseconds
}

impl<T> Client<T> {
    /// A fresh channel around `transport` — shared by ares_init and ares_init_options.
    pub fn new(transport: Transport<T>) -> Self {
        Client {
            transport,
            readbuf: vec![0u8; 65_535],
            server_health: ServerHealth::default(),
            sortlist: vec![],
            flags: 0,
            maxtimeout: 0,
            lookups: String::new(),
            resolvconf_path: String::new(),
            hosts_path: String::new(),
            query_cache: HashMap::new(),
            query_cache_max_ttl: 0,
            udp_max_queries: 0,
            udp_connections: vec![],
            tcp_connections: vec![],
            tcp_recv_buffers: HashMap::new(),
            server_failover_retry_chance: 0,
            server_failover_retry_delay: 0,
        }
    }

    /// The pure body of ares_dup: clone configuration, start with a fresh
    /// reactor state (empty query cache, no pooled connections, cleared
    /// failure timestamps — but cloned failure counts).
    pub fn duplicate(&self) -> Client<T> {
        let mut transport = Transport::new(self.transport.config.clone(), self.transport.socket_factory.clone());
        transport.default_udp_port = self.transport.default_udp_port;
        transport.default_tcp_port = self.transport.default_tcp_port;
        let mut dup = Client::new(transport);
        dup.server_health = ServerHealth {
            failures: self.server_health.failures.clone(),
            last_failure: vec![None; self.server_health.last_failure.len()],
        };
        dup.sortlist = self.sortlist.clone();
        dup.flags = self.flags;
        dup.maxtimeout = self.maxtimeout;
        dup.lookups = self.lookups.clone();
        dup.resolvconf_path = self.resolvconf_path.clone();
        dup.hosts_path = self.hosts_path.clone();
        dup.query_cache_max_ttl = self.query_cache_max_ttl;
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
            self.query_cache_max_ttl = o.qcache_max_ttl;
        }
        if optmask & ARES_OPT_UDP_MAX_QUERIES != 0 {
            self.udp_max_queries = o.udp_max_queries as u32;
        }
        if optmask & ARES_OPT_SERVER_FAILOVER != 0 {
            self.server_failover_retry_chance = o.failover_retry_chance;
            self.server_failover_retry_delay = o.failover_retry_delay;
        }
        self.server_health.reset(self.transport.config.nameservers.len());
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
        self.server_health.reset(self.transport.config.nameservers.len());
    }

    /// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
    pub fn clear_servers(&mut self) {
        self.transport.config.nameservers.clear();
        self.transport.config.tcp_ports.clear();
        self.server_health.clear();
    }

    /// Install a parsed CSV server list (ares_set_servers_ports_csv).
    pub fn install_csv_servers(&mut self, ns: Vec<(IpAddr, Option<u16>)>) {
        self.transport.config.tcp_ports = vec![None; ns.len()];
        self.server_health.reset(ns.len());
        self.transport.config.nameservers = ns;
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

    /// Phase-4 pool cleanup: drop UDP sockets past their query budget and TCP
    /// sockets no task references anymore (Rc::strong_count == 1 == pool-only).
    pub fn retain_pools(&mut self) {
        if self.udp_max_queries > 0 {
            let limit = self.udp_max_queries;
            self.udp_connections.retain(|(_, rc, count)| {
                *count < limit || Rc::strong_count(rc) > 1
            });
        }
        // Clean up TCP connections where no tasks reference the socket anymore
        self.tcp_connections.retain(|(_, rc)| Rc::strong_count(rc) > 1);
    }

    /// Store a dnsrec-flavored reply in the query cache (no-op when the
    /// cache is disabled) — the reactor's post-delivery hook.
    pub fn cache_dnsrec_reply(&mut self, buf: &[u8], now: Instant) {
        if self.query_cache_max_ttl > 0 {
            cache_reply(&mut self.query_cache, self.query_cache_max_ttl, buf, now);
        }
    }

    /// Drop every pooled connection and TCP reassembly buffer (ares_cancel).
    pub fn clear_pools(&mut self) {
        self.udp_connections.clear();
        self.tcp_connections.clear();
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

    /// Send executor for the gethostbyname machine: reuse a pooled socket when
    /// possible, otherwise create one — retrying across servers on socket-
    /// creation or consent failure (the failure accounting is ServerHealth's).
    #[allow(clippy::too_many_arguments)] // internal seam of gethostbyname / on_hostbyname_reply
    pub(crate) fn launch_pooled(
        &mut self,
        hostname: &str,
        family: i32,
        rtype: u16,
        use_tcp: bool,
        server_index: usize,
        sm: &Rc<RefCell<HostByNameSm>>,
        binding: T,
    ) -> LaunchOutcome
    where
        T: Copy,
    {
        let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
        let max_tries = self.transport.config.options.attempts as usize;
        let nservers = self.server_health.len().max(1);
        let mut si = server_index;
        let machine = || TaskMachine::HostByName(sm.clone());

        // TCP connection sharing: reuse an existing TCP connection to this server.
        if use_tcp {
            if let Some(idx) = self.tcp_connections.iter().position(|(s, _)| *s == si) {
                let shared_sock = self.tcp_connections[idx].1.clone();
                let _ = self.transport.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(crate::core::transport::DnsSocket::Tcp(shared_sock)), si, binding);
                self.stamp(machine(), family, rtype, 0);
                return LaunchOutcome::Launched;
            }
            // No existing TCP connection — fall through to create one.
        }

        // UDP max queries: try to reuse an existing shared socket.
        if !use_tcp && self.udp_max_queries > 0 {
            let limit = self.udp_max_queries;
            if let Some(idx) = self.udp_connections.iter().position(|(s, _, c)| *s == si && *c < limit) {
                let shared_sock = self.udp_connections[idx].1.clone();
                self.udp_connections[idx].2 += 1;
                let _ = self.transport.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(crate::core::transport::DnsSocket::Udp(shared_sock)), si, binding);
                self.stamp(machine(), family, rtype, 0);
                return LaunchOutcome::Launched;
            }
            // No reusable connection — create a fresh one, then pool it.
        }

        for _try in 0..max_tries {
            if self.transport.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), si, binding).is_ok() {
                self.stamp(machine(), family, rtype, 0);
                // Add the fresh socket to the connection pool for reuse.
                if use_tcp {
                    if let crate::core::transport::DnsSocket::Tcp(ref rc_sock) = self.transport.tasks.last().expect("just pushed").sock {
                        self.tcp_connections.push((si, rc_sock.clone()));
                    }
                } else if self.udp_max_queries > 0 {
                    if let crate::core::transport::DnsSocket::Udp(ref rc_sock) = self.transport.tasks.last().expect("just pushed").sock {
                        self.udp_connections.push((si, rc_sock.clone(), 1));
                    }
                }
                return LaunchOutcome::Launched;
            }
            // Socket creation failed — fd exhaustion, or a socket callback refused
            // the fd: treat as a server failure and try the next, like upstream.
            if nservers > 1 {
                self.server_health.record_failure(si);
                si = self.server_health.pick_next();
            }
        }
        // All retries exhausted.
        let timeouts = {
            let mut machine = sm.borrow_mut();
            machine.last_error = ARES_ECONNREFUSED.into();
            machine.timeouts
        };
        LaunchOutcome::Exhausted { timeouts }
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
                            machine.step(ev, &mut self.server_health)
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

    /// Launch a probe query to an expired-failure server in parallel with the
    /// primary query (no user callback; a failed/refused socket just skips it).
    pub(crate) fn maybe_launch_probe(
        &mut self,
        hostname: &str,
        family: i32,
        primary_server: usize,
        use_tcp: bool,
        probe_binding: T,
    ) {
        if self.server_failover_retry_chance == 0 {
            return;
        }
        let probe_server = match self.server_health.pick_probe(self.server_failover_retry_delay, primary_server) {
            Some(s) => s,
            None => return,
        };
        let core_family = if family == libc::AF_INET { Family::Ipv4 } else { Family::Ipv6 };
        // Best-effort: if the probe's socket can't be created (or is refused), skip it.
        // The probe carries a copy of the lookup's binding, but `TaskMachine::Probe`
        // marks it so the reply routes to the probe handler, never the user callback.
        if self.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), probe_server, probe_binding).is_ok() {
            if let Some(t) = self.transport.tasks.last_mut() {
                t.machine = TaskMachine::Probe;
            }
        }
    }

    // ===== Entry points (one method per ares_* export) =====

    /// ares_query: reject server-less channels, then enqueue.
    pub(crate) fn query(&mut self, name: &str, qtype: u16, userdata: T) -> Result<(), AresError> {
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        self.enqueue(dns_query_payload(name, qtype), SocketSource::Udp, 0, userdata)?;
        Ok(())
    }

    /// ares_send: a pre-built packet must at least hold a DNS header.
    pub(crate) fn send(&mut self, query_buf: &[u8], userdata: T) -> Result<(), AresError> {
        if query_buf.len() < 12 {
            return Err(ARES_EBADQUERY.into());
        }
        if no_servers(self) {
            return Err(ARES_ENOSERVER.into());
        }
        self.enqueue(BytesMut::from(query_buf), SocketSource::Udp, 0, userdata)?;
        Ok(())
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

    /// ares_gethostbyname: the full pre-DNS cascade, then the pooled launch and
    /// the failover probe. On exhaustion the probe still runs (its health
    /// bookkeeping sees the launch failures), and ECONNREFUSED is delivered by
    /// the shim afterwards. A synchronous hit (IP literal / hosts file / localhost
    /// / query cache) is `Ok(Operation::Ready(hostent))`.
    pub(crate) fn gethostbyname(
        &mut self,
        hostname: &str,
        family: i32,
        now: Instant,
        binding: T,
    ) -> Result<Operation<Hostent>, AresError>
    where
        T: Copy,
    {
        // Check order is behavior (each stage may deliver before the next runs):
        // ascii -> onion -> family-validate -> IP literal -> hosts file ->
        // localhost -> HOSTALIASES (fs read; PermissionDenied => Deliver(EFILE)) ->
        // no-servers -> query cache (evict expired; parse; sortlist; a cache-hit
        // parse error falls through to DNS) -> DNS launch.

        // Reject non-ASCII names
        if !hostname.is_ascii() {
            return Err(ARES_EBADNAME.into());
        }

        // Reject .onion domains immediately (RFC 7686)
        if is_onion_domain(hostname) {
            return Err(ARES_ENOTFOUND.into());
        }

        let family_filter = match family {
            libc::AF_INET => AddressFamily::Ipv4,
            libc::AF_INET6 => AddressFamily::Ipv6,
            libc::AF_UNSPEC => AddressFamily::Any,
            _ => return Err(ARES_ENOTIMP.into()),
        };

        // Check IP literal first
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            let matches = match family_filter {
                AddressFamily::Ipv4 => ip.is_ipv4(),
                AddressFamily::Ipv6 => ip.is_ipv6(),
                AddressFamily::Any => true,
            };
            if matches {
                return Ok(Operation::Ready(Hostent::new(hostname.to_string(), vec![ip])));
            }
        }

        // Check hosts file
        let hosts_result = self.transport.hosts().lookup(hostname, family_filter);
        if let Some(ref lookup) = hosts_result {
            if !lookup.addrs.is_empty() {
                return Ok(Operation::Ready(Hostent::from_lookup(lookup.clone())));
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
            return Ok(Operation::Ready(Hostent::new(hostname.to_string(), addrs)));
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
                        return Err(ARES_EFILE.into());
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
        if self.transport.config.nameservers.is_empty() {
            return Err(ARES_ENOSERVER.into());
        }

        // Check query cache
        if self.query_cache_max_ttl > 0 {
            let record_type = match family_filter {
                AddressFamily::Ipv4 => RECORD_TYPE_A,
                AddressFamily::Ipv6 | AddressFamily::Any => RECORD_TYPE_AAAA,
            };
            let cache_key = (resolved_name.clone(), record_type);
            if let Some((cached_buf, expires_at)) = self.query_cache.get(&cache_key) {
                if now < *expires_at {
                    let cached_buf = cached_buf.clone();
                    let parsed = (|| -> Result<ParsedRRs<AddrRecord>, AresError> {
                        let response = ParsedResponse::from_buf(&cached_buf)?;
                        let parsed_rrs = response.process_answers::<AddrRecord>(&cached_buf, record_type)?;
                        if parsed_rrs.items.is_empty() {
                            return Err(ARES_ENODATA.into());
                        }
                        Ok(parsed_rrs)
                    })();
                    // On a cache-hit parse error, fall through to a fresh DNS query.
                    if let Ok(mut parsed_rrs) = parsed {
                        if !self.sortlist.is_empty() {
                            apply_sortlist(&self.sortlist, &mut parsed_rrs.items);
                        }
                        let current_family = match family_filter {
                            AddressFamily::Ipv4 => libc::AF_INET,
                            AddressFamily::Ipv6 | AddressFamily::Any => libc::AF_INET6,
                        };
                        return Ok(Operation::Ready(Hostent::from_parsed(parsed_rrs, current_family)));
                    }
                } else {
                    self.query_cache.remove(&cache_key);
                }
            }
        }

        // Build the search plan + state machine, then the pooled launch and the
        // failover probe. On exhaustion the probe still runs (its health
        // bookkeeping sees the launch failures) and ECONNREFUSED is delivered.
        let use_tcp = self.transport.config.options.use_vc;
        let plan = SearchPlan::for_gethostbyname(
            &resolved_name,
            self.transport.config.options.ndots,
            &self.transport.config.search,
        );
        let query_hostname = plan.current.clone();
        let sm = HostByNameSm::new(plan, family, use_tcp);
        let first_server = self.server_health.pick_next();

        let (send_family, send_rtype) = (sm.current_family, sm.expected_rtype);
        let handle = Rc::new(RefCell::new(sm));
        let launched = self.launch_pooled(&query_hostname, send_family, send_rtype, use_tcp, first_server, &handle, binding);
        // Server failover probing: if enabled, probe an expired-failure
        // server in parallel with the primary query (its binding is a copy).
        self.maybe_launch_probe(&query_hostname, send_family, first_server, use_tcp, binding);
        match launched {
            LaunchOutcome::Launched => Ok(Operation::Pending),
            LaunchOutcome::Exhausted { .. } => Err(ARES_ECONNREFUSED.into()),
        }
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
        let first_server = self.server_health.pick_next();
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

    /// A gethostbyname task settled (reply or error): parse, feed the machine,
    /// perform its re-sends (pooled launch) and cache stores, apply the
    /// sortlist, and return what the shim must deliver to C.
    #[allow(clippy::too_many_arguments)] // reply-executor seam: the task's binding rides along
    pub(crate) fn on_hostbyname_reply(
        &mut self,
        sm: &Rc<RefCell<HostByNameSm>>,
        res: Result<&[u8], AresError>,
        server: usize,
        io_timeouts: i32,
        now: Instant,
        binding: T,
    ) -> Vec<HostDelivery>
    where
        T: Copy,
    {
        // Parse outside the machine; the machine sees only the outcome.
        let mut parsed_items: Option<ParsedRRs<AddrRecord>> = None;
        let ev = match res {
            Ok(buf) => {
                let expected_rtype = sm.borrow().expected_rtype;
                let outcome = match addr_reply(buf, expected_rtype, ReplyRequire::Items) {
                    Ok(rrs) => {
                        parsed_items = Some(rrs);
                        Ok(())
                    }
                    Err(e) => Err(e),
                };
                HostEvent::Reply { parse: outcome, io_timeouts, server }
            }
            Err(status) => HostEvent::Error { status },
        };

        let actions = {
            let cfg = LookupCfg {
                ndots: self.transport.config.options.ndots,
                search: &self.transport.config.search,
            };
            let mut machine = sm.borrow_mut();
            machine.step(ev, &cfg, &mut self.server_health)
        };

        let mut deliveries = Vec::new();
        for action in actions {
            match action {
                HostAction::Send { name, family, rtype, tcp, server } => {
                    if let LaunchOutcome::Exhausted { timeouts } =
                        self.launch_pooled(&name, family, rtype, tcp, server, sm, binding)
                    {
                        deliveries.push(HostDelivery::Fail { status: ARES_ECONNREFUSED.into(), timeouts });
                    }
                }
                HostAction::CacheStore { names, rtype } => {
                    if self.query_cache_max_ttl > 0 {
                        if let (Ok(buf), Some(rrs)) = (&res, &parsed_items) {
                            let ttl = rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                            cache_store_names(&mut self.query_cache, self.query_cache_max_ttl, names, rtype, ttl, buf, now);
                        }
                    }
                }
                HostAction::DeliverSuccess { family, timeouts } => {
                    let Some(mut rrs) = parsed_items.take() else { continue };
                    if !self.sortlist.is_empty() {
                        apply_sortlist(&self.sortlist, &mut rrs.items);
                    }
                    deliveries.push(HostDelivery::Success { hostent: Hostent::from_parsed(rrs, family), timeouts });
                }
                HostAction::DeliverFail { status, timeouts } => {
                    deliveries.push(HostDelivery::Fail { status, timeouts });
                }
            }
        }
        deliveries
    }

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

    /// A probe task settled: fold the reply's rcode into the server-health
    /// accounting. Some(ok) asks the shim to fire the server-state callback.
    pub(crate) fn on_probe_reply(&mut self, res: Result<&[u8], AresError>, server: usize) -> Option<bool> {
        let health = &mut self.server_health;
        match res {
            Ok(buf) => {
                let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0xff };
                if rcode == 0 || rcode == 3 {
                    // Success or NXDOMAIN — the server is alive again.
                    health.record_success(server).then_some(true)
                } else {
                    // SERVFAIL/NOTIMP/REFUSED — still failing.
                    health.record_failure(server).then_some(false)
                }
            }
            Err(_) => {
                // Timeout or other error — update the failure timestamp only.
                health.record_failure_time(server);
                None
            }
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

/// Store a successful reply under (qname, qtype), clamped to the minimum
/// answer TTL and the channel limit. `from_buf` only succeeds with a
/// non-empty answer section, so the historical `ancount > 0` guard is
/// implied by the parse.
pub(crate) fn cache_reply(
    cache: &mut HashMap<(String, u16), (Vec<u8>, Instant)>,
    max_ttl: u32,
    buf: &[u8],
    now: Instant,
) {
    // Extract query name and type from the response buffer
    if let Ok(parsed) = ParsedResponse::from_buf(buf) {
        let qname = parsed.query.name.join(".");
        let qtype = parsed.query.qtype;
        // Find minimum TTL from answers
        let min_ttl = parsed.answers.iter().map(|a| a.ttl).min().unwrap_or(0);
        let cache_ttl = std::cmp::min(min_ttl, max_ttl);
        if cache_ttl > 0 {
            let expires = now + Duration::from_secs(cache_ttl as u64);
            cache.insert((qname, qtype), (buf.to_vec(), expires));
        }
    }
}

/// The HostAction::CacheStore arm: store one reply under every search name
/// it answered, clamped to the minimum record TTL and the channel limit.
pub(crate) fn cache_store_names(
    cache: &mut HashMap<(String, u16), (Vec<u8>, Instant)>,
    max_ttl: u32,
    names: Vec<String>,
    rtype: u16,
    min_item_ttl: u32,
    buf: &[u8],
    now: Instant,
) {
    let cache_ttl = std::cmp::min(min_item_ttl, max_ttl);
    if cache_ttl > 0 {
        let expires = now + Duration::from_secs(cache_ttl as u64);
        for name in names {
            cache.insert((name, rtype), (buf.to_vec(), expires));
        }
    }
}

/// Strip the 2-byte TCP length prefix when re-framing a write buffer for a
/// retry (enqueue re-frames for the target transport).
pub(crate) fn tcp_payload(writebuf: &[u8], was_tcp: bool) -> &[u8] {
    if was_tcp && writebuf.len() > 2 {
        &writebuf[2..]
    } else {
        writebuf
    }
}
