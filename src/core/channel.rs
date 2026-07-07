//! The pure channel state and its configuration/lifecycle logic: everything
//! a channel owns except the C callbacks (which live in ffi::ChannelData
//! around this struct). Options application, server-list install/report,
//! reactor fd/timeout reporting, query-cache stores, and pool retention all
//! live here; the ffi shims only marshal C values in and out.

use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::core::transport::{Transport, Status};
use crate::core::lookup::ServerHealth;
use crate::core::response::ParsedResponse;
use crate::core::sortlist::SortlistEntry;
use crate::core::socket::Socket;
use crate::ffi::ares_options::{
    ARES_FLAG_EDNS, ARES_FLAG_PRIMARY, ARES_FLAG_USEVC, ARES_OPT_DOMAINS, ARES_OPT_FLAGS,
    ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS,
    ARES_OPT_NOROTATE, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF, ARES_OPT_ROTATE,
    ARES_OPT_SERVERS, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SORTLIST, ARES_OPT_TCP_PORT,
    ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES, ARES_OPT_UDP_MAX_QUERIES,
    ARES_OPT_UDP_PORT,
};

/// Everything a channel owns that is pure Rust: the engine, health/cache
/// bookkeeping, configuration strings, and the shared-socket pools. Generic
/// over the per-task userdata `T`, which core never inspects.
pub(crate) struct ChannelState<T> {
    pub ares: Transport<T>,
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

impl<T> ChannelState<T> {
    /// A fresh channel around `ares` — shared by ares_init and ares_init_options.
    pub fn new(ares: Transport<T>) -> Self {
        ChannelState {
            ares,
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
    pub fn duplicate(&self) -> ChannelState<T> {
        let mut ares = Transport::new(self.ares.config.clone(), self.ares.socket_factory.clone());
        ares.default_udp_port = self.ares.default_udp_port;
        ares.default_tcp_port = self.ares.default_tcp_port;
        let mut dup = ChannelState::new(ares);
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
            self.ares.config.nameservers.clear();
            self.ares.config.tcp_ports.clear();
            for v4 in &o.servers {
                self.ares.config.nameservers.push((IpAddr::V4(*v4), None));
                self.ares.config.tcp_ports.push(None);
            }
        }
        if optmask & ARES_OPT_UDP_PORT != 0 {
            self.ares.default_udp_port = o.udp_port;
        }
        if optmask & ARES_OPT_TCP_PORT != 0 {
            self.ares.default_tcp_port = o.tcp_port;
        }
        if optmask & ARES_OPT_TIMEOUTMS != 0 {
            self.ares.config.options.timeout_ms = std::cmp::max(1, o.timeout as u32);
        }
        if optmask & ARES_OPT_TIMEOUT != 0 {
            self.ares.config.options.timeout_ms = o.timeout as u32 * 1000;
        }
        if optmask & ARES_OPT_TRIES != 0 {
            self.ares.config.options.attempts = o.tries as u32;
        }
        if optmask & ARES_OPT_NDOTS != 0 {
            self.ares.config.options.ndots = o.ndots as u32;
        }
        if optmask & ARES_OPT_FLAGS != 0 {
            self.flags = o.flags;
            self.ares.config.options.use_vc = (o.flags & ARES_FLAG_USEVC) != 0;
            self.ares.config.options.edns0 = (o.flags & ARES_FLAG_EDNS) != 0;
            // ARES_FLAG_PRIMARY: truncate to first server only
            if (o.flags & ARES_FLAG_PRIMARY) != 0 {
                self.ares.config.nameservers.truncate(1);
                self.ares.config.tcp_ports.truncate(1);
            }
        }
        if optmask & ARES_OPT_DOMAINS != 0 {
            if let Some(domains) = o.domains {
                self.ares.config.search = domains;
            }
        }
        if optmask & ARES_OPT_NOROTATE != 0 {
            self.ares.config.options.rotate = false;
        }
        if optmask & ARES_OPT_ROTATE != 0 {
            self.ares.config.options.rotate = true;
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
        self.server_health.reset(self.ares.config.nameservers.len());
    }

    /// The pure inverse of the cascade: read the channel back into option fields.
    pub fn saved_options(&self) -> SavedOptions {
        let config = &self.ares.config;
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
            udp_port: self.ares.default_udp_port,
            tcp_port: self.ares.default_tcp_port,
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
        self.ares.config.nameservers.clear();
        self.ares.config.tcp_ports.clear();
        for server in servers {
            self.ares.config.nameservers.push((server.ip, server.udp_port));
            self.ares.config.tcp_ports.push(server.tcp_port);
        }
        self.server_health.reset(self.ares.config.nameservers.len());
    }

    /// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
    pub fn clear_servers(&mut self) {
        self.ares.config.nameservers.clear();
        self.ares.config.tcp_ports.clear();
        self.server_health.clear();
    }

    /// Install a parsed CSV server list (ares_set_servers_ports_csv).
    pub fn install_csv_servers(&mut self, ns: Vec<(IpAddr, Option<u16>)>) {
        self.ares.config.tcp_ports = vec![None; ns.len()];
        self.server_health.reset(ns.len());
        self.ares.config.nameservers = ns;
    }

    /// The configured servers with per-entry defaults applied, in order:
    /// (ip, udp_port, tcp_port) — the report behind ares_get_servers[_ports].
    pub fn server_list(&self) -> Vec<(IpAddr, u16, u16)> {
        self.ares
            .config
            .nameservers
            .iter()
            .map(|(ip, port)| {
                (
                    *ip,
                    port.unwrap_or(self.ares.default_udp_port),
                    port.unwrap_or(self.ares.default_tcp_port),
                )
            })
            .collect()
    }

    /// The `ip:port` CSV report behind ares_get_servers_csv (IPv6 bracketed).
    pub fn servers_csv_string(&self) -> String {
        let default_port = self.ares.default_udp_port;
        self.ares
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
        self.ares
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
        if self.ares.tasks.is_empty() {
            return None;
        }
        Some(self.ares.max_wait_time().as_millis())
    }

    /// Non-completed task count (ares_queue_active_queries).
    pub fn active_query_count(&self) -> usize {
        self.ares
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
        let (ip, port) = self.ares.config.nameservers.get(server_index)?;
        let port_val = port.unwrap_or(if is_tcp {
            self.ares.default_tcp_port
        } else {
            self.ares.default_udp_port
        });
        Some(match ip {
            IpAddr::V4(v4) => format!("{}:{}", v4, port_val),
            IpAddr::V6(v6) => format!("[{}]:{}", v6, port_val),
        })
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
