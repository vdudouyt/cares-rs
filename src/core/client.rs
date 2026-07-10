//! The pure channel state and its configuration/lifecycle logic: everything
//! a channel owns except the C callbacks (which live in ffi::ChannelData
//! around this struct). Options application, server-list install/report,
//! reactor fd/timeout reporting, query-cache stores, and pool retention all
//! live here; the ffi shims only marshal C values in and out.

use std::cell::RefCell;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use bytes::BytesMut;

use crate::core::cache::QueryCache;
use crate::core::async_client;
use crate::core::hostent::Hostent;
use crate::core::hostfile::{AddressFamily, HostLookup};
use crate::core::lookup::ServerHealth;
use crate::core::async_client::dns_query_payload;
use crate::core::sortlist::SortlistEntry;
use crate::core::transport::Transport;
use crate::core::AresError;
use crate::ffi::ares_options::{
    ARES_FLAG_EDNS, ARES_FLAG_PRIMARY, ARES_FLAG_USEVC, ARES_OPT_DOMAINS, ARES_OPT_FLAGS,
    ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS,
    ARES_OPT_NOROTATE, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF, ARES_OPT_ROTATE,
    ARES_OPT_SERVERS, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SORTLIST, ARES_OPT_TCP_PORT,
    ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES, ARES_OPT_UDP_MAX_QUERIES,
    ARES_OPT_UDP_PORT,
};
use crate::ffi::error::{ARES_EBADQUERY, ARES_ENOSERVER, ARES_ENOTFOUND};

/// Everything a channel owns that is pure Rust: config, health/cache
/// bookkeeping, configuration strings, and the shared-socket pools for the
/// async engine.
pub(crate) struct Client {
    pub transport: Transport,
    /// Shared with the async engine's in-flight futures (`Rc<RefCell<_>>`) so
    /// failover accounting and the probe agree across queries.
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
    pub tcp_pool: Rc<RefCell<crate::async_runtime::conn::TcpPool>>,
    /// Per-server connect endpoints, cached (rebuilt on server change) so each
    /// async launch clones an `Rc` instead of re-snapshotting the config.
    endpoints: Rc<Vec<async_client::ServerEndpoint>>,
    pub server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub server_failover_retry_delay: u64,  // milliseconds
    /// The channel-owned resolver client (config snapshot), built lazily and
    /// cached; each lookup derives a fresh-mailbox copy via `with_fresh_io`.
    /// Invalidated (`None`) on every config change — see `rebuild_endpoints`
    /// (the chokepoint for servers/options) and `set_sortlist`.
    async_base: Option<Rc<crate::core::async_client::AsyncClient>>,
}

impl Client {
    /// A fresh channel around `transport` — shared by ares_init and ares_init_options.
    pub fn new(transport: Transport) -> Self {
        let mut client = Client {
            transport,
            server_health: Rc::new(RefCell::new(ServerHealth::default())),
            sortlist: vec![],
            flags: 0,
            maxtimeout: 0,
            lookups: String::new(),
            resolvconf_path: String::new(),
            hosts_path: String::new(),
            cache: Rc::new(RefCell::new(QueryCache::default())),
            udp_max_queries: 0,
            tcp_pool: Rc::new(RefCell::new(crate::async_runtime::conn::TcpPool::new(
                async_client::dns_frame,
                async_client::dns_tag,
            ))),
            endpoints: Rc::new(Vec::new()),
            server_failover_retry_chance: 0,
            server_failover_retry_delay: 0,
            async_base: None,
        };
        client.rebuild_endpoints();
        client
    }

    /// The pure body of ares_dup: clone configuration, start with a fresh
    /// reactor state (empty query cache, no pooled connections, cleared
    /// failure timestamps — but cloned failure counts).
    pub fn duplicate(&self) -> Client {
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

/// The async-engine resource builders + the pure entry helpers the ffi shims
/// compose (query/send payloads, the gethostbyname/getaddrinfo/... contexts).
impl Client {
    // ===== Async-engine resource builders =====

    /// Rebuild the cached endpoint snapshot after a server/port change.
    pub fn rebuild_endpoints(&mut self) {
        self.endpoints = Rc::new(self.endpoint_snapshot());
        // The chokepoint for server/option changes (set_servers + the tail of
        // apply_options both land here): drop the cached async base so the next
        // lookup rebuilds it from current config.
        self.async_base = None;
    }

    /// Replace the sortlist and invalidate the cached async base. `sortlist` is a
    /// `pub` field mutated directly by `ares_set_sortlist` (the one config-change
    /// path that doesn't funnel through `rebuild_endpoints`), so it needs its own
    /// invalidation hook.
    pub(crate) fn set_sortlist(&mut self, entries: Vec<SortlistEntry>) {
        self.sortlist = entries;
        self.async_base = None;
    }

    /// Snapshot the per-server connect endpoints from config, so an async
    /// lifecycle future needs no `Transport`.
    fn endpoint_snapshot(&self) -> Vec<async_client::ServerEndpoint> {
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
                async_client::ServerEndpoint {
                    udp_addr: SocketAddr::from((ip, udp_port)),
                    tcp_addr: SocketAddr::from((ip, tcp_port)),
                    bind,
                }
            })
            .collect()
    }

    /// The retry/timeout knobs an async lifecycle needs.
    fn query_opts(&self) -> async_client::QueryOpts {
        async_client::QueryOpts {
            attempts: self.transport.config.options.attempts,
            timeout: Duration::from_millis(self.transport.config.options.timeout_ms as u64),
            failover_chance: self.server_failover_retry_chance,
            failover_delay: self.server_failover_retry_delay,
        }
    }

    /// Bundle the owned resources an async lifecycle future carries. Cheap: all
    /// `Rc` clones (endpoints cached, rebuilt only on server change).
    pub(crate) fn resources(&self) -> async_client::Resources {
        async_client::Resources {
            factory: self.transport.socket_factory.clone(),
            health: self.server_health.clone(),
            endpoints: self.endpoints.clone(),
            tcp_pool: self.tcp_pool.clone(),
            opts: self.query_opts(),
        }
    }

    /// Hand out a per-lookup resolver client: the channel-owned `AsyncClient`
    /// base (built lazily, cached, rebuilt on config change) derived into a copy
    /// with its own fresh mailbox. Each lookup thus owns a distinct `QueryIo`
    /// while sharing the config `Rc`s. The one spot that reads `Client` for the
    /// async lifecycles; the futures themselves name no channel.
    pub(crate) fn async_client(&mut self) -> Rc<crate::core::async_client::AsyncClient> {
        if self.async_base.is_none() {
            let base = self.build_async_base();
            self.async_base = Some(base);
        }
        self.async_base.as_ref().unwrap().with_fresh_io()
    }

    /// Build the channel-owned `AsyncClient` base: the socket resources plus
    /// `Rc`/snapshot handles for the preflight (hosts file, query cache, sortlist,
    /// ndots/search/use_vc). The `io` here is an inert placeholder — `async_client`
    /// replaces it per lookup. Returned as `Rc` so methods take `self: Rc<Self>`
    /// (spawnable `'static` futures + cheap sharing for nested calls).
    fn build_async_base(&mut self) -> Rc<crate::core::async_client::AsyncClient> {
        Rc::new(crate::core::async_client::AsyncClient {
            io: Rc::new(std::cell::RefCell::new(async_client::DnsMailbox::default())),
            res: self.resources(),
            hosts: self.transport.hosts(),
            cache: self.cache.clone(),
            sortlist: Rc::from(self.sortlist.clone()),
            ndots: self.transport.config.options.ndots,
            search: Rc::from(self.transport.config.search.clone()),
            use_vc: self.transport.config.options.use_vc,
        })
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
fn hosts_file_lookup(st: &mut Client, name: &str, family: i32) -> Result<HostLookup, AresError> {
    // Convert C family constant to our Family enum
    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => return Err(ARES_ENOTFOUND.into()),
    };

    // Lookup in the hosts file cache
    let lookup = st.transport.hosts().lookup(name, family_filter).ok_or(ARES_ENOTFOUND)?;
    if lookup.addrs.is_empty() {
        return Err(ARES_ENOTFOUND.into());
    }
    Ok(lookup)
}

/// ENOSERVER guard shared by ares_query / ares_query_dnsrec / ares_send.
fn no_servers(st: &Client) -> bool {
    st.transport.config.nameservers.is_empty()
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


