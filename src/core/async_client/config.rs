//! Channel construction and configuration: building from the system config,
//! `ares_reinit`, defaults, `ares_dup`, the `ares_options` mapping in both
//! directions, and the server-list exports.

use super::*;
use crate::plugins::dns0x20::Dns0x20Plugin;
use crate::plugins::edns::EdnsPlugin;

impl AsyncClient {
    /// A fresh channel from the system config (resolv.conf + env overrides).
    /// Defaults are applied separately so options/flags set afterwards win.
    pub fn from_sysconfig_path(factory: Rc<dyn SocketFactory>, path: Option<&str>) -> Self {
        let mut client = AsyncClient::build(build_sysconfig(path), factory, 53, 53);
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

        let mut servers_updated = false;
        if self.optmask & ARES_OPT_SERVERS == 0
            && !sys.nameservers.is_empty()
            && (sys.nameservers != self.config.nameservers || sys.scopes != self.config.scopes)
        {
            self.config.nameservers = sys.nameservers;
            self.config.tcp_ports = sys.tcp_ports;
            self.config.scopes = sys.scopes;
            servers_updated = true;
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
        // System `use-vc` must not override caller-supplied flags
        // (ares_reinit.3: configuration never overrides explicit options).
        if self.optmask & ARES_OPT_FLAGS == 0 && sys.options.use_vc {
            self.flags |= ARES_FLAG_USEVC;
            self.config.options.use_vc = true;
        }
        if servers_updated {
            self.servers_changed();
        }
        self.shared.cache.borrow_mut().flush();
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
            self.config.scopes.push(0);
        }
        // The end of every init path: options may have changed the servers or
        // their default ports.
        self.servers_changed();
    }

    /// The server list or its default ports were set or changed: resolve each
    /// server's identity (address + both ports) once — every lookup copy shares
    /// the list through the `Rc` — and sync per-server state to it, like
    /// upstream `ares_servers_update`: servers still configured keep their
    /// health, plugin state (DNS cookies) and pooled conns; removed ones lose them. Duplicate
    /// entries are skipped (upstream `ares_server_isdup`). A real change also
    /// flushes the query cache.
    pub(super) fn servers_changed(&mut self) {
        let mut servers: Vec<ServerId> = Vec::with_capacity(self.config.nameservers.len());
        for (i, &(addr, udp_port)) in self.config.nameservers.iter().enumerate() {
            let tcp_port = self.config.tcp_ports.get(i).copied().flatten();
            let scope_id = self.config.scopes.get(i).copied().unwrap_or(0);
            let id = ServerId {
                addr,
                udp_port: udp_port.unwrap_or(self.default_udp_port),
                tcp_port: tcp_port.unwrap_or(self.default_tcp_port),
                scope_id,
            };
            if !servers.contains(&id) {
                servers.push(id);
            }
        }
        if servers != *self.servers {
            self.shared.cache.borrow_mut().flush();
        }
        self.shared.health.borrow_mut().sync(&servers);
        for plugin in &self.plugins {
            plugin.on_servers_changed(&servers);
        }
        // Evicted conns are queued and dropped by the ffi caller after the
        // channel state borrow ends (closing fires C callbacks, which may
        // re-enter the channel).
        let tcp = self.shared.tcp_pool.borrow_mut().retain_servers(&servers);
        let udp = self.shared.udp_pool.borrow_mut().retain_servers(&servers);
        {
            let mut pending = self.pending_drops.borrow_mut();
            pending.extend(tcp.into_iter().map(DroppedConn::Tcp));
            pending.extend(udp.into_iter().map(DroppedConn::Udp));
        }
        self.servers = Rc::new(servers);
    }


    pub(super) fn build(
        config: SysConfig,
        factory: Rc<dyn SocketFactory>,
        default_udp_port: u16,
        default_tcp_port: u16,
    ) -> Self {
        let mut client = AsyncClient {
            config,
            rt: Runtime::new(factory),
            hosts: OnceCell::new(),
            default_udp_port,
            default_tcp_port,
            socket_send_buffer_size: 0,
            socket_receive_buffer_size: 0,
            local_ip4: 0,
            local_ip6: [0; 16],
            local_dev: String::new(),
            shared: ChannelShared::new(),
            plugins: Vec::new(),
            sortlist: vec![],
            flags: 0,
            ednspsz: EDNS_PACKETSZ as i32,
            maxtimeout: 0,
            optmask: 0,
            lookups: String::new(),
            resolvconf_path: String::new(),
            hosts_path: String::new(),
            udp_max_queries: 0,
            servers: Rc::new(Vec::new()),
            // Documented defaults (ares_init_options(3)): a 1-in-10 retry
            // chance with a 5 s minimum delay. They are applied here rather
            // than in `apply_defaults` so they never show up in the optmask.
            server_failover_retry_chance: 10,
            server_failover_retry_delay: 5000,
            pending_drops: RefCell::new(Vec::new()),
        };
        // Run order matters: 0x20 drops case-mismatched replies before EDNS
        // validates (and updates) the server's cookie state.
        client.add_plugin(Dns0x20Plugin::new());
        client.add_plugin(EdnsPlugin::new());
        client.servers_changed();
        client
    }

    /// Register a query plugin; plugins run in registration order.
    pub(crate) fn add_plugin(&mut self, plugin: impl Plugin + 'static) {
        self.plugins.push(Rc::new(plugin));
    }

    /// The hosts table as a shared `Rc`, lazily loaded once. An empty
    /// `ARES_OPT_HOSTS_FILE` path means the system `/etc/hosts`.
    pub fn hosts(&self) -> Rc<Hosts> {
        let path = if self.hosts_path.is_empty() {
            "/etc/hosts".to_string()
        } else {
            self.hosts_path.clone()
        };
        self.hosts
            .get_or_init(|| Rc::new(Hosts::from_path(path).unwrap_or_default()))
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
        dup.shared.health.borrow_mut().copy_failures_from(&self.shared.health.borrow());
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
        dup.shared.cache.borrow_mut().set_max_ttl(self.shared.cache.borrow().max_ttl());
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
            self.config.scopes.clear();
            for v4 in &o.servers {
                self.config.nameservers.push((IpAddr::V4(*v4), None));
                self.config.tcp_ports.push(None);
                self.config.scopes.push(0);
            }
        }
        if optmask & ARES_OPT_UDP_PORT != 0 {
            self.default_udp_port = o.udp_port;
        }
        if optmask & ARES_OPT_TCP_PORT != 0 {
            self.default_tcp_port = o.tcp_port;
        }
        if optmask & ARES_OPT_TIMEOUTMS != 0 {
            // Upstream: non-positive means "use the default" and drops the bit.
            if o.timeout <= 0 {
                stored_mask &= !ARES_OPT_TIMEOUTMS;
            } else {
                self.config.options.timeout_ms = o.timeout as u32;
            }
        } else if optmask & ARES_OPT_TIMEOUT != 0 {
            // ARES_OPT_TIMEOUT is converted to ARES_OPT_TIMEOUTMS; a
            // non-positive value drops the option entirely.
            stored_mask &= !ARES_OPT_TIMEOUT;
            if o.timeout > 0 {
                let ms = (o.timeout as u64).saturating_mul(1000);
                self.config.options.timeout_ms = ms.min(u32::MAX as u64) as u32;
                stored_mask |= ARES_OPT_TIMEOUTMS;
            }
        }
        if optmask & ARES_OPT_TRIES != 0 {
            if o.tries <= 0 {
                stored_mask &= !ARES_OPT_TRIES;
            } else {
                self.config.options.attempts = o.tries as u32;
            }
        }
        if optmask & ARES_OPT_NDOTS != 0 {
            if o.ndots < 0 {
                stored_mask &= !ARES_OPT_NDOTS;
            } else {
                self.config.options.ndots = o.ndots as u32;
            }
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
                self.config.scopes.truncate(1);
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
            if o.maxtimeout <= 0 {
                stored_mask &= !ARES_OPT_MAXTIMEOUTMS;
            } else {
                self.maxtimeout = o.maxtimeout;
            }
        }
        if optmask & ARES_OPT_LOOKUPS != 0 {
            if let Some(lookups) = o.lookups {
                self.lookups = lookups;
            } else {
                // A NULL pointer is "not supplied"; upstream drops the bit.
                stored_mask &= !ARES_OPT_LOOKUPS;
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
            } else {
                stored_mask &= !ARES_OPT_RESOLVCONF;
            }
        }
        if optmask & ARES_OPT_HOSTS_FILE != 0 {
            if let Some(path) = o.hosts_path {
                self.hosts_path = path;
            } else {
                stored_mask &= !ARES_OPT_HOSTS_FILE;
            }
        }
        if optmask & ARES_OPT_QUERY_CACHE != 0 {
            self.shared.cache.borrow_mut().set_max_ttl(o.qcache_max_ttl);
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

    /// The pure inverse of the cascade: read the channel back into option
    /// fields. Every reported value is gated on the channel's stored optmask
    /// so inherited/system defaults are not mistaken for explicit options.
    pub fn saved_options(&self) -> SavedOptions {
        let config = &self.config;
        let opts = &config.options;
        let mask = self.optmask;

        // servers (IPv4 only in ares_options)
        let v4_servers: Vec<Ipv4Addr> = if mask & ARES_OPT_SERVERS != 0 {
            config
                .nameservers
                .iter()
                .filter_map(|(ip, _)| match ip {
                    IpAddr::V4(v4) => Some(*v4),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };

        let domains: Vec<CString> = if mask & ARES_OPT_DOMAINS != 0 {
            config
                .search
                .iter()
                .map(|domain| CString::new(domain.as_str()).unwrap_or_default())
                .collect()
        } else {
            Vec::new()
        };

        let sortlist = if mask & ARES_OPT_SORTLIST != 0 {
            self.sortlist.clone()
        } else {
            Vec::new()
        };
        let maxtimeout = (mask & ARES_OPT_MAXTIMEOUTMS != 0).then_some(self.maxtimeout);
        let lookups = (mask & ARES_OPT_LOOKUPS != 0)
            .then(|| CString::new(self.lookups.as_str()).unwrap_or_default());
        let resolvconf_path = (mask & ARES_OPT_RESOLVCONF != 0)
            .then(|| CString::new(self.resolvconf_path.as_str()).unwrap_or_default());
        let hosts_path = (mask & ARES_OPT_HOSTS_FILE != 0)
            .then(|| CString::new(self.hosts_path.as_str()).unwrap_or_default());
        let qcache_max_ttl =
            (mask & ARES_OPT_QUERY_CACHE != 0).then(|| self.shared.cache.borrow().max_ttl());
        let server_failover = (mask & ARES_OPT_SERVER_FAILOVER != 0)
            .then_some((self.server_failover_retry_chance, self.server_failover_retry_delay));

        SavedOptions {
            mask,
            flags: self.flags,
            ednspsz: self.ednspsz,
            timeout: opts.timeout_ms as i32,
            tries: opts.attempts as i32,
            ndots: opts.ndots as i32,
            udp_port: self.default_udp_port,
            tcp_port: self.default_tcp_port,
            v4_servers,
            domains,
            sortlist,
            maxtimeout,
            lookups,
            resolvconf_path,
            hosts_path,
            udp_max_queries: self.udp_max_queries as i32,
            socket_send_buffer_size: self.socket_send_buffer_size,
            socket_receive_buffer_size: self.socket_receive_buffer_size,
            qcache_max_ttl,
            server_failover,
        }
    }

    /// Install a decoded server list (ares_set_servers / ares_set_servers_ports).
    pub fn set_servers(&mut self, servers: Vec<ServerSpec>) {
        self.config.nameservers.clear();
        self.config.tcp_ports.clear();
        self.config.scopes.clear();
        for server in servers {
            self.config.nameservers.push((server.ip, server.udp_port));
            self.config.tcp_ports.push(server.tcp_port);
            self.config.scopes.push(server.scope_id);
        }
        self.optmask |= ARES_OPT_SERVERS;
        self.servers_changed();
    }

    /// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
    pub fn clear_servers(&mut self) {
        self.config.nameservers.clear();
        self.config.tcp_ports.clear();
        self.config.scopes.clear();
        self.optmask |= ARES_OPT_SERVERS;
        self.servers_changed();
    }

    /// Install a parsed CSV server list (ares_set_servers_ports_csv). The CSV
    /// parser sets the same port on both transports; `scope_id` comes from
    /// resolving any `%iface` suffix through the channel's if-index adapter.
    pub fn install_csv_servers(&mut self, ns: Vec<ServerSpec>) {
        self.config.nameservers = ns.iter().map(|s| (s.ip, s.udp_port)).collect();
        self.config.tcp_ports = ns.iter().map(|s| s.tcp_port).collect();
        self.config.scopes = ns.iter().map(|s| s.scope_id).collect();
        self.optmask |= ARES_OPT_SERVERS;
        self.servers_changed();
    }

    /// The configured servers with per-entry defaults and IPv6 scope ids, in order.
    pub fn server_list(&self) -> Vec<(IpAddr, u16, u16, u32)> {
        self.config
            .nameservers
            .iter()
            .enumerate()
            .map(|(i, (ip, port))| {
                (
                    *ip,
                    port.unwrap_or(self.default_udp_port),
                    port.unwrap_or(self.default_tcp_port),
                    self.config.scopes.get(i).copied().unwrap_or(0),
                )
            })
            .collect()
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
    /// IPv6 scope id for link-local addresses; 0 when unscoped.
    pub scope_id: u32,
}

/// 0 and 53 mean "no override".
pub(crate) fn normalize_port(port: u16) -> Option<u16> {
    if port == 0 || port == 53 { None } else { Some(port) }
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

/// Everything ares_save_options reports. `mask` is the channel's stored
/// optmask; the shim only writes a field when its bit is present, and the
/// `Option` fields are populated only for explicitly-configured options.
pub(crate) struct SavedOptions {
    pub mask: i32,
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
    pub qcache_max_ttl: Option<u32>,
    /// `(retry_chance, retry_delay_ms)` when `ARES_OPT_SERVER_FAILOVER` is set.
    pub server_failover: Option<(u16, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

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

    /// Upstream `init_by_defaults`: without `ARES_OPT_SERVER_FAILOVER` the
    /// channel gets a 10% retry chance and a 5 s minimum delay, but the default
    /// is not recorded in the optmask (so `ares_save_options` must not report
    /// it as explicitly configured).
    #[test]
    fn defaults_set_server_failover_without_adding_optmask_bit() {
        let mut client = AsyncClient::build(SysConfig::default(), noop_factory(), 53, 53);
        client.apply_defaults();
        assert_eq!(
            client.server_failover_retry_chance, 10,
            "default server failover retry chance"
        );
        assert_eq!(
            client.server_failover_retry_delay, 5000,
            "default server failover retry delay (ms)"
        );
        assert_eq!(
            client.optmask & ARES_OPT_SERVER_FAILOVER,
            0,
            "applying defaults must not add ARES_OPT_SERVER_FAILOVER to the optmask"
        );
    }

    fn spec(last: u8) -> ServerSpec {
        ServerSpec { ip: IpAddr::from([10, 0, 0, last]), scope_id: 0, udp_port: None, tcp_port: None }
    }

    /// The server list is resolved once per change and shared by lookup copies.
    #[test]
    fn servers_resolved_per_server_change_and_shared() {
        let mut client = AsyncClient::build(SysConfig::default(), noop_factory(), 53, 53);
        client.set_servers(vec![spec(1)]);
        let copy = client.derive();
        assert!(Rc::ptr_eq(&copy.servers, &client.servers), "derive shares, not recomputes");
        assert_eq!(client.servers[0].udp_addr(), SocketAddr::from(([10, 0, 0, 1], 53)));

        client.set_servers(vec![spec(2)]);
        assert_eq!(client.servers[0].udp_addr(), SocketAddr::from(([10, 0, 0, 2], 53)));
        assert_eq!(copy.servers[0].udp_addr(), SocketAddr::from(([10, 0, 0, 1], 53)), "copies keep theirs");

        client.default_udp_port = 5353;
        client.servers_changed();
        assert_eq!(client.servers[0].udp_addr(), SocketAddr::from(([10, 0, 0, 2], 5353)));
    }

    /// A server keeps its state across a server-list change while it stays
    /// configured; duplicates are skipped; removed servers lose their state.
    #[test]
    fn server_state_survives_server_list_changes() {
        let mut client = AsyncClient::build(SysConfig::default(), noop_factory(), 53, 53);
        client.set_servers(vec![spec(1), spec(2)]);
        let first = client.servers.to_vec();
        client.shared.health.borrow_mut().record_failure(first[1]);

        client.set_servers(vec![spec(2), spec(3), spec(2)]);
        let second = client.servers.to_vec();
        assert_eq!(second.len(), 2, "the duplicate 10.0.0.2 is skipped");
        assert_eq!(second[0], first[1], "10.0.0.2 is the same server");
        let health = client.shared.health.borrow();
        assert!(!health.contains(first[0]), "10.0.0.1 left the list");
        assert_eq!(health.failure_counts(), vec![1, 0], "10.0.0.2 keeps its failure");
    }

    /// The query cache is flushed only when the server list really changes.
    #[test]
    fn cache_flushed_only_on_real_server_change() {
        let mut client = AsyncClient::build(SysConfig::default(), noop_factory(), 53, 53);
        client.set_servers(vec![spec(1)]);
        client.shared.cache.borrow_mut().set_max_ttl(3600);
        let key = CacheKey::new("cached.test", 1, ARES_CLASS_IN, 0, true, false);
        let store = |c: &AsyncClient| {
            c.shared.cache.borrow_mut().store_names(vec![key.name.clone()], &key, 60, &[0u8; 12], Instant::now())
        };
        let cached = |c: &AsyncClient| c.shared.cache.borrow_mut().get(&key, Instant::now()).is_some();

        store(&client);
        client.set_servers(vec![spec(1)]);
        assert!(cached(&client), "same list: cache kept");
        client.set_servers(vec![spec(2)]);
        assert!(!cached(&client), "different list: cache flushed");
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
        client.shared.cache.borrow_mut().set_max_ttl(3600);
        let key = CacheKey::new("cached.test", 1, ARES_CLASS_IN, 0, true, false);
        client.shared.cache.borrow_mut().store_names(
            vec![key.name.clone()],
            &key,
            60,
            &[0u8; 12],
            Instant::now(),
        );
        assert!(client.shared.cache.borrow_mut().get(&key, Instant::now()).is_some());

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
        assert!(client.shared.cache.borrow_mut().get(&key, Instant::now()).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reinit_preserves_explicitly_set_servers() {
        let path = temp_conf("nameserver 9.9.9.9\n");
        let mut client = AsyncClient::build(SysConfig::default(), super::tests::noop_factory(), 53, 53);
        client.resolvconf_path = path.to_string_lossy().into_owned();
        client.set_servers(vec![ServerSpec {
            ip: IpAddr::from([8, 8, 4, 4]),
            scope_id: 0,
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
