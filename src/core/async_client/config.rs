//! Channel construction and configuration: building from the system config,
//! `ares_reinit`, defaults, `ares_dup`, the `ares_options` mapping in both
//! directions, and the server-list exports.

use super::*;

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
            && sys.nameservers != self.config.nameservers
        {
            self.config.nameservers = sys.nameservers;
            self.config.tcp_ports = sys.tcp_ports;
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
        if sys.options.use_vc {
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
        }
        // The end of every init path: options may have changed the servers or
        // their default ports.
        self.servers_changed();
    }

    /// The server list or its default ports were set or changed: resolve each
    /// server's endpoints once (every lookup copy shares them through the `Rc`)
    /// and reset per-server state. A real change also flushes the query cache,
    /// as upstream `ares_servers_update` does.
    pub(super) fn servers_changed(&mut self) {
        let endpoints: Vec<ServerEndpoint> = self
            .config
            .nameservers
            .iter()
            .enumerate()
            .map(|(i, &(ip, udp_port))| {
                let udp_port = udp_port.unwrap_or(self.default_udp_port);
                let tcp_port = self.config.tcp_ports.get(i).copied().flatten().unwrap_or(self.default_tcp_port);
                // The socket's address family; local-address options are
                // applied by the socket factory.
                let bind = if ip.is_ipv6() {
                    SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                } else {
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                };
                ServerEndpoint {
                    udp_addr: SocketAddr::from((ip, udp_port)),
                    tcp_addr: SocketAddr::from((ip, tcp_port)),
                    bind,
                }
            })
            .collect();
        if endpoints != *self.endpoints {
            self.shared.cache.borrow_mut().flush();
        }
        self.shared.health.borrow_mut().reset(endpoints.len());
        self.shared.cookies.borrow_mut().clear();
        // Conns are dropped after each pool borrow ends (closing fires C callbacks).
        let tcp = self.shared.tcp_pool.borrow_mut().clear();
        drop(tcp);
        let udp = self.shared.udp_pool.borrow_mut().clear();
        drop(udp);
        self.endpoints = Rc::new(endpoints);
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
            hosts: None,
            default_udp_port,
            default_tcp_port,
            socket_send_buffer_size: 0,
            socket_receive_buffer_size: 0,
            local_ip4: 0,
            local_ip6: [0; 16],
            local_dev: String::new(),
            shared: ChannelShared::new(),
            sortlist: vec![],
            flags: 0,
            ednspsz: EDNS_PACKETSZ as i32,
            maxtimeout: 0,
            optmask: 0,
            lookups: String::new(),
            resolvconf_path: String::new(),
            hosts_path: String::new(),
            udp_max_queries: 0,
            endpoints: Rc::new(Vec::new()),
            server_failover_retry_chance: 0,
            server_failover_retry_delay: 0,
        };
        client.servers_changed();
        client
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
            let src = self.shared.health.borrow();
            let mut health = ServerHealth::default();
            health.reset(src.len());
            health.failures = src.failures.clone();
            *dup.shared.health.borrow_mut() = health;
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
        self.servers_changed();
    }

    /// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
    pub fn clear_servers(&mut self) {
        self.config.nameservers.clear();
        self.config.tcp_ports.clear();
        self.optmask |= ARES_OPT_SERVERS;
        self.servers_changed();
    }

    /// Install a parsed CSV server list (ares_set_servers_ports_csv). A CSV
    /// `ip:port` sets both transports; the ports variant can still override TCP.
    pub fn install_csv_servers(&mut self, ns: Vec<(IpAddr, Option<u16>)>) {
        self.config.tcp_ports = ns.iter().map(|&(_, port)| port).collect();
        self.config.nameservers = ns;
        self.optmask |= ARES_OPT_SERVERS;
        self.servers_changed();
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
    /// bracketed); None when the server id is stale.
    pub fn server_state_string(&self, server: ServerId, is_tcp: bool) -> Option<String> {
        let (ip, port) = self.config.nameservers.get(server.0)?;
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

    fn spec(last: u8) -> ServerSpec {
        ServerSpec { ip: IpAddr::from([10, 0, 0, last]), udp_port: None, tcp_port: None }
    }

    /// Endpoints are resolved once per change and shared by lookup copies.
    #[test]
    fn endpoints_resolved_per_server_change_and_shared() {
        let mut client = AsyncClient::build(SysConfig::default(), noop_factory(), 53, 53);
        client.set_servers(vec![spec(1)]);
        let copy = client.derive();
        assert!(Rc::ptr_eq(&copy.endpoints, &client.endpoints), "derive shares, not recomputes");
        assert_eq!(client.endpoints[0].udp_addr, SocketAddr::from(([10, 0, 0, 1], 53)));

        client.set_servers(vec![spec(2)]);
        assert_eq!(client.endpoints[0].udp_addr, SocketAddr::from(([10, 0, 0, 2], 53)));
        assert_eq!(copy.endpoints[0].udp_addr, SocketAddr::from(([10, 0, 0, 1], 53)), "copies keep theirs");

        client.default_udp_port = 5353;
        client.servers_changed();
        assert_eq!(client.endpoints[0].udp_addr, SocketAddr::from(([10, 0, 0, 2], 5353)));
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
