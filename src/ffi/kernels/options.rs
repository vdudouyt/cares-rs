//! The pure bodies of ares_init/ares_init_options/ares_save_options: fresh
//! channel construction, the optmask→config cascade, and its inverse. The
//! shims in ffi/ares_options.rs decode all raw pointers up front into
//! `DecodedOptions` and emit `SavedOptions` back through malloc'd C fields.

use std::ffi::{c_int, c_uint, c_ushort, CString};
use std::net::{IpAddr, Ipv4Addr};

use crate::core::ares::Ares;
use crate::core::lookup::ServerHealth;
use crate::ffi::ares_options::{
    ARES_FLAG_EDNS, ARES_FLAG_PRIMARY, ARES_FLAG_USEVC, ARES_OPT_DOMAINS, ARES_OPT_FLAGS,
    ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS,
    ARES_OPT_NOROTATE, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF, ARES_OPT_ROTATE,
    ARES_OPT_SERVERS, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SORTLIST, ARES_OPT_TCP_PORT,
    ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES, ARES_OPT_UDP_MAX_QUERIES,
    ARES_OPT_UDP_PORT,
};
use crate::ffi::channel::ChannelData;
use crate::ffi::lookups::FFIData;

/// A fully-owned mirror of the caller's `ares_options`, decoded by the shim
/// before any logic runs. `None`/empty encode the NULL-pointer cases so the
/// cascade below can reproduce the exact per-field guards.
pub(crate) struct DecodedOptions {
    pub flags: c_int,
    pub timeout: c_int,
    pub tries: c_int,
    pub ndots: c_int,
    pub udp_port: c_ushort,
    pub tcp_port: c_ushort,
    /// Decoded OPT_SERVERS list. Empty when the C pointer was NULL — the
    /// mask bit alone still clears the sysconfig servers.
    pub servers: Vec<Ipv4Addr>,
    /// None when the C pointer was NULL: the bit is then ignored entirely.
    pub domains: Option<Vec<String>>,
    pub lookups: Option<String>,
    pub resolvconf_path: Option<String>,
    pub hosts_path: Option<String>,
    pub udp_max_queries: c_int,
    pub maxtimeout: c_int,
    pub qcache_max_ttl: c_uint,
    pub failover_retry_chance: c_ushort,
    pub failover_retry_delay: u64,
}

/// A fresh channel around `ares` — shared by ares_init and ares_init_options.
pub(crate) fn new_channel_data(ares: Ares<FFIData>) -> ChannelData {
    ChannelData {
        ares,
        sock_create_callback: None,
        sock_create_callback_arg: std::ptr::null_mut(),
        sock_config_callback: None,
        sock_config_callback_arg: std::ptr::null_mut(),
        server_state_callback: None,
        server_state_callback_arg: std::ptr::null_mut(),
        readbuf: vec![0u8; 65_535],
        server_health: ServerHealth::default(),
        sortlist: vec![],
        flags: 0,
        maxtimeout: 0,
        lookups: String::new(),
        resolvconf_path: String::new(),
        hosts_path: String::new(),
        query_cache: std::collections::HashMap::new(),
        query_cache_max_ttl: 0,
        udp_max_queries: 0,
        udp_connections: vec![],
        tcp_connections: vec![],
        tcp_recv_buffers: std::collections::HashMap::new(),
        server_failover_retry_chance: 0,
        server_failover_retry_delay: 0,
    }
}

/// The optmask cascade from ares_init_options — order preserved bit for bit,
/// ending with the unconditional server-health reset.
pub(crate) fn apply_options(channeldata: &mut ChannelData, optmask: c_int, o: DecodedOptions) {
    if optmask & ARES_OPT_SERVERS != 0 {
        // Clear sysconfig servers when user explicitly provides servers
        channeldata.ares.config.nameservers.clear();
        channeldata.ares.config.tcp_ports.clear();
        for v4 in &o.servers {
            channeldata.ares.config.nameservers.push((IpAddr::V4(*v4), None));
            channeldata.ares.config.tcp_ports.push(None);
        }
    }
    if optmask & ARES_OPT_UDP_PORT != 0 {
        channeldata.ares.default_udp_port = o.udp_port;
    }
    if optmask & ARES_OPT_TCP_PORT != 0 {
        channeldata.ares.default_tcp_port = o.tcp_port;
    }
    if optmask & ARES_OPT_TIMEOUTMS != 0 {
        channeldata.ares.config.options.timeout_ms = std::cmp::max(1, o.timeout as u32);
    }
    if optmask & ARES_OPT_TIMEOUT != 0 {
        channeldata.ares.config.options.timeout_ms = o.timeout as u32 * 1000;
    }
    if optmask & ARES_OPT_TRIES != 0 {
        channeldata.ares.config.options.attempts = o.tries as u32;
    }
    if optmask & ARES_OPT_NDOTS != 0 {
        channeldata.ares.config.options.ndots = o.ndots as u32;
    }
    if optmask & ARES_OPT_FLAGS != 0 {
        channeldata.flags = o.flags;
        channeldata.ares.config.options.use_vc = (o.flags & ARES_FLAG_USEVC) != 0;
        channeldata.ares.config.options.edns0 = (o.flags & ARES_FLAG_EDNS) != 0;
        // ARES_FLAG_PRIMARY: truncate to first server only
        if (o.flags & ARES_FLAG_PRIMARY) != 0 {
            channeldata.ares.config.nameservers.truncate(1);
            channeldata.ares.config.tcp_ports.truncate(1);
        }
    }
    if optmask & ARES_OPT_DOMAINS != 0 {
        if let Some(domains) = o.domains {
            channeldata.ares.config.search = domains;
        }
    }
    if optmask & ARES_OPT_NOROTATE != 0 {
        channeldata.ares.config.options.rotate = false;
    }
    if optmask & ARES_OPT_ROTATE != 0 {
        channeldata.ares.config.options.rotate = true;
    }
    if optmask & ARES_OPT_MAXTIMEOUTMS != 0 {
        channeldata.maxtimeout = o.maxtimeout;
    }
    if optmask & ARES_OPT_LOOKUPS != 0 {
        if let Some(lookups) = o.lookups {
            channeldata.lookups = lookups;
        }
    }
    if optmask & ARES_OPT_RESOLVCONF != 0 {
        if let Some(path) = o.resolvconf_path {
            channeldata.resolvconf_path = path;
        }
    }
    if optmask & ARES_OPT_HOSTS_FILE != 0 {
        if let Some(path) = o.hosts_path {
            channeldata.hosts_path = path;
        }
    }
    if optmask & ARES_OPT_QUERY_CACHE != 0 {
        channeldata.query_cache_max_ttl = o.qcache_max_ttl;
    }
    if optmask & ARES_OPT_UDP_MAX_QUERIES != 0 {
        channeldata.udp_max_queries = o.udp_max_queries as u32;
    }
    if optmask & ARES_OPT_SERVER_FAILOVER != 0 {
        channeldata.server_failover_retry_chance = o.failover_retry_chance;
        channeldata.server_failover_retry_delay = o.failover_retry_delay;
    }
    channeldata.server_health.reset(channeldata.ares.config.nameservers.len());
}

/// Everything ares_save_options reports, precomputed. `base_mask` carries all
/// bits except SERVERS/DOMAINS, whose emission depends on libc::malloc
/// succeeding — the shim adds those two after the copies land.
pub(crate) struct SavedOptions {
    pub flags: c_int,
    pub timeout: c_int,
    pub tries: c_int,
    pub ndots: c_int,
    pub udp_port: c_ushort,
    pub tcp_port: c_ushort,
    pub v4_servers: Vec<libc::in_addr>,
    pub domains: Vec<CString>,
    pub maxtimeout: Option<c_int>,
    pub lookups: Option<CString>,
    pub resolvconf_path: Option<CString>,
    pub hosts_path: Option<CString>,
    pub base_mask: c_int,
}

/// The pure inverse of the cascade: read the channel back into option fields.
pub(crate) fn saved_options(channeldata: &ChannelData) -> SavedOptions {
    let config = &channeldata.ares.config;
    let opts = &config.options;

    let mut base_mask = ARES_OPT_FLAGS
        | ARES_OPT_TIMEOUTMS
        | ARES_OPT_TRIES
        | ARES_OPT_NDOTS
        | ARES_OPT_UDP_PORT
        | ARES_OPT_TCP_PORT;
    base_mask |= if opts.rotate { ARES_OPT_ROTATE } else { ARES_OPT_NOROTATE };
    if !channeldata.sortlist.is_empty() {
        base_mask |= ARES_OPT_SORTLIST;
    }

    // servers (IPv4 only in ares_options)
    let v4_servers: Vec<libc::in_addr> = config
        .nameservers
        .iter()
        .filter_map(|(ip, _)| match ip {
            IpAddr::V4(v4) => Some(libc::in_addr { s_addr: u32::from(*v4).to_be() }),
            _ => None,
        })
        .collect();

    let domains: Vec<CString> = config
        .search
        .iter()
        .map(|domain| CString::new(domain.as_str()).unwrap_or_default())
        .collect();

    let maxtimeout = (channeldata.maxtimeout != 0).then_some(channeldata.maxtimeout);
    if maxtimeout.is_some() {
        base_mask |= ARES_OPT_MAXTIMEOUTMS;
    }
    let lookups = (!channeldata.lookups.is_empty())
        .then(|| CString::new(channeldata.lookups.as_str()).unwrap_or_default());
    if lookups.is_some() {
        base_mask |= ARES_OPT_LOOKUPS;
    }
    let resolvconf_path = (!channeldata.resolvconf_path.is_empty())
        .then(|| CString::new(channeldata.resolvconf_path.as_str()).unwrap_or_default());
    if resolvconf_path.is_some() {
        base_mask |= ARES_OPT_RESOLVCONF;
    }
    let hosts_path = (!channeldata.hosts_path.is_empty())
        .then(|| CString::new(channeldata.hosts_path.as_str()).unwrap_or_default());
    if hosts_path.is_some() {
        base_mask |= ARES_OPT_HOSTS_FILE;
    }

    SavedOptions {
        flags: channeldata.flags,
        timeout: opts.timeout_ms as c_int,
        tries: opts.attempts as c_int,
        ndots: opts.ndots as c_int,
        udp_port: channeldata.ares.default_udp_port,
        tcp_port: channeldata.ares.default_tcp_port,
        v4_servers,
        domains,
        maxtimeout,
        lookups,
        resolvconf_path,
        hosts_path,
        base_mask,
    }
}
