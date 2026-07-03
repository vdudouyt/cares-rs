//! Channel-lifecycle and server-configuration kernels for ffi/channel.rs
//! shims: duplication, server-list install/report, reactor fd/timeout
//! reporting. The shims keep only the C linked-list walks, fd_set macros,
//! union construction, and out-pointer writes.

use std::ffi::c_int;
use std::net::IpAddr;

use crate::core::ares::{Ares, Status};
use crate::core::lookup::ServerHealth;
use crate::ffi::channel::ChannelData;

/// The pure body of ares_dup: clone configuration and callbacks, start with
/// a fresh reactor state (empty query cache, no pooled connections, cleared
/// failure timestamps).
pub(crate) fn dup_channel(src: &ChannelData) -> ChannelData {
    let mut ares = Ares::new(src.ares.config.clone(), src.ares.socket_factory.clone());
    ares.default_udp_port = src.ares.default_udp_port;
    ares.default_tcp_port = src.ares.default_tcp_port;
    ChannelData {
        ares,
        sock_create_callback: src.sock_create_callback,
        sock_create_callback_arg: src.sock_create_callback_arg,
        sock_config_callback: src.sock_config_callback,
        sock_config_callback_arg: src.sock_config_callback_arg,
        server_state_callback: src.server_state_callback,
        server_state_callback_arg: src.server_state_callback_arg,
        readbuf: vec![0u8; 65_535],
        server_health: ServerHealth {
            failures: src.server_health.failures.clone(),
            last_failure: vec![None; src.server_health.last_failure.len()],
        },
        sortlist: src.sortlist.clone(),
        flags: src.flags,
        maxtimeout: src.maxtimeout,
        lookups: src.lookups.clone(),
        resolvconf_path: src.resolvconf_path.clone(),
        hosts_path: src.hosts_path.clone(),
        query_cache: std::collections::HashMap::new(),
        query_cache_max_ttl: src.query_cache_max_ttl,
        udp_max_queries: src.udp_max_queries,
        udp_connections: vec![],
        tcp_connections: vec![],
        tcp_recv_buffers: std::collections::HashMap::new(),
        server_failover_retry_chance: src.server_failover_retry_chance,
        server_failover_retry_delay: src.server_failover_retry_delay,
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

/// Install a decoded server list (ares_set_servers / ares_set_servers_ports).
pub(crate) fn set_servers(channeldata: &mut ChannelData, servers: Vec<ServerSpec>) {
    channeldata.ares.config.nameservers.clear();
    channeldata.ares.config.tcp_ports.clear();
    for server in servers {
        channeldata.ares.config.nameservers.push((server.ip, server.udp_port));
        channeldata.ares.config.tcp_ports.push(server.tcp_port);
    }
    channeldata.server_health.reset(channeldata.ares.config.nameservers.len());
}

/// NULL/empty CSV clears every configured server (ares_set_servers*_csv).
pub(crate) fn clear_servers(channeldata: &mut ChannelData) {
    channeldata.ares.config.nameservers.clear();
    channeldata.ares.config.tcp_ports.clear();
    channeldata.server_health.clear();
}

/// Install a parsed CSV server list (ares_set_servers_ports_csv).
pub(crate) fn install_csv_servers(channeldata: &mut ChannelData, ns: Vec<(IpAddr, Option<u16>)>) {
    channeldata.ares.config.tcp_ports = vec![None; ns.len()];
    channeldata.server_health.reset(ns.len());
    channeldata.ares.config.nameservers = ns;
}

/// The configured servers with per-entry defaults applied, in order:
/// (ip, udp_port, tcp_port) — the report behind ares_get_servers[_ports].
pub(crate) fn server_list(channeldata: &ChannelData) -> Vec<(IpAddr, u16, u16)> {
    channeldata
        .ares
        .config
        .nameservers
        .iter()
        .map(|(ip, port)| {
            (
                *ip,
                port.unwrap_or(channeldata.ares.default_udp_port),
                port.unwrap_or(channeldata.ares.default_tcp_port),
            )
        })
        .collect()
}

/// The `ip:port` CSV report behind ares_get_servers_csv (IPv6 bracketed).
pub(crate) fn servers_csv_string(channeldata: &ChannelData) -> String {
    let default_port = channeldata.ares.default_udp_port;
    channeldata
        .ares
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
pub(crate) fn poll_fds(channeldata: &ChannelData) -> Vec<(i32, bool)> {
    channeldata
        .ares
        .tasks
        .iter()
        .filter_map(|task| match task.status {
            Status::Writing => Some((task.sock.as_raw_fd(), true)),
            Status::Reading => Some((task.sock.as_raw_fd(), false)),
            Status::Completed => None,
        })
        .collect()
}

/// ares_getsock's bitmask: bit i = slot readable, bit i+16 = slot writable.
pub(crate) fn getsock_mask(fds: &[(i32, bool)], slots: usize) -> c_int {
    let mut mask: c_int = 0;
    for (i, (_, writing)) in fds.iter().take(slots).enumerate() {
        if *writing {
            mask |= 1 << (i + 16); // writable
        }
        mask |= 1 << i; // readable
    }
    mask
}

/// The pending-query wait budget in milliseconds; None when no tasks are
/// pending (ares_timeout then reports maxtv/NULL).
pub(crate) fn timeout_millis(channeldata: &ChannelData) -> Option<u128> {
    if channeldata.ares.tasks.is_empty() {
        return None;
    }
    Some(channeldata.ares.max_wait_time().as_millis())
}

/// Non-completed task count (ares_queue_active_queries).
pub(crate) fn active_query_count(channeldata: &ChannelData) -> usize {
    channeldata
        .ares
        .tasks
        .iter()
        .filter(|t| t.status != Status::Completed)
        .count()
}
