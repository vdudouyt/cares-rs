//! Channel-lifecycle kernels for ffi/channel.rs shims.

use crate::core::ares::Ares;
use crate::core::lookup::ServerHealth;
use crate::ffi::channel::ChannelData;

/// The pure body of ares_dup: clone configuration and callbacks, start with
/// a fresh reactor state (empty query cache, no pooled connections, cleared
/// failure timestamps).
pub(crate) fn dup_channel(src: &ChannelData) -> ChannelData {
    let mut ares = Ares::new(src.ares.config.clone());
    ares.socket_factory = src.ares.socket_factory.clone();
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
