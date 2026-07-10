use std::net::IpAddr;
use std::rc::Rc;

use crate::core::hostfile::Hosts;
use crate::async_runtime::socket::SocketFactory;
use crate::core::sysconfig::SysConfig;

/// The channel's config + socket factory. The async lifecycles snapshot the
/// per-server connect endpoints (`Client::endpoint_snapshot`) and own their own
/// sockets, so this holds no in-flight state.
pub struct Transport {
    pub config: SysConfig,
    pub socket_factory: Rc<dyn SocketFactory>,
    hosts: Option<Rc<Hosts>>,
    pub default_udp_port: u16,
    pub default_tcp_port: u16,
}

impl Transport {
    pub fn new(config: SysConfig, socket_factory: Rc<dyn SocketFactory>) -> Self {
        Transport { config, socket_factory, hosts: None, default_udp_port: 53, default_tcp_port: 53 }
    }
    pub fn from_sysconfig(socket_factory: Rc<dyn SocketFactory>) -> Self {
        Transport::new(build_sysconfig(), socket_factory)
    }
    /// The `/etc/hosts` table as a shared `Rc` (lazily loaded once), so the ffi
    /// can hand a clone to the async lifecycles.
    pub fn hosts(&mut self) -> Rc<Hosts> {
        self.hosts.get_or_insert_with(|| Rc::new(Hosts::from_path("/etc/hosts").unwrap_or_default())).clone()
    }
}

/// The reverse-DNS (PTR) query name for an address.
pub fn rdns_name(ip: IpAddr) -> String {
    match ip {
        // decimal
        IpAddr::V4(v4) => v4.octets().into_iter().rev().map(|b| b.to_string())
            .collect::<Vec<_>>().join(".") + ".in-addr.arpa",
        // hex (low nibble first)
        IpAddr::V6(v6) => v6.octets().into_iter().flat_map(|b| [b >> 4, b & 0x0f]).map(|n| format!("{:x}", n))
            .collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".") + ".ip6.arpa",
    }
}

pub fn build_sysconfig() -> SysConfig {
    let try_resolv_conf = || std::fs::read_to_string("/etc/resolv.conf").ok()?.parse::<SysConfig>().ok();
    let mut config = try_resolv_conf().unwrap_or_else(SysConfig::default);
    crate::core::sysconfig::apply_env_overrides(&mut config);
    config
}
