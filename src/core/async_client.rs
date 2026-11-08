//! `AsyncClient` is both the ffi channel state and the resolver client; every
//! lookup runs on a [`AsyncClient::derive`]d copy (same runtime handle, shared
//! `Rc`s for cache/health/pools/effects/qids, endpoints snapshotted).
//!
//! This file holds the struct, `derive`, the shared result/effect types and the
//! hosts-file helpers. The rest lives in child modules (which see the private
//! fields through `use super::*`):
//! - `config`   — construction, `ares_reinit`, defaults, `ares_dup`, the
//!   `ares_options` mapping, server-list exports;
//! - `packet`   — query packet builders, EDNS, qid reservation;
//! - `lookups`  — `query_raw`, `gethostbyaddr`, `getnameinfo`, `search*`;
//! - `addrinfo` — `gethostbyname` / `getaddrinfo` over `resolve_addrinfo`;
//! - `request`  — the single-query engine, failover probes, transport helpers.

mod addrinfo;
mod config;
mod lookups;
mod packet;
mod request;

pub(crate) use addrinfo::*;
pub(crate) use config::*;
pub(crate) use lookups::*;
pub(crate) use packet::*;
pub(crate) use request::{Probe, ServerEndpoint};

use std::cell::{Cell, RefCell};
use std::ffi::{c_int, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::task::Poll;
use std::rc::Rc;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use futures_util::{select_biased, FutureExt};
use rand::Rng;

use crate::core::cache::{CacheKey, QueryCache};
use crate::core::conn::Conn;
use crate::core::tcp_pool::{TcpConn, TcpPool};
use crate::core::udp_pool::{UdpConn, UdpPool};
use crate::async_runtime::reactor::Runtime;
use crate::core::hostent::Hostent;
use crate::core::hostfile::{AddressFamily, HostLookup, Hosts};
use crate::core::lookup::{
    is_localhost, is_onion_domain, on_datagram, on_timeout, qid_matches,
    summarize, ReactorAction, ReplyPolicy, SearchPlan, ServerHealth, TaskVerdict,
    TimeoutVerdict, AF_INET, AF_INET6, RTYPE_A, RTYPE_AAAA,
};
use crate::core::dns_record::{ares_dns_record_t, class_isvalid, parse_record, rec_type_isvalid, write_record};
use crate::core::edns::{self, CookieVerdict, EDNS_PACKETSZ, ServerCookie};
use crate::core::packets::AddrRecord;
use crate::core::nameinfo::{assemble_nameinfo, format_ip_with_scope, get_service_string, AddrInfo, NameinfoReply};
use crate::core::qid::{QidLease, QidRegistry, ReservedQuery};
use crate::core::response::{addr_reply, push_synthetic_ptr, CnameEntry, ParsedRRs, ReplyRequire};
use crate::core::services::Services;
use crate::async_runtime::socket::SocketFactory;
use crate::core::sortlist::{parse_sortlist, sort_addrinfo, SortlistEntry};
use crate::core::sysconfig::SysConfig;
use crate::core::AresError;
use crate::ffi::dns_record::ARES_CLASS_IN;
use crate::ffi::ares_options::{
    ARES_FLAG_DNS0x20, ARES_FLAG_EDNS, ARES_FLAG_IGNTC, ARES_FLAG_NO_DFLT_SVR, ARES_FLAG_NOALIASES,
    ARES_FLAG_NOCHECKRESP, ARES_FLAG_NORECURSE, ARES_FLAG_NOSEARCH, ARES_FLAG_PRIMARY,
    ARES_FLAG_STAYOPEN, ARES_FLAG_USEVC, ARES_OPT_DOMAINS, ARES_OPT_EDNSPSZ,
    ARES_OPT_EVENT_THREAD, ARES_OPT_FLAGS,
    ARES_OPT_HOSTS_FILE, ARES_OPT_LOOKUPS, ARES_OPT_MAXTIMEOUTMS, ARES_OPT_NDOTS,
    ARES_OPT_NOROTATE, ARES_OPT_QUERY_CACHE, ARES_OPT_RESOLVCONF, ARES_OPT_ROTATE,
    ARES_OPT_SERVERS, ARES_OPT_SERVER_FAILOVER, ARES_OPT_SOCK_RCVBUF,
    ARES_OPT_SOCK_SNDBUF, ARES_OPT_SORTLIST, ARES_OPT_TCP_PORT,
    ARES_OPT_TIMEOUT, ARES_OPT_TIMEOUTMS, ARES_OPT_TRIES,
    ARES_OPT_UDP_MAX_QUERIES, ARES_OPT_UDP_PORT,
};
use crate::ffi::error::{
    ARES_ECONNREFUSED, ARES_EBADFLAGS, ARES_EBADNAME, ARES_EBADQUERY, ARES_EFILE,
    ARES_EFORMERR, ARES_ENODATA, ARES_ENOMEM, ARES_ENOSERVER, ARES_ENOTFOUND, ARES_ENOTIMP, ARES_EREFUSED,
    ARES_ESERVFAIL, ARES_ETIMEOUT,
};
use crate::ffi::{
    ARES_NI_LOOKUPHOST, ARES_NI_LOOKUPSERVICE, ARES_NI_NAMEREQD,
    ARES_NI_NUMERICHOST, ARES_SUCCESS, RECORD_TYPE_PTR,
};

/// THE channel: the state the ffi `ChannelData` wraps, and the resolver client
/// the async lifecycles run on. Each lookup uses a `derive`d copy (shared `Rc`s
/// and the same runtime handle).
pub(crate) struct AsyncClient {
    pub config: SysConfig,
    /// The channel's runtime handle (reactor + socket factory); every lookup
    /// copy shares it.
    pub rt: Runtime,
    /// Lazily loaded `/etc/hosts`; always `Some` on a lookup copy.
    hosts: Option<Rc<Hosts>>,
    pub default_udp_port: u16,
    pub default_tcp_port: u16,
    pub socket_send_buffer_size: i32,
    pub socket_receive_buffer_size: i32,
    pub local_ip4: u32,
    pub local_ip6: [u8; 16],
    pub local_dev: String,
    /// Shared with in-flight lookups so failover accounting and probes agree.
    pub health: Rc<RefCell<ServerHealth>>,
    pub sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    /// `ARES_OPT_EDNSPSZ` kept full-width until query construction, where
    /// values above 65535 are rejected with `ARES_EFORMERR`.
    pub ednspsz: i32,
    /// Per-server DNS cookie state, shared across lookups; reset by `duplicate`.
    pub cookies: Rc<RefCell<Vec<ServerCookie>>>,
    pub maxtimeout: i32,
    /// Option mask the channel was initialized with; `ares_reinit` preserves
    /// explicitly-set values.
    pub optmask: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    pub cache: Rc<RefCell<QueryCache>>,
    /// Shared TCP sockets (parallel lookups to one server share a connection).
    pub tcp_pool: Rc<RefCell<TcpPool>>,
    /// Shared UDP sockets (parallel lookups to one server share a socket, split
    /// across several once [`udp_max_queries`](Self::udp_max_queries) is reached).
    pub udp_pool: Rc<RefCell<UdpPool>>,
    /// `ARES_OPT_UDP_MAX_QUERIES`: max in-flight queries per UDP socket; 0 =
    /// unlimited (upstream default).
    pub udp_max_queries: usize,
    /// Per-server endpoints snapshotted by `derive` so lookup futures never
    /// re-read the config.
    pub endpoints: Rc<Vec<ServerEndpoint>>,
    pub server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub server_failover_retry_delay: u64,  // milliseconds
    /// Server-state notifications raised by in-flight lookups, drained by the
    /// host after each task poll (shared by every lookup copy).
    pub effects: Rc<RefCell<Vec<Effect>>>,
    /// The channel's in-flight transaction ids (shared by every lookup copy).
    pub qids: Rc<RefCell<QidRegistry>>,
}

impl AsyncClient {
    /// Mint the per-lookup copy every entry shim runs on: clone config and
    /// shared `Rc`s, and snapshot endpoints.
    pub(crate) fn derive(&mut self) -> Self {
        let hosts = self.hosts();
        AsyncClient {
            config: self.config.clone(),
            rt: self.rt.clone(),
            hosts: Some(hosts),
            default_udp_port: self.default_udp_port,
            default_tcp_port: self.default_tcp_port,
            socket_send_buffer_size: self.socket_send_buffer_size,
            socket_receive_buffer_size: self.socket_receive_buffer_size,
            local_ip4: self.local_ip4,
            local_ip6: self.local_ip6,
            local_dev: self.local_dev.clone(),
            health: self.health.clone(),
            sortlist: self.sortlist.clone(),
            flags: self.flags,
            ednspsz: self.ednspsz,
            cookies: self.cookies.clone(),
            maxtimeout: self.maxtimeout,
            optmask: self.optmask,
            lookups: self.lookups.clone(),
            resolvconf_path: self.resolvconf_path.clone(),
            hosts_path: self.hosts_path.clone(),
            cache: self.cache.clone(),
            tcp_pool: self.tcp_pool.clone(),
            udp_pool: self.udp_pool.clone(),
            udp_max_queries: self.udp_max_queries,
            endpoints: Rc::new(self.endpoint_snapshot()),
            server_failover_retry_chance: self.server_failover_retry_chance,
            server_failover_retry_delay: self.server_failover_retry_delay,
            effects: self.effects.clone(),
            qids: self.qids.clone(),
        }
    }

    /// The hosts table; empty only on the channel-owned instance before first use.
    fn hostsfile(&self) -> Rc<Hosts> {
        self.hosts.clone().unwrap_or_default()
    }

    /// Hosts lookup honouring ARES_AI_ENVHOSTS (`CARES_HOSTS`); HOSTALIASES
    /// remains on the legacy alias path.
    fn hosts_lookup(
        &self,
        name: &str,
        family: AddressFamily,
        use_env: bool,
    ) -> Option<HostLookup> {
        if use_env {
            if let Ok(path) = std::env::var("CARES_HOSTS") {
                return Hosts::from_path(path).ok().and_then(|h| h.lookup(name, family));
            }
        }
        self.hostsfile().lookup(name, family)
    }

    /// ares_gethostbyname_file: a synchronous hosts-file-only lookup.
    pub(crate) fn gethostbyname_file(&mut self, name: &str, family: i32) -> Result<Hostent, AresError> {
        hosts_file_lookup(self, name, family).map(Hostent::from_lookup)
    }

    /// ARES_FLAG_NORECURSE clears the RD bit in constructed queries.
    pub(crate) fn recursion_desired(&self) -> bool {
        self.flags & ARES_FLAG_NORECURSE == 0
    }

    /// Queue server-state notifications for the ffi to fire after this poll.
    fn notify(&self, actions: Vec<ReactorAction>) {
        let mut effects = self.effects.borrow_mut();
        for a in actions {
            match a {
                ReactorAction::NotifyServerState { server, ok, tcp } => {
                    effects.push(Effect::NotifyServerState { server, ok, tcp })
                }
            }
        }
    }
}

/// A fire-and-forget side effect the ffi applies after a poll.
pub(crate) enum Effect {
    NotifyServerState { server: usize, ok: bool, tcp: bool },
    /// Spawn this failover probe as its own task (no callback), so the lookup
    /// that raised it never waits for it.
    Probe(Probe),
}

/// A hostent lifecycle's result plus its timeout count, for `ares_host_callback`.
pub(crate) type HostReply = (Result<Hostent, AresError>, c_int);

/// What the raw (ares_query / ares_send) lifecycle delivers to C.
pub(crate) enum Delivery {
    Raw { result: Result<Vec<u8>, c_int>, timeouts: c_int },
}

fn hosts_file_lookup(st: &mut AsyncClient, name: &str, family: i32) -> Result<HostLookup, AresError> {
    let family_filter = AddressFamily::from_af(family).ok_or(ARES_ENOTFOUND)?;

    let lookup = st.hosts().lookup(name, family_filter).ok_or(ARES_ENOTFOUND)?;
    if lookup.addrs.is_empty() {
        return Err(ARES_ENOTFOUND.into());
    }
    Ok(lookup)
}

fn no_servers(st: &AsyncClient) -> bool {
    st.config.nameservers.is_empty()
}

/// One `request()`'s result plus its timed-out attempt count.
type QueryOutcome = (Result<Vec<u8>, c_int>, c_int);
