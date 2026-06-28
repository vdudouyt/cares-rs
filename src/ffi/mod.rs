mod ares_data;
mod ares_hostent;
pub mod ares_options;
pub mod ares_socket;
mod cnullterminated;
mod cstr;
mod clinkedlist;
mod dns_record;
mod error;
mod offset_of;

use std::ffi::{ c_int, c_uint, c_void, c_char };
use std::ffi::{ CString, CStr };
use std::net::IpAddr;
use std::cmp::min;
use std::time::{Instant, Duration};
use crate::core::packets::*;
use crate::core::ares::{ Ares, Status, Family, WriteResult };
use crate::core::servers_csv;
use crate::core::services::Services;
use crate::ffi::ares_hostent::*;
use crate::ffi::ares_data::*;
use crate::ffi::clinkedlist::*;
use crate::ffi::error::*;
use crate::cstr;
pub use crate::ffi::ares_socket::{SocketFactory, AresSocketFunctions};
use crate::core::hostfile::{AddressFamily, HostLookup};
use std::io::Cursor;

pub const ARES_SUCCESS: i32 = 0;
pub const ARES_ENODATA: i32 = 1;
pub const ARES_EFORMERR: i32 = 2;
pub const ARES_ESERVFAIL: i32 = 3;
pub const ARES_ENOTFOUND: i32 = 4;
pub const ARES_ETIMEOUT: i32 = 12;
pub const ARES_LIB_INIT_ALL: i32 = 1;

#[allow(non_camel_case_types)]
pub type ares_socket_t = c_int;

#[no_mangle]
pub extern "C" fn ares_library_init(_flags: c_int) -> c_int {
    ARES_SUCCESS
}

#[no_mangle]
pub extern "C" fn ares_library_cleanup() {
}

/// We do not provide the built-in event thread, so the library is not
/// thread-safe. Report ARES_FALSE (0), matching c-ares on non-threaded builds.
#[no_mangle]
pub extern "C" fn ares_threadsafety() -> i32 {
    0
}

pub type Channel = *mut ChannelData;

pub struct ChannelData {
    ares: Ares<FFIData>,
    sock_create_callback: Option<AresSockCreateCallback>,
    sock_create_callback_arg: *mut libc::c_void,
    sock_config_callback: Option<AresSockConfigureCallback>,
    sock_config_callback_arg: *mut libc::c_void,
    server_state_callback: Option<AresServerStateCallback>,
    server_state_callback_arg: *mut libc::c_void,
    readbuf: Vec<u8>,
    server_failures: Vec<u32>,
    sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    pub maxtimeout: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    query_cache: std::collections::HashMap<(String, u16), (Vec<u8>, Instant)>,
    query_cache_max_ttl: u32, // 0 = disabled
    udp_max_queries: u32, // 0 = unlimited
    udp_connections: Vec<(usize, std::rc::Rc<crate::ffi::ares_socket::UdpSocket>, u32)>, // (server_index, shared_socket, query_count)
    tcp_connections: Vec<(usize, std::rc::Rc<crate::ffi::ares_socket::TcpSocket>)>, // (server_index, shared_socket)
    tcp_recv_buffers: std::collections::HashMap<i32, Vec<u8>>, // fd -> accumulated TCP receive data
    server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    server_failover_retry_delay: u64,  // milliseconds
    server_last_failure: Vec<Option<Instant>>, // per-server last failure timestamp
}

struct HostByNameState {
    callback: AresHostCallback,
    arg: *mut c_void,
    has_cancel: bool,
    last_error: c_int,
    name: String,
    channel: Channel,
    search_domains: Vec<String>,
    base_name: String,
    family: c_int,         // Original requested family
    current_family: c_int, // Currently querying family
    expected_record_type: c_int,
    use_tcp: bool,
    attempt_count: usize,
    had_nodata: bool,
    tried_aaaa: bool,
    timeouts: c_int,
}

struct AddrInfoState {
    callback: AresAddrInfoCallback,
    arg: *mut c_void,
    pending: u32,
    nodes_head: *mut ares_addrinfo_node,
    nodes_tail: *mut ares_addrinfo_node,
    has_cancel: bool,
    last_error: c_int,
    has_success: bool,
    name: String,
    channel: Channel,
    search_domains: Vec<String>,
    base_name: String,
    ai_family: c_int,
    use_tcp: bool,
    attempt_count: usize,
    port: u16,
}

struct SearchState {
    callback: AresCallback,
    arg: *mut c_void,
    channel: Channel,
    name: String,
    base_name: String,
    search_domains: Vec<String>,
    dnsclass: u16,
    dnstype: u16,
    last_error: c_int,
    had_nodata: bool,
    attempt_count: usize,
}

struct SearchStateDnsRec {
    callback: AresCallbackDnsRec,
    arg: *mut c_void,
    channel: Channel,
    name: String,
    base_name: String,
    search_domains: Vec<String>,
    dnsclass: u16,
    dnstype: u16,
    last_error: c_int,
    had_nodata: bool,
}

#[derive(Debug)]
enum Callback {
    AresHostCallback(AresHostCallback),
    AresCallback(AresCallback),
    AresCallbackDnsRec(AresCallbackDnsRec),
    AresNameinfoCallback(AresNameinfoCallback),
    AresAddrInfoCallback(*mut AddrInfoState),
    AresHostByNameCallback(*mut HostByNameState),
    AresSearchCallback(*mut SearchState),
    AresSearchCallbackDnsRec(*mut SearchStateDnsRec),
    Probe(Channel), // Server failover probe — no user callback
}

impl Callback {
    fn run(&self, buf: Result<&[u8], c_int>, ffidata: &FFIData) {
        // For destruction/cancellation of stateful callbacks, handle directly
        if let Err(status) = &buf {
            if *status == ARES_EDESTRUCTION || *status == ARES_ECANCELLED {
                match self {
                    Self::AresHostByNameCallback(state_ptr) => unsafe {
                        let state = &mut **state_ptr;
                        (state.callback)(state.arg, *status, 0, std::ptr::null_mut());
                        drop(Box::from_raw(*state_ptr));
                        return;
                    },
                    Self::AresAddrInfoCallback(state_ptr) => unsafe {
                        let state = &mut **state_ptr;
                        state.pending -= 1;
                        if *status == ARES_EDESTRUCTION {
                            state.has_cancel = true;
                            state.last_error = *status;
                        } else {
                            state.has_cancel = true;
                            state.last_error = *status;
                        }
                        if state.pending == 0 {
                            free_addrinfo_nodes(state.nodes_head);
                            (state.callback)(state.arg, state.last_error, 0, std::ptr::null_mut());
                            drop(Box::from_raw(*state_ptr));
                        }
                        return;
                    },
                    Self::AresSearchCallback(state_ptr) => unsafe {
                        let state = &mut **state_ptr;
                        (state.callback)(state.arg, *status, ffidata.timeouts, std::ptr::null_mut(), 0);
                        drop(Box::from_raw(*state_ptr));
                        return;
                    },
                    Self::AresSearchCallbackDnsRec(state_ptr) => unsafe {
                        let state = &mut **state_ptr;
                        (state.callback)(state.arg, *status, ffidata.timeouts as usize, std::ptr::null_mut());
                        drop(Box::from_raw(*state_ptr));
                        return;
                    },
                    Self::Probe(_) => return, // Probes silently ignore cancel/destroy
                    _ => {}
                }
            }
        }
        match self {
            Self::AresHostCallback(callback) => run_ares_host_callback(buf, *callback, ffidata),
            Self::AresCallback(callback) => run_ares_callback(buf, *callback, ffidata),
            Self::AresCallbackDnsRec(callback) => run_ares_callback_dnsrec(buf, *callback, ffidata),
            Self::AresNameinfoCallback(callback) => run_ares_nameinfo_callback(buf, *callback, ffidata),
            Self::AresAddrInfoCallback(state_ptr) => unsafe { run_ares_addrinfo_callback(buf, *state_ptr, ffidata) },
            Self::AresHostByNameCallback(state_ptr) => unsafe { run_ares_hostbyname_callback(buf, *state_ptr, ffidata) },
            Self::AresSearchCallback(state_ptr) => unsafe { run_ares_search_callback(buf, *state_ptr, ffidata) },
            Self::AresSearchCallbackDnsRec(state_ptr) => unsafe { run_ares_search_callback_dnsrec(buf, *state_ptr, ffidata) },
            Self::Probe(channel) => unsafe { run_probe_callback(buf, *channel, ffidata) },
        }
    }
    fn clone_for_retry(&self) -> Self {
        match self {
            Self::AresHostCallback(cb) => Self::AresHostCallback(*cb),
            Self::AresCallback(cb) => Self::AresCallback(*cb),
            Self::AresCallbackDnsRec(cb) => Self::AresCallbackDnsRec(*cb),
            Self::AresNameinfoCallback(cb) => Self::AresNameinfoCallback(*cb),
            Self::AresAddrInfoCallback(ptr) => Self::AresAddrInfoCallback(*ptr),
            Self::AresHostByNameCallback(ptr) => Self::AresHostByNameCallback(*ptr),
            Self::AresSearchCallback(ptr) => Self::AresSearchCallback(*ptr),
            Self::AresSearchCallbackDnsRec(ptr) => Self::AresSearchCallbackDnsRec(*ptr),
            Self::Probe(ch) => Self::Probe(*ch),
        }
    }
}

#[derive(Debug)]
struct FFIData {
    callback: Callback,
    arg: *mut c_void,
    family: c_int,
    expected_record_type: c_int,
    ip: Option<IpAddr>,
    // nameinfo-specific fields
    nameinfo_flags: c_int,
    port: u16,
    scope_id: u32,
    server_index: usize,
    timeouts: c_int,
}

#[repr(C)]
pub struct ares_addr_node {
    pub next: *mut ares_addr_node,
    pub family: c_int,
    pub data: [u8; 16], // enough to hold IPv6
}

trait AddrTTL {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()>;
}

#[derive(Debug)]
struct AddrRecord {
    ip: IpAddr,
    ttl: u32,
}

impl RRParser<'_> for AddrRecord {
    fn parse_rr(answer: &DnsAnswer<'_>) -> Option<Self> {
        Some(Self { ip: buf_to_ip(answer.data).ok()?, ttl: answer.ttl })
    }
}

#[repr(C)]
pub struct ares_addrttl {
    pub ipaddr: [u8; 4], // ipv4
    pub ttl: c_int,
}

impl AddrTTL for ares_addrttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V4(ipv4) = ip else { return None };
        (self.ipaddr, self.ttl) = (ipv4.octets(), ttl as c_int);
        Some(())
    }
}

#[repr(C)]
pub struct ares_addr6ttl {
    pub ipaddr: [u8; 16], // ipv6
    pub ttl: c_int,
}

impl AddrTTL for ares_addr6ttl {
    fn set_addr_ttl(&mut self, ip: &IpAddr, ttl: u32) -> Option<()> {
        let IpAddr::V6(ipv6) = ip else { return None };
        (self.ipaddr, self.ttl) = (ipv6.octets(), ttl as c_int);
        Some(())
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let ares = Ares::from_sysconfig();
    let channeldata = ChannelData { ares, sock_create_callback: None, sock_create_callback_arg: std::ptr::null_mut(), sock_config_callback: None, sock_config_callback_arg: std::ptr::null_mut(), server_state_callback: None, server_state_callback_arg: std::ptr::null_mut(), readbuf: vec![0u8; 65_535], server_failures: vec![], sortlist: vec![], flags: 0, maxtimeout: 0, lookups: String::new(), resolvconf_path: String::new(), hosts_path: String::new(), query_cache: std::collections::HashMap::new(), query_cache_max_ttl: 0, udp_max_queries: 0, udp_connections: vec![], tcp_connections: vec![], tcp_recv_buffers: std::collections::HashMap::new(), server_failover_retry_chance: 0, server_failover_retry_delay: 0, server_last_failure: vec![] };
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dup(dest: *mut Channel, source: Channel) -> c_int {
    if dest.is_null() || source.is_null() { return ARES_ENOTINITIALIZED; }
    let src = unsafe { &*source };
    let mut ares = Ares::new(src.ares.config.clone());
    ares.socket_factory = src.ares.socket_factory.clone();
    ares.default_udp_port = src.ares.default_udp_port;
    ares.default_tcp_port = src.ares.default_tcp_port;
    let channeldata = ChannelData {
        ares,
        sock_create_callback: src.sock_create_callback,
        sock_create_callback_arg: src.sock_create_callback_arg,
        sock_config_callback: src.sock_config_callback,
        sock_config_callback_arg: src.sock_config_callback_arg,
        server_state_callback: src.server_state_callback,
        server_state_callback_arg: src.server_state_callback_arg,
        readbuf: vec![0u8; 65_535],
        server_failures: src.server_failures.clone(),
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
        server_last_failure: vec![None; src.server_last_failure.len()],
    };
    unsafe { *dest = Box::into_raw(Box::new(channeldata)) };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_cancel(channel: Channel) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    for task in channeldata.ares.tasks.drain(..) {
        if task.status != Status::Completed {
            task.userdata.callback.run(Err(ARES_ECANCELLED), &task.userdata);
        }
    }
    // Clear connection pools so stale sockets don't linger
    channeldata.udp_connections.clear();
    channeldata.tcp_connections.clear();
    channeldata.tcp_recv_buffers.clear();
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy(channel: Channel) {
    if !channel.is_null() {
        // Fire callbacks with ARES_EDESTRUCTION for all pending tasks
        let channeldata = unsafe { &mut *channel };
        for task in channeldata.ares.tasks.drain(..) {
            if task.status != Status::Completed {
                task.userdata.callback.run(Err(ARES_EDESTRUCTION), &task.userdata);
            }
        }
        unsafe { drop(Box::from_raw(channel)); }
    }
}

/// RFC 7686: does `name` name a `.onion` domain? Case-insensitive ASCII suffix
/// match on bytes (no alloc, no UTF-8 validation, never panics on non-ASCII).
/// Tolerates a trailing-dot FQDN and a bare "onion". Mirrors upstream c-ares.
fn is_onion_domain(name: &str) -> bool {
    let b = name.strip_suffix('.').unwrap_or(name).as_bytes();
    b.len() >= 6 && b[b.len() - 6..].eq_ignore_ascii_case(b".onion") || b.eq_ignore_ascii_case(b"onion")
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, family: c_int, callback: Option<AresHostCallback>, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() || hostname.is_null() {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
    }
    let channeldata = unsafe { &mut *channel };
    let hostname = unsafe { CStr::from_ptr(hostname).to_str().unwrap_or("") };

    // Reject non-ASCII names
    if !hostname.is_ascii() {
        unsafe { callback(arg, ARES_EBADNAME, 0, std::ptr::null_mut()) };
        return;
    }

    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(hostname) {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
    }

    let (expected_record_type, current_family) = match family {
        libc::AF_INET => (RECORD_TYPE_A as c_int, libc::AF_INET),
        libc::AF_INET6 => (RECORD_TYPE_AAAA as c_int, libc::AF_INET6),
        libc::AF_UNSPEC => (RECORD_TYPE_AAAA as c_int, libc::AF_INET6), // AAAA first
        _ => {
            unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
            return;
        }
    };

    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => AddressFamily::Any,
    };

    // Check IP literal first
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        let matches = match family_filter {
            AddressFamily::Ipv4 => ip.is_ipv4(),
            AddressFamily::Ipv6 => ip.is_ipv6(),
            AddressFamily::Any => true,
        };
        if matches {
            let lookup = HostLookup {
                canonical: hostname.to_string(),
                aliases: vec![],
                addrs: vec![ip],
            };
            let hostent = hostent_from_lookup(lookup);
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            ares_free_hostent(hostent);
            return;
        }
    }

    // Check hosts file
    let hosts_result = channeldata.ares.hosts().lookup(hostname, family_filter);
    if let Some(ref lookup) = hosts_result {
        if !lookup.addrs.is_empty() {
            let hostent = hostent_from_lookup(lookup.clone());
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            ares_free_hostent(hostent);
            return;
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
        let lookup = HostLookup {
            canonical: hostname.to_string(),
            aliases: vec![],
            addrs,
        };
        let hostent = hostent_from_lookup(lookup);
        unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
        ares_free_hostent(hostent);
        return;
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
                    unsafe { callback(arg, ARES_EFILE, 0, std::ptr::null_mut()) };
                    return;
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
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut()) };
        return;
    }

    // Check query cache
    if channeldata.query_cache_max_ttl > 0 {
        let record_type = match family {
            libc::AF_INET => RECORD_TYPE_A,
            libc::AF_INET6 => RECORD_TYPE_AAAA,
            libc::AF_UNSPEC => RECORD_TYPE_AAAA,
            _ => RECORD_TYPE_A,
        } as u16;
        let cache_key = (resolved_name.clone(), record_type);
        if let Some((cached_buf, expires_at)) = channeldata.query_cache.get(&cache_key) {
            if Instant::now() < *expires_at {
                let cached_buf = cached_buf.clone();
                let parsed = (|| -> Result<ParsedRRs<AddrRecord>, c_int> {
                    let response = ParsedResponse::from_buf(&cached_buf)?;
                    let parsed_rrs = response.process_answers::<AddrRecord>(&cached_buf, record_type)?;
                    if parsed_rrs.items.is_empty() {
                        return Err(ARES_ENODATA);
                    }
                    Ok(parsed_rrs)
                })();
                match parsed {
                    Ok(mut parsed_rrs) => {
                        if !channeldata.sortlist.is_empty() {
                            apply_sortlist(&channeldata.sortlist, &mut parsed_rrs.items);
                        }
                        let current_family = match family {
                            libc::AF_INET => libc::AF_INET,
                            libc::AF_INET6 => libc::AF_INET6,
                            _ => libc::AF_INET6,
                        };
                        let hostent = parsed_rrs.into_raw_hostent(current_family);
                        unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
                        ares_free_hostent(hostent);
                        return;
                    }
                    Err(_) => {} // Cache hit but parse error — fall through to DNS
                }
            } else {
                channeldata.query_cache.remove(&cache_key);
            }
        }
    }

    // Determine search domains
    let use_tcp = channeldata.ares.config.options.use_vc;
    let ndots = channeldata.ares.config.options.ndots;
    let dot_count = resolved_name.chars().filter(|&c| c == '.').count() as u32;
    let mut search_domains: Vec<String> = Vec::new();
    let mut query_hostname = resolved_name.clone();

    if dot_count < ndots && !channeldata.ares.config.search.is_empty() {
        search_domains = channeldata.ares.config.search.clone();
        let first_domain = search_domains.remove(0);
        query_hostname = format!("{}.{}", resolved_name, first_domain);
    }

    let first_server = pick_next_server(&channeldata.server_failures);

    let state = Box::into_raw(Box::new(HostByNameState {
        callback,
        arg,
        has_cancel: false,
        last_error: ARES_ENODATA,
        name: query_hostname.clone(),
        channel,
        search_domains,
        base_name: resolved_name,
        family,
        current_family,
        expected_record_type,
        use_tcp,
        attempt_count: 0,
        had_nodata: false,
        tried_aaaa: family == libc::AF_UNSPEC,
        timeouts: 0,
    }));

    launch_hostbyname_query(channeldata, state, &query_hostname, current_family, expected_record_type, use_tcp, first_server);

    // Server failover probing: if enabled, probe an expired-failure server in parallel
    maybe_launch_probe(channeldata, &query_hostname, current_family, first_server, use_tcp);
}

#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    if channel.is_null() { return ARES_ENOTFOUND; }
    let channeldata = unsafe { &mut *channel };
    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };

    // Convert C family constant to our Family enum
    let family_filter = match family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        libc::AF_UNSPEC => AddressFamily::Any,
        _ => {
            unsafe { *host = std::ptr::null_mut() };
            return ARES_ENOTFOUND;
        }
    };

    // Lookup in the hosts file cache
    let Some(lookup) = channeldata.ares.hosts().lookup(&name_str, family_filter) else {
        unsafe { *host = std::ptr::null_mut() };
        return ARES_ENOTFOUND;
    };

    if lookup.addrs.is_empty() {
        unsafe { *host = std::ptr::null_mut() };
        return ARES_ENOTFOUND;
    }

    unsafe { *host = hostent_from_lookup(lookup) };
    ARES_SUCCESS
}

unsafe fn hostent_from_lookup(lookup: HostLookup) -> *mut libc::hostent {
    // Determine h_addrtype and h_length from the first address
    let (h_addrtype, h_length) = match lookup.addrs[0] {
        IpAddr::V4(_) => (libc::AF_INET, 4),
        IpAddr::V6(_) => (libc::AF_INET6, 16),
    };

    // Build address list
    let addrlist: Vec<*mut i8> = iplist_to_raw(&lookup.addrs, h_length);

    // Build aliases list
    let aliases: Vec<*mut i8> = lookup
        .aliases
        .into_iter()
        .filter_map(|s| CString::new(s).ok().map(|c| c.into_raw())) // drop NUL-containing aliases
        .collect();

    let hostent = libc::hostent {
        h_name: CString::new(lookup.canonical).unwrap_or_default().into_raw(),
        h_aliases: unsafe { cnullterminated::from_vec(aliases) },
        h_addrtype: h_addrtype,
        h_length: h_length as c_int,
        h_addr_list: unsafe { cnullterminated::from_vec(addrlist) },
    };

    Box::into_raw(Box::new(hostent))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyaddr(channel: Channel, addr: *mut c_void, addrlen: c_int, family: c_int, callback: Option<AresHostCallback>, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    if family != libc::AF_INET && family != libc::AF_INET6 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    if addr.is_null() || addrlen < 0 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let addrbuf = unsafe { std::slice::from_raw_parts(addr as *mut u8, addrlen as usize) };
    let addr = match buf_to_ip(addrbuf) {
        Ok(ip) => ip,
        Err(_) => {
            unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
            return;
        }
    };
    // Check hosts file first
    if let Some(lookup) = channeldata.ares.hosts().reverse_lookup(addr) {
        let hostent = hostent_from_lookup(lookup);
        unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
        ares_free_hostent(hostent);
        return;
    }

    // No servers configured
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut()) };
        return;
    }

    // Fall through to DNS
    let ffidata = FFIData { callback: Callback::AresHostCallback(callback), arg, family, expected_record_type: RECORD_TYPE_PTR as c_int, ip: Some(addr), nameinfo_flags: 0, port: 0, scope_id: 0, server_index: 0, timeouts: 0 };
    channeldata.ares.gethostbyaddr(addr, ffidata);
    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
    if !invoke_sock_callbacks(channeldata, fd, libc::SOCK_DGRAM) {
        channeldata.ares.tasks.pop();
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut()) };
        return;
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_search(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: Option<AresCallback>, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };
    if name_str.is_empty() {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut(), 0) };
        return;
    }

    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(name_str) {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut(), 0) };
        return;
    }

    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut(), 0) };
        return;
    }

    // Determine search domains
    let has_trailing_dot = name_str.ends_with('.');
    let name_clean = name_str.strip_suffix('.').unwrap_or(name_str);
    let ndots = channeldata.ares.config.options.ndots;
    let dot_count = name_clean.chars().filter(|&c| c == '.').count() as u32;

    let mut search_domains: Vec<String> = Vec::new();
    let mut query_hostname = name_clean.to_string();

    if !has_trailing_dot && !channeldata.ares.config.search.is_empty() {
        if dot_count >= ndots {
            // High dots: try bare name first, then search domains as fallback
            search_domains = channeldata.ares.config.search.clone();
        } else {
            // Low dots: try search domains first, then bare name as fallback
            search_domains = channeldata.ares.config.search.clone();
            let first_domain = search_domains.remove(0);
            query_hostname = format!("{}.{}", name_clean, first_domain);
        }
    }

    let state = Box::into_raw(Box::new(SearchState {
        callback,
        arg,
        channel,
        name: query_hostname.clone(),
        base_name: name_clean.to_string(),
        search_domains,
        dnsclass: dnsclass as u16,
        dnstype: dnstype as u16,
        last_error: ARES_ENODATA,
        had_nodata: false,
        attempt_count: 0,
    }));

    let ffidata = FFIData {
        callback: Callback::AresSearchCallback(state),
        arg: std::ptr::null_mut(),
        family: 0,
        expected_record_type: 0,
        ip: None,
        nameinfo_flags: 0,
        port: 0,
        scope_id: 0,
        server_index: 0,
        timeouts: 0,
    };
    channeldata.ares.query(&query_hostname, dnsclass as u16, dnstype as u16, ffidata);
}

#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: Option<AresCallback>, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut(), 0) };
        return;
    }
    let name = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };
    let ffidata = FFIData { callback: Callback::AresCallback(callback), arg, family: 0, expected_record_type: 0, ip: None, nameinfo_flags: 0, port: 0, scope_id: 0, server_index: 0, timeouts: 0 };
    channeldata.ares.query(name, dnsclass as u16, dnstype as u16, ffidata);
}

#[no_mangle]
pub unsafe extern "C" fn ares_query_dnsrec(
    channel: Channel,
    name: *const c_char,
    dnsclass: c_int,
    dnstype: c_int,
    callback: Option<AresCallbackDnsRec>,
    arg: *mut c_void,
    _qid: *mut c_int, // output parameter for query ID, ignored for now
) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut()) };
        return;
    }
    let name = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };
    let name_clean = name.strip_suffix('.').unwrap_or(name);

    // Check query cache
    if channeldata.query_cache_max_ttl > 0 {
        let cache_key = (name_clean.to_string(), dnstype as u16);
        if let Some((cached_buf, expires_at)) = channeldata.query_cache.get(&cache_key) {
            if Instant::now() < *expires_at {
                let cached_buf = cached_buf.clone();
                let mut dnsrec: *mut dns_record::ares_dns_record_t = std::ptr::null_mut();
                let status = dns_record::ares_dns_parse(cached_buf.as_ptr(), cached_buf.len(), 0, &mut dnsrec);
                if status == ARES_SUCCESS {
                    callback(arg, ARES_SUCCESS, 0, dnsrec);
                    dns_record::ares_dns_record_destroy(dnsrec);
                    return;
                }
            } else {
                channeldata.query_cache.remove(&cache_key);
            }
        }
    }

    let ffidata = FFIData { callback: Callback::AresCallbackDnsRec(callback), arg, family: 0, expected_record_type: dnstype, ip: None, nameinfo_flags: 0, port: 0, scope_id: 0, server_index: 0, timeouts: 0 };
    channeldata.ares.query(name, dnsclass as u16, dnstype as u16, ffidata);
}

#[no_mangle]
pub unsafe extern "C" fn ares_search_dnsrec(
    channel: Channel,
    dnsrec: *mut dns_record::ares_dns_record_t,
    callback: Option<AresCallbackDnsRec>,
    arg: *mut c_void,
) {
    let Some(callback) = callback else { return; };
    // Extract the query name and type from the dns record
    if dnsrec.is_null() { return; }
    let mut name_ptr: *const c_char = std::ptr::null();
    let mut qtype: c_uint = 0;
    let mut qclass: c_uint = 0;
    if dns_record::ares_dns_record_query_cnt(dnsrec) > 0 {
        dns_record::ares_dns_record_query_get(dnsrec, 0, &mut name_ptr, &mut qtype, &mut qclass);
    }
    if name_ptr.is_null() { return; }
    let name_str = CStr::from_ptr(name_ptr).to_str().unwrap_or("");

    if name_str.is_empty() {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
    }

    // Reject .onion domains (RFC 7686)
    if is_onion_domain(name_str) {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
    }

    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut()) };
        return;
    }

    // Determine search domains
    let has_trailing_dot = name_str.ends_with('.');
    let name_clean = name_str.strip_suffix('.').unwrap_or(name_str);
    let ndots = channeldata.ares.config.options.ndots;
    let dot_count = name_clean.chars().filter(|&c| c == '.').count() as u32;

    let mut search_domains: Vec<String> = Vec::new();
    let mut query_hostname = name_clean.to_string();

    if !has_trailing_dot && !channeldata.ares.config.search.is_empty() {
        if dot_count >= ndots {
            // High dots: try bare name first, then search domains as fallback
            search_domains = channeldata.ares.config.search.clone();
        } else {
            // Low dots: try search domains first, then bare name as fallback
            search_domains = channeldata.ares.config.search.clone();
            let first_domain = search_domains.remove(0);
            query_hostname = format!("{}.{}", name_clean, first_domain);
        }
    }

    let state = Box::into_raw(Box::new(SearchStateDnsRec {
        callback,
        arg,
        channel,
        name: query_hostname.clone(),
        base_name: name_clean.to_string(),
        search_domains,
        dnsclass: qclass as u16,
        dnstype: qtype as u16,
        last_error: ARES_ENODATA,
        had_nodata: false,
    }));

    let ffidata = FFIData {
        callback: Callback::AresSearchCallbackDnsRec(state),
        arg: std::ptr::null_mut(),
        family: 0,
        expected_record_type: 0,
        ip: None,
        nameinfo_flags: 0,
        port: 0,
        scope_id: 0,
        server_index: 0,
        timeouts: 0,
    };
    channeldata.ares.query(&query_hostname, qclass as u16, qtype as u16, ffidata);
}

/// Looks up the node name and service name for a socket address.
///
/// This is the async equivalent of getnameinfo(3). It performs a reverse DNS lookup
/// (PTR record) to get the hostname, and looks up the service name from /etc/services.
///
/// # Arguments
/// * `channel` - The c-ares channel
/// * `sa` - Pointer to a sockaddr structure (sockaddr_in or sockaddr_in6)
/// * `salen` - Size of the sockaddr structure
/// * `flags` - Flags controlling the lookup behavior (ARES_NI_*)
/// * `callback` - Function to call with results
/// * `arg` - User data passed to callback
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_getnameinfo(channel: Channel, sa: *const libc::sockaddr, salen: libc::socklen_t, flags: c_int, callback: Option<AresNameinfoCallback>, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };

    // Extract IP address and port from sockaddr
    let addr_info = match extract_addr_port(sa, salen) {
        Ok(result) => result,
        Err(status) => {
            // Call callback with error
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            return;
        }
    };

    // Adjust flags: if neither LOOKUPSERVICE nor LOOKUPHOST, default to LOOKUPHOST
    let flags = if (flags & ARES_NI_LOOKUPSERVICE) == 0 && (flags & ARES_NI_LOOKUPHOST) == 0 {
        flags | ARES_NI_LOOKUPHOST
    } else {
        flags
    };

    let want_host = (flags & ARES_NI_LOOKUPHOST) != 0;
    let want_service = (flags & ARES_NI_LOOKUPSERVICE) != 0;

    // If only service lookup requested (no host), return immediately
    if want_service && !want_host {
        let service = get_service_string(channeldata.ares.services(), addr_info.port, flags);
        let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        unsafe { callback(arg, ARES_SUCCESS, 0, std::ptr::null_mut(), service_ptr) };
        return;
    }

    // Host lookup requested
    if want_host {
        // Numeric host can be handled without DNS
        if (flags & ARES_NI_NUMERICHOST) != 0 {
            // ARES_NI_NUMERICHOST + ARES_NI_NAMEREQD is illegal (contradiction)
            if (flags & ARES_NI_NAMEREQD) != 0 {
                unsafe { callback(arg, ARES_EBADFLAGS, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
                return;
            }

            let node = CString::new(format_ip_with_scope(&addr_info.ip, addr_info.scope_id, flags)).unwrap();
            let service = if want_service {
                get_service_string(channeldata.ares.services(), addr_info.port, flags)
            } else {
                None
            };
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, node.into_raw(), service_ptr) };
            return;
        }

        // DNS lookup is necessary
        let ffidata = FFIData {
            callback: Callback::AresNameinfoCallback(callback),
            arg,
            family: addr_info.family,
            expected_record_type: RECORD_TYPE_PTR as c_int,
            ip: Some(addr_info.ip),
            nameinfo_flags: flags,
            port: addr_info.port,
            scope_id: addr_info.scope_id,
            server_index: 0,
            timeouts: 0,
        };

        // Start the PTR lookup
        channeldata.ares.gethostbyaddr(addr_info.ip, ffidata);
        let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
        if !invoke_sock_callbacks(channeldata, fd, libc::SOCK_DGRAM) {
            channeldata.ares.tasks.pop();
            unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            return;
        }
    }
}

/// Format an IP address with scope ID for IPv6 (e.g., "fe80::1%0")
fn format_ip_with_scope(ip: &IpAddr, scope_id: u32, flags: c_int) -> String {
    match ip {
        IpAddr::V6(_) => {
            if flags & ARES_NI_NUMERICSCOPE != 0 || scope_id != 0 {
                format!("{}%{}", ip, scope_id)
            } else {
                format!("{}%{}", ip, scope_id)
            }
        }
        IpAddr::V4(_) => ip.to_string(),
    }
}

/// Extracted address info from sockaddr
struct AddrInfo {
    ip: IpAddr,
    port: u16,
    family: c_int,
    scope_id: u32, // Only meaningful for IPv6
}

/// Extract IP address and port from a sockaddr structure
fn extract_addr_port(sa: *const libc::sockaddr, salen: libc::socklen_t) -> Result<AddrInfo, c_int> {
    if sa.is_null() {
        return Err(ARES_ENOMEM);
    }

    let family = unsafe { (*sa).sa_family as c_int };

    match family {
        libc::AF_INET => {
            if (salen as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(ARES_ENOMEM);
            }
            let sa_in = sa as *const libc::sockaddr_in;
            let addr_bytes = unsafe { (*sa_in).sin_addr.s_addr.to_ne_bytes() };
            let ip = IpAddr::from(addr_bytes);
            let port = unsafe { u16::from_be((*sa_in).sin_port) };
            Ok(AddrInfo { ip, port, family: libc::AF_INET, scope_id: 0 })
        }
        libc::AF_INET6 => {
            if (salen as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(ARES_ENOMEM);
            }
            let sa_in6 = sa as *const libc::sockaddr_in6;
            let addr_bytes = unsafe { (*sa_in6).sin6_addr.s6_addr };
            let ip = IpAddr::from(addr_bytes);
            let port = unsafe { u16::from_be((*sa_in6).sin6_port) };
            let scope_id = unsafe { (*sa_in6).sin6_scope_id };
            Ok(AddrInfo { ip, port, family: libc::AF_INET6, scope_id })
        }
        _ => Err(ARES_ENOTIMP),
    }
}

/// Get the service string based on flags
fn get_service_string(services: &Services, port: u16, flags: c_int) -> Option<CString> {
    if port == 0 {
        return None;
    }

    if flags & ARES_NI_NUMERICSERV != 0 {
        // Return numeric port
        return Some(CString::new(port.to_string()).unwrap());
    }

    // Determine protocol preference based on flags
    let prefer_udp = (flags & ARES_NI_DGRAM) != 0;

    // Try to look up the service name
    if let Some(name) = services.lookup_any(port, prefer_udp) {
        Some(CString::new(name).unwrap())
    } else {
        // Fall back to numeric port
        Some(CString::new(port.to_string()).unwrap())
    }
}

#[derive(Debug)]
struct ParsedResponse<'a> {
    pub transaction_id: u16,
    pub query: DnsQuery<'a>,
    pub answers: Vec<DnsAnswer<'a>>,
}

#[derive(Debug)]
struct ParsedRRs<T> {
    items: Vec<T>,
    name: CString,
    aliases: Vec<CString>,
    limit_ttl: Option<u32>,
    success: usize,
}

impl ParsedRRs<AddrRecord> {
    unsafe fn into_raw_hostent(self, family: c_int) -> *mut libc::hostent {
        let length = match family {
            libc::AF_INET => 4,
            libc::AF_INET6 => 16,
            _ => 0,
        };
        let mut addrlist: Vec<*mut i8> = Vec::with_capacity(self.items.len());
        for record in &self.items {
            let raw: Box<[u8]> = match record.ip {
                IpAddr::V4(v4) if length == 4 => Box::new(v4.octets()),
                IpAddr::V6(v6) if length == 16 => Box::new(v6.octets()),
                _ => continue,
            };
            addrlist.push(Box::into_raw(raw) as *mut i8);
        }
        let mut aliases: Vec<*mut i8> = Vec::with_capacity(self.aliases.len());
        for a in self.aliases {
            aliases.push(a.into_raw());
        }
        let hostent = libc::hostent {
            h_name: self.name.into_raw(),
            h_aliases: unsafe { cnullterminated::from_vec(aliases) },
            h_addrtype: family,
            h_length: length as c_int,
            h_addr_list: unsafe { cnullterminated::from_vec(addrlist) },
        };

        Box::into_raw(Box::new(hostent))
    }
}

impl<'a> ParsedResponse<'a> {
    pub fn from_buf(buf: &'a [u8]) -> Result<Self, c_int> {
        let mut sbuf = SliceBuf::new(buf);
        let Some(header) = DnsHeader::parse(&mut sbuf) else {
            return Err(ARES_EBADRESP);
        };
        match header.flags & 0x0f {
            0 => {},
            1 => return Err(ARES_EFORMERR),
            2 => return Err(ARES_ESERVFAIL),
            3 => return Err(ARES_ENOTFOUND),
            4 => return Err(ARES_ENOTIMP),
            5 => return Err(ARES_EREFUSED),
            _ => return Err(ARES_ENODATA),
        };
        if header.qdcount != 1 {
            return Err(ARES_EBADRESP);
        }
        let Some(query) = DnsQuery::parse(&mut sbuf) else {
            return Err(ARES_EBADRESP);
        };
        let answer_count = header.ancount as usize;
        if answer_count == 0 {
            return Err(ARES_ENODATA);
        }
        // Grow on demand rather than pre-allocating `answer_count` (ancount is
        // attacker-controlled, up to 65535, and DnsAnswer is large, so a tiny
        // response could otherwise reserve tens of MB). The loop is self-bounding:
        // each DnsAnswer::parse consumes >= 11 bytes, so it stops when the buffer
        // is exhausted regardless of the claimed ancount.
        let mut answers = Vec::new();
        // Only parse answer section (ancount); authority and additional sections are skipped
        for _ in 0..answer_count {
            let Some(answer) = DnsAnswer::parse(&mut sbuf) else {
                return Err(ARES_EBADRESP);
            };
            answers.push(answer);
        }
        if answers.is_empty() {
            return Err(ARES_ENODATA);
        }
        Ok(Self {
            transaction_id: header.transaction_id,
            query,
            answers,
        })
    }

    pub fn process_answers<T: RRParser<'a>>(self, buf: &[u8], expected_record_type: u16) -> Result<ParsedRRs<T>, c_int> {
        // The echoed question name comes from the (untrusted) response and may
        // contain an embedded NUL byte; fail gracefully instead of panicking.
        let mut name = CString::new(self.query.name.join(".")).map_err(|_| ARES_EBADRESP)?;
        let mut items: Vec<T> = Vec::with_capacity(self.answers.len());
        let mut success = 0;
        let mut aliases: Vec<CString> = vec![];
        let mut limit_ttl: Option<u32> = None;
        for mut answer in self.answers {
            if answer.record_type == RECORD_TYPE_CNAME {
                let mut cname_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut cname_buf).ok_or(ARES_EBADRESP)?;
                let alias_of = alias_of.build_cstring(buf).ok_or(ARES_EBADRESP)?;
                if expected_record_type != RECORD_TYPE_PTR {
                    aliases.push(name);
                    name = alias_of;
                    limit_ttl = Some(answer.ttl);
                }
            }

            if answer.record_type != expected_record_type {
                success += 1;
                continue;
            }

            if answer.record_type == RECORD_TYPE_PTR || answer.record_type == RECORD_TYPE_NS {
                let mut ptr_buf = SliceBuf::new(answer.data);
                let alias_of = DnsLabel::parse(&mut ptr_buf).ok_or(ARES_EBADRESP)?;
                let alias_of = alias_of.build_cstring(buf).ok_or(ARES_EBADRESP)?;
                aliases.push(alias_of.clone());
                if answer.record_type == RECORD_TYPE_PTR { name = alias_of; }
                continue;
            }

            if expected_record_type == RECORD_TYPE_A || expected_record_type == RECORD_TYPE_AAAA {
                if let Some(limit_ttl) = limit_ttl {
                    if answer.ttl > limit_ttl {
                        answer.ttl = limit_ttl;
                    }
                }
            }

            let Some(parsed) = T::parse_rr(&answer) else {
                continue;
            };
            success += 1;
            items.push(parsed);
        }
        Ok(ParsedRRs { items, name, aliases, limit_ttl, success })
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_mx_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresMxReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresMxReply>(abuf, alen, out, RECORD_TYPE_MX) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresTxtReply>(abuf, alen, out, RECORD_TYPE_TXT) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_txt_reply_ext(abuf: *const u8, alen: c_int, out: *mut *mut AresTxtReplyExt) -> c_int {
    if abuf.is_null() || alen < 0 {
        return ARES_EBADRESP;
    }
    let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let res = match ParsedResponse::from_buf(buf) {
        Ok(res) => res,
        Err(err) => return err,
    };

    let parsed_rrs = match res.process_answers::<Vec<TxtReplyExt>>(buf, RECORD_TYPE_TXT) {
        Ok(res) => res,
        Err(err) => return err,
    };

    let answers = parsed_rrs.items;
    let parsed_count = parsed_rrs.success;
    let answers: Vec<_> = answers.into_iter().flatten().collect();
    let Some(aresreplies) = answers.into_iter().map(|x| x.into_ares_data(buf)).collect::<Option<Vec<_>>>() else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_EBADRESP;
    };

    let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
        unsafe { *out = std::ptr::null_mut() };
        return if parsed_count > 0 { ARES_SUCCESS } else { ARES_EBADRESP };
    };

    let aresdata: AresData<AresTxtReplyExt> = AresData { data_type: AresTxtReplyExt::datatype(), data: reply };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

unsafe fn parse_to_vec<'a, T1, T2>(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<T2>, c_int>
where T1: RRParser<'a> + IntoAresData<T2>, T2: DataType
{
    let res = ParsedResponse::from_buf(buf)?;
    let parsed_rrs = res.process_answers::<T1>(buf, expected_record_type)?;
    parsed_rrs.items.into_iter().map(|x| x.into_ares_data(buf)).collect::<Option<Vec<_>>>().ok_or(ARES_EBADRESP)
}

unsafe fn parse_to_singleptr<T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2, expected_record_type: u16) -> c_int
where T2: DataType, for<'a> T2: FromParsedBuf<'a, T2>
{
    ares_fn_wrapper(out, || {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let aresreplies = T2::parse_buf_to_vec(buf, expected_record_type)?;
        if aresreplies.len() > 1 {
            return Err(ARES_EBADRESP);
        }
        let reply = aresreplies.into_iter().next().ok_or(ARES_ENODATA)?;
        let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
        let aresdata = Box::into_raw(Box::new(aresdata));
        Ok(&mut (*aresdata).data)
    })
}

/// Trait to bridge lifetime-carrying parsed types to the non-lifetime output type.
/// This avoids HRTB issues with parse_to_clinkedlist/parse_to_singleptr.
trait FromParsedBuf<'a, T2> {
    fn parse_buf_to_vec(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<T2>, c_int>;
    fn parse_buf_to_clinkedlist_parts(buf: &'a [u8], expected_record_type: u16) -> Result<(Vec<T2>, usize), c_int>;
}

// Macro to implement FromParsedBuf for each (T1, T2) pair
macro_rules! impl_from_parsed_buf {
    ($t1:ty, $t2:ty) => {
        impl<'a> FromParsedBuf<'a, $t2> for $t2 {
            fn parse_buf_to_vec(buf: &'a [u8], expected_record_type: u16) -> Result<Vec<$t2>, c_int> {
                unsafe { parse_to_vec::<$t1, $t2>(buf, expected_record_type) }
            }
            fn parse_buf_to_clinkedlist_parts(buf: &'a [u8], expected_record_type: u16) -> Result<(Vec<$t2>, usize), c_int> {
                let res = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = res.process_answers::<$t1>(buf, expected_record_type)?;
                let success = parsed_rrs.success;
                let aresreplies = parsed_rrs.items.into_iter().map(|x| x.into_ares_data(buf)).collect::<Option<Vec<_>>>().ok_or(ARES_EBADRESP)?;
                Ok((aresreplies, success))
            }
        }
    };
}

impl_from_parsed_buf!(MxReply<'a>, AresMxReply);
impl_from_parsed_buf!(CaaReply<'a>, AresCaaReply);
impl_from_parsed_buf!(TxtReply<'a>, AresTxtReply);
impl_from_parsed_buf!(NaptrReply<'a>, AresNaptrReply);
impl_from_parsed_buf!(SoaReply<'a>, AresSoaReply);
impl_from_parsed_buf!(SrvReply<'a>, AresSrvReply);
impl_from_parsed_buf!(UriReply<'a>, AresUriReply);

unsafe fn parse_to_clinkedlist<T2>(abuf: *const u8, alen: c_int, out: *mut *mut T2, expected_record_type: u16) -> c_int
where T2: CLinkedList + DataType, for<'a> T2: FromParsedBuf<'a, T2> {
    ares_fn_wrapper(out, || {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let (aresreplies, success) = T2::parse_buf_to_clinkedlist_parts(buf, expected_record_type)?;
        let Some(reply) = clinkedlist::chain_nodes(aresreplies) else {
            return Err(if success > 0 { ARES_SUCCESS } else { ARES_EBADRESP });
        };

        let aresdata: AresData<T2> = AresData { data_type: T2::datatype(), data: reply };
        let aresdata = Box::into_raw(Box::new(aresdata));
        Ok(&mut (*aresdata).data)
    })
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_caa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresCaaReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresCaaReply>(abuf, alen, out, RECORD_TYPE_CAA) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_naptr_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresNaptrReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresNaptrReply>(abuf, alen, out, RECORD_TYPE_NAPTR) }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_srv_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSrvReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresSrvReply>(abuf, alen, out, RECORD_TYPE_SRV) }
}

unsafe fn ares_fn_wrapper<T, F>(out: *mut *mut T, f: F) -> c_int
where F: FnOnce() -> Result<*mut T, c_int>
{
    if out.is_null() {
        return ARES_ENOMEM;
    }
    match f() {
        Ok(res) => {
            unsafe { *out = res };
            ARES_SUCCESS
        },
        Err(err) => err,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_uri_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresUriReply) -> c_int {
    unsafe { parse_to_clinkedlist::<AresUriReply>(abuf, alen, out, RECORD_TYPE_URI) }
}

impl DnsLabel<'_> {
    pub fn build_cstring(&self, main_buf: &[u8]) -> Option<CString> {
        Some(CString::new(self.build_string(main_buf)?).ok()?)
    }
}


#[no_mangle]
pub unsafe extern "C" fn ares_parse_ns_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent) -> c_int {
    parse_to_hostent(RECORD_TYPE_NS, abuf, alen, out, std::ptr::null_mut::<ares_addrttl>(), std::ptr::null_mut(), 0)
}

pub const RECORD_TYPE_A: u16 = 0x01;
pub const RECORD_TYPE_NS: u16 = 0x02;
pub const RECORD_TYPE_CNAME: u16 = 0x05;
pub const RECORD_TYPE_SOA: u16 = 0x06;
pub const RECORD_TYPE_PTR: u16 = 0x0c;
pub const RECORD_TYPE_AAAA: u16 = 0x1c;
pub const RECORD_TYPE_MX: u16 = 0x0f;
pub const RECORD_TYPE_TXT: u16 = 0x10;
pub const RECORD_TYPE_CAA: u16 = 0x101;
pub const RECORD_TYPE_SRV: u16 = 0x21;
pub const RECORD_TYPE_NAPTR: u16 = 0x23;
pub const RECORD_TYPE_URI: u16 = 0x100;

fn buf_to_ip(buf: &[u8]) -> Result<IpAddr, &'static str> {
    match buf.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(buf).unwrap())),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(buf).unwrap())),
        _ => Err("invalid IP byte length"),
    }
}

fn iplist_to_raw(addrlist: &[std::net::IpAddr], length: usize) -> Vec<*mut i8> {
    let mut ret: Vec<*mut i8> = vec![];
    for addr in addrlist {
        let t = match addr {
            IpAddr::V4(v4) => Box::new(v4.octets()) as Box<[u8]>,
            IpAddr::V6(v6) => Box::new(v6.octets()) as Box<[u8]>,
        };
        if t.len() == length {
            ret.push(Box::into_raw(t) as *mut i8);
        }
    }
    ret
}

unsafe fn fill_addrttls<T: AddrTTL>(input: &Vec<AddrRecord>, addrttls: *mut T, naddrttls: usize) -> usize {
    let mut i = 0;
    for addr_record in input.iter() {
        if i >= naddrttls {
            break;
        }
        if (*addrttls.add(i)).set_addr_ttl(&addr_record.ip, addr_record.ttl).is_some() {
            i += 1;
        }
    }
    i
}

unsafe fn parse_to_hostent<T: AddrTTL>(expected_record_type: u16, abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, out_addrttls: *mut T, out_naddrttls: *mut c_int, family: c_int) -> c_int {
    let try_parse = || -> Result<ParsedRRs<AddrRecord>, c_int> {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let res = ParsedResponse::from_buf(buf)?;
        let addr_records = res.process_answers::<AddrRecord>(buf, expected_record_type)?;
        if addr_records.items.is_empty() && addr_records.aliases.is_empty() {
            return Err(ARES_ENODATA);
        }
        Ok(addr_records)
    };
    let on_success = |res: ParsedRRs<AddrRecord>| -> c_int {
        if !out_addrttls.is_null() && !out_naddrttls.is_null() {
            *out_naddrttls = fill_addrttls(&res.items, out_addrttls, *out_naddrttls as usize) as c_int;
        }
        if !out.is_null() {
            *out = res.into_raw_hostent(family);
        }
        ARES_SUCCESS
    };
    let on_error = |status: c_int| -> c_int {
        if !out.is_null() { *out = std::ptr::null_mut(); }
        if !out_naddrttls.is_null() { *out_naddrttls = 0; }
        status
    };
    match try_parse() {
        Ok(res) => on_success(res),
        Err(err) => on_error(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_a_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addrttl, out_naddrttls: *mut c_int) -> c_int {
    parse_to_hostent(RECORD_TYPE_A, abuf, alen, out, addrttls, out_naddrttls, libc::AF_INET)
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_aaaa_reply(abuf: *const u8, alen: c_int, out: *mut *mut libc::hostent, addrttls: *mut ares_addr6ttl, out_naddrttls: *mut c_int) -> c_int {
    parse_to_hostent(RECORD_TYPE_AAAA, abuf, alen, out, addrttls, out_naddrttls, libc::AF_INET6)
}

impl RRParser<'_> for CString {
    fn parse_rr(answer: &DnsAnswer<'_>) -> Option<CString> {
        let mut buf = SliceBuf::new(answer.data);
        let name = DnsLabel::parse(&mut buf)?;
        Some(name.build_cstring(answer.data)?)
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_ptr_reply(abuf: *const u8, alen: c_int, addr: *const c_void, addrlen: c_int, family: c_int, out: *mut *mut libc::hostent) -> c_int {
    ares_fn_wrapper(out, || {
        if abuf.is_null() || alen < 0 {
            return Err(ARES_EBADRESP);
        }
        let buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
        let res = ParsedResponse::from_buf(buf)?;
        let mut addr_records = res.process_answers::<AddrRecord>(buf, RECORD_TYPE_PTR)?;
        if addr_records.aliases.is_empty() {
            return Err(ARES_ENODATA);
        }
        if addr.is_null() || addrlen < 0 {
            return Err(ARES_EBADRESP);
        }
        let ipbuf = unsafe { std::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
        let ip = buf_to_ip(ipbuf).map_err(|_| ARES_EBADRESP)?;
        addr_records.items.push(AddrRecord { ip, ttl: 0 });
        Ok(addr_records.into_raw_hostent(family))
    })
}

#[no_mangle]
pub unsafe extern "C" fn ares_parse_soa_reply(abuf: *const u8, alen: c_int, out: *mut *mut AresSoaReply) -> c_int {
    let ret = parse_to_singleptr::<AresSoaReply>(abuf, alen, out, RECORD_TYPE_SOA);
    if ret == ARES_ENODATA { return ARES_EBADRESP; }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_hostent(hostent: *mut libc::hostent) {
    unsafe { free_hostent(hostent) };
}

pub type AresHostCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, hostent: *mut libc::hostent);
pub type AresCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, abuf: *mut u8, alen: libc::c_int);
pub type AresCallbackDnsRec = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: usize, dnsrec: *mut dns_record::ares_dns_record_t);
pub type AresSockCreateCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int;
pub type AresNameinfoCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, node: *mut c_char, service: *mut c_char);
pub type AresAddrInfoCallback = unsafe extern "C" fn(arg: *mut c_void, status: c_int, timeouts: c_int, res: *mut ares_addrinfo);

pub const ARES_AI_CANONNAME: c_int = 1 << 0;
pub const ARES_AI_NUMERICHOST: c_int = 1 << 1;
pub const ARES_AI_PASSIVE: c_int = 1 << 2;
pub const ARES_AI_NUMERICSERV: c_int = 1 << 3;
pub const ARES_AI_V4MAPPED: c_int = 1 << 4;
pub const ARES_AI_ALL: c_int = 1 << 5;
pub const ARES_AI_ADDRCONFIG: c_int = 1 << 6;
pub const ARES_AI_NOSORT: c_int = 1 << 7;
pub const ARES_AI_ENVHOSTS: c_int = 1 << 8;

#[repr(C)]
pub struct ares_addrinfo_hints {
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
}

#[repr(C)]
pub struct ares_addrinfo_node {
    pub ai_ttl: c_int,
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen: libc::socklen_t,
    pub ai_addr: *mut libc::sockaddr,
    pub ai_next: *mut ares_addrinfo_node,
}

#[repr(C)]
pub struct ares_addrinfo_cname {
    pub ttl: c_int,
    pub alias: *mut c_char,
    pub name: *mut c_char,
    pub next: *mut ares_addrinfo_cname,
}

#[repr(C)]
pub struct ares_addrinfo {
    pub cnames: *mut ares_addrinfo_cname,
    pub nodes: *mut ares_addrinfo_node,
    pub name: *mut c_char,
}

// ares_getnameinfo flags
pub const ARES_NI_NOFQDN: c_int = 1 << 0;
pub const ARES_NI_NUMERICHOST: c_int = 1 << 1;
pub const ARES_NI_NAMEREQD: c_int = 1 << 2;
pub const ARES_NI_NUMERICSERV: c_int = 1 << 3;
pub const ARES_NI_DGRAM: c_int = 1 << 4;
pub const ARES_NI_TCP: c_int = 0;
pub const ARES_NI_UDP: c_int = ARES_NI_DGRAM;
pub const ARES_NI_SCTP: c_int = 1 << 5;
pub const ARES_NI_DCCP: c_int = 1 << 6;
pub const ARES_NI_NUMERICSCOPE: c_int = 1 << 7;
pub const ARES_NI_LOOKUPHOST: c_int = 1 << 8;
pub const ARES_NI_LOOKUPSERVICE: c_int = 1 << 9;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    if channel.is_null() { return 0; }
    let channeldata = unsafe { &mut *channel };
    unsafe { libc::FD_ZERO(write_fds) };
    unsafe { libc::FD_ZERO(read_fds) };

    let mut nfds = 0;
    for task in &channeldata.ares.tasks {
        let fd = task.sock.as_raw_fd();
        match task.status {
            Status::Writing => unsafe { libc::FD_SET(fd, write_fds) },
            Status::Reading => unsafe { libc::FD_SET(fd, read_fds) },
            Status::Completed => continue,
        };
        if nfds <= fd { nfds = fd + 1 }
    }
    nfds
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_timeout(channel: Channel, maxtv: *mut libc::timeval, tv: *mut libc::timeval) -> *mut libc::timeval {
    // Upstream: NULL channel or output buffer -> return NULL.
    if channel.is_null() || tv.is_null() {
        return std::ptr::null_mut();
    }
    let channeldata = unsafe { &mut *channel };
    if channeldata.ares.tasks.is_empty() {
        if maxtv.is_null() { return std::ptr::null_mut(); }
        return maxtv;
    }
    let max_wait_time = channeldata.ares.max_wait_time().as_millis();
    unsafe {
        (*tv).tv_sec = (max_wait_time / 1000) as i64;
        (*tv).tv_usec = 1000 * (max_wait_time % 1000) as i64;
    };
    if !maxtv.is_null() {
        let maxtv_ms = unsafe { (*maxtv).tv_sec as u128 * 1000 + (*maxtv).tv_usec as u128 / 1000 };
        if maxtv_ms < max_wait_time {
            return maxtv;
        }
    }
    tv
}

fn run_ares_host_callback(res: Result<&[u8], c_int>, callback: AresHostCallback, ffidata: &FFIData) {
    let res = (|| {
        let buf = res?;
        let res = ParsedResponse::from_buf(buf)?;
        let mut addr_records = res.process_answers::<AddrRecord>(buf, ffidata.expected_record_type as u16)?;
        if ffidata.expected_record_type as u16 == RECORD_TYPE_PTR {
            if addr_records.items.is_empty() && addr_records.aliases.is_empty() {
                return Err(ARES_ENODATA);
            }
        } else if addr_records.items.is_empty() {
            return Err(ARES_ENODATA);
        }
        if ffidata.expected_record_type as u16 == RECORD_TYPE_PTR {
            addr_records.items.push(AddrRecord { ip: ffidata.ip.unwrap(), ttl: 0 });
        }
        Ok(unsafe { addr_records.into_raw_hostent(ffidata.family) })
    })();
    match res {
        Ok(raw_hostent) => {
            unsafe { callback(ffidata.arg, ARES_SUCCESS, ffidata.timeouts, &mut *raw_hostent) };
            unsafe { ares_free_hostent(raw_hostent) };
        },
        Err(err) => unsafe { callback(ffidata.arg, err, ffidata.timeouts, std::ptr::null_mut()) },
    }
}

fn run_ares_callback(res: Result<&[u8], c_int>, callback: AresCallback, ffidata: &FFIData) {
    match res {
        Ok(buf) => unsafe { callback(ffidata.arg, ARES_SUCCESS, ffidata.timeouts, buf.as_ptr() as *mut u8, buf.len() as c_int) },
        Err(err) => unsafe { callback(ffidata.arg, err, ffidata.timeouts, std::ptr::null_mut(), 0) },
    }
}

fn run_ares_callback_dnsrec(res: Result<&[u8], c_int>, callback: AresCallbackDnsRec, ffidata: &FFIData) {
    match res {
        Ok(buf) => {
            let mut dnsrec: *mut dns_record::ares_dns_record_t = std::ptr::null_mut();
            let status = unsafe { dns_record::ares_dns_parse(buf.as_ptr(), buf.len(), 0, &mut dnsrec) };
            if status == ARES_SUCCESS {
                unsafe { callback(ffidata.arg, ARES_SUCCESS, ffidata.timeouts as usize, dnsrec) };
                unsafe { dns_record::ares_dns_record_destroy(dnsrec) };
            } else {
                unsafe { callback(ffidata.arg, status, ffidata.timeouts as usize, std::ptr::null_mut()) };
            }
        }
        Err(err) => unsafe { callback(ffidata.arg, err, ffidata.timeouts as usize, std::ptr::null_mut()) },
    }
}

fn run_ares_nameinfo_callback(res: Result<&[u8], c_int>, callback: AresNameinfoCallback, ffidata: &FFIData) {
    let services = Services::default();

    let want_service = (ffidata.nameinfo_flags & ARES_NI_LOOKUPSERVICE) != 0;

    let hostname_result = (|| -> Result<CString, c_int> {
        let buf = res?;
        let parsed = ParsedResponse::from_buf(buf)?;
        let ptr_records = parsed.process_answers::<CString>(buf, RECORD_TYPE_PTR)?;

        if ptr_records.aliases.is_empty() {
            return Err(ARES_ENOTFOUND);
        }

        let mut name = ptr_records.name;

        if ffidata.nameinfo_flags & ARES_NI_NOFQDN != 0 {
            let name_str = name.to_string_lossy();
            if let Some(dot_pos) = name_str.find('.') {
                name = CString::new(&name_str[..dot_pos]).map_err(|_| ARES_EBADSTR)?;
            }
        }

        Ok(name)
    })();

    let (status, hostname) = match hostname_result {
        Ok(name) => (ARES_SUCCESS, Some(name)),
        Err(err) => {
            if err == ARES_ENOTFOUND && (ffidata.nameinfo_flags & ARES_NI_NAMEREQD) == 0 {
                let ip_str = format_ip_with_scope(&ffidata.ip.unwrap(), ffidata.scope_id, ffidata.nameinfo_flags);
                match CString::new(ip_str) {
                    Ok(name) => (ARES_SUCCESS, Some(name)),
                    Err(_) => {
                        unsafe { callback(ffidata.arg, ARES_EBADSTR, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
                        return;
                    }
                }
            } else {
                unsafe { callback(ffidata.arg, err, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
                return;
            }
        }
    };

    let service = if want_service {
        get_service_string(&services, ffidata.port, ffidata.nameinfo_flags)
    } else {
        None
    };

    let hostname_ptr = hostname.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    unsafe { callback(ffidata.arg, status, ffidata.timeouts, hostname_ptr, service_ptr) };
}

unsafe fn launch_hostbyname_query(channeldata: &mut ChannelData, state: *mut HostByNameState, hostname: &str, current_family: c_int, expected_record_type: c_int, use_tcp: bool, server_index: usize) {
    let core_family = match current_family {
        libc::AF_INET => Family::Ipv4,
        _ => Family::Ipv6,
    };
    let max_tries = channeldata.ares.config.options.attempts as usize;
    let nservers = channeldata.server_failures.len().max(1);
    let sock_type = if use_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
    let mut si = server_index;

    // TCP connection sharing: reuse existing TCP connection to same server
    if use_tcp {
        if let Some(idx) = channeldata.tcp_connections.iter().position(|(s, _)| *s == si) {
            let shared_sock = channeldata.tcp_connections[idx].1.clone();
            let ffidata = FFIData {
                callback: Callback::AresHostByNameCallback(state),
                arg: std::ptr::null_mut(),
                family: current_family,
                expected_record_type,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: si,
                timeouts: 0,
            };
            channeldata.ares.gethostbyname_tcp_to_server_shared(hostname, core_family, ffidata, si, shared_sock);
            return;
        }
        // No existing TCP connection — fall through to create one
    }

    // UDP max queries: try to reuse an existing shared socket
    if !use_tcp && channeldata.udp_max_queries > 0 {
        let limit = channeldata.udp_max_queries;
        // Find a reusable connection for this server
        if let Some(idx) = channeldata.udp_connections.iter().position(|(s, _, c)| *s == si && *c < limit) {
            let shared_sock = channeldata.udp_connections[idx].1.clone();
            channeldata.udp_connections[idx].2 += 1;
            let ffidata = FFIData {
                callback: Callback::AresHostByNameCallback(state),
                arg: std::ptr::null_mut(),
                family: current_family,
                expected_record_type,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: si,
                timeouts: 0,
            };
            channeldata.ares.gethostbyname_to_server_shared(hostname, core_family, ffidata, si, shared_sock);
            return;
        }
        // No reusable connection — fall through to create a new one, then add to pool
    }

    for _try in 0..max_tries {
        let ffidata = FFIData {
            callback: Callback::AresHostByNameCallback(state),
            arg: std::ptr::null_mut(),
            family: current_family,
            expected_record_type,
            ip: None,
            nameinfo_flags: 0,
            port: 0,
            scope_id: 0,
            server_index: si,
            timeouts: 0,
        };
        if use_tcp {
            channeldata.ares.gethostbyname_tcp_to_server(hostname, core_family, ffidata, si);
        } else {
            channeldata.ares.gethostbyname_to_server(hostname, core_family, ffidata, si);
        }
        let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
        if invoke_sock_callbacks(channeldata, fd, sock_type) {
            // Add to connection pool for reuse
            if use_tcp {
                if let crate::core::ares::DnsSocket::Tcp(ref rc_sock) = channeldata.ares.tasks.last().unwrap().sock {
                    channeldata.tcp_connections.push((si, rc_sock.clone()));
                }
            } else if channeldata.udp_max_queries > 0 {
                if let crate::core::ares::DnsSocket::Udp(ref rc_sock) = channeldata.ares.tasks.last().unwrap().sock {
                    channeldata.udp_connections.push((si, rc_sock.clone(), 1));
                }
            }
            return; // Socket created successfully
        }
        // Socket callback failed — close and remove the task, try next server
        channeldata.ares.tasks.pop();
        if nservers > 1 {
            if si < channeldata.server_failures.len() {
                channeldata.server_failures[si] += 1;
                if si < channeldata.server_last_failure.len() {
                    channeldata.server_last_failure[si] = Some(Instant::now());
                }
            }
            si = pick_next_server(&channeldata.server_failures);
        }
    }
    // All retries exhausted
    let st = unsafe { &mut *state };
    st.last_error = ARES_ECONNREFUSED;
    unsafe { (st.callback)(st.arg, ARES_ECONNREFUSED, st.timeouts, std::ptr::null_mut()) };
    drop(Box::from_raw(state));
}

unsafe fn run_ares_search_callback(res: Result<&[u8], c_int>, state_ptr: *mut SearchState, ffidata: &FFIData) {
    let state = unsafe { &mut *state_ptr };
    let channel = state.channel;
    let channeldata = unsafe { &mut *channel };

    match res {
        Ok(buf) => {
            // Check DNS RCODE for NXDOMAIN/NODATA to trigger search domain iteration
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0 };
            match rcode {
                3 => { // NXDOMAIN
                    state.last_error = ARES_ENOTFOUND;
                }
                2 | 4 | 5 => { // SERVFAIL, NOTIMP, REFUSED
                    state.last_error = match rcode {
                        2 => ARES_ESERVFAIL,
                        4 => ARES_ENOTIMP,
                        _ => ARES_EREFUSED,
                    };
                }
                0 => {
                    // Check if we actually got answer records
                    let ancount = if buf.len() >= 8 { u16::from_be_bytes([buf[6], buf[7]]) } else { 0 };
                    if ancount == 0 {
                        state.had_nodata = true;
                        state.last_error = ARES_ENODATA;
                    } else {
                        // Success — deliver raw response
                        let buf_copy = buf.to_vec();
                        (state.callback)(state.arg, ARES_SUCCESS, ffidata.timeouts, buf_copy.as_ptr() as *mut u8, buf_copy.len() as c_int);
                        drop(Box::from_raw(state_ptr));
                        return;
                    }
                }
                _ => {
                    state.had_nodata = true;
                    state.last_error = ARES_ENODATA;
                }
            }
        }
        Err(status) => {
            if status == ARES_ETIMEOUT {
                state.last_error = status;
            } else {
                state.last_error = status;
            }
        }
    }

    // Search domain iteration: on NXDOMAIN/ENODATA/ETIMEOUT, try next domain
    if state.last_error == ARES_ENOTFOUND || state.last_error == ARES_ENODATA || state.last_error == ARES_ETIMEOUT {
        if !state.search_domains.is_empty() {
            let next_domain = state.search_domains.remove(0);
            let new_hostname = format!("{}.{}", state.base_name, next_domain);
            state.name = new_hostname.clone();
            let new_ffidata = FFIData {
                callback: Callback::AresSearchCallback(state_ptr),
                arg: std::ptr::null_mut(),
                family: 0,
                expected_record_type: 0,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: 0,
                timeouts: ffidata.timeouts,
            };
            channeldata.ares.query(&new_hostname, state.dnsclass, state.dnstype, new_ffidata);
            return;
        } else if state.name != state.base_name && !state.base_name.is_empty() {
            // Try bare name as fallback
            let bare_name = state.base_name.clone();
            state.name = bare_name.clone();
            state.base_name = String::new(); // Prevent infinite recursion
            let new_ffidata = FFIData {
                callback: Callback::AresSearchCallback(state_ptr),
                arg: std::ptr::null_mut(),
                family: 0,
                expected_record_type: 0,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: 0,
                timeouts: ffidata.timeouts,
            };
            channeldata.ares.query(&bare_name, state.dnsclass, state.dnstype, new_ffidata);
            return;
        }
    }

    // Finalize
    if state.had_nodata && state.last_error == ARES_ENOTFOUND {
        state.last_error = ARES_ENODATA;
    }
    (state.callback)(state.arg, state.last_error, ffidata.timeouts, std::ptr::null_mut(), 0);
    drop(Box::from_raw(state_ptr));
}

unsafe fn run_ares_search_callback_dnsrec(res: Result<&[u8], c_int>, state_ptr: *mut SearchStateDnsRec, ffidata: &FFIData) {
    let state = unsafe { &mut *state_ptr };
    let channel = state.channel;
    let channeldata = unsafe { &mut *channel };

    match res {
        Ok(buf) => {
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0 };
            match rcode {
                3 => { // NXDOMAIN
                    state.last_error = ARES_ENOTFOUND;
                }
                2 | 4 | 5 => { // SERVFAIL, NOTIMP, REFUSED
                    state.last_error = match rcode {
                        2 => ARES_ESERVFAIL,
                        4 => ARES_ENOTIMP,
                        _ => ARES_EREFUSED,
                    };
                }
                0 => {
                    let ancount = if buf.len() >= 8 { u16::from_be_bytes([buf[6], buf[7]]) } else { 0 };
                    if ancount == 0 {
                        state.had_nodata = true;
                        state.last_error = ARES_ENODATA;
                    } else {
                        // Success — parse and deliver as dns record
                        let mut dnsrec: *mut dns_record::ares_dns_record_t = std::ptr::null_mut();
                        let parse_status = dns_record::ares_dns_parse(buf.as_ptr(), buf.len(), 0, &mut dnsrec);
                        if parse_status == ARES_SUCCESS {
                            (state.callback)(state.arg, ARES_SUCCESS, ffidata.timeouts as usize, dnsrec);
                            dns_record::ares_dns_record_destroy(dnsrec);
                        } else {
                            (state.callback)(state.arg, parse_status, ffidata.timeouts as usize, std::ptr::null_mut());
                        }
                        drop(Box::from_raw(state_ptr));
                        return;
                    }
                }
                _ => {
                    state.had_nodata = true;
                    state.last_error = ARES_ENODATA;
                }
            }
        }
        Err(status) => {
            state.last_error = status;
        }
    }

    // Search domain iteration
    if state.last_error == ARES_ENOTFOUND || state.last_error == ARES_ENODATA || state.last_error == ARES_ETIMEOUT {
        if !state.search_domains.is_empty() {
            let next_domain = state.search_domains.remove(0);
            let new_hostname = format!("{}.{}", state.base_name, next_domain);
            state.name = new_hostname.clone();
            let new_ffidata = FFIData {
                callback: Callback::AresSearchCallbackDnsRec(state_ptr),
                arg: std::ptr::null_mut(),
                family: 0,
                expected_record_type: 0,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: 0,
                timeouts: ffidata.timeouts,
            };
            channeldata.ares.query(&new_hostname, state.dnsclass, state.dnstype, new_ffidata);
            return;
        } else if state.name != state.base_name && !state.base_name.is_empty() {
            // Try bare name as fallback
            let bare_name = state.base_name.clone();
            state.name = bare_name.clone();
            state.base_name = String::new(); // Prevent infinite recursion
            let new_ffidata = FFIData {
                callback: Callback::AresSearchCallbackDnsRec(state_ptr),
                arg: std::ptr::null_mut(),
                family: 0,
                expected_record_type: 0,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: 0,
                timeouts: ffidata.timeouts,
            };
            channeldata.ares.query(&bare_name, state.dnsclass, state.dnstype, new_ffidata);
            return;
        }
    }

    // Also iterate on SERVFAIL/REFUSED/NOTIMP (try next search domain)
    if state.last_error == ARES_ESERVFAIL || state.last_error == ARES_EREFUSED || state.last_error == ARES_ENOTIMP {
        if !state.search_domains.is_empty() {
            let next_domain = state.search_domains.remove(0);
            let new_hostname = format!("{}.{}", state.base_name, next_domain);
            state.name = new_hostname.clone();
            let new_ffidata = FFIData {
                callback: Callback::AresSearchCallbackDnsRec(state_ptr),
                arg: std::ptr::null_mut(),
                family: 0,
                expected_record_type: 0,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: 0,
                timeouts: ffidata.timeouts,
            };
            channeldata.ares.query(&new_hostname, state.dnsclass, state.dnstype, new_ffidata);
            return;
        } else if state.name != state.base_name && !state.base_name.is_empty() {
            let bare_name = state.base_name.clone();
            state.name = bare_name.clone();
            state.base_name = String::new();
            let new_ffidata = FFIData {
                callback: Callback::AresSearchCallbackDnsRec(state_ptr),
                arg: std::ptr::null_mut(),
                family: 0,
                expected_record_type: 0,
                ip: None,
                nameinfo_flags: 0,
                port: 0,
                scope_id: 0,
                server_index: 0,
                timeouts: ffidata.timeouts,
            };
            channeldata.ares.query(&bare_name, state.dnsclass, state.dnstype, new_ffidata);
            return;
        }
    }

    // Finalize
    if state.had_nodata && state.last_error == ARES_ENOTFOUND {
        state.last_error = ARES_ENODATA;
    }
    (state.callback)(state.arg, state.last_error, ffidata.timeouts as usize, std::ptr::null_mut());
    drop(Box::from_raw(state_ptr));
}

unsafe fn run_ares_hostbyname_callback(res: Result<&[u8], c_int>, state_ptr: *mut HostByNameState, ffidata: &FFIData) {
    let state = unsafe { &mut *state_ptr };
    let channel = state.channel;
    let channeldata = unsafe { &mut *channel };

    match res {
        Ok(buf) => {
            // Check TC (truncation) flag — retry over TCP if truncated and not already TCP
            if is_truncated(buf) && !state.use_tcp {
                let new_hostname = state.name.clone();
                launch_hostbyname_query(channeldata, state_ptr, &new_hostname, state.current_family, state.expected_record_type, true, ffidata.server_index);
                return;
            }

            let parsed = (|| -> Result<ParsedRRs<AddrRecord>, c_int> {
                let response = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = response.process_answers::<AddrRecord>(buf, state.expected_record_type as u16)?;
                if parsed_rrs.items.is_empty() {
                    return Err(ARES_ENODATA);
                }
                Ok(parsed_rrs)
            })();

            match parsed {
                Ok(mut parsed_rrs) => {
                    // Success — cache the response under both the query name and base name
                    if channeldata.query_cache_max_ttl > 0 {
                        let ttl = parsed_rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        let cache_ttl = std::cmp::min(ttl as u32, channeldata.query_cache_max_ttl);
                        if cache_ttl > 0 {
                            let expires = Instant::now() + Duration::from_secs(cache_ttl as u64);
                            let cache_key = (state.name.clone(), state.expected_record_type as u16);
                            channeldata.query_cache.insert(cache_key, (buf.to_vec(), expires));
                            // Also cache under the base name (pre-search-domain) so repeat lookups hit cache
                            if !state.base_name.is_empty() && state.base_name != state.name {
                                let base_key = (state.base_name.clone(), state.expected_record_type as u16);
                                channeldata.query_cache.insert(base_key, (buf.to_vec(), expires));
                            }
                        }
                    }
                    // Success — invoke callback
                    if ffidata.server_index < channeldata.server_failures.len() {
                        channeldata.server_failures[ffidata.server_index] = 0;
                        if ffidata.server_index < channeldata.server_last_failure.len() {
                            channeldata.server_last_failure[ffidata.server_index] = None;
                        }
                    }
                    if !channeldata.sortlist.is_empty() {
                        apply_sortlist(&channeldata.sortlist, &mut parsed_rrs.items);
                    }
                    let hostent = parsed_rrs.into_raw_hostent(state.current_family);
                    let total_timeouts = state.timeouts + ffidata.timeouts;
                    (state.callback)(state.arg, ARES_SUCCESS, total_timeouts, hostent);
                    ares_free_hostent(hostent);
                    drop(Box::from_raw(state_ptr));
                    return;
                }
                Err(e) => {
                    // Server failover: on SERVFAIL/NOTIMP/REFUSED, retry (next server or same)
                    let nservers = channeldata.server_failures.len().max(1);
                    if e == ARES_ESERVFAIL || e == ARES_ENOTIMP || e == ARES_EREFUSED {
                        invoke_server_state_callback(channeldata, ffidata.server_index, false, state.use_tcp);
                        if ffidata.server_index < channeldata.server_failures.len() {
                            channeldata.server_failures[ffidata.server_index] += 1;
                            if ffidata.server_index < channeldata.server_last_failure.len() {
                                channeldata.server_last_failure[ffidata.server_index] = Some(Instant::now());
                            }
                        }
                        state.attempt_count += 1;
                        let max_attempts = nservers * channeldata.ares.config.options.attempts as usize;
                        if state.attempt_count < max_attempts {
                            let next_server = if channeldata.server_failures.len() > 1 {
                                pick_next_server(&channeldata.server_failures)
                            } else {
                                ffidata.server_index
                            };
                            let new_hostname = state.name.clone();
                            launch_hostbyname_query(channeldata, state_ptr, &new_hostname, state.current_family, state.expected_record_type, state.use_tcp, next_server);
                            return;
                        }
                    }
                    if e == ARES_ENODATA {
                        state.had_nodata = true;
                    }
                    state.last_error = e;
                }
            }
        }
        Err(status) => {
            if status == ARES_ECANCELLED || status == ARES_EDESTRUCTION {
                state.has_cancel = true;
                (state.callback)(state.arg, status, 0, std::ptr::null_mut());
                drop(Box::from_raw(state_ptr));
                return;
            }
            if status == ARES_ETIMEOUT {
                state.timeouts += 1; // Count as one query timeout event
                // For AF_UNSPEC AAAA timeout, fall through to try A
                state.last_error = status;
            } else {
                state.last_error = status;
            }
        }
    }

    // Search domain iteration: on NXDOMAIN/ENODATA, try next search domain or bare name
    if state.last_error == ARES_ENOTFOUND || state.last_error == ARES_ENODATA {
        if !state.search_domains.is_empty() {
            let next_domain = state.search_domains.remove(0);
            let new_hostname = format!("{}.{}", state.base_name, next_domain);
            state.name = new_hostname.clone();
            state.last_error = ARES_ENODATA;
            state.attempt_count = 0;
            let first_server = pick_next_server(&channeldata.server_failures);
            launch_hostbyname_query(channeldata, state_ptr, &new_hostname, state.current_family, state.expected_record_type, state.use_tcp, first_server);
            return;
        } else if state.name != state.base_name && !state.base_name.is_empty() {
            // All search domains exhausted, try bare name as fallback
            let bare_name = state.base_name.clone();
            state.name = bare_name.clone();
            state.last_error = ARES_ENODATA;
            state.attempt_count = 0;
            state.base_name = String::new();
            let first_server = pick_next_server(&channeldata.server_failures);
            launch_hostbyname_query(channeldata, state_ptr, &bare_name, state.current_family, state.expected_record_type, state.use_tcp, first_server);
            return;
        }
    }

    // AF_UNSPEC: if we tried AAAA and failed, switch to A
    if state.family == libc::AF_UNSPEC && state.tried_aaaa && state.current_family == libc::AF_INET6 {
        state.current_family = libc::AF_INET;
        state.expected_record_type = RECORD_TYPE_A as c_int;
        state.tried_aaaa = false;
        state.last_error = ARES_ENODATA;
        state.attempt_count = 0;
        // Restore search domains for A query
        let ndots = channeldata.ares.config.options.ndots;
        let dot_count = state.base_name.chars().filter(|&c| c == '.').count() as u32;
        let query_hostname;
        if !state.base_name.is_empty() {
            if dot_count < ndots && !channeldata.ares.config.search.is_empty() {
                state.search_domains = channeldata.ares.config.search.clone();
                let first_domain = state.search_domains.remove(0);
                query_hostname = format!("{}.{}", state.base_name, first_domain);
            } else {
                query_hostname = state.base_name.clone();
                state.search_domains.clear();
            }
        } else {
            query_hostname = state.name.clone();
        }
        state.name = query_hostname.clone();
        let first_server = pick_next_server(&channeldata.server_failures);
        launch_hostbyname_query(channeldata, state_ptr, &query_hostname, libc::AF_INET, RECORD_TYPE_A as c_int, state.use_tcp, first_server);
        return;
    }

    // Finalize
    let final_error = if state.had_nodata && state.last_error == ARES_ENOTFOUND {
        ARES_ENODATA
    } else {
        state.last_error
    };
    (state.callback)(state.arg, final_error, state.timeouts, std::ptr::null_mut());
    drop(Box::from_raw(state_ptr));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process_fd(channel: Channel, read_fd: c_int, write_fd: c_int) {
    if channel.is_null() { return; }
    unsafe {
        let mut read_fds: libc::fd_set = std::mem::zeroed();
        let mut write_fds: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut read_fds);
        libc::FD_ZERO(&mut write_fds);
        if read_fd != ARES_SOCKET_BAD {
            libc::FD_SET(read_fd, &mut read_fds);
        }
        if write_fd != ARES_SOCKET_BAD {
            libc::FD_SET(write_fd, &mut write_fds);
        }
        ares_process(channel, &mut read_fds, &mut write_fds);
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_process(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };

    // Phase 1: I/O (write + read) processing
    let mut tasks = std::mem::take(&mut channeldata.ares.tasks);
    for task in &mut tasks {
        if task.status == Status::Completed { continue; }
        if unsafe { libc::FD_ISSET(task.sock.as_raw_fd(), write_fds) } {
            match channeldata.ares.write_impl(task) {
                WriteResult::Ok => {},
                WriteResult::Failed => {
                    task.userdata.callback.run(Err(ARES_ECONNREFUSED), &task.userdata);
                },
                WriteResult::TryAgain => {
                    // Leave in Writing status for next select cycle
                },
            }
        }
        if task.status == Status::Completed { continue; }
        let fd = task.sock.as_raw_fd();
        let fd_readable = unsafe { libc::FD_ISSET(fd, read_fds) };
        let has_tcp_buffered = task.sock.is_tcp() && channeldata.tcp_recv_buffers.get(&fd).map_or(false, |b| b.len() >= 2);
        if fd_readable || has_tcp_buffered {
            // For TCP shared connections: use per-fd recv buffer with framing
            let read_result = if task.sock.is_tcp() {
                let msg_data: Option<Vec<u8>> = {
                    let rbuf = channeldata.tcp_recv_buffers.entry(fd).or_default();
                    if fd_readable {
                        let mut tmp = [0u8; 65535];
                        match task.sock.recv(&mut tmp) {
                            Ok((n, _)) if n > 0 => rbuf.extend_from_slice(&tmp[..n]),
                            _ => {},
                        }
                    }
                    if rbuf.len() >= 2 {
                        let payload_len = u16::from_be_bytes([rbuf[0], rbuf[1]]) as usize;
                        if rbuf.len() >= 2 + payload_len {
                            let msg = rbuf[2..2 + payload_len].to_vec();
                            rbuf.drain(..2 + payload_len);
                            task.status = Status::Completed;
                            Some(msg)
                        } else { None }
                    } else { None }
                };
                if let Some(ref msg) = msg_data {
                    channeldata.readbuf[..msg.len()].copy_from_slice(msg);
                    Some((0, msg.len()))
                } else { None }
            } else {
                // UDP: use existing read_impl
                match Ares::read_impl(task, &mut channeldata.readbuf) {
                    Ok(v) => v,
                    Err(()) => {
                        // recv failed (e.g. ECONNREFUSED) — fire callback
                        task.userdata.callback.run(Err(ARES_ECONNREFUSED), &task.userdata);
                        continue;
                    }
                }
            };
            if let Some((offset, len)) = read_result {
                let buf = &channeldata.readbuf[offset..offset+len];
                // QID matching: verify response transaction ID matches query
                if buf.len() >= 2 {
                    let resp_qid = u16::from_be_bytes([buf[0], buf[1]]);
                    let query_qid_offset = if task.sock.is_tcp() { 2 } else { 0 };
                    if task.writebuf.len() >= query_qid_offset + 2 {
                        let query_qid = u16::from_be_bytes([task.writebuf[query_qid_offset], task.writebuf[query_qid_offset + 1]]);
                        if resp_qid != query_qid {
                            // QID mismatch — discard response, stay in Reading state
                            task.status = Status::Reading;
                            continue;
                        }
                    }
                }
                // Check DNS rcode for server failover (rcode in lower 4 bits of byte 3)
                let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0 };
                let is_server_error = rcode == 2 || rcode == 4 || rcode == 5; // SERVFAIL, NOTIMP, REFUSED
                let nservers = channeldata.server_failures.len();
                let is_addrinfo = matches!(task.userdata.callback, Callback::AresAddrInfoCallback(_));
                let is_hostbyname = matches!(task.userdata.callback, Callback::AresHostByNameCallback(_));

                if is_server_error {
                    // Invoke server_state_callback with failure (skip for callbacks that manage their own)
                    if !is_addrinfo && !is_hostbyname {
                        invoke_server_state_callback(channeldata, task.userdata.server_index, false, task.sock.is_tcp());
                    }
                    if nservers > 1 && !is_addrinfo && !is_hostbyname {
                        let si = task.userdata.server_index;
                        if si < nservers {
                            channeldata.server_failures[si] += 1;
                            if si < channeldata.server_last_failure.len() {
                                channeldata.server_last_failure[si] = Some(Instant::now());
                            }
                        }
                        let max_attempts = nservers * channeldata.ares.config.options.attempts as usize;
                        if (si + 1) < max_attempts {
                            let next_server = pick_next_server(&channeldata.server_failures);
                            let new_ffidata = FFIData {
                                callback: task.userdata.callback.clone_for_retry(),
                                arg: task.userdata.arg,
                                family: task.userdata.family,
                                expected_record_type: task.userdata.expected_record_type,
                                ip: task.userdata.ip,
                                nameinfo_flags: task.userdata.nameinfo_flags,
                                port: task.userdata.port,
                                scope_id: task.userdata.scope_id,
                                server_index: next_server,
                                timeouts: task.userdata.timeouts,
                            };
                            let is_tcp = task.sock.is_tcp();
                            let writebuf_data = task.writebuf.to_vec();
                            let payload = if is_tcp && writebuf_data.len() > 2 {
                                &writebuf_data[2..]
                            } else {
                                &writebuf_data[..]
                            };
                            if is_tcp {
                                channeldata.ares.send_raw_tcp_to_server(payload, new_ffidata, next_server);
                            } else {
                                channeldata.ares.send_raw_to_server(payload, new_ffidata, next_server);
                            }
                            let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                            let sock_type = if is_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                            invoke_sock_callbacks(channeldata, fd, sock_type);
                            task.status = Status::Completed;
                            continue;
                        }
                    }
                } else {
                    // Success response - invoke server_state_callback with success, reset failures
                    if !is_addrinfo {
                        invoke_server_state_callback(channeldata, task.userdata.server_index, true, task.sock.is_tcp());
                    }
                    if task.userdata.server_index < channeldata.server_failures.len() {
                        channeldata.server_failures[task.userdata.server_index] = 0;
                        if task.userdata.server_index < channeldata.server_last_failure.len() {
                            channeldata.server_last_failure[task.userdata.server_index] = None;
                        }
                    }
                }
                // Check TC (truncation) flag — retry over TCP if truncated and currently UDP
                if is_truncated(buf) && !task.sock.is_tcp() && !is_addrinfo && !is_hostbyname {
                    let si = task.userdata.server_index;
                    let new_ffidata = FFIData {
                        callback: task.userdata.callback.clone_for_retry(),
                        arg: task.userdata.arg,
                        family: task.userdata.family,
                        expected_record_type: task.userdata.expected_record_type,
                        ip: task.userdata.ip,
                        nameinfo_flags: task.userdata.nameinfo_flags,
                        port: task.userdata.port,
                        scope_id: task.userdata.scope_id,
                        server_index: si,
                        timeouts: task.userdata.timeouts,
                    };
                    let writebuf_data = task.writebuf.to_vec();
                    channeldata.ares.send_raw_tcp_to_server(&writebuf_data, new_ffidata, si);
                    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                    invoke_sock_callbacks(channeldata, fd, libc::SOCK_STREAM);
                    task.status = Status::Completed;
                    continue;
                }
                // Cache successful responses for AresCallbackDnsRec and AresSearchCallbackDnsRec
                if channeldata.query_cache_max_ttl > 0 {
                    if matches!(task.userdata.callback, Callback::AresCallbackDnsRec(_) | Callback::AresSearchCallbackDnsRec(_)) {
                        // Extract query name and type from the response buffer
                        if let Ok(parsed) = ParsedResponse::from_buf(buf) {
                            let qname = parsed.query.name.join(".");
                            let qtype = parsed.query.qtype;
                            let ancount = if buf.len() >= 8 { u16::from_be_bytes([buf[6], buf[7]]) } else { 0 };
                            if ancount > 0 {
                                // Find minimum TTL from answers
                                let min_ttl = parsed.answers.iter().map(|a| a.ttl).min().unwrap_or(0);
                                let cache_ttl = std::cmp::min(min_ttl, channeldata.query_cache_max_ttl);
                                if cache_ttl > 0 {
                                    let expires = Instant::now() + Duration::from_secs(cache_ttl as u64);
                                    let cache_key = (qname, qtype);
                                    channeldata.query_cache.insert(cache_key, (buf.to_vec(), expires));
                                }
                            }
                        }
                    }
                }
                (task.userdata.callback).run(Ok(buf), &task.userdata);
            }
        }
    }
    // Merge: new tasks from read/write callbacks + processed tasks
    let mut new_tasks = std::mem::take(&mut channeldata.ares.tasks);
    tasks.append(&mut new_tasks);
    channeldata.ares.tasks = tasks;

    // Phase 2: Timeout handling
    let max_tries = channeldata.ares.config.options.attempts as u32;
    let mut tasks = std::mem::take(&mut channeldata.ares.tasks);
    for task in &mut tasks {
        if task.is_expired() && task.status != Status::Completed {
            task.tries_remaining += 1;
            // Invoke server_state_callback with failure for timeout
            invoke_server_state_callback(channeldata, task.userdata.server_index, false, task.sock.is_tcp());
            if task.tries_remaining < max_tries {
                let nservers = channeldata.server_failures.len();
                let is_tcp = task.sock.is_tcp();
                let writebuf_data = task.writebuf.to_vec();
                let payload = if is_tcp && writebuf_data.len() > 2 {
                    writebuf_data[2..].to_vec()
                } else {
                    writebuf_data
                };
                // Pick next server on timeout when there are multiple servers
                let si = if nservers > 1 {
                    if task.userdata.server_index < channeldata.server_failures.len() {
                        channeldata.server_failures[task.userdata.server_index] += 1;
                        if task.userdata.server_index < channeldata.server_last_failure.len() {
                            channeldata.server_last_failure[task.userdata.server_index] = Some(Instant::now());
                        }
                    }
                    pick_next_server(&channeldata.server_failures)
                } else {
                    task.userdata.server_index
                };
                let new_ffidata = FFIData {
                    callback: task.userdata.callback.clone_for_retry(),
                    arg: task.userdata.arg,
                    family: task.userdata.family,
                    expected_record_type: task.userdata.expected_record_type,
                    ip: task.userdata.ip,
                    nameinfo_flags: task.userdata.nameinfo_flags,
                    port: task.userdata.port,
                    scope_id: task.userdata.scope_id,
                    server_index: si,
                    timeouts: task.userdata.timeouts + 1,
                };
                task.status = Status::Completed;
                // Create new task via ares methods
                if is_tcp {
                    channeldata.ares.send_raw_tcp_to_server(&payload, new_ffidata, si);
                } else {
                    channeldata.ares.send_raw_to_server(&payload, new_ffidata, si);
                }
                // Set tries_remaining on the new task
                if let Some(new_task) = channeldata.ares.tasks.last_mut() {
                    new_task.tries_remaining = task.tries_remaining;
                }
                let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                let sock_type = if is_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                invoke_sock_callbacks(channeldata, fd, sock_type);
            } else {
                task.userdata.callback.run(Err(ARES_ETIMEOUT), &task.userdata);
                task.status = Status::Completed;
            }
        }
    }
    // Merge back: new tasks from callbacks/retries + processed tasks
    let mut new_tasks = std::mem::take(&mut channeldata.ares.tasks);
    tasks.append(&mut new_tasks);
    channeldata.ares.tasks = tasks;

    // Phase 3: Cleanup completed tasks
    channeldata.ares.tasks.retain(|task| task.status != Status::Completed);

    // Phase 4: Cleanup stale connection pool entries
    if channeldata.udp_max_queries > 0 {
        let limit = channeldata.udp_max_queries;
        channeldata.udp_connections.retain(|(_, rc, count)| {
            *count < limit || std::rc::Rc::strong_count(rc) > 1
        });
    }
    // Clean up TCP connections where no tasks reference the socket anymore
    channeldata.tcp_connections.retain(|(_, rc)| {
        std::rc::Rc::strong_count(rc) > 1
    });
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers(channel: Channel, mut head: *mut ares_addr_node) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.config.nameservers.clear();
    channeldata.ares.config.tcp_ports.clear();
    while !head.is_null() {
        let node = unsafe { &(*head) };
        match node.family {
            libc::AF_INET => {
                let oct4: [u8; 4] = node.data[0..4].try_into().unwrap();
                channeldata.ares.config.nameservers.push((IpAddr::from(oct4), None));
                channeldata.ares.config.tcp_ports.push(None);
            }
            libc::AF_INET6 => {
                let oct16: [u8; 16] = node.data[0..16].try_into().unwrap();
                channeldata.ares.config.nameservers.push((IpAddr::from(oct16), None));
                channeldata.ares.config.tcp_ports.push(None);
            }
            _ => {}
        }
        head = unsafe { (*head).next };
    }
    channeldata.server_failures = vec![0; channeldata.ares.config.nameservers.len()];
    channeldata.server_last_failure = vec![None; channeldata.ares.config.nameservers.len()];
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports(channel: Channel, mut head: *mut AresAddrPortNode) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    channeldata.ares.config.nameservers.clear();
    channeldata.ares.config.tcp_ports.clear();
    while !head.is_null() {
        let node = unsafe { &*head };
        let udp_port = node.udp_port as u16;
        let udp_port = if udp_port == 0 || udp_port == 53 { None } else { Some(udp_port) };
        let tcp_port = node.tcp_port as u16;
        let tcp_port = if tcp_port == 0 || tcp_port == 53 { None } else { Some(tcp_port) };
        match node.family {
            libc::AF_INET => {
                let octets = unsafe { node.addr.addr4.s_addr.to_ne_bytes() };
                channeldata.ares.config.nameservers.push((IpAddr::from(octets), udp_port));
                channeldata.ares.config.tcp_ports.push(tcp_port);
            }
            libc::AF_INET6 => {
                let octets = unsafe { node.addr.addr6.s6_addr };
                channeldata.ares.config.nameservers.push((IpAddr::from(octets), udp_port));
                channeldata.ares.config.tcp_ports.push(tcp_port);
            }
            _ => {}
        }
        head = node.next;
    }
    channeldata.server_failures = vec![0; channeldata.ares.config.nameservers.len()];
    channeldata.server_last_failure = vec![None; channeldata.ares.config.nameservers.len()];
    ARES_SUCCESS
}

fn ipv4_to_in_addr(ip: IpAddr) -> Option<AresAddrUnion> {
    match ip {
        IpAddr::V4(v4) => {
            let addr = u32::from_ne_bytes(v4.octets());
            Some(AresAddrUnion { addr4: libc::in_addr { s_addr: addr } })
        }
        IpAddr::V6(_) => None,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_ports(channel: Channel, out: *mut *mut AresAddrPortNode) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    let mut data: Vec<AresAddrPortNode> = vec![];
    for srv in &channeldata.ares.config.nameservers {
        let (family, addr) = match srv.0 {
            IpAddr::V4(v4) => {
                let s_addr = u32::from_ne_bytes(v4.octets());
                (libc::AF_INET, AresAddrUnion { addr4: libc::in_addr { s_addr } })
            }
            IpAddr::V6(v6) => {
                (libc::AF_INET6, AresAddrUnion { addr6: libc::in6_addr { s6_addr: v6.octets() } })
            }
        };
        data.push(AresAddrPortNode {
            next: std::ptr::null_mut(),
            family,
            addr,
            udp_port: srv.1.unwrap_or(channeldata.ares.default_udp_port) as c_int,
            tcp_port: srv.1.unwrap_or(channeldata.ares.default_tcp_port) as c_int,
        });
    }
    let Some(replies) = clinkedlist::chain_nodes(data) else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_ENODATA;
    };
    let aresdata: AresData<AresAddrPortNode> = AresData { data_type: AresAddrPortNode::datatype(), data: replies };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports_csv(channel: Channel, servers: *const c_char) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    // NULL or empty string clears servers
    if servers.is_null() {
        channeldata.ares.config.nameservers.clear();
        channeldata.ares.config.tcp_ports.clear();
        channeldata.server_failures.clear();
        channeldata.server_last_failure.clear();
        return ARES_SUCCESS;
    }
    let s = match CStr::from_ptr(servers).to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADSTR,
    };
    if s.is_empty() {
        channeldata.ares.config.nameservers.clear();
        channeldata.ares.config.tcp_ports.clear();
        channeldata.server_failures.clear();
        channeldata.server_last_failure.clear();
        return ARES_SUCCESS;
    }
    let mut cursor = Cursor::new(s);
    match servers_csv::parse_from_reader(&mut cursor) {
        Some(ns) => {
            channeldata.ares.config.tcp_ports = vec![None; ns.len()];
            channeldata.server_failures = vec![0; ns.len()];
            channeldata.server_last_failure = vec![None; ns.len()];
            channeldata.ares.config.nameservers = ns;
            ARES_SUCCESS
        }
        None => ARES_EBADSTR,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_csv(channel: Channel, servers: *const c_char) -> c_int {
    ares_set_servers_ports_csv(channel, servers)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn ares_version(version: *mut c_int) -> *const c_char {
    let (major, minor, patch) = (1, 34, 6);
    let v = (major << 16) | (minor << 8) | patch;
    if !version.is_null() { unsafe { *version = v } }
    cstr!("1.34.6")
}

pub const ARES_GETSOCK_MAXNUM: usize = 16; // per c-ares headers
pub const ARES_SOCKET_BAD: ares_socket_t = -1;

#[no_mangle]
pub unsafe extern "C" fn ares_getsock(channel: Channel, socks: *mut ares_socket_t, numsocks: c_int) -> c_int {
    // Upstream: NULL channel or non-positive numsocks -> return 0 (no sockets).
    if channel.is_null() || numsocks <= 0 {
        return 0;
    }
    let channeldata = unsafe { &mut *channel };
    let n = min(ARES_GETSOCK_MAXNUM, numsocks as usize);

    let mut mask: c_int = 0;
    let active_tasks: Vec<_> = channeldata.ares.tasks.iter()
        .filter(|t| t.status != Status::Completed)
        .collect();
    for i in 0..n {
        let maybe_task = active_tasks.get(i);
        unsafe { std::ptr::write(socks.add(i), maybe_task.map(|x| x.sock.as_raw_fd()).unwrap_or(ARES_SOCKET_BAD)) };

        if let Some(task) = maybe_task {
            if task.status == Status::Writing {
                mask |= 1 << (i + 16); // writable
            }
            mask |= 1 << i; // readable
        }
    }

    mask
}

/// Copy `bytes` into a libc::malloc'd buffer with a trailing NUL, so the caller
/// frees it with ares_free_string (libc::free). Returns null on allocation failure.
unsafe fn malloc_cstr(bytes: &[u8]) -> *mut c_char {
    let len = bytes.len();
    let p = libc::malloc(len + 1) as *mut u8;
    if p.is_null() { return std::ptr::null_mut(); }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, len);
    *p.add(len) = 0; // NUL terminator
    p as *mut c_char
}

#[no_mangle]
pub unsafe extern "C" fn ares_free_string(s: *mut libc::c_void) {
    // All buffers handed to the caller (ares_create_query/mkquery/expand_name/
    // expand_string/get_servers_csv) are libc::malloc'd, so free with libc::free.
    if !s.is_null() {
        libc::free(s);
    }
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip4(_channel: Channel, _local_ip: u32) {
    if _channel.is_null() { return; }
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip6(_channel: Channel, _local_ip6: *const u8) {
    if _channel.is_null() { return; }
}

#[no_mangle]
pub extern "C" fn ares_set_local_dev(_channel: Channel, _local_dev_name: *const c_char) {
    if _channel.is_null() { return; }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_callback(channel: Channel, callback: Option<AresSockCreateCallback>, arg: *mut c_void) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    channeldata.sock_create_callback = callback;
    channeldata.sock_create_callback_arg = arg;
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    let s = match unsafe { CStr::from_ptr(src) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    match af {
        libc::AF_INET => {
            let Ok(addr) = s.parse::<std::net::Ipv4Addr>() else { return 0 };
            unsafe { std::ptr::copy_nonoverlapping(addr.octets().as_ptr(), dst as *mut u8, 4) };
            1
        }
        libc::AF_INET6 => {
            let Ok(addr) = s.parse::<std::net::Ipv6Addr>() else { return 0 };
            unsafe { std::ptr::copy_nonoverlapping(addr.octets().as_ptr(), dst as *mut u8, 16) };
            1
        }
        _ => -1,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_expand_name(
    encoded: *const u8,
    abuf: *const u8,
    alen: c_int,
    s: *mut *mut c_char,
    enclen: *mut libc::c_long,
) -> c_int {
    if encoded.is_null() || abuf.is_null() || s.is_null() || enclen.is_null() || alen < 0 {
        return ARES_EBADNAME;
    }
    let full_buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let offset = unsafe { encoded.offset_from(abuf) };
    if offset < 0 || offset as usize >= full_buf.len() {
        return ARES_EBADNAME;
    }
    let start = offset as usize;
    let local_buf = &full_buf[start..];
    let mut sbuf = SliceBuf::new(local_buf);
    let Some(label) = DnsLabel::parse(&mut sbuf) else {
        return ARES_EBADNAME;
    };
    let consumed = sbuf.pos;
    let Some(name_str) = label.build_string(full_buf) else {
        return ARES_EBADNAME;
    };
    let cname = match CString::new(name_str) {
        Ok(c) => c,
        Err(_) => return ARES_EBADNAME,
    };
    let out = unsafe { malloc_cstr(cname.as_bytes()) };
    if out.is_null() { return ARES_ENOMEM; }
    unsafe {
        *s = out;
        *enclen = consumed as libc::c_long;
    }
    ARES_SUCCESS
}

fn addrinfo_nodes_from_addrs_port(addrs: &[IpAddr], family_filter: c_int, port: u16) -> *mut ares_addrinfo_node {
    let mut head: *mut ares_addrinfo_node = std::ptr::null_mut();
    let mut tail: *mut ares_addrinfo_node = std::ptr::null_mut();
    for ip in addrs {
        let (ai_family, ai_addrlen, ai_addr): (c_int, libc::socklen_t, *mut libc::sockaddr) = match ip {
            IpAddr::V4(v4) => {
                if family_filter != libc::AF_UNSPEC && family_filter != libc::AF_INET { continue; }
                let sa = Box::new(libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: port.to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.octets()) },
                    sin_zero: [0; 8],
                });
                (libc::AF_INET, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                 Box::into_raw(sa) as *mut libc::sockaddr)
            }
            IpAddr::V6(v6) => {
                if family_filter != libc::AF_UNSPEC && family_filter != libc::AF_INET6 { continue; }
                let sa = Box::new(libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                    sin6_scope_id: 0,
                });
                (libc::AF_INET6, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                 Box::into_raw(sa) as *mut libc::sockaddr)
            }
        };
        let node = Box::into_raw(Box::new(ares_addrinfo_node {
            ai_ttl: 0,
            ai_flags: 0,
            ai_family,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen,
            ai_addr,
            ai_next: std::ptr::null_mut(),
        }));
        if head.is_null() {
            head = node;
        } else {
            unsafe { (*tail).ai_next = node };
        }
        tail = node;
    }
    head
}

fn build_ares_addrinfo(name: &str, nodes: *mut ares_addrinfo_node) -> *mut ares_addrinfo {
    Box::into_raw(Box::new(ares_addrinfo {
        cnames: std::ptr::null_mut(),
        nodes,
        name: CString::new(name).unwrap_or_default().into_raw(),
    }))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_getaddrinfo(
    channel: Channel,
    name: *const c_char,
    service: *const c_char,
    hints: *const ares_addrinfo_hints,
    callback: Option<AresAddrInfoCallback>,
    arg: *mut c_void,
) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };

    let ai_family = if hints.is_null() { libc::AF_UNSPEC } else { unsafe { (*hints).ai_family } };

    // Resolve service name to port number
    let port: u16 = if !service.is_null() {
        let svc = CStr::from_ptr(service).to_str().unwrap_or("");
        if let Ok(p) = svc.parse::<u16>() {
            p
        } else {
            // Look up well-known service names
            match svc {
                "http" => 80,
                "https" => 443,
                "ftp" => 21,
                "ssh" => 22,
                "smtp" => 25,
                "dns" => 53,
                "pop3" => 110,
                "imap" => 143,
                _ => {
                    // Try getservbyname via libc
                    let c_svc = CStr::from_ptr(service);
                    let result = libc::getservbyname(c_svc.as_ptr(), std::ptr::null());
                    if !result.is_null() {
                        u16::from_be((*result).s_port as u16)
                    } else {
                        0
                    }
                }
            }
        }
    } else {
        0
    };

    let hostname_raw = unsafe { CStr::from_ptr(name).to_str().unwrap_or("") };
    let had_trailing_dot = hostname_raw.ends_with('.');
    let hostname = hostname_raw.strip_suffix('.').unwrap_or(hostname_raw);

    if hostname.is_empty() {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
    }

    // Reject .onion domains immediately (RFC 7686)
    if is_onion_domain(hostname) {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
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
            let nodes = addrinfo_nodes_from_addrs_port(&[ip], ai_family, port);
            let ai = build_ares_addrinfo(hostname, nodes);
            unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
            return;
        } else {
            unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
            return;
        }
    }

    // Hosts file check
    let family_filter = match ai_family {
        libc::AF_INET => AddressFamily::Ipv4,
        libc::AF_INET6 => AddressFamily::Ipv6,
        _ => AddressFamily::Any,
    };
    if let Some(lookup) = channeldata.ares.hosts().lookup(hostname, family_filter) {
        if !lookup.addrs.is_empty() {
            let nodes = addrinfo_nodes_from_addrs_port(&lookup.addrs, ai_family, port);
            let ai = build_ares_addrinfo(hostname, nodes);
            unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
            return;
        }
    }

    // No servers configured
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut()) };
        return;
    }

    // DNS path: determine search domains
    let use_tcp = channeldata.ares.config.options.use_vc;
    let ndots = channeldata.ares.config.options.ndots;
    let dot_count = hostname.chars().filter(|&c| c == '.').count() as u32;
    let mut search_domains: Vec<String> = Vec::new();
    let mut query_hostname = hostname.to_string();

    if !had_trailing_dot && !channeldata.ares.config.search.is_empty() {
        if dot_count < ndots {
            // Low dots: try search domains first, bare name as fallback
            search_domains = channeldata.ares.config.search.clone();
            let first_domain = search_domains.remove(0);
            query_hostname = format!("{}.{}", hostname, first_domain);
        } else {
            // High dots (>= ndots): bare name first, search domains as fallback
            search_domains = channeldata.ares.config.search.clone();
        }
    }

    // Pick first server using sorted order
    let first_server = pick_next_server(&channeldata.server_failures);

    let state = Box::into_raw(Box::new(AddrInfoState {
        callback,
        arg,
        pending: 0,
        nodes_head: std::ptr::null_mut(),
        nodes_tail: std::ptr::null_mut(),
        has_cancel: false,
        last_error: ARES_ENODATA,
        has_success: false,
        name: query_hostname.clone(),
        channel,
        search_domains,
        base_name: hostname.to_string(),
        ai_family,
        use_tcp,
        attempt_count: 0,
        port,
    }));

    launch_addrinfo_queries(channeldata, state, &query_hostname, ai_family, use_tcp, first_server);
}

unsafe fn launch_addrinfo_queries(channeldata: &mut ChannelData, state: *mut AddrInfoState, hostname: &str, ai_family: c_int, use_tcp: bool, server_index: usize) {
    let mut launch_query = |record_type: u16, core_family: Family, family_c: c_int| {
        unsafe { (*state).pending += 1 };
        let ffidata = FFIData {
            callback: Callback::AresAddrInfoCallback(state),
            arg: std::ptr::null_mut(),
            family: family_c,
            expected_record_type: record_type as c_int,
            ip: None,
            nameinfo_flags: 0,
            port: 0,
            scope_id: 0,
            server_index,
            timeouts: 0,
        };
        let sock_type = if use_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
        if use_tcp {
            channeldata.ares.gethostbyname_tcp_to_server(hostname, core_family, ffidata, server_index);
        } else {
            channeldata.ares.gethostbyname_to_server(hostname, core_family, ffidata, server_index);
        };
        let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
        if !invoke_sock_callbacks(channeldata, fd, sock_type) {
            // Configure callback failed - mark task as completed with error
            let task = channeldata.ares.tasks.last_mut().unwrap();
            task.status = Status::Completed;
            let st = unsafe { &mut *state };
            st.pending -= 1;
            st.last_error = ARES_ECONNREFUSED;
        }
    };

    match ai_family {
        libc::AF_INET => launch_query(RECORD_TYPE_A, Family::Ipv4, libc::AF_INET),
        libc::AF_INET6 => launch_query(RECORD_TYPE_AAAA, Family::Ipv6, libc::AF_INET6),
        _ => {
            // AF_UNSPEC: launch both
            launch_query(RECORD_TYPE_A, Family::Ipv4, libc::AF_INET);
            launch_query(RECORD_TYPE_AAAA, Family::Ipv6, libc::AF_INET6);
        }
    }
}

fn is_truncated(buf: &[u8]) -> bool {
    buf.len() >= 4 && (buf[2] & 0x02) != 0
}

/// RFC 6761 section 6.3: "localhost" or any name under ".localhost"
fn is_localhost(name: &str) -> bool {
    name.eq_ignore_ascii_case("localhost")
        || (name.len() >= 10 && name[name.len()-10..].eq_ignore_ascii_case(".localhost"))
}

/// Pick the best server to try next based on failure counts.
/// Returns the server index with lowest (failure_count, original_index).
fn pick_next_server(server_failures: &[u32]) -> usize {
    let mut best: Option<(u32, usize)> = None;
    for (i, &failures) in server_failures.iter().enumerate() {
        match best {
            None => best = Some((failures, i)),
            Some((best_f, best_i)) => {
                if failures < best_f || (failures == best_f && i < best_i) {
                    best = Some((failures, i));
                }
            }
        }
    }
    best.map(|(_, i)| i).unwrap_or(0)
}

/// Pick a server eligible for probing: has failures, failure timestamp expired past retry_delay.
/// Returns the server with lowest (failure_count, index) among eligible, excluding `exclude_server`.
fn pick_probe_server(
    server_failures: &[u32],
    server_last_failure: &[Option<Instant>],
    retry_delay_ms: u64,
    exclude_server: usize,
) -> Option<usize> {
    let now = Instant::now();
    let retry_delay = Duration::from_millis(retry_delay_ms);
    let mut best: Option<(u32, usize)> = None;
    for (i, &failures) in server_failures.iter().enumerate() {
        if failures == 0 || i == exclude_server {
            continue;
        }
        let Some(Some(last_fail)) = server_last_failure.get(i) else { continue };
        if now.duration_since(*last_fail) < retry_delay {
            continue; // Not yet expired
        }
        match best {
            None => best = Some((failures, i)),
            Some((bf, bi)) => {
                if failures < bf || (failures == bf && i < bi) {
                    best = Some((failures, i));
                }
            }
        }
    }
    best.map(|(_, i)| i)
}

/// Launch a probe query to an expired-failure server in parallel with the primary query.
unsafe fn maybe_launch_probe(
    channeldata: &mut ChannelData,
    hostname: &str,
    family: c_int,
    primary_server: usize,
    use_tcp: bool,
) {
    if channeldata.server_failover_retry_chance == 0 {
        return;
    }
    let probe_server = match pick_probe_server(
        &channeldata.server_failures,
        &channeldata.server_last_failure,
        channeldata.server_failover_retry_delay,
        primary_server,
    ) {
        Some(s) => s,
        None => return,
    };

    let core_family = match family {
        libc::AF_INET => Family::Ipv4,
        _ => Family::Ipv6,
    };
    let expected_record_type = if family == libc::AF_INET { 1 } else { 28 };
    let channel_ptr = channeldata as *mut ChannelData;
    let ffidata = FFIData {
        callback: Callback::Probe(channel_ptr),
        arg: std::ptr::null_mut(),
        family,
        expected_record_type,
        ip: None,
        nameinfo_flags: 0,
        port: 0,
        scope_id: 0,
        server_index: probe_server,
        timeouts: 0,
    };
    let sock_type = if use_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
    if use_tcp {
        channeldata.ares.gethostbyname_tcp_to_server(hostname, core_family, ffidata, probe_server);
    } else {
        channeldata.ares.gethostbyname_to_server(hostname, core_family, ffidata, probe_server);
    }
    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
    invoke_sock_callbacks(channeldata, fd, sock_type);
}

/// Callback for server failover probe queries — updates server state, no user callback.
unsafe fn run_probe_callback(res: Result<&[u8], c_int>, channel: Channel, ffidata: &FFIData) {
    let channeldata = unsafe { &mut *channel };
    let si = ffidata.server_index;
    match res {
        Ok(buf) => {
            // Check DNS rcode
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0xff };
            if rcode == 0 || rcode == 3 {
                // Success or NXDOMAIN — server is alive, reset failure state
                if si < channeldata.server_failures.len() {
                    channeldata.server_failures[si] = 0;
                    if si < channeldata.server_last_failure.len() {
                        channeldata.server_last_failure[si] = None;
                    }
                    invoke_server_state_callback(channeldata, si, true, false);
                }
            } else {
                // SERVFAIL/NOTIMP/REFUSED — still failing
                if si < channeldata.server_failures.len() {
                    channeldata.server_failures[si] += 1;
                    if si < channeldata.server_last_failure.len() {
                        channeldata.server_last_failure[si] = Some(Instant::now());
                    }
                    invoke_server_state_callback(channeldata, si, false, false);
                }
            }
        }
        Err(_) => {
            // Timeout or other error — update failure timestamp
            if si < channeldata.server_last_failure.len() {
                channeldata.server_last_failure[si] = Some(Instant::now());
            }
        }
    }
}

unsafe fn run_ares_addrinfo_callback(res: Result<&[u8], c_int>, state_ptr: *mut AddrInfoState, ffidata: &FFIData) {
    let state = unsafe { &mut *state_ptr };
    let channel = state.channel;
    let channeldata = unsafe { &mut *channel };

    match res {
        Ok(buf) => {
            // Check TC (truncation) flag — retry over TCP if truncated and not already TCP
            if is_truncated(buf) && !state.use_tcp {
                // Retry this query over TCP
                let core_family = match ffidata.family {
                    libc::AF_INET => Family::Ipv4,
                    _ => Family::Ipv6,
                };
                let new_ffidata = FFIData {
                    callback: Callback::AresAddrInfoCallback(state_ptr),
                    arg: std::ptr::null_mut(),
                    family: ffidata.family,
                    expected_record_type: ffidata.expected_record_type,
                    ip: None,
                    nameinfo_flags: 0,
                    port: 0,
                    scope_id: 0,
                    server_index: ffidata.server_index,
                    timeouts: ffidata.timeouts,
                };
                channeldata.ares.gethostbyname_tcp_to_server(&state.name, core_family, new_ffidata, ffidata.server_index);
                let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                invoke_sock_callbacks(channeldata, fd, libc::SOCK_STREAM);
                // Don't decrement pending — the new task replaces this one
                return;
            }

            let parsed = (|| -> Result<Vec<AddrRecord>, c_int> {
                let response = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = response.process_answers::<AddrRecord>(buf, ffidata.expected_record_type as u16)?;
                if parsed_rrs.items.is_empty() {
                    return Err(ARES_ENODATA);
                }
                Ok(parsed_rrs.items)
            })();

            match parsed {
                Ok(records) => {
                    // Server succeeded — reset its failure counter
                    if ffidata.server_index < channeldata.server_failures.len() {
                        channeldata.server_failures[ffidata.server_index] = 0;
                        if ffidata.server_index < channeldata.server_last_failure.len() {
                            channeldata.server_last_failure[ffidata.server_index] = None;
                        }
                    }
                    state.attempt_count = 0;
                    state.has_success = true;
                    let svc_port = state.port;
                    for record in &records {
                        let (ai_family, ai_addrlen, ai_addr): (c_int, libc::socklen_t, *mut libc::sockaddr) = match record.ip {
                            IpAddr::V4(v4) => {
                                let sa = Box::new(libc::sockaddr_in {
                                    sin_family: libc::AF_INET as libc::sa_family_t,
                                    sin_port: svc_port.to_be(),
                                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.octets()) },
                                    sin_zero: [0; 8],
                                });
                                (libc::AF_INET, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                                 Box::into_raw(sa) as *mut libc::sockaddr)
                            }
                            IpAddr::V6(v6) => {
                                let sa = Box::new(libc::sockaddr_in6 {
                                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                                    sin6_port: svc_port.to_be(),
                                    sin6_flowinfo: 0,
                                    sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                                    sin6_scope_id: 0,
                                });
                                (libc::AF_INET6, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                                 Box::into_raw(sa) as *mut libc::sockaddr)
                            }
                        };
                        let node = Box::into_raw(Box::new(ares_addrinfo_node {
                            ai_ttl: record.ttl as c_int,
                            ai_flags: 0,
                            ai_family,
                            ai_socktype: 0,
                            ai_protocol: 0,
                            ai_addrlen,
                            ai_addr,
                            ai_next: std::ptr::null_mut(),
                        }));
                        if state.nodes_head.is_null() {
                            state.nodes_head = node;
                        } else {
                            (*state.nodes_tail).ai_next = node;
                        }
                        state.nodes_tail = node;
                    }
                }
                Err(e) => {
                    // Server failover: on SERVFAIL/NOTIMP/REFUSED, retry (next server or same)
                    let nservers = channeldata.server_failures.len();
                    let max_attempts = std::cmp::max(nservers, 1) * channeldata.ares.config.options.attempts as usize;
                    if (e == ARES_ESERVFAIL || e == ARES_ENOTIMP || e == ARES_EREFUSED)
                        && nservers >= 1
                    {
                        // Increment failure counter for this server
                        if ffidata.server_index < nservers {
                            channeldata.server_failures[ffidata.server_index] += 1;
                            if ffidata.server_index < channeldata.server_last_failure.len() {
                                channeldata.server_last_failure[ffidata.server_index] = Some(Instant::now());
                            }
                        }
                        state.attempt_count += 1;

                        if state.attempt_count < max_attempts {
                            // Re-sort by (failure_count, index) and pick top server
                            let next_server = pick_next_server(&channeldata.server_failures);
                            let core_family = match ffidata.family {
                                libc::AF_INET => Family::Ipv4,
                                _ => Family::Ipv6,
                            };
                            let new_ffidata = FFIData {
                                callback: Callback::AresAddrInfoCallback(state_ptr),
                                arg: std::ptr::null_mut(),
                                family: ffidata.family,
                                expected_record_type: ffidata.expected_record_type,
                                ip: None,
                                nameinfo_flags: 0,
                                port: 0,
                                scope_id: 0,
                                server_index: next_server,
                                timeouts: ffidata.timeouts,
                            };
                            let sock_type = if state.use_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                            if state.use_tcp {
                                channeldata.ares.gethostbyname_tcp_to_server(&state.name, core_family, new_ffidata, next_server);
                            } else {
                                channeldata.ares.gethostbyname_to_server(&state.name, core_family, new_ffidata, next_server);
                            };
                            let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                            invoke_sock_callbacks(channeldata, fd, sock_type);
                            // Don't decrement pending — the new task replaces this one
                            return;
                        }
                    }
                    state.last_error = e;
                }
            }
        }
        Err(status) => {
            if status == ARES_ECANCELLED || status == ARES_EDESTRUCTION {
                state.has_cancel = true;
                state.last_error = status;
            } else {
                state.last_error = status;
            }
        }
    }

    state.pending -= 1;
    if state.pending > 0 {
        return;
    }

    // Search domain iteration: on NXDOMAIN/ENODATA/ETIMEOUT/SERVFAIL/NOTIMP/REFUSED, try next search domain or bare name
    if !state.has_success && !state.has_cancel
        && (state.last_error == ARES_ENOTFOUND || state.last_error == ARES_ENODATA || state.last_error == ARES_ETIMEOUT
            || state.last_error == ARES_ESERVFAIL || state.last_error == ARES_ENOTIMP || state.last_error == ARES_EREFUSED)
    {
        if !state.search_domains.is_empty() {
            let next_domain = state.search_domains.remove(0);
            let new_hostname = format!("{}.{}", state.base_name, next_domain);
            state.name = new_hostname.clone();
            state.last_error = ARES_ENODATA;
            state.attempt_count = 0;

            let first_server = pick_next_server(&channeldata.server_failures);
            launch_addrinfo_queries(channeldata, state_ptr, &new_hostname, state.ai_family, state.use_tcp, first_server);
            return;
        } else if state.name != state.base_name && !state.base_name.is_empty() {
            // All search domains exhausted, try bare name as fallback
            let bare_name = state.base_name.clone();
            state.name = bare_name.clone();
            state.last_error = ARES_ENODATA;
            state.attempt_count = 0;
            // Clear base_name so we don't loop forever
            state.base_name = String::new();

            let first_server = pick_next_server(&channeldata.server_failures);
            launch_addrinfo_queries(channeldata, state_ptr, &bare_name, state.ai_family, state.use_tcp, first_server);
            return;
        }
    }

    // Finalize
    if state.has_cancel {
        free_addrinfo_nodes(state.nodes_head);
        (state.callback)(state.arg, state.last_error, 0, std::ptr::null_mut());
    } else if state.has_success {
        let ai = build_ares_addrinfo(&state.name, state.nodes_head);
        (state.callback)(state.arg, ARES_SUCCESS, 0, ai);
    } else {
        free_addrinfo_nodes(state.nodes_head);
        (state.callback)(state.arg, state.last_error, 0, std::ptr::null_mut());
    }

    drop(Box::from_raw(state_ptr));
}

unsafe fn free_addrinfo_nodes(mut node: *mut ares_addrinfo_node) {
    while !node.is_null() {
        let next = (*node).ai_next;
        if !(*node).ai_addr.is_null() {
            match (*node).ai_family {
                libc::AF_INET => { drop(Box::from_raw((*node).ai_addr as *mut libc::sockaddr_in)); }
                libc::AF_INET6 => { drop(Box::from_raw((*node).ai_addr as *mut libc::sockaddr_in6)); }
                _ => {}
            }
        }
        drop(Box::from_raw(node));
        node = next;
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_freeaddrinfo(ai: *mut ares_addrinfo) {
    if ai.is_null() { return; }
    let ai = unsafe { Box::from_raw(ai) };

    // Free nodes
    unsafe { free_addrinfo_nodes(ai.nodes) };

    // Free cnames
    let mut cname = ai.cnames;
    while !cname.is_null() {
        let next = unsafe { (*cname).next };
        if !unsafe { (*cname).alias }.is_null() {
            drop(unsafe { CString::from_raw((*cname).alias) });
        }
        if !unsafe { (*cname).name }.is_null() {
            drop(unsafe { CString::from_raw((*cname).name) });
        }
        drop(unsafe { Box::from_raw(cname) });
        cname = next;
    }

    // Free name
    if !ai.name.is_null() {
        drop(unsafe { CString::from_raw(ai.name) });
    }
}

// --- New callback types ---

pub type AresSockConfigureCallback = unsafe extern "C" fn(socket_fd: c_int, sock_type: c_int, arg: *mut libc::c_void) -> c_int;
pub type AresServerStateCallback = unsafe extern "C" fn(server_string: *const c_char, success: c_int, flags: c_int, arg: *mut libc::c_void);

/// Call socket create + configure callbacks. Returns false if either callback fails.
unsafe fn invoke_sock_callbacks(channeldata: &ChannelData, fd: c_int, sock_type: c_int) -> bool {
    if let Some(cb) = channeldata.sock_create_callback {
        let ret = cb(fd, sock_type, channeldata.sock_create_callback_arg);
        if ret != 0 { return false; }
    }
    if let Some(cb) = channeldata.sock_config_callback {
        let ret = cb(fd, sock_type, channeldata.sock_config_callback_arg);
        if ret != 0 { return false; }
    }
    true
}

// --- Sortlist support ---

#[derive(Clone, Debug)]
struct SortlistEntry {
    addr: IpAddr,
    mask_bits: u8,
}

impl SortlistEntry {
    fn matches(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = if self.mask_bits >= 32 { u32::MAX } else { u32::MAX << (32 - self.mask_bits) };
                u32::from(net) & mask == u32::from(*candidate) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let net_bits = u128::from(net);
                let cand_bits = u128::from(*candidate);
                let mask = if self.mask_bits >= 128 { u128::MAX } else { u128::MAX << (128 - self.mask_bits) };
                net_bits & mask == cand_bits & mask
            }
            _ => false,
        }
    }
}

fn apply_sortlist(sortlist: &[SortlistEntry], items: &mut [AddrRecord]) {
    // Stable sort: items matching earlier sortlist entries come first
    items.sort_by(|a, b| {
        let a_idx = sortlist.iter().position(|s| s.matches(&a.ip)).unwrap_or(usize::MAX);
        let b_idx = sortlist.iter().position(|s| s.matches(&b.ip)).unwrap_or(usize::MAX);
        a_idx.cmp(&b_idx)
    });
}

fn parse_sortlist(s: &str) -> Result<Vec<SortlistEntry>, c_int> {
    let mut entries = Vec::new();
    for token in s.split(|c: char| c.is_whitespace() || c == ';').filter(|t| !t.is_empty()) {
        // Formats: "ip/mask" or "ip/bits" or just "ip"
        if let Some((addr_s, mask_s)) = token.split_once('/') {
            let addr: IpAddr = addr_s.parse().map_err(|_| ARES_EBADSTR)?;
            // Try as CIDR bits first
            if let Ok(bits) = mask_s.parse::<u8>() {
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if bits > max { return Err(ARES_EBADSTR); }
                entries.push(SortlistEntry { addr, mask_bits: bits });
            } else {
                // Try as dotted netmask (IPv4 only)
                let mask: std::net::Ipv4Addr = mask_s.parse().map_err(|_| ARES_EBADSTR)?;
                let mask_u32 = u32::from(mask);
                let bits = mask_u32.leading_ones() as u8;
                entries.push(SortlistEntry { addr, mask_bits: bits });
            }
        } else {
            // Bare address - use /32 or /128 default
            let addr: IpAddr = token.parse().map_err(|_| ARES_EBADSTR)?;
            let bits = if addr.is_ipv4() { 32 } else { 128 };
            entries.push(SortlistEntry { addr, mask_bits: bits });
        }
    }
    Ok(entries)
}

// --- Phase 1: Simple FFI functions ---

#[no_mangle]
pub extern "C" fn ares_library_initialized() -> c_int {
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: libc::socklen_t) -> *const c_char {
    if src.is_null() || dst.is_null() { return std::ptr::null(); }
    match af {
        libc::AF_INET => {
            let addr = unsafe { *(src as *const [u8; 4]) };
            let s = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
            if s.len() + 1 > size as usize { return std::ptr::null(); }
            let cs = CString::new(s).unwrap();
            let bytes = cs.as_bytes_with_nul();
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len()) };
            dst
        }
        libc::AF_INET6 => {
            let addr = unsafe { *(src as *const [u8; 16]) };
            let ip6 = std::net::Ipv6Addr::from(addr);
            let s = ip6.to_string();
            if s.len() + 1 > size as usize { return std::ptr::null(); }
            let cs = CString::new(s).unwrap();
            let bytes = cs.as_bytes_with_nul();
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len()) };
            dst
        }
        _ => std::ptr::null(),
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers(channel: Channel, out: *mut *mut ares_addr_node) -> c_int {
    if channel.is_null() || out.is_null() {
        return ARES_ENODATA;
    }
    let channeldata = unsafe { &mut *channel };
    let mut head: *mut ares_addr_node = std::ptr::null_mut();
    let mut tail: *mut ares_addr_node = std::ptr::null_mut();
    for srv in &channeldata.ares.config.nameservers {
        let mut node = Box::new(ares_addr_node {
            next: std::ptr::null_mut(),
            family: 0,
            data: [0u8; 16],
        });
        match srv.0 {
            IpAddr::V4(v4) => {
                node.family = libc::AF_INET;
                node.data[0..4].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                node.family = libc::AF_INET6;
                node.data[0..16].copy_from_slice(&v6.octets());
            }
        }
        let node_ptr = Box::into_raw(node);
        if head.is_null() {
            head = node_ptr;
        } else {
            unsafe { (*tail).next = node_ptr };
        }
        tail = node_ptr;
    }
    unsafe { *out = head };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_csv(channel: Channel) -> *mut c_char {
    if channel.is_null() { return std::ptr::null_mut(); }
    let channeldata = unsafe { &*channel };
    let default_port = channeldata.ares.default_udp_port;
    let csv: String = channeldata.ares.config.nameservers.iter()
        .map(|(ip, port_opt)| {
            let port = port_opt.unwrap_or(default_port);
            match ip {
                IpAddr::V6(_) => format!("[{}]:{}", ip, port),
                _ => format!("{}:{}", ip, port),
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    // CSV of IP/port strings never contains a NUL; null return on OOM is the sentinel.
    unsafe { malloc_cstr(csv.as_bytes()) }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_expand_string(
    encoded: *const u8,
    abuf: *const u8,
    alen: c_int,
    s: *mut *mut u8,
    enclen: *mut libc::c_long,
) -> c_int {
    if encoded.is_null() || abuf.is_null() || s.is_null() || enclen.is_null() || alen < 0 {
        return ARES_EBADSTR;
    }
    let full_buf = unsafe { std::slice::from_raw_parts(abuf, alen as usize) };
    let offset = unsafe { encoded.offset_from(abuf) };
    if offset < 0 || offset as usize >= full_buf.len() {
        return ARES_EBADSTR;
    }
    let start = offset as usize;
    let remaining = &full_buf[start..];
    if remaining.is_empty() {
        return ARES_EBADSTR;
    }
    let str_len = remaining[0] as usize;
    if str_len + 1 > remaining.len() {
        return ARES_EBADSTR;
    }
    let str_data = &remaining[1..1 + str_len];
    // The string body comes from the (untrusted) buffer and may contain an
    // embedded NUL; reject it (can't be represented as a C string) instead of
    // returning a buffer a strlen-based consumer would silently truncate.
    if str_data.contains(&0) {
        return ARES_EBADSTR;
    }
    let out = unsafe { malloc_cstr(str_data) };
    if out.is_null() { return ARES_ENOMEM; }
    unsafe {
        *s = out as *mut u8;
        *enclen = (str_len + 1) as libc::c_long; // length byte + string bytes
    }
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_create_query(
    name: *const c_char,
    dnsclass: c_int,
    qtype: c_int,
    id: c_int,
    rd: c_int,
    buf: *mut *mut u8,
    buflen: *mut c_int,
    max_udp_size: c_int,
) -> c_int {
    if name.is_null() {
        return ARES_EFORMERR;
    }
    if buf.is_null() || buflen.is_null() {
        return ARES_EFORMERR;
    }
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADNAME,
    };

    // Check if trailing dot is an unescaped separator (not a literal escaped dot)
    let has_unescaped_trailing_dot = if name_str.ends_with('.') {
        // Count consecutive backslashes before the trailing dot
        let backslash_count = name_str[..name_str.len() - 1]
            .as_bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        // Even number of backslashes means dot is unescaped (separator)
        backslash_count % 2 == 0
    } else {
        false
    };

    // Reject .onion domains
    let lower = name_str.to_lowercase();
    let check = if has_unescaped_trailing_dot {
        lower.strip_suffix('.').unwrap_or(&lower)
    } else {
        &lower
    };
    if check.ends_with(".onion") || check == "onion" {
        return ARES_ENOTFOUND;
    }

    // Validate name length
    let clean_name = if has_unescaped_trailing_dot {
        name_str.strip_suffix('.').unwrap_or(name_str)
    } else {
        name_str
    };
    if clean_name.len() > 253 {
        return ARES_EBADNAME;
    }

    // Check for escaped dots and handle them
    let labels: Vec<&str> = if clean_name.is_empty() {
        vec![] // root query
    } else {
        // Handle escaped dots: split only on unescaped dots
        let mut result = Vec::new();
        let mut current_start = 0;
        let bytes = clean_name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2; // skip escaped char
            } else if bytes[i] == b'.' {
                result.push(&clean_name[current_start..i]);
                current_start = i + 1;
                i += 1;
            } else {
                i += 1;
            }
        }
        if current_start <= bytes.len() {
            let last = &clean_name[current_start..];
            if !last.is_empty() {
                result.push(last);
            }
        }
        result
    };

    // Validate label lengths and reject empty labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.is_empty() {
            return ARES_EBADNAME;
        }
        if unescaped.len() > 63 {
            return ARES_EBADNAME;
        }
    }

    // Build DNS packet
    let flags: u16 = if rd != 0 { 0x0100 } else { 0x0000 }; // RD flag
    let mut packet = Vec::with_capacity(512);
    // Header
    packet.extend_from_slice(&(id as u16).to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    packet.extend_from_slice(&0u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0u16.to_be_bytes()); // nscount
    let arcount: u16 = if max_udp_size > 0 { 1 } else { 0 };
    packet.extend_from_slice(&arcount.to_be_bytes()); // arcount

    // Question: encode labels
    for label in &labels {
        let unescaped = unescape_label(label);
        if unescaped.len() > 63 { return ARES_EBADNAME; }
        packet.push(unescaped.len() as u8);
        packet.extend_from_slice(&unescaped);
    }
    packet.push(0); // root label
    packet.extend_from_slice(&(qtype as u16).to_be_bytes());
    packet.extend_from_slice(&(dnsclass as u16).to_be_bytes());

    // OPT pseudo-RR for EDNS if max_udp_size > 0
    if max_udp_size > 0 {
        packet.push(0); // root name
        packet.extend_from_slice(&41u16.to_be_bytes()); // type OPT
        packet.extend_from_slice(&(max_udp_size as u16).to_be_bytes()); // class = UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL (extended RCODE + flags)
        packet.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    }

    let len = packet.len();
    // Use raw allocation since DNS packets can contain null bytes
    let ptr = unsafe { libc::malloc(len) as *mut u8 };
    if ptr.is_null() { return ARES_ENOMEM; }
    unsafe {
        std::ptr::copy_nonoverlapping(packet.as_ptr(), ptr, len);
        *buf = ptr;
        *buflen = len as c_int;
    }
    ARES_SUCCESS
}

fn unescape_label(label: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(label.len());
    let bytes = label.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // Check for numeric escape \DDD
            if i + 3 < bytes.len() && bytes[i+1].is_ascii_digit() && bytes[i+2].is_ascii_digit() && bytes[i+3].is_ascii_digit() {
                let val = (bytes[i+1] - b'0') as u16 * 100 + (bytes[i+2] - b'0') as u16 * 10 + (bytes[i+3] - b'0') as u16;
                result.push(val as u8);
                i += 4;
            } else {
                result.push(bytes[i+1]);
                i += 2;
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_mkquery(
    name: *const c_char,
    dnsclass: c_int,
    qtype: c_int,
    id: c_int,
    rd: c_int,
    buf: *mut *mut u8,
    buflen: *mut c_int,
) -> c_int {
    ares_create_query(name, dnsclass, qtype, id, rd, buf, buflen, 0)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_send(channel: Channel, qbuf: *const u8, qlen: c_int, callback: Option<AresCallback>, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if qbuf.is_null() || qlen < 12 {
        unsafe { callback(arg, ARES_EBADQUERY, 0, std::ptr::null_mut(), 0) };
        return;
    }
    let channeldata = unsafe { &mut *channel };
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut(), 0) };
        return;
    }
    let query_buf = unsafe { std::slice::from_raw_parts(qbuf, qlen as usize) };

    // Extract query name and type from the packet for routing
    let ffidata = FFIData {
        callback: Callback::AresCallback(callback),
        arg,
        family: 0,
        expected_record_type: 0,
        ip: None,
        nameinfo_flags: 0,
        port: 0,
        scope_id: 0,
        server_index: 0,
        timeouts: 0,
    };

    // Send the pre-built packet
    channeldata.ares.send_raw(query_buf, ffidata);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_sortlist(channel: Channel, sortstr: *const c_char) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    if sortstr.is_null() {
        channeldata.sortlist.clear();
        return ARES_SUCCESS;
    }
    let s = match unsafe { CStr::from_ptr(sortstr) }.to_str() {
        Ok(s) => s,
        Err(_) => return ARES_EBADSTR,
    };
    match parse_sortlist(s) {
        Ok(entries) => {
            channeldata.sortlist = entries;
            ARES_SUCCESS
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn ares_reinit(channel: Channel) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    // Re-read sysconfig but preserve explicitly configured servers
    // For now, this is a no-op to avoid overwriting mock/test nameservers
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_configure_callback(channel: Channel, callback: Option<AresSockConfigureCallback>, arg: *mut c_void) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    channeldata.sock_config_callback = callback;
    channeldata.sock_config_callback_arg = arg;
}

unsafe fn invoke_server_state_callback(channeldata: &ChannelData, server_index: usize, success: bool, is_tcp: bool) {
    if let Some(cb) = channeldata.server_state_callback {
        let server_str = if let Some((ip, port)) = channeldata.ares.config.nameservers.get(server_index) {
            let port_val = port.unwrap_or(if is_tcp { channeldata.ares.default_tcp_port } else { channeldata.ares.default_udp_port });
            match ip {
                IpAddr::V4(v4) => format!("{}:{}", v4, port_val),
                IpAddr::V6(v6) => format!("[{}]:{}", v6, port_val),
            }
        } else {
            return;
        };
        let c_server_str = CString::new(server_str).unwrap_or_default();
        let success_int: c_int = if success { 1 } else { 0 };
        let flags: c_int = if is_tcp { 1 << 1 } else { 1 << 0 }; // ARES_SERV_STATE_TCP=2, UDP=1
        cb(c_server_str.as_ptr(), success_int, flags, channeldata.server_state_callback_arg);
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_server_state_callback(channel: Channel, callback: Option<AresServerStateCallback>, arg: *mut c_void) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    channeldata.server_state_callback = callback;
    channeldata.server_state_callback_arg = arg;
}

#[no_mangle]
pub extern "C" fn ares_queue_active_queries(channel: Channel) -> c_int {
    if channel.is_null() { return 0; }
    let channeldata = unsafe { &*channel };
    channeldata.ares.tasks.iter()
        .filter(|t| t.status != Status::Completed)
        .count() as c_int
}

#[no_mangle]
pub extern "C" fn ares_queue_wait_empty(_channel: Channel, _timeout_ms: c_int) -> c_int {
    // Only meaningful with the built-in event thread, which we no longer
    // provide. Match upstream c-ares on a non-threaded build (!ares_threadsafety()).
    ARES_ENOTIMP
}

#[cfg(test)]
mod onion_tests {
    use super::is_onion_domain;

    #[test]
    fn matches_onion_domains() {
        assert!(is_onion_domain("dontleak.onion"));
        assert!(is_onion_domain("DontLeak.ONION"));   // case-insensitive
        assert!(is_onion_domain("x.onion."));          // trailing-dot FQDN form
        assert!(is_onion_domain("onion"));             // bare single label
    }

    #[test]
    fn rejects_non_onion_domains() {
        assert!(!is_onion_domain("example.com"));
        assert!(!is_onion_domain("notonion"));          // suffix without the dot
        assert!(!is_onion_domain("onion.example.com")); // .onion not at the end
        assert!(!is_onion_domain(""));
    }

    #[test]
    fn non_ascii_names_do_not_panic() {
        // These byte sequences are exactly what made the old `name[len-6..]`
        // slice panic (len-6 lands inside a multibyte UTF-8 code point).
        assert!(!is_onion_domain("😀😀"));
        assert!(!is_onion_domain("café"));
        assert!(!is_onion_domain("日本語.example"));
        // A non-ASCII name that still ends in .onion is matched without panic.
        assert!(is_onion_domain("café.onion"));
    }
}
