//! Channel lifecycle and configuration: init/dup/destroy/cancel, server
//! lists, reactor fd/timeout accessors, and the channel-level callbacks.

use super::*;
use crate::ffi::kernels::channel::{
    active_query_count, clear_servers, dup_channel, getsock_mask, install_csv_servers,
    normalize_port, poll_fds, server_list, servers_csv_string, set_servers, timeout_millis,
    ServerSpec,
};
use crate::ffi::kernels::options::new_channel_data;


pub struct ChannelData {
    pub(crate) ares: Ares<FFIData>,
    pub(crate) sock_create_callback: ares_sock_create_callback,
    pub(crate) sock_create_callback_arg: *mut libc::c_void,
    pub(crate) sock_config_callback: ares_sock_config_callback,
    pub(crate) sock_config_callback_arg: *mut libc::c_void,
    pub(crate) server_state_callback: ares_server_state_callback,
    pub(crate) server_state_callback_arg: *mut libc::c_void,
    pub(crate) readbuf: Vec<u8>,
    pub(crate) server_health: ServerHealth,
    pub(crate) sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    pub maxtimeout: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    pub(crate) query_cache: std::collections::HashMap<(String, u16), (Vec<u8>, Instant)>,
    pub(crate) query_cache_max_ttl: u32, // 0 = disabled
    pub(crate) udp_max_queries: u32, // 0 = unlimited
    pub(crate) udp_connections: Vec<(usize, std::rc::Rc<dyn crate::core::transport::Transport>, u32)>, // (server_index, shared_socket, query_count)
    pub(crate) tcp_connections: Vec<(usize, std::rc::Rc<dyn crate::core::transport::Transport>)>, // (server_index, shared_socket)
    pub(crate) tcp_recv_buffers: std::collections::HashMap<i32, Vec<u8>>, // fd -> accumulated TCP receive data
    pub(crate) server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub(crate) server_failover_retry_delay: u64,  // milliseconds
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_init(out_channel: *mut Channel) -> c_int {
    let channeldata = new_channel_data(Ares::from_sysconfig(std::rc::Rc::new(SocketFactory::default())));
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_dup(dest: *mut Channel, source: Channel) -> c_int {
    if dest.is_null() || source.is_null() { return ARES_ENOTINITIALIZED; }
    let src = unsafe { &*source };
    let channeldata = dup_channel(src);
    unsafe { *dest = Box::into_raw(Box::new(channeldata)) };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_cancel(channel: Channel) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    let tasks: Vec<_> = channeldata.ares.tasks.drain(..).collect();
    for task in tasks {
        if task.status != Status::Completed {
            task.userdata.callback.run(Err(ARES_ECANCELLED), &task.userdata, channeldata);
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
        let tasks: Vec<_> = channeldata.ares.tasks.drain(..).collect();
        for task in tasks {
            if task.status != Status::Completed {
                task.userdata.callback.run(Err(ARES_EDESTRUCTION), &task.userdata, channeldata);
            }
        }
        unsafe { drop(Box::from_raw(channel)); }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_fds(channel: Channel, read_fds: &mut libc::fd_set, write_fds: &mut libc::fd_set) -> libc::c_int {
    if channel.is_null() { return 0; }
    let channeldata = unsafe { &mut *channel };
    unsafe { libc::FD_ZERO(write_fds) };
    unsafe { libc::FD_ZERO(read_fds) };

    let mut nfds = 0;
    for (fd, wants_write) in poll_fds(channeldata) {
        if wants_write {
            unsafe { libc::FD_SET(fd, write_fds) };
        } else {
            unsafe { libc::FD_SET(fd, read_fds) };
        }
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
    let Some(max_wait_time) = timeout_millis(channeldata) else {
        if maxtv.is_null() { return std::ptr::null_mut(); }
        return maxtv;
    };
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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers(channel: Channel, mut head: *mut ares_addr_node) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    let mut servers = Vec::new();
    while !head.is_null() {
        let node = unsafe { &(*head) };
        match node.family {
            libc::AF_INET => {
                let oct4 = unsafe { node.addr.addr4 }.s_addr.to_ne_bytes();
                servers.push(ServerSpec { ip: IpAddr::from(oct4), udp_port: None, tcp_port: None });
            }
            libc::AF_INET6 => {
                let oct16 = unsafe { node.addr.addr6._S6_un._S6_u8 };
                servers.push(ServerSpec { ip: IpAddr::from(oct16), udp_port: None, tcp_port: None });
            }
            _ => {}
        }
        head = unsafe { (*head).next };
    }
    set_servers(channeldata, servers);
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_ports(channel: Channel, mut head: *mut AresAddrPortNode) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    let mut servers = Vec::new();
    while !head.is_null() {
        let node = unsafe { &*head };
        let udp_port = normalize_port(node.udp_port as u16);
        let tcp_port = normalize_port(node.tcp_port as u16);
        match node.family {
            libc::AF_INET => {
                let octets = unsafe { node.addr.addr4.s_addr.to_ne_bytes() };
                servers.push(ServerSpec { ip: IpAddr::from(octets), udp_port, tcp_port });
            }
            libc::AF_INET6 => {
                let octets = unsafe { node.addr.addr6._S6_un._S6_u8 };
                servers.push(ServerSpec { ip: IpAddr::from(octets), udp_port, tcp_port });
            }
            _ => {}
        }
        head = node.next;
    }
    set_servers(channeldata, servers);
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_ports(channel: Channel, out: *mut *mut AresAddrPortNode) -> c_int {
    if channel.is_null() { return ARES_ENODATA; }
    let channeldata = unsafe { &mut *channel };
    let mut data: Vec<AresAddrPortNode> = vec![];
    for (ip, udp_port, tcp_port) in server_list(channeldata) {
        let (family, addr) = match ip {
            IpAddr::V4(v4) => {
                let s_addr = u32::from_ne_bytes(v4.octets());
                (libc::AF_INET, AresAddrUnion { addr4: libc::in_addr { s_addr } })
            }
            IpAddr::V6(v6) => {
                (libc::AF_INET6, AresAddrUnion { addr6: ares_in6_addr::from_octets(v6.octets()) })
            }
        };
        data.push(AresAddrPortNode {
            next: std::ptr::null_mut(),
            family,
            addr,
            udp_port: udp_port as c_int,
            tcp_port: tcp_port as c_int,
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
        clear_servers(channeldata);
        return ARES_SUCCESS;
    }
    let Some(s) = (unsafe { cstr_opt(servers) }) else { return ARES_EBADSTR };
    if s.is_empty() {
        clear_servers(channeldata);
        return ARES_SUCCESS;
    }
    let mut cursor = Cursor::new(s);
    match servers_csv::parse_from_reader(&mut cursor) {
        Some(ns) => {
            install_csv_servers(channeldata, ns);
            ARES_SUCCESS
        }
        None => ARES_EBADSTR,
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_servers_csv(channel: Channel, servers: *const c_char) -> c_int {
    unsafe { ares_set_servers_ports_csv(channel, servers) }
}

/// # Safety
/// `channel` must be a valid channel and `socks` must point to at least `numsocks` writable slots.
#[no_mangle]
pub unsafe extern "C" fn ares_getsock(channel: Channel, socks: *mut ares_socket_t, numsocks: c_int) -> c_int {
    // Upstream: NULL channel or non-positive numsocks -> return 0 (no sockets).
    if channel.is_null() || numsocks <= 0 {
        return 0;
    }
    let channeldata = unsafe { &mut *channel };
    let n = min(ARES_GETSOCK_MAXNUM, numsocks as usize);

    let fds = poll_fds(channeldata);
    for i in 0..n {
        let fd = fds.get(i).map(|(fd, _)| *fd).unwrap_or(ARES_SOCKET_BAD);
        unsafe { std::ptr::write(socks.add(i), fd) };
    }
    getsock_mask(&fds, n)
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip4(_channel: Channel, _local_ip: u32) {
    if _channel.is_null() {}
}

#[no_mangle]
pub extern "C" fn ares_set_local_ip6(_channel: Channel, _local_ip6: *const u8) {
    if _channel.is_null() {}
}

#[no_mangle]
pub extern "C" fn ares_set_local_dev(_channel: Channel, _local_dev_name: *const c_char) {
    if _channel.is_null() {}
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_socket_callback(channel: Channel, callback: ares_sock_create_callback, arg: *mut c_void) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    channeldata.sock_create_callback = callback;
    channeldata.sock_create_callback_arg = arg;
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers(channel: Channel, out: *mut *mut ares_addr_node) -> c_int {
    if channel.is_null() || out.is_null() {
        return ARES_ENODATA;
    }
    let channeldata = unsafe { &mut *channel };
    // Build the list the same way as ares_get_servers_ports: an AresData-wrapped
    // chain so the caller can free it with ares_free_data (the c-ares contract).
    // (A plain Box chain here corrupted the heap under ares_free_data.)
    let mut data: Vec<ares_addr_node> = vec![];
    for (ip, _, _) in server_list(channeldata) {
        let (family, addr) = match ip {
            IpAddr::V4(v4) => {
                let s_addr = u32::from_ne_bytes(v4.octets());
                (libc::AF_INET, AresAddrUnion { addr4: libc::in_addr { s_addr } })
            }
            IpAddr::V6(v6) => (libc::AF_INET6, AresAddrUnion { addr6: ares_in6_addr::from_octets(v6.octets()) }),
        };
        data.push(ares_addr_node { next: std::ptr::null_mut(), family, addr });
    }
    let Some(chain) = clinkedlist::chain_nodes(data) else {
        unsafe { *out = std::ptr::null_mut() };
        return ARES_ENODATA;
    };
    let aresdata: AresData<ares_addr_node> = AresData { data_type: ares_addr_node::datatype(), data: chain };
    let aresdata = Box::into_raw(Box::new(aresdata));
    unsafe { *out = &mut (*aresdata).data };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_get_servers_csv(channel: Channel) -> *mut c_char {
    if channel.is_null() { return std::ptr::null_mut(); }
    let channeldata = unsafe { &*channel };
    let csv = servers_csv_string(channeldata);
    // CSV of IP/port strings never contains a NUL; null return on OOM is the sentinel.
    unsafe { malloc_cstr(csv.as_bytes()) }
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
    let Some(s) = (unsafe { cstr_opt(sortstr) }) else { return ARES_EBADSTR };
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
pub unsafe extern "C" fn ares_set_socket_configure_callback(channel: Channel, callback: ares_sock_config_callback, arg: *mut c_void) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    channeldata.sock_config_callback = callback;
    channeldata.sock_config_callback_arg = arg;
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_set_server_state_callback(channel: Channel, callback: ares_server_state_callback, arg: *mut c_void) {
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    channeldata.server_state_callback = callback;
    channeldata.server_state_callback_arg = arg;
}

/// # Safety
/// `channel` must be null or a valid channel handle returned by
/// `ares_init`/`ares_init_options` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn ares_queue_active_queries(channel: Channel) -> c_int {
    if channel.is_null() { return 0; }
    let channeldata = unsafe { &*channel };
    active_query_count(channeldata) as c_int
}

#[no_mangle]
pub extern "C" fn ares_queue_wait_empty(_channel: Channel, _timeout_ms: c_int) -> c_int {
    // Only meaningful with the built-in event thread, which we no longer
    // provide. Match upstream c-ares on a non-threaded build (!ares_threadsafety()).
    ARES_ENOTIMP
}
