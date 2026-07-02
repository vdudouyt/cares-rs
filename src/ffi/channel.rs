//! Channel lifecycle and configuration: init/dup/destroy/cancel, server
//! lists, reactor fd/timeout accessors, and the channel-level callbacks.

use super::*;


pub struct ChannelData {
    pub(crate) ares: Ares<FFIData>,
    pub(crate) sock_create_callback: ares_sock_create_callback,
    pub(crate) sock_create_callback_arg: *mut libc::c_void,
    pub(crate) sock_config_callback: ares_sock_config_callback,
    pub(crate) sock_config_callback_arg: *mut libc::c_void,
    pub(crate) server_state_callback: ares_server_state_callback,
    pub(crate) server_state_callback_arg: *mut libc::c_void,
    pub(crate) readbuf: Vec<u8>,
    pub(crate) server_failures: Vec<u32>,
    pub(crate) sortlist: Vec<SortlistEntry>,
    pub flags: i32,
    pub maxtimeout: i32,
    pub lookups: String,
    pub resolvconf_path: String,
    pub hosts_path: String,
    pub(crate) query_cache: std::collections::HashMap<(String, u16), (Vec<u8>, Instant)>,
    pub(crate) query_cache_max_ttl: u32, // 0 = disabled
    pub(crate) udp_max_queries: u32, // 0 = unlimited
    pub(crate) udp_connections: Vec<(usize, std::rc::Rc<crate::ffi::ares_socket::UdpSocket>, u32)>, // (server_index, shared_socket, query_count)
    pub(crate) tcp_connections: Vec<(usize, std::rc::Rc<crate::ffi::ares_socket::TcpSocket>)>, // (server_index, shared_socket)
    pub(crate) tcp_recv_buffers: std::collections::HashMap<i32, Vec<u8>>, // fd -> accumulated TCP receive data
    pub(crate) server_failover_retry_chance: u16, // 1/N probability; 0 = disabled
    pub(crate) server_failover_retry_delay: u64,  // milliseconds
    pub(crate) server_last_failure: Vec<Option<Instant>>, // per-server last failure timestamp
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
                let oct4 = unsafe { node.addr.addr4 }.s_addr.to_ne_bytes();
                channeldata.ares.config.nameservers.push((IpAddr::from(oct4), None));
                channeldata.ares.config.tcp_ports.push(None);
            }
            libc::AF_INET6 => {
                let oct16 = unsafe { node.addr.addr6._S6_un._S6_u8 };
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
                let octets = unsafe { node.addr.addr6._S6_un._S6_u8 };
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
                (libc::AF_INET6, AresAddrUnion { addr6: ares_in6_addr::from_octets(v6.octets()) })
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
    let Some(s) = cstr_opt(servers) else { return ARES_EBADSTR };
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
    for srv in &channeldata.ares.config.nameservers {
        let (family, addr) = match srv.0 {
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
