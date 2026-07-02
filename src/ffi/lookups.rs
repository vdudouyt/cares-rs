//! Lookup entry points (gethostbyname/getaddrinfo/search/query/send/...)
//! and their per-query state + callback dispatch.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;


/// Live state of an ares_gethostbyname lookup: the pure state machine plus
/// the C callback to deliver to.
#[derive(Debug)]
pub(crate) struct HostByNameLookup {
    pub(crate) sm: HostByNameSm,
    pub(crate) callback: AresHostCallback,
    pub(crate) arg: *mut c_void,
}

pub(crate) struct AddrInfoState {
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

/// How a finished search lookup reports back to C: the raw-buffer callback of
/// ares_search, or the parsed-record callback of ares_search_dnsrec. Bare fn
/// pointers and the opaque arg are Copy; only *calling* them is unsafe.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SearchDelivery {
    Raw { callback: AresCallback, arg: *mut c_void },
    DnsRec { callback: AresCallbackDnsRec, arg: *mut c_void },
}

/// Live state of an ares_search / ares_search_dnsrec lookup: the pure state
/// machine plus what the executor needs to re-issue queries and deliver.
#[derive(Debug)]
pub(crate) struct SearchLookup {
    pub(crate) sm: SearchSm,
    pub(crate) dnstype: u16,
    pub(crate) delivery: SearchDelivery,
}

#[derive(Debug)]
// Variants are named after the c-ares FFI callback typedefs they dispatch to;
// the shared `Callback` suffix is intentional for that correspondence.
#[allow(clippy::enum_variant_names)]
pub(crate) enum Callback {
    AresHostCallback(AresHostCallback),
    AresCallback(AresCallback),
    AresCallbackDnsRec(AresCallbackDnsRec),
    AresNameinfoCallback(AresNameinfoCallback),
    AresAddrInfoCallback(*mut AddrInfoState),
    HostByName(Rc<RefCell<HostByNameLookup>>),
    Search(Rc<RefCell<SearchLookup>>),
    Probe, // Server failover probe — no user callback
}

impl Callback {
    pub(crate) fn run(&self, buf: Result<&[u8], c_int>, ffidata: &FFIData, channeldata: &mut ChannelData) {
        // For destruction/cancellation of stateful callbacks, handle directly
        if let Err(status) = &buf {
            if *status == ARES_EDESTRUCTION || *status == ARES_ECANCELLED {
                match self {
                    Self::HostByName(lookup) => {
                        let (callback, arg) = { let l = lookup.borrow(); (l.callback, l.arg) };
                        unsafe { callback(arg, *status, 0, std::ptr::null_mut()) };
                        return;
                    },
                    Self::AresAddrInfoCallback(state_ptr) => unsafe {
                        let state = &mut **state_ptr;
                        state.pending -= 1;
                        state.has_cancel = true;
                        state.last_error = *status;
                        if state.pending == 0 {
                            free_addrinfo_nodes(state.nodes_head);
                            (state.callback)(state.arg, state.last_error, 0, std::ptr::null_mut());
                            drop(Box::from_raw(*state_ptr));
                        }
                        return;
                    },
                    Self::Search(lookup) => {
                        match lookup.borrow().delivery {
                            SearchDelivery::Raw { callback, arg } => unsafe {
                                callback(arg, *status, ffidata.timeouts, std::ptr::null_mut(), 0);
                            },
                            SearchDelivery::DnsRec { callback, arg } => unsafe {
                                callback(arg, *status, ffidata.timeouts as usize, std::ptr::null_mut());
                            },
                        }
                        return;
                    },
                    Self::Probe => return, // Probes silently ignore cancel/destroy
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
            Self::HostByName(lookup) => unsafe { run_ares_hostbyname_callback(buf, lookup, ffidata, channeldata) },
            Self::Search(lookup) => unsafe { run_ares_search_callback(buf, lookup, ffidata, channeldata) },
            Self::Probe => unsafe { run_probe_callback(buf, channeldata, ffidata) },
        }
    }
    pub(crate) fn clone_for_retry(&self) -> Self {
        match self {
            Self::AresHostCallback(cb) => Self::AresHostCallback(*cb),
            Self::AresCallback(cb) => Self::AresCallback(*cb),
            Self::AresCallbackDnsRec(cb) => Self::AresCallbackDnsRec(*cb),
            Self::AresNameinfoCallback(cb) => Self::AresNameinfoCallback(*cb),
            Self::AresAddrInfoCallback(ptr) => Self::AresAddrInfoCallback(*ptr),
            Self::HostByName(lookup) => Self::HostByName(lookup.clone()),
            Self::Search(lookup) => Self::Search(lookup.clone()),
            Self::Probe => Self::Probe,
        }
    }
}

#[derive(Debug)]
pub(crate) struct FFIData {
    pub(crate) callback: Callback,
    pub(crate) arg: *mut c_void,
    pub(crate) family: c_int,
    pub(crate) expected_record_type: c_int,
    pub(crate) ip: Option<IpAddr>,
    // nameinfo-specific fields
    pub(crate) nameinfo_flags: c_int,
    pub(crate) port: u16,
    pub(crate) scope_id: u32,
    pub(crate) server_index: usize,
    pub(crate) timeouts: c_int,
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() || hostname.is_null() {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
    }
    let channeldata = unsafe { &mut *channel };
    let hostname = unsafe { cstr_lossy(hostname) };

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
        };
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
                // On a cache-hit parse error, fall through to a fresh DNS query.
                if let Ok(mut parsed_rrs) = parsed {
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
            } else {
                channeldata.query_cache.remove(&cache_key);
            }
        }
    }

    // Build the search plan + state machine and launch the first query
    let _ = (expected_record_type, current_family); // family mapping now lives in HostByNameSm::new
    let use_tcp = channeldata.ares.config.options.use_vc;
    let plan = SearchPlan::for_gethostbyname(&resolved_name, channeldata.ares.config.options.ndots, &channeldata.ares.config.search);
    let query_hostname = plan.current.clone();
    let sm = HostByNameSm::new(plan, family, use_tcp);
    let (send_family, send_rtype) = (sm.current_family, sm.expected_rtype);
    let first_server = channeldata.server_health.pick_next();

    let lookup = Rc::new(RefCell::new(HostByNameLookup { sm, callback, arg }));

    launch_hostbyname_query(channeldata, &lookup, &query_hostname, send_family, send_rtype, use_tcp, first_server);

    // Server failover probing: if enabled, probe an expired-failure server in parallel
    maybe_launch_probe(channeldata, &query_hostname, send_family, first_server, use_tcp);
}

/// # Safety
/// `channel` must be a valid channel, `name` a valid NUL-terminated C string, and `host` a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    if channel.is_null() { return ARES_ENOTFOUND; }
    let channeldata = unsafe { &mut *channel };
    let name_str = unsafe { cstr_lossy(name) };

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
    let Some(lookup) = channeldata.ares.hosts().lookup(name_str, family_filter) else {
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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyaddr(channel: Channel, addr: *mut c_void, addrlen: c_int, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
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
    if channeldata.ares.enqueue(dns_query_payload(&rdns_name(addr), RECORD_TYPE_PTR), SocketSource::Udp, 0, ffidata).is_err() {
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut()) };
        return;
    }
    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
    if !invoke_sock_callbacks(channeldata, fd, libc::SOCK_DGRAM) {
        channeldata.ares.tasks.pop();
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut()) };
    }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_search(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let name_str = unsafe { cstr_lossy(name) };
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

    let _ = dnsclass;
    let plan = SearchPlan::for_search(name_str, channeldata.ares.config.options.ndots, &channeldata.ares.config.search);
    let query_hostname = plan.current.clone();
    let lookup = Rc::new(RefCell::new(SearchLookup {
        sm: SearchSm::new(plan, false),
        dnstype: dnstype as u16,
        delivery: SearchDelivery::Raw { callback, arg },
    }));

    let ffidata = FFIData {
        callback: Callback::Search(lookup),
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
    if channeldata.ares.enqueue(dns_query_payload(&query_hostname, dnstype as u16), SocketSource::Udp, 0, ffidata).is_err() {
        // Socket creation failed: deliver the error (the lookup state is
        // freed when its last Rc — inside the failed FFIData — drops).
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut(), 0) };
    }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, _dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    if channeldata.ares.config.nameservers.is_empty() {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut(), 0) };
        return;
    }
    let name = unsafe { cstr_lossy(name) };
    let ffidata = FFIData { callback: Callback::AresCallback(callback), arg, family: 0, expected_record_type: 0, ip: None, nameinfo_flags: 0, port: 0, scope_id: 0, server_index: 0, timeouts: 0 };
    if channeldata.ares.enqueue(dns_query_payload(name, dnstype as u16), SocketSource::Udp, 0, ffidata).is_err() {
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut(), 0) };
    }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query_dnsrec(
    channel: Channel,
    name: *const c_char,
    _dnsclass: c_int,
    dnstype: c_int,
    callback: ares_callback_dnsrec,
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
    let name = unsafe { cstr_lossy(name) };
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
    if channeldata.ares.enqueue(dns_query_payload(name, dnstype as u16), SocketSource::Udp, 0, ffidata).is_err() {
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut()) };
    }
}

/// # Safety
/// `channel` must be a valid channel and `dnsrec` a valid `ares_dns_record_t` pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_search_dnsrec(
    channel: Channel,
    dnsrec: *mut dns_record::ares_dns_record_t,
    callback: ares_callback_dnsrec,
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
    let name_str = cstr_lossy(name_ptr);

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

    let _ = qclass;
    let plan = SearchPlan::for_search(name_str, channeldata.ares.config.options.ndots, &channeldata.ares.config.search);
    let query_hostname = plan.current.clone();
    let lookup = Rc::new(RefCell::new(SearchLookup {
        sm: SearchSm::new(plan, true),
        dnstype: qtype as u16,
        delivery: SearchDelivery::DnsRec { callback, arg },
    }));

    let ffidata = FFIData {
        callback: Callback::Search(lookup),
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
    if channeldata.ares.enqueue(dns_query_payload(&query_hostname, qtype as u16), SocketSource::Udp, 0, ffidata).is_err() {
        // Socket creation failed: deliver the error (the lookup state is
        // freed when its last Rc — inside the failed FFIData — drops).
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut()) };
    }
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
pub unsafe extern "C" fn ares_getnameinfo(channel: Channel, sa: *const libc::sockaddr, salen: libc::socklen_t, flags: c_int, callback: ares_nameinfo_callback, arg: *mut c_void) {
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
        if channeldata.ares.enqueue(dns_query_payload(&rdns_name(addr_info.ip), RECORD_TYPE_PTR), SocketSource::Udp, 0, ffidata).is_err() {
            unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            return;
        }
        let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
        if !invoke_sock_callbacks(channeldata, fd, libc::SOCK_DGRAM) {
            channeldata.ares.tasks.pop();
            unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
        }
    }
}

/// Format an IP address with scope ID for IPv6 (e.g., "fe80::1%0")
pub(crate) fn format_ip_with_scope(ip: &IpAddr, scope_id: u32, flags: c_int) -> String {
    match ip {
        // The scope id is currently appended regardless of the flag/scope_id
        // check; the branches are intentionally identical for now.
        #[allow(clippy::if_same_then_else)]
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

/// Get the service string based on flags
pub(crate) fn get_service_string(services: &Services, port: u16, flags: c_int) -> Option<CString> {
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

pub(crate) fn run_ares_host_callback(res: Result<&[u8], c_int>, callback: AresHostCallback, ffidata: &FFIData) {
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

pub(crate) fn run_ares_callback(res: Result<&[u8], c_int>, callback: AresCallback, ffidata: &FFIData) {
    match res {
        Ok(buf) => unsafe { callback(ffidata.arg, ARES_SUCCESS, ffidata.timeouts, buf.as_ptr() as *mut u8, buf.len() as c_int) },
        Err(err) => unsafe { callback(ffidata.arg, err, ffidata.timeouts, std::ptr::null_mut(), 0) },
    }
}

pub(crate) fn run_ares_callback_dnsrec(res: Result<&[u8], c_int>, callback: AresCallbackDnsRec, ffidata: &FFIData) {
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

pub(crate) fn run_ares_nameinfo_callback(res: Result<&[u8], c_int>, callback: AresNameinfoCallback, ffidata: &FFIData) {
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

/// Send executor for the gethostbyname machine: reuse a pooled socket when
/// possible, otherwise create one — retrying across servers on socket-creation
/// or sock-callback failure (the failure accounting itself is ServerHealth's,
/// i.e. core, logic). Exhaustion delivers ECONNREFUSED; the lookup state is
/// freed when its last Rc drops.
pub(crate) unsafe fn launch_hostbyname_query(channeldata: &mut ChannelData, lookup: &Rc<RefCell<HostByNameLookup>>, hostname: &str, current_family: c_int, expected_record_type: u16, use_tcp: bool, server_index: usize) {
    let core_family = match current_family {
        libc::AF_INET => Family::Ipv4,
        _ => Family::Ipv6,
    };
    let max_tries = channeldata.ares.config.options.attempts as usize;
    let nservers = channeldata.server_health.len().max(1);
    let sock_type = if use_tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
    let mut si = server_index;
    let make_ffidata = |si: usize| FFIData {
        callback: Callback::HostByName(lookup.clone()),
        arg: std::ptr::null_mut(),
        family: current_family,
        expected_record_type: expected_record_type as c_int,
        ip: None,
        nameinfo_flags: 0,
        port: 0,
        scope_id: 0,
        server_index: si,
        timeouts: 0,
    };

    // TCP connection sharing: reuse existing TCP connection to same server
    if use_tcp {
        if let Some(idx) = channeldata.tcp_connections.iter().position(|(s, _)| *s == si) {
            let shared_sock = channeldata.tcp_connections[idx].1.clone();
            let _ = channeldata.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(DnsSocket::Tcp(shared_sock)), si, make_ffidata(si));
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
            let _ = channeldata.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::Shared(DnsSocket::Udp(shared_sock)), si, make_ffidata(si));
            return;
        }
        // No reusable connection — fall through to create a new one, then add to pool
    }

    for _try in 0..max_tries {
        let issued = channeldata.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), si, make_ffidata(si)).is_ok();
        if !issued {
            // Socket creation failed (e.g. fd exhaustion): treat as a server
            // failure and try the next server, like upstream c-ares.
            if nservers > 1 {
                channeldata.server_health.record_failure(si);
                si = channeldata.server_health.pick_next();
            }
            continue;
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
            channeldata.server_health.record_failure(si);
            si = channeldata.server_health.pick_next();
        }
    }
    // All retries exhausted
    let (callback, arg, timeouts) = {
        let mut l = lookup.borrow_mut();
        l.sm.last_error = ARES_ECONNREFUSED;
        (l.callback, l.arg, l.sm.timeouts)
    };
    unsafe { callback(arg, ARES_ECONNREFUSED, timeouts, std::ptr::null_mut()) };
}

/// Issue the next search-domain query for an `ares_search`. On socket-creation
/// failure, deliver ARES_ECONNREFUSED to the user and free the search state
/// (rather than panicking or leaking).
/// Re-issue a search query for the next name in the plan. On socket-creation
/// failure, deliver ECONNREFUSED directly (the lookup's remaining Rcs drop
/// naturally — no manual free).
pub(crate) unsafe fn issue_search_query(channeldata: &mut ChannelData, hostname: &str, dnstype: u16, lookup: Rc<RefCell<SearchLookup>>, timeouts: c_int) {
    let delivery = lookup.borrow().delivery;
    let new_ffidata = FFIData {
        callback: Callback::Search(lookup),
        arg: std::ptr::null_mut(), family: 0, expected_record_type: 0, ip: None,
        nameinfo_flags: 0, port: 0, scope_id: 0, server_index: 0, timeouts,
    };
    if channeldata.ares.enqueue(dns_query_payload(hostname, dnstype), SocketSource::Udp, 0, new_ffidata).is_err() {
        match delivery {
            SearchDelivery::Raw { callback, arg } => unsafe {
                callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut(), 0);
            },
            SearchDelivery::DnsRec { callback, arg } => unsafe {
                callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut());
            },
        }
    }
}

/// Executor for the search state machine: feed the event to `SearchSm::step`
/// (borrow held for the decision only), then perform the returned action —
/// re-issue the query or call the C callback — with all borrows dropped.
pub(crate) unsafe fn run_ares_search_callback(res: Result<&[u8], c_int>, lookup: &Rc<RefCell<SearchLookup>>, ffidata: &FFIData, channeldata: &mut ChannelData) {
    let ev = match res {
        Ok(buf) => LookupEvent::Reply(buf),
        Err(status) => LookupEvent::Error(status),
    };
    let (action, dnstype, delivery) = {
        let mut l = lookup.borrow_mut();
        (l.sm.step(ev), l.dnstype, l.delivery)
    };
    match action {
        SearchAction::Send(next_name) => {
            issue_search_query(channeldata, &next_name, dnstype, lookup.clone(), ffidata.timeouts);
        }
        SearchAction::DeliverSuccess => {
            let buf = res.unwrap_or(&[]); // DeliverSuccess is only emitted for Ok replies
            match delivery {
                SearchDelivery::Raw { callback, arg } => {
                    let buf_copy = buf.to_vec();
                    unsafe { callback(arg, ARES_SUCCESS, ffidata.timeouts, buf_copy.as_ptr() as *mut u8, buf_copy.len() as c_int) };
                }
                SearchDelivery::DnsRec { callback, arg } => {
                    // Parse and deliver as dns record
                    let mut dnsrec: *mut dns_record::ares_dns_record_t = std::ptr::null_mut();
                    let parse_status = unsafe { dns_record::ares_dns_parse(buf.as_ptr(), buf.len(), 0, &mut dnsrec) };
                    if parse_status == ARES_SUCCESS {
                        unsafe {
                            callback(arg, ARES_SUCCESS, ffidata.timeouts as usize, dnsrec);
                            dns_record::ares_dns_record_destroy(dnsrec);
                        }
                    } else {
                        unsafe { callback(arg, parse_status, ffidata.timeouts as usize, std::ptr::null_mut()) };
                    }
                }
            }
        }
        SearchAction::DeliverFail(status) => match delivery {
            SearchDelivery::Raw { callback, arg } => unsafe {
                callback(arg, status, ffidata.timeouts, std::ptr::null_mut(), 0);
            },
            SearchDelivery::DnsRec { callback, arg } => unsafe {
                callback(arg, status, ffidata.timeouts as usize, std::ptr::null_mut());
            },
        },
    }
}

/// Executor for the gethostbyname state machine: parse the reply (parsing and
/// hostent building stay ffi-side), feed the event to `HostByNameSm::step`
/// (borrow held for the decision only), then perform the returned actions.
pub(crate) unsafe fn run_ares_hostbyname_callback(res: Result<&[u8], c_int>, lookup: &Rc<RefCell<HostByNameLookup>>, ffidata: &FFIData, channeldata: &mut ChannelData) {
    // Parse outside the machine; the machine sees only the outcome.
    let mut parsed_items: Option<ParsedRRs<AddrRecord>> = None;
    let ev = match res {
        Ok(buf) => {
            let expected_rtype = lookup.borrow().sm.expected_rtype;
            let parse = (|| -> Result<ParsedRRs<AddrRecord>, c_int> {
                let response = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = response.process_answers::<AddrRecord>(buf, expected_rtype)?;
                if parsed_rrs.items.is_empty() {
                    return Err(ARES_ENODATA);
                }
                Ok(parsed_rrs)
            })();
            let outcome = match parse {
                Ok(rrs) => {
                    parsed_items = Some(rrs);
                    Ok(())
                }
                Err(e) => Err(e),
            };
            HostEvent::Reply {
                truncated: is_truncated(buf),
                parse: outcome,
                io_timeouts: ffidata.timeouts,
                server: ffidata.server_index,
            }
        }
        Err(status) => HostEvent::Error { status },
    };

    let actions = {
        let cfg = LookupCfg {
            attempts: channeldata.ares.config.options.attempts,
            ndots: channeldata.ares.config.options.ndots,
            search: &channeldata.ares.config.search,
        };
        let mut l = lookup.borrow_mut();
        l.sm.step(ev, &cfg, &mut channeldata.server_health)
    };

    for action in actions {
        match action {
            HostAction::Send { name, family, rtype, tcp, server } => {
                launch_hostbyname_query(channeldata, lookup, &name, family, rtype, tcp, server);
            }
            HostAction::NotifyServerFail { server, tcp } => {
                invoke_server_state_callback(channeldata, server, false, tcp);
            }
            HostAction::CacheStore { names, rtype } => {
                if channeldata.query_cache_max_ttl > 0 {
                    if let (Ok(buf), Some(rrs)) = (&res, &parsed_items) {
                        let ttl = rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        let cache_ttl = std::cmp::min(ttl, channeldata.query_cache_max_ttl);
                        if cache_ttl > 0 {
                            let expires = Instant::now() + Duration::from_secs(cache_ttl as u64);
                            for name in names {
                                channeldata.query_cache.insert((name, rtype), (buf.to_vec(), expires));
                            }
                        }
                    }
                }
            }
            HostAction::DeliverSuccess { family, timeouts } => {
                let Some(mut rrs) = parsed_items.take() else { continue };
                if !channeldata.sortlist.is_empty() {
                    apply_sortlist(&channeldata.sortlist, &mut rrs.items);
                }
                let hostent = rrs.into_raw_hostent(family);
                let (callback, arg) = { let l = lookup.borrow(); (l.callback, l.arg) };
                unsafe { callback(arg, ARES_SUCCESS, timeouts, hostent) };
                ares_free_hostent(hostent);
            }
            HostAction::DeliverFail { status, timeouts } => {
                let (callback, arg) = { let l = lookup.borrow(); (l.callback, l.arg) };
                unsafe { callback(arg, status, timeouts, std::ptr::null_mut()) };
            }
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_getaddrinfo(
    channel: Channel,
    name: *const c_char,
    service: *const c_char,
    hints: *const ares_addrinfo_hints,
    callback: ares_addrinfo_callback,
    arg: *mut c_void,
) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };

    let ai_family = if hints.is_null() { libc::AF_UNSPEC } else { unsafe { (*hints).ai_family } };

    // Resolve service name to port number
    let port: u16 = if !service.is_null() {
        let svc = cstr_lossy(service);
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

    let hostname_raw = unsafe { cstr_lossy(name) };
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
    let first_server = channeldata.server_health.pick_next();

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

pub(crate) unsafe fn launch_addrinfo_queries(channeldata: &mut ChannelData, state: *mut AddrInfoState, hostname: &str, ai_family: c_int, use_tcp: bool, server_index: usize) {
    // Account for the whole batch up front so a per-query failure can't drive
    // `pending` to 0 prematurely (which would finalize/free the state before the
    // other query of an AF_UNSPEC pair is launched).
    unsafe {
        (*state).pending += match ai_family {
            libc::AF_INET | libc::AF_INET6 => 1,
            _ => 2,
        };
    }
    let mut launch_query = |record_type: u16, core_family: Family, family_c: c_int| {
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
        let issued = channeldata.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), server_index, ffidata).is_ok();
        if !issued {
            // Socket creation failed: this query won't launch. Account for it and,
            // if it was the last outstanding query, deliver the error now (the same
            // finalize the Callback::run path does when pending reaches 0).
            let st = unsafe { &mut *state };
            st.pending -= 1;
            st.last_error = ARES_ECONNREFUSED;
            if st.pending == 0 {
                free_addrinfo_nodes(st.nodes_head);
                unsafe { (st.callback)(st.arg, st.last_error, 0, std::ptr::null_mut()) };
                unsafe { drop(Box::from_raw(state)) };
            }
            return;
        }
        let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
        if !invoke_sock_callbacks(channeldata, fd, sock_type) {
            // Configure callback failed - mark task as completed with error
            let task = channeldata.ares.tasks.last_mut().unwrap();
            task.status = Status::Completed;
            let st = unsafe { &mut *state };
            st.pending -= 1;
            st.last_error = ARES_ECONNREFUSED;
            if st.pending == 0 {
                free_addrinfo_nodes(st.nodes_head);
                unsafe { (st.callback)(st.arg, st.last_error, 0, std::ptr::null_mut()) };
                unsafe { drop(Box::from_raw(state)) };
            }
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

/// Launch a probe query to an expired-failure server in parallel with the primary query.
pub(crate) unsafe fn maybe_launch_probe(
    channeldata: &mut ChannelData,
    hostname: &str,
    family: c_int,
    primary_server: usize,
    use_tcp: bool,
) {
    if channeldata.server_failover_retry_chance == 0 {
        return;
    }
    let probe_server = match channeldata.server_health.pick_probe(
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
    let ffidata = FFIData {
        callback: Callback::Probe,
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
    let issued = channeldata.ares.enqueue(dns_query_payload(hostname, qtype_of(core_family)), SocketSource::fresh(use_tcp), probe_server, ffidata).is_ok();
    // A probe has no user callback; if its socket can't be created, just skip it.
    if issued {
        let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
        invoke_sock_callbacks(channeldata, fd, sock_type);
    }
}

/// Callback for server failover probe queries — updates server state, no user callback.
pub(crate) unsafe fn run_probe_callback(res: Result<&[u8], c_int>, channeldata: &mut ChannelData, ffidata: &FFIData) {
    let si = ffidata.server_index;
    match res {
        Ok(buf) => {
            // Check DNS rcode
            let rcode = if buf.len() >= 4 { buf[3] & 0x0f } else { 0xff };
            if rcode == 0 || rcode == 3 {
                // Success or NXDOMAIN — server is alive, reset failure state
                if channeldata.server_health.record_success(si) {
                    invoke_server_state_callback(channeldata, si, true, false);
                }
            } else {
                // SERVFAIL/NOTIMP/REFUSED — still failing
                if channeldata.server_health.record_failure(si) {
                    invoke_server_state_callback(channeldata, si, false, false);
                }
            }
        }
        Err(_) => {
            // Timeout or other error — update failure timestamp
            channeldata.server_health.record_failure_time(si);
        }
    }
}

pub(crate) unsafe fn run_ares_addrinfo_callback(res: Result<&[u8], c_int>, state_ptr: *mut AddrInfoState, ffidata: &FFIData) {
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
                if channeldata.ares.enqueue(dns_query_payload(&state.name, qtype_of(core_family)), SocketSource::Tcp, ffidata.server_index, new_ffidata).is_ok() {
                    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                    invoke_sock_callbacks(channeldata, fd, libc::SOCK_STREAM);
                } else {
                    // TCP retry socket couldn't be created — finalize this query with the error.
                    state.pending -= 1;
                    if state.pending == 0 {
                        state.last_error = ARES_ECONNREFUSED;
                        free_addrinfo_nodes(state.nodes_head);
                        (state.callback)(state.arg, state.last_error, 0, std::ptr::null_mut());
                        drop(Box::from_raw(state_ptr));
                    }
                }
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
                    channeldata.server_health.record_success(ffidata.server_index);
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
                    let nservers = channeldata.server_health.len();
                    let max_attempts = std::cmp::max(nservers, 1) * channeldata.ares.config.options.attempts as usize;
                    if (e == ARES_ESERVFAIL || e == ARES_ENOTIMP || e == ARES_EREFUSED)
                        && nservers >= 1
                    {
                        // Increment failure counter for this server
                        channeldata.server_health.record_failure(ffidata.server_index);
                        state.attempt_count += 1;

                        if state.attempt_count < max_attempts {
                            // Re-sort by (failure_count, index) and pick top server
                            let next_server = channeldata.server_health.pick_next();
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
                            let issued = channeldata.ares.enqueue(dns_query_payload(&state.name, qtype_of(core_family)), SocketSource::fresh(state.use_tcp), next_server, new_ffidata).is_ok();
                            if issued {
                                let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                                invoke_sock_callbacks(channeldata, fd, sock_type);
                                // Success: the new task replaces this one; keep pending as-is.
                            } else {
                                // Retry socket couldn't be created — finalize this query with the error.
                                state.pending -= 1;
                                if state.pending == 0 {
                                    state.last_error = ARES_ECONNREFUSED;
                                    free_addrinfo_nodes(state.nodes_head);
                                    (state.callback)(state.arg, state.last_error, 0, std::ptr::null_mut());
                                    drop(Box::from_raw(state_ptr));
                                }
                            }
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

            let first_server = channeldata.server_health.pick_next();
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

            let first_server = channeldata.server_health.pick_next();
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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_send(channel: Channel, qbuf: *const u8, qlen: c_int, callback: ares_callback, arg: *mut c_void) {
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
    if channeldata.ares.enqueue(BytesMut::from(query_buf), SocketSource::Udp, 0, ffidata).is_err() {
        unsafe { callback(arg, ARES_ECONNREFUSED, 0, std::ptr::null_mut(), 0) };
    }
}

