//! Lookup entry points (gethostbyname/getaddrinfo/search/query/send/...)
//! and their per-query state + callback dispatch.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::ffi::kernels::process::cache_store_names;
use crate::ffi::kernels::lookups::{
    format_ip_with_scope, get_service_string, getaddrinfo_preflight, gethostbyname_preflight,
    cached_reply, gethostbyaddr_preflight, getnameinfo_preflight, hosts_file_lookup, no_servers,
    search_name_check, search_start, well_known_port, AddrInfoPreflight, AddrPreflight,
    HostPreflight, NameinfoPreflight,
};


/// Live state of an ares_gethostbyname lookup: the pure state machine plus
/// the C callback to deliver to.
#[derive(Debug)]
pub(crate) struct HostByNameLookup {
    pub(crate) sm: HostByNameSm,
    pub(crate) callback: AresHostCallback,
    pub(crate) arg: *mut c_void,
}

/// Live state of an ares_getaddrinfo lookup: the pure state machine plus
/// what the executor needs to deliver (records are accumulated as safe
/// AddrRecords in the machine; the C node list is built once, at delivery).
#[derive(Debug)]
pub(crate) struct AddrInfoLookup {
    pub(crate) sm: AddrInfoSm,
    pub(crate) callback: AresAddrInfoCallback,
    pub(crate) arg: *mut c_void,
    pub(crate) port: u16,
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

#[derive(Debug, Clone)]
// Variants are named after the c-ares FFI callback typedefs they dispatch to;
// the shared `Callback` suffix is intentional for that correspondence.
#[allow(clippy::enum_variant_names)]
pub(crate) enum Callback {
    AresHostCallback(AresHostCallback),
    AresCallback(AresCallback),
    AresCallbackDnsRec(AresCallbackDnsRec),
    AresNameinfoCallback(AresNameinfoCallback),
    AddrInfo(Rc<RefCell<AddrInfoLookup>>),
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
            Self::AddrInfo(lookup) => run_ares_addrinfo_callback(buf, lookup, ffidata, channeldata),
            Self::HostByName(lookup) => run_ares_hostbyname_callback(buf, lookup, ffidata, channeldata),
            Self::Search(lookup) => run_ares_search_callback(buf, lookup, ffidata, channeldata),
            Self::Probe => run_probe_callback(buf, channeldata, ffidata),
        }
    }
    /// Which reactor-level policies apply to a task carrying this callback.
    pub(crate) fn kind(&self) -> TaskKind {
        match self {
            Self::AddrInfo(_) => TaskKind::AddrInfo,
            Self::HostByName(_) => TaskKind::HostByName,
            Self::Search(_) => TaskKind::Search,
            Self::Probe => TaskKind::Probe,
            _ => TaskKind::Other,
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

    match gethostbyname_preflight(channeldata, hostname, family, Instant::now()) {
        HostPreflight::Fail(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        }
        HostPreflight::DeliverHost(lookup) => {
            let hostent = unsafe { hostent_from_lookup(lookup) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
        }
        HostPreflight::DeliverParsed(parsed_rrs, hostent_family) => {
            let hostent = unsafe { parsed_rrs.into_raw_hostent(hostent_family) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
        }
        HostPreflight::StartDns { sm, query_hostname, first_server, use_tcp } => {
            let (send_family, send_rtype) = (sm.current_family, sm.expected_rtype);
            let lookup = Rc::new(RefCell::new(HostByNameLookup { sm, callback, arg }));
            launch_hostbyname_query(channeldata, &lookup, &query_hostname, send_family, send_rtype, use_tcp, first_server);
            // Server failover probing: if enabled, probe an expired-failure server in parallel
            maybe_launch_probe(channeldata, &query_hostname, send_family, first_server, use_tcp);
        }
    }
}

/// # Safety
/// `channel` must be a valid channel, `name` a valid NUL-terminated C string, and `host` a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    if channel.is_null() { return ARES_ENOTFOUND; }
    let channeldata = unsafe { &mut *channel };
    let name_str = unsafe { cstr_lossy(name) };

    match hosts_file_lookup(channeldata, name_str, family) {
        Ok(lookup) => {
            unsafe { *host = hostent_from_lookup(lookup) };
            ARES_SUCCESS
        }
        Err(status) => {
            unsafe { *host = std::ptr::null_mut() };
            status
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyaddr(channel: Channel, addr: *mut c_void, addrlen: c_int, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    // NULL/negative-length buffers report the same ENOTIMP the family check
    // does, so guarding here first is observably identical.
    if addr.is_null() || addrlen < 0 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let addrbuf = unsafe { std::slice::from_raw_parts(addr as *mut u8, addrlen as usize) };
    let addr = match gethostbyaddr_preflight(channeldata, addrbuf, family) {
        AddrPreflight::Fail(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
            return;
        }
        AddrPreflight::DeliverHost(lookup) => {
            let hostent = unsafe { hostent_from_lookup(lookup) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
            return;
        }
        AddrPreflight::StartPtr(addr) => addr,
    };

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
    if let Some(status) = search_name_check(name_str) {
        unsafe { callback(arg, status, 0, std::ptr::null_mut(), 0) };
        return;
    }

    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    let _ = dnsclass;
    let (sm, query_hostname) = match search_start(channeldata, name_str, false) {
        Ok(seed) => seed,
        Err(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), 0) };
            return;
        }
    };
    let lookup = Rc::new(RefCell::new(SearchLookup {
        sm,
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
    if no_servers(channeldata) {
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
    if no_servers(channeldata) {
        unsafe { callback(arg, ARES_ENOSERVER, 0, std::ptr::null_mut()) };
        return;
    }
    let name = unsafe { cstr_lossy(name) };
    let name_clean = name.strip_suffix('.').unwrap_or(name);

    // Query-cache probe; a cached reply that fails to parse falls through
    // to a fresh DNS query (same as before the kernel split).
    if let Some(cached_buf) = cached_reply(channeldata, name_clean, dnstype as u16, Instant::now()) {
        if let Ok(rec) = dns_record::parse_record(&cached_buf) {
            let dnsrec = Box::into_raw(Box::new(rec));
            unsafe { callback(arg, ARES_SUCCESS, 0, dnsrec) };
            unsafe { dns_record::ares_dns_record_destroy(dnsrec) };
            return;
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
    // Extract the first query's name/type through the record's safe accessors.
    let rec = unsafe { &*dnsrec };
    let mut name_ptr: *const c_char = std::ptr::null();
    let mut qtype: c_uint = 0;
    if rec.query_cnt() > 0 {
        if let Some((q_name, q_type, _qclass)) = rec.query_at(0) {
            name_ptr = q_name;
            qtype = q_type as c_uint;
        }
    }
    if name_ptr.is_null() { return; }
    let name_str = unsafe { cstr_lossy(name_ptr) };

    if let Some(status) = search_name_check(name_str) {
        unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        return;
    }

    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    let (sm, query_hostname) = match search_start(channeldata, name_str, true) {
        Ok(seed) => seed,
        Err(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
            return;
        }
    };
    let lookup = Rc::new(RefCell::new(SearchLookup {
        sm,
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

    match getnameinfo_preflight(channeldata, &addr_info, flags) {
        NameinfoPreflight::Fail(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
        }
        NameinfoPreflight::DeliverService(service) => {
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, std::ptr::null_mut(), service_ptr) };
        }
        NameinfoPreflight::DeliverNumeric { node, service } => {
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, node.into_raw(), service_ptr) };
        }
        NameinfoPreflight::StartPtr { flags } => {
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
pub(crate) fn launch_hostbyname_query(channeldata: &mut ChannelData, lookup: &Rc<RefCell<HostByNameLookup>>, hostname: &str, current_family: c_int, expected_record_type: u16, use_tcp: bool, server_index: usize) {
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
pub(crate) fn issue_search_query(channeldata: &mut ChannelData, hostname: &str, dnstype: u16, lookup: Rc<RefCell<SearchLookup>>, timeouts: c_int) {
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
pub(crate) fn run_ares_search_callback(res: Result<&[u8], c_int>, lookup: &Rc<RefCell<SearchLookup>>, ffidata: &FFIData, channeldata: &mut ChannelData) {
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
pub(crate) fn run_ares_hostbyname_callback(res: Result<&[u8], c_int>, lookup: &Rc<RefCell<HostByNameLookup>>, ffidata: &FFIData, channeldata: &mut ChannelData) {
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
                        cache_store_names(&mut channeldata.query_cache, channeldata.query_cache_max_ttl, names, rtype, ttl, buf, Instant::now());
                    }
                }
            }
            HostAction::DeliverSuccess { family, timeouts } => {
                let Some(mut rrs) = parsed_items.take() else { continue };
                if !channeldata.sortlist.is_empty() {
                    apply_sortlist(&channeldata.sortlist, &mut rrs.items);
                }
                let hostent = unsafe { rrs.into_raw_hostent(family) };
                let (callback, arg) = { let l = lookup.borrow(); (l.callback, l.arg) };
                unsafe { callback(arg, ARES_SUCCESS, timeouts, hostent) };
                unsafe { ares_free_hostent(hostent) };
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

    // Resolve service name to port number (table in the kernel; the
    // libc::getservbyname fallback is inherently a C call, so it stays here)
    let port: u16 = if !service.is_null() {
        let svc = unsafe { cstr_lossy(service) };
        if let Ok(p) = svc.parse::<u16>() {
            p
        } else if let Some(p) = well_known_port(svc) {
            p
        } else {
            let c_svc = unsafe { CStr::from_ptr(service) };
            let result = unsafe { libc::getservbyname(c_svc.as_ptr(), std::ptr::null()) };
            if !result.is_null() {
                unsafe { u16::from_be((*result).s_port as u16) }
            } else {
                0
            }
        }
    } else {
        0
    };

    let hostname_raw = unsafe { cstr_lossy(name) };

    match getaddrinfo_preflight(channeldata, hostname_raw, ai_family) {
        AddrInfoPreflight::Fail(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        }
        AddrInfoPreflight::DeliverAddrs { addrs, canonical } => {
            let nodes = addrinfo_nodes_from_addrs_port(&addrs, ai_family, port);
            let ai = build_ares_addrinfo(&canonical, nodes);
            unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
        }
        AddrInfoPreflight::StartDns { sm, first_server } => {
            let lookup = Rc::new(RefCell::new(AddrInfoLookup { sm, callback, arg, port }));
            let actions = lookup.borrow_mut().sm.begin_batch(first_server);
            execute_addrinfo_actions(channeldata, &lookup, actions);
        }
    }
}

/// Send executor for the getaddrinfo machine. Executes the actions returned
/// by `AddrInfoSm`, feeding send failures back into the machine
/// (`LaunchFailed` for batch sends — which also run the socket callbacks —
/// `ResendFailed` for TC/failover re-sends, whose socket-callback results
/// are ignored, both as historically).
pub(crate) fn execute_addrinfo_actions(channeldata: &mut ChannelData, lookup: &Rc<RefCell<AddrInfoLookup>>, actions: Vec<AddrInfoAction>) {
    let mut queue: std::collections::VecDeque<AddrInfoAction> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            AddrInfoAction::Send { name, family, tcp, server, timeouts, batch } => {
                let core_family = match family {
                    libc::AF_INET => Family::Ipv4,
                    _ => Family::Ipv6,
                };
                let ffidata = FFIData {
                    callback: Callback::AddrInfo(lookup.clone()),
                    arg: std::ptr::null_mut(),
                    family,
                    expected_record_type: (if family == libc::AF_INET { RECORD_TYPE_A } else { RECORD_TYPE_AAAA }) as c_int,
                    ip: None,
                    nameinfo_flags: 0,
                    port: 0,
                    scope_id: 0,
                    server_index: server,
                    timeouts,
                };
                let sock_type = if tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                let issued = channeldata.ares.enqueue(dns_query_payload(&name, qtype_of(core_family)), SocketSource::fresh(tcp), server, ffidata).is_ok();
                let failed = if !issued {
                    true
                } else if batch {
                    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                    if invoke_sock_callbacks(channeldata, fd, sock_type) {
                        false
                    } else {
                        // Configure callback failed - mark task as completed with error
                        channeldata.ares.tasks.last_mut().unwrap().status = Status::Completed;
                        true
                    }
                } else {
                    // TC/failover re-send: socket-callback results are ignored
                    let fd = channeldata.ares.tasks.last().unwrap().sock.as_raw_fd();
                    invoke_sock_callbacks(channeldata, fd, sock_type);
                    false
                };
                if failed {
                    let ev = if batch { AddrInfoEvent::LaunchFailed } else { AddrInfoEvent::ResendFailed };
                    let more = {
                        let cfg = LookupCfg {
                            attempts: channeldata.ares.config.options.attempts,
                            ndots: channeldata.ares.config.options.ndots,
                            search: &channeldata.ares.config.search,
                        };
                        let mut l = lookup.borrow_mut();
                        l.sm.step(ev, &cfg, &mut channeldata.server_health)
                    };
                    queue.extend(more);
                }
            }
            AddrInfoAction::DeliverSuccess { name } => {
                let (callback, arg, records, port) = {
                    let mut l = lookup.borrow_mut();
                    (l.callback, l.arg, std::mem::take(&mut l.sm.addrs), l.port)
                };
                let nodes = nodes_from_addr_records(&records, port);
                let ai = build_ares_addrinfo(&name, nodes);
                unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
            }
            AddrInfoAction::DeliverFail { status } => {
                let (callback, arg) = { let l = lookup.borrow(); (l.callback, l.arg) };
                unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
            }
        }
    }
}

/// Launch a probe query to an expired-failure server in parallel with the primary query.
pub(crate) fn maybe_launch_probe(
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
pub(crate) fn run_probe_callback(res: Result<&[u8], c_int>, channeldata: &mut ChannelData, ffidata: &FFIData) {
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

/// Executor entry for a settled getaddrinfo task: parse the reply (parsing
/// stays ffi-side), feed the event to `AddrInfoSm::step` (borrow held for the
/// decision only), then perform the returned actions borrow-free.
pub(crate) fn run_ares_addrinfo_callback(res: Result<&[u8], c_int>, lookup: &Rc<RefCell<AddrInfoLookup>>, ffidata: &FFIData, channeldata: &mut ChannelData) {
    let ev = match res {
        Ok(buf) => {
            let parse = (|| -> Result<Vec<AddrRecord>, c_int> {
                let response = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = response.process_answers::<AddrRecord>(buf, ffidata.expected_record_type as u16)?;
                if parsed_rrs.items.is_empty() {
                    return Err(ARES_ENODATA);
                }
                Ok(parsed_rrs.items)
            })();
            AddrInfoEvent::Reply {
                truncated: is_truncated(buf),
                parse,
                family: ffidata.family,
                server: ffidata.server_index,
                io_timeouts: ffidata.timeouts,
            }
        }
        Err(status) => AddrInfoEvent::Error { status },
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
    execute_addrinfo_actions(channeldata, lookup, actions);
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
    if no_servers(channeldata) {
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

