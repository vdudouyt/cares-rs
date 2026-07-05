//! Lookup entry points (gethostbyname/getaddrinfo/search/query/send/...)
//! and their per-query state + callback dispatch.

use super::*;
use crate::core::api;
use crate::core::AresError;
use crate::core::ares::{Task, TaskMachine};
use crate::core::launch::{drive_addrinfo, AddrInfoDelivery};
use crate::core::preflight::{assemble_nameinfo, service_to_port, ServicePort};


/// The Copy delivery tail of an ares_gethostbyname lookup: where results go
/// once the shared, core-minted HostByNameSm settles. Bare fn pointer +
/// opaque arg are Copy; only *calling* them is unsafe.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HostTail {
    pub(crate) callback: AresHostCallback,
    pub(crate) arg: *mut c_void,
}

/// The Copy delivery tail of an ares_getaddrinfo lookup (the service port
/// travels with it into the node list built at delivery).
#[derive(Debug, Clone, Copy)]
pub(crate) struct AddrInfoTail {
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

/// The Copy delivery tail of an ares_search / ares_search_dnsrec lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SearchTail {
    pub(crate) dnstype: u16,
    pub(crate) delivery: SearchDelivery,
}

#[derive(Debug, Clone, Copy)]
// Variants are named after the c-ares FFI callback typedefs they dispatch to;
// the shared `Callback` suffix is intentional for that correspondence.
// Stateful lookups carry only their Copy C delivery tail here; the shared
// state-machine handle lives on the core `Task` (`Task.machine`), so this
// enum is a plain binding the shim builds and core clones per task.
#[allow(clippy::enum_variant_names)]
pub(crate) enum Callback {
    AresHostCallback(AresHostCallback),
    AresCallback(AresCallback),
    AresCallbackDnsRec(AresCallbackDnsRec),
    AresNameinfoCallback(AresNameinfoCallback),
    AddrInfo(AddrInfoTail),
    HostByName(HostTail),
    Search(SearchTail),
}

impl Callback {
    pub(crate) fn run(&self, buf: Result<&[u8], c_int>, task: &crate::core::ares::Task<FFIData>, channeldata: &mut ChannelData) {
        // A probe carries a copy of the lookup's binding but must never reach
        // the user callback: route it to the probe handler (and stay silent on
        // cancel/destroy). This is checked before the teardown dispatch below,
        // which keys off the (real) callback kind.
        if matches!(task.machine, TaskMachine::Probe) {
            if let Err(status) = &buf {
                if *status == ARES_EDESTRUCTION || *status == ARES_ECANCELLED { return; }
            }
            return run_probe_callback(buf, channeldata, task);
        }
        // Cancel/destroy deliveries follow the core policy table.
        if let Err(status) = &buf {
            if *status == ARES_EDESTRUCTION || *status == ARES_ECANCELLED {
                match teardown_delivery(self.kind()) {
                    TeardownDelivery::DeliverNull => {
                        match self {
                            Self::HostByName(tail) => {
                                unsafe { (tail.callback)(tail.arg, *status, 0, std::ptr::null_mut()) };
                            }
                            Self::Search(tail) => match tail.delivery {
                                SearchDelivery::Raw { callback, arg } => unsafe {
                                    callback(arg, *status, task.timeouts, std::ptr::null_mut(), 0);
                                },
                                SearchDelivery::DnsRec { callback, arg } => unsafe {
                                    callback(arg, *status, task.timeouts as usize, std::ptr::null_mut());
                                },
                            },
                            _ => unreachable!("core maps DeliverNull only to HostByName/Search"),
                        }
                        return;
                    }
                    TeardownDelivery::Silent => return,
                    TeardownDelivery::Full => {}
                }
            }
        }
        match self {
            Self::AresHostCallback(callback) => run_ares_host_callback(buf, *callback, task),
            Self::AresCallback(callback) => run_ares_callback(buf, *callback, task),
            Self::AresCallbackDnsRec(callback) => run_ares_callback_dnsrec(buf, *callback, task),
            Self::AresNameinfoCallback(callback) => run_ares_nameinfo_callback(buf, *callback, task),
            Self::AddrInfo(tail) => run_ares_addrinfo_callback(buf, *tail, task, channeldata),
            Self::HostByName(tail) => run_ares_hostbyname_callback(buf, *tail, task, channeldata),
            Self::Search(tail) => run_ares_search_callback(buf, *tail, task, channeldata),
        }
    }
    /// Which reactor-level policies apply to a task carrying this callback.
    pub(crate) fn kind(&self) -> TaskKind {
        match self {
            Self::AddrInfo(..) => TaskKind::AddrInfo,
            Self::HostByName(..) => TaskKind::HostByName,
            Self::Search(..) => TaskKind::Search,
            _ => TaskKind::Other,
        }
    }
    /// Whether a delivered reply should populate the query cache: plain dnsrec
    /// queries and dnsrec-delivery searches.
    pub(crate) fn wants_dnsrec_cache(&self) -> bool {
        match self {
            Self::AresCallbackDnsRec(_) => true,
            Self::Search(tail) => matches!(tail.delivery, SearchDelivery::DnsRec { .. }),
            _ => false,
        }
    }
}

/// The reactor's view of a task's kind: a failover probe (marked on the core
/// `Task`, carrying a copy of the lookup's binding) reads as `Probe`;
/// everything else defers to its `Callback`.
pub(crate) fn task_kind(task: &Task<FFIData>) -> TaskKind {
    if matches!(task.machine, TaskMachine::Probe) {
        TaskKind::Probe
    } else {
        task.userdata.callback.kind()
    }
}

/// The C-binding half of a task's userdata: only what the reply needs to
/// fire the user's C callback. All per-task core data (state-machine handle,
/// family/record-type, server, timeouts, queried ip) lives on the core
/// `Task`, so this is a plain value the shim builds eagerly and core clones
/// per task — no factory closure.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FFIData {
    pub(crate) callback: Callback,
    pub(crate) arg: *mut c_void,
    pub(crate) ip: Option<IpAddr>,
    // nameinfo-specific fields
    pub(crate) nameinfo_flags: c_int,
    pub(crate) port: u16,
    pub(crate) scope_id: u32,
}

impl FFIData {
    /// A blank userdata around `callback` — entry shims override the fields
    /// their flow needs via struct-update syntax.
    pub(crate) fn base(callback: Callback) -> FFIData {
        FFIData {
            callback,
            arg: std::ptr::null_mut(),
            ip: None,
            nameinfo_flags: 0,
            port: 0,
            scope_id: 0,
        }
    }
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
    // One plain binding (no factory closure); the failover probe reuses a copy
    // of it, marked TaskMachine::Probe by core so its reply never fires the callback.
    let binding = FFIData::base(Callback::HostByName(HostTail { callback, arg }));
    match api::gethostbyname(&mut channeldata.state, hostname, family, Instant::now(), binding) {
        Err(status) => {
            unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        }
        Ok(api::Operation::Ready(bp)) => {
            let hostent = unsafe { build_hostent(bp) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
        }
        Ok(api::Operation::Pending) => {}
    }
}

/// # Safety
/// `channel` must be a valid channel, `name` a valid NUL-terminated C string, and `host` a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENOTFOUND; };
    let name_str = unsafe { cstr_lossy(name) };

    match api::gethostbyname_file(&mut channeldata.state, name_str, family) {
        Ok(bp) => {
            unsafe { *host = build_hostent(bp) };
            ARES_SUCCESS
        }
        Err(status) => {
            unsafe { *host = std::ptr::null_mut() };
            status.code()
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyaddr(channel: Channel, addr: *mut c_void, addrlen: c_int, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    // NULL/negative-length buffers report the same ENOTIMP the family check
    // does, so guarding here first is observably identical.
    if addr.is_null() || addrlen < 0 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let addrbuf = unsafe { std::slice::from_raw_parts(addr as *mut u8, addrlen as usize) };
    // Built eagerly and passed by value — no factory closure. The queried
    // address, family and record type are core-owned (Task.queried_ip /
    // family / rtype), set by the handler, so they're not in the binding.
    let userdata = FFIData {
        arg,
        ..FFIData::base(Callback::AresHostCallback(callback))
    };
    match api::gethostbyaddr(&mut channeldata.state, addrbuf, family, userdata) {
        Err(status) => {
            unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        }
        Ok(api::Operation::Ready(bp)) => {
            let hostent = unsafe { build_hostent(bp) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
        }
        Ok(api::Operation::Pending) => {}
    }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_search(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let name_str = unsafe { cstr_lossy(name) };
    // Name sanity precedes the channel deref: a bad name reports even on a
    // NULL channel (upstream ordering), so this one check runs pre-state.
    if let Some(status) = api::search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) };
        return;
    }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let _ = dnsclass;
    let tail = SearchTail { dnstype: dnstype as u16, delivery: SearchDelivery::Raw { callback, arg } };
    let binding = FFIData::base(Callback::Search(tail));
    if let Err(status) = api::search(&mut channeldata.state, name_str, dnstype as u16, false, binding) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) };
    }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, _dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let name = unsafe { cstr_lossy(name) };
    let ffidata = FFIData { arg, ..FFIData::base(Callback::AresCallback(callback)) };
    if let Err(status) = api::query(&mut channeldata.state, name, dnstype as u16, ffidata) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) };
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
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let name = unsafe { cstr_lossy(name) };
    let ffidata = FFIData { arg, ..FFIData::base(Callback::AresCallbackDnsRec(callback)) };
    match api::query_dnsrec(&mut channeldata.state, name, dnstype as u16, Instant::now(), ffidata) {
        Err(status) => {
            unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        }
        Ok(api::Operation::Ready(rec)) => {
            let dnsrec = Box::into_raw(Box::new(rec));
            unsafe { callback(arg, ARES_SUCCESS, 0, dnsrec) };
            unsafe { dns_record::ares_dns_record_destroy(dnsrec) };
        }
        Ok(api::Operation::Pending) => {}
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
    let mut query_name: Option<&CStr> = None;
    let mut qtype: c_uint = 0;
    if rec.query_cnt() > 0 {
        if let Some((q_name, q_type, _qclass)) = rec.query_at(0) {
            query_name = Some(q_name);
            qtype = q_type as c_uint;
        }
    }
    let Some(query_name) = query_name else { return; };
    let name_str = query_name.to_str().unwrap_or("");

    // Same pre-state ordering as ares_search: bad names report before the
    // channel is dereferenced.
    if let Some(status) = api::search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        return;
    }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let tail = SearchTail { dnstype: qtype as u16, delivery: SearchDelivery::DnsRec { callback, arg } };
    let binding = FFIData::base(Callback::Search(tail));
    if let Err(status) = api::search(&mut channeldata.state, name_str, qtype as u16, true, binding) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
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
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };

    // Extract IP address and port from sockaddr
    let addr_info = match extract_addr_port(sa, salen) {
        Ok(result) => result,
        Err(status) => {
            // Call callback with error
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            return;
        }
    };

    // Built eagerly and passed by value — no factory closure. `flags` here is
    // the raw request; the handler's LOOKUPHOST defaulting affects only its
    // path choice, not the reply, so raw flags in the userdata are correct.
    let userdata = FFIData {
        arg, ip: Some(addr_info.ip), nameinfo_flags: flags, port: addr_info.port, scope_id: addr_info.scope_id,
        ..FFIData::base(Callback::AresNameinfoCallback(callback))
    };
    match api::getnameinfo(&mut channeldata.state, &addr_info, flags, userdata) {
        Err(status) => {
            unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), std::ptr::null_mut()) };
        }
        Ok(api::Operation::Ready(api::NameinfoResult::Service(service))) => {
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, std::ptr::null_mut(), service_ptr) };
        }
        Ok(api::Operation::Ready(api::NameinfoResult::Numeric { node, service })) => {
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, node.into_raw(), service_ptr) };
        }
        Ok(api::Operation::Pending) => {}
    }
}


pub(crate) fn run_ares_host_callback(res: Result<&[u8], c_int>, callback: AresHostCallback, task: &Task<FFIData>) {
    match api::on_host_reply(res.map_err(AresError::from), task.rtype, task.family, task.queried_ip) {
        Ok(bp) => {
            let raw_hostent = unsafe { build_hostent(bp) };
            unsafe { callback(task.userdata.arg, ARES_SUCCESS, task.timeouts, &mut *raw_hostent) };
            unsafe { ares_free_hostent(raw_hostent) };
        },
        Err(err) => unsafe { callback(task.userdata.arg, err.code(), task.timeouts, std::ptr::null_mut()) },
    }
}

pub(crate) fn run_ares_callback(res: Result<&[u8], c_int>, callback: AresCallback, task: &Task<FFIData>) {
    match res {
        Ok(buf) => unsafe { callback(task.userdata.arg, ARES_SUCCESS, task.timeouts, buf.as_ptr() as *mut u8, buf.len() as c_int) },
        Err(err) => unsafe { callback(task.userdata.arg, err, task.timeouts, std::ptr::null_mut(), 0) },
    }
}

pub(crate) fn run_ares_callback_dnsrec(res: Result<&[u8], c_int>, callback: AresCallbackDnsRec, task: &Task<FFIData>) {
    match res.map_err(AresError::from).and_then(dns_record::parse_record) {
        Ok(rec) => {
            let dnsrec = Box::into_raw(Box::new(rec));
            unsafe { callback(task.userdata.arg, ARES_SUCCESS, task.timeouts as usize, dnsrec) };
            unsafe { dns_record::ares_dns_record_destroy(dnsrec) };
        }
        Err(status) => unsafe { callback(task.userdata.arg, status.code(), task.timeouts as usize, std::ptr::null_mut()) },
    }
}

pub(crate) fn run_ares_nameinfo_callback(res: Result<&[u8], c_int>, callback: AresNameinfoCallback, task: &Task<FFIData>) {
    let ffidata = &task.userdata;
    let reply = assemble_nameinfo(
        res.map_err(AresError::from), ffidata.ip.unwrap(), ffidata.scope_id, ffidata.port,
        ffidata.nameinfo_flags, task.timeouts,
    );
    let node_ptr = reply.node.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    let service_ptr = reply.service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    unsafe { callback(ffidata.arg, reply.status.code(), reply.timeouts, node_ptr, service_ptr) };
}

/// Executor for a settled search task: one core call decides (and performs
/// any re-issue); the marshal here only fires the returned delivery.
pub(crate) fn run_ares_search_callback(res: Result<&[u8], c_int>, tail: SearchTail, task: &Task<FFIData>, channeldata: &mut ChannelData) {
    let TaskMachine::Search(sm) = &task.machine else { unreachable!("search task carries a Search machine") };
    let binding = task.userdata;
    match api::on_search_reply(&mut channeldata.state, sm, res.map_err(AresError::from), tail.dnstype, task.timeouts, binding) {
        None => {}
        Some(api::SearchReplyDelivery::Success { timeouts }) => {
            let buf = res.unwrap_or(&[]); // Success is only emitted for Ok replies
            match tail.delivery {
                SearchDelivery::Raw { callback, arg } => {
                    let buf_copy = buf.to_vec();
                    unsafe { callback(arg, ARES_SUCCESS, timeouts, buf_copy.as_ptr() as *mut u8, buf_copy.len() as c_int) };
                }
                SearchDelivery::DnsRec { callback, arg } => {
                    // Parse (in core) and deliver as a dns record
                    match dns_record::parse_record(buf) {
                        Ok(rec) => {
                            let dnsrec = Box::into_raw(Box::new(rec));
                            unsafe { callback(arg, ARES_SUCCESS, timeouts as usize, dnsrec) };
                            unsafe { dns_record::ares_dns_record_destroy(dnsrec) };
                        }
                        Err(parse_status) => {
                            unsafe { callback(arg, parse_status.code(), timeouts as usize, std::ptr::null_mut()) };
                        }
                    }
                }
            }
        }
        Some(api::SearchReplyDelivery::Fail { status, timeouts }) => match tail.delivery {
            SearchDelivery::Raw { callback, arg } => unsafe {
                callback(arg, status.code(), timeouts, std::ptr::null_mut(), 0);
            },
            SearchDelivery::DnsRec { callback, arg } => unsafe {
                callback(arg, status.code(), timeouts as usize, std::ptr::null_mut());
            },
        },
    }
}

/// Executor for a settled gethostbyname task: one core call parses, steps
/// the machine, re-sends and cache-stores; the marshal here builds hostents
/// and fires the C callbacks in the returned order.
pub(crate) fn run_ares_hostbyname_callback(res: Result<&[u8], c_int>, tail: HostTail, task: &Task<FFIData>, channeldata: &mut ChannelData) {
    let TaskMachine::HostByName(sm) = &task.machine else { unreachable!("gethostbyname task carries a HostByName machine") };
    let deliveries = api::on_hostbyname_reply(
        &mut channeldata.state, sm, res.map_err(AresError::from), task.server_index, task.timeouts,
        Instant::now(), task.userdata,
    );
    for delivery in deliveries {
        match delivery {
            api::HostDelivery::NotifyServerFail { server, tcp } => {
                invoke_server_state_callback(channeldata, server, false, tcp);
            }
            api::HostDelivery::Success { hostent, timeouts } => {
                let hostent = unsafe { build_hostent(hostent) };
                unsafe { (tail.callback)(tail.arg, ARES_SUCCESS, timeouts, hostent) };
                unsafe { ares_free_hostent(hostent) };
            }
            api::HostDelivery::Fail { status, timeouts } => {
                unsafe { (tail.callback)(tail.arg, status.code(), timeouts, std::ptr::null_mut()) };
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
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };

    let ai_family = if hints.is_null() { libc::AF_UNSPEC } else { unsafe { (*hints).ai_family } };

    // Resolve the service name to a port (order decided in core; the
    // libc::getservbyname fallback is inherently a C call, so it runs here).
    let port: u16 = if !service.is_null() {
        match service_to_port(unsafe { cstr_lossy(service) }) {
            ServicePort::Port(p) => p,
            ServicePort::NeedSystemLookup => {
                let c_svc = unsafe { CStr::from_ptr(service) };
                let result = unsafe { libc::getservbyname(c_svc.as_ptr(), std::ptr::null()) };
                if !result.is_null() {
                    unsafe { u16::from_be((*result).s_port as u16) }
                } else {
                    0
                }
            }
        }
    } else {
        0
    };

    let hostname_raw = unsafe { cstr_lossy(name) };
    let tail = AddrInfoTail { callback, arg, port };
    let binding = FFIData::base(Callback::AddrInfo(tail));

    match api::getaddrinfo(&mut channeldata.state, hostname_raw, ai_family, binding) {
        Err(status) => {
            unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        }
        Ok(api::Operation::Ready(api::AddrInfoResult { addrs, canonical })) => {
            let nodes = addrinfo_nodes_from_addrs_port(&addrs, port);
            let ai = build_ares_addrinfo(&canonical, nodes);
            unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
        }
        Ok(api::Operation::Pending) => {}
    }
}

/// Fire the deliveries a core drive returned: build the C node graph for a
/// success, or report the failure status.
fn fire_addrinfo_deliveries(deliveries: Vec<AddrInfoDelivery>, tail: AddrInfoTail) {
    for delivery in deliveries {
        match delivery {
            AddrInfoDelivery::Success { name, records } => {
                let nodes = nodes_from_addr_records(&records, tail.port);
                let ai = build_ares_addrinfo(&name, nodes);
                unsafe { (tail.callback)(tail.arg, ARES_SUCCESS, 0, ai) };
            }
            AddrInfoDelivery::Fail { status } => {
                unsafe { (tail.callback)(tail.arg, status.code(), 0, std::ptr::null_mut()) };
            }
        }
    }
}

/// Callback for server failover probe queries — the rcode→health verdict is
/// core's; only the server-state notification fires here.
pub(crate) fn run_probe_callback(res: Result<&[u8], c_int>, channeldata: &mut ChannelData, task: &Task<FFIData>) {
    let si = task.server_index;
    if let Some(ok) = api::on_probe_reply(res.map_err(AresError::from), si, &mut channeldata.state.server_health) {
        invoke_server_state_callback(channeldata, si, ok, false);
    }
}

/// Executor entry for a settled getaddrinfo task: parse the reply (parsing
/// stays ffi-side), feed the event to `AddrInfoSm::step` (borrow held for the
/// decision only), then perform the returned actions borrow-free.
pub(crate) fn run_ares_addrinfo_callback(res: Result<&[u8], c_int>, tail: AddrInfoTail, task: &Task<FFIData>, channeldata: &mut ChannelData) {
    let TaskMachine::AddrInfo(sm) = &task.machine else { unreachable!("getaddrinfo task carries an AddrInfo machine") };
    let ev = match res {
        Ok(buf) => {
            let parse = (|| -> Result<Vec<AddrRecord>, AresError> {
                let response = ParsedResponse::from_buf(buf)?;
                let parsed_rrs = response.process_answers::<AddrRecord>(buf, task.rtype)?;
                if parsed_rrs.items.is_empty() {
                    return Err(ARES_ENODATA.into());
                }
                Ok(parsed_rrs.items)
            })();
            AddrInfoEvent::Reply {
                parse,
                family: task.family,
                server: task.server_index,
                io_timeouts: task.timeouts,
            }
        }
        Err(status) => AddrInfoEvent::Error { status: status.into() },
    };
    let actions = {
        let cfg = LookupCfg {
            attempts: channeldata.state.ares.config.options.attempts,
            ndots: channeldata.state.ares.config.options.ndots,
            search: &channeldata.state.ares.config.search,
        };
        let mut machine = sm.borrow_mut();
        machine.step(ev, &cfg, &mut channeldata.state.server_health)
    };
    let deliveries = drive_addrinfo(&mut channeldata.state, sm, actions, task.userdata);
    fire_addrinfo_deliveries(deliveries, tail);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_send(channel: Channel, qbuf: *const u8, qlen: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if qbuf.is_null() || qlen < 12 {
        unsafe { callback(arg, ARES_EBADQUERY, 0, std::ptr::null_mut(), 0) };
        return;
    }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let query_buf = unsafe { std::slice::from_raw_parts(qbuf, qlen as usize) };
    let ffidata = FFIData { arg, ..FFIData::base(Callback::AresCallback(callback)) };
    if let Err(status) = api::send(&mut channeldata.state, query_buf, ffidata) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) };
    }
}

