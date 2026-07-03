//! Lookup entry points (gethostbyname/getaddrinfo/search/query/send/...)
//! and their per-query state + callback dispatch.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::core::api;
use crate::core::channel::cache_store_names;
use crate::core::launch::{
    drive_addrinfo, launch_pooled, AddrInfoDelivery, AddrInfoSeed, HostTaskSeed, LaunchOutcome,
};
use crate::core::preflight::{
    format_ip_with_scope, get_service_string, hosts_file_lookup, service_to_port, ServicePort,
};


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

#[derive(Debug, Clone)]
// Variants are named after the c-ares FFI callback typedefs they dispatch to;
// the shared `Callback` suffix is intentional for that correspondence.
// Stateful lookups pair a core-minted state-machine handle (the Rc is shared
// by every task of the lookup) with a Copy C delivery tail.
#[allow(clippy::enum_variant_names)]
pub(crate) enum Callback {
    AresHostCallback(AresHostCallback),
    AresCallback(AresCallback),
    AresCallbackDnsRec(AresCallbackDnsRec),
    AresNameinfoCallback(AresNameinfoCallback),
    AddrInfo(Rc<RefCell<AddrInfoSm>>, AddrInfoTail),
    HostByName(Rc<RefCell<HostByNameSm>>, HostTail),
    Search(Rc<RefCell<SearchSm>>, SearchTail),
    Probe, // Server failover probe — no user callback
}

impl Callback {
    pub(crate) fn run(&self, buf: Result<&[u8], c_int>, ffidata: &FFIData, channeldata: &mut ChannelData) {
        // Cancel/destroy deliveries follow the core policy table.
        if let Err(status) = &buf {
            if *status == ARES_EDESTRUCTION || *status == ARES_ECANCELLED {
                match teardown_delivery(self.kind()) {
                    TeardownDelivery::DeliverNull => {
                        match self {
                            Self::HostByName(_, tail) => {
                                unsafe { (tail.callback)(tail.arg, *status, 0, std::ptr::null_mut()) };
                            }
                            Self::Search(_, tail) => match tail.delivery {
                                SearchDelivery::Raw { callback, arg } => unsafe {
                                    callback(arg, *status, ffidata.timeouts, std::ptr::null_mut(), 0);
                                },
                                SearchDelivery::DnsRec { callback, arg } => unsafe {
                                    callback(arg, *status, ffidata.timeouts as usize, std::ptr::null_mut());
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
            Self::AresHostCallback(callback) => run_ares_host_callback(buf, *callback, ffidata),
            Self::AresCallback(callback) => run_ares_callback(buf, *callback, ffidata),
            Self::AresCallbackDnsRec(callback) => run_ares_callback_dnsrec(buf, *callback, ffidata),
            Self::AresNameinfoCallback(callback) => run_ares_nameinfo_callback(buf, *callback, ffidata),
            Self::AddrInfo(sm, tail) => run_ares_addrinfo_callback(buf, sm, *tail, ffidata, channeldata),
            Self::HostByName(sm, tail) => run_ares_hostbyname_callback(buf, sm, *tail, ffidata, channeldata),
            Self::Search(sm, tail) => run_ares_search_callback(buf, sm, *tail, ffidata, channeldata),
            Self::Probe => run_probe_callback(buf, channeldata, ffidata),
        }
    }
    /// Which reactor-level policies apply to a task carrying this callback.
    pub(crate) fn kind(&self) -> TaskKind {
        match self {
            Self::AddrInfo(..) => TaskKind::AddrInfo,
            Self::HostByName(..) => TaskKind::HostByName,
            Self::Search(..) => TaskKind::Search,
            Self::Probe => TaskKind::Probe,
            _ => TaskKind::Other,
        }
    }
    /// Whether a delivered reply should populate the query cache: plain dnsrec
    /// queries and dnsrec-delivery searches.
    pub(crate) fn wants_dnsrec_cache(&self) -> bool {
        match self {
            Self::AresCallbackDnsRec(_) => true,
            Self::Search(_, tail) => matches!(tail.delivery, SearchDelivery::DnsRec { .. }),
            _ => false,
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

impl FFIData {
    /// A blank userdata around `callback` — entry shims override the fields
    /// their flow needs via struct-update syntax.
    pub(crate) fn base(callback: Callback) -> FFIData {
        FFIData {
            callback,
            arg: std::ptr::null_mut(),
            family: 0,
            expected_record_type: 0,
            ip: None,
            nameinfo_flags: 0,
            port: 0,
            scope_id: 0,
            server_index: 0,
            timeouts: 0,
        }
    }
    /// A retry copy of this task's userdata aimed at `server_index`.
    pub(crate) fn retarget(&self, server_index: usize, timeouts: c_int) -> FFIData {
        FFIData {
            callback: self.callback.clone(),
            arg: self.arg,
            family: self.family,
            expected_record_type: self.expected_record_type,
            ip: self.ip,
            nameinfo_flags: self.nameinfo_flags,
            port: self.port,
            scope_id: self.scope_id,
            server_index,
            timeouts,
        }
    }
}

/// The gethostbyname userdata factory: wraps a core-issued task seed (a
/// lookup send for the shared machine, or a probe) into FFIData.
fn host_userdata(tail: HostTail) -> impl FnMut(HostTaskSeed, usize) -> FFIData {
    move |seed, server| match seed {
        HostTaskSeed::Lookup { sm, family, rtype } => FFIData {
            family, expected_record_type: rtype as c_int, server_index: server,
            ..FFIData::base(Callback::HostByName(sm, tail))
        },
        HostTaskSeed::Probe { family, rtype } => FFIData {
            family, expected_record_type: rtype as c_int, server_index: server,
            ..FFIData::base(Callback::Probe)
        },
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
    let mut consent = sock_consent(channeldata);
    let mut make_userdata = host_userdata(HostTail { callback, arg });

    match api::gethostbyname(&mut channeldata.state, hostname, family, Instant::now(), &mut make_userdata, &mut consent) {
        api::HostStart::Deliver(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        }
        api::HostStart::DeliverHost(lookup) => {
            let hostent = unsafe { hostent_from_lookup(lookup) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
        }
        api::HostStart::DeliverParsed(parsed_rrs, hostent_family) => {
            let hostent = unsafe { parsed_rrs.into_raw_hostent(hostent_family) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
        }
        api::HostStart::InFlight => {}
    }
}

/// # Safety
/// `channel` must be a valid channel, `name` a valid NUL-terminated C string, and `host` a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    if channel.is_null() { return ARES_ENOTFOUND; }
    let channeldata = unsafe { &mut *channel };
    let name_str = unsafe { cstr_lossy(name) };

    match hosts_file_lookup(&mut channeldata.state, name_str, family) {
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
    let mut consent = sock_consent(channeldata);
    let mut make_userdata = |ip: IpAddr| FFIData {
        arg, family, expected_record_type: RECORD_TYPE_PTR as c_int, ip: Some(ip),
        ..FFIData::base(Callback::AresHostCallback(callback))
    };
    match api::gethostbyaddr(&mut channeldata.state, addrbuf, family, &mut make_userdata, &mut consent) {
        api::HostByAddrStart::Deliver(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        }
        api::HostByAddrStart::DeliverHost(lookup) => {
            let hostent = unsafe { hostent_from_lookup(lookup) };
            unsafe { callback(arg, ARES_SUCCESS, 0, hostent) };
            unsafe { ares_free_hostent(hostent) };
        }
        api::HostByAddrStart::InFlight => {}
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
        unsafe { callback(arg, status, 0, std::ptr::null_mut(), 0) };
        return;
    }
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    let _ = dnsclass;
    let tail = SearchTail { dnstype: dnstype as u16, delivery: SearchDelivery::Raw { callback, arg } };
    let mut make_userdata = |sm| FFIData::base(Callback::Search(sm, tail));
    if let api::StartOutcome::Deliver(status) = api::search(&mut channeldata.state, name_str, dnstype as u16, false, &mut make_userdata) {
        unsafe { callback(arg, status, 0, std::ptr::null_mut(), 0) };
    }
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, _dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    let name = unsafe { cstr_lossy(name) };
    let ffidata = FFIData { arg, ..FFIData::base(Callback::AresCallback(callback)) };
    if let api::StartOutcome::Deliver(status) = api::query(&mut channeldata.state, name, dnstype as u16, ffidata) {
        unsafe { callback(arg, status, 0, std::ptr::null_mut(), 0) };
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
    let name = unsafe { cstr_lossy(name) };
    let ffidata = FFIData { arg, expected_record_type: dnstype, ..FFIData::base(Callback::AresCallbackDnsRec(callback)) };
    match api::query_dnsrec(&mut channeldata.state, name, dnstype as u16, Instant::now(), ffidata) {
        api::DnsrecStart::Deliver(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        }
        api::DnsrecStart::DeliverCached(cached_buf) => {
            if let Ok(rec) = dns_record::parse_record(&cached_buf) {
                let dnsrec = Box::into_raw(Box::new(rec));
                unsafe { callback(arg, ARES_SUCCESS, 0, dnsrec) };
                unsafe { dns_record::ares_dns_record_destroy(dnsrec) };
            } else {
                // Unparseable cache entry: fall through to a fresh query.
                // (Folds into api::query_dnsrec once the codec lives in core.)
                let ffidata = FFIData { arg, expected_record_type: dnstype, ..FFIData::base(Callback::AresCallbackDnsRec(callback)) };
                if let api::StartOutcome::Deliver(status) = api::query_dnsrec_uncached(&mut channeldata.state, name, dnstype as u16, ffidata) {
                    unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
                }
            }
        }
        api::DnsrecStart::InFlight => {}
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

    // Same pre-state ordering as ares_search: bad names report before the
    // channel is dereferenced.
    if let Some(status) = api::search_precheck(name_str) {
        unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        return;
    }
    if channel.is_null() { return; }
    let channeldata = unsafe { &mut *channel };
    let tail = SearchTail { dnstype: qtype as u16, delivery: SearchDelivery::DnsRec { callback, arg } };
    let mut make_userdata = |sm| FFIData::base(Callback::Search(sm, tail));
    if let api::StartOutcome::Deliver(status) = api::search(&mut channeldata.state, name_str, qtype as u16, true, &mut make_userdata) {
        unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
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

    let mut consent = sock_consent(channeldata);
    let mut make_userdata = |flags: c_int| FFIData {
        arg, family: addr_info.family, expected_record_type: RECORD_TYPE_PTR as c_int,
        ip: Some(addr_info.ip), nameinfo_flags: flags, port: addr_info.port, scope_id: addr_info.scope_id,
        ..FFIData::base(Callback::AresNameinfoCallback(callback))
    };
    match api::getnameinfo(&mut channeldata.state, &addr_info, flags, &mut make_userdata, &mut consent) {
        api::NameinfoStart::Fail(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
        }
        api::NameinfoStart::DeliverService(service) => {
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, std::ptr::null_mut(), service_ptr) };
        }
        api::NameinfoStart::DeliverNumeric { node, service } => {
            let service_ptr = service.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, ARES_SUCCESS, 0, node.into_raw(), service_ptr) };
        }
        api::NameinfoStart::InFlight => {}
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

/// Issue the next search-domain query for an `ares_search`. On socket-creation
/// failure, deliver ARES_ECONNREFUSED to the user and free the search state
/// (rather than panicking or leaking).
/// Re-issue a search query for the next name in the plan. On socket-creation
/// failure, deliver ECONNREFUSED directly (the lookup's remaining Rcs drop
/// naturally — no manual free).
pub(crate) fn issue_search_query(channeldata: &mut ChannelData, hostname: &str, sm: Rc<RefCell<SearchSm>>, tail: SearchTail, timeouts: c_int) {
    let new_ffidata = FFIData { timeouts, ..FFIData::base(Callback::Search(sm, tail)) };
    if channeldata.state.ares.enqueue(dns_query_payload(hostname, tail.dnstype), SocketSource::Udp, 0, new_ffidata).is_err() {
        match tail.delivery {
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
pub(crate) fn run_ares_search_callback(res: Result<&[u8], c_int>, sm: &Rc<RefCell<SearchSm>>, tail: SearchTail, ffidata: &FFIData, channeldata: &mut ChannelData) {
    let ev = match res {
        Ok(buf) => LookupEvent::Reply(buf),
        Err(status) => LookupEvent::Error(status),
    };
    let action = sm.borrow_mut().step(ev);
    match action {
        SearchAction::Send(next_name) => {
            issue_search_query(channeldata, &next_name, sm.clone(), tail, ffidata.timeouts);
        }
        SearchAction::DeliverSuccess => {
            let buf = res.unwrap_or(&[]); // DeliverSuccess is only emitted for Ok replies
            match tail.delivery {
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
        SearchAction::DeliverFail(status) => match tail.delivery {
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
pub(crate) fn run_ares_hostbyname_callback(res: Result<&[u8], c_int>, sm: &Rc<RefCell<HostByNameSm>>, tail: HostTail, ffidata: &FFIData, channeldata: &mut ChannelData) {
    // Parse outside the machine; the machine sees only the outcome.
    let mut parsed_items: Option<ParsedRRs<AddrRecord>> = None;
    let ev = match res {
        Ok(buf) => {
            let expected_rtype = sm.borrow().expected_rtype;
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
            attempts: channeldata.state.ares.config.options.attempts,
            ndots: channeldata.state.ares.config.options.ndots,
            search: &channeldata.state.ares.config.search,
        };
        let mut machine = sm.borrow_mut();
        machine.step(ev, &cfg, &mut channeldata.state.server_health)
    };

    for action in actions {
        match action {
            HostAction::Send { name, family, rtype, tcp, server } => {
                let mut consent = sock_consent(channeldata);
                let mut make_userdata = host_userdata(tail);
                if let LaunchOutcome::Exhausted { timeouts } = launch_pooled(&mut channeldata.state, &name, family, rtype, tcp, server, sm, &mut make_userdata, &mut consent) {
                    unsafe { (tail.callback)(tail.arg, ARES_ECONNREFUSED, timeouts, std::ptr::null_mut()) };
                }
            }
            HostAction::NotifyServerFail { server, tcp } => {
                invoke_server_state_callback(channeldata, server, false, tcp);
            }
            HostAction::CacheStore { names, rtype } => {
                if channeldata.state.query_cache_max_ttl > 0 {
                    if let (Ok(buf), Some(rrs)) = (&res, &parsed_items) {
                        let ttl = rrs.items.iter().map(|r| r.ttl).min().unwrap_or(0);
                        cache_store_names(&mut channeldata.state.query_cache, channeldata.state.query_cache_max_ttl, names, rtype, ttl, buf, Instant::now());
                    }
                }
            }
            HostAction::DeliverSuccess { family, timeouts } => {
                let Some(mut rrs) = parsed_items.take() else { continue };
                if !channeldata.state.sortlist.is_empty() {
                    apply_sortlist(&channeldata.state.sortlist, &mut rrs.items);
                }
                let hostent = unsafe { rrs.into_raw_hostent(family) };
                unsafe { (tail.callback)(tail.arg, ARES_SUCCESS, timeouts, hostent) };
                unsafe { ares_free_hostent(hostent) };
            }
            HostAction::DeliverFail { status, timeouts } => {
                unsafe { (tail.callback)(tail.arg, status, timeouts, std::ptr::null_mut()) };
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
    let mut consent = sock_consent(channeldata);
    let mut make_userdata = addrinfo_userdata(tail);

    match api::getaddrinfo(&mut channeldata.state, hostname_raw, ai_family, &mut make_userdata, &mut consent) {
        api::AddrInfoStart::Deliver(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
        }
        api::AddrInfoStart::DeliverAddrs { addrs, canonical } => {
            let nodes = addrinfo_nodes_from_addrs_port(&addrs, ai_family, port);
            let ai = build_ares_addrinfo(&canonical, nodes);
            unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
        }
        api::AddrInfoStart::Started(deliveries) => {
            fire_addrinfo_deliveries(deliveries, tail);
        }
    }
}

/// The getaddrinfo userdata factory: wraps a core-issued send seed into FFIData.
fn addrinfo_userdata(tail: AddrInfoTail) -> impl FnMut(AddrInfoSeed, usize) -> FFIData {
    move |seed, server| FFIData {
        family: seed.family,
        expected_record_type: seed.rtype as c_int,
        server_index: server,
        timeouts: seed.timeouts,
        ..FFIData::base(Callback::AddrInfo(seed.sm, tail))
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
                unsafe { (tail.callback)(tail.arg, status, 0, std::ptr::null_mut()) };
            }
        }
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
                if channeldata.state.server_health.record_success(si) {
                    invoke_server_state_callback(channeldata, si, true, false);
                }
            } else {
                // SERVFAIL/NOTIMP/REFUSED — still failing
                if channeldata.state.server_health.record_failure(si) {
                    invoke_server_state_callback(channeldata, si, false, false);
                }
            }
        }
        Err(_) => {
            // Timeout or other error — update failure timestamp
            channeldata.state.server_health.record_failure_time(si);
        }
    }
}

/// Executor entry for a settled getaddrinfo task: parse the reply (parsing
/// stays ffi-side), feed the event to `AddrInfoSm::step` (borrow held for the
/// decision only), then perform the returned actions borrow-free.
pub(crate) fn run_ares_addrinfo_callback(res: Result<&[u8], c_int>, sm: &Rc<RefCell<AddrInfoSm>>, tail: AddrInfoTail, ffidata: &FFIData, channeldata: &mut ChannelData) {
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
            attempts: channeldata.state.ares.config.options.attempts,
            ndots: channeldata.state.ares.config.options.ndots,
            search: &channeldata.state.ares.config.search,
        };
        let mut machine = sm.borrow_mut();
        machine.step(ev, &cfg, &mut channeldata.state.server_health)
    };
    let mut consent = sock_consent(channeldata);
    let mut make_userdata = addrinfo_userdata(tail);
    let deliveries = drive_addrinfo(&mut channeldata.state, sm, actions, &mut make_userdata, &mut consent);
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
    let channeldata = unsafe { &mut *channel };
    let query_buf = unsafe { std::slice::from_raw_parts(qbuf, qlen as usize) };
    let ffidata = FFIData { arg, ..FFIData::base(Callback::AresCallback(callback)) };
    if let api::StartOutcome::Deliver(status) = api::send(&mut channeldata.state, query_buf, ffidata) {
        unsafe { callback(arg, status, 0, std::ptr::null_mut(), 0) };
    }
}

