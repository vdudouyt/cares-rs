//! Lookup entry points (gethostbyname/getaddrinfo/search/query/send/...)
//! and their per-query state + callback dispatch.

use super::*;
use crate::core::api;
use crate::core::executor::QueryIo;
use crate::core::hostbyname::gethostbyname;
use crate::core::hostbyaddr::{gethostbyaddr, HostByAddrCtx};
use crate::core::hostent::Hostent;
use crate::core::preflight::{service_to_port, ServicePort};


/// The Copy delivery tail of an ares_gethostbyname / ares_gethostbyaddr lookup.
/// Bare fn pointer + opaque arg are Copy; only *calling* them is unsafe.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HostTail {
    pub(crate) callback: AresHostCallback,
    pub(crate) arg: *mut c_void,
}

/// The Copy delivery tail of an ares_getnameinfo lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NameinfoTail {
    pub(crate) callback: AresNameinfoCallback,
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
    pub(crate) delivery: SearchDelivery,
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
    // Build the resource bundle + the self-contained future and register it. A
    // synchronous preflight hit fires re-entrantly on this first `advance`.
    let io = std::rc::Rc::new(std::cell::RefCell::new(QueryIo::default()));
    let fut = Box::pin(gethostbyname(channeldata.state.host_ctx(), io.clone(), hostname.to_string(), family));
    channeldata.spawn(io, AsyncKind::Host { fut, tail: HostTail { callback, arg } });
}

/// # Safety
/// `channel` must be a valid channel, `name` a valid NUL-terminated C string, and `host` a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return ARES_ENOTFOUND; };
    let name_str = unsafe { cstr_lossy(name) };

    match channeldata.state.gethostbyname_file(name_str, family) {
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
    if addr.is_null() || addrlen < 0 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let addrbuf = unsafe { std::slice::from_raw_parts(addr as *mut u8, addrlen as usize) };
    // Family validation done here (reads raw C args; stays in the shim).
    if family != libc::AF_INET && family != libc::AF_INET6 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let Ok(ip) = crate::core::packets::buf_to_ip(addrbuf) else {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    };
    // Build the resource bundle and spawn the self-contained async future.
    let ctx = HostByAddrCtx {
        res: channeldata.state.resources(),
        hosts: channeldata.state.transport.hosts(),
    };
    let io = std::rc::Rc::new(std::cell::RefCell::new(QueryIo::default()));
    let fut = Box::pin(gethostbyaddr(ctx, io.clone(), ip, family));
    channeldata.spawn(io, AsyncKind::Host { fut, tail: HostTail { callback, arg } });
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_search(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let name_str = unsafe { cstr_lossy(name) };
    // Name sanity precedes the channel deref: a bad name reports even on a
    // NULL channel (upstream ordering).
    if let Some(status) = api::search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) };
        return;
    }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let _ = dnsclass;
    let ctx = crate::core::search::SearchCtx {
        res: channeldata.state.resources(),
        ndots: channeldata.state.transport.config.options.ndots,
        search: std::rc::Rc::from(channeldata.state.transport.config.search.clone()),
        use_vc: channeldata.state.transport.config.options.use_vc,
    };
    let tail = SearchTail { delivery: SearchDelivery::Raw { callback, arg } };
    channeldata.spawn_search(ctx, name_str.to_string(), dnstype as u16, false, tail);
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, _dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let name = unsafe { cstr_lossy(name) };
    // Preflight in core, then spawn an fd-owning async query lifecycle that
    // creates the socket, sends, and drives its own failover/TC/timeout.
    match channeldata.state.query_payload(name, dnstype as u16) {
        Ok(launch) => channeldata.spawn_query(launch, callback, arg),
        Err(status) => unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) },
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
    // Cache probe: if a fresh cached reply parses, deliver synchronously.
    let name_clean = name.strip_suffix('.').unwrap_or(name.as_ref());
    if let Some(cached_buf) = channeldata.state.cache.borrow_mut().get(name_clean, dnstype as u16, Instant::now()) {
        if let Ok(rec) = crate::core::dns_record::parse_record(&cached_buf) {
            let dnsrec = Box::into_raw(Box::new(rec));
            unsafe { callback(arg, ARES_SUCCESS, 0, dnsrec) };
            unsafe { crate::ffi::dns_record::ares_dns_record_destroy(dnsrec) };
            return;
        }
    }
    let launch = match channeldata.state.query_payload(name.as_ref(), dnstype as u16) {
        Ok(l) => l,
        Err(e) => { unsafe { callback(arg, e.code(), 0, std::ptr::null_mut()) }; return; }
    };
    channeldata.spawn_query_dnsrec(launch, callback, arg);
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
    if dnsrec.is_null() { return; }
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
    if let Some(status) = api::search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        return;
    }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let ctx = crate::core::search::SearchCtx {
        res: channeldata.state.resources(),
        ndots: channeldata.state.transport.config.options.ndots,
        search: std::rc::Rc::from(channeldata.state.transport.config.search.clone()),
        use_vc: channeldata.state.transport.config.options.use_vc,
    };
    let tail = SearchTail { delivery: SearchDelivery::DnsRec { callback, arg } };
    channeldata.spawn_search(ctx, name_str.to_string(), qtype as u16, true, tail);
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

    // Sockaddr unmarshal stays in the shim (reads raw C `*const sockaddr`).
    let addr_info = match extract_addr_port(sa, salen) {
        Ok(result) => result,
        Err(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            return;
        }
    };

    // Build the resource bundle and spawn the self-contained async future. The
    // three synchronous short-circuits (service-only / NUMERICHOST / no-servers)
    // fire re-entrantly on the first advance.
    let ctx = crate::core::nameinfo::NameinfoCtx {
        res: channeldata.state.resources(),
    };
    let io = std::rc::Rc::new(std::cell::RefCell::new(QueryIo::default()));
    let fut = Box::pin(crate::core::nameinfo::getnameinfo(ctx, io.clone(), addr_info, flags));
    channeldata.spawn(io, AsyncKind::Nameinfo { fut, tail: NameinfoTail { callback, arg } });
}


/// The single raw `ares_callback` invocation for the query/send path — the one
/// place the raw C callback is fired (from the async executor's completion).
pub(crate) fn fire_ares_callback(callback: AresCallback, arg: *mut c_void, res: Result<&[u8], c_int>, timeouts: c_int) {
    match res {
        Ok(buf) => unsafe { callback(arg, ARES_SUCCESS, timeouts, buf.as_ptr() as *mut u8, buf.len() as c_int) },
        Err(err) => unsafe { callback(arg, err, timeouts, std::ptr::null_mut(), 0) },
    }
}

/// Build a C hostent from a core one, fire the host callback with it, and free
/// it — the single success-firing site shared by the `ares_gethostbyname` shim
/// (synchronous hit) and the async executor's `finalize`.
pub(crate) fn fire_host_success(tail: HostTail, hostent: Hostent, timeouts: c_int) {
    let c_hostent = unsafe { build_hostent(hostent) };
    unsafe { (tail.callback)(tail.arg, ARES_SUCCESS, timeouts, c_hostent) };
    unsafe { ares_free_hostent(c_hostent) };
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

    // Build the resource bundle and spawn the self-contained async future. A
    // synchronous preflight hit (IP literal / hosts file) fires re-entrantly.
    let hostname_raw = unsafe { cstr_lossy(name) };
    let ctx = crate::core::addrinfo::AddrInfoCtx {
        res: channeldata.state.resources(),
        hosts: channeldata.state.transport.hosts(),
        ndots: channeldata.state.transport.config.options.ndots,
        search: std::rc::Rc::from(channeldata.state.transport.config.search.clone()),
        use_vc: channeldata.state.transport.config.options.use_vc,
        ai_family,
    };
    channeldata.spawn_addrinfo(ctx, hostname_raw.to_string(), AddrInfoTail { callback, arg, port });
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
    // Preflight in core, then spawn an fd-owning async query lifecycle.
    match channeldata.state.send_payload(query_buf) {
        Ok(launch) => channeldata.spawn_query(launch, callback, arg),
        Err(status) => unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) },
    }
}

