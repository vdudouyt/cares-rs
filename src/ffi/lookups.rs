//! Lookup entry points (gethostbyname/getaddrinfo/search/query/send/...)
//! and their per-query state + callback dispatch.

use super::*;
use crate::core::async_client::search_precheck;
use crate::core::hostent::Hostent;
use crate::core::async_client::{service_to_port, ServicePort};
use crate::core::async_client::{AddrInfoOut, Delivery, DnsMailbox, NameinfoReply};
use crate::core::cache::QueryCache;
use crate::core::AresError;
use std::cell::RefCell;
use std::rc::Rc;

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
    let client = channeldata.state.derive();
    let io = client.io.clone();
    let io_cb = io.clone();
    let fut = client.gethostbyname(hostname.to_string(), family);
    channeldata.spawn(io, fut, move |r| on_hostent_reply(callback, arg, &io_cb, r));
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
    let client = channeldata.state.derive();
    let io = client.io.clone();
    let io_cb = io.clone();
    let fut = client.gethostbyaddr(ip, family);
    channeldata.spawn(io, fut, move |r| on_hostent_reply(callback, arg, &io_cb, r));
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_search(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let name_str = unsafe { cstr_lossy(name) };
    // Name sanity precedes the channel deref: a bad name reports even on a
    // NULL channel (upstream ordering).
    if let Some(status) = search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) };
        return;
    }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let _ = dnsclass;
    let client = channeldata.state.derive();
    let io = client.io.clone();
    let fut = client.search(name_str.to_string(), dnstype as u16, false);
    channeldata.spawn(io, fut, move |r| on_raw_reply(callback, arg, r));
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
        Ok(payload) => {
            let client = channeldata.state.derive();
            let io = client.io.clone();
            let fut = client.query_raw(payload);
            channeldata.spawn(io, fut, move |r| on_raw_reply(callback, arg, r));
        }
        Err(status) => on_raw_reply(callback, arg, Err(status.code())),
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
    // Hoisted out of the `if let` scrutinee so the cache RefMut drops at the
    // `;` — a scrutinee guard would be held across the C callback below, and
    // a callback re-entering any cache path would then panic (regression
    // test: tests/reentrant_callback.rs).
    let cached = channeldata.state.cache.borrow_mut().get(name.strip_suffix('.').unwrap_or(name.as_ref()), dnstype as u16, Instant::now());
    if let Some(cached_buf) = cached {
        if let Ok(rec) = crate::core::dns_record::parse_record(&cached_buf) {
            let dnsrec = Box::into_raw(Box::new(rec));
            unsafe { callback(arg, ARES_SUCCESS, 0, dnsrec) };
            unsafe { crate::ffi::dns_record::ares_dns_record_destroy(dnsrec) };
            return;
        }
    }
    let payload = match channeldata.state.query_payload(name.as_ref(), dnstype as u16) {
        Ok(p) => p,
        Err(e) => { unsafe { callback(arg, e.code(), 0, std::ptr::null_mut()) }; return; }
    };
    let client = channeldata.state.derive();
    let cache = client.cache.clone();
    let io = client.io.clone();
    let fut = client.query_raw(payload);
    channeldata.spawn(io, fut, move |r| on_dnsrec_reply(callback, arg, &cache, r));
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
    if let Some(status) = search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        return;
    }
    let Some(channeldata) = (unsafe { channel.as_mut() }) else { return; };
    let client = channeldata.state.derive();
    let cache = client.cache.clone();
    let io = client.io.clone();
    let fut = client.search(name_str.to_string(), qtype as u16, true);
    channeldata.spawn(io, fut, move |r| on_dnsrec_reply(callback, arg, &cache, r));
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
    let client = channeldata.state.derive();
    let io = client.io.clone();
    let fut = client.getnameinfo(addr_info, flags);
    channeldata.spawn(io, fut, move |r| on_nameinfo_reply(callback, arg, r));
}


// ===== delivery handlers: a completed query's result (`Ok`) or a cancel status
// (`Err`) → the C callback. One per callback signature; the shim closures forward
// their `Result<T, c_int>` here. The only sites that call a C callback.

/// ares_query / ares_send / ares_search → `ares_callback`: reply bytes on success,
/// else the error/cancel status with a null buffer.
pub(crate) fn on_raw_reply(callback: AresCallback, arg: *mut c_void, r: Result<Delivery, c_int>) {
    let (res, timeouts): (Result<&[u8], c_int>, c_int) = match &r {
        Ok(Delivery::Raw { result, timeouts }) => (result.as_deref().map_err(|&e| e), *timeouts),
        Err(status) => (Err(*status), 0),
    };
    match res {
        Ok(buf) => unsafe { callback(arg, ARES_SUCCESS, timeouts, buf.as_ptr() as *mut u8, buf.len() as c_int) },
        Err(err) => unsafe { callback(arg, err, timeouts, std::ptr::null_mut(), 0) },
    }
}

/// ares_query_dnsrec / ares_search_dnsrec → `ares_callback_dnsrec`: cache-store +
/// parse the reply into an `ares_dns_record_t` on success, else the status.
pub(crate) fn on_dnsrec_reply(callback: AresCallbackDnsRec, arg: *mut c_void, cache: &Rc<RefCell<QueryCache>>, r: Result<Delivery, c_int>) {
    let (result, timeouts) = match r {
        Ok(Delivery::Raw { result, timeouts }) => (result, timeouts),
        Err(status) => (Err(status), 0),
    };
    match result {
        Ok(buf) => {
            cache.borrow_mut().store_reply(&buf, Instant::now());
            match crate::core::dns_record::parse_record(&buf) {
                Ok(rec) => {
                    let dnsrec = Box::into_raw(Box::new(rec));
                    unsafe { callback(arg, ARES_SUCCESS, timeouts as usize, dnsrec) };
                    unsafe { crate::ffi::dns_record::ares_dns_record_destroy(dnsrec) };
                }
                Err(e) => unsafe { callback(arg, e.code(), timeouts as usize, std::ptr::null_mut()) },
            }
        }
        Err(status) => unsafe { callback(arg, status, timeouts as usize, std::ptr::null_mut()) },
    }
}

/// ares_gethostbyname / ares_gethostbyaddr → `ares_host_callback`: build + fire +
/// free a C hostent on success, else the status. The timeout count (no room in the
/// `Result<Hostent, _>` output) is read from the mailbox on completion.
pub(crate) fn on_hostent_reply(callback: AresHostCallback, arg: *mut c_void, io: &Rc<RefCell<DnsMailbox>>, r: Result<Result<Hostent, AresError>, c_int>) {
    match r {
        Ok(inner) => {
            let timeouts = io.borrow().app.timeouts;
            match inner {
                Ok(hostent) => {
                    let c_hostent = unsafe { build_hostent(hostent) };
                    unsafe { callback(arg, ARES_SUCCESS, timeouts, c_hostent) };
                    unsafe { ares_free_hostent(c_hostent) };
                }
                Err(e) => unsafe { callback(arg, e.code(), timeouts, std::ptr::null_mut()) },
            }
        }
        Err(status) => unsafe { callback(arg, status, 0, std::ptr::null_mut()) },
    }
}

/// ares_getnameinfo → `ares_nameinfo_callback`: the node / service strings on
/// success, else the status with null strings.
pub(crate) fn on_nameinfo_reply(callback: AresNameinfoCallback, arg: *mut c_void, r: Result<NameinfoReply, c_int>) {
    match r {
        Ok(reply) => {
            let node_ptr = reply.node.as_ref().map(|s| s.as_ptr() as *mut c_char).unwrap_or(std::ptr::null_mut());
            let service_ptr = reply.service.as_ref().map(|s| s.as_ptr() as *mut c_char).unwrap_or(std::ptr::null_mut());
            unsafe { callback(arg, reply.status.code(), reply.timeouts, node_ptr, service_ptr) };
        }
        Err(status) => unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) },
    }
}

/// ares_getaddrinfo → `ares_addrinfo_callback`: build the `ares_addrinfo` (nodes at
/// `port`) on success, else the status with a null result.
pub(crate) fn on_addrinfo_reply(callback: AresAddrInfoCallback, arg: *mut c_void, port: u16, r: Result<AddrInfoOut, c_int>) {
    match r {
        Ok(out) if out.status.code() == ARES_SUCCESS => {
            let nodes = crate::ffi::addrinfo::nodes_from_addr_records(&out.records, port);
            let ai = crate::ffi::addrinfo::build_ares_addrinfo(&out.name, nodes);
            unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
        }
        Ok(out) => unsafe { callback(arg, out.status.code(), 0, std::ptr::null_mut()) },
        Err(status) => unsafe { callback(arg, status, 0, std::ptr::null_mut()) },
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

    // Build the resource bundle and spawn the self-contained async future. A
    // synchronous preflight hit (IP literal / hosts file) fires re-entrantly.
    let hostname_raw = unsafe { cstr_lossy(name) };
    let client = channeldata.state.derive();
    let io = client.io.clone();
    let fut = client.getaddrinfo(hostname_raw.to_string(), ai_family);
    channeldata.spawn(io, fut, move |r| on_addrinfo_reply(callback, arg, port, r));
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
        Ok(payload) => {
            let client = channeldata.state.derive();
            let io = client.io.clone();
            let fut = client.query_raw(payload);
            channeldata.spawn(io, fut, move |r| on_raw_reply(callback, arg, r));
        }
        Err(status) => on_raw_reply(callback, arg, Err(status.code())),
    }
}

