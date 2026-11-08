//! Lookup entry points (gethostbyname/getaddrinfo/search/query/send/...) and
//! their per-query state + callback dispatch.

use super::*;
use crate::core::async_client::search_precheck;
use crate::core::nameinfo::{service_to_port, ServicePort};
use crate::core::async_client::{AddrInfoOut, Delivery, HostReply};
use crate::core::nameinfo::NameinfoReply;
use crate::core::cache::{CacheKey, QueryCache};
use std::cell::RefCell;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_gethostbyname(channel: Channel, hostname: *const c_char, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    if channel.is_null() || hostname.is_null() {
        unsafe { callback(arg, ARES_ENOTFOUND, 0, std::ptr::null_mut()) };
        return;
    }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    let hostname = unsafe { cstr_lossy(hostname) };
    let client = channeldata.state.derive();
    let fut = client.gethostbyname(hostname.to_string(), family);
    channeldata.spawn(fut, move |r| on_hostent_reply(callback, arg, r));
}

/// # Safety
/// `channel` must be a valid channel, `name` a valid NUL-terminated C string, and `host` a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_gethostbyname_file(channel: *mut ChannelData, name: *const c_char, family: c_int, host: *mut *mut libc::hostent) -> c_int {
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENOTFOUND; };
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
pub unsafe extern "C" fn ares_gethostbyaddr(channel: Channel, addr: *const c_void, addrlen: c_int, family: c_int, callback: ares_host_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    if addr.is_null() || addrlen < 0 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let addrbuf = unsafe { std::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
    if family != libc::AF_INET && family != libc::AF_INET6 {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    }
    let Ok(ip) = crate::core::packets::buf_to_ip(addrbuf) else {
        unsafe { callback(arg, ARES_ENOTIMP, 0, std::ptr::null_mut()) };
        return;
    };
    let client = channeldata.state.derive();
    let fut = client.gethostbyaddr(ip, family);
    channeldata.spawn(fut, move |r| on_hostent_reply(callback, arg, r));
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_search(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    // Upstream returns silently on a NULL channel/name; no callback fires.
    if channel.is_null() || name.is_null() {
        return;
    }
    let name_str = unsafe { cstr_lossy(name) };
    if let Some(status) = search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut(), 0) };
        return;
    }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    let client = channeldata.state.derive();
    let fut = client.search(
        name_str.to_string(),
        dnsclass as u32,
        dnstype as u32,
        false,
    );
    channeldata.spawn(fut, move |r| on_raw_reply(callback, arg, r));
}

/// # Safety
/// `channel` must be a valid channel and `name` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ares_query(channel: Channel, name: *const c_char, dnsclass: c_int, dnstype: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    let name = unsafe { cstr_lossy(name) };
    match channeldata
        .state
        .query_payload(name, dnstype as u32, dnsclass as u32)
    {
        Ok(payload) => {
            let client = channeldata.state.derive();
                    let fut = client.query_raw(payload);
            channeldata.spawn(fut, move |r| on_raw_reply(callback, arg, r));
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
    dnsclass: crate::ffi::ares_dns_class_t,
    dnstype: crate::ffi::ares_dns_rec_type_t,
    callback: ares_callback_dnsrec,
    arg: *mut c_void,
    qid: *mut libc::c_ushort,
) -> crate::ffi::ares_status_t {
    let Some(callback) = callback else { return ARES_EFORMERR; };
    // Upstream checks the channel before any argument validation/callback.
    if channel.is_null() {
        return ARES_EFORMERR;
    }
    if name.is_null() {
        unsafe { callback(arg, ARES_EFORMERR, 0, std::ptr::null_mut()) };
        return ARES_EFORMERR;
    }
    let name = unsafe { cstr_lossy(name) };
    // SAFETY: the caller guarantees a live channel handle.
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
    query_dnsrec_record(channeldata, name, dnsclass, dnstype, callback, arg, qid)
}

fn query_dnsrec_record(
    channeldata: &mut ChannelData,
    name: &str,
    dnsclass: crate::ffi::ares_dns_class_t,
    dnstype: crate::ffi::ares_dns_rec_type_t,
    callback: AresCallbackDnsRec,
    arg: *mut c_void,
    qid: *mut libc::c_ushort,
) -> crate::ffi::ares_status_t {
    // Build (and thereby validate the raw class/type/name) once, before the
    // cache probe: upstream constructs the query before qcache_fetch.
    let payload = match channeldata.state.query_payload(name, dnstype, dnsclass) {
        Ok(p) => p,
        Err(e) => {
            let status = e.code();
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
            return status;
        }
    };
    // Cache probe: hoisted so the cache RefMut drops before the C callback;
    // holding it across a re-entrant cache access would panic
    // (tests/reentrant_callback.rs).
    let cache_key = CacheKey::new(
        name,
        dnstype as u16,
        dnsclass as u16,
        0,
        channeldata.state.recursion_desired(),
        false,
    );
    let cached = channeldata.state.shared.cache.borrow_mut().get(&cache_key, Instant::now());
    if let Some(cached_buf) = cached {
        if let Ok(rec) = crate::core::dns_record::parse_record(&cached_buf, 0) {
            let dnsrec = Box::into_raw(Box::new(rec));
            unsafe { callback(arg, ARES_SUCCESS, 0, dnsrec) };
            unsafe { crate::ffi::dns_record::ares_dns_record_destroy(dnsrec) };
            return ARES_SUCCESS;
        }
    }
    if !qid.is_null() {
        unsafe { *qid = payload.qid(); }
    }
    let client = channeldata.state.derive();
    let shared = client.shared.clone();
    let fut = client.query_raw(payload);
    channeldata.spawn(fut, move |r| {
        on_dnsrec_reply(callback, arg, &shared.cache, Some(cache_key), r)
    });
    ARES_SUCCESS
}

/// # Safety
/// `channel` must be a valid channel and `dnsrec` a valid `ares_dns_record_t` pointer.
#[no_mangle]
pub unsafe extern "C" fn ares_search_dnsrec(
    channel: Channel,
    dnsrec: *const dns_record::ares_dns_record_t,
    callback: ares_callback_dnsrec,
    arg: *mut c_void,
) -> crate::ffi::ares_status_t {
    let Some(callback) = callback else { return ARES_EFORMERR; };
    if channel.is_null() || dnsrec.is_null() { return ARES_EFORMERR; }
    // SAFETY: the caller guarantees live channel/record handles.
    let rec = unsafe { &*dnsrec };
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
    search_dnsrec_record(Some(channeldata), rec, callback, arg)
}

fn search_dnsrec_record(
    channeldata: Option<&mut ChannelData>,
    rec: &dns_record::ares_dns_record_t,
    callback: AresCallbackDnsRec,
    arg: *mut c_void,
) -> crate::ffi::ares_status_t {
    // Search only supports a single question (upstream ares_search_int).
    if rec.query_cnt() != 1 {
        unsafe { callback(arg, ARES_EBADQUERY, 0, std::ptr::null_mut()) };
        return ARES_EBADQUERY;
    }
    let Some((query_name, _qtype, _qclass)) = rec.query_at(0) else {
        return ARES_EFORMERR;
    };
    let name_str = query_name.to_str().unwrap_or("");
    if let Some(status) = search_precheck(name_str) {
        unsafe { callback(arg, status.code(), 0, std::ptr::null_mut()) };
        return status.code();
    }
    // The C record may be destroyed as soon as this call returns; the async
    // future owns a duplicate that keeps class, flags and all sections.
    let template = match crate::core::dns_record::duplicate_record(rec) {
        Some(t) => t,
        None => {
            unsafe { callback(arg, ARES_EBADQUERY, 0, std::ptr::null_mut()) };
            return ARES_EBADQUERY;
        }
    };
    let Some(channeldata) = channeldata else { return ARES_EFORMERR; };
    let client = channeldata.state.derive();
    let shared = client.shared.clone();
    let fut = client.search_dnsrec(template, true);
    channeldata.spawn(fut, move |r| on_dnsrec_reply(callback, arg, &shared.cache, None, r));
    ARES_SUCCESS
}

/// Async getnameinfo(3): reverse (PTR) lookup for the node plus a service-name
/// lookup.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_getnameinfo(channel: Channel, sa: *const libc::sockaddr, salen: libc::socklen_t, flags: c_int, callback: ares_nameinfo_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };

    let addr_info = match extract_addr_port(sa, salen) {
        Ok(result) => result,
        Err(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
            return;
        }
    };

    // Synchronous short-circuits (service-only / NUMERICHOST / no-servers) fire
    // re-entrantly on the first advance.
    let client = channeldata.state.derive();
    let fut = client.getnameinfo(addr_info, flags);
    channeldata.spawn(fut, move |r| on_nameinfo_reply(callback, arg, r));
}

/// ares_query / ares_send / ares_search → `ares_callback`.
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

/// ares_send → `ares_callback`; stores the reply in the cache first.
pub(crate) fn on_send_raw_reply(callback: AresCallback, arg: *mut c_void, cache: &RefCell<QueryCache>, key: Option<CacheKey>, r: Result<Delivery, c_int>) {
    let (result, timeouts) = match r {
        Ok(Delivery::Raw { result, timeouts }) => (result, timeouts),
        Err(status) => (Err(status), 0),
    };
    match result {
        Ok(buf) => {
            if let Some(key) = key {
                cache.borrow_mut().store_reply(&key, &buf, Instant::now());
            }
            unsafe { callback(arg, ARES_SUCCESS, timeouts, buf.as_ptr() as *mut u8, buf.len() as c_int) };
        }
        Err(status) => unsafe { callback(arg, status, timeouts, std::ptr::null_mut(), 0) },
    }
}

/// ares_query_dnsrec / ares_search_dnsrec → `ares_callback_dnsrec`.
pub(crate) fn on_dnsrec_reply(callback: AresCallbackDnsRec, arg: *mut c_void, cache: &RefCell<QueryCache>, key: Option<CacheKey>, r: Result<Delivery, c_int>) {
    let (result, timeouts) = match r {
        Ok(Delivery::Raw { result, timeouts }) => (result, timeouts),
        Err(status) => (Err(status), 0),
    };
    match result {
        Ok(buf) => {
            if let Some(key) = key {
                cache.borrow_mut().store_reply(&key, &buf, Instant::now());
            }
            match crate::core::dns_record::parse_record(&buf, 0) {
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

/// ares_gethostbyname/addr → `ares_host_callback`.
pub(crate) fn on_hostent_reply(callback: AresHostCallback, arg: *mut c_void, r: Result<HostReply, c_int>) {
    match r {
        Ok((inner, timeouts)) => {
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

/// ares_getnameinfo → `ares_nameinfo_callback`.
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

/// ares_getaddrinfo → `ares_addrinfo_callback`.
pub(crate) fn on_addrinfo_reply(callback: AresAddrInfoCallback, arg: *mut c_void, port: u16, r: Result<AddrInfoOut, c_int>) {
    match r {
        Ok(out) if out.status.code() == ARES_SUCCESS => {
            let nodes = crate::ffi::addrinfo::nodes_from_addr_records(
                &out.records,
                port,
                out.socktype,
                out.protocol,
            );
            let cnames = crate::ffi::addrinfo::cnames_from_entries(&out.cnames);
            let ai = crate::ffi::addrinfo::build_ares_addrinfo(&out.name, nodes, cnames);
            unsafe { callback(arg, ARES_SUCCESS, 0, ai) };
        }
        Ok(out) => unsafe { callback(arg, out.status.code(), 0, std::ptr::null_mut()) },
        Err(status) => unsafe { callback(arg, status, 0, std::ptr::null_mut()) },
    }
}

/// Resolve a getaddrinfo service string; `numeric_only` implements ARES_AI_NUMERICSERV.
fn resolve_service_port(service: *const c_char, numeric_only: bool) -> Result<u16, c_int> {
    let svc = unsafe { cstr_lossy(service) };
    if numeric_only {
        return svc.parse::<u16>().map_err(|_| ARES_ESERVICE);
    }
    match service_to_port(svc) {
        ServicePort::Port(p) => Ok(p),
        ServicePort::NeedSystemLookup => {
            let c_svc = unsafe { CStr::from_ptr(service) };
            let result = unsafe { libc::getservbyname(c_svc.as_ptr(), std::ptr::null()) };
            if result.is_null() {
                Err(ARES_ESERVICE)
            } else {
                Ok(unsafe { u16::from_be((*result).s_port as u16) })
            }
        }
    }
}

fn decode_addrinfo_hints(hints: *const ares_addrinfo_hints) -> (c_int, c_int, c_int, c_int) {
    if hints.is_null() {
        return (libc::AF_UNSPEC, 0, 0, 0);
    }
    let hints = unsafe { &*hints };
    (hints.ai_family, hints.ai_flags, hints.ai_socktype, hints.ai_protocol)
}

/// Resolve the service port, firing the callback; `None` means it already fired.
fn service_port_or_callback(
    service: *const c_char,
    ai_flags: c_int,
    callback: AresAddrInfoCallback,
    arg: *mut c_void,
) -> Option<u16> {
    if service.is_null() {
        return Some(0);
    }
    let numeric_only = ai_flags & crate::ffi::ARES_AI_NUMERICSERV != 0;
    match resolve_service_port(service, numeric_only) {
        Ok(port) => Some(port),
        Err(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
            None
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
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };

    let (ai_family, ai_flags, ai_socktype, ai_protocol) = decode_addrinfo_hints(hints);

    let Some(port) = service_port_or_callback(service, ai_flags, callback, arg) else {
        return;
    };

    // A synchronous preflight hit (IP literal / hosts file) fires re-entrantly.
    let hostname_raw = unsafe { cstr_lossy(name) };
    let client = channeldata.state.derive();
    let fut = client.getaddrinfo(
        hostname_raw.to_string(),
        ai_family,
        ai_flags,
        ai_socktype,
        ai_protocol,
    );
    channeldata.spawn(fut, move |r| on_addrinfo_reply(callback, arg, port, r));
}
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_send(channel: Channel, qbuf: *const u8, qlen: c_int, callback: ares_callback, arg: *mut c_void) {
    let Some(callback) = callback else { return; };
    // Upstream returns early on a NULL channel without firing the callback.
    if channel.is_null() {
        return;
    }
    // Upstream rejects packets shorter than a DNS header or too large for the
    // 16-bit TCP length prefix.
    if qbuf.is_null() || !(12..(1 << 16)).contains(&qlen) {
        unsafe { callback(arg, ARES_EBADQUERY, 0, std::ptr::null_mut(), 0) };
        return;
    }
    let query_buf = unsafe { std::slice::from_raw_parts(qbuf, qlen as usize) };
    // SAFETY: the caller guarantees a live channel handle.
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return; };
    send_raw_packet(channeldata, query_buf, callback, arg);
}

fn send_raw_packet(
    channeldata: &mut ChannelData,
    query_buf: &[u8],
    callback: AresCallback,
    arg: *mut c_void,
) {
    let rec = match crate::core::dns_record::parse_record(query_buf, 0) {
        Ok(rec) => rec,
        Err(e) => {
            unsafe { callback(arg, e.code(), 0, std::ptr::null_mut(), 0) };
            return;
        }
    };
    let shared = channeldata.state.shared.clone();
    let outcome = send_record(
        channeldata,
        &rec,
        std::ptr::null_mut(),
        move |r, key| on_send_raw_reply(callback, arg, &shared.cache, key, r),
    );
    match outcome {
        Ok(Some(buf)) => unsafe {
            callback(arg, ARES_SUCCESS, 0, buf.as_ptr() as *mut u8, buf.len() as c_int)
        },
        Ok(None) => {},
        Err(status) => unsafe {
            callback(arg, status, 0, std::ptr::null_mut(), 0)
        },
    }
}

/// Serialize a record; upstream maps EBADRESP from the write+parse round-trip to
/// EBADQUERY.
fn serialize_send_record(
    rec: &dns_record::ares_dns_record_t,
) -> Result<Vec<u8>, crate::ffi::ares_status_t> {
    match crate::core::dns_record::write_record(rec) {
        Ok(buf) => Ok(buf),
        Err(e) => Err(if e.code() == ARES_EBADRESP {
            ARES_EBADQUERY
        } else {
            e.code()
        }),
    }
}

/// Cache key from the first question; the name has no trailing dot (matches the cache writer).
fn record_cache_key(rec: &dns_record::ares_dns_record_t) -> Option<CacheKey> {
    let (name, qtype, qclass) = rec.query_at(0)?;
    let name = name.to_string_lossy();
    let flags = rec.flags();
    Some(CacheKey::new(
        &name,
        qtype,
        qclass,
        rec.opcode(),
        flags & dns_record::ARES_FLAG_RD != 0,
        flags & dns_record::ARES_FLAG_CD != 0,
    ))
}

/// Shared ares_send/ares_send_dnsrec path: preflight, cache probe, non-zero qid
/// stamp, async lifecycle. `Ok(Some)` is a cache hit (qid untouched).
fn send_record<F>(
    channeldata: &mut ChannelData,
    rec: &dns_record::ares_dns_record_t,
    qid: *mut libc::c_ushort,
    on_reply: F,
) -> Result<Option<Vec<u8>>, crate::ffi::ares_status_t>
where
    F: FnOnce(Result<Delivery, c_int>, Option<CacheKey>) + 'static,
{
    if channeldata.state.config.nameservers.is_empty() {
        return Err(ARES_ENOSERVER);
    }
    let cache_key = record_cache_key(rec);
    if let Some(key) = cache_key.as_ref() {
        let cached = channeldata.state.shared.cache.borrow_mut().get(key, Instant::now());
        if let Some(buf) = cached {
            return Ok(Some(buf));
        }
    }
    let buf = serialize_send_record(rec)?;
    // Upstream duplicates the record through a write+parse round-trip before
    // sending; a parse failure (EBADRESP) surfaces as EBADQUERY.
    if let Err(e) = crate::core::dns_record::parse_record(&buf, 0) {
        return Err(if e.code() == ARES_EBADRESP {
            ARES_EBADQUERY
        } else {
            e.code()
        });
    }
    // DNS messages carry a 16-bit length; upstream rejects larger queries.
    if buf.len() > u16::MAX as usize || buf.len() < 12 {
        return Err(ARES_EBADQUERY);
    }
    // send_payload stamps a fresh channel-unique id (upstream overwrites the
    // caller's id too); it stays fixed for every retry.
    let payload = match channeldata.state.send_payload(&buf) {
        Ok(p) => p,
        Err(e) => return Err(e.code()),
    };
    if !qid.is_null() {
        unsafe { *qid = payload.qid(); }
    }
    let client = channeldata.state.derive();
    // ares_send / ares_send_dnsrec: transmit the caller's bytes unchanged (no
    // synthesized OPT/COOKIE); a caller-supplied OPT is preserved because it is
    // already part of the serialized record.
    let fut = client.query_raw(payload);
    channeldata.spawn(fut, move |r| on_reply(r, cache_key));
    Ok(None)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_send_dnsrec(
    channel: Channel,
    dnsrec: *const dns_record::ares_dns_record_t,
    callback: ares_callback_dnsrec,
    arg: *mut c_void,
    qid: *mut libc::c_ushort,
) -> crate::ffi::ares_status_t {
    let Some(callback) = callback else { return ARES_EFORMERR; };
    if channel.is_null() || dnsrec.is_null() { return ARES_EFORMERR; }
    // SAFETY: the caller guarantees live channel/record handles.
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_EFORMERR; };
    let rec = unsafe { &*dnsrec };
    send_dnsrec_record(Some(channeldata), rec, callback, arg, qid)
}

fn send_dnsrec_record(
    channeldata: Option<&mut ChannelData>,
    rec: &dns_record::ares_dns_record_t,
    callback: AresCallbackDnsRec,
    arg: *mut c_void,
    qid: *mut libc::c_ushort,
) -> crate::ffi::ares_status_t {
    let Some(channeldata) = channeldata else { return ARES_EFORMERR; };
    let shared = channeldata.state.shared.clone();
    let outcome = send_record(
        channeldata,
        rec,
        qid,
        move |r, key| on_dnsrec_reply(callback, arg, &shared.cache, key, r),
    );
    match outcome {
        Ok(Some(buf)) => {
            // Cache hit (synchronous): parse the stored reply and deliver it;
            // *qid is deliberately left untouched (upstream behavior).
            match crate::core::dns_record::parse_record(&buf, 0) {
                Ok(cached) => {
                    let dnsrec = Box::into_raw(Box::new(cached));
                    unsafe { callback(arg, ARES_SUCCESS, 0, dnsrec) };
                    unsafe { crate::ffi::dns_record::ares_dns_record_destroy(dnsrec) };
                    ARES_SUCCESS
                }
                Err(e) => {
                    let status = e.code();
                    unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
                    status
                }
            }
        }
        Ok(None) => ARES_SUCCESS,
        Err(status) => {
            unsafe { callback(arg, status, 0, std::ptr::null_mut()) };
            status
        }
    }
}
