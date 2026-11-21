#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{in_addr};
use crate::ffi::Channel;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ffi::{c_char, c_int, c_uint, c_ushort, c_void, CStr};
use crate::ffi::error::*;
use crate::core::async_client::DecodedOptions;
use crate::ffi::channel::ChannelData;
use crate::ffi::channel::channel_access;
use crate::ares_socket_t;
use crate::mem::{String, Vec};

/// Upstream's private sortlist pattern (address + prefix length), mirrored
/// exactly because `ares_save_options` exposes its layout.
#[repr(C)]
pub struct apattern {
    pub addr: crate::ffi::ares_addr,
    pub mask: libc::c_uchar,
}

pub type ares_evsys_t = c_int;

pub type ares_sock_state_cb =
    Option<extern "C" fn(data: *mut c_void, socket_fd: ares_socket_t, readable: c_int, writable: c_int)>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ares_server_failover_options {
    pub retry_chance: c_ushort, // probability (1/N); 0 disables retries
    pub retry_delay:  libc::size_t,    // minimum delay in milliseconds
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ares_options {
    pub flags: c_int,
    pub timeout: c_int,                      // seconds or millis depending on optmask
    pub tries: c_int,
    pub ndots: c_int,
    pub udp_port: c_ushort,                  // host byte order
    pub tcp_port: c_ushort,                  // host byte order
    pub socket_send_buffer_size: c_int,
    pub socket_receive_buffer_size: c_int,
    pub servers: *mut in_addr,               // IPv4 only; use ares_set_servers for v4/v6
    pub nservers: c_int,
    pub domains: *mut *mut c_char,
    pub ndomains: c_int,
    pub lookups: *mut c_char,
    pub sock_state_cb: ares_sock_state_cb,
    pub sock_state_cb_data: *mut c_void,
    pub sortlist: *mut apattern,             // opaque; only valid via ares_save_options
    pub nsort: c_int,
    pub ednspsz: c_int,
    pub resolvconf_path: *mut c_char,
    pub hosts_path: *mut c_char,
    pub udp_max_queries: c_int,
    pub maxtimeout: c_int,                   // milliseconds
    pub qcache_max_ttl: c_uint,              // seconds; 0 disables cache
    pub evsys: ares_evsys_t,                 // set to ARES_EVSYS_DEFAULT (0)
    pub server_failover_opts: ares_server_failover_options,
}

impl Default for ares_options {
    fn default() -> Self {
        Self {
            flags: 0,
            timeout: 0,
            tries: 0,
            ndots: 0,
            udp_port: 0,
            tcp_port: 0,
            socket_send_buffer_size: 0,
            socket_receive_buffer_size: 0,
            servers: core::ptr::null_mut(),
            nservers: 0,
            domains: core::ptr::null_mut(),
            ndomains: 0,
            lookups: core::ptr::null_mut(),
            sock_state_cb: None,
            sock_state_cb_data: core::ptr::null_mut(),
            sortlist: core::ptr::null_mut(),
            nsort: 0,
            ednspsz: 0,
            resolvconf_path: core::ptr::null_mut(),
            hosts_path: core::ptr::null_mut(),
            udp_max_queries: 0,
            maxtimeout: 0,
            qcache_max_ttl: 0,
            evsys: 0, // ARES_EVSYS_DEFAULT
            server_failover_opts: ares_server_failover_options { retry_chance: 0, retry_delay: 0 },
        }
    }
}

/// Decode `ARES_OPT_SORTLIST` patterns; invalid families/masks are rejected.
fn decode_sortlist(patterns: &[apattern]) -> Result<Vec<(IpAddr, u8)>, c_int> {
    let mut out = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let (ip, max) = match pattern.addr.family {
            libc::AF_INET => {
                let raw = unsafe { pattern.addr.addr.addr4.s_addr };
                (IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))), 32)
            }
            libc::AF_INET6 => {
                let octets = unsafe { pattern.addr.addr.addr6._S6_un._S6_u8 };
                (IpAddr::V6(Ipv6Addr::from(octets)), 128)
            }
            _ => return Err(ARES_EBADSTR),
        };
        if pattern.mask > max {
            return Err(ARES_EBADSTR);
        }
        out.push((ip, pattern.mask));
    }
    Ok(out)
}

pub const ARES_OPT_FLAGS          : c_int = 1 << 0;
pub const ARES_OPT_TIMEOUT        : c_int = 1 << 1;
pub const ARES_OPT_TRIES          : c_int = 1 << 2;
pub const ARES_OPT_NDOTS          : c_int = 1 << 3;
pub const ARES_OPT_UDP_PORT       : c_int = 1 << 4;
pub const ARES_OPT_TCP_PORT       : c_int = 1 << 5;
pub const ARES_OPT_SERVERS        : c_int = 1 << 6;
pub const ARES_OPT_DOMAINS        : c_int = 1 << 7;
pub const ARES_OPT_LOOKUPS        : c_int = 1 << 8;
pub const ARES_OPT_SOCK_STATE_CB  : c_int = 1 << 9;
pub const ARES_OPT_SORTLIST       : c_int = 1 << 10;
pub const ARES_OPT_SOCK_SNDBUF    : c_int = 1 << 11;
pub const ARES_OPT_SOCK_RCVBUF    : c_int = 1 << 12;
pub const ARES_OPT_TIMEOUTMS      : c_int = 1 << 13;
pub const ARES_OPT_ROTATE         : c_int = 1 << 14;
pub const ARES_OPT_EDNSPSZ        : c_int = 1 << 15;
pub const ARES_OPT_NOROTATE       : c_int = 1 << 16;
pub const ARES_OPT_RESOLVCONF     : c_int = 1 << 17;
pub const ARES_OPT_HOSTS_FILE     : c_int = 1 << 18;
pub const ARES_OPT_UDP_MAX_QUERIES: c_int = 1 << 19;
pub const ARES_OPT_MAXTIMEOUTMS   : c_int = 1 << 20;
pub const ARES_OPT_QUERY_CACHE    : c_int = 1 << 21;
pub const ARES_OPT_EVENT_THREAD   : c_int = 1 << 22;
pub const ARES_OPT_SERVER_FAILOVER: c_int = 1 << 23;

pub const ARES_FLAG_USEVC: c_int = 1 << 0;
pub const ARES_FLAG_PRIMARY: c_int = 1 << 1;
pub const ARES_FLAG_IGNTC: c_int = 1 << 2;
pub const ARES_FLAG_NORECURSE: c_int = 1 << 3;
pub const ARES_FLAG_STAYOPEN: c_int = 1 << 4;
pub const ARES_FLAG_NOSEARCH: c_int = 1 << 5;
pub const ARES_FLAG_NOALIASES: c_int = 1 << 6;
pub const ARES_FLAG_NOCHECKRESP: c_int = 1 << 7;
pub const ARES_FLAG_EDNS: c_int = 1 << 8;
pub const ARES_FLAG_NO_DFLT_SVR: c_int = 1 << 9;
#[allow(non_upper_case_globals)] // upstream spelling
pub const ARES_FLAG_DNS0x20: c_int = 1 << 10;

/// # Safety
/// `out_channel` must be non-null; `options` must be NULL or a valid `ares_options` consistent with `optmask`.
#[no_mangle]
pub unsafe extern "C" fn ares_init_options(out_channel: *mut Channel, options: *const ares_options, optmask: c_int) -> c_int {
    // Upstream allows NULL options only when optmask == 0; otherwise ARES_ENODATA.
    if options.is_null() && optmask != 0 {
        return ARES_ENODATA;
    }
    // Bind a zeroed default so no field is read through a NULL pointer.
    let default_opts;
    let options_supplied = !options.is_null();
    let options = if options.is_null() {
        default_opts = ares_options::default();
        &default_opts
    } else {
        unsafe { & *options }
    };
    match init_options_from(optmask, options, options_supplied) {
        Ok(channeldata) => {
            let channel = crate::mem::into_raw(crate::mem::boxed_infallible(channeldata));
            let event_mode = unsafe { (*channel).event_mode.get() };
            if event_mode && !crate::ffi::event_thread::start(channel) {
                unsafe { crate::mem::drop_box(channel) };
                return crate::ffi::error::ARES_ESERVFAIL;
            }
            unsafe { *out_channel = channel };
            ARES_SUCCESS
        }
        Err(status) => status,
    }
}

/// Decode the C option struct and build the unfinalized channel.
fn init_options_from(
    optmask: c_int,
    options: &ares_options,
    options_supplied: bool,
) -> Result<ChannelData, c_int> {
    // Upstream `ares_init_by_options`: a caller-supplied `ares_options` with no
    // query-cache bit gets the documented 3600 s default, recorded in the mask.
    // The plain `ares_init` (NULL options) path does not.
    let query_cache_default = options_supplied && optmask & ARES_OPT_QUERY_CACHE == 0;
    let optmask = if query_cache_default {
        optmask | ARES_OPT_QUERY_CACHE
    } else {
        optmask
    };
    // Upstream rejects the event thread combined with a caller state callback,
    // since the event thread issues those notifications itself.
    if optmask & ARES_OPT_EVENT_THREAD != 0 && optmask & ARES_OPT_SOCK_STATE_CB != 0 {
        return Err(crate::ffi::error::ARES_EFORMERR);
    }
    // Upstream: a backend this platform lacks (kqueue, win32, junk) is ARES_ENOTIMP.
    if optmask & ARES_OPT_EVENT_THREAD != 0 && !crate::ffi::event_backend::supported(options.evsys) {
        return Err(crate::ffi::error::ARES_ENOTIMP);
    }
    let decoded_sortlist = match (optmask & ARES_OPT_SORTLIST != 0)
        .then(|| decode_sortlist_options(options))
    {
        Some(Err(status)) => return Err(status),
        Some(Ok(list)) => list,
        None => None,
    };
    // Only read fields the caller says are initialized (optmask).  C callers
    // commonly pass a partially initialized `struct ares_options`; reading an
    // unset pointer field (Xymon does exactly this) would dereference garbage.
    let decoded = DecodedOptions {
        flags: if optmask & ARES_OPT_FLAGS != 0 { options.flags } else { 0 },
        timeout: if optmask & (ARES_OPT_TIMEOUTMS | ARES_OPT_TIMEOUT) != 0 { options.timeout } else { 0 },
        tries: if optmask & ARES_OPT_TRIES != 0 { options.tries } else { 0 },
        ndots: if optmask & ARES_OPT_NDOTS != 0 { options.ndots } else { 0 },
        udp_port: if optmask & ARES_OPT_UDP_PORT != 0 { options.udp_port } else { 0 },
        tcp_port: if optmask & ARES_OPT_TCP_PORT != 0 { options.tcp_port } else { 0 },
        servers: if optmask & ARES_OPT_SERVERS != 0
            && !options.servers.is_null()
            && options.nservers > 0
        {
            unsafe { std::slice::from_raw_parts(options.servers, options.nservers as usize) }
                .iter()
                .map(|server| Ipv4Addr::from(u32::from_be(server.s_addr)))
                .collect()
        } else {
            // Upstream treats `nservers <= 0` as "not supplied".
            Vec::new()
        },
        domains: if optmask & ARES_OPT_DOMAINS != 0 && !options.domains.is_null() {
            if options.ndomains > 0 {
                let domains =
                    unsafe { std::slice::from_raw_parts(options.domains, options.ndomains as usize) };
                Some(
                    domains
                        .iter()
                        .map(|&p| String::from_utf8_lossy(unsafe { CStr::from_ptr(p) }.to_bytes()))
                        .collect(),
                )
            } else {
                // `ndomains <= 0` is "not supplied"; never build a slice from
                // a negative or huge length.
                Some(Vec::new())
            }
        } else {
            None
        },
        lookups: if optmask & ARES_OPT_LOOKUPS != 0 && !options.lookups.is_null() {
            Some(String::from_utf8_lossy(unsafe { CStr::from_ptr(options.lookups) }.to_bytes()))
        } else {
            None
        },
        sortlist: decoded_sortlist,
        resolvconf_path: if optmask & ARES_OPT_RESOLVCONF != 0 && !options.resolvconf_path.is_null() {
            Some(String::from_utf8_lossy(unsafe { CStr::from_ptr(options.resolvconf_path) }.to_bytes()))
        } else {
            None
        },
        hosts_path: if optmask & ARES_OPT_HOSTS_FILE != 0 && !options.hosts_path.is_null() {
            Some(String::from_utf8_lossy(unsafe { CStr::from_ptr(options.hosts_path) }.to_bytes()))
        } else {
            None
        },
        maxtimeout: if optmask & ARES_OPT_MAXTIMEOUTMS != 0 { options.maxtimeout } else { 0 },
        qcache_max_ttl: if optmask & ARES_OPT_QUERY_CACHE != 0 {
            if query_cache_default {
                3600
            } else {
                options.qcache_max_ttl
            }
        } else {
            0
        },
        ednspsz: if optmask & ARES_OPT_EDNSPSZ != 0 { options.ednspsz } else { 0 },
        udp_max_queries: if optmask & ARES_OPT_UDP_MAX_QUERIES != 0 { options.udp_max_queries } else { 0 },
        socket_send_buffer_size: if optmask & ARES_OPT_SOCK_SNDBUF != 0 { options.socket_send_buffer_size } else { 0 },
        socket_receive_buffer_size: if optmask & ARES_OPT_SOCK_RCVBUF != 0 { options.socket_receive_buffer_size } else { 0 },
        failover_retry_chance: if optmask & ARES_OPT_SERVER_FAILOVER != 0 {
            options.server_failover_opts.retry_chance
        } else {
            0
        },
        failover_retry_delay: if optmask & ARES_OPT_SERVER_FAILOVER != 0 {
            options.server_failover_opts.retry_delay as u64
        } else {
            0
        },
    };

    let resolvconf = if optmask & ARES_OPT_RESOLVCONF != 0 {
        decoded.resolvconf_path.clone()
    } else {
        None
    };
    let channeldata = ChannelData::new_unfinalized(resolvconf.as_deref());
    channeldata.event_mode.set(optmask & ARES_OPT_EVENT_THREAD != 0);
    if channeldata.event_mode.get() {
        channeldata.evsys.set(options.evsys);
    }
    channeldata.state.borrow_mut().apply_options(optmask, decoded);
    // Upstream `init_by_defaults`: with ARES_FLAG_NO_DFLT_SVR and no nameserver
    // configured there is nothing to resolve with, so initialization fails
    // rather than handing back a channel that can only return ENOSERVER.
    {
        let state = channeldata.state.borrow();
        if state.flags & ARES_FLAG_NO_DFLT_SVR != 0 && state.config.nameservers.is_empty() {
            drop(state);
            return Err(ARES_ENOSERVER);
        }
    }
    install_socket_options(&channeldata, optmask, options);
    Ok(channeldata)
}

/// Apply the socket state callback and refresh the socket configuration.
fn install_socket_options(channeldata: &ChannelData, optmask: c_int, options: &ares_options) {
    if optmask & ARES_OPT_SOCK_STATE_CB != 0 {
        channeldata.sock_state_cb.set(options.sock_state_cb);
        channeldata.sock_state_cb_data.set(options.sock_state_cb_data);
    }
    channeldata.refresh_socket_config();
}

/// Report the stored socket state callback. `out` is a raw pointer because the
/// caller's struct may be an older, smaller `ares_options`.
fn save_socket_options(channeldata: &ChannelData, out: *mut ares_options, mask: &mut c_int) {
    if channeldata.state.borrow().optmask & ARES_OPT_SOCK_STATE_CB != 0 {
        unsafe {
            std::ptr::addr_of_mut!((*out).sock_state_cb).write(channeldata.sock_state_cb.get());
            std::ptr::addr_of_mut!((*out).sock_state_cb_data)
                .write(channeldata.sock_state_cb_data.get());
        }
        *mask |= ARES_OPT_SOCK_STATE_CB;
    }
}

/// Decode `ARES_OPT_SORTLIST`; `Some(empty)` means explicit `nsort == 0` (clears).
fn decode_sortlist_options(options: &ares_options) -> Result<Option<Vec<(IpAddr, u8)>>, c_int> {
    if options.nsort <= 0 {
        return Ok(Some(Vec::new()));
    }
    if options.sortlist.is_null() {
        return Err(ARES_EBADSTR);
    }
    let patterns = unsafe {
        std::slice::from_raw_parts(options.sortlist as *const apattern, options.nsort as usize)
    };
    decode_sortlist(patterns).map(Some)
}

/// Copy sortlist entries into a caller-owned callback-allocated array.
fn save_sortlist(entries: &[crate::core::sortlist::SortlistEntry]) -> Option<(*mut apattern, c_int)> {
    let count = entries.len();
    let arr = crate::mem::malloc(count.checked_mul(std::mem::size_of::<apattern>())?) as *mut apattern;
    if arr.is_null() {
        return None;
    }
    for (i, entry) in entries.iter().enumerate() {
        let (family, addr) = match entry.addr() {
            IpAddr::V4(v4) => (
                libc::AF_INET,
                crate::ffi::AresAddrUnion {
                    addr4: libc::in_addr { s_addr: u32::from(v4).to_be() },
                },
            ),
            IpAddr::V6(v6) => (
                libc::AF_INET6,
                crate::ffi::AresAddrUnion {
                    addr6: crate::ffi::ares_in6_addr::from_octets(v6.octets()),
                },
            ),
        };
        unsafe {
            *arr.add(i) = apattern {
                addr: crate::ffi::ares_addr { family, addr },
                mask: entry.mask_bits(),
            };
        }
    }
    Some((arr, count as c_int))
}

/// Write one scalar field of the caller's (possibly older/smaller)
/// `ares_options` only when the channel's optmask selected it. Using
/// `addr_of_mut!` avoids forming a reference to the full current struct.
macro_rules! save_opt_field {
    ($out:expr, $mask:expr, $bit:expr, $field:ident, $value:expr) => {
        if $mask & $bit != 0 {
            unsafe { std::ptr::addr_of_mut!((*$out).$field).write($value) };
        }
    };
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_save_options(channel: *const ChannelData, options: *mut ares_options, optmask: *mut c_int) -> c_int {
    if options.is_null() || optmask.is_null() || channel.is_null() { return ARES_ENODATA; }
    let Some((_guard, channeldata)) = (unsafe { channel_access(channel) }) else { return ARES_ENODATA; };
    let state = channeldata.state.borrow();
    let saved = state.saved_options();
    let out = options;
    let mut mask = saved.mask;

    // `ares_destroy_options` has no optmask argument, so every pointer field it
    // may free must start out NULL. Do NOT zero the whole struct: the caller
    // may have compiled against an older, smaller `ares_options`.
    unsafe {
        std::ptr::addr_of_mut!((*out).servers).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*out).domains).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*out).sortlist).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*out).lookups).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*out).resolvconf_path).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*out).hosts_path).write(std::ptr::null_mut());
    }

    save_flags_and_ednspsz(out, saved.flags, saved.ednspsz, mask);
    save_opt_field!(out, mask, ARES_OPT_TIMEOUTMS, timeout, saved.timeout);
    save_opt_field!(out, mask, ARES_OPT_TRIES, tries, saved.tries);
    save_opt_field!(out, mask, ARES_OPT_NDOTS, ndots, saved.ndots);
    save_opt_field!(out, mask, ARES_OPT_UDP_PORT, udp_port, saved.udp_port);
    save_opt_field!(out, mask, ARES_OPT_TCP_PORT, tcp_port, saved.tcp_port);
    save_opt_field!(out, mask, ARES_OPT_UDP_MAX_QUERIES, udp_max_queries, saved.udp_max_queries);
    if mask & ARES_OPT_SOCK_SNDBUF != 0 && saved.socket_send_buffer_size > 0 {
        unsafe {
            std::ptr::addr_of_mut!((*out).socket_send_buffer_size)
                .write(saved.socket_send_buffer_size)
        };
    }
    if mask & ARES_OPT_SOCK_RCVBUF != 0 && saved.socket_receive_buffer_size > 0 {
        unsafe {
            std::ptr::addr_of_mut!((*out).socket_receive_buffer_size)
                .write(saved.socket_receive_buffer_size)
        };
    }

    // Servers/domains are malloc'd for the caller. An allocation failure is
    // ARES_ENOMEM (upstream behavior); fields already written remain freeable.
    if mask & ARES_OPT_SERVERS != 0 {
        let v4_servers = saved.servers.iter().filter_map(|(ip, _)| match ip {
            IpAddr::V4(v4) => Some(*v4), _ => None,
        });
        let count = v4_servers.clone().count();
        if count > 0 {
            let Some(size) = count.checked_mul(std::mem::size_of::<in_addr>()) else { return ARES_ENOMEM };
            let ptr = crate::mem::malloc(size) as *mut in_addr;
            if ptr.is_null() {
                return ARES_ENOMEM;
            }
            for (i, v4) in v4_servers.enumerate() {
                unsafe { *ptr.add(i) = in_addr { s_addr: u32::from(v4).to_be() } };
            }
            unsafe {
                std::ptr::addr_of_mut!((*out).servers).write(ptr);
                std::ptr::addr_of_mut!((*out).nservers).write(count as c_int);
            }
        } else {
            unsafe { std::ptr::addr_of_mut!((*out).nservers).write(0) };
        }
    }
    if mask & ARES_OPT_DOMAINS != 0 {
        let count = saved.domains.len();
        if count > 0 {
            let Some(size) = count.checked_mul(std::mem::size_of::<*mut c_char>()) else { return ARES_ENOMEM };
            let arr = crate::mem::malloc(size) as *mut *mut c_char;
            if arr.is_null() {
                return ARES_ENOMEM;
            }
            unsafe {
                std::ptr::addr_of_mut!((*out).domains).write(arr);
                std::ptr::addr_of_mut!((*out).ndomains).write(0);
            }
            for (i, domain) in saved.domains.iter().enumerate() {
                let cstr = save_string(domain);
                if cstr.is_null() { return ARES_ENOMEM; }
                unsafe {
                    arr.add(i).write(cstr);
                    std::ptr::addr_of_mut!((*out).ndomains).write((i + 1) as c_int);
                }
            }
        } else {
            unsafe { std::ptr::addr_of_mut!((*out).ndomains).write(0) };
        }
    }
    if mask & ARES_OPT_SORTLIST != 0 && !save_sortlist_into(out, saved.sortlist) {
        return ARES_ENOMEM;
    }

    if let Some(maxtimeout) = saved.maxtimeout {
        unsafe { std::ptr::addr_of_mut!((*out).maxtimeout).write(maxtimeout) };
    }
    if let Some(lookups) = saved.lookups {
        let ptr = save_string(lookups);
        if ptr.is_null() { return ARES_ENOMEM; }
        unsafe { std::ptr::addr_of_mut!((*out).lookups).write(ptr) };
    }
    if let Some(path) = saved.resolvconf_path {
        let ptr = save_string(path);
        if ptr.is_null() { return ARES_ENOMEM; }
        unsafe { std::ptr::addr_of_mut!((*out).resolvconf_path).write(ptr) };
    }
    if let Some(path) = saved.hosts_path {
        let ptr = save_string(path);
        if ptr.is_null() { return ARES_ENOMEM; }
        unsafe { std::ptr::addr_of_mut!((*out).hosts_path).write(ptr) };
    }
    if let Some(ttl) = saved.qcache_max_ttl {
        unsafe { std::ptr::addr_of_mut!((*out).qcache_max_ttl).write(ttl) };
    }
    if let Some((chance, delay)) = saved.server_failover {
        unsafe {
            std::ptr::addr_of_mut!((*out).server_failover_opts.retry_chance).write(chance);
            std::ptr::addr_of_mut!((*out).server_failover_opts.retry_delay)
                .write(delay as libc::size_t);
        }
    }
    save_socket_options(channeldata, out, &mut mask);
    if channeldata.event_mode.get() {
        mask |= ARES_OPT_EVENT_THREAD;
        unsafe { std::ptr::addr_of_mut!((*out).evsys).write(channeldata.evsys.get()) };
    }

    unsafe { *optmask = mask };
    ARES_SUCCESS
}

/// Copy the flags word and optional EDNS payload size into a saved options struct.
fn save_flags_and_ednspsz(out: *mut ares_options, flags: c_int, ednspsz: c_int, mask: c_int) {
    save_opt_field!(out, mask, ARES_OPT_FLAGS, flags, flags);
    save_opt_field!(out, mask, ARES_OPT_EDNSPSZ, ednspsz, ednspsz);
}

fn save_string(value: &str) -> *mut c_char {
    // Preserve the previous empty-string fallback for embedded NULs.
    let bytes = if value.as_bytes().contains(&0) { &[] } else { value.as_bytes() };
    unsafe { crate::ffi::convert::malloc_cstr(bytes) }
}

fn free_sortlist(ptr: *mut apattern) {
    if !ptr.is_null() {
        unsafe { crate::mem::free(ptr as *mut c_void) };
    }
}

/// Fill `out.sortlist`/`out.nsort`. Returns `false` only when the allocation
/// failed; the mask bit is provided by the caller.
fn save_sortlist_into(
    out: *mut ares_options,
    entries: &[crate::core::sortlist::SortlistEntry],
) -> bool {
    if entries.is_empty() {
        // An explicit empty sortlist is written as NULL/0.
        unsafe { std::ptr::addr_of_mut!((*out).nsort).write(0) };
        return true;
    }
    let Some((arr, count)) = save_sortlist(entries) else {
        return false;
    };
    unsafe {
        std::ptr::addr_of_mut!((*out).sortlist).write(arr);
        std::ptr::addr_of_mut!((*out).nsort).write(count);
    }
    true
}

/// Free and clear a saved sortlist on an options struct.
fn take_sortlist(opts: &mut ares_options) {
    if opts.sortlist.is_null() {
        return;
    }
    free_sortlist(opts.sortlist);
    opts.sortlist = std::ptr::null_mut();
    opts.nsort = 0;
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy_options(options: *mut ares_options) {
    if options.is_null() { return; }
    let opts = unsafe { &mut *options };

    if !opts.servers.is_null() {
        unsafe { crate::mem::free(opts.servers as *mut c_void) };
        opts.servers = std::ptr::null_mut();
    }

    if !opts.domains.is_null() {
        // Signed range: a negative ndomains yields no iterations, matching
        // upstream's `for (i = 0; i < ndomains; i++)` and avoiding a huge usize.
        for i in 0..opts.ndomains {
            let ptr = unsafe { *opts.domains.add(i as usize) };
            if !ptr.is_null() {
                unsafe { crate::mem::free(ptr.cast()) };
            }
        }
        unsafe { crate::mem::free(opts.domains as *mut c_void) };
        opts.domains = std::ptr::null_mut();
    }

    take_sortlist(opts);

    if !opts.lookups.is_null() {
        unsafe { crate::mem::free(opts.lookups.cast()) };
        opts.lookups = std::ptr::null_mut();
    }

    if !opts.resolvconf_path.is_null() {
        unsafe { crate::mem::free(opts.resolvconf_path.cast()) };
        opts.resolvconf_path = std::ptr::null_mut();
    }

    if !opts.hosts_path.is_null() {
        unsafe { crate::mem::free(opts.hosts_path.cast()) };
        opts.hosts_path = std::ptr::null_mut();
    }
}
