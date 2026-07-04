#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{in_addr};
use crate::ffi::Channel;
use std::net::Ipv4Addr;
use std::ffi::{c_char, c_int, c_uint, c_ushort, c_void, CStr};
use crate::ffi::error::*;
use crate::core::channel::DecodedOptions;
use crate::ffi::channel::ChannelData;
use crate::ares_socket_t;

#[repr(C)]
pub struct apattern {
    _private: [u8; 0],
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

// ------- The ares_options struct itself -------

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

pub(crate) const ARES_FLAG_USEVC: c_int = 1 << 0;
pub(crate) const ARES_FLAG_PRIMARY: c_int = 1 << 1;
pub(crate) const ARES_FLAG_NOCHECKRESP: c_int = 1 << 7;
pub(crate) const ARES_FLAG_EDNS: c_int = 1 << 8;

/// # Safety
/// `out_channel` must be non-null; `options` must be NULL or a valid `ares_options` consistent with `optmask`.
#[no_mangle]
pub unsafe extern "C" fn ares_init_options(out_channel: *mut Channel, options: *const ares_options, optmask: c_int) -> c_int {
    // The built-in event thread is not supported. Match upstream c-ares on a
    // non-threaded build: report ARES_ENOTIMP and leave *out_channel untouched.
    if optmask & ARES_OPT_EVENT_THREAD != 0 {
        return ARES_ENOTIMP;
    }
    // Upstream allows a NULL options pointer only when optmask == 0 (equivalent
    // to ares_init); a non-zero optmask with NULL options is ARES_ENODATA.
    if options.is_null() && optmask != 0 {
        return ARES_ENODATA;
    }
    // options may be NULL here only when optmask == 0 (checked above); bind a
    // zeroed default in that case so no field is ever read through a NULL pointer.
    let default_opts;
    let options = if options.is_null() {
        default_opts = ares_options::default();
        &default_opts
    } else {
        unsafe { & *options }
    };

    // Marshal every C field into an owned mirror before any logic runs.
    let decoded = DecodedOptions {
        flags: options.flags,
        timeout: options.timeout,
        tries: options.tries,
        ndots: options.ndots,
        udp_port: options.udp_port,
        tcp_port: options.tcp_port,
        servers: if optmask & ARES_OPT_SERVERS != 0 && !options.servers.is_null() {
            unsafe { std::slice::from_raw_parts(options.servers, options.nservers as usize) }
                .iter()
                .map(|server| Ipv4Addr::from(u32::from_be(server.s_addr)))
                .collect()
        } else {
            Vec::new()
        },
        domains: if optmask & ARES_OPT_DOMAINS != 0 && !options.domains.is_null() {
            let domains = unsafe { std::slice::from_raw_parts(options.domains, options.ndomains as usize) };
            Some(
                domains
                    .iter()
                    .map(|&p| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
                    .collect(),
            )
        } else {
            None
        },
        lookups: (!options.lookups.is_null())
            .then(|| unsafe { CStr::from_ptr(options.lookups) }.to_string_lossy().into_owned()),
        resolvconf_path: (!options.resolvconf_path.is_null())
            .then(|| unsafe { CStr::from_ptr(options.resolvconf_path) }.to_string_lossy().into_owned()),
        hosts_path: (!options.hosts_path.is_null())
            .then(|| unsafe { CStr::from_ptr(options.hosts_path) }.to_string_lossy().into_owned()),
        udp_max_queries: options.udp_max_queries,
        maxtimeout: options.maxtimeout,
        qcache_max_ttl: options.qcache_max_ttl,
        failover_retry_chance: options.server_failover_opts.retry_chance,
        failover_retry_delay: options.server_failover_opts.retry_delay as u64,
    };

    let mut channeldata = ChannelData::new_default();
    channeldata.state.apply_options(optmask, decoded);
    let channel = Box::into_raw(Box::new(channeldata));
    unsafe { *out_channel = channel };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_save_options(channel: Channel, options: *mut ares_options, optmask: *mut c_int) -> c_int {
    if options.is_null() || optmask.is_null() { return ARES_ENODATA; }
    let Some(channeldata) = (unsafe { channel.as_ref() }) else { return ARES_ENODATA; };
    let saved = channeldata.state.saved_options();

    let out = unsafe { &mut *options };
    *out = ares_options::default();
    let mut mask = saved.base_mask;

    out.flags = saved.flags;
    out.timeout = saved.timeout;
    out.tries = saved.tries;
    out.ndots = saved.ndots;
    out.udp_port = saved.udp_port;
    out.tcp_port = saved.tcp_port;

    // servers / domains transfer through libc::malloc; their mask bits are
    // reported only when the allocation lands (matches the historical shape).
    if !saved.v4_servers.is_empty() {
        let count = saved.v4_servers.len();
        let ptr = unsafe { libc::malloc(count * std::mem::size_of::<in_addr>()) as *mut in_addr };
        if !ptr.is_null() {
            for (i, v4) in saved.v4_servers.iter().enumerate() {
                unsafe { *ptr.add(i) = in_addr { s_addr: u32::from(*v4).to_be() } };
            }
            out.servers = ptr;
            out.nservers = count as c_int;
            mask |= ARES_OPT_SERVERS;
        }
    }
    if !saved.domains.is_empty() {
        let count = saved.domains.len();
        let arr = unsafe { libc::malloc(count * std::mem::size_of::<*mut c_char>()) as *mut *mut c_char };
        if !arr.is_null() {
            for (i, cstr) in saved.domains.into_iter().enumerate() {
                unsafe { *arr.add(i) = cstr.into_raw() };
            }
            out.domains = arr;
            out.ndomains = count as c_int;
            mask |= ARES_OPT_DOMAINS;
        }
    }

    if let Some(maxtimeout) = saved.maxtimeout {
        out.maxtimeout = maxtimeout;
    }
    if let Some(lookups) = saved.lookups {
        out.lookups = lookups.into_raw();
    }
    if let Some(path) = saved.resolvconf_path {
        out.resolvconf_path = path.into_raw();
    }
    if let Some(path) = saved.hosts_path {
        out.hosts_path = path.into_raw();
    }

    unsafe { *optmask = mask };
    ARES_SUCCESS
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn ares_destroy_options(options: *mut ares_options) {
    if options.is_null() { return; }
    let opts = unsafe { &mut *options };

    // Free servers array
    if !opts.servers.is_null() {
        unsafe { libc::free(opts.servers as *mut c_void) };
        opts.servers = std::ptr::null_mut();
    }

    // Free domains array
    if !opts.domains.is_null() {
        // Iterate the signed range so a negative ndomains yields no iterations
        // (`0..negative` is empty), exactly like upstream's signed
        // `for (i = 0; i < ndomains; i++)`. Avoids the negative-to-huge-usize trap.
        for i in 0..opts.ndomains {
            let ptr = unsafe { *opts.domains.add(i as usize) };
            if !ptr.is_null() {
                drop(unsafe { std::ffi::CString::from_raw(ptr) });
            }
        }
        unsafe { libc::free(opts.domains as *mut c_void) };
        opts.domains = std::ptr::null_mut();
    }

    // Free lookups string
    if !opts.lookups.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(opts.lookups) });
        opts.lookups = std::ptr::null_mut();
    }

    // Free resolvconf_path
    if !opts.resolvconf_path.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(opts.resolvconf_path) });
        opts.resolvconf_path = std::ptr::null_mut();
    }

    // Free hosts_path
    if !opts.hosts_path.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(opts.hosts_path) });
        opts.hosts_path = std::ptr::null_mut();
    }
}
